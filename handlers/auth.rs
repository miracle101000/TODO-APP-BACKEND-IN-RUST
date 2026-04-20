use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use tracing::{info, warn, error, instrument};
use metrics::{counter, histogram};
use std::time::Instant;

use crate::{
    models::{
        self, AppError, AppState, AuthRequest, AuthResponse, JwtInterceptor, RefreshTokenRequest,
    },
    utility::now_secs,
};

use anyhow::Context;

#[instrument(skip(state, payload), fields(username = %payload.username))]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Register attempt");

    let exists = sqlx::query_scalar!(
        "SELECT username FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.db)
    .await?; // ← just ? now, From<sqlx::Error> handles it

    if exists.is_some() {
        warn!("Registration attempted with existing username");
        counter!("auth.register.failures", "reason" => "username_taken").increment(1);
        return Ok((StatusCode::CONFLICT, "User already exists").into_response());
    }

    let username = payload.username;
    let password = payload.password;

    let hash_password = tokio::task::spawn_blocking(move || {
        bcrypt::hash(&password, 12)
    })
    .await
    // anyhow::Context adds a message to any error type
    .context("Hash thread panicked")?
    .context("Failed to hash password")?;

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        username,
        hash_password
    )
    .execute(&state.db)
    .await?; // ← just ? — sqlx::Error → AppError::Database automatically

    let username_for_email = username.clone();
    tokio::spawn(async move {
        if let Err(e) = send_welcome_email(&username_for_email).await {
            error!(error = %e, username = %username_for_email, "Failed to send welcome email");
            counter!("jobs.welcome_email.errors").increment(1);
        } else {
            info!(username = %username_for_email, "Welcome email sent");
            counter!("jobs.welcome_email.sent").increment(1);
        }
    });

    counter!("auth.register.success").increment(1);
    histogram!("auth.register.duration_ms").record(start.elapsed().as_millis() as f64);

    info!("User registered successfully");
    Ok((StatusCode::CREATED, "User Created Successfully").into_response())
}

#[instrument(skip(state, payload), fields(username = %payload.username))]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Login attempt");

    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.db)
    .await? // ← sqlx::Error handled automatically
    .ok_or_else(|| {
        warn!("Login with unknown username");
        counter!("auth.login.failures", "reason" => "unknown_user").increment(1);
        AppError::Auth("Invalid username or password".to_string())
    })?;

    let saved_hash = user.password_hash;
    let is_valid = tokio::task::spawn_blocking(move || {
        bcrypt::verify(&payload.password, &saved_hash).unwrap_or(false)
    })
    .await
    .context("Password verify thread panicked")?; // anyhow context

    if !is_valid {
        warn!("Login with wrong password");
        counter!("auth.login.failures", "reason" => "wrong_password").increment(1);
        return Err(AppError::Auth("Invalid username or password".to_string()));
    }

    let now = now_secs()?;
    let username = payload.username;

    let access_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: username.clone(),
            expiration_date_in_milliseconds: now + 15 * 60,
            issued_at: now,
            token_type: models::TokenType::Access,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?; // ← jwt error handled automatically via #[from]

    let refresh_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: username.clone(),
            expiration_date_in_milliseconds: now + 7 * 24 * 60 * 60,
            issued_at: now,
            token_type: models::TokenType::Refresh,
        },
        &EncodingKey::from_secret(state.refresh_secret.as_bytes()),
    )?;

    sqlx::query!(
        "INSERT INTO refresh_tokens (username, token)
         VALUES ($1, $2)
         ON CONFLICT (username) DO UPDATE SET token = $2, created_at = NOW()",
        username,
        refresh_token,
    )
    .execute(&state.db)
    .await?; // ← just ?

    counter!("auth.login.success").increment(1);
    histogram!("auth.login.duration_ms").record(start.elapsed().as_millis() as f64);

    info!("User logged in successfully");
    Ok(Json(AuthResponse { access_token, refresh_token }))
}

#[instrument(skip(state, payload))]
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Token refresh attempt");

    // jwt error → AppError::Jwt automatically
    let token_data = decode::<JwtInterceptor>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.refresh_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        warn!(error = %e, "Invalid or expired refresh token");
        counter!("auth.refresh.failures", "reason" => "invalid_token").increment(1);
        e // just return the jwt error — From converts it
    })?;

    let username = &token_data.claims.user_token_or_id;

    let stored = sqlx::query_scalar!(
        "SELECT token FROM refresh_tokens WHERE username = $1",
        username
    )
    .fetch_optional(&state.db)
    .await? // ← just ?
    .ok_or_else(|| {
        warn!(username = %username, "Refresh token not found");
        counter!("auth.refresh.failures", "reason" => "token_revoked").increment(1);
        AppError::Auth("Refresh token revoked or not found".to_string())
    })?;

    if stored != payload.refresh_token {
        warn!(username = %username, "Token reuse attack detected");
        counter!("auth.refresh.failures", "reason" => "token_reuse").increment(1);
        return Err(AppError::Auth("Refresh token revoked or not found".to_string()));
    }

    let now = now_secs()?;

    let access_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: username.clone(),
            expiration_date_in_milliseconds: now + 15 * 60,
            issued_at: now,
            token_type: models::TokenType::Access,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?;

    counter!("auth.refresh.success").increment(1);
    histogram!("auth.refresh.duration_ms").record(start.elapsed().as_millis() as f64);

    info!(username = %username, "Access token refreshed");
    Ok(Json(AuthResponse {
        access_token,
        refresh_token: payload.refresh_token,
    }))
}

#[instrument(skip(state), fields(username = %interceptor.user_token_or_id))]
pub async fn logout(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Logout attempt");

    let result = sqlx::query!(
        "DELETE FROM refresh_tokens WHERE username = $1",
        interceptor.user_token_or_id
    )
    .execute(&state.db)
    .await?; // ← just ?

    match result.rows_affected() {
        0 => {
            warn!("Logout called but no active session found");
            counter!("auth.logout.failures", "reason" => "no_session").increment(1);
        }
        _ => {
            counter!("auth.logout.success").increment(1);
            histogram!("auth.logout.duration_ms").record(start.elapsed().as_millis() as f64);
            info!("User logged out successfully");
        }
    }

    Ok(StatusCode::OK.into_response())
}