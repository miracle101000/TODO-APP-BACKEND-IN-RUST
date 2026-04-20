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

#[axum::debug_handler]
#[instrument(skip(state, payload), fields(username = %payload.username))]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Register attempt");

    let existing = sqlx::query_scalar!(
        "SELECT username FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error checking existing user");
        counter!("auth.register.db_errors", "op" => "check_existing").increment(1);
        AppError::Internal(e.to_string())
    })?;

    if existing.is_some() {
        warn!("Registration attempted with already existing username");
        counter!("auth.register.failures", "reason" => "username_taken").increment(1);
        return Ok((StatusCode::CONFLICT, "User already exists").into_response());
    }

    let password = payload.password.clone();
    let hash_password = tokio::task::spawn_blocking(move || {
        bcrypt::hash(&password, 12)
    })
    .await
    .map_err(|e| {
        error!(error = %e, "Thread error while hashing password");
        counter!("auth.register.failures", "reason" => "hash_thread_error").increment(1);
        AppError::Internal(e.to_string())
    })?
    .map_err(|e| {
        error!(error = %e, "Failed to hash password");
        counter!("auth.register.failures", "reason" => "hash_error").increment(1);
        AppError::Internal("Failed to hash password".to_string())
    })?;

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        payload.username,
        hash_password
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error inserting new user");
        counter!("auth.register.db_errors", "op" => "insert_user").increment(1);
        AppError::Internal(e.to_string())
    })?;

    let username_for_email = payload.username.clone();
    tokio::spawn(async move {
        if let Err(e) = send_welcome_email(&username_for_email).await {
            error!(
                error    = %e,
                username = %username_for_email,
                "Background: failed to send welcome email"
            );
            counter!("jobs.welcome_email.errors").increment(1);
        } else {
            info!(username = %username_for_email, "Background: welcome email sent");
            counter!("jobs.welcome_email.sent").increment(1);
        }
    });


    counter!("auth.register.success").increment(1);
    histogram!("auth.register.duration_ms").record(start.elapsed().as_millis() as f64);

    info!("User registered successfully");
    Ok((StatusCode::CREATED, "User Created Successfully").into_response())
}

async fn send_welcome_email(username: &str) -> Result<(), String> {
    info!(username = %username, "Sending welcome email");
    // e.g. resend_client.send(...).await
    Ok(())
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
    .await
    .map_err(|e| {
        error!(error = %e, "Database error fetching user during login");
        counter!("auth.login.db_errors", "op" => "fetch_user").increment(1);
        AppError::Internal(e.to_string())
    })?
    .ok_or_else(|| {
        warn!("Login attempted with unknown username");
        counter!("auth.login.failures", "reason" => "unknown_user").increment(1);
        AppError::AuthError("Invalid username or password".to_string())
    })?;

    let saved_hash = user.password_hash;
    let is_valid = tokio::task::spawn_blocking(move || {
        bcrypt::verify(&payload.password, &saved_hash).unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if !is_valid {
        warn!("Login attempted with wrong password");
        counter!("auth.login.failures", "reason" => "wrong_password").increment(1);
        return Err(AppError::AuthError("Invalid username or password".to_string()));
    }

    let now = now_secs()?;

    let access_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: payload.username.clone(),
            expiration_date_in_milliseconds: now + 15 * 60,
            issued_at: now,
            token_type: models::TokenType::Access,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?;

    let refresh_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: payload.username.clone(),
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
        payload.username,
        refresh_token,
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error storing refresh token");
        counter!("auth.login.db_errors", "op" => "store_refresh_token").increment(1);
        AppError::Internal(e.to_string())
    })?;

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

    let token_data = decode::<JwtInterceptor>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.refresh_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        warn!(error = %e, "Invalid or expired refresh token");
        counter!("auth.refresh.failures", "reason" => "invalid_token").increment(1);
        e
    })?;

    let username = &token_data.claims.user_token_or_id;

    let stored = sqlx::query_scalar!(
        "SELECT token FROM refresh_tokens WHERE username = $1",
        username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error fetching stored refresh token");
        counter!("auth.refresh.db_errors", "op" => "fetch_token").increment(1);
        AppError::Internal(e.to_string())
    })?
    .ok_or_else(|| {
        warn!(username = %username, "Refresh token not found — possibly revoked");
        counter!("auth.refresh.failures", "reason" => "token_revoked").increment(1);
        AppError::AuthError("Refresh token revoked or not found".to_string())
    })?;

    if stored != payload.refresh_token {
        warn!(username = %username, "Refresh token mismatch — possible token reuse attack");
        counter!("auth.refresh.failures", "reason" => "token_reuse").increment(1);
        return Err(AppError::AuthError("Refresh token revoked or not found".to_string()));
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

    info!(username = %username, "Access token refreshed successfully");
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
    .await;

    match result {
        Ok(r) if r.rows_affected() == 0 => {
            warn!("Logout called but no active session found");
            counter!("auth.logout.failures", "reason" => "no_session").increment(1);
            Ok(StatusCode::OK.into_response())
        }
        Ok(_) => {
            counter!("auth.logout.success").increment(1);
            histogram!("auth.logout.duration_ms").record(start.elapsed().as_millis() as f64);
            info!("User logged out successfully");
            Ok(StatusCode::OK.into_response())
        }
        Err(e) => {
            error!(error = %e, "Database error during logout");
            counter!("auth.logout.db_errors", "op" => "delete_token").increment(1);
            Err(AppError::Internal(format!("Logout failed: {}", e)))
        }
    }
}