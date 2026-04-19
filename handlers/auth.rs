use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    models::{
        self, AppError, AppState, AuthRequest, AuthResponse, JwtInterceptor, RefreshTokenRequest,
    },
    utility::now_secs,
};

#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let existing = sqlx::query_scalar!(
        "SELECT username FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if existing.is_some() {
        return Ok((StatusCode::CONFLICT, "User already exists").into_response());
    }

    // ← moved to spawn_blocking just like login
    let password = payload.password.clone();
    let hash_password = tokio::task::spawn_blocking(move || {
        bcrypt::hash(&password, 12)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|_| AppError::Internal("Failed to hash password".to_string()))?;

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        payload.username,
        hash_password
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((StatusCode::CREATED, "User Created Successfully").into_response())
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::AuthError("Invalid username or password".to_string()))?;

    let saved_hash = user.password_hash;
    let is_valid = tokio::task::spawn_blocking(move || {
        bcrypt::verify(&payload.password, &saved_hash).unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if !is_valid {
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

    // ← store in DB instead of memory
    sqlx::query!(
        "INSERT INTO refresh_tokens (username, token)
         VALUES ($1, $2)
         ON CONFLICT (username) DO UPDATE SET token = $2, created_at = NOW()",
        payload.username,
        refresh_token,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(AuthResponse { access_token, refresh_token }))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let token_data = decode::<JwtInterceptor>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.refresh_secret.as_bytes()),
        &Validation::default(),
    )?;

    let username = &token_data.claims.user_token_or_id;

    let stored = sqlx::query_scalar!(
        "SELECT token FROM refresh_tokens WHERE username = $1",
        username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::AuthError("Refresh token revoked or not found".to_string()))?;

    if stored != payload.refresh_token {
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

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: payload.refresh_token,
    }))
}

pub async fn logout(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // ← delete from DB instead of memory
    let _ = sqlx::query!(
        "DELETE FROM refresh_tokens WHERE username = $1",
        interceptor.user_token_or_id
    )
    .execute(&state.db)
    .await;

    StatusCode::OK.into_response()
}