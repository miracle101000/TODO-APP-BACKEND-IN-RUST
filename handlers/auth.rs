use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    models::{
        self, AppError, AppState, AuthRequest, AuthResponse, JwtInterceptor, RefreshTokenRequest,
    },
    utility::now_secs,
};

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let token_data = decode::<JwtInterceptor>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.refresh_secret.as_bytes()),
        &Validation::default(),
    )?;

    let claims = token_data.claims;
    let username = &claims.user_token_or_id;

    let stored_token = state
        .refresh_tokens
        .lock()
        .get(username)
        .cloned()
        .ok_or_else(|| AppError::AuthError("Refresh Token Revoked or Not found".to_string()))?;

    if stored_token != payload.refresh_token {
        return Err(AppError::AuthError(
            "Refresh Token Revoked or Not found".to_string(),
        ));
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

    let hash_password = bcrypt::hash(&payload.password, 12)
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
        return Err(AppError::AuthError(
            "Invalid username or password".to_string(),
        ));
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

    state
        .refresh_tokens
        .lock()
        .insert(payload.username.clone(), refresh_token.clone());

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn logout(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> impl IntoResponse {
    state
        .refresh_tokens
        .lock()
        .remove(&interceptor.user_token_or_id);
    StatusCode::OK.into_response()
}
