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

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let saved_hash = {
        let users = state.users.lock();
        users
            .get(&payload.username)
            .cloned()
            .ok_or_else(|| AppError::AuthError("Invalid username or password".to_string()))?
    };

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

#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let mut users = state.users.lock();

    if users.contains_key(&payload.username) {
        return Ok((StatusCode::CONFLICT, "User already exists").into_response());
    }

    let hash_password = bcrypt::hash(&payload.password, 12)
        .map_err(|_| AppError::Internal("Failed to hash password".to_string()))?;

    users.insert(payload.username.clone(), hash_password);

    Ok((StatusCode::CREATED, "User Created Successfully").into_response())
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
