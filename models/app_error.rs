// src/models/app_error.rs

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Validation failed: {0}")]
    Validation(String),         // 400 — input validation

    #[error("Bad request: {0}")]
    BadRequest(String),         // 400 — malformed upload, wrong file type

    #[error("Authentication failed: {0}")]
    Auth(String),               // 401

    #[error("{0} not found")]
    NotFound(String),           // 404

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Encryption failed")]
    Encryption,

    #[error(transparent)]
    Internal(#[from] anyhow::Error), // 500 — unexpected errors
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Auth(msg)       => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::NotFound(msg)   => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Jwt(e)          => (StatusCode::UNAUTHORIZED, e.to_string()),
            AppError::Encryption      => (StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed".into()),
            AppError::Database(e)     => {
                tracing::error!(error = %e, "Database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".into())
            }
            AppError::Internal(e)     => {
                tracing::error!(error = %e, "Internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
            }
        };

        (status, message).into_response()
    }
}