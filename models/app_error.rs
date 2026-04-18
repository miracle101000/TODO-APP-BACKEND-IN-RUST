use axum::{http::StatusCode,response::{IntoResponse, Response}};

pub enum AppError {
    AuthError(String),
    Internal(String),
    NotFound(String)
}

impl IntoResponse for AppError {
   fn into_response(self) -> Response {
    match self {
        AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg).into_response(),
        AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
        AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
    }
  }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}