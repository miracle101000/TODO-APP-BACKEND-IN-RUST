use std::env;

use axum::{Json, extract::State, response::IntoResponse};

use crate::{models::{AppError, AppState, JwtInterceptor}, utility::seal_data};

pub async fn get_business_news(
    _interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let api_key =
        env::var("RAPIDAPI_KEY").map_err(|_| AppError::Internal("Missing RAPIDAPI_KEY".into()))?;

    let response = state.http_client
        .get("https://google-news13.p.rapidapi.com/business?lr=en-US")
        .header("Content-Type", "application/json")
        .header("x-rapidapi-host", "google-news13.p.rapidapi.com")
        .header("x-rapidapi-key", api_key)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch news: {}", e)))?;

    let json_data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse news JSON: {}", e)))?;
    
    let encrypted = seal_data(&json_data, &state.jwt_secret)?;
    
    Ok(Json(encrypted))
}
