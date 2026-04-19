use std::env;

use axum::{Json, response::IntoResponse};
use reqwest::Client;

use crate::models::{AppError, JwtInterceptor};

pub async fn get_business_news(
    _interceptor: JwtInterceptor,
) -> Result<impl IntoResponse, AppError> {
    let api_key =
        env::var("RAPIDAPI_KEY").map_err(|_| AppError::Internal("Missing RAPIDAPI_KEY".into()))?;

    let client = Client::new();

    let response = client
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

    Ok(Json(json_data))
}
