use axum::{Json, extract::State, response::IntoResponse};
use chrono::Utc;
use anyhow::anyhow;
use tracing::{info, warn, instrument};
use metrics::{counter, histogram};
use std::time::Instant;

use crate::models::{AppError, AppState, JwtInterceptor};
use crate::utility::seal_data;

#[instrument(skip(state), fields(user = %interceptor.user_token_or_id))]
pub async fn get_business_news(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Fetching business news from cache");

    // read lock — many requests can hold this simultaneously
    let lock = state.news_cache.read().await;

    match &*lock {
        Some(cached) => {
            let age_secs = (Utc::now() - cached.cached_at).num_seconds();

            info!(
                cached_at = %cached.cached_at,
                age_secs  = %age_secs,
                "Serving news from cache"
            );
            counter!("news.cache.hits").increment(1);
            histogram!("news.handler.duration_ms").record(start.elapsed().as_millis() as f64);

            let encrypted = seal_data(&cached.data, &state.jwt_secret)?;
            Ok(Json(encrypted))
        }
        None => {
            warn!("News cache is empty — worker hasn't run yet");
            counter!("news.cache.misses").increment(1);
            Err(AppError::Internal(anyhow!("News cache not ready yet, try again shortly")))
        }
    }
}