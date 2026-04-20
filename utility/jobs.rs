use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{info, error};
use metrics::counter;
use chrono::Utc;

use crate::models::app_state::CachedNews;

use sqlx::PgPool;
use tokio::sync::broadcast::Receiver;
use tracing::warn;

use crate::models::TodoItem;

pub fn spawn_todo_event_worker(mut rx: Receiver<TodoItem>) {
    tokio::spawn(async move {
        info!("Todo event worker started");
        loop {
            match rx.recv().await {
                Ok(todo) => {
                    info!(
                        todo_id = %todo.id,
                        user_id = %todo.user_id,
                        status  = ?todo.status,   // Debug — TodoItemStatus has no Display
                        "Background: received todo event"
                    );
                    counter!("jobs.todo_events.received").increment(1);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "Todo event worker lagged");
                    counter!("jobs.todo_events.lagged").increment(1);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    info!("Todo event worker shutting down");
                    break;
                }
            }
        }
    });
}

pub fn spawn_cleanup_worker(pool: PgPool) {
    tokio::spawn(async move {
        info!("Cleanup worker started — runs every 24 hours");
        let mut tick = interval(Duration::from_secs(24 * 60 * 60));
        loop {
            tick.tick().await;
            match sqlx::query!(
                "DELETE FROM refresh_tokens WHERE created_at < NOW() - INTERVAL '7 days'"
            )
            .execute(&pool)
            .await
            {
                Ok(result) => {
                    let deleted = result.rows_affected();
                    info!(deleted, "Background: cleaned up expired refresh tokens");
                    counter!("jobs.cleanup.tokens_deleted").increment(deleted);
                }
                Err(e) => {
                    error!(error = %e, "Background: failed to clean up expired tokens");
                    counter!("jobs.cleanup.errors").increment(1);
                }
            }
        }
    });
}

pub fn spawn_news_cache_worker(
    client: reqwest::Client,
    cache:  Arc<RwLock<Option<CachedNews>>>,  // ← takes the cache, not the pool
) {
    tokio::spawn(async move {
        info!("News cache worker started — refreshes every 10 minutes");

        let mut tick = interval(Duration::from_secs(10 * 60));

        loop {
            tick.tick().await;
            info!("Background: refreshing news cache");

            match fetch_news(&client).await {
                Ok(data) => {
                    // write lock — blocks new readers briefly while we update
                    let mut lock = cache.write().await;
                    *lock = Some(CachedNews {
                        data:      data.clone(),
                        cached_at: Utc::now(),
                    });
                    // lock dropped here — all readers unblocked immediately

                    info!("Background: news cache refreshed");
                    counter!("jobs.news_cache.refreshed").increment(1);
                }
                Err(e) => {
                    error!(error = %e, "Background: failed to refresh news cache");
                    counter!("jobs.news_cache.errors").increment(1);
                    // cache keeps serving stale data — better than nothing
                }
            }
        }
    });
}

async fn fetch_news(client: &reqwest::Client) -> Result<serde_json::Value, String> {
    let api_key = std::env::var("RAPIDAPI_KEY")
        .map_err(|_| "Missing RAPIDAPI_KEY".to_string())?;

    let response = client
        .get("https://google-news13.p.rapidapi.com/business?lr=en-US")
        .header("Content-Type", "application/json")
        .header("x-rapidapi-host", "google-news13.p.rapidapi.com")
        .header("x-rapidapi-key", api_key)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch news: {}", e))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse news JSON: {}", e))?;

    Ok(response)
}