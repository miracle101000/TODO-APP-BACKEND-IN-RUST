use metrics::counter;
use sqlx::PgPool;
use tokio::sync::broadcast::Receiver;
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

use crate::models::TodoItem;

// ── Worker 1: Todo broadcast event consumer ───────────────────────────────────
//
// Listens to every todo create/update event fired via state.tx.send()
// and processes them in the background — e.g. push notifications, audit logs

pub fn spawn_todo_event_worker(mut rx: Receiver<TodoItem>) {
    tokio::spawn(async move {
        info!("Todo event worker started");

        loop {
            match rx.recv().await {
                Ok(todo) => {
                    info!(
                        todo_id = %todo.id,
                        user_id = %todo.user_id,
                        status  = %todo.status,
                        "Background: received todo event"
                    );
                    counter!("jobs.todo_events.received").increment(1);

                    // process the event — add whatever you need here
                    // e.g. send push notification, write to audit log, sync cache
                    if let Err(e) = process_todo_event(&todo).await {
                        error!(
                            todo_id = %todo.id,
                            error   = %e,
                            "Background: failed to process todo event"
                        );
                        counter!("jobs.todo_events.errors").increment(1);
                    }
                }

                // worker fell behind — channel dropped some messages
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "Todo event worker lagged — missed messages");
                    counter!("jobs.todo_events.lagged").increment(1);
                }

                // channel closed — app is shutting down
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    info!("Todo event worker shutting down — channel closed");
                    break;
                }
            }
        }
    });
}

async fn process_todo_event(todo: &TodoItem) -> Result<(), String> {
    // placeholder — add your real logic here
    // ideas:
    //   - send push notification when status changes to "done"
    //   - write to an audit log table
    //   - invalidate a cache entry
    info!(todo_id = %todo.id, "Processing todo event");
    Ok(())
}

// ── Worker 2: Nightly cleanup of expired refresh tokens ───────────────────────
//
// Runs every 24 hours and deletes refresh tokens older than 7 days.
// Keeps the refresh_tokens table from growing forever.

pub fn spawn_cleanup_worker(pool: PgPool) {
    tokio::spawn(async move {
        info!("Cleanup worker started — runs every 24 hours");

        // run immediately on startup, then every 24 hours
        let mut tick = interval(Duration::from_secs(24 * 60 * 60));

        loop {
            tick.tick().await;

            info!("Background: running expired token cleanup");

            match sqlx::query!(
                "DELETE FROM refresh_tokens WHERE created_at < NOW() - INTERVAL '7 days'"
            )
            .execute(&pool)
            .await
            {
                Ok(result) => {
                    let deleted = result.rows_affected();
                    info!(deleted = deleted, "Background: cleaned up expired refresh tokens");
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

// ── Worker 3: News cache — fetches and stores every 10 minutes ────────────────
//
// Instead of every user hitting the external news API directly,
// this worker fetches once and stores in the DB.
// Your get_business_news handler then just reads from the cache table.

pub fn spawn_news_cache_worker(pool: PgPool, client: reqwest::Client) {
    tokio::spawn(async move {
        info!("News cache worker started — refreshes every 10 minutes");

        let mut tick = interval(Duration::from_secs(10 * 60));

        loop {
            tick.tick().await;

            info!("Background: refreshing news cache");

            match fetch_and_cache_news(&pool, &client).await {
                Ok(count) => {
                    info!(articles = count, "Background: news cache refreshed");
                    counter!("jobs.news_cache.refreshed").increment(1);
                }
                Err(e) => {
                    error!(error = %e, "Background: failed to refresh news cache");
                    counter!("jobs.news_cache.errors").increment(1);
                }
            }
        }
    });
}

async fn fetch_and_cache_news(
    pool: &PgPool,
    client: &reqwest::Client,
) -> Result<usize, String> {
    let api_key = std::env::var("NEWS_API_KEY")
        .map_err(|_| "NEWS_API_KEY not set".to_string())?;

    let response = client
        .get("https://newsapi.org/v2/top-headlines")
        .query(&[("category", "business"), ("apiKey", &api_key)])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())?;

    let articles = response["articles"]
        .as_array()
        .ok_or("No articles in response")?;

    // upsert into cache table — one row, updated each refresh
    sqlx::query!(
        r#"
        INSERT INTO news_cache (key, data, cached_at)
        VALUES ('business', $1, NOW())
        ON CONFLICT (key) DO UPDATE
            SET data = $1, cached_at = NOW()
        "#,
        serde_json::to_value(articles).map_err(|e| e.to_string())?
    )
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(articles.len())
}