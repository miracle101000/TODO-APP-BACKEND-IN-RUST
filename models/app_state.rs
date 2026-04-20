use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::broadcast::Sender;

use crate::models::TodoItem;
use crate::repository::{RefreshTokenRepository, TodoRepository, UserRepository};

#[derive(Clone)]
pub struct AppState {
    pub tx:             Sender<TodoItem>,
    pub http_client:    reqwest::Client,
    pub jwt_secret:     String,
    pub refresh_secret: String,
    pub download_secret: String,

    pub todos:          Arc<dyn TodoRepository>,
    pub users:          Arc<dyn UserRepository>,
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,
   pub news_cache: Arc<tokio::sync::RwLock<Option<CachedNews>>>,
}

#[derive(Clone)]
pub struct CachedNews {
    pub data:       serde_json::Value,
    pub cached_at:  DateTime<Utc>,
}