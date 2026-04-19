use tokio::sync::broadcast::{Sender};

use crate::models::todo::TodoItem;


#[derive(Clone)]
pub struct AppState {
    pub tx: Sender<TodoItem>,
    pub http_client: reqwest::Client,
    pub db: sqlx::PgPool,
    pub jwt_secret: String,
    pub refresh_secret: String,
    pub download_secret: String
}

