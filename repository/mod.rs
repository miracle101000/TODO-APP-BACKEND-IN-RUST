
pub mod postgres;

pub use postgres::*;

use async_trait::async_trait;
use uuid::Uuid;
use crate::models::{AppError, TodoItem};

#[async_trait]
pub trait TodoRepository: Send + Sync {
    async fn create(&self, user_id: &str, title: &str, content: &str)
        -> Result<TodoItem, AppError>;

    async fn find_all(&self, user_id: &str, page_size: i64, after_id: Option<Uuid>)
        -> Result<Vec<TodoItem>, AppError>;

    async fn count(&self, user_id: &str)
        -> Result<i64, AppError>;

    async fn update_status(&self, id: Uuid, user_id: &str, status: &str)
        -> Result<Option<TodoItem>, AppError>;

    async fn update(&self, id: Uuid, user_id: &str, title: &str, content: &str)
        -> Result<Option<TodoItem>, AppError>;

    async fn delete(&self, id: Uuid, user_id: &str)
        -> Result<bool, AppError>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_username(&self, username: &str)
        -> Result<Option<String>, AppError>;

    async fn create(&self, username: &str, password_hash: &str)
        -> Result<(), AppError>;

    async fn username_exists(&self, username: &str)
        -> Result<bool, AppError>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn upsert(&self, username: &str, token: &str)
        -> Result<(), AppError>;

    async fn find(&self, username: &str)
        -> Result<Option<String>, AppError>;

    async fn delete(&self, username: &str)
        -> Result<bool, AppError>;
}