// src/repository/postgres.rs

use async_trait::async_trait;
use sqlx::PgPool;
use crate::models::{AppError, TodoItem, TodoItemStatus};
use super::{TodoRepository, UserRepository, RefreshTokenRepository};
use uuid::Uuid;
use chrono::Utc;

pub struct PgTodoRepository {
    pub pool: PgPool,
}

pub struct PgUserRepository {
    pub pool: PgPool,
}

pub struct PgRefreshTokenRepository {
    pub pool: PgPool,
}

#[async_trait]
impl TodoRepository for PgTodoRepository {
    async fn create(&self, user_id: &str, title: &str, content: &str) 
        -> Result<TodoItem, AppError> 
    {
        let now    = Utc::now();
        let new_id = Uuid::new_v4();
        let status = String::from(TodoItemStatus::Undone);

        sqlx::query_as!(
            TodoItem,
            r#"
            INSERT INTO todos (id, user_id, title, content, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
            new_id, user_id, title, content, status, now, now,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
    }

    async fn find_all(&self, user_id: &str, page_size: i64, after_id: Option<Uuid>) 
        -> Result<Vec<TodoItem>, AppError> 
    {
        sqlx::query_as!(
            TodoItem,
            r#"
            SELECT * FROM todos
            WHERE user_id = $1
              AND ($2::uuid IS NULL OR id < $2)
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
            user_id,
            after_id as Option<Uuid>,
            page_size,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
    }

    async fn update_status(&self, id: Uuid, user_id: &str, status: &str) 
        -> Result<Option<TodoItem>, AppError> 
    {
        sqlx::query_as!(
            TodoItem,
            r#"
            UPDATE todos SET status = $1, updated_at = $2
            WHERE id = $3 AND user_id = $4
            RETURNING *
            "#,
            status, Utc::now(), id, user_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
    }

    async fn delete(&self, id: Uuid, user_id: &str) -> Result<bool, AppError> {
        let result = sqlx::query!(
            "DELETE FROM todos WHERE id = $1 AND user_id = $2",
            id, user_id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<String>, AppError> {
        sqlx::query_scalar!(
            "SELECT password_hash FROM users WHERE username = $1",
            username
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
    }

    async fn create(&self, username: &str, password_hash: &str) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
            username, password_hash,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn username_exists(&self, username: &str) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM users WHERE username = $1",
            username
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or(0);

        Ok(exists > 0)
    }
}

#[async_trait]
impl RefreshTokenRepository for PgRefreshTokenRepository {
    async fn upsert(&self, username: &str, token: &str) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO refresh_tokens (username, token)
             VALUES ($1, $2)
             ON CONFLICT (username) DO UPDATE SET token = $2, created_at = NOW()",
            username, token,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn find(&self, username: &str) -> Result<Option<String>, AppError> {
        sqlx::query_scalar!(
            "SELECT token FROM refresh_tokens WHERE username = $1",
            username
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
    }

    async fn delete(&self, username: &str) -> Result<bool, AppError> {
        let result = sqlx::query!(
            "DELETE FROM refresh_tokens WHERE username = $1",
            username
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}