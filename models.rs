use std::sync::Arc;

use chrono::{ DateTime, Utc };
use parking_lot::Mutex;
use serde::{ Serialize, Deserialize };
use validator::{ Validate };
use tokio::sync::broadcast::{Sender};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub enum TodoItemStatus {
    #[default] Undone,
    Done,
}

#[derive(Serialize, Deserialize, Debug, Clone, Validate)]
pub struct TodoItem {
    #[serde(flatten)]
    pub id: IdPath,
    #[validate(length(min = 1, message = "Length must be greater than 1"))]
    pub title: String,
    #[validate(length(min = 1, max = 500))]
    pub content: String,
    pub status: TodoItemStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TodoItem {
    pub fn copy_with(
        &self,
        title: Option<String>,
        content: Option<String>,
        status: Option<TodoItemStatus>
    ) -> Self {
        Self {
            id: self.id.clone(),
            title: title.unwrap_or_else(|| self.title.clone()),
            content: content.unwrap_or_else(|| self.content.clone()),
            status: status.unwrap_or_else(|| self.status.clone()),
            created_at: self.created_at,
            updated_at: Utc::now(),
        }
    }
}

#[derive(Deserialize, Validate)]
pub struct CreateTodoRequest {
    #[validate(length(min = 1, message = "Length must be greater than 1"))]
    pub title: String,
    #[validate(length(min = 1, max = 500))]
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Validate)]
pub struct IdPath {
    pub id: uuid::Uuid,
}


#[derive(Clone)]
pub struct AppState {
    pub todo_list: Arc<Mutex<Vec<TodoItem>>>,
    pub tx: Sender<TodoItem>
}


