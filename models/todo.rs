use chrono::{ DateTime, Utc };
use serde::{ Serialize, Deserialize };
use validator::Validate;
use uuid::Uuid;

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TodoItemStatus {
    #[default]
    Undone,
    Done,
}

impl From<TodoItemStatus> for String {
    fn from(s: TodoItemStatus) -> Self {
        match s {
            TodoItemStatus::Undone => "undone".to_string(),
            TodoItemStatus::Done => "done".to_string(),
        }
    }
}

impl From<String> for TodoItemStatus {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "done" => TodoItemStatus::Done,
            _ => TodoItemStatus::Undone,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct TodoItem {
    pub id: Uuid,         
    pub user_id: String,
    pub title: String,
    pub content: String,
    #[sqlx(try_from = "String")]  
    pub status: TodoItemStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TodoItem {
    pub fn copy_with(
        &self,
        title: Option<String>,
        content: Option<String>,
        status: Option<TodoItemStatus>,
    ) -> Self {
        Self {
            id: self.id,
            user_id: self.user_id.clone(),
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

#[derive(Deserialize, Validate)]
pub struct UpdateTodoRequestStatus {
    pub status: TodoItemStatus,
}

// Keep IdPath for route path extraction only
#[derive(Serialize, Deserialize, Debug, Clone, Validate)]
pub struct IdPath {
    pub id: Uuid,
}

#[derive(serde::Serialize)]
pub struct EncryptedTodoResponse {
    pub ciphertext: String,
    pub nonce: String,
}