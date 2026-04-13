use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use validator::{Validate};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub enum TodoItemStatus { #[default] Undone, Done}

#[derive(Serialize, Deserialize, Debug, Clone, Validate)]
pub struct TodoItem {
    id: String,
    #[validate(length(min = 1, message = "Length must be greater than 1"))]
    title: String,
    #[validate(length(min = 1, max = 500))]
    content: String,
    status: TodoItemStatus,
    created_at: DateTime<Utc>,
    update_at:  DateTime<Utc>
}