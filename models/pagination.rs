use serde::{Deserialize,Serialize};

use chrono::{DateTime, Utc};

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub page_size: Option<i64>,
    pub after_id: Option<uuid::Uuid>,
    pub after_created_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page_size: i64,
    pub total_count: i64,
    pub next_cursor: Option<uuid::Uuid>,
    pub has_more: bool,
}