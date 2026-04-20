use crate::{
    models::{
        AppError, AppState, CreateTodoRequest, EncryptedTodoResponse, IdPath, JwtInterceptor,
        PaginatedResponse, PaginationQuery, TodoItem, TodoItemStatus, UpdateTodoRequestStatus,
    },
    utility::seal_data,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_valid::Valid;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use validator::Validate;
use tracing::{info, warn, error, instrument};
use metrics::{counter, histogram, gauge};
use std::time::Instant;

#[instrument(skip(state, payload), fields(user = %interceptor.user_token_or_id))]
pub async fn add_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Json(payload): Json<CreateTodoRequest>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!(title = %payload.title, "Creating todo item");

    payload
        .validate()
        .map_err(|e| {
            warn!(error = %e, "Invalid input on todo creation");
            counter!("todos.create.failures", "reason" => "validation").increment(1);
            AppError::Internal(format!("Invalid input: {}", e))
        })?;

    let initial_timestamp = Utc::now();
    let new_id = Uuid::new_v4();
    let status = String::from(TodoItemStatus::Undone);

    let new_item = sqlx::query_as!(
        TodoItem,
        r#"
        INSERT INTO todos (id, user_id, title, content, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
        new_id,
        interceptor.user_token_or_id,
        payload.title,
        payload.content,
        status,
        initial_timestamp,
        initial_timestamp,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error inserting todo item");
        counter!("todos.create.db_errors").increment(1);
        AppError::Internal(e.to_string())
    })?;

    let _ = state.tx.send(new_item.clone());
    let encrypted = seal_data(&new_item, &state.jwt_secret)?;

    counter!("todos.created").increment(1);
    histogram!("todos.create.duration_ms").record(start.elapsed().as_millis() as f64);

    info!(todo_id = %new_item.id, "Todo item created successfully");
    Ok(Json(encrypted))
}

#[instrument(skip(state), fields(user = %interceptor.user_token_or_id))]
pub async fn get_todo_items(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<EncryptedTodoResponse>>, AppError> {
    let start = Instant::now();
    info!("Fetching todo items");

    let page_size = pagination.page_size.unwrap_or(10).clamp(1, 100);
    let page_size_plus_one = page_size + 1;

    let (count_result, todos_result) = tokio::join!(
        sqlx::query_scalar!(
            "SELECT COUNT(*) FROM todos WHERE user_id = $1",
            interceptor.user_token_or_id
        )
        .fetch_one(&state.db),
        sqlx::query_as!(
            TodoItem,
            r#"
            SELECT * FROM todos
            WHERE user_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR (created_at, id) < ($2::timestamptz, $3::uuid)
              )
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
            interceptor.user_token_or_id,
            pagination.after_created_at as Option<DateTime<Utc>>,
            pagination.after_id as Option<Uuid>,
            page_size_plus_one
        )
        .fetch_all(&state.db)
    );

    let total_count = count_result
        .map_err(|e| {
            error!(error = %e, "Database error counting todos");
            counter!("todos.fetch.db_errors", "op" => "count").increment(1);
            AppError::Internal(e.to_string())
        })?
        .unwrap_or(0);

    let mut todos = todos_result.map_err(|e| {
        error!(error = %e, "Database error fetching todos");
        counter!("todos.fetch.db_errors", "op" => "fetch").increment(1);
        AppError::Internal(e.to_string())
    })?;

    let has_more = todos.len() as i64 == page_size_plus_one;
    if has_more {
        todos.pop();
    }

    let next_cursor = todos.last().map(|t| t.id);

    let encrypted_data: Result<Vec<EncryptedTodoResponse>, AppError> = todos
        .iter()
        .map(|item| seal_data(item, &state.jwt_secret))
        .collect();

    // gauge tracks the real current total for this user
    gauge!("todos.user_total").set(total_count as f64);
    histogram!("todos.fetch.returned_count").record(todos.len() as f64);
    histogram!("todos.fetch.duration_ms").record(start.elapsed().as_millis() as f64);

    info!(
        total = %total_count,
        returned = %todos.len(),
        has_more = %has_more,
        "Todo items fetched successfully"
    );

    Ok(Json(PaginatedResponse {
        data: encrypted_data?,
        page_size,
        total_count,
        next_cursor,
        has_more,
    }))
}

#[instrument(skip(state, payload), fields(user = %interceptor.user_token_or_id, todo_id = %path.id))]
pub async fn update_todo_item_status(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<UpdateTodoRequestStatus>>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    let status_str = String::from(payload.status.clone());
    info!(new_status = %status_str, "Updating todo status");

    let status = String::from(payload.status);

    let updated_item = sqlx::query_as!(
        TodoItem,
        r#"
        UPDATE todos
        SET status = $1, updated_at = $2
        WHERE id = $3 AND user_id = $4
        RETURNING *
        "#,
        status,
        Utc::now(),
        path.id,
        interceptor.user_token_or_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error updating todo status");
        counter!("todos.update_status.db_errors").increment(1);
        AppError::Internal(e.to_string())
    })?
    .ok_or_else(|| {
        warn!("Update status attempted on non-existent todo");
        counter!("todos.update_status.failures", "reason" => "not_found").increment(1);
        AppError::NotFound(format!("Item {} not found", path.id))
    })?;

    let _ = state.tx.send(updated_item.clone());
    let encrypted = seal_data(&updated_item, &state.jwt_secret)?;

    // track which status values are being set most
    counter!("todos.status_updated", "new_status" => status_str).increment(1);
    histogram!("todos.update_status.duration_ms").record(start.elapsed().as_millis() as f64);

    info!("Todo status updated successfully");
    Ok(Json(encrypted))
}

#[instrument(skip(state, payload), fields(user = %interceptor.user_token_or_id, todo_id = %path.id))]
pub async fn update_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<CreateTodoRequest>>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!(new_title = %payload.title, "Updating todo item");

    let updated_item = sqlx::query_as!(
        TodoItem,
        r#"
        UPDATE todos
        SET title = $1, content = $2, updated_at = $3
        WHERE id = $4 AND user_id = $5
        RETURNING *
        "#,
        payload.title,
        payload.content,
        Utc::now(),
        path.id,
        interceptor.user_token_or_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error updating todo item");
        counter!("todos.update.db_errors").increment(1);
        AppError::Internal(e.to_string())
    })?
    .ok_or_else(|| {
        warn!("Update attempted on non-existent todo");
        counter!("todos.update.failures", "reason" => "not_found").increment(1);
        AppError::NotFound(format!("Item {} not found", path.id))
    })?;

    let _ = state.tx.send(updated_item.clone());
    let encrypted = seal_data(&updated_item, &state.jwt_secret)?;

    counter!("todos.updated").increment(1);
    histogram!("todos.update.duration_ms").record(start.elapsed().as_millis() as f64);

    info!("Todo item updated successfully");
    Ok(Json(encrypted))
}

#[instrument(skip(state), fields(user = %interceptor.user_token_or_id, todo_id = %params.id))]
pub async fn delete_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(params): Path<IdPath>,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    info!("Deleting todo item");

    let result = sqlx::query!(
        "DELETE FROM todos WHERE id = $1 AND user_id = $2",
        params.id,
        interceptor.user_token_or_id,
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!(error = %e, "Database error deleting todo item");
        counter!("todos.delete.db_errors").increment(1);
        AppError::Internal(e.to_string())
    })?;

    if result.rows_affected() == 0 {
        warn!("Delete attempted on non-existent todo");
        counter!("todos.delete.failures", "reason" => "not_found").increment(1);
        return Err(AppError::NotFound(format!(
            "Item with id: {} not found",
            params.id
        )));
    }

    counter!("todos.deleted").increment(1);
    histogram!("todos.delete.duration_ms").record(start.elapsed().as_millis() as f64);

    info!("Todo item deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}