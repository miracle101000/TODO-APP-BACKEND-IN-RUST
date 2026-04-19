use crate::{
    models::{
        AppError, AppState, CreateTodoRequest, IdPath, JwtInterceptor, TodoItem, TodoItemStatus,
        UpdateTodoRequestStatus,
    },
    utility::seal_data,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_valid::Valid;
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

pub async fn add_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Json(payload): Json<CreateTodoRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate().map_err(|e| {
        AppError::Internal(format!("Invalid input: {}", e))
    })?;

    let initial_timestamp = Utc::now();
    let new_id = Uuid::new_v4();
    let status = String::from(TodoItemStatus::Undone); // ← fixed

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
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let _ = state.tx.send(new_item.clone());

    let encrypted = seal_data(&new_item, &state.jwt_secret)?;

    Ok(Json(encrypted))
}

pub async fn get_todo_items(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> Result<Json<Vec<TodoItem>>, AppError> {
    let todos = sqlx::query_as!(
        TodoItem,
        "SELECT * FROM todos WHERE user_id = $1 ORDER BY created_at DESC",
        interceptor.user_token_or_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(todos))
}

pub async fn update_todo_item_status(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<UpdateTodoRequestStatus>>,
) -> Result<impl IntoResponse, AppError> {
    let status = String::from(payload.status); // ← fixed

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
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("Item {} not found", path.id)))?;

    let _ = state.tx.send(updated_item.clone());

    Ok(Json(updated_item))
}

pub async fn update_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<CreateTodoRequest>>,
) -> Result<impl IntoResponse, AppError> {
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
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("Item {} not found", path.id)))?;

    let _ = state.tx.send(updated_item.clone());

    Ok(Json(updated_item))
}

pub async fn delete_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(params): Path<IdPath>,
) -> Result<impl IntoResponse, AppError> {
    let result = sqlx::query!(
        "DELETE FROM todos WHERE id = $1 AND user_id = $2",
        params.id,
        interceptor.user_token_or_id,
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Item with id: {} not found", params.id)));
    }

    Ok(StatusCode::NO_CONTENT)
}