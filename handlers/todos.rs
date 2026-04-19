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

pub async fn add_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Json(payload): Json<CreateTodoRequest>,
) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Internal(format!("Invalid input: {}", e)))?;

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
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let _ = state.tx.send(new_item.clone());

    let encrypted = seal_data(&new_item, &state.jwt_secret)?;

    Ok(Json(encrypted))
}

pub async fn get_todo_items(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<EncryptedTodoResponse>>, AppError> {
    let page_size = pagination.page_size.unwrap_or(10).clamp(1, 100);
    let page_size_plus_one = page_size + 1;
    // Run count and fetch in parallel
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
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or(0);

    let todos = todos_result.map_err(|e| AppError::Internal(e.to_string()))?;

    let encrypted_data: Result<Vec<EncryptedTodoResponse>, AppError> = todos
        .iter()
        .map(|item| seal_data(item, &state.jwt_secret))
        .collect();

    let has_more = todos.len() as i64 == page_size_plus_one;

    let todos = if has_more {
        &todos[..page_size as usize] // drop the last one
    } else {
        &todos[..]
    };
    
    let next_cursor = todos.last().map(|t| t.id);

    Ok(Json(PaginatedResponse {
        data: encrypted_data?,
        page_size,
        total_count,
        next_cursor,
        has_more,
    }))
}

pub async fn update_todo_item_status(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<UpdateTodoRequestStatus>>,
) -> Result<impl IntoResponse, AppError> {
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
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::NotFound(format!("Item {} not found", path.id)))?;

    let _ = state.tx.send(updated_item.clone());

    let encrypted = seal_data(&updated_item, &state.jwt_secret)?;

    Ok(Json(encrypted))
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

    let encrypted = seal_data(&updated_item, &state.jwt_secret)?;

    Ok(Json(encrypted))
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
        return Err(AppError::NotFound(format!(
            "Item with id: {} not found",
            params.id
        )));
    }

    Ok(StatusCode::NO_CONTENT)
}
