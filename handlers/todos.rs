use crate::models::{
    AppError, AppState, CreateTodoRequest, IdPath, JwtInterceptor, TodoItem, TodoItemStatus,
    UpdateTodoRequestStatus,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_valid::Valid;
use chrono::Utc;
use validator::Validate;

pub async fn add_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Json(payload): Json<CreateTodoRequest>,
) -> impl IntoResponse {
    if let Err(errors) = payload.validate() {
        return (StatusCode::BAD_REQUEST, format!("Invalid input {}", errors)).into_response();
    }

    let mut list = state.todo_list.lock();
    let initial_timestamp = Utc::now();
    let new_id = IdPath {
        id: uuid::Uuid::new_v4(),
    };

    let new_item = TodoItem {
        id: new_id,
        user_id: interceptor.user_token_or_id,
        title: payload.title,
        content: payload.content,
        status: TodoItemStatus::Undone,
        created_at: initial_timestamp,
        updated_at: initial_timestamp,
    };

    list.push(new_item.clone());

    let _ = state.tx.send(new_item.clone());

    Json(new_item).into_response()
}

pub async fn get_todo_items(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
) -> Json<Vec<TodoItem>> {
    let list = state.todo_list.lock();
    let user_todos = list
        .iter()
        .filter(|item| item.user_id == interceptor.user_token_or_id)
        .cloned()
        .collect();
    Json(user_todos)
}

pub async fn update_todo_item_status(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<UpdateTodoRequestStatus>>,
) -> Result<impl IntoResponse, AppError> {
    let mut list = state.todo_list.lock();
    let index = list
        .iter()
        .position(|item| {
            item.id.id.to_string() == path.id.to_string()
                && item.user_id == interceptor.user_token_or_id
        })
        .ok_or_else(|| AppError::NotFound(format!("Item {} not found", path.id)))?;

    let updated_item = list[index].copy_with(None, None, Some(payload.status));
    list[index] = updated_item.clone();
    let _ = state.tx.send(updated_item.clone());

    Ok(Json(updated_item))
}

pub async fn update_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(path): Path<IdPath>,
    Valid(Json(payload)): Valid<Json<CreateTodoRequest>>,
) -> Result<impl IntoResponse, AppError> {
    let mut list = state.todo_list.lock();
    let index = list
        .iter()
        .position(|item| {
            item.id.id.to_string() == path.id.to_string()
                && item.user_id == interceptor.user_token_or_id
        })
        .ok_or_else(|| AppError::NotFound(format!("Item {} not found", path.id)))?;

    let updated_item = list[index].copy_with(Some(payload.title), Some(payload.content), None);
    list[index] = updated_item.clone();
    let _ = state.tx.send(updated_item.clone());

    Ok(Json(updated_item))
}

pub async fn delete_todo_item(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(params): Path<IdPath>,
) -> Result<impl IntoResponse, AppError> {
    let mut list = state.todo_list.lock();
    let index = list
        .iter()
        .position(|item| {
            item.id.id.to_string() == params.id.to_string()
                && item.user_id == interceptor.user_token_or_id
        })
        .ok_or_else(|| AppError::NotFound(format!("Item with id: {} not found", params.id)))?;

    list.remove(index);

    Ok(StatusCode::NO_CONTENT)
}
