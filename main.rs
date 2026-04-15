mod models;
use axum::{ Json, Router, extract::{State, ws::{Message, WebSocket, WebSocketUpgrade}}, routing::{ delete, get, patch, post } };
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_valid::Valid;
use chrono::Utc;
use tokio::sync::broadcast;
use validator::Validate;
use parking_lot::Mutex;
use std::sync::{ Arc };
use models::{ TodoItem, TodoItemStatus };

use crate::models::{ AppState, CreateTodoRequest, IdPath };

async fn handler(ws:WebSocketUpgrade,State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket,state))
}

async fn handle_websocket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.tx.subscribe();
    while let Ok(item) = rx.recv().await {
       
       match serde_json::to_string(&item){
         Ok(json) => {
           if socket.send(Message::Text(json.into())).await.is_err(){
                break;
            } 
         }
         Err(e)=>{
            eprint!("Failed to serialize item {}",e);
         }

       }
            
  }
}

async fn add_todo_item(
    State(state): State<AppState>,
    Json(payload): Json<CreateTodoRequest>
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

async fn get_todo_items(State(state): State<AppState>) -> Json<Vec<TodoItem>> {
    let list = state.todo_list.lock();
    Json(list.to_vec())
}

async fn update_todo_item_status_to_done(
    State(state): State<AppState>,
    Valid(Json(payload)): Valid<Json<IdPath>>
) -> impl IntoResponse {
    let mut list = state.todo_list.lock();
    let index = list.iter().position(|item| item.id.id.to_string() == payload.id.to_string());

    match index {
        Some(index) => {
            let updated_item = list[index].copy_with(None, None, Some(TodoItemStatus::Done));

            list[index] = updated_item.clone();

            Json(updated_item).into_response()
        }
        None => {
            (
                StatusCode::NOT_FOUND,
                format!("Item with id: {} not found", payload.id),
            ).into_response()
        }
    }
}

async fn delete_todo_item(
    State(state): State<AppState>,
    Valid(Json(payload)): Valid<Json<IdPath>>
) -> impl IntoResponse {
    let mut list = state.todo_list.lock();
    let index = list.iter().position(|item| item.id.id.to_string() == payload.id.to_string());

    match index {
        Some(index) => {
            list.remove(index);
            StatusCode::OK.into_response()
        }
        None => {
            (
                StatusCode::NOT_FOUND,
                format!("Item with id: {} not found", payload.id),
            ).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    let todo_list = Arc::new(Mutex::new(Vec::<TodoItem>::new()));

    let (tx, _) = broadcast::channel::<TodoItem>(100);
    
    let state =  AppState {
        todo_list,
        tx
    };

    let app = Router::new()
    .route("/ws", get(handler))
        .route("/add_todo_item", post(add_todo_item))
        .route("/get_todo_items", get(get_todo_items))
        .route("/update_todo_item_to_done", patch(update_todo_item_status_to_done))
        .route("/delete_todo_item", delete(delete_todo_item))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
