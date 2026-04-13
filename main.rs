mod models;

use axum::Error;
use axum::serve::Listener;
use axum::{routing::{post, get}, Json, Router, extract::State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use validator::Validate;
use std::sync::{Mutex, Arc};
use models::{TodoItem,TodoItemStatus};

type SharedState = Arc<Mutex<Vec<TodoItem>>>;

async fn add_todo_item(State(todo_list): State<SharedState>,
  Json(payload): Json<TodoItem>)-> impl IntoResponse{

   if let Err(errors) = payload.validate() {
     return  (StatusCode::BAD_REQUEST, format!("Invalid input {}", errors)).into_response();
   }

    let mut list = todo_list.lock().unwrap();

    list.push(payload.clone());

    Json(payload).into_response()
  }

async fn get_todo_items(State(todo_list):State<SharedState>)->Json<Vec<TodoItem>>{
    let  list = todo_list.lock().unwrap();
    Json(list.to_vec())
}

async fn update_todo_item_status(){}

async fn delete_todo_items(){}


#[tokio::main]
async fn main() {
    let todo_list = Arc::new(Mutex::new(Vec::<TodoItem>::new()));

    let app = Router::new()
    .route("/add_todo_item", post(add_todo_item))
    .route("/get_todo_items", get(get_todo_items))
    .with_state(todo_list);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener,app).await.unwrap();


}