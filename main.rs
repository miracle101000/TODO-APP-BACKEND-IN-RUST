mod handlers;
mod models;
mod utility;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use dotenvy::dotenv;
use models::TodoItem;
use parking_lot::Mutex;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;

use crate::handlers::{
    add_todo_item, delete_todo_item, download_document, get_todo_items, handler, login, logout,
    refresh, register, sign_download, signed_download, update_todo_item_status, upload_avatar,
    upload_document,
};
use crate::models::AppState;
use crate::utility::require_json;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let _ = rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let todo_list = Arc::new(Mutex::new(Vec::<TodoItem>::new()));
    let tx = broadcast::channel::<TodoItem>(100).0;
    let users = Arc::new(Mutex::new(HashMap::new()));
    let refresh_tokens = Arc::new(Mutex::new(HashMap::new()));

    let state = AppState {
        todo_list,
        tx,
        refresh_tokens,
        users,
        jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET missing"),
        refresh_secret: env::var("REFRESH_SECRET").expect("REFRESH_SECRET missing"),
        download_secret: env::var("DOWNLOAD_SECRET").expect("DOWNLOAD_SECRET missing"),
    };

    let auth_routes = Router::new()
        .route("/refresh", post(refresh))
        .route("/login", post(login))
        .route("/register", post(register))
        .layer(middleware::from_fn(require_json))
        .route("/logout", post(logout));

    let todo_routes = Router::new()
        .route("/add_todo_item", post(add_todo_item))
        .route("/get_todo_items", get(get_todo_items))
        .route("/update_todo_item/{id}", patch(update_todo_item_status))
        .route("/delete_todo_item/{id}", delete(delete_todo_item))
        .layer(middleware::from_fn(require_json));

    let uploads_route = Router::new()
        .route(
            "/avatar",
            post(upload_avatar).layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/documents",
            post(upload_document).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/documents/{filename}", get(download_document))
        .route("/documents/sign/{filename}", get(sign_download))
        .route("/documents/download", get(signed_download));

    let app = Router::new()
        .nest("/auth", auth_routes)
        .nest("/todos", todo_routes)
        .nest("/uploads", uploads_route)
        // /static serves only uploads/public — avatars and intentionally public
        // assets. Private documents are in uploads/documents and never exposed here.
        .nest_service("/static", ServeDir::new("uploads/public"))
        .route("/ws", get(handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
