mod models;

use axum::{
    Json,
    Router,
    extract::{ State, ws::{ Message, WebSocket, WebSocketUpgrade } },
    routing::{ delete, get, patch, post },
};
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_valid::Valid;
use chrono::Utc;
use jsonwebtoken::{ DecodingKey, EncodingKey, Header, Validation, decode, encode };
use tokio::sync::broadcast;
use validator::Validate;
use parking_lot::Mutex;
use std::{ collections::HashMap, sync::Arc, time::{ SystemTime, UNIX_EPOCH } };
use models::{ TodoItem, TodoItemStatus };

use crate::models::{
    AppState,
    AuthRequest,
    AuthResponse,
    CreateTodoRequest,
    IdPath,
    JwtInterceptor,
    RefreshTokenRequest,
    WsQuery,
};

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>
) -> impl IntoResponse {
    let token_data = match
        decode::<JwtInterceptor>(
            &payload.refresh_token,
            &DecodingKey::from_secret(b"refresh_secret"),
            &Validation::default()
        )
    {
        Ok(data) => data,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "Invalid refresh token").into_response();
        }
    };

    let claims = token_data.claims;
    let username = &claims.user_token_or_id;

    let stored = state.refresh_tokens.lock().get(username).cloned();

    match stored {
        Some(refresh_token) if refresh_token == payload.refresh_token => {}
        _ => {
            return (StatusCode::UNAUTHORIZED, "Refresh Token Revoked or Not found").into_response();
        }
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let acces_token_interceptor = JwtInterceptor {
        user_token_or_id: username.clone(),
        expiration_date_in_milliseconds: now + 15 * 60,
        issued_at: now,
        token_type: models::TokenType::Access,
    };

    let access_token = encode(
        &Header::default(),
        &acces_token_interceptor,
        &EncodingKey::from_secret(b"secret".as_ref())
    ).unwrap();

    Json(AuthResponse { access_token, refresh_token: payload.refresh_token }).into_response()
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>
) -> impl IntoResponse {
    let saved_hash = {
        let users = state.users.lock();
        match users.get(&payload.username) {
            Some(hash) => hash.clone(),
            None => {
                return (StatusCode::UNAUTHORIZED, "Invalid username or password").into_response();
            }
        }
    };

    let is_valid = tokio::task
        ::spawn_blocking(move || {
            bcrypt::verify(&payload.password, &saved_hash).unwrap_or(false)
        }).await
        .unwrap_or(false);

    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Invalid username or password").into_response();
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let acces_token_interceptor = JwtInterceptor {
        user_token_or_id: payload.username.clone(),
        expiration_date_in_milliseconds: now + 15 * 60,
        issued_at: now,
        token_type: models::TokenType::Access,
    };

    let refresh_token_interceptor = JwtInterceptor {
        user_token_or_id: payload.username.clone(),
        expiration_date_in_milliseconds: now + 7 * 24 * 60 * 60,
        issued_at: now,
        token_type: models::TokenType::Refresh,
    };

    let access_token = encode(
        &Header::default(),
        &acces_token_interceptor,
        &EncodingKey::from_secret(b"secret".as_ref())
    ).unwrap();
    let refresh_token = encode(
        &Header::default(),
        &refresh_token_interceptor,
        &EncodingKey::from_secret(b"refresh_secret".as_ref())
    ).unwrap();

    state.refresh_tokens.lock().insert(payload.username.clone(), refresh_token.clone());

    Json(AuthResponse { access_token, refresh_token }).into_response()
}

#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>
) -> impl IntoResponse {
    let mut users = state.users.lock();

    if users.contains_key(&payload.username) {
        return (StatusCode::CONFLICT, "User already exists").into_response();
    }

    let hash_password = match bcrypt::hash(&payload.password, 4) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response();
        }
    };

    users.insert(payload.username.clone(), hash_password);

    (StatusCode::CREATED, "User Created Successfully").into_response()
}

async fn logout(interceptor: JwtInterceptor, State(state): State<AppState>) -> impl IntoResponse {
    state.refresh_tokens.lock().remove(&interceptor.user_token_or_id);
    StatusCode::OK.into_response()
}

async fn add_todo_item(
    interceptor: JwtInterceptor,
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

async fn get_todo_items(
    _interceptor: JwtInterceptor,
    State(state): State<AppState>
) -> Json<Vec<TodoItem>> {
    let list = state.todo_list.lock();
    Json(list.to_vec())
}

async fn update_todo_item_status_to_done(
    _interceptor: JwtInterceptor,
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
    _interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Valid(Json(payload)): Valid<Json<IdPath>>
) -> impl IntoResponse {
    let mut list = state.todo_list.lock();
    let index = list.iter().position(|item| item.id.id.to_string() == payload.id.to_string());

    match index {
        Some(index) => {
            list.remove(index);
            (StatusCode::OK, format!("Item with id: {} deleted!!", payload.id)).into_response()
        }
        None => {
            (
                StatusCode::NOT_FOUND,
                format!("Item with id: {} not found", payload.id),
            ).into_response()
        }
    }
}

async fn handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<WsQuery>
) -> impl IntoResponse {
    let token_data = decode::<JwtInterceptor>(
        &query.token,
        &DecodingKey::from_secret(b"secret".as_ref()),
        &Validation::default()
    );

    match token_data {
        Ok(data) =>  ws.on_upgrade(move |socket| handle_websocket(socket, state, data.claims)),
        Err(_) =>  return (StatusCode::UNAUTHORIZED, "Invalid token").into_response()
    }
   
}

async fn handle_websocket(mut socket: WebSocket, state: AppState, interceptor:JwtInterceptor) {
    let mut rx = state.tx.subscribe();
    while let Ok(item) = rx.recv().await {
        if item.user_id != interceptor.user_token_or_id {continue;}
        match serde_json::to_string(&item) {
            Ok(json) => {
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                eprint!("Failed to serialize item {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs
        ::default_provider()
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
    };

    let app = Router::new()
        .route("/refresh", post(refresh))
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/logout", post(logout))
        .route("/ws", get(handler))
        .route("/add_todo_item", post(add_todo_item))
        .route("/get_todo_items", get(get_todo_items))
        .route("/update_todo_item_to_done", patch(update_todo_item_status_to_done))
        .route("/delete_todo_item", delete(delete_todo_item))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
