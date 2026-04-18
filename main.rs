mod models;

use axum::extract::{DefaultBodyLimit, Multipart, Path, Query};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    routing::{delete, get, patch, post},
};
use axum_valid::Valid;
use chrono::Utc;
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use models::{TodoItem, TodoItemStatus};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use validator::Validate;

use crate::models::{
    AppError, AppState, AuthRequest, AuthResponse, CreateTodoRequest, IdPath, JwtInterceptor,
    RefreshTokenRequest, UpdateTodoRequestStatus, WsQuery
};

// Token
async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) ->  Result<impl IntoResponse, AppError> {
    let token_data = decode::<JwtInterceptor>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.refresh_secret.as_bytes()),
        &Validation::default(),
    )?;
    
    let claims = token_data.claims;
    let username = &claims.user_token_or_id;

    let stored_token = state.refresh_tokens.lock()
    .get(username).cloned()
    .ok_or_else(||AppError::AuthError("Refresh Token Revoked or Not found".to_string()))?;

    if stored_token != payload.refresh_token {
        return  Err(AppError::AuthError("Refresh Token Revoked or Not found".to_string()));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal("System time error".to_string()))?
        .as_secs();

    let acces_token_interceptor = JwtInterceptor {
        user_token_or_id: username.clone(),
        expiration_date_in_milliseconds: now + 15 * 60,
        issued_at: now,
        token_type: models::TokenType::Access,
    };

    let access_token = encode(
        &Header::default(),
        &acces_token_interceptor,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: payload.refresh_token,
    }))
}

//Auth
async fn login(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let saved_hash = {
        let users = state.users.lock();
        users
            .get(&payload.username)
            .cloned()
            .ok_or_else(|| AppError::AuthError("Invalid username or password".to_string()))?
    };

    let is_valid = tokio::task::spawn_blocking(move || {
        bcrypt::verify(&payload.password, &saved_hash).unwrap_or(false)
    })
    .await
    .unwrap_or(false);

    if !is_valid {
        return Err(AppError::AuthError(
            "Invalid username or password".to_string(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal("System time error".to_string()))?
        .as_secs();

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
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?;

    let refresh_token = encode(
        &Header::default(),
        &refresh_token_interceptor,
        &EncodingKey::from_secret(state.refresh_secret.as_bytes()),
    )?;

    state
        .refresh_tokens
        .lock()
        .insert(payload.username.clone(), refresh_token.clone());

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
)-> Result<impl IntoResponse, AppError> {
    let mut users = state.users.lock();

    if users.contains_key(&payload.username) {
        return Ok((StatusCode::CONFLICT, "User already exists").into_response());
    }

    let hash_password = bcrypt::hash(&payload.password, 12)
     .map_err(|_| AppError::Internal("Failed to hash password".to_string()))?;
    
    users.insert(payload.username.clone(), hash_password);

    Ok((StatusCode::CREATED, "User Created Successfully").into_response())
}

async fn logout(interceptor: JwtInterceptor, State(state): State<AppState>) -> impl IntoResponse {
    state
        .refresh_tokens
        .lock()
        .remove(&interceptor.user_token_or_id);
    StatusCode::OK.into_response()
}

//todos
async fn add_todo_item(
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

async fn get_todo_items(
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

async fn update_todo_item_status(
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

async fn delete_todo_item(
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

//Web Socket
async fn handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
) -> impl IntoResponse {
    let token_data = decode::<JwtInterceptor>(
        &query.token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    );

    match token_data {
        Ok(data) => ws.on_upgrade(move |socket| handle_websocket(socket, state, data.claims)),
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    }
}

async fn handle_websocket(mut socket: WebSocket, state: AppState, interceptor: JwtInterceptor) {
    let mut rx = state.tx.subscribe();
    while let Ok(item) = rx.recv().await {
        if item.user_id != interceptor.user_token_or_id {
            continue;
        }
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

//Upload File
async fn upload_avatar(
    interceptor: JwtInterceptor,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    while let Some(field) = multipart.next_field().await.map_err(|e| AppError::Internal(e.to_string()))? {
        let content_type = field.content_type().unwrap_or("").to_string();
        
        // Check extension/mime type
        if !content_type.starts_with("image/") {
            return Err(AppError::Internal("Only images are allowed for avatars".into()));
        }

        let data = field.bytes().await.map_err(|e| AppError::Internal(e.to_string()))?;

        // SECURITY: Don't trust user filename. Name it after the user ID.
        let extension = content_type.split('/').last().unwrap_or("png");
        let file_name = format!("avatar_{}.{}", interceptor.user_token_or_id, extension);
        let path = std::path::Path::new("uploads/avatars").join(file_name);

        tokio::fs::create_dir_all("uploads/avatars").await.ok();
        tokio::fs::write(&path, data).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    Ok(StatusCode::OK)
}

async fn upload_document(
    interceptor: JwtInterceptor,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    while let Some(field) = multipart.next_field().await.map_err(|e| AppError::Internal(e.to_string()))? {
        let content_type = field.content_type().unwrap_or("").to_string();
        let original_name = field.file_name().unwrap_or("doc.pdf").to_string();

        if content_type != "application/pdf" {
            return Err(AppError::Internal("Document must be a PDF".into()));
        }

        let data = field.bytes().await.map_err(|e| AppError::Internal(e.to_string()))?;
        
        // SECURITY: Sanitize the filename to prevent directory traversal
        let safe_name = original_name.chars().filter(|c| c.is_alphanumeric() || *c == '.').collect::<String>();
        let path = std::path::Path::new("uploads/documents")
            .join(format!("{}_{}", interceptor.user_token_or_id, safe_name));

        tokio::fs::create_dir_all("uploads/documents").await.ok();
        tokio::fs::write(&path, data).await.map_err(|e| AppError::Internal(e.to_string()))?;
    }
    Ok(StatusCode::OK)
}

async fn require_json (
    req:Request<axum::body::Body>,
    next: Next
) -> Result<Response, StatusCode> {
    match *req.method(){
        Method::POST | Method::PATCH => {
            let content_type = req
            .headers().get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()).unwrap_or("");
            
            if !content_type.starts_with("application/json"){
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }
        _=> {}
    }
    Ok(next.run(req).await)
}


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
    };

    let auth_routes = Router::new()
        .route("/refresh", post(refresh))
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/logout", post(logout))
        .layer(middleware::from_fn(require_json));

    let todo_routes =  Router::new().route("/add_todo_item", post(add_todo_item))
        .route("/get_todo_items", get(get_todo_items))
        .route("/update_todo_item/{id}", patch(update_todo_item_status))
        .route("/delete_todo_item/{id}", delete(delete_todo_item))
        .layer(middleware::from_fn(require_json));

    let uploads_route =  Router::new()
        .route("/upload_avatar", post(upload_avatar)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)))
        .route("/upload_pdf", post(upload_document)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)));

    let app = Router::new()
        .nest("/auth", auth_routes)
        .nest("/todos", todo_routes)
        .nest("/uploads",uploads_route)
        .route("/ws", get(handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
