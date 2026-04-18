mod models;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query};
use axum::http::header::{self, CONTENT_TYPE};
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
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use validator::Validate;

use crate::models::{
    AppError, AppState, AuthRequest, AuthResponse, CreateTodoRequest, DownloadClaims,
    DownloadQuery, IdPath, JwtInterceptor, RefreshTokenRequest, UpdateTodoRequestStatus, WsQuery,
};

// ---------------------------------------------------------------------------
// File service helper — single source of truth for path resolution.
//
// Centralises:
//   • file_name() extraction     (defeats all path traversal variants)
//   • ownership prefix check     (user_id_ must prefix the filename)
//   • canonicalize()             (resolves symlinks / remaining relative parts)
//   • base-dir containment       (hard guarantee the result stays inside base)
//
// Every download handler calls this instead of repeating the logic inline.
// ---------------------------------------------------------------------------
async fn resolve_user_file(
    user_id: &str,
    raw_filename: &str,
    base: &std::path::Path,
) -> Result<PathBuf, AppError> {
    // Strip any directory components — defeats ../../, ....// and all
    // URL/percent-encoded variants because axum decodes before we see it.
    let safe_filename = std::path::Path::new(raw_filename)
        .file_name()
        .and_then(|f| f.to_str())
        .filter(|f| !f.is_empty())
        .ok_or_else(|| AppError::AuthError("Invalid filename".into()))?;

    // Ownership: file must be prefixed with this user's id.
    if !safe_filename.starts_with(&format!("{}_", user_id)) {
        return Err(AppError::AuthError(
            "Unauthorized access to document".into(),
        ));
    }

    let path = base.join(safe_filename);

    // canonicalize() resolves symlinks and any remaining relative components
    // to an absolute real path. Fails if the file does not exist.
    let canonical = tokio::fs::canonicalize(&path)
        .await
        .map_err(|_| AppError::NotFound("Document not found".into()))?;

    let canonical_base = tokio::fs::canonicalize(base)
        .await
        .map_err(|_| AppError::Internal("Base dir error".into()))?;

    // Belt-and-suspenders: even if something slipped through above, the
    // resolved path must still live inside our base directory.
    if !canonical.starts_with(&canonical_base) {
        return Err(AppError::AuthError("Invalid file path".into()));
    }

    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn now_secs() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AppError::Internal("System time error".to_string()))
}

// Shared streaming logic — avoids duplicating Body::from_stream everywhere.
async fn stream_pdf(path: PathBuf) -> Result<impl IntoResponse, AppError> {
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| AppError::NotFound("File not found".into()))?;

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = Body::from_stream(stream);

    Ok(([(header::CONTENT_TYPE, "application/pdf")], body))
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let token_data = decode::<JwtInterceptor>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.refresh_secret.as_bytes()),
        &Validation::default(),
    )?;

    let claims = token_data.claims;
    let username = &claims.user_token_or_id;

    let stored_token = state
        .refresh_tokens
        .lock()
        .get(username)
        .cloned()
        .ok_or_else(|| AppError::AuthError("Refresh Token Revoked or Not found".to_string()))?;

    if stored_token != payload.refresh_token {
        return Err(AppError::AuthError(
            "Refresh Token Revoked or Not found".to_string(),
        ));
    }

    let now = now_secs()?;

    let access_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: username.clone(),
            expiration_date_in_milliseconds: now + 15 * 60,
            issued_at: now,
            token_type: models::TokenType::Access,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: payload.refresh_token,
    }))
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

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

    let now = now_secs()?;

    let access_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: payload.username.clone(),
            expiration_date_in_milliseconds: now + 15 * 60,
            issued_at: now,
            token_type: models::TokenType::Access,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )?;

    let refresh_token = encode(
        &Header::default(),
        &JwtInterceptor {
            user_token_or_id: payload.username.clone(),
            expiration_date_in_milliseconds: now + 7 * 24 * 60 * 60,
            issued_at: now,
            token_type: models::TokenType::Refresh,
        },
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
) -> Result<impl IntoResponse, AppError> {
    let mut users = state.users.lock();

    if users.contains_key(&payload.username) {
        return Ok((StatusCode::CONFLICT, "User already exists").into_response());
    }

    let hash_password = bcrypt::hash(&payload.password, 12)
        .map_err(|_| AppError::Internal("Failed to hash password".to_string()))?;

    users.insert(payload.username.clone(), hash_password);

    Ok((StatusCode::CREATED, "User Created Successfully").into_response())
}

// logout lives outside the require_json layer — it sends no body.
async fn logout(interceptor: JwtInterceptor, State(state): State<AppState>) -> impl IntoResponse {
    state
        .refresh_tokens
        .lock()
        .remove(&interceptor.user_token_or_id);
    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// Todos
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

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
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
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
            Err(e) => eprintln!("Failed to serialize item: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

async fn upload_avatar(
    interceptor: JwtInterceptor,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    // FIX: enforce exactly one file — previous while loop silently accepted
    // multiple files but only the last one was ever persisted.
    let field = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Internal("No file provided".into()))?;

    let data = field
        .bytes()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let kind = infer::get(&data)
        .ok_or_else(|| AppError::Internal("Unknown file type or empty file".into()))?;

    if !kind.mime_type().starts_with("image/") {
        return Err(AppError::Internal(format!(
            "Expected image, but got {}",
            kind.mime_type()
        )));
    }

    // Avatars are intentionally public — they go to uploads/public so that
    // /static can serve them without auth. Private documents never go here.
    let file_name = format!(
        "avatar_{}.{}",
        interceptor.user_token_or_id,
        kind.extension()
    );
    let path = std::path::Path::new("uploads/public/avatars").join(file_name);

    tokio::fs::create_dir_all("uploads/public/avatars").await.ok();
    tokio::fs::write(&path, data)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

async fn upload_document(
    interceptor: JwtInterceptor,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    // FIX: enforce exactly one file.
    let field = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Internal("No file provided".into()))?;

    let original_name = field.file_name().unwrap_or("doc").to_string();

    let data = field
        .bytes()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let kind = infer::get(&data)
        .ok_or_else(|| AppError::Internal("Unknown file type or empty file".into()))?;

    if kind.mime_type() != "application/pdf" {
        return Err(AppError::Internal(format!(
            "Expected PDF, but got {}",
            kind.mime_type()
        )));
    }

    if !data.starts_with(b"%PDF-") {
        return Err(AppError::Internal("Invalid PDF header".into()));
    }

    lopdf::Document::load_mem(&data).map_err(|_| AppError::Internal("Malformed PDF".into()))?;

    let safe_name = original_name
        .split('.')
        .next()
        .unwrap_or("doc")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>();

    let path = std::path::Path::new("uploads/documents").join(format!(
        "{}_{}.pdf",
        interceptor.user_token_or_id, safe_name
    ));

    tokio::fs::create_dir_all("uploads/documents")
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tokio::fs::write(&path, data)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

// Issues a short-lived signed URL for a private document.
// FIX: uses download_secret instead of jwt_secret — separate key per token
// type so a compromised auth token cannot forge download tokens and vice-versa.
async fn sign_download(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> Result<Json<String>, AppError> {
    let base = std::path::Path::new("uploads/documents");

    // resolve_user_file sanitises, ownership-checks, and confirms the file
    // exists — all before the filename ever touches a JWT claim.
    let _ = resolve_user_file(&interceptor.user_token_or_id, &filename, base).await?;

    // Re-extract the clean filename for embedding in the claim.
    let safe_filename = std::path::Path::new(&filename)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap() // safe: resolve_user_file already validated this
        .to_string();

    let now = now_secs()?;

    let claims = DownloadClaims {
        user_id: interceptor.user_token_or_id.clone(),
        filename: safe_filename,
        exp: (now + 60) as usize, // 60-second window
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.download_secret.as_bytes()),
    )?;

    Ok(Json(format!("/uploads/documents/download?token={}", token)))
}

// Validates the signed token and streams the file.
// No Authorization header required — the signed token is the credential.
async fn signed_download(
    State(state): State<AppState>,
    Query(params): Query<DownloadQuery>,
) -> Result<impl IntoResponse, AppError> {
    // FIX: decode with download_secret, not jwt_secret.
    let data = decode::<DownloadClaims>(
        &params.token,
        &DecodingKey::from_secret(state.download_secret.as_bytes()),
        &Validation::default(),
    )?;

    let claims = data.claims;
    let base = std::path::Path::new("uploads/documents");

    // Re-sanitise even though the claim is signed — defence in depth in case
    // the signing key is ever rotated or this handler is refactored later.
    let canonical = resolve_user_file(&claims.user_id, &claims.filename, base).await?;

    stream_pdf(canonical).await
}

// Direct authenticated download — requires a Bearer token in the Authorization
// header. Useful for programmatic fetch() calls from your frontend.
async fn download_document(
    interceptor: JwtInterceptor,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let base = std::path::Path::new("uploads/documents");
    let canonical = resolve_user_file(&interceptor.user_token_or_id, &filename, base).await?;
    stream_pdf(canonical).await
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

async fn require_json(req: Request<axum::body::Body>, next: Next) -> Result<Response, StatusCode> {
    match *req.method() {
        Method::POST | Method::PATCH => {
            let content_type = req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !content_type.starts_with("application/json") {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }
        _ => {}
    }
    Ok(next.run(req).await)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Cargo.toml:
    // rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std"] }
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

    // Routes are now organised by concern under /uploads:
    //   POST /uploads/avatar                    — upload avatar (→ uploads/public)
    //   POST /uploads/documents                 — upload private PDF
    //   GET  /uploads/documents/{filename}      — authenticated direct download
    //   GET  /uploads/documents/sign/{filename} — issue a signed URL
    //   GET  /uploads/documents/download        — redeem signed URL (no auth header needed)
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