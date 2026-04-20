mod handlers;
mod models;
mod utility;
mod repository;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use dotenvy::dotenv;
use models::TodoItem;
use tokio::sync::broadcast;
use tower_http::services::ServeDir;

use crate::handlers::{
    add_todo_item, delete_todo_item, download_document, get_business_news, get_todo_items, handler,
    login, logout, refresh, register, sign_download, signed_download, update_todo_item,
    update_todo_item_status, upload_avatar, upload_document,
};
use crate::utility::{spawn_cleanup_worker, spawn_todo_event_worker};

use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::info;

use crate::models::{AppState, CachedNews};
use crate::utility::{require_json, rate_limit::{make_limiter, rate_limit_middleware}};
use crate::utility::jobs::{spawn_news_cache_worker};
use crate::repository::postgres::{
    PgTodoRepository, PgUserRepository, PgRefreshTokenRepository,
};

use sqlx::postgres::PgPoolOptions;
use metrics_exporter_prometheus::PrometheusBuilder;

fn init_tracer() -> opentelemetry_sdk::trace::Tracer {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://localhost:4317"),
        )
        .with_trace_config(
            sdktrace::config().with_resource(
                opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", "todo-api"),
                    opentelemetry::KeyValue::new("service.version", "1.0.0"),
                    opentelemetry::KeyValue::new("deployment.environment", "production"),
                ])
            )
        )
        .install_batch(runtime::Tokio)
        .expect("Failed to install OTel tracer")
}

#[tokio::main]
async fn main() {
    let tracer = init_tracer();
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .init();

    PrometheusBuilder::new()
        .install()
        .expect("Failed to install Prometheus recorder");

    dotenv().ok();

    let _ = rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let news_cache: Arc<tokio::sync::RwLock<Option<CachedNews>>> =
    Arc::new(tokio::sync::RwLock::new(None));

    let (tx, _) = broadcast::channel::<TodoItem>(100);

    let state = AppState {
        tx:             tx.clone(),
        http_client:    reqwest::Client::new(),
        jwt_secret:     env::var("JWT_SECRET").expect("JWT_SECRET missing"),
        refresh_secret: env::var("REFRESH_SECRET").expect("REFRESH_SECRET missing"),
        download_secret: env::var("DOWNLOAD_SECRET").expect("DOWNLOAD_SECRET missing"),

        // swap these for mock implementations in tests
        todos:          Arc::new(PgTodoRepository          { pool: pool.clone() }),
        users:          Arc::new(PgUserRepository          { pool: pool.clone() }),
        refresh_tokens: Arc::new(PgRefreshTokenRepository  { pool: pool.clone() }),
        news_cache:     news_cache.clone(),
    };

    // ── Background workers ────────────────────────────────────────────
    spawn_todo_event_worker(tx.subscribe());
    spawn_cleanup_worker(pool.clone());
    spawn_news_cache_worker(state.http_client.clone(), news_cache);

    // ── Rate limiters ─────────────────────────────────────────────────
    let auth_limiter   = make_limiter(1, 5);
    let todo_limiter   = make_limiter(10, 50);
    let upload_limiter = make_limiter(1, 5);
    let news_limiter   = make_limiter(5, 20);

    // ── Routes ────────────────────────────────────────────────────────
    let auth_routes = Router::new()
        .route("/refresh", post(refresh))
        .route("/login", post(login))
        .route("/register", post(register))
        .layer(middleware::from_fn(require_json))
        .route("/logout", post(logout))
        .layer(middleware::from_fn_with_state(auth_limiter, rate_limit_middleware));

    let todo_routes = Router::new()
        .route("/add_todo_item", post(add_todo_item))
        .route("/get_todo_items", get(get_todo_items))
        .route("/update_todo_item_status/{id}", patch(update_todo_item_status))
        .route("/update_todo_item/{id}", patch(update_todo_item))
        .route("/delete_todo_item/{id}", delete(delete_todo_item))
        .layer(middleware::from_fn(require_json))
        .layer(middleware::from_fn_with_state(todo_limiter, rate_limit_middleware));

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
        .route("/documents/download", get(signed_download))
        .layer(middleware::from_fn_with_state(upload_limiter, rate_limit_middleware));

    let news_route = Router::new()
        .route("/business_news", get(get_business_news))
        .layer(middleware::from_fn(require_json))
        .layer(middleware::from_fn_with_state(news_limiter, rate_limit_middleware));

    let app = Router::new()
        .nest("/auth", auth_routes)
        .nest("/todos", todo_routes)
        .nest("/news", news_route)
        .nest("/uploads", uploads_route)
        .nest_service("/static", ServeDir::new("uploads/public"))
        .route("/ws", get(handler))
        .with_state(state);

    info!("Server starting up on 0.0.0.0:3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    global::shutdown_tracer_provider();
}