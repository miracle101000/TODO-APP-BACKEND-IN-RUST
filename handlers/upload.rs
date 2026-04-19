use std::path::PathBuf;

use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    models::{AppError, AppState, DownloadClaims, DownloadQuery, JwtInterceptor},
    utility::now_secs,
};

async fn resolve_user_file(
    user_id: &str,
    raw_filename: &str,
    base: &std::path::Path,
) -> Result<PathBuf, AppError> {
    let safe_filename = std::path::Path::new(raw_filename)
        .file_name()
        .and_then(|f| f.to_str())
        .filter(|f| !f.is_empty())
        .ok_or_else(|| AppError::AuthError("Invalid filename".into()))?;

    if !safe_filename.starts_with(&format!("{}_", user_id)) {
        return Err(AppError::AuthError(
            "Unauthorized access to document".into(),
        ));
    }

    let path = base.join(safe_filename);

    let canonical = tokio::fs::canonicalize(&path)
        .await
        .map_err(|_| AppError::NotFound("Document not found".into()))?;

    let canonical_base = tokio::fs::canonicalize(base)
        .await
        .map_err(|_| AppError::Internal("Base dir error".into()))?;

    if !canonical.starts_with(&canonical_base) {
        return Err(AppError::AuthError("Invalid file path".into()));
    }

    Ok(canonical)
}

async fn stream_pdf(path: PathBuf) -> Result<impl IntoResponse, AppError> {
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| AppError::NotFound("File not found".into()))?;

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = Body::from_stream(stream);

    Ok(([(header::CONTENT_TYPE, "application/pdf")], body))
}

pub async fn upload_avatar(
    interceptor: JwtInterceptor,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
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

    let file_name = format!(
        "avatar_{}.{}",
        interceptor.user_token_or_id,
        kind.extension()
    );
    let path = std::path::Path::new("uploads/public/avatars").join(file_name);

    tokio::fs::create_dir_all("uploads/public/avatars")
        .await
        .ok();
    tokio::fs::write(&path, data)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

pub async fn upload_document(
    interceptor: JwtInterceptor,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
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

pub async fn sign_download(
    interceptor: JwtInterceptor,
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> Result<Json<String>, AppError> {
    let base = std::path::Path::new("uploads/documents");

    let _ = resolve_user_file(&interceptor.user_token_or_id, &filename, base).await?;

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

pub async fn signed_download(
    State(state): State<AppState>,
    Query(params): Query<DownloadQuery>,
) -> Result<impl IntoResponse, AppError> {
    let data = decode::<DownloadClaims>(
        &params.token,
        &DecodingKey::from_secret(state.download_secret.as_bytes()),
        &Validation::default(),
    )?;

    let claims = data.claims;
    let base = std::path::Path::new("uploads/documents");

    let canonical = resolve_user_file(&claims.user_id, &claims.filename, base).await?;

    stream_pdf(canonical).await
}

pub async fn download_document(
    interceptor: JwtInterceptor,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let base = std::path::Path::new("uploads/documents");
    let canonical = resolve_user_file(&interceptor.user_token_or_id, &filename, base).await?;
    stream_pdf(canonical).await
}
