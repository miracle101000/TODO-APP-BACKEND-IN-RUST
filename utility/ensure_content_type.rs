use axum::{
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    middleware::Next,
    response::Response,
};

pub async fn require_json(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
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
