use serde::{Deserialize,Serialize};
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode}
};
use jsonwebtoken::{decode,DecodingKey,Validation};

#[derive(Serialize, Deserialize, Debug)]
pub enum TokenType { Access, Refresh}


#[derive(Debug, Deserialize, Serialize)]
pub struct JwtInterceptor {
    pub user_token_or_id: String,
    #[serde(rename="exp")]
    pub expiration_date_in_milliseconds: u64,
    #[serde(rename="iat")]
    pub issued_at: u64,
    pub token_type: TokenType
}


// Confirm token is valid and accessible accross instances
impl<S> FromRequestParts<S> for JwtInterceptor
where S: Send + Sync {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts:&mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
          let auth_header = parts.headers.get("Authorization")
          .and_then(|h| h.to_str().ok())
          .ok_or((StatusCode::UNAUTHORIZED,"Missing Token".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED,"Invalid Token Type".to_string()))
        }

        let token = &auth_header[7..];
        let secret = std::env::var("JWT_SECRET").unwrap();
        decode::<JwtInterceptor> (
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default()
        ).map(|data| data.claims)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Token".to_string()))
    }

}