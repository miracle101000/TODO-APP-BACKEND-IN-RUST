use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize)]
pub struct AuthRequest {
 pub username: String,
 pub password: String
}

#[derive(Deserialize,Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String
}

#[derive(Deserialize,Serialize)]
pub struct RefreshTokenRequest{
    pub refresh_token: String
}

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: String
}
