use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DownloadClaims {
    pub user_id: String,
    pub filename: String,
    pub exp: usize,
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    pub token: String,
}