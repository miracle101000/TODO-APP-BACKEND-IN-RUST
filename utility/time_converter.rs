use std::time::SystemTime;

use crate::models::AppError;

pub fn now_secs() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AppError::Internal("System time error".to_string()))
}