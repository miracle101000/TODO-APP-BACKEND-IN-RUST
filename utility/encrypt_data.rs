use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, aead::{Aead, OsRng}};
use base64::{engine::general_purpose, Engine as _};

use crate::models::{AppError, EncryptedTodoResponse};

pub fn seal_data<T: serde::Serialize>(data: &T, key_str: &str) -> Result<EncryptedTodoResponse, AppError> {
    let json = serde_json::to_string(data).map_err(|_| AppError::Internal("Serialization failed".into()))?;
    
    // Key must be 32 bytes for AES-256
    let key = Key::<Aes256Gcm>::from_slice(key_str.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, json.as_bytes())
        .map_err(|_| AppError::Internal("Encryption failed".into()))?;

    Ok(EncryptedTodoResponse {
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
        nonce: general_purpose::STANDARD.encode(nonce),
    })
}