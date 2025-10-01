use argon2::{Argon2, PasswordHasher, password_hash::SaltString, PasswordVerifier};
use axum::http::StatusCode;
use base64::engine::Engine;
use serde_json::Value;

use crate::db::{db_connection, get_password_hash, get_device_id, new_device};

pub async fn authenticate_user_on_new_device(data: Value) -> Result<Value, StatusCode> {
    let client = db_connection().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let username = data.get("username").and_then(|v| v.as_str());
    let password = data.get("password").and_then(|v| v.as_str());
    let uuid = data.get("uuid").and_then(|v| v.as_str());

    if username.is_none() || password.is_none() || uuid.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !verify_password(username.unwrap(), password.unwrap()).await.unwrap() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Hash the uuid
    let hashed_uuid = hash_argon2(uuid.unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let tok = generate_token().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _result = new_device(username.unwrap(), &hashed_uuid, &tok, &client)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let device_id = get_device_id(&username.unwrap(), &hashed_uuid, &client)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(serde_json::json!({
        "status": "success",
        "message": format!("Authentication successful for user: {}", username.unwrap()),
        "token": tok,
        "device_id": device_id.to_string(),
    }))
}

pub async fn hash_argon2(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("Failed to generate salt: {}", e))?;
    let salt = SaltString::encode_b64(&seed).map_err(|e| format!("Failed to encode salt: {}", e))?;
    let argon2 = Argon2::default();
    let hashed_password = argon2.hash_password(password.as_bytes(), &salt).map_err(|e| format!("Failed to hash password: {}", e))?;
    Ok(hashed_password.to_string())
}

pub async fn generate_token() -> Result<String, Box<dyn std::error::Error>> {
    let mut token_bytes = [0u8; 64];
    getrandom::getrandom(&mut token_bytes)
        .map_err(|e| format!("Failed to generate token: {}", e))?;
    let token = base64::engine::general_purpose::STANDARD.encode(&token_bytes);
    Ok(token)
}

async fn verify_password(username: &str, password: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let client = db_connection().await?;

    let password_hash = get_password_hash(username, &client).await?;
    if password_hash.is_empty() {
        return Ok(false);
    }

    let argon2 = Argon2::default();
    let parsed_hash = password_hash::PasswordHash::new(&password_hash)
        .map_err(|_| "Failed to parse password hash")?;
    
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}