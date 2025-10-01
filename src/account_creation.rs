use axum::{
    http::{StatusCode},
};
use serde_json::Value;
use base64::engine::Engine; 

use crate::db::{self, db_connection};
use crate::authentication::{hash_argon2, generate_token};

pub async fn new_account_logic(data: Value) -> Result<Value, StatusCode> {
    //Connect to the database
    let client = db_connection().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    //Retrieve username, password, email, and uuid from the request body
    let username = data.get("username").and_then(|v| v.as_str());
    let password = data.get("password").and_then(|v| v.as_str());
    let email = data.get("email").and_then(|v| v.as_str());
    let uuid = data.get("uuid").and_then(|v| v.as_str());

    //Verify that all required fields are present
    if username.is_none() || password.is_none() || email.is_none() || uuid.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Hash the password
    let hashed_password = hash_argon2(password.unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    //hash the uuid
    let hashed_uuid = hash_argon2(uuid.unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Insert user into database
    let _result = db::new_user(username.unwrap(), &hashed_password.to_string(), email.unwrap(), &client)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    //Get token for future auth from this device
    let tok = generate_token().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    //insert device into database
    let _result = db::new_device(username.unwrap(), &hashed_uuid, &tok, &client)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result = db::get_device_id(username.unwrap(), &hashed_uuid, &client).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result < 0 {
        eprintln!("Device not found for user: {}", username.unwrap());
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let device_id: i32 = result;

    Ok(serde_json::json!({
        "status": "success",
        "message": "Account created successfully",
        "username": username.unwrap(),
        "token": tok,
        "device_id": device_id.to_string(),
    }))
}