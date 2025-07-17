use axum::{
    extract::{Query, Json, WebSocketUpgrade, ws::WebSocket},
    http::{StatusCode, HeaderMap},
    response::{Json as ResponseJson, IntoResponse},
    routing::{get, post},
    Router,
};
use serde_json::Value;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use futures_util::{StreamExt, SinkExt};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use password_hash::{SaltString};
use base64::engine::Engine; // Import the Engine trait for encode()

use crate::connect_to_db::db_connection;
use crate::websocket_helpers;
use crate::messages_outbound;

type Users = Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>;

pub async fn app() -> tokio::io::Result<()> {
    let users: Users = Arc::new(Mutex::new(HashMap::new()));

    let app: Router = Router::new()
        .route("/authenticate", post(authenticate))
        .route("/new_account", post(new_account))
        .route("/ws", get(websocket_handler))
        .with_state(users);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("server running on http://localhost:3000");
    axum::serve(listener, app.into_make_service()).await?;
    
    Ok(())
}
async fn websocket_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    axum::extract::State(users): axum::extract::State<Users>,
) -> impl IntoResponse {
    
    let parsed_headers = websocket_helpers::extract_auth_headers(headers)
        .await;
    //If client does not provide required headers, return HTTP400
    if let Err(_) = parsed_headers {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (user_id, token, uuid, device_id) = parsed_headers.unwrap();

    //Connect to the database
    let client = db_connection().await;
    if client.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let client = client.unwrap();
    // Query for device uuid and token (both used for auth)
    let query = "SELECT uuid, current_token FROM devices WHERE user_id = $1 AND device_id = $2";
    let result = client.query(query, &[&user_id, &device_id.as_ref().unwrap().parse::<i32>().unwrap()]).await;

    let rows = match result {
        Ok(ref rows) if !rows.is_empty() => rows,
        Ok(_) | Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };
    //extract the uuid and token from the output
    let row = &rows[0];
    let db_uuid = row.get::<_, String>(0);
    let db_token = row.get::<_, String>(1);

    //uuid is hashed in the database, so verify with argon2
    let argon2 = Argon2::default();
    let parsed_uuid = password_hash::PasswordHash::new(&db_uuid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if argon2.verify_password(uuid.unwrap().as_bytes(), &parsed_uuid).is_err() || token.unwrap() != db_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Delete the old device token and replace it with a new one
    // This is to prevent replay attacks and ensure the token is fresh
    let new_token = generate_token().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _query = client.execute("UPDATE devices SET current_token = $1 WHERE user_id = $2 AND device_id = $3", &[&new_token, &user_id, &device_id.as_ref().unwrap().parse::<i32>().unwrap()])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, users, user_id, device_id, new_token)))
}

async fn handle_socket(socket: WebSocket, users: Users, user_id: String, device_id: String, new_token: String) {
    let (mut sender, mut receiver) = socket.split();
    
    // Create broadcast channel for this user
    let (tx, mut rx) = broadcast::channel::<String>(100);

    //send a confirmation message to the confirm successful connection
    let confirmation_message = messages_outbound::confirmation(&user_id, &new_token).await?;
    tx.send(confirmation_message.to_string()).unwrap();

    //insert the user into the users map
    // This allows us to send messages to this user later
    users.lock().await.insert(format!("{}:{}", user_id.clone(), device_id.clone()), tx.clone());

    // Spawn task to send messages to this client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(axum::extract::ws::Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages
    //Create clones to allow an owned copy of each channel for each task
    let tx_clone = tx.clone();
    let users_clone = users.clone();
    let user_id_clone = user_id.clone();


    //new message recieve task
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let axum::extract::ws::Message::Text(text) = msg {
                match serde_json::from_str::<Value>(&text) {
                    Ok(json) => {
                        if let Some(msg_type) = json.get("type").and_then(|v| v.as_str()) {
                            match msg_type {
                                "message" => {
                                    // Handle encrypted messages
                                    if let (Some(content), Some(recipient)) = (
                                        json.get("content").and_then(|v| v.as_str()),
                                        json.get("recipient").and_then(|v| v.as_str())
                                    ) {
                                        // Forward encrypted message to recipient
                                        let users_lock = users_clone.lock().await;
                                        // Check if recipient exists in the users map
                                        if let Some(recipient_tx) = users_lock.get(recipient) {
                                            let message = messages_outbound::message(&user_id_clone, content).await?;
                                            let _ = recipient_tx.send(message.to_string());
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse WebSocket message: {}", e);
                    }
                }
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        },
        _ = &mut recv_task => {
            send_task.abort();
        }
    }

    // Clean up user when they disconnect
    users.lock().await.remove(&user_id);
    println!("User {} disconnected", user_id);
}

async fn new_account(Json(payload): Json<Value>) -> Result<ResponseJson<Value>, StatusCode> { 
    match new_account_logic(payload).await {
        Ok(response) => Ok(ResponseJson(response)),
        Err(e) => Err(e),
    }    
}

/*For new device authentication
This function is used to authenticate a user with their credentials
Returning users will authenticate directly using a token at the /ws endpoint
TL;DR: Use this function to register a new device and get a token
*/
async fn authenticate(Json(payload): Json<Value>) -> Result<ResponseJson<Value>, StatusCode> {
    match authenticate_logic(payload).await {
        Ok(response) => Ok(ResponseJson(response)),
        Err(e) => Err(e),
    }
}

async fn new_account_logic(data: Value) -> Result<Value, StatusCode> {
    let client = db_connection().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    //verify values
    //username == user_id
    let username = data.get("username").and_then(|v| v.as_str());
    let password = data.get("password").and_then(|v| v.as_str());
    let email = data.get("email").and_then(|v| v.as_str());
    let uuid = data.get("uuid").and_then(|v| v.as_str());

    if username.is_none() || password.is_none() || email.is_none() || uuid.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    //implement email verification here

    // Hash the password
    //Using less secure method temporarily due to errors in WSL
    let hashed_password = hash_argon2(password.unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    //hash the uuid
    let hashed_uuid = hash_argon2(uuid.unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Insert user into database
    let query = "INSERT INTO users (user_id, password_hash, email) VALUES ($1, $2, $3)";
    let _result = client.execute(query, &[&username, &hashed_password.to_string(), &email])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    //Get token for future auth from this device
    let tok = generate_token().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("username: {}, uuid: {}, token: {}", username.unwrap(), hashed_uuid, tok);

    //insert device into database
    let query = "INSERT INTO devices (user_id, uuid, current_token) VALUES ($1, $2, $3)";
    let _result =  match client.execute(query, &[&username, &hashed_uuid, &tok]).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Database insert error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };


    let query = "SELECT device_id from devices WHERE user_id = $1 AND uuid = $2";
    let _result = match client.query(query, &[&username, &hashed_uuid]).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Database query error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if _result.is_empty() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let row = &_result[0];
    let device_id: i32 = row.get(0);
    
    Ok(serde_json::json!({
        "status": "success",
        "message": "Account created successfully",
        "username": username.unwrap(),
        "token": tok,
        "device_id": device_id.to_string(),
    }))
}
/*
Logic to authenticate a user on a new device (using username and password)
TODO: add email verification and verification using user trusted device
*/
async fn authenticate_logic(data: Value) -> Result<Value, StatusCode> {
    let client = db_connection().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let username = data.get("username").and_then(|v| v.as_str());
    let password = data.get("password").and_then(|v| v.as_str());
    let uuid = data.get("uuid").and_then(|v| v.as_str());

    if username.is_none() || password.is_none() || uuid.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let query = "SELECT password_hash FROM users WHERE username = $1";
    let result = client.query(query, &[&username])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let row = &result[0];
    let password_hash: String = row.get(0);

    let argon2 = Argon2::default();

    // Parse the password hash string into a PasswordHash object
    let parsed_hash = password_hash::PasswordHash::new(&password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if argon2.verify_password(password.unwrap().as_bytes(), &parsed_hash).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Hash the uuid
    let hashed_uuid = hash_argon2(uuid.unwrap())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let tok = generate_token().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let query = client.execute("INSERT INTO devices (user_id, device_uuid, current_token) VALUES ($1, $2, $3)", &[&username, &hashed_uuid, &tok])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let query = "SELECT device_id FROM devices WHERE user_id = $1 AND device_uuid = $2";
    let result = client.query(query, &[&username, &hashed_uuid]).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result.is_empty() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let row = &result[0];
    let device_id: i32 = row.get(0);


    Ok(serde_json::json!({
        "status": "success",
        "message": format!("Authentication successful for user: {}", username.unwrap()),
        "token": tok,
        "device_id": device_id.to_string(),
    }))
}

async fn generate_token() -> Result<String, Box<dyn std::error::Error>> {
    let mut token_bytes = [0u8; 64];
    getrandom::getrandom(&mut token_bytes)
        .map_err(|e| format!("Failed to generate token: {}", e))?;
    let token = base64::engine::general_purpose::STANDARD.encode(&token_bytes);
    Ok(token)
}

async fn hash_argon2(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("Failed to generate salt: {}", e))?;
    let salt = SaltString::encode_b64(&seed).map_err(|e| format!("Failed to encode salt: {}", e))?;
    let argon2 = Argon2::default();
    let hashed_password = argon2.hash_password(password.as_bytes(), &salt).map_err(|e| format!("Failed to hash password: {}", e))?;
    Ok(hashed_password.to_string())
}