use serde_json::{Map, Value};
use chrono::Utc;

use crate::db;

pub async fn auth(user_id: &str, token: &str, subtype: &str) -> Result<Value, Box<dyn std::error::Error>> {

    let auth_message = serde_json::json!({
        "type": "auth",
        "subtype": subtype,
        "user_id": user_id,
        "token": token,
        "timestamp": Utc::now().timestamp()
    });

    Ok(auth_message)
}

pub async fn message(user_id: &str, content: &str) -> Result<Value, Box<dyn std::error::Error>> {
    
    let message = serde_json::json!({
        "type": "message",
        "sender": user_id,
        "content": content,
        "timestamp": Utc::now().timestamp()
    });

    Ok(message)
}

pub async fn devices(user_id: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let db_conn = db::db_connection().await?;
    let result = db_conn.query("SELECT device_id FROM devices WHERE user_id = $1", &[&user_id]).await?;
    
    let devices: Vec<i32> = result.iter().map(|row| row.get(0)).collect();

    let ret = serde_json::json!({
        "user_id": user_id,
        "devices": devices,
        "timestamp": Utc::now().timestamp()
    });

    Ok(ret)
}