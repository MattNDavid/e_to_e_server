use serde_json::Value;

use crate::messages_outbound;

pub async fn handler(message: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let msg_type = message.get("type").and_then(|v| v.as_str());

    match msg_type {
        Some("user") => {
            // Handle user-related messages
            return user_handler(message).await;
        }
        _ => Err("Invalid message format".into()),
    }
}

async fn user_handler(message: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let user_id = message.get("user_id").and_then(|v| v.as_str()).ok_or("Missing user_id")?;
    let action = message.get("action").and_then(|v| v.as_str()).ok_or("Missing action")?;

    match action {
        "get_devices" => {
            // Fetch user devices from the database
            return messages_outbound::devices(user_id).await;
        }
        _ => Err("Unknown action".into()),
    }
}