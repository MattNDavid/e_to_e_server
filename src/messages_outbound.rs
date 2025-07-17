use serde_json::Value;
use Chrono::Utc;

pub async fn confirmation(user_id: &str, token: &str) -> Result<Value, Box<dyn std::error::Error>> {
    
    let confirmation_message = serde_json::json!({
        "type": "confirmation",
        "message": format!("User {} connected successfully", user_id),
        "token": token,
        "timestamp": Utc::now().timestamp()
    });

    Ok(confirmation_message)
}

pub async fn message(user_id: &str, content: &str) -> Result<Value, Box<dyn std::error::Error>> {
    
    let message = serde_json::json!({
        "type": "message",
        "from": user_id,
        "content": content,
        "timestamp": Utc::now().timestamp()
    });

    Ok(message)
}