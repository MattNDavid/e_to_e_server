use axum::http::HeaderMap;

pub async fn extract_auth_headers(headers: HeaderMap) -> Result<(String, String, String, String), Box<dyn std::error::Error>> {
    
    let user_id = headers.get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let token = headers.get("x-auth-token")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let uuid = headers.get("x-device-uuid")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let device_id = headers.get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if(user_id.is_none() || token.is_none() || uuid.is_none() || device_id.is_none()) {
        return Err("Missing required headers".into());
    }

    Ok((
        user_id.unwrap(),
        token.unwrap(),
        uuid.unwrap(),
        device_id.unwrap(),
    ))
}