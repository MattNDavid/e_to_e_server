use postgres::error::DbError;
use tokio_postgres::{NoTls, Error, Client};
use dotenv::dotenv;
use std::env;

// This module connects to a PostgreSQL database using the tokio_postgres crate.
pub async fn db_connection() -> Result<Client, Error> {
    dotenv().ok();
    
    // Handle the Result from env::var properly
    let dbpword = env::var("DBPASSWORD")
        .expect("DBPASSWORD environment variable not set");
    
    // Use format! macro for string concatenation
    let connection_string = format!(
        "host=localhost user=dev password={} dbname=msgr_db", 
        dbpword
    );

    let (_client, connection) =
        tokio_postgres::connect(&connection_string, NoTls).await?;
    // Spawn the connection to run in the background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    Ok(_client)
}

pub async fn new_user(username: &str, password_hash: &str, email: &str, db: &Client) -> Result<u64, Error> {
    let query = "INSERT INTO users (user_id, password_hash, email) VALUES ($1, $2, $3)";
    let result = db.execute(query, &[&username, &password_hash, &email]).await?;
    Ok(result)
}

pub async fn new_device(username: &str, uuid: &str, token: &str, db: &Client) -> Result<u64, Error> {
    let query = "INSERT INTO devices (user_id, uuid, current_token) VALUES ($1, $2, $3)";
    let result = db.execute(query, &[&username, &uuid, &token]).await?;
    Ok(result)
}

pub async fn get_device_id(username: &str, uuid: &str, db: &Client) -> Result<i32, Error> {
    let query = "SELECT device_id FROM devices WHERE user_id = $1 AND uuid = $2";
    let rows = db.query(query, &[&username, &uuid]).await?;
    
    if rows.is_empty() {
        return Ok(-1);
    }
    
    let row = &rows[0];
    Ok(row.get(0))
}

pub async fn get_password_hash(username: &str, db: &Client) -> Result<String, Error> {
    let query = "SELECT password_hash FROM users WHERE user_id = $1";
    let rows = db.query(query, &[&username]).await?;

    if rows.is_empty() {
        return Ok("".into());
    }

    let row = &rows[0];
    Ok(row.get(0))
}