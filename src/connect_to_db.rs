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