use tokio_postgres::{Client};
mod connect_to_db;
mod server;
mod websocket_helpers;
mod messages_outbound;

#[tokio::main]
async fn main() {
    
    //await client connections
    server::app().await.unwrap_or_else(|err| {
        eprintln!("Error in awaitCnxns: {}", err);
        std::process::exit(1);
    });
}
