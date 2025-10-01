use tokio_postgres::{Client};
mod db;
mod server;
mod websocket_helpers;
mod messages_outbound;
mod messages_inbound;
mod account_creation;
mod authentication;

#[tokio::main]
async fn main() {
    
    //await client connections
    server::app().await.unwrap_or_else(|err| {
        eprintln!("Error in awaitCnxns: {}", err);
        std::process::exit(1);
    });
}
