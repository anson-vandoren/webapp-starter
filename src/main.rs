use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use dotenvy::dotenv;
use sqlx::SqlitePool;

use crate::{config::Config, encryption::EncryptionProvider};

mod config;
mod db;
mod encryption;
mod error;
mod handler;
mod route;

// TODO: add application-specific state here
/// Shared application state accessible across all request handlers.
pub struct AppState {
    /// Encryption provider for password hashing and token generation.
    pub encryption: EncryptionProvider,
    /// Database connection pool for `SQLite`.
    pub pool: SqlitePool,
}

/// Type alias for extracting the application state in request handlers.
pub type ApiState = State<Arc<AppState>>;

/// Main entry point for the application.
///
/// Initializes the application by:
/// 1. Loading environment variables from `.env` file
/// 2. Initializing configuration
/// 3. Establishing database connection
/// 4. Setting up encryption provider
/// 5. Starting the web server
///
/// # Errors
///
/// Returns an error if:
/// - Database connection fails
/// - Server fails to bind to the configured address
/// - Server encounters an unrecoverable error during operation
#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from the .env file
    dotenv().ok();
    let config = Config::try_init()?;
    let pool = db::connect(&config.database_url).await?;
    let encryption = EncryptionProvider::new(config.root_key);

    let app_state = Arc::new(AppState { encryption, pool });

    route::serve(app_state).await?;

    Ok(())
}
