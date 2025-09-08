//! Database module for managing `SQLite` connections and migrations.
//!
//! This module provides database connection pooling, automatic migrations,
//! and submodules for specific database operations.

pub mod user_session;
pub mod users;
use anyhow::{Context as _, Result};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

const MAX_CONNECTIONS: u32 = 10;

/// Establishes a connection pool to the `SQLite` database.
///
/// This function:
/// 1. Creates a connection pool with configured limits
/// 2. Runs any pending database migrations
/// 3. In debug mode, creates a default admin user if needed
///
/// # Errors
///
/// Returns an error if:
/// - Database connection fails
/// - Migrations fail to run
/// - Debug initialization fails
pub async fn connect(pool_uri: &str) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect(pool_uri)
        .await
        .context("Error: 🔥 unable to connect to the database!")?;

    sqlx::migrate!()
        .run(&pool)
        .await
        .with_context(|| format!("🚨 Could not run database migrations for database at '{pool_uri}'"))?;

    #[cfg(debug_assertions)]
    init_for_dev(&pool).await?;

    println!("✅ Successfully connected to database!");
    Ok(pool)
}

/// Initializes development-specific database data.
///
/// Creates a default admin user for testing purposes in debug builds.
/// Username: admin
/// Password: admin123 (pre-hashed with Argon2)
///
/// # Errors
///
/// Returns an error if database operations fail.
#[cfg(debug_assertions)]
async fn init_for_dev(pool: &SqlitePool) -> Result<()> {
    const ADMIN_USERNAME: &str = "admin";
    const ADMIN_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$LL8PlWjHaOuA6gLK2+x1fQ$LY791mB/ymrCS/HgwSHqj4Mc9eEnOcZB/OT5bu9+GFY";
    let has_admin = sqlx::query!(
        r#"
            select user_id from users
            where username = ?
        "#,
        "admin"
    )
    .fetch_optional(pool)
    .await?;

    if has_admin.is_none() {
        println!("👤 No dev-mode admin user found, adding...");
        let _res = sqlx::query!(
            r#"
                insert into users (
                    username,
                    password_hash
                )
                values (?, ?)
            "#,
            ADMIN_USERNAME,
            ADMIN_PASSWORD_HASH
        )
        .execute(pool)
        .await?;
        println!("✨ Added dev user: admin");
    }

    Ok(())
}
