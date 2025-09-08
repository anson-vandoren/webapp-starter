//! User database operations and password management.
use anyhow::anyhow;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier as _,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::error::AppError;

/// Represents a user in the system. Its claims should only be treated as valid
/// and correct for the lifetime of the single request in which it was generated.
#[derive(Clone, Debug)]
pub struct User {
    #[allow(clippy::struct_field_names)]
    pub user_id: Uuid,
    pub username: String,
    pub is_revoked: bool,
}

const TIMING_PASSWORD_HASH: &str = "ThisIsNotARealPasswordNorAHash";

/// Authenticates a user by verifying their username and password.
///
/// # Errors
///
/// Returns an error if:
/// - User doesn't exist
/// - Password is incorrect
/// - Password hash verification fails
pub async fn check_username_password(pool: &SqlitePool, username: String, password: String) -> Result<User, AppError> {
    let user = sqlx::query!(
        r#"
            select user_id as "user_id: Uuid", username, password_hash, is_revoked
            from users where username = $1
        "#,
        username
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::bad_login(anyhow!("Username '{username}' not found")));

    let user = match user {
        Ok(user) => {
            verify_hash(&password, &user.password_hash)?;
            user
        }
        Err(e) => {
            // Eliminate timing attack by calculating a password hash anyway even though we know it will fail
            let _ = verify_hash(&password, TIMING_PASSWORD_HASH);
            return Err(e);
        }
    };

    Ok(User {
        user_id: user.user_id,
        username: user.username,
        is_revoked: user.is_revoked,
    })
}

/// Retrieves a user by their ID.
///
/// # Errors
///
/// Returns an error if:
/// - User doesn't exist (`SqliteError::RowNotFound`)
/// - Database query fails
pub async fn get_by_id(pool: &SqlitePool, user_id: Uuid) -> Result<User, AppError> {
    let record = sqlx::query!(
        r#"
            select
                user_id as "user_id: Uuid",
                username,
                is_revoked
            from users
            where user_id = ?
        "#,
        user_id
    )
    .fetch_one(pool)
    .await?;

    Ok(User {
        user_id: record.user_id,
        username: record.username,
        is_revoked: record.is_revoked,
    })
}

/// Verifies a plaintext password against an Argon2 hash.
///
/// # Errors
///
/// Returns `AppError::internal` if the hash cannot be parsed.
/// Returns `AppError::bad_login` if the password doesn't match.
pub fn verify_hash(plaintext: &str, hash: &str) -> Result<(), AppError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| AppError::internal(anyhow!("Stored password hash could not be parsed: {e}")))?;
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed_hash)
        .map_err(|e| AppError::bad_login(anyhow!("Password hash comparison task failed: {e}")))?;
    Ok(())
}

/// Creates an Argon2 hash from a plaintext password.
///
/// # Errors
///
/// Returns `AppError::internal` if hashing fails.
#[allow(unused)]
pub fn create_hash(plaintext: &[u8]) -> Result<String, AppError> {
    let hash = PasswordHasher::hash_password(&argon2::Argon2::default(), plaintext, &SaltString::generate(&mut OsRng))
        .map_err(|e| AppError::internal(anyhow!("Failed to hash password: {e}")))?
        .to_string();
    Ok(hash)
}
