//! User session management and persistence.

use anyhow::anyhow;
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::{
    db::{self, users::User},
    error::AppError,
    handler::Toast,
};

/// Token representing a user's session.
///
/// This struct is converted to a JWT and signed, then used
/// as the session cookie. It contains no "claims" on its own
/// and is only a signed identifier with which to look up the
/// session on the backend.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct SessionToken(pub Uuid);

/// User session containing authentication state and messages.
#[derive(Debug, Deserialize, Serialize)]
pub struct Session {
    sid: SessionToken,
    messages: Vec<Toast>,
}

impl Session {
    const RECORD_SEP: u8 = 0x1E;
    const UNIT_SEP: u8 = 0x1F;

    /// Creates a new session from a token and serialized messages.
    pub fn new(sid: SessionToken, message_blob: &[u8]) -> Self {
        Self {
            sid,
            messages: Self::deserialize_messages(message_blob),
        }
    }

    /// Returns a clone of the session token.
    pub fn session_token(&self) -> SessionToken {
        self.sid
    }

    /// Takes all messages from the session and clears them, saving state to the database.
    pub async fn take_messages(&mut self, pool: &SqlitePool) -> Vec<Toast> {
        let messages = std::mem::take(&mut self.messages);
        let _ = save_session(pool, self)
            .await
            .inspect_err(|e| error!(error = ?e, "Failed to save session after retrieving messages."));
        messages
    }

    /// Adds a message to the session, persisting to the database.
    pub async fn add_message(&mut self, pool: &SqlitePool, message: Toast) {
        self.messages.push(message);
        let _ = save_session(pool, self)
            .await
            .inspect_err(|e| error!(error=?e, "Failed to save session after adding message."));
    }

    fn serialize_messages(&self) -> Vec<u8> {
        let mut blob = Vec::new();

        for (i, toast) in self.messages.iter().enumerate() {
            if i > 0 {
                blob.push(Self::RECORD_SEP);
            }

            blob.push(if toast.is_success { b'1' } else { b'0' });
            blob.push(Self::UNIT_SEP);
            blob.extend_from_slice(toast.message.as_bytes());
        }

        blob
    }

    fn deserialize_messages(blob: &[u8]) -> Vec<Toast> {
        if blob.is_empty() {
            return Vec::new();
        }

        let mut messages = Vec::new();
        for record in blob.split(|&b| b == Self::RECORD_SEP) {
            if record.is_empty() {
                warn!("Found an empty record in blob={blob:?}");
                continue;
            }
            if let Some(sep_pos) = record.iter().position(|&b| b == Self::UNIT_SEP) {
                // First byte should be '1' for is_success=true or '0' for false
                let is_success = record[0] == b'1';
                let message_bytes = &record[sep_pos + 1..];
                if let Ok(message) = String::from_utf8(message_bytes.to_vec()) {
                    messages.push(Toast { is_success, message });
                } else {
                    warn!("Invalid UTF-8 message in record={record:?}");
                }
            }
        }

        messages
    }
}

/// Creates a new session for a user.
///
/// This function:
/// 1. Checks if the user is revoked
/// 2. Cleans expired sessions from the database
/// 3. Creates a new session with a 60-minute expiration
///
/// # Errors
///
/// Returns `AppError::unauthorized` if the user is revoked.
/// Returns database errors if session creation fails.
pub async fn make_user_session(pool: &SqlitePool, user: &User) -> Result<Session, AppError> {
    if user.is_revoked {
        return Err(AppError::unauthorized(anyhow::anyhow!("User is revoked")));
    }

    if let Err(err) = clean_expired_sessions(pool).await {
        // Log it, but don't prevent making a new session
        error!(error = ?err, "Could not clean expired user sessions.");
    }

    let now = chrono::Utc::now();
    let expires_at = now.checked_add_signed(DEFAULT_SESSION_DURATION).unwrap().timestamp();
    let record = sqlx::query!(
        r#"
            insert into user_sessions (
                user_id,
                expires_at
            )
            values (?, ?)
            returning token_id as "token_id: Uuid"
        "#,
        user.user_id,
        expires_at
    )
    .fetch_one(pool)
    .await?;

    debug!(username = user.username, "Created new user session.");
    Ok(Session {
        sid: SessionToken(record.token_id),
        messages: vec![],
    })
}

/// Removes a session from the database.
///
/// Used for logout functionality.
///
/// # Errors
///
/// Returns database errors if deletion fails.
pub async fn remove_session(pool: &SqlitePool, session_token: &SessionToken) -> Result<(), AppError> {
    let res = sqlx::query!(
        r#"
                delete from user_sessions
                where token_id = ?
            "#,
        session_token.0
    )
    .execute(pool)
    .await?;

    let rows = res.rows_affected();
    debug!(rows, "Removed user session.");
    Ok(())
}

/// Result of a session lookup operation.
///
/// Contains the user, their session, and the signed token.
pub struct SessionLookup {
    pub user: User,
    pub session: Session,
    pub signed_token: String,
}

/// Looks up a session and associated user from a session token.
///
/// # Errors
///
/// Returns `AppError::unauthorized` if the session doesn't exist.
/// Returns database errors if queries fail.
pub async fn from_token(pool: &SqlitePool, session_token: SessionToken, signed_token: String) -> Result<SessionLookup, AppError> {
    // TODO: extend duration
    let record = sqlx::query!(
        r#"
            select
                user_id as "user_id: Uuid",
                messages
            from user_sessions
            where token_id = ?
        "#,
        session_token.0
    )
    .fetch_optional(pool)
    .await?;

    let Some(record) = record else {
        return Err(AppError::unauthorized(anyhow!("No user session found.")));
    };

    let user = db::users::get_by_id(pool, record.user_id).await?;
    let session = Session::new(session_token, &record.messages.unwrap_or_default());
    Ok(SessionLookup {
        user,
        session,
        signed_token,
    })
}

pub async fn save_session(pool: &SqlitePool, session: &Session) -> Result<(), AppError> {
    let messages = session.serialize_messages();
    let res = sqlx::query!(
        r#"
            update user_sessions
            set messages = ?
            where token_id = ?
        "#,
        messages,
        session.sid.0
    )
    .execute(pool)
    .await?;

    if res.rows_affected() == 0 {
        Err(AppError::internal(anyhow!("Tried to save a non-existent session: {session:?}")))
    } else {
        Ok(())
    }
}

pub const DEFAULT_SESSION_MINUTES: i64 = 60;
const DEFAULT_SESSION_DURATION: TimeDelta = TimeDelta::minutes(DEFAULT_SESSION_MINUTES);

/// Removes expired sessions from the database.
///
/// Called automatically when creating new sessions to prevent
/// accumulation of expired session records.
///
/// # Errors
///
/// Returns database errors if deletion fails.
async fn clean_expired_sessions(pool: &SqlitePool) -> Result<(), AppError> {
    let now = chrono::Utc::now().timestamp();
    let res = sqlx::query!(
        r#"
            delete
            from user_sessions
            where expires_at < ?
        "#,
        now
    )
    .execute(pool)
    .await?;

    debug!(sessions_deleted = res.rows_affected(), "Deleted expired user sessions.");

    Ok(())
}
