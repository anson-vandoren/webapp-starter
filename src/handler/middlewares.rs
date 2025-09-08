//! Middleware functions for authentication and session management.
//!
//! This module provides middleware that validates user sessions
//! and enforces authentication requirements for protected routes.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use cookie::Cookie;
use tracing::warn;

use crate::{
    ApiState, AppState,
    db::{
        self,
        user_session::{SessionLookup, SessionToken},
    },
    handler::{
        Error401Template, HtmlTemplate,
        auth_handler::{SESSION_COOKIE, set_session},
    },
};

/// Authentication middleware that validates user sessions.
///
/// This middleware:
/// 1. Checks for a valid session cookie
/// 2. Verifies the JWT signature
/// 3. Looks up the session in the database
/// 4. Adds the user to the request extensions if valid
/// 5. Returns 401 Unauthorized if authentication fails
///
/// Applied to routes that require authentication.
pub async fn auth_user_middleware(State(state): ApiState, jar: CookieJar, mut req: Request, next: Next) -> impl IntoResponse {
    let user = check_session_cookie(&state, &jar).await;
    let SessionLookup { user, signed_token, .. } = match user {
        Ok(user) => user,
        Err(reason) => {
            let template = Error401Template {
                title: "Unauthorized",
                reason: &reason,
                is_error: true,
                ..Default::default()
            };
            return (StatusCode::UNAUTHORIZED, jar.remove(SESSION_COOKIE), HtmlTemplate(template)).into_response();
        }
    };

    // TODO: extend cookie duration
    let jar = set_session(jar, signed_token);

    req.extensions_mut().insert(user);

    let response = next.run(req).await;

    (jar, response).into_response()
}

/// Validates a session cookie and retrieves the associated user.
///
/// This function performs a complete session validation:
/// 1. Extracts the session cookie from the jar
/// 2. Verifies the JWT signature
/// 3. Looks up the session and user in the database
/// 4. Returns the complete session lookup data
///
/// # Errors
///
/// Returns a string error message if:
/// - No session cookie exists
/// - JWT signature is invalid
/// - Session doesn't exist in database
/// - User associated with session doesn't exist
pub async fn check_session_cookie(state: &Arc<AppState>, jar: &CookieJar) -> Result<SessionLookup, String> {
    let maybe_token = jar.get(SESSION_COOKIE).map(Cookie::value);
    let Some(token) = maybe_token else {
        warn!("API access attempted with no session cookie");
        return Err("Not logged in.".to_string());
    };
    let session_token = match state.encryption.verify_token_sig::<SessionToken>(token) {
        Ok(signed_session) => signed_session,
        Err(err) => {
            warn!(?err, "Token signature invalid on session cookie.");
            return Err("Invalid session, please log in again.".to_string());
        }
    };

    let session_lookup = match db::user_session::from_token(&state.pool, session_token, token.to_string()).await {
        Ok(user) => user,
        Err(err) => {
            warn!(?err, "Session is not valid.");
            return Err("Invalid session, please log in again.".to_string());
        }
    };

    Ok(session_lookup)
}
