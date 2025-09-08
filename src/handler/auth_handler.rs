//! Authentication handlers for login, logout, and session management.
//!
//! This module provides handlers for user authentication operations,
//! including login form display, login processing, and logout.

use axum::{
    Form,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use serde::Deserialize;
use tracing::warn;

use crate::{
    ApiState,
    db::{
        self,
        user_session::{DEFAULT_SESSION_MINUTES, SessionToken, make_user_session},
        users::check_username_password,
    },
    error::AppResult,
    handler::{AuthState, HtmlTemplate, LoginTemplate, Toast, middlewares::check_session_cookie},
};

/// Serves the login page template.
///
/// Redirects to home page if the user is already authenticated.
pub async fn login_page_handler(State(state): ApiState, jar: CookieJar) -> impl IntoResponse {
    let maybe_user = check_session_cookie(&state, &jar).await;

    // Redirect to home if already authenticated
    if maybe_user.is_ok() {
        return Redirect::to("/").into_response();
    }

    HtmlTemplate(LoginTemplate {
        title: "Login",
        auth_state: AuthState::LoginPage,
        ..Default::default()
    })
    .into_response()
}

/// Form data structure for login requests.
#[derive(Debug, Deserialize)]
pub struct LoginUserSchema {
    pub username: String,
    pub password: String,
}

/// Name of the session cookie.
///
/// DO NOT USE THIS TO REMOVE THE COOKIE - it won't work. Instead, use [`clear_session`],
/// which will set the correct attributes such that the cookie will actually be removed
/// by the browser.
pub const SESSION_COOKIE: &str = "session_cookie";

/// Creates a session cookie with appropriate security settings.
///
/// The cookie is configured with:
/// - HTTP-only flag to prevent JavaScript access
/// - Strict same-site policy
/// - Secure flag in production (HTTPS only)
/// - Session duration matching the database session
fn session_cookie<'a>(token: impl Into<String>) -> Cookie<'a> {
    Cookie::build((SESSION_COOKIE.to_string(), token.into()))
        .path("/")
        .http_only(true)
        .max_age(cookie::time::Duration::minutes(DEFAULT_SESSION_MINUTES))
        .same_site(cookie::SameSite::Strict)
        .secure(if cfg!(debug_assertions) {
            false
        } else {
            // Secure cookies always for prod
            true
        })
        .build()
}

/// Adds a session cookie to the jar.
///
/// Used after successful authentication to establish a session.
pub(super) fn set_session(jar: CookieJar, token: String) -> CookieJar {
    jar.add(session_cookie(token))
}

/// Removes the session cookie from the jar.
///
/// Used during logout to clear the client's session.
fn clear_session(jar: CookieJar) -> CookieJar {
    jar.remove(session_cookie(String::new()))
}

/// Handles the POST request for user login.
///
/// This function:
/// 1. Validates username and password
/// 2. Creates a new session in the database
/// 3. Signs a session token with JWT
/// 4. Sets the session cookie
/// 5. Redirects to the home page
///
/// # Errors
///
/// Returns `AppError::bad_login` if credentials are invalid.
/// Returns database errors if session creation fails.
pub async fn login_user_handler(State(state): ApiState, jar: CookieJar, Form(form_data): Form<LoginUserSchema>) -> AppResult<Response> {
    let LoginUserSchema { username, password } = form_data;
    let user = check_username_password(&state.pool, username, password).await?;
    let mut session = make_user_session(&state.pool, &user).await?;
    session
        .add_message(
            &state.pool,
            Toast {
                is_success: true,
                message: "Logged in.".to_string(),
            },
        )
        .await;

    let signed_token = state.encryption.sign_token(session.session_token())?;

    Ok((set_session(jar, signed_token), Redirect::to("/")).into_response())
}

/// Handles user logout.
///
/// This function:
/// 1. Validates the session token
/// 2. Removes the session from the database
/// 3. Clears the session cookie
/// 4. Redirects to the login page
///
/// Returns `UNAUTHORIZED` if no valid session exists.
pub async fn logout_handler(State(state): ApiState, jar: CookieJar) -> impl IntoResponse {
    let Some(token) = jar.get(SESSION_COOKIE).map(Cookie::value) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let signed_token = match state.encryption.verify_token_sig::<SessionToken>(token) {
        Ok(signed_token) => signed_token,
        Err(err) => {
            warn!(err = ?err, "Session token signature is invalid, not attempting to remove session but clearing cookie anyway.");
            return (clear_session(jar), StatusCode::UNAUTHORIZED).into_response();
        }
    };
    if let Err(err) = db::user_session::remove_session(&state.pool, &signed_token).await {
        warn!(err = ?err, "Error invalidating user session, but clearing session cookie anyway.");
    }

    (clear_session(jar), Redirect::to("/login")).into_response()
}
