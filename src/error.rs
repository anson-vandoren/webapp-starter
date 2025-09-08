//! Error handling and custom error types for the application.

use anyhow::anyhow;
use argon2::password_hash;
use askama::Template;
use axum::{http::StatusCode, response::IntoResponse};
use tracing::{error, warn};

use crate::handler::HtmlTemplate;

/// Application-wide error type that encapsulates both internal and user-facing errors.
///
/// This type serves as the main error type for the application, providing:
/// - HTTP status codes for proper response handling
/// - Internal error context for debugging and logging
/// - Optional user-facing messages for better UX
#[derive(Debug)]
pub struct AppError {
    /// HTTP status code to return
    status: StatusCode,
    /// Internal error context (not shown to users)
    internal: anyhow::Error,
    /// Optional user-facing message (if None, generic message based on status code)
    user_message: Option<String>,
}

/// Type alias for Results that use `AppError` as the error type.
pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    /// Creates an unauthorized (401) error.
    ///
    /// Used when authentication is required but not provided or invalid.
    #[must_use]
    pub fn unauthorized(internal_msg: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            internal: internal_msg.into(),
            user_message: None, // Let it autofill
        }
    }

    /// Creates a bad login error with a user-friendly message, specifically
    /// designed for failed login attempts.
    #[must_use]
    pub fn bad_login(internal_msg: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            internal: internal_msg.into(),
            user_message: Some("Incorrect username or password.".to_string()),
        }
    }

    /// Creates an internal server error (500).
    ///
    /// Used for unexpected server-side errors that shouldn't expose
    /// internal details to the user.
    #[must_use]
    pub fn internal(internal: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            internal: internal.into(),
            user_message: None, // Let it autofill
        }
    }

    /// Creates a bad request error (400) with a user-facing message.
    ///
    /// Used when the client sends invalid data or makes an invalid request.
    #[must_use]
    pub fn bad_request(user_reason: impl Into<String>) -> AppError {
        let reason: String = user_reason.into();
        Self {
            status: StatusCode::BAD_REQUEST,
            internal: anyhow!(reason.clone()),
            user_message: Some(reason),
        }
    }

    /// Creates an error with a specific HTTP status code.
    pub fn with_status<E>(err: E, status: StatusCode) -> Self
    where
        E: Into<anyhow::Error>,
    {
        let internal = err.into();

        Self {
            status,
            internal,
            user_message: None,
        }
    }

    /// Adds a user-facing message to the error.
    ///
    /// This message will be displayed to the user instead of the default
    /// message for the status code.
    pub fn user_message(mut self, msg: impl Into<String>) -> Self {
        self.user_message = Some(msg.into());
        self
    }

    /// Logs the error at the appropriate level based on status code.
    ///
    /// - 5xx errors are logged as errors
    /// - 4xx errors are logged as warnings
    /// - Other errors are logged as warnings
    fn log_error(&self) {
        match self.status.as_u16() {
            status @ 500..=599 => {
                error!(
                  status,
                  error = ?self.internal,
                  "Internal server error."
                );
            }
            status @ 400..=499 => {
                warn!(
                  status,
                  error = ?self.internal,
                  "Client error."
                );
            }
            status => {
                warn!(
                  status,
                  error = ?self.internal,
                  "Unhandled error."
                );
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        self.log_error();

        let message = self.user_message.unwrap_or_else(|| {
            match self.status {
                StatusCode::BAD_REQUEST => "Invalid request. Please check your input and try again.",
                StatusCode::UNAUTHORIZED => "You need to log in to access this resource.",
                StatusCode::FORBIDDEN => "You don't have permission to access this resource.",
                StatusCode::NOT_FOUND => "The requested resource was not found.",
                StatusCode::SERVICE_UNAVAILABLE => "The service is temporarily unavailable. Please try again later.",
                _ => "An error occurred while processing your request.",
            }
            .to_string()
        });

        let template = ErrorTemplate {
            title: "Error",
            message,
            status_code: self.status.as_u16(),
        };

        let headers = [("hx-retarget", "#error-container"), ("hx-reswap", "innerHTML")];

        (self.status, headers, HtmlTemplate(template)).into_response()
    }
}

/// Template for rendering error pages or page sections.
#[derive(Template)]
#[template(path = "partials/error.html")]
struct ErrorTemplate<'a> {
    title: &'a str,
    message: String,
    status_code: u16,
}

/// Template for inline error messages in forms.
///
/// Used with HTMX to display field-specific validation errors.
#[derive(Template)]
#[template(path = "partials/error_inline.html")]
pub struct InlineErrorTemplate<'a> {
    pub field: &'a str,
    pub message: &'a str,
}

impl IntoResponse for InlineErrorTemplate<'_> {
    fn into_response(self) -> axum::response::Response {
        let headers = [
            ("hx-retarget", format!("#error-{}", self.field)),
            ("hx-reswap", "innerHTML".to_string()),
        ];

        (StatusCode::BAD_REQUEST, headers, HtmlTemplate(self)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        let status = match &err {
            sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Self {
            status,
            internal: err.into(),
            user_message: None,
        }
    }
}

impl From<password_hash::Error> for AppError {
    fn from(value: password_hash::Error) -> Self {
        match value {
            password_hash::Error::Password => AppError::bad_login(anyhow!("Password hashes do not match.")),
            e => AppError::internal(anyhow!("Password verification error: {e}")),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        AppError::with_status(error, StatusCode::INTERNAL_SERVER_ERROR)
    }
}
