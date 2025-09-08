//! HTTP routing configuration and server setup.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    handler::Handler,
    middleware::from_fn_with_state,
    routing::{get, post},
};
use tokio::time;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{classify::StatusInRangeAsFailures, compression::CompressionLayer, services::ServeDir, trace::TraceLayer};
use tracing::info;

use crate::{
    AppState,
    handler::{
        auth_handler::{login_page_handler, login_user_handler, logout_handler},
        handle_404, home_handler,
        middlewares::auth_user_middleware,
    },
};

/// Starts the HTTP server with the configured routes and middleware.
///
/// This function:
/// 1. Initializes the tracing subscriber for logging
/// 2. Creates the router with all routes and middleware
/// 3. Binds to port 8888 and starts serving requests
///
/// # Errors
///
/// Returns an error if the server fails to bind to the port or encounters
/// a fatal error during operation.
pub(crate) async fn serve(app_state: Arc<AppState>) -> Result<()> {
    init_tracing()?;

    let app = create_router(app_state)?;

    let port = 8888;

    let address = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Could not bind to TCP listener port");

    axum::serve(address, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

fn create_router(app_state: Arc<AppState>) -> Result<Router> {
    let assets_path = std::env::current_dir()?;

    let login_conf = Arc::new(GovernorConfigBuilder::default().per_second(1).burst_size(3).finish().unwrap());
    let login_limiter = login_conf.limiter().clone();

    let general_conf = Arc::new(GovernorConfigBuilder::default().per_second(2).burst_size(500).finish().unwrap());
    let general_limiter = general_conf.limiter().clone();

    // Start cleanup tasks for both rate limiters
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let login_len = login_limiter.len();
            let general_len = general_limiter.len();
            info!(login_len, general_len, "Login rate limiter cleanup");
            login_limiter.retain_recent();
            general_limiter.retain_recent();
        }
    });

    let login_handler = login_user_handler.layer(GovernorLayer::new(login_conf));

    let route = Router::new()
        .route("/", get(home_handler))
        .layer(from_fn_with_state(app_state.clone(), auth_user_middleware))
        .route("/login", get(login_page_handler).post(login_handler))
        .route("/logout", post(logout_handler));
    let route = if cfg!(debug_assertions) {
        route.route("/sse-reload", get(dev_mode::sse_reload))
    } else {
        route
    };
    let route = route
        .nest_service("/assets", ServeDir::new(format!("{}/assets", assets_path.to_str().unwrap())))
        .fallback(handle_404)
        .with_state(app_state)
        .layer(GovernorLayer::new(general_conf)) // Apply general rate limiting to all routes
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new(StatusInRangeAsFailures::new(400..=599).into_make_classifier()));

    Ok(route)
}

#[cfg(debug_assertions)]
mod dev_mode {
    use std::convert::Infallible;

    use axum::response::{Sse, sse::Event};
    use futures::{Stream, stream};
    use tokio_stream::StreamExt as _;

    /// Server-sent events endpoint for development hot reload.
    ///
    /// Sends heartbeat events every second to keep the connection alive
    /// and allow the client to detect when the server restarts.
    pub async fn sse_reload() -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
        let stream = stream::repeat_with(|| Ok(Event::default().data("heartbeat"))).throttle(std::time::Duration::from_secs(1));
        Sse::new(stream)
    }
}

fn init_tracing() -> anyhow::Result<()> {
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::{EnvFilter, Layer as _, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};

    let app_name = env!("CARGO_CRATE_NAME");

    // Treat external crates differently because we almost never care about line numbers and internal module names there.
    // By default, show tower_http at debug, other external crates at warn, and nothing from ours for this formatter,
    // but, still respect RUST_LOG env var (tho still filter out ours there, too).
    let default_external_filter = "warn,tower_http=debug".into();
    let external_filter = EnvFilter::try_from_default_env()
        .unwrap_or(default_external_filter)
        .add_directive(format!("{app_name}=off").parse()?);
    let external_crates_layer = fmt::layer()
        .pretty()
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .with_filter(external_filter);

    // Now, config for just our logs, where we probably care about things like files & line numbers
    let our_app_only_filter = EnvFilter::builder()
        .from_env_lossy()
        .add_directive(LevelFilter::OFF.into())
        .add_directive(format!("{app_name}=debug").parse()?);
    let our_app_layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_filter(our_app_only_filter);

    tracing_subscriber::registry()
        .with(external_crates_layer)
        .with(our_app_layer)
        .init();

    Ok(())
}
