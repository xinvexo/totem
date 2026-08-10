mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod static_files;
mod totp;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use auth::LoginLimiter;
use config::Config;
use crypto::Crypto;

pub struct AppState {
    pub db: Mutex<Connection>,
    pub crypto: Crypto,
    pub events: broadcast::Sender<()>,
    pub config: Config,
    pub login_limiter: Mutex<LoginLimiter>,
}

fn now_seconds() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Support both `./totem` from the deployment directory and `cargo run`
    // from backend/ while keeping the canonical development .env at repo root.
    dotenvy::dotenv().ok();
    dotenvy::from_filename("../.env").ok();
    init_tracing();

    if std::env::args().nth(1).as_deref() == Some("reset-password") {
        return reset_password_command();
    }

    let config = Config::from_env()?;
    let initial_password = std::env::var("ADMIN_PASSWORD").ok();
    let connection = db::open(&config.database_path)?;
    auth::ensure_admin(&connection, initial_password.as_deref())?;

    let (events, _) = broadcast::channel(64);
    let state = Arc::new(AppState {
        db: Mutex::new(connection),
        crypto: Crypto::new(config.master_key),
        events,
        config: config.clone(),
        login_limiter: Mutex::new(LoginLimiter::default()),
    });
    tokio::spawn(api::scheduler(state.clone()));

    let app = api::app(state);
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;
    info!(address = %config.bind_addr, "Totem is listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server stopped unexpectedly")?;
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn reset_password_command() -> Result<()> {
    let path = Config::database_path_from_env();
    let connection = db::open(&path)?;
    let password = rpassword::prompt_password("New admin password: ")?;
    if password.is_empty() {
        anyhow::bail!("password cannot be empty");
    }
    let confirmation = rpassword::prompt_password("Confirm new admin password: ")?;
    if password != confirmation {
        anyhow::bail!("passwords do not match");
    }
    auth::reset_admin_password(&connection, &password)?;
    println!("Administrator password updated.");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
