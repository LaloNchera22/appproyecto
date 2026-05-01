// backend/src/main.rs
mod api;
mod crypto;
mod db;
mod engine;
mod models;
mod services;

use axum::{routing::get, Router};
use hyper_util::rt::TokioIo;
use std::{env, sync::Arc, time::Duration};
use tokio::net::UnixListener;
use tower::Service;
use tower_http::timeout::TimeoutLayer;

/// Shared application state injected into every request handler via Axum's
/// `State` extractor.  Wrapped in `Arc` so it can be cheaply cloned across
/// async tasks without copying the underlying resources.
pub struct AppState {
    pub ledger: Arc<db::Ledger>,
    pub crypto: crypto::CryptoService,
    pub escrow: services::EscrowService,
    /// Static bearer token for the admin API.  Loaded from `ADMIN_TOKEN` at
    /// startup; never logged, never returned in any HTTP response.
    pub admin_token: String,
}

async fn health() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() {
    let db_path = env::var("DATABASE_PATH")
        .unwrap_or_else(|_| "./data/ledger".to_string());
    let socket_path = env::var("SOCKET_PATH")
        .unwrap_or_else(|_| "/tmp/app/engine.sock".to_string());
    let rpc_url = env::var("MONERO_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18083/json_rpc".to_string());

    // Fail-secure: refuse to start without a strong admin bearer token.
    // The minimum length (32 chars) defends against accidental
    // misconfiguration with a short, brute-forceable secret.
    let admin_token = env::var("ADMIN_TOKEN")
        .unwrap_or_else(|_| panic!("FATAL: ADMIN_TOKEN environment variable is not set"));
    if admin_token.len() < 32 {
        panic!("FATAL: ADMIN_TOKEN must be at least 32 characters long");
    }

    let ledger = Arc::new(db::Ledger::new(&db_path));
    let escrow = services::EscrowService::new(Arc::clone(&ledger));

    // Two independent CryptoService instances share the same wallet RPC
    // endpoint; each owns its own reqwest::Client (Arc-backed, cheap to clone).
    let crypto_scanner = crypto::CryptoService::new(rpc_url.clone())
        .unwrap_or_else(|e| panic!("FATAL: cannot initialise scanner CryptoService: {}", e));
    let crypto = crypto::CryptoService::new(rpc_url)
        .unwrap_or_else(|e| panic!("FATAL: cannot initialise CryptoService: {}", e));

    // Spawn the blockchain scanner as an independent background Tokio task.
    // It runs on the same runtime as Axum but never blocks the web server —
    // slow or failed RPC calls only affect the scanner's own polling cycle.
    let scanner = services::BlockchainScanner::new(Arc::clone(&ledger), crypto_scanner);
    tokio::spawn(scanner.start_polling());

    let state = Arc::new(AppState {
        ledger,
        crypto,
        escrow,
        admin_token,
    });

    // Remove stale socket file before binding (fail-secure: no ghost sockets).
    if std::path::Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path).unwrap_or_else(|e| {
            panic!("FATAL: cannot remove stale socket '{}': {}", socket_path, e)
        });
    }

    let app = Router::new()
        .route("/api/health", get(health))
        .merge(api::user_routes::user_router())
        .merge(api::admin_routes::admin_router())
        .with_state(state)
        .layer(TimeoutLayer::new(Duration::from_secs(10)));

    let listener = UnixListener::bind(&socket_path)
        .unwrap_or_else(|e| panic!("FATAL: cannot bind UDS at '{}': {}", socket_path, e));

    println!("Engine listening on unix:{}", socket_path);

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("FATAL: accept error: {}", e));

        let app = app.clone();

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                app.clone().call(req.map(axum::body::Body::new))
            });

            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await
                .unwrap_or_else(|e| eprintln!("connection error: {e}"));
        });
    }
}
