// backend/src/main.rs
//
// Runtime entry point.  All engine code lives in the `sicbox` library crate
// (see `lib.rs`); this file is purely the Tokio bootstrap and the UDS accept
// loop, kept minimal so integration tests under `tests/` can exercise the
// same code paths via the library target.

use axum::{routing::get, Router};
use hyper_util::rt::TokioIo;
use sicbox::{api, crypto, db, services, AppState};
use std::{env, sync::Arc, time::Duration};
use tokio::net::UnixListener;
use tower::Service;
use tower_http::timeout::TimeoutLayer;

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
    let admin_token = env::var("ADMIN_TOKEN").unwrap_or_else(|_| {
        eprintln!("[main] ADMIN_TOKEN environment variable is not set");
        panic!("FATAL: missing required configuration");
    });
    if admin_token.len() < 32 {
        eprintln!("[main] ADMIN_TOKEN length below required minimum");
        panic!("FATAL: invalid admin configuration");
    }

    let ledger = Arc::new(db::Ledger::new(&db_path));

    // Three independent CryptoService instances share the same wallet RPC
    // endpoint; each owns its own reqwest::Client (Arc-backed, cheap to clone).
    let crypto_scanner = crypto::CryptoService::new(rpc_url.clone()).unwrap_or_else(|e| {
        eprintln!("[main] scanner CryptoService init error: {}", e);
        panic!("FATAL: cannot initialise scanner crypto component");
    });
    let crypto_escrow = crypto::CryptoService::new(rpc_url.clone()).unwrap_or_else(|e| {
        eprintln!("[main] escrow CryptoService init error: {}", e);
        panic!("FATAL: cannot initialise escrow crypto component");
    });
    let crypto = crypto::CryptoService::new(rpc_url).unwrap_or_else(|e| {
        eprintln!("[main] CryptoService init error: {}", e);
        panic!("FATAL: cannot initialise crypto component");
    });

    let escrow = services::EscrowService::new(Arc::clone(&ledger), crypto_escrow);

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
            eprintln!("[main] cannot remove stale socket {}: {}", socket_path, e);
            panic!("FATAL: stale socket cleanup failed");
        });
    }

    let app = Router::new()
        .route("/api/health", get(health))
        .merge(api::user_routes::user_router())
        .merge(api::admin_routes::admin_router())
        .with_state(state)
        .layer(TimeoutLayer::new(Duration::from_secs(10)));

    let listener = UnixListener::bind(&socket_path).unwrap_or_else(|e| {
        eprintln!("[main] UDS bind error at {}: {}", socket_path, e);
        panic!("FATAL: cannot bind UDS");
    });

    println!("Engine listening on unix:{}", socket_path);

    loop {
        // Transient `accept` errors (EMFILE — too many open files,
        // ECONNABORTED, kernel resource pressure) MUST NOT crash the engine.
        // Log them and back off so the loop does not spin tightly on EMFILE.
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[main] accept error (continuing): {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        let app = app.clone();

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                app.clone().call(req.map(axum::body::Body::new))
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                eprintln!("[main] connection error: {e}");
            }
        });
    }
}
