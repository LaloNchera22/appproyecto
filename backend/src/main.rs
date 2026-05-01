mod crypto;
mod db;

use axum::{routing::get, Router};
use hyper_util::rt::TokioIo;
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

    let _ledger = Arc::new(db::Ledger::new(&db_path));

    // Remove stale socket file before binding (fail-secure: no ghost sockets).
    if std::path::Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path).unwrap_or_else(|e| {
            panic!("FATAL: cannot remove stale socket '{}': {}", socket_path, e)
        });
    }

    let app = Router::new()
        .route("/api/health", get(health))
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
