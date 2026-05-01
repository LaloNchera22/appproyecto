// backend/src/lib.rs
//
// Library entry point for the SicBox engine.
//
// `main.rs` is a thin runtime wrapper around this crate.  Re-exporting the
// engine's modules through a `[lib]` target also makes them reachable from
// integration tests under `tests/` (notably `tests/security_tests.rs`),
// without forcing those tests to duplicate the module source paths.

pub mod api;
pub mod crypto;
pub mod db;
pub mod engine;
pub mod models;
pub mod services;

use std::sync::Arc;

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
