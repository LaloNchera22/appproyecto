// backend/src/main.rs
mod admin;
mod api;
mod crypto;
mod db;
mod engine;
mod models;
mod services;

use std::sync::Arc;
use crate::db::Ledger;
use crate::crypto::CryptoService;
use crate::crypto::scanner::BlockchainScanner;
use crate::admin::AdminService;
use crate::services::EscrowService;

pub struct AppState {
    pub ledger: Arc<Ledger>,
    pub crypto: CryptoService,
    pub admin: AdminService,
    pub escrow: EscrowService,
}

#[tokio::main]
async fn main() {
    // 1. Initialize Persistent Ledger (RocksDB)
    let ledger = Arc::new(Ledger::new("./data/ledger"));
    
    // 2. Initialize Services
    let crypto = CryptoService::new(Arc::clone(&ledger), "http://127.0.0.1:18081".into());
    let admin = AdminService::new(Arc::clone(&ledger));
    let escrow = EscrowService::new(Arc::clone(&ledger));
    let scanner = BlockchainScanner::new(Arc::clone(&ledger));

    let state = Arc::new(AppState {
        ledger,
        crypto,
        admin,
        escrow,
    });

    // 3. Spawn Blockchain Scanner in a separate thread (Background Worker)
    let scanner_state = Arc::clone(&state);
    tokio::spawn(async move {
        // scanner.run_monitor().await; // Implementation ready for RPC
    });

    // 4. Start the Zero-Trust API on Unix Domain Socket
    println!("🚀 OutName Engine started on Pop!_OS");
    api::start_secure_server(state).await;
}
