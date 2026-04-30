// backend/src/crypto/scanner.rs
use crate::db::Ledger;
use crate::models::TournamentStatus;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct BlockchainScanner {
    ledger: Arc<Ledger>,
}

impl BlockchainScanner {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    /// Background task to monitor Monero transactions.
    /// Professional Rule: Verify against local node only.
    pub async fn run_monitor(&self) {
        println!("🔍 Blockchain Scanner: Monitoring local XMR node...");
        loop {
            // Logic to poll monerod RPC for new transactions in our subaddresses
            // If a payment is found, update the tournament pool in the Ledger
            sleep(Duration::from_secs(20)).await;
        }
    }
}
