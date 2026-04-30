// backend/src/api/mod.rs
use axum::{routing::post, Json, Router, extract::State};
use std::sync::Arc;
use crate::AppState;
use crate::models::{BetEntry, BetGroup};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BetRequest {
    pub tournament_id: String,
    pub group: BetGroup,
    pub amount: u64,
}

pub fn bet_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/request-address", post(handle_address_request))
}

async fn handle_address_request(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<BetRequest>,
) -> Json<serde_json::Value> {
    // 1. Calculate the 1% fee using the CryptoService
    let (net_amount, fee) = state.crypto.calculate_entry_fee(payload.amount);
    
    // 2. Generate a unique Monero subaddress
    let address = state.crypto.generate_bet_address(&payload.tournament_id).await.unwrap_or_default();

    // 3. Log the intent in the Ledger (Zero-Trust: record before payment)
    println!("Audit: Bet initialized for {} - Net: {} piconeros, Fee: {} piconeros", 
             payload.tournament_id, net_amount, fee);

    Json(serde_json::Value::Object(serde_json::from_str(&format!(
        "{{\"address\": \"{}\", \"net\": {}}}", address, net_amount
    )).unwrap()))
}
