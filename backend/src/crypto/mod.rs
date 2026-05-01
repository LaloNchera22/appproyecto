// backend/src/crypto/mod.rs
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// JSON-RPC wire types — create_address
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: CreateAddressParams<'a>,
}

#[derive(Serialize)]
struct CreateAddressParams<'a> {
    account_index: u32,
    label: &'a str,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<CreateAddressResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct CreateAddressResult {
    address: String,
}

// Consumed only to detect the error path; fields are intentionally ignored so
// that raw node error messages never propagate to the caller.
#[derive(Deserialize)]
struct RpcError {
    #[allow(dead_code)]
    code: i64,
}

// ---------------------------------------------------------------------------
// JSON-RPC wire types — get_transfers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct GetTransfersRpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: GetTransfersParams,
}

#[derive(Serialize)]
struct GetTransfersParams {
    // `in` is a Rust keyword; renamed on the wire.
    #[serde(rename = "in")]
    incoming: bool,
    pool: bool,
    account_index: u32,
}

#[derive(Deserialize)]
struct GetTransfersRpcResponse {
    result: Option<GetTransfersResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct GetTransfersResult {
    #[serde(rename = "in", default)]
    incoming: Vec<TransferEntry>,
    #[serde(default)]
    pool: Vec<TransferEntry>,
}

/// A single transfer record returned by the Monero Wallet RPC.
/// Used by `BlockchainScanner` to detect and credit confirmed deposits.
#[derive(Deserialize, Clone, Debug)]
pub struct TransferEntry {
    pub address: String,
    pub amount: u64,
    pub confirmations: u64,
    pub double_spend_seen: bool,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// `Clone` is cheap — `reqwest::Client` is `Arc`-backed internally.
#[derive(Clone)]
pub struct CryptoService {
    rpc_url: String,
    http_client: Client,
}

impl CryptoService {
    /// Build a service bound to the given Monero Wallet RPC endpoint.
    ///
    /// The client is configured with a 5-second total timeout so the backend
    /// cannot hang indefinitely if the local wallet daemon is unresponsive.
    pub fn new(rpc_url: String) -> Result<Self, String> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            // Disable clearnet redirects; the wallet RPC is local-only.
            .redirect(reqwest::redirect::Policy::none())
            // Reject any response that is obviously too large to be a valid
            // JSON-RPC reply from a wallet daemon (guards against memory bombs).
            .connection_verbose(false)
            .build()
            .map_err(|_| "Payment gateway configuration error".to_string())?;

        Ok(Self {
            rpc_url,
            http_client,
        })
    }

    /// Request a fresh subaddress from the local Monero Wallet RPC.
    ///
    /// `event_label` (e.g. a tournament ID) is stored as the address label in
    /// the wallet's own ledger so incoming payments can be reconciled without
    /// an external database scan.
    ///
    /// # Zero-Trust error contract
    /// On **any** failure — network, timeout, malformed payload, or a wallet
    /// daemon error code — this method returns the generic sentinel string
    /// `"Payment gateway temporarily unavailable"`.  The internal cause is
    /// logged to stderr (visible only in server logs) and is **never** included
    /// in the returned `Err` value, preventing information leakage to callers.
    pub async fn generate_subaddress(&self, event_label: &str) -> Result<String, String> {
        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: "0",
            method: "create_address",
            params: CreateAddressParams {
                account_index: 0,
                label: event_label,
            },
        };

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                // Log internally; do NOT surface URL or raw error to caller.
                eprintln!("[crypto] RPC transport error: {e}");
                "Payment gateway temporarily unavailable".to_string()
            })?;

        // Treat any non-2xx status as an opaque failure.
        if !response.status().is_success() {
            eprintln!("[crypto] RPC returned HTTP {}", response.status());
            return Err("Payment gateway temporarily unavailable".to_string());
        }

        let rpc_response: RpcResponse = response.json().await.map_err(|e| {
            eprintln!("[crypto] RPC response deserialization error: {e}");
            "Payment gateway temporarily unavailable".to_string()
        })?;

        // An explicit JSON-RPC error object from the daemon is still an error.
        if rpc_response.error.is_some() {
            eprintln!("[crypto] RPC daemon returned an error object");
            return Err("Payment gateway temporarily unavailable".to_string());
        }

        match rpc_response.result {
            Some(r) if !r.address.is_empty() => Ok(r.address),
            _ => {
                eprintln!("[crypto] RPC result missing or contained empty address");
                Err("Payment gateway temporarily unavailable".to_string())
            }
        }
    }

    /// Pull all incoming (`in`) and unconfirmed (`pool`) transfers from the
    /// local Monero Wallet RPC.
    ///
    /// This is a strict PULL operation — the engine initiates every request.
    /// The existing 5-second HTTP timeout enforced by the client applies here,
    /// so a non-responsive node cannot stall the scanner indefinitely.
    ///
    /// Returns the combined list; callers filter by confirmation depth.
    /// On any failure the generic sentinel is returned (no internal detail leak).
    pub async fn get_transfers(&self) -> Result<Vec<TransferEntry>, String> {
        let payload = GetTransfersRpcRequest {
            jsonrpc: "2.0",
            id: "0",
            method: "get_transfers",
            params: GetTransfersParams {
                incoming: true,
                pool: true,
                account_index: 0,
            },
        };

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                eprintln!("[crypto] get_transfers transport error: {e}");
                "Payment gateway temporarily unavailable".to_string()
            })?;

        if !response.status().is_success() {
            eprintln!("[crypto] get_transfers HTTP {}", response.status());
            return Err("Payment gateway temporarily unavailable".to_string());
        }

        let rpc_response: GetTransfersRpcResponse = response.json().await.map_err(|e| {
            eprintln!("[crypto] get_transfers deserialization error: {e}");
            "Payment gateway temporarily unavailable".to_string()
        })?;

        if rpc_response.error.is_some() {
            eprintln!("[crypto] get_transfers RPC daemon returned an error object");
            return Err("Payment gateway temporarily unavailable".to_string());
        }

        match rpc_response.result {
            Some(r) => {
                let mut transfers = r.incoming;
                transfers.extend(r.pool);
                Ok(transfers)
            }
            None => Ok(Vec::new()),
        }
    }
}
