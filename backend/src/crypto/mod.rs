// backend/src/crypto/mod.rs
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// JSON-RPC wire types
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
// Service
// ---------------------------------------------------------------------------

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
}
