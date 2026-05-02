// backend/src/crypto/mod.rs
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Hard ceilings
// ---------------------------------------------------------------------------

/// Maximum body size accepted from the wallet RPC.  A legitimate
/// `get_transfers` reply is well under this; anything larger is rejected
/// before deserialisation to defuse RPC memory bombs (Finding #4).
const MAX_RPC_BODY_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

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
// JSON-RPC wire types — get_balance
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct GetBalanceRpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: GetBalanceParams,
}

#[derive(Serialize)]
struct GetBalanceParams {
    account_index: u32,
}

#[derive(Deserialize)]
struct GetBalanceRpcResponse {
    result: Option<GetBalanceResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct GetBalanceResult {
    /// Total piconeros currently spendable (excludes locked / unconfirmed).
    /// Exposed by the Monero Wallet RPC as `unlocked_balance`.
    unlocked_balance: u64,
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
    /// Body-size capping is enforced separately by `read_capped_json` to guard
    /// against memory-bomb responses (Finding #4) — `reqwest` itself does not
    /// expose a payload-size cap on `Client`.
    pub fn new(rpc_url: String) -> Result<Self, String> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            // Disable clearnet redirects; the wallet RPC is local-only.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "Payment gateway configuration error".to_string())?;

        Ok(Self {
            rpc_url,
            http_client,
        })
    }

    /// Stream a JSON-RPC response body into a bounded buffer and deserialize
    /// it.  Aborts with a generic sentinel error if the body grows past
    /// `MAX_RPC_BODY_BYTES`, defusing memory-bomb attacks from a compromised
    /// wallet daemon (Finding #4).
    async fn read_capped_json<T>(mut response: Response) -> Result<T, String>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len().saturating_add(chunk.len()) > MAX_RPC_BODY_BYTES {
                        eprintln!(
                            "[crypto] RPC body exceeded {} bytes — aborting",
                            MAX_RPC_BODY_BYTES
                        );
                        return Err("Payment gateway temporarily unavailable".to_string());
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!("[crypto] body read error: {e}");
                    return Err("Payment gateway temporarily unavailable".to_string());
                }
            }
        }
        serde_json::from_slice::<T>(&buf).map_err(|e| {
            eprintln!("[crypto] JSON parse error: {e}");
            "Payment gateway temporarily unavailable".to_string()
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

        let rpc_response: RpcResponse = Self::read_capped_json(response).await?;

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
    /// so a non-responsive node cannot stall the scanner indefinitely.  The
    /// response is read via `read_capped_json` so a malicious daemon cannot
    /// stream a multi-GB body to exhaust the engine's heap (Finding #4).
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

        let rpc_response: GetTransfersRpcResponse = Self::read_capped_json(response).await?;

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

    /// Probe the wallet's currently-unlocked balance (account 0) in
    /// piconeros.  Used by the escrow service to refuse settlement when the
    /// declared payout map exceeds the wallet's actual XMR holdings — the
    /// last line of defence against a compromised RPC inflating pool totals
    /// (Finding #5b).
    ///
    /// Same Zero-Trust error contract as the other RPC methods: every
    /// internal cause is logged to stderr and collapsed into the same
    /// opaque sentinel string before returning to the caller.
    pub async fn get_unlocked_balance(&self) -> Result<u64, String> {
        let payload = GetBalanceRpcRequest {
            jsonrpc: "2.0",
            id: "0",
            method: "get_balance",
            params: GetBalanceParams { account_index: 0 },
        };

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                eprintln!("[crypto] get_balance transport error: {e}");
                "Payment gateway temporarily unavailable".to_string()
            })?;

        if !response.status().is_success() {
            eprintln!("[crypto] get_balance HTTP {}", response.status());
            return Err("Payment gateway temporarily unavailable".to_string());
        }

        let rpc_response: GetBalanceRpcResponse = Self::read_capped_json(response).await?;

        if rpc_response.error.is_some() {
            eprintln!("[crypto] get_balance RPC daemon returned an error object");
            return Err("Payment gateway temporarily unavailable".to_string());
        }

        match rpc_response.result {
            Some(r) => Ok(r.unlocked_balance),
            None => {
                eprintln!("[crypto] get_balance result missing");
                Err("Payment gateway temporarily unavailable".to_string())
            }
        }
    }
}
