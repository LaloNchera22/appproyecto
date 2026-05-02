// backend/src/config.rs
use std::env;

pub struct AppConfig {
    pub database_path: String,
    pub socket_path: String,
    pub monero_rpc_url: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            database_path: env::var("DATABASE_PATH").unwrap_or_else(|_| "./data/ledger".into()),
            socket_path: env::var("SOCKET_PATH").unwrap_or_else(|_| "/tmp/app/engine.sock".into()),
            monero_rpc_url: env::var("MONERO_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18083/json_rpc".into()),
        }
    }
}
