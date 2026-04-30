// backend/src/db/mod.rs
use rocksdb::{DB, Options};
use crate::models::Tournament;
use serde_json;

pub struct Ledger {
    db: DB,
}

impl Ledger {
    pub fn new(path: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        // Optimize for local persistent storage on Pop!_OS
        let db = DB::open(&opts, path).expect("Critical: RocksDB failed to initialize");
        Ledger { db }
    }

    pub fn get_tournament(&self, id: &str) -> Result<Tournament, String> {
        match self.db.get(id).map_err(|e| e.to_string())? {
            Some(data) => serde_json::from_slice(&data).map_err(|e| e.to_string()),
            None => Err("Tournament not found".into()),
        }
    }

    pub fn update_tournament(&self, id: &str, tournament: &Tournament) -> Result<(), String> {
        let serialized = serde_json::to_vec(tournament).map_err(|e| e.to_string())?;
        self.db.put(id, serialized).map_err(|e| e.to_string())?;
        Ok(())
    }
}
