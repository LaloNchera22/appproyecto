// backend/src/db/mod.rs
use std::collections::HashMap;

use rocksdb::{Options, WriteBatch, DB};
use serde_json;

use crate::models::{Event, EventStatus, Tournament};

// ---------------------------------------------------------------------------
// Key-space prefixes — all RocksDB keys are namespaced to avoid collisions.
// ---------------------------------------------------------------------------
const PREFIX_EVENT:   &str = "event:";
const PREFIX_PAYOUTS: &str = "payouts:";
const PREFIX_TOURNEY: &str = "tournament:";

pub struct Ledger {
    db: DB,
}

impl Ledger {
    /// Opens or creates the RocksDB ledger at `path`.
    /// Panics immediately (fail-secure) if the database cannot be opened.
    pub fn new(path: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)
            .unwrap_or_else(|e| panic!("FATAL: cannot open ledger at '{}': {}", path, e));
        Ledger { db }
    }

    // -----------------------------------------------------------------------
    // Event API (parimutuel engine)
    // -----------------------------------------------------------------------

    pub fn get_event(&self, id: &str) -> Result<Event, String> {
        let key = format!("{}{}", PREFIX_EVENT, id);
        match self.db.get(key.as_bytes()).map_err(|e| e.to_string())? {
            Some(data) => serde_json::from_slice(&data).map_err(|e| e.to_string()),
            None => Err(format!("event '{}' not found", id)),
        }
    }

    pub fn put_event(&self, event: &Event) -> Result<(), String> {
        let key = format!("{}{}", PREFIX_EVENT, event.id);
        let data = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        self.db.put(key.as_bytes(), &data).map_err(|e| e.to_string())
    }

    /// Atomically mark an event as `Settled` and persist the computed payout
    /// map in a single `WriteBatch`.
    ///
    /// RocksDB `WriteBatch` is applied atomically at the storage level: either
    /// both the updated event record and the payout map land on disk, or
    /// neither does.  The event is re-read inside this method to tighten the
    /// TOCTOU window between the caller's status check and the actual write.
    pub fn settle_event_atomic(
        &self,
        event_id: &str,
        winning_option: u8,
        payouts: &HashMap<String, u64>,
    ) -> Result<(), String> {
        // Re-read within the write path — second line of defence against races.
        let mut event = self.get_event(event_id)?;

        if event.status == EventStatus::Settled {
            return Err(format!(
                "double-spend prevention: event '{}' is already settled",
                event_id
            ));
        }

        event.status = EventStatus::Settled;
        event.winning_option = Some(winning_option);

        let event_key   = format!("{}{}", PREFIX_EVENT,   event_id);
        let payouts_key = format!("{}{}", PREFIX_PAYOUTS, event_id);

        let event_bytes   = serde_json::to_vec(&event)  .map_err(|e| e.to_string())?;
        let payouts_bytes = serde_json::to_vec(payouts) .map_err(|e| e.to_string())?;

        let mut batch = WriteBatch::default();
        batch.put(event_key.as_bytes(),   &event_bytes);
        batch.put(payouts_key.as_bytes(), &payouts_bytes);

        self.db.write(batch).map_err(|e| e.to_string())
    }

    /// Retrieve the previously computed payout map for a settled event.
    pub fn get_payouts(&self, event_id: &str) -> Result<HashMap<String, u64>, String> {
        let key = format!("{}{}", PREFIX_PAYOUTS, event_id);
        match self.db.get(key.as_bytes()).map_err(|e| e.to_string())? {
            Some(data) => serde_json::from_slice(&data).map_err(|e| e.to_string()),
            None => Err(format!("payouts for event '{}' not found", event_id)),
        }
    }

    // -----------------------------------------------------------------------
    // Legacy Tournament API — kept for admin service compatibility
    // -----------------------------------------------------------------------

    pub fn get_tournament(&self, id: &str) -> Result<Tournament, String> {
        let key = format!("{}{}", PREFIX_TOURNEY, id);
        match self.db.get(key.as_bytes()).map_err(|e| e.to_string())? {
            Some(data) => serde_json::from_slice(&data).map_err(|e| e.to_string()),
            None => Err(format!("tournament '{}' not found", id)),
        }
    }

    pub fn update_tournament(&self, id: &str, tournament: &Tournament) -> Result<(), String> {
        let key = format!("{}{}", PREFIX_TOURNEY, id);
        let data = serde_json::to_vec(tournament).map_err(|e| e.to_string())?;
        self.db.put(key.as_bytes(), &data).map_err(|e| e.to_string())
    }
}
