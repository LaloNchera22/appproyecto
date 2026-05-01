// backend/src/db/mod.rs
use std::collections::HashMap;

use rocksdb::{Direction, IteratorMode, Options, WriteBatch, DB};
use serde_json;

use crate::models::{Event, EventStatus, Tournament};

// ---------------------------------------------------------------------------
// Key-space prefixes — all RocksDB keys are namespaced to avoid collisions.
// ---------------------------------------------------------------------------
const PREFIX_EVENT:   &str = "event:";
const PREFIX_PAYOUTS: &str = "payouts:";
const PREFIX_TOURNEY: &str = "tournament:";
/// Written by the scanner once a deposit has been credited; prevents
/// double-processing across polling intervals.
const PREFIX_FUNDED:  &str = "funded:";

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

    /// Scans the ledger and returns all events whose status is `Open`.
    ///
    /// Uses a forward key-range scan from the `"event:"` prefix boundary so
    /// only event records are read; other key families are never touched.
    /// Any record that fails to deserialize is silently skipped rather than
    /// aborting the entire scan.
    pub fn get_open_events(&self) -> Vec<Event> {
        let prefix = PREFIX_EVENT.as_bytes();
        self.db
            .iterator(IteratorMode::From(prefix, Direction::Forward))
            .take_while(|item| {
                item.as_ref()
                    .map(|(k, _)| k.starts_with(prefix))
                    .unwrap_or(false)
            })
            .filter_map(|item| {
                item.ok()
                    .and_then(|(_, v)| serde_json::from_slice::<Event>(&v).ok())
            })
            .filter(|e| e.status == EventStatus::Open)
            .collect()
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

    // -----------------------------------------------------------------------
    // Deposit / scanner API
    // -----------------------------------------------------------------------

    /// Register a freshly generated deposit subaddress against an event option.
    ///
    /// Inserts `subaddress -> 0` into `event.option_pools[option]`, marking the
    /// address as "pending deposit".  The scanner will later call
    /// `record_deposit_atomic` to credit the actual net amount.
    pub fn register_subaddress(
        &self,
        event_id: &str,
        option: u8,
        subaddress: &str,
    ) -> Result<(), String> {
        let mut event = self.get_event(event_id)?;
        event
            .option_pools
            .entry(option)
            .or_default()
            .entry(subaddress.to_string())
            .or_insert(0);
        self.put_event(&event)
    }

    /// Returns `true` if this subaddress has already been credited by the
    /// scanner.  Errors from RocksDB are treated conservatively as `false`
    /// (the scanner's atomic write has its own re-entrancy guard).
    pub fn is_subaddress_funded(&self, subaddress: &str) -> bool {
        let key = format!("{}{}", PREFIX_FUNDED, subaddress);
        self.db.get(key.as_bytes()).unwrap_or(None).is_some()
    }

    /// Atomically credit `net_amount` piconeros to an event option pool and
    /// mark the subaddress as funded so it is never scanned again.
    ///
    /// A single `WriteBatch` guarantees that either both the updated event
    /// record and the funded marker land on disk, or neither does.  The funded
    /// marker is checked first for idempotency — if already present the call
    /// returns `Ok(())` without writing anything.
    pub fn record_deposit_atomic(
        &self,
        event_id: &str,
        option: u8,
        subaddress: &str,
        net_amount: u64,
    ) -> Result<(), String> {
        // Idempotency: a previous iteration may have already processed this.
        if self.is_subaddress_funded(subaddress) {
            return Ok(());
        }

        let mut event = self.get_event(event_id)?;

        // Update per-subaddress contribution.
        event
            .option_pools
            .entry(option)
            .or_default()
            .insert(subaddress.to_string(), net_amount);

        // Update running pool total; overflow on a u64 piconero total would
        // require ~18 million XMR in a single pool — guard it anyway.
        let total = event.pool_totals.entry(option).or_insert(0);
        *total = total
            .checked_add(net_amount)
            .ok_or_else(|| format!("pool total overflow for event '{}'", event_id))?;

        let event_key  = format!("{}{}", PREFIX_EVENT,  event_id);
        let funded_key = format!("{}{}", PREFIX_FUNDED, subaddress);
        let event_bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?;

        let mut batch = WriteBatch::default();
        batch.put(event_key.as_bytes(),  &event_bytes);
        batch.put(funded_key.as_bytes(), b"1");

        self.db.write(batch).map_err(|e| e.to_string())
    }
}
