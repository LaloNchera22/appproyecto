// backend/src/db/mod.rs
use std::collections::HashMap;

use rocksdb::{
    Direction, ErrorKind, IteratorMode, OptimisticTransactionDB, OptimisticTransactionOptions,
    Options, WriteOptions,
};
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

/// Optimistic-transaction retry budget for an event read-modify-write cycle.
/// After this many `Busy` aborts the caller is told the contention is
/// pathological rather than allowed to spin indefinitely.
const MAX_TXN_RETRIES: u32 = 5;

pub struct Ledger {
    db: OptimisticTransactionDB,
}

impl Ledger {
    /// Opens or creates the RocksDB ledger at `path`.
    /// Panics immediately (fail-secure) if the database cannot be opened.
    ///
    /// The panic payload is intentionally generic — operational detail
    /// (full path, raw RocksDB error) is logged to stderr but never embedded
    /// in the panic string itself, since panic payloads are propagated to
    /// supervisor logs and crash-reporter sinks where they may be observable
    /// by attackers chaining unrelated log-disclosure bugs.
    pub fn new(path: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = OptimisticTransactionDB::open(&opts, path).unwrap_or_else(|e| {
            eprintln!("[ledger] open failure at '{}': {}", path, e);
            panic!("FATAL: ledger initialisation failed");
        });
        Ledger { db }
    }

    // -----------------------------------------------------------------------
    // Internal: optimistic-transaction wrapper for event read-modify-write.
    //
    // Centralises the only path through which a stored Event may be mutated.
    // `get_for_update` registers the event key in the transaction's read set
    // so a concurrent committer touching the same key forces this transaction
    // to retry instead of overwriting (Findings #2, #6).
    // -----------------------------------------------------------------------
    fn mutate_event<F>(&self, event_id: &str, mut mutator: F) -> Result<(), String>
    where
        F: FnMut(&mut Event) -> Result<(), String>,
    {
        let key = format!("{}{}", PREFIX_EVENT, event_id);

        for _ in 0..MAX_TXN_RETRIES {
            let txn = self.db.transaction_opt(
                &WriteOptions::default(),
                &OptimisticTransactionOptions::default(),
            );
            let bytes = txn
                .get_for_update(key.as_bytes(), true)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("event '{}' not found", event_id))?;
            let mut event: Event = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            mutator(&mut event)?;
            let new_bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
            txn.put(key.as_bytes(), &new_bytes).map_err(|e| e.to_string())?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Busy => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("event mutation conflict: retry budget exhausted".into())
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
    /// map in a single optimistic transaction.
    ///
    /// The status flip and the payout map land in the same RocksDB transaction
    /// commit, so a crash mid-write cannot leave the ledger in a partially
    /// settled state. The transaction's read set includes the event key,
    /// causing concurrent committers to be forced into a retry rather than
    /// silently overwriting the settled status (Findings #2, #6).
    pub fn settle_event_atomic(
        &self,
        event_id: &str,
        winning_option: u8,
        payouts: &HashMap<String, u64>,
    ) -> Result<(), String> {
        let event_key   = format!("{}{}", PREFIX_EVENT,   event_id);
        let payouts_key = format!("{}{}", PREFIX_PAYOUTS, event_id);
        let payouts_bytes = serde_json::to_vec(payouts).map_err(|e| e.to_string())?;

        for _ in 0..MAX_TXN_RETRIES {
            let txn = self.db.transaction_opt(
                &WriteOptions::default(),
                &OptimisticTransactionOptions::default(),
            );
            let bytes = txn
                .get_for_update(event_key.as_bytes(), true)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("event '{}' not found", event_id))?;
            let mut event: Event = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;

            if event.status == EventStatus::Settled {
                return Err(format!(
                    "double-spend prevention: event '{}' is already settled",
                    event_id
                ));
            }

            event.status = EventStatus::Settled;
            event.winning_option = Some(winning_option);

            let event_bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
            txn.put(event_key.as_bytes(), &event_bytes).map_err(|e| e.to_string())?;
            txn.put(payouts_key.as_bytes(), &payouts_bytes).map_err(|e| e.to_string())?;

            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Busy => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("settlement conflict: retry budget exhausted".into())
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
    /// Inserts `subaddress -> 0` into `event.option_pools[option]`, marking
    /// the address as "pending deposit".  The scanner will later call
    /// `record_deposit_atomic` to credit the actual net amount.  Routed
    /// through `mutate_event` so a concurrent settlement or another
    /// participation cannot lose the new subaddress (Finding #6).
    pub fn register_subaddress(
        &self,
        event_id: &str,
        option: u8,
        subaddress: &str,
    ) -> Result<(), String> {
        self.mutate_event(event_id, |event| {
            // Refuse to attach new participants to a non-Open event.
            if event.status != EventStatus::Open {
                return Err(format!("event '{}' is not Open", event_id));
            }
            event
                .option_pools
                .entry(option)
                .or_default()
                .entry(subaddress.to_string())
                .or_insert(0);
            Ok(())
        })
    }

    /// Returns `Ok(true)` iff this subaddress has already been credited by the
    /// scanner.  RocksDB read failures are propagated as `Err` so the scanner
    /// can defer processing instead of treating a transient I/O error as
    /// "not yet credited" (Finding #3).
    pub fn is_subaddress_funded(&self, subaddress: &str) -> Result<bool, String> {
        let key = format!("{}{}", PREFIX_FUNDED, subaddress);
        self.db
            .get(key.as_bytes())
            .map(|v| v.is_some())
            .map_err(|e| e.to_string())
    }

    /// Atomically credit `net_amount` piconeros to an event option pool and
    /// mark the subaddress as funded so it is never scanned again.
    ///
    /// All writes (event update + funded marker) land in a single RocksDB
    /// optimistic transaction.  The transaction's read-set on the event key
    /// also serialises this writer against `register_subaddress` and
    /// `settle_event_atomic`, eliminating the read-modify-write race that
    /// could otherwise revert a settled event to `Open` or apply a deposit to
    /// an already-settled pool (Findings #2, #6).
    ///
    /// Pool-total updates use a *delta* (`net_amount - previous_value`) rather
    /// than blind addition, so a re-credit of the same address is a no-op
    /// even if the funded marker check was bypassed by a transient read
    /// failure (Findings #3, #7).
    pub fn record_deposit_atomic(
        &self,
        event_id: &str,
        option: u8,
        subaddress: &str,
        net_amount: u64,
    ) -> Result<(), String> {
        // Fast-path idempotency check.  A propagated `Err` here means we
        // could not authoritatively determine whether this subaddress was
        // already credited — the caller (scanner) is expected to skip and
        // retry on the next polling tick.
        if self.is_subaddress_funded(subaddress)? {
            return Ok(());
        }

        let event_key  = format!("{}{}", PREFIX_EVENT,  event_id);
        let funded_key = format!("{}{}", PREFIX_FUNDED, subaddress);

        for _ in 0..MAX_TXN_RETRIES {
            let txn = self.db.transaction_opt(
                &WriteOptions::default(),
                &OptimisticTransactionOptions::default(),
            );
            let bytes = txn
                .get_for_update(event_key.as_bytes(), true)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("event '{}' not found", event_id))?;
            let mut event: Event = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;

            // Hard guard: refuse to credit a non-Open event.  This closes the
            // race in which the scanner reads an event before settlement and
            // tries to credit a deposit after the operator settled it.
            if event.status != EventStatus::Open {
                return Err(format!(
                    "event '{}' is not Open (status={:?}); deposit dropped",
                    event_id, event.status
                ));
            }

            // Update per-subaddress contribution and compute the delta against
            // the previous value (which may exist from `register_subaddress`
            // as a zero placeholder, or from a recovered earlier credit).
            let pool = event.option_pools.entry(option).or_default();
            let previous = pool
                .insert(subaddress.to_string(), net_amount)
                .unwrap_or(0);
            let delta = net_amount.checked_sub(previous).ok_or_else(|| {
                format!(
                    "refusing negative-delta deposit for '{}' on event '{}'",
                    subaddress, event_id
                )
            })?;

            let total = event.pool_totals.entry(option).or_insert(0);
            *total = total.checked_add(delta).ok_or_else(|| {
                format!("pool total overflow for event '{}'", event_id)
            })?;

            let event_bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
            txn.put(event_key.as_bytes(), &event_bytes).map_err(|e| e.to_string())?;
            txn.put(funded_key.as_bytes(), b"1").map_err(|e| e.to_string())?;

            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Busy => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("deposit credit conflict: retry budget exhausted".into())
    }
}
