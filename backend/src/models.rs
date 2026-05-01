// backend/src/models.rs
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Lifecycle states for a parimutuel event.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum EventStatus {
    /// Accepting bets from participants.
    Open,
    /// Betting window closed; awaiting admin resolution.
    Closed,
    /// Admin has declared a winner; payouts computed and locked.
    Settled,
}

/// A parimutuel betting event with N binary or multi-option pools.
///
/// All monetary values are in piconeros (smallest XMR unit) as `u64`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub id: String,
    pub status: EventStatus,
    /// option_pools[option_index] -> { subaddress -> piconero contribution }
    pub option_pools: HashMap<u8, HashMap<String, u64>>,
    /// pool_totals[option_index] -> aggregate piconeros in that pool
    pub pool_totals: HashMap<u8, u64>,
    pub winning_option: Option<u8>,
}

impl Event {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: EventStatus::Open,
            option_pools: HashMap::new(),
            pool_totals: HashMap::new(),
            winning_option: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy Tournament model — kept for backward compatibility with admin service
// and existing Ledger serialization. New code should use Event.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum TournamentStatus {
    Open,
    WaitingWinner,
    Settled,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BetGroup {
    A,
    B,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tournament {
    pub id: String,
    pub pool_a_total: u64,
    pub pool_b_total: u64,
    pub status: TournamentStatus,
    pub winning_group: Option<BetGroup>,
}
