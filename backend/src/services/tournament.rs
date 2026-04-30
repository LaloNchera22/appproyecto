// backend/src/services/tournament.rs
use crate::db::Ledger;
use crate::models::{Tournament, TournamentStatus};
use std::sync::Arc;

pub struct TournamentService {
    ledger: Arc<Ledger>,
}

impl TournamentService {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    /// Retrieves all active tournaments for the frontend display.
    pub fn get_active_tournaments(&self) -> Vec<Tournament> {
        // In a real scenario, we would iterate over a specific column family in RocksDB
        println!("Fetching active tournaments from immutable ledger...");
        vec![] // Returning empty vec for now until seeding logic is added
    }

    /// Initializes a new tournament pool.
    pub fn create_tournament(&self, id: &str) -> Result<(), String> {
        let new_tournament = Tournament {
            id: id.to_string(),
            pool_a_total: 0,
            pool_b_total: 0,
            status: TournamentStatus::Open,
            winning_group: None,
        };
        self.ledger.update_tournament(id, &new_tournament)
    }
}
