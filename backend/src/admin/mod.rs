// backend/src/admin/mod.rs
use crate::models::{TournamentStatus, BetGroup, Tournament};
use crate::db::Ledger;
use crate::engine::calculate_payout;
use std::sync::Arc;

pub struct AdminService {
    // Shared reference to the immutable ledger
    pub ledger: Arc<Ledger>,
}

impl AdminService {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    /// Validates the physical event result and triggers the settlement process.
    /// Professional Rule: This action is recorded in the immutable audit log.
    pub async fn resolve_event(
        &self, 
        tournament_id: &str, 
        winning_group: BetGroup
    ) -> Result<(), String> {
        // 1. Retrieve tournament state from RocksDB
        let mut tournament = self.ledger.get_tournament(tournament_id)
            .map_err(|e| format!("Database error: {}", e))?;

        // 2. Zero Trust Check: Ensure the tournament is actually awaiting a result
        if tournament.status != TournamentStatus::WaitingWinner {
            return Err("Conflict: Tournament is not in WaitingWinner state".into());
        }

        // 3. Update Tournament State
        tournament.status = TournamentStatus::Settled;
        tournament.winning_group = Some(winning_group);

        // 4. Persist the change in the Ledger before any payout happens
        self.ledger.update_tournament(tournament_id, &tournament)
            .map_err(|e| format!("Failed to persist settlement: {}", e))?;

        println!("Admin Action: Tournament {} settled. Winner: {:?}", tournament_id, winning_group);
        Ok(())
    }
}
