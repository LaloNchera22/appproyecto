// backend/src/admin/mod.rs
use crate::models::{TournamentStatus, BetGroup};
use crate::db::Ledger;
use std::sync::Arc;

pub struct AdminService {
    ledger: Arc<Ledger>,
}

impl AdminService {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    /// Validates the physical event result and updates the Ledger.
    /// Access is restricted via the UDS and Nginx proxy.
    pub async fn resolve_tournament(
        &self, 
        tournament_id: &str, 
        winner: BetGroup
    ) -> Result<(), String> {
        let mut tournament = self.ledger.get_tournament(tournament_id)?;

        // Zero-Trust Check: Ensure state is WaitingWinner before resolution
        if tournament.status != TournamentStatus::WaitingWinner {
            return Err("Resolution denied: Tournament is not awaiting a winner.".into());
        }

        tournament.status = TournamentStatus::Settled;
        tournament.winning_group = Some(winner);

        // Commit change to the immutable local ledger
        self.ledger.update_tournament(tournament_id, &tournament)?;
        
        println!("Audit Log: Tournament {} settled by support team.", tournament_id);
        Ok(())
    }
}
