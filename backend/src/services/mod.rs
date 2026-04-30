// backend/src/services/mod.rs
use crate::db::Ledger;
use crate::engine::{calculate_payout, PoolStats};
use crate::models::{BetGroup, TournamentStatus};
use std::sync::Arc;

pub struct EscrowService {
    ledger: Arc<Ledger>,
}

impl EscrowService {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    pub fn finalize_tournament(&self, tournament_id: &str, winner: BetGroup) -> Result<(), String> {
        let tournament = self.ledger.get_tournament(tournament_id)?;
        
        // Zero-Trust Check: Status must be Settled by Admin first
        if tournament.status != TournamentStatus::Settled {
            return Err("Tournament not yet settled by admin".into());
        }

        let stats = PoolStats {
            total_a: tournament.pool_a_total,
            total_b: tournament.pool_b_total,
        };

        // Here the logic would iterate through bets and execute XMR transfers
        println!("Escrow: Executing payouts for tournament {} based on {:?} victory", 
                 tournament_id, winner);
        
        Ok(())
    }
}
