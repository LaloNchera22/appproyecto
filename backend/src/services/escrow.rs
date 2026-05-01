// backend/src/services/escrow.rs
//
// Zero-Trust escrow resolution service.
//
// Responsibilities:
//   1. Enforce settlement preconditions (idempotency / double-spend guard).
//   2. Delegate all arithmetic to the pure parimutuel engine.
//   3. Persist outcome atomically via the Ledger's WriteBatch path.
//
// This module intentionally performs NO network I/O and NO floating-point
// arithmetic.  All monetary values are piconeros (u64).

use std::sync::Arc;

use crate::db::Ledger;
use crate::engine::parimutuel::calculate_payouts;
use crate::models::EventStatus;

pub struct EscrowService {
    ledger: Arc<Ledger>,
}

impl EscrowService {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    /// Resolve a parimutuel event: compute payouts and atomically settle the
    /// ledger record.
    ///
    /// # Zero-Trust contract
    /// * If the event is already `Settled` the call is rejected immediately —
    ///   no payout is recomputed and no ledger write is attempted.
    /// * The `Settled` state transition and the payout map are written in a
    ///   single `WriteBatch` (see `Ledger::settle_event_atomic`), so a crash
    ///   mid-write cannot leave the ledger in a partially-settled state.
    ///
    /// # Arguments
    /// * `event_id`       — stable identifier of the event in the ledger.
    /// * `winning_option` — index of the winning pool (e.g. `0` or `1` for a
    ///   binary market).
    pub fn resolve_event(&self, event_id: &str, winning_option: u8) -> Result<(), String> {
        // ------------------------------------------------------------------
        // Step 1 — Fetch event and enforce idempotency.
        // ------------------------------------------------------------------
        let event = self.ledger.get_event(event_id)?;

        if event.status == EventStatus::Settled {
            return Err(format!(
                "resolve_event rejected: event '{}' is already Settled \
                 (double-spend prevention)",
                event_id
            ));
        }

        // ------------------------------------------------------------------
        // Step 2 — Extract pool data for the declared winner.
        // ------------------------------------------------------------------

        // Contributions for the winning side: subaddress → piconeros.
        let winning_pool = event
            .option_pools
            .get(&winning_option)
            .cloned()
            .unwrap_or_default();

        let winning_pool_total = event
            .pool_totals
            .get(&winning_option)
            .copied()
            .unwrap_or(0);

        // Sum all other pools as the losing pool.  Use checked_add on every
        // accumulation step — a corrupt ledger record must not cause silent
        // overflow and wrong payouts.
        let losing_pool_total = event
            .pool_totals
            .iter()
            .filter(|(&opt, _)| opt != winning_option)
            .try_fold(0_u64, |acc, (_, &total)| acc.checked_add(total))
            .ok_or_else(|| {
                format!(
                    "arithmetic overflow while summing losing pools for event '{}'",
                    event_id
                )
            })?;

        // ------------------------------------------------------------------
        // Step 3 — Delegate all arithmetic to the pure parimutuel engine.
        // ------------------------------------------------------------------
        let payouts = calculate_payouts(winning_pool_total, losing_pool_total, &winning_pool)
            .map_err(|e| {
                format!(
                    "payout calculation failed for event '{}': {}",
                    event_id, e
                )
            })?;

        // ------------------------------------------------------------------
        // Step 4 — Atomic settlement: Settled flag + payout map in one batch.
        // ------------------------------------------------------------------
        self.ledger
            .settle_event_atomic(event_id, winning_option, &payouts)
            .map_err(|e| {
                format!(
                    "ledger write failed while settling event '{}': {}",
                    event_id, e
                )
            })?;

        Ok(())
    }
}
