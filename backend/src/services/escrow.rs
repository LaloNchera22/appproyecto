// backend/src/services/escrow.rs
//
// Zero-Trust escrow resolution service.
//
// Responsibilities:
//   1. Enforce settlement preconditions (idempotency / double-spend guard).
//   2. Delegate all arithmetic to the pure parimutuel engine.
//   3. Probe the wallet's actual unlocked balance and refuse settlement when
//      the declared payouts exceed it (defence against a compromised RPC
//      inflating pool totals — Finding #5b).
//   4. Persist outcome atomically via the Ledger's optimistic-transaction
//      path.
//
// Apart from the wallet-balance probe in step 3 this module performs no
// network I/O, and it never uses floating-point arithmetic.  All monetary
// values are piconeros (u64).

use std::sync::Arc;

use crate::crypto::CryptoService;
use crate::db::Ledger;
use crate::engine::parimutuel::calculate_payouts;
use crate::models::EventStatus;

pub struct EscrowService {
    ledger: Arc<Ledger>,
    crypto: CryptoService,
}

impl EscrowService {
    pub fn new(ledger: Arc<Ledger>, crypto: CryptoService) -> Self {
        Self { ledger, crypto }
    }

    /// Resolve a parimutuel event: compute payouts, verify the wallet can
    /// cover them, and atomically settle the ledger record.
    ///
    /// # Zero-Trust contract
    /// * If the event is already `Settled` the call is rejected immediately —
    ///   no payout is recomputed and no ledger write is attempted.
    /// * Before committing settlement, the wallet's `unlocked_balance` is
    ///   probed via the `CryptoService`.  Settlement is **refused** if the
    ///   probe fails or if the on-hand balance is insufficient to cover the
    ///   declared payout map — eliminating the most direct path by which a
    ///   compromised wallet RPC could trick the operator into draining real
    ///   XMR via an inflated pool total.
    /// * The `Settled` state transition and the payout map are written in a
    ///   single optimistic transaction (see `Ledger::settle_event_atomic`),
    ///   so a crash mid-write cannot leave the ledger in a partially
    ///   settled state.
    ///
    /// # Arguments
    /// * `event_id`       — stable identifier of the event in the ledger.
    /// * `winning_option` — index of the winning pool (e.g. `0` or `1` for a
    ///   binary market).
    pub async fn resolve_event(
        &self,
        event_id: &str,
        winning_option: u8,
    ) -> Result<(), String> {
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
        // Step 4 — Wallet-balance reconciliation (Finding #5b).
        //
        // Sum the declared payouts and compare against the wallet's actual
        // unlocked balance.  Refuse to commit settlement if either:
        //   • the balance probe itself fails (treat as "do not pay out"); or
        //   • on-hand balance is below the declared total.
        //
        // This ensures that even if a compromised RPC inflated `pool_totals`
        // via fabricated transfers, the engine never authorises a payout map
        // that the wallet cannot actually fund.
        // ------------------------------------------------------------------
        let total_payout = payouts
            .values()
            .try_fold(0_u64, |acc, &p| acc.checked_add(p))
            .ok_or_else(|| format!("payout sum overflow for event '{}'", event_id))?;

        let on_hand = self.crypto.get_unlocked_balance().await.map_err(|_| {
            format!(
                "wallet balance probe failed; settlement of event '{}' aborted",
                event_id
            )
        })?;

        if on_hand < total_payout {
            eprintln!(
                "[escrow] refusing settle: balance {} < payout {} for event '{}'",
                on_hand, total_payout, event_id
            );
            return Err(format!(
                "insufficient wallet balance for declared payouts on event '{}'",
                event_id
            ));
        }

        // ------------------------------------------------------------------
        // Step 5 — Atomic settlement: Settled flag + payout map in one txn.
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
