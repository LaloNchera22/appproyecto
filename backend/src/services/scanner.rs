// backend/src/services/scanner.rs
//
// Zero-Trust PULL-only blockchain deposit scanner.
//
// Design constraints enforced here:
//   • Data is PULLED from the local RPC on a fixed interval.
//     The engine never opens a listener port and never accepts PUSH events
//     (webhook, tx_notify, etc.) — eliminating an entire command-injection
//     attack surface.
//   • Runs as a dedicated Tokio task, fully decoupled from the Axum web
//     server thread.  A slow or failing wallet node cannot affect HTTP
//     request handling.
//   • All monetary arithmetic uses integer math (piconeros, u64).
//     No floating-point operations anywhere in this file.
//   • Every confirmed deposit is written atomically: pool update + funded
//     marker land in a single RocksDB WriteBatch or not at all.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time;

use crate::crypto::CryptoService;
use crate::db::Ledger;

/// Minimum on-chain confirmations before a deposit is credited.
const REQUIRED_CONFIRMATIONS: u64 = 2;

/// Platform fee: 1 % deducted from every deposit using integer floor division.
/// net = gross - floor(gross / 100)  →  exactly 99 % of gross in piconeros.
const PLATFORM_FEE_DIVISOR: u64 = 100;

/// Interval between consecutive RPC polls.
const POLL_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// BlockchainScanner
// ---------------------------------------------------------------------------

pub struct BlockchainScanner {
    ledger: Arc<Ledger>,
    crypto: CryptoService,
}

impl BlockchainScanner {
    pub fn new(ledger: Arc<Ledger>, crypto: CryptoService) -> Self {
        Self { ledger, crypto }
    }

    /// Enter the polling loop.  This method never returns under normal
    /// operation; call it inside `tokio::spawn` to run as a background task.
    ///
    /// Loop invariants:
    ///   1. Only OPEN events are examined.
    ///   2. Only subaddresses without a `funded:` marker are queried.
    ///   3. Only transfers with ≥ `REQUIRED_CONFIRMATIONS` blocks and no
    ///      double-spend flag are credited.
    ///   4. If the wallet RPC is unreachable, the iteration is skipped
    ///      gracefully — the task does not panic.
    pub async fn start_polling(self) {
        let mut interval = time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
        // If a scan iteration takes longer than the interval, delay the next
        // tick rather than firing a burst of catch-up ticks.
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;

            // ------------------------------------------------------------------
            // Step 1 — Collect every unfunded subaddress from all open events.
            //
            // Build a reverse index:
            //   deposit_address  →  (event_id, option_index)
            //
            // Subaddresses already marked `funded:` in RocksDB are excluded so
            // they are never re-processed.
            // ------------------------------------------------------------------
            let open_events = self.ledger.get_open_events();

            let mut pending: HashMap<String, (String, u8)> = HashMap::new();
            for event in &open_events {
                for (&option, pool) in &event.option_pools {
                    for subaddress in pool.keys() {
                        if !self.ledger.is_subaddress_funded(subaddress) {
                            pending.insert(
                                subaddress.clone(),
                                (event.id.clone(), option),
                            );
                        }
                    }
                }
            }

            if pending.is_empty() {
                continue;
            }

            // ------------------------------------------------------------------
            // Step 2 — PULL transfers from the local Monero Wallet RPC.
            //
            // `get_transfers` fetches both confirmed (`in`) and unconfirmed
            // (`pool`) transfers.  The 5-second HTTP timeout baked into
            // `CryptoService` ensures the call cannot block this task
            // indefinitely.  Any error is logged generically and this iteration
            // is skipped; the next tick will retry.
            // ------------------------------------------------------------------
            let transfers = match self.crypto.get_transfers().await {
                Ok(t) => t,
                Err(_) => {
                    eprintln!(
                        "[scanner] wallet RPC unreachable — skipping this iteration"
                    );
                    continue;
                }
            };

            // ------------------------------------------------------------------
            // Step 3 — Process each transfer that meets confirmation threshold.
            // ------------------------------------------------------------------
            for transfer in &transfers {
                // Reject unconfirmed and double-spend-flagged entries.
                if transfer.double_spend_seen
                    || transfer.confirmations < REQUIRED_CONFIRMATIONS
                {
                    continue;
                }

                // Only care about addresses we issued for open events.
                let Some((event_id, option)) = pending.get(&transfer.address) else {
                    continue;
                };

                // ------------------------------------------------------------------
                // Fee & net calculation — pure integer arithmetic, no floats.
                //
                //   fee        = floor(gross / 100)      →  1 % platform fee
                //   net_amount = gross − fee              →  99 % to the pool
                //
                // A dust deposit that rounds to net == 0 is silently dropped.
                // ------------------------------------------------------------------
                let fee = transfer.amount / PLATFORM_FEE_DIVISOR;
                let net_amount = match transfer.amount.checked_sub(fee) {
                    Some(n) if n > 0 => n,
                    _ => continue,
                };

                // ------------------------------------------------------------------
                // Atomic ledger update:
                //   • option_pools[option][subaddress] ← net_amount
                //   • pool_totals[option]              += net_amount
                //   • funded:{subaddress}              ← "1"
                //
                // All three writes land in a single RocksDB WriteBatch so a crash
                // mid-write cannot leave the ledger in a partially-credited state.
                // The `funded:` marker also provides idempotency if this iteration
                // is interrupted and retried.
                // ------------------------------------------------------------------
                if let Err(e) = self.ledger.record_deposit_atomic(
                    event_id,
                    *option,
                    &transfer.address,
                    net_amount,
                ) {
                    eprintln!(
                        "[scanner] failed to record deposit for address {}: {}",
                        transfer.address, e
                    );
                }
            }
        }
    }
}
