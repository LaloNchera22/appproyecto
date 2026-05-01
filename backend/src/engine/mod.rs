// backend/src/engine/mod.rs
pub mod parimutuel;

pub use parimutuel::calculate_payouts;

// ---------------------------------------------------------------------------
// Legacy re-exports — satisfy existing references in services/mod.rs stub
// that used the old `calculate_payout` / `PoolStats` API.
// ---------------------------------------------------------------------------

/// Pool totals for a binary (A vs B) parimutuel event.
pub struct PoolStats {
    pub total_a: u64,
    pub total_b: u64,
}

/// Single-winner convenience wrapper around the full `calculate_payouts` engine.
/// Returns the payout for one contributor given pool statistics.
///
/// Kept for backward compatibility only; prefer `calculate_payouts` directly.
pub fn calculate_payout(stats: &PoolStats, contribution: u64) -> Result<u64, &'static str> {
    use std::collections::HashMap;

    if contribution == 0 {
        return Ok(0);
    }

    let mut contribs = HashMap::with_capacity(1);
    contribs.insert("_single".to_string(), contribution);

    let payouts = calculate_payouts(stats.total_a, stats.total_b, &contribs)?;
    Ok(*payouts.get("_single").unwrap_or(&0))
}
