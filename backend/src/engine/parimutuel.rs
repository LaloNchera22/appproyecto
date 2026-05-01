// backend/src/engine/parimutuel.rs
//
// Pure, stateless, deterministic parimutuel payout engine.
// No I/O, no floating point, no side effects — only integer arithmetic.
//
// All amounts are in piconeros (1 XMR = 1_000_000_000_000 piconeros).

use std::collections::HashMap;

/// Computes the exact payout for every winner in a parimutuel pool.
///
/// The platform deducts exactly 1% of the gross pool as a fee (integer floor
/// division).  The remaining net pool is distributed proportionally among
/// winners based on each contributor's share of the winning pool.
///
/// # Arguments
/// * `winning_pool_total` — sum of all piconeros placed on the winning option.
/// * `losing_pool_total`  — sum of all piconeros placed on every other option.
/// * `winners_contributions` — map of subaddress → piconero amount for every
///   participant who wagered on the winning option.
///
/// # Returns
/// `Ok(HashMap<subaddress, payout_piconeros>)` on success, or a `&'static str`
/// describing the first arithmetic failure encountered.
///
/// # Errors
/// Returns `Err` if:
/// * `winning_pool_total` is zero (would cause division by zero).
/// * Any intermediate multiplication overflows `u64`.
pub fn calculate_payouts(
    winning_pool_total: u64,
    losing_pool_total: u64,
    winners_contributions: &HashMap<String, u64>,
) -> Result<HashMap<String, u64>, &'static str> {
    // Guard: a zero winning pool makes proportional division undefined.
    if winning_pool_total == 0 {
        return Err("winning_pool_total is zero: cannot compute proportional payouts");
    }

    // Step 1 — gross pool (winning + losing).
    let gross_pool = winning_pool_total
        .checked_add(losing_pool_total)
        .ok_or("arithmetic overflow: gross_pool = winning + losing")?;

    // Step 2 — platform fee: exactly 1% via integer floor division.
    // No checked_div needed; 100 is a non-zero constant.
    let fee = gross_pool / 100;

    // Step 3 — net pool distributed to winners.
    // checked_sub is safe: fee <= gross_pool always (fee = gross_pool / 100).
    let net_pool = gross_pool
        .checked_sub(fee)
        .ok_or("arithmetic overflow: net_pool = gross_pool - fee")?;

    // Step 4 — proportional payout per winner.
    //
    // payout_i = floor( contribution_i * net_pool / winning_pool_total )
    //
    // Multiplication must be checked; net_pool and contributions can both be
    // large u64 values (piconero amounts across many participants).
    let mut payouts = HashMap::with_capacity(winners_contributions.len());

    for (subaddress, &contribution) in winners_contributions {
        let numerator = contribution
            .checked_mul(net_pool)
            .ok_or("arithmetic overflow: contribution * net_pool")?;

        // winning_pool_total > 0 is guaranteed by the guard above.
        let payout = numerator
            .checked_div(winning_pool_total)
            .ok_or("arithmetic overflow: numerator / winning_pool_total")?;

        payouts.insert(subaddress.clone(), payout);
    }

    Ok(payouts)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn contributions(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn test_zero_winning_pool_is_rejected() {
        let result = calculate_payouts(0, 1_000, &contributions(&[("addr_a", 0)]));
        assert!(result.is_err());
    }

    #[test]
    fn test_single_winner_takes_net_pool() {
        // Keep values small enough that contribution * net_pool stays < u64::MAX.
        // contribution * net_pool ≤ winning * (winning + losing) * 99/100
        // With 1_000_000 per side: 1e6 * ~2e6 = ~2e12, well within u64::MAX.
        let winning = 1_000_000_u64;
        let losing  = 1_000_000_u64;
        let contribs = contributions(&[("addr_winner", winning)]);

        let payouts = calculate_payouts(winning, losing, &contribs).unwrap();
        let gross = winning + losing;
        let fee   = gross / 100;
        let net   = gross - fee;

        // The sole winner contributed the entire winning pool, so they receive
        // the full net pool.
        assert_eq!(payouts["addr_winner"], net);
    }

    #[test]
    fn test_proportional_split_two_winners() {
        // Winner A put in 3 units, winner B put in 1 unit → A gets 75% of net.
        let winning_total = 4_000_000_u64;
        let losing_total  = 4_000_000_u64;
        let contribs = contributions(&[
            ("addr_a", 3_000_000),
            ("addr_b", 1_000_000),
        ]);

        let payouts = calculate_payouts(winning_total, losing_total, &contribs).unwrap();
        let gross = 8_000_000_u64;
        let fee   = gross / 100;   // 80_000
        let net   = gross - fee;   // 7_920_000

        // A's share: 3_000_000 * 7_920_000 / 4_000_000 = 5_940_000
        assert_eq!(payouts["addr_a"], 3_000_000 * net / winning_total);
        // B's share: 1_000_000 * 7_920_000 / 4_000_000 = 1_980_000
        assert_eq!(payouts["addr_b"], 1_000_000 * net / winning_total);

        // Total paid out must not exceed net pool (integer truncation only
        // drops dust, never creates piconeros from thin air).
        let total_out: u64 = payouts.values().sum();
        assert!(total_out <= net);
    }

    #[test]
    fn test_empty_winners_returns_empty_map() {
        let payouts = calculate_payouts(1_000, 1_000, &HashMap::new()).unwrap();
        assert!(payouts.is_empty());
    }
}
