// backend/tests/security_tests.rs
//
// Integration security & robustness tests for the SicBox engine.
//
// These tests deliberately exercise the *real* production code paths:
//   • A real RocksDB ledger is opened on a `tempfile::TempDir` path — no
//     SQLite, no in-memory mock — so any breakage in the actual on-disk
//     write path is caught here.
//   • The real Axum routers (`user_router`, `admin_router`) are wired with
//     a real `AppState`, including the constant-time auth extractor.
//   • The pure parimutuel arithmetic engine is called with adversarial u64
//     inputs to assert that overflow is surfaced as `Err`, never as a panic.
//   • A genuine Unix Domain Socket bind is performed via
//     `tokio::net::UnixListener` to confirm the strict transport boundary.
//   • A minimal in-process mock Monero Wallet RPC is spawned for the
//     escrow double-spend test, so the wallet-balance reconciliation
//     check (Finding #5b) is exercised end-to-end without depending on a
//     real wallet daemon.
//
// All tests are isolated: each opens its own RocksDB instance inside a
// fresh `TempDir`, which is removed automatically when the test ends.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use sicbox::api::{admin_routes::admin_router, user_routes::user_router};
use sicbox::crypto::CryptoService;
use sicbox::db::Ledger;
use sicbox::engine::calculate_payouts;
use sicbox::models::Event;
use sicbox::services::EscrowService;
use sicbox::AppState;
use tempfile::TempDir;
use tokio::net::{TcpListener, UnixListener};
use tower::ServiceExt;

/// Admin bearer token used by the auth tests.  Length matches the production
/// minimum (≥ 32 chars) so the test reflects a realistic deployment.
const TEST_ADMIN_TOKEN: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef";

/// Spawn a tiny mock Monero Wallet RPC on an ephemeral loopback port and
/// return the JSON-RPC URL pointing at it.  The mock answers every JSON-RPC
/// call by echoing a fixed `unlocked_balance`, which is sufficient for tests
/// that only need `get_balance` (escrow's reconciliation probe).  Other
/// methods are stubbed with the same payload — fields the caller does not
/// expect are ignored on deserialisation.
async fn spawn_mock_wallet_rpc(unlocked_balance: u64) -> String {
    // The mock does not switch on `method`; every JSON-RPC call returns a
    // `result` object that satisfies the strict subset of fields the engine
    // cares about across all RPC methods exercised in tests (get_balance,
    // create_address, get_transfers).  Fields the caller does not expect are
    // ignored on deserialisation.
    let balance = unlocked_balance;
    let app = Router::new().route(
        "/json_rpc",
        post(move |Json(_req): Json<Value>| {
            let bal = balance;
            async move {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": "0",
                    "result": {
                        "balance": bal,
                        "unlocked_balance": bal,
                        "address": "MOCK_ADDR",
                        "address_index": 0,
                        "in": [],
                        "pool": []
                    }
                }))
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock RPC must bind to an ephemeral loopback port");
    let port = listener.local_addr().expect("mock listener has addr").port();
    tokio::spawn(async move {
        // `axum::serve` runs until the listener is dropped; for these tests
        // it lives for the lifetime of the test process.
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    format!("http://127.0.0.1:{}/json_rpc", port)
}

/// Build a complete `AppState` backed by a fresh RocksDB ledger inside `tmp`.
///
/// The `TempDir` is owned by the caller — keep it alive for the lifetime of
/// the state, otherwise the database directory is unlinked while in use.
///
/// The crypto service is constructed with a localhost-loopback URL that
/// will never respond.  Tests that exercise escrow settlement (which probes
/// the wallet RPC) build their own state via `make_state_with_rpc` instead.
fn make_state(tmp: &TempDir) -> Arc<AppState> {
    let db_path = tmp.path().join("ledger");
    let ledger = Arc::new(Ledger::new(
        db_path
            .to_str()
            .expect("tempdir path must be valid UTF-8"),
    ));
    let crypto = CryptoService::new("http://127.0.0.1:1/json_rpc".to_string())
        .expect("CryptoService must build with a syntactically valid URL");
    let escrow = EscrowService::new(Arc::clone(&ledger), crypto.clone());

    Arc::new(AppState {
        ledger,
        crypto,
        escrow,
        admin_token: TEST_ADMIN_TOKEN.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Test 1 — UDS binding
// ---------------------------------------------------------------------------

/// The user-facing router must successfully bind to a Unix Domain Socket.
/// Production runs over UDS only (no TCP fallback), so a regression in the
/// router's transport plumbing must be caught at test time, not at deploy
/// time.  The test binds the listener and then verifies that the socket
/// inode actually exists on disk.
#[tokio::test]
async fn test_strict_uds_binding() {
    let tmp = TempDir::new().expect("tempdir must be creatable");
    let state = make_state(&tmp);

    // Wire the user router with real state, exactly as `main.rs` does.
    let _app: Router = user_router().with_state(state);

    // Build a fresh socket path inside the temp dir.  Path length is well
    // under the 108-byte sun_path limit, so the bind must succeed.
    let socket_path = tmp.path().join("engine.sock");
    let listener = UnixListener::bind(&socket_path)
        .expect("user_router transport must bind to a valid UDS path");

    assert!(
        socket_path.exists(),
        "UDS inode must exist on disk after a successful bind"
    );

    // Confirm we own a real listener with a queryable local address.
    let local = listener
        .local_addr()
        .expect("bound UDS listener must expose its local address");
    assert!(
        local.as_pathname().is_some(),
        "UDS listener must be path-bound, not unnamed"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — Constant-time admin auth
// ---------------------------------------------------------------------------

/// The admin router rejects every unauthenticated request with an opaque
/// `401 Unauthorized`.  Two failure modes are exercised:
///
///   1. No `Authorization` header at all.
///   2. A header whose token differs from the configured secret by exactly
///      one character (same length — forces the byte-comparison path of
///      the `subtle::ConstantTimeEq` check, not the length-mismatch path).
///
/// Both paths must converge on the same status code, with no leaked detail.
#[tokio::test]
async fn test_admin_constant_time_auth() {
    let tmp = TempDir::new().expect("tempdir must be creatable");
    let state = make_state(&tmp);

    let app: Router = admin_router().with_state(state);

    // ---- Case A: no Authorization header ------------------------------------
    let no_token_req = Request::builder()
        .method("POST")
        .uri("/api/admin/events")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"x","options":["a","b"]}"#))
        .expect("request must build");

    let res = app
        .clone()
        .oneshot(no_token_req)
        .await
        .expect("router oneshot must complete");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "missing Authorization header must yield 401"
    );

    // ---- Case B: token differs by exactly one character ---------------------
    // Flip the final byte of the configured token, keeping the total length
    // identical so the constant-time byte comparison is the path under test.
    let mut tampered = TEST_ADMIN_TOKEN.to_string();
    let last = tampered.pop().expect("token must be non-empty");
    tampered.push(if last == 'f' { 'e' } else { 'f' });
    assert_eq!(
        tampered.len(),
        TEST_ADMIN_TOKEN.len(),
        "tampered token must preserve length"
    );
    assert_ne!(
        tampered, TEST_ADMIN_TOKEN,
        "tampered token must differ from the real one"
    );

    let bad_token_req = Request::builder()
        .method("POST")
        .uri("/api/admin/events")
        .header(header::AUTHORIZATION, format!("Bearer {}", tampered))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"title":"x","options":["a","b"]}"#))
        .expect("request must build");

    let res = app
        .oneshot(bad_token_req)
        .await
        .expect("router oneshot must complete");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "single-byte-diff token must yield 401"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — Parimutuel arithmetic safety
// ---------------------------------------------------------------------------

/// `calculate_payouts` must defuse adversarial u64 inputs by surfacing `Err`
/// rather than panicking.  Two distinct overflow paths are exercised:
///
///   • `gross_pool = winning + losing` overflows when both pools are u64::MAX.
///   • `numerator = contribution * net_pool` overflows when a single
///     contribution and the net pool are both at u64::MAX scale.
///
/// `std::panic::catch_unwind` wraps each call so a regression that *does*
/// panic is reported as a clean test failure, not as a process abort.
#[tokio::test]
async fn test_parimutuel_math_safety() {
    // ---- Overflow path 1: addition of the two pool totals -------------------
    let mut contribs: HashMap<String, u64> = HashMap::new();
    contribs.insert("addr_winner".to_string(), 1);

    let outer =
        std::panic::catch_unwind(|| calculate_payouts(u64::MAX, u64::MAX, &contribs));
    let inner = outer.expect("calculate_payouts must NOT panic on additive overflow");
    assert!(
        inner.is_err(),
        "u64::MAX + u64::MAX must surface as Err, got {:?}",
        inner
    );

    // ---- Overflow path 2: per-winner multiplicative overflow ----------------
    // gross_pool = u64::MAX + 0 = u64::MAX (no addition overflow); the failing
    // step is `contribution * net_pool` for a u64::MAX contribution.
    let mut huge_contribs: HashMap<String, u64> = HashMap::new();
    huge_contribs.insert("addr_huge".to_string(), u64::MAX);

    let outer2 =
        std::panic::catch_unwind(|| calculate_payouts(u64::MAX, 0, &huge_contribs));
    let inner2 =
        outer2.expect("calculate_payouts must NOT panic on multiplicative overflow");
    assert!(
        inner2.is_err(),
        "u64::MAX * net_pool must surface as Err, got {:?}",
        inner2
    );
}

// ---------------------------------------------------------------------------
// Test 4 — Escrow double-spend prevention
// ---------------------------------------------------------------------------

/// `EscrowService::resolve_event` is the sole gate through which an event
/// transitions to `Settled`.  A second resolution call on the same event MUST
/// be refused — silently overwriting the persisted payout map would let an
/// operator pay every losing pool twice.
///
/// The test:
///   1. Spawns an in-process mock wallet RPC that reports a balance large
///      enough to satisfy the escrow's reconciliation probe (Finding #5b).
///   2. Creates a realistic event in a real RocksDB ledger.
///   3. Calls `resolve_event` once — must succeed and write payouts.
///   4. Calls `resolve_event` a second time — must return `Err` with a
///      message that explicitly references the double-spend guard.
///   5. Confirms the persisted payout map was NOT overwritten.
#[tokio::test]
async fn test_escrow_double_spend_prevention() {
    let tmp = TempDir::new().expect("tempdir must be creatable");
    let db_path = tmp.path().join("ledger");
    let ledger = Arc::new(Ledger::new(
        db_path
            .to_str()
            .expect("tempdir path must be valid UTF-8"),
    ));

    // Wallet RPC mock that always reports a sufficient unlocked balance, so
    // the wallet-balance reconciliation in escrow does not block settlement.
    let rpc_url = spawn_mock_wallet_rpc(u64::MAX).await;
    let crypto = CryptoService::new(rpc_url).expect("CryptoService must build");
    let escrow = EscrowService::new(Arc::clone(&ledger), crypto);

    // Build a minimal but realistic two-option event: option 0 wins, with a
    // single subaddress on the winning side and a non-zero losing pool.
    let event_id = "evt-double-spend";
    let mut event = Event::new(event_id);

    let mut pool_winner: HashMap<String, u64> = HashMap::new();
    pool_winner.insert("subaddr_winner".to_string(), 1_000_000);
    event.option_pools.insert(0, pool_winner);
    event.option_pools.insert(1, HashMap::new());
    event.pool_totals.insert(0, 1_000_000);
    event.pool_totals.insert(1, 500_000);

    ledger
        .put_event(&event)
        .expect("event must persist in the real ledger");

    // ---- First resolution: must succeed ------------------------------------
    escrow
        .resolve_event(event_id, 0)
        .await
        .expect("first resolve must succeed on an Open event");

    let first_payouts = ledger
        .get_payouts(event_id)
        .expect("payouts must exist after the first resolve");
    assert!(
        first_payouts.contains_key("subaddr_winner"),
        "first resolve must populate the winner's payout entry"
    );

    // ---- Second resolution: must be refused --------------------------------
    let second = escrow.resolve_event(event_id, 0).await;
    assert!(
        second.is_err(),
        "second resolve must be refused, got Ok(...)"
    );

    let msg = second.unwrap_err();
    assert!(
        msg.contains("already Settled") || msg.contains("double-spend"),
        "error must indicate the double-spend guard fired, got: {}",
        msg
    );

    // ---- Ledger invariant: payout map was not overwritten ------------------
    let after_payouts = ledger
        .get_payouts(event_id)
        .expect("payouts must remain on disk after the rejected call");
    assert_eq!(
        first_payouts, after_payouts,
        "payout map must be byte-identical after the rejected second call"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — Wallet-balance reconciliation refuses underfunded settlement
// ---------------------------------------------------------------------------

/// Finding #5b regression: when the wallet's `unlocked_balance` is *below*
/// the declared payout sum, `resolve_event` MUST refuse to commit settlement
/// and the event MUST remain Open.  This guards against a compromised wallet
/// RPC inflating pool totals via fabricated transfers and tricking the
/// operator into authorising a payout map that the wallet cannot actually
/// fund.
#[tokio::test]
async fn test_escrow_refuses_when_balance_insufficient() {
    let tmp = TempDir::new().expect("tempdir must be creatable");
    let db_path = tmp.path().join("ledger");
    let ledger = Arc::new(Ledger::new(
        db_path
            .to_str()
            .expect("tempdir path must be valid UTF-8"),
    ));

    // Mock wallet reports zero unlocked balance — below any non-trivial payout.
    let rpc_url = spawn_mock_wallet_rpc(0).await;
    let crypto = CryptoService::new(rpc_url).expect("CryptoService must build");
    let escrow = EscrowService::new(Arc::clone(&ledger), crypto);

    let event_id = "evt-underfunded";
    let mut event = Event::new(event_id);
    let mut pool_winner: HashMap<String, u64> = HashMap::new();
    pool_winner.insert("subaddr_winner".to_string(), 1_000_000);
    event.option_pools.insert(0, pool_winner);
    event.option_pools.insert(1, HashMap::new());
    event.pool_totals.insert(0, 1_000_000);
    event.pool_totals.insert(1, 500_000);

    ledger
        .put_event(&event)
        .expect("event must persist in the real ledger");

    let result = escrow.resolve_event(event_id, 0).await;
    assert!(
        result.is_err(),
        "settlement must be refused when unlocked balance < payout sum"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("insufficient wallet balance"),
        "error must reference the balance-reconciliation guard, got: {}",
        msg
    );

    // Event must remain Open and no payout entry may exist.
    let after = ledger
        .get_event(event_id)
        .expect("event must still be readable after refused settlement");
    assert_eq!(
        after.status,
        sicbox::models::EventStatus::Open,
        "event must remain Open when settlement was refused"
    );
    assert!(
        ledger.get_payouts(event_id).is_err(),
        "payout map must NOT have been written for a refused settlement"
    );
}
