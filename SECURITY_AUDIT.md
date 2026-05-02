# SicBox Engine — Security & Cryptographic Audit

**Branch:** `claude/security-crypto-audit-xqX4d`
**Scope:** `backend/src/{main.rs, db/mod.rs, crypto/mod.rs, services/scanner.rs, services/escrow.rs, engine/parimutuel.rs, api/*}`
**Threat model:** Admin token compromised. Goals — crash the backend (DoS), corrupt the immutable Ledger, or trick the Escrow into paying out more XMR than the wallet holds.

---

## Finding #1

**[VULNERABILITY ID: LOGIC — Backend DoS via UDS `accept()` panic]**

**Severity Score:** Critical (CVSS v3.1: 8.6 — `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)

The accept loop in `backend/src/main.rs:81-84` panics on **any** error returned by `UnixListener::accept`:

```rust
let (stream, _) = listener
    .accept()
    .await
    .unwrap_or_else(|e| panic!("FATAL: accept error: {}", e));
```

A single transient failure (`EMFILE` — too many open files, `ECONNABORTED`, kernel resource pressure) aborts the entire Tokio runtime. The blockchain scanner background task dies with it. Any deposit currently mid-credit (read-but-not-yet-written) is lost from in-memory state. Recovery is manual.

### Proof of Concept (PoC) Attack
On the same host (or any process able to reach the UDS path), open connections faster than they close:

```bash
# Saturate the engine's RLIMIT_NOFILE
ulimit -n 1024
for i in $(seq 1 4096); do
  socat - UNIX-CONNECT:/tmp/app/engine.sock &
done
# Once the engine's FD table is full, the next accept() returns EMFILE
# → unwrap → panic → entire process exits.
```

### The Remediation
```rust
loop {
    let (stream, _) = match listener.accept().await {
        Ok(conn) => conn,
        Err(e) => {
            // Transient errors (EMFILE, ECONNABORTED) must NOT crash the
            // engine.  Log and back off so we do not spin on EMFILE.
            eprintln!("[main] accept error (continuing): {}", e);
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
    };

    let app = app.clone();
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            app.clone().call(req.map(axum::body::Body::new))
        });
        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), svc)
            .await
        {
            eprintln!("[main] connection error: {}", e);
        }
    });
}
```

---

## Finding #2

**[VULNERABILITY ID: LOGIC — RocksDB State Desync via TOCTOU on Settled Event]**

**Severity Score:** Critical (CVSS v3.1: 9.1 — `AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`)

`Ledger::record_deposit_atomic` (`db/mod.rs:181-218`) reads the **entire** `Event`, mutates only the pool fields, and writes the **fully re-serialized** event back inside a `WriteBatch`. It performs **no** check that `event.status == Open`, and the batch atomicity does not extend to the read. The function therefore races `settle_event_atomic` and `register_subaddress` and can:

1. Overwrite a `Settled` status back to `Open` (because the in-memory copy still carries the older `Open` value), reanimating an already-settled event whose `payouts:{event_id}` key remains on disk.
2. Apply a deposit to an already-settled pool, inflating `pool_totals` after `payouts` were locked → trapped funds with no payout entry.

The same R-M-W pattern exists in `register_subaddress` (`db/mod.rs:150-164`) and `settle_event_atomic` (`db/mod.rs:82-112`); each can clobber the others.

### Proof of Concept (PoC) Attack
Attacker has the leaked admin token. Scanner runs every 60 s.

1. T₀: Scanner enters its iteration, calls `get_open_events()` → list contains Event `X`. Scanner calls `get_transfers()` and is blocked on the RPC for ~1 s.
2. T₀ + 100 ms: Attacker fires `POST /api/admin/events/X/resolve`. `settle_event_atomic` writes `{status: Settled, payouts: ...}` atomically.
3. T₀ + 1 s: Scanner finishes the RPC, processes the next transfer for event `X`, enters `record_deposit_atomic`. The function re-reads `event` (status is now `Settled`), but blindly mutates `pool_totals[opt] += net_amount` and serialises the whole struct back. Result A: the new write reverts `status` to `Open` if the read raced before settlement; Result B: the deposit is added after the payout map was finalised, permanently locked away from any winner.
4. Subsequent attempts to re-settle fail because `settle_event_atomic` rejects on `status == Settled` — but the ledger is now permanently inconsistent.

### The Remediation
Replace `DB` with `OptimisticTransactionDB` and route every event mutation through a single helper that uses `get_for_update` so concurrent writers are forced to retry instead of overwriting:

```rust
use rocksdb::{OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions, ErrorKind};

pub struct Ledger {
    db: OptimisticTransactionDB,
}

impl Ledger {
    /// Read-modify-write an Event under optimistic concurrency control.
    /// `mutator` may reject the update by returning Err.
    fn mutate_event<F>(&self, event_id: &str, mut mutator: F) -> Result<(), String>
    where
        F: FnMut(&mut Event) -> Result<(), String>,
    {
        const MAX_RETRIES: u32 = 5;
        let key = format!("{}{}", PREFIX_EVENT, event_id);

        for _ in 0..MAX_RETRIES {
            let txn = self.db.transaction_opt(
                &WriteOptions::default(),
                &OptimisticTransactionOptions::default(),
            );
            let bytes = txn
                .get_for_update(key.as_bytes(), true)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("event '{}' not found", event_id))?;
            let mut event: Event = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            mutator(&mut event)?;
            let new_bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
            txn.put(key.as_bytes(), &new_bytes).map_err(|e| e.to_string())?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Busy => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("event mutation conflict: retry budget exhausted".into())
    }

    pub fn record_deposit_atomic(
        &self,
        event_id: &str,
        option: u8,
        subaddress: &str,
        net_amount: u64,
    ) -> Result<(), String> {
        if self.is_subaddress_funded(subaddress)? {
            return Ok(());
        }
        self.mutate_event(event_id, |event| {
            // Hard guard: refuse to credit a non-Open event.
            if event.status != EventStatus::Open {
                return Err(format!(
                    "event '{}' is not Open (status={:?}); deposit dropped",
                    event_id, event.status
                ));
            }
            let pool = event.option_pools.entry(option).or_default();
            let prev = pool.insert(subaddress.to_string(), net_amount).unwrap_or(0);
            let delta = net_amount.checked_sub(prev)
                .ok_or("refusing negative-delta deposit")?;
            let total = event.pool_totals.entry(option).or_insert(0);
            *total = total.checked_add(delta)
                .ok_or("pool total overflow")?;
            Ok(())
        })?;
        // Funded marker — separate write, idempotent.
        let funded_key = format!("{}{}", PREFIX_FUNDED, subaddress);
        self.db.put(funded_key.as_bytes(), b"1").map_err(|e| e.to_string())
    }
}
```

Apply the same `mutate_event` wrapper inside `register_subaddress` and `settle_event_atomic`, both of which are otherwise vulnerable to symmetric races.

---

## Finding #3

**[VULNERABILITY ID: LOGIC — Silent RocksDB Error Bypasses Funded-Marker Idempotency]**

**Severity Score:** High (CVSS v3.1: 7.5 — `AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`)

`Ledger::is_subaddress_funded` (`db/mod.rs:169-172`) collapses every RocksDB error into "not funded":

```rust
pub fn is_subaddress_funded(&self, subaddress: &str) -> bool {
    let key = format!("{}{}", PREFIX_FUNDED, subaddress);
    self.db.get(key.as_bytes()).unwrap_or(None).is_some()
}
```

A transient `Err(IOError)` (compaction lock contention, cache eviction races, EBUSY, EAGAIN, partial CF corruption) returns `false`, telling the scanner the address has never been credited. The scanner then proceeds to `record_deposit_atomic` and the existing `option_pools[opt][addr]` entry is **replaced** by `insert`, while `pool_totals[opt]` is **incremented again** — see Finding #7 for the drift mechanics. Net effect: free credit on every transient read failure.

### Proof of Concept (PoC) Attack
1. Push the host into RocksDB compaction pressure (heavy concurrent writes during a snapshot).  Some `db.get` calls return `Err(IOError)`.
2. Scanner iteration N+1 re-encounters a transfer whose subaddress `S` is already funded on disk.
3. `is_subaddress_funded("S")` swallows the error and returns `false`.
4. `record_deposit_atomic` re-reads the event (containing `option_pools[opt]["S"] = old`), executes `insert("S", new)` (replaces) and `*total = total.checked_add(new)` (adds). The pool total is now `prev_total + new` while the per-subaddress map stores `new` — and **no** funded-marker write is needed because `unwrap_or(b"1")` already exists.

### The Remediation
Propagate read failures rather than treating them as authoritative `false`:

```rust
pub fn is_subaddress_funded(&self, subaddress: &str) -> Result<bool, String> {
    let key = format!("{}{}", PREFIX_FUNDED, subaddress);
    self.db
        .get(key.as_bytes())
        .map(|v| v.is_some())
        .map_err(|e| e.to_string())
}
```

In the scanner, treat any propagated error as "skip this transfer; retry next tick":
```rust
match self.ledger.is_subaddress_funded(&transfer.address) {
    Ok(true)  => continue,
    Ok(false) => { /* proceed to record_deposit_atomic */ }
    Err(e) => {
        eprintln!("[scanner] funded-marker read failed for {}: {}", transfer.address, e);
        continue;
    }
}
```

A read failure must never imply "go ahead and credit again."

---

## Finding #4

**[VULNERABILITY ID: CRYPTO — RPC Memory-Bomb via Unbounded JSON Body]**

**Severity Score:** High (CVSS v3.1: 7.5 — `AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H`)

`CryptoService::generate_subaddress` and `CryptoService::get_transfers` call `response.json::<T>().await` directly. The `reqwest::Client` is built with a 5-second total timeout but **no body-size cap**. The comment at `crypto/mod.rs:109-111` is misleading — `connection_verbose(false)` only toggles wire-level debug logging; it does not bound payload size.

Under the audit threat model (compromised local Monero Wallet RPC), the daemon can stream multi-GB JSON within the 5-second window, exhausting heap and aborting the scanner Tokio task.

### Proof of Concept (PoC) Attack
A compromised wallet RPC at `127.0.0.1:18083` answers `get_transfers`:

```text
HTTP/1.1 200 OK
Content-Type: application/json
Transfer-Encoding: chunked

{"jsonrpc":"2.0","id":"0","result":{"in":[<4 GiB of synthetic TransferEntry objects>],"pool":[]}}
```

`response.json::<GetTransfersRpcResponse>().await` allocates the entire body into a `Vec<u8>` and then into the deserialized struct → backend OOM. The scanner task aborts; the supervisor restart loop is itself irrelevant because the malicious node will trigger the same OOM on the next poll.

### The Remediation
Stream the body with a hard cap before deserialising, and remove the misleading `connection_verbose` comment:

```rust
use futures_util::StreamExt;

const MAX_RPC_BODY_BYTES: usize = 4 * 1024 * 1024; // 4 MiB ceiling

async fn read_capped_json<T: for<'de> serde::Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            eprintln!("[crypto] body read error: {e}");
            "Payment gateway temporarily unavailable".to_string()
        })?;
        if buf.len().saturating_add(chunk.len()) > MAX_RPC_BODY_BYTES {
            eprintln!(
                "[crypto] RPC body exceeded {MAX_RPC_BODY_BYTES} bytes — aborting"
            );
            return Err("Payment gateway temporarily unavailable".to_string());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<T>(&buf).map_err(|e| {
        eprintln!("[crypto] JSON parse error: {e}");
        "Payment gateway temporarily unavailable".to_string()
    })
}
```

Replace every `response.json::<T>().await` site in `crypto/mod.rs` with `read_capped_json::<T>(response).await`.

---

## Finding #5

**[VULNERABILITY ID: MATH — Compromised RPC Inflates Pool Totals → Escrow Over-Pay]**

**Severity Score:** Critical (CVSS v3.1: 9.0 — `AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:H`)

The scanner trusts every field of the `TransferEntry` returned by the RPC: `address`, `amount`, `confirmations`, `double_spend_seen`. There is no upper bound on `amount`, no cross-check against the daemon's chain state, and no reconciliation between *what the wallet claims to hold* and *what the engine plans to pay out*.

The audit threat model **explicitly assumes** a compromised node. Under that assumption a single fabricated transfer mints arbitrary balance against any subaddress the engine has ever issued, and the parimutuel engine — being mathematically correct — faithfully computes a payout proportional to the inflated contribution. The escrow then writes a payout map larger than the wallet's actual XMR holdings, and the operator drains real funds collected on **other** events into the attacker's wallet.

This is the single most direct realisation of the threat statement *"trick the Escrow service into sending more XMR than available in the pool."*

### Proof of Concept (PoC) Attack
1. Attacker (1) calls `POST /api/participate` for Event `X`, option `0`. The engine returns subaddress `S`. Attacker (1) deposits **0 XMR** — they never actually send anything.
2. Attacker (2) controls the wallet RPC (or sits between the engine and the wallet). On the next `get_transfers` poll, the malicious RPC returns one fabricated entry:
   ```json
   { "result": { "in": [{
       "address":            "<S>",
       "amount":             9000000000000000000,
       "confirmations":      100,
       "double_spend_seen":  false
   }], "pool": [] } }
   ```
3. Scanner credits `S` with `9e18 − 9e18/100 ≈ 8.91e18` piconeros. `pool_totals[0] = 8.91e18`.
4. Attacker (3, with leaked admin token) calls `POST /api/admin/events/X/resolve { "winning_option": 0 }`.
5. `EscrowService::resolve_event` calls `calculate_payouts(8.91e18, losing_total, {S: 8.91e18})` → `payouts[S] ≈ net_pool` (≈ 99 % of gross).
6. The operator/payout job reads `payouts:{X}` and submits an outbound `transfer` from the wallet — draining real XMR collected on every other concurrent event.

### The Remediation
Two layered defences. **Both** must ship — neither alone is sufficient.

**(a)** Per-transfer sanity cap in the scanner:

```rust
// services/scanner.rs
/// Maximum piconeros credited from a single transfer.  Tighter than the
/// XMR supply ceiling so a fabricated `amount` cannot inflate a pool past
/// the platform's real holdings.  Configurable via env in production.
const MAX_PICONEROS_PER_TRANSFER: u64 = 1_000 * 1_000_000_000_000; // 1 000 XMR

for transfer in &transfers {
    if transfer.double_spend_seen
        || transfer.confirmations < REQUIRED_CONFIRMATIONS
        || transfer.amount > MAX_PICONEROS_PER_TRANSFER
    {
        if transfer.amount > MAX_PICONEROS_PER_TRANSFER {
            eprintln!(
                "[scanner] transfer.amount {} > per-tx cap; dropped",
                transfer.amount
            );
        }
        continue;
    }
    // ... existing flow
}
```

**(b)** Wallet-balance reconciliation in `EscrowService::resolve_event`, **before** committing the payout map:

```rust
// crypto/mod.rs — new method (sketch; uses the same hardened JSON pattern)
pub async fn get_unlocked_balance(&self) -> Result<u64, String> {
    // RPC method "get_balance", account_index 0; parse `unlocked_balance` (u64)
    // through read_capped_json from Finding #4.
    /* ... */
}

// services/escrow.rs — augmented resolve_event
let total_payout: u64 = payouts
    .values()
    .try_fold(0_u64, |acc, &p| acc.checked_add(p))
    .ok_or_else(|| format!("payout sum overflow for event '{}'", event_id))?;

let on_hand = self.crypto
    .get_unlocked_balance()
    .await
    .map_err(|_| "wallet balance probe failed; settlement aborted".to_string())?;

if on_hand < total_payout {
    eprintln!(
        "[escrow] refusing settle: balance {} < payout {} for '{}'",
        on_hand, total_payout, event_id
    );
    return Err("insufficient wallet balance for declared payouts".to_string());
}
```

If the malicious RPC inflated `amount`, the wallet's *real* `unlocked_balance` will not cover `total_payout`, and the engine refuses to settle. No XMR moves.

---

## Finding #6

**[VULNERABILITY ID: LOGIC — Read-Modify-Write Race Across Three Mutator Paths]**

**Severity Score:** High (CVSS v3.1: 7.4 — `AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`)

Three call sites perform `read full event → mutate in memory → write full event back`, with **no** coordination among them:

| Call site                                    | Trigger                |
|----------------------------------------------|------------------------|
| `Ledger::register_subaddress` (`db:150`)     | `POST /api/participate` |
| `Ledger::record_deposit_atomic` (`db:181`)   | scanner background task |
| `Ledger::settle_event_atomic` (`db:82`)      | `POST /api/admin/.../resolve` |

The `WriteBatch` is atomic for the *final* writes only. The window between `get_event` and `db.write(batch)` is unprotected. Two concurrent participations on the same event silently lose one subaddress; a participation that races settlement can de-settle a finalised event (see also Finding #2).

### Proof of Concept (PoC) Attack
1. Two users (or one user via two HTTP/1.1 keep-alive connections) submit `POST /api/participate` for Event `X`, option `0`, simultaneously.
2. Both Axum handlers enter `register_subaddress` and call `get_event` — both observe the same `event` snapshot `E₀`.
3. Handler A sets `option_pools[0]["S_a"] = 0`; Handler B sets `option_pools[0]["S_b"] = 0`. Both write the full event back via `put_event`.
4. The later write wins: `option_pools[0]` contains either `{"S_a": 0}` or `{"S_b": 0}` — never both.
5. The losing user's wallet RPC still tracks their subaddress; their on-chain deposit credits the wallet but the scanner's `pending` index never sees the lost subaddress on subsequent ticks → funds are trapped in the wallet with no payout entry.

### The Remediation
Centralise every event read-modify-write through a single optimistic-transaction helper (see Finding #2's `mutate_event`). All three handlers become thin callers:

```rust
pub fn register_subaddress(
    &self,
    event_id: &str,
    option: u8,
    subaddress: &str,
) -> Result<(), String> {
    self.mutate_event(event_id, |event| {
        if event.status != EventStatus::Open {
            return Err(format!("event '{}' is not Open", event_id));
        }
        event.option_pools
            .entry(option)
            .or_default()
            .entry(subaddress.to_string())
            .or_insert(0);
        Ok(())
    })
}

pub fn settle_event_atomic(
    &self,
    event_id: &str,
    winning_option: u8,
    payouts: &HashMap<String, u64>,
) -> Result<(), String> {
    self.mutate_event(event_id, |event| {
        if event.status == EventStatus::Settled {
            return Err(format!(
                "double-spend prevention: event '{}' already settled",
                event_id
            ));
        }
        event.status = EventStatus::Settled;
        event.winning_option = Some(winning_option);
        Ok(())
    })?;
    let payouts_key = format!("{}{}", PREFIX_PAYOUTS, event_id);
    let payouts_bytes = serde_json::to_vec(payouts).map_err(|e| e.to_string())?;
    self.db.put(payouts_key.as_bytes(), &payouts_bytes).map_err(|e| e.to_string())
}
```

`get_for_update` inside `mutate_event` adds the event key to the optimistic-transaction's read set. A concurrent committer that touches the same key forces this transaction to rebuild on commit, eliminating lost writes deterministically.

---

## Finding #7

**[VULNERABILITY ID: MATH — Pool-Total / Option-Pool Drift in `record_deposit_atomic`]**

**Severity Score:** Medium (CVSS v3.1: 6.5 — `AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N`)

```rust
event.option_pools.entry(option).or_default()
    .insert(subaddress.to_string(), net_amount); // REPLACES previous value, return value discarded
let total = event.pool_totals.entry(option).or_insert(0);
*total = total.checked_add(net_amount)?;        // ADDS unconditionally
```

`HashMap::insert` returns the previous value when a key already existed; the code throws it away. If `record_deposit_atomic` ever runs for a subaddress with a non-zero existing entry — which is the **exact** outcome of the bypass in Finding #3 — the per-subaddress balance is **replaced** while the pool total is **incremented**. The two views drift permanently.

The downstream effect is subtle but real: `EscrowService::resolve_event` extracts `winning_pool_total` from `pool_totals`, while `winners_contributions` is read from `option_pools`. If they disagree, `calculate_payouts` computes a `net_pool` from the inflated total but distributes shares from the (correct, smaller) per-subaddress map. The sum of all winner payouts will **exceed** the actual sum of winner contributions — overpaying winners with funds drawn from the losing pool's actual deposits, plus possibly other events' funds when the wallet pays out.

### Proof of Concept (PoC) Attack
Combine with Finding #3:

1. Address `S` is already funded with `100` piconeros. `pool_totals[0] = 500` (across all winners).
2. RocksDB read pressure → `is_subaddress_funded("S")` returns `false` (Finding #3).
3. Scanner receives a (legitimate or fabricated) transfer for `S`, `amount = 200`. `net_amount = 198`.
4. `record_deposit_atomic` overwrites `option_pools[0]["S"] = 198` and adds 198 to the total → `pool_totals[0] = 698`.
5. Sum of `option_pools[0].values() = ... + 198` (without the original 100); `pool_totals[0] = 698 = 500 + 198`. Drift = 100 piconeros.
6. At settlement, `calculate_payouts(698, losing_total, option_pools[0])` distributes a `net_pool` derived from 698 across contributions summing to 598 → every winner is over-paid pro-rata; the operator's wallet pays out 100 piconeros that no one ever deposited.

### The Remediation
Use the previous value to update by *delta*, never blind-add:

```rust
let pool_for_option = event.option_pools.entry(option).or_default();
let previous = pool_for_option
    .insert(subaddress.to_string(), net_amount)
    .unwrap_or(0);
let delta = net_amount
    .checked_sub(previous)
    .ok_or_else(|| format!(
        "refusing negative-delta deposit for '{}' on event '{}'",
        subaddress, event_id
    ))?;

let total = event.pool_totals.entry(option).or_insert(0);
*total = total
    .checked_add(delta)
    .ok_or_else(|| format!("pool total overflow for event '{}'", event_id))?;
```

Combined with the strict funded-marker propagation (Finding #3) and the optimistic-transaction wrapper (Finding #6), the drift window collapses to zero.

---

## Finding #8

**[VULNERABILITY ID: CRYPTO — Path Disclosure in Startup Panic Strings]**

**Severity Score:** Low (CVSS v3.1: 4.3 — `AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N`)

Three startup panics embed sensitive operational detail directly in the panic payload (which is forwarded to any panic-hook crash reporter, supervisor log, or container stderr collector):

| Site                       | Leaks                                                                              |
|----------------------------|------------------------------------------------------------------------------------|
| `db/mod.rs:30`             | Full RocksDB ledger filesystem path **and** raw `rocksdb::Error` (file-lock paths) |
| `main.rs:64`               | UDS socket path                                                                    |
| `main.rs:76`               | UDS socket path **and** raw `bind` error                                           |
| `main.rs:33`               | Phrasing implies `ADMIN_TOKEN` was the missing env var (acceptable; informational) |

Combined with any unrelated log-disclosure bug (compromised observability stack, error-reporting webhook misrouted to attacker), these paths reveal the on-disk layout — useful for chained attacks.

### Proof of Concept (PoC) Attack
1. Backend is configured with `DATABASE_PATH=/srv/sicbox/ledger`. RocksDB's lock file is held by a stale process.
2. Engine starts, panics with `"FATAL: cannot open ledger at '/srv/sicbox/ledger': IO error: lock /srv/sicbox/ledger/LOCK: Resource temporarily unavailable"`.
3. The attacker, separately able to read crash-report stderr (e.g., misconfigured Sentry sink, log-aggregation IDOR), now knows the exact ledger directory and that RocksDB is the storage engine.
4. The attacker's next stage targets that path directly (e.g., via an unrelated LFI in a sidecar admin tool).

### The Remediation
Log full detail to local stderr, panic with a stable identifier:

```rust
// db/mod.rs
pub fn new(path: &str) -> Self {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open(&opts, path).unwrap_or_else(|e| {
        // Detail goes to local stderr only.
        eprintln!("[ledger] open failure: {}", e);
        // Panic payload is generic — never embeds the path or RocksDB error.
        panic!("FATAL: ledger initialisation failed");
    });
    Ledger { db }
}
```

```rust
// main.rs — apply the same split for the UDS-bind panics
let listener = UnixListener::bind(&socket_path).unwrap_or_else(|e| {
    eprintln!("[main] UDS bind error at {}: {}", socket_path, e);
    panic!("FATAL: cannot bind UDS");
});

if std::path::Path::new(&socket_path).exists() {
    std::fs::remove_file(&socket_path).unwrap_or_else(|e| {
        eprintln!("[main] cannot remove stale socket {}: {}", socket_path, e);
        panic!("FATAL: stale socket cleanup failed");
    });
}
```

Same principle applied to the `accept` panic (Finding #1) once it is converted to a continue-loop.

---

## Audit Closure — Items Verified Sound

The following are intentionally listed as *not findings*, so the next reviewer does not duplicate effort:

- **`engine/parimutuel.rs`** is exemplary: `checked_{add,sub,mul,div}` everywhere, explicit zero-pool guard, no floats, no panics. The arithmetic core is the strongest part of the codebase.
- **Constant-time admin-token comparison** in `api/admin_routes.rs::AdminAuth` is correct — length and byte equality are combined via bitwise `&` of two `subtle::Choice` values; the buffer is padded to `expected.len()` so the inner loop's iteration count is invariant.
- **`tower_http::limit::RequestBodyLimitLayer`** is applied to both routers (4 KiB admin, 2 KiB user), preventing oversized JSON DoS at the HTTP layer.
- **`serde(deny_unknown_fields)`** on every admin wire type rejects payload smuggling.
- **Server-generated `Uuid::new_v4()` event IDs** prevent admin-supplied identifiers from shadowing existing keys.
- **`MissedTickBehavior::Delay`** on the scanner's interval prevents catch-up bursts after a slow iteration.

The remaining risk surface is concentrated in the ledger's read-modify-write window and the unconditional trust placed in the wallet RPC's response payload — addressed by Findings #2, #3, #5, #6, and #7 above.
