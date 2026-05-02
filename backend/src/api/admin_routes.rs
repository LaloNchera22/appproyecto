// backend/src/api/admin_routes.rs
//
// Zero-Trust administrative API for parimutuel event lifecycle management.
//
// Authorization model
// -------------------
// A single static bearer token loaded from the `ADMIN_TOKEN` environment
// variable at process start.  Every request to this router must carry an
// `Authorization: Bearer <token>` header whose value matches the configured
// token under a constant-time comparison from the `subtle` crate.
//
// Any authentication failure — missing header, malformed prefix, length
// mismatch, or value mismatch — is collapsed into the same opaque
// `401 Unauthorized` response.  Internal error detail (RocksDB / engine
// messages) is never leaked to the caller; it is logged to stderr only.

use std::sync::Arc;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

use crate::models::Event;
use crate::AppState;

// ---------------------------------------------------------------------------
// Hard limits
// ---------------------------------------------------------------------------

/// Whole-request body ceiling.  Enforced via Tower so over-sized payloads are
/// rejected with `413 Payload Too Large` before any handler executes.
const BODY_LIMIT_BYTES: usize = 4 * 1024;

/// Maximum permitted length for any user-supplied string (event title or
/// option label).  Defends the ledger against bloat from oversized values
/// and protects the JSON parser against amplification attacks.
const MAX_STRING_LEN: usize = 200;

/// Minimum number of options for a valid parimutuel event.
const MIN_OPTIONS: usize = 2;

/// Sanity ceiling on the option count.  The on-disk index type is `u8`,
/// but a far smaller cap keeps validation costs and ledger size predictable.
const MAX_OPTIONS: usize = 32;

// ---------------------------------------------------------------------------
// Wire types — all use `deny_unknown_fields` so unexpected payload keys are
// rejected outright rather than silently ignored.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEventRequest {
    title: String,
    options: Vec<String>,
}

#[derive(Serialize)]
struct CreateEventResponse {
    event_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    winning_option: u8,
}

#[derive(Serialize)]
struct GenericError {
    error: &'static str,
}

// ---------------------------------------------------------------------------
// Auth extractor
// ---------------------------------------------------------------------------

/// Type-level proof that the caller supplied a valid bearer token.
/// Carries no data — its mere presence in a handler signature is the
/// guarantee that authentication succeeded.
struct AdminAuth;

/// The single, opaque 401 response returned for every authentication
/// failure.  Body shape and length are fixed so response-size differential
/// analysis cannot be used to enumerate which check rejected the request.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(GenericError {
            error: "Unauthorized",
        }),
    )
        .into_response()
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AdminAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Default to an empty slice on every "header missing / malformed"
        // path so the constant-time comparison below always executes,
        // keeping the timing of the 401 path uniform regardless of which
        // check failed.
        let presented: &[u8] = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::as_bytes)
            .unwrap_or(b"");

        let expected: &[u8] = state.admin_token.as_bytes();

        // `subtle::ConstantTimeEq::ct_eq` for `[u8]` short-circuits on a
        // length mismatch.  Pad the presented value into a buffer of the
        // expected length so the inner byte-by-byte loop always runs in
        // time independent of the supplied length.
        let mut padded = vec![0u8; expected.len()];
        let n = presented.len().min(expected.len());
        padded[..n].copy_from_slice(&presented[..n]);

        // Combine "length matches" and "bytes match" into a single Choice
        // using bitwise AND.  Short-circuit evaluation is intentionally
        // avoided so timing is invariant to which condition would fail.
        let length_eq = (presented.len() as u64).ct_eq(&(expected.len() as u64));
        let bytes_eq = padded.ct_eq(expected);
        let ok: bool = (length_eq & bytes_eq).into();

        if ok {
            Ok(AdminAuth)
        } else {
            Err(unauthorized())
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/events", post(create_event))
        .route("/api/admin/events/:event_id/resolve", post(resolve_event))
        // Hard cap on body size — Tower returns 413 before the handler runs.
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/admin/events`
///
/// Strictly validates the inbound payload and persists a new `Open` event.
/// The event identifier is a server-generated v4 UUID so admin-supplied
/// strings cannot be used to overwrite or shadow an existing record.
async fn create_event(
    _: AdminAuth,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateEventRequest>,
) -> Result<(StatusCode, Json<CreateEventResponse>), (StatusCode, Json<GenericError>)> {
    let bad = |code: StatusCode, msg: &'static str| (code, Json(GenericError { error: msg }));

    // ---- Input validation -------------------------------------------------
    let title = payload.title.trim();
    if title.is_empty() || title.len() > MAX_STRING_LEN {
        return Err(bad(StatusCode::BAD_REQUEST, "Invalid event payload"));
    }

    if payload.options.len() < MIN_OPTIONS || payload.options.len() > MAX_OPTIONS {
        return Err(bad(StatusCode::BAD_REQUEST, "Invalid event payload"));
    }

    // Reject empty / oversized / duplicate option labels.  Duplicates would
    // create an ambiguous settlement model where two indices share an outcome.
    let mut seen: Vec<&str> = Vec::with_capacity(payload.options.len());
    for opt in &payload.options {
        let trimmed = opt.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_STRING_LEN || seen.contains(&trimmed) {
            return Err(bad(StatusCode::BAD_REQUEST, "Invalid event payload"));
        }
        seen.push(trimmed);
    }

    // ---- Build event record ----------------------------------------------
    let event_id = Uuid::new_v4().to_string();
    let mut event = Event::new(&event_id);

    // Pre-allocate one empty pool per option index so the option count is
    // recoverable from the ledger after a restart.  Indices `0..options.len()`
    // correspond to the order of the original `options` array.
    for idx in 0..payload.options.len() {
        let key = idx as u8;
        event.option_pools.insert(key, Default::default());
        event.pool_totals.insert(key, 0);
    }

    state.ledger.put_event(&event).map_err(|e| {
        // Internal-only logging; never echo RocksDB error text to the caller.
        eprintln!("[admin] put_event failed for '{}': {}", event_id, e);
        bad(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateEventResponse { event_id }),
    ))
}

/// `POST /api/admin/events/{event_id}/resolve`
///
/// Triggers parimutuel settlement for an existing event.  Delegates to
/// `EscrowService::resolve_event`, which is itself idempotent — a second
/// resolution call on an already-settled event is rejected without
/// recomputing payouts.
async fn resolve_event(
    _: AdminAuth,
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
    Json(payload): Json<ResolveRequest>,
) -> Result<StatusCode, (StatusCode, Json<GenericError>)> {
    // Defence-in-depth: refuse pathological identifiers before touching
    // RocksDB or echoing anything to the client.
    if event_id.is_empty() || event_id.len() > MAX_STRING_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GenericError {
                error: "Invalid request",
            }),
        ));
    }

    state
        .escrow
        .resolve_event(&event_id, payload.winning_option)
        .await
        .map_err(|e| {
            // Internal-only logging.  Engine and RocksDB messages are never
            // echoed to the caller — they could reveal ledger invariants
            // or internal key shapes useful for enumeration.
            eprintln!(
                "[admin] resolve_event failed for '{}': {}",
                event_id, e
            );
            (
                StatusCode::BAD_REQUEST,
                Json(GenericError {
                    error: "Resolution failed",
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
