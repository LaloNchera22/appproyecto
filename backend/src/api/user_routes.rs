// backend/src/api/user_routes.rs
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tower_http::limit::RequestBodyLimitLayer;

use crate::models::EventStatus;
use crate::AppState;

// 2 KB hard ceiling on all request bodies for this router.
// Prevents memory-exhaustion attacks from oversized JSON payloads.
const BODY_LIMIT_BYTES: usize = 2 * 1024;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ParticipateRequest {
    event_id: String,
    option: u8,
}

/// Sanitized public view of an event.
///
/// Deliberately omits raw ledger keys, participant subaddresses, and any
/// internal identifiers — only the data a user needs to make a bet decision
/// is exposed.
#[derive(Serialize)]
struct EventView {
    /// The event's own logical identifier (not the RocksDB key prefix).
    event_id: String,
    /// Aggregate piconeros committed to each option index.
    pool_totals: HashMap<u8, u64>,
}

#[derive(Serialize)]
struct ParticipateResponse {
    deposit_address: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn user_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/events", get(list_open_events))
        .route("/api/participate", post(participate))
        // Hard body-size ceiling applied to the entire sub-router.
        // Returns 413 Payload Too Large before the handler is reached.
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list_open_events(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<EventView>> {
    let views = state
        .ledger
        .get_open_events()
        .into_iter()
        .map(|e| EventView {
            event_id: e.id,
            pool_totals: e.pool_totals,
        })
        .collect();
    Json(views)
}

async fn participate(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ParticipateRequest>,
) -> Result<Json<ParticipateResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Zero-Trust: collapse "not found" and "not open" into the same 400 so
    // callers cannot enumerate which event IDs exist in the ledger.
    let valid = state
        .ledger
        .get_event(&payload.event_id)
        .map(|e| e.status == EventStatus::Open && e.pool_totals.contains_key(&payload.option))
        .unwrap_or(false);

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid or closed event",
            }),
        ));
    }

    let address = state
        .crypto
        .generate_subaddress(&payload.event_id)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Payment gateway temporarily unavailable",
                }),
            )
        })?;

    Ok(Json(ParticipateResponse {
        deposit_address: address,
    }))
}
