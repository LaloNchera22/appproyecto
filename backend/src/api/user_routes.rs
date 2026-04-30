// backend/src/api/user_routes.rs
use ax_um::{routing::get, Json, Router, extract::State};
use std::sync::Arc;
use crate::AppState;
use crate::models::Tournament;

pub fn user_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/tournaments", get(list_tournaments))
}

async fn list_tournaments(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<Tournament>> {
    // Zero-Trust: Data is pulled directly from the local ledger, no external cache
    let tournaments = state.tournament_service.get_active_tournaments();
    Json(tournaments)
}
