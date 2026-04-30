// backend/src/api/admin_routes.rs
use axum::{routing::post, Json, Router, extract::State};
use crate::AppState;
use crate::models::BetGroup;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub tournament_id: String,
    pub winner: BetGroup,
}

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/resolve", post(handle_resolve))
}

async fn handle_resolve(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResolveRequest>,
) -> Json<String> {
    match state.admin.resolve_event(&payload.tournament_id, payload.winner).await {
        Ok(_) => Json("Success: Tournament settled and locked.".into()),
        Err(e) => Json(format!("Error: {}", e)),
    }
}
