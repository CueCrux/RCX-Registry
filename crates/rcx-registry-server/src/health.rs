//! `/healthz` and `/readyz` endpoints.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::db::PgPool;

#[derive(Clone)]
pub struct HealthState {
    pub pool: PgPool,
    pub commit: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub component: &'static str,
    pub commit: &'static str,
}

/// Liveness — always 200 if the process is up.
pub async fn healthz(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            component: "rcx-registry-server",
            commit: state.commit,
        }),
    )
}

/// Readiness — 200 only if the Postgres pool can hand out a connection.
pub async fn readyz(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let pool = state.pool.clone();
    let result = tokio::task::spawn_blocking(move || pool.get().map(|_| ()))
        .await
        .map_err(|error| error.to_string())
        .and_then(|inner| inner.map_err(|error| error.to_string()));
    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ready",
                component: "rcx-registry-server",
                commit: state.commit,
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "unready",
                "component": "rcx-registry-server",
                "error": error,
            })),
        )
            .into_response(),
    }
}
