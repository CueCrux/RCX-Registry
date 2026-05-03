//! Prometheus metrics — hand-rolled exposition; no `metrics` crate
//! dependency to keep the dependency footprint small for v1.0.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::header::CONTENT_TYPE;
use http::StatusCode;

#[derive(Default)]
pub struct Metrics {
    pub mcp_servers_mirrored: AtomicU64,
    pub mcp_fetch_errors_total: AtomicU64,
    pub snapshots_total: AtomicU64,
    pub publisher_declarations_total: AtomicU64,
    pub publisher_declaration_errors_total: AtomicU64,
    pub auto_enrichment_rows: AtomicU64,
    pub publisher_rights_verified_total: AtomicU64,
    pub sync_loop_runs_total: AtomicU64,
    pub sync_loop_errors_total: AtomicU64,
    pub enrichment_loop_runs_total: AtomicU64,
    pub enrichment_loop_errors_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        write_metric(
            &mut out,
            "rcx_registry_mcp_servers_mirrored",
            "gauge",
            "Number of MCP servers currently mirrored.",
            &self.mcp_servers_mirrored,
        );
        write_metric(
            &mut out,
            "rcx_registry_mcp_fetch_errors_total",
            "counter",
            "Total number of upstream MCP fetch errors observed.",
            &self.mcp_fetch_errors_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_snapshots_total",
            "counter",
            "Total number of MCP registry snapshots minted.",
            &self.snapshots_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_publisher_declarations_total",
            "counter",
            "Total number of publisher declarations accepted.",
            &self.publisher_declarations_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_publisher_declaration_errors_total",
            "counter",
            "Total number of publisher declarations rejected during validation.",
            &self.publisher_declaration_errors_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_auto_enrichment_rows",
            "gauge",
            "Number of auto-enrichment rows persisted.",
            &self.auto_enrichment_rows,
        );
        write_metric(
            &mut out,
            "rcx_registry_publisher_rights_verified_total",
            "counter",
            "Total number of publisher-rights verifications minted.",
            &self.publisher_rights_verified_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_sync_loop_runs_total",
            "counter",
            "Total number of MCP sync loop runs.",
            &self.sync_loop_runs_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_sync_loop_errors_total",
            "counter",
            "Total number of MCP sync loop errors.",
            &self.sync_loop_errors_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_enrichment_loop_runs_total",
            "counter",
            "Total number of enrichment loop runs.",
            &self.enrichment_loop_runs_total,
        );
        write_metric(
            &mut out,
            "rcx_registry_enrichment_loop_errors_total",
            "counter",
            "Total number of enrichment loop errors.",
            &self.enrichment_loop_errors_total,
        );
        out
    }
}

fn write_metric(out: &mut String, name: &str, kind: &str, help: &str, value: &AtomicU64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.load(Ordering::Relaxed).to_string());
    out.push('\n');
}

pub async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> Response {
    let body = metrics.render_prometheus();
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::Metrics;
    use std::sync::atomic::Ordering;

    #[test]
    fn render_lists_all_documented_series() {
        let metrics = Metrics::new();
        metrics.mcp_servers_mirrored.store(5, Ordering::Relaxed);
        metrics.snapshots_total.store(2, Ordering::Relaxed);
        let body = metrics.render_prometheus();

        assert!(body.contains("# TYPE rcx_registry_mcp_servers_mirrored gauge"));
        assert!(body.contains("rcx_registry_mcp_servers_mirrored 5"));
        assert!(body.contains("# TYPE rcx_registry_snapshots_total counter"));
        assert!(body.contains("rcx_registry_snapshots_total 2"));
        assert!(body.contains("rcx_registry_mcp_fetch_errors_total"));
        assert!(body.contains("rcx_registry_publisher_declarations_total"));
        assert!(body.contains("rcx_registry_publisher_rights_verified_total"));
    }
}
