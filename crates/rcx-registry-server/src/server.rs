//! Composes the API router with health + metrics routes, builds the
//! state object the API crate expects, and exposes a shutdown-capable
//! `serve` entry point.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use rcx_registry_api::{
    router_with_state, ApiState, GitHubOAuthProvider, MirrorStore, PublisherEnrichmentStore,
    PublisherRightsStore, UnavailableDnsTxtResolver, UnavailableGitHubOAuthProvider,
};
use tokio::sync::watch;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::Config;
use crate::db::PgPool;
use crate::health::{self, HealthState};
use crate::metrics::{self, Metrics};

/// Wires together the full HTTP surface — API routes from
/// `rcx-registry-api`, plus this crate's `/healthz`, `/readyz`, and
/// `/metrics` operator routes.
pub fn build_router(
    api_state: ApiState,
    health_state: HealthState,
    metrics: Arc<Metrics>,
) -> Router {
    let api = router_with_state(api_state);
    let health_routes: Router = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .with_state(Arc::new(health_state));
    let metrics_routes: Router = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(metrics);
    Router::new()
        .merge(api)
        .merge(health_routes)
        .merge(metrics_routes)
        .layer(TraceLayer::new_for_http())
}

/// Compose [`ApiState`] from concrete store + provider impls. When
/// optional providers are absent, falls back to the `Unavailable*` 503
/// stubs so the route still exists.
pub struct ApiStateBuilder {
    pub mirror: Arc<dyn MirrorStore>,
    pub publisher_rights: Arc<dyn PublisherRightsStore>,
    pub publisher_enrichment: Arc<dyn PublisherEnrichmentStore>,
    pub dns_resolver: Option<Arc<dyn rcx_registry_api::DnsTxtResolver>>,
    pub github_oauth: Option<Arc<dyn GitHubOAuthProvider>>,
}

impl ApiStateBuilder {
    pub fn build(self) -> ApiState {
        let mut state = ApiState::new(self.mirror)
            .with_publisher_rights_store(self.publisher_rights)
            .with_publisher_enrichment_store(self.publisher_enrichment);
        state = match self.dns_resolver {
            Some(resolver) => state.with_dns_resolver(resolver),
            None => state.with_dns_resolver(Arc::new(UnavailableDnsTxtResolver)),
        };
        state = match self.github_oauth {
            Some(provider) => state.with_github_oauth_provider(provider),
            None => state.with_github_oauth_provider(Arc::new(UnavailableGitHubOAuthProvider)),
        };
        state
    }
}

/// Bind + serve, with cooperative shutdown.
pub async fn serve(
    config: &Config,
    router: Router,
    pool: PgPool,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    info!(addr = %config.bind_addr, "rcx-registry-server listening");
    let _ = pool;
    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
}

async fn shutdown_signal(mut shutdown: watch::Receiver<bool>) {
    let _ = shutdown.changed().await;
}
