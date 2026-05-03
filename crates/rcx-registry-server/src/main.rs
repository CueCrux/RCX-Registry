//! `rcx-registry-server` binary.
//!
//! Boots the HTTP surface, runs embedded migrations, spawns the sync and
//! enrichment loops, and shuts everything down cleanly on SIGINT/SIGTERM.

use std::process::ExitCode;
use std::sync::Arc;

use rcx_registry_server::config::Config;
use rcx_registry_server::db;
use rcx_registry_server::db::mirror::PgMirrorStore;
use rcx_registry_server::db::publisher_enrichment::PgPublisherEnrichmentStore;
use rcx_registry_server::db::publisher_rights::PgPublisherRightsStore;
use rcx_registry_server::db::snapshots::PgSnapshotStore;
use rcx_registry_server::dns::HickoryDnsTxtResolver;
use rcx_registry_server::github_oauth::GitHubOAuthClient;
use rcx_registry_server::health::HealthState;
use rcx_registry_server::loops;
use rcx_registry_server::metrics::Metrics;
use rcx_registry_server::server::{self, ApiStateBuilder};
use rcx_registry_server::vault::{Signer, UnsignedSigner, VaultTransitSigner};
use tokio::signal;
use tokio::sync::watch;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const COMMIT: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> ExitCode {
    let _ = dotenvy::dotenv();
    init_tracing();

    if let Err(error) = run().await {
        tracing::error!(error = %error, "rcx-registry-server exiting with error");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env()?;

    let pool = db::build_pool(&config.database_url)?;
    if config.run_migrations {
        let pool_for_migrations = pool.clone();
        let applied =
            tokio::task::spawn_blocking(move || db::migrations::run(&pool_for_migrations))
                .await??;
        if applied.is_empty() {
            tracing::info!("no pending migrations");
        } else {
            tracing::info!(applied = ?applied, "migrations applied");
        }
    }

    let mirror_store: Arc<PgMirrorStore> = Arc::new(PgMirrorStore::new(pool.clone()));
    let publisher_rights: Arc<PgPublisherRightsStore> =
        Arc::new(PgPublisherRightsStore::new(pool.clone()));
    let publisher_enrichment: Arc<PgPublisherEnrichmentStore> =
        Arc::new(PgPublisherEnrichmentStore::new(pool.clone()));
    let snapshots = PgSnapshotStore::new(pool.clone());

    let dns_resolver: Arc<dyn rcx_registry_api::DnsTxtResolver> = if config.dns.use_system_resolver
    {
        Arc::new(HickoryDnsTxtResolver::system()?)
    } else {
        Arc::new(HickoryDnsTxtResolver::cloudflare()?)
    };
    let github_oauth: Option<Arc<dyn rcx_registry_api::GitHubOAuthProvider>> =
        match &config.github_oauth {
            Some(oauth) => Some(Arc::new(GitHubOAuthClient::new(
                oauth.client_id.clone(),
                oauth.client_secret.clone(),
                oauth.scope.clone(),
            )?)),
            None => None,
        };

    let signer: Arc<dyn Signer> = match &config.signer.vault {
        Some(vault) => Arc::new(VaultTransitSigner::new(
            vault.addr.clone(),
            vault.token.clone(),
            vault.namespace.clone(),
            vault.key_name.clone(),
            config.signer.signer_kid.clone(),
        )?),
        None => {
            tracing::warn!(
                "VAULT_ADDR is not set — receipts will be minted with zeroed signatures. \
                 This is only acceptable for local development."
            );
            Arc::new(UnsignedSigner::new(config.signer.signer_kid.clone()))
        }
    };

    let metrics = Metrics::new();
    let api_state = ApiStateBuilder {
        mirror: mirror_store.clone(),
        publisher_rights: publisher_rights.clone(),
        publisher_enrichment: publisher_enrichment.clone(),
        dns_resolver: Some(dns_resolver),
        github_oauth,
    }
    .build();

    let health_state = HealthState {
        pool: pool.clone(),
        commit: COMMIT,
    };
    let router = server::build_router(api_state, health_state, metrics.clone());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let sync_deps = loops::sync::SyncDeps {
        mirror: PgMirrorStore::new(pool.clone()),
        snapshots,
        signer: signer.clone(),
        metrics: metrics.clone(),
    };
    let enrich_deps = loops::enrich::EnrichDeps {
        pool: pool.clone(),
        publisher_rights_store: publisher_rights.clone(),
        publisher_enrichment_store: publisher_enrichment.clone(),
        signer: signer.clone(),
        metrics: metrics.clone(),
    };

    let sync_handle = if config.feature_flags.feature_rcx_registry {
        Some(tokio::spawn(loops::sync::run(
            config.mcp.clone(),
            sync_deps,
            shutdown_rx.clone(),
        )))
    } else {
        tracing::info!(
            "FEATURE_RCX_REGISTRY=false — MCP sync loop NOT started; serving MCP-mirror baseline only"
        );
        None
    };
    let enrich_handle = if config.feature_flags.publisher_declarations {
        Some(tokio::spawn(loops::enrich::run(
            loops::enrich::DEFAULT_REFRESH_CADENCE,
            enrich_deps,
            shutdown_rx.clone(),
        )))
    } else {
        tracing::info!(
            "FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS=false — declaration refresh loop NOT started"
        );
        None
    };

    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received");
        let _ = shutdown_tx.send(true);
    });

    server::serve(&config, router, pool, shutdown_rx).await?;

    if let Some(handle) = sync_handle {
        let _ = handle.await;
    }
    if let Some(handle) = enrich_handle {
        let _ = handle.await;
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use signal::unix::{signal as unix_signal, SignalKind};
        let mut sigterm =
            unix_signal(SignalKind::terminate()).expect("install SIGTERM handler should not fail");
        let mut sigint =
            unix_signal(SignalKind::interrupt()).expect("install SIGINT handler should not fail");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}
