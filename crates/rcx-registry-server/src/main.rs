//! `rcx-registry-server` binary.
//!
//! Boots the HTTP surface, runs embedded migrations, spawns the sync and
//! enrichment loops, and shuts everything down cleanly on SIGINT/SIGTERM.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rcx_registry_server::config::Config;
use rcx_registry_server::db;
use rcx_registry_server::db::mirror::PgMirrorStore;
use rcx_registry_server::db::publisher_enrichment::PgPublisherEnrichmentStore;
use rcx_registry_server::db::publisher_rights::PgPublisherRightsStore;
use rcx_registry_server::db::snapshots::{PgSnapshotArtifactStore, PgSnapshotStore};
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
        Some(vault) => {
            // Warn rather than abort: with a vault-agent sink the container and the
            // agent have no guaranteed start order, so an unreadable path at boot is
            // often a transient race. Aborting would turn it into a crash loop.
            if let Err(err) = vault.token.resolve() {
                tracing::warn!(
                    error = %err,
                    "vault token source is not readable at startup — signing will fail until it is"
                );
            }
            Arc::new(VaultTransitSigner::new(
                vault.addr.clone(),
                vault.token.clone(),
                vault.namespace.clone(),
                vault.key_name.clone(),
                config.signer.signer_kid.clone(),
            )?)
        }
        None => {
            tracing::warn!(
                "VAULT_ADDR is not set — receipts will be minted with zeroed signatures. \
                 This is only acceptable for local development."
            );
            Arc::new(UnsignedSigner::new(config.signer.signer_kid.clone()))
        }
    };

    // The key is resolved in the background rather than inline, because a
    // failure here is expected rather than exceptional: with a `vault-agent`
    // sink there is no guaranteed start order between the agent and this
    // process, and the token file is routinely unreadable for the first few
    // seconds. Reading it once at boot would turn that ordinary race into a
    // registry that publishes no key until somebody notices and restarts it.
    //
    // Until it resolves, the endpoint reports `unavailable` (retryable) rather
    // than an empty key list, so a caller polling for a key is never told the
    // registry is unsigned when it is merely not ready.
    let signing_keys = Arc::new(rcx_registry_api::SigningKeyPublication::default());
    let snapshot_artifacts: Arc<dyn rcx_registry_api::SnapshotArtifactStore> = Arc::new(
        PgSnapshotArtifactStore::new(snapshots.clone(), signing_keys.clone()),
    );

    let metrics = Metrics::new();
    let api_state = ApiStateBuilder {
        mirror: mirror_store.clone(),
        publisher_rights: publisher_rights.clone(),
        publisher_enrichment: publisher_enrichment.clone(),
        dns_resolver: Some(dns_resolver),
        github_oauth,
        snapshot_artifacts: Some(snapshot_artifacts),
    }
    .build();

    let health_state = HealthState {
        pool: pool.clone(),
        commit: COMMIT,
    };
    let router = server::build_router(api_state, health_state, metrics.clone());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(resolve_signing_key(
        signer.clone(),
        signing_keys,
        shutdown_rx.clone(),
    ));

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

/// Fill the signing-key slot, retrying until it succeeds.
///
/// Terminates on exactly two outcomes: the key is published, or the signer
/// reports it has none. Everything else is transient by assumption and retried
/// with capped backoff, because the common failure — a `vault-agent` sink that
/// has not written its token yet — resolves itself within seconds, and the less
/// common one (Vault down) resolves itself within hours. Neither should require
/// an operator to restart the registry to get a key published.
async fn resolve_signing_key(
    signer: Arc<dyn Signer>,
    publication: Arc<rcx_registry_api::SigningKeyPublication>,
    mut shutdown: watch::Receiver<bool>,
) {
    const FIRST_DELAY: Duration = Duration::from_secs(2);
    const MAX_DELAY: Duration = Duration::from_secs(300);

    let mut delay = FIRST_DELAY;
    let mut attempts: u32 = 0;

    loop {
        if *shutdown.borrow() {
            return;
        }

        let probe = signer.clone();
        // `public_key` uses a blocking HTTP client; calling it directly on the
        // async runtime would panic.
        let outcome = tokio::task::spawn_blocking(move || probe.public_key()).await;
        attempts += 1;

        match outcome {
            Ok(Ok(Some(key))) => {
                publication.publish(vec![rcx_registry_api::PublishedSigningKey::ed25519(
                    signer.signer_kid(),
                    key,
                )]);
                tracing::info!(
                    signer_kid = signer.signer_kid(),
                    attempts,
                    "signing public key published — receipts are now independently verifiable"
                );
                return;
            }
            Ok(Ok(None)) => {
                // Terminal: there is no key, so retrying would never produce one
                // and the endpoint should say so rather than say "try later".
                publication.mark_unsigned();
                tracing::warn!(
                    "signer exposes no public key — this registry is unsigned and its receipts \
                     cannot be verified by a third party"
                );
                return;
            }
            Ok(Err(error)) => {
                // Loud once, quiet after. A vault-agent race is normal at boot
                // and should not look like an incident; a persistent outage
                // should still leave a trail.
                if attempts == 1 {
                    tracing::warn!(error = %error, "could not read the signing public key yet — retrying");
                } else {
                    tracing::debug!(error = %error, attempts, "signing public key still unreadable");
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "signing key probe task failed");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
        delay = (delay * 2).min(MAX_DELAY);
    }
}
