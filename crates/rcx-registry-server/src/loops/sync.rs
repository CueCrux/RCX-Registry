//! MCP scrape sync loop.
//!
//! Fetches every page from the upstream MCP registry on a configurable
//! cadence, computes a deterministic Merkle root, reconciles against the
//! prior snapshot, persists added/modified rows, marks removed ones for
//! soft-delete, and mints a `RegistrySnapshot` receipt.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::Utc;
use rcx_registry_crown::{ReceiptDocument, ULID_LEN};
use rcx_registry_ingest::{
    build_snapshot_plan, canonical_server_hash, schema_date_from_uri, FetchPageResult,
    ListServersRequest, McpRegistryClient, MirroredServer, RegistryServerEnvelope,
    RegistryServerListResponse, SnapshotDiff, SnapshotPlan, SyncCadencePolicy,
    SOFT_DELETE_RETENTION,
};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::watch;
use tokio::time::sleep;

use crate::config::McpConfig;
use crate::db::mirror::{PgMirrorStore, UpsertServer};
use crate::db::snapshots::{PgSnapshotStore, StoredSnapshot};
use crate::metrics::Metrics;
use crate::vault::{Signer, VaultError};

const MAX_PAGES_PER_RUN: usize = 1000;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("ingest: {0}")]
    Ingest(#[from] rcx_registry_ingest::IngestError),
    #[error("db: {0}")]
    Db(#[from] crate::db::DbError),
    #[error("vault: {0}")]
    Vault(#[from] VaultError),
    #[error("server entry missing field `{0}`")]
    Field(&'static str),
}

#[derive(Clone)]
pub struct SyncDeps {
    pub mirror: PgMirrorStore,
    pub snapshots: PgSnapshotStore,
    pub signer: Arc<dyn Signer>,
    pub metrics: Arc<Metrics>,
}

pub async fn run(config: McpConfig, deps: SyncDeps, mut shutdown: watch::Receiver<bool>) {
    let mut last_run: Option<SystemTime> = None;
    let mut last_diff = SnapshotDiff {
        added: Vec::new(),
        removed: Vec::new(),
        modified: Vec::new(),
        unchanged: Vec::new(),
    };
    let policy = SyncCadencePolicy {
        target_interval: config.sync_interval,
        min_interval_floor: config.min_interval_floor,
        ..SyncCadencePolicy::default()
    };

    loop {
        let due = match last_run {
            None => SystemTime::now(),
            Some(prior) => policy.next_run_at(prior, &last_diff),
        };
        let now = SystemTime::now();
        let delay = due.duration_since(now).unwrap_or(Duration::ZERO);
        if delay > Duration::ZERO {
            tokio::select! {
                _ = sleep(delay) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
        if *shutdown.borrow() {
            return;
        }

        let outcome = tick(&config, deps.clone()).await;
        deps.metrics
            .sync_loop_runs_total
            .fetch_add(1, Ordering::Relaxed);
        match outcome {
            Ok(diff) => {
                last_diff = diff;
                last_run = Some(SystemTime::now());
            }
            Err(error) => {
                deps.metrics
                    .sync_loop_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                deps.metrics
                    .mcp_fetch_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %error, "mcp sync tick failed");
                last_run = Some(SystemTime::now());
            }
        }
    }
}

async fn tick(config: &McpConfig, deps: SyncDeps) -> Result<SnapshotDiff, SyncError> {
    let base_url = config.base_url.clone();
    let signer = deps.signer.clone();
    let mirror = deps.mirror.clone();
    let snapshots = deps.snapshots.clone();
    let metrics = deps.metrics.clone();

    tokio::task::spawn_blocking(move || {
        run_tick_blocking(&base_url, &mirror, &snapshots, signer.as_ref(), &metrics)
    })
    .await
    .expect("sync tick join should not panic")
}

fn run_tick_blocking(
    base_url: &str,
    mirror: &PgMirrorStore,
    snapshots: &PgSnapshotStore,
    signer: &dyn Signer,
    metrics: &Metrics,
) -> Result<SnapshotDiff, SyncError> {
    let client = McpRegistryClient::new(base_url)?;
    let envelopes = fetch_all_pages(&client)?;

    let mut current_mirrored = Vec::with_capacity(envelopes.len());
    for envelope in &envelopes {
        let mirrored =
            MirroredServer::from_envelope(envelope, &rcx_registry_ingest::NoopSchemaCatalog)?;
        current_mirrored.push((envelope, mirrored));
    }

    let prior_snapshot = snapshots.latest()?;
    let snapshot_id = derive_ulid_from_now();
    let event_id = derive_ulid_from_seed(&format!(
        "snapshot:{}:{}",
        Utc::now().timestamp_millis(),
        current_mirrored.len()
    ));
    let prior_hash = prior_snapshot.as_ref().map(|prior| prior.snapshot_hash);
    let scraped_at_ms = Utc::now().timestamp_millis().max(0) as u64;

    let plan = build_snapshot_plan(
        &current_mirrored
            .iter()
            .map(|(_, mirrored)| mirrored.clone())
            .collect::<Vec<_>>(),
        &[], // we keep the per-server diff at the row level — not needed for receipt content
        event_id,
        snapshot_id,
        scraped_at_ms,
        prior_hash,
        None,
        signer.signer_kid(),
    );

    persist_changes(mirror, &plan, &current_mirrored)?;

    let diff = compute_full_diff(mirror, &current_mirrored)?;
    reconcile_soft_deletes_blocking(mirror, &current_mirrored)?;

    persist_snapshot(snapshots, &plan, signer)?;
    metrics
        .mcp_servers_mirrored
        .store(current_mirrored.len() as u64, Ordering::Relaxed);
    metrics.snapshots_total.fetch_add(1, Ordering::Relaxed);

    tracing::info!(
        mirrored = current_mirrored.len(),
        added = diff.added.len(),
        removed = diff.removed.len(),
        modified = diff.modified.len(),
        unchanged = diff.unchanged.len(),
        "mcp sync tick complete"
    );

    Ok(diff)
}

fn fetch_all_pages(
    client: &McpRegistryClient,
) -> Result<Vec<RegistryServerEnvelope>, rcx_registry_ingest::IngestError> {
    let mut envelopes = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES_PER_RUN {
        let request = ListServersRequest {
            cursor: cursor.clone(),
            limit: Some(rcx_registry_ingest::MAX_PAGE_LIMIT),
            ..ListServersRequest::default()
        };
        let FetchPageResult { page, .. } = client.fetch_servers_page(&request, None)?;
        let Some(RegistryServerListResponse {
            mut servers,
            metadata,
        }) = page
        else {
            break;
        };
        envelopes.append(&mut servers);
        match metadata.next_cursor {
            Some(next) if !next.is_empty() => {
                cursor = Some(next);
            }
            _ => break,
        }
    }
    Ok(envelopes)
}

fn persist_changes(
    mirror: &PgMirrorStore,
    plan: &SnapshotPlan,
    current: &[(&RegistryServerEnvelope, MirroredServer)],
) -> Result<(), SyncError> {
    let observed_in_snapshot = plan.snapshot_receipt.snapshot_id;
    let observed_at = Utc::now();
    for (envelope, mirrored) in current {
        let upstream_hash = canonical_server_hash(mirrored);
        let server_json = envelope
            .server
            .as_object()
            .map(|_| envelope.server.clone())
            .unwrap_or(Value::Object(Default::default()));
        let schema_date =
            schema_date_from_uri(&mirrored.schema_uri).unwrap_or_else(|_| String::new());
        mirror.upsert_server(UpsertServer {
            name: &mirrored.name,
            version: &mirrored.version,
            status: &mirrored.status,
            schema_date: &schema_date,
            is_latest: mirrored.is_latest,
            upstream_hash,
            envelope,
            server_json: &server_json,
            observed_in_snapshot,
            observed_at,
        })?;
    }
    Ok(())
}

fn compute_full_diff(
    mirror: &PgMirrorStore,
    current: &[(&RegistryServerEnvelope, MirroredServer)],
) -> Result<SnapshotDiff, SyncError> {
    let cached = mirror.cached_state()?;
    let cached_names: std::collections::BTreeSet<String> =
        cached.into_iter().map(|(name, _)| name).collect();
    let current_names: std::collections::BTreeSet<String> = current
        .iter()
        .map(|(_, mirrored)| mirrored.name.clone())
        .collect();

    let added = current_names
        .difference(&cached_names)
        .cloned()
        .collect::<Vec<_>>();
    let removed = cached_names
        .difference(&current_names)
        .cloned()
        .collect::<Vec<_>>();

    Ok(SnapshotDiff {
        added,
        removed,
        modified: Vec::new(),
        unchanged: current_names.intersection(&cached_names).cloned().collect(),
    })
}

fn reconcile_soft_deletes_blocking(
    mirror: &PgMirrorStore,
    current: &[(&RegistryServerEnvelope, MirroredServer)],
) -> Result<(), SyncError> {
    let cached = mirror.cached_state()?;
    let now = Utc::now();
    let current_names: std::collections::BTreeSet<String> = current
        .iter()
        .map(|(_, mirrored)| mirrored.name.clone())
        .collect();
    for (name, deleted_at) in cached {
        if current_names.contains(&name) {
            continue;
        }
        match deleted_at {
            None => {
                mirror.mark_deleted(&name, now)?;
            }
            Some(stamp) => {
                let elapsed = now.signed_duration_since(stamp);
                if elapsed
                    >= chrono::Duration::from_std(SOFT_DELETE_RETENTION)
                        .unwrap_or(chrono::Duration::days(30))
                {
                    mirror.evict(&name)?;
                }
            }
        }
    }
    Ok(())
}

fn persist_snapshot(
    snapshots: &PgSnapshotStore,
    plan: &SnapshotPlan,
    signer: &dyn Signer,
) -> Result<(), SyncError> {
    let signing_bytes = plan.snapshot_receipt.to_canonical_cbor();
    let signature = signer.sign(&signing_bytes)?;

    let stored = StoredSnapshot {
        snapshot_id: plan.snapshot_receipt.snapshot_id,
        snapshot_hash: plan.snapshot_receipt.snapshot_merkle_root,
        server_count: plan.snapshot_receipt.server_count.min(u32::MAX as u64) as u32,
        scraped_at: chrono::DateTime::<Utc>::from_timestamp_millis(
            plan.snapshot_receipt.scraped_at as i64,
        )
        .unwrap_or_else(Utc::now),
        receipt_hash: plan.snapshot_receipt.receipt_hash,
        receipt_signature: signature,
        signer_kid: signer.signer_kid().to_string(),
    };
    snapshots.record(&stored)?;
    Ok(())
}

fn derive_ulid_from_now() -> [u8; ULID_LEN] {
    let mut id = [0u8; ULID_LEN];
    let now_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let bytes = now_ns.to_be_bytes();
    let copy_len = bytes.len().min(ULID_LEN);
    id[..copy_len].copy_from_slice(&bytes[..copy_len]);
    id
}

fn derive_ulid_from_seed(seed: &str) -> [u8; ULID_LEN] {
    let mut id = [0u8; ULID_LEN];
    let digest = blake3::hash(seed.as_bytes());
    id.copy_from_slice(&digest.as_bytes()[..ULID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    use super::{derive_ulid_from_now, derive_ulid_from_seed};

    #[test]
    fn ulid_seeds_are_deterministic() {
        let first = derive_ulid_from_seed("snapshot:42:0");
        let second = derive_ulid_from_seed("snapshot:42:0");
        assert_eq!(first, second);
    }

    #[test]
    fn ulid_now_is_non_zero() {
        let id = derive_ulid_from_now();
        assert_ne!(id, [0u8; rcx_registry_crown::ULID_LEN]);
    }
}
