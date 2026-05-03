//! Publisher-declared enrichment refresh loop.
//!
//! Periodically (default 24h) walks every mirrored server, parses any
//! `_meta.org.rcxprotocol.publisher` discovery metadata, refetches the
//! declaration, validates it, and refreshes the publisher-enrichment row
//! if the hash changed.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rcx_registry_admin::{classify_namespace, NamespaceClaim};
use rcx_registry_api::{ApiError, PublisherEnrichmentStore, PublisherRightsStore};
use rcx_registry_crown::{ReceiptDocument, HASH_LEN, ULID_LEN};
use rcx_registry_enrich::{
    build_entry_enriched_receipt, build_publisher_enrichment_payload,
    build_publisher_enrichment_record, declaration_discovery_from_envelope, declaration_hash,
    validate_publisher_declaration_value, DeclarationDiscovery, EnrichError,
    PublisherDeclarationClient,
};
use rcx_registry_ingest::RegistryServerEnvelope;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::watch;
use tokio::time::sleep;

use crate::db::PgPool;
use crate::metrics::Metrics;
use crate::vault::Signer;

/// Default cadence for the publisher-declaration refresh sweep when no
/// per-publisher override is set.
pub const DEFAULT_REFRESH_CADENCE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Error)]
pub enum EnrichLoopError {
    #[error("db: {0}")]
    Db(#[from] crate::db::DbError),
    #[error("postgres: {0}")]
    Postgres(#[from] postgres::Error),
    #[error("api: {0}")]
    Api(String),
    #[error("enrich: {0}")]
    Enrich(#[from] EnrichError),
    #[error("vault: {0}")]
    Vault(#[from] crate::vault::VaultError),
}

#[derive(Clone)]
pub struct EnrichDeps {
    pub pool: PgPool,
    pub publisher_rights_store: Arc<dyn PublisherRightsStore>,
    pub publisher_enrichment_store: Arc<dyn PublisherEnrichmentStore>,
    pub signer: Arc<dyn Signer>,
    pub metrics: Arc<Metrics>,
}

/// Run the enrichment refresh loop until `shutdown` is signalled.
pub async fn run(cadence: Duration, deps: EnrichDeps, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = sleep(cadence) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }

        if *shutdown.borrow() {
            return;
        }

        let outcome = tick(deps.clone()).await;
        deps.metrics
            .enrichment_loop_runs_total
            .fetch_add(1, Ordering::Relaxed);
        if let Err(error) = outcome {
            deps.metrics
                .enrichment_loop_errors_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %error, "enrichment refresh tick failed");
        }
    }
}

async fn tick(deps: EnrichDeps) -> Result<(), EnrichLoopError> {
    tokio::task::spawn_blocking(move || tick_blocking(deps))
        .await
        .expect("enrich tick join should not panic")
}

fn tick_blocking(deps: EnrichDeps) -> Result<(), EnrichLoopError> {
    let mut conn = deps.pool.get().map_err(crate::db::DbError::from)?;
    let rows = conn.query("SELECT name, envelope_json FROM mcp_servers", &[])?;
    let client = PublisherDeclarationClient::new()?;
    let mut accepted = 0u64;
    let mut rejected = 0u64;

    for row in rows {
        let name: String = row.get(0);
        let envelope_json: Value = row.get(1);
        let envelope: RegistryServerEnvelope = match serde_json::from_value(envelope_json) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::debug!(server = %name, error = %error, "skipping non-envelope row");
                continue;
            }
        };
        let Some(discovery) = declaration_discovery_from_envelope(&envelope)? else {
            continue;
        };
        match refresh_one(&deps, &client, &name, &discovery) {
            Ok(true) => accepted += 1,
            Ok(false) => {}
            Err(error) => {
                rejected += 1;
                tracing::debug!(server = %name, error = %error, "enrichment refresh skipped");
            }
        }
    }

    deps.metrics
        .publisher_declarations_total
        .fetch_add(accepted, Ordering::Relaxed);
    deps.metrics
        .publisher_declaration_errors_total
        .fetch_add(rejected, Ordering::Relaxed);
    Ok(())
}

fn refresh_one(
    deps: &EnrichDeps,
    client: &PublisherDeclarationClient,
    server_name: &str,
    discovery: &DeclarationDiscovery,
) -> Result<bool, EnrichLoopError> {
    let claim: NamespaceClaim =
        classify_namespace(server_name).map_err(|error| EnrichLoopError::Api(error.to_string()))?;

    let fetched = client.fetch(&discovery.declaration_uri)?;
    let declaration = validate_publisher_declaration_value(&fetched.raw_value, Some(server_name))?;

    let rights = deps
        .publisher_rights_store
        .lookup(&declaration.publisher_passport, &claim.namespace)
        .map_err(map_api_error)?
        .ok_or_else(|| {
            EnrichLoopError::Api(format!(
                "publisher passport `{}` has no verified rights for namespace `{}`",
                declaration.publisher_passport, claim.namespace
            ))
        })?;

    let prior = deps
        .publisher_enrichment_store
        .get(server_name)
        .map_err(map_api_error)?;
    let prior_hash_bytes = prior
        .as_ref()
        .and_then(|record| parse_blake3_prefixed_hash(&record.block.declared_hash));
    if matches!(prior_hash_bytes, Some(prior) if prior == fetched.declared_hash) {
        return Ok(false);
    }

    let (declared_hash_bytes, _canonical_json) = declaration_hash(&fetched.raw_value);
    let payload = build_publisher_enrichment_payload(
        &declaration,
        &discovery.declaration_uri,
        &declared_hash_bytes,
        &rights.verification_method,
        discovery.refresh_interval_seconds,
    );
    let prior_receipt_hash_bytes = prior
        .as_ref()
        .and_then(|record| parse_blake3_prefixed_hash(&record.block.enrichment_receipt_hash));
    let event_id = derive_ulid_from_seed(&format!(
        "enrichment:{}:{}:{}",
        server_name, discovery.declaration_uri, declaration.declared_at
    ));
    let mut receipt = build_entry_enriched_receipt(
        server_name,
        &declaration,
        &discovery.declaration_uri,
        declared_hash_bytes,
        &payload,
        event_id,
        deps.signer.signer_kid(),
        prior_receipt_hash_bytes,
    )?;
    let signing_bytes = receipt.to_canonical_cbor();
    receipt.receipt_signature = deps.signer.sign(&signing_bytes)?;

    let record = build_publisher_enrichment_record(
        server_name,
        &declaration,
        &payload,
        &receipt.receipt_hash,
        prior.map(|record| record.block.enrichment_receipt_hash),
    );
    deps.publisher_enrichment_store
        .upsert(record)
        .map_err(map_api_error)?;
    Ok(true)
}

fn map_api_error(error: ApiError) -> EnrichLoopError {
    EnrichLoopError::Api(error.to_string())
}

fn parse_blake3_prefixed_hash(value: &str) -> Option<[u8; HASH_LEN]> {
    let trimmed = value.strip_prefix("blake3:").unwrap_or(value);
    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() != HASH_LEN {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn derive_ulid_from_seed(seed: &str) -> [u8; ULID_LEN] {
    let mut id = [0u8; ULID_LEN];
    let digest = blake3::hash(seed.as_bytes());
    id.copy_from_slice(&digest.as_bytes()[..ULID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    use super::{derive_ulid_from_seed, parse_blake3_prefixed_hash};

    #[test]
    fn ulid_seed_is_deterministic() {
        let first = derive_ulid_from_seed("enrichment:foo:bar");
        let second = derive_ulid_from_seed("enrichment:foo:bar");
        assert_eq!(first, second);
    }

    #[test]
    fn parses_blake3_prefixed_hex_hash() {
        let hex_value = format!("blake3:{}", "ab".repeat(32));
        let parsed = parse_blake3_prefixed_hash(&hex_value).expect("hash should parse");
        assert_eq!(parsed[0], 0xab);
        assert_eq!(parsed[31], 0xab);
    }

    #[test]
    fn rejects_short_hashes() {
        let hex_value = format!("blake3:{}", "ab".repeat(31));
        assert!(parse_blake3_prefixed_hash(&hex_value).is_none());
    }
}
