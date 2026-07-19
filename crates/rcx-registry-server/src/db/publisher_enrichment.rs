//! Postgres-backed [`rcx_registry_api::PublisherEnrichmentStore`] impl.

use chrono::{DateTime, Utc};
use rcx_registry_api::{ApiError, PublisherEnrichmentStore};
use rcx_registry_enrich::{PublisherEnrichmentBlock, PublisherEnrichmentRecord};
use serde_json::Value;

use super::PgPool;

#[derive(Clone)]
pub struct PgPublisherEnrichmentStore {
    pool: PgPool,
}

impl PgPublisherEnrichmentStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl PublisherEnrichmentStore for PgPublisherEnrichmentStore {
    fn upsert(&self, record: PublisherEnrichmentRecord) -> Result<(), ApiError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let block = &record.block;
        let declared_hash = decode_blake3_prefixed(&block.declared_hash)
            .ok_or_else(|| ApiError::Store("invalid declared_hash format".to_string()))?;
        let receipt_hash = decode_blake3_prefixed(&block.enrichment_receipt_hash)
            .ok_or_else(|| ApiError::Store("invalid enrichment_receipt_hash format".to_string()))?;
        let enriched_at = parse_iso8601(&block.declared_at).ok_or_else(|| {
            ApiError::Store(format!(
                "declared_at `{}` is not a valid ISO-8601 timestamp",
                block.declared_at
            ))
        })?;

        conn.execute(
            "INSERT INTO rcx_enrichment (\
                server_name, capability_graph, category, min_tier, required_affinity,\
                enrichment_source, declared_uri, declared_hash, enriched_at, enrichment_receipt_hash\
             ) VALUES ($1, $2, $3, $4, $5, 'publisher', $6, $7, $8, $9) \
             ON CONFLICT (server_name) DO UPDATE SET \
                capability_graph = EXCLUDED.capability_graph,\
                category = EXCLUDED.category,\
                min_tier = EXCLUDED.min_tier,\
                required_affinity = EXCLUDED.required_affinity,\
                enrichment_source = EXCLUDED.enrichment_source,\
                declared_uri = EXCLUDED.declared_uri,\
                declared_hash = EXCLUDED.declared_hash,\
                enriched_at = EXCLUDED.enriched_at,\
                enrichment_receipt_hash = EXCLUDED.enrichment_receipt_hash",
            &[
                &record.server_name,
                &block.capability_graph,
                &block.category,
                &block.min_tier,
                &block.required_affinity,
                &block.declared_uri,
                &declared_hash,
                &enriched_at,
                &receipt_hash,
            ],
        )
        .map_err(|error| ApiError::Store(error.to_string()))?;

        // Verification metadata lives in the sidecar table created by
        // migration 0006 — DDL must not run in the request path.
        let refresh_interval = block.refresh_interval_seconds.map(|seconds| seconds as i64);
        conn.execute(
            "INSERT INTO rcx_enrichment_publisher_meta (\
                server_name, publisher_passport, publisher_rights_verified,\
                verification_method, refresh_interval_seconds, supersedes_prior_receipt_hash\
             ) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (server_name) DO UPDATE SET \
                publisher_passport = EXCLUDED.publisher_passport,\
                publisher_rights_verified = EXCLUDED.publisher_rights_verified,\
                verification_method = EXCLUDED.verification_method,\
                refresh_interval_seconds = EXCLUDED.refresh_interval_seconds,\
                supersedes_prior_receipt_hash = EXCLUDED.supersedes_prior_receipt_hash",
            &[
                &record.server_name,
                &record.publisher_passport,
                &block.publisher_rights_verified,
                &block.verification_method,
                &refresh_interval,
                &record.supersedes_prior_receipt_hash,
            ],
        )
        .map_err(|error| ApiError::Store(error.to_string()))?;

        Ok(())
    }

    fn get(&self, server_name: &str) -> Result<Option<PublisherEnrichmentRecord>, ApiError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let row = conn
            .query_opt(
                "SELECT e.server_name, e.capability_graph, e.category, e.min_tier,\
                        e.required_affinity, e.declared_uri, e.declared_hash, e.enriched_at,\
                        e.enrichment_receipt_hash,\
                        m.publisher_passport, m.publisher_rights_verified, m.verification_method,\
                        m.refresh_interval_seconds, m.supersedes_prior_receipt_hash \
                   FROM rcx_enrichment e \
              LEFT JOIN rcx_enrichment_publisher_meta m ON m.server_name = e.server_name \
                  WHERE e.server_name = $1 AND e.enrichment_source = 'publisher'",
                &[&server_name],
            )
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let Some(row) = row else { return Ok(None) };

        let declared_hash: Vec<u8> = row.get("declared_hash");
        let receipt_hash: Vec<u8> = row.get("enrichment_receipt_hash");
        let enriched_at: DateTime<Utc> = row.get("enriched_at");
        let capability_graph: Option<Value> = row.try_get("capability_graph").ok();

        let block = PublisherEnrichmentBlock {
            category: row.get("category"),
            min_tier: row.get("min_tier"),
            required_affinity: row.get("required_affinity"),
            capability_graph: capability_graph.unwrap_or(Value::Null),
            declared_at: enriched_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            declared_uri: row.get("declared_uri"),
            declared_hash: encode_blake3_prefixed(&declared_hash),
            enrichment_receipt_hash: encode_blake3_prefixed(&receipt_hash),
            publisher_rights_verified: row.try_get("publisher_rights_verified").unwrap_or(false),
            verification_method: row
                .try_get::<_, Option<String>>("verification_method")
                .ok()
                .flatten()
                .unwrap_or_default(),
            refresh_interval_seconds: row
                .try_get::<_, Option<i64>>("refresh_interval_seconds")
                .ok()
                .flatten()
                .map(|value| value.max(0) as u64),
        };
        let publisher_passport: String = row
            .try_get::<_, Option<String>>("publisher_passport")
            .ok()
            .flatten()
            .unwrap_or_default();
        let supersedes_prior_receipt_hash: Option<String> = row
            .try_get::<_, Option<String>>("supersedes_prior_receipt_hash")
            .ok()
            .flatten();

        Ok(Some(PublisherEnrichmentRecord {
            server_name: row.get("server_name"),
            publisher_passport,
            block,
            supersedes_prior_receipt_hash,
        }))
    }
}

fn decode_blake3_prefixed(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.strip_prefix("blake3:").unwrap_or(value);
    hex::decode(trimmed).ok().filter(|bytes| bytes.len() == 32)
}

fn encode_blake3_prefixed(bytes: &[u8]) -> String {
    format!("blake3:{}", hex::encode(bytes))
}

fn parse_iso8601(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::{decode_blake3_prefixed, encode_blake3_prefixed, parse_iso8601};

    #[test]
    fn blake3_prefix_round_trip() {
        let bytes = (0..32).collect::<Vec<u8>>();
        let encoded = encode_blake3_prefixed(&bytes);
        assert!(encoded.starts_with("blake3:"));
        let decoded = decode_blake3_prefixed(&encoded).expect("encoded value should decode");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn iso_timestamp_with_offset_normalises_to_utc() {
        let parsed = parse_iso8601("2026-04-19T10:00:00+02:00").expect("should parse");
        assert_eq!(parsed.timezone(), chrono::Utc);
    }
}
