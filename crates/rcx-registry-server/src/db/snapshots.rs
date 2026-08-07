//! Postgres-backed snapshot storage helper used by the sync loop.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rcx_registry_api::{
    ApiError, SigningKeyPublication, SigningKeyStatus, SnapshotArtifact, SnapshotArtifactStore,
};
use rcx_registry_crown::{HASH_LEN, SIGNATURE_LEN, ULID_LEN};

use super::{DbError, PgPool};

/// How many snapshots keep their entry set before it is dropped.
///
/// An entry set is ~10 MB at 17.4k servers and the sync loop ticks hourly, so
/// keeping every one would add ~240 MB/day to the database for data whose only
/// use is verifying a *current* server. Receipts are ~250 bytes and form the
/// history chain, so they are never pruned — only the blob is.
const DEFAULT_ENTRY_SET_RETENTION: i64 = 24;

fn entry_set_retention() -> i64 {
    std::env::var("RCX_REGISTRY_ENTRY_SET_RETENTION")
        .ok()
        .and_then(|raw| raw.parse::<i64>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(DEFAULT_ENTRY_SET_RETENTION)
}

#[derive(Debug, Clone)]
pub struct StoredSnapshot {
    pub snapshot_id: [u8; ULID_LEN],
    pub snapshot_hash: [u8; HASH_LEN],
    pub server_count: u32,
    pub scraped_at: DateTime<Utc>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
    /// The exact canonical-CBOR bytes that were signed, signature filled in.
    ///
    /// Captured at sign time because it cannot be rebuilt afterwards: the other
    /// columns here are derived, and `event_id`, `previous_snapshot_hash`,
    /// `upstream_registry_uri`, `upstream_snapshot_etag` and `changes` are not
    /// stored at all.
    pub receipt_cbor: Vec<u8>,
    /// The `{name, version, canonical_json}` set this snapshot's root digests,
    /// as a JSON array. Captured at sign time because the mirror is mutable and
    /// a past snapshot's membership is unrecoverable once servers update.
    pub entries_json: Vec<u8>,
}

/// What a third party needs to verify a snapshot, read back out.
#[derive(Debug, Clone)]
pub struct StoredSnapshotArtifact {
    pub snapshot_id: [u8; ULID_LEN],
    pub snapshot_hash: [u8; HASH_LEN],
    pub server_count: u32,
    pub scraped_at: DateTime<Utc>,
    pub receipt_hash: [u8; HASH_LEN],
    pub signer_kid: String,
    pub receipt_cbor: Vec<u8>,
    pub has_entries: bool,
}

#[derive(Clone)]
pub struct PgSnapshotStore {
    pool: PgPool,
}

impl PgSnapshotStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn record(&self, snapshot: &StoredSnapshot) -> Result<(), DbError> {
        let mut conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO snapshots (\
                snapshot_id, snapshot_hash, server_count, scraped_at, receipt_hash, \
                receipt_signature, signer_kid, receipt_cbor, entries_json\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (snapshot_id) DO NOTHING",
            &[
                &snapshot.snapshot_id.to_vec(),
                &snapshot.snapshot_hash.to_vec(),
                &(snapshot.server_count as i32),
                &snapshot.scraped_at,
                &snapshot.receipt_hash.to_vec(),
                &snapshot.receipt_signature.to_vec(),
                &snapshot.signer_kid,
                &snapshot.receipt_cbor,
                &snapshot.entries_json,
            ],
        )?;
        self.prune_entry_sets()?;
        Ok(())
    }

    /// Drop entry-set blobs beyond the retention window, keeping their rows.
    ///
    /// Separate statement rather than part of the insert so a prune failure
    /// cannot roll back a recorded snapshot — losing the receipt to save disk
    /// would be the wrong trade in every direction.
    fn prune_entry_sets(&self) -> Result<(), DbError> {
        let mut conn = self.pool.get()?;
        conn.execute(
            "UPDATE snapshots SET entries_json = NULL \
              WHERE entries_json IS NOT NULL \
                AND snapshot_id NOT IN (\
                    SELECT snapshot_id FROM snapshots \
                     WHERE entries_json IS NOT NULL \
                     ORDER BY scraped_at DESC LIMIT $1\
                )",
            &[&entry_set_retention()],
        )?;
        Ok(())
    }

    /// The most recent snapshot that is actually verifiable.
    ///
    /// Not the same as the most recent snapshot: rows written before the
    /// artifact columns existed have no signed bytes and never will, so serving
    /// them would hand a caller a snapshot they cannot check.
    pub fn latest_artifact(&self) -> Result<Option<StoredSnapshotArtifact>, DbError> {
        let mut conn = self.pool.get()?;
        let row = conn.query_opt(
            "SELECT snapshot_id, snapshot_hash, server_count, scraped_at, receipt_hash, \
                    signer_kid, receipt_cbor, (entries_json IS NOT NULL) AS has_entries \
               FROM snapshots WHERE receipt_cbor IS NOT NULL \
              ORDER BY scraped_at DESC LIMIT 1",
            &[],
        )?;
        Ok(row.map(artifact_from_row))
    }

    pub fn artifact_by_id(
        &self,
        snapshot_id: &[u8],
    ) -> Result<Option<StoredSnapshotArtifact>, DbError> {
        let mut conn = self.pool.get()?;
        let row = conn.query_opt(
            "SELECT snapshot_id, snapshot_hash, server_count, scraped_at, receipt_hash, \
                    signer_kid, receipt_cbor, (entries_json IS NOT NULL) AS has_entries \
               FROM snapshots WHERE snapshot_id = $1 AND receipt_cbor IS NOT NULL",
            &[&snapshot_id.to_vec()],
        )?;
        Ok(row.map(artifact_from_row))
    }

    /// The entry set as stored, byte for byte.
    ///
    /// Returned raw rather than parsed: re-serialising through a JSON writer
    /// could change how `canonical_json` is escaped, and the whole point of
    /// these bytes is that they re-digest to the published root.
    pub fn entries_json(&self, snapshot_id: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        let mut conn = self.pool.get()?;
        let row = conn.query_opt(
            "SELECT entries_json FROM snapshots \
              WHERE snapshot_id = $1 AND entries_json IS NOT NULL",
            &[&snapshot_id.to_vec()],
        )?;
        Ok(row.map(|row| row.get::<_, Vec<u8>>("entries_json")))
    }

    /// The prior snapshot's root, which is all the sync loop needs to chain.
    ///
    /// Narrowed from returning a whole `StoredSnapshot`: the row no longer
    /// carries the artifact columns this query selects, and reconstructing a
    /// half-populated struct would invite a caller to read fields that are
    /// silently empty rather than absent.
    pub fn latest_hash(&self) -> Result<Option<[u8; HASH_LEN]>, DbError> {
        let mut conn = self.pool.get()?;
        let row = conn.query_opt(
            "SELECT snapshot_hash FROM snapshots ORDER BY scraped_at DESC LIMIT 1",
            &[],
        )?;
        Ok(row.map(|row| vec_to_fixed::<{ HASH_LEN }>(row.get("snapshot_hash"))))
    }
}

fn artifact_from_row(row: postgres::Row) -> StoredSnapshotArtifact {
    StoredSnapshotArtifact {
        snapshot_id: vec_to_fixed::<{ ULID_LEN }>(row.get("snapshot_id")),
        snapshot_hash: vec_to_fixed::<{ HASH_LEN }>(row.get("snapshot_hash")),
        server_count: row.get::<_, i32>("server_count").max(0) as u32,
        scraped_at: row.get("scraped_at"),
        receipt_hash: vec_to_fixed::<{ HASH_LEN }>(row.get("receipt_hash")),
        signer_kid: row.get("signer_kid"),
        receipt_cbor: row.get("receipt_cbor"),
        has_entries: row.get("has_entries"),
    }
}

fn vec_to_fixed<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    let mut out = [0u8; N];
    let copy_len = bytes.len().min(N);
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}

/// Adapts the Postgres store to the API's artifact trait.
///
/// Reads the signing key from a slot filled asynchronously rather than calling
/// the signer: the public half only changes on a rotation (M3c), so a Vault
/// round-trip per request would buy nothing and would make a Vault outage
/// degrade every key read. Using a slot rather than a value captured at boot is
/// what lets a startup failure recover without a restart.
pub struct PgSnapshotArtifactStore {
    store: PgSnapshotStore,
    keys: Arc<SigningKeyPublication>,
}

impl PgSnapshotArtifactStore {
    pub fn new(store: PgSnapshotStore, keys: Arc<SigningKeyPublication>) -> Self {
        Self { store, keys }
    }
}

/// Snapshot ids are addressed as hex. Anything else is a 404 rather than a 500:
/// a malformed id is a request for a snapshot that does not exist.
fn decode_snapshot_id(hex_id: &str) -> Option<Vec<u8>> {
    let bytes = hex::decode(hex_id.trim()).ok()?;
    (bytes.len() == ULID_LEN).then_some(bytes)
}

fn to_api(artifact: StoredSnapshotArtifact) -> SnapshotArtifact {
    SnapshotArtifact {
        snapshot_id: hex::encode(artifact.snapshot_id),
        scraped_at: artifact.scraped_at.to_rfc3339(),
        server_count: artifact.server_count,
        snapshot_root: hex::encode(artifact.snapshot_hash),
        receipt_hash: hex::encode(artifact.receipt_hash),
        signer_kid: artifact.signer_kid,
        receipt_cbor_hex: hex::encode(&artifact.receipt_cbor),
        entries_available: artifact.has_entries,
    }
}

impl SnapshotArtifactStore for PgSnapshotArtifactStore {
    fn latest(&self) -> Result<Option<SnapshotArtifact>, ApiError> {
        Ok(self
            .store
            .latest_artifact()
            .map_err(|error| ApiError::Store(error.to_string()))?
            .map(to_api))
    }

    fn by_id(&self, snapshot_id_hex: &str) -> Result<Option<SnapshotArtifact>, ApiError> {
        let Some(id) = decode_snapshot_id(snapshot_id_hex) else {
            return Ok(None);
        };
        Ok(self
            .store
            .artifact_by_id(&id)
            .map_err(|error| ApiError::Store(error.to_string()))?
            .map(to_api))
    }

    fn entries_json(&self, snapshot_id_hex: &str) -> Result<Option<Vec<u8>>, ApiError> {
        let Some(id) = decode_snapshot_id(snapshot_id_hex) else {
            return Ok(None);
        };
        self.store
            .entries_json(&id)
            .map_err(|error| ApiError::Store(error.to_string()))
    }

    fn signing_keys(&self) -> SigningKeyStatus {
        self.keys.status()
    }
}

#[cfg(test)]
mod tests {
    use super::decode_snapshot_id;
    use rcx_registry_crown::ULID_LEN;

    #[test]
    fn snapshot_ids_round_trip_and_reject_malformed() {
        let id = vec![7u8; ULID_LEN];
        let encoded = hex::encode(&id);
        assert_eq!(decode_snapshot_id(&encoded), Some(id));

        // Not hex, right length once decoded, and wrong length: all "no such
        // snapshot", never an error page.
        assert_eq!(decode_snapshot_id("zzzz"), None);
        assert_eq!(decode_snapshot_id(&hex::encode([1u8; ULID_LEN - 1])), None);
        assert_eq!(decode_snapshot_id(&hex::encode([1u8; ULID_LEN + 1])), None);
    }
}
