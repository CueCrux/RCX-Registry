//! Postgres-backed snapshot storage helper used by the sync loop.

use chrono::{DateTime, Utc};
use rcx_registry_crown::{HASH_LEN, SIGNATURE_LEN, ULID_LEN};

use super::{DbError, PgPool};

#[derive(Debug, Clone)]
pub struct StoredSnapshot {
    pub snapshot_id: [u8; ULID_LEN],
    pub snapshot_hash: [u8; HASH_LEN],
    pub server_count: u32,
    pub scraped_at: DateTime<Utc>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
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
                receipt_signature, signer_kid\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (snapshot_id) DO NOTHING",
            &[
                &snapshot.snapshot_id.to_vec(),
                &snapshot.snapshot_hash.to_vec(),
                &(snapshot.server_count as i32),
                &snapshot.scraped_at,
                &snapshot.receipt_hash.to_vec(),
                &snapshot.receipt_signature.to_vec(),
                &snapshot.signer_kid,
            ],
        )?;
        Ok(())
    }

    pub fn latest(&self) -> Result<Option<StoredSnapshot>, DbError> {
        let mut conn = self.pool.get()?;
        let row = conn.query_opt(
            "SELECT snapshot_id, snapshot_hash, server_count, scraped_at, receipt_hash, \
                    receipt_signature, signer_kid \
               FROM snapshots ORDER BY scraped_at DESC LIMIT 1",
            &[],
        )?;
        Ok(row.map(|row| StoredSnapshot {
            snapshot_id: vec_to_fixed::<{ ULID_LEN }>(row.get("snapshot_id")),
            snapshot_hash: vec_to_fixed::<{ HASH_LEN }>(row.get("snapshot_hash")),
            server_count: row.get::<_, i32>("server_count").max(0) as u32,
            scraped_at: row.get("scraped_at"),
            receipt_hash: vec_to_fixed::<{ HASH_LEN }>(row.get("receipt_hash")),
            receipt_signature: vec_to_fixed::<{ SIGNATURE_LEN }>(row.get("receipt_signature")),
            signer_kid: row.get("signer_kid"),
        }))
    }
}

fn vec_to_fixed<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    let mut out = [0u8; N];
    let copy_len = bytes.len().min(N);
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}
