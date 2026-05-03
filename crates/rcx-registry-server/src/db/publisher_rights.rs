//! Postgres-backed [`rcx_registry_api::PublisherRightsStore`] impl.

use chrono::{DateTime, TimeZone, Utc};
use rcx_registry_admin::PublisherRightsRecord;
use rcx_registry_api::{ApiError, PublisherRightsStore};

use super::PgPool;

#[derive(Clone)]
pub struct PgPublisherRightsStore {
    pool: PgPool,
}

impl PgPublisherRightsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl PublisherRightsStore for PgPublisherRightsStore {
    fn upsert(&self, record: PublisherRightsRecord) -> Result<(), ApiError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let receipt_hash = decode_receipt_hash(&record.receipt_hash)
            .ok_or_else(|| ApiError::Store("invalid receipt_hash format".to_string()))?;
        let verified_at = millis_to_datetime(record.verified_at)
            .ok_or_else(|| ApiError::Store("invalid verified_at value".to_string()))?;
        conn.execute(
            "INSERT INTO publisher_rights (\
                publisher_passport, namespace, verification_method, verified_at, receipt_hash\
             ) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (publisher_passport, namespace) DO UPDATE SET \
                verification_method = EXCLUDED.verification_method,\
                verified_at = EXCLUDED.verified_at,\
                receipt_hash = EXCLUDED.receipt_hash",
            &[
                &record.publisher_passport,
                &record.namespace,
                &record.verification_method,
                &verified_at,
                &receipt_hash,
            ],
        )
        .map_err(|error| ApiError::Store(error.to_string()))?;
        Ok(())
    }

    fn list_by_publisher(
        &self,
        publisher_passport: &str,
    ) -> Result<Vec<PublisherRightsRecord>, ApiError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let rows = conn
            .query(
                "SELECT publisher_passport, namespace, verification_method, verified_at, receipt_hash \
                 FROM publisher_rights WHERE publisher_passport = $1 ORDER BY namespace ASC",
                &[&publisher_passport],
            )
            .map_err(|error| ApiError::Store(error.to_string()))?;
        rows.into_iter()
            .map(|row| {
                let verified_at_ts: DateTime<Utc> = row.get("verified_at");
                Ok(PublisherRightsRecord {
                    publisher_passport: row.get("publisher_passport"),
                    namespace: row.get("namespace"),
                    server_name: String::new(),
                    verification_method: row.get("verification_method"),
                    verified_at: datetime_to_millis(verified_at_ts),
                    receipt_hash: encode_receipt_hash(row.get::<_, Vec<u8>>("receipt_hash")),
                })
            })
            .collect()
    }

    fn lookup(
        &self,
        publisher_passport: &str,
        namespace: &str,
    ) -> Result<Option<PublisherRightsRecord>, ApiError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let row = conn
            .query_opt(
                "SELECT publisher_passport, namespace, verification_method, verified_at, receipt_hash \
                 FROM publisher_rights WHERE publisher_passport = $1 AND namespace = $2",
                &[&publisher_passport, &namespace],
            )
            .map_err(|error| ApiError::Store(error.to_string()))?;
        Ok(row.map(|row| {
            let verified_at_ts: DateTime<Utc> = row.get("verified_at");
            PublisherRightsRecord {
                publisher_passport: row.get("publisher_passport"),
                namespace: row.get("namespace"),
                server_name: String::new(),
                verification_method: row.get("verification_method"),
                verified_at: datetime_to_millis(verified_at_ts),
                receipt_hash: encode_receipt_hash(row.get::<_, Vec<u8>>("receipt_hash")),
            }
        }))
    }
}

fn decode_receipt_hash(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.strip_prefix("blake3:").unwrap_or(value);
    hex::decode(trimmed).ok().filter(|bytes| bytes.len() == 32)
}

fn encode_receipt_hash(bytes: Vec<u8>) -> String {
    format!("blake3:{}", hex::encode(bytes))
}

fn millis_to_datetime(value: u64) -> Option<DateTime<Utc>> {
    let secs = (value / 1000) as i64;
    let nsecs = ((value % 1000) * 1_000_000) as u32;
    Utc.timestamp_opt(secs, nsecs).single()
}

fn datetime_to_millis(value: DateTime<Utc>) -> u64 {
    let millis = value.timestamp_millis();
    millis.max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::{datetime_to_millis, decode_receipt_hash, encode_receipt_hash, millis_to_datetime};

    #[test]
    fn receipt_hash_round_trips() {
        let bytes = vec![0xab; 32];
        let encoded = encode_receipt_hash(bytes.clone());
        let decoded = decode_receipt_hash(&encoded).expect("encoded value should decode");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn millis_round_trip_zero_pads_correctly() {
        let original = 1_776_683_200_000u64;
        let datetime = millis_to_datetime(original).expect("millis should convert");
        assert_eq!(datetime_to_millis(datetime), original);
    }

    #[test]
    fn rejects_malformed_receipt_hash() {
        assert!(decode_receipt_hash("blake3:zz").is_none());
        assert!(decode_receipt_hash("not-hex").is_none());
        assert!(decode_receipt_hash(&format!("blake3:{}", "ab".repeat(31))).is_none());
    }
}
