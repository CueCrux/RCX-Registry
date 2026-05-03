//! Postgres-backed [`rcx_registry_api::MirrorStore`] impl.

use chrono::{DateTime, Utc};
use postgres::Row;
use rcx_registry_api::{ApiError, MirrorStore};
use rcx_registry_ingest::{
    ListServersRequest, RegistryListMetadata, RegistryServerEnvelope, RegistryServerListResponse,
};
use serde_json::Value;

use super::{DbError, PgPool};

/// Newly-mirrored or modified server payload to persist.
#[derive(Debug, Clone)]
pub struct UpsertServer<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub status: &'a str,
    pub schema_date: &'a str,
    pub is_latest: bool,
    pub upstream_hash: [u8; 32],
    pub envelope: &'a RegistryServerEnvelope,
    pub server_json: &'a Value,
    pub observed_in_snapshot: [u8; 16],
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct PgMirrorStore {
    pool: PgPool,
}

impl PgMirrorStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Upsert a single mirrored server row. Used by the sync loop.
    pub fn upsert_server(&self, request: UpsertServer<'_>) -> Result<(), DbError> {
        let mut conn = self.pool.get()?;
        let envelope_json = serde_json::to_value(request.envelope)
            .map_err(|error| DbError::Config(error.to_string()))?;
        conn.execute(
            "INSERT INTO mcp_servers (\
                name, server_json, upstream_hash, first_observed_at, last_observed_at, \
                status, schema_date, observed_in_snapshot, envelope_json, version, is_latest, \
                deleted_upstream_at\
             ) VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, NULL)\
             ON CONFLICT (name) DO UPDATE SET \
                server_json = EXCLUDED.server_json,\
                upstream_hash = EXCLUDED.upstream_hash,\
                last_observed_at = EXCLUDED.last_observed_at,\
                status = EXCLUDED.status,\
                schema_date = EXCLUDED.schema_date,\
                observed_in_snapshot = EXCLUDED.observed_in_snapshot,\
                envelope_json = EXCLUDED.envelope_json,\
                version = EXCLUDED.version,\
                is_latest = EXCLUDED.is_latest,\
                deleted_upstream_at = NULL",
            &[
                &request.name,
                &request.server_json,
                &request.upstream_hash.to_vec(),
                &request.observed_at,
                &request.status,
                &request.schema_date,
                &request.observed_in_snapshot.to_vec(),
                &envelope_json,
                &request.version,
                &request.is_latest,
            ],
        )?;
        Ok(())
    }

    /// Mark a server as deleted upstream — keeps the row queryable for the
    /// 30-day soft-delete window.
    pub fn mark_deleted(&self, name: &str, when: DateTime<Utc>) -> Result<(), DbError> {
        let mut conn = self.pool.get()?;
        conn.execute(
            "UPDATE mcp_servers SET status = 'deleted', deleted_upstream_at = $2 \
             WHERE name = $1 AND deleted_upstream_at IS NULL",
            &[&name, &when],
        )?;
        Ok(())
    }

    /// Permanently evict a row whose soft-delete window has expired.
    pub fn evict(&self, name: &str) -> Result<(), DbError> {
        let mut conn = self.pool.get()?;
        conn.execute("DELETE FROM mcp_servers WHERE name = $1", &[&name])?;
        Ok(())
    }

    /// Read the names + soft-delete timestamps for soft-delete reconciliation.
    #[allow(clippy::type_complexity)]
    pub fn cached_state(&self) -> Result<Vec<(String, Option<DateTime<Utc>>)>, DbError> {
        let mut conn = self.pool.get()?;
        let rows = conn.query("SELECT name, deleted_upstream_at FROM mcp_servers", &[])?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<_, String>(0),
                    row.get::<_, Option<DateTime<Utc>>>(1),
                )
            })
            .collect())
    }

    fn query_envelopes(
        &self,
        request: &ListServersRequest,
    ) -> Result<Vec<RegistryServerEnvelope>, DbError> {
        let mut conn = self.pool.get()?;
        let include_deleted = request.include_deleted || request.updated_since.is_some();
        let search_pattern = request
            .search
            .as_deref()
            .map(|needle| format!("%{}%", needle.to_ascii_lowercase()));
        let version_filter = request.version.as_deref();
        let updated_since = request.updated_since.as_deref();

        let rows = conn.query(
            "SELECT envelope_json, name, version, is_latest \
               FROM mcp_servers \
              WHERE ($1::bool OR status <> 'deleted') \
                AND ($2::text IS NULL OR LOWER(name) LIKE $2) \
                AND ($3::text IS NULL \
                     OR ($3::text = 'latest' AND is_latest = TRUE) \
                     OR version = $3::text) \
                AND ($4::text IS NULL \
                     OR COALESCE(\
                          envelope_json #>> '{_meta,io.modelcontextprotocol.registry/official,updatedAt}',\
                          envelope_json #>> '{_meta,io.modelcontextprotocol.registry/official,statusChangedAt}',\
                          envelope_json #>> '{_meta,io.modelcontextprotocol.registry/official,publishedAt}'\
                     ) >= $4::text) \
              ORDER BY name ASC, version ASC",
            &[
                &include_deleted,
                &search_pattern,
                &version_filter,
                &updated_since,
            ],
        )?;

        rows.into_iter()
            .map(|row| envelope_from_row(&row))
            .collect()
    }
}

impl MirrorStore for PgMirrorStore {
    fn list_servers(
        &self,
        request: &ListServersRequest,
    ) -> Result<RegistryServerListResponse, ApiError> {
        let mut envelopes = self
            .query_envelopes(request)
            .map_err(|error| ApiError::Store(error.to_string()))?;
        // Cursor handling matches `InMemoryMirrorStore` semantics — skip
        // until the cursor record, then return the next page.
        if let Some(cursor) = request.cursor.as_deref() {
            let position = envelopes.iter().position(|envelope| {
                cursor_token(envelope)
                    .map(|token| token == cursor)
                    .unwrap_or(false)
            });
            match position {
                Some(index) => envelopes = envelopes.split_off(index + 1),
                None => return Err(ApiError::InvalidCursor),
            }
        }

        let limit = request.normalized_limit();
        let mut page: Vec<RegistryServerEnvelope> = envelopes.into_iter().take(limit + 1).collect();
        let has_more = page.len() > limit;
        if has_more {
            page.pop();
        }
        let next_cursor = if has_more {
            page.last().and_then(cursor_token)
        } else {
            None
        };

        Ok(RegistryServerListResponse {
            metadata: RegistryListMetadata {
                next_cursor,
                count: page.len(),
            },
            servers: page,
        })
    }

    fn list_versions(
        &self,
        server_name: &str,
        include_deleted: bool,
    ) -> Result<RegistryServerListResponse, ApiError> {
        let request = ListServersRequest {
            include_deleted,
            ..ListServersRequest::default()
        };
        let envelopes = self
            .query_envelopes(&ListServersRequest {
                search: None,
                ..request
            })
            .map_err(|error| ApiError::Store(error.to_string()))?;
        let mut matching: Vec<RegistryServerEnvelope> = envelopes
            .into_iter()
            .filter(|envelope| {
                envelope
                    .server
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|name| name == server_name)
                    .unwrap_or(false)
            })
            .collect();
        matching.sort_by(|left, right| {
            envelope_version(right)
                .unwrap_or_default()
                .cmp(envelope_version(left).unwrap_or_default())
        });
        let count = matching.len();
        Ok(RegistryServerListResponse {
            metadata: RegistryListMetadata {
                next_cursor: None,
                count,
            },
            servers: matching,
        })
    }

    fn get_version(
        &self,
        server_name: &str,
        version: &str,
        include_deleted: bool,
    ) -> Result<RegistryServerEnvelope, ApiError> {
        let envelopes = self
            .query_envelopes(&ListServersRequest {
                include_deleted,
                ..ListServersRequest::default()
            })
            .map_err(|error| ApiError::Store(error.to_string()))?;

        envelopes
            .into_iter()
            .filter(|envelope| {
                envelope
                    .server
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|name| name == server_name)
                    .unwrap_or(false)
            })
            .find(|envelope| {
                if version == "latest" {
                    envelope.meta.official.is_latest
                } else {
                    envelope_version(envelope)
                        .map(|candidate| candidate == version)
                        .unwrap_or(false)
                }
            })
            .ok_or(ApiError::NotFound)
    }
}

fn envelope_from_row(row: &Row) -> Result<RegistryServerEnvelope, DbError> {
    let json: Value = row.get("envelope_json");
    serde_json::from_value(json).map_err(|error| DbError::Config(error.to_string()))
}

fn cursor_token(envelope: &RegistryServerEnvelope) -> Option<String> {
    let name = envelope.server.get("name").and_then(Value::as_str)?;
    let version = envelope_version(envelope)?;
    Some(format!("{name}:{version}"))
}

fn envelope_version(envelope: &RegistryServerEnvelope) -> Option<&str> {
    envelope.server.get("version").and_then(Value::as_str)
}
