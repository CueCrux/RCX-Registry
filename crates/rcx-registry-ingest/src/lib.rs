//! MCP mirror and snapshot-ingestion helpers for RCX-Registry.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use jsonschema::{validator_for, Validator};
use rcx_registry_crown::{
    ReceiptDocument, RegistrySnapshotReceipt, SnapshotChanges, HASH_LEN, SIGNATURE_LEN, ULID_LEN,
};
use reqwest::blocking::Client;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const MCP_REGISTRY_BASE_URL: &str = "https://registry.modelcontextprotocol.io";
pub const MCP_REGISTRY_LIST_PATH: &str = "/v0/servers";

pub const METRIC_SNAPSHOTS_TOTAL: &str = "rcx_registry_snapshots_total";
pub const METRIC_MCP_SERVERS_MIRRORED: &str = "rcx_registry_mcp_servers_mirrored";
pub const METRIC_MCP_FETCH_ERRORS_TOTAL: &str = "rcx_registry_mcp_fetch_errors_total";

pub const DEFAULT_PAGE_LIMIT: usize = 30;
pub const MAX_PAGE_LIMIT: usize = 100;
pub const SOFT_DELETE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    #[error("invalid field `{0}`")]
    InvalidField(&'static str),
    #[error("invalid schema uri `{0}`")]
    InvalidSchemaUri(String),
    #[error("unknown schema `{0}`")]
    UnknownSchema(String),
    #[error("schema validation failed for `{schema_uri}`: {message}")]
    SchemaValidation { schema_uri: String, message: String },
    #[error("unexpected upstream status {0}")]
    UnexpectedStatus(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialRegistryMeta {
    pub status: String,
    #[serde(rename = "statusChangedAt", default)]
    pub status_changed_at: Option<String>,
    #[serde(rename = "publishedAt", default)]
    pub published_at: Option<String>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<String>,
    #[serde(rename = "isLatest", default)]
    pub is_latest: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryServerMeta {
    #[serde(rename = "io.modelcontextprotocol.registry/official")]
    pub official: OfficialRegistryMeta,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

impl RegistryServerMeta {
    pub fn insert_extension(&mut self, key: impl Into<String>, value: Value) {
        self.extra.insert(key.into(), value);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryServerEnvelope {
    pub server: Value,
    #[serde(rename = "_meta")]
    pub meta: RegistryServerMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryListMetadata {
    #[serde(rename = "nextCursor", default)]
    pub next_cursor: Option<String>,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryServerListResponse {
    pub servers: Vec<RegistryServerEnvelope>,
    pub metadata: RegistryListMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredServer {
    pub name: String,
    pub version: String,
    pub schema_uri: String,
    pub schema_date: String,
    pub status: String,
    pub updated_at: Option<String>,
    pub is_latest: bool,
    pub canonical_json: String,
}

impl MirroredServer {
    pub fn from_envelope(
        envelope: &RegistryServerEnvelope,
        schemas: &dyn ServerSchemaCatalog,
    ) -> Result<Self, IngestError> {
        let schema_uri = envelope
            .server
            .get("$schema")
            .and_then(Value::as_str)
            .ok_or(IngestError::MissingField("server.$schema"))?
            .to_string();
        let name = envelope
            .server
            .get("name")
            .and_then(Value::as_str)
            .ok_or(IngestError::MissingField("server.name"))?
            .to_string();
        let version = envelope
            .server
            .get("version")
            .and_then(Value::as_str)
            .ok_or(IngestError::MissingField("server.version"))?
            .to_string();

        schemas.validate_server(&schema_uri, &envelope.server)?;

        Ok(Self {
            name,
            version,
            schema_date: schema_date_from_uri(&schema_uri)?,
            schema_uri,
            status: envelope.meta.official.status.clone(),
            updated_at: envelope.meta.official.updated_at.clone(),
            is_latest: envelope.meta.official.is_latest,
            canonical_json: canonicalize_json(&envelope.server),
        })
    }

    pub fn cursor_token(&self) -> String {
        format!("{}:{}", self.name, self.version)
    }
}

pub fn canonicalize_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).expect("strings should serialize"),
        Value::Array(items) => {
            let rendered = items
                .iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{rendered}]")
        }
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let rendered = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(&key).expect("object key should serialize");
                    let encoded_value = canonicalize_json(map.get(&key).expect("key should exist"));
                    format!("{encoded_key}:{encoded_value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

pub fn schema_date_from_uri(schema_uri: &str) -> Result<String, IngestError> {
    let marker = "/schemas/";
    let Some(remainder) = schema_uri.split(marker).nth(1) else {
        return Err(IngestError::InvalidSchemaUri(schema_uri.to_string()));
    };
    let date = remainder
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| IngestError::InvalidSchemaUri(schema_uri.to_string()))?;

    let bytes = date.as_bytes();
    let valid = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
    if !valid {
        return Err(IngestError::InvalidSchemaUri(schema_uri.to_string()));
    }

    Ok(date.to_string())
}

pub trait ServerSchemaCatalog: Send + Sync {
    fn validate_server(&self, schema_uri: &str, server: &Value) -> Result<(), IngestError>;
}

#[derive(Debug, Default)]
pub struct NoopSchemaCatalog;

impl ServerSchemaCatalog for NoopSchemaCatalog {
    fn validate_server(&self, _schema_uri: &str, _server: &Value) -> Result<(), IngestError> {
        Ok(())
    }
}

pub struct StaticSchemaCatalog {
    validators: BTreeMap<String, Validator>,
}

impl StaticSchemaCatalog {
    pub fn new(entries: impl IntoIterator<Item = (String, Value)>) -> Result<Self, IngestError> {
        let mut validators = BTreeMap::new();
        for (schema_uri, schema) in entries {
            let validator =
                validator_for(&schema).map_err(|error| IngestError::SchemaValidation {
                    schema_uri: schema_uri.clone(),
                    message: error.to_string(),
                })?;
            validators.insert(schema_uri, validator);
        }

        Ok(Self { validators })
    }
}

impl ServerSchemaCatalog for StaticSchemaCatalog {
    fn validate_server(&self, schema_uri: &str, server: &Value) -> Result<(), IngestError> {
        let validator = self
            .validators
            .get(schema_uri)
            .ok_or_else(|| IngestError::UnknownSchema(schema_uri.to_string()))?;
        if validator.is_valid(server) {
            return Ok(());
        }

        let message = validator
            .iter_errors(server)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(IngestError::SchemaValidation {
            schema_uri: schema_uri.to_string(),
            message,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListServersRequest {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub updated_since: Option<String>,
    pub search: Option<String>,
    pub version: Option<String>,
    pub include_deleted: bool,
}

impl ListServersRequest {
    pub fn normalized_limit(&self) -> usize {
        self.limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchPageResult {
    pub page: Option<RegistryServerListResponse>,
    pub etag: Option<String>,
}

pub struct McpRegistryClient {
    base_url: String,
    client: Client,
}

impl McpRegistryClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, IngestError> {
        let client = Client::builder().build()?;
        Ok(Self {
            base_url: base_url.into(),
            client,
        })
    }

    pub fn fetch_servers_page(
        &self,
        request: &ListServersRequest,
        etag: Option<&str>,
    ) -> Result<FetchPageResult, IngestError> {
        let url = format!(
            "{}{}",
            self.base_url.trim_end_matches('/'),
            MCP_REGISTRY_LIST_PATH
        );
        let mut builder = self
            .client
            .get(url)
            .query(&[("limit", request.normalized_limit().to_string())]);

        if let Some(cursor) = request.cursor.as_deref() {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(updated_since) = request.updated_since.as_deref() {
            builder = builder.query(&[("updated_since", updated_since)]);
        }
        if let Some(search) = request.search.as_deref() {
            builder = builder.query(&[("search", search)]);
        }
        if let Some(version) = request.version.as_deref() {
            builder = builder.query(&[("version", version)]);
        }
        if request.include_deleted {
            builder = builder.query(&[("include_deleted", "true")]);
        }
        if let Some(etag) = etag {
            builder = builder.header(IF_NONE_MATCH, etag);
        }

        let response = builder.send()?;
        if response.status().as_u16() == 304 {
            return Ok(FetchPageResult {
                page: None,
                etag: response
                    .headers()
                    .get(ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(ToString::to_string),
            });
        }
        if !response.status().is_success() {
            return Err(IngestError::UnexpectedStatus(response.status().as_u16()));
        }

        let response_etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let page = response.json::<RegistryServerListResponse>()?;

        Ok(FetchPageResult {
            page: Some(page),
            etag: response_etag,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub unchanged: Vec<String>,
}

impl SnapshotDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified.is_empty()
            && self.unchanged.is_empty()
    }

    pub fn changed_count(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

/// Compute a deterministic BLAKE3 root over lex-sorted mirrored entries.
pub fn snapshot_merkle_root(entries: &[MirroredServer]) -> [u8; 32] {
    let mut ordered: Vec<&MirroredServer> = entries.iter().collect();
    ordered.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });

    let mut hasher = Hasher::new();
    for entry in ordered {
        hasher.update(entry.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(entry.version.as_bytes());
        hasher.update(&[0]);
        hasher.update(entry.canonical_json.as_bytes());
        hasher.update(&[0xff]);
    }
    *hasher.finalize().as_bytes()
}

/// Compare two mirrored snapshots by server name and canonical content hash.
pub fn reconcile_snapshots(
    previous: &[MirroredServer],
    current: &[MirroredServer],
) -> SnapshotDiff {
    let previous_by_name = by_name(previous);
    let current_by_name = by_name(current);

    let mut names = BTreeSet::new();
    names.extend(previous_by_name.keys().cloned());
    names.extend(current_by_name.keys().cloned());

    let mut diff = SnapshotDiff {
        added: Vec::new(),
        removed: Vec::new(),
        modified: Vec::new(),
        unchanged: Vec::new(),
    };

    for name in names {
        match (previous_by_name.get(&name), current_by_name.get(&name)) {
            (None, Some(_)) => diff.added.push(name),
            (Some(_), None) => diff.removed.push(name),
            (Some(previous), Some(current)) => {
                if canonical_server_hash(previous) == canonical_server_hash(current) {
                    diff.unchanged.push(name);
                } else {
                    diff.modified.push(name);
                }
            }
            (None, None) => {}
        }
    }

    diff
}

/// Compute the per-entry upstream hash used by reconciliation.
pub fn canonical_server_hash(entry: &MirroredServer) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(entry.name.as_bytes());
    hasher.update(&[0]);
    hasher.update(entry.version.as_bytes());
    hasher.update(&[0]);
    hasher.update(entry.canonical_json.as_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaQueryMode {
    Disabled,
    UpdatedSince,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCadencePolicy {
    pub target_interval: Duration,
    pub min_interval_floor: Duration,
    pub burst_follow_up_delay: Duration,
    pub burst_change_threshold: usize,
    pub delta_query_mode: DeltaQueryMode,
}

impl Default for SyncCadencePolicy {
    fn default() -> Self {
        Self {
            target_interval: Duration::from_secs(60 * 60),
            min_interval_floor: Duration::from_secs(10 * 60),
            burst_follow_up_delay: Duration::from_secs(15 * 60),
            burst_change_threshold: 50,
            delta_query_mode: DeltaQueryMode::UpdatedSince,
        }
    }
}

impl SyncCadencePolicy {
    pub fn next_run_at(&self, last_success: SystemTime, diff: &SnapshotDiff) -> SystemTime {
        let base_due = last_success + self.target_interval;
        let earliest_allowed = last_success + self.min_interval_floor;
        if diff.changed_count() > self.burst_change_threshold {
            max_system_time(earliest_allowed, last_success + self.burst_follow_up_delay)
        } else {
            max_system_time(earliest_allowed, base_due)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedServerState {
    pub name: String,
    pub deleted_upstream_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftDeletePlan {
    pub mark_deleted: Vec<String>,
    pub retain_deleted: Vec<String>,
    pub evict: Vec<String>,
}

pub fn reconcile_soft_deletes(
    cached: &[CachedServerState],
    current: &[MirroredServer],
    now: SystemTime,
    retention: Duration,
) -> SoftDeletePlan {
    let current_names = current
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<BTreeSet<_>>();
    let mut plan = SoftDeletePlan {
        mark_deleted: Vec::new(),
        retain_deleted: Vec::new(),
        evict: Vec::new(),
    };

    for entry in cached {
        if current_names.contains(&entry.name) {
            continue;
        }

        match entry.deleted_upstream_at {
            None => plan.mark_deleted.push(entry.name.clone()),
            Some(deleted_at) => {
                if now.duration_since(deleted_at).unwrap_or_default() >= retention {
                    plan.evict.push(entry.name.clone());
                } else {
                    plan.retain_deleted.push(entry.name.clone());
                }
            }
        }
    }

    plan
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestMetricsSample {
    pub mirrored_servers: usize,
    pub fetch_errors_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPlan {
    pub diff: SnapshotDiff,
    pub snapshot_receipt: RegistrySnapshotReceipt,
}

pub fn build_snapshot_plan(
    current: &[MirroredServer],
    previous: &[MirroredServer],
    event_id: [u8; ULID_LEN],
    snapshot_id: [u8; ULID_LEN],
    scraped_at_ms: u64,
    previous_snapshot_hash: Option<[u8; HASH_LEN]>,
    etag: Option<&str>,
    signer_kid: &str,
) -> SnapshotPlan {
    let diff = reconcile_snapshots(previous, current);
    let snapshot_merkle_root = snapshot_merkle_root(current);

    let mut receipt = RegistrySnapshotReceipt {
        event_id,
        snapshot_id,
        scraped_at: scraped_at_ms,
        server_count: current.len() as u64,
        snapshot_merkle_root,
        previous_snapshot_hash,
        upstream_registry_uri: format!("{MCP_REGISTRY_BASE_URL}{MCP_REGISTRY_LIST_PATH}"),
        upstream_snapshot_etag: etag.map(ToString::to_string),
        changes: SnapshotChanges {
            added: diff.added.len() as u64,
            removed: diff.removed.len() as u64,
            modified: diff.modified.len() as u64,
        },
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; SIGNATURE_LEN],
        signer_kid: signer_kid.to_string(),
    };
    receipt.receipt_hash = receipt.compute_hash();

    SnapshotPlan {
        diff,
        snapshot_receipt: receipt,
    }
}

fn by_name(entries: &[MirroredServer]) -> BTreeMap<String, &MirroredServer> {
    entries
        .iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect()
}

fn max_system_time(left: SystemTime, right: SystemTime) -> SystemTime {
    if left.duration_since(UNIX_EPOCH).unwrap_or_default()
        >= right.duration_since(UNIX_EPOCH).unwrap_or_default()
    {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_snapshot_plan, canonicalize_json, reconcile_snapshots, reconcile_soft_deletes,
        schema_date_from_uri, snapshot_merkle_root, CachedServerState, DeltaQueryMode,
        ListServersRequest, MirroredServer, NoopSchemaCatalog, RegistryServerEnvelope,
        RegistryServerMeta, StaticSchemaCatalog, SyncCadencePolicy, METRIC_MCP_FETCH_ERRORS_TOTAL,
        METRIC_MCP_SERVERS_MIRRORED, METRIC_SNAPSHOTS_TOTAL, SOFT_DELETE_RETENTION,
    };
    use serde_json::json;
    use std::time::{Duration, UNIX_EPOCH};

    fn mirrored(name: &str, version: &str, canonical_json: &str) -> MirroredServer {
        MirroredServer {
            name: name.to_string(),
            version: version.to_string(),
            schema_uri:
                "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
                    .to_string(),
            schema_date: "2025-12-11".to_string(),
            status: "active".to_string(),
            updated_at: Some("2026-04-20T12:00:00Z".to_string()),
            is_latest: true,
            canonical_json: canonical_json.to_string(),
        }
    }

    #[test]
    fn metric_names_match_plan_expectations() {
        assert_eq!(METRIC_SNAPSHOTS_TOTAL, "rcx_registry_snapshots_total");
        assert_eq!(
            METRIC_MCP_SERVERS_MIRRORED,
            "rcx_registry_mcp_servers_mirrored"
        );
        assert_eq!(
            METRIC_MCP_FETCH_ERRORS_TOTAL,
            "rcx_registry_mcp_fetch_errors_total"
        );
    }

    #[test]
    fn list_request_normalizes_limit() {
        let request = ListServersRequest {
            limit: Some(500),
            ..ListServersRequest::default()
        };

        assert_eq!(request.normalized_limit(), 100);
    }

    #[test]
    fn schema_date_extracts_from_modelcontextprotocol_uri() {
        let schema_uri =
            "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";
        assert_eq!(
            schema_date_from_uri(schema_uri).expect("schema date should parse"),
            "2025-12-11"
        );
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let value = json!({
            "b": 2,
            "a": {
                "z": true,
                "m": ["x", {"k": 1, "a": 2}]
            }
        });

        assert_eq!(
            canonicalize_json(&value),
            "{\"a\":{\"m\":[\"x\",{\"a\":2,\"k\":1}],\"z\":true},\"b\":2}"
        );
    }

    #[test]
    fn mirrored_server_validates_against_catalog() {
        let schema_uri =
            "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
                .to_string();
        let catalog = StaticSchemaCatalog::new([(
            schema_uri.clone(),
            json!({
                "type": "object",
                "required": ["$schema", "name", "version"],
                "properties": {
                    "$schema": {"type": "string"},
                    "name": {"type": "string"},
                    "version": {"type": "string"}
                }
            }),
        )])
        .expect("catalog should compile");

        let server = RegistryServerEnvelope {
            server: json!({
                "$schema": schema_uri,
                "name": "io.github.example/server",
                "version": "1.0.0",
                "description": "Example"
            }),
            meta: RegistryServerMeta {
                official: serde_json::from_value(json!({
                    "status": "active",
                    "updatedAt": "2026-04-20T12:00:00Z",
                    "isLatest": true
                }))
                .expect("official meta should parse"),
                extra: Default::default(),
            },
        };

        let mirrored =
            MirroredServer::from_envelope(&server, &catalog).expect("server should validate");
        assert_eq!(mirrored.name, "io.github.example/server");
        assert_eq!(mirrored.version, "1.0.0");
        assert_eq!(mirrored.schema_date, "2025-12-11");
    }

    #[test]
    fn snapshot_root_is_order_independent() {
        let left = vec![
            mirrored("io.github.example/beta", "1.0.0", "{\"name\":\"beta\"}"),
            mirrored("io.github.example/alpha", "1.0.0", "{\"name\":\"alpha\"}"),
        ];
        let right = vec![left[1].clone(), left[0].clone()];

        assert_eq!(snapshot_merkle_root(&left), snapshot_merkle_root(&right));
    }

    #[test]
    fn reconcile_snapshots_covers_all_statuses() {
        let previous = vec![
            mirrored(
                "io.github.example/alpha",
                "1.0.0",
                "{\"name\":\"alpha\",\"version\":\"1.0.0\"}",
            ),
            mirrored(
                "io.github.example/beta",
                "1.0.0",
                "{\"name\":\"beta\",\"version\":\"1.0.0\"}",
            ),
            mirrored(
                "io.github.example/gamma",
                "1.0.0",
                "{\"name\":\"gamma\",\"version\":\"1.0.0\"}",
            ),
        ];
        let current = vec![
            mirrored(
                "io.github.example/alpha",
                "1.0.0",
                "{\"name\":\"alpha\",\"version\":\"1.0.0\"}",
            ),
            mirrored(
                "io.github.example/beta",
                "1.0.0",
                "{\"name\":\"beta\",\"version\":\"2.0.0\"}",
            ),
            mirrored(
                "io.github.example/delta",
                "1.0.0",
                "{\"name\":\"delta\",\"version\":\"1.0.0\"}",
            ),
        ];

        let diff = reconcile_snapshots(&previous, &current);

        assert_eq!(diff.added, vec!["io.github.example/delta".to_string()]);
        assert_eq!(diff.removed, vec!["io.github.example/gamma".to_string()]);
        assert_eq!(diff.modified, vec!["io.github.example/beta".to_string()]);
        assert_eq!(diff.unchanged, vec!["io.github.example/alpha".to_string()]);
        assert!(!diff.is_empty());
    }

    #[test]
    fn cadence_policy_uses_burst_follow_up_when_change_count_is_large() {
        let policy = SyncCadencePolicy {
            burst_change_threshold: 2,
            delta_query_mode: DeltaQueryMode::UpdatedSince,
            ..SyncCadencePolicy::default()
        };
        let last_success = UNIX_EPOCH + Duration::from_secs(1_000);
        let diff = super::SnapshotDiff {
            added: vec!["a".to_string(), "b".to_string()],
            removed: vec!["c".to_string()],
            modified: Vec::new(),
            unchanged: Vec::new(),
        };

        assert_eq!(
            policy.next_run_at(last_success, &diff),
            last_success + Duration::from_secs(15 * 60)
        );
    }

    #[test]
    fn soft_delete_policy_marks_retains_and_evicts() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000_000);
        let cached = vec![
            CachedServerState {
                name: "io.github.example/mark".to_string(),
                deleted_upstream_at: None,
            },
            CachedServerState {
                name: "io.github.example/retain".to_string(),
                deleted_upstream_at: Some(now - Duration::from_secs(60)),
            },
            CachedServerState {
                name: "io.github.example/evict".to_string(),
                deleted_upstream_at: Some(now - SOFT_DELETE_RETENTION - Duration::from_secs(60)),
            },
        ];
        let current = vec![mirrored(
            "io.github.example/live",
            "1.0.0",
            "{\"name\":\"live\",\"version\":\"1.0.0\"}",
        )];

        let plan = reconcile_soft_deletes(&cached, &current, now, SOFT_DELETE_RETENTION);

        assert_eq!(
            plan.mark_deleted,
            vec!["io.github.example/mark".to_string()]
        );
        assert_eq!(
            plan.retain_deleted,
            vec!["io.github.example/retain".to_string()]
        );
        assert_eq!(plan.evict, vec!["io.github.example/evict".to_string()]);
    }

    #[test]
    fn snapshot_plan_computes_receipt_hash_with_zeroed_signature_fields() {
        let previous = vec![mirrored(
            "io.github.example/alpha",
            "1.0.0",
            "{\"name\":\"alpha\",\"version\":\"1.0.0\"}",
        )];
        let current = vec![
            previous[0].clone(),
            mirrored(
                "io.github.example/beta",
                "1.0.0",
                "{\"name\":\"beta\",\"version\":\"1.0.0\"}",
            ),
        ];

        let snapshot = build_snapshot_plan(
            &current,
            &previous,
            [0x11; 16],
            [0x22; 16],
            1_776_683_200_000,
            Some([0x33; 32]),
            Some("\"etag-1\""),
            "vault:transit:rcx-registry-signing-key-1",
        );

        assert_eq!(
            snapshot.diff.added,
            vec!["io.github.example/beta".to_string()]
        );
        assert_eq!(snapshot.snapshot_receipt.server_count, 2);
        assert_ne!(snapshot.snapshot_receipt.receipt_hash, [0u8; 32]);
        assert_eq!(snapshot.snapshot_receipt.receipt_signature, [0u8; 64]);
    }

    #[test]
    fn noop_catalog_allows_local_unit_tests_without_official_schema() {
        let envelope = RegistryServerEnvelope {
            server: json!({
                "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
                "name": "io.github.example/noop",
                "version": "1.0.0"
            }),
            meta: RegistryServerMeta {
                official: serde_json::from_value(json!({
                    "status": "active",
                    "updatedAt": null,
                    "isLatest": false
                }))
                .expect("official meta should parse"),
                extra: Default::default(),
            },
        };

        let mirrored = MirroredServer::from_envelope(&envelope, &NoopSchemaCatalog)
            .expect("noop catalog should accept");
        assert_eq!(mirrored.cursor_token(), "io.github.example/noop:1.0.0");
    }
}
