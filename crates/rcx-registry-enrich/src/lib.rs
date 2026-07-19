//! Auto and publisher-declared enrichment workflows.

use std::collections::BTreeSet;
use std::time::Duration;

use blake3::Hasher;
use jsonschema::validator_for;
use rcx_registry_crown::{
    CborValue, EntryAutoEnrichedReceipt, EntryEnrichedReceipt, ReceiptDocument, HASH_LEN, ULID_LEN,
};
use rcx_registry_ingest::{canonicalize_json, RegistryServerEnvelope};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const DEFAULT_CATEGORY: &str = "public";
pub const META_KEY_AUTO: &str = "org.rcxprotocol.registry/auto";
pub const META_KEY_PUBLISHER: &str = "org.rcxprotocol.registry/publisher";
pub const META_KEY_PUBLISHER_DISCOVERY: &str = "org.rcxprotocol.publisher";
pub const META_KEY_PUBLISHER_DECLARATION_URI: &str = "org.rcxprotocol.publisher/declaration-uri";
pub const META_KEY_PUBLISHER_REFRESH_INTERVAL: &str =
    "org.rcxprotocol.publisher/refresh_interval_seconds";
pub const DEFAULT_REFRESH_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
pub const ENRICHMENT_SCHEMA_URI: &str =
    "https://static.rcxprotocol.org/schemas/2026-04-19/rcx-enrichment.schema.json";

#[derive(Debug, Error)]
pub enum EnrichError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("declaration mcp_name `{actual}` did not match expected `{expected}`")]
    DeclarationNameMismatch { expected: String, actual: String },
    #[error("capability graph edge `{from}` -> `{to}` references missing node")]
    GraphEdgeMissingNode { from: String, to: String },
    #[error("duplicate capability `{0}` in capability graph")]
    DuplicateCapability(String),
    #[error("declaration metadata missing declaration-uri")]
    MissingDeclarationUri,
    #[error("negative numbers are not supported in canonical enrichment cbor")]
    NegativeNumber,
    #[error("unexpected upstream status {0}")]
    UnexpectedStatus(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationDiscovery {
    pub declaration_uri: String,
    pub refresh_interval_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherDeclaration {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    pub mcp_name: String,
    pub rcx_version: String,
    pub category: String,
    #[serde(default)]
    pub min_tier: Option<String>,
    #[serde(default)]
    pub required_affinity: Option<String>,
    pub capability_graph: Value,
    pub declared_at: String,
    pub publisher_passport: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchedPublisherDeclaration {
    pub declared_uri: String,
    pub raw_value: Value,
    pub declaration: PublisherDeclaration,
    pub declared_hash: [u8; HASH_LEN],
    pub canonical_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherEnrichmentPayload {
    pub category: String,
    pub min_tier: Option<String>,
    pub required_affinity: Option<String>,
    pub capability_graph: Value,
    pub declared_at: String,
    pub declared_uri: String,
    pub declared_hash: String,
    pub publisher_rights_verified: bool,
    pub verification_method: String,
    pub refresh_interval_seconds: Option<u64>,
}

impl PublisherEnrichmentPayload {
    pub fn to_cbor_value(&self) -> Result<CborValue, EnrichError> {
        Ok(CborValue::Map(vec![
            ("category".into(), CborValue::Text(self.category.clone())),
            (
                "min_tier".into(),
                match &self.min_tier {
                    Some(value) => CborValue::Text(value.clone()),
                    None => CborValue::Null,
                },
            ),
            (
                "required_affinity".into(),
                match &self.required_affinity {
                    Some(value) => CborValue::Text(value.clone()),
                    None => CborValue::Null,
                },
            ),
            (
                "capability_graph".into(),
                json_to_cbor(&self.capability_graph)?,
            ),
            (
                "declared_at".into(),
                CborValue::Text(self.declared_at.clone()),
            ),
            (
                "declared_uri".into(),
                CborValue::Text(self.declared_uri.clone()),
            ),
            (
                "declared_hash".into(),
                CborValue::Text(self.declared_hash.clone()),
            ),
            (
                "publisher_rights_verified".into(),
                CborValue::Bool(self.publisher_rights_verified),
            ),
            (
                "verification_method".into(),
                CborValue::Text(self.verification_method.clone()),
            ),
            (
                "refresh_interval_seconds".into(),
                match self.refresh_interval_seconds {
                    Some(value) => CborValue::Uint(value),
                    None => CborValue::Null,
                },
            ),
        ]))
    }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, EnrichError> {
        Ok(self.to_cbor_value()?.encode())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherEnrichmentBlock {
    pub category: String,
    pub min_tier: Option<String>,
    pub required_affinity: Option<String>,
    pub capability_graph: Value,
    pub declared_at: String,
    pub declared_uri: String,
    pub declared_hash: String,
    pub enrichment_receipt_hash: String,
    pub publisher_rights_verified: bool,
    pub verification_method: String,
    pub refresh_interval_seconds: Option<u64>,
}

impl PublisherEnrichmentBlock {
    pub fn from_payload(
        payload: &PublisherEnrichmentPayload,
        receipt_hash: &[u8; HASH_LEN],
    ) -> Self {
        Self {
            category: payload.category.clone(),
            min_tier: payload.min_tier.clone(),
            required_affinity: payload.required_affinity.clone(),
            capability_graph: payload.capability_graph.clone(),
            declared_at: payload.declared_at.clone(),
            declared_uri: payload.declared_uri.clone(),
            declared_hash: payload.declared_hash.clone(),
            enrichment_receipt_hash: format!("blake3:{}", hex::encode(receipt_hash)),
            publisher_rights_verified: payload.publisher_rights_verified,
            verification_method: payload.verification_method.clone(),
            refresh_interval_seconds: payload.refresh_interval_seconds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublisherEnrichmentRecord {
    pub server_name: String,
    pub publisher_passport: String,
    pub block: PublisherEnrichmentBlock,
    pub supersedes_prior_receipt_hash: Option<String>,
}

pub struct PublisherDeclarationClient {
    client: Client,
}

impl PublisherDeclarationClient {
    pub fn new() -> Result<Self, EnrichError> {
        // Match the ingest client: a declaration host that never responds
        // must not wedge the 24h refresh loop.
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(60))
                .build()?,
        })
    }

    pub fn fetch(&self, declared_uri: &str) -> Result<FetchedPublisherDeclaration, EnrichError> {
        let response = self.client.get(declared_uri).send()?;
        if !response.status().is_success() {
            return Err(EnrichError::UnexpectedStatus(response.status().as_u16()));
        }
        let raw_value = response.json::<Value>()?;
        let (declared_hash, canonical_json) = declaration_hash(&raw_value);
        let declaration = validate_publisher_declaration_value(&raw_value, None)?;

        Ok(FetchedPublisherDeclaration {
            declared_uri: declared_uri.to_string(),
            raw_value,
            declaration,
            declared_hash,
            canonical_json,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoEnrichmentPayload {
    pub category: String,
    pub attestations_count: u64,
    pub auto_enriched_at: String,
}

impl AutoEnrichmentPayload {
    pub fn new(auto_enriched_at: impl Into<String>) -> Self {
        Self {
            category: DEFAULT_CATEGORY.to_string(),
            attestations_count: 0,
            auto_enriched_at: auto_enriched_at.into(),
        }
    }

    pub fn to_cbor_value(&self) -> CborValue {
        CborValue::Map(vec![
            ("category".into(), CborValue::Text(self.category.clone())),
            ("capability_graph".into(), CborValue::Null),
            (
                "attestations_count".into(),
                CborValue::Uint(self.attestations_count),
            ),
            (
                "auto_enriched_at".into(),
                CborValue::Text(self.auto_enriched_at.clone()),
            ),
        ])
    }

    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value().encode()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoEnrichmentBlock {
    pub category: String,
    pub capability_graph: Value,
    pub attestations_count: u64,
    pub auto_enriched_at: String,
    pub auto_enrichment_receipt: String,
}

impl AutoEnrichmentBlock {
    pub fn from_receipt(payload: &AutoEnrichmentPayload, receipt_hash: &[u8; HASH_LEN]) -> Self {
        Self {
            category: payload.category.clone(),
            capability_graph: Value::Null,
            attestations_count: payload.attestations_count,
            auto_enriched_at: payload.auto_enriched_at.clone(),
            auto_enrichment_receipt: format!("blake3:{}", hex::encode(receipt_hash)),
        }
    }
}

pub fn build_entry_auto_enriched_receipt(
    server_name: &str,
    snapshot_id: [u8; ULID_LEN],
    event_id: [u8; ULID_LEN],
    payload: &AutoEnrichmentPayload,
    signer_kid: &str,
) -> EntryAutoEnrichedReceipt {
    let mut receipt = EntryAutoEnrichedReceipt {
        event_id,
        server_name: server_name.to_string(),
        snapshot_id,
        auto_enrichment_bytes: payload.to_canonical_cbor(),
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; 64],
        signer_kid: signer_kid.to_string(),
    };
    receipt.receipt_hash = receipt.compute_hash();
    receipt
}

pub fn declaration_discovery_from_envelope(
    envelope: &RegistryServerEnvelope,
) -> Result<Option<DeclarationDiscovery>, EnrichError> {
    if let Some(Value::Object(object)) = envelope.meta.extra.get(META_KEY_PUBLISHER_DISCOVERY) {
        let declaration_uri = object
            .get("declaration-uri")
            .and_then(Value::as_str)
            .ok_or(EnrichError::MissingDeclarationUri)?
            .to_string();
        let refresh_interval_seconds = object
            .get("refresh_interval_seconds")
            .and_then(Value::as_u64);
        return Ok(Some(DeclarationDiscovery {
            declaration_uri,
            refresh_interval_seconds,
        }));
    }

    if let Some(declaration_uri) = envelope
        .meta
        .extra
        .get(META_KEY_PUBLISHER_DECLARATION_URI)
        .and_then(Value::as_str)
    {
        let refresh_interval_seconds = envelope
            .meta
            .extra
            .get(META_KEY_PUBLISHER_REFRESH_INTERVAL)
            .and_then(Value::as_u64);
        return Ok(Some(DeclarationDiscovery {
            declaration_uri: declaration_uri.to_string(),
            refresh_interval_seconds,
        }));
    }

    Ok(None)
}

pub fn declaration_hash(value: &Value) -> ([u8; HASH_LEN], String) {
    let canonical_json = canonicalize_json(value);
    let mut hasher = Hasher::new();
    hasher.update(canonical_json.as_bytes());
    (*hasher.finalize().as_bytes(), canonical_json)
}

pub fn validate_publisher_declaration_value(
    raw_value: &Value,
    expected_server_name: Option<&str>,
) -> Result<PublisherDeclaration, EnrichError> {
    let schema = serde_json::from_str::<Value>(include_str!(
        "../../../schemas/2026-04-19/rcx-enrichment.schema.json"
    ))?;
    let validator =
        validator_for(&schema).map_err(|error| EnrichError::SchemaValidation(error.to_string()))?;

    if !validator.is_valid(raw_value) {
        let message = validator
            .iter_errors(raw_value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(EnrichError::SchemaValidation(message));
    }

    let declaration = serde_json::from_value::<PublisherDeclaration>(raw_value.clone())?;
    if let Some(expected_server_name) = expected_server_name {
        if declaration.mcp_name != expected_server_name {
            return Err(EnrichError::DeclarationNameMismatch {
                expected: expected_server_name.to_string(),
                actual: declaration.mcp_name.clone(),
            });
        }
    }
    validate_capability_graph_edges(&declaration.capability_graph)?;

    Ok(declaration)
}

pub fn build_publisher_enrichment_payload(
    declaration: &PublisherDeclaration,
    declared_uri: &str,
    declared_hash: &[u8; HASH_LEN],
    verification_method: &str,
    refresh_interval_seconds: Option<u64>,
) -> PublisherEnrichmentPayload {
    PublisherEnrichmentPayload {
        category: declaration.category.clone(),
        min_tier: declaration.min_tier.clone(),
        required_affinity: declaration.required_affinity.clone(),
        capability_graph: declaration.capability_graph.clone(),
        declared_at: declaration.declared_at.clone(),
        declared_uri: declared_uri.to_string(),
        declared_hash: format!("blake3:{}", hex::encode(declared_hash)),
        publisher_rights_verified: true,
        verification_method: verification_method.to_string(),
        refresh_interval_seconds,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_entry_enriched_receipt(
    server_name: &str,
    declaration: &PublisherDeclaration,
    declared_uri: &str,
    declared_hash: [u8; HASH_LEN],
    payload: &PublisherEnrichmentPayload,
    event_id: [u8; ULID_LEN],
    signer_kid: &str,
    supersedes_prior: Option<[u8; HASH_LEN]>,
) -> Result<EntryEnrichedReceipt, EnrichError> {
    let mut receipt = EntryEnrichedReceipt {
        event_id,
        server_name: server_name.to_string(),
        publisher_passport: declaration.publisher_passport.clone(),
        declared_uri: declared_uri.to_string(),
        declared_hash,
        enrichment_bytes: payload.to_canonical_cbor()?,
        supersedes_prior,
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; 64],
        signer_kid: signer_kid.to_string(),
    };
    receipt.receipt_hash = receipt.compute_hash();
    Ok(receipt)
}

pub fn build_publisher_enrichment_record(
    server_name: &str,
    declaration: &PublisherDeclaration,
    payload: &PublisherEnrichmentPayload,
    receipt_hash: &[u8; HASH_LEN],
    supersedes_prior: Option<String>,
) -> PublisherEnrichmentRecord {
    PublisherEnrichmentRecord {
        server_name: server_name.to_string(),
        publisher_passport: declaration.publisher_passport.clone(),
        block: PublisherEnrichmentBlock::from_payload(payload, receipt_hash),
        supersedes_prior_receipt_hash: supersedes_prior,
    }
}

pub fn attach_auto_enrichment(
    envelope: &mut RegistryServerEnvelope,
    block: &AutoEnrichmentBlock,
) -> Result<(), serde_json::Error> {
    envelope
        .meta
        .insert_extension(META_KEY_AUTO, serde_json::to_value(block)?);
    Ok(())
}

pub fn attach_publisher_enrichment(
    envelope: &mut RegistryServerEnvelope,
    block: &PublisherEnrichmentBlock,
) -> Result<(), serde_json::Error> {
    envelope
        .meta
        .insert_extension(META_KEY_PUBLISHER, serde_json::to_value(block)?);
    Ok(())
}

pub fn auto_enrichment_parity_ok(server_count: usize, enrichment_count: usize) -> bool {
    server_count == enrichment_count
}

fn validate_capability_graph_edges(capability_graph: &Value) -> Result<(), EnrichError> {
    let Some(graph_object) = capability_graph.as_object() else {
        if capability_graph.is_null() {
            return Ok(());
        }
        return Err(EnrichError::SchemaValidation(
            "capability_graph must be an object or null".to_string(),
        ));
    };

    let mut node_caps = BTreeSet::new();
    if let Some(nodes) = graph_object.get("nodes").and_then(Value::as_array) {
        for node in nodes {
            let cap = node
                .get("cap")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    EnrichError::SchemaValidation("capability graph node missing `cap`".to_string())
                })?
                .to_string();
            if !node_caps.insert(cap.clone()) {
                return Err(EnrichError::DuplicateCapability(cap));
            }
        }
    }

    if let Some(edges) = graph_object.get("edges").and_then(Value::as_array) {
        for edge in edges {
            let from = edge
                .get("from")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    EnrichError::SchemaValidation(
                        "capability graph edge missing `from`".to_string(),
                    )
                })?
                .to_string();
            let to = edge
                .get("to")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    EnrichError::SchemaValidation("capability graph edge missing `to`".to_string())
                })?
                .to_string();
            if !node_caps.contains(&from) || !node_caps.contains(&to) {
                return Err(EnrichError::GraphEdgeMissingNode { from, to });
            }
        }
    }

    Ok(())
}

fn json_to_cbor(value: &Value) -> Result<CborValue, EnrichError> {
    match value {
        Value::Null => Ok(CborValue::Null),
        Value::Bool(value) => Ok(CborValue::Bool(*value)),
        Value::String(value) => Ok(CborValue::Text(value.clone())),
        Value::Array(items) => Ok(CborValue::Array(
            items
                .iter()
                .map(json_to_cbor)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Object(map) => Ok(CborValue::Map(
            map.iter()
                .map(|(key, value)| Ok((key.clone(), json_to_cbor(value)?)))
                .collect::<Result<Vec<_>, EnrichError>>()?,
        )),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                Ok(CborValue::Uint(value))
            } else if let Some(value) = number.as_i64() {
                if value < 0 {
                    Err(EnrichError::NegativeNumber)
                } else {
                    Ok(CborValue::Uint(value as u64))
                }
            } else if let Some(value) = number.as_f64() {
                Ok(CborValue::Float(value))
            } else {
                Err(EnrichError::SchemaValidation(
                    "unsupported numeric representation".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attach_auto_enrichment, attach_publisher_enrichment, auto_enrichment_parity_ok,
        build_entry_auto_enriched_receipt, build_entry_enriched_receipt,
        build_publisher_enrichment_payload, build_publisher_enrichment_record,
        declaration_discovery_from_envelope, declaration_hash,
        validate_publisher_declaration_value, AutoEnrichmentBlock, AutoEnrichmentPayload,
        PublisherDeclaration, META_KEY_AUTO, META_KEY_PUBLISHER,
    };
    use rcx_registry_ingest::{OfficialRegistryMeta, RegistryServerEnvelope, RegistryServerMeta};
    use serde_json::json;

    fn example_declaration() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../fixtures/examples/rcx-enrichment.valid.json"
        ))
        .expect("fixture should parse")
    }

    fn envelope_with_meta(extra: serde_json::Value) -> RegistryServerEnvelope {
        let mut meta = RegistryServerMeta {
            official: OfficialRegistryMeta {
                status: "active".to_string(),
                status_changed_at: None,
                published_at: None,
                updated_at: None,
                is_latest: true,
            },
            extra: Default::default(),
        };
        if let serde_json::Value::Object(map) = extra {
            for (key, value) in map {
                meta.extra.insert(key, value);
            }
        }
        RegistryServerEnvelope {
            server: json!({
                "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
                "name": "io.github.example-org/document-proofer",
                "version": "1.0.0"
            }),
            meta,
        }
    }

    #[test]
    fn auto_enrichment_payload_encodes_default_block_shape() {
        let payload = AutoEnrichmentPayload::new("2026-04-20T12:00:00Z");
        let encoded = payload.to_canonical_cbor();

        assert!(!encoded.is_empty());
        assert_eq!(payload.category, "public");
        assert_eq!(payload.attestations_count, 0);
    }

    #[test]
    fn auto_enrichment_receipt_and_block_are_derived_together() {
        let payload = AutoEnrichmentPayload::new("2026-04-20T12:00:00Z");
        let receipt = build_entry_auto_enriched_receipt(
            "io.github.example/server-a",
            [0x11; 16],
            [0x22; 16],
            &payload,
            "vault:transit:rcx-registry-signing-key-1",
        );
        let block = AutoEnrichmentBlock::from_receipt(&payload, &receipt.receipt_hash);

        assert_eq!(block.category, "public");
        assert_eq!(block.capability_graph, serde_json::Value::Null);
        assert_eq!(block.attestations_count, 0);
        assert!(block.auto_enrichment_receipt.starts_with("blake3:"));
        assert_ne!(receipt.receipt_hash, [0u8; 32]);
    }

    #[test]
    fn auto_enrichment_attaches_under_namespaced_meta_key() {
        let payload = AutoEnrichmentPayload::new("2026-04-20T12:00:00Z");
        let receipt = build_entry_auto_enriched_receipt(
            "io.github.example/server-a",
            [0x11; 16],
            [0x22; 16],
            &payload,
            "vault:transit:rcx-registry-signing-key-1",
        );
        let block = AutoEnrichmentBlock::from_receipt(&payload, &receipt.receipt_hash);
        let mut envelope = envelope_with_meta(json!({}));

        attach_auto_enrichment(&mut envelope, &block).expect("block should serialize");

        assert_eq!(
            envelope.meta.extra.get(META_KEY_AUTO),
            Some(&serde_json::to_value(block).expect("block should serialize"))
        );
    }

    #[test]
    fn declaration_discovery_supports_nested_metadata() {
        let envelope = envelope_with_meta(json!({
            "org.rcxprotocol.publisher": {
                "declaration-uri": "https://example.org/.rcx/document-proofer.rcx.json",
                "refresh_interval_seconds": 3600
            }
        }));

        let discovery = declaration_discovery_from_envelope(&envelope)
            .expect("metadata should parse")
            .expect("discovery should exist");
        assert_eq!(
            discovery.declaration_uri,
            "https://example.org/.rcx/document-proofer.rcx.json"
        );
        assert_eq!(discovery.refresh_interval_seconds, Some(3600));
    }

    #[test]
    fn declaration_validates_against_schema_and_graph_rules() {
        let declaration = validate_publisher_declaration_value(
            &example_declaration(),
            Some("io.github.example-org/document-proofer"),
        )
        .expect("valid fixture should validate");

        assert_eq!(
            declaration.publisher_passport,
            "passport:github:example-org"
        );
        assert_eq!(declaration.category, "tier_gated");
    }

    #[test]
    fn invalid_declaration_reports_schema_failure() {
        let invalid = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../fixtures/examples/rcx-enrichment.invalid.missing-min-tier.json"
        ))
        .expect("fixture should parse");

        assert!(validate_publisher_declaration_value(
            &invalid,
            Some("io.github.example-org/document-proofer"),
        )
        .is_err());
    }

    #[test]
    fn declaration_rejects_edges_to_missing_nodes() {
        let invalid = json!({
            "$schema": "https://static.rcxprotocol.org/schemas/2026-04-19/rcx-enrichment.schema.json",
            "mcp_name": "io.github.example-org/document-proofer",
            "rcx_version": "1.0",
            "category": "public",
            "capability_graph": {
                "version": 1,
                "nodes": [
                    {
                        "cap": "io.github.example-org.document-proofer/proof_document",
                        "category": "public",
                        "prefer": "mcp",
                        "shape": "Promise<ProofResult>",
                        "cost_class": "metered",
                        "stability": "stable"
                    }
                ],
                "edges": [
                    {
                        "from": "io.github.example-org.document-proofer/proof_document",
                        "to": "io.github.example-org.document-proofer/missing",
                        "kind": "composes_with"
                    }
                ]
            },
            "declared_at": "2026-04-19T10:00:00Z",
            "publisher_passport": "passport:github:example-org"
        });

        assert!(validate_publisher_declaration_value(
            &invalid,
            Some("io.github.example-org/document-proofer"),
        )
        .is_err());
    }

    #[test]
    fn publisher_enrichment_receipt_and_block_are_derived_together() {
        let raw = example_declaration();
        let declaration = validate_publisher_declaration_value(
            &raw,
            Some("io.github.example-org/document-proofer"),
        )
        .expect("valid fixture should validate");
        let (declared_hash, _canonical_json) = declaration_hash(&raw);
        let payload = build_publisher_enrichment_payload(
            &declaration,
            "https://example.org/.rcx/document-proofer.rcx.json",
            &declared_hash,
            "github_oauth",
            Some(3600),
        );
        let receipt = build_entry_enriched_receipt(
            "io.github.example-org/document-proofer",
            &declaration,
            "https://example.org/.rcx/document-proofer.rcx.json",
            declared_hash,
            &payload,
            [0x33; 16],
            "vault:transit:rcx-registry-signing-key-1",
            None,
        )
        .expect("receipt should build");
        let record = build_publisher_enrichment_record(
            "io.github.example-org/document-proofer",
            &declaration,
            &payload,
            &receipt.receipt_hash,
            None,
        );

        assert_eq!(record.block.category, "tier_gated");
        assert_eq!(record.block.min_tier.as_deref(), Some("starter"));
        assert_eq!(record.block.verification_method, "github_oauth");
        assert!(record.block.enrichment_receipt_hash.starts_with("blake3:"));

        let mut envelope = envelope_with_meta(json!({}));
        attach_publisher_enrichment(&mut envelope, &record.block).expect("block should serialize");
        assert_eq!(
            envelope.meta.extra.get(META_KEY_PUBLISHER),
            Some(&serde_json::to_value(record.block).expect("block should serialize"))
        );
    }

    #[test]
    fn parity_invariant_matches_m2_gate() {
        assert!(auto_enrichment_parity_ok(10, 10));
        assert!(!auto_enrichment_parity_ok(10, 9));
    }

    #[test]
    fn declaration_hash_is_stable_for_canonical_json() {
        let raw = example_declaration();
        let (first_hash, first_json) = declaration_hash(&raw);
        let (second_hash, second_json) = declaration_hash(&raw);

        assert_eq!(first_hash, second_hash);
        assert_eq!(first_json, second_json);
    }

    #[test]
    fn declaration_type_deserializes_after_validation() {
        let declaration = serde_json::from_value::<PublisherDeclaration>(example_declaration())
            .expect("fixture should deserialize");
        assert_eq!(declaration.schema_uri, super::ENRICHMENT_SCHEMA_URI);
    }
}
