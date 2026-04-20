//! Auto and publisher-declared enrichment workflows.

use rcx_registry_crown::{
    CborValue, EntryAutoEnrichedReceipt, ReceiptDocument, HASH_LEN, ULID_LEN,
};
use rcx_registry_ingest::RegistryServerEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_CATEGORY: &str = "public";
pub const META_KEY_AUTO: &str = "org.rcxprotocol.registry/auto";

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

pub fn attach_auto_enrichment(
    envelope: &mut RegistryServerEnvelope,
    block: &AutoEnrichmentBlock,
) -> Result<(), serde_json::Error> {
    envelope
        .meta
        .insert_extension(META_KEY_AUTO, serde_json::to_value(block)?);
    Ok(())
}

pub fn auto_enrichment_parity_ok(server_count: usize, enrichment_count: usize) -> bool {
    server_count == enrichment_count
}

#[cfg(test)]
mod tests {
    use super::{
        attach_auto_enrichment, auto_enrichment_parity_ok, build_entry_auto_enriched_receipt,
        AutoEnrichmentBlock, AutoEnrichmentPayload, META_KEY_AUTO,
    };
    use rcx_registry_ingest::{OfficialRegistryMeta, RegistryServerEnvelope, RegistryServerMeta};
    use serde_json::json;

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
        let mut envelope = RegistryServerEnvelope {
            server: json!({
                "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
                "name": "io.github.example/server-a",
                "version": "1.0.0"
            }),
            meta: RegistryServerMeta {
                official: OfficialRegistryMeta {
                    status: "active".to_string(),
                    status_changed_at: None,
                    published_at: None,
                    updated_at: None,
                    is_latest: true,
                },
                extra: Default::default(),
            },
        };

        attach_auto_enrichment(&mut envelope, &block).expect("block should serialize");

        assert_eq!(
            envelope.meta.extra.get(META_KEY_AUTO),
            Some(&serde_json::to_value(block).expect("block should serialize"))
        );
    }

    #[test]
    fn parity_invariant_matches_m2_gate() {
        assert!(auto_enrichment_parity_ok(10, 10));
        assert!(!auto_enrichment_parity_ok(10, 9));
    }
}
