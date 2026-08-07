//! The artifacts a third party needs to verify a snapshot without trusting us.
//!
//! Three things, and all three are required — any two of them prove nothing
//! useful:
//!
//! 1. the **signed receipt**, as the exact canonical-CBOR bytes that were signed
//! 2. the **entry set** the snapshot's root digests
//! 3. the **public key** the signature verifies under
//!
//! Why the entry set rather than a proof: spec v1's `snapshot_merkle_root` is a
//! flat BLAKE3 set digest, not a tree, so no inclusion proof is derivable from
//! it. The only way to establish that a named server is inside a signed snapshot
//! is to recompute the whole digest over the full membership. Per-server proofs
//! need the v2 tree and are a separate, HIGH-gated milestone — offering a
//! cheaper-looking check before then would be offering a weaker guarantee under
//! the same name.

use std::sync::Arc;

use serde::Serialize;

use crate::ApiError;

/// A snapshot's verifiable form, minus the entry set (which is large and fetched
/// separately).
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotArtifact {
    /// Hex, and the id used to address the other endpoints.
    pub snapshot_id: String,
    pub scraped_at: String,
    pub server_count: u32,
    /// Hex of the flat set digest over this snapshot's membership.
    pub snapshot_root: String,
    pub receipt_hash: String,
    pub signer_kid: String,
    /// The signed canonical CBOR, hex. This is the input to `verifyReceipt`.
    pub receipt_cbor_hex: String,
    /// False once the entry set has aged out of the retention window. The
    /// receipt still verifies; membership can no longer be recomputed, and a
    /// caller needs to know which of those two it is holding.
    pub entries_available: bool,
}

/// An ed25519 public key receipts verify under, keyed by the `signer_kid` that
/// appears inside the receipt itself.
#[derive(Debug, Clone, Serialize)]
pub struct PublishedSigningKey {
    pub signer_kid: String,
    pub algorithm: &'static str,
    pub public_key_hex: String,
}

impl PublishedSigningKey {
    pub fn ed25519(signer_kid: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            signer_kid: signer_kid.into(),
            algorithm: "ed25519",
            public_key_hex: hex::encode(public_key),
        }
    }
}

pub trait SnapshotArtifactStore: Send + Sync + 'static {
    /// The most recent snapshot that is actually verifiable — which is not
    /// necessarily the most recent snapshot. Rows minted before the signed bytes
    /// were persisted cannot be verified and must not be offered as if they
    /// could.
    fn latest(&self) -> Result<Option<SnapshotArtifact>, ApiError>;

    fn by_id(&self, snapshot_id_hex: &str) -> Result<Option<SnapshotArtifact>, ApiError>;

    /// The entry set as stored, byte for byte.
    ///
    /// Raw bytes, never a parsed value: re-serialising through a JSON writer
    /// could change how `canonical_json` is escaped, and these bytes only have
    /// worth because they re-digest to the published root.
    fn entries_json(&self, snapshot_id_hex: &str) -> Result<Option<Vec<u8>>, ApiError>;

    /// Empty means no key is publishable, which is the honest answer when the
    /// registry is running unsigned. Never synthesise one.
    fn signing_keys(&self) -> Vec<PublishedSigningKey>;
}

/// Test double. Also what a registry with no signer configured effectively is:
/// nothing to serve, and it says so rather than pretending.
#[derive(Default)]
pub struct InMemorySnapshotArtifactStore {
    artifacts: Vec<(SnapshotArtifact, Option<Vec<u8>>)>,
    keys: Vec<PublishedSigningKey>,
}

impl InMemorySnapshotArtifactStore {
    pub fn with_artifact(mut self, artifact: SnapshotArtifact, entries: Option<Vec<u8>>) -> Self {
        self.artifacts.push((artifact, entries));
        self
    }

    pub fn with_key(mut self, key: PublishedSigningKey) -> Self {
        self.keys.push(key);
        self
    }

    pub fn shared(self) -> Arc<dyn SnapshotArtifactStore> {
        Arc::new(self)
    }
}

impl SnapshotArtifactStore for InMemorySnapshotArtifactStore {
    fn latest(&self) -> Result<Option<SnapshotArtifact>, ApiError> {
        Ok(self.artifacts.last().map(|(artifact, _)| artifact.clone()))
    }

    fn by_id(&self, snapshot_id_hex: &str) -> Result<Option<SnapshotArtifact>, ApiError> {
        Ok(self
            .artifacts
            .iter()
            .find(|(artifact, _)| artifact.snapshot_id == snapshot_id_hex)
            .map(|(artifact, _)| artifact.clone()))
    }

    fn entries_json(&self, snapshot_id_hex: &str) -> Result<Option<Vec<u8>>, ApiError> {
        Ok(self
            .artifacts
            .iter()
            .find(|(artifact, _)| artifact.snapshot_id == snapshot_id_hex)
            .and_then(|(_, entries)| entries.clone()))
    }

    fn signing_keys(&self) -> Vec<PublishedSigningKey> {
        self.keys.clone()
    }
}
