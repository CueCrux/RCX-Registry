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

use std::sync::{Arc, RwLock};

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

/// Whether a key is publishable, and if not, *why* not.
///
/// The two negative cases are deliberately distinct, for the same reason the
/// CLI separates exit 1 from exit 2: "this registry signs nothing" and "we could
/// not read the key just now" are opposite instructions to a caller. Collapsing
/// them into an empty list tells someone polling for a key to give up when they
/// should retry, or to retry forever when they should give up.
#[derive(Debug, Clone)]
pub enum SigningKeyStatus {
    Published(Vec<PublishedSigningKey>),
    /// The signer has no key at all — an unsigned registry. Terminal; nothing
    /// will arrive by waiting.
    Unsigned,
    /// A key exists but has not been read yet. Retryable.
    Unavailable,
}

/// A key slot that starts empty and is filled once resolution succeeds.
///
/// Resolution happens off the request path, so a key store that is briefly
/// unreachable never adds latency to a public read — and, unlike a value
/// captured once at boot, a transient failure at startup does not leave the
/// registry publishing nothing until someone restarts it. That startup race is
/// the expected case, not the exotic one: with a `vault-agent` sink there is no
/// guaranteed start order between the agent and this process.
pub struct SigningKeyPublication {
    status: RwLock<SigningKeyStatus>,
}

impl Default for SigningKeyPublication {
    fn default() -> Self {
        Self {
            status: RwLock::new(SigningKeyStatus::Unavailable),
        }
    }
}

impl SigningKeyPublication {
    pub fn status(&self) -> SigningKeyStatus {
        match self.status.read() {
            Ok(guard) => guard.clone(),
            // A poisoned lock means a writer panicked. Report unavailable rather
            // than an empty list: we genuinely do not know what the key is.
            Err(_) => SigningKeyStatus::Unavailable,
        }
    }

    pub fn publish(&self, keys: Vec<PublishedSigningKey>) {
        if let Ok(mut guard) = self.status.write() {
            *guard = SigningKeyStatus::Published(keys);
        }
    }

    pub fn mark_unsigned(&self) {
        if let Ok(mut guard) = self.status.write() {
            *guard = SigningKeyStatus::Unsigned;
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

    /// Verifiable snapshots, newest first, optionally starting before an
    /// RFC-3339 instant.
    ///
    /// Only snapshots that can actually be checked appear here. Listing one a
    /// caller cannot verify would put a row in an explorer that dead-ends.
    fn list(&self, limit: u32, before: Option<&str>) -> Result<Vec<SnapshotArtifact>, ApiError>;

    /// The entry set as stored, byte for byte.
    ///
    /// Raw bytes, never a parsed value: re-serialising through a JSON writer
    /// could change how `canonical_json` is escaped, and these bytes only have
    /// worth because they re-digest to the published root.
    fn entries_json(&self, snapshot_id_hex: &str) -> Result<Option<Vec<u8>>, ApiError>;

    /// Never synthesise a key: a placeholder would have third parties verifying
    /// against something that signs nothing.
    fn signing_keys(&self) -> SigningKeyStatus;
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

    fn list(&self, limit: u32, _before: Option<&str>) -> Result<Vec<SnapshotArtifact>, ApiError> {
        Ok(self
            .artifacts
            .iter()
            .rev()
            .take(limit as usize)
            .map(|(artifact, _)| artifact.clone())
            .collect())
    }

    /// No keys configured reports `Unsigned`, not `Unavailable`: an in-memory
    /// store has no key source to wait on, so telling a caller to retry would be
    /// telling them to wait for something that is never coming.
    fn signing_keys(&self) -> SigningKeyStatus {
        if self.keys.is_empty() {
            SigningKeyStatus::Unsigned
        } else {
            SigningKeyStatus::Published(self.keys.clone())
        }
    }
}
