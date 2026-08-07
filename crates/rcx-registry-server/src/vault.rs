//! Vault Transit ed25519 signer.
//!
//! Signs canonical CBOR receipt bytes (with sig + signer_kid zeroed) by
//! POSTing them to `<VAULT_ADDR>/v1/transit/sign/<key>` with header
//! `X-Vault-Token: <token>`. Returns the raw 64-byte ed25519 signature.
//!
//! Vault returns signatures prefixed with `vault:v1:`; we strip the
//! prefix, base64-decode the rest, and verify the byte length.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use rcx_registry_crown::SIGNATURE_LEN;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("vault returned status {0}")]
    Status(u16),
    #[error("reading vault token file `{path}`: {source}")]
    TokenFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("vault token file `{0}` is empty")]
    EmptyTokenFile(String),
    #[error("vault response missing expected `data.signature` field")]
    MissingSignature,
    #[error("signature lacked `vault:v1:` prefix: `{0}`")]
    UnexpectedPrefix(String),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("expected {SIGNATURE_LEN}-byte ed25519 signature, got {0}")]
    SignatureLength(usize),
    #[error("expected 32-byte ed25519 public key, got {0}")]
    PublicKeyLength(usize),
}

pub trait Signer: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], VaultError>;
    fn signer_kid(&self) -> &str;

    /// The ed25519 **public** key this signer's receipts verify under.
    ///
    /// `None` means "no verifiable key", not "not fetched yet" — a caller that
    /// gets `None` must publish nothing rather than publish a placeholder, or
    /// third parties would verify against a key that signs nothing.
    fn public_key(&self) -> Result<Option<[u8; 32]>, VaultError> {
        Ok(None)
    }
}

/// Where the Vault token comes from.
///
/// `File` is the production shape: a `vault-agent` sink writes a short-TTL token
/// to a root-only file and rotates it in place. The value is therefore read fresh
/// on every sign rather than captured at boot, so rotation needs no restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// Literal token from `VAULT_TOKEN`. Rotating it requires recreating the process.
    Static(String),
    /// Path to a token file, typically a `vault-agent` sink.
    File(PathBuf),
}

impl TokenSource {
    /// Read the current token. Called once per sign.
    pub fn resolve(&self) -> Result<String, VaultError> {
        match self {
            TokenSource::Static(token) => Ok(token.clone()),
            TokenSource::File(path) => Self::read_file(path),
        }
    }

    fn read_file(path: &Path) -> Result<String, VaultError> {
        let raw = fs::read_to_string(path).map_err(|source| VaultError::TokenFile {
            path: path.display().to_string(),
            source,
        })?;
        // Sinks and hand-written files both tend to carry a trailing newline.
        let token = raw.trim().to_string();
        if token.is_empty() {
            return Err(VaultError::EmptyTokenFile(path.display().to_string()));
        }
        Ok(token)
    }
}

/// Logs the message and returns a zeroed signature. Use ONLY when no
/// `VAULT_ADDR` is configured (e.g. local dev) — the resulting receipt is
/// not signed and must not be considered verifiable.
pub struct UnsignedSigner {
    signer_kid: String,
}

impl UnsignedSigner {
    pub fn new(signer_kid: impl Into<String>) -> Self {
        Self {
            signer_kid: signer_kid.into(),
        }
    }
}

impl Signer for UnsignedSigner {
    fn sign(&self, _message: &[u8]) -> Result<[u8; SIGNATURE_LEN], VaultError> {
        Ok([0u8; SIGNATURE_LEN])
    }
    fn signer_kid(&self) -> &str {
        &self.signer_kid
    }
}

/// Real Vault Transit signer.
pub struct VaultTransitSigner {
    client: Client,
    addr: String,
    token: TokenSource,
    namespace: Option<String>,
    key_name: String,
    signer_kid: String,
}

impl VaultTransitSigner {
    pub fn new(
        addr: impl Into<String>,
        token: TokenSource,
        namespace: Option<String>,
        key_name: impl Into<String>,
        signer_kid: impl Into<String>,
    ) -> Result<Self, VaultError> {
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        Ok(Self {
            client,
            addr: addr.into().trim_end_matches('/').to_string(),
            token,
            namespace,
            key_name: key_name.into(),
            signer_kid: signer_kid.into(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct VaultSignResponse {
    data: VaultSignData,
}

#[derive(Debug, Deserialize)]
struct VaultSignData {
    signature: String,
}

impl Signer for VaultTransitSigner {
    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], VaultError> {
        let url = format!("{}/v1/transit/sign/{}", self.addr, self.key_name);
        // Resolved per call so a rotating `vault-agent` sink is picked up in place.
        let token = self.token.resolve()?;
        let mut request = self
            .client
            .post(&url)
            .header("X-Vault-Token", &token)
            .json(&json!({
                "input": BASE64_STANDARD.encode(message),
                "signature_algorithm": "ed25519",
                "marshaling_algorithm": "asn1",
            }));
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        let response = request.send()?;
        if !response.status().is_success() {
            return Err(VaultError::Status(response.status().as_u16()));
        }
        let body: VaultSignResponse = response.json()?;
        let stripped = body
            .data
            .signature
            .strip_prefix("vault:v1:")
            .ok_or(VaultError::UnexpectedPrefix(body.data.signature.clone()))?;
        let bytes = BASE64_STANDARD.decode(stripped)?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(VaultError::SignatureLength(bytes.len()));
        }
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes);
        Ok(signature)
    }

    fn signer_kid(&self) -> &str {
        &self.signer_kid
    }

    /// Reads the public half from Vault Transit.
    ///
    /// Transit returns one entry per key version; we take the highest, which is
    /// the version `sign` uses. Key *history* — so that receipts signed under a
    /// rotated key still verify — is M3c and deliberately not attempted here: a
    /// half-built history that silently drops old versions would break exactly
    /// the receipts it claims to preserve.
    fn public_key(&self) -> Result<Option<[u8; 32]>, VaultError> {
        let url = format!("{}/v1/transit/keys/{}", self.addr, self.key_name);
        let token = self.token.resolve()?;
        let mut request = self.client.get(&url).header("X-Vault-Token", &token);
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        let response = request.send()?;
        if !response.status().is_success() {
            return Err(VaultError::Status(response.status().as_u16()));
        }
        let body: VaultKeyResponse = response.json()?;

        let latest = body
            .data
            .keys
            .iter()
            .filter_map(|(version, entry)| {
                version.parse::<u64>().ok().map(|number| (number, entry))
            })
            .max_by_key(|(number, _)| *number);
        let Some((_, entry)) = latest else {
            return Ok(None);
        };

        let bytes = BASE64_STANDARD.decode(entry.public_key.trim())?;
        if bytes.len() != 32 {
            return Err(VaultError::PublicKeyLength(bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Some(key))
    }
}

#[derive(Debug, Deserialize)]
struct VaultKeyResponse {
    data: VaultKeyData,
}

#[derive(Debug, Deserialize)]
struct VaultKeyData {
    keys: std::collections::BTreeMap<String, VaultKeyEntry>,
}

#[derive(Debug, Deserialize)]
struct VaultKeyEntry {
    public_key: String,
}

#[cfg(test)]
mod tests {
    use super::{Signer, TokenSource, UnsignedSigner, VaultError};
    use rcx_registry_crown::SIGNATURE_LEN;
    use std::fs;
    use std::path::PathBuf;

    /// Unique scratch path — no `tempfile` dev-dependency in this crate.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rcx-token-{}-{}", std::process::id(), name));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn unsigned_signer_returns_zero_signature() {
        let signer = UnsignedSigner::new("vault:transit:test-key");
        let signature = signer.sign(b"any-bytes").expect("noop sign should succeed");
        assert_eq!(signature, [0u8; SIGNATURE_LEN]);
        assert_eq!(signer.signer_kid(), "vault:transit:test-key");
    }

    #[test]
    fn static_token_source_resolves_to_its_literal() {
        let source = TokenSource::Static("hvs.example".to_string());
        assert_eq!(source.resolve().expect("static resolves"), "hvs.example");
    }

    #[test]
    fn file_token_source_reads_and_trims() {
        let path = scratch("trims");
        // vault-agent sinks and hand-written files both carry a trailing newline.
        fs::write(&path, "  hvs.from-sink\n").expect("write scratch token");
        let source = TokenSource::File(path.clone());
        assert_eq!(source.resolve().expect("file resolves"), "hvs.from-sink");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn file_token_source_picks_up_rotation_without_reconstruction() {
        let path = scratch("rotates");
        fs::write(&path, "hvs.first\n").expect("write scratch token");
        let source = TokenSource::File(path.clone());
        assert_eq!(source.resolve().expect("first resolve"), "hvs.first");
        // Simulate the sink rotating the token in place.
        fs::write(&path, "hvs.second\n").expect("rotate scratch token");
        assert_eq!(source.resolve().expect("second resolve"), "hvs.second");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_token_file_is_rejected() {
        let path = scratch("empty");
        fs::write(&path, "\n   \n").expect("write scratch token");
        let source = TokenSource::File(path.clone());
        assert!(matches!(
            source.resolve(),
            Err(VaultError::EmptyTokenFile(_))
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_token_file_reports_its_path() {
        let path = scratch("absent");
        let source = TokenSource::File(path.clone());
        match source.resolve() {
            Err(VaultError::TokenFile { path: reported, .. }) => {
                assert_eq!(reported, path.display().to_string());
            }
            other => panic!("expected TokenFile error, got {other:?}"),
        }
    }
}
