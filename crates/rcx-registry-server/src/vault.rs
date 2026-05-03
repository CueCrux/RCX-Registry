//! Vault Transit ed25519 signer.
//!
//! Signs canonical CBOR receipt bytes (with sig + signer_kid zeroed) by
//! POSTing them to `<VAULT_ADDR>/v1/transit/sign/<key>` with header
//! `X-Vault-Token: <token>`. Returns the raw 64-byte ed25519 signature.
//!
//! Vault returns signatures prefixed with `vault:v1:`; we strip the
//! prefix, base64-decode the rest, and verify the byte length.

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
    #[error("vault response missing expected `data.signature` field")]
    MissingSignature,
    #[error("signature lacked `vault:v1:` prefix: `{0}`")]
    UnexpectedPrefix(String),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("expected {SIGNATURE_LEN}-byte ed25519 signature, got {0}")]
    SignatureLength(usize),
}

pub trait Signer: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], VaultError>;
    fn signer_kid(&self) -> &str;
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
    token: String,
    namespace: Option<String>,
    key_name: String,
    signer_kid: String,
}

impl VaultTransitSigner {
    pub fn new(
        addr: impl Into<String>,
        token: impl Into<String>,
        namespace: Option<String>,
        key_name: impl Into<String>,
        signer_kid: impl Into<String>,
    ) -> Result<Self, VaultError> {
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        Ok(Self {
            client,
            addr: addr.into().trim_end_matches('/').to_string(),
            token: token.into(),
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
        let mut request = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
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
}

#[cfg(test)]
mod tests {
    use super::{Signer, UnsignedSigner};
    use rcx_registry_crown::SIGNATURE_LEN;

    #[test]
    fn unsigned_signer_returns_zero_signature() {
        let signer = UnsignedSigner::new("vault:transit:test-key");
        let signature = signer.sign(b"any-bytes").expect("noop sign should succeed");
        assert_eq!(signature, [0u8; SIGNATURE_LEN]);
        assert_eq!(signer.signer_kid(), "vault:transit:test-key");
    }
}
