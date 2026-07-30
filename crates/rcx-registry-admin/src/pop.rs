//! Publisher proof-of-possession.
//!
//! A publisher identity is a passport fingerprint that **commits to** an ed25519
//! public key: `p_` followed by the hex of the first 16 bytes of
//! `blake3(public_key)`. That is the portfolio-canonical derivation — see
//! `crux-session::passport::passport_fpr_from_public_key`, whose own doc comment
//! names RCX as a consumer. It is reproduced here rather than imported because
//! RCX-Registry does not link the daemon crates.
//!
//! Verifying a publisher's right to a namespace is three *independent* facts:
//!
//! 1. the stated fingerprint really is the fingerprint of the presented key
//!    (`check_fingerprint`) — stops a caller naming someone else's passport;
//! 2. the caller holds that key's private half (`verify_pop`, a signature over a
//!    server-issued nonce) — stops replay of a public proof by an observer;
//! 3. the namespace proof (DNS TXT / GitHub OAuth) names that same fingerprint —
//!    stops a keyholder claiming a namespace they do not control.
//!
//! Any one of the three alone is insufficient, which is precisely why the routes
//! that shipped with only (3) were closed.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

/// Bytes of `blake3(pubkey)` that form a passport fingerprint.
pub const PASSPORT_FPR_BYTES: usize = 16;
/// How long an issued challenge nonce stays usable.
pub const DEFAULT_NONCE_TTL_MS: u64 = 900_000;
/// Domain separator for the proof-of-possession preimage.
const POP_DOMAIN: &[u8] = b"rcx-pop-v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PopError {
    #[error("public key is not valid hex: {0}")]
    MalformedPublicKey(String),
    #[error("public key is {0} bytes, expected 32")]
    PublicKeyLength(usize),
    #[error("signature is not valid hex: {0}")]
    MalformedSignature(String),
    #[error("signature is {0} bytes, expected 64")]
    SignatureLength(usize),
    #[error(
        "passport fingerprint `{stated}` does not match the presented key (derived `{derived}`)"
    )]
    FingerprintMismatch { stated: String, derived: String },
    #[error("proof-of-possession signature did not verify")]
    BadSignature,
    #[error("challenge nonce is unknown, already used, or expired")]
    UnknownNonce,
    #[error("challenge nonce was issued for a different server_name, passport, or key")]
    NonceBindingMismatch,
    #[error("nonce store mutex poisoned")]
    StorePoisoned,
}

/// Canonical passport fingerprint of an ed25519 public key.
pub fn passport_fpr_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    format!(
        "p_{}",
        hex::encode(&digest.as_bytes()[..PASSPORT_FPR_BYTES])
    )
}

fn decode_public_key(public_key_hex: &str) -> Result<[u8; 32], PopError> {
    let bytes =
        hex::decode(public_key_hex).map_err(|e| PopError::MalformedPublicKey(e.to_string()))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| PopError::PublicKeyLength(len))
}

/// Fact (1): the stated fingerprint is genuinely derived from the presented key.
pub fn check_fingerprint(fpr: &str, public_key_hex: &str) -> Result<(), PopError> {
    let key = decode_public_key(public_key_hex)?;
    let derived = passport_fpr_from_public_key(&key);
    if derived != fpr {
        return Err(PopError::FingerprintMismatch {
            stated: fpr.to_string(),
            derived,
        });
    }
    Ok(())
}

/// The exact bytes a caller signs to prove key possession.
///
/// Domain-separated and length-prefixed: without the length prefixes,
/// `(server_name="a", fpr="bc")` and `(server_name="ab", fpr="c")` would produce
/// the same preimage and a signature for one would validate the other.
pub fn challenge_signing_bytes(nonce_hex: &str, server_name: &str, passport_fpr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + server_name.len() + passport_fpr.len());
    out.extend_from_slice(POP_DOMAIN);
    out.push(0);
    for field in [nonce_hex, server_name, passport_fpr] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// Fact (2): the caller holds the private half of the presented key.
///
/// Re-checks the fingerprint binding, so a caller cannot present key A with a
/// valid signature while claiming fingerprint B.
pub fn verify_pop(
    nonce_hex: &str,
    server_name: &str,
    passport_fpr: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), PopError> {
    check_fingerprint(passport_fpr, public_key_hex)?;
    let key_bytes = decode_public_key(public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| PopError::BadSignature)?;

    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| PopError::MalformedSignature(e.to_string()))?;
    let sig_len = sig_bytes.len();
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| PopError::SignatureLength(sig_len))?;

    let message = challenge_signing_bytes(nonce_hex, server_name, passport_fpr);
    verifying_key
        .verify(&message, &Signature::from_bytes(&sig_arr))
        .map_err(|_| PopError::BadSignature)
}

/// What a nonce was issued for. A nonce is only usable with the same triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceBinding {
    pub server_name: String,
    pub passport_fpr: String,
    pub public_key_hex: String,
}

struct NonceEntry {
    binding: NonceBinding,
    expires_at_ms: u64,
}

/// Single-use, TTL-bounded challenge nonces.
///
/// `consume` removes the entry before validating the binding, so a wrong-binding
/// attempt still burns the nonce rather than allowing unlimited guesses against a
/// live challenge.
pub struct NonceStore {
    ttl_ms: u64,
    entries: Mutex<HashMap<String, NonceEntry>>,
}

impl NonceStore {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    /// Record a server-generated nonce. Returns its expiry.
    pub fn issue(
        &self,
        now_ms: u64,
        nonce_hex: &str,
        binding: NonceBinding,
    ) -> Result<u64, PopError> {
        let expires_at_ms = now_ms.saturating_add(self.ttl_ms);
        let mut guard = self.entries.lock().map_err(|_| PopError::StorePoisoned)?;
        guard.retain(|_, e| now_ms <= e.expires_at_ms);
        guard.insert(
            nonce_hex.to_string(),
            NonceEntry {
                binding,
                expires_at_ms,
            },
        );
        Ok(expires_at_ms)
    }

    /// Spend a nonce. Fails closed on unknown, expired, reused, or rebound nonces.
    pub fn consume(
        &self,
        now_ms: u64,
        nonce_hex: &str,
        expected: &NonceBinding,
    ) -> Result<(), PopError> {
        let mut guard = self.entries.lock().map_err(|_| PopError::StorePoisoned)?;
        let entry = guard.remove(nonce_hex).ok_or(PopError::UnknownNonce)?;
        if now_ms > entry.expires_at_ms {
            return Err(PopError::UnknownNonce);
        }
        if &entry.binding != expected {
            return Err(PopError::NonceBindingMismatch);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What an OAuth `state` value was issued for.
///
/// `redirect_uri` is part of the binding deliberately: without it, a caller who
/// obtains a valid `state` could complete the flow against a redirect target the
/// server never authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthStateBinding {
    pub server_name: String,
    pub publisher_passport: String,
    pub redirect_uri: String,
}

struct OAuthStateEntry {
    binding: OAuthStateBinding,
    expires_at_ms: u64,
}

/// Server-issued, single-use, TTL-bounded OAuth `state` values.
///
/// Deliberately a separate type from [`NonceStore`] rather than a generic reuse:
/// the two bindings protect different things, and conflating them invites a change
/// to one silently weakening the other.
pub struct OAuthStateStore {
    ttl_ms: u64,
    entries: Mutex<HashMap<String, OAuthStateEntry>>,
}

impl OAuthStateStore {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(
        &self,
        now_ms: u64,
        state: &str,
        binding: OAuthStateBinding,
    ) -> Result<u64, PopError> {
        let expires_at_ms = now_ms.saturating_add(self.ttl_ms);
        let mut guard = self.entries.lock().map_err(|_| PopError::StorePoisoned)?;
        guard.retain(|_, e| now_ms <= e.expires_at_ms);
        guard.insert(
            state.to_string(),
            OAuthStateEntry {
                binding,
                expires_at_ms,
            },
        );
        Ok(expires_at_ms)
    }

    /// Spend a `state`. Fails closed on unknown, expired, replayed, or rebound values.
    pub fn consume(
        &self,
        now_ms: u64,
        state: &str,
        expected: &OAuthStateBinding,
    ) -> Result<(), PopError> {
        let mut guard = self.entries.lock().map_err(|_| PopError::StorePoisoned)?;
        let entry = guard.remove(state).ok_or(PopError::UnknownNonce)?;
        if now_ms > entry.expires_at_ms {
            return Err(PopError::UnknownNonce);
        }
        if &entry.binding != expected {
            return Err(PopError::NonceBindingMismatch);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> (SigningKey, String, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public = key.verifying_key().to_bytes();
        (
            key,
            passport_fpr_from_public_key(&public),
            hex::encode(public),
        )
    }

    fn binding(server: &str, fpr: &str, pk: &str) -> NonceBinding {
        NonceBinding {
            server_name: server.to_string(),
            passport_fpr: fpr.to_string(),
            public_key_hex: pk.to_string(),
        }
    }

    #[test]
    fn fingerprint_derivation_matches_the_documented_shape() {
        let (_, fpr, pk) = keypair(1);
        assert!(fpr.starts_with("p_"));
        // p_ + 16 bytes hex
        assert_eq!(fpr.len(), 2 + PASSPORT_FPR_BYTES * 2);
        assert!(check_fingerprint(&fpr, &pk).is_ok());
    }

    #[test]
    fn fingerprint_check_rejects_key_substitution() {
        let (_, fpr_a, _) = keypair(1);
        let (_, _, pk_b) = keypair(2);
        // Claiming A's passport while presenting B's key must fail.
        assert!(matches!(
            check_fingerprint(&fpr_a, &pk_b),
            Err(PopError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn pop_round_trip_verifies() {
        let (sk, fpr, pk) = keypair(3);
        let msg = challenge_signing_bytes("abcd", "io.example.com/thing", &fpr);
        let sig = hex::encode(sk.sign(&msg).to_bytes());
        assert!(verify_pop("abcd", "io.example.com/thing", &fpr, &pk, &sig).is_ok());
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let (_, fpr, pk) = keypair(3);
        let (attacker, _, _) = keypair(9);
        let msg = challenge_signing_bytes("abcd", "io.example.com/thing", &fpr);
        let sig = hex::encode(attacker.sign(&msg).to_bytes());
        assert_eq!(
            verify_pop("abcd", "io.example.com/thing", &fpr, &pk, &sig),
            Err(PopError::BadSignature)
        );
    }

    #[test]
    fn signature_is_bound_to_nonce_and_server_name() {
        let (sk, fpr, pk) = keypair(4);
        let msg = challenge_signing_bytes("nonce-one", "io.example.com/a", &fpr);
        let sig = hex::encode(sk.sign(&msg).to_bytes());
        // Same signature must not validate for a different nonce...
        assert_eq!(
            verify_pop("nonce-two", "io.example.com/a", &fpr, &pk, &sig),
            Err(PopError::BadSignature)
        );
        // ...nor a different server_name.
        assert_eq!(
            verify_pop("nonce-one", "io.example.com/b", &fpr, &pk, &sig),
            Err(PopError::BadSignature)
        );
    }

    #[test]
    fn signing_bytes_are_unambiguous_across_field_boundaries() {
        // Without length prefixes these two would collide.
        let a = challenge_signing_bytes("n", "a", "bc");
        let b = challenge_signing_bytes("n", "ab", "c");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_is_single_use() {
        let (_, fpr, pk) = keypair(5);
        let store = NonceStore::new(DEFAULT_NONCE_TTL_MS);
        let b = binding("io.example.com/x", &fpr, &pk);
        store.issue(1_000, "n1", b.clone()).expect("issue");
        assert!(store.consume(2_000, "n1", &b).is_ok());
        // Replay must fail.
        assert_eq!(store.consume(3_000, "n1", &b), Err(PopError::UnknownNonce));
    }

    #[test]
    fn expired_nonce_is_rejected() {
        let (_, fpr, pk) = keypair(6);
        let store = NonceStore::new(1_000);
        let b = binding("io.example.com/x", &fpr, &pk);
        store.issue(1_000, "n2", b.clone()).expect("issue");
        assert_eq!(
            store.consume(1_000 + 1_001, "n2", &b),
            Err(PopError::UnknownNonce)
        );
    }

    #[test]
    fn nonce_bound_to_a_different_passport_is_rejected_and_burned() {
        let (_, fpr_a, pk_a) = keypair(7);
        let (_, fpr_b, pk_b) = keypair(8);
        let store = NonceStore::new(DEFAULT_NONCE_TTL_MS);
        store
            .issue(1_000, "n3", binding("io.example.com/x", &fpr_a, &pk_a))
            .expect("issue");
        // Wrong passport for this nonce.
        assert_eq!(
            store.consume(2_000, "n3", &binding("io.example.com/x", &fpr_b, &pk_b)),
            Err(PopError::NonceBindingMismatch)
        );
        // The failed attempt still consumed it — no unlimited guessing.
        assert_eq!(
            store.consume(2_000, "n3", &binding("io.example.com/x", &fpr_a, &pk_a)),
            Err(PopError::UnknownNonce)
        );
    }

    #[test]
    fn unknown_nonce_is_rejected() {
        let (_, fpr, pk) = keypair(1);
        let store = NonceStore::new(DEFAULT_NONCE_TTL_MS);
        assert_eq!(
            store.consume(
                1_000,
                "never-issued",
                &binding("io.example.com/x", &fpr, &pk)
            ),
            Err(PopError::UnknownNonce)
        );
    }

    fn oauth_binding(server: &str, passport: &str, redirect: &str) -> OAuthStateBinding {
        OAuthStateBinding {
            server_name: server.to_string(),
            publisher_passport: passport.to_string(),
            redirect_uri: redirect.to_string(),
        }
    }

    #[test]
    fn oauth_state_never_issued_is_rejected() {
        let store = OAuthStateStore::new(DEFAULT_NONCE_TTL_MS);
        // The CSRF case: an attacker-chosen state must not be accepted.
        assert_eq!(
            store.consume(
                1_000,
                "attacker-chosen",
                &oauth_binding("io.github.org/x", "passport:github:org", "https://cb")
            ),
            Err(PopError::UnknownNonce)
        );
    }

    #[test]
    fn oauth_state_is_single_use() {
        let store = OAuthStateStore::new(DEFAULT_NONCE_TTL_MS);
        let b = oauth_binding("io.github.org/x", "passport:github:org", "https://cb");
        store.issue(1_000, "s1", b.clone()).expect("issue");
        assert!(store.consume(2_000, "s1", &b).is_ok());
        assert_eq!(store.consume(3_000, "s1", &b), Err(PopError::UnknownNonce));
    }

    #[test]
    fn oauth_state_is_bound_to_redirect_uri() {
        let store = OAuthStateStore::new(DEFAULT_NONCE_TTL_MS);
        store
            .issue(
                1_000,
                "s2",
                oauth_binding("io.github.org/x", "passport:github:org", "https://good"),
            )
            .expect("issue");
        assert_eq!(
            store.consume(
                2_000,
                "s2",
                &oauth_binding("io.github.org/x", "passport:github:org", "https://evil")
            ),
            Err(PopError::NonceBindingMismatch)
        );
    }

    #[test]
    fn oauth_state_expires() {
        let store = OAuthStateStore::new(1_000);
        let b = oauth_binding("io.github.org/x", "passport:github:org", "https://cb");
        store.issue(1_000, "s3", b.clone()).expect("issue");
        assert_eq!(store.consume(2_002, "s3", &b), Err(PopError::UnknownNonce));
    }

    #[test]
    fn issuing_sweeps_expired_entries() {
        let (_, fpr, pk) = keypair(2);
        let store = NonceStore::new(1_000);
        store
            .issue(1_000, "old", binding("io.example.com/x", &fpr, &pk))
            .expect("issue");
        assert_eq!(store.len(), 1);
        store
            .issue(10_000, "new", binding("io.example.com/x", &fpr, &pk))
            .expect("issue");
        assert_eq!(store.len(), 1, "expired entry should have been swept");
    }
}
