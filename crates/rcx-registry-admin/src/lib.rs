//! Internal onboarding and moderation helpers.

use rcx_registry_crown::{PublisherRightsVerifiedReceipt, ReceiptDocument, HASH_LEN, ULID_LEN};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported publisher-rights verification methods in v1.0.
pub const VERIFICATION_METHODS: [&str; 3] = ["github_oauth", "dns_txt", "manual"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceKind {
    GitHub { owner: String },
    ReverseDns { domain: String },
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceClaim {
    pub namespace: String,
    pub server_name: String,
    pub kind: NamespaceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTxtChallenge {
    pub record_name: String,
    pub expected_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherRightsRecord {
    pub publisher_passport: String,
    pub namespace: String,
    pub server_name: String,
    pub verification_method: String,
    pub verified_at: u64,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationMethod {
    GitHubOAuth,
    DnsTxt,
    Manual,
}

impl VerificationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitHubOAuth => "github_oauth",
            Self::DnsTxt => "dns_txt",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdminError {
    #[error("server name must include a namespace and path")]
    InvalidServerName,
    #[error("unsupported namespace `{0}`")]
    UnsupportedNamespace(String),
    #[error("passport `{passport}` does not control github owner `{owner}`")]
    GitHubPassportMismatch { passport: String, owner: String },
    #[error("anonymous namespaces cannot be rights-verified in v1.0")]
    AnonymousNamespace,
    #[error("dns txt verification only applies to reverse-dns namespaces")]
    DnsNamespaceRequired,
    #[error("manual verification requires a non-anonymous namespace")]
    ManualNamespaceRequired,
    #[error("dns txt record `{record_name}` did not contain `{expected_value}`")]
    DnsTxtMismatch {
        record_name: String,
        expected_value: String,
    },
}

pub fn classify_namespace(server_name: &str) -> Result<NamespaceClaim, AdminError> {
    let Some((namespace, _rest)) = server_name.split_once('/') else {
        return Err(AdminError::InvalidServerName);
    };

    let kind = if let Some(owner) = namespace.strip_prefix("io.github.") {
        NamespaceKind::GitHub {
            owner: owner.to_string(),
        }
    } else if namespace == "io.modelcontextprotocol.anonymous" {
        NamespaceKind::Anonymous
    } else if let Some(domain) = namespace.strip_prefix("io.") {
        NamespaceKind::ReverseDns {
            domain: domain.to_string(),
        }
    } else {
        return Err(AdminError::UnsupportedNamespace(namespace.to_string()));
    };

    Ok(NamespaceClaim {
        namespace: namespace.to_string(),
        server_name: server_name.to_string(),
        kind,
    })
}

pub fn verify_github_passport(
    claim: &NamespaceClaim,
    publisher_passport: &str,
) -> Result<(), AdminError> {
    match &claim.kind {
        NamespaceKind::GitHub { owner } => {
            let expected = format!("passport:github:{owner}");
            if publisher_passport == expected {
                Ok(())
            } else {
                Err(AdminError::GitHubPassportMismatch {
                    passport: publisher_passport.to_string(),
                    owner: owner.clone(),
                })
            }
        }
        NamespaceKind::Anonymous => Err(AdminError::AnonymousNamespace),
        NamespaceKind::ReverseDns { .. } => {
            Err(AdminError::UnsupportedNamespace(claim.namespace.clone()))
        }
    }
}

pub fn dns_txt_challenge(domain: &str, passport_fingerprint: &str) -> DnsTxtChallenge {
    DnsTxtChallenge {
        record_name: format!("_rcx-registry.{domain}"),
        expected_value: passport_fingerprint.to_string(),
    }
}

pub fn verify_dns_txt(
    claim: &NamespaceClaim,
    passport_fingerprint: &str,
    observed_values: &[String],
) -> Result<DnsTxtChallenge, AdminError> {
    let NamespaceKind::ReverseDns { domain } = &claim.kind else {
        return Err(AdminError::DnsNamespaceRequired);
    };

    let challenge = dns_txt_challenge(domain, passport_fingerprint);
    if observed_values
        .iter()
        .any(|value| value == &challenge.expected_value)
    {
        Ok(challenge)
    } else {
        Err(AdminError::DnsTxtMismatch {
            record_name: challenge.record_name,
            expected_value: challenge.expected_value,
        })
    }
}

pub fn verify_manual_review(claim: &NamespaceClaim) -> Result<(), AdminError> {
    match claim.kind {
        NamespaceKind::Anonymous => Err(AdminError::ManualNamespaceRequired),
        NamespaceKind::GitHub { .. } | NamespaceKind::ReverseDns { .. } => Ok(()),
    }
}

pub fn build_publisher_rights_verified_receipt(
    event_id: [u8; ULID_LEN],
    publisher_passport: &str,
    namespace: &str,
    method: VerificationMethod,
    verified_at_ms: u64,
    signer_kid: &str,
) -> PublisherRightsVerifiedReceipt {
    let mut receipt = PublisherRightsVerifiedReceipt {
        event_id,
        publisher_passport: publisher_passport.to_string(),
        namespace: namespace.to_string(),
        verification_method: method.as_str().to_string(),
        verified_at: verified_at_ms,
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; 64],
        signer_kid: signer_kid.to_string(),
    };
    receipt.receipt_hash = receipt.compute_hash();
    receipt
}

pub fn publisher_rights_record(
    claim: &NamespaceClaim,
    publisher_passport: &str,
    method: VerificationMethod,
    verified_at_ms: u64,
    receipt_hash: &[u8; HASH_LEN],
) -> PublisherRightsRecord {
    PublisherRightsRecord {
        publisher_passport: publisher_passport.to_string(),
        namespace: claim.namespace.clone(),
        server_name: claim.server_name.clone(),
        verification_method: method.as_str().to_string(),
        verified_at: verified_at_ms,
        receipt_hash: format!("blake3:{}", hex::encode(receipt_hash)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_publisher_rights_verified_receipt, classify_namespace, dns_txt_challenge,
        publisher_rights_record, verify_dns_txt, verify_github_passport, verify_manual_review,
        NamespaceKind, VerificationMethod, VERIFICATION_METHODS,
    };

    #[test]
    fn supported_verification_methods_match_plan() {
        assert_eq!(VERIFICATION_METHODS, ["github_oauth", "dns_txt", "manual"]);
    }

    #[test]
    fn classify_github_namespace() {
        let claim = classify_namespace("io.github.example-org/document-proofer")
            .expect("github namespace should parse");
        assert_eq!(claim.namespace, "io.github.example-org");
        assert_eq!(
            claim.kind,
            NamespaceKind::GitHub {
                owner: "example-org".to_string()
            }
        );
    }

    #[test]
    fn classify_reverse_dns_and_anonymous_namespaces() {
        let reverse_dns = classify_namespace("io.example.com/document-proofer")
            .expect("reverse dns should parse");
        assert_eq!(
            reverse_dns.kind,
            NamespaceKind::ReverseDns {
                domain: "example.com".to_string()
            }
        );

        let anonymous = classify_namespace("io.modelcontextprotocol.anonymous/tool")
            .expect("anonymous namespace should parse");
        assert_eq!(anonymous.kind, NamespaceKind::Anonymous);
    }

    #[test]
    fn github_passport_must_match_owner() {
        let claim = classify_namespace("io.github.example-org/document-proofer")
            .expect("github namespace should parse");

        verify_github_passport(&claim, "passport:github:example-org")
            .expect("matching github passport should verify");
        assert!(verify_github_passport(&claim, "passport:github:other-org").is_err());
    }

    #[test]
    fn dns_txt_helper_uses_required_record_name() {
        let challenge = dns_txt_challenge("example.com", "fingerprint:abc123");
        assert_eq!(challenge.record_name, "_rcx-registry.example.com");
        assert_eq!(challenge.expected_value, "fingerprint:abc123");
    }

    #[test]
    fn dns_txt_verification_requires_expected_value() {
        let claim = classify_namespace("io.example.com/document-proofer")
            .expect("reverse dns namespace should parse");

        let challenge = verify_dns_txt(
            &claim,
            "fingerprint:abc123",
            &["fingerprint:abc123".to_string()],
        )
        .expect("matching dns value should verify");
        assert_eq!(challenge.record_name, "_rcx-registry.example.com");

        assert!(verify_dns_txt(&claim, "fingerprint:abc123", &[]).is_err());
    }

    #[test]
    fn manual_review_rejects_anonymous_namespace() {
        let anonymous = classify_namespace("io.modelcontextprotocol.anonymous/tool")
            .expect("anonymous namespace should parse");
        assert!(verify_manual_review(&anonymous).is_err());

        let github = classify_namespace("io.github.example-org/document-proofer")
            .expect("github namespace should parse");
        verify_manual_review(&github).expect("github namespace should allow manual review");
    }

    #[test]
    fn publisher_rights_receipt_is_hashable_before_signing() {
        let receipt = build_publisher_rights_verified_receipt(
            [0x11; 16],
            "passport:github:example-org",
            "io.github.example-org",
            VerificationMethod::GitHubOAuth,
            1_776_683_200_000,
            "vault:transit:rcx-registry-signing-key-1",
        );

        assert_eq!(receipt.verification_method, "github_oauth");
        assert_ne!(receipt.receipt_hash, [0u8; 32]);
        assert_eq!(receipt.receipt_signature, [0u8; 64]);

        let claim = classify_namespace("io.github.example-org/document-proofer")
            .expect("github namespace should parse");
        let record = publisher_rights_record(
            &claim,
            "passport:github:example-org",
            VerificationMethod::GitHubOAuth,
            1_776_683_200_000,
            &receipt.receipt_hash,
        );

        assert_eq!(record.namespace, "io.github.example-org");
        assert!(record.receipt_hash.starts_with("blake3:"));
    }
}
