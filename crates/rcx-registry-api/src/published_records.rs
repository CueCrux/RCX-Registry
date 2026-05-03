// Published records — passport + project descriptors that originate on a
// Crux Daemon and land in the registry via `corecruxctl publish`. Fully
// additive vs. the existing publisher-rights / enrichment surfaces. Backs the
// Plan C R2 milestone (cuecrux-portfolio-tier-uplift-from-coordination).
//
// Scope of this module:
//   * Type definitions for PassportPublishRecord + ProjectPublishRecord
//     (mirror schemas/2026-05-01/{passport,project}-publish.schema.json).
//   * Storage trait + in-memory impl.
//   * Lookup + filtered-list helpers used by the HTTP handlers.
//
// Out of scope (TODO for the registry team):
//   * Persistent storage (Postgres / sled) — drop in alongside the in-memory
//     impl when the production rollout lands.
//   * Signature verification on insert. The HTTP handlers in lib.rs accept
//     records as already-validated; a real publish flow MUST verify
//     `signature` against `publisher_passport`'s public key over the
//     canonical-CBOR encoding of the record (project_hash / passport_hash).
//   * Sponsor-chain traversal — `lookup_lineage(passport_fpr)` returns just
//     the immediate `sponsor_passport_fpr` for now.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassportPublishRecord {
    pub schema_uri: String,
    pub publisher_passport: String,
    pub passport_fpr: String,
    pub passport_id: String,
    pub category: String,
    pub public_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor_passport_fpr: Option<String>,
    pub reputation_tier: String,
    pub receipt_count: u64,
    pub agent_work_gate: bool,
    #[serde(default)]
    pub is_default_for_category: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_metadata: Option<serde_json::Value>,
    pub issued_at: String,
    pub published_at: String,
    pub signature: String,
    pub signer_kid: String,
    pub passport_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectPublishRecord {
    pub schema_uri: String,
    pub publisher_passport: String,
    pub project_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planning_target: Option<String>,
    pub default_passport_fpr: String,
    pub allowed_passport_fprs: Vec<String>,
    pub working_tenant_categories: Vec<String>,
    #[serde(default)]
    pub linked_github_repos: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_metadata: Option<serde_json::Value>,
    pub created_at: String,
    pub published_at: String,
    pub signature: String,
    pub signer_kid: String,
    pub project_hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct PassportFilter {
    pub category: Option<String>,
    pub min_tier: Option<String>,
    pub agent_work_gate: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectFilter {
    pub publisher: Option<String>,
}

const TIER_ORDER: &[&str] = &["unverified", "basic", "established", "trusted", "elite"];

pub fn tier_rank(tier: &str) -> Option<usize> {
    TIER_ORDER.iter().position(|t| *t == tier)
}

pub trait PublishedRecordStore: Send + Sync + 'static {
    fn upsert_passport(&self, record: PassportPublishRecord) -> Result<(), ApiError>;
    fn get_passport(&self, passport_fpr: &str) -> Result<Option<PassportPublishRecord>, ApiError>;
    fn list_passports(&self, filter: &PassportFilter) -> Result<Vec<PassportPublishRecord>, ApiError>;
    fn upsert_project(&self, record: ProjectPublishRecord) -> Result<(), ApiError>;
    fn get_project(&self, publisher_passport: &str, project_id: &str)
        -> Result<Option<ProjectPublishRecord>, ApiError>;
    fn list_projects(&self, filter: &ProjectFilter) -> Result<Vec<ProjectPublishRecord>, ApiError>;
}

#[derive(Default)]
pub struct InMemoryPublishedRecordStore {
    passports: Mutex<BTreeMap<String, PassportPublishRecord>>,
    // Keyed by (publisher_passport, project_id).
    projects: Mutex<BTreeMap<(String, String), ProjectPublishRecord>>,
}

impl PublishedRecordStore for InMemoryPublishedRecordStore {
    fn upsert_passport(&self, record: PassportPublishRecord) -> Result<(), ApiError> {
        let mut guard = self
            .passports
            .lock()
            .map_err(|_| ApiError::Store("passport store mutex poisoned".to_string()))?;
        guard.insert(record.passport_fpr.clone(), record);
        Ok(())
    }

    fn get_passport(&self, passport_fpr: &str) -> Result<Option<PassportPublishRecord>, ApiError> {
        let guard = self
            .passports
            .lock()
            .map_err(|_| ApiError::Store("passport store mutex poisoned".to_string()))?;
        Ok(guard.get(passport_fpr).cloned())
    }

    fn list_passports(&self, filter: &PassportFilter) -> Result<Vec<PassportPublishRecord>, ApiError> {
        let guard = self
            .passports
            .lock()
            .map_err(|_| ApiError::Store("passport store mutex poisoned".to_string()))?;
        let min_rank = filter.min_tier.as_deref().and_then(tier_rank);
        let out: Vec<_> = guard
            .values()
            .filter(|r| filter.category.as_deref().map_or(true, |c| r.category == c))
            .filter(|r| filter.agent_work_gate.map_or(true, |g| r.agent_work_gate == g))
            .filter(|r| {
                min_rank
                    .map(|m| tier_rank(&r.reputation_tier).map_or(false, |t| t >= m))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        Ok(out)
    }

    fn upsert_project(&self, record: ProjectPublishRecord) -> Result<(), ApiError> {
        let mut guard = self
            .projects
            .lock()
            .map_err(|_| ApiError::Store("project store mutex poisoned".to_string()))?;
        guard.insert(
            (record.publisher_passport.clone(), record.project_id.clone()),
            record,
        );
        Ok(())
    }

    fn get_project(
        &self,
        publisher_passport: &str,
        project_id: &str,
    ) -> Result<Option<ProjectPublishRecord>, ApiError> {
        let guard = self
            .projects
            .lock()
            .map_err(|_| ApiError::Store("project store mutex poisoned".to_string()))?;
        Ok(guard
            .get(&(publisher_passport.to_string(), project_id.to_string()))
            .cloned())
    }

    fn list_projects(&self, filter: &ProjectFilter) -> Result<Vec<ProjectPublishRecord>, ApiError> {
        let guard = self
            .projects
            .lock()
            .map_err(|_| ApiError::Store("project store mutex poisoned".to_string()))?;
        let out: Vec<_> = guard
            .values()
            .filter(|r| {
                filter
                    .publisher
                    .as_deref()
                    .map_or(true, |p| r.publisher_passport == p)
            })
            .cloned()
            .collect();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_passport(fpr: &str, category: &str, tier: &str) -> PassportPublishRecord {
        PassportPublishRecord {
            schema_uri: "https://static.rcxprotocol.org/schemas/2026-05-01/passport-publish.schema.json"
                .to_string(),
            publisher_passport: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            passport_fpr: fpr.to_string(),
            passport_id: "alpha".to_string(),
            category: category.to_string(),
            public_key_hex: "00".repeat(32),
            sponsor_passport_fpr: None,
            reputation_tier: tier.to_string(),
            receipt_count: 0,
            agent_work_gate: false,
            is_default_for_category: true,
            operator_metadata: None,
            issued_at: "2026-05-01T00:00:00Z".to_string(),
            published_at: "2026-05-01T00:00:00Z".to_string(),
            signature: "00".repeat(64),
            signer_kid: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            passport_hash: "00".repeat(32),
        }
    }

    #[test]
    fn passport_upsert_get_round_trip() {
        let store = InMemoryPublishedRecordStore::default();
        let rec = sample_passport("p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "personal", "basic");
        store.upsert_passport(rec.clone()).expect("upsert");
        let loaded = store.get_passport(&rec.passport_fpr).expect("get").expect("present");
        assert_eq!(loaded, rec);
    }

    #[test]
    fn passport_filter_min_tier_and_category() {
        let store = InMemoryPublishedRecordStore::default();
        store
            .upsert_passport(sample_passport(
                "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "personal",
                "basic",
            ))
            .unwrap();
        store
            .upsert_passport(sample_passport(
                "p_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "work",
                "elite",
            ))
            .unwrap();
        store
            .upsert_passport(sample_passport(
                "p_cccccccccccccccccccccccccccccccc",
                "personal",
                "trusted",
            ))
            .unwrap();
        let trusted_or_better = store
            .list_passports(&PassportFilter {
                category: None,
                min_tier: Some("trusted".to_string()),
                agent_work_gate: None,
            })
            .unwrap();
        assert_eq!(trusted_or_better.len(), 2);
        let work_only = store
            .list_passports(&PassportFilter {
                category: Some("work".to_string()),
                min_tier: None,
                agent_work_gate: None,
            })
            .unwrap();
        assert_eq!(work_only.len(), 1);
        assert_eq!(work_only[0].passport_fpr, "p_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    }

    #[test]
    fn project_keyed_by_publisher_and_id() {
        let store = InMemoryPublishedRecordStore::default();
        let rec = ProjectPublishRecord {
            schema_uri: "https://static.rcxprotocol.org/schemas/2026-05-01/project-publish.schema.json"
                .to_string(),
            publisher_passport: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            project_id: "alpha".to_string(),
            name: "Alpha".to_string(),
            planning_target: Some("github://owner/repo".to_string()),
            default_passport_fpr: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            allowed_passport_fprs: vec!["p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
            working_tenant_categories: vec!["personal".to_string()],
            linked_github_repos: vec!["owner/repo".to_string()],
            operator_metadata: None,
            created_at: "2026-05-01T00:00:00Z".to_string(),
            published_at: "2026-05-01T00:00:00Z".to_string(),
            signature: "00".repeat(64),
            signer_kid: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            project_hash: "00".repeat(32),
        };
        store.upsert_project(rec.clone()).unwrap();
        let got = store
            .get_project(&rec.publisher_passport, &rec.project_id)
            .unwrap()
            .expect("present");
        assert_eq!(got, rec);
        // Wrong publisher returns None.
        let miss = store
            .get_project("p_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", &rec.project_id)
            .unwrap();
        assert!(miss.is_none());
    }

    #[test]
    fn tier_rank_orders_correctly() {
        assert!(tier_rank("trusted").unwrap() > tier_rank("basic").unwrap());
        assert_eq!(tier_rank("unknown"), None);
    }
}
