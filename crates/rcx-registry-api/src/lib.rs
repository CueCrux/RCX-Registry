//! MCP-compatible HTTP surface plus RCX-specific extensions.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use http::StatusCode;
use rcx_registry_admin::{
    build_publisher_rights_verified_receipt, classify_namespace, dns_txt_challenge,
    publisher_rights_record, verify_dns_txt, verify_github_passport, AdminError, NamespaceKind,
    PublisherRightsRecord, VerificationMethod,
};
use rcx_registry_crown::ULID_LEN;
use rcx_registry_enrich::{attach_publisher_enrichment, PublisherEnrichmentRecord};
use rcx_registry_ingest::{ListServersRequest, RegistryServerEnvelope, RegistryServerListResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Canonical upstream registry URL mirrored by RCX-Registry.
pub const MCP_REGISTRY_BASE_URL: &str = "https://registry.modelcontextprotocol.io";
pub const DEFAULT_PUBLISHER_SIGNER_KID: &str = "vault:transit:rcx-registry-signing-key-1";

pub mod published_records;
pub use published_records::{
    InMemoryPublishedRecordStore, PassportFilter, PassportPublishRecord, ProjectFilter,
    ProjectPublishRecord, PublishedRecordStore,
};

pub type SharedMirrorStore = Arc<dyn MirrorStore>;
pub type SharedPublisherRightsStore = Arc<dyn PublisherRightsStore>;
pub type SharedPublisherEnrichmentStore = Arc<dyn PublisherEnrichmentStore>;
pub type SharedPublishedRecordStore = Arc<dyn PublishedRecordStore>;
pub type SharedDnsTxtResolver = Arc<dyn DnsTxtResolver>;
pub type SharedGitHubOAuthProvider = Arc<dyn GitHubOAuthProvider>;

pub trait MirrorStore: Send + Sync + 'static {
    fn list_servers(
        &self,
        request: &ListServersRequest,
    ) -> Result<RegistryServerListResponse, ApiError>;
    fn list_versions(
        &self,
        server_name: &str,
        include_deleted: bool,
    ) -> Result<RegistryServerListResponse, ApiError>;
    fn get_version(
        &self,
        server_name: &str,
        version: &str,
        include_deleted: bool,
    ) -> Result<RegistryServerEnvelope, ApiError>;
}

pub trait PublisherRightsStore: Send + Sync + 'static {
    fn upsert(&self, record: PublisherRightsRecord) -> Result<(), ApiError>;
    fn list_by_publisher(
        &self,
        publisher_passport: &str,
    ) -> Result<Vec<PublisherRightsRecord>, ApiError>;
    fn lookup(
        &self,
        publisher_passport: &str,
        namespace: &str,
    ) -> Result<Option<PublisherRightsRecord>, ApiError>;
}

pub trait PublisherEnrichmentStore: Send + Sync + 'static {
    fn upsert(&self, record: PublisherEnrichmentRecord) -> Result<(), ApiError>;
    fn get(&self, server_name: &str) -> Result<Option<PublisherEnrichmentRecord>, ApiError>;
}

pub trait DnsTxtResolver: Send + Sync + 'static {
    fn lookup_txt(&self, record_name: &str) -> Result<Vec<String>, ApiError>;
}

pub trait GitHubOAuthProvider: Send + Sync + 'static {
    fn authorize_url(
        &self,
        owner: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<String, ApiError>;
    fn exchange_code(&self, code: &str, state: &str) -> Result<String, ApiError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorModel {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ApiError {
    #[error("server not found")]
    NotFound,
    #[error("invalid cursor")]
    InvalidCursor,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("feature unavailable: {0}")]
    Unavailable(&'static str),
    #[error("internal store error: {0}")]
    Store(String),
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidCursor | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::VerificationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::InvalidCursor => "invalid_cursor",
            Self::BadRequest(_) => "bad_request",
            Self::VerificationFailed(_) => "verification_failed",
            Self::Unavailable(_) => "unavailable",
            Self::Store(_) => "store_error",
        }
    }
}

impl From<AdminError> for ApiError {
    fn from(value: AdminError) -> Self {
        match value {
            AdminError::GitHubPassportMismatch { .. } | AdminError::DnsTxtMismatch { .. } => {
                Self::VerificationFailed(value.to_string())
            }
            _ => Self::BadRequest(value.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorModel {
            code: self.code(),
            message: self.to_string(),
        });
        (self.status_code(), body).into_response()
    }
}

#[derive(Clone)]
pub struct ApiState {
    mirror_store: SharedMirrorStore,
    publisher_rights_store: SharedPublisherRightsStore,
    publisher_enrichment_store: SharedPublisherEnrichmentStore,
    dns_resolver: SharedDnsTxtResolver,
    github_oauth_provider: SharedGitHubOAuthProvider,
    published_record_store: SharedPublishedRecordStore,
}

impl ApiState {
    pub fn new(mirror_store: SharedMirrorStore) -> Self {
        Self {
            mirror_store,
            publisher_rights_store: Arc::new(InMemoryPublisherRightsStore::default()),
            publisher_enrichment_store: Arc::new(InMemoryPublisherEnrichmentStore::default()),
            dns_resolver: Arc::new(UnavailableDnsTxtResolver),
            github_oauth_provider: Arc::new(UnavailableGitHubOAuthProvider),
            published_record_store: Arc::new(InMemoryPublishedRecordStore::default()),
        }
    }

    pub fn with_published_record_store(mut self, store: SharedPublishedRecordStore) -> Self {
        self.published_record_store = store;
        self
    }

    pub fn with_publisher_rights_store(
        mut self,
        publisher_rights_store: SharedPublisherRightsStore,
    ) -> Self {
        self.publisher_rights_store = publisher_rights_store;
        self
    }

    pub fn with_dns_resolver(mut self, dns_resolver: SharedDnsTxtResolver) -> Self {
        self.dns_resolver = dns_resolver;
        self
    }

    pub fn with_publisher_enrichment_store(
        mut self,
        publisher_enrichment_store: SharedPublisherEnrichmentStore,
    ) -> Self {
        self.publisher_enrichment_store = publisher_enrichment_store;
        self
    }

    pub fn with_github_oauth_provider(
        mut self,
        github_oauth_provider: SharedGitHubOAuthProvider,
    ) -> Self {
        self.github_oauth_provider = github_oauth_provider;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct ListServersQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub updated_since: Option<String>,
    pub search: Option<String>,
    pub version: Option<String>,
    pub include_deleted: Option<bool>,
}

impl From<ListServersQuery> for ListServersRequest {
    fn from(value: ListServersQuery) -> Self {
        Self {
            cursor: value.cursor,
            limit: value.limit,
            updated_since: value.updated_since,
            search: value.search,
            version: value.version,
            include_deleted: value.include_deleted.unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct IncludeDeletedQuery {
    pub include_deleted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnsChallengeRequest {
    pub server_name: String,
    pub publisher_passport: String,
    pub passport_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsChallengeResponse {
    pub publisher_passport: String,
    pub namespace: String,
    pub server_name: String,
    pub verification_method: &'static str,
    pub record_name: String,
    pub expected_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnsVerifyRequest {
    pub server_name: String,
    pub publisher_passport: String,
    pub passport_fingerprint: String,
    pub verified_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GitHubStartQuery {
    pub server_name: String,
    pub publisher_passport: String,
    pub redirect_uri: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GitHubCallbackQuery {
    pub server_name: String,
    pub publisher_passport: String,
    pub code: String,
    pub state: String,
    pub verified_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublisherRightsListResponse {
    pub publisher_passport: String,
    pub rights: Vec<PublisherRightsRecord>,
}

pub fn router(store: SharedMirrorStore) -> Router {
    router_with_state(ApiState::new(store))
}

pub fn router_with_state(state: ApiState) -> Router {
    Router::new()
        .route("/v0/servers", get(list_servers))
        .route("/v0/servers/{server_name}/versions", get(list_versions))
        .route(
            "/v0/servers/{server_name}/versions/{version}",
            get(get_version),
        )
        .route("/publish", get(publish_onboarding_page))
        .route("/v0/publisher-rights/dns-challenge", post(dns_challenge))
        .route("/v0/publisher-rights/dns-verify", post(dns_verify))
        .route("/v0/publisher-rights/github/start", get(github_oauth_start))
        .route(
            "/v0/publisher-rights/github/callback",
            get(github_oauth_callback),
        )
        .route(
            "/v0/publishers/{publisher_passport}",
            get(list_publisher_rights),
        )
        // Plan C R2 — passport + project discovery.
        .route("/v0/passports", get(list_passports_handler))
        .route("/v0/passports/{passport_fpr}", get(get_passport_handler))
        .route("/v0/projects", get(list_projects_handler))
        .route(
            "/v0/projects/{publisher_passport}/{project_id}",
            get(get_project_handler),
        )
        .with_state(state)
}

/// Run synchronous store work (the `r2d2_postgres` layer blocks on a runtime
/// internally) on a blocking thread so it never nests inside the async runtime.
/// Without this the sync `postgres` client panics with "Cannot start a runtime
/// from within a runtime" and aborts the process.
async fn spawn_store<T, F>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|error| ApiError::Store(format!("blocking task failed: {error}")))?
}

#[derive(Debug, Deserialize)]
struct ListPassportsQuery {
    category: Option<String>,
    min_tier: Option<String>,
    agent_work_gate: Option<bool>,
}

async fn list_passports_handler(
    State(state): State<ApiState>,
    Query(query): Query<ListPassportsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let value = spawn_store(move || {
        let filter = PassportFilter {
            category: query.category.filter(|s| !s.is_empty()),
            min_tier: query.min_tier.filter(|s| !s.is_empty()),
            agent_work_gate: query.agent_work_gate,
        };
        let records = state.published_record_store.list_passports(&filter)?;
        Ok(serde_json::json!({
            "count": records.len(),
            "passports": records,
        }))
    })
    .await?;
    Ok(Json(value))
}

async fn get_passport_handler(
    State(state): State<ApiState>,
    Path(passport_fpr): Path<String>,
) -> Result<Json<PassportPublishRecord>, ApiError> {
    let record =
        spawn_store(move || state.published_record_store.get_passport(&passport_fpr)).await?;
    record.map(Json).ok_or(ApiError::NotFound)
}

#[derive(Debug, Deserialize)]
struct ListProjectsQuery {
    publisher: Option<String>,
}

async fn list_projects_handler(
    State(state): State<ApiState>,
    Query(query): Query<ListProjectsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let value = spawn_store(move || {
        let filter = ProjectFilter {
            publisher: query.publisher.filter(|s| !s.is_empty()),
        };
        let records = state.published_record_store.list_projects(&filter)?;
        Ok(serde_json::json!({
            "count": records.len(),
            "projects": records,
        }))
    })
    .await?;
    Ok(Json(value))
}

async fn get_project_handler(
    State(state): State<ApiState>,
    Path((publisher_passport, project_id)): Path<(String, String)>,
) -> Result<Json<ProjectPublishRecord>, ApiError> {
    let record = spawn_store(move || {
        state
            .published_record_store
            .get_project(&publisher_passport, &project_id)
    })
    .await?;
    record.map(Json).ok_or(ApiError::NotFound)
}

async fn list_servers(
    State(state): State<ApiState>,
    Query(query): Query<ListServersQuery>,
) -> Result<Json<RegistryServerListResponse>, ApiError> {
    let resp = spawn_store(move || {
        decorate_list_response(&state, state.mirror_store.list_servers(&query.into())?)
    })
    .await?;
    Ok(Json(resp))
}

async fn list_versions(
    State(state): State<ApiState>,
    Path(server_name): Path<String>,
    Query(query): Query<IncludeDeletedQuery>,
) -> Result<Json<RegistryServerListResponse>, ApiError> {
    let resp = spawn_store(move || {
        let listing = state
            .mirror_store
            .list_versions(&server_name, query.include_deleted.unwrap_or(false))?;
        decorate_list_response(&state, listing)
    })
    .await?;
    Ok(Json(resp))
}

async fn get_version(
    State(state): State<ApiState>,
    Path((server_name, version)): Path<(String, String)>,
    Query(query): Query<IncludeDeletedQuery>,
) -> Result<Json<RegistryServerEnvelope>, ApiError> {
    let envelope = spawn_store(move || {
        let found = state.mirror_store.get_version(
            &server_name,
            &version,
            query.include_deleted.unwrap_or(false),
        )?;
        decorate_envelope(&state, found)
    })
    .await?;
    Ok(Json(envelope))
}

async fn publish_onboarding_page() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>RCX-Registry Publisher Onboarding</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: sans-serif; margin: 2rem auto; max-width: 48rem; line-height: 1.5; padding: 0 1rem; }
      code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }
      h1, h2 { line-height: 1.2; }
      .card { border: 1px solid #ddd; border-radius: 0.5rem; padding: 1rem; margin: 1rem 0; }
    </style>
  </head>
  <body>
    <h1>RCX-Registry Publisher Onboarding</h1>
    <p>Publisher onboarding is currently fail-closed. The production edge returns 404 for every verification and declaration write until caller identity, proof binding, server-owned audit time, signing, and receipt retrieval pass review.</p>
    <div class="card">
      <h2>GitHub OAuth</h2>
      <p>The implementation targets <code>io.github.&lt;owner&gt;/&lt;server&gt;</code>, but production OAuth credentials are unset and the public start/callback routes are disabled. Reopening also requires server-bound state and explicit organization ownership proof.</p>
    </div>
    <div class="card">
      <h2>DNS TXT</h2>
      <p>The intended contract covers <code>io.&lt;domain&gt;/&lt;server&gt;</code>. Its TXT value is exactly the passport fingerprint supplied as <code>expected_value</code>, with no prefix. <code>POST /v0/publisher-rights/dns-challenge</code> and <code>POST /v0/publisher-rights/dns-verify</code> remain disabled at the production edge until that domain proof is bound to an authenticated passport.</p>
    </div>
    <div class="card">
      <h2>Manual Review</h2>
      <p>Operator-mediated manual review is deliberately unavailable on the public API until an authenticated operator surface ships. Anonymous namespaces remain accepted but unverified in v1.0.</p>
    </div>
  </body>
</html>"#,
    )
}

async fn dns_challenge(
    Json(body): Json<DnsChallengeRequest>,
) -> Result<Json<DnsChallengeResponse>, ApiError> {
    let claim = classify_namespace(&body.server_name)?;
    let NamespaceKind::ReverseDns { domain } = &claim.kind else {
        return Err(ApiError::BadRequest(
            "dns txt verification only applies to reverse-dns namespaces".to_string(),
        ));
    };
    let challenge = dns_txt_challenge(domain, &body.passport_fingerprint);
    Ok(Json(DnsChallengeResponse {
        publisher_passport: body.publisher_passport,
        namespace: claim.namespace,
        server_name: claim.server_name,
        verification_method: VerificationMethod::DnsTxt.as_str(),
        record_name: challenge.record_name,
        expected_value: challenge.expected_value,
    }))
}

async fn dns_verify(
    State(state): State<ApiState>,
    Json(body): Json<DnsVerifyRequest>,
) -> Result<(StatusCode, Json<PublisherRightsRecord>), ApiError> {
    let record = spawn_store(move || {
        let claim = classify_namespace(&body.server_name)?;
        let NamespaceKind::ReverseDns { domain } = &claim.kind else {
            return Err(ApiError::BadRequest(
                "dns txt verification only applies to reverse-dns namespaces".to_string(),
            ));
        };
        let challenge = dns_txt_challenge(domain, &body.passport_fingerprint);
        let observed_values = state.dns_resolver.lookup_txt(&challenge.record_name)?;
        verify_dns_txt(&claim, &body.passport_fingerprint, &observed_values)?;

        let verified_at = body.verified_at.unwrap_or_else(now_ms);
        let record = build_verified_rights_record(
            &claim,
            &body.publisher_passport,
            VerificationMethod::DnsTxt,
            verified_at,
        );
        state.publisher_rights_store.upsert(record.clone())?;
        Ok(record)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn github_oauth_start(
    State(state): State<ApiState>,
    Query(query): Query<GitHubStartQuery>,
) -> Result<Redirect, ApiError> {
    let claim = classify_namespace(&query.server_name)?;
    verify_github_passport(&claim, &query.publisher_passport)?;

    let owner = match &claim.kind {
        NamespaceKind::GitHub { owner } => owner,
        _ => {
            return Err(ApiError::BadRequest(
                "github oauth only applies to io.github.<owner> namespaces".to_string(),
            ))
        }
    };

    let authorize_url =
        state
            .github_oauth_provider
            .authorize_url(owner, &query.redirect_uri, &query.state)?;
    Ok(Redirect::temporary(&authorize_url))
}

async fn github_oauth_callback(
    State(state): State<ApiState>,
    Query(query): Query<GitHubCallbackQuery>,
) -> Result<(StatusCode, Json<PublisherRightsRecord>), ApiError> {
    let record = spawn_store(move || {
        let claim = classify_namespace(&query.server_name)?;
        verify_github_passport(&claim, &query.publisher_passport)?;

        let expected_owner = match &claim.kind {
            NamespaceKind::GitHub { owner } => owner,
            _ => {
                return Err(ApiError::BadRequest(
                    "github oauth only applies to io.github.<owner> namespaces".to_string(),
                ))
            }
        };

        // `exchange_code` uses a blocking reqwest client, so it must run off the
        // async runtime here alongside the sync store write (see spawn_store).
        let resolved_owner = state
            .github_oauth_provider
            .exchange_code(&query.code, &query.state)?;
        if &resolved_owner != expected_owner {
            return Err(ApiError::VerificationFailed(format!(
                "github callback resolved owner `{resolved_owner}` but namespace requires `{expected_owner}`"
            )));
        }

        let verified_at = query.verified_at.unwrap_or_else(now_ms);
        let record = build_verified_rights_record(
            &claim,
            &query.publisher_passport,
            VerificationMethod::GitHubOAuth,
            verified_at,
        );
        state.publisher_rights_store.upsert(record.clone())?;
        Ok(record)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn list_publisher_rights(
    State(state): State<ApiState>,
    Path(publisher_passport): Path<String>,
) -> Result<Json<PublisherRightsListResponse>, ApiError> {
    let lookup_passport = publisher_passport.clone();
    let rights = spawn_store(move || {
        state
            .publisher_rights_store
            .list_by_publisher(&lookup_passport)
    })
    .await?;
    Ok(Json(PublisherRightsListResponse {
        publisher_passport,
        rights,
    }))
}

fn decorate_list_response(
    state: &ApiState,
    response: RegistryServerListResponse,
) -> Result<RegistryServerListResponse, ApiError> {
    let servers = response
        .servers
        .into_iter()
        .map(|envelope| decorate_envelope(state, envelope))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RegistryServerListResponse {
        servers,
        metadata: response.metadata,
    })
}

fn decorate_envelope(
    state: &ApiState,
    mut envelope: RegistryServerEnvelope,
) -> Result<RegistryServerEnvelope, ApiError> {
    let Some(server_name) = envelope
        .server
        .get("name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
    else {
        return Ok(envelope);
    };

    if let Some(record) = state.publisher_enrichment_store.get(&server_name)? {
        attach_publisher_enrichment(&mut envelope, &record.block)
            .map_err(|error| ApiError::Store(error.to_string()))?;
    }

    Ok(envelope)
}

fn build_verified_rights_record(
    claim: &rcx_registry_admin::NamespaceClaim,
    publisher_passport: &str,
    method: VerificationMethod,
    verified_at: u64,
) -> PublisherRightsRecord {
    let receipt = build_publisher_rights_verified_receipt(
        derived_event_id(&format!(
            "{}:{}:{}:{}",
            claim.server_name,
            publisher_passport,
            method.as_str(),
            verified_at
        )),
        publisher_passport,
        &claim.namespace,
        method.clone(),
        verified_at,
        DEFAULT_PUBLISHER_SIGNER_KID,
    );
    publisher_rights_record(
        claim,
        publisher_passport,
        method,
        verified_at,
        &receipt.receipt_hash,
    )
}

fn derived_event_id(seed: &str) -> [u8; ULID_LEN] {
    let digest = blake3::hash(seed.as_bytes());
    let mut event_id = [0u8; ULID_LEN];
    event_id.copy_from_slice(&digest.as_bytes()[..ULID_LEN]);
    event_id
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredServerRecord {
    pub envelope: RegistryServerEnvelope,
}

impl StoredServerRecord {
    fn name(&self) -> Result<&str, ApiError> {
        self.envelope
            .server
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::BadRequest("server.name missing".to_string()))
    }

    fn version(&self) -> Result<&str, ApiError> {
        self.envelope
            .server
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ApiError::BadRequest("server.version missing".to_string()))
    }

    fn cursor_token(&self) -> Result<String, ApiError> {
        Ok(format!("{}:{}", self.name()?, self.version()?))
    }

    fn is_deleted(&self) -> bool {
        self.envelope.meta.official.status == "deleted"
    }

    fn is_latest(&self) -> bool {
        self.envelope.meta.official.is_latest
    }

    fn comparison_timestamp(&self) -> Option<&str> {
        self.envelope
            .meta
            .official
            .updated_at
            .as_deref()
            .or(self.envelope.meta.official.status_changed_at.as_deref())
            .or(self.envelope.meta.official.published_at.as_deref())
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryMirrorStore {
    records: Vec<StoredServerRecord>,
}

impl InMemoryMirrorStore {
    pub fn new(records: Vec<StoredServerRecord>) -> Self {
        Self { records }
    }

    fn filtered_records<'a>(
        &'a self,
        request: &ListServersRequest,
    ) -> Result<Vec<&'a StoredServerRecord>, ApiError> {
        let include_deleted = request.include_deleted || request.updated_since.is_some();
        let search = request.search.as_deref().map(str::to_ascii_lowercase);
        let version_filter = request.version.as_deref();

        let mut records = self
            .records
            .iter()
            .filter(|record| include_deleted || !record.is_deleted())
            .filter(|record| {
                search.as_ref().is_none_or(|needle| {
                    record
                        .name()
                        .map(|name| name.to_ascii_lowercase().contains(needle))
                        .unwrap_or(false)
                })
            })
            .filter(|record| match version_filter {
                Some("latest") => record.is_latest(),
                Some(version) => record
                    .version()
                    .map(|candidate| candidate == version)
                    .unwrap_or(false),
                None => true,
            })
            .filter(|record| {
                request
                    .updated_since
                    .as_deref()
                    .is_none_or(|updated_since| {
                        record
                            .comparison_timestamp()
                            .is_some_and(|timestamp| timestamp >= updated_since)
                    })
            })
            .collect::<Vec<_>>();

        records.sort_by(|left, right| {
            left.name()
                .unwrap_or_default()
                .cmp(right.name().unwrap_or_default())
                .then(
                    left.version()
                        .unwrap_or_default()
                        .cmp(right.version().unwrap_or_default()),
                )
        });

        if let Some(cursor) = request.cursor.as_deref() {
            let Some(index) = records
                .iter()
                .position(|record| record.cursor_token().ok().as_deref() == Some(cursor))
            else {
                return Err(ApiError::InvalidCursor);
            };
            records = records.into_iter().skip(index + 1).collect();
        }

        Ok(records)
    }
}

impl MirrorStore for InMemoryMirrorStore {
    fn list_servers(
        &self,
        request: &ListServersRequest,
    ) -> Result<RegistryServerListResponse, ApiError> {
        let records = self.filtered_records(request)?;
        let limit = request.normalized_limit();
        let mut page = records.into_iter().take(limit + 1).collect::<Vec<_>>();
        let has_more = page.len() > limit;
        if has_more {
            page.pop();
        }

        let servers = page
            .iter()
            .map(|record| record.envelope.clone())
            .collect::<Vec<_>>();
        let next_cursor = if has_more {
            page.last()
                .map(|record| record.cursor_token())
                .transpose()?
        } else {
            None
        };

        Ok(RegistryServerListResponse {
            metadata: rcx_registry_ingest::RegistryListMetadata {
                next_cursor,
                count: servers.len(),
            },
            servers,
        })
    }

    fn list_versions(
        &self,
        server_name: &str,
        include_deleted: bool,
    ) -> Result<RegistryServerListResponse, ApiError> {
        let mut records = self
            .records
            .iter()
            .filter(|record| {
                record
                    .name()
                    .map(|name| name == server_name)
                    .unwrap_or(false)
            })
            .filter(|record| include_deleted || !record.is_deleted())
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .version()
                .unwrap_or_default()
                .cmp(left.version().unwrap_or_default())
        });

        Ok(RegistryServerListResponse {
            metadata: rcx_registry_ingest::RegistryListMetadata {
                next_cursor: None,
                count: records.len(),
            },
            servers: records
                .into_iter()
                .map(|record| record.envelope.clone())
                .collect(),
        })
    }

    fn get_version(
        &self,
        server_name: &str,
        version: &str,
        include_deleted: bool,
    ) -> Result<RegistryServerEnvelope, ApiError> {
        self.records
            .iter()
            .filter(|record| {
                record
                    .name()
                    .map(|name| name == server_name)
                    .unwrap_or(false)
            })
            .filter(|record| include_deleted || !record.is_deleted())
            .find(|record| {
                if version == "latest" {
                    record.is_latest()
                } else {
                    record
                        .version()
                        .map(|candidate| candidate == version)
                        .unwrap_or(false)
                }
            })
            .map(|record| record.envelope.clone())
            .ok_or(ApiError::NotFound)
    }
}

#[derive(Default)]
pub struct InMemoryPublisherRightsStore {
    records: Mutex<BTreeMap<(String, String), PublisherRightsRecord>>,
}

impl PublisherRightsStore for InMemoryPublisherRightsStore {
    fn upsert(&self, record: PublisherRightsRecord) -> Result<(), ApiError> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| ApiError::Store("publisher rights mutex poisoned".to_string()))?;
        guard.insert(
            (record.publisher_passport.clone(), record.namespace.clone()),
            record,
        );
        Ok(())
    }

    fn list_by_publisher(
        &self,
        publisher_passport: &str,
    ) -> Result<Vec<PublisherRightsRecord>, ApiError> {
        let guard = self
            .records
            .lock()
            .map_err(|_| ApiError::Store("publisher rights mutex poisoned".to_string()))?;
        let mut records = guard
            .values()
            .filter(|record| record.publisher_passport == publisher_passport)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.namespace.cmp(&right.namespace));
        Ok(records)
    }

    fn lookup(
        &self,
        publisher_passport: &str,
        namespace: &str,
    ) -> Result<Option<PublisherRightsRecord>, ApiError> {
        let guard = self
            .records
            .lock()
            .map_err(|_| ApiError::Store("publisher rights mutex poisoned".to_string()))?;
        Ok(guard
            .get(&(publisher_passport.to_string(), namespace.to_string()))
            .cloned())
    }
}

#[derive(Default)]
pub struct InMemoryPublisherEnrichmentStore {
    records: Mutex<BTreeMap<String, PublisherEnrichmentRecord>>,
}

impl PublisherEnrichmentStore for InMemoryPublisherEnrichmentStore {
    fn upsert(&self, record: PublisherEnrichmentRecord) -> Result<(), ApiError> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| ApiError::Store("publisher enrichment mutex poisoned".to_string()))?;
        guard.insert(record.server_name.clone(), record);
        Ok(())
    }

    fn get(&self, server_name: &str) -> Result<Option<PublisherEnrichmentRecord>, ApiError> {
        let guard = self
            .records
            .lock()
            .map_err(|_| ApiError::Store("publisher enrichment mutex poisoned".to_string()))?;
        Ok(guard.get(server_name).cloned())
    }
}

#[derive(Default)]
pub struct InMemoryDnsTxtResolver {
    records: BTreeMap<String, Vec<String>>,
}

impl InMemoryDnsTxtResolver {
    pub fn new(records: BTreeMap<String, Vec<String>>) -> Self {
        Self { records }
    }
}

impl DnsTxtResolver for InMemoryDnsTxtResolver {
    fn lookup_txt(&self, record_name: &str) -> Result<Vec<String>, ApiError> {
        Ok(self.records.get(record_name).cloned().unwrap_or_default())
    }
}

pub struct UnavailableDnsTxtResolver;

impl DnsTxtResolver for UnavailableDnsTxtResolver {
    fn lookup_txt(&self, _record_name: &str) -> Result<Vec<String>, ApiError> {
        Err(ApiError::Unavailable("dns_txt_resolver_not_configured"))
    }
}

pub struct UnavailableGitHubOAuthProvider;

impl GitHubOAuthProvider for UnavailableGitHubOAuthProvider {
    fn authorize_url(
        &self,
        _owner: &str,
        _redirect_uri: &str,
        _state: &str,
    ) -> Result<String, ApiError> {
        Err(ApiError::Unavailable("github_oauth_not_configured"))
    }

    fn exchange_code(&self, _code: &str, _state: &str) -> Result<String, ApiError> {
        Err(ApiError::Unavailable("github_oauth_not_configured"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        router, router_with_state, ApiError, ApiState, GitHubOAuthProvider, InMemoryDnsTxtResolver,
        InMemoryMirrorStore, InMemoryPublishedRecordStore, InMemoryPublisherEnrichmentStore,
        InMemoryPublisherRightsStore, MirrorStore, PassportPublishRecord, ProjectPublishRecord,
        PublishedRecordStore, PublisherRightsStore, SharedMirrorStore, StoredServerRecord,
    };
    use axum::body::{to_bytes, Body};
    use axum::response::IntoResponse;
    use http::{Request, StatusCode};
    use rcx_registry_admin::PublisherRightsRecord;
    use rcx_registry_ingest::{OfficialRegistryMeta, RegistryServerEnvelope, RegistryServerMeta};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tower::util::ServiceExt;

    struct StaticGitHubOAuthProvider {
        authorize_url: String,
        resolved_owner: String,
    }

    impl GitHubOAuthProvider for StaticGitHubOAuthProvider {
        fn authorize_url(
            &self,
            _owner: &str,
            _redirect_uri: &str,
            _state: &str,
        ) -> Result<String, super::ApiError> {
            Ok(self.authorize_url.clone())
        }

        fn exchange_code(&self, _code: &str, _state: &str) -> Result<String, super::ApiError> {
            Ok(self.resolved_owner.clone())
        }
    }

    fn record(
        name: &str,
        version: &str,
        status: &str,
        is_latest: bool,
        updated_at: &str,
    ) -> StoredServerRecord {
        StoredServerRecord {
            envelope: RegistryServerEnvelope {
                server: json!({
                    "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
                    "name": name,
                    "version": version,
                    "description": format!("{name} {version}")
                }),
                meta: RegistryServerMeta {
                    official: OfficialRegistryMeta {
                        status: status.to_string(),
                        status_changed_at: Some(updated_at.to_string()),
                        published_at: Some(updated_at.to_string()),
                        updated_at: Some(updated_at.to_string()),
                        is_latest,
                    },
                    extra: Default::default(),
                },
            },
        }
    }

    fn store() -> SharedMirrorStore {
        Arc::new(InMemoryMirrorStore::new(vec![
            record(
                "io.github.example/server-a",
                "1.0.0",
                "active",
                false,
                "2026-04-19T10:00:00Z",
            ),
            record(
                "io.github.example/server-a",
                "2.0.0",
                "active",
                true,
                "2026-04-20T10:00:00Z",
            ),
            record(
                "io.github.example/server-b",
                "1.0.0",
                "deleted",
                true,
                "2026-04-18T09:00:00Z",
            ),
        ]))
    }

    fn publisher_state() -> ApiState {
        let mut dns_records = BTreeMap::new();
        dns_records.insert(
            "_rcx-registry.example.com".to_string(),
            vec!["fingerprint:abc123".to_string()],
        );

        ApiState::new(store())
            .with_publisher_rights_store(Arc::new(InMemoryPublisherRightsStore::default()))
            .with_publisher_enrichment_store(Arc::new(InMemoryPublisherEnrichmentStore::default()))
            .with_dns_resolver(Arc::new(InMemoryDnsTxtResolver::new(dns_records)))
            .with_github_oauth_provider(Arc::new(StaticGitHubOAuthProvider {
                authorize_url: "https://github.com/login/oauth/authorize?client_id=test"
                    .to_string(),
                resolved_owner: "example-org".to_string(),
            }))
    }

    fn publisher_state_with_verified_rights() -> ApiState {
        let rights_store = Arc::new(InMemoryPublisherRightsStore::default());
        rights_store
            .upsert(PublisherRightsRecord {
                publisher_passport: "passport:github:example-org".to_string(),
                namespace: "io.github.example-org".to_string(),
                server_name: "io.github.example-org/document-proofer".to_string(),
                verification_method: "github_oauth".to_string(),
                verified_at: 1_776_683_200_000,
                receipt_hash:
                    "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
            })
            .expect("seed github rights should insert");

        let mut dns_records = BTreeMap::new();
        dns_records.insert(
            "_rcx-registry.example.com".to_string(),
            vec!["fingerprint:abc123".to_string()],
        );

        ApiState::new(Arc::new(InMemoryMirrorStore::new(vec![record(
            "io.github.example-org/document-proofer",
            "1.2.0",
            "active",
            true,
            "2026-04-20T10:00:00Z",
        )])))
        .with_publisher_rights_store(rights_store)
        .with_publisher_enrichment_store(Arc::new(InMemoryPublisherEnrichmentStore::default()))
        .with_dns_resolver(Arc::new(InMemoryDnsTxtResolver::new(dns_records)))
        .with_github_oauth_provider(Arc::new(StaticGitHubOAuthProvider {
            authorize_url: "https://github.com/login/oauth/authorize?client_id=test".to_string(),
            resolved_owner: "example-org".to_string(),
        }))
    }

    #[tokio::test]
    async fn list_endpoint_returns_paginated_mcp_shaped_response() {
        let app = router(store());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v0/servers?limit=1")
                    .body(axum::body::Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["metadata"]["count"], 1);
        assert_eq!(
            json["servers"][0]["server"]["name"],
            "io.github.example/server-a"
        );
        assert_eq!(
            json["metadata"]["nextCursor"],
            "io.github.example/server-a:1.0.0"
        );
    }

    #[tokio::test]
    async fn list_endpoint_rejects_unknown_cursor() {
        let app = router(store());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v0/servers?cursor=missing:cursor")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn versions_endpoint_returns_all_versions_for_server() {
        let app = router(store());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v0/servers/io.github.example%2Fserver-a/versions")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["metadata"]["count"], 2);
        assert_eq!(json["servers"][0]["server"]["version"], "2.0.0");
        assert_eq!(json["servers"][1]["server"]["version"], "1.0.0");
    }

    #[tokio::test]
    async fn version_endpoint_supports_latest_alias() {
        let app = router(store());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v0/servers/io.github.example%2Fserver-a/versions/latest")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["server"]["version"], "2.0.0");
    }

    #[tokio::test]
    async fn list_endpoint_hides_deleted_by_default_and_includes_on_request() {
        let store = InMemoryMirrorStore::new(vec![record(
            "io.github.example/server-b",
            "1.0.0",
            "deleted",
            true,
            "2026-04-18T09:00:00Z",
        )]);

        let hidden = store
            .list_servers(&rcx_registry_ingest::ListServersRequest::default())
            .expect("default listing should succeed");
        assert_eq!(hidden.metadata.count, 0);

        let visible = store
            .list_servers(&rcx_registry_ingest::ListServersRequest {
                include_deleted: true,
                ..rcx_registry_ingest::ListServersRequest::default()
            })
            .expect("listing with include_deleted should succeed");
        assert_eq!(visible.metadata.count, 1);
    }

    #[tokio::test]
    async fn list_endpoint_surfaces_auto_enrichment_under_namespaced_meta() {
        let mut record = record(
            "io.github.example/server-a",
            "2.0.0",
            "active",
            true,
            "2026-04-20T10:00:00Z",
        );
        record.envelope.meta.extra.insert(
            "org.rcxprotocol.registry/auto".to_string(),
            json!({
                "category": "public",
                "capability_graph": null,
                "attestations_count": 0,
                "auto_enriched_at": "2026-04-20T12:00:00Z",
                "auto_enrichment_receipt": "blake3:deadbeef"
            }),
        );
        let app = router(Arc::new(InMemoryMirrorStore::new(vec![record])));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v0/servers")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(
            json["servers"][0]["_meta"]["org.rcxprotocol.registry/auto"]["auto_enrichment_receipt"],
            "blake3:deadbeef"
        );
    }

    #[tokio::test]
    async fn publish_page_renders_minimal_onboarding_html() {
        let app = router_with_state(publisher_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/publish")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let html = String::from_utf8(body.to_vec()).expect("html should decode");
        assert!(html.contains("RCX-Registry Publisher Onboarding"));
        assert!(html.contains("currently fail-closed"));
        assert!(html.contains("/v0/publisher-rights/dns-challenge"));
    }

    #[tokio::test]
    async fn dns_challenge_route_returns_expected_record_name() {
        let app = router_with_state(publisher_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v0/publisher-rights/dns-challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "server_name": "io.example.com/document-proofer",
                            "publisher_passport": "passport:dns:example.com",
                            "passport_fingerprint": "fingerprint:abc123"
                        }))
                        .expect("json body should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["record_name"], "_rcx-registry.example.com");
        assert_eq!(json["verification_method"], "dns_txt");
    }

    #[tokio::test]
    async fn dns_verify_route_persists_verified_namespace() {
        let app = router_with_state(publisher_state());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v0/publisher-rights/dns-verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "server_name": "io.example.com/document-proofer",
                            "publisher_passport": "passport:dns:example.com",
                            "passport_fingerprint": "fingerprint:abc123",
                            "verified_at": 1776683200000u64
                        }))
                        .expect("json body should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["namespace"], "io.example.com");
        assert_eq!(json["verification_method"], "dns_txt");

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v0/publishers/passport:dns:example.com")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(list_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn manual_verify_route_is_not_publicly_mounted() {
        let state = publisher_state();
        let rights_store = state.publisher_rights_store.clone();
        let app = router_with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v0/publisher-rights/manual-verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "server_name": "io.github.example-org/document-proofer",
                            "publisher_passport": "passport:github:example-org",
                            "reviewer_passport": "passport:ops:reviewer-1",
                            "review_note": "Validated via operator workflow",
                            "verified_at": 1776683200000u64
                        }))
                        .expect("json body should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(rights_store
            .list_by_publisher("passport:github:example-org")
            .expect("rights lookup should succeed")
            .is_empty());
    }

    #[tokio::test]
    async fn github_start_route_redirects_when_provider_is_configured() {
        let app = router_with_state(publisher_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v0/publisher-rights/github/start?server_name=io.github.example-org%2Fdocument-proofer&publisher_passport=passport:github:example-org&redirect_uri=https%3A%2F%2Fregistry.rcxprotocol.org%2Fv0%2Fpublisher-rights%2Fgithub%2Fcallback&state=test-state")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("https://github.com/login/oauth/authorize?client_id=test")
        );
    }

    #[tokio::test]
    async fn github_callback_route_records_verified_owner() {
        let app = router_with_state(publisher_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v0/publisher-rights/github/callback?server_name=io.github.example-org%2Fdocument-proofer&publisher_passport=passport:github:example-org&code=abc123&state=test-state&verified_at=1776683200000")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("body should be json");
        assert_eq!(json["verification_method"], "github_oauth");
        assert_eq!(json["namespace"], "io.github.example-org");
    }

    #[tokio::test]
    async fn declare_route_is_not_publicly_mounted_and_cannot_write_enrichment() {
        let state = publisher_state_with_verified_rights();
        let enrichment_store = state.publisher_enrichment_store.clone();
        let app = router_with_state(state);
        let declaration = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../fixtures/examples/rcx-enrichment.valid.json"
        ))
        .expect("fixture should parse");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v0/publishers/declare")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "server_name": "io.github.example-org/document-proofer",
                            "declared_uri": "https://example.org/.rcx/document-proofer.rcx.json",
                            "declaration": declaration
                        }))
                        .expect("json body should serialize"),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(enrichment_store
            .get("io.github.example-org/document-proofer")
            .expect("enrichment lookup should succeed")
            .is_none());
    }

    #[test]
    fn not_found_error_maps_to_404() {
        let response = ApiError::NotFound.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn empty_mirror_store() -> Arc<InMemoryMirrorStore> {
        Arc::new(InMemoryMirrorStore::new(Vec::new()))
    }

    fn sample_passport_record(fpr: &str, category: &str, tier: &str) -> PassportPublishRecord {
        PassportPublishRecord {
            schema_uri:
                "https://static.rcxprotocol.org/schemas/2026-05-01/passport-publish.schema.json"
                    .to_string(),
            publisher_passport: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            passport_fpr: fpr.to_string(),
            passport_id: "alpha".to_string(),
            category: category.to_string(),
            public_key_hex: "0".repeat(64),
            sponsor_passport_fpr: None,
            reputation_tier: tier.to_string(),
            receipt_count: 0,
            agent_work_gate: false,
            is_default_for_category: true,
            operator_metadata: None,
            issued_at: "2026-05-01T00:00:00Z".to_string(),
            published_at: "2026-05-01T00:00:00Z".to_string(),
            signature: "0".repeat(128),
            signer_kid: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            passport_hash: "0".repeat(64),
        }
    }

    #[tokio::test]
    async fn passport_get_endpoint_returns_404_when_missing() {
        let state = ApiState::new(empty_mirror_store());
        let app = router_with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v0/passports/p_unknown00000000000000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn passport_get_endpoint_returns_seeded_record() {
        let store = Arc::new(InMemoryPublishedRecordStore::default());
        store
            .upsert_passport(sample_passport_record(
                "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "personal",
                "basic",
            ))
            .unwrap();
        let state = ApiState::new(empty_mirror_store()).with_published_record_store(store);
        let app = router_with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v0/passports/p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: PassportPublishRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.passport_fpr, "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(parsed.category, "personal");
    }

    #[tokio::test]
    async fn passport_list_endpoint_filters_by_min_tier() {
        let store = Arc::new(InMemoryPublishedRecordStore::default());
        store
            .upsert_passport(sample_passport_record(
                "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "personal",
                "basic",
            ))
            .unwrap();
        store
            .upsert_passport(sample_passport_record(
                "p_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "work",
                "elite",
            ))
            .unwrap();
        let state = ApiState::new(empty_mirror_store()).with_published_record_store(store);
        let app = router_with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v0/passports?min_tier=trusted")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["count"], 1);
        assert_eq!(
            parsed["passports"][0]["passport_fpr"],
            "p_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[tokio::test]
    async fn project_get_endpoint_returns_seeded_record_with_correct_publisher() {
        let store = Arc::new(InMemoryPublishedRecordStore::default());
        store
            .upsert_project(ProjectPublishRecord {
                schema_uri:
                    "https://static.rcxprotocol.org/schemas/2026-05-01/project-publish.schema.json"
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
                signature: "0".repeat(128),
                signer_kid: "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                project_hash: "0".repeat(64),
            })
            .unwrap();
        let state = ApiState::new(empty_mirror_store()).with_published_record_store(store);
        let app = router_with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v0/projects/p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/alpha")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let parsed: ProjectPublishRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.project_id, "alpha");
        assert_eq!(
            parsed.planning_target.as_deref(),
            Some("github://owner/repo")
        );
    }
}
