//! MCP-compatible HTTP surface plus RCX-specific extensions.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use http::StatusCode;
use rcx_registry_ingest::{ListServersRequest, RegistryServerEnvelope, RegistryServerListResponse};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical upstream registry URL mirrored by RCX-Registry.
pub const MCP_REGISTRY_BASE_URL: &str = "https://registry.modelcontextprotocol.io";

pub type SharedMirrorStore = Arc<dyn MirrorStore>;

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
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidCursor | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::InvalidCursor => "invalid_cursor",
            Self::BadRequest(_) => "bad_request",
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

pub fn router(store: SharedMirrorStore) -> Router {
    Router::new()
        .route("/v0/servers", get(list_servers))
        .route("/v0/servers/{server_name}/versions", get(list_versions))
        .route(
            "/v0/servers/{server_name}/versions/{version}",
            get(get_version),
        )
        .with_state(store)
}

async fn list_servers(
    State(store): State<SharedMirrorStore>,
    Query(query): Query<ListServersQuery>,
) -> Result<Json<RegistryServerListResponse>, ApiError> {
    Ok(Json(store.list_servers(&query.into())?))
}

async fn list_versions(
    State(store): State<SharedMirrorStore>,
    Path(server_name): Path<String>,
    Query(query): Query<IncludeDeletedQuery>,
) -> Result<Json<RegistryServerListResponse>, ApiError> {
    Ok(Json(store.list_versions(
        &server_name,
        query.include_deleted.unwrap_or(false),
    )?))
}

async fn get_version(
    State(store): State<SharedMirrorStore>,
    Path((server_name, version)): Path<(String, String)>,
    Query(query): Query<IncludeDeletedQuery>,
) -> Result<Json<RegistryServerEnvelope>, ApiError> {
    Ok(Json(store.get_version(
        &server_name,
        &version,
        query.include_deleted.unwrap_or(false),
    )?))
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

#[cfg(test)]
mod tests {
    use super::{
        router, ApiError, InMemoryMirrorStore, MirrorStore, SharedMirrorStore, StoredServerRecord,
    };
    use axum::body::{to_bytes, Body};
    use axum::response::IntoResponse;
    use http::{Request, StatusCode};
    use rcx_registry_ingest::{OfficialRegistryMeta, RegistryServerEnvelope, RegistryServerMeta};
    use serde_json::json;
    use std::sync::Arc;
    use tower::util::ServiceExt;

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

    #[tokio::test]
    async fn list_endpoint_returns_paginated_mcp_shaped_response() {
        let app = router(store());

        let response = app
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

    #[test]
    fn not_found_error_maps_to_404() {
        let response = ApiError::NotFound.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
