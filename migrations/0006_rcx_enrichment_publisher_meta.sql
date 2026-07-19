-- Sidecar table for publisher-declared verification metadata.
-- Previously created lazily inside PgPublisherEnrichmentStore::upsert, which
-- left every read path that LEFT JOINs it broken until the first declaration
-- arrived (surfaced live 2026-07-19: /v0/servers 500'd once the mirror
-- populated). DDL belongs here, not in the request path.
CREATE TABLE IF NOT EXISTS rcx_enrichment_publisher_meta (
    server_name TEXT PRIMARY KEY REFERENCES rcx_enrichment(server_name) ON DELETE CASCADE,
    publisher_passport TEXT NOT NULL,
    publisher_rights_verified BOOLEAN NOT NULL,
    verification_method TEXT NOT NULL,
    refresh_interval_seconds BIGINT,
    supersedes_prior_receipt_hash TEXT
);
