CREATE TABLE rcx_enrichment (
  server_name TEXT PRIMARY KEY REFERENCES mcp_servers(name),
  capability_graph JSONB,
  category TEXT,
  min_tier TEXT,
  required_affinity TEXT,
  enrichment_source TEXT NOT NULL,
  declared_uri TEXT,
  declared_hash BYTEA,
  enriched_at TIMESTAMPTZ NOT NULL,
  enrichment_receipt_hash BYTEA NOT NULL
);

CREATE INDEX rcx_enrichment_source_idx ON rcx_enrichment (enrichment_source);
CREATE INDEX rcx_enrichment_enriched_at_idx ON rcx_enrichment (enriched_at DESC);
