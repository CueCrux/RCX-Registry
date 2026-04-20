CREATE TABLE mcp_servers (
  name TEXT PRIMARY KEY,
  server_json JSONB NOT NULL,
  upstream_hash BYTEA NOT NULL,
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL,
  schema_date TEXT NOT NULL,
  observed_in_snapshot BYTEA NOT NULL
);

CREATE INDEX mcp_servers_status_idx ON mcp_servers (status);
CREATE INDEX mcp_servers_last_observed_idx ON mcp_servers (last_observed_at DESC);
