CREATE TABLE snapshots (
  snapshot_id BYTEA PRIMARY KEY,
  snapshot_hash BYTEA NOT NULL,
  server_count INTEGER NOT NULL,
  scraped_at TIMESTAMPTZ NOT NULL,
  receipt_hash BYTEA NOT NULL,
  receipt_signature BYTEA NOT NULL,
  signer_kid TEXT NOT NULL
);

CREATE INDEX snapshots_scraped_at_idx ON snapshots (scraped_at DESC);
