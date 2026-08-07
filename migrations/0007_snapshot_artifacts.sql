-- Persist the artifacts a third party needs to verify a snapshot without
-- trusting the operator.
--
-- Both columns are NULLable and both must be, because neither is recoverable
-- for snapshots already recorded:
--
--   receipt_cbor  The exact canonical-CBOR bytes that were signed, with the
--                 signature filled in. The seven columns already on this table
--                 are DERIVED fields — event_id, previous_snapshot_hash,
--                 upstream_registry_uri, upstream_snapshot_etag and changes
--                 never landed here, so the signed preimage cannot be
--                 reconstructed from a row. Rows written before this migration
--                 therefore stay NULL forever and are not serveable.
--
--   entries_json  The {name, version, canonical_json} set the root digests, as
--                 a JSON array. v1's snapshot_merkle_root is a FLAT set digest,
--                 not a tree, so there is no inclusion proof: the only way to
--                 prove a named server is inside a signed snapshot is to
--                 recompute the whole digest over the full set. The mirror is
--                 mutable, so a past snapshot's membership is gone once servers
--                 update — it has to be captured at sign time or not at all.
--
-- Stored as BYTEA and left to Postgres TOAST for compression. An entry set is
-- ~10 MB at 17.4k servers, well past the 2 KB TOAST threshold, so it is
-- compressed out of line without this schema (or the application) taking a
-- compression dependency.
--
-- Retention is asymmetric on purpose. Receipts are ~250 bytes and form the
-- history chain, so they are kept indefinitely. Entry sets are ~10 MB on an
-- hourly sync (~240 MB/day) and are only needed to verify a CURRENT server, so
-- the sync loop nulls all but the most recent N after each write.

ALTER TABLE snapshots
  ADD COLUMN IF NOT EXISTS receipt_cbor BYTEA,
  ADD COLUMN IF NOT EXISTS entries_json BYTEA;

-- Serving /v0/snapshots/latest means "most recent snapshot that is actually
-- verifiable", which is not the same row as "most recent snapshot" until the
-- pre-migration rows age out.
CREATE INDEX IF NOT EXISTS snapshots_verifiable_idx
  ON snapshots (scraped_at DESC)
  WHERE receipt_cbor IS NOT NULL;
