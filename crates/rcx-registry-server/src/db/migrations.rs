//! Embedded SQL migrations + minimal applied-tracker.
//!
//! Avoids pulling sqlx-cli or refinery; the registry only needs simple
//! forward-only migration application keyed by filename.

use super::{DbError, PgPool};

/// Migration files baked into the binary at compile time, applied in order.
pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_mcp_servers.sql",
        include_str!("../../../../migrations/0001_mcp_servers.sql"),
    ),
    (
        "0002_snapshots.sql",
        include_str!("../../../../migrations/0002_snapshots.sql"),
    ),
    (
        "0003_rcx_enrichment.sql",
        include_str!("../../../../migrations/0003_rcx_enrichment.sql"),
    ),
    (
        "0004_publisher_rights.sql",
        include_str!("../../../../migrations/0004_publisher_rights.sql"),
    ),
    ("0005_mcp_servers_envelope.sql", MIGRATION_0005),
    (
        "0006_rcx_enrichment_publisher_meta.sql",
        include_str!("../../../../migrations/0006_rcx_enrichment_publisher_meta.sql"),
    ),
];

const MIGRATION_0005: &str = r#"
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS envelope_json JSONB;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS version TEXT;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS is_latest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS deleted_upstream_at TIMESTAMPTZ;

UPDATE mcp_servers
   SET envelope_json = jsonb_build_object(
         'server', server_json,
         '_meta', jsonb_build_object(
           'io.modelcontextprotocol.registry/official',
           jsonb_build_object('status', status, 'isLatest', is_latest)
         )
       )
 WHERE envelope_json IS NULL;

ALTER TABLE mcp_servers ALTER COLUMN envelope_json SET NOT NULL;

CREATE INDEX IF NOT EXISTS mcp_servers_is_latest_idx ON mcp_servers (is_latest) WHERE is_latest = TRUE;
"#;

/// Apply all pending migrations idempotently.
///
/// Tracks applied filenames in `_rcx_registry_migrations`. Each migration's
/// SQL runs inside a transaction; failure rolls back and surfaces the error
/// without marking the file as applied.
pub fn run(pool: &PgPool) -> Result<Vec<&'static str>, DbError> {
    let mut conn = pool.get()?;
    conn.batch_execute(
        "CREATE TABLE IF NOT EXISTS _rcx_registry_migrations (\
            filename TEXT PRIMARY KEY,\
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
        )",
    )?;

    let mut applied = Vec::new();
    for (filename, sql) in MIGRATIONS {
        let already_applied: bool = conn
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM _rcx_registry_migrations WHERE filename = $1)",
                &[filename],
            )?
            .get(0);
        if already_applied {
            continue;
        }

        let mut tx = conn.transaction()?;
        tx.batch_execute(sql)?;
        tx.execute(
            "INSERT INTO _rcx_registry_migrations (filename) VALUES ($1)",
            &[filename],
        )?;
        tx.commit()?;
        applied.push(*filename);
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    #[test]
    fn embedded_migrations_are_in_dependency_order() {
        let names: Vec<&str> = MIGRATIONS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                "0001_mcp_servers.sql",
                "0002_snapshots.sql",
                "0003_rcx_enrichment.sql",
                "0004_publisher_rights.sql",
                "0005_mcp_servers_envelope.sql",
                "0006_rcx_enrichment_publisher_meta.sql",
            ]
        );
    }

    #[test]
    fn embedded_migrations_are_non_empty_strings() {
        for (name, sql) in MIGRATIONS {
            assert!(
                !sql.trim().is_empty(),
                "migration `{name}` is empty — include_str! path is wrong"
            );
        }
    }
}
