//! Postgres connection pool, embedded migrations, and store impls.

use std::time::Duration;

use postgres::NoTls;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;
use thiserror::Error;

pub mod migrations;
pub mod mirror;
pub mod publisher_enrichment;
pub mod publisher_rights;
pub mod snapshots;

pub type PgConnectionManager = PostgresConnectionManager<NoTls>;
pub type PgPool = Pool<PgConnectionManager>;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("postgres: {0}")]
    Postgres(#[from] postgres::Error),
    #[error("pool: {0}")]
    Pool(#[from] r2d2::Error),
    #[error("config: {0}")]
    Config(String),
}

/// Build a connection pool against the given Postgres URL.
pub fn build_pool(database_url: &str) -> Result<PgPool, DbError> {
    let config = database_url
        .parse::<postgres::Config>()
        .map_err(|error| DbError::Config(error.to_string()))?;
    let manager = PostgresConnectionManager::new(config, NoTls);
    let pool = Pool::builder()
        .max_size(8)
        .min_idle(Some(1))
        .connection_timeout(Duration::from_secs(10))
        .build(manager)?;
    Ok(pool)
}
