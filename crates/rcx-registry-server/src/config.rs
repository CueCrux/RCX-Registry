//! Environment-driven server configuration.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;

/// Where the binary listens for HTTP requests.
pub const DEFAULT_BIND: &str = "0.0.0.0:3030";
/// Default upstream MCP registry base URL.
pub const DEFAULT_MCP_BASE_URL: &str = "https://registry.modelcontextprotocol.io";
/// Default Vault Transit signing key id (matches the master plan / ExecPlan §M0).
pub const DEFAULT_SIGNER_KID: &str = "vault:transit:rcx-registry-signing-key-1";
/// Default GitHub OAuth scope — only need login claim, not repo or email.
pub const DEFAULT_GITHUB_OAUTH_SCOPE: &str = "read:user";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required env var `{0}` is not set")]
    Missing(&'static str),
    #[error("invalid env var `{name}`: {message}")]
    Invalid { name: &'static str, message: String },
}

/// Top-level server configuration. Built from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub run_migrations: bool,
    pub mcp: McpConfig,
    pub feature_flags: FeatureFlags,
    pub signer: SignerConfig,
    pub github_oauth: Option<GitHubOAuthConfig>,
    pub dns: DnsConfig,
}

#[derive(Debug, Clone)]
pub struct McpConfig {
    pub base_url: String,
    pub sync_interval: Duration,
    pub min_interval_floor: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct FeatureFlags {
    /// Master flag — when off, RCX-specific endpoints return 503 and the
    /// MCP-mirror baseline keeps serving.
    pub feature_rcx_registry: bool,
    /// Off → declaration fetcher idle; publisher-enriched entries fall back.
    pub publisher_declarations: bool,
    /// Off → submission endpoints return 503; existing rows still queryable.
    pub attestations: bool,
    /// Off → SessionPlans emit no `AttestationRef` entries.
    pub protocol_integration: bool,
    /// Off → cursors emit unsigned (compat fallback).
    pub signed_cursors: bool,
}

#[derive(Debug, Clone)]
pub struct SignerConfig {
    pub signer_kid: String,
    pub vault: Option<VaultConfig>,
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub addr: String,
    pub token: String,
    pub key_name: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GitHubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub use_system_resolver: bool,
}

impl Config {
    /// Build a `Config` from process environment.
    ///
    /// Recognised variables:
    ///
    /// | Variable | Default | Notes |
    /// |---|---|---|
    /// | `RCX_REGISTRY_BIND` | `0.0.0.0:3030` | listen address |
    /// | `DATABASE_URL` | required | Postgres URL |
    /// | `RCX_REGISTRY_RUN_MIGRATIONS` | `true` | run embedded migrations on boot |
    /// | `MCP_REGISTRY_BASE_URL` | `https://registry.modelcontextprotocol.io` | upstream |
    /// | `RCX_REGISTRY_SYNC_INTERVAL_SECS` | `3600` | sync cadence |
    /// | `RCX_REGISTRY_MIN_INTERVAL_FLOOR_SECS` | `600` | min sync gap |
    /// | `FEATURE_RCX_REGISTRY` | `false` | master |
    /// | `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS` | `false` | |
    /// | `FEATURE_RCX_REGISTRY_ATTESTATIONS` | `false` | |
    /// | `FEATURE_RCX_REGISTRY_PROTOCOL_INTEGRATION` | `false` | |
    /// | `FEATURE_RCX_REGISTRY_SIGNED_CURSORS` | `false` | |
    /// | `RCX_REGISTRY_SIGNER_KID` | `vault:transit:rcx-registry-signing-key-1` | |
    /// | `VAULT_ADDR` | unset | enables Vault Transit signer when set |
    /// | `VAULT_TOKEN` | required if `VAULT_ADDR` set | |
    /// | `VAULT_TRANSIT_KEY_NAME` | `rcx-registry-signing-key-1` | |
    /// | `VAULT_NAMESPACE` | unset | optional |
    /// | `GITHUB_OAUTH_CLIENT_ID` | unset | enables real GitHub OAuth when both set |
    /// | `GITHUB_OAUTH_CLIENT_SECRET` | unset | |
    /// | `GITHUB_OAUTH_SCOPE` | `read:user` | |
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = parse_socket_addr_env("RCX_REGISTRY_BIND", DEFAULT_BIND)?;
        let database_url = require_env("DATABASE_URL")?;
        let run_migrations = parse_bool_env("RCX_REGISTRY_RUN_MIGRATIONS", true)?;
        let mcp = McpConfig {
            base_url: env::var("MCP_REGISTRY_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_MCP_BASE_URL.to_string()),
            sync_interval: Duration::from_secs(parse_u64_env(
                "RCX_REGISTRY_SYNC_INTERVAL_SECS",
                3600,
            )?),
            min_interval_floor: Duration::from_secs(parse_u64_env(
                "RCX_REGISTRY_MIN_INTERVAL_FLOOR_SECS",
                600,
            )?),
        };
        let feature_flags = FeatureFlags {
            feature_rcx_registry: parse_bool_env("FEATURE_RCX_REGISTRY", false)?,
            publisher_declarations: parse_bool_env(
                "FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS",
                false,
            )?,
            attestations: parse_bool_env("FEATURE_RCX_REGISTRY_ATTESTATIONS", false)?,
            protocol_integration: parse_bool_env(
                "FEATURE_RCX_REGISTRY_PROTOCOL_INTEGRATION",
                false,
            )?,
            signed_cursors: parse_bool_env("FEATURE_RCX_REGISTRY_SIGNED_CURSORS", false)?,
        };
        let signer = SignerConfig {
            signer_kid: env::var("RCX_REGISTRY_SIGNER_KID")
                .unwrap_or_else(|_| DEFAULT_SIGNER_KID.to_string()),
            vault: match env::var("VAULT_ADDR")
                .ok()
                .filter(|value| !value.is_empty())
            {
                Some(addr) => Some(VaultConfig {
                    addr,
                    token: require_env("VAULT_TOKEN")?,
                    key_name: env::var("VAULT_TRANSIT_KEY_NAME")
                        .unwrap_or_else(|_| "rcx-registry-signing-key-1".to_string()),
                    namespace: env::var("VAULT_NAMESPACE")
                        .ok()
                        .filter(|value| !value.is_empty()),
                }),
                None => None,
            },
        };
        let github_oauth = match (
            env::var("GITHUB_OAUTH_CLIENT_ID").ok(),
            env::var("GITHUB_OAUTH_CLIENT_SECRET").ok(),
        ) {
            (Some(client_id), Some(client_secret))
                if !client_id.is_empty() && !client_secret.is_empty() =>
            {
                Some(GitHubOAuthConfig {
                    client_id,
                    client_secret,
                    scope: env::var("GITHUB_OAUTH_SCOPE")
                        .unwrap_or_else(|_| DEFAULT_GITHUB_OAUTH_SCOPE.to_string()),
                })
            }
            _ => None,
        };
        let dns = DnsConfig {
            use_system_resolver: parse_bool_env("RCX_REGISTRY_DNS_USE_SYSTEM_RESOLVER", false)?,
        };

        Ok(Self {
            bind_addr,
            database_url,
            run_migrations,
            mcp,
            feature_flags,
            signer,
            github_oauth,
            dns,
        })
    }

    pub fn loopback() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3030),
            database_url: "postgres://localhost/rcx_registry".to_string(),
            run_migrations: true,
            mcp: McpConfig {
                base_url: DEFAULT_MCP_BASE_URL.to_string(),
                sync_interval: Duration::from_secs(3600),
                min_interval_floor: Duration::from_secs(600),
            },
            feature_flags: FeatureFlags::default(),
            signer: SignerConfig {
                signer_kid: DEFAULT_SIGNER_KID.to_string(),
                vault: None,
            },
            github_oauth: None,
            dns: DnsConfig {
                use_system_resolver: false,
            },
        }
    }
}

fn require_env(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_socket_addr_env(name: &'static str, default: &str) -> Result<SocketAddr, ConfigError> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    raw.parse::<SocketAddr>()
        .map_err(|error| ConfigError::Invalid {
            name,
            message: error.to_string(),
        })
}

fn parse_u64_env(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env::var(name).ok().filter(|value| !value.is_empty()) {
        Some(value) => value.parse::<u64>().map_err(|error| ConfigError::Invalid {
            name,
            message: error.to_string(),
        }),
        None => Ok(default),
    }
}

fn parse_bool_env(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name).ok().filter(|value| !value.is_empty()) {
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid {
                name,
                message: format!("expected boolean, got `{other}`"),
            }),
        },
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bool_env, parse_u64_env};
    use std::env;

    fn with_env<R>(name: &'static str, value: Option<&str>, run: impl FnOnce() -> R) -> R {
        let prior = env::var(name).ok();
        match value {
            Some(value) => env::set_var(name, value),
            None => env::remove_var(name),
        }
        let outcome = run();
        match prior {
            Some(value) => env::set_var(name, value),
            None => env::remove_var(name),
        }
        outcome
    }

    #[test]
    fn parses_bool_env_variants() {
        let result = with_env("RCX_TEST_BOOL_TRUE", Some("yes"), || {
            parse_bool_env("RCX_TEST_BOOL_TRUE", false)
        });
        assert!(result.expect("env should parse"));

        let result = with_env("RCX_TEST_BOOL_FALSE", Some("0"), || {
            parse_bool_env("RCX_TEST_BOOL_FALSE", true)
        });
        assert!(!result.expect("env should parse"));

        let result = with_env("RCX_TEST_BOOL_DEFAULT", None, || {
            parse_bool_env("RCX_TEST_BOOL_DEFAULT", true)
        });
        assert!(result.expect("env should parse"));
    }

    #[test]
    fn parses_u64_env_with_default() {
        let result = with_env("RCX_TEST_U64", Some("42"), || {
            parse_u64_env("RCX_TEST_U64", 0)
        });
        assert_eq!(result.expect("env should parse"), 42);

        let result = with_env("RCX_TEST_U64_MISSING", None, || {
            parse_u64_env("RCX_TEST_U64_MISSING", 99)
        });
        assert_eq!(result.expect("env should parse"), 99);
    }
}
