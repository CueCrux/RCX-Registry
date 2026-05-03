//! Real DNS TXT resolver backed by hickory-resolver.
//!
//! Used to verify `_rcx-registry.<domain>` TXT records during publisher
//! rights verification (M3). The trait surface is sync to match the API
//! crate, so we keep a blocking [`hickory_resolver::Resolver`] inside.

use std::sync::Arc;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use rcx_registry_api::{ApiError, DnsTxtResolver};

/// DNS TXT resolver that talks to the system resolver or Cloudflare 1.1.1.1.
pub struct HickoryDnsTxtResolver {
    inner: Arc<Resolver>,
}

impl HickoryDnsTxtResolver {
    /// Build a resolver using Cloudflare's public 1.1.1.1 servers.
    pub fn cloudflare() -> Result<Self, ApiError> {
        let resolver = Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default())
            .map_err(|error| ApiError::Store(format!("dns resolver init failed: {error}")))?;
        Ok(Self {
            inner: Arc::new(resolver),
        })
    }

    /// Build a resolver from `/etc/resolv.conf` style system configuration.
    pub fn system() -> Result<Self, ApiError> {
        let resolver = Resolver::from_system_conf().map_err(|error| {
            ApiError::Store(format!("dns resolver system init failed: {error}"))
        })?;
        Ok(Self {
            inner: Arc::new(resolver),
        })
    }
}

impl DnsTxtResolver for HickoryDnsTxtResolver {
    fn lookup_txt(&self, record_name: &str) -> Result<Vec<String>, ApiError> {
        match self.inner.txt_lookup(record_name) {
            Ok(response) => {
                let mut values = Vec::new();
                for txt in response.iter() {
                    let mut joined = String::new();
                    for chunk in txt.txt_data() {
                        if let Ok(text) = std::str::from_utf8(chunk) {
                            joined.push_str(text);
                        }
                    }
                    if !joined.is_empty() {
                        values.push(joined);
                    }
                }
                Ok(values)
            }
            Err(error) => {
                use hickory_resolver::error::ResolveErrorKind;
                if matches!(error.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                    Ok(Vec::new())
                } else {
                    Err(ApiError::Store(format!("dns lookup failed: {error}")))
                }
            }
        }
    }
}
