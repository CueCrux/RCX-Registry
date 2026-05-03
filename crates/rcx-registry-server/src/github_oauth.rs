//! GitHub OAuth provider — backs the publisher-rights verification flow.
//!
//! Implements [`rcx_registry_api::GitHubOAuthProvider`]:
//!  - `authorize_url` constructs the canonical
//!    `https://github.com/login/oauth/authorize` URL with `client_id`,
//!    `redirect_uri`, `scope`, and `state`.
//!  - `exchange_code` POSTs the callback `code` to
//!    `https://github.com/login/oauth/access_token`, then GETs
//!    `https://api.github.com/user` with the resulting token to read the
//!    canonical login. The login is what the API handler compares to the
//!    namespace owner.
//!
//! The state token is opaque to the provider; the registry only forwards
//! whatever the caller supplied. v1.0 does not implement server-side CSRF
//! tracking — clients are expected to bind their own state.

use std::time::Duration;

use rcx_registry_api::{ApiError, GitHubOAuthProvider};
use reqwest::blocking::Client;
use serde::Deserialize;
use url::Url;

const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const GITHUB_USER_AGENT: &str = "rcx-registry/0.1 (+https://registry.rcxprotocol.org)";

pub struct GitHubOAuthClient {
    client: Client,
    client_id: String,
    client_secret: String,
    scope: String,
}

impl GitHubOAuthClient {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let client = Client::builder()
            .user_agent(GITHUB_USER_AGENT)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| ApiError::Store(format!("github oauth client: {error}")))?;
        Ok(Self {
            client,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: scope.into(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    login: String,
}

impl GitHubOAuthProvider for GitHubOAuthClient {
    fn authorize_url(
        &self,
        _owner: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<String, ApiError> {
        let mut url = Url::parse(GITHUB_AUTHORIZE_URL)
            .map_err(|error| ApiError::Store(format!("github authorize url: {error}")))?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &self.scope)
            .append_pair("state", state)
            .append_pair("allow_signup", "false");
        Ok(url.to_string())
    }

    fn exchange_code(&self, code: &str, state: &str) -> Result<String, ApiError> {
        let response = self
            .client
            .post(GITHUB_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("state", state),
            ])
            .send()
            .map_err(|error| ApiError::VerificationFailed(format!("github token: {error}")))?;
        if !response.status().is_success() {
            return Err(ApiError::VerificationFailed(format!(
                "github token exchange returned status {}",
                response.status().as_u16()
            )));
        }
        let body: AccessTokenResponse = response.json().map_err(|error| {
            ApiError::VerificationFailed(format!("github token decode: {error}"))
        })?;
        let access_token = body.access_token.ok_or_else(|| {
            ApiError::VerificationFailed(format!(
                "github token error: {} ({})",
                body.error.unwrap_or_else(|| "unknown".to_string()),
                body.error_description.unwrap_or_default()
            ))
        })?;

        let user_response = self
            .client
            .get(GITHUB_USER_URL)
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(&access_token)
            .send()
            .map_err(|error| ApiError::VerificationFailed(format!("github user: {error}")))?;
        if !user_response.status().is_success() {
            return Err(ApiError::VerificationFailed(format!(
                "github user lookup returned status {}",
                user_response.status().as_u16()
            )));
        }
        let user: GitHubUser = user_response.json().map_err(|error| {
            ApiError::VerificationFailed(format!("github user decode: {error}"))
        })?;
        Ok(user.login)
    }
}
