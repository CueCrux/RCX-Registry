//! Internal onboarding and moderation helpers.

/// Supported publisher-rights verification methods in v1.0.
pub const VERIFICATION_METHODS: [&str; 3] = ["github_oauth", "dns_txt", "manual"];
