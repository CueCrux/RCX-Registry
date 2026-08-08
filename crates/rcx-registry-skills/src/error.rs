use thiserror::Error;

#[derive(Debug, Error)]
pub enum SkillsError {
    #[error("lockfile json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("frontmatter yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The document did not open with a `---` frontmatter fence, or the closing
    /// fence was missing. Both are fatal: a SKILL.md with no frontmatter has no
    /// name or description, so nothing downstream can index it.
    #[error("SKILL.md has no closing frontmatter fence")]
    MalformedFrontMatter,

    /// A `computedHash` that is not 64 lowercase hex characters. Rejected at parse
    /// time rather than at compare time, so a malformed lockfile cannot silently
    /// verify against a digest it could never equal.
    #[error("lock entry `{name}`: computedHash must be 64 lowercase hex chars, got {got:?}")]
    BadHash { name: String, got: String },

    /// A source type this crate cannot fetch. Kept explicit rather than defaulted
    /// so adding a transport is a compile-time decision, not a silent fallthrough.
    #[error("lock entry `{name}`: unsupported sourceType {source_type:?}")]
    UnsupportedSource { name: String, source_type: String },

    /// The lockfile parses but must not be signed. Distinct from a validation
    /// failure: the file is well-formed, it just does not carry enough to make a
    /// signature mean anything.
    #[error("lockfile is not signable: {reason}")]
    NotSignable { reason: String },

    /// A `skill://` URI could not be parsed. The grammar is public, so the parser
    /// rejects anything ambiguous rather than guessing.
    #[error("bad skill uri {uri:?}: {reason}")]
    BadSkillUri { uri: String, reason: String },

    /// A ref could not be resolved to a commit, so nothing can be pinned.
    ///
    /// The repo field is `repo`, not `source`: `thiserror` reserves `source` for the
    /// underlying-error accessor and rejects a plain `String` there.
    #[error("could not resolve a commit for source `{repo}`: {detail}")]
    RefResolution { repo: String, detail: String },
}
