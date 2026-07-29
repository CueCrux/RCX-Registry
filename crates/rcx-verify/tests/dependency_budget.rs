//! CONTRACT.md §8.3 — the SDK's dependency tree must contain no HTTP client, TLS
//! stack, async runtime or JSON-schema validator.
//!
//! Asserted mechanically because the failure mode is silent: someone adds a
//! convenience dependency, the tree grows a TLS stack, and "offline verification"
//! becomes untrue without a single test going red. Reading the manifest is not
//! enough — the forbidden crates arrive transitively.

use std::process::Command;

/// Substring match against crate names in the resolved tree. Deliberately blunt:
/// a false positive is a one-line conversation, a false negative is a shipped lie.
const FORBIDDEN: &[&str] = &[
    "reqwest",
    "hyper",
    "tokio",
    "async-std",
    "rustls",
    "native-tls",
    "openssl",
    "jsonschema",
    "h2",
    "mio",
];

#[test]
fn sdk_tree_contains_no_http_tls_async_or_schema_dependency() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--package",
            "rcx-verify",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--no-dedupe",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree should run");

    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let tree = String::from_utf8_lossy(&output.stdout);
    let names: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();

    // Positive control: if the tree came back empty or unparseable, the absence
    // of forbidden crates would be meaningless. A green assertion must mean
    // "we looked and they were not there", never "we failed to look".
    assert!(
        names.contains(&"rcx-verify"),
        "cargo tree output did not contain rcx-verify itself — parse failed, so \
         this test proves nothing:\n{tree}"
    );
    assert!(
        names.contains(&"rcx-registry-crown"),
        "expected rcx-registry-crown in the tree; got:\n{tree}"
    );

    let found: Vec<&&str> = FORBIDDEN
        .iter()
        .filter(|forbidden| names.iter().any(|name| name.contains(**forbidden)))
        .collect();

    assert!(
        found.is_empty(),
        "rcx-verify must verify offline from bytes, but its dependency tree \
         contains {found:?}. Either drop the dependency or amend CONTRACT.md §8.3 \
         deliberately — do not relax this test to make a build pass."
    );
}
