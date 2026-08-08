//! M4 gate: the `skill://` scheme, its immutability property, and resolution order.
//!
//! This grammar becomes public with this milestone. Third parties will parse these
//! strings, so the round-trip and rejection cases below are a compatibility contract,
//! not just unit tests — changing them later breaks other people's software silently.

use std::collections::BTreeMap;

use rcx_registry_skills::{
    resolution_order, resolve, resolve_by_id, uris_for, LockEntry, Registry, RegistryKind,
    SkillLock, SkillUri, LOCK_VERSION, RCX_SKILL_REGISTRY_AUTHORITY,
};

const SHA_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
const SHA_B: &str = "0fedcba98765432100112233445566778899aabb";
const HASH_A: &str = "4ea04d576507f4a683e6203737c33993fb36add719f628b7200649a9cb87b5fe";
const HASH_B: &str = "fc517263c322bfba196a3da7f3c63fa4e650edaecbe34b966438f03719d8f695";

fn entry(git_ref: &str, hash: &str) -> LockEntry {
    LockEntry {
        source: "a/b".into(),
        source_type: "github".into(),
        skill_path: "skills/x/SKILL.md".into(),
        git_ref: git_ref.into(),
        computed_hash: hash.into(),
    }
}

fn lock_with(pairs: &[(&str, &str, &str)]) -> SkillLock {
    let mut skills = BTreeMap::new();
    for (name, git_ref, hash) in pairs {
        skills.insert((*name).to_string(), entry(git_ref, hash));
    }
    SkillLock {
        version: LOCK_VERSION,
        skills,
    }
}

// ── grammar ──────────────────────────────────────────────────────────────────

#[test]
fn a_pinned_uri_round_trips() {
    let raw = format!("skill://{RCX_SKILL_REGISTRY_AUTHORITY}/ab-testing@{SHA_A}");
    let uri = SkillUri::parse(&raw).expect("parses");
    assert_eq!(uri.registry, RCX_SKILL_REGISTRY_AUTHORITY);
    assert_eq!(uri.skill_id, "ab-testing");
    assert_eq!(uri.version.as_deref(), Some(SHA_A));
    assert!(uri.is_pinned());
    assert_eq!(
        uri.to_string(),
        raw,
        "render must reproduce the input exactly"
    );
}

#[test]
fn an_unpinned_uri_round_trips() {
    let raw = format!("skill://{RCX_SKILL_REGISTRY_AUTHORITY}/ab-testing");
    let uri = SkillUri::parse(&raw).expect("parses");
    assert!(!uri.is_pinned());
    assert_eq!(uri.to_string(), raw);
    assert_eq!(uri.pinned_to(SHA_A).to_string(), format!("{raw}@{SHA_A}"));
}

#[test]
fn other_authorities_and_ports_parse() {
    for raw in [
        "skill://internal.acme.corp/acme-deploy-pipeline",
        "skill://localhost:8000/my-local-skill",
        "skill://skills-mcp.workers.dev/stripe-integration",
    ] {
        let uri = SkillUri::parse(raw).expect("parses");
        assert_eq!(uri.to_string(), raw, "round trip for {raw}");
    }
}

#[test]
fn version_case_is_normalised() {
    let upper = format!("skill://h/x@{}", SHA_A.to_uppercase());
    let uri = SkillUri::parse(&upper).expect("parses");
    assert_eq!(
        uri.version.as_deref(),
        Some(SHA_A),
        "one spelling per commit"
    );
}

#[test]
fn a_mutable_version_is_refused() {
    // The property the whole scheme rests on. A tag or semver can be moved by the
    // publisher, so a URI carrying one is not an identifier — it only looks like one.
    for bad in ["@v1.2", "@latest", "@main", "@1.0.0", "@a1b2c3d", "@"] {
        let raw = format!("skill://h/x{bad}");
        assert!(
            SkillUri::parse(&raw).is_err(),
            "expected {raw} to be refused"
        );
    }
}

#[test]
fn malformed_uris_are_refused() {
    for bad in [
        "",
        "https://h/x",
        "skill://",
        "skill://h",               // no /skill-id
        "skill:///x",              // empty authority
        "skill://h/",              // empty skill id
        "skill://h/a/b",           // '/' in the id makes the boundary ambiguous
        "skill://h/../etc/passwd", // traversal
        "skill://h /x",            // space in authority
        "skill://h/x@y@z",         // ambiguous double pin
    ] {
        assert!(
            SkillUri::parse(bad).is_err(),
            "expected {bad:?} to be refused"
        );
    }
}

// ── immutability ─────────────────────────────────────────────────────────────

#[test]
fn a_pinned_uri_resolves_to_exactly_one_object() {
    let registries = vec![Registry {
        host: RCX_SKILL_REGISTRY_AUTHORITY.to_string(),
        kind: RegistryKind::Local,
        lock: lock_with(&[("ab-testing", SHA_A, HASH_A)]),
    }];

    let pinned = SkillUri::parse(&format!(
        "skill://{RCX_SKILL_REGISTRY_AUTHORITY}/ab-testing@{SHA_A}"
    ))
    .expect("parses");
    let hit = resolve(&pinned, &registries).expect("resolves");
    assert_eq!(hit.entry.computed_hash, HASH_A);
    assert_eq!(hit.kind, RegistryKind::Local);

    // The same id at a different commit is a *different object*, not a stale hit.
    let moved = vec![Registry {
        host: RCX_SKILL_REGISTRY_AUTHORITY.to_string(),
        kind: RegistryKind::Local,
        lock: lock_with(&[("ab-testing", SHA_B, HASH_B)]),
    }];
    assert!(
        resolve(&pinned, &moved).is_none(),
        "a pinned URI must never silently resolve to another commit's content"
    );
}

#[test]
fn a_named_registry_cannot_be_substituted_by_a_higher_precedence_one() {
    // The substitution the scheme exists to prevent: a URI that explicitly asked
    // a remote must not be answered by the local registry just because local wins
    // the *search* order. Precedence applies to search, never to an explicit URI.
    let registries = vec![
        Registry {
            host: "local.example".to_string(),
            kind: RegistryKind::Local,
            lock: lock_with(&[("ab-testing", SHA_B, HASH_B)]),
        },
        Registry {
            host: "remote.example".to_string(),
            kind: RegistryKind::PublicFallback,
            lock: lock_with(&[("ab-testing", SHA_A, HASH_A)]),
        },
    ];

    let uri = SkillUri::parse("skill://remote.example/ab-testing").expect("parses");
    let hit = resolve(&uri, &registries).expect("resolves");
    assert_eq!(hit.registry, "remote.example");
    assert_eq!(
        hit.entry.computed_hash, HASH_A,
        "the named registry must answer, not the higher-precedence one"
    );

    assert!(
        resolve(
            &SkillUri::parse("skill://unknown.example/ab-testing").expect("parses"),
            &registries
        )
        .is_none(),
        "an unknown authority must not fall through to any registry"
    );
}

// ── resolution order ─────────────────────────────────────────────────────────

#[test]
fn search_precedence_is_local_then_trusted_then_public() {
    let registries = vec![
        Registry {
            host: "public.example".to_string(),
            kind: RegistryKind::PublicFallback,
            lock: lock_with(&[("shared", SHA_A, HASH_A)]),
        },
        Registry {
            host: "trusted-b.example".to_string(),
            kind: RegistryKind::TrustedRemote,
            lock: lock_with(&[("shared", SHA_A, HASH_A)]),
        },
        Registry {
            host: "local.example".to_string(),
            kind: RegistryKind::Local,
            lock: lock_with(&[("shared", SHA_B, HASH_B)]),
        },
        Registry {
            host: "trusted-a.example".to_string(),
            kind: RegistryKind::TrustedRemote,
            lock: lock_with(&[("shared", SHA_A, HASH_A)]),
        },
    ];

    let order: Vec<&str> = resolution_order(&registries)
        .iter()
        .map(|r| r.host.as_str())
        .collect();
    assert_eq!(
        order,
        vec![
            "local.example",
            // configured order preserved within a kind — not re-sorted by host
            "trusted-b.example",
            "trusted-a.example",
            "public.example",
        ]
    );

    let hit = resolve_by_id("shared", &registries).expect("resolves");
    assert_eq!(hit.registry, "local.example");
    assert_eq!(
        hit.entry.computed_hash, HASH_B,
        "a local pin must never be overridden by a remote answer"
    );
    // The bare-id path hands back a fully pinned URI, so the caller can cache an
    // identifier rather than a query.
    assert!(hit.uri.is_pinned());
    assert_eq!(
        hit.uri.to_string(),
        format!("skill://local.example/shared@{SHA_B}")
    );
}

#[test]
fn an_unknown_skill_resolves_nowhere() {
    let registries = vec![Registry {
        host: "local.example".to_string(),
        kind: RegistryKind::Local,
        lock: lock_with(&[("present", SHA_A, HASH_A)]),
    }];
    assert!(resolve_by_id("absent", &registries).is_none());
}

// ── publishing a lockfile ────────────────────────────────────────────────────

#[test]
fn uris_for_addresses_every_skill_and_round_trips() {
    let lock = lock_with(&[
        ("ab-testing", SHA_A, HASH_A),
        ("ad-creative", SHA_B, HASH_B),
    ]);
    let uris = uris_for(&lock, RCX_SKILL_REGISTRY_AUTHORITY);
    assert_eq!(uris.len(), 2);
    for uri in &uris {
        assert!(uri.is_pinned(), "a v2 lockfile yields stable identifiers");
        assert_eq!(
            SkillUri::parse(&uri.to_string()).expect("re-parses"),
            *uri,
            "every emitted URI must parse back to itself"
        );
    }
}

#[test]
fn a_v1_lockfile_yields_unpinned_uris() {
    // Browsable, but it cannot hand out stable identifiers — the same reason it
    // cannot be signed.
    let lock = lock_with(&[("ab-testing", "", HASH_A)]);
    let uris = uris_for(&lock, RCX_SKILL_REGISTRY_AUTHORITY);
    assert!(!uris[0].is_pinned());
}
