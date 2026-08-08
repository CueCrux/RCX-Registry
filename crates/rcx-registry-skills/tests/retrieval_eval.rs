//! M6 gate: skill retrieval through CoreCrux instead of Qdrant.
//!
//! `#[ignore]` — needs a reachable Crux daemon. Run it deliberately:
//!
//! ```text
//! CRUX_HTTP_URL=http://<host>:14800 CRUX_AGENT_TOKEN=<tok> \
//!   cargo test -p rcx-registry-skills --test retrieval_eval -- --ignored --nocapture
//! ```
//!
//! ## Corpus and baseline
//!
//! Corpus is **SKILLS-32**: the 32 vendored skills from the reference
//! implementation, frontmatter only. Queries are one per skill, written as tasks
//! rather than paraphrases of the descriptions — a query set lifted from the
//! descriptions measures string overlap, not retrieval.
//!
//! The milestone's original gate said "parity or better vs the Qdrant baseline".
//! **There is no such baseline and there cannot be one here:** upstream's Qdrant
//! index is built with Cloudflare Workers AI embeddings, which needs an account
//! this project does not have, and standing up Qdrant with a *different* embedder
//! would produce a number that looks comparable and is not. Rather than
//! manufacture a false comparison, this reports an absolute recall figure against
//! a named corpus, which is the thing anyone can reproduce and re-run.

use std::collections::BTreeMap;

use rcx_registry_skills::{ingest_body, SkillDocument};
use serde::Deserialize;

const QUERIES: &str = include_str!("fixtures/skills-32-queries.json");
const TENANT: &str = "skills-registry-eval";
const CORPUS: &str = "SKILLS-32";

/// Absolute bars. Deliberately not 100%: several queries are genuinely hard for a
/// lexical index ("our landing page looks like every other generic AI site"), and
/// a gate that demands perfection on a hand-written set invites tuning the set.
const MIN_R_AT_5: f64 = 0.75;
const MIN_R_AT_1: f64 = 0.50;

#[derive(Deserialize)]
struct QuerySet {
    corpus: String,
    queries: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    q: String,
    expect: String,
}

fn load_corpus() -> Vec<(String, SkillDocument, Option<String>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/skills-32");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixture dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_string();
        let raw = std::fs::read_to_string(&path).expect("read");
        let doc =
            SkillDocument::parse(&raw).unwrap_or_else(|e| panic!("{id} failed to parse: {e}"));
        let uri = Some(format!(
            "skill://{}/{id}",
            rcx_registry_skills::RCX_SKILL_REGISTRY_AUTHORITY
        ));
        out.push((id, doc, uri));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Map a search hit back to a skill id.
///
/// The daemon returns pointers, not content: a hit carries `segment_index`,
/// `doc_id`, `score` and offsets, but no title, metadata or text. `doc_id` is a
/// daemon-assigned **integer**, not the `doc_id` string supplied at ingest, and
/// this build exposes no hydration route (`/v1/query/fetch-content` 404s), so
/// there is nothing to resolve it against server-side.
///
/// Empirically — verified against five unambiguous probes, each hitting rank 1 —
/// the integer is the zero-based index of the document within the ingest request.
/// That is sound *here* because this test ingests the corpus itself and therefore
/// knows the order.
///
/// **It is not a production mechanism.** A resolve surface that cannot turn a hit
/// into a skill id without having performed the ingest is unusable; see the M6
/// notes on what M5 needs.
fn hit_to_skill_id(
    doc_id: u64,
    corpus: &[(String, SkillDocument, Option<String>)],
) -> Option<String> {
    corpus.get(doc_id as usize).map(|(id, _, _)| id.clone())
}

fn search(
    base: &str,
    token: &str,
    query: &str,
    limit: usize,
    corpus: &[(String, SkillDocument, Option<String>)],
) -> Vec<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client");
    let body = serde_json::json!({
        "tenant_id": TENANT,
        "query": query,
        "limit": limit,
        "token_budget": 2000,
    });
    let response = client
        .post(format!("{base}/v1/query/text-search"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .expect("search request");
    let json: serde_json::Value = response.json().expect("search json");

    // `limit` is advisory on this build — it returns more than asked — so the
    // truncation to top-`limit` happens here rather than being trusted.
    json["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["doc_id"].as_u64())
                .filter_map(|id| hit_to_skill_id(id, corpus))
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "network: needs a reachable Crux daemon"]
fn skills_are_retrievable_from_corecrux() {
    let base = env("CRUX_HTTP_URL").expect("set CRUX_HTTP_URL");
    let token = env("CRUX_AGENT_TOKEN").expect("set CRUX_AGENT_TOKEN");

    let corpus = load_corpus();
    assert_eq!(corpus.len(), 32, "SKILLS-32 must have 32 skills");

    let set: QuerySet = serde_json::from_str(QUERIES).expect("query set parses");
    assert_eq!(
        set.corpus, CORPUS,
        "query set must name the corpus it was written for"
    );

    // Every expected skill must exist, or the query set silently measures nothing.
    let ids: BTreeMap<&str, ()> = corpus.iter().map(|(id, _, _)| (id.as_str(), ())).collect();
    for case in &set.queries {
        assert!(
            ids.contains_key(case.expect.as_str()),
            "query set expects {:?}, which is not in the corpus",
            case.expect
        );
    }

    // Ingest. Additive and tenant-isolated: a fresh tenant named for what it is.
    let payload = ingest_body(TENANT, CORPUS, &corpus);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .expect("client");
    let response = client
        .post(format!("{base}/v1/local/ingest"))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .expect("ingest request");
    let status = response.status();
    let text = response.text().unwrap_or_default();
    assert!(
        status.is_success(),
        "ingest failed: HTTP {status}: {}",
        text.chars().take(400).collect::<String>()
    );
    println!("ingested {} skills into {TENANT}/{CORPUS}", corpus.len());

    let mut hit_at_1 = 0usize;
    let mut hit_at_5 = 0usize;
    let mut misses = Vec::new();

    for case in &set.queries {
        let ranked = search(&base, &token, &case.q, 5, &corpus);
        let rank = ranked.iter().position(|id| id == &case.expect);
        match rank {
            Some(0) => {
                hit_at_1 += 1;
                hit_at_5 += 1;
            }
            Some(_) => hit_at_5 += 1,
            None => misses.push((case.q.as_str(), case.expect.as_str(), ranked)),
        }
    }

    let n = set.queries.len() as f64;
    let r1 = hit_at_1 as f64 / n;
    let r5 = hit_at_5 as f64 / n;

    println!(
        "\ncorpus={CORPUS} n={} R@1={r1:.3} R@5={r5:.3}",
        set.queries.len()
    );
    if !misses.is_empty() {
        println!("\nmisses ({}):", misses.len());
        for (q, expect, got) in &misses {
            println!("  {q:?}\n    expected {expect}, got {got:?}");
        }
    }

    assert!(r5 >= MIN_R_AT_5, "R@5 {r5:.3} below the {MIN_R_AT_5} bar");
    assert!(r1 >= MIN_R_AT_1, "R@1 {r1:.3} below the {MIN_R_AT_1} bar");
}
