//! Projecting skills into a CoreCrux tenant for retrieval.
//!
//! Replaces the reference implementation's Qdrant + Cloudflare-Workers-AI stack
//! with the retrieval spine the platform already runs — BM25 today, fused with
//! dense once a caller supplies vectors (`dense_vector` on a chunk). Two upstream
//! limitations go away with it: a pinned embedding model that only its vendor can
//! keep alive, and a second datastore to operate.
//!
//! ## Only frontmatter is indexed
//!
//! Upstream states this as a non-negotiable invariant and it is preserved here.
//! The reason is not storage: an agent picks a skill from `name` + `description`
//! alone (progressive disclosure), so indexing bodies would rank on text the agent
//! never sees at decision time — a query could match a skill through a paragraph
//! buried in its instructions and score above the skill whose *description*
//! actually answers it. [`indexed_text`] is the whole surface, and
//! `body_is_never_indexed` guards it.

use serde::{Deserialize, Serialize};

use crate::skill::SkillDocument;

/// A `POST /v1/local/ingest` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestBody {
    pub tenant_id: String,
    pub corpus_id: String,
    pub documents: Vec<IngestDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestDocument {
    pub doc_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The skill's `skill://` URI, so a retrieval hit carries an address that can
    /// be resolved and verified rather than just a name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub chunks: Vec<IngestChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestChunk {
    pub chunk_id: String,
    pub text: String,
    pub chunk_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// The text a skill is retrievable by: name, description, and tags.
///
/// Exactly the fields an agent sees before it decides to load a skill. Tags are
/// included because they carry vocabulary a description often omits ("bugs",
/// "security") without adding prose the agent will not see.
pub fn indexed_text(doc: &SkillDocument) -> String {
    let fm = &doc.front_matter;
    let mut text = format!("{}\n{}", fm.name, fm.description);
    for tag in tags_of(doc) {
        text.push(' ');
        text.push_str(&tag);
    }
    text
}

/// Tags from `metadata.tags`, which is where the Agent Skills corpora in the wild
/// put them. Absent or malformed metadata yields none rather than an error — a
/// skill without tags is still perfectly indexable.
fn tags_of(doc: &SkillDocument) -> Vec<String> {
    doc.front_matter
        .extra
        .get("metadata")
        .and_then(|m| m.get("tags"))
        .and_then(|t| t.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Build an ingest payload for a set of `(skill_id, document, uri)` triples.
///
/// One chunk per skill: the indexed surface is a couple of hundred characters, so
/// splitting it would only dilute the term statistics that make BM25 work.
pub fn ingest_body(
    tenant_id: &str,
    corpus_id: &str,
    skills: &[(String, SkillDocument, Option<String>)],
) -> IngestBody {
    let documents = skills
        .iter()
        .map(|(id, doc, uri)| IngestDocument {
            doc_id: id.clone(),
            title: Some(doc.front_matter.name.clone()),
            url: uri.clone(),
            chunks: vec![IngestChunk {
                chunk_id: format!("{id}#frontmatter"),
                text: indexed_text(doc),
                chunk_index: 0,
                metadata: Some(serde_json::json!({
                    "skill_id": id,
                    "license": doc.front_matter.license,
                    "tags": tags_of(doc),
                })),
            }],
        })
        .collect();

    IngestBody {
        tenant_id: tenant_id.to_string(),
        corpus_id: corpus_id.to_string(),
        documents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `premergesentinel` is a tag and appears in no other field, so an assertion on
    // it proves tags reached the index. Asserting on a word the description already
    // contains would pass even with tag extraction removed entirely — cargo-mutants
    // caught exactly that.
    const DOC: &str = "---\nname: code-review\ndescription: \"Review code for correctness, bugs and security.\"\nlicense: Apache-2.0\nmetadata:\n  author: anthropics\n  tags:\n    - code-review\n    - premergesentinel\n---\n\n# Body\n\nThis paragraph mentions kubernetes, which appears nowhere in the frontmatter.\n";

    fn doc() -> SkillDocument {
        SkillDocument::parse(DOC).expect("parses")
    }

    #[test]
    fn indexed_text_carries_name_description_and_tags() {
        let text = indexed_text(&doc());
        assert!(text.contains("code-review"));
        assert!(text.contains("Review code for correctness"));
        assert!(
            text.contains("premergesentinel"),
            "tags must reach the index; this term exists in no other field: {text}"
        );
    }

    #[test]
    fn body_is_never_indexed() {
        // The invariant. A term that appears only in the instructions must not be
        // retrievable, or a skill can win a query through text the agent never
        // sees when it chooses.
        let text = indexed_text(&doc());
        assert!(
            !text.contains("kubernetes"),
            "body text leaked into the index: {text}"
        );
        let body = ingest_body("t", "c", &[("code-review".into(), doc(), None)]);
        let serialised = serde_json::to_string(&body).expect("serialises");
        assert!(
            !serialised.contains("kubernetes"),
            "body leaked into the payload"
        );
    }

    #[test]
    fn a_skill_without_tags_still_indexes() {
        let plain =
            SkillDocument::parse("---\nname: n\ndescription: d\n---\nbody\n").expect("parses");
        assert_eq!(indexed_text(&plain), "n\nd");
    }

    #[test]
    fn ingest_body_shapes_one_chunk_per_skill() {
        let body = ingest_body(
            "skills-eval",
            "SKILLS-32",
            &[(
                "code-review".into(),
                doc(),
                Some("skill://registry.rcxprotocol.org/code-review".into()),
            )],
        );
        assert_eq!(body.tenant_id, "skills-eval");
        assert_eq!(body.corpus_id, "SKILLS-32");
        assert_eq!(body.documents.len(), 1);
        let d = &body.documents[0];
        assert_eq!(d.doc_id, "code-review");
        assert_eq!(d.chunks.len(), 1, "one chunk keeps BM25 term stats intact");
        assert_eq!(d.chunks[0].chunk_id, "code-review#frontmatter");
        // Tags survive into chunk metadata too, not only the indexed text.
        let meta = d.chunks[0].metadata.as_ref().expect("metadata");
        assert!(
            meta["tags"]
                .as_array()
                .expect("tags array")
                .iter()
                .any(|t| t == "premergesentinel"),
            "tags must reach chunk metadata: {meta}"
        );
        assert!(d.url.as_deref().unwrap().starts_with("skill://"));
    }
}
