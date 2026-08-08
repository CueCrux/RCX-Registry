//! `SKILL.md` — YAML frontmatter followed by the instruction body.
//!
//! Per the [Agent Skills](https://agentskills.io) format, `name` and `description`
//! are the only required keys; everything else is optional and varies by publisher.
//! Unknown keys are preserved in [`SkillFrontMatter::extra`] rather than dropped,
//! because ingest must not be lossy: a field this crate does not understand today
//! is still part of the bytes the lockfile hashes.
//!
//! Progressive disclosure — the reason `description` is load-bearing — means agents
//! see only name + description at discovery time and load the body on match. A
//! description that does not say when to use the skill makes it unreachable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::SkillsError;

const FENCE: &str = "---";

/// Frontmatter of a `SKILL.md`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillFrontMatter {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Every key this crate does not model. Preserved so a re-serialised skill is
    /// still the publisher's skill.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

/// A parsed `SKILL.md`: its frontmatter and the instruction body beneath it.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillDocument {
    pub front_matter: SkillFrontMatter,
    pub body: String,
}

impl SkillDocument {
    /// Parse a `SKILL.md`.
    ///
    /// A leading UTF-8 BOM is stripped and CRLF is accepted — both turn up in
    /// skills authored on Windows, and a BOM would otherwise push the opening fence
    /// off byte zero and read as "no frontmatter".
    pub fn parse(raw: &str) -> Result<Self, SkillsError> {
        let text = raw
            .strip_prefix('\u{feff}')
            .unwrap_or(raw)
            .replace("\r\n", "\n");
        let rest = text
            .strip_prefix(&format!("{FENCE}\n"))
            .ok_or(SkillsError::MalformedFrontMatter)?;

        // The closing fence is a `---` alone on its line. Searching for "\n---\n"
        // would miss a file whose frontmatter ends at EOF with no trailing newline.
        let (yaml, body) = split_at_closing_fence(rest).ok_or(SkillsError::MalformedFrontMatter)?;

        Ok(Self {
            front_matter: serde_yaml::from_str(yaml)?,
            body: body.trim_start_matches('\n').to_string(),
        })
    }

    /// Description as agents see it at discovery time.
    ///
    /// Claude Code truncates each description to 250 characters in its skill index
    /// and caps the whole index at 1% of the context window, so a long description
    /// does not merely get cut — it crowds out other skills' descriptions too.
    pub fn discovery_description(&self, limit: usize) -> &str {
        let d = &self.front_matter.description;
        match d.char_indices().nth(limit) {
            Some((byte_idx, _)) => &d[..byte_idx],
            None => d,
        }
    }
}

/// Split frontmatter from body at the first line that is exactly `---`.
fn split_at_closing_fence(rest: &str) -> Option<(&str, &str)> {
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        if line.trim_end_matches('\n') == FENCE {
            return Some((&rest[..offset], &rest[offset + line.len()..]));
        }
        offset += line.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "---\nname: ab-testing\ndescription: \"Run an A/B test: design, size, read out.\"\nversion: \"1.2\"\ntags:\n  - growth\n---\n\n# A/B testing\n\nBody here.\n";

    #[test]
    fn parses_frontmatter_and_body() {
        let d = SkillDocument::parse(DOC).expect("parses");
        assert_eq!(d.front_matter.name, "ab-testing");
        assert_eq!(d.front_matter.version.as_deref(), Some("1.2"));
        assert!(d.front_matter.description.contains("A/B test"));
        assert!(d.body.starts_with("# A/B testing"));
    }

    #[test]
    fn preserves_unmodelled_keys() {
        let d = SkillDocument::parse(DOC).expect("parses");
        assert!(
            d.front_matter.extra.contains_key("tags"),
            "tags must survive ingest"
        );
    }

    #[test]
    fn accepts_bom_and_crlf() {
        let windows = format!("\u{feff}{}", DOC.replace('\n', "\r\n"));
        let d = SkillDocument::parse(&windows).expect("parses");
        assert_eq!(d.front_matter.name, "ab-testing");
    }

    #[test]
    fn frontmatter_ending_at_eof_still_parses() {
        let d = SkillDocument::parse("---\nname: n\ndescription: d\n---").expect("parses");
        assert_eq!(d.front_matter.name, "n");
        assert_eq!(d.body, "");
    }

    #[test]
    fn rejects_missing_and_unterminated_frontmatter() {
        assert!(matches!(
            SkillDocument::parse("# no frontmatter\n"),
            Err(SkillsError::MalformedFrontMatter)
        ));
        assert!(matches!(
            SkillDocument::parse("---\nname: n\ndescription: d\n"),
            Err(SkillsError::MalformedFrontMatter)
        ));
    }

    #[test]
    fn discovery_description_truncates_on_char_boundaries() {
        let raw = "---\nname: n\ndescription: \"ünïcödé description that runs long\"\n---\nbody\n";
        let d = SkillDocument::parse(raw).expect("parses");
        // Would panic on a byte slice through a multi-byte char.
        assert_eq!(d.discovery_description(5).chars().count(), 5);
        assert_eq!(d.discovery_description(10_000), d.front_matter.description);
    }
}
