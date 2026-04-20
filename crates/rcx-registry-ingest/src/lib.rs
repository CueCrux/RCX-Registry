//! MCP mirror and snapshot-ingestion helpers for RCX-Registry.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;

/// Minimal mirrored server record used for snapshot hashing in early milestones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredServer {
    pub name: String,
    pub canonical_json: String,
}

/// Compute a deterministic BLAKE3 root over lex-sorted mirrored entries.
pub fn snapshot_merkle_root(entries: &[MirroredServer]) -> [u8; 32] {
    let mut ordered: Vec<&MirroredServer> = entries.iter().collect();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));

    let mut hasher = Hasher::new();
    for entry in ordered {
        hasher.update(entry.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(entry.canonical_json.as_bytes());
        hasher.update(&[0xff]);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub unchanged: Vec<String>,
}

impl SnapshotDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified.is_empty()
            && self.unchanged.is_empty()
    }
}

/// Compare two mirrored snapshots by server name and canonical content hash.
pub fn reconcile_snapshots(
    previous: &[MirroredServer],
    current: &[MirroredServer],
) -> SnapshotDiff {
    let previous_by_name = by_name(previous);
    let current_by_name = by_name(current);

    let mut names = BTreeSet::new();
    names.extend(previous_by_name.keys().cloned());
    names.extend(current_by_name.keys().cloned());

    let mut diff = SnapshotDiff {
        added: Vec::new(),
        removed: Vec::new(),
        modified: Vec::new(),
        unchanged: Vec::new(),
    };

    for name in names {
        match (previous_by_name.get(&name), current_by_name.get(&name)) {
            (None, Some(_)) => diff.added.push(name),
            (Some(_), None) => diff.removed.push(name),
            (Some(previous), Some(current)) => {
                if canonical_server_hash(previous) == canonical_server_hash(current) {
                    diff.unchanged.push(name);
                } else {
                    diff.modified.push(name);
                }
            }
            (None, None) => {}
        }
    }

    diff
}

/// Compute the per-entry upstream hash used by reconciliation.
pub fn canonical_server_hash(entry: &MirroredServer) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(entry.name.as_bytes());
    hasher.update(&[0]);
    hasher.update(entry.canonical_json.as_bytes());
    *hasher.finalize().as_bytes()
}

fn by_name(entries: &[MirroredServer]) -> BTreeMap<String, &MirroredServer> {
    entries
        .iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{reconcile_snapshots, snapshot_merkle_root, MirroredServer};

    #[test]
    fn snapshot_root_is_order_independent() {
        let left = vec![
            MirroredServer {
                name: "io.github.example/beta".to_string(),
                canonical_json: "{\"name\":\"beta\"}".to_string(),
            },
            MirroredServer {
                name: "io.github.example/alpha".to_string(),
                canonical_json: "{\"name\":\"alpha\"}".to_string(),
            },
        ];
        let right = vec![left[1].clone(), left[0].clone()];

        assert_eq!(snapshot_merkle_root(&left), snapshot_merkle_root(&right));
    }

    #[test]
    fn reconcile_snapshots_covers_all_statuses() {
        let previous = vec![
            MirroredServer {
                name: "io.github.example/alpha".to_string(),
                canonical_json: "{\"name\":\"alpha\",\"version\":\"1.0.0\"}".to_string(),
            },
            MirroredServer {
                name: "io.github.example/beta".to_string(),
                canonical_json: "{\"name\":\"beta\",\"version\":\"1.0.0\"}".to_string(),
            },
            MirroredServer {
                name: "io.github.example/gamma".to_string(),
                canonical_json: "{\"name\":\"gamma\",\"version\":\"1.0.0\"}".to_string(),
            },
        ];
        let current = vec![
            MirroredServer {
                name: "io.github.example/alpha".to_string(),
                canonical_json: "{\"name\":\"alpha\",\"version\":\"1.0.0\"}".to_string(),
            },
            MirroredServer {
                name: "io.github.example/beta".to_string(),
                canonical_json: "{\"name\":\"beta\",\"version\":\"2.0.0\"}".to_string(),
            },
            MirroredServer {
                name: "io.github.example/delta".to_string(),
                canonical_json: "{\"name\":\"delta\",\"version\":\"1.0.0\"}".to_string(),
            },
        ];

        let diff = reconcile_snapshots(&previous, &current);

        assert_eq!(diff.added, vec!["io.github.example/delta".to_string()]);
        assert_eq!(diff.removed, vec!["io.github.example/gamma".to_string()]);
        assert_eq!(diff.modified, vec!["io.github.example/beta".to_string()]);
        assert_eq!(diff.unchanged, vec!["io.github.example/alpha".to_string()]);
        assert!(!diff.is_empty());
    }
}
