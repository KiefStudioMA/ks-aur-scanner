//! Provenance tracking: detect a package *gaining* risky behavior over time.
//!
//! The Atomic Arch hijacks were spotted because a package that never used Node
//! suddenly shelled out to `npm`/`bun`. Heuristic rules see each scan in
//! isolation; provenance compares the current PKGBUILD/install content against
//! the last time this package was seen and flags newly-introduced risk markers.
//!
//! State is a small JSON store keyed by package name. The first sighting of a
//! package establishes a baseline (no finding); subsequent additions are flagged.

use crate::types::{Category, Finding, Location, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A coarse risk marker: an id/label and the lowercase substrings that signal it.
struct Marker {
    id: &'static str,
    label: &'static str,
    needles: &'static [&'static str],
}

/// Behaviours whose *introduction* on an update is noteworthy. Deliberately
/// coarse: a legitimate package newly pulling npm is itself worth a heads-up.
const MARKERS: &[Marker] = &[
    Marker {
        id: "npm",
        label: "npm package install",
        needles: &["npm install", "npm i ", "npm ci"],
    },
    Marker {
        id: "pnpm",
        label: "pnpm install",
        needles: &["pnpm install", "pnpm add"],
    },
    Marker {
        id: "yarn",
        label: "yarn install",
        needles: &["yarn add", "yarn install"],
    },
    Marker {
        id: "bun",
        label: "bun install",
        needles: &["bun install", "bun add", "bunx"],
    },
    Marker {
        id: "pipe-shell",
        label: "pipe to shell",
        needles: &["| sh", "|sh", "| bash", "|bash"],
    },
    Marker {
        id: "eval",
        label: "eval",
        needles: &["eval "],
    },
    Marker {
        id: "base64-decode",
        label: "base64 decode",
        needles: &["base64 -d", "base64 --decode"],
    },
    Marker {
        id: "reverse-shell",
        label: "raw TCP socket",
        needles: &["/dev/tcp/"],
    },
    Marker {
        id: "ebpf",
        label: "eBPF object",
        needles: &[".bpf.c", ".bpf.o"],
    },
    Marker {
        id: "curl-net",
        label: "curl/wget fetch",
        needles: &["curl ", "wget "],
    },
];

/// One package's last-seen fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Snapshot {
    content_sha256: String,
    /// Marker ids present at last sighting (sorted, unique).
    markers: Vec<String>,
    last_seen: String,
}

/// Persistent provenance store.
#[derive(Debug)]
pub struct ProvenanceStore {
    path: PathBuf,
    snapshots: HashMap<String, Snapshot>,
    dirty: bool,
}

impl ProvenanceStore {
    /// Default on-disk location: `$XDG_CACHE_HOME/aur-scanner/provenance.json`.
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("aur-scanner/provenance.json")
    }

    /// Load the store from `path`.
    ///
    /// A *missing* file is a legitimate first run and yields an empty baseline.
    /// A *present but unparseable* file is different: silently resetting it would
    /// erase every package's baseline (disabling the "gained risky behavior"
    /// detection that PROV-001 depends on) and could hide tampering. So we warn
    /// loudly and move the unreadable file aside to `*.corrupt` rather than
    /// overwriting it, then start fresh.
    pub fn load(path: PathBuf) -> Self {
        let snapshots = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(s) => s,
                Err(e) => {
                    let backup = path.with_extension("json.corrupt");
                    tracing::warn!(
                        "provenance store at {} is unreadable ({e}); moving it to {} and \
                         starting a fresh baseline. Behavior-change detection is degraded until \
                         packages are re-seen.",
                        path.display(),
                        backup.display()
                    );
                    let _ = std::fs::rename(&path, &backup);
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Self {
            path,
            snapshots,
            dirty: false,
        }
    }

    /// Compute the marker ids present in `content`.
    fn markers_in(content: &str) -> Vec<String> {
        let lc = content.to_lowercase();
        let mut found: Vec<String> = MARKERS
            .iter()
            .filter(|m| m.needles.iter().any(|n| lc.contains(n)))
            .map(|m| m.id.to_string())
            .collect();
        found.sort();
        found.dedup();
        found
    }

    fn label_for(id: &str) -> &'static str {
        MARKERS
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.label)
            .unwrap_or("risky behavior")
    }

    /// Evaluate a package's current content against its last-seen snapshot,
    /// returning findings for newly-introduced risk markers, and record the
    /// new baseline. `now` is an RFC3339 timestamp supplied by the caller.
    pub fn evaluate(
        &mut self,
        package: &str,
        content: &str,
        now: &str,
        file: &Path,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let current_markers = Self::markers_in(content);
        let sha = sha256_hex(content);

        if let Some(prev) = self.snapshots.get(package) {
            let added: Vec<&String> = current_markers
                .iter()
                .filter(|m| !prev.markers.contains(m))
                .collect();
            if !added.is_empty() {
                let labels: Vec<&str> = added.iter().map(|id| Self::label_for(id)).collect();
                findings.push(Finding {
                    id: "PROV-001".to_string(),
                    severity: Severity::High,
                    category: Category::SuspiciousMetadata,
                    title: format!(
                        "Package gained risky behavior since last scan: {}",
                        labels.join(", ")
                    ),
                    description: format!(
                        "'{}' introduced behavior it did not have at the previous scan ({}). \
                         A package suddenly fetching/executing code on update is the primary \
                         tell of an AUR hijack.",
                        package,
                        labels.join(", ")
                    ),
                    location: Location {
                        file: file.to_path_buf(),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    recommendation:
                        "Review the PKGBUILD/install diff before building. If the new behavior \
                         is unexplained, do not build and report the package."
                            .to_string(),
                    cwe_id: Some("CWE-506".to_string()),
                    metadata: serde_json::json!({
                        "added_markers": added,
                        "previous_seen": prev.last_seen,
                    }),
                });
            }
        }

        let changed = self
            .snapshots
            .get(package)
            .map(|s| s.content_sha256 != sha)
            .unwrap_or(true);
        if changed {
            self.snapshots.insert(
                package.to_string(),
                Snapshot {
                    content_sha256: sha,
                    markers: current_markers,
                    last_seen: now.to_string(),
                },
            );
            self.dirty = true;
        }

        findings
    }

    /// Persist the store if modified. Creates parent directories as needed.
    pub fn save(&self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.snapshots).map_err(std::io::Error::other)?;
        // Atomic replace: write to a sibling temp file then rename over the
        // target, so a crash mid-write cannot truncate the baseline into the
        // "corrupt" state handled by `load`.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Number of tracked packages.
    pub fn tracked(&self) -> usize {
        self.snapshots.len()
    }
}

fn sha256_hex(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ProvenanceStore {
        ProvenanceStore {
            path: PathBuf::from("/dev/null"),
            snapshots: HashMap::new(),
            dirty: false,
        }
    }

    #[test]
    fn first_sighting_is_baseline_no_finding() {
        let mut s = store();
        let f = s.evaluate(
            "pkg",
            "build() { make }",
            "2026-06-13T00:00:00Z",
            Path::new("PKGBUILD"),
        );
        assert!(f.is_empty());
        assert_eq!(s.tracked(), 1);
    }

    #[test]
    fn flags_newly_added_npm() {
        let mut s = store();
        s.evaluate("pkg", "build() { make }", "t0", Path::new("PKGBUILD"));
        let f = s.evaluate(
            "pkg",
            "build() { make }\npost_install() { npm install atomic-lockfile }",
            "t1",
            Path::new("PKGBUILD"),
        );
        assert!(f.iter().any(|x| x.id == "PROV-001"));
    }

    #[test]
    fn no_finding_when_behavior_unchanged() {
        let mut s = store();
        let c = "build() { make }\npost_install() { npm install foo }";
        s.evaluate("pkg", c, "t0", Path::new("PKGBUILD"));
        let f = s.evaluate("pkg", c, "t1", Path::new("PKGBUILD"));
        assert!(f.is_empty());
    }

    #[test]
    fn preexisting_behavior_not_flagged_on_first_sight() {
        // A package that already had npm at first sight must not be flagged
        // (provenance only flags *additions*, not steady state).
        let mut s = store();
        let f = s.evaluate("pkg", "npm install foo", "t0", Path::new("PKGBUILD"));
        assert!(f.is_empty());
    }

    #[test]
    fn corrupt_store_is_moved_aside_not_silently_reset() {
        // ME-3: a present-but-unreadable store must not be silently overwritten.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provenance.json");
        std::fs::write(&path, "{ this is not valid json ]").unwrap();
        let store = ProvenanceStore::load(path.clone());
        assert_eq!(store.tracked(), 0, "corrupt file yields a fresh baseline");
        assert!(
            path.with_extension("json.corrupt").exists(),
            "the unreadable file must be preserved as .corrupt, not destroyed"
        );
    }

    #[test]
    fn config_loads_from_toml_or_defaults() {
        use crate::ScanConfig;
        // Missing file -> defaults.
        let cfg =
            ScanConfig::from_toml_file_or_default(Path::new("/nonexistent/aur.toml")).unwrap();
        assert_eq!(cfg.timeout_seconds, 30);
    }
}
