//! The detection-code catalog: the single authoritative, auditable index of
//! every finding code the tool can emit.
//!
//! Each code is defined exactly once. Pattern-based codes come from the rule
//! engine (`owner = "rules"`); analyzer-based codes are listed in
//! [`analyzer_codes`] (`owner = <analyzer name>`); community codes loaded from
//! user rule directories get `owner = "user"`. [`Catalog::validate`] enforces
//! that every ID is unique, so the index can never silently develop a
//! collision, and the `codes`/`explain` commands and the docs are all
//! generated from it -- they cannot drift from what the tool actually emits.

use crate::rules::{get_builtin_rules, user_rule_dirs, Rule, RuleLoader};
use crate::types::{Category, Severity};
use serde::Serialize;

/// One entry in the catalog: the canonical definition of a finding code.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntry {
    /// Unique identifier (e.g. "DLE-001", "EXEC-REMOTE").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Severity.
    pub severity: Severity,
    /// Category.
    pub category: Category,
    /// Description.
    pub description: String,
    /// Remediation guidance.
    pub recommendation: String,
    /// CWE identifier, if any.
    pub cwe: Option<String>,
    /// Detecting subsystem: "rules", an analyzer name, or "user".
    pub owner: String,
    /// Whether this code is matched by a regex pattern (vs analyzer logic).
    pub pattern_based: bool,
}

impl CatalogEntry {
    fn from_rule(rule: &Rule, owner: &str) -> Self {
        CatalogEntry {
            id: rule.id.clone(),
            name: rule.name.clone(),
            severity: rule.severity,
            category: rule.category.clone(),
            description: rule.description.clone(),
            recommendation: rule.recommendation.clone(),
            cwe: rule.cwe_id.clone(),
            owner: owner.to_string(),
            pattern_based: !rule.patterns.is_empty(),
        }
    }
}

/// The loaded catalog.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Catalog {
    /// All entries, sorted by id.
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    /// Build the catalog from built-in pattern rules, analyzer codes, and any
    /// community rule files found in the standard directories.
    pub fn load() -> Self {
        let mut entries: Vec<CatalogEntry> = Vec::new();

        // 1. Built-in pattern rules.
        for rule in get_builtin_rules() {
            entries.push(CatalogEntry::from_rule(&rule, "rules"));
        }
        // 2. Analyzer-owned codes (logic in Rust, metadata here).
        entries.extend(analyzer_codes());
        // 3. Community rule files.
        let loader = RuleLoader::new();
        for dir in user_rule_dirs() {
            if dir.is_dir() {
                if let Ok(rules) = loader.load_from_directory(&dir) {
                    for rule in rules {
                        entries.push(CatalogEntry::from_rule(&rule, "user"));
                    }
                }
            }
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Catalog { entries }
    }

    /// Return the IDs that appear more than once (must be empty for a valid
    /// catalog). This is the auditable uniqueness guarantee.
    pub fn duplicate_ids(&self) -> Vec<String> {
        let mut seen = std::collections::HashMap::new();
        for e in &self.entries {
            *seen.entry(e.id.clone()).or_insert(0usize) += 1;
        }
        let mut dups: Vec<String> = seen.into_iter().filter(|(_, n)| *n > 1).map(|(k, _)| k).collect();
        dups.sort();
        dups
    }

    /// Validate the catalog: error if any ID is duplicated.
    pub fn validate(&self) -> Result<(), String> {
        let dups = self.duplicate_ids();
        if dups.is_empty() {
            Ok(())
        } else {
            Err(format!("duplicate finding IDs in catalog: {}", dups.join(", ")))
        }
    }

    /// Look up an entry by exact ID.
    pub fn get(&self, id: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// All distinct category display names present, sorted.
    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self.entries.iter().map(|e| e.category.to_string()).collect();
        cats.sort();
        cats.dedup();
        cats
    }
}

/// The authoritative list of analyzer-owned codes. This is the ONE place these
/// codes' metadata lives; the analyzers emit the matching IDs and an audit test
/// (`tests`) asserts the two stay in sync.
pub fn analyzer_codes() -> Vec<CatalogEntry> {
    #[allow(clippy::too_many_arguments)]
    fn e(
        id: &str,
        name: &str,
        sev: Severity,
        cat: Category,
        owner: &str,
        cwe: Option<&str>,
        desc: &str,
        rec: &str,
    ) -> CatalogEntry {
        CatalogEntry {
            id: id.into(),
            name: name.into(),
            severity: sev,
            category: cat,
            description: desc.into(),
            recommendation: rec.into(),
            cwe: cwe.map(String::from),
            owner: owner.into(),
            pattern_based: false,
        }
    }
    use Category::*;
    use Severity::*;
    vec![
        // -- checksum analyzer --
        e("CHK-001", "No checksums for sources", High, Cryptography, "checksum", Some("CWE-354"),
          "Package sources have no checksum verification.", "Provide sha256sums or stronger for every source."),
        e("CHK-002", "MD5 checksums used", Medium, Cryptography, "checksum", Some("CWE-328"),
          "MD5 is cryptographically broken.", "Replace md5sums with sha256sums or sha512sums."),
        e("CHK-003", "SHA1 checksums used", Medium, Cryptography, "checksum", Some("CWE-328"),
          "SHA1 is cryptographically weak.", "Replace sha1sums with sha256sums or sha512sums."),
        e("CHK-004", "Some sources use SKIP checksum", Medium, Cryptography, "checksum", Some("CWE-354"),
          "Some non-VCS sources skip integrity verification.", "Provide real checksums for non-VCS sources."),
        e("CHK-005", "All non-VCS sources use SKIP", High, Cryptography, "checksum", Some("CWE-354"),
          "No integrity verification is performed on any non-VCS source.", "Provide real checksums for non-VCS sources."),
        e("CHK-006", "Checksum count mismatch", High, Configuration, "checksum", None,
          "The number of checksums does not match the number of sources.", "Align the checksum array with the source array."),
        // -- privilege analyzer --
        e("PRIV-001", "Sudo usage in a build function", Critical, PrivilegeEscalation, "privilege", Some("CWE-250"),
          "A PKGBUILD function uses sudo, which is never needed during a build.", "Remove sudo; makepkg handles permissions."),
        e("PRIV-002", "SUID/SGID bit set in a function", Critical, PrivilegeEscalation, "privilege", Some("CWE-732"),
          "A function sets SUID/SGID bits, which can enable privilege escalation.", "Avoid SUID; use capabilities or polkit."),
        e("PRIV-003", "Sudoers modification", Critical, PrivilegeEscalation, "privilege", Some("CWE-250"),
          "A function modifies sudoers.", "Packages must never modify sudoers."),
        e("PRIV-004", "Capabilities being set", Medium, PrivilegeEscalation, "privilege", Some("CWE-250"),
          "A function sets file capabilities, granting elevated privileges.", "Verify capabilities are necessary and minimal."),
        e("PRIV-005", "Kernel module operations", High, PrivilegeEscalation, "privilege", None,
          "A function performs kernel module operations (insmod/modprobe).", "Kernel module handling in a package is suspicious."),
        e("PRIV-006", "Sudo in an install hook", High, PrivilegeEscalation, "privilege", Some("CWE-250"),
          "An install scriptlet uses sudo.", "Install hooks must not require sudo."),
        // -- source analyzer --
        e("SRC-001", "Insecure source/transport protocol", Medium, NetworkSecurity, "source", Some("CWE-319"),
          "A source uses an insecure transport (http://, ftp://, git://, git+http://), tamperable in transit.", "Use https/git+https from a trusted host."),
        e("SRC-002", "Suspicious source domain", High, NetworkSecurity, "source", None,
          "A source is hosted on a paste/anonymous-file/free-TLD domain.", "Use the project's official repository."),
        e("SRC-003", "Raw IP address in source URL", High, NetworkSecurity, "source", None,
          "A source URL uses a raw IP address instead of a domain.", "Use domain names from trusted sources."),
        e("SRC-004", "URL shortener in source", High, NetworkSecurity, "source", None,
          "A source uses a URL shortener that hides the real destination.", "Use full URLs to official sources."),
        e("SRC-005", "No sources with a build function", Medium, Configuration, "source", None,
          "Package defines build() but has no source array.", "Verify this is intentional."),
        e("SRC-006", "VCS source from non-standard host", Low, NetworkSecurity, "source", None,
          "A git/VCS checkout is from a host outside the common providers.", "Verify the upstream host is official."),
        e("SRC-007", "VCS source not pinned to a commit", Low, NetworkSecurity, "source", Some("CWE-494"),
          "A git/VCS source uses a movable ref (branch/tag or none), so the fetched content is not integrity-pinned and can change between scan and build.", "Pin the VCS source to an immutable revision with #commit=<sha>."),
        // -- ioc analyzer --
        e("IOC-001", "Known indicator-of-compromise match", Critical, MaliciousCode, "ioc", Some("CWE-506"),
          "Content matches a known IOC (malicious npm/bun package, file artifact, or C2 domain).", "Do not build; treat the host as compromised if already built."),
        // -- deep analyzer --
        e("DEEP-001", "Decode-and-execute flow", Critical, Obfuscation, "deep", Some("CWE-506"),
          "The file decodes/decompresses data and dynamically executes shell input, possibly across lines.", "Decode and review the payload manually."),
        e("DEEP-002", "Large embedded encoded blob", High, Obfuscation, "deep", Some("CWE-506"),
          "A large base64-like blob is embedded in the package.", "Decode and verify the blob is legitimate data."),
        // -- remote_exec analyzer --
        e("EXEC-REMOTE", "Fetches and runs external code", Critical, MaliciousCode, "remote_exec", Some("CWE-494"),
          "The package downloads and executes code from an external URL at build/install time; the scanner does not follow it (opaque boundary).", "Do not build; obtain software that ships its real code."),
        // -- provenance --
        e("PROV-001", "Package gained risky behavior", High, SuspiciousMetadata, "provenance", Some("CWE-506"),
          "The package introduced fetch/execute behavior it did not have at the previous scan.", "Review the PKGBUILD/install diff before building."),
        // -- pattern analyzer (function body) --
        e("FUNC-001", "Network access in a build function", High, NetworkSecurity, "pattern", None,
          "A build/package function performs network access (curl/wget/fetch); downloads belong in the source array.", "Move downloads to the source= array."),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_no_duplicate_ids() {
        let catalog = Catalog::load();
        assert_eq!(catalog.validate(), Ok(()), "catalog must have unique IDs");
        assert!(catalog.entries.len() > 50);
    }

    #[test]
    fn analyzer_codes_are_unique_among_themselves() {
        let codes = analyzer_codes();
        let mut ids: Vec<&str> = codes.iter().map(|c| c.id.as_str()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "analyzer_codes has duplicate IDs");
    }

    /// Audit guard: the complete set of analyzer-emitted IDs. If an analyzer
    /// starts emitting a new ID (or stops), update this list AND the catalog so
    /// the index stays 100% complete. Keeps docs honest.
    #[test]
    fn catalog_covers_every_analyzer_emitted_id() {
        const EMITTED: &[&str] = &[
            "CHK-001", "CHK-002", "CHK-003", "CHK-004", "CHK-005", "CHK-006",
            "PRIV-001", "PRIV-002", "PRIV-003", "PRIV-004", "PRIV-005", "PRIV-006",
            "SRC-001", "SRC-002", "SRC-003", "SRC-004", "SRC-005", "SRC-006", "SRC-007",
            "IOC-001", "DEEP-001", "DEEP-002", "EXEC-REMOTE", "PROV-001", "FUNC-001",
        ];
        let catalog = Catalog::load();
        for id in EMITTED {
            assert!(catalog.get(id).is_some(), "emitted code {id} missing from catalog");
        }
        // And no phantom analyzer codes (every analyzer_codes id is in EMITTED).
        for c in analyzer_codes() {
            assert!(EMITTED.contains(&c.id.as_str()), "catalog has phantom analyzer code {}", c.id);
        }
    }
}
