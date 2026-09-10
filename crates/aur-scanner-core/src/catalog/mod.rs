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
        Self::load_with(&[])
    }

    /// Like [`load`](Self::load) but also scans `extra_dirs` (e.g. a config's
    /// `rules_path`) so the listing matches what the scan engine actually loads.
    pub fn load_with(extra_dirs: &[std::path::PathBuf]) -> Self {
        let mut entries: Vec<CatalogEntry> = Vec::new();

        // 1. Built-in pattern rules.
        for rule in get_builtin_rules() {
            entries.push(CatalogEntry::from_rule(&rule, "rules"));
        }
        // 2. Analyzer-owned codes (logic in Rust, metadata here).
        entries.extend(analyzer_codes());
        // 3. Community rule files (standard dirs + any caller-supplied extras).
        let loader = RuleLoader::new();
        for dir in user_rule_dirs()
            .into_iter()
            .chain(extra_dirs.iter().cloned())
        {
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
        let mut dups: Vec<String> = seen
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(k, _)| k)
            .collect();
        dups.sort();
        dups
    }

    /// Validate the catalog: error if any ID is duplicated.
    pub fn validate(&self) -> Result<(), String> {
        let dups = self.duplicate_ids();
        if dups.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "duplicate finding IDs in catalog: {}",
                dups.join(", ")
            ))
        }
    }

    /// Look up an entry by exact ID.
    pub fn get(&self, id: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// All distinct category display names present, sorted.
    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.category.to_string())
            .collect();
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
        // -- threat_intel analyzer (opt-in, networked) --
        e("TI-VT-001", "VirusTotal flags a source artifact", Critical, MaliciousCode, "threat_intel", Some("CWE-506"),
          "An opt-in VirusTotal lookup reports engines detecting the declared sha256 of a source artifact as malicious.", "Do not build or install; review the VirusTotal report for this hash."),
        e("TI-URLHAUS-001", "URLhaus lists a source URL", Critical, MaliciousCode, "threat_intel", Some("CWE-494"),
          "An opt-in abuse.ch/URLhaus lookup lists a source= URL as a known malware/payload distribution URL.", "Do not build or install; the source URL is a known-bad distribution point."),
        // -- provenance --
        e("PROV-001", "Package gained risky behavior", High, SuspiciousMetadata, "provenance", Some("CWE-506"),
          "The package introduced fetch/execute behavior it did not have at the previous scan.", "Review the PKGBUILD/install diff before building."),
        // -- pattern analyzer (function body) --
        e("FUNC-001", "Network access in a build function", High, NetworkSecurity, "pattern", None,
          "A build/package function performs network access (curl/wget/fetch); downloads belong in the source array.", "Move downloads to the source= array."),
        // -- metadata analyzer (parsed packaging fields) --
        e("META-002", "validpgpkeys declared but no signature verified", Low, SuspiciousMetadata, "metadata", Some("CWE-347"),
          "validpgpkeys= lists signing keys but no source carries a detached signature or ?signed fragment, so the key verifies nothing.", "Verify a signed source against the key, or remove the unused validpgpkeys."),
        e("META-003", "Replaces/conflicts a core or security package", High, SuspiciousMetadata, "metadata", Some("CWE-1357"),
          "replaces=/conflicts= forces pacman to displace an official (often security-critical) package with this AUR build.", "Remove unless this is the legitimate provider; report to the AUR maintainers."),
        e("META-004", "epoch set (forces upgrade over the repo version)", Low, SuspiciousMetadata, "metadata", None,
          "epoch>=1 makes the package outrank the official version regardless of pkgver; escalates when combined with provides/replaces of a trusted name.", "Confirm the epoch is a real upstream versioning reset, not a stealth supersede."),
        e("META-005", "install= points outside the package", Medium, SuspiciousMetadata, "metadata", Some("CWE-426"),
          "install= is not a plain <name>.install file (contains a path, .., or non-.install name).", "Use a plain <pkgname>.install shipped with the PKGBUILD."),
        e("META-006", "backup= of a security-sensitive file", Medium, SuspiciousMetadata, "metadata", Some("CWE-426"),
          "backup= lists a security-sensitive path (sudoers/ssh/pam.d/ld.so/etc.), a persistent root-level tamper surface.", "Packages should not own/back up authentication, linker, or privilege files."),
        e("DEP-001", "Provides a core package name (dependency confusion)", High, SuspiciousMetadata, "metadata", Some("CWE-427"),
          "provides= a curated core package name from a package that is not that package's own alternate, satisfying a dependency in its place.", "Remove the provides unless this is the legitimate provider."),
        e("DEEP-003", "Unicode bidirectional control characters", Critical, Obfuscation, "deep", Some("CWE-94"),
          "Bidi control characters reorder how text DISPLAYS without changing what executes, so a reviewer can read different code than makepkg runs (Trojan Source, CVE-2021-42574). Shell source has no legitimate use for an explicit directional override.", "Strip the bidi characters and re-read the file before trusting any review of it."),
        e("SRC-010", "Source is a different owner's copy of the upstream repo", High, NetworkSecurity, "source", Some("CWE-494"),
          "url= names one owner/repo on a forge while a source= fetches the SAME repository name under a different account -- the shape of a fork substituted for the real project, reported in the openconnect-sso case (issue #29).", "Confirm the source account is an official mirror of the declared upstream."),
        // -- binary analyzer (prebuilt artifacts in the package directory) --
        e("BIN-001", "Prebuilt binary committed in the package directory", High, SuspiciousMetadata, "binary", Some("CWE-494"),
          "An executable ships inside the package directory rather than being fetched from a declared source. An AUR repository holds a build recipe; a compiled artifact in it has no upstream anyone can review. High when nothing in the PKGBUILD references it, Medium when package() installs it.", "Confirm why a compiled artifact ships with the build recipe, and where it came from."),
        e("BIN-002", "Prebuilt binary executed during the build", Critical, MaliciousCode, "binary", Some("CWE-506"),
          "A build function runs an executable that was committed alongside the PKGBUILD. Building should compile source, not run an opaque binary that arrived with the recipe -- the shape reported in issue #29 (openconnect-sso).", "Do not build. A build step that runs a bundled binary is running unreviewed code."),
        e("BIN-003", "Prebuilt eBPF object", Critical, MaliciousCode, "binary", Some("CWE-506"),
          "An eBPF object ships as a compiled blob. eBPF runs in the KERNEL, and this one has no source to read. The June 2026 Atomic Arch campaign delivered an eBPF rootkit through AUR packages this way.", "Do not install; obtain the eBPF source and build it."),
        e("BIN-004", "Binary searches for libraries in an unsafe location", High, PrivilegeEscalation, "binary", Some("CWE-426"),
          "A DT_RPATH/DT_RUNPATH points somewhere world-writable, resolves against the working directory, or climbs out of the install tree. A library placed there is loaded in preference to the system copy.", "Do not install a binary whose library search path others can write."),
        e("BIN-005", "Binary contains a packed or encrypted section", Medium, Obfuscation, "binary", Some("CWE-506"),
          "A section measures over 7.5 bits/byte of entropy. Ordinary compiled code measures 6.0-6.9 and compressed data ~8.0, so content this dense is packed or encrypted and cannot be statically reviewed.", "Treat a packed binary in a source package as unreviewable."),
        // -- squat analyzer (name impersonation; requires registry context) --
        e("SQUAT-001", "Package name imitates a trusted name", Critical, MaliciousCode, "squat", Some("CWE-1007"),
          "The package name renders like a trusted package's name -- via non-ASCII lookalike characters, or a separator swap. Two distinct packages do not display the same name by accident.", "Compare the name character by character against the package you meant to install."),
        e("SQUAT-002", "Package name is one keystroke from a widely-installed package", High, MaliciousCode, "squat", Some("CWE-1007"),
          "The name differs by a single visually-similar or keyboard-adjacent character from a high-value package, and the package has no age or community standing of its own.", "Confirm which package you actually meant to install."),
        e("SQUAT-003", "Build variant is in different hands from its base", Low, SuspiciousMetadata, "squat", None,
          "The package is the -bin/-git build of another AUR package but is published by a different account. Informational only: measured against the live AUR, 42.5% of build variants are in different hands and are legitimate, so this is context for a human, never evidence on its own.", "If you expected the base project to publish this build, confirm that they do; declare names you own under [[owned_namespaces]] to make this decisive."),
        // -- ownership analyzer (point-in-time; requires registry context) --
        e("OWN-001", "Package is orphaned", Low, SuspiciousMetadata, "ownership", None,
          "The package has no maintainer, so anyone may adopt it and inherit every existing installation. About 12% of the AUR is orphaned, so this is context rather than evidence -- but adoption of an orphan is how the known AUR supply-chain campaigns began.", "Note that nobody is responsible for this package; review updates to it yourself."),
        e("OWN-002", "Package is orphaned and flagged out-of-date", Medium, SuspiciousMetadata, "ownership", None,
          "No maintainer AND visibly behind upstream -- roughly 4% of the AUR, and the exact profile the 2018 xeactor and 2026 Atomic Arch campaigns selected for.", "Prefer a maintained alternative; review the PKGBUILD yourself if you install it."),
        e("OWN-003", "Flagged out-of-date for over a year", Low, SuspiciousMetadata, "ownership", None,
          "The package has a maintainer but has been flagged out-of-date for more than a year, so it is unmaintained in practice and likely missing upstream fixes.", "Check whether upstream has fixes this package does not carry."),
        e("OWN-004", "New package with no community validation", Low, SuspiciousMetadata, "ownership", None,
          "Submitted within the last 30 days, zero votes, and runs build or install code. Each part is unremarkable alone (half the AUR has zero votes); together they mean nobody has reviewed this yet.", "Read the PKGBUILD and any install script in full before building."),
        // -- change detection (requires a previous scan of the same package) --
        e("DIFF-001", "New findings since the last scan", High, SuspiciousMetadata, "diff", None,
          "The package raised findings it did not raise when it was last scanned. Reported at the severity of the worst NEW finding: a long-standing SKIP checksum is not news, a newly-appeared curl|sh is. Silent on a first scan.", "Review the new findings specifically -- they are what changed since you approved this package."),
        e("DIFF-002", "Package ownership changed", High, SuspiciousMetadata, "diff", None,
          "The maintainer changed since the last scan. Adoption of a previously orphaned package is High and is the documented mechanism of both the 2018 xeactor hijack and the 2026 Atomic Arch campaign; an ordinary handover, or a package becoming orphaned, is Medium.", "Confirm the handover is legitimate before installing an update."),
        e("DIFF-003", "Package fetches from a new upstream", High, NetworkSecurity, "diff", Some("CWE-494"),
          "A source now points at a host/owner/repo it did not use at the last scan. Compared at owner/repo depth, so routine version bumps and new release tarballs do not fire -- upstream itself moved.", "Verify the new upstream is the project's real home and not a fork impersonating it."),
        e("DIFF-004", "Install script added or changed", High, Persistence, "diff", Some("CWE-506"),
          "The package gained an install scriptlet or ALPM hook (High), or an existing one changed (Medium). This code runs as root at install time, so acquiring one changes what the package can do to the system regardless of its current contents.", "Read the new or changed install script in full before installing."),
        e("SQUAT-004", "Package occupies an owned namespace under an unauthorised account", Critical, MaliciousCode, "squat", Some("CWE-1007"),
          "A package matching a name prefix the operator declared they publish is maintained by an account they did not authorise. The AUR reserves no variant namespace, so owning 'foo' does not reserve 'foo-bin'.", "Do not install it; report it to the AUR maintainers as an impersonation."),
        // -- source analyzer (host-aware metadata) --
        e("SRC-008", "Source host differs from upstream url host", Low, NetworkSecurity, "source", None,
          "url= and a source= are both on known forges but different ones (a personal-fork-vs-upstream signal).", "Verify the source forge is the project's official one."),
        // -- checksum analyzer (hash shape) --
        e("CHK-008", "Malformed or wrong-length checksum", Medium, Cryptography, "checksum", Some("CWE-354"),
          "A checksum is not valid hex of the algorithm's expected length (md5=32, sha1=40, sha256=64, sha512/b2=128).", "Regenerate checksums with updpkgsums; a malformed hash silently disables integrity verification."),
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
            "CHK-001",
            "CHK-002",
            "CHK-003",
            "CHK-004",
            "CHK-005",
            "CHK-006",
            "CHK-008",
            "PRIV-001",
            "PRIV-002",
            "PRIV-003",
            "PRIV-004",
            "PRIV-005",
            "PRIV-006",
            "SRC-001",
            "SRC-002",
            "SRC-003",
            "SRC-004",
            "SRC-005",
            "SRC-006",
            "SRC-007",
            "SRC-008",
            "SRC-010",
            "IOC-001",
            "DEEP-001",
            "DEEP-002",
            "DEEP-003",
            "EXEC-REMOTE",
            "TI-VT-001",
            "TI-URLHAUS-001",
            "PROV-001",
            "FUNC-001",
            "META-002",
            "META-003",
            "META-004",
            "META-005",
            "META-006",
            "BIN-001",
            "BIN-002",
            "BIN-003",
            "BIN-004",
            "BIN-005",
            "SQUAT-001",
            "SQUAT-002",
            "SQUAT-003",
            "SQUAT-004",
            "OWN-001",
            "OWN-002",
            "OWN-003",
            "OWN-004",
            "DIFF-001",
            "DIFF-002",
            "DIFF-003",
            "DIFF-004",
            "DEP-001",
        ];
        let catalog = Catalog::load();
        for id in EMITTED {
            assert!(
                catalog.get(id).is_some(),
                "emitted code {id} missing from catalog"
            );
        }
        // And no phantom analyzer codes (every analyzer_codes id is in EMITTED).
        for c in analyzer_codes() {
            assert!(
                EMITTED.contains(&c.id.as_str()),
                "catalog has phantom analyzer code {}",
                c.id
            );
        }
    }
}
