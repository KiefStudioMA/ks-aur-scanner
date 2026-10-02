//! Core type definitions for the AUR security scanner

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The root-owned configuration file. The only path a privileged consumer will
/// read — see [`ScanConfig::config_paths_for`].
pub const SYSTEM_CONFIG_PATH: &str = "/etc/aur-scanner/config.toml";

/// The per-user config path implied by `XDG_CONFIG_HOME` and the home
/// directory, or `None` when neither yields one.
///
/// Pure so the precedence is unit-testable: `XDG_CONFIG_HOME` is process-global
/// state, and a test that sets it would race every other test in the binary.
///
/// An **empty** `XDG_CONFIG_HOME` falls back to `~/.config` rather than
/// disabling the user path. Written as an `else if` against the same `if let`,
/// the empty case silently dropped the user path altogether — a config the user
/// believes is in effect and is not, which is exactly the issue #25 failure this
/// search order exists to prevent.
fn user_config_path(xdg: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    xdg.filter(|p| !p.as_os_str().is_empty())
        .or_else(|| home.map(|h| h.join(".config")))
        .map(|base| base.join("aur-scanner").join("config.toml"))
}

/// Severity levels for security findings
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Critical security issue - likely malicious
    Critical = 0,
    /// High severity - significant security risk
    High = 1,
    /// Medium severity - potential security concern
    Medium = 2,
    /// Low severity - minor issue or best practice violation
    Low = 3,
    /// Informational - not a security issue but worth noting
    #[default]
    Info = 4,
}

impl Severity {
    /// Is this finding at least as severe as `threshold`?
    ///
    /// Gate decisions throughout the tool ("block if a finding is at or above
    /// the threshold") depend on the enum's numeric order (`Critical = 0` is the
    /// most severe). Routing every comparison through this method — instead of
    /// open-coding `self <= threshold` — makes the load-bearing direction
    /// explicit and is pinned by `severity_ordering_is_load_bearing` below, so a
    /// future reorder of the variants can never silently invert a gate.
    pub fn is_at_least(self, threshold: Severity) -> bool {
        // Lower discriminant == higher severity.
        self <= threshold
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Category of security finding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Command injection vulnerabilities
    CommandInjection,
    /// Privilege escalation attempts
    PrivilegeEscalation,
    /// Network security issues
    NetworkSecurity,
    /// Data exfiltration patterns
    DataExfiltration,
    /// Malicious code indicators
    MaliciousCode,
    /// Cryptographic issues
    Cryptography,
    /// Configuration problems
    Configuration,
    /// Dependency issues
    Dependencies,
    /// Obfuscation techniques
    Obfuscation,
    /// Credential theft
    CredentialTheft,
    /// Persistence mechanisms
    Persistence,
    /// Cryptomining
    Cryptomining,
    /// Suspicious package metadata
    SuspiciousMetadata,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::CommandInjection => write!(f, "Command Injection"),
            Category::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            Category::NetworkSecurity => write!(f, "Network Security"),
            Category::DataExfiltration => write!(f, "Data Exfiltration"),
            Category::MaliciousCode => write!(f, "Malicious Code"),
            Category::Cryptography => write!(f, "Cryptography"),
            Category::Configuration => write!(f, "Configuration"),
            Category::Dependencies => write!(f, "Dependencies"),
            Category::Obfuscation => write!(f, "Obfuscation"),
            Category::CredentialTheft => write!(f, "Credential Theft"),
            Category::Persistence => write!(f, "Persistence"),
            Category::Cryptomining => write!(f, "Cryptomining"),
            Category::SuspiciousMetadata => write!(f, "Suspicious Metadata"),
        }
    }
}

/// Location within a file where an issue was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path
    pub file: PathBuf,
    /// Line number (1-indexed)
    pub line: Option<usize>,
    /// Column number (1-indexed)
    pub column: Option<usize>,
    /// Code snippet showing the issue
    pub snippet: Option<String>,
}

/// A security finding from the scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding type (e.g., "DLE-001")
    pub id: String,
    /// Severity level
    pub severity: Severity,
    /// Category of finding
    pub category: Category,
    /// Short title describing the issue
    pub title: String,
    /// Detailed description of the finding
    pub description: String,
    /// Location in the file
    pub location: Location,
    /// Recommendation for fixing the issue
    pub recommendation: String,
    /// CWE ID if applicable (e.g., "CWE-78")
    pub cwe_id: Option<String>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Finding code emitted when a file the package ships or declares could not be
/// read, was not a regular file, or was only partly analyzed.
pub const UNANALYZABLE_CODE: &str = "SCAN-001";

/// Result of scanning a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Name of the scanned package
    pub package_name: String,
    /// Version of the package (pkgver-pkgrel)
    pub package_version: String,
    /// Security findings
    pub findings: Vec<Finding>,
    /// Files that were scanned
    pub scanned_files: Vec<PathBuf>,
    /// Timestamp of the scan
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Duration of scan in milliseconds
    pub scan_duration_ms: u64,
}

impl ScanResult {
    /// Check if any critical findings were found
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// Check if any findings at or above the given severity were found. Routes
    /// through `Severity::is_at_least` so the order-dependent gate semantics
    /// stay covered by the pinning test (and a variant reorder can't silently
    /// invert this gate).
    pub fn has_severity_or_above(&self, severity: Severity) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity.is_at_least(severity))
    }

    /// Get findings filtered by severity
    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// A copy of this result holding only findings at or above `min`
    /// (display filtering).
    ///
    /// `min_severity` used to drop findings inside the scan, BEFORE any gate
    /// ran, so a user-writable config of `min_severity = "critical"` silently
    /// disabled every High gate. The scan now always returns the full set; this
    /// is the one sanctioned way to narrow what is *shown*. Gates
    /// (`--fail-on`, install, hook, wrapper) must evaluate the unfiltered
    /// result.
    pub fn visible(&self, min: Severity) -> ScanResult {
        let mut out = self.clone();
        out.findings.retain(|f| f.severity.is_at_least(min));
        out
    }

    /// Whether any file the package declared could not be fully analyzed
    /// (`SCAN-001`). Callers that distinguish "reviewed and risky" from "never
    /// reviewed" (install's `--force` rule) should treat this as unscannable.
    pub fn has_unanalyzable(&self) -> bool {
        self.findings.iter().any(|f| f.id == UNANALYZABLE_CODE)
    }

    /// Count findings by severity
    pub fn count_by_severity(&self) -> std::collections::HashMap<Severity, usize> {
        let mut counts = std::collections::HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.severity).or_insert(0) += 1;
        }
        counts
    }
}

/// Configuration for the scanner.
///
/// `deny_unknown_fields`, for the same reason the `[output]` table has it: a
/// mistyped key that silently does nothing is worse than an error, because the
/// operator believes a setting is in force when it is not. That failure mode is
/// exactly issue #25 -- threat-intel keys that were never read, so threat intel
/// looked enabled and was not. A security tool must not have settings that
/// quietly evaporate.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Path to custom rules directory
    pub rules_path: Option<PathBuf>,
    /// Minimum severity to report
    #[serde(default)]
    pub min_severity: Severity,
    /// Enable threat intelligence lookups
    #[serde(default)]
    pub enable_threat_intel: bool,
    /// Threat intelligence configuration
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,
    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,
    /// Human-readable output display configuration
    #[serde(default)]
    pub output: OutputConfig,
    /// Scan timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Package-name namespaces you publish, and the accounts allowed to
    /// publish them. Empty by default.
    #[serde(default)]
    pub owned_namespaces: Vec<OwnedNamespace>,
}

/// A package-name namespace the operator claims, and who is allowed to publish
/// in it.
///
/// The AUR reserves nothing: owning `foo` does not reserve `foo-bin`, and
/// anyone may publish it. Measured across the live AUR, 42.5% of build-variant
/// packages are maintained by someone other than the base package's maintainer
/// and essentially all of them are legitimate -- different people package the
/// git build and the release build all the time. So "different maintainer" is
/// not, on its own, evidence of anything, and the scanner will not accuse
/// anyone on that basis.
///
/// What *is* evidence is a publisher you did not authorise using a name you
/// own. Only you know that. Declaring it here converts knowledge the scanner
/// cannot infer into a precise, zero-false-positive check:
///
/// ```toml
/// [[owned_namespaces]]
/// prefix = "aur-scanner"
/// maintainers = ["KiefStudio"]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedNamespace {
    /// Package-name prefix you claim (`"aur-scanner"` covers `aur-scanner`,
    /// `aur-scanner-bin`, `aur-scanner-git`, ...).
    pub prefix: String,
    /// AUR accounts permitted to publish in this namespace. A package matching
    /// `prefix` maintained by anyone else -- including an orphaned one -- is
    /// reported.
    pub maintainers: Vec<String>,
}

fn default_timeout() -> u64 {
    30
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            rules_path: None,
            min_severity: Severity::Low,
            enable_threat_intel: false,
            threat_intel: ThreatIntelConfig::default(),
            cache: CacheConfig::default(),
            output: OutputConfig::default(),
            timeout_seconds: default_timeout(),
            owned_namespaces: Vec::new(),
        }
    }
}

/// Which fields the human-readable text output includes for each finding.
///
/// **Display-only.** These toggles change *what is printed*, never which
/// findings exist, the process exit code, or whether a security gate trips. A
/// field hidden here is still present in the [`ScanResult`] and in the
/// machine-readable JSON/SARIF output — those always emit the complete record so
/// CI and tooling are never blinded by a display preference. There is
/// deliberately **no** key to suppress a finding itself: verbosity is
/// configurable, a finding's existence is not.
///
/// Rich by default — every field is shown unless explicitly disabled, so a
/// config can only ever make the output terser, never silently drop detail the
/// reader did not ask to drop. `deny_unknown_fields` turns a mistyped key
/// (`line_numbers = true`) into a hard error rather than a silent no-op.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    /// Append the `file:line` location to each finding.
    pub line: bool,
    /// Show the matched code snippet.
    pub snippet: bool,
    /// Show the remediation recommendation.
    pub recommendation: bool,
    /// Show the CWE reference.
    pub cwe: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            line: true,
            snippet: true,
            recommendation: true,
            cwe: true,
        }
    }
}

impl ScanConfig {
    /// Load configuration from a TOML file. Returns an error if the file exists
    /// but cannot be read or parsed (callers decide whether to fall back to
    /// defaults), so a malformed security config is never silently ignored.
    pub fn from_toml_file(path: &std::path::Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let config: ScanConfig = toml::from_str(&text)
            .map_err(|e| crate::ScanError::Config(format!("{}: {}", path.display(), e)))?;
        Ok(config)
    }

    /// Load from `path` if it exists, otherwise return defaults. A present but
    /// malformed file is a hard error (surfaced to the caller).
    pub fn from_toml_file_or_default(path: &std::path::Path) -> crate::Result<Self> {
        if path.exists() {
            Self::from_toml_file(path)
        } else {
            Ok(Self::default())
        }
    }

    /// Default config search paths, highest priority first.
    ///
    /// 1. `$XDG_CONFIG_HOME/aur-scanner/config.toml` (or `~/.config/...`)
    /// 2. `/etc/aur-scanner/config.toml`
    ///
    /// An explicit `-c/--config` path is handled by the CLI and is never in this
    /// list. The first path that exists wins; a present-but-malformed file is a
    /// hard error (never silently skipped in favor of a lower-priority path).
    ///
    /// This is the UNPRIVILEGED list. A root-running consumer must call
    /// [`Self::config_paths_for`] instead -- see the note there.
    pub fn default_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(2);
        if let Some(user) = user_config_path(
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            dirs::home_dir(),
        ) {
            paths.push(user);
        }
        paths.push(PathBuf::from(SYSTEM_CONFIG_PATH));
        paths
    }

    /// Config search paths for a caller that may hold elevated privileges.
    ///
    /// Unprivileged callers get [`Self::default_config_paths`]. A **privileged**
    /// caller gets `/etc` and nothing else.
    ///
    /// The pacman hook runs as root, and it resolves its config before it can
    /// drop privileges (it needs the config to build the scanner, and `/etc` may
    /// be root-readable only). If that resolution consulted the user path first,
    /// a root process would take its security configuration from a file any
    /// unprivileged user can write. The cheapest exploit is not escalation, it
    /// is denial of service: a hostile `build()` drops a syntactically broken
    /// TOML in `~/.config/aur-scanner/`, and because a malformed security config
    /// is deliberately a hard error, every subsequent pacman transaction dies at
    /// the parse. Restricting privileged lookups to `/etc` puts that back behind
    /// root-owned write access, where it was before the hook moved off its
    /// hardcoded path.
    pub fn config_paths_for(privileged: bool) -> Vec<PathBuf> {
        if privileged {
            return vec![PathBuf::from(SYSTEM_CONFIG_PATH)];
        }
        Self::default_config_paths()
    }

    /// Load the effective config: `cli_path` if given, otherwise the first
    /// existing default path, otherwise built-in defaults.
    ///
    /// Returns `(config, path_loaded)` where `path_loaded` is `None` only when
    /// no file was found and defaults were used. A present-but-unreadable or
    /// malformed file is always an error — a security config must never look
    /// like it is in effect while being silently ignored (issue #25).
    pub fn resolve(cli_path: Option<&std::path::Path>) -> crate::Result<(Self, Option<PathBuf>)> {
        Self::resolve_for_privilege(cli_path, false)
    }

    /// [`Self::resolve`], but restricted to root-owned paths when `privileged`.
    ///
    /// Call this from any consumer that can run as root — see
    /// [`Self::config_paths_for`] for why a root process must not read a
    /// user-writable security config.
    pub fn resolve_for_privilege(
        cli_path: Option<&std::path::Path>,
        privileged: bool,
    ) -> crate::Result<(Self, Option<PathBuf>)> {
        if let Some(path) = cli_path {
            let cfg = Self::from_toml_file(path)?;
            return Ok((cfg, Some(path.to_path_buf())));
        }
        for path in Self::config_paths_for(privileged) {
            if path.exists() {
                let cfg = Self::from_toml_file(&path)?;
                return Ok((cfg, Some(path)));
            }
        }
        Ok((Self::default(), None))
    }
}

/// Threat intelligence provider configuration.
///
/// All of this is inert unless [`ScanConfig::enable_threat_intel`] is set: the
/// scanner is offline/static by default. Keys may also be supplied via the
/// environment (`VT_API_KEY`/`VIRUSTOTAL_API_KEY`, `URLHAUS_AUTH_KEY`) so they
/// need not be written to a config file.
#[derive(Debug, Clone, Default, Deserialize)]
// A typo in a threat-intel key is the exact failure this whole validation
// posture exists for: the operator believes lookups are on, and they are not.
#[serde(deny_unknown_fields)]
pub struct ThreatIntelConfig {
    /// VirusTotal API key. Without it, the VirusTotal hash lookup is skipped.
    pub virustotal_api_key: Option<String>,
    /// Enable URLhaus URL-reputation lookups. Requires `urlhaus_auth_key`.
    #[serde(default)]
    pub urlhaus_enabled: bool,
    /// URLhaus Auth-Key. abuse.ch made this header mandatory (free key from
    /// <https://auth.abuse.ch/>), so URLhaus is skipped when it is absent.
    pub urlhaus_auth_key: Option<String>,
    /// Cache duration for threat intel results in hours
    #[serde(default = "default_cache_hours")]
    pub cache_duration_hours: u64,
}

fn default_cache_hours() -> u64 {
    24
}

/// Cache configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Enable caching
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cache directory
    #[serde(default = "default_cache_dir")]
    pub directory: PathBuf,
    /// Maximum cache size in MB
    #[serde(default = "default_cache_size")]
    pub max_size_mb: usize,
    /// Cache TTL in hours
    #[serde(default = "default_cache_hours")]
    pub ttl_hours: u64,
}

fn default_true() -> bool {
    true
}

fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aur-scanner")
}

fn default_cache_size() -> usize {
    100
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: default_cache_dir(),
            max_size_mb: default_cache_size(),
            ttl_hours: default_cache_hours(),
        }
    }
}

/// Context passed to analyzers
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Parsed PKGBUILD
    pub pkgbuild: crate::parser::ParsedPkgbuild,
    /// Parsed install script if present (`install=` / `*.install`)
    pub install_script: Option<crate::parser::ParsedInstallScript>,
    /// Additional package-side scripts discovered next to the PKGBUILD
    /// (notably ALPM `*.hook` files used in later Atomic Arch waves).
    /// Analyzed with the same install-script rule surface; never executed.
    pub side_scripts: Vec<crate::parser::ParsedInstallScript>,
    /// Prebuilt executables found in the package directory.
    ///
    /// Only a bounded PREFIX of each file is held: the ELF header, section
    /// table and string tables live at the front, and reading a whole
    /// multi-hundred-megabyte artifact into memory to look at its header would
    /// be a resource-exhaustion vector from a hostile repository.
    pub local_binaries: Vec<BinaryArtifact>,
    /// Scanner configuration
    pub config: ScanConfig,
    /// Path to the PKGBUILD file
    pub file_path: PathBuf,
    /// Registry metadata for this package, when the caller knows it.
    ///
    /// `check`, `install`, and `system` all resolve the package through the AUR
    /// RPC before scanning, so they can say who maintains it, how long it has
    /// existed, and how much community validation it has. A bare
    /// `scan <path>` has no registry context and leaves this `None`.
    ///
    /// Analyzers that consume this **must** degrade to silence when it is
    /// absent rather than guessing: a missing maintainer field means "we did
    /// not look", not "orphaned".
    pub registry: Option<RegistryContext>,
}

/// A prebuilt executable shipped inside a package directory.
#[derive(Debug, Clone)]
pub struct BinaryArtifact {
    /// Where it is on disk.
    pub path: PathBuf,
    /// Detected container format ("ELF", "PE/COFF", ...).
    pub format: &'static str,
    /// Full size on disk, even though only `head` was read.
    pub size: u64,
    /// A bounded prefix of the file, enough for header and section parsing.
    pub head: Vec<u8>,
}

/// What the package registry says about a package, independent of its files.
///
/// Ownership and community-validation signals are a real part of AUR risk --
/// the 2018 xeactor hijack and the June 2026 Atomic Arch campaign both worked
/// by adopting orphaned packages rather than by writing novel malicious code --
/// but they are *context*, not proof, so they are reported at modest severity
/// and always alongside what the files actually do.
#[derive(Debug, Clone, Default)]
pub struct RegistryContext {
    /// Current maintainer; `None` means the package is orphaned.
    pub maintainer: Option<String>,
    /// Community votes, when known.
    pub num_votes: Option<i32>,
    /// Popularity score, when known.
    pub popularity: Option<f64>,
    /// Unix timestamp the package was flagged out-of-date, if it is.
    pub out_of_date: Option<i64>,
    /// Unix timestamp of first submission to the AUR.
    pub first_submitted: Option<i64>,
    /// Unix timestamp of the last modification.
    pub last_modified: Option<i64>,
    /// Names of packages in the official repositories, for typo-squat
    /// comparison. Empty when the sync databases could not be read.
    pub official_names: Vec<String>,
    /// When this package's name is a build variant of another package
    /// (`foo-bin` of `foo`), what the registry says about that base package.
    ///
    /// The AUR does not reserve a package's variant namespace, so anyone may
    /// publish `foo-bin`. Knowing who maintains `foo` is the only way to tell
    /// an upstream's own binary build from someone else trading on the name.
    pub variant_base: Option<VariantBase>,
}

/// The registry record of the package a variant name is derived from.
#[derive(Debug, Clone)]
pub struct VariantBase {
    /// The base package name (`foo` for `foo-bin`).
    pub name: String,
    /// The base package's maintainer; `None` if the base is orphaned.
    pub maintainer: Option<String>,
    /// Whether the base package lives in the official repositories, which
    /// makes an AUR variant of it a strictly stronger reputation claim.
    pub official: bool,
    /// Community votes on the base, when known.
    pub num_votes: Option<i32>,
}

impl AnalysisContext {
    /// Every package-side scriptlet (primary `.install` plus side scripts such
    /// as ALPM hooks). Analyzers that scan install-time content should iterate
    /// this rather than only `install_script`, so a payload moved into a `.hook`
    /// file cannot escape analysis.
    pub fn all_scripts(&self) -> impl Iterator<Item = &crate::parser::ParsedInstallScript> {
        self.install_script.iter().chain(self.side_scripts.iter())
    }

    /// The package name this context is about, preferring the parsed PKGBUILD.
    pub fn package_name(&self) -> Option<&str> {
        self.pkgbuild.pkgname.first().map(|s| s.as_str())
    }
}

/// File type for rule matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    /// PKGBUILD file
    Pkgbuild,
    /// .install script
    InstallScript,
    /// Patch or source file
    SourceFile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_is_load_bearing() {
        // Critical is the most severe; Info the least. Every gate depends on
        // this. If a variant is ever reordered, these assertions must fail.
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);

        // A Critical finding trips a High gate; a High finding does NOT trip a
        // Critical gate. This is the exact semantic the install/check gates rely
        // on.
        assert!(Severity::Critical.is_at_least(Severity::High));
        assert!(Severity::Critical.is_at_least(Severity::Critical));
        assert!(!Severity::High.is_at_least(Severity::Critical));
        assert!(Severity::High.is_at_least(Severity::High));
        assert!(!Severity::Info.is_at_least(Severity::Low));
    }

    #[test]
    fn resolve_prefers_explicit_path_and_errors_on_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.toml");
        std::fs::write(&good, "enable_threat_intel = true\n").unwrap();
        let (cfg, path) = ScanConfig::resolve(Some(&good)).unwrap();
        assert!(cfg.enable_threat_intel);
        assert_eq!(path.as_deref(), Some(good.as_path()));

        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "enable_threat_intel = [not valid\n").unwrap();
        assert!(
            ScanConfig::resolve(Some(&bad)).is_err(),
            "malformed config must be a hard error"
        );
    }

    #[test]
    fn default_config_paths_put_user_before_system() {
        let paths = ScanConfig::default_config_paths();
        assert!(
            !paths.is_empty(),
            "must always include at least the system path"
        );
        assert_eq!(
            paths.last().map(|p| p.as_os_str()),
            Some(std::ffi::OsStr::new("/etc/aur-scanner/config.toml"))
        );
        if paths.len() > 1 {
            assert!(
                paths[0].ends_with("aur-scanner/config.toml"),
                "user path should be first when present: {:?}",
                paths[0]
            );
        }
    }

    #[test]
    fn empty_xdg_config_home_still_falls_back_to_dot_config() {
        // `XDG_CONFIG_HOME=""` is a real shell condition (`export XDG_CONFIG_HOME=`
        // with nothing after it). Treated as "set", it dropped the user path
        // entirely and the user's config silently stopped being read -- the
        // issue #25 symptom.
        assert_eq!(
            user_config_path(Some(PathBuf::from("")), Some(PathBuf::from("/home/alice"))),
            Some(PathBuf::from("/home/alice/.config/aur-scanner/config.toml"))
        );
        // A set, non-empty XDG_CONFIG_HOME still wins over the home directory.
        assert_eq!(
            user_config_path(
                Some(PathBuf::from("/xdg")),
                Some(PathBuf::from("/home/alice"))
            ),
            Some(PathBuf::from("/xdg/aur-scanner/config.toml"))
        );
        // Unset XDG uses home.
        assert_eq!(
            user_config_path(None, Some(PathBuf::from("/home/alice"))),
            Some(PathBuf::from("/home/alice/.config/aur-scanner/config.toml"))
        );
        // Neither available: no user path at all (the system path is added by
        // the caller, so the list is never empty).
        assert_eq!(user_config_path(None, None), None);
        assert_eq!(user_config_path(Some(PathBuf::from("")), None), None);
    }

    #[test]
    fn a_privileged_caller_reads_only_the_root_owned_config() {
        // The pacman hook runs as root and resolves its config before it can
        // drop privileges. If the user path were consulted there, an
        // unprivileged user could feed a root process its security config --
        // and, because a malformed config is a deliberate hard error, could
        // wedge every pacman transaction by dropping broken TOML in ~/.config.
        let privileged = ScanConfig::config_paths_for(true);
        assert_eq!(
            privileged,
            vec![PathBuf::from(SYSTEM_CONFIG_PATH)],
            "a privileged lookup must consult /etc and nothing else"
        );
        assert!(
            !privileged.iter().any(|p| p.starts_with("/home")
                || p.starts_with(
                    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/nonexistent"))
                )),
            "no user-writable path may appear in a privileged lookup: {privileged:?}"
        );

        // And the unprivileged list is genuinely different, so this test cannot
        // pass by the two paths having quietly become the same thing.
        let unprivileged = ScanConfig::config_paths_for(false);
        assert_eq!(unprivileged, ScanConfig::default_config_paths());
        assert_eq!(
            unprivileged.last().map(PathBuf::as_path),
            Some(std::path::Path::new(SYSTEM_CONFIG_PATH)),
            "the system path stays last in the unprivileged list"
        );
    }

    #[test]
    fn output_config_is_rich_by_default() {
        // The default must show everything: a config can make output terser, but
        // the absence of an [output] table never silently hides detail.
        let cfg = OutputConfig::default();
        assert!(cfg.line && cfg.snippet && cfg.recommendation && cfg.cwe);
        // And the default ScanConfig carries that rich OutputConfig.
        assert!(ScanConfig::default().output.line);
    }

    #[test]
    fn output_config_partial_table_keeps_other_fields_default() {
        // Setting one field must not reset the others to false (serde container
        // default fills the omitted fields from OutputConfig::default()).
        let cfg: ScanConfig = toml::from_str("[output]\nline = false\n").unwrap();
        assert!(!cfg.output.line, "explicitly disabled");
        assert!(cfg.output.snippet, "omitted field stays rich-default");
        assert!(cfg.output.recommendation);
        assert!(cfg.output.cwe);
    }

    #[test]
    fn output_config_missing_table_is_rich() {
        // No [output] table at all => every field on.
        let cfg: ScanConfig = toml::from_str("min_severity = \"low\"\n").unwrap();
        assert!(cfg.output.line && cfg.output.snippet);
    }

    #[test]
    fn output_config_rejects_unknown_key() {
        // A mistyped key must be a hard error, not a silent no-op that leaves the
        // user thinking they disabled something they did not.
        let err = toml::from_str::<ScanConfig>("[output]\nline_numbers = true\n");
        assert!(err.is_err(), "unknown [output] key should be rejected");
    }
}
