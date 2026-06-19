//! Core type definitions for the AUR security scanner

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

    /// Count findings by severity
    pub fn count_by_severity(&self) -> std::collections::HashMap<Severity, usize> {
        let mut counts = std::collections::HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.severity).or_insert(0) += 1;
        }
        counts
    }
}

/// Configuration for the scanner
#[derive(Debug, Clone, Deserialize)]
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
}

/// Threat intelligence provider configuration.
///
/// All of this is inert unless [`ScanConfig::enable_threat_intel`] is set: the
/// scanner is offline/static by default. Keys may also be supplied via the
/// environment (`VT_API_KEY`/`VIRUSTOTAL_API_KEY`, `URLHAUS_AUTH_KEY`) so they
/// need not be written to a config file.
#[derive(Debug, Clone, Default, Deserialize)]
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
    /// Parsed install script if present
    pub install_script: Option<crate::parser::ParsedInstallScript>,
    /// Scanner configuration
    pub config: ScanConfig,
    /// Path to the PKGBUILD file
    pub file_path: PathBuf,
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
