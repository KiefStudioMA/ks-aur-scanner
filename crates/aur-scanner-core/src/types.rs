//! Core type definitions for the AUR security scanner

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity levels for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
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
        self.findings.iter().any(|f| f.severity == Severity::Critical)
    }

    /// Check if any findings at or above the given severity were found
    pub fn has_severity_or_above(&self, severity: Severity) -> bool {
        self.findings.iter().any(|f| f.severity <= severity)
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
            timeout_seconds: default_timeout(),
        }
    }
}

/// Threat intelligence provider configuration
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ThreatIntelConfig {
    /// VirusTotal API key
    pub virustotal_api_key: Option<String>,
    /// Enable URLhaus lookups
    #[serde(default)]
    pub urlhaus_enabled: bool,
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
