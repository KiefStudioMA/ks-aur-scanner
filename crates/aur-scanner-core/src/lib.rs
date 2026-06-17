//! AUR Security Scanner Core Library
//!
//! Provides security analysis capabilities for Arch Linux AUR packages.
//! Detects malicious patterns in PKGBUILDs and install scripts.

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod analyzer;
pub mod aur;
pub mod cache;
pub mod catalog;
pub mod depgraph;
pub mod error;
pub mod neturl;
pub mod overlay;
pub mod parser;
pub mod provenance;
pub mod resolve;
pub mod rules;
pub mod sbom;
pub mod textutil;
pub mod threat_intel;
pub mod types;
pub mod validate;

pub use error::{ParseError, Result, ScanError};
pub use types::*;

use analyzer::SecurityAnalyzer;
use parser::PkgbuildParser;
use rules::RuleEngine;
use std::path::Path;
use std::sync::Arc;
use threat_intel::IocDatabase;
use tracing::{debug, info, warn};

/// Main scanner that orchestrates all security analysis
pub struct Scanner {
    analyzers: Vec<Arc<dyn SecurityAnalyzer>>,
    parser: Box<dyn PkgbuildParser>,
    rule_engine: Arc<RuleEngine>,
    ioc_db: Arc<IocDatabase>,
    config: ScanConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Result<Self> {
        // Use default() which loads built-in rules
        let rule_engine = Arc::new(RuleEngine::default());
        let ioc_db = Arc::new(IocDatabase::load());

        let mut analyzers: Vec<Arc<dyn SecurityAnalyzer>> = vec![
            Arc::new(analyzer::PatternAnalyzer::new(rule_engine.clone())),
            Arc::new(analyzer::IocAnalyzer::new(ioc_db.clone())),
            Arc::new(analyzer::DeepAnalyzer::new()),
            Arc::new(analyzer::RemoteExecAnalyzer::new()),
            Arc::new(analyzer::SourceAnalyzer::new()),
            Arc::new(analyzer::ChecksumAnalyzer::new()),
            Arc::new(analyzer::PrivilegeAnalyzer::new()),
            Arc::new(analyzer::MetadataAnalyzer::new()),
        ];

        // Opt-in, networked threat-intel analyzer. Added ONLY when the operator
        // explicitly enabled it AND a provider key is available (config or env).
        // Everything above this point is offline/static.
        if config.enable_threat_intel {
            if let Some(ti) = build_threat_intel_analyzer(&config) {
                analyzers.push(Arc::new(ti));
                info!("threat-intel lookups enabled (opt-in network access)");
            } else {
                warn!(
                    "enable_threat_intel is set but no VirusTotal/URLhaus key was found \
                     (config or env); threat-intel lookups are disabled"
                );
            }
        }

        let parser: Box<dyn PkgbuildParser> = Box::new(parser::StaticParser::new());

        Ok(Self {
            analyzers,
            parser,
            rule_engine,
            ioc_db,
            config,
        })
    }

    /// The IOC database backing this scanner (embedded defaults + overrides).
    pub fn ioc_database(&self) -> Arc<IocDatabase> {
        self.ioc_db.clone()
    }

    /// Create a scanner with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(ScanConfig::default())
    }

    /// Load rules from a directory
    pub fn load_rules(&mut self, rules_dir: &Path) -> Result<()> {
        Arc::get_mut(&mut self.rule_engine)
            .ok_or_else(|| ScanError::Config("Cannot modify rule engine".into()))?
            .load_rules_from_dir(rules_dir)?;
        Ok(())
    }

    /// Scan a PKGBUILD file
    pub async fn scan_pkgbuild(&self, path: &Path) -> Result<ScanResult> {
        let start = std::time::Instant::now();
        info!("Scanning PKGBUILD: {}", path.display());

        // Read and parse PKGBUILD. Cap the read: a real PKGBUILD is a few KB,
        // so a multi-megabyte one is itself abnormal and a memory-DoS risk from
        // a hostile repo. Refuse rather than load it all.
        let content = read_text_capped(path)?;
        let pkgbuild = self.parser.parse(&content)?;

        debug!(
            "Parsed package: {} version {}-{}",
            pkgbuild.pkgname.first().unwrap_or(&"unknown".to_string()),
            pkgbuild.pkgver,
            pkgbuild.pkgrel
        );

        // Parse install script if present. The install= filename is frequently
        // written with variables (install="$pkgname.install"), and the install
        // hook is exactly where install-time payloads (CHAOS RAT, Atomic Arch)
        // live -- so resolution must expand variables and fall back to globbing.
        let dir = path.parent().unwrap_or(Path::new("."));
        let install_path = resolve_install_path(dir, &pkgbuild);
        let install_script = if let Some(install_path) = install_path {
            match read_text_capped(&install_path) {
                Ok(script_content) => Some(parser::ParsedInstallScript {
                    content: script_content.clone(),
                    path: install_path,
                    hooks: parser::parse_install_hooks(&script_content),
                }),
                Err(e) => {
                    warn!(
                        "Failed to read install script {}: {}",
                        install_path.display(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        };
        let scanned_install = install_script.as_ref().map(|s| s.path.clone());

        // Create analysis context
        let context = AnalysisContext {
            pkgbuild: pkgbuild.clone(),
            install_script,
            config: self.config.clone(),
            file_path: path.to_path_buf(),
        };

        // Run all analyzers
        let mut findings = Vec::new();
        for analyzer in &self.analyzers {
            match analyzer.analyze(&context).await {
                Ok(analyzer_findings) => {
                    debug!(
                        "Analyzer {} found {} issues",
                        analyzer.name(),
                        analyzer_findings.len()
                    );
                    findings.extend(analyzer_findings);
                }
                Err(e) => {
                    warn!("Analyzer {} failed: {}", analyzer.name(), e);
                }
            }
        }

        // Filter by minimum severity (lower enum value = higher severity)
        findings.retain(|f| f.severity <= self.config.min_severity);

        // Sort by severity (critical first)
        findings.sort_by_key(|f| f.severity);

        let duration = start.elapsed();
        info!(
            "Scan complete: {} findings in {:?}",
            findings.len(),
            duration
        );

        let mut scanned_files = vec![path.to_path_buf()];
        if let Some(install_path) = scanned_install {
            scanned_files.push(install_path);
        }

        Ok(ScanResult {
            package_name: pkgbuild.pkgname.first().cloned().unwrap_or_default(),
            package_version: format!("{}-{}", pkgbuild.pkgver, pkgbuild.pkgrel),
            findings,
            scanned_files,
            timestamp: chrono::Utc::now(),
            scan_duration_ms: duration.as_millis() as u64,
        })
    }

    /// Scan a directory containing a PKGBUILD
    pub async fn scan_directory(&self, dir: &Path) -> Result<ScanResult> {
        let pkgbuild_path = dir.join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Err(ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("PKGBUILD not found in {}", dir.display()),
            )));
        }
        self.scan_pkgbuild(&pkgbuild_path).await
    }
}

/// Resolve a key from an explicit config value first, then a list of
/// environment variables, returning the first non-empty match. Lets keys stay
/// out of config files (`VT_API_KEY` etc.) without hard-coding precedence at
/// each call site.
fn resolve_key(configured: Option<&String>, env_vars: &[&str]) -> Option<String> {
    configured
        .map(|s| s.to_string())
        .or_else(|| env_vars.iter().find_map(|v| std::env::var(v).ok()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Construct the opt-in threat-intel analyzer from config + environment.
///
/// VirusTotal is enabled by a key alone; URLhaus additionally requires
/// `urlhaus_enabled` (its `Auth-Key` is now mandatory). The verdict cache is
/// built from [`CacheConfig`] when caching is on; if the (hardened, owner-only)
/// cache dir cannot be created, we log and proceed without a cache rather than
/// fail the scan. Returns `None` if no provider ends up usable.
fn build_threat_intel_analyzer(config: &ScanConfig) -> Option<analyzer::ThreatIntelAnalyzer> {
    let ti = &config.threat_intel;
    let vt_key = resolve_key(
        ti.virustotal_api_key.as_ref(),
        &["VT_API_KEY", "VIRUSTOTAL_API_KEY"],
    );
    let urlhaus_key = if ti.urlhaus_enabled {
        resolve_key(ti.urlhaus_auth_key.as_ref(), &["URLHAUS_AUTH_KEY"])
    } else {
        None
    };

    let cache = if config.cache.enabled {
        match cache::DiskCache::new(config.cache.directory.clone(), config.cache.max_size_mb) {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                warn!("threat-intel cache disabled (cannot use cache dir): {e}");
                None
            }
        }
    } else {
        None
    };
    let ttl = std::time::Duration::from_secs(ti.cache_duration_hours.saturating_mul(3600));

    analyzer::ThreatIntelAnalyzer::new(vt_key, urlhaus_key, cache, ttl)
}

/// Maximum size of a file the scanner will read into memory. Real PKGBUILDs
/// and install scripts are a few KB; anything past this is abnormal and a
/// memory-exhaustion risk from a hostile repository.
const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Read a text file, refusing files larger than [`MAX_SCAN_FILE_BYTES`].
fn read_text_capped(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_SCAN_FILE_BYTES {
        warn!(
            "refusing to read {} ({} bytes > {} cap): possible resource-exhaustion attempt",
            path.display(),
            len,
            MAX_SCAN_FILE_BYTES
        );
        return Err(ScanError::Io(std::io::Error::other(format!(
            "file too large to scan safely: {len} bytes"
        ))));
    }
    Ok(std::fs::read_to_string(path)?)
}

/// Resolve the path to a package's install script.
///
/// PKGBUILDs commonly reference the install file via variables
/// (`install="$pkgname.install"`), and some omit `install=` while still
/// shipping a `*.install` hook. Both cases must be resolved, because the
/// install hook is a primary malware delivery vector. Resolution order:
/// 1. Expand `$pkgname`/`$pkgbase` in the declared `install=` value.
/// 2. Fall back to a single `*.install` file in the package directory.
fn resolve_install_path(
    dir: &Path,
    pkgbuild: &parser::ParsedPkgbuild,
) -> Option<std::path::PathBuf> {
    let pkgname = pkgbuild.pkgname.first().cloned().unwrap_or_default();

    if let Some(install_file) = &pkgbuild.install {
        let expanded = expand_pkg_vars(install_file, &pkgname);
        // An install scriptlet is always a bare filename inside the package
        // directory. Reject path separators / traversal so a hostile install=
        // value cannot make us read a file outside the cloned package dir.
        if expanded.is_empty() || expanded.contains('/') || expanded.contains("..") {
            warn!(
                "ignoring suspicious install= value '{}' (path traversal)",
                install_file
            );
        } else {
            let candidate = dir.join(&expanded);
            if candidate.is_file() {
                return Some(candidate);
            }
            warn!(
                "install= references '{}' (resolved '{}') but the file is missing; \
                 falling back to *.install discovery",
                install_file, expanded
            );
        }
    }

    // Fallback: a lone *.install file in the package directory.
    let mut install_files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("install"))
        .collect();
    install_files.sort();
    match install_files.len() {
        0 => None,
        1 => Some(install_files.remove(0)),
        _ => {
            // Prefer the one matching the package name; otherwise scan the first
            // and warn so the gap is visible rather than silent.
            let preferred = install_files
                .iter()
                .find(|p| p.file_stem().and_then(|s| s.to_str()) == Some(pkgname.as_str()))
                .cloned();
            if preferred.is_none() {
                warn!(
                    "multiple *.install files in {}; scanning '{}'",
                    dir.display(),
                    install_files[0].display()
                );
            }
            preferred.or_else(|| Some(install_files.remove(0)))
        }
    }
}

/// Expand the small set of PKGBUILD variables that legitimately appear in an
/// `install=` value: `$pkgname`/`${pkgname}` and `$pkgbase`/`${pkgbase}`.
fn expand_pkg_vars(value: &str, pkgname: &str) -> String {
    value
        .replace("${pkgname}", pkgname)
        .replace("$pkgname", pkgname)
        .replace("${pkgbase}", pkgname)
        .replace("$pkgbase", pkgname)
        .trim_matches(['"', '\''])
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = Scanner::with_defaults();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_install_path_rejects_traversal() {
        // A hostile install= value must not let resolution read outside the dir.
        let pkg = parser::ParsedPkgbuild {
            pkgname: vec!["x".into()],
            install: Some("../../../../etc/passwd".into()),
            ..Default::default()
        };
        let resolved = resolve_install_path(Path::new("/tmp/some-pkg-dir"), &pkg);
        assert!(resolved.is_none(), "traversal value must be rejected");
    }

    #[test]
    fn test_expand_pkg_vars() {
        assert_eq!(
            expand_pkg_vars("${pkgname}.install", "alvr"),
            "alvr.install"
        );
        assert_eq!(expand_pkg_vars("$pkgname.install", "alvr"), "alvr.install");
        assert_eq!(
            expand_pkg_vars("\"$pkgbase.install\"", "alvr"),
            "alvr.install"
        );
        assert_eq!(expand_pkg_vars("custom.install", "alvr"), "custom.install");
    }

    #[tokio::test]
    async fn test_scan_detects_install_hook_with_var_filename() {
        // Regression: install="${pkgname}.install" must still resolve so the
        // install-hook rules actually run.
        let scanner = Scanner::with_defaults().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/malicious/atomic-arch");
        if !fixture.join("PKGBUILD").exists() {
            return; // fixture not present in this checkout
        }
        let result = scanner.scan_directory(&fixture).await.unwrap();
        assert!(
            result.findings.iter().any(|f| f.id == "ATOMIC-001"),
            "expected ATOMIC-001 from the install hook; got: {:?}",
            result.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        assert!(result
            .scanned_files
            .iter()
            .any(|p| { p.extension().and_then(|e| e.to_str()) == Some("install") }));
    }
}
