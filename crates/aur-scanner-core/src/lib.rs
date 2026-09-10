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
pub mod history;
pub mod neturl;
pub mod overlay;
pub mod parser;
pub mod provenance;
pub mod registry;
pub mod resolve;
pub mod rules;
pub mod sbom;
pub mod squat;
pub mod textutil;
pub mod threat_intel;
pub mod types;
pub mod validate;

pub use error::{ParseError, Result, ScanError};
pub use types::*;

use analyzer::SecurityAnalyzer;
use parser::PkgbuildParser;
use rules::RuleEngine;
use std::path::{Path, PathBuf};
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
        // Built-in rules + the standard rules.d dirs, plus any custom rules
        // directory the config points at (so `rules_path` actually reaches the
        // matching engine, not just the catalog listing).
        let mut engine = RuleEngine::default();
        if let Some(rules_path) = config.rules_path.as_ref() {
            if let Err(e) = engine.load_rules_from_dir(rules_path) {
                warn!(
                    "failed to load custom rules from {}: {}",
                    rules_path.display(),
                    e
                );
            }
        }
        let rule_engine = Arc::new(engine);
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
            Arc::new(analyzer::SquatAnalyzer::new()),
            Arc::new(analyzer::OwnershipAnalyzer::new()),
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

    /// The minimum severity this scanner reports.
    ///
    /// Exposed so that findings produced *after* a scan returns -- change
    /// detection compares against stored history, which the scan itself cannot
    /// do -- can be filtered by the same threshold. Otherwise `DIFF-*` would
    /// appear at severities the operator had explicitly filtered out, while
    /// every other code obeyed the setting.
    pub fn min_severity(&self) -> Severity {
        self.config.min_severity
    }

    /// The IOC database backing this scanner (embedded defaults + overrides).
    pub fn ioc_database(&self) -> Arc<IocDatabase> {
        self.ioc_db.clone()
    }

    /// Create a scanner with **built-in** configuration only (no config file).
    ///
    /// Prefer [`Self::with_system_config`] for user-facing gates (CLI install,
    /// `aur-scan-wrap`, hook already resolves explicitly) so XDG/`/etc` settings
    /// such as threat-intel are honored. This method stays pure for unit tests
    /// and callers that must not touch the filesystem.
    pub fn with_defaults() -> Result<Self> {
        Self::new(ScanConfig::default())
    }

    /// Create a scanner using the same config discovery as the CLI without
    /// `-c` and the pacman hook: first existing path among
    /// `$XDG_CONFIG_HOME/aur-scanner/config.toml` (or `~/.config/...`) and
    /// `/etc/aur-scanner/config.toml`, else built-in defaults.
    ///
    /// A present-but-malformed file is a hard error (fail closed) — the same
    /// contract as [`ScanConfig::resolve`].
    pub fn with_system_config() -> Result<Self> {
        let (config, path) = ScanConfig::resolve(None)?;
        if let Some(p) = &path {
            debug!("loaded scanner config from {}", p.display());
        }
        Self::new(config)
    }

    /// Load rules from a directory
    pub fn load_rules(&mut self, rules_dir: &Path) -> Result<()> {
        Arc::get_mut(&mut self.rule_engine)
            .ok_or_else(|| ScanError::Config("Cannot modify rule engine".into()))?
            .load_rules_from_dir(rules_dir)?;
        Ok(())
    }

    /// Scan a PKGBUILD file.
    ///
    /// `registry` is required and has no default **on purpose**. It selects
    /// between the full analyzer set and a strictly smaller one, and an earlier
    /// version of this API offered a convenient `scan_pkgbuild(path)` that
    /// passed `None` for you. Every new call site took it: seven of the eight
    /// callers in this workspace silently ran the reduced set, including
    /// `install`, the AUR-helper wrapper, and the pacman hook — the three paths
    /// that actually gate an installation. Nothing in the type system or the
    /// test suite noticed, because a reduced scan is not an error, it is just
    /// quieter.
    ///
    /// Naming the choice fixes that: a caller must write [`Registry::None`] to
    /// get the reduced set, which is greppable, reviewable, and impossible to
    /// reach by omission.
    pub async fn scan_pkgbuild(&self, path: &Path, registry: Registry) -> Result<ScanResult> {
        let registry = registry.into_context();
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
        // ALPM .hook files ship next to the PKGBUILD in some attack waves and
        // are installed into /usr/share/libalpm/hooks/ — scan them as side
        // scriptlets. Never execute; text only.
        let mut side_scripts = discover_alpm_hooks(dir);
        // Files the PKGBUILD pulls in from the package directory itself --
        // patches, sidecar shell scripts, .service units. These were previously
        // never read at all, so a payload in `0001-fix.patch`, or a
        // `. ./helper.sh` that moves every interesting line out of the file
        // under review, was completely invisible. They go through the same rule
        // surface as an install scriptlet; never executed.
        side_scripts.extend(discover_local_sources(dir, &pkgbuild));
        let scanned_install = install_script.as_ref().map(|s| s.path.clone());

        // Create analysis context
        let context = AnalysisContext {
            pkgbuild: pkgbuild.clone(),
            install_script,
            side_scripts,
            config: self.config.clone(),
            file_path: path.to_path_buf(),
            registry,
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

    /// Scan a directory containing a PKGBUILD.
    ///
    /// `registry` is required for the same reason as on [`Self::scan_pkgbuild`].
    pub async fn scan_directory(&self, dir: &Path, registry: Registry) -> Result<ScanResult> {
        let pkgbuild_path = dir.join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Err(ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("PKGBUILD not found in {}", dir.display()),
            )));
        }
        self.scan_pkgbuild(&pkgbuild_path, registry).await
    }
}

/// Whether a scan is performed with knowledge of what the package registry says.
///
/// Deliberately not an `Option<RegistryContext>`. This is the switch between the
/// full analyzer set and a strictly reduced one, and an `Option` makes the
/// reduced path the ergonomic default that every new call site falls into by
/// accident — which is exactly what happened: seven of eight callers passed
/// `None` without anyone choosing to.
#[derive(Debug, Clone)]
pub enum Registry {
    /// The caller looked the package up and is supplying what it found.
    ///
    /// Enables the ownership analyzer (`OWN-*`), name-impersonation analysis
    /// (`SQUAT-*`), and the operator's `[[owned_namespaces]]` declarations.
    From(RegistryContext),

    /// No registry lookup was performed, and the scan is knowingly reduced.
    ///
    /// `OWN-*` and `SQUAT-*` emit **nothing** on this path — not "no findings",
    /// but "not evaluated". Correct for a bare `scan <path>`, for `diff` (which
    /// compares two directories with no package identity), and for the pacman
    /// hook (offline by design). Wrong anywhere the package name was resolved
    /// through the AUR, because there the information was already in hand.
    None,
}

impl Registry {
    fn into_context(self) -> Option<RegistryContext> {
        match self {
            Registry::From(ctx) => Some(ctx),
            Registry::None => None,
        }
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
///
/// Public so every caller that touches package-controlled files -- including the
/// CLI's history and diff paths -- shares one cap rather than each reaching for
/// `std::fs::read_to_string`.
pub fn read_text_capped(path: &Path) -> Result<String> {
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

/// Read the local (non-remote) entries of `source=()` so their contents are
/// analyzed rather than merely counted.
///
/// A `source=()` entry with no scheme is a file shipped in the package
/// directory. Two well-known techniques live there and were previously
/// invisible: a build fix `.patch` that quietly adds a command to a Makefile,
/// and a sidecar script the PKGBUILD `source`s so that the file a reviewer reads
/// contains almost nothing.
///
/// Everything here is read as text and capped; binary blobs are skipped rather
/// than force-decoded. Path handling refuses anything that is not a plain
/// relative name inside the package directory, so a hostile
/// `source=('../../etc/shadow')` cannot make the scanner read outside the tree.
fn discover_local_sources(
    dir: &Path,
    pkgbuild: &parser::ParsedPkgbuild,
) -> Vec<parser::ParsedInstallScript> {
    let mut out = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();

    for entry in &pkgbuild.source {
        if entry.protocol.is_remote() {
            continue;
        }
        // makepkg fetches a renamed source as the rename; otherwise the entry
        // itself is the filename.
        let name = entry.filename.clone().unwrap_or_else(|| entry.url.clone());
        let name = name.trim();

        // Plain relative filename only. No separators, no traversal, no
        // absolute paths, no shell metacharacters left unexpanded.
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.contains("..")
            || name.starts_with('.')
            || name.contains('$')
        {
            if !name.is_empty() {
                debug!("not reading local source {name:?}: not a plain in-directory filename");
            }
            continue;
        }

        let path = dir.join(name);
        if !path.is_file() || seen.contains(&path) {
            continue;
        }
        seen.push(path.clone());

        match read_text_capped(&path) {
            Ok(content) => {
                // Skip anything that is not text: a NUL byte means a binary
                // blob, and running text rules over decoded binary produces
                // noise, not findings.
                if content.contains('\0') {
                    debug!("skipping binary local source {}", path.display());
                    continue;
                }
                out.push(parser::ParsedInstallScript {
                    hooks: parser::parse_install_hooks(&content),
                    content,
                    path,
                });
            }
            Err(e) => debug!("could not read local source {}: {e}", path.display()),
        }
    }
    out
}

/// Discover ALPM hook files (`*.hook`) beside the PKGBUILD.
///
/// Atomic Arch wave 4 delivered payload via `.hook` files installed into
/// `/usr/share/libalpm/hooks/`. These are not referenced by `install=`, so a
/// scanner that only reads the install scriptlet misses them. Each discovered
/// file is read as text (capped) and returned for static analysis — never
/// executed. Path components are the directory listing only (no attacker-
/// controlled name expansion).
fn discover_alpm_hooks(dir: &Path) -> Vec<parser::ParsedInstallScript> {
    let mut hooks: Vec<parser::ParsedInstallScript> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hooks;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension().and_then(|e| e.to_str()) == Some("hook")
                // Refuse odd names that look like traversal even though
                // read_dir only yields direct children.
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| !n.is_empty() && !n.starts_with('.') && !n.contains(".."))
        })
        .collect();
    paths.sort();
    for path in paths {
        match read_text_capped(&path) {
            Ok(content) => hooks.push(parser::ParsedInstallScript {
                content: content.clone(),
                path,
                hooks: parser::parse_install_hooks(&content),
            }),
            Err(e) => {
                warn!("Failed to read ALPM hook {}: {}", path.display(), e);
            }
        }
    }
    hooks
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
    fn with_system_config_matches_resolve() {
        // Same discovery path as ScanConfig::resolve(None): built-in defaults
        // when no file exists, hard error only when a present file is bad.
        let a = Scanner::with_system_config();
        let b = ScanConfig::resolve(None).and_then(|(c, _)| Scanner::new(c));
        assert_eq!(a.is_ok(), b.is_ok());
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
        let result = scanner
            .scan_directory(&fixture, Registry::None)
            .await
            .unwrap();
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
