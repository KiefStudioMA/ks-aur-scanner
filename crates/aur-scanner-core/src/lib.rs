//! AUR Security Scanner Core Library
//!
//! Provides security analysis capabilities for Arch Linux AUR packages.
//! Detects malicious patterns in PKGBUILDs and install scripts.

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod analyzer;
pub mod aur;
pub mod cache;
pub mod error;
pub mod parser;
pub mod rules;
pub mod threat_intel;
pub mod types;

pub use error::{ParseError, Result, ScanError};
pub use types::*;

use analyzer::SecurityAnalyzer;
use parser::PkgbuildParser;
use rules::RuleEngine;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Main scanner that orchestrates all security analysis
pub struct Scanner {
    analyzers: Vec<Arc<dyn SecurityAnalyzer>>,
    parser: Box<dyn PkgbuildParser>,
    rule_engine: Arc<RuleEngine>,
    config: ScanConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Result<Self> {
        // Use default() which loads built-in rules
        let rule_engine = Arc::new(RuleEngine::default());

        let analyzers: Vec<Arc<dyn SecurityAnalyzer>> = vec![
            Arc::new(analyzer::PatternAnalyzer::new(rule_engine.clone())),
            Arc::new(analyzer::SourceAnalyzer::new()),
            Arc::new(analyzer::ChecksumAnalyzer::new()),
            Arc::new(analyzer::PrivilegeAnalyzer::new()),
        ];

        let parser: Box<dyn PkgbuildParser> = Box::new(parser::StaticParser::new());

        Ok(Self {
            analyzers,
            parser,
            rule_engine,
            config,
        })
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

        // Read and parse PKGBUILD
        let content = std::fs::read_to_string(path)?;
        let pkgbuild = self.parser.parse(&content)?;

        debug!(
            "Parsed package: {} version {}-{}",
            pkgbuild.pkgname.first().unwrap_or(&"unknown".to_string()),
            pkgbuild.pkgver,
            pkgbuild.pkgrel
        );

        // Parse install script if present
        let install_script = if let Some(ref install_file) = pkgbuild.install {
            let install_path = path.parent().unwrap_or(Path::new(".")).join(install_file);
            if install_path.exists() {
                let script_content = std::fs::read_to_string(&install_path)?;
                Some(parser::ParsedInstallScript {
                    content: script_content.clone(),
                    path: install_path,
                    hooks: parser::parse_install_hooks(&script_content),
                })
            } else {
                None
            }
        } else {
            None
        };

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
        findings.sort_by(|a, b| a.severity.cmp(&b.severity));

        let duration = start.elapsed();
        info!(
            "Scan complete: {} findings in {:?}",
            findings.len(),
            duration
        );

        Ok(ScanResult {
            package_name: pkgbuild.pkgname.first().cloned().unwrap_or_default(),
            package_version: format!("{}-{}", pkgbuild.pkgver, pkgbuild.pkgrel),
            findings,
            scanned_files: vec![path.to_path_buf()],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = Scanner::with_defaults();
        assert!(scanner.is_ok());
    }
}
