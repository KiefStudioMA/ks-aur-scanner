//! AUR helper plugin library
//!
//! Provides integration capabilities for AUR helpers like yay and paru.

use aur_scanner_core::{Registry, ScanConfig, ScanResult, Scanner, Severity};
use colored::Colorize;
use std::io::{self, Write};
use std::path::Path;

/// Plugin for AUR helper integration
pub struct AurScannerPlugin {
    scanner: Scanner,
    interactive: bool,
}

impl AurScannerPlugin {
    /// Create a new plugin instance
    pub fn new(config: ScanConfig) -> Result<Self, aur_scanner_core::ScanError> {
        Ok(Self {
            scanner: Scanner::new(config)?,
            interactive: true,
        })
    }

    /// Create a plugin using the same config discovery as `aur-scan` / the
    /// pacman hook (XDG user config, then `/etc`, else built-in defaults).
    ///
    /// Malformed config files are hard errors. For unit tests that must ignore
    /// on-disk config, use [`Self::new`] with [`ScanConfig::default`].
    pub fn with_system_config() -> Result<Self, aur_scanner_core::ScanError> {
        let (config, _) = ScanConfig::resolve(None)?;
        Self::new(config)
    }

    /// Built-in engine defaults only (no config file load).
    ///
    /// Prefer [`Self::with_system_config`] for real AUR-helper gates so threat
    /// intel and other file settings apply. Kept for tests and explicit pure
    /// defaults.
    pub fn with_defaults() -> Result<Self, aur_scanner_core::ScanError> {
        Self::new(ScanConfig::default())
    }

    /// Set whether to prompt user interactively
    pub fn set_interactive(&mut self, interactive: bool) {
        self.interactive = interactive;
    }

    /// Scan a package directory before building.
    ///
    /// `registry` is required rather than defaulted: it selects between the
    /// full analyzer set and a strictly smaller one. An embedder that has
    /// already resolved the package through the AUR should pass
    /// [`Registry::From`] so ownership (`OWN-*`) and name-impersonation
    /// (`SQUAT-*`) analysis runs; one scanning an arbitrary directory should
    /// pass [`Registry::None`] and know that those codes are *not evaluated*
    /// rather than clean.
    pub async fn pre_build_scan(
        &self,
        package_dir: &Path,
        registry: Registry,
    ) -> Result<ScanResult, aur_scanner_core::ScanError> {
        self.scanner.scan_directory(package_dir, registry).await
    }

    /// Display scan results and optionally prompt user
    ///
    /// Returns true if installation should proceed, false to abort
    pub fn handle_results(&self, result: &ScanResult) -> bool {
        if result.findings.is_empty() {
            println!(
                "{} No security issues found in {}",
                "OK:".green().bold(),
                result.package_name
            );
            return true;
        }

        println!();
        println!(
            "{} Security Scan Results for {}",
            "SCAN:".cyan().bold(),
            result.package_name.bold()
        );
        println!("{}", "=".repeat(60));

        for finding in &result.findings {
            let severity_str = match finding.severity {
                Severity::Critical => "[CRITICAL]".red().bold().to_string(),
                Severity::High => "[HIGH]".yellow().bold().to_string(),
                Severity::Medium => "[MEDIUM]".cyan().to_string(),
                Severity::Low => "[LOW]".to_string(),
                Severity::Info => "[INFO]".dimmed().to_string(),
            };

            println!();
            println!("{} {} {}", severity_str, finding.id.bold(), finding.title);
            println!("    {}", finding.description);
            println!("    {}", finding.recommendation.green());
        }

        println!();
        println!("{}", "=".repeat(60));

        // Check for critical issues. In non-interactive mode every prompt below
        // fails closed (deny): there is no one to confirm an override, so the
        // safe default is to abort rather than proceed.
        if result.has_critical() {
            println!(
                "{} Critical security issues detected!",
                "ERROR:".red().bold()
            );

            if self.interactive {
                if !prompt_typed_yes("Continue anyway? (type 'yes' to confirm): ") {
                    println!("Installation aborted.");
                    return false;
                }
            } else {
                println!("Aborting due to critical issues (non-interactive mode).");
                return false;
            }
        } else if result.has_severity_or_above(Severity::High) {
            println!(
                "{} High severity issues detected.",
                "WARNING:".yellow().bold()
            );

            if self.interactive {
                if !prompt_default_no("Continue with installation? [y/N]: ") {
                    println!("Installation aborted.");
                    return false;
                }
            } else {
                // High findings, no one to confirm: abort.
                println!("Aborting due to high-severity issues (non-interactive mode).");
                return false;
            }
        } else if self.interactive {
            // Only low/medium/info remain; default to proceeding but honor "no".
            if !prompt_default_yes("Continue with installation? [Y/n]: ") {
                println!("Installation aborted.");
                return false;
            }
        }

        true
    }
}

/// Prompt requiring the literal word `yes`. Any read error / EOF is a refusal.
fn prompt_typed_yes(prompt: &str) -> bool {
    read_response(prompt)
        .map(|r| r.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// `[y/N]` prompt: defaults to NO, and a read error / EOF is a refusal.
fn prompt_default_no(prompt: &str) -> bool {
    read_response(prompt)
        .map(|r| matches!(r.trim().to_lowercase().as_str(), "y" | "yes"))
        .unwrap_or(false)
}

/// `[Y/n]` prompt: defaults to YES; only an explicit no aborts. A read error /
/// EOF is treated as the default (yes) since no security threshold was crossed.
fn prompt_default_yes(prompt: &str) -> bool {
    match read_response(prompt) {
        Ok(r) => !matches!(r.trim().to_lowercase().as_str(), "n" | "no"),
        Err(_) => true,
    }
}

/// Print `prompt`, flush, and read one line. Returns an error on EOF or I/O
/// failure so callers can apply their own fail-open/closed default.
fn read_response(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut response = String::new();
    if io::stdin().read_line(&mut response)? == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aur_scanner_core::types::{Category, Finding, Location, ScanResult};
    use std::path::PathBuf;

    fn result_with(sev: Option<Severity>) -> ScanResult {
        let findings = sev
            .map(|s| {
                vec![Finding {
                    id: "TST-001".into(),
                    severity: s,
                    category: Category::MaliciousCode,
                    title: "test".into(),
                    description: "test finding".into(),
                    location: Location {
                        file: PathBuf::from("PKGBUILD"),
                        line: Some(1),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "review".into(),
                    cwe_id: None,
                    metadata: serde_json::Value::Null,
                }]
            })
            .unwrap_or_default();
        ScanResult {
            package_name: "p".into(),
            package_version: "1-1".into(),
            findings,
            scanned_files: vec![],
            timestamp: chrono::Utc::now(),
            scan_duration_ms: 0,
        }
    }

    fn plugin(interactive: bool) -> AurScannerPlugin {
        let mut p = AurScannerPlugin::with_defaults().expect("plugin");
        p.set_interactive(interactive);
        p
    }

    // The core security contract: with no human to confirm an override, anything
    // at or above High must DENY (return false), never proceed.
    #[test]
    fn non_interactive_denies_critical() {
        assert!(!plugin(false).handle_results(&result_with(Some(Severity::Critical))));
    }

    #[test]
    fn non_interactive_denies_high() {
        assert!(!plugin(false).handle_results(&result_with(Some(Severity::High))));
    }

    // Below the gate (medium/low/info) there is no threshold to refuse, so a
    // non-interactive run proceeds rather than blocking every package forever.
    #[test]
    fn non_interactive_allows_medium_and_below() {
        assert!(plugin(false).handle_results(&result_with(Some(Severity::Medium))));
        assert!(plugin(false).handle_results(&result_with(Some(Severity::Low))));
        assert!(plugin(false).handle_results(&result_with(Some(Severity::Info))));
    }

    #[test]
    fn clean_result_proceeds() {
        assert!(plugin(false).handle_results(&result_with(None)));
    }
}
