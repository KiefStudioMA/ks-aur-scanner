//! AUR helper plugin library
//!
//! Provides integration capabilities for AUR helpers like yay and paru.

use aur_scanner_core::{ScanConfig, ScanResult, Scanner, Severity};
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

    /// Create a plugin with default configuration
    pub fn with_defaults() -> Result<Self, aur_scanner_core::ScanError> {
        Self::new(ScanConfig::default())
    }

    /// Set whether to prompt user interactively
    pub fn set_interactive(&mut self, interactive: bool) {
        self.interactive = interactive;
    }

    /// Scan a package directory before building
    pub async fn pre_build_scan(
        &self,
        package_dir: &Path,
    ) -> Result<ScanResult, aur_scanner_core::ScanError> {
        self.scanner.scan_directory(package_dir).await
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
