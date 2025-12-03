//! Pacman hook for AUR security scanning
//!
//! This binary is invoked by pacman before package transactions
//! to scan AUR packages for security issues.

use anyhow::Result;
use aur_scanner_core::{ScanConfig, Scanner, Severity};
use colored::Colorize;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .init();

    // Load configuration
    let config_path = PathBuf::from("/etc/aur-scanner/config.toml");
    let config = if config_path.exists() {
        // TODO: Load from file
        ScanConfig::default()
    } else {
        ScanConfig::default()
    };

    let scanner = Scanner::new(config)?;

    // Read package names from stdin (pacman hook provides this)
    let stdin = io::stdin();
    let packages: Vec<String> = stdin
        .lock()
        .lines()
        .map_while(Result::ok)
        .collect();

    let mut has_critical = false;
    let mut has_high = false;

    for package in packages {
        // Try to find PKGBUILD in common cache locations
        if let Some(pkgbuild_path) = find_pkgbuild_for_package(&package) {
            match scanner.scan_pkgbuild(&pkgbuild_path).await {
                Ok(result) => {
                    if !result.findings.is_empty() {
                        eprintln!();
                        eprintln!(
                            "{} Security findings for {}:",
                            "WARNING:".yellow().bold(),
                            package.bold()
                        );

                        for finding in &result.findings {
                            let severity_str = match finding.severity {
                                Severity::Critical => "CRITICAL".red().bold(),
                                Severity::High => "HIGH".yellow().bold(),
                                Severity::Medium => "MEDIUM".cyan(),
                                Severity::Low => "LOW".normal(),
                                Severity::Info => "INFO".dimmed(),
                            };

                            eprintln!("  [{}] {}: {}", severity_str, finding.id, finding.title);

                            if finding.severity == Severity::Critical {
                                has_critical = true;
                            }
                            if finding.severity == Severity::High {
                                has_high = true;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to scan {}: {}", package, e);
                }
            }
        }
    }

    if has_critical {
        eprintln!();
        eprintln!(
            "{} Critical security issues found. Aborting transaction.",
            "ERROR:".red().bold()
        );
        eprintln!("Use 'aur-scan scan <package-dir>' for details.");
        eprintln!();
        std::process::exit(1);
    }

    if has_high {
        eprintln!();
        eprintln!(
            "{} High severity issues found. Review recommended.",
            "WARNING:".yellow().bold()
        );
        eprintln!();
    }

    Ok(())
}

/// Find PKGBUILD for a package in common cache locations
fn find_pkgbuild_for_package(package: &str) -> Option<PathBuf> {
    // Get the user who invoked sudo (if applicable)
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());

    let cache_dirs = vec![
        format!("/home/{}/.cache/yay/{}", user, package),
        format!("/home/{}/.cache/paru/clone/{}", user, package),
        format!("/home/{}/.cache/pikaur/aur_repos/{}", user, package),
        format!("/home/{}/.cache/trizen/{}", user, package),
        format!("/var/cache/aur/{}", package),
    ];

    for dir in cache_dirs {
        let pkgbuild = PathBuf::from(&dir).join("PKGBUILD");
        if pkgbuild.exists() {
            return Some(pkgbuild);
        }
    }

    None
}
