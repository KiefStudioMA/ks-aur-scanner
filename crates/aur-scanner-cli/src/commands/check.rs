//! Check command - fetch and scan a package from AUR before installation

use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, Write};

use aur_scanner_core::aur::AurClient;
use aur_scanner_core::{Scanner, Severity};

use super::banner;
use crate::output;

/// Run the check command - fetch package from AUR and scan it
pub async fn run(
    package_names: Vec<String>,
    min_severity: Option<Severity>,
    interactive: bool,
    fail_on: Option<Severity>,
) -> Result<()> {
    let client = AurClient::new().context("Failed to create AUR client")?;
    let scanner = Scanner::with_defaults().context("Failed to create scanner")?;

    let mut total_critical = 0;
    let mut total_high = 0;
    let mut all_passed = true;

    for (idx, package_name) in package_names.iter().enumerate() {
        if idx == 0 {
            banner::print_header("Pre-Install Check");
        }

        println!();
        println!(
            "{} {}",
            "Package:".cyan().bold(),
            package_name.white().bold()
        );
        banner::print_divider();

        // Fetch package info first
        match client.get_package_info(package_name).await {
            Ok(info) => {
                print_package_info(&info);
                println!();
            }
            Err(e) => {
                println!("{} {}", "Error:".red().bold(), e);
                all_passed = false;
                continue;
            }
        }

        // Fetch and scan PKGBUILD
        println!("{}", "Fetching PKGBUILD...".dimmed());

        let fetched = match client.fetch_pkgbuild(package_name).await {
            Ok(f) => f,
            Err(e) => {
                println!("{} {}", "Failed to fetch:".red().bold(), e);
                all_passed = false;
                continue;
            }
        };

        println!(
            "{} {}",
            "Scanning:".dimmed(),
            fetched.pkgbuild_path.display()
        );

        let result = scanner
            .scan_pkgbuild(&fetched.pkgbuild_path)
            .await
            .context("Scan failed")?;

        // Filter by severity if specified
        let findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| {
                if let Some(min) = min_severity {
                    f.severity <= min
                } else {
                    true
                }
            })
            .collect();

        // Count severity levels
        let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low_count = findings.iter().filter(|f| f.severity == Severity::Low).count();

        total_critical += critical_count;
        total_high += high_count;

        println!();

        if findings.is_empty() {
            println!(
                "{}",
                "No security issues found.".green().bold()
            );
        } else {
            // Print findings
            for finding in &findings {
                output::print_finding(finding);
            }

            println!();
            println!("{}", "=".repeat(60));
            print!("Found ");
            if critical_count > 0 {
                print!("{} ", format!("{} CRITICAL", critical_count).red().bold());
            }
            if high_count > 0 {
                print!("{} ", format!("{} HIGH", high_count).yellow().bold());
            }
            if medium_count > 0 {
                print!("{} ", format!("{} MEDIUM", medium_count).blue());
            }
            if low_count > 0 {
                print!("{} ", format!("{} LOW", low_count).white());
            }
            println!("issue(s)");
        }

        // Check fail condition
        if let Some(fail_severity) = fail_on {
            let should_fail = findings.iter().any(|f| f.severity <= fail_severity);
            if should_fail {
                all_passed = false;
            }
        }

        // Interactive prompt
        if interactive && !findings.is_empty() {
            println!();
            if critical_count > 0 {
                println!(
                    "{}",
                    "WARNING: Critical security issues detected!".red().bold()
                );
            }

            print!(
                "{} ",
                "Proceed with installation? [y/N]:".yellow().bold()
            );
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            if input != "y" && input != "yes" {
                println!("{}", "Installation aborted by user.".yellow());
                all_passed = false;
            } else {
                println!("{}", "User accepted risks, proceeding...".dimmed());
            }
        }

        println!();
    }

    // Summary for multiple packages
    if package_names.len() > 1 {
        println!("{}", "=".repeat(60));
        println!("{}", "Summary".cyan().bold());
        println!(
            "Scanned {} packages: {} CRITICAL, {} HIGH issues total",
            package_names.len(),
            total_critical,
            total_high
        );
    }

    if all_passed {
        Ok(())
    } else {
        anyhow::bail!("Security issues detected or user aborted")
    }
}

fn print_package_info(info: &aur_scanner_core::aur::AurPackageInfo) {
    println!(
        "  {} {} {}",
        "Package:".dimmed(),
        info.name.white().bold(),
        format!("v{}", info.version).dimmed()
    );

    if let Some(ref desc) = info.description {
        println!("  {} {}", "Description:".dimmed(), desc);
    }

    if let Some(ref maintainer) = info.maintainer {
        println!("  {} {}", "Maintainer:".dimmed(), maintainer);
    } else {
        println!(
            "  {} {}",
            "Maintainer:".dimmed(),
            "ORPHAN (no maintainer!)".red().bold()
        );
    }

    if let Some(votes) = info.num_votes {
        let popularity = info.popularity.unwrap_or(0.0);
        println!(
            "  {} {} votes, {:.2} popularity",
            "Votes:".dimmed(),
            votes,
            popularity
        );
    }

    if info.out_of_date.is_some() {
        println!(
            "  {} {}",
            "Status:".dimmed(),
            "OUT OF DATE".yellow().bold()
        );
    }

    // Check for warning signs
    let mut warnings = Vec::new();

    if info.maintainer.is_none() {
        warnings.push("Package is orphaned - higher risk of malicious takeover");
    }

    if let Some(votes) = info.num_votes {
        if votes < 5 {
            warnings.push("Very few votes - package may be new or unknown");
        }
    }

    if let Some(popularity) = info.popularity {
        if popularity < 0.1 {
            warnings.push("Low popularity - limited community vetting");
        }
    }

    if !warnings.is_empty() {
        println!();
        println!("  {}", "Warnings:".yellow().bold());
        for warning in warnings {
            println!("  {} {}", "-".yellow(), warning.yellow());
        }
    }
}
