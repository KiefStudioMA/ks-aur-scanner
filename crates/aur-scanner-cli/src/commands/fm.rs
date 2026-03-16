//! FileManager command for paru integration
//!
//! This command is designed to be used as paru's `FileManager` option,
//! providing automatic PKGBUILD security scanning during the review step.
//!
//! ## Setup
//!
//! Add to `~/.config/paru/paru.conf`:
//! ```ini
//! [bin]
//! FileManager = aur-scan fm
//! ```
//!
//! ## How it works
//!
//! When paru updates AUR packages, it invokes the FileManager with a
//! temporary view directory. This command:
//!
//! 1. Discovers all packages in the paru view
//! 2. Displays the PKGBUILD diff for each package
//! 3. Runs a full security scan
//! 4. Shows findings with severity-aware prompts
//! 5. Returns exit code 0 (proceed) or 1 (abort)

use anyhow::{Context, Result};
use aur_scanner_core::paru::{self, ParuViewPackage};
use aur_scanner_core::{ScanConfig, Scanner, Severity};
use colored::Colorize;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use crate::output;

/// Run the fm (FileManager) command
pub async fn run(
    path: PathBuf,
    fail_on: Option<Severity>,
    min_severity: Option<Severity>,
) -> Result<()> {
    // Discover packages in the paru view
    let packages = paru::discover_paru_view(&path).context(format!(
        "Failed to discover packages in paru view: {}",
        path.display()
    ))?;

    let total = packages.len();
    println!(
        "\n{} Scanning {} package(s)...\n",
        "aur-scan fm:".cyan().bold(),
        total
    );

    // Create scanner
    let mut config = ScanConfig::default();
    if let Some(severity) = min_severity {
        config.min_severity = severity;
    }
    let scanner = Scanner::new(config).context("Failed to create scanner")?;

    for (i, pkg) in packages.iter().enumerate() {
        if total > 1 {
            println!(
                "{} {} {}",
                format!("[{}/{}]", i + 1, total).dimmed(),
                pkg.name.white().bold(),
                "─".repeat(50).dimmed()
            );
        }

        if let Err(e) = process_package(&scanner, pkg, fail_on).await {
            // If the user aborted, propagate as an error (exit code 1)
            // so paru knows the review was rejected
            if e.to_string().contains("aborted") {
                return Err(e);
            }
            eprintln!("{} Failed to scan {}: {}", "Warning:".yellow(), pkg.name, e);
        }
    }

    Ok(())
}

/// Process a single package: show diff, scan, prompt
async fn process_package(
    scanner: &Scanner,
    pkg: &ParuViewPackage,
    fail_on: Option<Severity>,
) -> Result<()> {
    // Read and display diff
    let diff_text = paru::read_package_diff(pkg);
    if let Some(ref diff) = diff_text {
        display_diff(diff);
    }

    // Run security scan
    let result = scanner
        .scan_pkgbuild(&pkg.pkgbuild_path)
        .await
        .context(format!("Scan failed for {}", pkg.name))?;

    // Display findings
    if result.findings.is_empty() {
        println!(
            "\n{}  {} — {}\n",
            "✓".green().bold(),
            "No issues found".green(),
            pkg.name
        );
        return Ok(());
    }

    // Show findings
    let output_str = output::format_result(&result, output::OutputFormat::Text)?;
    println!("{}", output_str);

    // Print severity summary
    let counts = result.count_by_severity();
    let critical = counts.get(&Severity::Critical).unwrap_or(&0);
    let high = counts.get(&Severity::High).unwrap_or(&0);
    let medium = counts.get(&Severity::Medium).unwrap_or(&0);

    print!("  Summary: ");
    if *critical > 0 {
        print!("{} ", format!("{} CRITICAL", critical).red().bold());
    }
    if *high > 0 {
        print!("{} ", format!("{} HIGH", high).yellow().bold());
    }
    if *medium > 0 {
        print!("{} ", format!("{} MEDIUM", medium).cyan());
    }
    println!();

    // Check fail_on threshold
    if let Some(threshold) = fail_on {
        if result.has_severity_or_above(threshold) {
            anyhow::bail!(
                "Review aborted: findings at or above {} severity in {}",
                threshold,
                pkg.name
            );
        }
    }

    // Interactive prompt (only if connected to a terminal)
    if atty_is_interactive() {
        let proceed = prompt_user(&result)?;
        if !proceed {
            anyhow::bail!("Review aborted by user for {}", pkg.name);
        }
    }

    Ok(())
}

/// Display a unified diff with colored output
fn display_diff(diff_text: &str) {
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "  PKGBUILD DIFF".bold());
    println!("{}\n", "═".repeat(60).dimmed());

    for line in diff_text.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            println!("{}", line.green());
        } else if line.starts_with('-') && !line.starts_with("---") {
            println!("{}", line.red());
        } else if line.starts_with("@@") {
            println!("{}", line.cyan());
        } else {
            println!("{}", line.dimmed());
        }
    }
    println!();
}

/// Prompt the user based on the severity of findings
fn prompt_user(result: &aur_scanner_core::ScanResult) -> Result<bool> {
    let has_critical = result.has_critical();
    let has_high = result.has_severity_or_above(Severity::High);

    if has_critical {
        print!(
            "{} ",
            "CRITICAL issues detected. Continue anyway? [y/N]:"
                .red()
                .bold()
        );
    } else if has_high {
        print!(
            "{} ",
            "High-risk patterns found. Continue? [y/N]:".yellow().bold()
        );
    } else {
        print!("{} ", "Warnings found. Continue? [Y/n]:".yellow());
    }
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();

    if has_critical || has_high {
        // Default to No for critical/high
        Ok(answer == "y" || answer == "yes")
    } else {
        // Default to Yes for medium/low
        Ok(answer.is_empty() || answer == "y" || answer == "yes")
    }
}

/// Check if stdin is connected to a terminal
fn atty_is_interactive() -> bool {
    io::stdin().is_terminal()
}
