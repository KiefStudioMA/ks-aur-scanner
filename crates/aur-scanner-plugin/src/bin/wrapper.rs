//! AUR helper wrapper
//!
//! Wraps yay/paru to add security scanning before package installation.
//!
//! Usage:
//!   aur-scan-wrap paru -S package
//!   aur-scan-wrap yay -S package1 package2
//!
//! Can be aliased:
//!   alias paru='aur-scan-wrap paru'

use anyhow::{Context, Result};
use aur_scanner_core::aur::{is_aur_package, AurClient};
use aur_scanner_core::{Scanner, Severity};
use colored::Colorize;
use std::env;
use std::io::{self, Write};
use std::process::{Command, Stdio, ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args: Vec<String> = env::args().collect();

    // Need at least: wrapper helper [args...]
    if args.len() < 2 {
        print_usage();
        return Ok(ExitCode::FAILURE);
    }

    let helper = &args[1];
    let helper_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    // Check if this is an install/sync operation that might involve AUR
    let is_sync = helper_args.iter().any(|a| {
        *a == "-S" || a.starts_with("-S") || *a == "--sync"
    });

    // Check for flags that shouldn't trigger scanning
    let is_search = helper_args.iter().any(|a| a.contains('s') && a.starts_with('-') && !a.starts_with("--"));
    let is_query = helper_args.iter().any(|a| *a == "-Q" || a.starts_with("-Q"));
    let is_info = helper_args.iter().any(|a| a.contains('i') && a.starts_with('-'));

    if !is_sync || is_search || is_query || is_info {
        // Not an install operation, just pass through
        return run_helper(helper, &helper_args);
    }

    // Extract package names (arguments that don't start with -)
    let packages: Vec<&str> = helper_args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .copied()
        .collect();

    if packages.is_empty() {
        // No packages specified (maybe -Syu), pass through
        return run_helper(helper, &helper_args);
    }

    // Filter to only AUR packages
    let mut aur_packages = Vec::new();
    for pkg in &packages {
        match is_aur_package(pkg).await {
            Ok(true) => aur_packages.push(*pkg),
            Ok(false) => {} // Official repo package, skip
            Err(_) => aur_packages.push(*pkg), // Assume AUR if check fails
        }
    }

    if aur_packages.is_empty() {
        // No AUR packages, pass through
        return run_helper(helper, &helper_args);
    }

    println!();
    println!(
        "{} Pre-scanning {} AUR package(s)...",
        "AUR Security Scanner:".cyan().bold(),
        aur_packages.len()
    );
    println!("{}", "=".repeat(60));

    let client = AurClient::new().context("Failed to create AUR client")?;
    let scanner = Scanner::with_defaults().context("Failed to create scanner")?;

    let mut all_passed = true;
    let mut critical_found = false;

    for package in &aur_packages {
        println!();
        print!("{} {}... ", "Checking:".dimmed(), package.white().bold());
        io::stdout().flush()?;

        // Fetch PKGBUILD from AUR
        let fetched = match client.fetch_pkgbuild(package).await {
            Ok(f) => f,
            Err(e) => {
                println!("{}", format!("fetch failed: {}", e).yellow());
                all_passed = false;
                continue;
            }
        };

        // Scan
        let result = match scanner.scan_pkgbuild(&fetched.pkgbuild_path).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("scan failed: {}", e).yellow());
                all_passed = false;
                continue;
            }
        };

        // Filter to high and above
        let findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity <= Severity::High)
            .collect();

        if findings.is_empty() {
            println!("{}", "OK".green());
        } else {
            all_passed = false;
            let crit_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
            let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();

            if crit_count > 0 {
                critical_found = true;
                print!("{} ", format!("{} CRITICAL", crit_count).red().bold());
            }
            if high_count > 0 {
                print!("{} ", format!("{} HIGH", high_count).yellow());
            }
            println!();

            // Show critical findings
            for finding in findings.iter().filter(|f| f.severity == Severity::Critical) {
                println!(
                    "  {} {} - {}",
                    finding.id.red(),
                    finding.title,
                    finding.description
                );
            }
        }
    }

    println!();
    println!("{}", "=".repeat(60));

    // Prompt based on findings
    if critical_found {
        println!(
            "{}",
            "CRITICAL security issues detected!".red().bold()
        );
        println!();
        print!(
            "{} ",
            "Type 'yes' to proceed anyway, or press Enter to abort:".yellow()
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() != "yes" {
            println!("{}", "Installation aborted.".yellow());
            return Ok(ExitCode::FAILURE);
        }

        println!("{}", "User accepted risks.".dimmed());
    } else if !all_passed {
        print!(
            "{} ",
            "Some issues found. Continue? [Y/n]:".yellow()
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "n" {
            println!("{}", "Installation aborted.".yellow());
            return Ok(ExitCode::FAILURE);
        }
    }

    println!();
    println!("{}", "Proceeding with installation...".green());
    println!();

    run_helper(helper, &helper_args)
}

fn run_helper(helper: &str, args: &[&str]) -> Result<ExitCode> {
    let status = Command::new(helper)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context(format!("Failed to run {}", helper))?;

    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(status.code().unwrap_or(1) as u8)
    })
}

fn print_usage() {
    eprintln!("AUR Security Scanner Wrapper");
    eprintln!();
    eprintln!("Usage: aur-scan-wrap <helper> [args...]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  aur-scan-wrap paru -S package");
    eprintln!("  aur-scan-wrap yay -S package1 package2");
    eprintln!();
    eprintln!("Setup as alias:");
    eprintln!("  alias paru='aur-scan-wrap paru'");
    eprintln!("  alias yay='aur-scan-wrap yay'");
}
