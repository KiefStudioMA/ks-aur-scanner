//! Scan command implementation

use crate::output::{self, OutputFormat};
use anyhow::{Context, Result};
use aur_scanner_core::{ScanConfig, ScanResult, Scanner, Severity};
use colored::Colorize;
use std::path::PathBuf;

/// Run the scan command
pub async fn run(
    path: PathBuf,
    format: crate::OutputFormat,
    output_path: Option<PathBuf>,
    fail_on: Option<Severity>,
    min_severity: Option<Severity>,
    include_info: bool,
) -> Result<()> {
    // Determine if path is file or directory
    let scan_path = if path.is_dir() {
        path.join("PKGBUILD")
    } else {
        path.clone()
    };

    if !scan_path.exists() {
        anyhow::bail!("PKGBUILD not found at: {}", scan_path.display());
    }

    // Create scanner configuration
    let mut config = ScanConfig::default();
    if let Some(severity) = min_severity {
        config.min_severity = severity;
    } else if !include_info {
        config.min_severity = Severity::Low;
    }

    // Create scanner
    let scanner = Scanner::new(config).context("Failed to create scanner")?;

    // Run scan
    tracing::info!("Scanning: {}", scan_path.display());
    let result = scanner
        .scan_pkgbuild(&scan_path)
        .await
        .context("Scan failed")?;

    // Format output
    let format = match format {
        crate::OutputFormat::Text => OutputFormat::Text,
        crate::OutputFormat::Json => OutputFormat::Json,
        crate::OutputFormat::Sarif => OutputFormat::Sarif,
    };

    let output_str = output::format_result(&result, format)?;

    // Write output
    if let Some(output_file) = output_path {
        std::fs::write(&output_file, &output_str)
            .context(format!("Failed to write to {}", output_file.display()))?;
        tracing::info!("Results written to: {}", output_file.display());
    } else {
        println!("{}", output_str);
    }

    // Print summary
    print_summary(&result);

    // Exit with appropriate code
    if let Some(threshold) = fail_on {
        if result.has_severity_or_above(threshold) {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_summary(result: &ScanResult) {
    let counts = result.count_by_severity();

    let critical = counts.get(&Severity::Critical).unwrap_or(&0);
    let high = counts.get(&Severity::High).unwrap_or(&0);
    let medium = counts.get(&Severity::Medium).unwrap_or(&0);
    let low = counts.get(&Severity::Low).unwrap_or(&0);

    println!();
    println!("{}", "=".repeat(60));
    println!(
        "Package: {} v{}",
        result.package_name.bold(),
        result.package_version
    );
    println!("Scan duration: {}ms", result.scan_duration_ms);
    println!();

    if result.findings.is_empty() {
        println!("{}", "No security issues found.".green().bold());
    } else {
        println!(
            "Found {} issue(s):",
            result.findings.len().to_string().bold()
        );
        if *critical > 0 {
            println!("  {} {}", critical.to_string().red().bold(), "CRITICAL".red());
        }
        if *high > 0 {
            println!("  {} {}", high.to_string().yellow().bold(), "HIGH".yellow());
        }
        if *medium > 0 {
            println!("  {} {}", medium.to_string().cyan(), "MEDIUM".cyan());
        }
        if *low > 0 {
            println!("  {} LOW", low);
        }
    }
    println!("{}", "=".repeat(60));
}
