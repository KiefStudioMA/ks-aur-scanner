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
    let wrote_to_file = output_path.is_some();
    if let Some(output_file) = output_path {
        std::fs::write(&output_file, &output_str)
            .context(format!("Failed to write to {}", output_file.display()))?;
        tracing::info!("Results written to: {}", output_file.display());
    } else {
        println!("{}", output_str);
    }

    // Print the human summary. For a machine-readable format written to stdout,
    // the summary would corrupt the JSON/SARIF stream (`aur-scan scan --format
    // json | jq` must work), so send it to stderr instead. When the machine
    // output went to a file, or for the text format, stdout is free for it.
    let machine_format = !matches!(format, OutputFormat::Text);
    if machine_format && !wrote_to_file {
        print_summary(&result, &mut std::io::stderr());
    } else {
        print_summary(&result, &mut std::io::stdout());
    }

    // Exit with appropriate code
    if let Some(threshold) = fail_on {
        if result.has_severity_or_above(threshold) {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_summary<W: std::io::Write>(result: &ScanResult, w: &mut W) {
    // Best-effort: a broken pipe / closed stderr must not crash the scan.
    let _ = write_summary(result, w);
}

fn write_summary<W: std::io::Write>(result: &ScanResult, w: &mut W) -> std::io::Result<()> {
    let counts = result.count_by_severity();

    let critical = counts.get(&Severity::Critical).unwrap_or(&0);
    let high = counts.get(&Severity::High).unwrap_or(&0);
    let medium = counts.get(&Severity::Medium).unwrap_or(&0);
    let low = counts.get(&Severity::Low).unwrap_or(&0);

    writeln!(w)?;
    writeln!(w, "{}", "=".repeat(60))?;
    writeln!(
        w,
        "Package: {} v{}",
        result.package_name.bold(),
        result.package_version
    )?;
    writeln!(w, "Scan duration: {}ms", result.scan_duration_ms)?;
    writeln!(w)?;

    if result.findings.is_empty() {
        writeln!(w, "{}", "No security issues found.".green().bold())?;
    } else {
        writeln!(
            w,
            "Found {} issue(s):",
            result.findings.len().to_string().bold()
        )?;
        if *critical > 0 {
            writeln!(
                w,
                "  {} {}",
                critical.to_string().red().bold(),
                "CRITICAL".red()
            )?;
        }
        if *high > 0 {
            writeln!(
                w,
                "  {} {}",
                high.to_string().yellow().bold(),
                "HIGH".yellow()
            )?;
        }
        if *medium > 0 {
            writeln!(w, "  {} {}", medium.to_string().cyan(), "MEDIUM".cyan())?;
        }
        if *low > 0 {
            writeln!(w, "  {} LOW", low)?;
        }
    }
    writeln!(w, "{}", "=".repeat(60))?;
    Ok(())
}
