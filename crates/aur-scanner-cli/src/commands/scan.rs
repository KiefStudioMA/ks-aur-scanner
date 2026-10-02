//! Scan command implementation

use crate::output::{self, OutputFormat};
use anyhow::{Context, Result};
use aur_scanner_core::{Registry, ScanConfig, ScanResult, Scanner, Severity};
use colored::Colorize;
use std::path::PathBuf;

/// Run the scan command
#[allow(clippy::too_many_arguments)]
pub async fn run(
    path: PathBuf,
    format: crate::OutputFormat,
    output_path: Option<PathBuf>,
    fail_on: Option<Severity>,
    min_severity: Option<Severity>,
    include_info: bool,
    quiet: bool,
    mut config: ScanConfig,
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

    // Severity floor. An explicit --severity wins; otherwise --include-info
    // lowers the floor to Info so informational findings surface; otherwise we
    // keep whatever the config carries (Low by default).
    if let Some(severity) = min_severity {
        config.min_severity = severity;
    } else if include_info {
        config.min_severity = Severity::Info;
    }

    // Snapshot the display config before `config` is consumed by the scanner;
    // it controls only how the text output is rendered, not what is scanned.
    let display = config.output.clone();
    // `min_severity` trims what is SHOWN. The scan itself returns every finding
    // and `--fail-on` evaluates all of them, so a low display threshold (or a
    // user-writable config) can never switch a gate off.
    let shown_min = config.min_severity;

    // Create scanner
    let scanner = Scanner::new(config).context("Failed to create scanner")?;

    // Run scan
    tracing::info!("Scanning: {}", scan_path.display());
    let result = scanner
        // Deliberate: `scan <path>` is a local file scan with no package
        // identity to look up, so ownership and name-impersonation analysis
        // cannot run and must not guess.
        .scan_pkgbuild(&scan_path, Registry::None)
        .await
        .context("Scan failed")?;

    // Format output
    let format = match format {
        crate::OutputFormat::Text => OutputFormat::Text,
        crate::OutputFormat::Json => OutputFormat::Json,
        crate::OutputFormat::Sarif => OutputFormat::Sarif,
    };

    let shown = result.visible(shown_min);
    let gate_note = hidden_note(&result, &shown, shown_min, fail_on);
    // JSON and SARIF are the complete record: every finding, whatever the
    // display floor. Only the human text output is narrowed.
    let output_str = match format {
        OutputFormat::Text => {
            output::format_result(&shown, format, &display, gate_note.as_deref())?
        }
        _ => output::format_result(&result, format, &display, None)?,
    };

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
    // In quiet mode, show only the findings — suppress the summary block.
    if !quiet {
        let machine_format = !matches!(format, OutputFormat::Text);
        if machine_format && !wrote_to_file {
            print_summary(&shown, gate_note.is_some(), &mut std::io::stderr());
        } else {
            print_summary(&shown, gate_note.is_some(), &mut std::io::stdout());
        }
    }

    // Exit with appropriate code
    if let Some(threshold) = fail_on {
        if result.has_severity_or_above(threshold) {
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Explain findings the severity floor removed from the text view. When the
/// hidden findings are what trips `--fail-on`, say so: otherwise the output
/// reads "clean" while the exit code is 1.
fn hidden_note(
    full: &ScanResult,
    shown: &ScanResult,
    floor: Severity,
    fail_on: Option<Severity>,
) -> Option<String> {
    let hidden = full.findings.len() - shown.findings.len();
    if hidden == 0 {
        return None;
    }
    if let Some(gate) = fail_on {
        let gated = full
            .findings
            .iter()
            .filter(|f| !f.severity.is_at_least(floor) && f.severity.is_at_least(gate))
            .count();
        if gated > 0 {
            return Some(format!(
                "{gated} finding(s) at or above {gate} are hidden by --severity/min_severity; the gate tripped. Use --format json for the complete record."
            ));
        }
    }
    Some(format!(
        "{hidden} finding(s) below {floor} are hidden by --severity/min_severity."
    ))
}

fn print_summary<W: std::io::Write>(result: &ScanResult, filtered: bool, w: &mut W) {
    // Best-effort: a broken pipe / closed stderr must not crash the scan.
    let _ = write_summary(result, filtered, w);
}

fn write_summary<W: std::io::Write>(
    result: &ScanResult,
    filtered: bool,
    w: &mut W,
) -> std::io::Result<()> {
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
        if filtered {
            writeln!(w, "No findings at the displayed severity (see above).")?;
        } else {
            writeln!(w, "{}", "No security issues found.".green().bold())?;
        }
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
