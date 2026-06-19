//! Output formatting for scan results

use anyhow::Result;
use aur_scanner_core::{Finding, OutputConfig, ScanResult, Severity};
use colored::Colorize;

/// Output format options
#[derive(Clone, Copy)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

/// Format a scan result according to the specified format.
///
/// `display` controls which fields the human-readable **text** output includes;
/// it is intentionally ignored by the JSON and SARIF formatters, which always
/// emit the complete record so CI and tooling are never blinded by a display
/// preference.
pub fn format_result(
    result: &ScanResult,
    format: OutputFormat,
    display: &OutputConfig,
) -> Result<String> {
    match format {
        OutputFormat::Text => format_text(result, display),
        OutputFormat::Json => format_json(result),
        OutputFormat::Sarif => format_sarif(result),
    }
}

fn format_text(result: &ScanResult, display: &OutputConfig) -> Result<String> {
    let mut output = String::new();

    output.push_str(&format!(
        "\n{} {}\n",
        "Scan Results:".bold(),
        result.package_name
    ));
    output.push_str(&format!("{}\n\n", "=".repeat(60)));

    if result.findings.is_empty() {
        output.push_str(&format!("{}\n", "No security issues found.".green()));
        return Ok(output);
    }

    for finding in &result.findings {
        output.push_str(&format_finding(finding, display));
        output.push('\n');
    }

    Ok(output)
}

fn format_finding(finding: &Finding, display: &OutputConfig) -> String {
    let mut output = String::new();

    let severity_badge = match finding.severity {
        Severity::Critical => "[CRITICAL]".red().bold().to_string(),
        Severity::High => "[HIGH]".yellow().bold().to_string(),
        Severity::Medium => "[MEDIUM]".cyan().to_string(),
        Severity::Low => "[LOW]".to_string(),
        Severity::Info => "[INFO]".dimmed().to_string(),
    };

    output.push_str(&format!(
        "{} {} {}\n",
        severity_badge,
        finding.id.bold(),
        finding.title
    ));
    output.push_str(&format!("    {}\n", finding.description));

    if display.line {
        if let Some(line) = finding.location.line {
            output.push_str(&format!(
                "    Location: {}:{}\n",
                finding.location.file.display(),
                line
            ));
        }
    }

    if display.snippet {
        if let Some(ref snippet) = finding.location.snippet {
            output.push_str(&format!("    Code: {}\n", snippet.dimmed()));
        }
    }

    if display.recommendation {
        output.push_str(&format!(
            "    Recommendation: {}\n",
            finding.recommendation.green()
        ));
    }

    if display.cwe {
        if let Some(ref cwe) = finding.cwe_id {
            output.push_str(&format!("    Reference: {}\n", cwe.dimmed()));
        }
    }

    output
}

fn format_json(result: &ScanResult) -> Result<String> {
    Ok(serde_json::to_string_pretty(result)?)
}

fn format_sarif(result: &ScanResult) -> Result<String> {
    // SARIF (Static Analysis Results Interchange Format)
    // https://sarifweb.azurewebsites.net/

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aur-scan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/kiefstudio/aur-security-scanner",
                    "rules": result.findings.iter().map(|f| {
                        serde_json::json!({
                            "id": f.id,
                            "name": f.title,
                            "shortDescription": {
                                "text": f.title
                            },
                            "fullDescription": {
                                "text": f.description
                            },
                            "help": {
                                "text": f.recommendation
                            },
                            "defaultConfiguration": {
                                "level": match f.severity {
                                    Severity::Critical | Severity::High => "error",
                                    Severity::Medium => "warning",
                                    _ => "note",
                                }
                            }
                        })
                    }).collect::<Vec<_>>()
                }
            },
            "results": result.findings.iter().map(|f| {
                serde_json::json!({
                    "ruleId": f.id,
                    "level": match f.severity {
                        Severity::Critical | Severity::High => "error",
                        Severity::Medium => "warning",
                        _ => "note",
                    },
                    "message": {
                        "text": f.description
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.location.file.to_string_lossy()
                            },
                            "region": {
                                "startLine": f.location.line.unwrap_or(1)
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aur_scanner_core::{Category, Location};
    use std::path::PathBuf;

    fn sample_finding() -> Finding {
        Finding {
            id: "ENV-003".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            title: "Bashrc/profile modification".to_string(),
            description: "desc".to_string(),
            location: Location {
                file: PathBuf::from("cdu.install"),
                line: Some(4),
                column: None,
                snippet: Some("source ~/.bashrc".to_string()),
            },
            recommendation: "review".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn rich_default_shows_every_field() {
        colored::control::set_override(false);
        let out = format_finding(&sample_finding(), &OutputConfig::default());
        assert!(out.contains("Location: cdu.install:4"));
        assert!(out.contains("Code: source ~/.bashrc"));
        assert!(out.contains("Recommendation: review"));
        assert!(out.contains("Reference: CWE-506"));
    }

    #[test]
    fn toggles_suppress_only_the_disabled_fields() {
        colored::control::set_override(false);
        let display = OutputConfig {
            line: false,
            snippet: false,
            recommendation: true,
            cwe: false,
        };
        let out = format_finding(&sample_finding(), &display);
        assert!(!out.contains("Location:"), "line disabled: {out}");
        assert!(!out.contains("Code:"), "snippet disabled: {out}");
        assert!(!out.contains("Reference:"), "cwe disabled: {out}");
        assert!(out.contains("Recommendation: review"), "rec stays: {out}");
        // The finding header (severity + id + title) is never gated away.
        assert!(out.contains("ENV-003") && out.contains("Bashrc/profile modification"));
    }
}
