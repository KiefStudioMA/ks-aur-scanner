//! Output formatting for scan results

use anyhow::Result;
use aur_scanner_core::textutil::sanitize_for_terminal;
use aur_scanner_core::{Finding, OutputConfig, ScanResult, Severity};
use colored::Colorize;
use std::collections::HashMap;
use std::path::{Component, Path};

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

    // Findings quote package-controlled text (source URLs, pkgnames, matched
    // snippets) into their title and description. Printed raw, an escape
    // sequence in any of those lets the scanned file drive the terminal --
    // cursor movement can overwrite the severity that was just printed. JSON
    // and SARIF do not need this: serde escapes control characters, and those
    // consumers are programs.
    output.push_str(&format!(
        "{} {} {}\n",
        severity_badge,
        finding.id.bold(),
        sanitize_for_terminal(&finding.title)
    ));
    output.push_str(&format!(
        "    {}\n",
        sanitize_for_terminal(&finding.description)
    ));

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
            // The snippet is verbatim package text -- the single most likely
            // place for an injected escape sequence.
            output.push_str(&format!(
                "    Code: {}\n",
                sanitize_for_terminal(snippet).dimmed()
            ));
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

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}

/// Longest directory that contains every scanned/reported file, used as the
/// SARIF `%SRCROOT%` so artifact URIs are relative and stable across machines
/// instead of leaking absolute local paths. `None` when there is no common
/// directory (e.g. mixed absolute and relative paths).
fn sarif_root(result: &ScanResult) -> Option<std::path::PathBuf> {
    let mut dirs = result
        .scanned_files
        .iter()
        .chain(result.findings.iter().map(|f| &f.location.file))
        .map(|p| p.parent().map(Path::to_path_buf).unwrap_or_default());
    let first = dirs.next()?;
    let mut common: Vec<_> = first.components().collect();
    for d in dirs {
        let comps: Vec<_> = d.components().collect();
        let n = common
            .iter()
            .zip(&comps)
            .take_while(|(a, b)| a == b)
            .count();
        common.truncate(n);
    }
    if common.is_empty() && first.is_absolute() {
        return None;
    }
    Some(common.iter().collect())
}

/// Percent-encode a path into a SARIF URI reference (forward slashes).
/// Returns the URI and whether it is relative to the `%SRCROOT%` base.
fn sarif_uri(path: &Path, root: Option<&Path>) -> (String, bool) {
    let (rel, relative) = match root.and_then(|r| path.strip_prefix(r).ok()) {
        Some(r) => (r, true),
        None => (path, false),
    };
    let joined = rel
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    let joined = if relative || !path.is_absolute() {
        joined
    } else {
        format!("/{joined}")
    };
    let mut out = String::new();
    for b in joined.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    (out, relative)
}

fn format_sarif(result: &ScanResult) -> Result<String> {
    // SARIF (Static Analysis Results Interchange Format)
    // https://sarifweb.azurewebsites.net/

    // One driver rule per distinct id (the schema requires unique items); each
    // result points at its rule with `ruleIndex`.
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_index: HashMap<&str, usize> = HashMap::new();
    for f in &result.findings {
        rule_index.entry(f.id.as_str()).or_insert_with(|| {
            rules.push(serde_json::json!({
                "id": f.id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "help": { "text": f.recommendation },
                "defaultConfiguration": { "level": sarif_level(f.severity) }
            }));
            rules.len() - 1
        });
    }

    let root = sarif_root(result);
    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            let (uri, relative) = sarif_uri(&f.location.file, root.as_deref());
            let mut artifact = serde_json::json!({ "uri": uri });
            if relative {
                artifact["uriBaseId"] = serde_json::json!("%SRCROOT%");
            }
            let mut physical = serde_json::json!({ "artifactLocation": artifact });
            // Only claim a line when the finding has one; a fabricated
            // `startLine: 1` points reviewers at the wrong place.
            if let Some(line) = f.location.line {
                physical["region"] = serde_json::json!({ "startLine": line });
            }
            serde_json::json!({
                "ruleId": f.id,
                "ruleIndex": rule_index[f.id.as_str()],
                "level": sarif_level(f.severity),
                "message": { "text": f.description },
                "locations": [{ "physicalLocation": physical }]
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aur-scan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/kiefstudio/aur-security-scanner",
                    "rules": rules
                }
            },
            "results": results
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

    fn result_with(findings: Vec<Finding>, scanned: Vec<PathBuf>) -> ScanResult {
        serde_json::from_value(serde_json::json!({
            "package_name": "p",
            "package_version": "1-1",
            "findings": findings,
            "scanned_files": scanned,
            "timestamp": "2026-01-01T00:00:00Z",
            "scan_duration_ms": 0
        }))
        .unwrap()
    }

    #[test]
    fn sarif_rules_are_unique_and_indexed() {
        let mut a = sample_finding();
        a.location.file = PathBuf::from("/work/pkg/PKGBUILD");
        let mut b = a.clone();
        b.location.line = Some(9);
        let mut c = a.clone();
        c.id = "OTHER-1".into();
        let res = result_with(vec![a, b, c], vec![PathBuf::from("/work/pkg/PKGBUILD")]);
        let v: serde_json::Value = serde_json::from_str(&format_sarif(&res).unwrap()).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "duplicate rules: {rules:?}");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        for r in results {
            let idx = r["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"], r["ruleId"]);
        }
    }

    #[test]
    fn sarif_omits_region_without_line_and_uses_relative_uri() {
        let mut f = sample_finding();
        f.location.file = PathBuf::from("/work/pkg/PKGBUILD");
        f.location.line = None;
        let res = result_with(vec![f], vec![PathBuf::from("/work/pkg/PKGBUILD")]);
        let v: serde_json::Value = serde_json::from_str(&format_sarif(&res).unwrap()).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert!(loc.get("region").is_none(), "fabricated region: {loc}");
        assert_eq!(loc["artifactLocation"]["uri"], "PKGBUILD");
        assert_eq!(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%");
    }

    #[test]
    fn sarif_uri_is_relative_to_common_root_and_encoded() {
        let mut a = sample_finding();
        a.location.file = PathBuf::from("/work/my pkg/PKGBUILD");
        let mut b = sample_finding();
        b.location.file = PathBuf::from("/work/my pkg/sub/x.install");
        let res = result_with(vec![a, b], vec![PathBuf::from("/work/my pkg/PKGBUILD")]);
        let v: serde_json::Value = serde_json::from_str(&format_sarif(&res).unwrap()).unwrap();
        let uri = |i: usize| {
            v["runs"][0]["results"][i]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(uri(0), "PKGBUILD");
        assert_eq!(uri(1), "sub/x.install");
    }
}
