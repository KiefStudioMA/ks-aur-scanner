//! `aur-scan diff` -- compare two versions of a package.
//!
//! Scans both sides and reports what moved: findings that appeared, findings
//! that were resolved, and the structural changes (maintainer, upstream,
//! install scripts) that a severity count alone would hide.
//!
//! This is the manual-review and CI counterpart to the automatic
//! change-detection that `check` and `install` perform against the scan
//! history. Same comparison engine; this one takes both sides explicitly and
//! keeps no state, so it is safe to run in a pipeline.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

use aur_scanner_core::history::{compare, PackageRecord};
use aur_scanner_core::parser::{PkgbuildParser, StaticParser};
use aur_scanner_core::{Finding, ScanConfig, Scanner, Severity};

/// Output format for the diff.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiffFormat {
    Text,
    Json,
}

/// Scan one side and return its result plus the parsed PKGBUILD.
async fn scan_side(
    scanner: &Scanner,
    dir: &Path,
) -> Result<(
    aur_scanner_core::ScanResult,
    aur_scanner_core::parser::ParsedPkgbuild,
)> {
    let pkgbuild_path = if dir.is_dir() {
        dir.join("PKGBUILD")
    } else {
        dir.to_path_buf()
    };
    if !pkgbuild_path.is_file() {
        bail!("no PKGBUILD at {}", pkgbuild_path.display());
    }
    let content = std::fs::read_to_string(&pkgbuild_path)
        .with_context(|| format!("reading {}", pkgbuild_path.display()))?;
    let parsed = StaticParser::new()
        .parse(&content)
        .with_context(|| format!("parsing {}", pkgbuild_path.display()))?;
    let result = scanner
        .scan_pkgbuild(&pkgbuild_path)
        .await
        .with_context(|| format!("scanning {}", pkgbuild_path.display()))?;
    Ok((result, parsed))
}

/// Read every package-side script beside a PKGBUILD, so the diff can tell an
/// install scriptlet appearing from one merely changing.
fn side_scripts(dir: &Path) -> Vec<String> {
    let dir = if dir.is_dir() {
        dir.to_path_buf()
    } else {
        dir.parent().unwrap_or(Path::new(".")).to_path_buf()
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("install") | Some("hook")
                )
        })
        .collect();
    paths.sort();
    paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect()
}

/// Run the diff.
pub async fn run(
    old: PathBuf,
    new: PathBuf,
    format: DiffFormat,
    fail_on: Option<Severity>,
    config: ScanConfig,
) -> Result<()> {
    let scanner = Scanner::new(config).context("Failed to create scanner")?;

    let (old_result, old_pkg) = scan_side(&scanner, &old).await?;
    let (new_result, new_pkg) = scan_side(&scanner, &new).await?;

    let old_record =
        PackageRecord::from_scan(&old_result, &old_pkg, None).with_scripts(&side_scripts(&old));
    let new_record =
        PackageRecord::from_scan(&new_result, &new_pkg, None).with_scripts(&side_scripts(&new));
    let changes = compare(&old_record, &new_record);

    // Partition findings by whether the other side raised the same code.
    let old_ids: std::collections::BTreeSet<&str> =
        old_result.findings.iter().map(|f| f.id.as_str()).collect();
    let new_ids: std::collections::BTreeSet<&str> =
        new_result.findings.iter().map(|f| f.id.as_str()).collect();

    let added: Vec<&Finding> = new_result
        .findings
        .iter()
        .filter(|f| !old_ids.contains(f.id.as_str()))
        .collect();
    let removed: Vec<&Finding> = old_result
        .findings
        .iter()
        .filter(|f| !new_ids.contains(f.id.as_str()))
        .collect();
    let unchanged = new_result
        .findings
        .iter()
        .filter(|f| old_ids.contains(f.id.as_str()))
        .count();

    match format {
        DiffFormat::Json => {
            let doc = serde_json::json!({
                "old": { "package": old_record.package, "version": old_record.version },
                "new": { "package": new_record.package, "version": new_record.version },
                "added": added,
                "removed": removed,
                "unchanged_count": unchanged,
                "changes": {
                    "pkgbuild_changed": changes.pkgbuild_changed,
                    "scripts_changed": changes.scripts_changed,
                    "scripts_added": changes.scripts_added,
                    "origins_added": changes.origins_added,
                    "origins_removed": changes.origins_removed,
                    "functions_added": changes.functions_added,
                },
            });
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        DiffFormat::Text => {
            println!(
                "{} {} {} {} {}",
                "Comparing".bold(),
                old_record.version.yellow(),
                "->".dimmed(),
                new_record.version.green(),
                format!("({})", new_record.package).dimmed()
            );
            println!();

            // Compute the structural list up front so "nothing changed" can be
            // stated plainly. A bare header after a routine version bump reads
            // like the tool gave up rather than like a clean result.
            let mut structural: Vec<String> = Vec::new();
            if changes.scripts_added {
                structural.push("gained an install script (runs as root)".to_string());
            } else if changes.scripts_changed {
                structural.push("install script changed".to_string());
            }
            for o in &changes.origins_added {
                structural.push(format!("now fetches from {o}"));
            }
            for o in &changes.origins_removed {
                structural.push(format!("no longer fetches from {o}"));
            }
            for f in &changes.functions_added {
                structural.push(format!("new {f}() function"));
            }

            if added.is_empty() && removed.is_empty() && structural.is_empty() {
                println!(
                    "  {}",
                    "No findings changed and no structural differences.".green()
                );
                if changes.pkgbuild_changed {
                    println!(
                        "  {}",
                        "(the PKGBUILD text differs, but nothing security-relevant moved)".dimmed()
                    );
                }
                println!();
            }

            if !added.is_empty() {
                println!("{} ({})", "ADDED".red().bold(), added.len());
                for f in &added {
                    println!(
                        "  {} {:<9} {}  {}",
                        "+".red(),
                        f.severity.to_string(),
                        f.id,
                        f.title
                    );
                }
                println!();
            }
            if !removed.is_empty() {
                println!("{} ({})", "RESOLVED".green().bold(), removed.len());
                for f in &removed {
                    println!(
                        "  {} {:<9} {}  {}",
                        "-".green(),
                        f.severity.to_string(),
                        f.id,
                        f.title
                    );
                }
                println!();
            }

            // Structural movement a severity count would hide.
            if !structural.is_empty() {
                println!("{}", "STRUCTURAL CHANGES".yellow().bold());
                for s in &structural {
                    println!("  {} {}", "~".yellow(), s);
                }
                println!();
            }

            if unchanged > 0 {
                println!(
                    "{}",
                    format!("{unchanged} finding(s) carried over unchanged").dimmed()
                );
            }
        }
    }

    // Exit code reflects only what is NEW. A package that still has its
    // long-standing Medium findings has not regressed, and a diff gate that
    // trips on pre-existing state cannot be used to approve an update.
    if let Some(threshold) = fail_on {
        if added.iter().any(|f| f.severity.is_at_least(threshold)) {
            std::process::exit(1);
        }
    }
    Ok(())
}
