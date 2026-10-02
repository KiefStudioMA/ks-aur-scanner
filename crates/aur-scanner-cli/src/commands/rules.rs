//! `aur-scan rules`: the detection rule listing.
//!
//! Generated from the authoritative catalog (the same source as `aur-scan
//! codes`), never from a hand-maintained list, so names and severities cannot
//! drift from what the scanner really emits.

use anyhow::Result;
use aur_scanner_core::catalog::{Catalog, CatalogEntry};
use aur_scanner_core::Severity;
use colored::Colorize;

/// Run the rules command
pub fn run(
    severity_filter: Option<Severity>,
    details: bool,
    extra_rule_dirs: &[std::path::PathBuf],
) -> Result<()> {
    let catalog = Catalog::load_with(extra_rule_dirs);
    println!();
    println!("{}", "Available Detection Rules".bold().underline());
    println!();

    let shown = select(&catalog, severity_filter);
    for e in &shown {
        println!(
            "{} [{}] {}",
            e.id.bold(),
            format_severity(e.severity),
            e.name
        );
        if details {
            println!("    {}", e.description.dimmed());
            println!();
        }
    }

    println!();
    println!(
        "Total rules loaded: {} (shown: {})",
        catalog.entries.len(),
        shown.len()
    );
    Ok(())
}

/// Catalog entries to list, in catalog order, optionally limited to a severity.
fn select(catalog: &Catalog, severity_filter: Option<Severity>) -> Vec<&CatalogEntry> {
    catalog
        .entries
        .iter()
        .filter(|e| severity_filter.is_none_or(|s| e.severity == s))
        .collect()
}

fn format_severity(severity: Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MEDIUM".cyan().to_string(),
        Severity::Low => "LOW".to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_listing_is_the_catalog() {
        // Cannot drift: the listing is exactly the catalog, same ids, severities
        // and names, and a severity filter only narrows it.
        let catalog = Catalog::load();
        let all = select(&catalog, None);
        assert_eq!(all.len(), catalog.entries.len());
        for (listed, entry) in all.iter().zip(&catalog.entries) {
            assert_eq!(listed.id, entry.id);
            assert_eq!(listed.severity, entry.severity);
            assert_eq!(listed.name, entry.name);
        }
        let crit = select(&catalog, Some(Severity::Critical));
        assert!(!crit.is_empty());
        assert!(crit.iter().all(|e| e.severity == Severity::Critical));
        // The previously stale entry: PERSIST-002 is a Critical systemd timer.
        let p2 = catalog.get("PERSIST-002").unwrap();
        assert_eq!(p2.severity, Severity::Critical);
    }
}
