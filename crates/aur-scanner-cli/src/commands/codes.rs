//! List all detection codes, generated from the authoritative catalog.

use anyhow::Result;
use colored::Colorize;

use aur_scanner_core::catalog::Catalog;
use aur_scanner_core::Severity;

pub fn run(
    category: Option<&str>,
    format: &str,
    extra_rule_dirs: &[std::path::PathBuf],
) -> Result<()> {
    let catalog = Catalog::load_with(extra_rule_dirs);
    // The catalog enforces uniqueness; surface any problem loudly.
    if let Err(e) = catalog.validate() {
        eprintln!("{} {}", "catalog error:".red().bold(), e);
    }

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&catalog)?);
            return Ok(());
        }
        "markdown" | "md" => {
            print_markdown(&catalog);
            return Ok(());
        }
        _ => {}
    }

    println!("{}", "AUR Security Scanner - Detection Codes".bold());
    println!("{}", "=".repeat(60));
    println!(
        "{}",
        format!(
            "{} codes across {} categories\n",
            catalog.entries.len(),
            catalog.categories().len()
        )
        .dimmed()
    );

    let filter = category.map(|c| c.to_lowercase());
    for cat in catalog.categories() {
        if let Some(ref f) = filter {
            if !cat.to_lowercase().contains(f) {
                continue;
            }
        }
        let in_cat: Vec<_> = catalog
            .entries
            .iter()
            .filter(|e| e.category.to_string() == cat)
            .collect();
        if in_cat.is_empty() {
            continue;
        }
        println!("{}", format!("[{cat}]").cyan().bold());
        for e in in_cat {
            let sev = color_sev(e.severity);
            let owner = if e.owner == "rules" || e.owner == "user" {
                String::new()
            } else {
                format!(" ({})", e.owner).dimmed().to_string()
            };
            println!("  {} [{}] {}{}", e.id.green().bold(), sev, e.name, owner);
        }
        println!();
    }

    println!("{}", "Use 'aur-scan explain <CODE>' for details.".dimmed());
    println!(
        "{}",
        "Add your own: drop a .toml rule file in ~/.config/aur-scanner/rules.d/".dimmed()
    );
    Ok(())
}

/// Emit the full detection reference as Markdown, grouped by severity then
/// category. Used to keep the README and docs site in lockstep with the catalog.
fn print_markdown(catalog: &Catalog) {
    println!("# Detection Codes\n");
    println!(
        "_{} codes across {} categories. Generated from the catalog; do not edit by hand._\n",
        catalog.entries.len(),
        catalog.categories().len()
    );
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let rows: Vec<_> = catalog
            .entries
            .iter()
            .filter(|e| e.severity == sev)
            .collect();
        if rows.is_empty() {
            continue;
        }
        println!("## {} severity\n", sev);
        println!("| Code | Name | Category | Detector | CWE |");
        println!("|------|------|----------|----------|-----|");
        for e in rows {
            println!(
                "| `{}` | {} | {} | {} | {} |",
                e.id,
                e.name,
                e.category,
                e.owner,
                e.cwe.as_deref().unwrap_or("-")
            );
        }
        println!();
    }
}

fn color_sev(sev: Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => "Critical".red().bold(),
        Severity::High => "High".yellow(),
        Severity::Medium => "Medium".blue(),
        Severity::Low => "Low".white(),
        Severity::Info => "Info".dimmed(),
    }
}
