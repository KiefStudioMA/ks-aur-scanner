//! IOC database inspection command.

use anyhow::Result;
use colored::Colorize;

use aur_scanner_core::threat_intel::{ioc::active_override_path, IocDatabase};

/// Show IOC database stats, or check a single name/value against it.
pub fn run(check: Option<&str>) -> Result<()> {
    let db = IocDatabase::load();

    if let Some(value) = check {
        return run_check(&db, value);
    }

    println!("{}", "AUR Security Scanner - IOC Database".bold());
    println!("{}", "=".repeat(60));
    println!();
    println!("  Schema version : {}", db.schema_version);
    println!("  Last updated   : {}", db.updated);
    match active_override_path() {
        Some(p) => println!("  Override file  : {}", p.display().to_string().green()),
        None => println!(
            "  Override file  : {}",
            "(none; embedded defaults only)".dimmed()
        ),
    }
    println!(
        "  Indicators     : {}",
        db.indicator_count().to_string().bold()
    );
    println!(
        "    npm/bun packages {}, fake AUR packages {}, file artifacts {}, domains {}, hashes {}",
        db.npm_packages.len(),
        db.aur_packages.len(),
        db.files.len(),
        db.domains.len(),
        db.sha256.len(),
    );
    println!();

    println!("{}", "Campaigns".cyan().bold());
    for c in &db.campaigns {
        println!(
            "  {} {}",
            c.id.green().bold(),
            format!("({})", c.date).dimmed()
        );
        println!("    {}", c.name.bold());
        if !c.description.is_empty() {
            println!("    {}", c.description);
        }
        if !c.reference.is_empty() {
            println!("    {}", c.reference.dimmed());
        }
        println!();
    }

    println!(
        "{}",
        "Add a feed file at /usr/share/aur-scanner/ioc.toml or \
         ~/.local/share/aur-scanner/ioc.toml to extend indicators."
            .dimmed()
    );
    Ok(())
}

fn run_check(db: &IocDatabase, value: &str) -> Result<()> {
    let mut matched = false;

    if let Some(campaign) = db.match_aur_package(value) {
        matched = true;
        report_hit(db, "known-malicious AUR package", value, campaign);
    }
    if let Some(campaign) = db.npm_packages.get(value) {
        matched = true;
        report_hit(db, "malicious npm/bun package", value, campaign);
    }
    if let Some(campaign) = db.files.get(value) {
        matched = true;
        report_hit(db, "payload file artifact", value, campaign);
    }
    if let Some(campaign) = db.match_sha256(value) {
        matched = true;
        report_hit(db, "malicious payload hash", value, campaign);
    }

    if !matched {
        println!(
            "{} '{}' is not a known indicator.",
            "OK:".green().bold(),
            value
        );
    }
    Ok(())
}

fn report_hit(db: &IocDatabase, kind: &str, value: &str, campaign_id: &str) {
    let campaign = db
        .campaign(campaign_id)
        .map(|c| format!("{} ({})", c.name, c.id))
        .unwrap_or_else(|| campaign_id.to_string());
    println!(
        "{} '{}' is a {} -- campaign: {}",
        "MATCH:".red().bold(),
        value.bold(),
        kind,
        campaign,
    );
}
