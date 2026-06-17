//! System command - scan all installed AUR packages

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;

use aur_scanner_core::aur::{get_installed_aur_packages, AurClient};
use aur_scanner_core::{Scanner, Severity};

use super::banner;

/// Run the system scan command
pub async fn run(
    min_severity: Option<Severity>,
    rescan: bool,
    cache_dir: Option<PathBuf>,
) -> Result<()> {
    banner::print_header("System Audit");
    println!();

    // Get list of installed AUR packages
    println!("{}", "Getting installed AUR packages...".dimmed());
    let packages = get_installed_aur_packages()
        .await
        .context("Failed to get installed AUR packages")?;

    if packages.is_empty() {
        println!("{}", "No AUR packages installed.".green());
        return Ok(());
    }

    println!(
        "Found {} AUR packages installed",
        packages.len().to_string().white().bold()
    );
    println!();

    // Cross-reference installed package names against the IOC database FIRST.
    // This catches wholly-malicious packages by name even if their PKGBUILD is
    // not cached locally -- directly answering "am I affected?".
    let ioc_db = aur_scanner_core::threat_intel::IocDatabase::load();
    let name_hits: Vec<(&String, String)> = packages
        .iter()
        .filter_map(|p| {
            ioc_db.match_aur_package(p).map(|cid| {
                let label = ioc_db
                    .campaign(cid)
                    .map(|c| format!("{} ({})", c.name, c.id))
                    .unwrap_or_else(|| cid.to_string());
                (p, label)
            })
        })
        .collect();
    if name_hits.is_empty() {
        println!(
            "{} no installed package matches a known-malicious name indicator.",
            "IOC name check:".green().bold()
        );
    } else {
        println!(
            "{} {} installed package(s) match known-malicious indicators:",
            "IOC ALERT:".red().bold(),
            name_hits.len()
        );
        for (pkg, campaign) in &name_hits {
            println!("  {} -> {}", pkg.red().bold(), campaign);
        }
        println!(
            "  {}",
            "Remove these immediately and treat the host as compromised.".red()
        );
    }
    println!();

    // Determine where to find PKGBUILDs
    let cache_dirs = get_aur_cache_dirs(cache_dir);

    let scanner = Scanner::with_defaults().context("Failed to create scanner")?;
    let mut prov_store = aur_scanner_core::provenance::ProvenanceStore::load(
        aur_scanner_core::provenance::ProvenanceStore::default_path(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("epoch:{}", d.as_secs()))
        .unwrap_or_default();
    let client = if rescan {
        Some(AurClient::new().context("Failed to create AUR client")?)
    } else {
        None
    };

    let mut total_packages = 0;
    let mut packages_with_issues = 0;
    let mut total_critical = 0;
    let mut total_high = 0;
    let mut not_found = Vec::new();

    for package in &packages {
        // Try to find cached PKGBUILD
        let pkgbuild_path = if rescan {
            // Fetch fresh from AUR
            None
        } else {
            find_cached_pkgbuild(package, &cache_dirs)
        };

        let scan_result = if let Some(path) = pkgbuild_path {
            // Scan from cache
            print!("{} {} ", "Scanning:".dimmed(), package.white());

            match scanner.scan_pkgbuild(&path).await {
                Ok(result) => Some(result),
                Err(e) => {
                    println!("{}", format!("error: {}", e).red());
                    None
                }
            }
        } else if let Some(ref aur_client) = client {
            // Fetch and scan from AUR
            print!("{} {} ", "Fetching:".dimmed(), package.white());

            match aur_client.fetch_pkgbuild(package).await {
                Ok(fetched) => match scanner.scan_pkgbuild(&fetched.pkgbuild_path).await {
                    Ok(result) => Some(result),
                    Err(e) => {
                        println!("{}", format!("scan error: {}", e).red());
                        None
                    }
                },
                Err(e) => {
                    println!("{}", format!("fetch error: {}", e).red());
                    None
                }
            }
        } else {
            not_found.push(package.clone());
            continue;
        };

        if let Some(mut result) = scan_result {
            total_packages += 1;

            // Provenance: flag this package gaining risky behavior since the
            // last scan (the primary tell of an AUR hijack).
            let combined = result
                .scanned_files
                .iter()
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .collect::<Vec<_>>()
                .join("\n");
            if !combined.is_empty() {
                let anchor = result.scanned_files.first().cloned().unwrap_or_default();
                let prov = prov_store.evaluate(package, &combined, &now, &anchor);
                result.findings.extend(prov);
            }

            // Filter by severity
            let findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| {
                    if let Some(min) = min_severity {
                        f.severity <= min
                    } else {
                        f.severity <= Severity::High // Default to high and above
                    }
                })
                .collect();

            let critical = findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count();
            let high = findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count();

            if findings.is_empty() {
                println!("{}", "OK".green());
            } else {
                packages_with_issues += 1;
                total_critical += critical;
                total_high += high;

                print!("{}", "ISSUES: ".yellow());
                if critical > 0 {
                    print!("{} ", format!("{} critical", critical).red().bold());
                }
                if high > 0 {
                    print!("{} ", format!("{} high", high).yellow());
                }
                println!();

                // Print details for critical findings
                if critical > 0 {
                    for finding in findings.iter().filter(|f| f.severity == Severity::Critical) {
                        println!(
                            "    {} {} - {}",
                            finding.id.red(),
                            finding.title.red(),
                            finding.location.file.display()
                        );
                    }
                }
            }
        }
    }

    // Persist provenance baselines for next time.
    if let Err(e) = prov_store.save() {
        tracing::warn!("could not save provenance store: {}", e);
    }

    // Summary
    println!();
    println!("{}", "=".repeat(60));
    println!("{}", "System Scan Summary".cyan().bold());
    println!();

    println!(
        "  {} {} packages scanned",
        "Total:".dimmed(),
        total_packages
    );

    if packages_with_issues > 0 {
        println!(
            "  {} {} packages with issues",
            "Issues:".yellow(),
            packages_with_issues
        );
        println!(
            "  {} {} critical, {} high severity findings",
            "Severity:".dimmed(),
            total_critical.to_string().red().bold(),
            total_high.to_string().yellow()
        );
    } else {
        println!(
            "  {}",
            "No security issues found in installed AUR packages.".green()
        );
    }

    if !not_found.is_empty() {
        println!();
        println!(
            "  {} {} packages not found in cache (use --rescan to fetch from AUR):",
            "Skipped:".yellow(),
            not_found.len()
        );
        for pkg in &not_found {
            println!("    - {}", pkg.dimmed());
        }
    }

    println!();

    if packages_with_issues > 0 {
        println!(
            "{}",
            "Run 'aur-scan check <package>' for detailed analysis of specific packages.".dimmed()
        );
    }

    Ok(())
}

/// Get possible AUR helper cache directories
fn get_aur_cache_dirs(custom: Option<PathBuf>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(custom_dir) = custom {
        dirs.push(custom_dir);
    }

    // Default per-helper clone/build locations for maintained AUR helpers.
    // Resolved through the XDG base dirs so a user's XDG_CACHE_HOME /
    // XDG_DATA_HOME / XDG_CONFIG_HOME overrides are honored.
    if let Some(cache) = dirs::cache_dir() {
        dirs.push(cache.join("yay")); // yay
        dirs.push(cache.join("paru/clone")); // paru
        dirs.push(cache.join("aura/packages")); // aura
        dirs.push(cache.join("pakku")); // pakku
        dirs.push(cache.join("trizen/sources")); // trizen
        dirs.push(cache.join("aurutils/sync")); // aurutils
        dirs.push(cache.join("pat-aur/pkgbuild/aur")); // pat-aur
    }
    if let Some(data) = dirs::data_dir() {
        dirs.push(data.join("pikaur/aur_repos")); // pikaur (data dir, not cache)
    }
    if let Some(config) = dirs::config_dir() {
        dirs.push(config.join("rua/pkg")); // rua (config dir, not cache)
    }

    // Filter to existing directories
    dirs.into_iter().filter(|d| d.exists()).collect()
}

/// Find a cached PKGBUILD for a package
fn find_cached_pkgbuild(package: &str, cache_dirs: &[PathBuf]) -> Option<PathBuf> {
    for cache_dir in cache_dirs {
        let pkg_dir = cache_dir.join(package);
        let pkgbuild = pkg_dir.join("PKGBUILD");
        if pkgbuild.exists() {
            return Some(pkgbuild);
        }
    }
    None
}
