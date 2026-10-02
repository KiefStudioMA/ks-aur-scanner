//! System command - scan all installed AUR packages

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;

use aur_scanner_core::aur::{get_installed_aur_packages, AurClient, PackageInfoSource};
use aur_scanner_core::registry;
use aur_scanner_core::{Registry, ScanConfig, Scanner, Severity};
use std::collections::HashMap;

use super::banner;

/// Run the system scan command
pub async fn run(
    min_severity: Option<Severity>,
    fail_on: Severity,
    rescan: bool,
    cache_dir: Option<PathBuf>,
    config: ScanConfig,
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

    // Build the scanner from the loaded config so a `-c/--config` passed to the
    // system audit applies here too (enable_threat_intel, rules_path, cache) --
    // not just to `scan`/`codes`. With no `-c`, this is an empty default config,
    // identical to the previous `Scanner::with_defaults()` behavior.
    let scanner = Scanner::new(config).context("Failed to create scanner")?;
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
    // Packages that were found but could not be fetched or scanned. They were
    // never reviewed, so they are listed in the summary and fail the exit code
    // rather than vanishing from the totals.
    let mut errored: Vec<(String, String)> = Vec::new();
    // The gate looks at EVERY finding; `min_severity` only trims the display.
    let mut gate_tripped = false;

    // Registry inputs for the whole installed set, in one batch. `system`
    // audits what is already on the machine, so ownership signals (an installed
    // package that has since been orphaned or adopted) are exactly what this
    // command is for -- it previously could not emit any of them.
    let official_names = registry::load_official_names().await;
    let node_info: HashMap<String, aur_scanner_core::aur::AurPackageInfo> = match &client {
        Some(c) => {
            let refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
            match c.info_batch(&refs).await {
                Ok(infos) => infos.into_iter().map(|i| (i.name.clone(), i)).collect(),
                Err(e) => {
                    eprintln!(
                        "{} could not load AUR metadata ({e}); ownership and \
                         name-impersonation checks are disabled for this run",
                        "note:".yellow()
                    );
                    HashMap::new()
                }
            }
        }
        None => HashMap::new(),
    };

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

            let reg = match node_info.get(package.as_str()) {
                Some(info) if client.is_some() => Registry::From(
                    registry::context_for(info, official_names.clone(), client.as_ref().unwrap())
                        .await,
                ),
                _ => Registry::None,
            };
            match scanner.scan_pkgbuild(&path, reg).await {
                Ok(result) => Some(result),
                Err(e) => {
                    println!("{}", format!("error: {}", e).red());
                    errored.push((package.clone(), format!("scan error: {e}")));
                    None
                }
            }
        } else if let Some(ref aur_client) = client {
            // Fetch and scan from AUR
            print!("{} {} ", "Fetching:".dimmed(), package.white());

            match aur_client.fetch_pkgbuild(package).await {
                Ok(fetched) => {
                    let reg = Registry::From(
                        registry::context_for(&fetched.info, official_names.clone(), aur_client)
                            .await,
                    );
                    match scanner.scan_pkgbuild(&fetched.pkgbuild_path, reg).await {
                        Ok(result) => Some(result),
                        Err(e) => {
                            println!("{}", format!("scan error: {}", e).red());
                            errored.push((package.clone(), format!("scan error: {e}")));
                            None
                        }
                    }
                }
                Err(e) => {
                    println!("{}", format!("fetch error: {}", e).red());
                    errored.push((package.clone(), format!("fetch error: {e}")));
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
                // Capped, lossy and never following symlinks: an uncapped
                // `read_to_string` here loaded every scanned file (committed
                // binaries included) whole, and failed on a single non-UTF-8
                // byte, silently skipping the provenance check.
                .filter_map(|p| aur_scanner_core::pkgfiles::read_capped_lossy(p).ok())
                .map(|r| r.content.replace('\0', ""))
                .collect::<Vec<_>>()
                .join("\n");
            if !combined.is_empty() {
                let anchor = result.scanned_files.first().cloned().unwrap_or_default();
                let prov = prov_store.evaluate(package, &combined, &now, &anchor);
                result.findings.extend(prov);
            }

            if result
                .findings
                .iter()
                .any(|f| f.severity.is_at_least(fail_on))
            {
                gate_tripped = true;
            }

            // Filter by severity (display only)
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

    if !errored.is_empty() {
        println!();
        println!(
            "  {} {} package(s) could not be fetched or scanned and were NOT reviewed:",
            "Errors:".red().bold(),
            errored.len()
        );
        for (pkg, why) in &errored {
            println!("    - {}: {}", pkg.red(), why.dimmed());
        }
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

    // Exit status: non-zero when an installed package matches a known-malicious
    // IOC, when any finding reaches `--fail-on` (default: critical), or when a
    // package could not be reviewed. `system` used to exit 0 unconditionally,
    // so a cron job or script could never tell a compromised host from a clean
    // one.
    if !name_hits.is_empty() || gate_tripped || !errored.is_empty() {
        std::process::exit(1);
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
