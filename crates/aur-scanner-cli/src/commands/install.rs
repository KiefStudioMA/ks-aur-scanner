//! Race-free install: resolve the AUR dependency tree, fetch every package
//! once into a persistent workspace, scan those EXACT directories, and only if
//! the scan passes, build them in dependency order with `makepkg` -- from the
//! same directories that were scanned.
//!
//! This closes the time-of-check/time-of-use gap that a "scan then call paru"
//! wrapper has (paru re-fetches and builds its own copy). Dependency ordering
//! is computed from our own resolved graph, so we never reimplement makepkg --
//! we just invoke it per package in a valid order.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

use aur_scanner_core::aur::AurClient;
use aur_scanner_core::depgraph::{self, ResolveOptions};
use aur_scanner_core::sbom::{self, ComponentScan};
use aur_scanner_core::{Scanner, Severity};

use super::banner;

/// Arguments for the race-free install.
pub struct InstallArgs {
    /// Packages to install (roots).
    pub package_names: Vec<String>,
    /// Build even if findings at or above this severity are present? No -- this
    /// is the gate threshold; findings at/above it block the build.
    pub fail_on: Severity,
    /// Follow optional dependencies when resolving.
    pub include_optional: bool,
    /// Pass --noconfirm to makepkg and skip our own build prompt.
    pub noconfirm: bool,
    /// Build even if the scan gate trips (requires the interactive ack too).
    pub force: bool,
    /// Keep the workspace after a successful build.
    pub keep_workspace: bool,
    /// Workspace for clones/builds (default: ~/.cache/aur-scan/build).
    pub workspace: Option<PathBuf>,
    /// Optional CycloneDX SBOM output path.
    pub sbom_path: Option<PathBuf>,
}

pub async fn run(args: InstallArgs) -> Result<()> {
    if args.package_names.is_empty() {
        anyhow::bail!("no packages specified");
    }
    let client = AurClient::new().context("Failed to create AUR client")?;
    let scanner = Scanner::with_defaults().context("Failed to create scanner")?;

    banner::print_header("Race-Free Install");
    println!();

    // 1. Resolve the full dependency tree.
    let opts = ResolveOptions {
        include_optional: args.include_optional,
        ..Default::default()
    };
    println!("{}", "Resolving dependency tree...".dimmed());
    let graph = depgraph::resolve(&client, &args.package_names, &opts)
        .await
        .context("Failed to resolve dependency tree")?;
    let (aur_count, repo_count) = graph.counts();
    println!("  {aur_count} AUR package(s), {repo_count} repo/virtual dependencies");

    // 2. Fetch each unique AUR package base ONCE into the workspace.
    let workspace = args
        .workspace
        .clone()
        .or_else(|| dirs::cache_dir().map(|c| c.join("aur-scan/build")))
        .context("could not determine workspace directory")?;
    std::fs::create_dir_all(&workspace)
        .with_context(|| format!("creating workspace {}", workspace.display()))?;

    // Group AUR nodes by package base (split packages share one repo/build).
    let mut base_dirs: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut node_base: BTreeMap<String, String> = BTreeMap::new();
    for node in graph.aur_packages() {
        let base = node
            .package_base
            .clone()
            .unwrap_or_else(|| node.name.clone());
        node_base.insert(node.name.clone(), base.clone());
        base_dirs.entry(base).or_default();
    }

    println!();
    let mut scans: BTreeMap<String, ComponentScan> = BTreeMap::new();
    let mut blocked = false;
    for base in base_dirs.keys().cloned().collect::<Vec<_>>() {
        let dir = workspace.join(&base);
        // Fresh clone: remove any stale copy so we scan and build the same bytes.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

        print!("{} {} ", "Fetching:".dimmed(), base.white());
        io::stdout().flush().ok();
        if let Err(e) = client.clone_repo(&base, &dir).await {
            println!("{}", format!("clone failed: {e}").red());
            blocked = true; // a package we cannot fetch is unreviewed -> block
            continue;
        }
        let result = match scanner.scan_pkgbuild(&dir.join("PKGBUILD")).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("scan failed: {e}").red());
                blocked = true;
                continue;
            }
        };
        let scan = ComponentScan::from_findings(&result.findings);
        let trips = result.findings.iter().any(|f| f.severity <= args.fail_on);
        if scan.critical > 0 || scan.high > 0 {
            println!("{}", format!("{}C/{}H", scan.critical, scan.high).red());
        } else {
            println!("{}", "ok".green());
        }
        if trips {
            blocked = true;
        }
        // Attribute this base's scan to all of its package names for the tree.
        for (name, b) in &node_base {
            if b == &base {
                scans.insert(name.clone(), scan.clone());
            }
        }
        base_dirs.insert(base, dir);
    }

    // 3. Show the reviewable tree + opaque boundaries.
    println!();
    println!("{}", "Dependency tree:".cyan().bold());
    print!("{}", sbom::render_tree(&graph, &scans));
    let opaque: Vec<&String> = scans
        .iter()
        .filter(|(_, s)| s.opaque)
        .map(|(k, _)| k)
        .collect();
    if !opaque.is_empty() {
        println!(
            "{} {} package(s) fetch/run external code (opaque): {}",
            "OPAQUE:".red().bold(),
            opaque.len(),
            opaque
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if let Some(path) = &args.sbom_path {
        let bom = sbom::to_cyclonedx(
            &graph,
            &scans,
            env!("CARGO_PKG_VERSION"),
            &sbom::new_serial(),
            &sbom::now_timestamp(),
        );
        std::fs::write(path, serde_json::to_string_pretty(&bom)?)
            .with_context(|| format!("writing SBOM to {}", path.display()))?;
        println!(
            "{} SBOM written to {}",
            "SBOM:".green().bold(),
            path.display()
        );
    }

    // 4. Gate.
    println!();
    if blocked {
        println!(
            "{}",
            "GATE: findings at or above the threshold (or an unscannable package)."
                .red()
                .bold()
        );
        if !args.force {
            anyhow::bail!(
                "blocked by scan gate; not building (use --force to override deliberately)"
            );
        }
        println!("{}", "--force given: overriding the gate.".yellow().bold());
    } else {
        println!("{}", "GATE: passed -- no blocking findings.".green().bold());
    }

    // 5. Confirm, then build in dependency order from the SAME directories.
    if !args.noconfirm {
        print!(
            "{} ",
            "Build and install these packages now? [y/N]:"
                .yellow()
                .bold()
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("{}", "Aborted by user. Nothing was built.".yellow());
            return Ok(());
        }
    }

    let order = depgraph::topo_order(&graph);
    let mut built: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for name in &order {
        let base = match node_base.get(name) {
            Some(b) => b.clone(),
            None => continue,
        };
        if !built.insert(base.clone()) {
            continue; // base already built (split package / shared)
        }
        let dir = match base_dirs.get(&base) {
            Some(d) if d.join("PKGBUILD").is_file() => d.clone(),
            _ => {
                eprintln!("{} {} not fetched; skipping", "warning:".yellow(), base);
                continue;
            }
        };
        println!();
        println!("{} {}", "Building:".cyan().bold(), base.white().bold());
        let mut cmd = tokio::process::Command::new("makepkg");
        cmd.arg("-si").current_dir(&dir);
        if args.noconfirm {
            cmd.arg("--noconfirm");
        }
        let status = cmd.status().await.context("failed to launch makepkg")?;
        if !status.success() {
            anyhow::bail!(
                "makepkg failed for '{}' (exit {:?}); stopping. Built so far: {}",
                base,
                status.code(),
                built
                    .iter()
                    .filter(|b| *b != &base)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    if !args.keep_workspace {
        for base in base_dirs.keys() {
            let dir = workspace.join(base);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    println!();
    println!("{}", "All packages built and installed.".green().bold());
    Ok(())
}
