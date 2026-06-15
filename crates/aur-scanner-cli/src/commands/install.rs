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
use aur_scanner_core::validate::validate_package_name;
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
    /// Workspace for clones/builds (default: ~/.cache/aur-scan/build).
    pub workspace: Option<PathBuf>,
    /// Optional CycloneDX SBOM output path.
    pub sbom_path: Option<PathBuf>,
    /// Keep the per-package build directories after a successful install.
    /// Default is to clean them up (the install tidies after itself).
    pub keep_build: bool,
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
    let opts = ResolveOptions { include_optional: args.include_optional, ..Default::default() };
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
        let base = node.package_base.clone().unwrap_or_else(|| node.name.clone());
        // `package_base`/`name` come straight from AUR RPC JSON and are about to
        // become filesystem paths (clone dest, and `remove_dir_all`/`create_dir_all`
        // targets). A value like `../../../.config/systemd/user` would escape the
        // workspace and delete arbitrary directories BEFORE any gate runs. Reject
        // anything that is not a bare package identifier up front.
        validate_package_name(&base)
            .with_context(|| format!("refusing to install: illegal package base {base:?}"))?;
        node_base.insert(node.name.clone(), base.clone());
        base_dirs.entry(base).or_default();
    }

    println!();
    let mut scans: BTreeMap<String, ComponentScan> = BTreeMap::new();
    // Distinguish two block reasons. `gate_tripped`: a package was reviewed and
    // had findings at/above the threshold -- a deliberate --force can override
    // this. `unscannable`: a package could not be fetched or scanned at all, so
    // it was never reviewed -- --force must NOT build these blind.
    let mut gate_tripped = false;
    let mut unscannable: Vec<String> = Vec::new();
    for base in base_dirs.keys().cloned().collect::<Vec<_>>() {
        let dir = workspace.join(&base);
        // Defense in depth: `base` is a validated single component, so the clone
        // directory must be a direct child of the workspace. Refuse to touch
        // (remove/create) anything that is not, so a future bug can never turn
        // this into an out-of-tree delete.
        if dir.parent() != Some(workspace.as_path()) {
            anyhow::bail!("internal error: build dir {} escaped workspace", dir.display());
        }
        // Fresh clone: remove any stale copy so we scan and build the same bytes.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

        print!("{} {} ", "Fetching:".dimmed(), base.white());
        io::stdout().flush().ok();
        if let Err(e) = client.clone_repo(&base, &dir).await {
            println!("{}", format!("clone failed: {e}").red());
            unscannable.push(base.clone()); // cannot fetch -> never reviewed
            continue;
        }
        let result = match scanner.scan_pkgbuild(&dir.join("PKGBUILD")).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("scan failed: {e}").red());
                unscannable.push(base.clone()); // cannot scan -> never reviewed
                continue;
            }
        };
        let scan = ComponentScan::from_findings(&result.findings);
        let trips = result.findings.iter().any(|f| f.severity.is_at_least(args.fail_on));
        if scan.critical > 0 || scan.high > 0 {
            println!("{}", format!("{}C/{}H", scan.critical, scan.high).red());
        } else {
            println!("{}", "ok".green());
        }
        if trips {
            gate_tripped = true;
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
    let opaque: Vec<&String> = scans.iter().filter(|(_, s)| s.opaque).map(|(k, _)| k).collect();
    if !opaque.is_empty() {
        println!(
            "{} {} package(s) fetch/run external code (opaque): {}",
            "OPAQUE:".red().bold(),
            opaque.len(),
            opaque.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
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
        println!("{} SBOM written to {}", "SBOM:".green().bold(), path.display());
    }

    // 4. Gate.
    println!();
    // Unscannable packages were never reviewed; building them blind defeats the
    // tool. This is a hard stop that --force cannot override -- override is only
    // for findings the user has actually seen.
    if !unscannable.is_empty() {
        println!(
            "{} could not fetch/scan (unreviewed): {}",
            "GATE:".red().bold(),
            unscannable.join(", ")
        );
        anyhow::bail!(
            "refusing to build {} unreviewed package(s); --force cannot override unscannable packages",
            unscannable.len()
        );
    }
    if gate_tripped {
        println!(
            "{}",
            "GATE: findings at or above the threshold.".red().bold()
        );
        if !args.force {
            anyhow::bail!("blocked by scan gate; not building (use --force to override deliberately)");
        }
        println!("{}", "--force given: overriding findings gate.".yellow().bold());
    } else {
        println!("{}", "GATE: passed -- no blocking findings.".green().bold());
    }

    // 5. Confirm, then build in dependency order from the SAME directories.
    if !args.noconfirm {
        print!("{} ", "Build and install these packages now? [y/N]:".yellow().bold());
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
        // Resolve makepkg to an absolute path rather than letting it be looked
        // up relative to the (attacker-controlled) package directory we set as
        // the cwd. This prevents a hostile package from shipping its own
        // `makepkg` that would run if `.` were ever on PATH.
        let makepkg_bin = ["/usr/bin/makepkg", "/bin/makepkg"]
            .iter()
            .find(|p| std::path::Path::new(p).is_file())
            .copied()
            .unwrap_or("makepkg");
        let mut cmd = tokio::process::Command::new(makepkg_bin);
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
                built.iter().filter(|b| *b != &base).cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }

    // 6. Tidy up after a successful install: remove the per-package build dirs we
    //    created in the workspace (large clones + build trees that otherwise just
    //    accumulate). Only on full success, and only dirs that are direct children
    //    of the workspace (the same invariant enforced at fetch time).
    if !args.keep_build {
        let mut cleaned = 0usize;
        for base in &built {
            if let Some(dir) = base_dirs.get(base) {
                if dir.parent() == Some(workspace.as_path())
                    && std::fs::remove_dir_all(dir).is_ok()
                {
                    cleaned += 1;
                }
            }
        }
        if cleaned > 0 {
            println!(
                "{} removed {} build dir(s) from {} (use --keep-build to retain)",
                "cleanup:".dimmed(),
                cleaned,
                workspace.display()
            );
        }
    }

    println!();
    println!("{}", "All packages built and installed.".green().bold());
    Ok(())
}
