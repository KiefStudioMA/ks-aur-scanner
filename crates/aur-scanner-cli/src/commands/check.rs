//! Check command - resolve the dependency tree, scan it, and emit a reviewable
//! SBOM BEFORE installation.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::PathBuf;

use aur_scanner_core::aur::{AurClient, PackageInfoSource};
use aur_scanner_core::depgraph::{self, DependencyGraph, PackageSource, ResolveOptions};
use aur_scanner_core::overlay::{info_from_pkgbuild, OverlaySource};
use aur_scanner_core::parser::{PkgbuildParser, StaticParser};
use aur_scanner_core::sbom::{self, ComponentScan};
use aur_scanner_core::validate::{is_valid_package_name, validate_package_name};
use aur_scanner_core::{Scanner, Severity};

use super::banner;

/// Arguments for the pre-install check.
pub struct CheckArgs {
    /// Packages the user asked to install (the roots).
    pub package_names: Vec<String>,
    /// Minimum severity to report.
    pub min_severity: Option<Severity>,
    /// Prompt before "proceeding".
    pub interactive: bool,
    /// Fail (non-zero exit) if findings at or above this severity exist.
    pub fail_on: Option<Severity>,
    /// Resolve and scan the full AUR dependency tree, not just the roots.
    pub resolve_deps: bool,
    /// Follow optional dependencies.
    pub include_optional: bool,
    /// Write a CycloneDX SBOM here.
    pub sbom_path: Option<PathBuf>,
    /// Already-fetched package directories to scan from disk (race-free).
    pub local_dirs: Vec<PathBuf>,
}

/// How a `--local` dir's self-declared pkgname relates to what the user asked
/// for (audit ME-6). A local PKGBUILD is untrusted input that *names itself*, so
/// a clean scan of it must never be silently attributed to an AUR node the user
/// did not explicitly request.
#[derive(Debug, PartialEq, Eq)]
enum LocalDirBinding {
    /// The declared name is one the user explicitly requested on the command
    /// line: the on-disk bytes legitimately stand in for that node.
    RequestedRoot,
    /// The declared name was NOT explicitly requested: the local dir is standing
    /// in for some other node (a transitive dependency, or an identity injected
    /// solely by the local PKGBUILD). Its real AUR source is therefore not what
    /// gets scanned -- surfaced loudly rather than masked.
    UnrequestedShadow,
}

/// Classify a `--local` dir by its declared name against the explicitly-requested
/// roots. Pure, so the binding policy is unit-testable independently of the scan.
fn classify_local_dir(
    declared_name: &str,
    requested_roots: &std::collections::HashSet<String>,
) -> LocalDirBinding {
    if requested_roots.contains(declared_name) {
        LocalDirBinding::RequestedRoot
    } else {
        LocalDirBinding::UnrequestedShadow
    }
}

/// Run the pre-install check.
pub async fn run(args: CheckArgs) -> Result<()> {
    let client = AurClient::new().context("Failed to create AUR client")?;
    let scanner = Scanner::with_defaults().context("Failed to create scanner")?;

    banner::print_header("Pre-Install Check");
    println!();

    // Parse any local package dirs so we can scan the EXACT on-disk bytes the
    // build will use (closing the time-of-check/time-of-use gap) and feed their
    // declared dependencies into resolution.
    let mut local_infos = Vec::new();
    let mut local_dir_by_name: HashMap<String, PathBuf> = HashMap::new();
    let parser = StaticParser::new();
    for dir in &args.local_dirs {
        let pkgbuild_path = dir.join("PKGBUILD");
        let content = std::fs::read_to_string(&pkgbuild_path)
            .with_context(|| format!("reading {}", pkgbuild_path.display()))?;
        let parsed = parser
            .parse(&content)
            .with_context(|| format!("parsing {}", pkgbuild_path.display()))?;
        for info in info_from_pkgbuild(&parsed) {
            // The name is parsed from a local PKGBUILD and becomes a resolution
            // key and a network query; reject illegal identifiers rather than
            // letting them overlay the AUR tree or hit the RPC.
            if !is_valid_package_name(&info.name) {
                eprintln!(
                    "{} ignoring local dir {} with illegal pkgname {:?}",
                    "warning:".yellow(),
                    dir.display(),
                    info.name
                );
                continue;
            }
            local_dir_by_name.insert(info.name.clone(), dir.clone());
            local_infos.push(info);
        }
    }
    if !local_dir_by_name.is_empty() {
        println!(
            "{} scanning {} package dir(s) from disk (race-free)",
            "local:".green().bold(),
            local_dir_by_name.len()
        );
    }

    // Explicit names the user asked for on the command line. A --local dir is
    // only allowed to substitute its on-disk bytes for one of THESE (or a node
    // resolved from them); a local dir that claims a different package's name
    // must not silently mask that package's real AUR PKGBUILD.
    for name in &args.package_names {
        validate_package_name(name).with_context(|| format!("illegal package name {name:?}"))?;
    }
    let requested_roots: std::collections::HashSet<String> =
        args.package_names.iter().cloned().collect();

    // Roots: explicit names plus any package names discovered in local dirs.
    let mut roots = args.package_names.clone();
    for name in local_dir_by_name.keys() {
        if !roots.contains(name) {
            roots.push(name.clone());
        }
    }
    if roots.is_empty() {
        anyhow::bail!("no packages to check (pass package names and/or --local <dir>)");
    }

    // 1. Resolve the dependency closure (roots only if --no-deps). Local dirs
    // overlay the AUR RPC so the full tree still resolves.
    let opts = ResolveOptions {
        include_optional: args.include_optional,
        // --no-deps => expand nothing past the roots.
        max_depth: if args.resolve_deps {
            ResolveOptions::default().max_depth
        } else {
            0
        },
        ..ResolveOptions::default()
    };
    println!("{}", "Resolving dependency tree...".dimmed());
    let overlay = OverlaySource::new(local_infos, &client);
    let source: &dyn PackageInfoSource = if local_dir_by_name.is_empty() {
        &client
    } else {
        &overlay
    };
    let graph = depgraph::resolve(source, &roots, &opts)
        .await
        .context("Failed to resolve dependency tree")?;

    let (aur_count, repo_count) = graph.counts();
    println!(
        "  {} AUR package(s) to scan, {} repo/virtual dependencies",
        aur_count.to_string().bold(),
        repo_count
    );
    if !graph.truncated.is_empty() {
        println!(
            "  {} tree truncated at depth/size cap for: {}",
            "note:".yellow(),
            graph.truncated.join(", ")
        );
    }
    println!();

    // 2. Scan every AUR node (the untrusted set).
    let mut scans: BTreeMap<String, ComponentScan> = BTreeMap::new();
    let mut total_critical = 0usize;
    let mut total_high = 0usize;
    let mut gate_tripped = false;
    let mut fetch_failures: Vec<String> = Vec::new();

    for node in graph.aur_packages() {
        // Prefer the exact on-disk PKGBUILD when the package was provided via
        // --local: that is the same content the build will use (no TOCTOU).
        // But if a local dir is standing in for a node the user did NOT ask for
        // (a transitive dependency), surface it: a local PKGBUILD claiming a
        // dependency's name would otherwise mask that dependency's real AUR
        // source from the scan.
        let local_pkgbuild = local_dir_by_name
            .get(&node.name)
            .map(|d| d.join("PKGBUILD"));
        if local_pkgbuild.is_some()
            && classify_local_dir(&node.name, &requested_roots)
                == LocalDirBinding::UnrequestedShadow
        {
            eprintln!(
                "{} a --local dir is providing {:?}, which you did not explicitly request; \
                 its real AUR source is NOT being checked",
                "note:".yellow(),
                node.name
            );
        }
        let origin = if local_pkgbuild.is_some() {
            "local"
        } else {
            "aur"
        };
        print!(
            "{} {} {} ",
            "Scanning:".dimmed(),
            node.name.white(),
            format!("({origin})").dimmed()
        );
        io::stdout().flush().ok();

        let result = match &local_pkgbuild {
            Some(p) => scanner
                .scan_pkgbuild(p)
                .await
                .map_err(|e| format!("scan error: {e}")),
            None => match client.fetch_pkgbuild(&node.name).await {
                Ok(fetched) => scanner
                    .scan_pkgbuild(&fetched.pkgbuild_path)
                    .await
                    .map_err(|e| format!("scan error: {e}")),
                Err(e) => Err(format!("fetch error: {e}")),
            },
        };
        match result {
            Ok(result) => {
                let scan = ComponentScan::from_findings(&result.findings);
                total_critical += scan.critical;
                total_high += scan.high;
                if let Some(threshold) = args.fail_on {
                    if result
                        .findings
                        .iter()
                        .any(|f| f.severity.is_at_least(threshold))
                    {
                        gate_tripped = true;
                    }
                }
                if scan.critical > 0 || scan.high > 0 {
                    println!("{}", format!("{}C/{}H", scan.critical, scan.high).red());
                } else {
                    println!("{}", "ok".green());
                }
                print_findings_for(&node.name, &result.findings, args.min_severity);
                scans.insert(node.name.clone(), scan);
            }
            Err(e) => {
                println!("{}", e.red());
                fetch_failures.push(node.name.clone());
            }
        }
    }

    // 3. Render the reviewable tree.
    println!();
    println!(
        "{}",
        "Dependency tree (review before installing):".cyan().bold()
    );
    print!("{}", sbom::render_tree(&graph, &scans));
    print_orphans(&graph);

    // Loudly call out opaque boundaries: packages that fetch/run external code.
    // The scanner intentionally does NOT follow these, so their real behavior
    // is unknown -- this is the "it's trying to run something from <url>" case.
    let opaque: Vec<(&String, &ComponentScan)> = scans.iter().filter(|(_, s)| s.opaque).collect();
    if !opaque.is_empty() {
        println!();
        println!(
            "{}",
            "OPAQUE BOUNDARY - these packages run code fetched from outside any package:"
                .red()
                .bold()
        );
        for (pkg, scan) in &opaque {
            let urls = if scan.remote_urls.is_empty() {
                "an external source".to_string()
            } else {
                scan.remote_urls.join(", ")
            };
            println!("  {} runs code from {}", pkg.red().bold(), urls.yellow());
        }
        println!(
            "  {}",
            "The scanner does not follow these. What they run is unknown -- you likely do not want this."
                .red()
        );
    }
    println!();

    // 4. Emit the SBOM if requested.
    if let Some(path) = &args.sbom_path {
        let bom = sbom::to_cyclonedx(
            &graph,
            &scans,
            env!("CARGO_PKG_VERSION"),
            &sbom::new_serial(),
            &sbom::now_timestamp(),
        );
        let json = serde_json::to_string_pretty(&bom)?;
        std::fs::write(path, json)
            .with_context(|| format!("writing SBOM to {}", path.display()))?;
        println!(
            "{} CycloneDX SBOM written to {}",
            "SBOM:".green().bold(),
            path.display()
        );
        println!();
    }

    // 5. Summary.
    println!("{}", "=".repeat(60));
    print!("Tree totals: ");
    if total_critical > 0 {
        print!("{} ", format!("{total_critical} CRITICAL").red().bold());
    }
    if total_high > 0 {
        print!("{} ", format!("{total_high} HIGH").yellow().bold());
    }
    if total_critical == 0 && total_high == 0 {
        print!("{}", "no critical/high findings".green());
    }
    println!();
    if !fetch_failures.is_empty() {
        println!(
            "{} could not fetch/scan: {} (treat as unreviewed)",
            "warning:".yellow(),
            fetch_failures.join(", ")
        );
    }

    // 6. Decide pass/fail. The gate trips if any finding was at or above the
    // requested threshold (computed per-finding via `is_at_least` during the
    // scan, so it honors any threshold -- not just critical/high).
    let mut failed = gate_tripped;
    // A package we could not fetch/scan is unreviewed; treat that as a failure
    // when a gate threshold was requested rather than silently passing.
    if args.fail_on.is_some() && !fetch_failures.is_empty() {
        failed = true;
    }

    if args.interactive && (total_critical > 0 || total_high > 0) {
        println!();
        if total_critical > 0 {
            println!(
                "{}",
                "WARNING: Critical security issues in the dependency tree!"
                    .red()
                    .bold()
            );
        }
        print!("{} ", "Proceed with installation? [y/N]:".yellow().bold());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("{}", "Installation aborted by user.".yellow());
            failed = true;
        } else {
            println!("{}", "User accepted risks, proceeding...".dimmed());
        }
    }

    if failed {
        anyhow::bail!("Security issues detected or user aborted");
    }
    Ok(())
}

fn print_findings_for(pkg: &str, findings: &[aur_scanner_core::Finding], min: Option<Severity>) {
    for f in findings.iter().filter(|f| {
        min.map(|m| f.severity <= m)
            .unwrap_or(f.severity <= Severity::High)
    }) {
        println!(
            "    {} {} [{}] {}",
            "·".dimmed(),
            pkg.dimmed(),
            f.severity,
            f.title
        );
    }
}

fn print_orphans(graph: &DependencyGraph) {
    let orphans: Vec<&str> = graph
        .nodes
        .values()
        .filter(|n| n.source == PackageSource::Aur && n.orphaned)
        .map(|n| n.name.as_str())
        .collect();
    if !orphans.is_empty() {
        println!(
            "  {} orphaned AUR package(s) in tree (higher hijack risk): {}",
            "note:".yellow(),
            orphans.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // --- --local name binding (audit ME-6) -----------------------------------
    // A local dir's declared name is honored as a stand-in only for a node the
    // user explicitly requested; any other name is an unrequested shadow whose
    // real AUR source is not what gets scanned.

    #[test]
    fn local_dir_for_requested_name_is_bound() {
        let roots: HashSet<String> = ["firefox".to_string()].into_iter().collect();
        assert_eq!(
            classify_local_dir("firefox", &roots),
            LocalDirBinding::RequestedRoot
        );
    }

    #[test]
    fn local_dir_claiming_an_unrequested_name_is_a_shadow() {
        let roots: HashSet<String> = ["firefox".to_string()].into_iter().collect();
        // A crafted local PKGBUILD claiming a different package's name must not be
        // silently treated as that package -- it is an unrequested shadow.
        assert_eq!(
            classify_local_dir("openssl", &roots),
            LocalDirBinding::UnrequestedShadow
        );
        // Even with no explicit request, a local-only name is a shadow (its AUR
        // source is not what was scanned).
        let empty: HashSet<String> = HashSet::new();
        assert_eq!(
            classify_local_dir("anything", &empty),
            LocalDirBinding::UnrequestedShadow
        );
    }

    #[test]
    fn illegal_pkgnames_are_rejected_before_binding() {
        // The name-validation half of ME-6: a local PKGBUILD's declared name is an
        // identifier that becomes a resolution key + network query; illegal ones
        // are refused up front (run() drops them) so they can never bind at all.
        for bad in ["../etc/passwd", "a/b", "a;rm -rf /", "", "-rf", "a$(id)"] {
            assert!(
                !is_valid_package_name(bad),
                "must reject local pkgname {bad:?}"
            );
        }
        for good in ["firefox", "python-requests", "lib32-foo"] {
            assert!(is_valid_package_name(good), "must accept {good}");
        }
    }
}
