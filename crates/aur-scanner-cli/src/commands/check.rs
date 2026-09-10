//! Check command - resolve the dependency tree, scan it, and emit a reviewable
//! SBOM BEFORE installation.

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::PathBuf;

use aur_scanner_core::aur::{AurClient, PackageInfoSource};
use aur_scanner_core::depgraph::{self, DependencyGraph, PackageSource, ResolveOptions};
use aur_scanner_core::history::{
    compare as history_compare, findings_for_changes, History, PackageRecord, Scope,
};
use aur_scanner_core::overlay::{info_from_pkgbuild, OverlaySource};
use aur_scanner_core::parser::{PkgbuildParser, StaticParser};
use aur_scanner_core::registry;
use aur_scanner_core::sbom::{self, ComponentScan};
use aur_scanner_core::validate::{is_valid_package_name, validate_package_name};
use aur_scanner_core::{Finding, OutputConfig, Registry, ScanConfig, Scanner, Severity};

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
    /// Full scan configuration (threat-intel, cache, rules, display). The
    /// `[output]` table is display-only and never affects findings or exit
    /// codes; every other field is honored by the scanner engine.
    pub config: ScanConfig,
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

/// Compare a fresh scan against the stored record for the same package, emit
/// findings for what moved, and store the new record.
///
/// Returns an empty vector on a first scan. Every failure path is an `Err` the
/// caller logs and discards: change detection is an enhancement layered on top
/// of the scan, and a broken cache must never turn a good scan into a bad one.
pub(crate) fn diff_against_history(
    history: &History,
    result: &aur_scanner_core::ScanResult,
    pkgbuild_path: &std::path::Path,
    maintainer: MaintainerLookup,
    scope: Scope,
    fingerprint: String,
) -> anyhow::Result<Vec<Finding>> {
    // Capped, like every other read the scanner does. An uncapped
    // read_to_string here bypasses MAX_SCAN_FILE_BYTES and lets a hostile repo
    // hand the history layer a multi-gigabyte "PKGBUILD".
    let content = aur_scanner_core::read_text_capped(pkgbuild_path)?;
    let parsed = StaticParser::new().parse(&content)?;

    // Hash the package-side scripts separately from the PKGBUILD so "gained an
    // install script" is distinguishable from "the PKGBUILD changed".
    let dir = pkgbuild_path.parent().unwrap_or(std::path::Path::new("."));
    let mut scripts: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
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
        for path in paths {
            if let Ok(c) = aur_scanner_core::read_text_capped(&path) {
                scripts.push(c);
            }
        }
    }

    let previous = history.get(&current_key(result), scope);

    // A lookup that FAILED is not a package that is orphaned.
    //
    // `PackageRecord.maintainer` is `Option<String>` where `None` documents
    // "orphaned". Both writers derived it from an AUR lookup that also yields
    // `None` when the RPC call errored, so one transient failure rewrote every
    // record's maintainer to None -- and `compare` then read that as
    // `Some("alice") -> None` and emitted DIFF-002 "Package has been orphaned"
    // for the whole tree. The next successful run emitted the mirror image at
    // HIGH: "Orphaned package has been adopted", naming maintainers who never
    // changed. That is the code meant to catch the xeactor pattern, firing
    // dozens of times about nothing, which teaches people to ignore it.
    //
    // When we did not look, carry the previous value forward instead of
    // asserting anything.
    let maintainer = match maintainer {
        MaintainerLookup::Known(m) => m,
        MaintainerLookup::NotLookedUp => previous.as_ref().and_then(|p| p.maintainer.clone()),
    };

    let current = PackageRecord::from_scan(result, &parsed, maintainer)
        .with_scripts(&scripts)
        .with_fingerprint(fingerprint);
    let findings = match &previous {
        Some(previous) => {
            let changes = history_compare(previous, &current);
            findings_for_changes(
                previous,
                &current,
                &changes,
                &result.findings,
                pkgbuild_path,
            )
        }
        None => Vec::new(),
    };

    // Return the findings even if the store cannot be updated. Computing a real
    // delta and then discarding it because the cache is full or read-only is a
    // fail-OPEN: the tool has a baseline, has detected a hijack-shaped change
    // against it, and says nothing. Report first, persist second.
    if let Err(e) = history.put(&current, scope) {
        tracing::warn!(
            "could not update scan history for {}: {e}; change detection will \
             re-report this next run",
            current.package
        );
    }
    Ok(findings)
}

/// The history key for a completed scan.
fn current_key(result: &aur_scanner_core::ScanResult) -> String {
    result.package_name.clone()
}

/// What we know about a package's maintainer, distinguishing "the registry says
/// nobody" from "we never asked".
#[derive(Debug, Clone)]
pub(crate) enum MaintainerLookup {
    /// The registry answered. `None` inside means genuinely orphaned.
    Known(Option<String>),
    /// No lookup happened, or it failed. Asserts nothing.
    NotLookedUp,
}

/// Run the pre-install check.
pub async fn run(args: CheckArgs) -> Result<()> {
    let client = AurClient::new().context("Failed to create AUR client")?;
    let output = args.config.output.clone();
    let scanner = Scanner::new(args.config).context("Failed to create scanner")?;

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
    //
    // The official-repo name list is the trusted corpus for name-impersonation
    // comparison. Read it once for the whole tree rather than per package.
    // Scan history: how this package looked last time. Opening it is
    // best-effort -- if the cache directory is unusable we simply do not do
    // change detection, rather than refusing to scan.
    let history = match History::open(History::default_dir()) {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!(
                "{} scan history unavailable ({e}); change detection is off for this run",
                "note:".yellow()
            );
            None
        }
    };

    let official_names = registry::load_official_names().await;
    if official_names.is_empty() {
        eprintln!(
            "{} could not read the pacman sync databases; name-impersonation \
             checks are disabled for this run",
            "note:".yellow()
        );
    }

    // Registry records for the AUR nodes, in one batch. Resolution kept only the
    // fields it needed for the graph; ownership analysis needs the rest
    // (submission date, votes, out-of-date flag). A failure here is not fatal --
    // the scan proceeds with no registry context and the name analyzers stay
    // silent rather than guessing.
    let aur_node_names: Vec<String> = graph
        .aur_packages()
        .iter()
        .map(|n| n.name.clone())
        .collect();
    let node_info: HashMap<String, aur_scanner_core::aur::AurPackageInfo> = {
        let refs: Vec<&str> = aur_node_names.iter().map(|s| s.as_str()).collect();
        match source.info_batch(&refs).await {
            Ok(infos) => infos.into_iter().map(|i| (i.name.clone(), i)).collect(),
            Err(e) => {
                eprintln!(
                    "{} could not load AUR package metadata ({e}); ownership and \
                     name-impersonation checks are disabled for this run",
                    "note:".yellow()
                );
                HashMap::new()
            }
        }
    };

    // The threshold that actually blocks.
    //
    // `--fail-on` when given. Otherwise: a NON-INTERACTIVE run has no prompt to
    // fall back on, so it must fail closed on Critical rather than exit 0.
    //
    // It did not. `gate_tripped` was only ever written inside
    // `if let Some(threshold) = args.fail_on`, and the shell integrations invoke
    // `aur-scan check --severity <sev> --no-confirm <pkgs>` with no `--fail-on`
    // at all -- `--severity` is a DISPLAY floor, not a gate. So a user with
    // AUR_SCAN_INTERACTIVE=0 got "Tree totals: 3 CRITICAL", exit 0, and
    // `if ! aur-scan check ...` handed straight off to paru. The primary
    // documented protection was a no-op in exactly the mode people script.
    //
    // An interactive run keeps its previous behaviour: the prompt is the gate,
    // and the user may knowingly accept the risk.
    let effective_gate = match (args.fail_on, args.interactive) {
        (Some(t), _) => t,
        (None, false) => Severity::Critical,
        // Interactive with no explicit threshold: the prompt below decides.
        (None, true) => Severity::Critical,
    };

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
        // History is keyed by package NAME, and for a --local dir that name is
        // whatever the PKGBUILD declares about itself. Recording it in the same
        // namespace as AUR packages lets a directory declaring
        // `pkgname=firefox` overwrite the real firefox baseline -- and because
        // DIFF-* are pure deltas, a poisoned baseline does not raise a false
        // alarm, it SILENCES the next real change. So local scans go in their
        // own namespace: they still diff against previous local scans of the
        // same directory (which is the whole point of `check --local`), and can
        // never touch an AUR package's record.
        let scope = if local_pkgbuild.is_some() {
            History::LOCAL
        } else {
            History::AUR
        };
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

        // What the registry says about this package: who maintains it, how long
        // it has existed, and -- when the name is a `-bin`/`-git` variant --
        // who maintains the package it is a variant of. Absent for a node the
        // RPC did not return, in which case the name analyzers stay silent.
        let registry_ctx = match node_info.get(&node.name) {
            Some(info) => {
                Registry::From(registry::context_for(info, official_names.clone(), source).await)
            }
            None => Registry::None,
        };

        // Distinguish "the registry says nobody" from "we never asked" -- see
        // MaintainerLookup. Conflating them made one RPC blip rewrite every
        // record to orphaned and emit a false DIFF-002 pair across the tree.
        let maintainer = match node_info.get(&node.name) {
            Some(i) => MaintainerLookup::Known(i.maintainer.clone()),
            None => MaintainerLookup::NotLookedUp,
        };

        let result = match &local_pkgbuild {
            Some(p) => scanner
                .scan_pkgbuild(p, registry_ctx)
                .await
                .map(|r| (r, p.clone()))
                .map_err(|e| format!("scan error: {e}")),
            None => match client.fetch_pkgbuild(&node.name).await {
                Ok(fetched) => scanner
                    .scan_pkgbuild(&fetched.pkgbuild_path, registry_ctx)
                    .await
                    .map(|r| (r, fetched.pkgbuild_path.clone()))
                    .map_err(|e| format!("scan error: {e}")),
                Err(e) => Err(format!("fetch error: {e}")),
            },
        };
        match result {
            Ok((mut result, scanned_path)) => {
                // Compare against the last time we saw this package and record
                // what it looks like now. A first scan is silent -- there is
                // nothing to compare against, and complaining about a cold
                // cache is noise. Any failure here is logged and ignored: the
                // history is an enhancement, never a reason to fail a scan.
                if let Some(h) = history.as_ref() {
                    match diff_against_history(
                        h,
                        &result,
                        &scanned_path,
                        maintainer,
                        scope,
                        aur_scanner_core::history::analysis_fingerprint(scanner.min_severity()),
                    ) {
                        // Honour the configured threshold. These are produced
                        // after the scan returns, so they miss the filter the
                        // engine applies to everything else.
                        Ok(diff_findings) => result.findings.extend(
                            diff_findings
                                .into_iter()
                                .filter(|f| f.severity <= scanner.min_severity()),
                        ),
                        Err(e) => {
                            tracing::debug!("history comparison for {} failed: {e}", node.name)
                        }
                    }
                }
                result.findings.sort_by_key(|f| f.severity);
                let scan = ComponentScan::from_findings(&result.findings);
                total_critical += scan.critical;
                total_high += scan.high;
                if result
                    .findings
                    .iter()
                    .any(|f| f.severity.is_at_least(effective_gate))
                {
                    gate_tripped = true;
                }
                if scan.critical > 0 || scan.high > 0 {
                    println!("{}", format!("{}C/{}H", scan.critical, scan.high).red());
                } else {
                    println!("{}", "ok".green());
                }
                print_findings_for(&node.name, &result.findings, args.min_severity, &output);
                scans.insert(node.name.clone(), scan);
            }
            Err(e) => {
                println!("{}", e.red());
                fetch_failures.push(node.name.clone());
            }
        }
    }

    // Housekeeping, once per run and after every record for this scan is
    // written. Failures are ignored: pruning must never affect a scan's outcome.
    if let Some(h) = history.as_ref() {
        h.prune(History::DEFAULT_MAX_AGE_DAYS, History::DEFAULT_MAX_RECORDS);
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
    // An interactive run defers to the prompt; a non-interactive one cannot,
    // so the computed gate is what decides.
    let mut failed = gate_tripped && !args.interactive;
    // A package we could not fetch/scan is unreviewed. Treat that as a failure
    // rather than silently passing -- "could not analyze" is not "clean".
    // "Could not analyze" is not "clean". Block on an unreviewed package whenever
    // there is a gate to trip: a non-interactive run always has one now, and an
    // interactive run has one only if a threshold was asked for explicitly.
    if !fetch_failures.is_empty() && (!args.interactive || args.fail_on.is_some()) {
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

fn print_findings_for(
    pkg: &str,
    findings: &[Finding],
    min: Option<Severity>,
    display: &OutputConfig,
) {
    for f in findings.iter().filter(|f| {
        min.map(|m| f.severity <= m)
            .unwrap_or(f.severity <= Severity::High)
    }) {
        println!("{}", format_finding_compact(pkg, f, display));
    }
}

/// Render the one-line compact form `check` uses for each finding. Pure (no
/// I/O) so the formatting — including the optional `(file:line)` indicator — is
/// unit-testable. The location is appended only when `display.line` is set and
/// the analyzer captured one; the file is shown by basename so a fetched
/// temp-dir path does not bury the signal.
fn format_finding_compact(pkg: &str, f: &Finding, display: &OutputConfig) -> String {
    let loc = if display.line {
        match (f.location.file.file_name(), f.location.line) {
            (Some(name), Some(line)) => {
                format!(
                    "  {}",
                    format!("({}:{line})", name.to_string_lossy()).dimmed()
                )
            }
            (Some(name), None) => {
                format!("  {}", format!("({})", name.to_string_lossy()).dimmed())
            }
            _ => String::new(),
        }
    } else {
        String::new()
    };
    format!(
        "    {} {} [{}] {}{}",
        "·".dimmed(),
        pkg.dimmed(),
        f.severity,
        f.title,
        loc
    )
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

    // --- compact finding rendering (#16: file:line indicator) ----------------

    fn finding_with_location(line: Option<usize>) -> Finding {
        Finding {
            id: "ENV-003".to_string(),
            severity: Severity::Critical,
            category: aur_scanner_core::Category::Persistence,
            title: "Bashrc/profile modification".to_string(),
            description: "test".to_string(),
            location: aur_scanner_core::Location {
                file: PathBuf::from("/home/eric/.cache/yay/cdu/cdu.install"),
                line,
                column: None,
                snippet: None,
            },
            recommendation: "review".to_string(),
            cwe_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn compact_shows_basename_and_line_when_enabled() {
        colored::control::set_override(false);
        let out = format_finding_compact(
            "cdu",
            &finding_with_location(Some(4)),
            &OutputConfig::default(),
        );
        // The full temp path is reduced to a basename so the signal is readable.
        assert!(out.contains("(cdu.install:4)"), "got: {out}");
        assert!(
            !out.contains(".cache/yay"),
            "must not bury the line in a temp path: {out}"
        );
        assert!(out.contains("[CRITICAL]") && out.contains("Bashrc/profile modification"));
    }

    #[test]
    fn compact_omits_location_when_line_disabled() {
        colored::control::set_override(false);
        let display = OutputConfig {
            line: false,
            ..OutputConfig::default()
        };
        let out = format_finding_compact("cdu", &finding_with_location(Some(4)), &display);
        assert!(
            !out.contains("cdu.install"),
            "line indicator must be suppressed: {out}"
        );
        // The finding itself is still rendered -- display toggles never hide it.
        assert!(
            out.contains("Bashrc/profile modification"),
            "finding still shown: {out}"
        );
    }

    #[test]
    fn compact_handles_missing_line_number() {
        colored::control::set_override(false);
        let out = format_finding_compact(
            "cdu",
            &finding_with_location(None),
            &OutputConfig::default(),
        );
        // No line captured: show the file, no colon-line.
        assert!(out.contains("(cdu.install)"), "got: {out}");
        assert!(!out.contains("cdu.install:"), "no dangling colon: {out}");
    }
}
