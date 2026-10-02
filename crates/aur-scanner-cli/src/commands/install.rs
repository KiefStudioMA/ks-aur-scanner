//! Race-free install: resolve the AUR dependency tree, fetch every package
//! once into a persistent workspace, scan those EXACT directories, and only if
//! the scan passes, build them in dependency order with `makepkg` -- from the
//! same directories that were scanned.
//!
//! This closes the re-fetch gap that a "scan then call paru" wrapper has (paru
//! re-clones and builds its own copy), and every scanned directory is hashed at
//! scan time and re-verified immediately before `makepkg` runs. It does NOT
//! cover what `makepkg` itself fetches later: `source=` downloads, VCS checkouts
//! and `pkgver()` run after the scan. Packages with such sources are called out
//! before the build. Dependency ordering is computed from our own resolved
//! graph, so we never reimplement makepkg -- we just invoke it per package in a
//! valid order (dependencies get `--asdeps`).

use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use aur_scanner_core::aur::{
    package_deadline, snapshot_changes, snapshot_dir, with_deadline, AurClient, PackageInfoSource,
};
use aur_scanner_core::depgraph::{self, DependencyGraph, PackageSource, ResolveOptions};
use aur_scanner_core::history::{History, Scope};
use aur_scanner_core::parser::{ParsedPkgbuild, PkgbuildParser, Protocol, StaticParser};
use aur_scanner_core::registry;
use aur_scanner_core::sbom::{self, ComponentScan};
use aur_scanner_core::validate::validate_package_name;
use aur_scanner_core::{Registry, ScanConfig, Scanner, Severity};

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
    /// The resolved scan configuration (honours `-c`).
    pub config: ScanConfig,
}

/// Decision for the pre-build confirmation, computed before any answer is read.
/// Kept separate from the IO so the fail-closed contract is unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum ConsentGate {
    /// `--noconfirm` given: the operator pre-consented; build without prompting.
    Proceed,
    /// Interactive terminal: prompt the user for an explicit yes.
    Prompt,
    /// Non-interactive stdin and no `--noconfirm`: fail closed and abort.
    AbortNonInteractive,
}

/// Map `(--noconfirm, stdin-is-a-terminal)` to a consent decision.
///
/// SECURITY (defect #11): without this guard the prompt was read unconditionally,
/// so a piped `y` on a non-terminal stdin (CI, cron, `yes |`) was accepted as
/// consent to build attacker-authored AUR code. Only an explicit `--noconfirm`
/// or a real interactive `yes` may proceed.
fn consent_gate(noconfirm: bool, stdin_is_terminal: bool) -> ConsentGate {
    if noconfirm {
        ConsentGate::Proceed
    } else if stdin_is_terminal {
        ConsentGate::Prompt
    } else {
        ConsentGate::AbortNonInteractive
    }
}

/// What the scan gate decided about building. Pure so the fail-closed invariant
/// (audit ME-8) is unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum GateOutcome {
    /// One or more packages could not be fetched/scanned at all. This is a HARD
    /// stop: `--force` is for findings the user has actually seen, and must NEVER
    /// wave through a package that was never analyzed.
    BlockUnscannable,
    /// Findings at/above the threshold and no `--force`: blocked.
    BlockFindings,
    /// Findings at/above the threshold, but `--force` was given: proceed, having
    /// shown the user the findings they are overriding.
    ForceOverride,
    /// No blocking findings: proceed.
    Pass,
}

/// Decide the gate outcome (audit ME-8). The ordering is the invariant: an
/// unscannable package blocks BEFORE the `--force`-overridable findings gate is
/// even consulted, so `--force` can never silently build a package that was
/// never reviewed.
fn gate_outcome(has_unscannable: bool, gate_tripped: bool, force: bool) -> GateOutcome {
    if has_unscannable {
        GateOutcome::BlockUnscannable
    } else if gate_tripped {
        if force {
            GateOutcome::ForceOverride
        } else {
            GateOutcome::BlockFindings
        }
    } else {
        GateOutcome::Pass
    }
}

/// Build a sanitized environment for the `makepkg` invocation (audit ME-4).
///
/// A clean scan can be undone at *build* time by a poisoned environment: a
/// hostile `PATH` pointing `gpg`/`git`/`sed`/`sudo` at attacker binaries, a
/// `GNUPGHOME` of attacker keys that makes signature checks pass, a `BUILDDIR`/
/// `PKGDEST` redirect, or `GIT_SSL_NO_VERIFY`/`GIT_SSH`. So we do NOT inherit the
/// ambient environment for the build: start from empty, force a known-good
/// `PATH`, and pass through only an allowlist of variables makepkg legitimately
/// needs and that are not a vector for redirecting a trusted helper.
///
/// Build-control and redirect variables (`GNUPGHOME`, `BUILDDIR`, `PKGDEST`,
/// `SRCDEST`, `GIT_*`, `LD_*`, …) are deliberately dropped: makepkg falls back to
/// `/etc/makepkg.conf` + the user's real `$HOME/.gnupg`, which is what a from-a-
/// clean-scan build must use.
fn sanitized_build_env<I>(ambient: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    /// Variables passed through unchanged: locale/UX and build parallelism, none
    /// of which can redirect a trusted helper binary.
    const ALLOW: &[&str] = &[
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "TZ",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_COLLATE",
        "LC_NUMERIC",
        "LC_TIME",
        "MAKEFLAGS",
        "PACKAGER",
    ];
    /// Known-good search path so a poisoned ambient `PATH` cannot point makepkg's
    /// helpers at attacker-controlled binaries. `.`/cwd is never on it.
    const SAFE_PATH: &str = "/usr/bin:/bin:/usr/local/bin";

    let mut env: Vec<(String, String)> = ambient
        .into_iter()
        .filter(|(k, _)| ALLOW.contains(&k.as_str()))
        .collect();
    env.push(("PATH".to_string(), SAFE_PATH.to_string()));
    env
}

/// Requested roots that are not AUR packages (an official repo package, a
/// virtual name, or something unresolvable). `install` builds AUR packages only:
/// silently skipping these while reporting success would install nothing.
fn non_aur_roots(graph: &DependencyGraph) -> Vec<String> {
    graph
        .roots
        .iter()
        .filter(|r| {
            graph
                .nodes
                .get(r.as_str())
                .map(|n| n.source != PackageSource::Aur)
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

/// One package base to build, in order.
#[derive(Debug, PartialEq, Eq)]
struct BuildStep {
    base: String,
    /// Pulled in as a dependency (installed `--asdeps`), not requested.
    as_dep: bool,
}

/// Order the package bases so every base's AUR dependencies (looking through
/// virtual providers, and across split packages) are built first. Cycles are
/// broken deterministically. A base is a root if any requested name lives in it.
fn build_plan(graph: &DependencyGraph, node_base: &BTreeMap<String, String>) -> Vec<BuildStep> {
    let roots: std::collections::BTreeSet<&str> = graph
        .roots
        .iter()
        .filter_map(|r| node_base.get(r.as_str()).map(|b| b.as_str()))
        .collect();

    fn emit<'a>(
        base: &'a str,
        graph: &DependencyGraph,
        node_base: &'a BTreeMap<String, String>,
        done: &mut std::collections::BTreeSet<&'a str>,
        out: &mut Vec<&'a str>,
    ) {
        if !done.insert(base) {
            return; // already emitted, or in progress (a cycle)
        }
        for (name, b) in node_base {
            if b != base {
                continue;
            }
            if let Some(node) = graph.nodes.get(name) {
                for dep in depgraph::aur_dependencies(graph, node) {
                    if let Some(db) = node_base.get(dep) {
                        emit(db, graph, node_base, done, out);
                    }
                }
            }
        }
        out.push(base);
    }

    let mut done = std::collections::BTreeSet::new();
    let mut order: Vec<&str> = Vec::new();
    for name in depgraph::topo_order(graph) {
        if let Some(b) = node_base.get(&name) {
            emit(b, graph, node_base, &mut done, &mut order);
        }
    }
    order
        .into_iter()
        .map(|b| BuildStep {
            base: b.to_string(),
            as_dep: !roots.contains(b),
        })
        .collect()
}

/// Why a scanned package still counts as never reviewed, if it does.
fn unreviewed_reason(result: &aur_scanner_core::ScanResult) -> Option<&'static str> {
    result
        .has_unanalyzable()
        .then_some("contains a file that could not be analyzed (SCAN-001)")
}

/// `makepkg` arguments for one step.
fn makepkg_args(as_dep: bool, noconfirm: bool) -> Vec<&'static str> {
    let mut a = vec!["-si"];
    if as_dep {
        a.push("--asdeps");
    }
    if noconfirm {
        a.push("--noconfirm");
    }
    a
}

/// Things `makepkg` will fetch or run AFTER this scan, which the scan of the
/// package repository cannot cover: unchecksummed downloads, unpinned VCS
/// checkouts and a `pkgver()` function. Returned as printable lines.
fn late_fetch_notices(pkg: &ParsedPkgbuild) -> Vec<String> {
    let sums = [
        &pkg.checksums.md5sums,
        &pkg.checksums.sha1sums,
        &pkg.checksums.sha256sums,
        &pkg.checksums.sha512sums,
        &pkg.checksums.b2sums,
    ];
    let mut out = Vec::new();
    for (i, src) in pkg.source.iter().enumerate() {
        // Files shipped in the package repository are covered by the scan/hash.
        if src.protocol == Protocol::File {
            continue;
        }
        if src.is_vcs() {
            if !src.is_vcs_pinned_commit() {
                out.push(format!(
                    "{}: VCS source is not pinned to a commit; makepkg fetches whatever it points at when you build",
                    src.url
                ));
            }
        } else if !sums.iter().any(|v| matches!(v.get(i), Some(Some(_)))) {
            out.push(format!(
                "{}: downloaded at build time with checksum SKIP (not integrity-checked)",
                src.url
            ));
        }
    }
    if pkg.functions.contains_key("pkgver") {
        out.push(
            "pkgver() runs during the build and can fetch or execute code that was not scanned"
                .to_string(),
        );
    }
    out
}

pub async fn run(args: InstallArgs) -> Result<()> {
    if args.package_names.is_empty() {
        anyhow::bail!("no packages specified");
    }
    // Same config discovery as `scan` / `check` / hook / wrap (XDG then /etc).
    let timeout_seconds = args.config.timeout_seconds;
    let client = AurClient::with_timeout(timeout_seconds).context("Failed to create AUR client")?;
    let scanner = Scanner::new(args.config.clone()).context("Failed to create scanner")?;

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

    // Only AUR packages can be built here. Refuse (loudly, non-zero) rather than
    // skip them and report success after installing nothing.
    let not_aur = non_aur_roots(&graph);
    if !not_aur.is_empty() {
        anyhow::bail!(
            "not AUR packages, nothing to build: {}. `aur-scan install` only builds AUR packages; \
             install official repo packages with `pacman -S` (names that nothing provides are unresolved)",
            not_aur.join(", ")
        );
    }

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
    // Registry inputs, loaded once for the whole tree rather than per package.
    let official_names = registry::load_official_names().await;
    let aur_base_names: Vec<String> = graph
        .aur_packages()
        .iter()
        .map(|n| n.package_base.clone().unwrap_or_else(|| n.name.clone()))
        .collect();
    let node_info: HashMap<String, aur_scanner_core::aur::AurPackageInfo> = {
        let refs: Vec<&str> = aur_base_names.iter().map(|s| s.as_str()).collect();
        match client.info_batch(&refs).await {
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
    // Scan history, best-effort: an unusable cache disables change detection
    // rather than refusing to install.
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

    let mut gate_tripped = false;
    let mut unscannable: Vec<String> = Vec::new();
    // Dependencies we could not classify, or a tree that was cut off, are
    // unreviewed packages: --force must not build around them.
    unscannable.extend(graph.blocking_issues());
    for n in graph.ambiguous() {
        unscannable.push(format!(
            "ambiguous provider for {:?} ({}): install the one you want explicitly",
            n.name,
            n.depends.join(", ")
        ));
    }
    // Scan-time hash of every scanned directory, re-checked before its build.
    let mut snapshots: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut late_notices: Vec<(String, Vec<String>)> = Vec::new();
    for base in base_dirs.keys().cloned().collect::<Vec<_>>() {
        let dir = workspace.join(&base);
        // Defense in depth: `base` is a validated single component, so the clone
        // directory must be a direct child of the workspace. Refuse to touch
        // (remove/create) anything that is not, so a future bug can never turn
        // this into an out-of-tree delete.
        if dir.parent() != Some(workspace.as_path()) {
            anyhow::bail!(
                "internal error: build dir {} escaped workspace",
                dir.display()
            );
        }
        // Fresh clone: remove any stale copy so we scan and build the same bytes.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

        print!("{} {} ", "Fetching:".dimmed(), base.white());
        io::stdout().flush().ok();
        // Registry context for this package base. `install` is the path that
        // actually BUILDS, so running it with a smaller analyzer set than
        // `check` -- as this did until the wiring was audited -- inverted the
        // security posture: the mode documented as stronger was the weaker one.
        let registry_ctx = match node_info.get(base.as_str()) {
            Some(info) => {
                Registry::From(registry::context_for(info, official_names.clone(), &client).await)
            }
            None => Registry::None,
        };
        let pkgbuild_path = dir.join("PKGBUILD");
        // Overall per-package deadline from `timeout_seconds`; elapsing means the
        // package was never reviewed (fail closed).
        let fetched_and_scanned = with_deadline(package_deadline(timeout_seconds), async {
            client.clone_repo(&base, &dir).await?;
            scanner.scan_pkgbuild(&pkgbuild_path, registry_ctx).await
        })
        .await;
        let mut result = match fetched_and_scanned {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("fetch/scan failed: {e}").red());
                unscannable.push(base.clone()); // never reviewed
                continue;
            }
        };

        // Compare against the last time this package was seen and record the
        // new state, exactly as `check` does. Without this, installing laid no
        // baseline, so a later `check` took the first-scan branch and was
        // silent for a cycle -- while quietly recording the post-hijack state
        // as normal.
        if let Some(h) = history.as_ref() {
            let maintainer = match node_info.get(base.as_str()) {
                Some(i) => super::check::MaintainerLookup::Known(i.maintainer.clone()),
                None => super::check::MaintainerLookup::NotLookedUp,
            };
            match super::check::diff_against_history(
                h,
                &result,
                &pkgbuild_path,
                maintainer,
                Scope::Aur,
                aur_scanner_core::history::analysis_fingerprint(scanner.min_severity()),
            ) {
                // Gates see the full set: `min_severity` is display-only.
                Ok(diff_findings) => result.findings.extend(diff_findings),
                Err(e) => tracing::debug!("history comparison for {base} failed: {e}"),
            }
            result.findings.sort_by_key(|f| f.severity);
        }
        // A file the scanner could not analyze (SCAN-001) was never reviewed:
        // that is a hard stop, which --force must not override.
        if let Some(why) = unreviewed_reason(&result) {
            println!("{}", why.red());
            unscannable.push(format!("{base} ({why})"));
        }
        let scan = ComponentScan::from_findings(&result.findings);
        let trips = result
            .findings
            .iter()
            .any(|f| f.severity.is_at_least(args.fail_on));
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
        // Pin what was scanned: the build must run on exactly these bytes.
        match snapshot_dir(&dir) {
            Ok(snap) => {
                snapshots.insert(base.clone(), snap);
            }
            Err(e) => {
                println!("{}", format!("could not hash scanned files: {e}").red());
                unscannable.push(base.clone());
                continue;
            }
        }
        if let Ok(text) = std::fs::read_to_string(dir.join("PKGBUILD")) {
            if let Ok(parsed) = StaticParser::new().parse(&text) {
                let notices = late_fetch_notices(&parsed);
                if !notices.is_empty() {
                    late_notices.push((base.clone(), notices));
                }
            }
        }
        base_dirs.insert(base, dir);
    }

    // Housekeeping, once per run and after every record for this scan is
    // written. Failures are ignored: pruning must never affect a scan's outcome.
    if let Some(h) = history.as_ref() {
        h.prune(History::DEFAULT_MAX_AGE_DAYS, History::DEFAULT_MAX_RECORDS);
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

    for note in &graph.notes {
        println!("{} {}", "note:".yellow(), note);
    }
    if !late_notices.is_empty() {
        println!();
        println!(
            "{}",
            "NOTICE: the scan covers the files in each package repository. makepkg will still \
             fetch and run the following AFTER this scan; that content is NOT covered:"
                .yellow()
                .bold()
        );
        for (base, lines) in &late_notices {
            for l in lines {
                println!("  {} {}", base.white().bold(), l);
            }
        }
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

    // 4. Gate (audit ME-8: --force can override reviewed findings, but NEVER an
    //    unscannable/never-reviewed package).
    println!();
    match gate_outcome(!unscannable.is_empty(), gate_tripped, args.force) {
        GateOutcome::BlockUnscannable => {
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
        GateOutcome::BlockFindings => {
            println!(
                "{}",
                "GATE: findings at or above the threshold.".red().bold()
            );
            anyhow::bail!(
                "blocked by scan gate; not building (use --force to override deliberately)"
            );
        }
        GateOutcome::ForceOverride => {
            println!(
                "{}",
                "GATE: findings at or above the threshold.".red().bold()
            );
            println!(
                "{}",
                "--force given: overriding findings gate.".yellow().bold()
            );
        }
        GateOutcome::Pass => {
            println!("{}", "GATE: passed -- no blocking findings.".green().bold());
        }
    }

    // 5. Confirm, then build in dependency order from the SAME directories.
    match consent_gate(args.noconfirm, io::stdin().is_terminal()) {
        // Explicit --noconfirm: the operator has pre-consented; build.
        ConsentGate::Proceed => {}
        // Non-interactive stdin without --noconfirm cannot give genuine consent.
        // A piped "y" is not a person agreeing to build attacker-authored code,
        // so fail closed and abort (mirrors the wrapper's confirm contract).
        ConsentGate::AbortNonInteractive => {
            println!(
                "{}",
                "Aborted: stdin is not a terminal and --noconfirm was not given; \
                 refusing to build without interactive consent."
                    .yellow()
            );
            anyhow::bail!(
                "no interactive consent (stdin is not a terminal and --noconfirm not given)"
            );
        }
        // Interactive TTY: prompt and require an explicit yes.
        ConsentGate::Prompt => {
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
                anyhow::bail!("aborted by user; nothing was built");
            }
        }
    }

    let plan = build_plan(&graph, &node_base);
    let mut built: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for step in &plan {
        let base = step.base.clone();
        let dir = match base_dirs.get(&base) {
            Some(d) if d.join("PKGBUILD").is_file() => d.clone(),
            _ => {
                anyhow::bail!(
                    "{base} was not fetched; refusing to continue (built so far: {built:?})"
                );
            }
        };
        // Re-verify the scanned bytes immediately before building: abort if
        // anything in the directory changed since the scan.
        let before = snapshots
            .get(&base)
            .with_context(|| format!("no scan-time snapshot for {base}"))?;
        let changed = snapshot_changes(&dir, before)
            .with_context(|| format!("re-hashing {}", dir.display()))?;
        if !changed.is_empty() {
            anyhow::bail!(
                "{base} changed after it was scanned ({}); refusing to build unscanned content",
                changed.join(", ")
            );
        }
        built.insert(base.clone());
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
        cmd.args(makepkg_args(step.as_dep, args.noconfirm))
            .current_dir(&dir);
        // Sanitize the build environment (audit ME-4): do not let a poisoned
        // ambient PATH/GNUPGHOME/GIT_*/BUILDDIR undo the clean scan by redirecting
        // makepkg's trusted helpers. Start empty and apply only the allowlist.
        cmd.env_clear();
        for (k, v) in sanitized_build_env(std::env::vars()) {
            cmd.env(k, v);
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

    // 6. Tidy up after a successful install: remove the per-package build dirs we
    //    created in the workspace (large clones + build trees that otherwise just
    //    accumulate). Only on full success, and only dirs that are direct children
    //    of the workspace (the same invariant enforced at fetch time).
    if !args.keep_build {
        let mut cleaned = 0usize;
        for base in &built {
            if let Some(dir) = base_dirs.get(base) {
                if dir.parent() == Some(workspace.as_path()) && std::fs::remove_dir_all(dir).is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- build-consent fail-closed contract (defect #11) ---------------------

    #[test]
    fn noconfirm_proceeds_regardless_of_tty() {
        // Explicit operator pre-consent: build whether or not stdin is a TTY.
        assert_eq!(consent_gate(true, true), ConsentGate::Proceed);
        assert_eq!(consent_gate(true, false), ConsentGate::Proceed);
    }

    #[test]
    fn interactive_without_noconfirm_prompts() {
        assert_eq!(consent_gate(false, true), ConsentGate::Prompt);
    }

    #[test]
    fn non_interactive_without_noconfirm_fails_closed() {
        // The regression for defect #11: a pipe/CI/cron stdin with no
        // --noconfirm must abort, never silently accept a piped "y".
        assert_eq!(consent_gate(false, false), ConsentGate::AbortNonInteractive);
    }

    // --- gate: --force never overrides an unscannable package (audit ME-8) ----

    #[test]
    fn force_cannot_override_unscannable() {
        // The invariant: a never-reviewed package is a hard stop regardless of
        // --force, and regardless of whether the findings gate also tripped.
        assert_eq!(
            gate_outcome(true, false, false),
            GateOutcome::BlockUnscannable
        );
        assert_eq!(
            gate_outcome(true, false, true),
            GateOutcome::BlockUnscannable
        );
        assert_eq!(
            gate_outcome(true, true, true),
            GateOutcome::BlockUnscannable
        );
    }

    #[test]
    fn force_overrides_only_reviewed_findings() {
        // Findings the user has seen: blocked without --force, overridable with.
        assert_eq!(gate_outcome(false, true, false), GateOutcome::BlockFindings);
        assert_eq!(gate_outcome(false, true, true), GateOutcome::ForceOverride);
    }

    #[test]
    fn clean_scan_passes_the_gate() {
        assert_eq!(gate_outcome(false, false, false), GateOutcome::Pass);
        assert_eq!(gate_outcome(false, false, true), GateOutcome::Pass);
    }

    // --- sanitized build environment (audit ME-4) ----------------------------

    #[test]
    fn build_env_forces_known_good_path() {
        // A poisoned ambient PATH must be replaced, never inherited.
        let env = sanitized_build_env([(
            "PATH".to_string(),
            "/tmp/evil:/home/x/.local/bin".to_string(),
        )]);
        let path = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str());
        assert_eq!(path, Some("/usr/bin:/bin:/usr/local/bin"));
        assert!(
            !env.iter().any(|(_, v)| v.contains("evil")),
            "poisoned PATH must be dropped"
        );
    }

    #[test]
    fn build_env_drops_redirect_vectors() {
        // GNUPGHOME / BUILDDIR / GIT_* / LD_PRELOAD must NOT pass through, so they
        // cannot redirect a trusted helper or weaken signature checks.
        let ambient = [
            ("GNUPGHOME", "/tmp/attacker-keys"),
            ("BUILDDIR", "/tmp/redirect"),
            ("PKGDEST", "/tmp/redirect"),
            ("GIT_SSL_NO_VERIFY", "1"),
            ("GIT_SSH", "/tmp/evil-ssh"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("PATH", "/tmp/evil"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let env = sanitized_build_env(ambient);
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for dropped in [
            "GNUPGHOME",
            "BUILDDIR",
            "PKGDEST",
            "GIT_SSL_NO_VERIFY",
            "GIT_SSH",
            "LD_PRELOAD",
        ] {
            assert!(
                !keys.contains(&dropped),
                "{dropped} must be dropped from the build env"
            );
        }
    }

    #[test]
    fn build_env_keeps_safe_passthroughs() {
        let ambient = [
            ("HOME", "/home/alice"),
            ("LANG", "en_US.UTF-8"),
            ("MAKEFLAGS", "-j4"),
            ("EVIL", "x"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let env = sanitized_build_env(ambient);
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.clone());
        assert_eq!(get("HOME").as_deref(), Some("/home/alice"));
        assert_eq!(get("LANG").as_deref(), Some("en_US.UTF-8"));
        assert_eq!(get("MAKEFLAGS").as_deref(), Some("-j4"));
        assert_eq!(get("EVIL"), None, "non-allowlisted vars must be dropped");
    }

    // --- refuse non-AUR roots, build order, --asdeps, notices ------------------

    fn aur_node(name: &str, deps: &[&str]) -> depgraph::PackageNode {
        depgraph::PackageNode {
            name: name.to_string(),
            source: PackageSource::Aur,
            package_base: Some(name.to_string()),
            depends: deps.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn graph_of(roots: &[&str], nodes: Vec<depgraph::PackageNode>) -> DependencyGraph {
        DependencyGraph {
            roots: roots.iter().map(|s| s.to_string()).collect(),
            nodes: nodes.into_iter().map(|n| (n.name.clone(), n)).collect(),
            ..Default::default()
        }
    }

    fn bases(g: &DependencyGraph) -> BTreeMap<String, String> {
        g.aur_packages()
            .iter()
            .map(|n| (n.name.clone(), n.package_base.clone().unwrap()))
            .collect()
    }

    #[test]
    fn repo_and_virtual_roots_are_refused() {
        // `paru -S firefox` with AUR_SCAN_MODE=install: firefox is a repo package.
        let mut firefox = aur_node("firefox", &[]);
        firefox.source = PackageSource::Repo;
        let mut ghost = aur_node("ghost", &[]);
        ghost.source = PackageSource::Unresolved;
        let mut virt = aur_node("virt", &["thing-git"]);
        virt.source = PackageSource::Provided;
        let g = graph_of(
            &["firefox", "ghost", "virt", "mine", "absent"],
            vec![
                firefox,
                ghost,
                virt,
                aur_node("mine", &[]),
                aur_node("thing-git", &[]),
            ],
        );
        assert_eq!(
            non_aur_roots(&g),
            vec!["firefox", "ghost", "virt", "absent"]
        );
        let ok = graph_of(&["mine"], vec![aur_node("mine", &[])]);
        assert!(non_aur_roots(&ok).is_empty());
    }

    #[test]
    fn dependencies_build_first_and_get_asdeps() {
        // app -> lib -> base (all AUR), plus app -> virt -> prov (virtual).
        let mut virt = aur_node("virt", &["prov"]);
        virt.source = PackageSource::Provided;
        let g = graph_of(
            &["app"],
            vec![
                aur_node("app", &["lib", "virt"]),
                aur_node("lib", &["base"]),
                aur_node("base", &[]),
                virt,
                aur_node("prov", &[]),
            ],
        );
        let plan = build_plan(&g, &bases(&g));
        let names: Vec<&str> = plan.iter().map(|s| s.base.as_str()).collect();
        let pos = |n: &str| names.iter().position(|x| *x == n).unwrap();
        assert!(pos("base") < pos("lib") && pos("lib") < pos("app"));
        assert!(pos("prov") < pos("app"));
        assert_eq!(names.len(), 4);
        for step in &plan {
            assert_eq!(step.as_dep, step.base != "app", "{step:?}");
        }
    }

    #[test]
    fn split_package_base_waits_for_all_member_dependencies() {
        // base `multi` ships `multi-a` and `multi-b`; `multi-b` needs `late`.
        let mut a = aur_node("multi-a", &[]);
        a.package_base = Some("multi".into());
        let mut b = aur_node("multi-b", &["late"]);
        b.package_base = Some("multi".into());
        let g = graph_of(&["multi-a"], vec![a, b, aur_node("late", &[])]);
        let plan = build_plan(&g, &bases(&g));
        let names: Vec<&str> = plan.iter().map(|s| s.base.as_str()).collect();
        assert_eq!(names, vec!["late", "multi"]);
        assert!(!plan[1].as_dep, "a base containing a root is explicit");
    }

    #[test]
    fn makepkg_args_mark_dependencies() {
        assert_eq!(makepkg_args(false, false), vec!["-si"]);
        assert_eq!(makepkg_args(true, false), vec!["-si", "--asdeps"]);
        assert_eq!(
            makepkg_args(true, true),
            vec!["-si", "--asdeps", "--noconfirm"]
        );
    }

    #[test]
    fn unpinned_and_unchecked_sources_are_called_out() {
        let text = "pkgname=a\npkgver=1\npkgrel=1\n\
source=('local.patch' 'https://x.example/a.tar.gz' 'git+https://x.example/r.git' \
'git+https://x.example/p.git#commit=0123456789abcdef0123456789abcdef01234567')\n\
sha256sums=('aaaa' 'SKIP' 'SKIP' 'SKIP')\n\
pkgver() { echo 1; }\n";
        let parsed = StaticParser::new().parse(text).unwrap();
        let n = late_fetch_notices(&parsed);
        assert!(
            n.iter()
                .any(|l| l.contains("a.tar.gz") && l.contains("SKIP")),
            "{n:?}"
        );
        assert!(
            n.iter()
                .any(|l| l.contains("r.git") && l.contains("not pinned")),
            "{n:?}"
        );
        assert!(
            !n.iter().any(|l| l.contains("p.git")),
            "pinned commit is fine: {n:?}"
        );
        assert!(!n.iter().any(|l| l.contains("local.patch")), "{n:?}");
        assert!(n.iter().any(|l| l.contains("pkgver()")), "{n:?}");

        let clean = "pkgname=a\npkgver=1\npkgrel=1\nsource=('https://x.example/a.tar.gz')\nsha256sums=('aaaa')\n";
        let parsed = StaticParser::new().parse(clean).unwrap();
        assert!(late_fetch_notices(&parsed).is_empty());
    }

    #[test]
    fn unanalyzable_file_is_unreviewed_and_force_cannot_override() {
        use aur_scanner_core::{Category, Finding, Location, ScanResult};
        let finding = |id: &str| Finding {
            id: id.to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            title: "t".into(),
            description: "d".into(),
            location: Location {
                file: PathBuf::from("x.install"),
                line: None,
                column: None,
                snippet: None,
            },
            recommendation: "r".into(),
            cwe_id: None,
            metadata: serde_json::Value::Null,
        };
        let mk = |ids: &[&str]| ScanResult {
            package_name: "p".into(),
            package_version: "1-1".into(),
            findings: ids.iter().map(|i| finding(i)).collect(),
            scanned_files: vec![],
            timestamp: "2026-01-01T00:00:00Z".parse().unwrap(),
            scan_duration_ms: 0,
        };
        assert!(unreviewed_reason(&mk(&["EXEC-001"])).is_none());
        let r = mk(&["SCAN-001"]);
        assert!(unreviewed_reason(&r).is_some());
        // Feeding it into the gate: blocked even with --force.
        assert_eq!(
            gate_outcome(unreviewed_reason(&r).is_some(), false, true),
            GateOutcome::BlockUnscannable
        );
    }
}
