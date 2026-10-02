//! Pacman hook for AUR security scanning
//!
//! This binary is invoked by pacman before package transactions
//! to scan AUR packages for security issues.
//!
//! The hook is a BACKSTOP behind the shell integrations / wrapper: it fires on
//! the actually-installed target regardless of which helper (or none) started
//! the transaction. By default it never aborts a transaction merely because it
//! could not find a PKGBUILD to scan (that would brick `pacman -U` of a local
//! package), but it says so loudly for every target it did not scan. Opt in to
//! aborting on those with `AUR_SCAN_HOOK_STRICT=1` or by creating the marker
//! file `/etc/aur-scanner/hook-strict`.

use anyhow::Result;
use aur_scanner_core::validate::is_valid_package_name;
use aur_scanner_core::{Registry, ScanConfig, Scanner, Severity};
use colored::Colorize;
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Marker file that turns on strict mode (abort on an unscanned target).
const STRICT_MARKER: &str = "/etc/aur-scanner/hook-strict";
/// Read caps for untrusted cache files.
const SRCINFO_CAP: u64 = 64 * 1024;
const PKGBUILD_VERSION_CAP: u64 = 256 * 1024;
/// Bound on directories examined per cache root while indexing `.SRCINFO`.
const MAX_INDEX_DIRS: usize = 4096;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .init();

    // Load configuration. This MUST happen before the privilege drop below --
    // /etc/aur-scanner/config.toml may be root-readable only -- which is exactly
    // why the lookup is privilege-aware: as root we read `/etc` and nothing
    // else. Consulting the CLI's user-first search order here would let any
    // unprivileged user hand a root process its security config, and because a
    // malformed security config is a deliberate hard error, let them wedge every
    // pacman transaction with broken TOML in `~/.config/aur-scanner/`.
    //
    // Failing closed on a malformed config is still correct: scanning silently
    // with defaults is worse than refusing the transaction.
    let config = match ScanConfig::resolve_for_privilege(None, running_as_root()) {
        Ok((config, _)) => config,
        Err(e) => {
            eprintln!("{} invalid config: {}", "aur-scanner:".red().bold(), e);
            std::process::exit(2);
        }
    };

    let scanner = Scanner::new(config)?;

    // Strict mode is decided while we still have root (the marker lives in /etc).
    let strict = strict_mode(
        std::env::var("AUR_SCAN_HOOK_STRICT").ok().as_deref(),
        std::fs::symlink_metadata(STRICT_MARKER).is_ok(),
    );

    // Drop root before touching user-owned cache files. The hook runs as root
    // (pacman context) but only ever needs to READ a user's AUR build cache and
    // set an exit code -- nothing requires root. Dropping to the invoking user
    // means a hostile file in that cache (symlink, payload) is parsed with the
    // user's privileges, not root's. If we are root but cannot identify the
    // invoking user, we do not scan user caches as root.
    let scan_user = drop_privileges_to_invoking_user();

    // Read package names from stdin (pacman hook provides this)
    let stdin = io::stdin();
    let packages: Vec<String> = stdin.lock().lines().map_while(Result::ok).collect();

    let scan_user = match scan_user {
        Some(u) => u,
        None => {
            eprintln!(
                "{} could not determine the invoking user (checked SUDO_UID, DOAS_USER, \
                 PKEXEC_UID and the login uid); {} package(s) were NOT scanned. \
                 Use the shell integration for full coverage.",
                "WARNING:".yellow().bold(),
                packages.len()
            );
            if strict {
                eprintln!(
                    "{} strict mode: aborting the transaction (nothing was scanned).",
                    "ERROR:".red().bold()
                );
                std::process::exit(1);
            }
            return Ok(());
        }
    };

    let roots = candidate_roots(
        &scan_user.home,
        &XdgDirs::from_env(),
        &helper_config_dirs(&scan_user.home),
    );
    let srcinfo_index: OnceCell<HashMap<String, Vec<PathBuf>>> = OnceCell::new();

    // Which targets are in a sync repo (so legitimately have no PKGBUILD), and
    // the versions being installed from local package files (`pacman -U`).
    let sync_names = list_sync_names();
    if sync_names.is_none() {
        eprintln!(
            "{} could not list the sync repositories; targets without a cached \
             PKGBUILD cannot be told apart from official packages.",
            "WARNING:".yellow().bold()
        );
    }
    let upgrade_versions = versions_from_pacman_upgrade_files();

    let mut has_critical = false;
    let mut has_high = false;
    // A PKGBUILD we located but could not scan is a failure to analyze a package
    // that is about to be built: fail closed (abort the transaction) rather than
    // logging at debug and letting it through.
    let mut scan_failed = false;
    // Targets that were not (or not verifiably) scanned.
    let mut unscanned: Vec<String> = Vec::new();

    for package in packages {
        let package = package.trim().to_string();
        if package.is_empty() {
            continue;
        }
        if !is_valid_package_name(&package) {
            eprintln!(
                "{} not scanned: target {:?} is not a valid package name.",
                "WARNING:".yellow().bold(),
                package
            );
            unscanned.push(package);
            continue;
        }

        // Try to find PKGBUILD(s) in the helpers' cache locations. A helper clones
        // by pkgbase, so a split package's target name is found via `.SRCINFO`.
        // The `.SRCINFO` index is consulted for EVERY target, not only when the
        // exact-name directory is missing: a stale `<root>/<pkgname>/` must not
        // hide the real pkgbase clone that is actually being built.
        let lookup = locate_pkgbuilds(&package, &roots, &srcinfo_index);
        let pkgbuild_paths = match lookup {
            PkgbuildLookup::Found(p) => p,
            PkgbuildLookup::RefusedOnly => {
                // A non-regular file where a PKGBUILD belongs: cannot analyze it,
                // so fail closed rather than treat it like an absent package.
                eprintln!(
                    "{} {} has a non-regular file where its PKGBUILD should be; \
                     refusing the transaction.",
                    "ERROR:".red().bold(),
                    package.bold()
                );
                scan_failed = true;
                continue;
            }
            PkgbuildLookup::NotFound => {
                // No cached PKGBUILD. Fine for an official-repo package; a foreign
                // package (AUR, `pacman -U`) is unscanned: say so loudly.
                let official = sync_names.as_ref().is_some_and(|s| s.contains(&package));
                if !official {
                    eprintln!(
                        "{} not scanned: no PKGBUILD found for {} (not in any sync repository).",
                        "WARNING:".yellow().bold(),
                        package.bold()
                    );
                    unscanned.push(package);
                }
                continue;
            }
        };

        // Is the cached PKGBUILD the one being installed? Compare the version it
        // declares with the version the transaction installs, when both are known.
        let installing = upgrade_versions
            .get(&package)
            .cloned()
            .or_else(|| sync_version(&package));
        let declared: Vec<Option<String>> = pkgbuild_paths
            .iter()
            .map(|p| read_capped(p, PKGBUILD_VERSION_CAP).and_then(|t| pkgbuild_version(&t)))
            .collect();
        // Several candidates (a stale clone next to the real one): scan them
        // all, the one matching the version being installed first, and say so
        // when they disagree.
        let (pkgbuild_paths, divergence) =
            order_candidates(pkgbuild_paths, &declared, installing.as_deref());
        if let Some(note) = divergence {
            eprintln!(
                "{} {} has {}",
                "WARNING:".yellow().bold(),
                package.bold(),
                note
            );
        }
        if let Some(installing) = installing {
            if version_mismatch(&declared, &installing) {
                eprintln!(
                    "{} the cached PKGBUILD for {} does not match the version being installed \
                     ({}); what gets installed was not scanned.",
                    "WARNING:".yellow().bold(),
                    package.bold(),
                    installing
                );
                unscanned.push(package.clone());
            }
        }

        for pkgbuild_path in pkgbuild_paths {
            // Deliberate: the hook runs inside a pacman transaction and is
            // offline by design -- it must not make network calls mid-install.
            // Ownership and name-impersonation analysis therefore cannot run
            // here (documented limitation); every static analyzer still runs.
            match scanner.scan_pkgbuild(&pkgbuild_path, Registry::None).await {
                Ok(result) => {
                    if !result.findings.is_empty() {
                        eprintln!();
                        eprintln!(
                            "{} Security findings for {}:",
                            "WARNING:".yellow().bold(),
                            package.bold()
                        );

                        for finding in &result.findings {
                            let severity_str = match finding.severity {
                                Severity::Critical => "CRITICAL".red().bold(),
                                Severity::High => "HIGH".yellow().bold(),
                                Severity::Medium => "MEDIUM".cyan(),
                                Severity::Low => "LOW".normal(),
                                Severity::Info => "INFO".dimmed(),
                            };

                            eprintln!("  [{}] {}: {}", severity_str, finding.id, finding.title);

                            if finding.severity == Severity::Critical {
                                has_critical = true;
                            }
                            if finding.severity == Severity::High {
                                has_high = true;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} could not scan {} ({}); refusing the transaction.",
                        "ERROR:".red().bold(),
                        package.bold(),
                        e
                    );
                    scan_failed = true;
                }
            }
        }
    }

    // Fail-closed exit decision (precedence: a scan failure or a critical finding
    // aborts the transaction; high-severity only warns; unscanned targets abort
    // only in strict mode). The precedence/branch selection is a pure function so
    // the fail-closed contract is unit-testable; the messaging + process exit stay
    // here.
    match decide_hook_outcome(
        scan_failed,
        has_critical,
        has_high,
        strict && !unscanned.is_empty(),
    ) {
        HookDecision::Abort(AbortReason::ScanFailed) => {
            eprintln!();
            eprintln!(
                "{} a package could not be analyzed. Aborting transaction (fail-closed).",
                "ERROR:".red().bold()
            );
            std::process::exit(1);
        }
        HookDecision::Abort(AbortReason::Critical) => {
            eprintln!();
            eprintln!(
                "{} Critical security issues found. Aborting transaction.",
                "ERROR:".red().bold()
            );
            eprintln!("Use 'aur-scan scan <package-dir>' for details.");
            eprintln!();
            std::process::exit(1);
        }
        HookDecision::Abort(AbortReason::Unscanned) => {
            eprintln!();
            eprintln!(
                "{} strict mode: not scanned: {}. Aborting transaction.",
                "ERROR:".red().bold(),
                unscanned.join(", ")
            );
            std::process::exit(1);
        }
        HookDecision::Proceed { warn_high } => {
            if warn_high {
                eprintln!();
                eprintln!(
                    "{} High severity issues found. Review recommended.",
                    "WARNING:".yellow().bold()
                );
                eprintln!();
            }
            if !unscanned.is_empty() {
                eprintln!(
                    "{} {} target(s) were not scanned: {}. \
                     (Set AUR_SCAN_HOOK_STRICT=1 or create {} to abort on this.)",
                    "WARNING:".yellow().bold(),
                    unscanned.len(),
                    unscanned.join(", "),
                    STRICT_MARKER
                );
            }
        }
    }

    Ok(())
}

/// Strict mode: `AUR_SCAN_HOOK_STRICT=1`, or the marker file exists.
fn strict_mode(env: Option<&str>, marker_exists: bool) -> bool {
    env == Some("1") || marker_exists
}

/// Why the hook is aborting the pacman transaction (exit 1). Carried so the
/// caller can print the reason-specific message while the precedence stays in
/// one tested place.
#[derive(Debug, PartialEq, Eq)]
enum AbortReason {
    /// A located PKGBUILD could not be analyzed -> fail closed.
    ScanFailed,
    /// At least one Critical finding was raised.
    Critical,
    /// Strict mode and at least one target was not (verifiably) scanned.
    Unscanned,
}

/// What the hook should do once every package has been scanned.
#[derive(Debug, PartialEq, Eq)]
enum HookDecision {
    /// Abort the transaction (exit 1).
    Abort(AbortReason),
    /// Allow the transaction; print the high-severity notice when `warn_high`.
    Proceed { warn_high: bool },
}

/// Decide the hook's terminal action from the accumulated scan state.
///
/// Fail-closed precedence: an un-analyzable package aborts BEFORE a critical
/// finding (both exit 1), a critical finding aborts before an unscanned target
/// in strict mode, and any of those before a high-severity warning. High
/// severity alone proceeds with a warning; a fully clean run proceeds silently.
/// `strict_unscanned` is true only when strict mode is on AND something was not
/// scanned.
fn decide_hook_outcome(
    scan_failed: bool,
    has_critical: bool,
    has_high: bool,
    strict_unscanned: bool,
) -> HookDecision {
    if scan_failed {
        HookDecision::Abort(AbortReason::ScanFailed)
    } else if has_critical {
        HookDecision::Abort(AbortReason::Critical)
    } else if strict_unscanned {
        HookDecision::Abort(AbortReason::Unscanned)
    } else {
        HookDecision::Proceed {
            warn_high: has_high,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache roots
// ---------------------------------------------------------------------------

/// XDG base directories, honoured only when set to an absolute path. The hook
/// cannot see the invoking user's own environment (it runs under pacman as
/// root), so these only apply when pacman's environment carries them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct XdgDirs {
    cache: Option<PathBuf>,
    data: Option<PathBuf>,
    config: Option<PathBuf>,
}

impl XdgDirs {
    fn from_env() -> Self {
        let abs = |k: &str| {
            std::env::var_os(k)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        XdgDirs {
            cache: abs("XDG_CACHE_HOME"),
            data: abs("XDG_DATA_HOME"),
            config: abs("XDG_CONFIG_HOME"),
        }
    }
}

/// Every directory that may hold `<pkgbase>/PKGBUILD` clones, in probe order.
///
/// Mirrors the per-helper list `aur-scan system` uses (note pikaur stores
/// PKGBUILDs under the *data* dir and rua under the *config* dir, not
/// `~/.cache`). For each of cache/data/config the XDG override is probed first,
/// then the `$HOME` default; `extra` carries directories read from the helpers'
/// own config (paru `CloneDir`, yay `buildDir`). `/var/cache/aur` is last.
/// Pure (no filesystem access).
fn candidate_roots(home: &Path, xdg: &XdgDirs, extra: &[PathBuf]) -> Vec<PathBuf> {
    let cache_bases = [xdg.cache.clone(), Some(home.join(".cache"))];
    let data_bases = [xdg.data.clone(), Some(home.join(".local/share"))];
    let config_bases = [xdg.config.clone(), Some(home.join(".config"))];

    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !roots.contains(&p) {
            roots.push(p);
        }
    };
    for p in extra {
        push(p.clone());
    }
    for base in cache_bases.iter().flatten() {
        for rel in [
            "yay",
            "paru/clone",
            "aura/packages",
            "pakku",
            "trizen/sources",
            "aurutils/sync",
            "pat-aur/pkgbuild/aur",
        ] {
            push(base.join(rel));
        }
    }
    for base in data_bases.iter().flatten() {
        push(base.join("pikaur/aur_repos"));
    }
    for base in config_bases.iter().flatten() {
        push(base.join("rua/pkg"));
    }
    push(PathBuf::from("/var/cache/aur"));
    roots
}

/// Expand a leading `~`/`$HOME` against `home`; only absolute results are kept.
fn expand_home(value: &str, home: &Path) -> Option<PathBuf> {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    let p = if let Some(rest) = v.strip_prefix("~/") {
        home.join(rest)
    } else if v == "~" {
        home.to_path_buf()
    } else if let Some(rest) = v.strip_prefix("$HOME/") {
        home.join(rest)
    } else {
        PathBuf::from(v)
    };
    (p.is_absolute() && !p.components().any(|c| c.as_os_str() == "..")).then_some(p)
}

/// paru.conf `CloneDir = <path>` (the `[options]` section).
fn parse_paru_clonedir(text: &str, home: &Path) -> Option<PathBuf> {
    text.lines().take(2000).find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix("CloneDir")?.trim_start().strip_prefix('=')?;
        expand_home(rest, home)
    })
}

/// yay `config.json` `"buildDir": "<path>"` (crude on purpose: no JSON dep).
fn parse_yay_builddir(text: &str, home: &Path) -> Option<PathBuf> {
    let idx = text.find("\"buildDir\"")?;
    let after = &text[idx + "\"buildDir\"".len()..];
    let after = after.trim_start().strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    expand_home(&after[..end], home)
}

/// Extra cache roots from the helpers' own config files (read as the invoking
/// user, size-capped, never following a symlink).
fn helper_config_dirs(home: &Path) -> Vec<PathBuf> {
    let xdg_config = XdgDirs::from_env()
        .config
        .unwrap_or_else(|| home.join(".config"));
    let mut out = Vec::new();
    if let Some(t) = read_capped(&xdg_config.join("paru/paru.conf"), SRCINFO_CAP) {
        out.extend(parse_paru_clonedir(&t, home));
    }
    if let Some(t) = read_capped(&xdg_config.join("yay/config.json"), SRCINFO_CAP) {
        out.extend(parse_yay_builddir(&t, home));
    }
    out
}

// ---------------------------------------------------------------------------
// Safe reads of untrusted cache files
// ---------------------------------------------------------------------------

/// Read at most `cap` bytes from a regular file WITHOUT following a final
/// symlink and without blocking on a FIFO. Returns `None` for anything else.
fn read_capped(path: &Path, cap: u64) -> Option<String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    file.take(cap).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The `pkgname = ...` entries of a `.SRCINFO` (bounded, validated).
fn srcinfo_pkgnames(text: &str) -> Vec<String> {
    text.lines()
        .take(10_000)
        .filter_map(|l| {
            let v = l
                .trim()
                .strip_prefix("pkgname")?
                .trim_start()
                .strip_prefix('=')?
                .trim();
            is_valid_package_name(v).then(|| v.to_string())
        })
        .collect()
}

/// Index `pkgname -> cache dirs` over the immediate children of every root, using
/// each child's `.SRCINFO`. Helpers clone by *pkgbase*, so a split package's
/// target name only appears here. Bounded (entries per root, bytes per file) and
/// symlinks are never followed (`DirEntry::file_type` does not resolve them).
fn build_srcinfo_index(roots: &[PathBuf]) -> HashMap<String, Vec<PathBuf>> {
    let mut index: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for root in roots {
        let Ok(rd) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in rd.flatten().take(MAX_INDEX_DIRS) {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let dir = entry.path();
            if !entry
                .file_name()
                .to_str()
                .is_some_and(is_valid_package_name)
            {
                continue;
            }
            let Some(text) = read_capped(&dir.join(".SRCINFO"), SRCINFO_CAP) else {
                continue;
            };
            for name in srcinfo_pkgnames(&text) {
                let dirs = index.entry(name).or_default();
                if !dirs.contains(&dir) {
                    dirs.push(dir.clone());
                }
            }
        }
    }
    index
}

// ---------------------------------------------------------------------------
// PKGBUILD lookup
// ---------------------------------------------------------------------------

/// Outcome of probing one candidate PKGBUILD path. `symlink_metadata` does NOT
/// follow the final symlink, so a symlink/FIFO/dir cache entry is classified
/// `RefusedNonRegular` (an O_NOFOLLOW-equivalent on the last component) and is
/// never read through.
#[derive(Debug, PartialEq, Eq)]
enum PkgbuildProbe {
    /// A regular file -- safe to read.
    Usable,
    /// Exists but is not a regular file (symlink / FIFO / dir / ...) -- refuse.
    RefusedNonRegular,
    /// Nothing at this path.
    Absent,
}

/// Classify a candidate PKGBUILD path WITHOUT following a final symlink.
fn classify_pkgbuild(path: &Path) -> PkgbuildProbe {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_file() => PkgbuildProbe::Usable,
        Ok(_) => PkgbuildProbe::RefusedNonRegular,
        Err(_) => PkgbuildProbe::Absent,
    }
}

/// Result of probing every candidate location for a package's PKGBUILD.
#[derive(Debug, PartialEq, Eq)]
enum PkgbuildLookup {
    /// Regular, readable PKGBUILD(s) were found. Every one is scanned.
    Found(Vec<PathBuf>),
    /// No usable PKGBUILD, but at least one candidate existed as a non-regular
    /// file (dir/symlink/FIFO) -- anomalous, so the transaction fails closed.
    RefusedOnly,
    /// No candidate existed at all (an official-repo package, or a foreign one
    /// the hook cannot see).
    NotFound,
}

/// Locate every cached PKGBUILD for `package`: the exact-name directories AND
/// every directory whose `.SRCINFO` lists it. The index is always consulted so
/// a stale or decoy `<root>/<package>/` can never stand in for (shadow) the real
/// pkgbase clone.
fn locate_pkgbuilds(
    package: &str,
    roots: &[PathBuf],
    index: &OnceCell<HashMap<String, Vec<PathBuf>>>,
) -> PkgbuildLookup {
    let index = index.get_or_init(|| build_srcinfo_index(roots));
    find_pkgbuilds_for_package(package, roots, Some(index))
}

/// Order the candidate PKGBUILDs so the one whose declared version matches the
/// version being installed comes first, and describe any disagreement between
/// the candidates. Nothing is dropped: the caller scans every candidate.
/// `declared[i]` is the version `paths[i]` declares (`None` = not statically
/// known, e.g. a VCS `pkgver()`).
fn order_candidates(
    paths: Vec<PathBuf>,
    declared: &[Option<String>],
    installing: Option<&str>,
) -> (Vec<PathBuf>, Option<String>) {
    if paths.len() < 2 {
        return (paths, None);
    }
    let want = installing.map(normalize_version);
    let mut items: Vec<(PathBuf, Option<String>)> = paths
        .into_iter()
        .zip(declared.iter().cloned().chain(std::iter::repeat(None)))
        .collect();
    // Stable: matching versions first, otherwise discovery order.
    items.sort_by_key(|(_, d)| !(want.is_some() && d.as_deref().map(normalize_version) == want));
    let mut known: Vec<&str> = items
        .iter()
        .filter_map(|(_, d)| d.as_deref().map(normalize_version))
        .collect();
    known.sort_unstable();
    known.dedup();
    let note = (known.len() > 1).then(|| {
        let list = items
            .iter()
            .map(|(p, d)| {
                format!(
                    "{} ({})",
                    p.display(),
                    d.as_deref().unwrap_or("version unknown")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} cached PKGBUILDs that declare different versions: {list}. \
             Scanning all of them; a stale clone may be shadowing the real one.",
            items.len()
        )
    });
    (items.into_iter().map(|(p, _)| p).collect(), note)
}

/// Find the PKGBUILD(s) for `package` under `roots`.
///
/// The exact `<root>/<package>/PKGBUILD` is probed first. When `index` is given
/// (the `.SRCINFO` pkgname index) the directories that list `package` as a split
/// member are probed too. ALL usable matches are returned and scanned, so a
/// decoy cache entry can never shadow the real one.
///
/// Hardening: the name is validated before it becomes a path component, and a
/// PKGBUILD that is not a regular file is refused without being followed.
fn find_pkgbuilds_for_package(
    package: &str,
    roots: &[PathBuf],
    index: Option<&HashMap<String, Vec<PathBuf>>>,
) -> PkgbuildLookup {
    if !is_valid_package_name(package) {
        tracing::warn!("skipping target with illegal package name: {package:?}");
        return PkgbuildLookup::NotFound;
    }
    let mut dirs: Vec<PathBuf> = roots.iter().map(|r| r.join(package)).collect();
    if let Some(extra) = index.and_then(|i| i.get(package)) {
        for d in extra {
            if !dirs.contains(d) {
                dirs.push(d.clone());
            }
        }
    }

    // Track whether a candidate existed but was refused (non-regular). A package
    // that is simply absent is legitimate (the hook fires for every transaction,
    // including official-repo packages); but a non-regular file sitting exactly
    // where a PKGBUILD belongs is anomalous and must fail closed rather than be
    // treated like "absent".
    let mut found = Vec::new();
    let mut saw_non_regular = false;
    for dir in dirs {
        let pkgbuild = dir.join("PKGBUILD");
        match classify_pkgbuild(&pkgbuild) {
            PkgbuildProbe::Usable => found.push(pkgbuild),
            PkgbuildProbe::RefusedNonRegular => {
                tracing::warn!("refusing non-regular PKGBUILD at {}", pkgbuild.display());
                saw_non_regular = true;
            }
            PkgbuildProbe::Absent => {}
        }
    }
    if !found.is_empty() {
        PkgbuildLookup::Found(found)
    } else if saw_non_regular {
        PkgbuildLookup::RefusedOnly
    } else {
        PkgbuildLookup::NotFound
    }
}

// ---------------------------------------------------------------------------
// Version matching
// ---------------------------------------------------------------------------

/// The `[epoch:]pkgver-pkgrel` a PKGBUILD declares, or `None` when it cannot be
/// known statically (a `pkgver()` function, or a value built from a variable or
/// command). Static text parsing only -- the PKGBUILD is never executed.
fn pkgbuild_version(text: &str) -> Option<String> {
    let (mut epoch, mut pkgver, mut pkgrel) = (None, None, None);
    for line in text.lines().take(5000) {
        if line.starts_with("pkgver()") || line.starts_with("function pkgver") {
            return None;
        }
        for (key, slot) in [
            ("epoch=", &mut epoch),
            ("pkgver=", &mut pkgver),
            ("pkgrel=", &mut pkgrel),
        ] {
            if let Some(v) = line.strip_prefix(key) {
                if slot.is_none() {
                    let v = v.split(['#', ' ', '\t']).next().unwrap_or("");
                    let v = v.trim_matches(|c| c == '"' || c == '\'');
                    if v.is_empty() || v.contains(['$', '(', '`']) {
                        return None;
                    }
                    *slot = Some(v.to_string());
                }
            }
        }
    }
    let (pkgver, pkgrel) = (pkgver?, pkgrel?);
    Some(match epoch.as_deref() {
        Some(e) if e != "0" => format!("{e}:{pkgver}-{pkgrel}"),
        _ => format!("{pkgver}-{pkgrel}"),
    })
}

/// Normalise a pacman version string (`0:` epoch is implicit).
fn normalize_version(v: &str) -> &str {
    v.trim().strip_prefix("0:").unwrap_or(v.trim())
}

/// True when every PKGBUILD whose version IS known disagrees with `installing`
/// (so none of the scanned PKGBUILDs is the one being installed). Unknown
/// versions (VCS packages) are never a mismatch.
fn version_mismatch(declared: &[Option<String>], installing: &str) -> bool {
    let known: Vec<&String> = declared.iter().flatten().collect();
    if known.is_empty() {
        return false;
    }
    let want = normalize_version(installing);
    !known.iter().any(|d| normalize_version(d) == want)
}

/// `Name`/`Version` out of `pacman -Qi`/`-Si`/`-Qip` output.
fn parse_pacman_info(text: &str) -> (Option<String>, Option<String>) {
    let field = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };
    (field("Name"), field("Version"))
}

/// Package files named by a `pacman -U`/`--upgrade` command line, from the raw
/// `/proc/<pid>/cmdline` bytes (NUL-separated). URLs are skipped (nothing local
/// to inspect).
fn upgrade_files_from_cmdline(cmdline: &[u8]) -> Vec<PathBuf> {
    let args: Vec<&str> = cmdline
        .split(|b| *b == 0)
        .filter_map(|a| std::str::from_utf8(a).ok())
        .filter(|a| !a.is_empty())
        .collect();
    let Some(first) = args.first() else {
        return Vec::new();
    };
    if !Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("pacman"))
    {
        return Vec::new();
    }
    let is_upgrade = args[1..].iter().any(|a| {
        *a == "--upgrade" || (a.starts_with('-') && !a.starts_with("--") && a.contains('U'))
    });
    if !is_upgrade {
        return Vec::new();
    }
    args[1..]
        .iter()
        .filter(|a| !a.starts_with('-') && !a.contains("://") && a.contains(".pkg.tar"))
        .map(PathBuf::from)
        .collect()
}

/// Run a read-only `pacman` query (absolute path, cleared environment, no
/// stdin). `None` when it cannot run or exits non-zero.
fn pacman_query(args: &[&str]) -> Option<String> {
    let out = Command::new("/usr/bin/pacman")
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Names of every package in the sync databases (`pacman -Slq`).
fn list_sync_names() -> Option<HashSet<String>> {
    pacman_query(&["-Slq"]).map(|o| o.lines().map(|l| l.trim().to_string()).collect())
}

/// The version a sync-database target will install (`pacman -Si`), if any.
fn sync_version(package: &str) -> Option<String> {
    pacman_query(&["-Si", "--", package]).and_then(|o| parse_pacman_info(&o).1)
}

/// `name -> version` for the package files of a running `pacman -U`, read from
/// the parent (pacman) command line and `pacman -Qip`. Best effort.
#[cfg(unix)]
fn versions_from_pacman_upgrade_files() -> HashMap<String, String> {
    let mut map = HashMap::new();
    // SAFETY: getppid takes no arguments and cannot fail.
    let ppid = unsafe { libc::getppid() };
    let Ok(cmdline) = std::fs::read(format!("/proc/{ppid}/cmdline")) else {
        return map;
    };
    for file in upgrade_files_from_cmdline(&cmdline).into_iter().take(256) {
        let Some(file) = file.to_str() else { continue };
        if let Some(info) = pacman_query(&["-Qip", file]) {
            if let (Some(name), Some(version)) = parse_pacman_info(&info) {
                map.insert(name, version);
            }
        }
    }
    map
}

#[cfg(not(unix))]
fn versions_from_pacman_upgrade_files() -> HashMap<String, String> {
    HashMap::new()
}

// ---------------------------------------------------------------------------
// Invoking user + privilege drop
// ---------------------------------------------------------------------------

/// A resolved account (from the passwd database, never from `/home/{name}`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Passwd {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
}

/// The environment facts that identify who invoked the transaction.
#[derive(Debug, Default, Clone, Copy)]
struct InvokerEnv<'a> {
    sudo_uid: Option<&'a str>,
    sudo_gid: Option<&'a str>,
    sudo_user: Option<&'a str>,
    doas_user: Option<&'a str>,
    pkexec_uid: Option<&'a str>,
    /// Contents of `/proc/self/loginuid` (the audit login uid; survives `su`,
    /// root shells, run0).
    loginuid: Option<&'a str>,
}

/// What the hook should do about privileges before touching user files, decided
/// purely from the process state and environment. Separated from the syscalls so
/// the security-critical branch selection is unit-testable without actually
/// being root or dropping privileges.
#[derive(Debug, PartialEq, Eq)]
enum PrivilegeDecision {
    /// Not root: no drop needed. Scan caches of this account (`None` = the
    /// current account could not be resolved).
    NoDropNeeded(Option<Passwd>),
    /// Root with a valid, non-root invoking user: drop groups -> gid -> uid, then
    /// scan caches as that account.
    DropTo(Passwd),
    /// Root but no safe invoking user can be determined: skip scanning entirely
    /// (never read user caches as root).
    SkipRootNoTarget,
}

/// The audit "unset" login uid (`(uid_t)-1`).
const LOGINUID_UNSET: u32 = u32::MAX;

/// Decide the privilege action.
///
/// Not root: scan as the current account. Root: find the invoking user from, in
/// order, `SUDO_UID` (cross-checked against `SUDO_USER` when both are set),
/// `DOAS_USER`, `PKEXEC_UID`, and the kernel login uid. The first source that
/// resolves to a real account with a NON-ROOT uid AND gid wins; a uid-0 target
/// keeps the root user and a gid-0 target keeps the root group, so neither is a
/// real drop and the next source is tried. If none qualifies the answer is
/// `SkipRootNoTarget`: root never scans user files with a root credential.
fn decide_privilege_drop(
    is_root: bool,
    env: &InvokerEnv,
    current: Option<Passwd>,
    by_uid: &dyn Fn(u32) -> Option<Passwd>,
    by_name: &dyn Fn(&str) -> Option<Passwd>,
) -> PrivilegeDecision {
    if !is_root {
        return PrivilegeDecision::NoDropNeeded(current.filter(|p| p.uid != 0));
    }

    let parse_uid = |s: Option<&str>| s.and_then(|s| s.trim().parse::<u32>().ok());
    let mut candidates: Vec<Passwd> = Vec::new();

    if let Some(pw) = parse_uid(env.sudo_uid).and_then(by_uid) {
        // sudo sets SUDO_USER from the same account; disagreement means the
        // environment is not what sudo wrote, so distrust this source.
        if env
            .sudo_user
            .filter(|u| !u.is_empty())
            .is_none_or(|u| u == pw.name)
        {
            let mut pw = pw;
            if let Some(gid) = parse_uid(env.sudo_gid).filter(|g| *g != 0) {
                pw.gid = gid;
            }
            candidates.push(pw);
        }
    }
    if let Some(pw) = env.doas_user.filter(|u| !u.is_empty()).and_then(by_name) {
        candidates.push(pw);
    }
    if let Some(pw) = parse_uid(env.pkexec_uid).and_then(by_uid) {
        candidates.push(pw);
    }
    if let Some(pw) = parse_uid(env.loginuid)
        .filter(|u| *u != LOGINUID_UNSET)
        .and_then(by_uid)
    {
        candidates.push(pw);
    }

    candidates
        .into_iter()
        .find(|p| p.uid != 0 && p.gid != 0 && is_valid_package_name(&p.name))
        .map(PrivilegeDecision::DropTo)
        .unwrap_or(PrivilegeDecision::SkipRootNoTarget)
}

/// Whether this process currently holds root.
///
/// Used both to pick the config search path (before the drop, so the lookup can
/// exclude user-writable paths) and to decide the drop itself.
#[cfg(unix)]
fn running_as_root() -> bool {
    // SAFETY: simple libc getter with no memory operands.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
}

/// Look an account up through `getpwuid_r`/`getpwnam_r` (thread-safe variants;
/// the buffer is owned here, the returned strings are copied out).
#[cfg(unix)]
fn passwd_lookup(uid: Option<u32>, name: Option<&str>) -> Option<Passwd> {
    use std::ffi::{CStr, CString};
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16 * 1024];
    let cname = match name {
        Some(n) => Some(CString::new(n).ok()?),
        None => None,
    };
    // SAFETY: `pwd`, `buf` and `result` outlive the call; `buf.len()` is passed
    // as the buffer size; `cname` (when used) is a valid NUL-terminated string.
    let rc = unsafe {
        match (&cname, uid) {
            (Some(c), _) => libc::getpwnam_r(
                c.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            ),
            (None, Some(u)) => {
                libc::getpwuid_r(u, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result)
            }
            (None, None) => return None,
        }
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success `pw_name`/`pw_dir` point at NUL-terminated strings
    // inside `buf`, which is still alive.
    let (name, home) = unsafe {
        (
            CStr::from_ptr(pwd.pw_name).to_str().ok()?.to_string(),
            CStr::from_ptr(pwd.pw_dir).to_str().ok()?.to_string(),
        )
    };
    let home = PathBuf::from(home);
    // The home becomes a root of path probes: it must be an absolute, normal path.
    if !home.is_absolute() || home.components().any(|c| c.as_os_str() == "..") {
        return None;
    }
    Some(Passwd {
        name,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home,
    })
}

/// Drop root privileges to the invoking user before touching their files, and
/// return the account to scan caches for.
///
/// - Not running as root: keep current privileges; use the current account.
/// - Root with an identifiable invoking user (see [`decide_privilege_drop`]):
///   drop supplementary groups, then gid, then uid (order matters -- dropping
///   uid first would forfeit the privilege needed to drop the gid), verify the
///   drop is irreversible, and return the account.
/// - Root without that info: return `None` (caller warns, and aborts in strict
///   mode, rather than reading user caches as root).
#[cfg(unix)]
fn drop_privileges_to_invoking_user() -> Option<Passwd> {
    let is_root = running_as_root();
    let get = |k: &str| std::env::var(k).ok();
    let (sudo_uid, sudo_gid, sudo_user) = (get("SUDO_UID"), get("SUDO_GID"), get("SUDO_USER"));
    let (doas_user, pkexec_uid) = (get("DOAS_USER"), get("PKEXEC_UID"));
    let loginuid = std::fs::read_to_string("/proc/self/loginuid").ok();
    let env = InvokerEnv {
        sudo_uid: sudo_uid.as_deref(),
        sudo_gid: sudo_gid.as_deref(),
        sudo_user: sudo_user.as_deref(),
        doas_user: doas_user.as_deref(),
        pkexec_uid: pkexec_uid.as_deref(),
        loginuid: loginuid.as_deref(),
    };
    // SAFETY: simple libc getter with no memory operands.
    let current = passwd_lookup(Some(unsafe { libc::geteuid() }), None);

    match decide_privilege_drop(
        is_root,
        &env,
        current,
        &|uid| passwd_lookup(Some(uid), None),
        &|name| passwd_lookup(None, Some(name)),
    ) {
        PrivilegeDecision::NoDropNeeded(pw) => pw,
        PrivilegeDecision::SkipRootNoTarget => None,
        PrivilegeDecision::DropTo(pw) => {
            // SAFETY: setgroups/setgid/setuid are FFI calls with scalar arguments;
            // the null pointer for setgroups(0, NULL) clears the supplementary
            // group list. Order matters -- groups, then gid, then uid -- and each
            // failure aborts immediately (fail closed); never continue a partial
            // drop.
            unsafe {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    eprintln!("aur-scanner: failed to drop supplementary groups; aborting");
                    std::process::exit(3);
                }
                if libc::setgid(pw.gid) != 0 {
                    eprintln!("aur-scanner: failed to drop gid; aborting");
                    std::process::exit(3);
                }
                if libc::setuid(pw.uid) != 0 {
                    eprintln!("aur-scanner: failed to drop uid; aborting");
                    std::process::exit(3);
                }
                // Verify the drop is irreversible: regaining root must now fail.
                if libc::setuid(0) == 0 {
                    eprintln!("aur-scanner: privilege drop did not stick; aborting");
                    std::process::exit(3);
                }
            }
            Some(pw)
        }
    }
}

#[cfg(not(unix))]
fn drop_privileges_to_invoking_user() -> Option<Passwd> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(name: &str, uid: u32, gid: u32) -> Passwd {
        Passwd {
            name: name.to_string(),
            uid,
            gid,
            home: PathBuf::from(format!("/home/{name}")),
        }
    }

    /// A tiny fake passwd database.
    fn db() -> Vec<Passwd> {
        vec![
            pw("root", 0, 0),
            pw("alice", 1000, 1000),
            pw("bob", 1001, 1001),
            // a uid-nonzero account whose primary group is root's
            pw("rootgrp", 1002, 0),
        ]
    }
    fn decide(is_root: bool, env: InvokerEnv) -> PrivilegeDecision {
        let d = db();
        decide_privilege_drop(
            is_root,
            &env,
            Some(pw("carol", 1500, 1500)),
            &|uid| d.iter().find(|p| p.uid == uid).cloned(),
            &|name| d.iter().find(|p| p.name == name).cloned(),
        )
    }

    // The hook turns the pacman-supplied target into filesystem path
    // components, so it must reject anything that isn't a clean identifier.
    #[test]
    fn hook_rejects_path_traversal_and_injection_targets() {
        for bad in [
            "../etc/passwd",
            "a/b",
            "..",
            "a;rm -rf /",
            "a b",
            "a$(id)",
            "",
        ] {
            assert!(!is_valid_package_name(bad), "must reject {bad:?}");
        }
        for good in ["firefox", "aur-scanner-git", "lib32-foo", "python-requests"] {
            assert!(is_valid_package_name(good), "must accept {good}");
        }
    }

    // --- privilege-drop decision (pure; no syscalls, no real root) -----------
    // The hook runs as root under pacman. The security contract: it may only scan
    // user caches after an irreversible drop to a *non-root* invoking user, and
    // must otherwise SKIP rather than read user files as root.

    #[test]
    fn non_root_scans_as_current_account() {
        // SUDO_* are ignored when we are not root.
        let env = InvokerEnv {
            sudo_uid: Some("1001"),
            sudo_gid: Some("1001"),
            sudo_user: Some("bob"),
            ..Default::default()
        };
        assert_eq!(
            decide(false, env),
            PrivilegeDecision::NoDropNeeded(Some(pw("carol", 1500, 1500)))
        );
    }

    #[test]
    fn root_with_valid_sudo_env_drops_to_invoking_user() {
        let env = InvokerEnv {
            sudo_uid: Some("1000"),
            sudo_gid: Some("1000"),
            sudo_user: Some("alice"),
            ..Default::default()
        };
        assert_eq!(
            decide(true, env),
            PrivilegeDecision::DropTo(pw("alice", 1000, 1000))
        );
    }

    // Regression: without a complete SUDO_* the hook scanned nothing (doas, run0,
    // pkexec, root shells). Each alternate source must now identify the user.
    #[test]
    fn root_identifies_user_without_sudo_env() {
        let alice = PrivilegeDecision::DropTo(pw("alice", 1000, 1000));
        let doas = InvokerEnv {
            doas_user: Some("alice"),
            ..Default::default()
        };
        assert_eq!(decide(true, doas), alice);
        let pkexec = InvokerEnv {
            pkexec_uid: Some("1000"),
            ..Default::default()
        };
        assert_eq!(decide(true, pkexec), alice);
        let login = InvokerEnv {
            loginuid: Some("1000\n"),
            ..Default::default()
        };
        assert_eq!(decide(true, login), alice);
        // SUDO_UID alone (no SUDO_GID/SUDO_USER): resolved through passwd.
        let sudo_uid_only = InvokerEnv {
            sudo_uid: Some("1000"),
            ..Default::default()
        };
        assert_eq!(decide(true, sudo_uid_only), alice);
    }

    #[test]
    fn root_shell_falls_through_to_loginuid() {
        // `su -`/root shell: SUDO_UID absent or 0, but the login uid survives.
        let env = InvokerEnv {
            sudo_uid: Some("0"),
            sudo_gid: Some("0"),
            sudo_user: Some("root"),
            loginuid: Some("1001"),
            ..Default::default()
        };
        assert_eq!(
            decide(true, env),
            PrivilegeDecision::DropTo(pw("bob", 1001, 1001))
        );
    }

    #[test]
    fn unset_loginuid_and_root_targets_skip() {
        for env in [
            InvokerEnv::default(),
            InvokerEnv {
                loginuid: Some("4294967295"),
                ..Default::default()
            },
            InvokerEnv {
                loginuid: Some("0"),
                ..Default::default()
            },
            InvokerEnv {
                sudo_uid: Some("0"),
                sudo_gid: Some("0"),
                sudo_user: Some("root"),
                ..Default::default()
            },
            InvokerEnv {
                doas_user: Some("root"),
                ..Default::default()
            },
            InvokerEnv {
                doas_user: Some("nosuchuser"),
                pkexec_uid: Some("not-a-number"),
                ..Default::default()
            },
        ] {
            assert_eq!(
                decide(true, env),
                PrivilegeDecision::SkipRootNoTarget,
                "{env:?}"
            );
        }
    }

    #[test]
    fn root_never_drops_to_gid_zero() {
        // A gid-0 target keeps the root group (setgid(0)): not a real drop.
        let env = InvokerEnv {
            sudo_uid: Some("1002"),
            sudo_gid: Some("0"),
            sudo_user: Some("rootgrp"),
            ..Default::default()
        };
        assert_eq!(decide(true, env), PrivilegeDecision::SkipRootNoTarget);
    }

    #[test]
    fn mismatched_sudo_user_is_distrusted() {
        // SUDO_UID says alice but SUDO_USER says bob: not what sudo wrote.
        let env = InvokerEnv {
            sudo_uid: Some("1000"),
            sudo_user: Some("bob"),
            ..Default::default()
        };
        assert_eq!(decide(true, env), PrivilegeDecision::SkipRootNoTarget);
    }

    #[test]
    fn sudo_gid_is_used_when_valid() {
        let env = InvokerEnv {
            sudo_uid: Some("1000"),
            sudo_gid: Some("2000"),
            sudo_user: Some("alice"),
            ..Default::default()
        };
        assert_eq!(
            decide(true, env),
            PrivilegeDecision::DropTo(pw("alice", 1000, 2000))
        );
    }

    // --- cache roots (pure) --------------------------------------------------

    #[test]
    fn roots_use_the_passwd_home_not_a_hardcoded_home() {
        let roots = candidate_roots(Path::new("/srv/users/al"), &XdgDirs::default(), &[]);
        assert!(roots.contains(&PathBuf::from("/srv/users/al/.cache/yay")));
        assert!(roots.contains(&PathBuf::from("/srv/users/al/.cache/paru/clone")));
        assert!(roots.contains(&PathBuf::from(
            "/srv/users/al/.local/share/pikaur/aur_repos"
        )));
        assert!(roots.contains(&PathBuf::from("/srv/users/al/.config/rua/pkg")));
        assert!(roots.contains(&PathBuf::from("/var/cache/aur")));
        assert!(roots.iter().all(|r| !r.starts_with("/home/")));
        assert_eq!(roots.len(), 10);
    }

    #[test]
    fn roots_honour_xdg_and_helper_config() {
        let xdg = XdgDirs {
            cache: Some(PathBuf::from("/x/cache")),
            data: Some(PathBuf::from("/x/data")),
            config: Some(PathBuf::from("/x/config")),
        };
        let roots = candidate_roots(
            Path::new("/home/al"),
            &xdg,
            &[PathBuf::from("/builds/paru")],
        );
        assert_eq!(roots[0], PathBuf::from("/builds/paru"));
        assert!(roots.contains(&PathBuf::from("/x/cache/yay")));
        assert!(roots.contains(&PathBuf::from("/x/data/pikaur/aur_repos")));
        assert!(roots.contains(&PathBuf::from("/x/config/rua/pkg")));
        // defaults are still probed alongside an override
        assert!(roots.contains(&PathBuf::from("/home/al/.cache/yay")));
    }

    #[test]
    fn helper_config_parsers() {
        let home = Path::new("/home/al");
        assert_eq!(
            parse_paru_clonedir("[options]\nBottomUp\nCloneDir = ~/aur\n", home),
            Some(PathBuf::from("/home/al/aur"))
        );
        assert_eq!(
            parse_paru_clonedir("CloneDir=/b/c", home),
            Some(PathBuf::from("/b/c"))
        );
        assert_eq!(parse_paru_clonedir("CloneDir = ../../etc", home), None);
        assert_eq!(parse_paru_clonedir("# nothing\n", home), None);
        assert_eq!(
            parse_yay_builddir(r#"{"aururl":"x","buildDir": "$HOME/b"}"#, home),
            Some(PathBuf::from("/home/al/b"))
        );
        assert_eq!(parse_yay_builddir(r#"{"buildDir":"rel"}"#, home), None);
    }

    // --- PKGBUILD lookup (real temp filesystem) ------------------------------

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn lookup_finds_exact_dir() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "yay/firefox-dev/PKGBUILD",
            "pkgname=firefox-dev\n",
        );
        let roots = vec![t.path().join("yay")];
        match find_pkgbuilds_for_package("firefox-dev", &roots, None) {
            PkgbuildLookup::Found(v) => {
                assert_eq!(v, vec![t.path().join("yay/firefox-dev/PKGBUILD")])
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            find_pkgbuilds_for_package("absent", &roots, None),
            PkgbuildLookup::NotFound
        );
    }

    // Regression: helpers clone by pkgbase, so a split package's target name has
    // no directory of its own and used to be silently never found.
    #[test]
    fn lookup_finds_split_package_via_srcinfo() {
        let t = tempfile::tempdir().unwrap();
        write(
            t.path(),
            "paru/clone/mybase/PKGBUILD",
            "pkgbase=mybase\npkgname=(mybase-cli mybase-lib)\n",
        );
        write(
            t.path(),
            "paru/clone/mybase/.SRCINFO",
            "pkgbase = mybase\n\tpkgver = 1\npkgname = mybase-cli\n\npkgname = mybase-lib\n",
        );
        let roots = vec![t.path().join("paru/clone")];
        // The exact-dir probe misses (the dir is named for the pkgbase)...
        assert_eq!(
            find_pkgbuilds_for_package("mybase-lib", &roots, None),
            PkgbuildLookup::NotFound
        );
        // ...the .SRCINFO index finds it.
        let index = build_srcinfo_index(&roots);
        match find_pkgbuilds_for_package("mybase-lib", &roots, Some(&index)) {
            PkgbuildLookup::Found(v) => {
                assert_eq!(v, vec![t.path().join("paru/clone/mybase/PKGBUILD")])
            }
            other => panic!("{other:?}"),
        }
        assert!(index.contains_key("mybase-cli"));
    }

    // Regression: the index was only consulted when the exact-name directory
    // was missing, so a stale `<root>/<pkgname>/` hid the real pkgbase clone
    // (the doc comment claimed a decoy could never shadow the real one).
    #[test]
    fn stale_exact_dir_does_not_shadow_the_pkgbase_clone() {
        let t = tempfile::tempdir().unwrap();
        // The stale/decoy clone, named for the split package.
        write(
            t.path(),
            "paru/clone/mybase-lib/PKGBUILD",
            "pkgname=mybase-lib\npkgver=0.1\npkgrel=1\n",
        );
        // The real one: a pkgbase clone that lists mybase-lib in its .SRCINFO.
        write(
            t.path(),
            "paru/clone/mybase/PKGBUILD",
            "pkgbase=mybase\npkgname=(mybase-cli mybase-lib)\npkgver=2.0\npkgrel=1\n",
        );
        write(
            t.path(),
            "paru/clone/mybase/.SRCINFO",
            "pkgbase = mybase\n\tpkgver = 2.0\npkgname = mybase-cli\n\npkgname = mybase-lib\n",
        );
        let roots = vec![t.path().join("paru/clone")];
        // The old call shape (no index) only ever sees the decoy.
        match find_pkgbuilds_for_package("mybase-lib", &roots, None) {
            PkgbuildLookup::Found(v) => {
                assert_eq!(v, vec![t.path().join("paru/clone/mybase-lib/PKGBUILD")])
            }
            other => panic!("{other:?}"),
        }
        // The hook's lookup now sees both and scans both.
        let cell = OnceCell::new();
        match locate_pkgbuilds("mybase-lib", &roots, &cell) {
            PkgbuildLookup::Found(mut v) => {
                v.sort();
                assert_eq!(
                    v,
                    vec![
                        t.path().join("paru/clone/mybase/PKGBUILD"),
                        t.path().join("paru/clone/mybase-lib/PKGBUILD"),
                    ]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn candidates_prefer_the_installing_version_and_warn_on_disagreement() {
        let a = PathBuf::from("/c/mybase-lib/PKGBUILD");
        let b = PathBuf::from("/c/mybase/PKGBUILD");
        let declared = [Some("0.1-1".to_string()), Some("2.0-1".to_string())];
        let (ordered, note) =
            order_candidates(vec![a.clone(), b.clone()], &declared, Some("2.0-1"));
        assert_eq!(
            ordered,
            vec![b.clone(), a.clone()],
            "matching version first"
        );
        let note = note.expect("versions differ, must warn");
        assert!(note.contains("0.1-1") && note.contains("2.0-1"), "{note}");
        // Nothing is ever dropped.
        assert_eq!(ordered.len(), 2);
        // Epoch-0 normalisation: `0:2.0-1` matches `2.0-1`.
        let (ordered, _) = order_candidates(vec![a.clone(), b.clone()], &declared, Some("0:2.0-1"));
        assert_eq!(ordered[0], b);
        // Agreeing candidates: no warning, order untouched.
        let same = [Some("2.0-1".to_string()), Some("2.0-1".to_string())];
        let (ordered, note) = order_candidates(vec![a.clone(), b.clone()], &same, Some("2.0-1"));
        assert_eq!((ordered, note), (vec![a.clone(), b.clone()], None));
        // Unknown versions (VCS) never warn.
        let unknown = [None, Some("2.0-1".to_string())];
        let (_, note) = order_candidates(vec![a.clone(), b.clone()], &unknown, None);
        assert_eq!(note, None);
        // A single candidate is returned as-is.
        assert_eq!(
            order_candidates(vec![a.clone()], &declared[..1], Some("9")),
            (vec![a], None)
        );
    }

    #[test]
    fn srcinfo_parsing_is_strict() {
        assert_eq!(
            srcinfo_pkgnames(
                "pkgbase = b\npkgname = a\n\tpkgname = c\npkgnamefoo = x\npkgname = ../evil\n"
            ),
            vec!["a".to_string(), "c".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn index_does_not_follow_symlinked_dirs_or_srcinfo() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        // a symlinked cache directory
        write(t.path(), "elsewhere/PKGBUILD", "x\n");
        write(t.path(), "elsewhere/.SRCINFO", "pkgname = viadir\n");
        std::os::unix::fs::symlink(t.path().join("elsewhere"), root.join("linked")).unwrap();
        // a symlinked .SRCINFO inside a real directory
        write(t.path(), "secret", "pkgname = viafile\n");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(t.path().join("secret"), root.join("real/.SRCINFO")).unwrap();
        let index = build_srcinfo_index(&[root]);
        assert!(index.is_empty(), "{index:?}");
    }

    #[test]
    fn index_reads_are_capped() {
        let t = tempfile::tempdir().unwrap();
        // The only pkgname line sits beyond the read cap.
        let mut body = "#".repeat(SRCINFO_CAP as usize + 10);
        body.push_str("\npkgname = hidden\n");
        write(t.path(), "r/big/.SRCINFO", &body);
        assert!(build_srcinfo_index(&[t.path().join("r")]).is_empty());
    }

    // --- version matching ----------------------------------------------------

    #[test]
    fn pkgbuild_version_is_read_statically() {
        assert_eq!(
            pkgbuild_version("pkgname=x\npkgver=1.2.3\npkgrel=2\n"),
            Some("1.2.3-2".into())
        );
        assert_eq!(
            pkgbuild_version("epoch=1\npkgver='4.5'\npkgrel=1 # c\n"),
            Some("1:4.5-1".into())
        );
        assert_eq!(
            pkgbuild_version("epoch=0\npkgver=1\npkgrel=1\n"),
            Some("1-1".into())
        );
        // VCS / computed versions cannot be known statically.
        assert_eq!(
            pkgbuild_version("pkgver=1\npkgrel=1\npkgver() {\n  echo 2\n}\n"),
            None
        );
        assert_eq!(pkgbuild_version("pkgver=$(date)\npkgrel=1\n"), None);
        assert_eq!(pkgbuild_version("pkgver=${_v}\npkgrel=1\n"), None);
        assert_eq!(pkgbuild_version("pkgname=x\n"), None);
    }

    #[test]
    fn version_mismatch_policy() {
        let v = |s: &str| Some(s.to_string());
        assert!(!version_mismatch(&[v("1-1")], "1-1"));
        assert!(!version_mismatch(&[v("1-1")], "0:1-1"));
        assert!(version_mismatch(&[v("1-1")], "2-1"));
        // any matching PKGBUILD satisfies the check
        assert!(!version_mismatch(&[v("1-1"), v("2-1")], "2-1"));
        // unknown (VCS) is never a mismatch
        assert!(!version_mismatch(&[None], "9-9"));
        assert!(!version_mismatch(&[], "9-9"));
    }

    #[test]
    fn pacman_output_and_cmdline_parsing() {
        let info = "Name            : foo\nVersion         : 1:2.0-3\nDescription     : x: y\n";
        assert_eq!(
            parse_pacman_info(info),
            (Some("foo".into()), Some("1:2.0-3".into()))
        );
        let cl =
            b"pacman\0-U\0--noconfirm\0/tmp/a-1-1-x86_64.pkg.tar.zst\0https://x/b.pkg.tar.zst\0";
        assert_eq!(
            upgrade_files_from_cmdline(cl),
            vec![PathBuf::from("/tmp/a-1-1-x86_64.pkg.tar.zst")]
        );
        // not an upgrade, or not pacman: nothing
        assert!(upgrade_files_from_cmdline(b"pacman\0-S\0foo\0").is_empty());
        assert!(upgrade_files_from_cmdline(b"evil\0-U\0/tmp/a.pkg.tar.zst\0").is_empty());
        assert!(upgrade_files_from_cmdline(b"").is_empty());
    }

    // --- strict mode ---------------------------------------------------------

    #[test]
    fn strict_mode_sources() {
        assert!(!strict_mode(None, false));
        assert!(!strict_mode(Some("0"), false));
        assert!(strict_mode(Some("1"), false));
        assert!(strict_mode(None, true));
    }

    // --- PKGBUILD file-type refusal (real temp filesystem) -------------------
    // A regular file is usable; a symlink (even to a regular file), FIFO, or dir
    // must be refused without following it.

    #[test]
    fn classify_pkgbuild_accepts_regular_file_and_refuses_dir_and_absent() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("PKGBUILD");
        std::fs::write(&regular, b"pkgname=x\n").unwrap();
        assert_eq!(classify_pkgbuild(&regular), PkgbuildProbe::Usable);

        assert_eq!(
            classify_pkgbuild(&dir.path().join("missing")),
            PkgbuildProbe::Absent
        );

        let subdir = dir.path().join("adir");
        std::fs::create_dir(&subdir).unwrap();
        assert_eq!(classify_pkgbuild(&subdir), PkgbuildProbe::RefusedNonRegular);
    }

    #[cfg(unix)]
    #[test]
    fn classify_pkgbuild_refuses_symlink_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_PKGBUILD");
        std::fs::write(&target, b"pkgname=x\n").unwrap();
        let link = dir.path().join("PKGBUILD");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // The symlink resolves to a regular file, but we must NOT follow the final
        // component -- a hostile cache entry could otherwise redirect the reader.
        assert_eq!(classify_pkgbuild(&link), PkgbuildProbe::RefusedNonRegular);
    }

    #[cfg(unix)]
    #[test]
    fn lookup_refuses_symlinked_pkgbuild() {
        let t = tempfile::tempdir().unwrap();
        write(t.path(), "r/pkg/real", "x\n");
        std::os::unix::fs::symlink(t.path().join("r/pkg/real"), t.path().join("r/pkg/PKGBUILD"))
            .unwrap();
        assert_eq!(
            find_pkgbuilds_for_package("pkg", &[t.path().join("r")], None),
            PkgbuildLookup::RefusedOnly
        );
    }

    #[test]
    fn lookup_rejects_illegal_names() {
        let roots = vec![PathBuf::from("/nonexistent")];
        for bad in ["../etc", "a/b", "", "-rf", "a$(id)"] {
            assert_eq!(
                find_pkgbuilds_for_package(bad, &roots, None),
                PkgbuildLookup::NotFound
            );
        }
    }

    // --- fail-closed exit decision -------------------------------------------

    #[test]
    fn scan_failure_aborts_even_with_no_findings() {
        assert_eq!(
            decide_hook_outcome(true, false, false, false),
            HookDecision::Abort(AbortReason::ScanFailed)
        );
    }

    #[test]
    fn critical_finding_aborts() {
        assert_eq!(
            decide_hook_outcome(false, true, false, false),
            HookDecision::Abort(AbortReason::Critical)
        );
    }

    #[test]
    fn scan_failure_takes_precedence_over_critical() {
        assert_eq!(
            decide_hook_outcome(true, true, true, true),
            HookDecision::Abort(AbortReason::ScanFailed)
        );
    }

    #[test]
    fn high_only_proceeds_with_warning() {
        assert_eq!(
            decide_hook_outcome(false, false, true, false),
            HookDecision::Proceed { warn_high: true }
        );
    }

    #[test]
    fn clean_run_proceeds_without_warning() {
        assert_eq!(
            decide_hook_outcome(false, false, false, false),
            HookDecision::Proceed { warn_high: false }
        );
    }

    // Strict mode aborts on an unscanned target; the default does not (backstop
    // semantics -- aborting by default would brick `pacman -U`).
    #[test]
    fn unscanned_target_aborts_only_in_strict_mode() {
        assert_eq!(
            decide_hook_outcome(false, false, false, true),
            HookDecision::Abort(AbortReason::Unscanned)
        );
        assert_eq!(
            decide_hook_outcome(false, true, false, true),
            HookDecision::Abort(AbortReason::Critical)
        );
        assert_eq!(
            decide_hook_outcome(false, false, false, false),
            HookDecision::Proceed { warn_high: false }
        );
    }
}
