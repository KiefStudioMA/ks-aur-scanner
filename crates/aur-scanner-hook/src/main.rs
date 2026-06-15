//! Pacman hook for AUR security scanning
//!
//! This binary is invoked by pacman before package transactions
//! to scan AUR packages for security issues.

use anyhow::Result;
use aur_scanner_core::validate::is_valid_package_name;
use aur_scanner_core::{ScanConfig, Scanner, Severity};
use colored::Colorize;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .init();

    // Load configuration. A present-but-malformed security config is a hard
    // error: failing closed is safer than silently scanning with defaults.
    let config_path = PathBuf::from("/etc/aur-scanner/config.toml");
    let config = match ScanConfig::from_toml_file_or_default(&config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!(
                "{} invalid config at {}: {}",
                "aur-scanner:".red().bold(),
                config_path.display(),
                e
            );
            std::process::exit(2);
        }
    };

    let scanner = Scanner::new(config)?;

    // Drop root before touching user-owned cache files. The hook runs as root
    // (pacman context) but only ever needs to READ a user's AUR build cache and
    // set an exit code -- nothing requires root. Dropping to the invoking user
    // means a hostile file in that cache (symlink, payload) is parsed with the
    // user's privileges, not root's. If we are root but cannot identify the
    // invoking user, we do not scan user caches as root.
    let scan_user = drop_privileges_to_invoking_user();

    // Read package names from stdin (pacman hook provides this)
    let stdin = io::stdin();
    let packages: Vec<String> = stdin
        .lock()
        .lines()
        .map_while(Result::ok)
        .collect();

    let scan_user = match scan_user {
        Some(u) => u,
        None => {
            tracing::warn!(
                "could not determine the invoking user (no SUDO_USER); \
                 skipping AUR cache scan. Use the shell integration for full coverage."
            );
            return Ok(());
        }
    };

    let mut has_critical = false;
    let mut has_high = false;
    // A PKGBUILD we located but could not scan is a failure to analyze a package
    // that is about to be built: fail closed (abort the transaction) rather than
    // logging at debug and letting it through.
    let mut scan_failed = false;

    for package in packages {
        // Try to find PKGBUILD in common cache locations
        if let Some(pkgbuild_path) = find_pkgbuild_for_package(&package, &scan_user) {
            match scanner.scan_pkgbuild(&pkgbuild_path).await {
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
    // aborts the transaction; high-severity only warns). The precedence/branch
    // selection is a pure function so the fail-closed contract is unit-testable;
    // the messaging + process exit stay here.
    match decide_hook_outcome(scan_failed, has_critical, has_high) {
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
        HookDecision::Proceed { warn_high } => {
            if warn_high {
                eprintln!();
                eprintln!(
                    "{} High severity issues found. Review recommended.",
                    "WARNING:".yellow().bold()
                );
                eprintln!();
            }
        }
    }

    Ok(())
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
/// Fail-closed precedence (unchanged from the original inline logic): an
/// un-analyzable package aborts BEFORE a critical finding (both exit 1), and a
/// critical finding aborts before a high-severity warning. High severity alone
/// proceeds with a warning; a fully clean run proceeds silently.
fn decide_hook_outcome(scan_failed: bool, has_critical: bool, has_high: bool) -> HookDecision {
    if scan_failed {
        HookDecision::Abort(AbortReason::ScanFailed)
    } else if has_critical {
        HookDecision::Abort(AbortReason::Critical)
    } else {
        HookDecision::Proceed {
            warn_high: has_high,
        }
    }
}

/// Build the ordered list of candidate PKGBUILD paths to probe for `user`/`package`.
///
/// Both names become filesystem path components, so this is the name-validation
/// gate: an illegal name (`..`, `/`, shell metacharacters, empty, leading `-`)
/// yields an EMPTY list and the package is skipped -- a value cannot inject `..`
/// or `/` into the probed paths. Pure (no filesystem access), so the gate and the
/// path construction are unit-testable.
fn candidate_pkgbuild_paths(package: &str, user: &str) -> Vec<PathBuf> {
    // Defense in depth: this gate stands even if a future caller forgets to
    // pre-validate. `find_pkgbuild_for_package` validates first for a precise
    // diagnostic, so it never reaches here with an illegal name.
    if !is_valid_package_name(package) || !is_valid_package_name(user) {
        return Vec::new();
    }
    [
        format!("/home/{user}/.cache/yay/{package}"),
        format!("/home/{user}/.cache/paru/clone/{package}"),
        format!("/home/{user}/.cache/pikaur/aur_repos/{package}"),
        format!("/home/{user}/.cache/trizen/{package}"),
        format!("/var/cache/aur/{package}"),
    ]
    .into_iter()
    .map(|dir| PathBuf::from(dir).join("PKGBUILD"))
    .collect()
}

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

/// Find PKGBUILD for a package in common cache locations for `user`.
///
/// Hardening notes: even after dropping privileges, this validates the package
/// name before using it as a path component (so a surprising target cannot
/// inject `..`/`/`) and refuses a PKGBUILD that is not a regular file -- a
/// symlink/FIFO cache entry cannot redirect the reader (an O_NOFOLLOW-equivalent
/// check on the final component).
fn find_pkgbuild_for_package(package: &str, user: &str) -> Option<PathBuf> {
    // Pacman provides the target name, but treat it as untrusted: it becomes a
    // filesystem path below. Validate up front so the warning names the offender.
    if !is_valid_package_name(package) {
        tracing::warn!("skipping target with illegal package name: {package:?}");
        return None;
    }
    if !is_valid_package_name(user) {
        // User names are not package names, but they share the safe charset we
        // need for a path component (no `/`, no `..`).
        tracing::warn!("refusing to build cache path from unusual user name");
        return None;
    }

    for pkgbuild in candidate_pkgbuild_paths(package, user) {
        match classify_pkgbuild(&pkgbuild) {
            PkgbuildProbe::Usable => return Some(pkgbuild),
            PkgbuildProbe::RefusedNonRegular => {
                tracing::warn!("refusing non-regular PKGBUILD at {}", pkgbuild.display());
            }
            PkgbuildProbe::Absent => {}
        }
    }

    None
}

/// What the hook should do about privileges before touching user files, decided
/// purely from the process state and environment. Separated from the syscalls so
/// the security-critical branch selection is unit-testable without actually
/// being root or dropping privileges.
#[derive(Debug, PartialEq, Eq)]
enum PrivilegeDecision {
    /// Not root: no drop needed. Scan caches as `Some(user)`, or skip if `None`
    /// (no usable, non-root `$USER`).
    NoDropNeeded(Option<String>),
    /// Root with a valid, non-root invoking user: drop groups -> gid -> uid, then
    /// scan caches as `user`.
    DropTo { uid: u32, gid: u32, user: String },
    /// Root but no safe invoking user can be determined: skip scanning entirely
    /// (never read user caches as root).
    SkipRootNoTarget,
}

/// Decide the privilege action from `(is_root, SUDO_UID, SUDO_GID, SUDO_USER,
/// USER)`. Fail-closed: when running as root, the only outcome that scans is a
/// fully-specified, non-root `SUDO_*` target; anything missing/unparseable, or a
/// target uid OR gid of 0, yields `SkipRootNoTarget` rather than scanning with a
/// root credential.
fn decide_privilege_drop(
    is_root: bool,
    sudo_uid: Option<&str>,
    sudo_gid: Option<&str>,
    sudo_user: Option<&str>,
    user_env: Option<&str>,
) -> PrivilegeDecision {
    if !is_root {
        // Not root: keep current privileges; scan as $USER unless it is empty or
        // literally "root" (matching the original filter).
        let scan_as = user_env
            .filter(|u| !u.is_empty() && *u != "root")
            .map(str::to_string);
        return PrivilegeDecision::NoDropNeeded(scan_as);
    }

    // Root: require a complete, parseable, non-root SUDO_* target.
    let target = (|| {
        let uid: u32 = sudo_uid?.parse().ok()?;
        let gid: u32 = sudo_gid?.parse().ok()?;
        let user = sudo_user.filter(|u| !u.is_empty())?.to_string();
        Some((uid, gid, user))
    })();
    match target {
        // Require BOTH a non-root uid AND a non-root gid: a uid-0 target keeps
        // the root user, and a gid-0 target keeps the ROOT GROUP (setgid(0)) --
        // neither is a real privilege drop, so refuse to scan with either.
        Some((uid, gid, user)) if uid != 0 && gid != 0 => {
            PrivilegeDecision::DropTo { uid, gid, user }
        }
        // missing/unparseable field, or a uid-0 / gid-0 target.
        _ => PrivilegeDecision::SkipRootNoTarget,
    }
}

/// Drop root privileges to the invoking user before touching their files, and
/// return the user name to scan caches for.
///
/// - Not running as root: keep current privileges; use `$USER`.
/// - Root with a valid `SUDO_UID`/`SUDO_GID`/`SUDO_USER`: drop supplementary
///   groups, then gid, then uid (order matters -- dropping uid first would
///   forfeit the privilege needed to drop the gid), verify the drop is
///   irreversible, and return the user.
/// - Root without that info: return `None` (caller skips scanning rather than
///   reading user caches as root).
#[cfg(unix)]
fn drop_privileges_to_invoking_user() -> Option<String> {
    // SAFETY: simple libc getter with no memory operands.
    let is_root = unsafe { libc::geteuid() } == 0;
    let sudo_uid = std::env::var("SUDO_UID").ok();
    let sudo_gid = std::env::var("SUDO_GID").ok();
    let sudo_user = std::env::var("SUDO_USER").ok();
    let user_env = std::env::var("USER").ok();

    match decide_privilege_drop(
        is_root,
        sudo_uid.as_deref(),
        sudo_gid.as_deref(),
        sudo_user.as_deref(),
        user_env.as_deref(),
    ) {
        PrivilegeDecision::NoDropNeeded(scan_as) => scan_as,
        PrivilegeDecision::SkipRootNoTarget => None,
        PrivilegeDecision::DropTo { uid, gid, user } => {
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
                if libc::setgid(gid) != 0 {
                    eprintln!("aur-scanner: failed to drop gid; aborting");
                    std::process::exit(3);
                }
                if libc::setuid(uid) != 0 {
                    eprintln!("aur-scanner: failed to drop uid; aborting");
                    std::process::exit(3);
                }
                // Verify the drop is irreversible: regaining root must now fail.
                if libc::setuid(0) == 0 {
                    eprintln!("aur-scanner: privilege drop did not stick; aborting");
                    std::process::exit(3);
                }
            }
            Some(user)
        }
    }
}

#[cfg(not(unix))]
fn drop_privileges_to_invoking_user() -> Option<String> {
    std::env::var("USER").ok().filter(|u| !u.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aur_scanner_core::validate::is_valid_package_name;

    // The hook turns the pacman-supplied target (and SUDO_USER) into filesystem
    // path components, so it must reject anything that isn't a clean identifier.
    #[test]
    fn hook_rejects_path_traversal_and_injection_targets() {
        for bad in ["../etc/passwd", "a/b", "..", "a;rm -rf /", "a b", "a$(id)", ""] {
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
    fn non_root_scans_as_current_user() {
        assert_eq!(
            decide_privilege_drop(false, None, None, None, Some("alice")),
            PrivilegeDecision::NoDropNeeded(Some("alice".to_string()))
        );
        // SUDO_* are ignored when we are not root.
        assert_eq!(
            decide_privilege_drop(false, Some("0"), Some("0"), Some("root"), Some("bob")),
            PrivilegeDecision::NoDropNeeded(Some("bob".to_string()))
        );
    }

    #[test]
    fn non_root_without_usable_user_skips() {
        // unset / empty / literally "root" $USER ⇒ no scan target.
        for u in [None, Some(""), Some("root")] {
            assert_eq!(
                decide_privilege_drop(false, None, None, None, u),
                PrivilegeDecision::NoDropNeeded(None),
                "USER={u:?}"
            );
        }
    }

    #[test]
    fn root_with_valid_sudo_env_drops_to_invoking_user() {
        assert_eq!(
            decide_privilege_drop(
                true,
                Some("1000"),
                Some("1000"),
                Some("alice"),
                Some("root")
            ),
            PrivilegeDecision::DropTo {
                uid: 1000,
                gid: 1000,
                user: "alice".to_string()
            }
        );
    }

    #[test]
    fn root_never_drops_to_uid_or_gid_zero() {
        // A uid-0 target keeps the root user; a gid-0 target keeps the root group
        // (setgid(0)). Neither is a real drop -- skip rather than scan with any
        // root credential. Covers uid=0/gid=0, uid=0 alone, and gid=0 alone.
        for (uid, gid) in [("0", "0"), ("0", "1000"), ("1000", "0")] {
            assert_eq!(
                decide_privilege_drop(true, Some(uid), Some(gid), Some("alice"), None),
                PrivilegeDecision::SkipRootNoTarget,
                "uid={uid} gid={gid} must not be treated as a drop"
            );
        }
    }

    #[test]
    fn root_without_complete_sudo_env_skips_rather_than_scanning_as_root() {
        // Any missing field, an empty SUDO_USER, or an unparseable id ⇒ fail
        // closed to skip (never read user caches with root privileges).
        let cases = [
            (None, Some("1000"), Some("alice")),               // no SUDO_UID
            (Some("1000"), None, Some("alice")),               // no SUDO_GID
            (Some("1000"), Some("1000"), None),                // no SUDO_USER
            (Some("1000"), Some("1000"), Some("")),            // empty SUDO_USER
            (Some("notanumber"), Some("1000"), Some("alice")), // unparseable uid
            (Some("1000"), Some("x"), Some("alice")),          // unparseable gid
        ];
        for (uid, gid, user) in cases {
            assert_eq!(
                decide_privilege_drop(true, uid, gid, user, None),
                PrivilegeDecision::SkipRootNoTarget,
                "uid={uid:?} gid={gid:?} user={user:?}"
            );
        }
    }

    // --- candidate-path name gate (pure) -------------------------------------

    #[test]
    fn candidate_paths_empty_for_illegal_package_or_user() {
        for bad_pkg in ["../etc", "a/b", "a;rm -rf /", "", "-rf", "a$(id)"] {
            assert!(
                candidate_pkgbuild_paths(bad_pkg, "alice").is_empty(),
                "illegal package {bad_pkg:?} must yield no paths"
            );
        }
        for bad_user in ["../root", "a/b", "", "a;b", "-x"] {
            assert!(
                candidate_pkgbuild_paths("firefox", bad_user).is_empty(),
                "illegal user {bad_user:?} must yield no paths"
            );
        }
    }

    #[test]
    fn candidate_paths_built_for_valid_names_without_escape() {
        let paths = candidate_pkgbuild_paths("firefox", "alice");
        assert_eq!(paths.len(), 5);
        assert!(paths.iter().all(|p| p.ends_with("PKGBUILD")));
        assert!(paths[0]
            .to_string_lossy()
            .contains("/home/alice/.cache/yay/firefox/PKGBUILD"));
        // No traversal/escape can appear once the names are validated.
        assert!(paths.iter().all(|p| !p.to_string_lossy().contains("..")));
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

    // --- fail-closed exit decision -------------------------------------------

    #[test]
    fn scan_failure_aborts_even_with_no_findings() {
        assert_eq!(
            decide_hook_outcome(true, false, false),
            HookDecision::Abort(AbortReason::ScanFailed)
        );
    }

    #[test]
    fn critical_finding_aborts() {
        assert_eq!(
            decide_hook_outcome(false, true, false),
            HookDecision::Abort(AbortReason::Critical)
        );
    }

    #[test]
    fn scan_failure_takes_precedence_over_critical() {
        assert_eq!(
            decide_hook_outcome(true, true, true),
            HookDecision::Abort(AbortReason::ScanFailed)
        );
    }

    #[test]
    fn high_only_proceeds_with_warning() {
        assert_eq!(
            decide_hook_outcome(false, false, true),
            HookDecision::Proceed { warn_high: true }
        );
    }

    #[test]
    fn clean_run_proceeds_without_warning() {
        assert_eq!(
            decide_hook_outcome(false, false, false),
            HookDecision::Proceed { warn_high: false }
        );
    }
}
