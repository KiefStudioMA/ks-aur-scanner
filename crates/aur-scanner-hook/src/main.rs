//! Pacman hook for AUR security scanning
//!
//! This binary is invoked by pacman before package transactions
//! to scan AUR packages for security issues.

use anyhow::Result;
use aur_scanner_core::validate::is_valid_package_name;
use aur_scanner_core::{ScanConfig, Scanner, Severity};
use colored::Colorize;
use std::io::{self, BufRead};
use std::path::PathBuf;

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

    if scan_failed {
        eprintln!();
        eprintln!(
            "{} a package could not be analyzed. Aborting transaction (fail-closed).",
            "ERROR:".red().bold()
        );
        std::process::exit(1);
    }

    if has_critical {
        eprintln!();
        eprintln!(
            "{} Critical security issues found. Aborting transaction.",
            "ERROR:".red().bold()
        );
        eprintln!("Use 'aur-scan scan <package-dir>' for details.");
        eprintln!();
        std::process::exit(1);
    }

    if has_high {
        eprintln!();
        eprintln!(
            "{} High severity issues found. Review recommended.",
            "WARNING:".yellow().bold()
        );
        eprintln!();
    }

    Ok(())
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
    // filesystem path below.
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

    let cache_dirs = vec![
        format!("/home/{}/.cache/yay/{}", user, package),
        format!("/home/{}/.cache/paru/clone/{}", user, package),
        format!("/home/{}/.cache/pikaur/aur_repos/{}", user, package),
        format!("/home/{}/.cache/trizen/{}", user, package),
        format!("/var/cache/aur/{}", package),
    ];

    for dir in cache_dirs {
        let pkgbuild = PathBuf::from(&dir).join("PKGBUILD");
        // symlink_metadata does not follow the final symlink: if PKGBUILD is a
        // symlink (or anything but a regular file), skip it rather than read
        // through it.
        match std::fs::symlink_metadata(&pkgbuild) {
            Ok(md) if md.file_type().is_file() => return Some(pkgbuild),
            Ok(_) => {
                tracing::warn!("refusing non-regular PKGBUILD at {}", pkgbuild.display());
            }
            Err(_) => {}
        }
    }

    None
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
    // SAFETY: these are simple libc getters/setters with no memory operands.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty() && u != "root");
    }

    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid: u32 = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    let user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty())?;
    if uid == 0 {
        return None; // never "drop" to root
    }

    // SAFETY: setgroups/setgid/setuid are FFI calls with scalar arguments; the
    // null pointer for setgroups(0, NULL) clears the supplementary group list.
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

#[cfg(not(unix))]
fn drop_privileges_to_invoking_user() -> Option<String> {
    std::env::var("USER").ok().filter(|u| !u.is_empty())
}
