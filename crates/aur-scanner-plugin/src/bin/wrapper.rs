//! AUR helper wrapper
//!
//! Wraps yay/paru to add security scanning before package installation.
//!
//! Usage:
//!   aur-scan-wrap paru -S package
//!   aur-scan-wrap yay -S package1 package2
//!
//! Can be aliased:
//!   alias paru='aur-scan-wrap paru'

use anyhow::{Context, Result};
use aur_scanner_core::aur::{is_aur_package, AurClient};
use aur_scanner_core::validate::is_valid_package_name;
use aur_scanner_core::{Scanner, Severity};
use colored::Colorize;
use std::env;
use std::io::{self, IsTerminal, Write};
use std::process::{Command, ExitCode, Stdio};

/// What a helper invocation means for scanning.
enum Operation {
    /// An install-class sync that may build AUR packages: scan these operands.
    Install(Vec<String>),
    /// A read-only or non-install operation (search/info/query/remove/...): no scan.
    PassThrough,
}

/// Classify a pacman/paru/yay invocation by its *operation*, not by substring
/// sniffing. The previous implementation tested `contains('i')`/`contains('s')`
/// over the whole arg vector, so an unrelated flag could flip an install to
/// "skip scan" (fail-open). Here we parse the operation properly and default to
/// scanning whenever an invocation could install packages.
fn classify(helper_args: &[&str]) -> Operation {
    let mut op_letters = String::new(); // uppercase operation selectors (S/Q/R/U/F/D/T)
    let mut sync_mods = String::new(); // lowercase modifiers seen in short -S groups
    let mut long_opts: Vec<&str> = Vec::new();
    let mut operands: Vec<String> = Vec::new();
    let mut end_of_opts = false;

    for arg in helper_args {
        if end_of_opts {
            operands.push((*arg).to_string());
            continue;
        }
        if *arg == "--" {
            end_of_opts = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            // Long option; take the bare name (drop any =value).
            long_opts.push(long.split('=').next().unwrap_or(long));
        } else if let Some(short) = arg.strip_prefix('-') {
            // Short option group, e.g. -Syu. Uppercase letters select the
            // operation; lowercase letters are modifiers.
            for c in short.chars() {
                if c.is_ascii_uppercase() {
                    op_letters.push(c);
                } else {
                    sync_mods.push(c);
                }
            }
        } else {
            operands.push((*arg).to_string());
        }
    }

    // Map long operation aliases onto the same letters.
    let has = |c: char, long: &str| op_letters.contains(c) || long_opts.contains(&long);
    let is_sync = has('S', "sync");
    let is_upgrade_file = has('U', "upgrade");
    let non_install_op = has('Q', "query")
        || has('R', "remove")
        || has('F', "files")
        || has('D', "database")
        || has('T', "deptest")
        || has('V', "version")
        // yay/paru AUR extensions that are read-only and must never gate:
        || has('G', "getpkgbuild") // downloads a PKGBUILD only
        || has('P', "show"); // print stats / PKGBUILD to stdout

    // Read-only sync sub-operations that never install anything.
    let readonly_sync = long_opts.iter().any(|o| {
        matches!(
            *o,
            "search" | "info" | "list" | "groups" | "clean" | "print"
        )
    }) || sync_mods
        .chars()
        .any(|m| matches!(m, 's' | 'i' | 'l' | 'g' | 'c' | 'p'));

    // Decide. The bias is fail-closed: scan whenever the invocation could build
    // an AUR package and there is something to scan.
    if non_install_op && !is_sync && !is_upgrade_file {
        return Operation::PassThrough;
    }
    if is_sync && readonly_sync {
        return Operation::PassThrough;
    }
    if (is_sync || is_upgrade_file) && !operands.is_empty() {
        return Operation::Install(operands);
    }
    // Fail closed: any invocation that carries package operands and is NOT a
    // recognized read-only/non-install operation can install (AUR helpers treat
    // bare operands as an install, even alongside long flags like `--noconfirm`
    // or `--needed`). Scan them rather than risk a silent skip. Over-scanning an
    // occasional flag value is harmless -- a non-AUR name is dropped downstream.
    if !operands.is_empty() && !non_install_op && !readonly_sync {
        return Operation::Install(operands);
    }
    // -Syu with no operands, -Sy, bare -S, search/query/remove, etc.: nothing to scan.
    Operation::PassThrough
}

/// Keep only operands that are syntactically legal Arch package identifiers.
/// Anything else (a leading-hyphen arg-injection attempt, a `../traversal`, an
/// embedded URL/shell metacharacter, an empty string) cannot name a real AUR
/// package and must never become an AUR-lookup or PKGBUILD-fetch key.
fn fetch_candidates(operands: &[String]) -> Vec<String> {
    operands
        .iter()
        .filter(|p| is_valid_package_name(p))
        .cloned()
        .collect()
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let args: Vec<String> = env::args().collect();

    // Need at least: wrapper helper [args...]
    if args.len() < 2 {
        print_usage();
        return Ok(ExitCode::FAILURE);
    }

    let helper = &args[1];
    let helper_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    // Classify by operation (not substring sniffing). Only install-class
    // operations with operands are scanned; everything else passes through.
    let packages: Vec<String> = match classify(&helper_args) {
        Operation::Install(pkgs) => pkgs,
        Operation::PassThrough => return run_helper(helper, &helper_args),
    };

    if packages.is_empty() {
        return run_helper(helper, &helper_args);
    }

    // Validate every operand BEFORE it becomes a network/fetch key. An operand
    // that is not a bare package identifier cannot be a real AUR package (pacman
    // and the helper would reject it too); never feed such a value to the AUR
    // membership lookup or the PKGBUILD fetch. `is_aur_package`/`fetch_pkgbuild`
    // re-validate internally, but rejecting here keeps garbage out of the gate
    // entirely and surfaces it to the user.
    let candidates = fetch_candidates(&packages);
    for dropped in packages.iter().filter(|p| !candidates.contains(p)) {
        eprintln!(
            "{} ignoring invalid package operand (not scanned): {dropped:?}",
            "warning:".yellow()
        );
    }

    // Filter to only AUR packages. If the AUR membership check itself fails we
    // assume AUR and scan -- failing toward more scanning, never less.
    let mut aur_packages: Vec<String> = Vec::new();
    for pkg in &candidates {
        match is_aur_package(pkg).await {
            Ok(true) => aur_packages.push(pkg.clone()),
            Ok(false) => {}                           // Official repo package, skip
            Err(_) => aur_packages.push(pkg.clone()), // could not determine -> fail closed, scan
        }
    }

    if aur_packages.is_empty() {
        // No AUR packages, pass through
        return run_helper(helper, &helper_args);
    }

    println!();
    println!(
        "{} Pre-scanning {} AUR package(s)...",
        "AUR Security Scanner:".cyan().bold(),
        aur_packages.len()
    );
    println!("{}", "=".repeat(60));

    let client = AurClient::new().context("Failed to create AUR client")?;
    let scanner = Scanner::with_defaults().context("Failed to create scanner")?;

    let mut high_found = false;
    let mut critical_found = false;
    // Packages we could not fetch or scan. These are UNREVIEWED -- a security
    // gate must treat "could not analyze" as deny, not as a soft warning.
    let mut unreviewed: Vec<String> = Vec::new();

    for package in &aur_packages {
        println!();
        print!("{} {}... ", "Checking:".dimmed(), package.white().bold());
        io::stdout().flush()?;

        // Fetch PKGBUILD from AUR
        let fetched = match client.fetch_pkgbuild(package).await {
            Ok(f) => f,
            Err(e) => {
                println!("{}", format!("fetch failed: {}", e).red());
                unreviewed.push(package.clone());
                continue;
            }
        };

        // Scan
        let result = match scanner.scan_pkgbuild(&fetched.pkgbuild_path).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("scan failed: {}", e).red());
                unreviewed.push(package.clone());
                continue;
            }
        };

        // Filter to high and above
        let findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity <= Severity::High)
            .collect();

        if findings.is_empty() {
            println!("{}", "OK".green());
        } else {
            let crit_count = findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count();
            let high_count = findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count();

            if crit_count > 0 {
                critical_found = true;
                print!("{} ", format!("{} CRITICAL", crit_count).red().bold());
            }
            if high_count > 0 {
                high_found = true;
                print!("{} ", format!("{} HIGH", high_count).yellow());
            }
            println!();

            // Show critical findings
            for finding in findings.iter().filter(|f| f.severity == Severity::Critical) {
                println!(
                    "  {} {} - {}",
                    finding.id.red(),
                    finding.title,
                    finding.description
                );
            }
        }
    }

    println!();
    println!("{}", "=".repeat(60));

    // A non-interactive stdin (pipe, CI, cron) cannot answer a safety prompt.
    // Treat the inability to confirm as a refusal: never let an empty read be
    // taken as "yes" and proceed past an unreviewed or flagged package.
    let interactive = io::stdin().is_terminal();

    // Unreviewed packages are the most dangerous: we have no idea what they do.
    if !unreviewed.is_empty() {
        println!(
            "{} could not fetch/scan: {} (unreviewed)",
            "BLOCKED:".red().bold(),
            unreviewed.join(", ")
        );
        if !confirm_typed_yes(
            interactive,
            "Could not analyze the above package(s). Type 'yes' to install them UNREVIEWED, or press Enter to abort:",
        )? {
            println!("{}", "Installation aborted (unreviewed packages).".yellow());
            return Ok(ExitCode::FAILURE);
        }
        println!(
            "{}",
            "User accepted installing unreviewed packages.".dimmed()
        );
    }

    if critical_found {
        println!("{}", "CRITICAL security issues detected!".red().bold());
        if !confirm_typed_yes(
            interactive,
            "Type 'yes' to proceed anyway, or press Enter to abort:",
        )? {
            println!("{}", "Installation aborted.".yellow());
            return Ok(ExitCode::FAILURE);
        }
        println!("{}", "User accepted risks.".dimmed());
    } else if high_found {
        // High findings default to NO and abort in non-interactive mode.
        if !confirm_default_no(interactive, "High-severity issues found. Continue? [y/N]:")? {
            println!("{}", "Installation aborted.".yellow());
            return Ok(ExitCode::FAILURE);
        }
    }

    println!();
    // TOCTOU disclosure (defect #2): this wrapper scanned PKGBUILDs it fetched
    // itself, but `run_helper` now hands the operation to the AUR helper, which
    // RE-FETCHES and builds its OWN copy. The bytes built are therefore not
    // guaranteed to be the bytes scanned -- a maintainer can update the PKGBUILD
    // between the two fetches, and VCS (`-git`) sources move regardless. This
    // pre-scan is advisory for the wrapper path. The race-free `aur-scan install`
    // command fetches once and builds the exact directories it scanned; use it
    // when a scan==build guarantee is required.
    println!(
        "{} the helper re-fetches and builds its own copy, so this pre-scan is {}. \
         For a scan==build guarantee use: {}",
        "NOTE:".yellow().bold(),
        "advisory".yellow(),
        "aur-scan install <pkg>".white().bold()
    );
    println!();
    println!("{}", "Proceeding with installation...".green());
    println!();

    run_helper(helper, &helper_args)
}

/// Require the user to type exactly `yes`. In non-interactive mode this is
/// always a refusal (fail-closed): there is no one to confirm.
fn confirm_typed_yes(interactive: bool, prompt: &str) -> Result<bool> {
    if !interactive {
        eprintln!(
            "{} non-interactive; refusing without confirmation.",
            "abort:".red()
        );
        return Ok(false);
    }
    print!("{} ", prompt.yellow());
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Ok(false); // EOF == no confirmation
    }
    Ok(input.trim().eq_ignore_ascii_case("yes"))
}

/// `[y/N]` prompt that defaults to NO and refuses in non-interactive mode.
fn confirm_default_no(interactive: bool, prompt: &str) -> Result<bool> {
    if !interactive {
        eprintln!(
            "{} non-interactive; refusing without confirmation.",
            "abort:".red()
        );
        return Ok(false);
    }
    print!("{} ", prompt.yellow());
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Ok(false);
    }
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn run_helper(helper: &str, args: &[&str]) -> Result<ExitCode> {
    let status = Command::new(helper)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context(format!("Failed to run {}", helper))?;

    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(status.code().unwrap_or(1) as u8)
    })
}

fn print_usage() {
    eprintln!("AUR Security Scanner Wrapper");
    eprintln!();
    eprintln!("Usage: aur-scan-wrap <helper> [args...]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  aur-scan-wrap paru -S package");
    eprintln!("  aur-scan-wrap yay -S package1 package2");
    eprintln!();
    eprintln!("Setup as alias:");
    eprintln!("  alias paru='aur-scan-wrap paru'");
    eprintln!("  alias yay='aur-scan-wrap yay'");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanned(args: &[&str]) -> Option<Vec<String>> {
        match classify(args) {
            Operation::Install(p) => Some(p),
            Operation::PassThrough => None,
        }
    }

    #[test]
    fn installs_are_scanned() {
        assert_eq!(scanned(&["-S", "firefox"]), Some(vec!["firefox".into()]));
        assert_eq!(scanned(&["-Syu", "pkg"]), Some(vec!["pkg".into()]));
        assert_eq!(scanned(&["--sync", "pkg"]), Some(vec!["pkg".into()]));
        // bare operand, no operation (helpers treat as install)
        assert_eq!(scanned(&["foo"]), Some(vec!["foo".into()]));
        // end-of-options: the name after -- is still an operand
        assert_eq!(scanned(&["-S", "--", "pkg"]), Some(vec!["pkg".into()]));
        // yay's `-Y` (its default search-and-install) must be scanned (#12).
        assert_eq!(scanned(&["-Y", "cheese"]), Some(vec!["cheese".into()]));
        assert_eq!(scanned(&["--yay", "cheese"]), Some(vec!["cheese".into()]));
    }

    #[test]
    fn read_only_ops_pass_through() {
        // These previously could flip scanning off via substring sniffing; now
        // they are correctly classified and never misread as installs.
        assert!(scanned(&["-Ss", "firefox"]).is_none()); // search
        assert!(scanned(&["-Si", "firefox"]).is_none()); // info
        assert!(scanned(&["-Sl"]).is_none()); // list
        assert!(scanned(&["-Sg"]).is_none()); // groups
        assert!(scanned(&["-Sc"]).is_none()); // clean
        assert!(scanned(&["-Qi", "firefox"]).is_none()); // query
        assert!(scanned(&["-Q"]).is_none());
        assert!(scanned(&["-R", "firefox"]).is_none()); // remove
        assert!(scanned(&["-Syu"]).is_none()); // upgrade, no operands

        // yay/paru AUR extensions that only read: must not gate even with an
        // operand (a malicious PKGBUILD fetched by -G is reviewed, not built).
        assert!(scanned(&["-G", "firefox"]).is_none()); // getpkgbuild (download only)
        assert!(scanned(&["--getpkgbuild", "firefox"]).is_none());
        assert!(scanned(&["-P"]).is_none()); // show / print stats
        assert!(scanned(&["-Y", "--gendb"]).is_none()); // -Y devel-db setup, no operands
    }

    #[test]
    fn unrelated_flags_do_not_disable_scanning() {
        // The old code skipped scanning if any arg merely contained 'i' or 's'.
        assert_eq!(
            scanned(&["-S", "--needed", "--noconfirm", "pkg"]),
            Some(vec!["pkg".into()])
        );
        assert_eq!(
            scanned(&["-S", "--rebuild", "pkg"]),
            Some(vec!["pkg".into()])
        );
    }

    #[test]
    fn bare_operand_with_long_flag_is_still_scanned() {
        // Regression for the fail-open: an install expressed as a bare operand
        // plus a long flag (no -S) must NOT pass through unscanned.
        assert_eq!(
            scanned(&["--noconfirm", "evilpkg"]),
            Some(vec!["evilpkg".into()])
        );
        assert_eq!(scanned(&["--needed", "pkg"]), Some(vec!["pkg".into()]));
        // ...but a read-only/non-install op with a long flag still passes through.
        assert!(scanned(&["--color=always", "-Ss", "firefox"]).is_none());
        assert!(scanned(&["-Qi", "firefox"]).is_none());
        assert!(scanned(&["-R", "firefox"]).is_none());
    }

    #[test]
    fn upgrade_with_operands_is_scanned_but_refresh_only_is_not() {
        // `-Syu pkg` installs pkg (scan it); `-Sy`/`-Syu` alone only refreshes.
        assert_eq!(scanned(&["-Syu", "pkg"]), Some(vec!["pkg".into()]));
        assert!(scanned(&["-Sy"]).is_none());
        assert!(scanned(&["-Syyuu"]).is_none());
    }

    #[test]
    fn multiple_operands_all_scanned() {
        assert_eq!(
            scanned(&["-S", "a", "b", "c"]),
            Some(vec!["a".into(), "b".into(), "c".into()])
        );
    }

    // --- fail-closed confirmation prompts (the security-critical contract) ---
    // In non-interactive mode (pipe/cron/CI: no TTY to answer), every override
    // prompt MUST refuse. An unattended run can never be talked into proceeding.
    #[test]
    fn confirm_typed_yes_refuses_when_non_interactive() {
        assert!(!confirm_typed_yes(false, "continue?").unwrap());
    }

    #[test]
    fn confirm_default_no_refuses_when_non_interactive() {
        assert!(!confirm_default_no(false, "continue?").unwrap());
    }

    // --- operand validation before fetch (defect #2) -------------------------
    // Illegal operands must never reach the AUR lookup / PKGBUILD fetch.
    #[test]
    fn fetch_candidates_keeps_only_valid_names() {
        let operands: Vec<String> = [
            "firefox",
            "google-chrome",
            "-rf",
            "../../etc/passwd",
            "a;b",
            "",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            fetch_candidates(&operands),
            vec!["firefox".to_string(), "google-chrome".to_string()]
        );
    }

    #[test]
    fn fetch_candidates_passes_clean_set_unchanged() {
        let operands: Vec<String> = ["paru", "yay"].iter().map(|s| s.to_string()).collect();
        assert_eq!(fetch_candidates(&operands), operands);
    }
}
