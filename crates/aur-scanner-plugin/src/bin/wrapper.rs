//! AUR helper wrapper
//!
//! Wraps yay/paru (and other pacman-grammar helpers) to scan before anything is
//! built or installed.
//!
//! Usage:
//!   aur-scan-wrap paru -S package
//!   aur-scan-wrap yay -S package1 package2
//!   aur-scan-wrap paru -Syu          # scans the pending AUR update set
//!   aur-scan-wrap paru -B ./mydir    # scans the local build dir
//!
//! Can be aliased:
//!   alias paru='aur-scan-wrap paru'
//!
//! The wrapper is a thin, fail-closed gate. It classifies the invocation,
//! works out WHAT would be built (named operands, the AUR update set, local
//! build directories) and delegates the actual dependency-tree scan to the
//! `aur-scan check` subcommand (argv only, no shell) so it inherits every fix
//! in the resolver and the scanner. Anything it cannot validate, resolve, or
//! enumerate BLOCKS; it never degrades to "run the helper anyway".
//!
//! Environment (same names as the shell integrations):
//!   AUR_SCAN_SEVERITY         gate threshold (critical|high|medium|low|info), default high
//!   AUR_SCAN_INTERACTIVE      0 = never prompt (deny findings), default 1 (prompt on a TTY)
//!   AUR_SCAN_MODE             `install` = race-free `aur-scan install` for named installs
//!   AUR_SCAN_SCAN_UPGRADES    0 = do not scan the AUR update set on -Syu / bare helper
//!   AUR_SCAN_SCAN_GETPKGBUILD 1 = also scan `-G` downloads

use aur_scanner_core::validate::is_valid_package_name;
use colored::Colorize;
use std::env;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

/// Long options (pacman / paru / yay) that consume the NEXT argv element as
/// their value in the `--opt value` form. Without this the value would be read
/// as a package operand. Only options that ALWAYS take a value are listed:
/// listing a boolean flag here would swallow a real operand (fail-open).
const VALUE_LONG_OPTS: &[&str] = &[
    "root",
    "dbpath",
    "cachedir",
    "logfile",
    "gpgdir",
    "hookdir",
    "arch",
    "color",
    "config",
    "sysroot",
    "ignore",
    "ignoregroup",
    "assume-installed",
    "overwrite",
    "print-format",
    "aururl",
    "clonedir",
    "builddir",
    "makepkg",
    "makepkgconf",
    "pacman",
    "pacmanconf",
    "git",
    "gitflags",
    "sudo",
    "sudoflags",
    "asp",
    "bat",
    "batflags",
    "fm",
    "fmflags",
    "editor",
    "editorflags",
    "mflags",
    "gpg",
    "gpgflags",
    "answerclean",
    "answerdiff",
    "answeredit",
    "answerupgrade",
    "searchby",
    "sortby",
    "completioninterval",
];

/// Long options that mean "this is not an install/upgrade at all".
const BENIGN_LONG_OPTS: &[&str] = &[
    "help", "version", "gendb", "stats", "news", "order", "comments",
];

/// How one `-S`-style operand is to be treated.
#[derive(Debug, PartialEq, Eq)]
enum Operand {
    /// Scan this AUR package name (`name`, or the `name` of `aur/name`).
    Aur(String),
    /// Explicit non-AUR repository target (`core/name`): nothing to scan.
    Repo,
    /// Cannot be validated: the invocation is blocked.
    Invalid(String),
}

/// Is `s` a plausible pacman repository name (the `repo` of `repo/name`)?
fn is_repo_token(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Normalise an install operand, understanding pacman's `repo/name` syntax.
fn parse_operand(raw: &str) -> Operand {
    if let Some((repo, name)) = raw.split_once('/') {
        if !is_valid_package_name(name) {
            return Operand::Invalid(raw.to_string());
        }
        if repo == "aur" {
            return Operand::Aur(name.to_string());
        }
        if is_repo_token(repo) {
            return Operand::Repo;
        }
        return Operand::Invalid(raw.to_string());
    }
    if is_valid_package_name(raw) {
        Operand::Aur(raw.to_string())
    } else {
        Operand::Invalid(raw.to_string())
    }
}

/// Everything the gate must do for one helper invocation.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    /// AUR package names that would be built/installed (roots).
    names: Vec<String>,
    /// A system upgrade: the AUR update set must be enumerated and scanned.
    upgrade: bool,
    /// `-G` operands (scanned only on opt-in).
    getpkgbuild: Vec<String>,
    /// Local build directories (`-B dir`, `-Ui`, `-U dir`).
    local_dirs: Vec<PathBuf>,
    /// One-line notices to print (e.g. prebuilt packages that cannot be scanned).
    notices: Vec<String>,
    /// Reasons the invocation must be refused outright.
    blocked: Vec<String>,
}

/// Classify a pacman/paru/yay invocation by its *operation*, not by substring
/// sniffing, and fail closed: anything that could install and cannot be
/// validated ends up in `blocked`.
///
/// `is_dir` answers "is this operand an existing directory" (injected so the
/// classifier stays unit-testable).
fn classify(helper_args: &[&str], is_dir: &dyn Fn(&str) -> bool) -> Plan {
    let mut op = String::new(); // uppercase operation selectors
    let mut mods = String::new(); // lowercase modifiers from short groups
    let mut long_opts: Vec<&str> = Vec::new();
    let mut operands: Vec<String> = Vec::new();
    let mut end_of_opts = false;
    let mut skip_value = false;

    for arg in helper_args {
        if end_of_opts {
            operands.push((*arg).to_string());
            continue;
        }
        if skip_value {
            skip_value = false;
            continue;
        }
        if *arg == "--" {
            end_of_opts = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            let (name, has_value) = match long.split_once('=') {
                Some((n, _)) => (n, true),
                None => (long, false),
            };
            long_opts.push(name);
            match name {
                "sync" => op.push('S'),
                "upgrade" => op.push('U'),
                "query" => op.push('Q'),
                "remove" => op.push('R'),
                "files" => op.push('F'),
                "database" => op.push('D'),
                "deptest" => op.push('T'),
                "getpkgbuild" => op.push('G'),
                "show" => op.push('P'),
                "build" => op.push('B'),
                "yay" => op.push('Y'),
                "sysupgrade" => mods.push('u'),
                "search" => mods.push('s'),
                "info" => mods.push('i'),
                "install" => mods.push('i'),
                "list" => mods.push('l'),
                "groups" => mods.push('g'),
                "clean" => mods.push('c'),
                "print" => mods.push('p'),
                _ => {}
            }
            if !has_value && VALUE_LONG_OPTS.contains(&name) {
                skip_value = true;
            }
        } else if let Some(short) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
            for c in short.chars() {
                if c.is_ascii_uppercase() {
                    op.push(c);
                } else {
                    mods.push(c);
                }
            }
            // pacman's -b <dbpath> / -r <root> take a separate value.
            if matches!(short, "b" | "r") {
                skip_value = true;
            }
        } else {
            operands.push((*arg).to_string());
        }
    }

    let mut plan = Plan::default();
    let has = |c: char| op.contains(c);
    let (is_sync, is_upfile, is_build) = (has('S'), has('U'), has('B'));
    let sysupgrade = mods.contains('u');
    let readonly_sync = mods
        .chars()
        .any(|m| matches!(m, 's' | 'i' | 'l' | 'g' | 'c' | 'p'));

    // -G only downloads a PKGBUILD for review: recorded, scanned on opt-in.
    if has('G') {
        plan.getpkgbuild = operands;
        return plan;
    }
    // -B (paru): build local PKGBUILD directories. Each directory is scanned.
    if is_build {
        let dirs = if operands.is_empty() {
            vec![".".to_string()]
        } else {
            operands
        };
        for d in dirs {
            if is_dir(&d) {
                plan.local_dirs.push(PathBuf::from(d));
            } else {
                plan.blocked.push(format!(
                    "-B operand {d:?} is not a directory; cannot scan it"
                ));
            }
        }
        return plan;
    }
    let non_install = ['Q', 'R', 'F', 'D', 'T', 'V', 'P'].iter().any(|c| has(*c));
    if non_install && !is_sync && !is_upfile {
        return plan;
    }
    if is_sync && readonly_sync {
        return plan;
    }
    if mods.contains('h') || long_opts.iter().any(|o| BENIGN_LONG_OPTS.contains(o)) {
        return plan;
    }

    // -U / -Ui: install a local file, or build a local PKGBUILD directory.
    if is_upfile && !is_sync {
        let build = mods.contains('i');
        if operands.is_empty() {
            if build {
                plan.local_dirs.push(PathBuf::from("."));
            }
            return plan;
        }
        for o in operands {
            let as_path = Path::new(&o);
            if is_dir(&o) {
                plan.local_dirs.push(PathBuf::from(&o));
            } else if as_path.file_name().is_some_and(|n| n == "PKGBUILD") {
                let parent = as_path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                plan.local_dirs.push(parent.to_path_buf());
            } else {
                plan.notices.push(format!(
                    "{o}: prebuilt package/URL installed as-is; aur-scan cannot pre-scan it"
                ));
            }
        }
        return plan;
    }

    // System upgrade: -Syu/-Su/-Sua, yay -Yu, or the helper's default action
    // (no operation and no operands, e.g. bare `paru` == `paru -Syu`).
    let bare = op.is_empty() && operands.is_empty();
    let bare_y = op == "Y" && mods.is_empty() && operands.is_empty() && long_opts.is_empty();
    if ((is_sync || has('Y')) && sysupgrade) || bare || bare_y {
        plan.upgrade = true;
    }

    // Named install: any operand of a non-read-only invocation (covers
    // `-S pkg`, `-Sw pkg`, bare `helper pkg`, yay `-Y pkg`). Fail closed on an
    // operand that cannot be validated.
    if !readonly_sync {
        for o in &operands {
            match parse_operand(o) {
                Operand::Aur(n) => {
                    if !plan.names.contains(&n) {
                        plan.names.push(n);
                    }
                }
                Operand::Repo => {}
                Operand::Invalid(bad) => plan.blocked.push(format!(
                    "package operand {bad:?} is not a valid package name; \
                     refusing to install what cannot be scanned"
                )),
            }
        }
    }
    plan
}

/// Outcome of enumerating the AUR update set via `<helper> -Quaq`.
#[derive(Debug, PartialEq, Eq)]
enum UpdateSet {
    Names(Vec<String>),
    Failed(String),
}

/// Interpret the result of `<helper> -Quaq`. pacman-style helpers exit 1 with
/// NO output when nothing is pending, so that exact shape means "no updates".
/// Any other failure (network down, helper error) must NOT be read as an empty
/// update set: that is how an unscanned upgrade slipped through.
fn parse_update_set(code: Option<i32>, stdout: &str, stderr: &str) -> UpdateSet {
    let nothing_pending = code == Some(1) && stdout.trim().is_empty() && stderr.trim().is_empty();
    if code != Some(0) && !nothing_pending {
        let detail = stderr.trim();
        return UpdateSet::Failed(if detail.is_empty() {
            format!("exit status {code:?}")
        } else {
            detail.lines().next().unwrap_or("").to_string()
        });
    }
    let mut names = Vec::new();
    for line in stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if !is_valid_package_name(line) {
            return UpdateSet::Failed(format!("unexpected update entry {line:?}"));
        }
        if !names.iter().any(|n| n == line) {
            names.push(line.to_string());
        }
    }
    UpdateSet::Names(names)
}

/// Severity names accepted by `aur-scan --severity/--fail-on`.
fn valid_severity(s: &str) -> bool {
    matches!(s, "critical" | "high" | "medium" | "low" | "info")
}

/// Build the argv (after `aur-scan`) for the dependency-tree check.
///
/// Interactive runs let `check` prompt on findings (no `--fail-on`: with a
/// threshold set the prompt could not override it). Non-interactive runs deny.
fn check_argv(
    names: &[String],
    local_dirs: &[PathBuf],
    severity: &str,
    interactive: bool,
) -> Vec<String> {
    let mut a: Vec<String> = vec!["--severity".into(), severity.into(), "check".into()];
    if !interactive {
        a.extend(["--no-confirm".into(), "--fail-on".into(), severity.into()]);
    }
    for d in local_dirs {
        a.push("--local".into());
        a.push(d.to_string_lossy().into_owned());
    }
    a.extend(names.iter().cloned());
    a
}

fn block(msg: &str) -> ExitCode {
    eprintln!("{} {}", "BLOCKED:".red().bold(), msg);
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::FAILURE;
    }
    let helper = &args[1];
    let helper_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    let plan = classify(&helper_args, &|p| Path::new(p).is_dir());

    if !plan.blocked.is_empty() {
        for reason in &plan.blocked {
            eprintln!("{} {}", "BLOCKED:".red().bold(), reason);
        }
        eprintln!(
            "Nothing was installed. Use '{helper}-unsafe' in your shell to bypass the scan deliberately."
        );
        return ExitCode::FAILURE;
    }
    for n in &plan.notices {
        eprintln!("{} {}", "notice:".yellow(), n);
    }

    let severity = env::var("AUR_SCAN_SEVERITY")
        .unwrap_or_else(|_| "high".into())
        .to_ascii_lowercase();
    let mut names = plan.names.clone();
    if env_is("AUR_SCAN_SCAN_GETPKGBUILD", "1") {
        names.extend(plan.getpkgbuild.iter().cloned());
    }

    if plan.upgrade && !env_is("AUR_SCAN_SCAN_UPGRADES", "0") {
        match enumerate_updates(helper) {
            Ok(upd) => names.extend(upd),
            Err(e) => {
                return block(&format!(
                    "could not list pending AUR updates ({helper} -Quaq failed: {e}); \
                     refusing to upgrade unscanned"
                ))
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));

    if names.is_empty() && plan.local_dirs.is_empty() {
        return run_helper(helper, &helper_args);
    }
    if !valid_severity(&severity) {
        return block(&format!(
            "AUR_SCAN_SEVERITY={severity:?} is not one of critical|high|medium|low|info"
        ));
    }

    // Race-free mode: a NAMED install that is not also an upgrade or local build.
    if env_is("AUR_SCAN_MODE", "install")
        && !plan.names.is_empty()
        && !plan.upgrade
        && plan.local_dirs.is_empty()
    {
        let mut argv = vec!["install".to_string()];
        argv.extend(plan.names.iter().cloned());
        return match run_aur_scan(&argv) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => block(&e),
        };
    }

    let interactive = !env_is("AUR_SCAN_INTERACTIVE", "0") && io::stdin().is_terminal();
    println!(
        "{} pre-checking {} package(s), {} local dir(s)...",
        "AUR Security Scanner:".cyan().bold(),
        names.len(),
        plan.local_dirs.len()
    );
    match run_aur_scan(&check_argv(
        &names,
        &plan.local_dirs,
        &severity,
        interactive,
    )) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "{} scan failed or aborted. Not proceeding with {helper}.",
                "BLOCKED:".red().bold()
            );
            return ExitCode::FAILURE;
        }
        Err(e) => return block(&e),
    }

    // TOCTOU disclosure: the helper re-fetches and builds its own copy, so for
    // named packages this pre-scan is advisory. `aur-scan install` is race-free.
    println!(
        "{} the helper re-fetches and builds its own copy, so this pre-scan is {}. \
         For a scan==build guarantee use: {}",
        "NOTE:".yellow().bold(),
        "advisory".yellow(),
        "aur-scan install <pkg>".white().bold()
    );
    run_helper(helper, &helper_args)
}

fn env_is(key: &str, val: &str) -> bool {
    env::var(key).is_ok_and(|v| v == val)
}

/// Run `aur-scan <argv>` (resolved through PATH, no shell). `Ok(true)` = exit 0.
fn run_aur_scan(argv: &[String]) -> Result<bool, String> {
    match Command::new("aur-scan")
        .args(argv)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(format!(
            "could not run `aur-scan` ({e}); refusing to proceed unscanned"
        )),
    }
}

fn enumerate_updates(helper: &str) -> Result<Vec<String>, String> {
    let out = Command::new(helper)
        .arg("-Quaq")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {helper}: {e}"))?;
    match parse_update_set(
        out.status.code(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    ) {
        UpdateSet::Names(n) => Ok(n),
        UpdateSet::Failed(e) => Err(e),
    }
}

fn run_helper(helper: &str, args: &[&str]) -> ExitCode {
    match Command::new(helper)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(st) if st.success() => ExitCode::SUCCESS,
        Ok(st) => ExitCode::from(st.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("{} failed to run {helper}: {e}", "Error:".red().bold());
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("AUR Security Scanner Wrapper");
    eprintln!();
    eprintln!("Usage: aur-scan-wrap <helper> [args...]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  aur-scan-wrap paru -S package");
    eprintln!("  aur-scan-wrap yay -Syu");
    eprintln!("  aur-scan-wrap paru -B ./pkgdir");
    eprintln!();
    eprintln!("Setup as alias:");
    eprintln!("  alias paru='aur-scan-wrap paru'");
    eprintln!("  alias yay='aur-scan-wrap yay'");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_dirs(_: &str) -> bool {
        false
    }
    fn plan(args: &[&str]) -> Plan {
        classify(args, &no_dirs)
    }
    fn names(args: &[&str]) -> Vec<String> {
        let p = plan(args);
        assert!(p.blocked.is_empty(), "unexpected block: {:?}", p.blocked);
        p.names
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn installs_are_scanned() {
        assert_eq!(names(&["-S", "firefox"]), s(&["firefox"]));
        assert_eq!(names(&["-Syu", "pkg"]), s(&["pkg"]));
        assert_eq!(names(&["--sync", "pkg"]), s(&["pkg"]));
        assert_eq!(names(&["foo"]), s(&["foo"]));
        assert_eq!(names(&["-S", "--", "pkg"]), s(&["pkg"]));
        assert_eq!(names(&["-Y", "cheese"]), s(&["cheese"]));
        assert_eq!(names(&["--yay", "cheese"]), s(&["cheese"]));
        assert_eq!(names(&["-S", "a", "b", "c"]), s(&["a", "b", "c"]));
    }

    #[test]
    fn read_only_ops_pass_through() {
        for args in [
            &["-Ss", "firefox"][..],
            &["-Si", "firefox"],
            &["-Sl"],
            &["-Sg"],
            &["-Sc"],
            &["-Qi", "firefox"],
            &["-Q"],
            &["-R", "firefox"],
            &["-Quaq"],
            &["-P"],
            &["-Y", "--gendb"],
            &["--help"],
            &["-h"],
            &["--version"],
        ] {
            assert_eq!(plan(args), Plan::default(), "{args:?} must pass through");
        }
        // -G downloads a PKGBUILD only: never gates by default.
        let g = plan(&["-G", "firefox"]);
        assert!(!g.upgrade && g.names.is_empty() && g.blocked.is_empty());
        assert_eq!(g.getpkgbuild, s(&["firefox"]));
    }

    #[test]
    fn unrelated_flags_do_not_disable_scanning() {
        assert_eq!(
            names(&["-S", "--needed", "--noconfirm", "pkg"]),
            s(&["pkg"])
        );
        assert_eq!(names(&["-S", "--rebuild", "pkg"]), s(&["pkg"]));
        assert_eq!(names(&["--noconfirm", "evilpkg"]), s(&["evilpkg"]));
        assert_eq!(names(&["--needed", "pkg"]), s(&["pkg"]));
    }

    // Regression: `-Syu`, `-Sua` and bare `paru`/`yay` used to pass straight
    // through unscanned (the old test asserted exactly that).
    #[test]
    fn upgrades_and_bare_invocations_are_gated() {
        for args in [
            &["-Syu"][..],
            &["-Su"],
            &["-Sua"],
            &["-Syyuu"],
            &["--sync", "--sysupgrade"],
            &[],
            &["--noconfirm"],
            &["-Yu"],
            &["-Y"],
        ] {
            assert!(plan(args).upgrade, "{args:?} must be treated as an upgrade");
        }
        assert!(!plan(&["-Sy"]).upgrade, "refresh only installs nothing");
        // `-Syu pkg` is both.
        let p = plan(&["-Syu", "pkg"]);
        assert!(p.upgrade);
        assert_eq!(p.names, s(&["pkg"]));
    }

    // Regression: `aur-scan-wrap paru -S aur/evil` used to warn "ignoring
    // invalid package operand (not scanned)" and run the helper.
    #[test]
    fn repo_prefix_syntax() {
        assert_eq!(names(&["-S", "aur/evil"]), s(&["evil"]));
        assert!(names(&["-S", "core/glibc", "extra/vim"]).is_empty());
        assert_eq!(names(&["-S", "core/glibc", "aur/evil"]), s(&["evil"]));
        assert_eq!(parse_operand("aur/a/b"), Operand::Invalid("aur/a/b".into()));
    }

    #[test]
    fn unvalidatable_operands_block() {
        for bad in [
            "../../etc/passwd",
            "a;b",
            "-rf",
            "https://evil.example/x",
            "./dir",
            "/abs/path",
            "aur/../x",
            "$(id)",
        ] {
            let p = plan(&["-S", bad]);
            // A leading-dash arg is an option, not an operand; everything else blocks.
            if bad.starts_with('-') {
                continue;
            }
            assert!(!p.blocked.is_empty(), "{bad:?} must block");
        }
        // Mixed: one good, one bad -> still blocked.
        assert!(!plan(&["-S", "ok", "a;b"]).blocked.is_empty());
    }

    #[test]
    fn option_values_are_not_operands() {
        // `--sudo doas` / `--aurdir /x` consume their value; it must neither be
        // scanned nor (for a path) block the install.
        let p = plan(&["-S", "--sudo", "doas", "--clonedir", "/tmp/x", "pkg"]);
        assert!(p.blocked.is_empty());
        assert_eq!(p.names, s(&["pkg"]));
        // `=` form carries its value inline.
        assert_eq!(names(&["--clonedir=/tmp/x", "-S", "pkg"]), s(&["pkg"]));
        // A boolean flag must NOT swallow an operand.
        assert_eq!(names(&["-S", "--needed", "pkg"]), s(&["pkg"]));
    }

    // Local builds.
    #[test]
    fn local_builds_are_scanned() {
        let dirs = |p: &str| p == "mydir" || p == "." || p == "./d";
        let p = classify(&["-B", "mydir"], &dirs);
        assert_eq!(p.local_dirs, vec![PathBuf::from("mydir")]);
        assert!(p.names.is_empty(), "-B operands are dirs, not AUR names");
        let p = classify(&["-Ui"], &dirs);
        assert_eq!(p.local_dirs, vec![PathBuf::from(".")]);
        let p = classify(&["-U", "./d"], &dirs);
        assert_eq!(p.local_dirs, vec![PathBuf::from("./d")]);
        let p = classify(&["-U", "sub/PKGBUILD"], &dirs);
        assert_eq!(p.local_dirs, vec![PathBuf::from("sub")]);
        // -B on something that is not a directory cannot be scanned: block.
        assert!(!classify(&["-B", "nope"], &dirs).blocked.is_empty());
    }

    #[test]
    fn prebuilt_package_install_passes_with_notice() {
        let p = plan(&["-U", "foo-1-1-x86_64.pkg.tar.zst"]);
        assert!(p.blocked.is_empty() && p.local_dirs.is_empty() && p.names.is_empty());
        assert_eq!(p.notices.len(), 1);
    }

    #[test]
    fn update_set_fails_closed() {
        assert_eq!(
            parse_update_set(Some(0), "a\nb\n", ""),
            UpdateSet::Names(s(&["a", "b"]))
        );
        // pacman-style "nothing pending": exit 1, completely silent.
        assert_eq!(parse_update_set(Some(1), "", ""), UpdateSet::Names(vec![]));
        // Network down / helper error: must NOT read as "no updates".
        assert!(matches!(
            parse_update_set(Some(1), "", "error: failed to connect"),
            UpdateSet::Failed(_)
        ));
        assert!(matches!(
            parse_update_set(Some(2), "", ""),
            UpdateSet::Failed(_)
        ));
        assert!(matches!(
            parse_update_set(None, "", ""),
            UpdateSet::Failed(_)
        ));
        assert!(matches!(
            parse_update_set(Some(0), "ok\n../evil\n", ""),
            UpdateSet::Failed(_)
        ));
    }

    #[test]
    fn check_argv_honours_severity_and_tty() {
        let a = check_argv(&s(&["p"]), &[PathBuf::from("d")], "medium", false);
        assert_eq!(
            a,
            s(&[
                "--severity",
                "medium",
                "check",
                "--no-confirm",
                "--fail-on",
                "medium",
                "--local",
                "d",
                "p"
            ])
        );
        let a = check_argv(&s(&["p"]), &[], "high", true);
        assert_eq!(a, s(&["--severity", "high", "check", "p"]));
        assert!(valid_severity("critical") && !valid_severity("hgih"));
    }
}
