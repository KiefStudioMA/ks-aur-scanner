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
    let (_, _, scan_code) = run(&["-c", bad.to_str().unwrap(), "codes"]);
    assert_ne!(scan_code, 0, "a malformed config must still fail elsewhere");

    std::fs::remove_file(&bad).ok();
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
        (
            "crates/aur-scanner-plugin/src/bin/wrapper.rs",
            "the AUR-helper wrapper every paru/yay/nushell user goes through",
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
