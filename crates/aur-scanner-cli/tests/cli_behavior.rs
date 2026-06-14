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
        .args(["scan", dir.to_str().unwrap(), "--include-info", "--format", fmt])
        .output()
        .expect("failed to run aur-scan");
    (out.stdout, out.stderr, out.status.code().unwrap_or(-1))
}

fn parse_findings(stdout: &[u8]) -> Vec<serde_json::Value> {
    // from_slice (not a lenient reader) rejects ANY trailing bytes after the
    // JSON document -- this is the exact assertion the summary-on-stdout bug
    // failed.
    let v: serde_json::Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|e| panic!("stdout was not a single clean JSON document: {e}\n--- stdout ---\n{}", String::from_utf8_lossy(stdout)));
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
    for dir in fixture_dirs("malicious").into_iter().chain(fixture_dirs("clean")) {
        let (stdout, _err, _code) = scan(&dir, "json");
        let findings = parse_findings(&stdout);
        // Sanity: each finding has the fields downstream tooling relies on.
        for f in &findings {
            assert!(f["id"].is_string(), "finding missing id in {dir:?}");
            assert!(f["severity"].is_string(), "finding missing severity in {dir:?}");
        }
    }
}

#[test]
fn sarif_stdout_is_valid() {
    let dir = &fixture_dirs("malicious")[0];
    let (stdout, _err, _code) = scan(dir, "sarif");
    let v: serde_json::Value = serde_json::from_slice(&stdout)
        .expect("SARIF stdout must be a single clean JSON document");
    assert!(v["runs"][0]["results"].is_array(), "SARIF missing runs[0].results");
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
    for dir in fixture_dirs("malicious").into_iter().chain(fixture_dirs("clean")) {
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

    assert_eq!(code(mal, "critical"), 1, "malicious must exit 1 under --fail-on critical");
    assert_eq!(code(clean, "critical"), 0, "clean must exit 0 under --fail-on critical");
}
