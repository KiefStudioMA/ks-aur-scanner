//! Self-adversarial evasion fuzzer (task 4038).
//!
//! Premise: the AUR attacker reads our public ruleset and auto-generates the
//! re-spelling we don't catch. Counter: red-team ourselves first. This harness
//! takes every malicious fixture and applies a library of **semantics-preserving**
//! evasion transforms (a real attacker's respellings of the same payload) to
//! every scannable file in it, then asserts the scanner STILL gates the mutated
//! package (`--fail-on high` ⇒ exit 1). A variant that drops below the gate is a
//! real false-negative hole and fails the build.
//!
//! The generated variants live only in a scratch temp dir — the evasion corpus is
//! never written into the repo (it would be an evasion cookbook).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_aur-scan")
}

fn malicious_fixtures() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/malicious");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("reading {}: {e}", root.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("PKGBUILD").is_file())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no malicious fixtures found");
    dirs
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("aurfuzz-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).expect("mk scratch dir");
    dir
}

/// A file the scanner reads (so a payload in it counts). Mirrors the scanner's
/// own inputs: the PKGBUILD and any install scriptlet / shipped shell script.
fn is_scannable(p: &Path) -> bool {
    let n = p
        .file_name()
        .map(|x| x.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    n == "pkgbuild" || n.ends_with(".install") || n.ends_with(".sh") || n.ends_with(".bash")
}

/// Copy a fixture's files into a scratch dir (recursively), optionally applying
/// `tf` to each scannable file's text. Returns (scratch_dir, any_file_changed).
fn materialize(src: &Path, tf: Option<fn(&str) -> Option<String>>) -> (PathBuf, bool) {
    let dst = scratch();
    let mut changed = false;
    copy_into(src, &dst, tf, &mut changed);
    (dst, changed)
}

fn copy_into(src: &Path, dst: &Path, tf: Option<fn(&str) -> Option<String>>, changed: &mut bool) {
    for entry in std::fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            std::fs::create_dir_all(&target).expect("mkdir");
            copy_into(&path, &target, tf, changed);
        } else if let (Some(tf), true) = (tf, is_scannable(&path)) {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            match tf(&text) {
                Some(mutated) => {
                    *changed = true;
                    std::fs::write(&target, mutated).expect("write mutated");
                }
                None => std::fs::copy(&path, &target)
                    .map(|_| ())
                    .expect("copy file"),
            }
        } else {
            std::fs::copy(&path, &target)
                .map(|_| ())
                .expect("copy file");
        }
    }
}

/// Whether the scanner BLOCKS the package in `dir` (`scan --fail-on high` exits 1).
fn gates_dir(dir: &Path) -> bool {
    Command::new(bin())
        .args(["scan", dir.to_str().unwrap(), "--fail-on", "high"])
        .output()
        .expect("run aur-scan")
        .status
        .code()
        == Some(1)
}

/// A transform returns `Some(mutated)` when it applies (changed the text), else
/// `None` (its target token isn't present in this file).
fn changed(orig: &str, new: String) -> Option<String> {
    (new != orig).then_some(new)
}

type Transform = (&'static str, fn(&str) -> Option<String>);

fn transforms() -> Vec<Transform> {
    vec![
        // --- functional respellings (the payload still runs the same) ---
        ("fetcher-swap curl→wget", |s| {
            changed(
                s,
                s.replace("curl -fsSL ", "wget -qO- ")
                    .replace("curl -sSL ", "wget -qO- ")
                    .replace("curl -s ", "wget -qO- ")
                    .replace("curl ", "wget -qO- "),
            )
        }),
        ("interpreter-swap bash→dash", |s| {
            changed(
                s,
                s.replace("| bash", "| dash").replace("bash -c", "dash -c"),
            )
        }),
        ("interpreter-swap →busybox sh", |s| {
            changed(
                s,
                s.replace("| sh", "| busybox sh")
                    .replace("| bash", "| busybox sh"),
            )
        }),
        ("printf-assembly of curl", |s| {
            changed(s, s.replacen("curl ", "$(printf '\\x63url') ", 1))
        }),
        ("variable-indirection of bash", |s| {
            if !s.contains("| bash") {
                return None;
            }
            changed(
                s,
                s.replacen("| bash", "| $_r", 1)
                    .replacen("{\n", "{\n  _r=bash\n", 1),
            )
        }),
        ("IFS-for-space after fetcher", |s| {
            changed(
                s,
                s.replacen("curl ", "curl${IFS}", 1)
                    .replacen("wget ", "wget${IFS}", 1),
            )
        }),
        ("adjacent-quote split of curl", |s| {
            changed(s, s.replacen("curl", "\"c\"url", 1))
        }),
        ("line-continuation before pipe", |s| {
            changed(s, s.replacen("| ", "\\\n  | ", 1))
        }),
        // --- defense-in-depth (validates the case-insensitivity work, 4119) ---
        ("case-variation of command tokens", |s| {
            changed(
                s,
                s.replace("curl", "CURL")
                    .replace("wget", "WGET")
                    .replace("sudo", "SUDO")
                    .replace("setcap", "SETCAP")
                    .replace("| bash", "| BASH")
                    .replace("eval ", "EVAL "),
            )
        }),
    ]
}

#[test]
fn every_malicious_fixture_resists_evasion_transforms() {
    let transforms = transforms();
    let mut evasions: Vec<String> = Vec::new();
    let mut applied = 0usize;

    for src in malicious_fixtures() {
        let name = src.file_name().unwrap().to_string_lossy().to_string();

        // Sanity: the untouched fixture must gate (whole dir, companion files
        // included). If not, the fixture is broken — fail loudly.
        let (base, _) = materialize(&src, None);
        let base_gates = gates_dir(&base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            base_gates,
            "baseline: malicious fixture `{name}` does not gate"
        );

        for (tname, tf) in &transforms {
            let (variant, did) = materialize(&src, Some(*tf));
            if did {
                applied += 1;
                if !gates_dir(&variant) {
                    evasions.push(format!("  EVADES: `{name}` × `{tname}`"));
                }
            }
            let _ = std::fs::remove_dir_all(&variant);
        }
    }

    eprintln!(
        "evasion fuzzer: {applied} mutated variants tested across the malicious corpus, {} evasion(s)",
        evasions.len()
    );
    assert!(
        applied > 0,
        "no transforms applied to any fixture (harness broken)"
    );
    assert!(
        evasions.is_empty(),
        "{} evasion(s) slipped the gate ({} variants tested):\n{}",
        evasions.len(),
        applied,
        evasions.join("\n")
    );
}
