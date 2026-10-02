//! Behavioural tests for the install gates: the bash/zsh/fish/nushell
//! integrations (`install/integration.*`) and the `aur-scan-wrap` binary.
//!
//! Every gate is driven against STUB executables on a temp `PATH` -- a fake
//! `paru`/`yay`/`aur-scan` that only append to a log. Nothing here ever runs a
//! real AUR helper, pacman or makepkg, and nothing is installed.
//!
//! One shared case table is run through every gate, so the shells and the
//! wrapper are held to the same contract (the README calls the nushell path
//! "the same scan-then-handoff gate"). A shell that is not installed is
//! skipped, with a note on stderr.
//!
//! Run just these:  cargo test -p aur-scanner-plugin --test shell_gate

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug)]
enum Expect {
    /// Non-zero exit and the helper never ran.
    Blocked,
    /// Helper ran (exit 0). `scan`: `None` = `aur-scan` must NOT be called;
    /// `Some((names, locals))` = exactly one `check` with these roots/--local dirs.
    Ran(Option<(&'static [&'static str], &'static [&'static str])>),
}

struct Case {
    name: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    /// Do not provide an `aur-scan` stub (scanner missing).
    no_scanner: bool,
    expect: Expect,
    /// Wrapper binary has no `*-unsafe` commands.
    skip_wrapper: bool,
    /// Optional: required severity token on the `check` call.
    severity: Option<&'static str>,
}

const fn case(
    name: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    expect: Expect,
) -> Case {
    Case {
        name,
        args,
        env,
        no_scanner: false,
        expect,
        skip_wrapper: false,
        severity: None,
    }
}

fn cases() -> Vec<Case> {
    use Expect::*;
    const UPD: (&str, &str) = ("STUB_UPDATES", "foo bar");
    vec![
        // --- operands -------------------------------------------------------
        // Regression: `aur/evil` used to be dropped with a warning and run.
        case(
            "aur-prefix scans the name",
            &["-S", "aur/evil"],
            &[],
            Ran(Some((&["evil"], &[]))),
        ),
        case(
            "repo-prefix passes unscanned",
            &["-S", "core/glibc"],
            &[],
            Ran(None),
        ),
        case(
            "mixed repo and aur prefix",
            &["-S", "core/glibc", "aur/evil"],
            &[],
            Ran(Some((&["evil"], &[]))),
        ),
        case("illegal operand blocks", &["-S", "ok", "a;b"], &[], Blocked),
        case(
            "url operand blocks",
            &["-S", "https://evil.example/x"],
            &[],
            Blocked,
        ),
        case("path operand to -S blocks", &["-S", "./dir"], &[], Blocked),
        case(
            "scanner failure blocks",
            &["-S", "aur/evil"],
            &[("STUB_SCAN_RC", "1")],
            Blocked,
        ),
        case(
            "option values are not operands",
            &["-S", "--sudo", "doas", "--clonedir", "/tmp/x", "foo"],
            &[],
            Ran(Some((&["foo"], &[]))),
        ),
        // --- upgrades -------------------------------------------------------
        // Regression: -Syu / -Sua / bare helper used to pass through unscanned.
        case(
            "-Syu scans the update set",
            &["-Syu"],
            &[UPD],
            Ran(Some((&["foo", "bar"], &[]))),
        ),
        case(
            "-Sua scans the update set",
            &["-Sua"],
            &[UPD],
            Ran(Some((&["foo", "bar"], &[]))),
        ),
        case(
            "bare helper scans the update set",
            &[],
            &[UPD],
            Ran(Some((&["foo", "bar"], &[]))),
        ),
        case(
            "-Syu pkg scans both",
            &["-Syu", "aur/evil"],
            &[UPD],
            Ran(Some((&["evil", "foo", "bar"], &[]))),
        ),
        // Regression: a failing `-Quaq` (network down) used to mean "no updates".
        case(
            "-Quaq failure blocks the upgrade",
            &["-Syu"],
            &[
                ("STUB_QUAQ_RC", "1"),
                ("STUB_QUAQ_ERR", "error: could not resolve host"),
            ],
            Blocked,
        ),
        case(
            "-Quaq exit 2 blocks the upgrade",
            &["-Syu"],
            &[("STUB_QUAQ_RC", "2")],
            Blocked,
        ),
        case(
            "silent exit 1 means no updates",
            &["-Syu"],
            &[("STUB_QUAQ_RC", "1")],
            Ran(None),
        ),
        case(
            "upgrade scan finding blocks",
            &["-Syu"],
            &[UPD, ("STUB_SCAN_RC", "1")],
            Blocked,
        ),
        case(
            "AUR_SCAN_SCAN_UPGRADES=0 skips the update scan",
            &["-Syu"],
            &[("AUR_SCAN_SCAN_UPGRADES", "0")],
            Ran(None),
        ),
        // --- read-only ------------------------------------------------------
        case("search passes", &["-Ss", "foo"], &[], Ran(None)),
        case("query passes", &["-Qi", "foo"], &[], Ran(None)),
        case("refresh only passes", &["-Sy"], &[], Ran(None)),
        // --- local builds ---------------------------------------------------
        case("-Ui scans cwd", &["-Ui"], &[], Ran(Some((&[], &["."])))),
        case(
            "-B dir scans the dir",
            &["-B", "mydir"],
            &[],
            Ran(Some((&[], &["mydir"]))),
        ),
        case(
            "-B ./dir scans the dir",
            &["-B", "./mydir"],
            &[],
            Ran(Some((&[], &["./mydir"]))),
        ),
        case(
            "-B on a non-directory blocks",
            &["-B", "nodir"],
            &[],
            Blocked,
        ),
        case(
            "-U dir scans the dir",
            &["-U", "mydir"],
            &[],
            Ran(Some((&[], &["mydir"]))),
        ),
        case(
            "-U PKGBUILD scans its dir",
            &["-U", "mydir/PKGBUILD"],
            &[],
            Ran(Some((&[], &["mydir"]))),
        ),
        case(
            "-U built package passes",
            &["-U", "foo-1-1-x86_64.pkg.tar.zst"],
            &[],
            Ran(None),
        ),
        case(
            "local scan failure blocks",
            &["-B", "mydir"],
            &[("STUB_SCAN_RC", "1")],
            Blocked,
        ),
        // --- configuration --------------------------------------------------
        Case {
            severity: Some("medium"),
            ..case(
                "AUR_SCAN_SEVERITY is honoured",
                &["-S", "foo"],
                &[("AUR_SCAN_SEVERITY", "medium")],
                Ran(Some((&["foo"], &[]))),
            )
        },
        // --- scanner missing ------------------------------------------------
        Case {
            no_scanner: true,
            ..case(
                "missing aur-scan refuses an install",
                &["-S", "foo"],
                &[],
                Blocked,
            )
        },
        Case {
            no_scanner: true,
            ..case(
                "missing aur-scan refuses an upgrade",
                &["-Syu"],
                &[UPD],
                Blocked,
            )
        },
        Case {
            no_scanner: true,
            ..case(
                "missing aur-scan still allows read-only",
                &["-Ss", "foo"],
                &[],
                Ran(None),
            )
        },
    ]
}

// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum Gate {
    Bash,
    Zsh,
    Fish,
    Nu,
    Wrapper,
}

fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(bin))
            .find(|c| c.is_file())
    })
}

fn install_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../install")
        .join(name)
        .canonicalize()
        .expect("install file")
}

struct Sandbox {
    root: PathBuf,
    bin: PathBuf,
    work: PathBuf,
    log: PathBuf,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl Sandbox {
    fn new(with_scanner: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aur-scan-gate-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let bin = root.join("bin");
        let work = root.join("work");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(work.join("mydir")).unwrap();
        fs::write(work.join("mydir/PKGBUILD"), "pkgname=x\n").unwrap();
        let log = root.join("log");
        fs::write(&log, "").unwrap();

        let stub = |name: &str, body: &str| {
            let p = bin.join(name);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            }
        };
        if with_scanner {
            stub(
                "aur-scan",
                r#"printf 'SCAN' >> "$STUB_LOG"; for a in "$@"; do printf ' %s' "$a" >> "$STUB_LOG"; done; echo >> "$STUB_LOG"
exit "${STUB_SCAN_RC:-0}""#,
            );
        }
        let helper = r#"n=$(basename "$0")
if [ "$1" = "-Quaq" ]; then
  echo "QUAQ" >> "$STUB_LOG"
  [ -n "$STUB_UPDATES" ] && printf '%s\n' $STUB_UPDATES
  [ -n "$STUB_QUAQ_ERR" ] && echo "$STUB_QUAQ_ERR" >&2
  exit "${STUB_QUAQ_RC:-0}"
fi
echo "RAN $n $*" >> "$STUB_LOG"
exit 0"#;
        stub("paru", helper);
        stub("yay", helper);
        // nushell routes through the real wrapper binary.
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            env!("CARGO_BIN_EXE_aur-scan-wrap"),
            bin.join("aur-scan-wrap"),
        )
        .unwrap();
        Sandbox {
            root,
            bin,
            work,
            log,
        }
    }

    fn base_cmd(&self, mut cmd: Command, extra_env: &[(&str, &str)]) -> Command {
        cmd.env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("HOME", &self.root)
            .env("NO_COLOR", "1")
            .env("STUB_LOG", &self.log)
            .current_dir(&self.work)
            .stdin(Stdio::null());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Run `helper args...` through `gate` in the sandbox; returns (exit ok, log lines, stderr+stdout).
fn run_gate(
    gate: Gate,
    sb: &Sandbox,
    helper: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> (bool, Vec<String>, String) {
    let out = match gate {
        Gate::Wrapper => {
            let mut c = sb.base_cmd(Command::new(env!("CARGO_BIN_EXE_aur-scan-wrap")), env);
            c.arg(helper).args(args);
            c.output().unwrap()
        }
        Gate::Bash => {
            let mut c = sb.base_cmd(Command::new(which("bash").unwrap()), env);
            c.args([
                "--noprofile",
                "--norc",
                "-c",
                r#"source "$1"; shift; "$@""#,
                "_",
            ])
            .arg(install_file("integration.bash"))
            .arg(helper)
            .args(args);
            c.output().unwrap()
        }
        Gate::Zsh => {
            let mut c = sb.base_cmd(Command::new(which("zsh").unwrap()), env);
            c.args(["-f", "-c", r#"source "$1"; shift; "$@""#, "_"])
                .arg(install_file("integration.zsh"))
                .arg(helper)
                .args(args);
            c.output().unwrap()
        }
        Gate::Fish => {
            let mut c = sb.base_cmd(Command::new(which("fish").unwrap()), env);
            c.args([
                "--no-config",
                "-c",
                "source $argv[1]; set -e argv[1]; $argv",
            ])
            .arg(install_file("integration.fish"))
            .arg(helper)
            .args(args);
            c.output().unwrap()
        }
        Gate::Nu => {
            let script = sb.root.join("gate.nu");
            fs::write(
                &script,
                format!(
                    "source {:?}\ndef --wrapped main [...rest] {{\n  let h = ($rest | first)\n  let a = ($rest | skip 1)\n  match $h {{\n    \"paru\" => {{ paru ...$a }}\n    \"yay\" => {{ yay ...$a }}\n    \"paru-unsafe\" => {{ paru-unsafe ...$a }}\n    _ => {{ error make {{msg: \"bad helper\"}} }}\n  }}\n}}\n",
                    install_file("integration.nu").display().to_string()
                ),
            )
            .unwrap();
            let mut c = sb.base_cmd(Command::new(which("nu").unwrap()), env);
            c.args(["--no-config-file"])
                .arg(&script)
                .arg(helper)
                .args(args);
            c.output().unwrap()
        }
    };
    let log = fs::read_to_string(&sb.log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), log, text)
}

/// Parse a logged `SCAN ...` line into (severity, roots, local dirs).
fn parse_scan(line: &str) -> (Option<String>, Vec<String>, Vec<String>) {
    let toks: Vec<&str> = line.split_whitespace().skip(1).collect();
    let (mut sev, mut names, mut locals) = (None, vec![], vec![]);
    let mut i = 0;
    let mut seen_check = false;
    while i < toks.len() {
        match toks[i] {
            "check" => seen_check = true,
            "--severity" => {
                sev = toks.get(i + 1).map(|s| s.to_string());
                i += 1;
            }
            "--fail-on" => i += 1,
            "--no-confirm" => {}
            "--local" => {
                locals.push(toks[i + 1].to_string());
                i += 1;
            }
            t if seen_check => names.push(t.to_string()),
            _ => {}
        }
        i += 1;
    }
    (sev, names, locals)
}

fn run_all(gate: Gate) {
    let (bin, skip_note) = match gate {
        Gate::Bash => ("bash", "bash"),
        Gate::Zsh => ("zsh", "zsh"),
        Gate::Fish => ("fish", "fish"),
        Gate::Nu => ("nu", "nu"),
        Gate::Wrapper => ("sh", "sh"),
    };
    if which(bin).is_none() {
        eprintln!("SKIP: {skip_note} is not installed; {gate:?} gate not exercised");
        return;
    }
    let mut failures = Vec::new();
    for c in cases() {
        if gate == Gate::Wrapper && c.skip_wrapper {
            continue;
        }
        let sb = Sandbox::new(!c.no_scanner);
        let (ok, log, text) = run_gate(gate, &sb, "paru", c.args, c.env);
        let ran: Vec<&String> = log.iter().filter(|l| l.starts_with("RAN ")).collect();
        let scans: Vec<&String> = log.iter().filter(|l| l.starts_with("SCAN ")).collect();
        let mut why = None;
        match c.expect {
            Expect::Blocked => {
                if ok || !ran.is_empty() {
                    why = Some(format!("expected BLOCK, ok={ok} ran={ran:?}"));
                }
            }
            Expect::Ran(scan) => {
                let want_run = format!("RAN paru {}", c.args.join(" "));
                if !ok || ran.len() != 1 || *ran[0] != want_run {
                    why = Some(format!(
                        "expected helper run {want_run:?}, ok={ok} log={log:?}"
                    ));
                } else if let Some((names, locals)) = scan {
                    if scans.len() != 1 {
                        why = Some(format!("expected exactly one scan, got {scans:?}"));
                    } else {
                        let (sev, n, l) = parse_scan(scans[0]);
                        let mut nn = n.clone();
                        nn.sort();
                        let mut wn: Vec<String> = names.iter().map(|s| s.to_string()).collect();
                        wn.sort();
                        if nn != wn || l != locals {
                            why = Some(format!("scan roots {n:?}/{l:?} != {names:?}/{locals:?}"));
                        }
                        if let Some(want) = c.severity {
                            if sev.as_deref() != Some(want) {
                                why = Some(format!("severity {sev:?} != {want}"));
                            }
                        }
                    }
                } else if !scans.is_empty() {
                    why = Some(format!("unexpected scan {scans:?}"));
                }
            }
        }
        if let Some(w) = why {
            failures.push(format!(
                "[{gate:?}] {}: {w}\n--- output ---\n{text}",
                c.name
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn bash_gate() {
    run_all(Gate::Bash);
}

#[test]
fn zsh_gate() {
    run_all(Gate::Zsh);
}

#[test]
fn fish_gate() {
    run_all(Gate::Fish);
}

#[test]
fn nushell_gate() {
    run_all(Gate::Nu);
}

#[test]
fn wrapper_gate() {
    run_all(Gate::Wrapper);
}

/// The `*-unsafe` escape hatch must run the helper unscanned even with no
/// scanner installed, in every shell (fish's used to be an interactive-only
/// abbreviation).
#[test]
fn unsafe_commands_bypass_in_every_shell() {
    for gate in [Gate::Bash, Gate::Zsh, Gate::Fish, Gate::Nu] {
        let bin = match gate {
            Gate::Bash => "bash",
            Gate::Zsh => "zsh",
            Gate::Fish => "fish",
            _ => "nu",
        };
        if which(bin).is_none() {
            eprintln!("SKIP: {bin} not installed");
            continue;
        }
        let sb = Sandbox::new(false);
        let (ok, log, text) = run_gate(gate, &sb, "paru-unsafe", &["-S", "foo"], &[]);
        assert!(
            ok && log == vec!["RAN paru -S foo".to_string()],
            "[{gate:?}] paru-unsafe should run unscanned: ok={ok} log={log:?}\n{text}"
        );
    }
}

/// Nushell used to run the helper unscanned (warning only) when
/// `aur-scan-wrap` was missing.
#[test]
fn nushell_refuses_when_wrapper_missing() {
    if which("nu").is_none() {
        eprintln!("SKIP: nu not installed");
        return;
    }
    let sb = Sandbox::new(true);
    fs::remove_file(sb.bin.join("aur-scan-wrap")).unwrap();
    let (ok, log, text) = run_gate(Gate::Nu, &sb, "paru", &["-S", "foo"], &[]);
    assert!(
        !ok && log.is_empty(),
        "nu must refuse: ok={ok} log={log:?}\n{text}"
    );
    // ...and the hatch still works.
    let (ok, log, _) = run_gate(Gate::Nu, &sb, "paru-unsafe", &["-S", "foo"], &[]);
    assert!(ok && log == vec!["RAN paru -S foo".to_string()]);
}

/// An invalid AUR_SCAN_SEVERITY must block rather than silently weaken the gate.
#[test]
fn wrapper_rejects_bogus_severity() {
    let sb = Sandbox::new(true);
    let (ok, log, _) = run_gate(
        Gate::Wrapper,
        &sb,
        "paru",
        &["-S", "foo"],
        &[("AUR_SCAN_SEVERITY", "hgih")],
    );
    assert!(!ok && !log.iter().any(|l| l.starts_with("RAN ")));
}

/// `AUR_SCAN_MODE=install` must hand `aur-scan install` the same threshold the
/// gate path uses (its own default is `critical`, which would raise the bar),
/// and the gate path must always carry a blocking `--fail-on`.
#[test]
fn install_mode_and_gate_pass_the_configured_threshold() {
    for gate in [Gate::Bash, Gate::Zsh, Gate::Fish, Gate::Wrapper] {
        let bin = match gate {
            Gate::Bash => "bash",
            Gate::Zsh => "zsh",
            Gate::Fish => "fish",
            _ => "sh",
        };
        if which(bin).is_none() {
            continue;
        }
        let sb = Sandbox::new(true);
        let env = [
            ("AUR_SCAN_MODE", "install"),
            ("AUR_SCAN_SEVERITY", "medium"),
        ];
        let (_, log, text) = run_gate(gate, &sb, "paru", &["-S", "foo"], &env);
        assert!(
            log.contains(&"SCAN install --gate medium foo".to_string()),
            "[{gate:?}] {log:?}\n{text}"
        );
        let sb = Sandbox::new(true);
        let env = [("AUR_SCAN_SEVERITY", "medium")];
        let (_, log, _) = run_gate(gate, &sb, "paru", &["-S", "foo"], &env);
        let scan = log.iter().find(|l| l.starts_with("SCAN ")).unwrap();
        assert!(scan.contains("--fail-on medium"), "[{gate:?}] {scan}");
    }
}
