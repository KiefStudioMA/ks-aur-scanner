//! Privilege escalation analyzer

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::informational_lines_with;
use crate::textutil::{logical_lines, normalize_shell_quoting, split_statements, split_words};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashSet;

/// Reduce a shell body to only the lines that are actually executed, so the
/// privilege patterns never match printed text. Backslash-newline continuations
/// are spliced; comment lines and informational lines (a non-redirected heredoc
/// message body, or a pure `echo`/`msg "..."` print) are dropped using the exact
/// same pre-filter the rule engine uses (`informational_lines`).
///
/// Without this, the analyzer matched its regexes over the raw function body and
/// raised a Critical false positive on a benign package that merely *printed* a
/// `sudo systemctl ...` instruction, or shipped a heredoc/`note` mentioning
/// `/etc/sudoers` or `setcap` (defect #5). A printed mention is not an action.
fn executable_body(content: &str, shadowed: &HashSet<String>) -> String {
    executable_lines(content, shadowed)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The executable logical lines of `content` with the line each starts on.
fn executable_lines(content: &str, shadowed: &HashSet<String>) -> Vec<(usize, String)> {
    let lines = logical_lines(content);
    let strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
    let info = informational_lines_with(&strs, shadowed);
    lines
        .into_iter()
        .enumerate()
        .filter(|(i, (_, l))| !l.trim_start().starts_with('#') && !info[*i])
        .map(|(_, l)| l)
        .collect()
}

/// Whether one shell statement sets a setuid/setgid bit ONLY on files named
/// `chrome-sandbox` inside `$pkgdir` -- the standard, expected install step of
/// every Electron/Chromium `-bin` package (the sandbox helper must be setuid
/// root to create user namespaces on kernels that restrict them). Every path
/// operand must be exactly a `chrome-sandbox` file and at least one must live
/// under `$pkgdir`; a statement that also touches any other file is NOT exempt,
/// so `chmod 4755 "$pkgdir/opt/x/chrome-sandbox" "$pkgdir/usr/bin/y"` stays
/// Critical.
fn is_pkgdir_chrome_sandbox_suid(stmt: &str) -> bool {
    let words = split_words(stmt);
    let Some(cmd_idx) = words.iter().position(|w| {
        let w = normalize_shell_quoting(w);
        let base = w.rsplit('/').next().unwrap_or("");
        base == "chmod" || base == "install"
    }) else {
        return false;
    };
    // Everything before the command may only be a harmless launcher.
    if words[..cmd_idx]
        .iter()
        .any(|w| !matches!(w.as_str(), "sudo" | "command" | "exec" | "env"))
    {
        return false;
    }
    let is_mode = |w: &str| {
        let digits = w.len() >= 3 && w.chars().all(|c| c.is_ascii_digit());
        let symbolic = w.chars().any(|c| matches!(c, '+' | '='))
            && w.chars().all(|c| "ugoa+-=rwxXst".contains(c));
        digits || symbolic
    };
    let mut paths = Vec::new();
    for w in &words[cmd_idx + 1..] {
        let n = normalize_shell_quoting(w);
        if n.starts_with('-') || is_mode(&n) {
            continue;
        }
        paths.push(n);
    }
    !paths.is_empty()
        && paths
            .iter()
            .all(|p| p.rsplit('/').next() == Some("chrome-sandbox"))
        && paths.iter().any(|p| p.contains("pkgdir"))
}

/// The module name (`-` folded to `_`) of a `*.ko[.zst|.xz|.gz]` path.
fn module_basename(path: &str) -> Option<String> {
    let base = path.rsplit('/').next()?;
    for ext in [".ko", ".ko.zst", ".ko.xz", ".ko.gz"] {
        if let Some(stem) = base.strip_suffix(ext) {
            if !stem.is_empty() {
                return Some(stem.replace('-', "_").to_ascii_lowercase());
            }
        }
    }
    None
}

/// Names (`-` folded to `_`) of kernel modules this package ships or builds:
/// every `*.ko` it names in the PKGBUILD or its scripts, every module file in
/// the package directory, and the package's own name.
fn shipped_modules(context: &AnalysisContext) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut scan = |text: &str| {
        for tok in text.split(|c: char| !(c.is_ascii_alphanumeric() || "_.-/".contains(c))) {
            if let Some(m) = module_basename(tok) {
                out.insert(m);
            }
        }
    };
    scan(&context.pkgbuild.raw_content);
    for s in context.all_scripts() {
        scan(&s.content);
    }
    for entry in &context.pkgbuild.source {
        scan(&entry.url);
    }
    if let Some(dir) = context.file_path.parent() {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if let Some(m) = module_basename(&e.file_name().to_string_lossy()) {
                    out.insert(m);
                }
            }
        }
    }
    for n in &context.pkgbuild.pkgname {
        out.insert(n.replace('-', "_").to_ascii_lowercase());
    }
    out
}

/// Whether a module path lies in the kernel's own module tree.
fn in_kernel_tree(path: &str) -> bool {
    path.starts_with("/lib/modules/") || path.starts_with("/usr/lib/modules/")
}

/// How a module command ranks: `None` = not a module command, `Some(None)` =
/// ordinary (High), `Some(Some(reason))` = package-shipped module (Critical).
fn classify_module_stmt(stmt: &str, shipped: &HashSet<String>) -> Option<Option<String>> {
    let words: Vec<String> = split_words(stmt)
        .iter()
        .map(|w| normalize_shell_quoting(w))
        .collect();
    let idx = words.iter().position(|w| {
        let base = w.rsplit('/').next().unwrap_or("");
        ["insmod", "modprobe", "rmmod"]
            .iter()
            .any(|c| base.eq_ignore_ascii_case(c))
    })?;
    let cmd = words[idx]
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if cmd == "rmmod" {
        return Some(None);
    }
    let mut positional: Vec<&str> = Vec::new();
    let mut custom_root = false;
    let mut skip_value = false;
    for w in &words[idx + 1..] {
        if skip_value {
            skip_value = false;
            continue;
        }
        if matches!(w.as_str(), "-d" | "--dirname" | "-C" | "--config")
            || w.starts_with("--dirname=")
        {
            custom_root = true;
            skip_value = !w.contains('=');
        } else if matches!(w.as_str(), "-S" | "--set-version") {
            skip_value = true;
        } else if !w.starts_with('-') {
            positional.push(w);
        }
    }
    if custom_root {
        return Some(Some(
            "loads modules from a module root or config the package chooses".to_string(),
        ));
    }
    let Some(first) = positional.first() else {
        return Some(None);
    };
    let is_path = first.contains('/') || module_basename(first).is_some();
    if is_path {
        if !in_kernel_tree(first) {
            return Some(Some(format!(
                "loads a module from '{first}', a location outside the kernel's module tree"
            )));
        }
        if module_basename(first).is_some_and(|m| shipped.contains(&m)) {
            return Some(Some(format!(
                "loads '{first}', a module this package ships"
            )));
        }
        return Some(None);
    }
    if cmd == "modprobe" && shipped.contains(&first.replace('-', "_").to_ascii_lowercase()) {
        return Some(Some(format!(
            "loads module '{first}', which this package ships"
        )));
    }
    Some(None)
}

/// `insmod` / `modprobe` / `rmmod` in install scriptlets and ALPM hooks. A
/// scriptlet runs as root at install time, so a module loaded from there runs in
/// the kernel; one the package ships itself is the rootkit pattern (Critical).
/// `depmod` alone and `dkms` are not module loads and do not match.
fn install_module_findings(context: &AnalysisContext, shadowed: &HashSet<String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let shipped = shipped_modules(context);
    for script in context.all_scripts() {
        if script.file_type != crate::types::FileType::InstallScript {
            continue;
        }
        let mut first_plain: Option<(usize, String)> = None;
        for (line_no, line) in executable_lines(&script.content, shadowed) {
            for (stmt, _) in split_statements(&line) {
                match classify_module_stmt(&stmt, &shipped) {
                    None => {}
                    Some(None) => {
                        first_plain.get_or_insert((line_no, stmt.trim().to_string()));
                    }
                    Some(Some(reason)) => findings.push(Finding {
                        id: "PRIV-009".to_string(),
                        severity: Severity::Critical,
                        category: Category::PrivilegeEscalation,
                        title: "Kernel module loaded from a package-shipped file".to_string(),
                        description: format!(
                            "Install script '{}' {reason}. A module runs with full kernel privilege.",
                            script.path.display()
                        ),
                        location: Location {
                            file: script.path.clone(),
                            line: Some(line_no),
                            column: None,
                            snippet: Some(stmt.trim().to_string()),
                        },
                        recommendation: "Do not install; kernel modules must not be loaded from a package's own files by a scriptlet.".to_string(),
                        cwe_id: Some("CWE-506".to_string()),
                        metadata: serde_json::json!({ "reason": reason }),
                    }),
                }
            }
        }
        if let Some((line_no, stmt)) = first_plain {
            findings.push(Finding {
                id: "PRIV-005".to_string(),
                severity: Severity::High,
                category: Category::PrivilegeEscalation,
                title: "Kernel module operations".to_string(),
                description: format!(
                    "Install script '{}' performs kernel module operations (insmod/modprobe/rmmod)",
                    script.path.display()
                ),
                location: Location {
                    file: script.path.clone(),
                    line: Some(line_no),
                    column: None,
                    snippet: Some(stmt),
                },
                recommendation: "Verify kernel module operations are legitimate".to_string(),
                cwe_id: None,
                metadata: serde_json::json!({ "file": script.path.display().to_string() }),
            });
        }
    }
    findings
}

/// Analyzer for privilege escalation patterns
pub struct PrivilegeAnalyzer {
    module_pattern: Regex,
    sudo_pattern: Regex,
    suid_pattern: Regex,
    sudoers_pattern: Regex,
    capabilities_pattern: Regex,
}

impl PrivilegeAnalyzer {
    /// Create a new privilege analyzer
    pub fn new() -> Self {
        Self {
            // `(?i)` so `SUDO`/`Sudo` cannot evade PRIV-001 (audit HI-6). The
            // analyzer matches only `executable_body()` (printed/informational
            // lines stripped), so a documented mention still cannot false-fire.
            sudo_pattern: Regex::new(r"(?i)\bsudo\b").unwrap(),
            // SUID/SGID is the *special* permission bit. In numeric form it only
            // exists in a 4-digit octal mode whose leading digit has the suid (4)
            // or sgid (2) bit set, i.e. leading digit 2-7 (a leading 0 = no special
            // bit, 1 = sticky only). Plain 3-digit modes (755, 644, 700) CANNOT set
            // suid/sgid and must never match. Symbolic forms that *set* the bit
            // (`u+s`, `g+s`, `+s`, `u=s`) are covered; forms that *clear* it
            // (`u-s`, `g-s`, `-s`) must NOT fire — removing a setuid bit is the
            // safe direction (issue #21, visual-studio-code-bin).
            // `(?ix)` so `CHMOD`/`INSTALL` case variants cannot evade PRIV-002
            // (audit HI-6). The octal mode digits are case-irrelevant; `(?i)` only
            // additionally lets the symbolic suid bit match `S` as well as `s`,
            // which is still a suid set.
            suid_pattern: Regex::new(
                r"(?ix)
                  chmod \s+ (?:-[A-Za-z]+ \s+)* 0?[2-7][0-7]{3} \b   # chmod [flags] 4755 / 02755
                | chmod \s+ [ugoa]* [+=] [rwxXt]* s \b               # chmod u+s / g+s / +s / u=s (SET only)
                | install \s [^\n]* -[A-Za-z]*m [=\s]? 0?[2-7][0-7]{3} \b  # install -m4755 / -Dm4755
                ",
            )
            .unwrap(),
            // `(?i)` for audit HI-6 consistency; printed mentions are already
            // stripped by `executable_body()` so this adds no false positives.
            sudoers_pattern: Regex::new(r"(?i)/etc/sudoers").unwrap(),
            capabilities_pattern: Regex::new(r"(?i)setcap\s+").unwrap(),
            // A kernel-module COMMAND (`modprobe`, `insmod`, `rmmod`, optionally
            // path-prefixed or behind a launcher). A path that merely CONTAINS the
            // word -- installing `$pkgdir/usr/lib/modprobe.d/foo.conf` -- is a
            // config file, not a module operation.
            module_pattern: Regex::new(
                r#"(?i)(?:^|[\s;&|(`'"])(?:\S*/)?(?:insmod|rmmod|modprobe)(?:\s|$|;|&|\||\)|`|'|")"#,
            )
            .unwrap(),
        }
    }
}

impl Default for PrivilegeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for PrivilegeAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let shadowed = context.shadowed_printers().names();

        // Check functions for privilege escalation patterns. Match only the
        // executable lines of the body (printed/informational lines stripped) so
        // a documented `sudo`/`setcap`/`sudoers` mention cannot raise a Critical
        // false positive (defect #5).
        for (func_name, func_body) in &context.pkgbuild.functions {
            let body = executable_body(&func_body.content, &shadowed);
            // Check for sudo in build functions
            if self.sudo_pattern.is_match(&body) {
                let severity = if func_name == "build" || func_name.starts_with("package") {
                    Severity::Critical
                } else {
                    Severity::High
                };

                findings.push(Finding {
                    id: "PRIV-001".to_string(),
                    severity,
                    category: Category::PrivilegeEscalation,
                    title: format!("Sudo usage in {}()", func_name),
                    description: format!(
                        "Function '{}' uses sudo, which should never be needed in PKGBUILDs",
                        func_name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(func_body.line_start),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Remove sudo; makepkg handles permissions correctly"
                        .to_string(),
                    cwe_id: Some("CWE-250".to_string()),
                    metadata: serde_json::json!({
                        "function": func_name,
                    }),
                });
            }

            // Check for SUID bit setting. Judge each statement: the Electron
            // `chmod 4755 "$pkgdir/opt/<app>/chrome-sandbox"` step is an expected,
            // known pattern (Low); anything else stays Critical.
            let (mut suid_real, mut suid_sandbox) = (0usize, 0usize);
            for line in body.lines() {
                for (stmt, _) in split_statements(line) {
                    if self.suid_pattern.is_match(&stmt) {
                        if is_pkgdir_chrome_sandbox_suid(&stmt) {
                            suid_sandbox += 1;
                        } else {
                            suid_real += 1;
                        }
                    }
                }
            }
            // A multi-line match the per-statement walk could not attribute is
            // treated as real (never weaker than the whole-body match).
            if suid_real == 0 && suid_sandbox == 0 && self.suid_pattern.is_match(&body) {
                suid_real = 1;
            }
            if suid_real == 0 && suid_sandbox > 0 {
                findings.push(Finding {
                    id: "PRIV-002".to_string(),
                    severity: Severity::Low,
                    category: Category::PrivilegeEscalation,
                    title: format!("Expected SUID chrome-sandbox in {}()", func_name),
                    description: format!(
                        "Function '{}' sets the setuid bit on a `chrome-sandbox` helper under $pkgdir. This is the standard step for Electron/Chromium-based packages and is expected; verify the package really bundles that runtime.",
                        func_name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(func_body.line_start),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "No action needed for a genuine Electron/Chromium bundle; no other file is made setuid".to_string(),
                    cwe_id: Some("CWE-732".to_string()),
                    metadata: serde_json::json!({
                        "function": func_name,
                        "known_pattern": "chrome-sandbox",
                    }),
                });
            }
            if suid_real > 0 {
                findings.push(Finding {
                    id: "PRIV-002".to_string(),
                    severity: Severity::Critical,
                    category: Category::PrivilegeEscalation,
                    title: format!("SUID bit in {}()", func_name),
                    description: format!(
                        "Function '{}' sets SUID/SGID bits, which can create privilege escalation vulnerabilities",
                        func_name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(func_body.line_start),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Avoid setting SUID bits; use capabilities or polkit instead"
                        .to_string(),
                    cwe_id: Some("CWE-732".to_string()),
                    metadata: serde_json::json!({
                        "function": func_name,
                    }),
                });
            }

            // Check for sudoers modification
            if self.sudoers_pattern.is_match(&body) {
                findings.push(Finding {
                    id: "PRIV-003".to_string(),
                    severity: Severity::Critical,
                    category: Category::PrivilegeEscalation,
                    title: "Sudoers modification".to_string(),
                    description: format!(
                        "Function '{}' modifies sudoers, which is a critical security concern",
                        func_name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(func_body.line_start),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Packages should never modify sudoers".to_string(),
                    cwe_id: Some("CWE-250".to_string()),
                    metadata: serde_json::json!({
                        "function": func_name,
                    }),
                });
            }

            // Check for capabilities setting (could be legitimate but worth noting)
            if self.capabilities_pattern.is_match(&body) {
                findings.push(Finding {
                    id: "PRIV-004".to_string(),
                    severity: Severity::Medium,
                    category: Category::PrivilegeEscalation,
                    title: "Capabilities being set".to_string(),
                    description: format!(
                        "Function '{}' sets file capabilities, which grants elevated privileges",
                        func_name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(func_body.line_start),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Verify capabilities are necessary and minimal".to_string(),
                    cwe_id: Some("CWE-250".to_string()),
                    metadata: serde_json::json!({
                        "function": func_name,
                    }),
                });
            }

            // Check for kernel module loading
            if self.module_pattern.is_match(&body) || body.contains("/lib/modules") {
                findings.push(Finding {
                    id: "PRIV-005".to_string(),
                    severity: Severity::High,
                    category: Category::PrivilegeEscalation,
                    title: "Kernel module operations".to_string(),
                    description: format!(
                        "Function '{}' performs kernel module operations",
                        func_name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(func_body.line_start),
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Verify kernel module operations are legitimate".to_string(),
                    cwe_id: None,
                    metadata: serde_json::json!({
                        "function": func_name,
                    }),
                });
            }
        }

        // Kernel module commands in install scriptlets and ALPM hooks.
        findings.extend(install_module_findings(context, &shadowed));

        // Check install scriptlets and ALPM side scripts for sudo in hook bodies.
        for script in context.all_scripts() {
            for hook in &script.hooks {
                let body = executable_body(&hook.content, &shadowed);
                if self.sudo_pattern.is_match(&body) {
                    findings.push(Finding {
                        id: "PRIV-006".to_string(),
                        severity: Severity::High,
                        category: Category::PrivilegeEscalation,
                        title: format!("Sudo in {}()", hook.name),
                        description: format!(
                            "Install hook '{}' uses sudo (install hooks already run as root)",
                            hook.name
                        ),
                        location: Location {
                            file: script.path.clone(),
                            line: Some(hook.line_start),
                            column: None,
                            snippet: None,
                        },
                        recommendation: "Remove sudo from install hooks; they run as root"
                            .to_string(),
                        cwe_id: Some("CWE-250".to_string()),
                        metadata: serde_json::json!({
                            "hook": hook.name,
                        }),
                    });
                }
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "privilege"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn create_test_context(pkgbuild_content: &str) -> AnalysisContext {
        let parser = StaticParser::new();
        let pkgbuild = parser.parse(pkgbuild_content).unwrap();

        AnalysisContext {
            pkgbuild,
            install_script: None,
            side_scripts: vec![],
            local_binaries: vec![],
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
            registry: None,
        }
    }

    #[tokio::test]
    async fn test_detect_sudo() {
        let analyzer = PrivilegeAnalyzer::new();

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
build() {
    sudo make install
}
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "PRIV-001"));
    }

    #[tokio::test]
    async fn test_detect_suid() {
        let analyzer = PrivilegeAnalyzer::new();

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
package() {
    chmod 4755 "$pkgdir/usr/bin/mybin"
}
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "PRIV-002"));
    }

    #[tokio::test]
    async fn case_variation_does_not_evade_privilege() {
        // Audit HI-6: upper/mixed-case privilege tokens must still fire. sudo
        // (PRIV-001), setcap (PRIV-004), and CHMOD/INSTALL suid modes (PRIV-002).
        let analyzer = PrivilegeAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
package() {
    SUDO make install
    SETCAP cap_setuid+ep "$pkgdir/usr/bin/x"
    CHMOD 4755 "$pkgdir/usr/bin/y"
}
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "PRIV-001"),
            "SUDO must fire PRIV-001"
        );
        assert!(
            findings.iter().any(|f| f.id == "PRIV-004"),
            "SETCAP must fire PRIV-004"
        );
        assert!(
            findings.iter().any(|f| f.id == "PRIV-002"),
            "CHMOD 4755 must fire PRIV-002"
        );
    }

    #[tokio::test]
    async fn test_benign_chmod_is_not_suid() {
        // Regression: plain 3-digit modes (755/644/700) set NO special bit and
        // must never raise PRIV-002. This is exactly what normal icon-theme and
        // file-installing PKGBUILDs do.
        let analyzer = PrivilegeAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
package() {
    find "$pkgdir/usr" -type f -exec chmod 644 {} \;
    find "$pkgdir/usr" -type d -exec chmod 755 {} \;
    chmod 700 "$pkgdir/etc/secret"
    install -Dm755 binary "$pkgdir/usr/bin/binary"
    install -Dm644 data "$pkgdir/usr/share/data"
}
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            !findings.iter().any(|f| f.id == "PRIV-002"),
            "benign chmod 644/755/700 and install -m644/755 must not trip PRIV-002, got: {:?}",
            findings
                .iter()
                .filter(|f| f.id == "PRIV-002")
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_printed_privilege_message_is_not_flagged() {
        // Defect #5: a package that merely PRINTS a sudo/setcap/sudoers
        // instruction (or documents one in a non-redirected heredoc) must NOT
        // raise a Critical privilege finding. A mention is not an action.
        let analyzer = PrivilegeAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
package() {
    echo "To enable the service, run: sudo systemctl enable test.service"
    msg "Grant the capability with: setcap cap_net_raw+ep /usr/bin/test"
    cat <<EOF
After install, add a rule to /etc/sudoers.d/test if you want passwordless use.
EOF
}
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.id.as_str(), "PRIV-001" | "PRIV-003" | "PRIV-004")),
            "printed sudo/sudoers/setcap messages must not raise a privilege finding, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_real_sudo_still_detected_alongside_printed_message() {
        // The filter must not blind us: a printed note PLUS a real `sudo` action
        // still fires PRIV-001 (the action is on its own executable line).
        let analyzer = PrivilegeAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
build() {
    echo "this build uses sudo for nothing, ignore"
    sudo make install
}
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "PRIV-001"),
            "a real sudo action must still be detected: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_symbolic_and_install_suid_detected() {
        let analyzer = PrivilegeAnalyzer::new();
        for body in [
            "chmod u+s \"$pkgdir/usr/bin/mybin\"",
            "chmod g+s \"$pkgdir/usr/bin/mybin\"",
            "chmod 2755 \"$pkgdir/usr/bin/mybin\"",
            "install -Dm4755 mybin \"$pkgdir/usr/bin/mybin\"",
        ] {
            let src = format!("pkgname=test\npkgver=1.0\npkgrel=1\npackage() {{\n    {body}\n}}\n");
            let context = create_test_context(&src);
            let findings = analyzer.analyze(&context).await.unwrap();
            assert!(
                findings.iter().any(|f| f.id == "PRIV-002"),
                "expected PRIV-002 for: {body}"
            );
        }
    }

    #[tokio::test]
    async fn clearing_suid_bit_does_not_trip_priv002() {
        // Issue #21: visual-studio-code-bin and similar packages *remove* the
        // SUID bit for sandbox safety. That is the opposite of escalation.
        let analyzer = PrivilegeAnalyzer::new();
        for body in [
            "chmod u-s \"$pkgdir/usr/bin/code\"",
            "chmod g-s \"$pkgdir/opt/app/chrome-sandbox\"",
            "chmod -s \"$pkgdir/usr/lib/chromium/chrome-sandbox\"",
        ] {
            let src = format!("pkgname=test\npkgver=1.0\npkgrel=1\npackage() {{\n    {body}\n}}\n");
            let context = create_test_context(&src);
            let findings = analyzer.analyze(&context).await.unwrap();
            assert!(
                !findings.iter().any(|f| f.id == "PRIV-002"),
                "clearing SUID must not trip PRIV-002 for: {body}; got {:?}",
                findings.iter().map(|f| &f.id).collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn test_redirected_heredoc_privilege_still_fires() {
        // Boundary lock (task 4050b): the informational carve-out must NOT
        // suppress a heredoc that is REDIRECTED to a file. Writing a setcap/SUID
        // script INTO a file is an action, not a printed message, so the body
        // must still be scanned and fire.
        let analyzer = PrivilegeAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
package() {
    cat <<EOF > "$pkgdir/usr/bin/setup-helper.sh"
setcap cap_net_raw+ep /usr/bin/victim
chmod 4755 /usr/bin/victim
EOF
}
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        let ids: Vec<&String> = findings.iter().map(|f| &f.id).collect();
        assert!(
            findings.iter().any(|f| f.id == "PRIV-002"),
            "SUID inside a REDIRECTED heredoc must still fire PRIV-002: {ids:?}"
        );
        assert!(
            findings.iter().any(|f| f.id == "PRIV-004"),
            "setcap inside a REDIRECTED heredoc must still fire PRIV-004: {ids:?}"
        );
    }

    #[tokio::test]
    async fn test_privilege_action_after_heredoc_still_fires() {
        // Boundary lock (task 4050b): a non-redirected heredoc message is
        // suppressed, but a real privilege action AFTER the terminator must NOT
        // be swallowed by the carve-out — the informational state resets at EOF.
        let analyzer = PrivilegeAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
package() {
    cat <<EOF
Reminder: you may want to run sudo systemctl enable test.service
EOF
    install -Dm4755 evil "$pkgdir/usr/bin/evil"
}
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        let ids: Vec<&String> = findings.iter().map(|f| &f.id).collect();
        // The printed reminder must NOT fire...
        assert!(
            !findings.iter().any(|f| f.id == "PRIV-001"),
            "the printed sudo reminder must not fire PRIV-001: {ids:?}"
        );
        // ...but the real SUID install AFTER the heredoc must.
        assert!(
            findings.iter().any(|f| f.id == "PRIV-002"),
            "a real SUID install after a heredoc must still fire PRIV-002: {ids:?}"
        );
    }
}
