//! Privilege escalation analyzer

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::informational_lines;
use crate::textutil::logical_lines;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use regex::Regex;

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
fn executable_body(content: &str) -> String {
    let lines = logical_lines(content);
    let strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
    let info = informational_lines(&strs);
    lines
        .iter()
        .enumerate()
        .filter(|(i, (_, l))| !l.trim_start().starts_with('#') && !info[*i])
        .map(|(_, (_, l))| l.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Analyzer for privilege escalation patterns
pub struct PrivilegeAnalyzer {
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
            // suid/sgid and must never match. Symbolic forms (u+s, g+s, +s) and
            // `install -m<mode>` with a special bit are also covered.
            // `(?ix)` so `CHMOD`/`INSTALL` case variants cannot evade PRIV-002
            // (audit HI-6). The octal mode digits are case-irrelevant; `(?i)` only
            // additionally lets the symbolic suid bit match `S` as well as `s`,
            // which is still a suid set.
            suid_pattern: Regex::new(
                r"(?ix)
                  chmod \s+ (?:-[A-Za-z]+ \s+)* 0?[2-7][0-7]{3} \b   # chmod [flags] 4755 / 02755
                | chmod \s+ [ugoa]* [-+=] [rwxXt]* s \b              # chmod u+s / g+s / +s
                | install \s [^\n]* -[A-Za-z]*m [=\s]? 0?[2-7][0-7]{3} \b  # install -m4755 / -Dm4755
                ",
            )
            .unwrap(),
            // `(?i)` for audit HI-6 consistency; printed mentions are already
            // stripped by `executable_body()` so this adds no false positives.
            sudoers_pattern: Regex::new(r"(?i)/etc/sudoers").unwrap(),
            capabilities_pattern: Regex::new(r"(?i)setcap\s+").unwrap(),
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

        // Check functions for privilege escalation patterns. Match only the
        // executable lines of the body (printed/informational lines stripped) so
        // a documented `sudo`/`setcap`/`sudoers` mention cannot raise a Critical
        // false positive (defect #5).
        for (func_name, func_body) in &context.pkgbuild.functions {
            let body = executable_body(&func_body.content);
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

            // Check for SUID bit setting
            if self.suid_pattern.is_match(&body) {
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
            if body.contains("insmod") || body.contains("modprobe") || body.contains("/lib/modules")
            {
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

        // Check install script if present
        if let Some(ref install_script) = context.install_script {
            for hook in &install_script.hooks {
                let body = executable_body(&hook.content);
                // Check for sudo in install hooks
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
                            file: install_script.path.clone(),
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
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
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
