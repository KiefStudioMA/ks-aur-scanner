//! Privilege escalation analyzer

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use regex::Regex;

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
            sudo_pattern: Regex::new(r"\bsudo\b").unwrap(),
            suid_pattern: Regex::new(r"chmod\s+[0-7]*[4-7][0-7]{2,3}\s").unwrap(),
            sudoers_pattern: Regex::new(r"/etc/sudoers").unwrap(),
            capabilities_pattern: Regex::new(r"setcap\s+").unwrap(),
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

        // Check functions for privilege escalation patterns
        for (func_name, func_body) in &context.pkgbuild.functions {
            // Check for sudo in build functions
            if self.sudo_pattern.is_match(&func_body.content) {
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
            if self.suid_pattern.is_match(&func_body.content) {
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
            if self.sudoers_pattern.is_match(&func_body.content) {
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
            if self.capabilities_pattern.is_match(&func_body.content) {
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
            if func_body.content.contains("insmod")
                || func_body.content.contains("modprobe")
                || func_body.content.contains("/lib/modules")
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
                // Check for sudo in install hooks
                if self.sudo_pattern.is_match(&hook.content) {
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
    use crate::parser::{StaticParser, PkgbuildParser};
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
}
