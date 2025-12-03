//! Checksum analyzer

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;

/// Analyzer for checksum validation
pub struct ChecksumAnalyzer;

impl ChecksumAnalyzer {
    /// Create a new checksum analyzer
    pub fn new() -> Self {
        Self
    }
}

impl Default for ChecksumAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for ChecksumAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let checksums = &context.pkgbuild.checksums;

        // Check if sources exist but no checksums
        if !context.pkgbuild.source.is_empty() && !checksums.has_any() {
            findings.push(Finding {
                id: "CHK-001".to_string(),
                severity: Severity::High,
                category: Category::Cryptography,
                title: "No checksums for sources".to_string(),
                description: "Package has sources but no checksums to verify integrity".to_string(),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Add sha256sums or sha512sums for all sources".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "source_count": context.pkgbuild.source.len(),
                }),
            });
        }

        // Check for weak checksums
        if !checksums.md5sums.is_empty() {
            findings.push(Finding {
                id: "CHK-002".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "MD5 checksums used".to_string(),
                description: "MD5 is cryptographically broken and should not be used".to_string(),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: Some("md5sums=(...)".to_string()),
                },
                recommendation: "Replace md5sums with sha256sums or sha512sums".to_string(),
                cwe_id: Some("CWE-328".to_string()),
                metadata: serde_json::json!({
                    "algorithm": "MD5",
                }),
            });
        }

        if !checksums.sha1sums.is_empty() {
            findings.push(Finding {
                id: "CHK-003".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "SHA1 checksums used".to_string(),
                description: "SHA1 is cryptographically weak and should be avoided".to_string(),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: Some("sha1sums=(...)".to_string()),
                },
                recommendation: "Replace sha1sums with sha256sums or sha512sums".to_string(),
                cwe_id: Some("CWE-328".to_string()),
                metadata: serde_json::json!({
                    "algorithm": "SHA1",
                }),
            });
        }

        // Check for SKIP checksums (all sources should have real checksums)
        let skip_count = self.count_skip_checksums(checksums);
        let source_count = context.pkgbuild.source.len();

        if skip_count > 0 && skip_count < source_count {
            // Some sources have SKIP - this is concerning
            findings.push(Finding {
                id: "CHK-004".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "Some sources have SKIP checksum".to_string(),
                description: format!(
                    "{} of {} sources use SKIP instead of real checksums",
                    skip_count, source_count
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Provide real checksums for all sources where possible".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "skip_count": skip_count,
                    "total_sources": source_count,
                }),
            });
        } else if skip_count == source_count && source_count > 0 {
            // All sources use SKIP - highly suspicious
            findings.push(Finding {
                id: "CHK-005".to_string(),
                severity: Severity::High,
                category: Category::Cryptography,
                title: "All sources use SKIP checksum".to_string(),
                description: "No integrity verification is performed on any source".to_string(),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Provide real checksums for sources".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "source_count": source_count,
                }),
            });
        }

        // Check checksum count matches source count
        let checksum_count = self.get_checksum_count(checksums);
        if checksum_count > 0 && checksum_count != source_count {
            findings.push(Finding {
                id: "CHK-006".to_string(),
                severity: Severity::High,
                category: Category::Configuration,
                title: "Checksum count mismatch".to_string(),
                description: format!(
                    "Number of checksums ({}) doesn't match number of sources ({})",
                    checksum_count, source_count
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Ensure each source has a corresponding checksum".to_string(),
                cwe_id: None,
                metadata: serde_json::json!({
                    "checksum_count": checksum_count,
                    "source_count": source_count,
                }),
            });
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "checksum"
    }
}

impl ChecksumAnalyzer {
    /// Count SKIP entries in checksums
    fn count_skip_checksums(&self, checksums: &crate::parser::Checksums) -> usize {
        let mut count = 0;

        // Check all checksum arrays for None entries (SKIP)
        for sums in [
            &checksums.sha256sums,
            &checksums.sha512sums,
            &checksums.b2sums,
            &checksums.sha1sums,
            &checksums.md5sums,
        ] {
            if !sums.is_empty() {
                count = sums.iter().filter(|s| s.is_none()).count();
                break; // Only count from one array
            }
        }

        count
    }

    /// Get the number of checksums defined
    fn get_checksum_count(&self, checksums: &crate::parser::Checksums) -> usize {
        // Return the count from the first non-empty checksum array
        for sums in [
            &checksums.sha256sums,
            &checksums.sha512sums,
            &checksums.b2sums,
            &checksums.sha1sums,
            &checksums.md5sums,
        ] {
            if !sums.is_empty() {
                return sums.len();
            }
        }
        0
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
    async fn test_detect_missing_checksums() {
        let analyzer = ChecksumAnalyzer::new();

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/file.tar.gz")
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "CHK-001"));
    }

    #[tokio::test]
    async fn test_detect_md5() {
        let analyzer = ChecksumAnalyzer::new();

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/file.tar.gz")
md5sums=('abc123')
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "CHK-002"));
    }
}
