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

        // Check for SKIP checksums
        // VCS sources (git, svn, hg, bzr) legitimately use SKIP since their content changes
        let source_count = context.pkgbuild.source.len();
        let vcs_count = self.count_vcs_sources(&context.pkgbuild.source);
        let non_vcs_count = source_count - vcs_count;
        let (skip_count, vcs_skip_count) =
            self.count_skip_checksums_detailed(checksums, &context.pkgbuild.source);
        let non_vcs_skip_count = skip_count - vcs_skip_count;

        if non_vcs_skip_count > 0 && non_vcs_skip_count < non_vcs_count {
            // Some non-VCS sources have SKIP - this is concerning
            findings.push(Finding {
                id: "CHK-004".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "Some sources have SKIP checksum".to_string(),
                description: format!(
                    "{} of {} non-VCS sources use SKIP instead of real checksums",
                    non_vcs_skip_count, non_vcs_count
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Provide real checksums for all non-VCS sources".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "skip_count": non_vcs_skip_count,
                    "total_non_vcs_sources": non_vcs_count,
                    "vcs_sources": vcs_count,
                }),
            });
        } else if non_vcs_skip_count == non_vcs_count && non_vcs_count > 0 {
            // All non-VCS sources use SKIP - highly suspicious
            findings.push(Finding {
                id: "CHK-005".to_string(),
                severity: Severity::High,
                category: Category::Cryptography,
                title: "All non-VCS sources use SKIP checksum".to_string(),
                description: format!(
                    "No integrity verification is performed on {} non-VCS source(s)",
                    non_vcs_count
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Provide real checksums for non-VCS sources".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "non_vcs_source_count": non_vcs_count,
                    "vcs_source_count": vcs_count,
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
    /// Count VCS sources (git, svn, hg, bzr) which legitimately use SKIP
    fn count_vcs_sources(&self, sources: &[crate::parser::SourceEntry]) -> usize {
        use crate::parser::Protocol;
        sources
            .iter()
            .filter(|s| {
                matches!(
                    s.protocol,
                    Protocol::Git | Protocol::Svn | Protocol::Hg | Protocol::Bzr
                )
            })
            .count()
    }

    /// Count SKIP entries in checksums, returning (total_skips, vcs_skips)
    fn count_skip_checksums_detailed(
        &self,
        checksums: &crate::parser::Checksums,
        sources: &[crate::parser::SourceEntry],
    ) -> (usize, usize) {
        use crate::parser::Protocol;

        // Get the first non-empty checksum array
        let sums = [
            &checksums.sha256sums,
            &checksums.sha512sums,
            &checksums.b2sums,
            &checksums.sha1sums,
            &checksums.md5sums,
        ]
        .into_iter()
        .find(|s| !s.is_empty());

        let Some(sums) = sums else {
            return (0, 0);
        };

        let mut total_skips = 0;
        let mut vcs_skips = 0;

        for (i, sum) in sums.iter().enumerate() {
            if sum.is_none() {
                total_skips += 1;
                // Check if corresponding source is VCS
                if let Some(source) = sources.get(i) {
                    if matches!(
                        source.protocol,
                        Protocol::Git | Protocol::Svn | Protocol::Hg | Protocol::Bzr
                    ) {
                        vcs_skips += 1;
                    }
                }
            }
        }

        (total_skips, vcs_skips)
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

    #[tokio::test]
    async fn test_vcs_source_skip_allowed() {
        let analyzer = ChecksumAnalyzer::new();

        // Git source with SKIP is legitimate - should not trigger CHK-004 or CHK-005
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("git+https://github.com/user/repo.git")
sha256sums=('SKIP')
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        // Should NOT have CHK-004 or CHK-005 for VCS sources
        assert!(
            !findings.iter().any(|f| f.id == "CHK-004" || f.id == "CHK-005"),
            "VCS source with SKIP should not trigger checksum warnings"
        );
    }

    #[tokio::test]
    async fn test_mixed_vcs_and_regular_source() {
        let analyzer = ChecksumAnalyzer::new();

        // Git source with SKIP + regular source with checksum - should be fine
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("git+https://github.com/user/repo.git"
        "https://example.com/file.tar.gz")
sha256sums=('SKIP'
            'abc123def456')
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        // Should NOT have CHK-004 or CHK-005
        assert!(
            !findings.iter().any(|f| f.id == "CHK-004" || f.id == "CHK-005"),
            "Mixed VCS+regular sources with appropriate checksums should not trigger warnings"
        );
    }

    #[tokio::test]
    async fn test_non_vcs_skip_still_detected() {
        let analyzer = ChecksumAnalyzer::new();

        // Regular HTTP source with SKIP - should trigger CHK-005
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/file.tar.gz")
sha256sums=('SKIP')
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "CHK-005"),
            "Non-VCS source with SKIP should trigger CHK-005"
        );
    }
}
