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

        // Check for SKIP/unverified checksums.
        //
        // A source is "verified" iff at least one PRESENT checksum array gives
        // it a real (non-SKIP) hash. Evaluating across ALL arrays (not just the
        // first non-empty one) defeats laundering: an attacker cannot hide a
        // SKIP in the strong array behind a populated weak array. VCS sources
        // legitimately use SKIP (their content is a moving checkout); a movable
        // (unpinned) VCS ref is the source analyzer's concern -- it is reported
        // at the appropriate severity by SRC-007. Flagging every HEAD-tracking
        // -git package as a High "no integrity" finding here would be noise, so
        // the checksum analyzer only evaluates NON-VCS sources.
        let source_count = context.pkgbuild.source.len();
        let non_vcs_count = context
            .pkgbuild
            .source
            .iter()
            .filter(|s| !s.is_vcs())
            .count();
        let vcs_count = source_count - non_vcs_count;
        // Name the offending sources, not just count them. A bare "3 of 7
        // sources use SKIP" tells a maintainer that something is wrong but not
        // *what*, so it cannot be acted on or triaged -- and a reader who
        // cannot see which entry is unverified cannot tell a detached signature
        // (legitimately unhashable) from a tarball (not) (issue #31).
        let unverified = self.unverified_non_vcs(checksums, &context.pkgbuild.source);
        let non_vcs_skip_count = unverified.len();
        let names: Vec<String> = unverified.iter().map(|(_, name)| name.clone()).collect();

        if non_vcs_skip_count > 0 && non_vcs_skip_count < non_vcs_count {
            // Some non-VCS sources have SKIP - this is concerning
            findings.push(Finding {
                id: "CHK-004".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "Some sources have SKIP checksum".to_string(),
                description: format!(
                    "{} of {} non-VCS sources use SKIP instead of real checksums: {}",
                    non_vcs_skip_count,
                    non_vcs_count,
                    names.join(", ")
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: Some(format!("source: {}", names.join(", "))),
                },
                recommendation: "Provide real checksums for all non-VCS sources".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "skip_count": non_vcs_skip_count,
                    "total_non_vcs_sources": non_vcs_count,
                    "vcs_sources": vcs_count,
                    // Machine-readable, so a caller can filter on exactly which
                    // entries are unverified rather than re-parsing the prose.
                    "unverified_sources": names,
                    "unverified_indices": unverified.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
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
                    "No integrity verification is performed on {} non-VCS source(s): {}",
                    non_vcs_count,
                    names.join(", ")
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: Some(format!("source: {}", names.join(", "))),
                },
                recommendation: "Provide real checksums for non-VCS sources".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({
                    "non_vcs_source_count": non_vcs_count,
                    "vcs_source_count": vcs_count,
                    "unverified_sources": names,
                    "unverified_indices": unverified.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
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

        // CHK-008 — a present checksum that is not valid hex of the algorithm's
        // expected length (md5=32, sha1=40, sha256=64, sha512/b2=128). A
        // wrong-length or non-hex hash can never match the fetched bytes, so
        // makepkg's integrity check is silently defeated (whether by tamper or a
        // copy-paste error). `SKIP` is stored as `None` and is handled by
        // CHK-004/005, so it is not considered malformed here.
        let algos: [(&str, usize, &[Option<String>]); 5] = [
            ("md5", 32, checksums.md5sums.as_slice()),
            ("sha1", 40, checksums.sha1sums.as_slice()),
            ("sha256", 64, checksums.sha256sums.as_slice()),
            ("sha512", 128, checksums.sha512sums.as_slice()),
            ("b2", 128, checksums.b2sums.as_slice()),
        ];
        let mut malformed: Vec<String> = Vec::new();
        for (algo, len, arr) in algos {
            for sum in arr.iter().flatten() {
                let s = sum.trim();
                if s.eq_ignore_ascii_case("SKIP") {
                    continue;
                }
                if s.len() != len || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let shown = if s.len() > 12 { &s[..12] } else { s };
                    malformed.push(format!(
                        "{algo}sums has a bad entry '{shown}…' (len {})",
                        s.len()
                    ));
                }
            }
        }
        if !malformed.is_empty() {
            findings.push(Finding {
                id: "CHK-008".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "Malformed or wrong-length checksum".to_string(),
                description: format!(
                    "One or more checksums are not valid hex of the expected length, so they \
                     cannot match the source and integrity verification is effectively disabled: {}.",
                    malformed.join("; ")
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Regenerate the checksums with updpkgsums; a malformed hash \
                                 silently disables integrity verification."
                    .to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({ "malformed": malformed }),
            });
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "checksum"
    }
}

impl ChecksumAnalyzer {
    /// All checksum arrays that are actually present (non-empty), in priority
    /// order. A source is only verified if one of THESE gives it a real hash.
    fn present_arrays(checksums: &crate::parser::Checksums) -> Vec<&[Option<String>]> {
        [
            checksums.sha256sums.as_slice(),
            checksums.sha512sums.as_slice(),
            checksums.b2sums.as_slice(),
            checksums.sha1sums.as_slice(),
            checksums.md5sums.as_slice(),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect()
    }

    /// The non-VCS sources that have NO real (non-SKIP) hash in ANY present
    /// checksum array, as `(source index, display name)`.
    ///
    /// Checking every array -- not just the first non-empty one -- is what
    /// prevents SKIP-laundering: a strong-array SKIP hidden behind a populated
    /// weak array is still counted as unverified.
    ///
    /// The index is reported alongside the name because `source=()` entries are
    /// positional: "entry 3" is what a maintainer edits, and two entries can
    /// share a display name.
    fn unverified_non_vcs(
        &self,
        checksums: &crate::parser::Checksums,
        sources: &[crate::parser::SourceEntry],
    ) -> Vec<(usize, String)> {
        let present = Self::present_arrays(checksums);
        sources
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                !s.is_vcs()
                    && !present
                        .iter()
                        .any(|arr| matches!(arr.get(*i), Some(Some(_))))
            })
            .map(|(i, s)| (i, Self::display_name(s)))
            .collect()
    }

    /// How a source entry should be named in a finding: the `::` rename when
    /// there is one (that is the local filename makepkg uses), otherwise the
    /// URL as written.
    fn display_name(entry: &crate::parser::SourceEntry) -> String {
        entry.filename.clone().unwrap_or_else(|| entry.url.clone())
    }

    /// Get the number of checksums defined: the maximum length across all
    /// present arrays (so a short decoy array cannot mask a count mismatch).
    fn get_checksum_count(&self, checksums: &crate::parser::Checksums) -> usize {
        Self::present_arrays(checksums)
            .iter()
            .map(|a| a.len())
            .max()
            .unwrap_or(0)
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
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
            registry: None,
        }
    }

    #[tokio::test]
    async fn chk004_names_the_unverified_sources() {
        // Issue #31: a bare count is unactionable. The reporter's actual case
        // was wanting to tell a detached signature (which cannot carry a
        // meaningful hash) from a tarball (which must), and the finding gave
        // them nothing to filter on.
        let analyzer = ChecksumAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/app-1.0.tar.gz"
        "https://example.com/app-1.0.tar.gz.sig"
        "local-fix.patch")
sha256sums=('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'
            'SKIP'
            'SKIP')
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        let f = findings
            .iter()
            .find(|f| f.id == "CHK-004")
            .expect("two of three sources are unverified");

        // Named in the prose...
        assert!(
            f.description.contains("app-1.0.tar.gz.sig"),
            "description must name the signature file: {}",
            f.description
        );
        assert!(
            f.description.contains("local-fix.patch"),
            "description must name the patch: {}",
            f.description
        );
        // ...and available structurally, so a caller can filter on `\.sig$`
        // without scraping English.
        let names: Vec<&str> = f.metadata["unverified_sources"]
            .as_array()
            .expect("unverified_sources must be an array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["https://example.com/app-1.0.tar.gz.sig", "local-fix.patch"]
        );
        // Positional indices, because that is what a maintainer edits.
        let idx: Vec<u64> = f.metadata["unverified_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(idx, vec![1, 2]);
        // The verified tarball must NOT be listed.
        assert!(!names.iter().any(|n| n.ends_with("app-1.0.tar.gz")));
    }

    #[tokio::test]
    async fn chk004_uses_the_rename_when_a_source_declares_one() {
        // `name::url` sources are fetched as `name`, which is what the
        // maintainer sees on disk and in the checksum array position.
        let analyzer = ChecksumAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("app.tar.gz::https://example.com/download?id=42"
        "https://example.com/other.tar.gz")
sha256sums=('SKIP'
            'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234')
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        let f = findings.iter().find(|f| f.id == "CHK-004").unwrap();
        assert!(
            f.description.contains("app.tar.gz"),
            "the local filename is the useful name: {}",
            f.description
        );
    }

    #[tokio::test]
    async fn chk005_also_names_the_sources() {
        let analyzer = ChecksumAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/a.tar.gz" "https://example.com/b.tar.gz")
sha256sums=('SKIP' 'SKIP')
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        let f = findings.iter().find(|f| f.id == "CHK-005").unwrap();
        assert!(f.description.contains("a.tar.gz"));
        assert!(f.description.contains("b.tar.gz"));
        assert_eq!(
            f.metadata["unverified_sources"].as_array().unwrap().len(),
            2
        );
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
            !findings
                .iter()
                .any(|f| f.id == "CHK-004" || f.id == "CHK-005"),
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
            !findings
                .iter()
                .any(|f| f.id == "CHK-004" || f.id == "CHK-005"),
            "Mixed VCS+regular sources with appropriate checksums should not trigger warnings"
        );
    }

    #[tokio::test]
    async fn test_skip_laundering_across_arrays_detected() {
        // HI-7: coverage is evaluated per-source across ALL present arrays. Here
        // source #2 is SKIP in BOTH arrays (unverified) while source #1 is
        // covered by sha256. The old "first non-empty array only" logic looked
        // solely at sha256sums -- which has a real hash for #1 and SKIP for #2 --
        // and could misreport; the per-source/all-array check correctly flags
        // that one source is unverified (CHK-004, partial coverage).
        let analyzer = ChecksumAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/a.tar.gz"
        "https://example.com/b.tar.gz")
sha256sums=('realhash0000000000000000000000000000000000000000000000000000000'
            'SKIP')
sha512sums=('SKIP'
            'SKIP')
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "CHK-004"),
            "the source that is SKIP across every present array must be flagged: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_pinned_git_skip_is_ok_but_movable_is_flagged() {
        // HI-7: a git source pinned to a commit may SKIP; a movable branch ref
        // must be flagged (SRC-007 lives in the source analyzer; here we just
        // confirm the pinned case is not a checksum finding).
        let analyzer = ChecksumAnalyzer::new();
        let pinned = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("git+https://github.com/u/r.git#commit=abcdef1234567890")
sha256sums=('SKIP')
"#,
        );
        let findings = analyzer.analyze(&pinned).await.unwrap();
        assert!(!findings
            .iter()
            .any(|f| f.id == "CHK-004" || f.id == "CHK-005"));
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
