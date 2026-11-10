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
        // Elements the scanner cannot read as a hash (SKIP, `SKIP${_x}`,
        // `$(cmd)`) are "not verified", never a hash.
        let normalized = Self::normalize(&context.pkgbuild);
        let checksums = &normalized;
        let raw_checksums = &context.pkgbuild.checksums;
        let limit = Self::align_limit(&context.pkgbuild);

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
        if !raw_checksums.md5sums.is_empty() {
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

        if !raw_checksums.sha1sums.is_empty() {
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
        // Only the sources before the first uncountable element can be paired
        // with their checksum by position.
        let aligned_len = limit
            .as_ref()
            .map_or(source_count, |(i, _)| (*i).min(source_count));
        let aligned = &context.pkgbuild.source[..aligned_len];
        let non_vcs_count = aligned.iter().filter(|s| !s.is_vcs()).count();
        let vcs_count = context
            .pkgbuild
            .source
            .iter()
            .filter(|s| s.is_vcs())
            .count();
        // When NOTHING anywhere is a real hash, and a SKIP is actually
        // written down, every downloaded source is unverified whatever the
        // counts say or what stands in front of the SKIP (a miscounted or
        // unreadable element must not hide it). Judged over the WHOLE arrays,
        // past any uncountable element too.
        let judged = |a: &[Option<String>]| -> usize {
            limit.as_ref().map_or(a.len(), |(i, _)| (*i).min(a.len()))
        };
        let present: Vec<&[Option<String>]> = Self::present_arrays(checksums);
        // (a malformed value is CHK-008's business; it is still not SKIP)
        let real_hash = present.iter().any(|a| a.iter().any(|e| e.is_some()));
        // a literal SKIP (or empty) element, as opposed to an unreadable one
        let literal_skip = [
            &raw_checksums.md5sums,
            &raw_checksums.sha1sums,
            &raw_checksums.sha256sums,
            &raw_checksums.sha512sums,
            &raw_checksums.b2sums,
        ]
        .iter()
        .any(|a| a.iter().any(|e| e.is_none()));
        let no_real_hash = !present.is_empty()
            && !real_hash
            && (limit.is_none() || literal_skip)
            && context.pkgbuild.source.iter().any(|s| !s.is_vcs());
        // Name the offending sources, not just count them (issue #31).
        let (unverified, non_vcs_count) = if no_real_hash {
            let all: Vec<(usize, String)> = context
                .pkgbuild
                .source
                .iter()
                .enumerate()
                .filter(|(_, s)| !s.is_vcs())
                .map(|(i, s)| (i, Self::display_name(s)))
                .collect();
            let n = all.len();
            (all, n)
        } else {
            (self.unverified_non_vcs(checksums, aligned), non_vcs_count)
        };
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

        // A SKIP that sits AFTER an uncountable element cannot be matched to
        // a source, but it is still a visible SKIP: say so (Medium) instead of
        // letting a good-looking hash at index 0 launder it.
        if limit.is_some()
            && !findings
                .iter()
                .any(|f| f.id == "CHK-004" || f.id == "CHK-005")
        {
            let keyed: [(&str, &Vec<Option<String>>); 5] = [
                ("md5sums", &checksums.md5sums),
                ("sha1sums", &checksums.sha1sums),
                ("sha256sums", &checksums.sha256sums),
                ("sha512sums", &checksums.sha512sums),
                ("b2sums", &checksums.b2sums),
            ];
            let mut hidden = 0usize;
            for (key, arr) in keyed {
                let own = context.pkgbuild.uncertain_from.get(key).copied();
                let from = judged(arr);
                hidden += arr
                    .iter()
                    .enumerate()
                    .skip(from)
                    .filter(|(i, e)| e.is_none() && Some(*i) != own)
                    .count();
            }
            if hidden > 0 {
                findings.push(Finding {
                    id: "CHK-004".to_string(),
                    severity: Severity::Medium,
                    category: Category::Cryptography,
                    title: "Some sources have SKIP checksum".to_string(),
                    description: format!(
                        "{hidden} checksum entr{} after an uncountable element are SKIP or unreadable, so the source{} they belong to cannot be named; at least one downloaded file is unverified.",
                        if hidden == 1 { "y" } else { "ies" },
                        if hidden == 1 { "" } else { "s" }
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Provide real checksums for non-VCS sources, as a plain literal list.".to_string(),
                    cwe_id: Some("CWE-354".to_string()),
                    metadata: serde_json::json!({ "skip_after_uncountable": hidden }),
                });
            }
        }

        // Check checksum count matches source count
        let checksum_count = self.get_checksum_count(checksums);
        if limit.is_none() && checksum_count > 0 && checksum_count != source_count {
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

        // CHK-009 -- an element of source=() or a checksum array whose count
        // cannot be known statically (an unquoted command substitution or
        // variable, a whole-array expansion, a brace list past the expansion
        // limits). Positions before it are still checked; from it on the
        // checksum a source gets is unknown, which is reported instead of
        // being silently skipped.
        if let Some((idx, array)) = &limit {
            findings.push(Finding {
                id: "CHK-009".to_string(),
                severity: Severity::Medium,
                category: Category::Cryptography,
                title: "Checksum alignment cannot be determined".to_string(),
                description: format!(
                    "{array}=() has an element at position {} that cannot be counted statically (command substitution, variable or array expansion, or an oversized brace list), so sources from there on cannot be matched to their checksums.",
                    idx + 1
                ),
                location: Location {
                    file: context.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Write source= and the checksum arrays as plain literal lists, or review which source is left unverified by hand.".to_string(),
                cwe_id: Some("CWE-354".to_string()),
                metadata: serde_json::json!({ "array": array, "first_uncountable_index": idx }),
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
                if s.eq_ignore_ascii_case("SKIP") || s.contains('$') || s.contains('`') {
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

/// Replace `$name` / `${name}` with the PKGBUILD's own plain assignments.
/// `None` when something unresolvable (`$(...)`, a backtick, an unknown or
/// array variable) is left.
fn resolve_plain_vars(s: &str, vars: &std::collections::HashMap<String, String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(['$', '`']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let after = tail.strip_prefix('$')?;
        let (name, consumed) = if let Some(braced) = after.strip_prefix('{') {
            let end = braced.find('}')?;
            (&braced[..end], 2 + end + 1)
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            (&after[..end], 1 + end)
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        let v = vars.get(name)?;
        if v.contains(['$', '`']) {
            return None;
        }
        out.push_str(v);
        rest = &tail[consumed..];
    }
    out.push_str(rest);
    Some(out)
}

impl ChecksumAnalyzer {
    /// The checksum arrays with every element reduced to "a hash" or "not
    /// verified": SKIP, empty, and anything that still holds an unresolved
    /// expansion (`SKIP${_x}`, `$(cmd)`) become `None`. An element the
    /// scanner cannot read is not evidence of a hash.
    fn normalize(pkg: &crate::parser::ParsedPkgbuild) -> crate::parser::Checksums {
        let norm = |arr: &[Option<String>]| -> Vec<Option<String>> {
            arr.iter()
                .map(|e| {
                    let s = e.as_deref()?;
                    if !s.contains(['$', '`']) {
                        return Some(s.to_string());
                    }
                    let r = resolve_plain_vars(s, &pkg.variables)?;
                    (!r.is_empty() && !r.eq_ignore_ascii_case("SKIP")).then_some(r)
                })
                .collect()
        };
        let c = &pkg.checksums;
        crate::parser::Checksums {
            md5sums: norm(&c.md5sums),
            sha1sums: norm(&c.sha1sums),
            sha256sums: norm(&c.sha256sums),
            sha512sums: norm(&c.sha512sums),
            b2sums: norm(&c.b2sums),
        }
    }

    /// Index from which `source` and the checksum arrays can no longer be
    /// lined up by position, if any array holds an uncountable element.
    fn align_limit(pkg: &crate::parser::ParsedPkgbuild) -> Option<(usize, String)> {
        [
            "source",
            "md5sums",
            "sha1sums",
            "sha256sums",
            "sha512sums",
            "b2sums",
        ]
        .iter()
        .filter_map(|k| pkg.uncertain_from.get(*k).map(|i| (*i, (*k).to_string())))
        .min()
    }

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
            shadow: Default::default(),
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
        // Coverage is evaluated per-source across ALL present arrays. Here
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
        // A git source pinned to a commit may SKIP; a movable branch ref
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

    #[tokio::test]
    async fn arch_specific_skip_on_a_downloaded_source_is_reported() {
        let analyzer = ChecksumAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
arch=('x86_64')
source_x86_64=('https://evil.example/helper-x86_64.tar.gz')
sha256sums_x86_64=('SKIP')
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "CHK-005"), "{findings:?}");
    }

    #[tokio::test]
    async fn arch_specific_real_checksum_is_clean() {
        let analyzer = ChecksumAnalyzer::new();
        let h = "a".repeat(64);
        let context = create_test_context(&format!(
            "pkgname=test\npkgver=1.0\npkgrel=1\narch=('x86_64' 'aarch64')\n\
             source_x86_64=('https://e.example/x.tar.gz')\nsha256sums_x86_64=('{h}')\n\
             source_aarch64=('https://e.example/a.tar.gz')\nsha256sums_aarch64=('{h}')\n"
        ));
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.is_empty(), "{findings:?}");
    }

    async fn ids_of(pkg: &str) -> Vec<String> {
        let findings = ChecksumAnalyzer::new()
            .analyze(&create_test_context(pkg))
            .await
            .unwrap();
        let mut v: Vec<String> = findings.into_iter().map(|f| f.id).collect();
        v.sort();
        v
    }

    const H: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[tokio::test]
    async fn quoted_literal_braces_do_not_silence_skip() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let control = ids_of(&format!("{pre}source=('https://evil.example/p.tar.gz' 'https://ok.example/ab.txt')\nsha256sums=('SKIP' '{H}')\n")).await;
        assert_eq!(control, ["CHK-004"]);
        // single-quoted braces and array syntax are literal: same answer
        for lit in ["a{b,c}.txt", "a[@].txt", "a{,.txt", "x,}"] {
            let ids = ids_of(&format!("{pre}source=('https://evil.example/p.tar.gz' 'https://ok.example/{lit}')\nsha256sums=('SKIP' '{H}')\n")).await;
            assert_eq!(ids, ["CHK-004"], "{lit}");
        }
    }

    #[tokio::test]
    async fn skip_hidden_behind_an_expansion_is_still_unverified() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        // bash: SKIP${_x} with _x unset is SKIP
        let ids = ids_of(&format!(
            "{pre}source=('https://evil.example/p.tar.gz')\nsha256sums=(\"SKIP${{_x}}\")\n"
        ))
        .await;
        assert_eq!(ids, ["CHK-005"]);
        // brace sequence assembling SKIP
        let ids = ids_of(&format!(
            "{pre}source=('https://evil.example/p.tar.gz')\nsha256sums=(S{{K..K}}IP)\n"
        ))
        .await;
        assert_eq!(ids, ["CHK-005"]);
        let ids = ids_of(&format!(
            "{pre}source=('https://evil.example/p.tar.gz')\nsha256sums=(S{{K,K}}IP)\n"
        ))
        .await;
        assert!(ids.contains(&"CHK-005".to_string()), "{ids:?}");
    }

    #[tokio::test]
    async fn quoted_command_substitution_is_one_countable_element() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!("{pre}source=('https://evil.example/p.tar.gz' \"$(echo https://ok.example/b.txt)\")\nsha256sums=('SKIP' '{H}')\n")).await;
        assert_eq!(ids, ["CHK-004"]);
    }

    #[tokio::test]
    async fn unquoted_substitution_reports_alignment_and_checks_before_it() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!("{pre}source=('https://evil.example/p.tar.gz' $(echo https://ok.example/b.txt))\nsha256sums=('SKIP' '{H}')\n")).await;
        assert!(ids.contains(&"CHK-009".to_string()), "{ids:?}");
        assert!(
            ids.contains(&"CHK-005".to_string()),
            "index 0 is still checked: {ids:?}"
        );
        assert!(!ids.contains(&"CHK-006".to_string()), "{ids:?}");
        // an array expansion: weak algorithm still reported, alignment flagged
        let ids = ids_of(&format!(
            "{pre}source=(\"${{files[@]}}\")\nmd5sums=('abc')\n"
        ))
        .await;
        assert!(
            ids.contains(&"CHK-002".to_string()) && ids.contains(&"CHK-009".to_string()),
            "{ids:?}"
        );
    }

    #[tokio::test]
    async fn oversized_brace_list_is_reported_not_ignored() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!("{pre}source=('https://evil.example/p.tar.gz' https://ok.example/x{{1..300}}.txt)\nsha256sums=('SKIP' '{H}')\n")).await;
        assert!(ids.contains(&"CHK-009".to_string()), "{ids:?}");
    }

    #[tokio::test]
    async fn checksum_from_a_plain_variable_is_a_hash() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!(
            "{pre}_h={H}\nsource=('https://ok.example/p.tar.gz')\nsha256sums=(\"$_h\")\n"
        ))
        .await;
        assert!(ids.is_empty(), "{ids:?}");
    }

    #[tokio::test]
    async fn generated_checksum_array_is_flagged_as_unknown_not_as_all_skip() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!(
            "{pre}source=('https://ok.example/a.tar.gz' 'https://ok.example/b.tar.gz')\nsha256sums=($(gen-sums))\n"
        ))
        .await;
        assert_eq!(ids, ["CHK-009"]);
    }

    #[tokio::test]
    async fn leading_uncountable_element_does_not_hide_skip() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let src = "source=('https://evil.example/x.tar.gz')\n";
        let ids = ids_of(&format!("{pre}{src}sha256sums=($(true) 'SKIP')\n")).await;
        assert!(ids.contains(&"CHK-005".to_string()), "{ids:?}");
        assert!(ids.contains(&"CHK-009".to_string()), "{ids:?}");
        // an empty variable is zero words: nothing uncountable at all
        let ids = ids_of(&format!("{pre}_e=\n{src}sha256sums=($_e 'SKIP')\n")).await;
        assert_eq!(ids, ["CHK-005"]);
        let ids = ids_of(&format!("{pre}_e=\"\"\n{src}sha256sums=(${{_e}} 'SKIP')\n")).await;
        assert_eq!(ids, ["CHK-005"]);
        // an uncountable SOURCE in front of the downloaded one
        let ids = ids_of(&format!(
            "{pre}source=($(true) 'https://evil.example/x.tar.gz')\nsha256sums=('SKIP')\n"
        ))
        .await;
        assert!(ids.contains(&"CHK-005".to_string()), "{ids:?}");
    }

    #[tokio::test]
    async fn fake_hash_up_front_cannot_launder_a_skip_behind_an_expansion() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!(
            "{pre}source=('https://evil.example/a.tar.gz' 'https://evil.example/x.tar.gz')\nsha256sums=('{H}' $(true) 'SKIP')\n"
        ))
        .await;
        assert!(ids.contains(&"CHK-004".to_string()), "{ids:?}");
        assert!(ids.contains(&"CHK-009".to_string()), "{ids:?}");
    }

    #[tokio::test]
    async fn plain_variable_holding_a_hash_is_not_all_skip() {
        let pre = "pkgname=t\npkgver=1\npkgrel=1\n";
        let ids = ids_of(&format!(
            "{pre}_h={H}\nsource=('https://ok.example/a.tar.gz')\nsha256sums=($_h)\n"
        ))
        .await;
        assert!(ids.is_empty(), "{ids:?}");
    }
}
