//! Source URL analyzer

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::parser::Protocol;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Regex for matching IP addresses in URLs
    static ref IP_REGEX: Regex = Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
}

/// Analyzer for source URLs
pub struct SourceAnalyzer;

impl SourceAnalyzer {
    /// Create a new source analyzer
    pub fn new() -> Self {
        Self
    }
}

impl Default for SourceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for SourceAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (idx, source) in context.pkgbuild.source.iter().enumerate() {
            // Insecure transport: cleartext protocols (http/ftp) OR unauthenticated
            // git transports (git://, git+http://), which are tamperable in transit.
            let lurl = source.url.to_lowercase();
            let insecure_git = lurl.contains("git://") || lurl.contains("git+http://");
            if !source.protocol.is_secure() || insecure_git {
                let severity = match source.protocol {
                    Protocol::Http | Protocol::Ftp => Severity::Medium,
                    _ if insecure_git => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(Finding {
                    id: "SRC-001".to_string(),
                    severity,
                    category: Category::NetworkSecurity,
                    title: "Insecure source/transport protocol".to_string(),
                    description: format!(
                        "Source #{} uses an insecure transport: {}",
                        idx + 1,
                        source.url
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: None,
                        column: None,
                        snippet: Some(format!("source=(\"{}\")", source.url)),
                    },
                    recommendation: "Use HTTPS instead of HTTP for source downloads".to_string(),
                    cwe_id: Some("CWE-319".to_string()),
                    metadata: serde_json::json!({
                        "url": source.url,
                        "protocol": format!("{:?}", source.protocol),
                        "source_index": idx,
                    }),
                });
            }

            // Check for suspicious domains
            let suspicious_patterns = [
                ("pastebin.com", "Code hosting on pastebin is suspicious"),
                ("paste.ee", "Code hosting on paste site is suspicious"),
                ("hastebin.com", "Code hosting on paste site is suspicious"),
                ("0x0.st", "Anonymous file hosting is suspicious"),
                ("transfer.sh", "Temporary file hosting is suspicious"),
                (".tk", "Free TLD domains are often used for malware"),
                (".ml", "Free TLD domains are often used for malware"),
                (".ga", "Free TLD domains are often used for malware"),
                (".cf", "Free TLD domains are often used for malware"),
            ];

            for (pattern, message) in &suspicious_patterns {
                if source.url.to_lowercase().contains(pattern) {
                    findings.push(Finding {
                        id: "SRC-002".to_string(),
                        severity: Severity::High,
                        category: Category::NetworkSecurity,
                        title: "Suspicious source domain".to_string(),
                        description: format!("{}: {}", message, source.url),
                        location: Location {
                            file: context.file_path.clone(),
                            line: None,
                            column: None,
                            snippet: Some(format!("source=(\"{}\")", source.url)),
                        },
                        recommendation: "Use official project repositories for sources".to_string(),
                        cwe_id: None,
                        metadata: serde_json::json!({
                            "url": source.url,
                            "pattern": pattern,
                        }),
                    });
                }
            }

            // Check for raw IP addresses in URLs
            if IP_REGEX.is_match(&source.url) {
                findings.push(Finding {
                    id: "SRC-003".to_string(),
                    severity: Severity::High,
                    category: Category::NetworkSecurity,
                    title: "Raw IP address in source URL".to_string(),
                    description: format!("Source uses raw IP address: {}", source.url),
                    location: Location {
                        file: context.file_path.clone(),
                        line: None,
                        column: None,
                        snippet: Some(format!("source=(\"{}\")", source.url)),
                    },
                    recommendation: "Use domain names from trusted sources".to_string(),
                    cwe_id: None,
                    metadata: serde_json::json!({
                        "url": source.url,
                    }),
                });
            }

            // Check for URL shorteners
            let shorteners = [
                "bit.ly",
                "t.co",
                "goo.gl",
                "tinyurl.com",
                "is.gd",
                "cli.gs",
                "ow.ly",
            ];

            for shortener in &shorteners {
                if source.url.to_lowercase().contains(shortener) {
                    findings.push(Finding {
                        id: "SRC-004".to_string(),
                        severity: Severity::High,
                        category: Category::NetworkSecurity,
                        title: "URL shortener in source".to_string(),
                        description: format!(
                            "Source uses URL shortener which hides the real destination: {}",
                            source.url
                        ),
                        location: Location {
                            file: context.file_path.clone(),
                            line: None,
                            column: None,
                            snippet: Some(format!("source=(\"{}\")", source.url)),
                        },
                        recommendation: "Use full URLs to official sources".to_string(),
                        cwe_id: None,
                        metadata: serde_json::json!({
                            "url": source.url,
                            "shortener": shortener,
                        }),
                    });
                }
            }

            // A VCS source on a movable ref (branch/tag, or no fragment) is not
            // integrity-pinned: the fetched bytes can change after review, and a
            // SKIP checksum on it (which makepkg accepts for VCS) provides no
            // guarantee. Require a pinned `#commit=`/`#revision=`.
            if source.is_vcs() && !source.is_vcs_pinned_commit() {
                findings.push(Finding {
                    // Low, not Medium: tracking a branch HEAD is the normal,
                    // accepted pattern for rolling -git packages, so this is a
                    // reproducibility/hardening nudge ("pin with #commit="), not
                    // a security concern on its own. Rating it higher would fire
                    // on nearly every -git package and cause alert fatigue.
                    id: "SRC-007".to_string(),
                    severity: Severity::Low,
                    category: Category::NetworkSecurity,
                    title: "VCS source not pinned to a commit".to_string(),
                    description: format!(
                        "Source #{} is a VCS checkout on a movable ref (branch/tag or none): {}. \
                         Its content is not integrity-pinned and can change between scan and build.",
                        idx + 1,
                        source.url
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: None,
                        column: None,
                        snippet: Some(format!("source=(\"{}\")", source.url)),
                    },
                    recommendation:
                        "Pin the VCS source to an immutable revision with #commit=<sha>."
                            .to_string(),
                    cwe_id: Some("CWE-494".to_string()),
                    metadata: serde_json::json!({
                        "url": source.url,
                        "fragment": source.fragment,
                    }),
                });
            }

            // Check for git/VCS sources hosted on non-standard providers.
            // (Code-based allow-list: the regex rule engine cannot express a
            // negative host match, so this lives here.)
            let lurl = source.url.to_lowercase();
            if source.is_vcs() && !lurl.is_empty() {
                let trusted_vcs_hosts = [
                    "github.com",
                    "gitlab.com",
                    "codeberg.org",
                    "bitbucket.org",
                    "sr.ht",
                    "git.sr.ht",
                    "git.kernel.org",
                    "gitlab.freedesktop.org",
                    "gitlab.gnome.org",
                    "invent.kde.org",
                    "salsa.debian.org",
                    "git.savannah.gnu.org",
                ];
                if !trusted_vcs_hosts.iter().any(|h| lurl.contains(h)) {
                    findings.push(Finding {
                        id: "SRC-006".to_string(),
                        severity: Severity::Low,
                        category: Category::NetworkSecurity,
                        title: "VCS source from non-standard host".to_string(),
                        description: format!(
                            "Source #{} is a VCS checkout from a non-standard host: {}",
                            idx + 1,
                            source.url
                        ),
                        location: Location {
                            file: context.file_path.clone(),
                            line: None,
                            column: None,
                            snippet: Some(format!("source=(\"{}\")", source.url)),
                        },
                        recommendation:
                            "Verify the upstream host is the project's official repository."
                                .to_string(),
                        cwe_id: None,
                        metadata: serde_json::json!({
                            "url": source.url,
                            "protocol": format!("{:?}", source.protocol),
                        }),
                    });
                }
            }
        }

        // Check if source array is empty (for non-meta packages)
        if context.pkgbuild.source.is_empty() && !context.pkgbuild.pkgname.is_empty() {
            // This might be a meta package, which is fine
            // But if it has a build function, that's suspicious
            if context.pkgbuild.functions.contains_key("build") {
                findings.push(Finding {
                    id: "SRC-005".to_string(),
                    severity: Severity::Medium,
                    category: Category::Configuration,
                    title: "No sources with build function".to_string(),
                    description: "Package has build() function but no source array".to_string(),
                    location: Location {
                        file: context.file_path.clone(),
                        line: None,
                        column: None,
                        snippet: None,
                    },
                    recommendation: "Verify this is intentional; build() usually needs sources"
                        .to_string(),
                    cwe_id: None,
                    metadata: serde_json::json!({}),
                });
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "source"
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
    async fn test_detect_http_source() {
        let analyzer = SourceAnalyzer::new();

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("http://example.com/file.tar.gz")
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "SRC-001"));
    }

    #[tokio::test]
    async fn test_movable_git_ref_flagged_but_pinned_ok() {
        let analyzer = SourceAnalyzer::new();
        // Movable branch ref -> SRC-007.
        let movable = create_test_context(
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(\"git+https://github.com/u/r.git#branch=main\")\n",
        );
        let f = analyzer.analyze(&movable).await.unwrap();
        assert!(f.iter().any(|x| x.id == "SRC-007"), "movable ref should trip SRC-007");

        // Pinned commit -> no SRC-007.
        let pinned = create_test_context(
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(\"git+https://github.com/u/r.git#commit=deadbeefcafebabe\")\n",
        );
        let f = analyzer.analyze(&pinned).await.unwrap();
        assert!(!f.iter().any(|x| x.id == "SRC-007"), "pinned commit must not trip SRC-007");
    }

    #[tokio::test]
    async fn test_detect_suspicious_domain() {
        let analyzer = SourceAnalyzer::new();

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://pastebin.com/raw/abc123")
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "SRC-002"));
    }
}
