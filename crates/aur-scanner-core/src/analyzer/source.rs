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

/// Known URL-shortener hosts. Compared with label-boundary equality against the
/// URL's authority host (not a substring of the full URL string).
const URL_SHORTENERS: &[&str] = &[
    "bit.ly",
    "t.co",
    "goo.gl",
    "tinyurl.com",
    "is.gd",
    "cli.gs",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "tiny.cc",
];

/// If `url`'s host is a known shortener (exact host or subdomain of one), return
/// that shortener's registrable name. Uses the shared [`crate::neturl`] host
/// primitive so label-boundary matching stays consistent with SRC-006/IOC.
fn url_shortener_host(url: &str) -> Option<&'static str> {
    // Strip a leading `name::` source rename (`pkg::https://...`) before host
    // extraction — neturl does not know about makepkg rename syntax.
    let bare = url.find("::").map(|i| &url[i + 2..]).unwrap_or(url).trim();
    let host = crate::neturl::extract_host(bare)?;
    URL_SHORTENERS
        .iter()
        .copied()
        .find(|s| crate::neturl::host_matches(&host, s))
}

/// Map a host to its forge "identity" (so `github.com` and
/// `raw.githubusercontent.com` are the same forge, but `gitlab.com` is a
/// different one). Returns `None` for hosts that are not a recognized code
/// forge, so a normal project download host never triggers SRC-008.
fn forge_key(host: &str) -> Option<&'static str> {
    const FORGES: &[(&str, &str)] = &[
        ("github.com", "github"),
        ("githubusercontent.com", "github"),
        ("github.io", "github"),
        ("gitlab.com", "gitlab"),
        ("gitlab.io", "gitlab"),
        ("codeberg.org", "codeberg"),
        ("bitbucket.org", "bitbucket"),
        ("sr.ht", "sourcehut"),
        ("gitea.com", "gitea"),
        ("sourceforge.net", "sourceforge"),
    ];
    FORGES
        .iter()
        .find(|(suffix, _)| host == *suffix || host.ends_with(&format!(".{suffix}")))
        .map(|(_, key)| *key)
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

            // URL shorteners hide the real destination. Match on the *host*
            // with label boundaries — never a raw substring of the full URL.
            // Substring matching falsely hits `t.co` inside
            // `raw.githubusercontent.com` (issue #22).
            if let Some(shortener) = url_shortener_host(&source.url) {
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
                // Match on the PARSED host at label boundaries, not a raw
                // substring: `git+https://github.com.evil.tld/x` merely *contains*
                // `github.com` but its host is `github.com.evil.tld` (untrusted),
                // and `https://github.com@evil.tld/x` resolves to `evil.tld`. An
                // unparseable host fails closed (treated as untrusted -> flagged).
                let trusted = crate::neturl::extract_host(&source.url)
                    .as_deref()
                    .map(|host| {
                        trusted_vcs_hosts
                            .iter()
                            .any(|t| crate::neturl::host_matches(host, t))
                    })
                    .unwrap_or(false);
                if !trusted {
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

        // SRC-010 — same forge, SAME REPOSITORY NAME, DIFFERENT OWNER.
        //
        // This is the shape reported in issue #29: url= names
        // `github.com/vlaci/openconnect-sso` while source= fetches
        // `github.com/PrestonHager/openconnect-sso`. SRC-008 cannot see it --
        // it compares forge HOSTS (both github) and skips VCS sources entirely,
        // and this one is a `git+` source.
        //
        // Requiring the repo NAME to match while the owner differs is what makes
        // this tight. A genuine mirror or vendor fork is normally named for what
        // it is; an impersonation has to keep the name to be convincing. A
        // package that merely builds from a different project entirely does not
        // match, and neither does the common `url=` homepage /
        // `source=` release-host split, because that has no owner/repo on the
        // url side.
        if let Some(url) = &context.pkgbuild.url {
            if let Some(url_origin) = crate::neturl::origin_of(url) {
                let url_parts: Vec<&str> = url_origin.split('/').collect();
                if url_parts.len() == 3 {
                    let (url_host, url_owner, url_repo) =
                        (url_parts[0], url_parts[1], url_parts[2]);
                    // Only on a MULTI-TENANT forge, where `host/owner/repo` is
                    // genuinely the layout and "a different owner" is a
                    // meaningful statement about who published something.
                    //
                    // Self-hosted git does not work that way. On
                    // `git.savannah.gnu.org` the first path segment is the
                    // service (`cgit/bash` is the web UI, `git/bash` is the
                    // clone path) -- same project, and reading those as two
                    // owners flags GNU bash as impersonating itself.
                    let on_multi_tenant_forge = forge_key(url_host).is_some();
                    for source in &context.pkgbuild.source {
                        if !on_multi_tenant_forge {
                            break;
                        }
                        let Some(src_origin) = crate::neturl::origin_of(&source.url) else {
                            continue;
                        };
                        let sp: Vec<&str> = src_origin.split('/').collect();
                        if sp.len() != 3 {
                            continue;
                        }
                        let (src_host, src_owner, src_repo) = (sp[0], sp[1], sp[2]);
                        if src_host == url_host && src_repo == url_repo && src_owner != url_owner {
                            findings.push(Finding {
                                id: "SRC-010".to_string(),
                                severity: Severity::High,
                                category: Category::NetworkSecurity,
                                title: "Source is a different owner's copy of the upstream repo"
                                    .to_string(),
                                description: format!(
                                    "The declared upstream is '{url_owner}/{url_repo}' on \
                                     {url_host}, but a source fetches '{src_owner}/{url_repo}' \
                                     from the same forge. Same repository name under a different \
                                     account is how a fork is substituted for the real project: \
                                     the PKGBUILD still points reviewers at the genuine upstream \
                                     while building someone else's code."
                                ),
                                location: Location {
                                    file: context.file_path.clone(),
                                    line: None,
                                    column: None,
                                    snippet: Some(format!("url={url}  source={}", source.url)),
                                },
                                recommendation: format!(
                                    "Confirm '{src_owner}' is an official mirror of \
                                     '{url_owner}/{url_repo}'. If it is not, this package builds \
                                     code the upstream project did not publish."
                                ),
                                cwe_id: Some("CWE-494".to_string()),
                                metadata: serde_json::json!({
                                    "declared_upstream": url_origin,
                                    "actual_source": src_origin,
                                    "repo": url_repo,
                                    "declared_owner": url_owner,
                                    "actual_owner": src_owner,
                                }),
                            });
                        }
                    }
                }
            }
        }

        // SRC-008 — the declared upstream url= and a (non-VCS) source= are on two
        // DIFFERENT known forges (a personal-fork-vs-upstream signal). Host-aware
        // via neturl (registrable/forge identity, not substring). Conservative:
        // only when BOTH hosts resolve to a recognized forge and they disagree, so
        // a normal `url=project.org` + `source=github.com/releases` does not fire.
        if let Some(url) = &context.pkgbuild.url {
            if let Some(url_forge) = crate::neturl::extract_host(url)
                .as_deref()
                .and_then(forge_key)
            {
                for source in &context.pkgbuild.source {
                    if source.is_vcs() {
                        continue;
                    }
                    let src_forge = crate::neturl::extract_host(&source.url)
                        .as_deref()
                        .and_then(forge_key);
                    if let Some(sf) = src_forge {
                        if sf != url_forge {
                            findings.push(Finding {
                                id: "SRC-008".to_string(),
                                severity: Severity::Low,
                                category: Category::NetworkSecurity,
                                title: "Source host differs from upstream url host".to_string(),
                                description: format!(
                                    "url= is on the {url_forge} forge but a source is on {sf}. \
                                     A source hosted on a different forge than the stated \
                                     upstream can be a personal fork swapped in for the real \
                                     project."
                                ),
                                location: Location {
                                    file: context.file_path.clone(),
                                    line: None,
                                    column: None,
                                    snippet: Some(format!("url={url}  source={}", source.url)),
                                },
                                recommendation:
                                    "Verify the source forge is the project's official one."
                                        .to_string(),
                                cwe_id: None,
                                metadata: serde_json::json!({
                                    "url_forge": url_forge,
                                    "source_forge": sf,
                                    "source": source.url,
                                }),
                            });
                            break;
                        }
                    }
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
    async fn src010_does_not_fire_on_self_hosted_git_service_paths() {
        // git.savannah.gnu.org serves the web UI at /cgit/<repo> and the clone
        // path at /git/<repo>. Those are not two owners, they are two service
        // prefixes for the same project -- reading them as owners flagged GNU
        // bash as impersonating itself. "A different owner" is only a
        // meaningful statement on a multi-tenant forge.
        let ctx = create_test_context(
            r#"
pkgname=bash
pkgver=5.2
pkgrel=1
url="https://git.savannah.gnu.org/cgit/bash.git"
source=("git+https://git.savannah.gnu.org/git/bash.git#commit=abc1234")
sha256sums=('SKIP')
"#,
        );
        let findings = SourceAnalyzer::new().analyze(&ctx).await.unwrap();
        assert!(
            !findings.iter().any(|f| f.id == "SRC-010"),
            "self-hosted service paths are not distinct owners: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn src010_fires_on_a_forge_fork_substituted_for_upstream() {
        // Issue #29: url= points reviewers at the real project while source=
        // builds a different account's copy of the same repository.
        let ctx = create_test_context(
            r#"
pkgname=openconnect-sso
pkgver=0.8.1
pkgrel=1
url="https://github.com/vlaci/openconnect-sso"
source=("git+https://github.com/PrestonHager/openconnect-sso.git")
sha256sums=('SKIP')
"#,
        );
        let findings = SourceAnalyzer::new().analyze(&ctx).await.unwrap();
        let f = findings
            .iter()
            .find(|f| f.id == "SRC-010")
            .expect("fork substitution must be flagged");
        assert_eq!(f.severity, Severity::High);
        // origin_of normalises case for comparison (forge accounts are
        // case-insensitive), so match case-insensitively.
        assert!(
            f.description.to_lowercase().contains("prestonhager"),
            "{}",
            f.description
        );
        assert_eq!(f.metadata["actual_owner"], "prestonhager");
    }

    #[tokio::test]
    async fn src010_is_quiet_when_owner_matches() {
        let ctx = create_test_context(
            r#"
pkgname=tool
pkgver=1.0
pkgrel=1
url="https://github.com/alice/tool"
source=("https://github.com/alice/tool/archive/v1.0.tar.gz")
sha256sums=('SKIP')
"#,
        );
        let findings = SourceAnalyzer::new().analyze(&ctx).await.unwrap();
        assert!(!findings.iter().any(|f| f.id == "SRC-010"));
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
    async fn raw_githubusercontent_is_not_a_url_shortener() {
        // Issue #22: substring match for `t.co` hit inside
        // `raw.githubusercontent.com`. Host-boundary matching must not.
        let analyzer = SourceAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=xremap
pkgver=1.0
pkgrel=1
source=("LICENSE::https://raw.githubusercontent.com/xremap/xremap/v1.0/LICENSE")
sha256sums=('SKIP')
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            !findings.iter().any(|f| f.id == "SRC-004"),
            "raw.githubusercontent.com must not trip SRC-004, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn real_shortener_still_trips_src004() {
        let analyzer = SourceAnalyzer::new();
        let context = create_test_context(
            r#"
pkgname=evil
pkgver=1.0
pkgrel=1
source=("https://bit.ly/totally-legit")
sha256sums=('SKIP')
"#,
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "SRC-004"),
            "bit.ly must still trip SRC-004"
        );
    }

    #[test]
    fn shortener_host_match_is_label_boundary() {
        assert_eq!(url_shortener_host("https://t.co/abc"), Some("t.co"));
        assert_eq!(url_shortener_host("https://bit.ly/x"), Some("bit.ly"));
        assert_eq!(
            url_shortener_host("LICENSE::https://raw.githubusercontent.com/x/y"),
            None,
            "t.co must not match inside githubusercontent.com"
        );
        assert_eq!(url_shortener_host("git+https://github.com/u/r.git"), None);
    }

    #[tokio::test]
    async fn test_movable_git_ref_flagged_but_pinned_ok() {
        let analyzer = SourceAnalyzer::new();
        // Movable branch ref -> SRC-007.
        let movable = create_test_context(
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(\"git+https://github.com/u/r.git#branch=main\")\n",
        );
        let f = analyzer.analyze(&movable).await.unwrap();
        assert!(
            f.iter().any(|x| x.id == "SRC-007"),
            "movable ref should trip SRC-007"
        );

        // Pinned commit -> no SRC-007.
        let pinned = create_test_context(
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(\"git+https://github.com/u/r.git#commit=deadbeefcafebabe\")\n",
        );
        let f = analyzer.analyze(&pinned).await.unwrap();
        assert!(
            !f.iter().any(|x| x.id == "SRC-007"),
            "pinned commit must not trip SRC-007"
        );
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

    #[tokio::test]
    async fn test_src006_trusts_host_not_substring() {
        // Task 4120: SRC-006 must match the trusted host on label boundaries,
        // not as a raw substring. A trusted host (or its subdomain) is OK; a
        // host that merely CONTAINS a trusted host as a substring is NOT.
        async fn fires(src: &str) -> bool {
            let analyzer = SourceAnalyzer::new();
            let ctx = create_test_context(&format!(
                "pkgname=t\npkgver=1\npkgrel=1\nsource=(\"{src}\")\n"
            ));
            analyzer
                .analyze(&ctx)
                .await
                .unwrap()
                .iter()
                .any(|f| f.id == "SRC-006")
        }

        // TRUSTED: exact host and a subdomain of a trusted host -> no SRC-006.
        assert!(!fires("git+https://github.com/u/r.git#commit=deadbeefcafebabe").await);
        assert!(!fires("git+https://git.sr.ht/~u/r").await);

        // UNTRUSTED via the substring-bypass class -> SRC-006 MUST fire:
        // left-extended host, userinfo confusion, the backslash parser-differential
        // (F1), and a genuinely untrusted host.
        assert!(fires("git+https://github.com.evil.tld/u/r.git").await);
        assert!(fires("git+https://github.com@evil.tld/u/r.git").await);
        assert!(fires(r"git+https://github.com\@evil.tld/u/r.git").await);
        assert!(fires("git+https://evil.example/u/r.git").await);
    }
}
