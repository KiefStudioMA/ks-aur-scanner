//! Opt-in threat-intelligence analyzer.
//!
//! This is the ONLY analyzer that touches the network, and the scanner adds it
//! to the pipeline ONLY when the operator opted in (`enable_threat_intel`) AND a
//! provider key is configured (see `Scanner::new`). A default build never
//! constructs it, so a default scan stays fully offline and static.
//!
//! It transmits only data already public in the PKGBUILD — declared
//! `sha256sums` (to VirusTotal) and `source=` URLs (to URLhaus) — and is
//! strictly advisory: every lookup fails open, verdicts are cached in the
//! MAC-authenticated [`DiskCache`](crate::cache) to respect VirusTotal's
//! 4-request/minute public quota, and the number of lookups per scan is capped.

use super::SecurityAnalyzer;
use crate::cache::{Cache, DiskCache};
use crate::error::Result;
use crate::parser::Protocol;
use crate::threat_intel::{ThreatIntelProvider, ThreatScore, UrlHausProvider, VirusTotalProvider};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Upper bound on third-party lookups considered in a single package scan. A
/// guardrail against a hostile PKGBUILD declaring hundreds of sources to burn
/// the operator's API quota or stall the scan. (VirusTotal's public API is only
/// 4 req/min; cached hits are cheap but still counted so the bound is simple.)
const MAX_LOOKUPS_PER_SCAN: usize = 20;

/// Networked, opt-in analyzer. Holds whichever providers have keys plus the
/// verdict cache.
pub struct ThreatIntelAnalyzer {
    vt: Option<VirusTotalProvider>,
    urlhaus: Option<UrlHausProvider>,
    /// Verdict cache. `None` disables caching (the `Cache` trait is not
    /// dyn-compatible, so we hold the concrete type behind an `Option`).
    cache: Option<Arc<DiskCache>>,
    ttl: Duration,
}

impl ThreatIntelAnalyzer {
    /// Build from already-resolved keys (config or env) and an optional cache.
    /// A `None` key disables that provider. Returns `None` when NEITHER provider
    /// is usable, so the caller never adds an inert analyzer to the pipeline.
    pub fn new(
        vt_key: Option<String>,
        urlhaus_key: Option<String>,
        cache: Option<Arc<DiskCache>>,
        ttl: Duration,
    ) -> Option<Self> {
        let vt = vt_key.map(VirusTotalProvider::new);
        let urlhaus = urlhaus_key.map(UrlHausProvider::new);
        if vt.is_none() && urlhaus.is_none() {
            return None;
        }
        Some(Self {
            vt,
            urlhaus,
            cache,
            ttl,
        })
    }

    /// Read `key` from the cache; on a miss, run `fetch`, store the result, and
    /// return it. Fail-open: a provider error yields `None` (no finding) and is
    /// not cached. A cached "no_data"/clean verdict legitimately suppresses a
    /// repeat network call within the TTL.
    async fn cached<F, Fut>(&self, key: &str, fetch: F) -> Option<ThreatScore>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<ThreatScore>>,
    {
        if let Some(cache) = &self.cache {
            if let Ok(Some(hit)) = cache.get::<ThreatScore>(key) {
                debug!("threat-intel cache hit: {key}");
                return Some(hit);
            }
        }
        match fetch().await {
            Ok(score) => {
                if let Some(cache) = &self.cache {
                    let _ = cache.set(key, &score, self.ttl);
                }
                Some(score)
            }
            Err(e) => {
                debug!("threat-intel lookup failed (fail-open): {key}: {e}");
                None
            }
        }
    }
}

/// Declared sha256sums of non-VCS source artifacts, deduped. VCS checkouts have
/// no meaningful artifact hash, and `SKIP` carries no hash, so both are omitted.
fn collect_sha256s(ctx: &AnalysisContext) -> Vec<String> {
    let pkg = &ctx.pkgbuild;
    let mut out = BTreeSet::new();
    for (i, src) in pkg.source.iter().enumerate() {
        if src.is_vcs() {
            continue;
        }
        if let Some(Some(sum)) = pkg.checksums.sha256sums.get(i) {
            let sum = sum.trim();
            if !sum.eq_ignore_ascii_case("SKIP") && sum.len() == 64 {
                out.insert(sum.to_lowercase());
            }
        }
    }
    out.into_iter().collect()
}

/// `http(s)` `source=` URLs (not VCS), fragment stripped, deduped.
fn collect_urls(ctx: &AnalysisContext) -> Vec<String> {
    let mut out = BTreeSet::new();
    for src in &ctx.pkgbuild.source {
        if src.is_vcs() {
            continue;
        }
        if matches!(src.protocol, Protocol::Http | Protocol::Https) {
            let url = src.url.split('#').next().unwrap_or(&src.url);
            out.insert(url.to_string());
        }
    }
    out.into_iter().collect()
}

fn finding(
    id: &str,
    title: String,
    description: String,
    snippet: String,
    cwe: &str,
    ctx: &AnalysisContext,
) -> Finding {
    Finding {
        id: id.to_string(),
        severity: Severity::Critical,
        category: Category::MaliciousCode,
        title,
        description,
        location: Location {
            file: ctx.file_path.clone(),
            line: None,
            column: None,
            snippet: Some(snippet),
        },
        recommendation: "Do NOT build or install. Review the provider's report for this artifact; \
                         a third-party engine flagged it as malicious."
            .to_string(),
        cwe_id: Some(cwe.to_string()),
        metadata: serde_json::json!({ "provider_malicious_count": "see description" }),
    }
}

#[async_trait]
impl SecurityAnalyzer for ThreatIntelAnalyzer {
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut budget = MAX_LOOKUPS_PER_SCAN;

        // VirusTotal — declared sha256sums of source artifacts.
        if let Some(vt) = &self.vt {
            for sha in collect_sha256s(ctx) {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                let key = format!("ti:vt:file:{sha}");
                if let Some(score) = self.cached(&key, || vt.check_hash(&sha)).await {
                    if score.is_malicious() {
                        findings.push(finding(
                            "TI-VT-001",
                            "VirusTotal flags a source artifact".to_string(),
                            format!(
                                "VirusTotal reports {} engine(s) detecting the declared sha256 \
                                 {sha} as malicious.",
                                score.malicious_count
                            ),
                            format!("sha256: {sha}"),
                            "CWE-506",
                            ctx,
                        ));
                    }
                }
            }
        }

        // URLhaus — http(s) source URLs.
        if let Some(urlhaus) = &self.urlhaus {
            for url in collect_urls(ctx) {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                let key = format!("ti:urlhaus:url:{url}");
                if let Some(score) = self.cached(&key, || urlhaus.check_url(&url)).await {
                    if score.is_malicious() {
                        findings.push(finding(
                            "TI-URLHAUS-001",
                            "URLhaus lists a source URL as malicious".to_string(),
                            format!(
                                "abuse.ch URLhaus lists the source URL '{url}' as a known \
                                 malware/payload distribution URL."
                            ),
                            url.clone(),
                            "CWE-494",
                            ctx,
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "threat_intel"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn ctx(pkgbuild: &str) -> AnalysisContext {
        let parsed = StaticParser::new().parse(pkgbuild).unwrap();
        AnalysisContext {
            pkgbuild: parsed,
            install_script: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        }
    }

    #[test]
    fn no_keys_means_no_analyzer() {
        let a = ThreatIntelAnalyzer::new(None, None, None, Duration::from_secs(60));
        assert!(a.is_none(), "an inert analyzer must never be constructed");
    }

    #[test]
    fn collects_hashes_and_urls_skipping_vcs_and_skip() {
        let c = ctx(r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/app.tar.gz"
        "git+https://github.com/x/y.git"
        "local.patch")
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            'SKIP'
            '0000000000000000000000000000000000000000000000000000000000000000')
"#);
        let hashes = collect_sha256s(&c);
        assert!(hashes.contains(&"a".repeat(64)));
        assert_eq!(
            hashes.len(),
            2,
            "VCS source has no artifact hash; SKIP excluded"
        );

        let urls = collect_urls(&c);
        assert_eq!(urls, vec!["https://example.com/app.tar.gz".to_string()]);
    }

    #[tokio::test]
    async fn disabled_provider_side_is_silent() {
        // Only VT configured: a PKGBUILD with only a URL source yields no
        // findings and makes no calls (no URLhaus key).
        let a = ThreatIntelAnalyzer::new(Some("k".into()), None, None, Duration::from_secs(60))
            .unwrap();
        let c = ctx("pkgname=t\npkgver=1\npkgrel=1\nsource=('local.patch')\nsha256sums=('SKIP')\n");
        let findings = a.analyze(&c).await.unwrap();
        assert!(findings.is_empty());
    }
}
