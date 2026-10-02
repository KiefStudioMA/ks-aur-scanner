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
//! integrity-checked [`DiskCache`](crate::cache) to respect VirusTotal's
//! 4-request/minute public quota, and the number of network lookups per scan is
//! capped. Anything the cap or the provider's quota stops us from checking is
//! reported (a warning on stderr and a `TI-UNCHECKED-001` info finding), never
//! silently dropped.

use super::SecurityAnalyzer;
use crate::cache::{Cache, DiskCache};
use crate::error::Result;
use crate::parser::Protocol;
use crate::threat_intel::remote;
use crate::threat_intel::{ThreatIntelProvider, ThreatScore, UrlHausProvider, VirusTotalProvider};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Upper bound on URLhaus network lookups in a single package scan: a guardrail
/// against a hostile PKGBUILD declaring hundreds of sources to stall the scan.
const MAX_URLHAUS_LOOKUPS_PER_SCAN: usize = 20;

/// Default VirusTotal network lookups per scan. The public API allows 4
/// requests/minute, so a default scan issues at most 4 and never waits out the
/// quota window; the rest are reported as unchecked. Override with
/// [`ThreatIntelAnalyzer::with_vt_lookup_cap`] or the `AUR_SCAN_VT_MAX_LOOKUPS`
/// environment variable (e.g. for a paid VirusTotal key).
pub const DEFAULT_VT_LOOKUPS_PER_SCAN: usize = 4;

/// Networked, opt-in analyzer. Holds whichever providers have keys plus the
/// verdict cache.
pub struct ThreatIntelAnalyzer {
    vt: Option<VirusTotalProvider>,
    urlhaus: Option<UrlHausProvider>,
    /// Verdict cache. `None` disables caching (the `Cache` trait is not
    /// dyn-compatible, so we hold the concrete type behind an `Option`).
    cache: Option<Arc<DiskCache>>,
    ttl: Duration,
    vt_lookup_cap: usize,
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
        let vt_lookup_cap = std::env::var("AUR_SCAN_VT_MAX_LOOKUPS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(DEFAULT_VT_LOOKUPS_PER_SCAN);
        Some(Self {
            vt,
            urlhaus,
            cache,
            ttl,
            vt_lookup_cap,
        })
    }

    /// Set the per-scan cap on VirusTotal network lookups (cache hits are free
    /// and do not count). Hashes beyond the cap are reported as unchecked.
    pub fn with_vt_lookup_cap(mut self, cap: usize) -> Self {
        self.vt_lookup_cap = cap;
        self
    }

    /// Look up `items` (each paired with its cache key) in declared order.
    ///
    /// Cache hits are served without spending `cap`. A miss runs `fetch` while
    /// budget remains. Once the provider answers HTTP 429 the quota is gone, so
    /// no further requests are made; every item that was not resolved (over the
    /// cap, or after a 429, or a transient failure) is counted in `unchecked`
    /// so the caller can surface it. Fail-open: a failed lookup never becomes a
    /// verdict and is not cached.
    async fn run_lookups<F, Fut>(
        &self,
        items: Vec<(String, String)>,
        cap: usize,
        fetch: F,
    ) -> LookupRun
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<ThreatScore>>,
    {
        let mut run = LookupRun::default();
        let mut remaining = cap;
        for (item, key) in items {
            if let Some(cache) = &self.cache {
                if let Ok(Some(hit)) = cache.get::<ThreatScore>(&key) {
                    debug!("threat-intel cache hit: {key}");
                    run.scores.push((item, hit));
                    continue;
                }
            }
            if run.rate_limited || remaining == 0 {
                run.unchecked += 1;
                continue;
            }
            remaining -= 1;
            match fetch(item.clone()).await {
                Ok(score) => {
                    if let Some(cache) = &self.cache {
                        let _ = cache.set(&key, &score, self.ttl);
                    }
                    run.scores.push((item, score));
                }
                Err(e) => {
                    run.unchecked += 1;
                    if remote::is_rate_limited(&e) {
                        run.rate_limited = true;
                    }
                    debug!("threat-intel lookup failed (fail-open): {key}: {e}");
                }
            }
        }
        run
    }
}

/// Result of [`ThreatIntelAnalyzer::run_lookups`].
#[derive(Default, Debug)]
struct LookupRun {
    /// Resolved lookups (item, score) in declared order.
    scores: Vec<(String, ThreatScore)>,
    /// Items that were not checked (over the cap, rate-limited, or failed).
    unchecked: usize,
    /// The provider answered HTTP 429 during this scan.
    rate_limited: bool,
}

/// Declared sha256sums of non-VCS source artifacts, deduped, **in declared
/// order**. (A sorted set would let an attacker pad the PKGBUILD with decoy
/// hashes that sort first and push the real artifact's hash past the lookup
/// cap.) VCS checkouts have no meaningful artifact hash, and `SKIP` carries no
/// hash, so both are omitted.
fn collect_sha256s(ctx: &AnalysisContext) -> Vec<String> {
    let pkg = &ctx.pkgbuild;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (i, src) in pkg.source.iter().enumerate() {
        if src.is_vcs() {
            continue;
        }
        if let Some(Some(sum)) = pkg.checksums.sha256sums.get(i) {
            let sum = sum.trim();
            if !sum.eq_ignore_ascii_case("SKIP") && sum.len() == 64 {
                let sum = sum.to_lowercase();
                if seen.insert(sum.clone()) {
                    out.push(sum);
                }
            }
        }
    }
    out
}

/// `http(s)` `source=` URLs (not VCS) in declared order, deduped, with userinfo
/// and fragment stripped (see [`remote::sanitize_url_for_lookup`]).
fn collect_urls(ctx: &AnalysisContext) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for src in &ctx.pkgbuild.source {
        if src.is_vcs() {
            continue;
        }
        if matches!(src.protocol, Protocol::Http | Protocol::Https) {
            let url = remote::sanitize_url_for_lookup(&src.url);
            if seen.insert(url.clone()) {
                out.push(url);
            }
        }
    }
    out
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
        let mut unchecked: Vec<String> = Vec::new();

        // VirusTotal: declared sha256sums of source artifacts.
        if let Some(vt) = &self.vt {
            let items = collect_sha256s(ctx)
                .into_iter()
                .map(|sha| {
                    let key = format!("ti:vt:file:{sha}");
                    (sha, key)
                })
                .collect();
            let run = self
                .run_lookups(items, self.vt_lookup_cap, |sha| async move {
                    vt.check_hash(&sha).await
                })
                .await;
            for (sha, score) in &run.scores {
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
            if run.unchecked > 0 {
                unchecked.push(format!(
                    "{} source hash(es) not checked against VirusTotal ({})",
                    run.unchecked,
                    if run.rate_limited {
                        "rate limited (HTTP 429)".to_string()
                    } else {
                        format!("per-scan cap of {} network lookups", self.vt_lookup_cap)
                    }
                ));
            }
        }

        // URLhaus: http(s) source URLs.
        if let Some(urlhaus) = &self.urlhaus {
            let items = collect_urls(ctx)
                .into_iter()
                .map(|url| {
                    let key = format!("ti:urlhaus:url:{url}");
                    (url, key)
                })
                .collect();
            let run = self
                .run_lookups(items, MAX_URLHAUS_LOOKUPS_PER_SCAN, |url| async move {
                    urlhaus.check_url(&url).await
                })
                .await;
            for (url, score) in &run.scores {
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
            if run.unchecked > 0 {
                unchecked.push(format!(
                    "{} source URL(s) not checked against URLhaus ({})",
                    run.unchecked,
                    if run.rate_limited {
                        "rate limited (HTTP 429)".to_string()
                    } else {
                        format!("per-scan cap of {MAX_URLHAUS_LOOKUPS_PER_SCAN} lookups")
                    }
                ));
            }
        }

        // Never silent: say what the threat-intel pass could not cover.
        if !unchecked.is_empty() {
            let msg = unchecked.join("; ");
            tracing::warn!("threat-intel coverage incomplete: {msg}");
            findings.push(Finding {
                id: "TI-UNCHECKED-001".to_string(),
                severity: Severity::Info,
                category: Category::Configuration,
                title: "Threat-intel lookups incomplete".to_string(),
                description: format!(
                    "Some source artifacts were not checked by the opt-in threat-intel \
                     providers: {msg}. A clean result does not cover them."
                ),
                location: Location {
                    file: ctx.file_path.clone(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Re-scan later (cached verdicts are reused), raise the cap with \
                                 AUR_SCAN_VT_MAX_LOOKUPS if your VirusTotal key allows it, or \
                                 review the remaining sources manually."
                    .to_string(),
                cwe_id: None,
                metadata: serde_json::json!({ "unchecked": unchecked }),
            });
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
            side_scripts: vec![],
            local_binaries: vec![],
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
            registry: None,
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

    fn analyzer_no_cache() -> ThreatIntelAnalyzer {
        ThreatIntelAnalyzer::new(Some("k".into()), None, None, Duration::from_secs(60)).unwrap()
    }

    fn items(n: usize) -> Vec<(String, String)> {
        (0..n).map(|i| (format!("h{i}"), format!("k{i}"))).collect()
    }

    fn score() -> ThreatScore {
        ThreatScore {
            malicious_count: 0,
            suspicious_count: 0,
            total_engines: 1,
            provider: "t".into(),
        }
    }

    #[tokio::test]
    async fn cap_limits_network_lookups_and_counts_the_rest() {
        let a = analyzer_no_cache();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let run = a
            .run_lookups(items(10), 4, |_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Ok(score()) }
            })
            .await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(run.scores.len(), 4);
        assert_eq!(run.unchecked, 6);
        assert!(!run.rate_limited);
        // Declared order is preserved: the first four items are the ones checked.
        let got: Vec<&str> = run.scores.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(got, ["h0", "h1", "h2", "h3"]);
    }

    #[tokio::test]
    async fn a_429_stops_further_requests_and_is_reported() {
        let a = analyzer_no_cache();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let run = a
            .run_lookups(items(10), 10, |_| {
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Ok(score())
                    } else {
                        Err(crate::error::ScanError::Network(
                            "VirusTotal HTTP 429 Too Many Requests".into(),
                        ))
                    }
                }
            })
            .await;
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "no request after the 429"
        );
        assert!(run.rate_limited);
        assert_eq!(run.scores.len(), 2);
        assert_eq!(run.unchecked, 8);
    }

    #[test]
    fn declared_order_is_kept_so_decoys_cannot_push_real_hashes_out() {
        // The real artifact's hash sorts LAST; with a sorted set and a small cap
        // it would never be looked up.
        let z = "f".repeat(64);
        let c = ctx(&format!(
            "pkgname=t\npkgver=1\npkgrel=1\nsource=('https://e.example/real.tgz' 'https://e.example/d1' 'https://e.example/d2')\nsha256sums=('{z}' '{a}' '{b}')\n",
            a = "0".repeat(64),
            b = "1".repeat(64),
        ));
        assert_eq!(collect_sha256s(&c)[0], z);
    }

    #[test]
    fn source_urls_lose_userinfo_before_lookup() {
        let c = ctx(
            "pkgname=t\npkgver=1\npkgrel=1\nsource=('https://bob:hunter2@host.example/x.tgz?t=1#frag')\nsha256sums=('SKIP')\n",
        );
        assert_eq!(
            collect_urls(&c),
            vec!["https://host.example/x.tgz?t=1".to_string()]
        );
    }
}
