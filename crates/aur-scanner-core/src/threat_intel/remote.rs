//! The scanner's ONLY outbound network surface for third-party threat
//! intelligence. Every call to VirusTotal or abuse.ch / URLhaus lives in this
//! file and nowhere else, so the project's entire external egress can be
//! audited in one place.
//!
//! Invariants every function here upholds:
//!
//!   * **Opt-in only.** These functions are reached only when the operator set
//!     `enable_threat_intel` *and* supplied the relevant API key. With no key
//!     the call is never made — a default scan is fully offline.
//!   * **Least disclosure.** Only a content hash (`sha256`) or a `source=` URL
//!     already declared in the *public* PKGBUILD is ever transmitted. Never file
//!     contents, never anything about the user or their system.
//!   * **HTTPS-only, no redirects, time-bounded.** A followed redirect is the
//!     classic SSRF / exfil amplifier, so it is refused outright.
//!   * **Fail-open and advisory.** Any network, quota, auth, or parse error
//!     yields `Ok(None)` — never a hard error, never a fabricated verdict. A
//!     scan must not depend on a third party being reachable, and a provider
//!     outage must never block an install.
//!
//! Credit: the VirusTotal-by-hash approach originates with @SuitablyMysterious
//! in <https://github.com/KiefStudioMA/ks-aur-scanner/pull/9> (the `vt_lookup`
//! reference implementation). This module generalizes it behind the provider
//! trait and adds URLhaus, response caching, and per-scan throttling.

use super::ThreatScore;
use crate::error::{Result, ScanError};
use base64::Engine;
use std::time::Duration;

/// Per-request timeout. Threat intel is advisory, so we wait only briefly
/// before failing open.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

const VT_API: &str = "https://www.virustotal.com/api/v3";
const URLHAUS_API: &str = "https://urlhaus-api.abuse.ch/v1";

/// The hardened client used for every egress call in this module: HTTPS-only,
/// redirects refused, bounded timeout, identifiable user-agent.
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("aur-scan/{}", crate::VERSION))
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .map_err(|e| ScanError::Network(e.to_string()))
}

/// True for a clean 64-char hex sha256. A hash is interpolated into a URL path,
/// so anything else is rejected before it can reach the network.
fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// VirusTotal v3 file (hash) report. `sha256` is a hex digest already declared
/// in the PKGBUILD's `sha256sums`. `Ok(None)` if VT has never seen the hash
/// (404) or on any error (fail-open). Endpoint/auth per the VT v3 reference
/// (`GET /files/{id}`, `x-apikey` header). The public API allows only 4 req/min
/// & 500/day, so callers MUST cache and bound their lookups.
pub async fn virustotal_file(api_key: &str, sha256: &str) -> Result<Option<ThreatScore>> {
    if !is_hex_sha256(sha256) {
        return Ok(None);
    }
    let resp = match client()?
        .get(format!("{VT_API}/files/{sha256}"))
        .header("x-apikey", api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    // 404 = VT has never analyzed this hash; 401/429/5xx = bad key/quota/outage.
    // All are advisory: fail open rather than fail the scan.
    if !resp.status().is_success() {
        return Ok(None);
    }
    match resp.json::<serde_json::Value>().await {
        Ok(json) => Ok(parse_vt_stats(&json)),
        Err(_) => Ok(None),
    }
}

/// VirusTotal v3 URL report. The URL identifier is the unpadded URL-safe base64
/// of the URL (per the VT v3 reference). Fail-open like [`virustotal_file`].
pub async fn virustotal_url(api_key: &str, url: &str) -> Result<Option<ThreatScore>> {
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());
    let resp = match client()?
        .get(format!("{VT_API}/urls/{id}"))
        .header("x-apikey", api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    if !resp.status().is_success() {
        return Ok(None);
    }
    match resp.json::<serde_json::Value>().await {
        Ok(json) => Ok(parse_vt_stats(&json)),
        Err(_) => Ok(None),
    }
}

/// URLhaus URL lookup. abuse.ch made the `Auth-Key` header MANDATORY (free key
/// from <https://auth.abuse.ch/>), so this is only called when a key is set.
/// `POST /v1/url/` with form field `url=`. Fail-open.
pub async fn urlhaus_url(auth_key: &str, url: &str) -> Result<Option<ThreatScore>> {
    let resp = match client()?
        .post(format!("{URLHAUS_API}/url/"))
        .header("Auth-Key", auth_key)
        .form(&[("url", url)])
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    if !resp.status().is_success() {
        return Ok(None);
    }
    match resp.json::<serde_json::Value>().await {
        Ok(json) => Ok(Some(parse_urlhaus(&json))),
        Err(_) => Ok(None),
    }
}

/// URLhaus payload (hash) lookup: `POST /v1/payload/` with `sha256_hash=`.
/// Reports whether the artifact with this hash is a known malware payload.
pub async fn urlhaus_payload(auth_key: &str, sha256: &str) -> Result<Option<ThreatScore>> {
    if !is_hex_sha256(sha256) {
        return Ok(None);
    }
    let resp = match client()?
        .post(format!("{URLHAUS_API}/payload/"))
        .header("Auth-Key", auth_key)
        .form(&[("sha256_hash", sha256)])
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    if !resp.status().is_success() {
        return Ok(None);
    }
    match resp.json::<serde_json::Value>().await {
        Ok(json) => Ok(Some(parse_urlhaus(&json))),
        Err(_) => Ok(None),
    }
}

/// Parse a VirusTotal v3 report body (file or URL) into a [`ThreatScore`]. The
/// engine tally lives at `data.attributes.last_analysis_stats`
/// (`{ malicious, suspicious, harmless, undetected, timeout }`). Returns `None`
/// if that block is absent (e.g. an unexpected/error body).
fn parse_vt_stats(json: &serde_json::Value) -> Option<ThreatScore> {
    let stats = json.pointer("/data/attributes/last_analysis_stats")?;
    let g = |k: &str| {
        stats
            .get(k)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32
    };
    let malicious = g("malicious");
    let suspicious = g("suspicious");
    let total = malicious + suspicious + g("harmless") + g("undetected") + g("timeout");
    Some(ThreatScore {
        malicious_count: malicious,
        suspicious_count: suspicious,
        total_engines: total,
        provider: "VirusTotal".to_string(),
    })
}

/// Parse a URLhaus `/url/` or `/payload/` response. `query_status == "ok"` means
/// the URL/payload is listed in URLhaus — a known malware/payload distribution
/// artifact. Anything else (`no_results`, `invalid_url`, `http_post_expected`,
/// …) is treated as not-listed.
fn parse_urlhaus(json: &serde_json::Value) -> ThreatScore {
    let listed = json.get("query_status").and_then(|v| v.as_str()) == Some("ok");
    ThreatScore {
        malicious_count: u32::from(listed),
        suspicious_count: 0,
        total_engines: 1,
        provider: "URLhaus".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_sha256_gate() {
        assert!(is_hex_sha256(&"a".repeat(64)));
        assert!(!is_hex_sha256(&"a".repeat(63)));
        assert!(!is_hex_sha256("../../etc/passwd"));
        assert!(!is_hex_sha256(&"g".repeat(64)));
    }

    #[test]
    fn vt_stats_parsed_from_real_shape() {
        let json = serde_json::json!({
            "data": { "attributes": { "last_analysis_stats": {
                "malicious": 7, "suspicious": 1, "harmless": 2,
                "undetected": 60, "timeout": 0
            }}}
        });
        let s = parse_vt_stats(&json).expect("stats present");
        assert_eq!(s.malicious_count, 7);
        assert_eq!(s.suspicious_count, 1);
        assert_eq!(s.total_engines, 70);
        assert!(s.is_malicious());
    }

    #[test]
    fn vt_clean_is_not_malicious() {
        let json = serde_json::json!({
            "data": { "attributes": { "last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5
            }}}
        });
        let s = parse_vt_stats(&json).unwrap();
        assert!(!s.is_malicious());
    }

    #[test]
    fn vt_missing_stats_is_none() {
        assert!(parse_vt_stats(&serde_json::json!({"error": "NotFound"})).is_none());
    }

    #[test]
    fn urlhaus_listed_vs_not() {
        let listed =
            parse_urlhaus(&serde_json::json!({"query_status": "ok", "threat": "malware_download"}));
        assert!(listed.is_malicious());
        let clean = parse_urlhaus(&serde_json::json!({"query_status": "no_results"}));
        assert!(!clean.is_malicious());
    }
}
