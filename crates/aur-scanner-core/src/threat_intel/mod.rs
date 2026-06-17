//! Threat intelligence integration module
//!
//! Provides a local, updatable IOC database ([`ioc`]) plus optional hooks for
//! external threat-intelligence services.

pub mod ioc;
pub mod remote;

pub use ioc::{Campaign, IocDatabase, IocHit, IocKind};

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Score from threat intelligence lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    /// Number of engines flagging as malicious
    pub malicious_count: u32,
    /// Number of engines flagging as suspicious
    pub suspicious_count: u32,
    /// Total number of engines
    pub total_engines: u32,
    /// Provider name
    pub provider: String,
}

impl ThreatScore {
    /// Check if the target is considered malicious
    pub fn is_malicious(&self) -> bool {
        self.malicious_count > 0 || self.suspicious_count > 2
    }

    /// Get a risk score from 0-100
    pub fn risk_score(&self) -> u32 {
        if self.total_engines == 0 {
            return 0;
        }
        ((self.malicious_count * 100 + self.suspicious_count * 50) / self.total_engines).min(100)
    }
}

/// Trait for threat intelligence providers
#[async_trait]
pub trait ThreatIntelProvider: Send + Sync {
    /// Check if a URL is malicious
    async fn check_url(&self, url: &str) -> Result<ThreatScore>;

    /// Check if a file hash is malicious
    async fn check_hash(&self, hash: &str) -> Result<ThreatScore>;

    /// Get provider name
    fn name(&self) -> &str;
}

/// A score from a lookup the provider could not actually perform (network
/// error, missing data). Distinct from a real all-clear: `total_engines == 0`
/// and `is_malicious()` is false, so it never produces a finding.
fn no_data(provider: &str) -> ThreatScore {
    ThreatScore {
        malicious_count: 0,
        suspicious_count: 0,
        total_engines: 0,
        provider: provider.to_string(),
    }
}

/// VirusTotal provider. All network I/O lives in [`remote`]; this is just the
/// typed entry point. The key is supplied by the operator (config or env) and a
/// provider is only ever constructed when one is present.
pub struct VirusTotalProvider {
    api_key: String,
}

impl VirusTotalProvider {
    /// Create a VirusTotal provider with an API key.
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }
}

#[async_trait]
impl ThreatIntelProvider for VirusTotalProvider {
    async fn check_url(&self, url: &str) -> Result<ThreatScore> {
        Ok(remote::virustotal_url(&self.api_key, url)
            .await?
            .unwrap_or_else(|| no_data(self.name())))
    }

    async fn check_hash(&self, hash: &str) -> Result<ThreatScore> {
        Ok(remote::virustotal_file(&self.api_key, hash)
            .await?
            .unwrap_or_else(|| no_data(self.name())))
    }

    fn name(&self) -> &str {
        "VirusTotal"
    }
}

/// URLhaus (abuse.ch) provider. abuse.ch now requires an `Auth-Key` for every
/// query, so the provider always carries one; it is constructed only when the
/// operator has supplied a key.
pub struct UrlHausProvider {
    auth_key: String,
}

impl UrlHausProvider {
    /// Create a URLhaus provider with an abuse.ch Auth-Key.
    pub fn new(auth_key: String) -> Self {
        Self { auth_key }
    }
}

#[async_trait]
impl ThreatIntelProvider for UrlHausProvider {
    async fn check_url(&self, url: &str) -> Result<ThreatScore> {
        Ok(remote::urlhaus_url(&self.auth_key, url)
            .await?
            .unwrap_or_else(|| no_data(self.name())))
    }

    async fn check_hash(&self, hash: &str) -> Result<ThreatScore> {
        Ok(remote::urlhaus_payload(&self.auth_key, hash)
            .await?
            .unwrap_or_else(|| no_data(self.name())))
    }

    fn name(&self) -> &str {
        "URLhaus"
    }
}
