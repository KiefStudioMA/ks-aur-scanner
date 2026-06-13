use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use std::collections::HashSet;

/// Vendored snapshot of the known-compromised package list.
const BLOCKLIST_RAW: &str = include_str!("../data/aur_malware_packages.txt");

lazy_static! {
    /// Parsed set of compromised package names (comments and blanks stripped).
    static ref BLOCKLIST: HashSet<&'static str> = BLOCKLIST_RAW
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
}

/// Analyzer that checks the package name against the compromised-package blocklist.
pub struct BlocklistAnalyzer;

impl BlocklistAnalyzer {
    /// Create a new blocklist analyzer
    pub fn new() -> Self {
        Self
    }

    /// Number of packages in the loaded blocklist (useful for diagnostics/tests).
    pub fn blocklist_len() -> usize {
        BLOCKLIST.len()
    }

    /// Check whether a given package name is in the compromised set.
    pub fn is_compromised(name: &str) -> bool {
        BLOCKLIST.contains(name)
    }
}

impl Default for BlocklistAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for BlocklistAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Match on declared package name(s) only. We deliberately do NOT match on
        // `provides`, since those are capability names (e.g. provides=firefox) and
        // would cause false positives against compromised package names.
        for name in &context.pkgbuild.pkgname {
            if BlocklistAnalyzer::is_compromised(name) {
                findings.push(Finding {
                    id: "BLOCK-001".to_string(),
                    severity: Severity::Critical,
                    category: Category::MaliciousCode,
                    title: "Package appeared in June 2026 AUR compromise list".to_string(),
                    description: format!(
                        "'{}' is on the list of ~1600 AUR packages compromised during the \
                         June 2026 supply-chain attack, in which malicious npm/bun package \
                         installs (atomic-lockfile, js-digest) were injected into build and \
                         install files to deliver an infostealer. The package may have been \
                         cleaned since; verify the current PKGBUILD and install script.",
                        name
                    ),
                    location: Location {
                        file: context.file_path.clone(),
                        line: None,
                        column: None,
                        snippet: Some(format!("pkgname={}", name)),
                    },
                    recommendation:
                        "Do not install without auditing the current sources. Confirm the \
                         malicious commits were reverted and the maintainer account recovered. \
                         When in doubt, choose a trusted alternative."
                            .to_string(),
                    cwe_id: Some("CWE-506".to_string()),
                    metadata: serde_json::json!({
                        "package": name,
                        "source": "lenucksi/aur-malware-check",
                        "campaign": "june-2026-aur-supply-chain",
                    }),
                });
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "blocklist"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn ctx(pkgbuild: &str) -> AnalysisContext {
        let parser = StaticParser::new();
        AnalysisContext {
            pkgbuild: parser.parse(pkgbuild).unwrap(),
            install_script: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        }
    }

    #[test]
    fn test_blocklist_loaded() {
        // The vendored snapshot contains ~1600 entries.
        assert!(BlocklistAnalyzer::blocklist_len() > 1000);
        // Header comment lines must not leak into the set.
        assert!(!BLOCKLIST.iter().any(|e| e.starts_with('#')));
    }

    #[tokio::test]
    async fn test_flags_known_compromised_package() {
        // "1code" is a real entry from the vendored list.
        let analyzer = BlocklistAnalyzer::new();
        let findings = analyzer
            .analyze(&ctx("pkgname=1code\npkgver=1.0\npkgrel=1\n"))
            .await
            .unwrap();
        assert!(findings.iter().any(|f| f.id == "BLOCK-001"));
    }

    #[tokio::test]
    async fn test_clean_package_not_flagged() {
        let analyzer = BlocklistAnalyzer::new();
        let findings = analyzer
            .analyze(&ctx(
                "pkgname=definitely-not-compromised-xyz\npkgver=1.0\npkgrel=1\n",
            ))
            .await
            .unwrap();
        assert!(findings.is_empty());
    }
}
