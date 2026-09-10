//! Point-in-time ownership and community-standing signals.
//!
//! Who stands behind a package is part of its risk, and it is not visible in
//! the PKGBUILD at all. The 2018 xeactor hijack and the June 2026 Atomic Arch
//! campaign both worked by taking over *abandoned* packages: the code was fine
//! until it wasn't, and the thing that made those packages targets was that
//! nobody was watching them.
//!
//! These are context findings, and their severities were chosen by measuring
//! how common each signal actually is across all 119,170 AUR packages:
//!
//! | Signal | Share of the AUR | Reported as |
//! |---|---|---|
//! | Orphaned | 11.9% | `OWN-001`, Low |
//! | Orphaned **and** flagged out-of-date | 4.2% | `OWN-002`, Medium |
//! | Flagged out-of-date over a year | 5.4% | `OWN-003`, Low |
//! | Zero votes | **50.0%** | never reported on its own |
//!
//! Half the AUR has zero votes, so unpopularity is not a signal -- it is the
//! median. It is used only as a *modifier* on a package that is also brand new.
//!
//! Change over time (a maintainer appearing, an orphan being adopted) is a
//! different and stronger signal, handled by the `DIFF-*` codes in
//! [`crate::history`]. This module answers "what is true right now".

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, RegistryContext, Severity};
use async_trait::async_trait;

/// A package younger than this, with nothing else vouching for it, is worth
/// noting when it also runs build or install code.
const NEW_PACKAGE_DAYS: i64 = 30;

/// Out-of-date for longer than this means nobody is maintaining it in practice,
/// whatever the maintainer field says.
const STALE_FLAG_DAYS: i64 = 365;

/// Analyzer for ownership and community-standing signals.
pub struct OwnershipAnalyzer;

impl OwnershipAnalyzer {
    /// Create a new ownership analyzer.
    pub fn new() -> Self {
        Self
    }

    fn analyze_with(
        &self,
        name: &str,
        reg: &RegistryContext,
        has_executable_functions: bool,
        file: &std::path::Path,
        now: i64,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let loc = || Location {
            file: file.to_path_buf(),
            line: None,
            column: None,
            snippet: None,
        };

        let orphaned = reg.maintainer.is_none();
        let ood_days = reg
            .out_of_date
            .map(|t| now.saturating_sub(t) / 86_400)
            .filter(|d| *d >= 0);

        // OWN-002 -- abandoned in both senses. 4.2% of the AUR, and the exact
        // profile both documented hijack campaigns selected for: nobody
        // responsible, and visibly not keeping up with upstream. Reported
        // instead of OWN-001, not alongside it, so one package does not produce
        // two findings about the same fact.
        if orphaned && ood_days.is_some() {
            let days = ood_days.unwrap_or(0);
            findings.push(Finding {
                id: "OWN-002".to_string(),
                severity: Severity::Medium,
                category: Category::SuspiciousMetadata,
                title: "Package is orphaned and flagged out-of-date".to_string(),
                description: format!(
                    "'{name}' has no maintainer and has been flagged out-of-date for {days} day(s). \
                     Roughly 4% of the AUR is in this state, and it is the profile both the 2018 \
                     xeactor hijack and the 2026 Atomic Arch campaign selected for: an abandoned \
                     package that people still have installed can be adopted by anyone."
                ),
                location: loc(),
                recommendation: "Prefer a maintained alternative. If you adopt or install it, \
                                 review the PKGBUILD yourself -- nobody else is."
                    .to_string(),
                cwe_id: None,
                metadata: serde_json::json!({
                    "orphaned": true,
                    "out_of_date_days": days,
                    "num_votes": reg.num_votes,
                }),
            });
        } else if orphaned {
            // OWN-001 -- orphaned only. 11.9% of the AUR: common enough that
            // anything above Low would be noise for anyone with a normal number
            // of AUR packages installed, but worth being a real finding rather
            // than a printed aside, so it reaches JSON, SARIF, and gates.
            findings.push(Finding {
                id: "OWN-001".to_string(),
                severity: Severity::Low,
                category: Category::SuspiciousMetadata,
                title: "Package is orphaned".to_string(),
                description: format!(
                    "'{name}' has no maintainer. Anyone may adopt it, and whoever does inherits \
                     every existing installation without further review. About 12% of the AUR is \
                     orphaned, so this is context rather than evidence -- but adoption of an \
                     orphan is how the known AUR supply-chain campaigns began."
                ),
                location: loc(),
                recommendation: "Note that no one is responsible for this package; review updates \
                                 to it yourself."
                    .to_string(),
                cwe_id: None,
                metadata: serde_json::json!({
                    "orphaned": true,
                    "num_votes": reg.num_votes,
                }),
            });
        } else if let Some(days) = ood_days {
            // OWN-003 -- maintained on paper, but flagged out-of-date for a
            // long time. Only reported past a year: a package flagged last week
            // is a maintainer who has not got to it yet, which is not a
            // security observation.
            if days >= STALE_FLAG_DAYS {
                findings.push(Finding {
                    id: "OWN-003".to_string(),
                    severity: Severity::Low,
                    category: Category::SuspiciousMetadata,
                    title: "Package has been flagged out-of-date for over a year".to_string(),
                    description: format!(
                        "'{name}' has a maintainer but has been flagged out-of-date for {days} \
                         day(s). It is likely to be shipping a version with known upstream fixes \
                         missing, and in practice is unmaintained regardless of the maintainer \
                         field."
                    ),
                    location: loc(),
                    recommendation: "Check whether upstream has fixes this package does not carry."
                        .to_string(),
                    cwe_id: None,
                    metadata: serde_json::json!({
                        "out_of_date_days": days,
                        "maintainer": reg.maintainer,
                    }),
                });
            }
        }

        // OWN-004 -- brand new, nothing vouching for it, and it runs code.
        //
        // Each part of this is worthless alone: half the AUR has zero votes,
        // and nearly every package has a build() function. The conjunction is
        // narrow -- under 2% of the AUR is less than a month old -- and it
        // describes the position an attacker is in on day one of a new package.
        let age_days = reg.first_submitted.map(|t| now.saturating_sub(t) / 86_400);
        let brand_new = age_days.is_some_and(|d| d < NEW_PACKAGE_DAYS);
        let unvouched = reg.num_votes.unwrap_or(0) == 0;
        if brand_new && unvouched && has_executable_functions {
            let days = age_days.unwrap_or(0);
            findings.push(Finding {
                id: "OWN-004".to_string(),
                severity: Severity::Low,
                category: Category::SuspiciousMetadata,
                title: "New package with no community validation".to_string(),
                description: format!(
                    "'{name}' was submitted {days} day(s) ago, has no votes, and runs build or \
                     install code. None of those is unusual by itself -- half the AUR has zero \
                     votes -- but together they mean nobody has looked at this yet and you would \
                     be among the first to run it."
                ),
                location: loc(),
                recommendation: "Read the PKGBUILD and any install script in full before building."
                    .to_string(),
                cwe_id: None,
                metadata: serde_json::json!({
                    "age_days": days,
                    "num_votes": reg.num_votes,
                    "maintainer": reg.maintainer,
                }),
            });
        }

        findings
    }
}

impl Default for OwnershipAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for OwnershipAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        // No registry lookup means no maintainer field at all. A missing
        // maintainer must never be read as "orphaned" -- it means "we did not
        // look", and inventing an ownership finding from that would be a
        // fabrication about a real person.
        let Some(reg) = &context.registry else {
            return Ok(Vec::new());
        };
        let Some(name) = context.package_name() else {
            return Ok(Vec::new());
        };
        let has_executable_functions =
            !context.pkgbuild.functions.is_empty() || context.all_scripts().next().is_some();
        let now = chrono::Utc::now().timestamp();
        Ok(self.analyze_with(name, reg, has_executable_functions, &context.file_path, now))
    }

    fn name(&self) -> &str {
        "ownership"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const NOW: i64 = 1_780_000_000;
    fn days_ago(d: i64) -> i64 {
        NOW - d * 86_400
    }

    fn reg() -> RegistryContext {
        RegistryContext {
            maintainer: Some("alice".into()),
            num_votes: Some(120),
            popularity: Some(3.0),
            out_of_date: None,
            first_submitted: Some(days_ago(900)),
            last_modified: Some(days_ago(10)),
            official_names: vec![],
            variant_base: None,
        }
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    fn run(r: &RegistryContext, has_fns: bool) -> Vec<Finding> {
        OwnershipAnalyzer::new().analyze_with("tool", r, has_fns, Path::new("PKGBUILD"), NOW)
    }

    #[test]
    fn a_healthy_package_produces_nothing() {
        assert!(run(&reg(), true).is_empty());
    }

    #[test]
    fn an_orphan_is_low() {
        let mut r = reg();
        r.maintainer = None;
        let f = run(&r, true);
        assert_eq!(ids(&f), vec!["OWN-001"]);
        assert_eq!(
            f[0].severity,
            Severity::Low,
            "12% of the AUR is orphaned; anything above Low is noise"
        );
    }

    #[test]
    fn an_orphan_that_is_also_out_of_date_is_medium_and_reported_once() {
        let mut r = reg();
        r.maintainer = None;
        r.out_of_date = Some(days_ago(200));
        let f = run(&r, true);
        assert_eq!(
            ids(&f),
            vec!["OWN-002"],
            "must not also emit OWN-001 about the same fact"
        );
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn a_recently_flagged_maintained_package_is_not_reported() {
        // A maintainer who has not got to a flag from last week is not a
        // security observation.
        let mut r = reg();
        r.out_of_date = Some(days_ago(20));
        assert!(run(&r, true).is_empty());
    }

    #[test]
    fn a_long_stale_flag_on_a_maintained_package_is_low() {
        let mut r = reg();
        r.out_of_date = Some(days_ago(500));
        let f = run(&r, true);
        assert_eq!(ids(&f), vec!["OWN-003"]);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn zero_votes_alone_is_never_a_finding() {
        // Half the AUR has zero votes. Reporting it would be reporting the
        // median.
        let mut r = reg();
        r.num_votes = Some(0);
        assert!(
            run(&r, true).is_empty(),
            "zero votes is the median, not a signal"
        );
    }

    #[test]
    fn an_established_package_with_zero_votes_is_still_quiet() {
        let mut r = reg();
        r.num_votes = Some(0);
        r.first_submitted = Some(days_ago(2000));
        assert!(run(&r, true).is_empty());
    }

    #[test]
    fn a_brand_new_unvouched_package_that_runs_code_is_low() {
        let mut r = reg();
        r.num_votes = Some(0);
        r.first_submitted = Some(days_ago(3));
        let f = run(&r, true);
        assert_eq!(ids(&f), vec!["OWN-004"]);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn a_brand_new_package_that_runs_no_code_is_quiet() {
        // A metapackage with no functions and no install script has no
        // execution path to worry about.
        let mut r = reg();
        r.num_votes = Some(0);
        r.first_submitted = Some(days_ago(3));
        assert!(run(&r, false).is_empty());
    }

    #[test]
    fn a_new_package_with_real_votes_is_quiet() {
        let mut r = reg();
        r.num_votes = Some(80);
        r.first_submitted = Some(days_ago(3));
        assert!(run(&r, true).is_empty());
    }

    #[test]
    fn an_orphan_can_also_be_brand_new() {
        let mut r = reg();
        r.maintainer = None;
        r.num_votes = Some(0);
        r.first_submitted = Some(days_ago(2));
        let f = run(&r, true);
        let got = ids(&f);
        assert!(got.contains(&"OWN-001"));
        assert!(got.contains(&"OWN-004"));
    }

    #[tokio::test]
    async fn no_registry_context_means_no_ownership_findings() {
        // A missing maintainer field means "we did not look", never
        // "orphaned". Inventing a finding here would be a fabrication about a
        // named person.
        use crate::parser::{PkgbuildParser, StaticParser};
        use crate::types::ScanConfig;
        let parsed = StaticParser::new()
            .parse("pkgname=tool\npkgver=1\npkgrel=1\nbuild() { make; }\n")
            .unwrap();
        let ctx = AnalysisContext {
            pkgbuild: parsed,
            install_script: None,
            side_scripts: vec![],
            config: ScanConfig::default(),
            file_path: "PKGBUILD".into(),
            registry: None,
        };
        let f = OwnershipAnalyzer::new().analyze(&ctx).await.unwrap();
        assert!(f.is_empty());
    }
}
