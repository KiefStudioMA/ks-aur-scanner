//! Typo-squat and name-impersonation analysis.
//!
//! The package name is the only thing most people read before they type
//! `yay -S <name>`. Three distinct attacks live in that gap:
//!
//! * **Lookalike names** -- a Cyrillic `а` or an underscore-for-hyphen swap
//!   renders identically to a trusted name (`SQUAT-001`).
//! * **One-keystroke names** -- `openss1` for `openssl`, but only when the
//!   imitated package is one worth imitating (`SQUAT-002`).
//! * **Variant-namespace claims** -- the AUR reserves nothing, so anyone may
//!   publish `<yourpackage>-bin` and inherit your reputation (`SQUAT-003`).
//!
//! Every one of these is gated on **registry standing**, not name shape alone.
//! Name proximity is dense and cheap: measured across the 15,436 official
//! package names, `bibutils`/`binutils` and `python-ijson`/`python-ujson` are
//! each a single keyboard-adjacent character apart and both are entirely
//! legitimate. What separates a squat from a neighbour is that a squat is new,
//! unvalidated, and published by someone other than the party whose name it is
//! trading on. Without registry context this analyzer emits nothing at all.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::squat::{self, SquatKind};
use crate::types::{
    AnalysisContext, Category, Finding, Location, OwnedNamespace, RegistryContext, Severity,
};
use async_trait::async_trait;

/// Packages worth impersonating: widely installed, widely typed, and valuable
/// to compromise. The one-keystroke rule only ever runs against this list --
/// against the whole corpus it produces 264 false positives, mostly locale
/// families like `aspell-ca`/`aspell-cs`.
///
/// This is deliberately short and hand-picked. A long list buys very little
/// extra coverage and costs precision on every entry.
pub const HIGH_VALUE_TARGETS: &[&str] = &[
    // AUR helpers -- the highest-value target of all, since they run as the
    // user and install everything else.
    "yay",
    "yay-bin",
    "paru",
    "paru-bin",
    "pikaur",
    "trizen",
    "aurutils",
    // Core system and toolchain.
    "systemd",
    "pacman",
    "sudo",
    "openssh",
    "openssl",
    "gnupg",
    "linux",
    "glibc",
    "curl",
    "wget",
    "git",
    "gcc",
    "docker",
    "podman",
    "containerd",
    // Runtimes and package managers.
    "python",
    "python3",
    "nodejs",
    "npm",
    "yarn",
    "rust",
    "rustup",
    "go",
    "jre-openjdk",
    "jdk-openjdk",
    // Widely installed desktop and developer software, where a `-bin` build is
    // the norm and therefore an easy thing to impersonate.
    "firefox",
    "chromium",
    "google-chrome",
    "brave-bin",
    "visual-studio-code-bin",
    "code",
    "sublime-text-4",
    "discord",
    "slack-desktop",
    "spotify",
    "zoom",
    "teamviewer",
    "anydesk-bin",
    "postman-bin",
    "insomnia-bin",
    "virtualbox",
    "qemu",
    "wireshark-qt",
    "keepassxc",
    "bitwarden",
    "protonvpn-gui",
    "signal-desktop",
    "telegram-desktop",
    // Cloud and infrastructure CLIs -- credential-bearing by definition.
    "kubectl",
    "terraform",
    "ansible",
    "aws-cli",
    "azure-cli",
    "google-cloud-cli",
    "helm",
    "vagrant",
];

/// How long a package must have existed, and how much community validation it
/// must have, before a near-miss name is treated as coincidence rather than
/// impersonation.
///
/// These are not magic numbers so much as a statement of what the finding
/// means: "this name is close to something trusted, and there is nothing else
/// here to reassure me". A package with years of history and hundreds of votes
/// supplies that reassurance.
const ESTABLISHED_DAYS: i64 = 365;
const ESTABLISHED_VOTES: i32 = 50;

/// Analyzer for name impersonation.
pub struct SquatAnalyzer;

impl SquatAnalyzer {
    /// Create a new squat analyzer.
    pub fn new() -> Self {
        Self
    }

    /// Whether a package has enough independent standing that a near-miss name
    /// is not, on its own, worth accusing anyone over.
    ///
    /// Deliberately generous. A false accusation of typo-squatting is a
    /// reputational attack on a named maintainer, so the bar to stay silent is
    /// low and the bar to speak is high.
    fn is_established(reg: &RegistryContext, now: i64) -> bool {
        let old_enough = reg
            .first_submitted
            .is_some_and(|t| now.saturating_sub(t) >= ESTABLISHED_DAYS * 86_400);
        let popular_enough = reg.num_votes.is_some_and(|v| v >= ESTABLISHED_VOTES);
        old_enough || popular_enough
    }

    /// A short phrase describing why the package has no standing yet, for the
    /// finding text. Returns `None` when it does have standing.
    fn standing_note(reg: &RegistryContext, now: i64) -> Option<String> {
        if Self::is_established(reg, now) {
            return None;
        }
        let mut parts = Vec::new();
        if let Some(first) = reg.first_submitted {
            let days = now.saturating_sub(first) / 86_400;
            parts.push(format!("submitted {days} day(s) ago"));
        }
        match reg.num_votes {
            Some(v) => parts.push(format!("{v} vote(s)")),
            None => parts.push("no vote data".to_string()),
        }
        if reg.maintainer.is_none() {
            parts.push("orphaned".to_string());
        }
        Some(parts.join(", "))
    }

    fn analyze_with(
        &self,
        name: &str,
        reg: &RegistryContext,
        file: &std::path::Path,
        now: i64,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // SQUAT-001 -- a name that renders identically to a trusted one.
        //
        // Reported regardless of standing, and at Critical, because it is the
        // one signal with no innocent explanation. AUR package names are ASCII
        // by policy; a Cyrillic character in a package name is not a typo a
        // maintainer makes by accident. Zero false positives across the full
        // official corpus.
        let marks = squat::confusables(name);
        if !marks.is_empty() {
            let rendered: String = marks
                .iter()
                .map(|(c, a)| format!("{c:?} (U+{:04X}) imitating '{a}'", *c as u32))
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding {
                id: "SQUAT-001".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousCode,
                title: "Package name contains lookalike characters".to_string(),
                description: format!(
                    "The package name '{name}' contains non-ASCII character(s) that render like \
                     ASCII letters: {rendered}. AUR package names are ASCII, so a name that only \
                     looks like a familiar one is impersonation, not a typo."
                ),
                location: Location {
                    file: file.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: Some(format!("pkgname={name}")),
                },
                recommendation: "Do not install this package. Compare the name character by \
                                 character against the package you intended to install."
                    .to_string(),
                cwe_id: Some("CWE-1007".to_string()),
                metadata: serde_json::json!({
                    "confusables": marks
                        .iter()
                        .map(|(c, a)| serde_json::json!({
                            "char": c.to_string(),
                            "codepoint": format!("U+{:04X}", *c as u32),
                            "imitates": a.to_string(),
                        }))
                        .collect::<Vec<_>>(),
                }),
            });
        }

        // A name that folds onto a real package name, even in pure ASCII
        // (`python_requests` for `python-requests`).
        if let Some(m) = squat::nearest(name, reg.official_names.iter().map(|s| s.as_str()), false)
        {
            if m.kind == SquatKind::Lookalike && marks.is_empty() {
                findings.push(Finding {
                    id: "SQUAT-001".to_string(),
                    severity: Severity::High,
                    category: Category::MaliciousCode,
                    title: "Package name renders like an official package".to_string(),
                    description: format!(
                        "The AUR package '{name}' {} the official package '{}'. Two distinct \
                         packages do not display the same name by accident.",
                        m.kind.describe(),
                        m.target
                    ),
                    location: Location {
                        file: file.to_path_buf(),
                        line: None,
                        column: None,
                        snippet: Some(format!("pkgname={name}")),
                    },
                    recommendation: format!(
                        "Confirm you meant this package and not '{}' from the official \
                         repositories.",
                        m.target
                    ),
                    cwe_id: Some("CWE-1007".to_string()),
                    metadata: serde_json::json!({ "imitates": m.target }),
                });
            }
        }

        // SQUAT-002 -- one lookalike keystroke from a high-value package.
        //
        // Gated on standing: `bibutils` is genuinely one character from
        // `binutils` and is genuinely a real package.
        if let Some(note) = Self::standing_note(reg, now) {
            if let Some(m) = squat::nearest(name, HIGH_VALUE_TARGETS.iter().copied(), true) {
                if m.kind == SquatKind::OneCharSubstitution {
                    findings.push(Finding {
                        id: "SQUAT-002".to_string(),
                        severity: Severity::High,
                        category: Category::MaliciousCode,
                        title: "Package name is one keystroke from a widely-installed package"
                            .to_string(),
                        description: format!(
                            "'{name}' {} '{}', and has no independent standing of its own ({note}). \
                             A single substituted character against a package this widely \
                             installed is the classic install-typo trap.",
                            m.kind.describe(),
                            m.target
                        ),
                        location: Location {
                            file: file.to_path_buf(),
                            line: None,
                            column: None,
                            snippet: Some(format!("pkgname={name}")),
                        },
                        recommendation: format!(
                            "Check whether you meant '{}'. If this package is genuinely distinct, \
                             its name is still an accident waiting to happen.",
                            m.target
                        ),
                        cwe_id: Some("CWE-1007".to_string()),
                        metadata: serde_json::json!({
                            "imitates": m.target,
                            "standing": note,
                        }),
                    });
                }
            }
        }

        // SQUAT-003 -- a build variant in different hands from its base package.
        //
        // Reported as CONTEXT, at Low, and deliberately not as an accusation.
        //
        // The temptation here is to treat "different maintainer" as evidence,
        // because the attack is real: the AUR reserves no namespace, so owning
        // `foo` does not reserve `foo-bin`, and users assume `foo-bin` is your
        // binary build. But measured against the live AUR, 5,650 of 13,292
        // build-variant packages (42.5%) are maintained by someone other than
        // the base maintainer, and they are overwhelmingly legitimate -- one
        // person packages the release, another packages the git build. Even
        // narrowing to a differing upstream `url=` still leaves 1,820 pairs,
        // most of them a project homepage on one side and its git repo on the
        // other.
        //
        // So there is no metadata field that separates the impostor from the
        // 5,650. What the scanner can honestly do is *say what it sees* and let
        // the reader judge. Where certainty is available -- because the operator
        // told us who owns the namespace -- SQUAT-004 below reports it properly.
        if let Some(base) = &reg.variant_base {
            if let Some(suffix) = squat::variant_claim_on(name, &base.name) {
                let same_hands = match (&reg.maintainer, &base.maintainer) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                if !same_hands {
                    let who = match (&reg.maintainer, &base.maintainer) {
                        (Some(v), Some(b)) => {
                            format!("'{v}' publishes it; '{b}' publishes the base")
                        }
                        (Some(v), None) => {
                            format!("'{v}' publishes it; the base package is orphaned")
                        }
                        (None, Some(b)) => {
                            format!("it is orphaned; '{b}' publishes the base package")
                        }
                        (None, None) => "both it and the base package are orphaned".to_string(),
                    };
                    findings.push(Finding {
                        id: "SQUAT-003".to_string(),
                        severity: Severity::Low,
                        category: Category::SuspiciousMetadata,
                        title: format!("'{suffix}' variant is in different hands from its base"),
                        description: format!(
                            "'{name}' is the '{suffix}' build of '{}', and {who}. This is common \
                             and usually legitimate -- roughly 42% of AUR build variants are \
                             packaged by someone other than the base maintainer. It is noted \
                             because the AUR reserves no variant namespace, so this is also the \
                             shape an impersonation takes. Judge it on the source and the \
                             publisher, not on this note alone.",
                            base.name
                        ),
                        location: Location {
                            file: file.to_path_buf(),
                            line: None,
                            column: None,
                            snippet: Some(format!("pkgname={name}")),
                        },
                        recommendation: format!(
                            "If you expected '{}' upstream to publish this build, confirm that \
                             they do. To make this decisive for names you own, declare them under \
                             [[owned_namespaces]] in your config.",
                            base.name
                        ),
                        cwe_id: None,
                        metadata: serde_json::json!({
                            "base_package": base.name,
                            "variant_suffix": suffix,
                            "variant_maintainer": reg.maintainer,
                            "base_maintainer": base.maintainer,
                        }),
                    });
                }
            }
        }

        findings
    }

    /// SQUAT-004 -- a package in a namespace the operator claims, published by
    /// an account they did not authorise.
    ///
    /// This is the one variant-namespace check that can be stated as fact
    /// rather than suspicion, because it rests on knowledge the scanner cannot
    /// derive: *you* know you publish `aur-scanner`, and *you* know you never
    /// shipped an `aur-scanner-bin`. Nothing in the AUR's own metadata encodes
    /// that. Declaring it turns the ambiguous 42% case into a certainty for the
    /// names you actually own, with no false positives by construction.
    fn check_owned_namespaces(
        &self,
        name: &str,
        reg: &RegistryContext,
        owned: &[OwnedNamespace],
        file: &std::path::Path,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for ns in owned {
            // The namespace covers the exact name and any suffixed variant of
            // it, but not an unrelated name that merely starts with the same
            // letters (`aur-scannerfoo` is not in the `aur-scanner` namespace).
            let in_namespace = name == ns.prefix
                || name
                    .strip_prefix(&ns.prefix)
                    .is_some_and(|rest| rest.starts_with('-'));
            if !in_namespace {
                continue;
            }
            let authorised = reg
                .maintainer
                .as_ref()
                .is_some_and(|m| ns.maintainers.iter().any(|a| a.eq_ignore_ascii_case(m)));
            if authorised {
                continue;
            }
            let who = match &reg.maintainer {
                Some(m) => format!("published by '{m}'"),
                None => "orphaned, with no publisher at all".to_string(),
            };
            findings.push(Finding {
                id: "SQUAT-004".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousCode,
                title: "Package occupies a namespace you own, under an unauthorised account"
                    .to_string(),
                description: format!(
                    "'{name}' falls inside the '{}' namespace, which your configuration declares \
                     is published by {}. This package is {who}. The AUR does not reserve variant \
                     names, so an account that is not yours can publish inside your namespace and \
                     inherit your reputation -- which is exactly what this looks like.",
                    ns.prefix,
                    ns.maintainers.join(", ")
                ),
                location: Location {
                    file: file.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: Some(format!("pkgname={name}")),
                },
                recommendation: format!(
                    "Do not install this package. If '{name}' should not exist, report it to the \
                     AUR maintainers for removal as an impersonation of '{}'.",
                    ns.prefix
                ),
                cwe_id: Some("CWE-1007".to_string()),
                metadata: serde_json::json!({
                    "namespace": ns.prefix,
                    "authorised_maintainers": ns.maintainers,
                    "actual_maintainer": reg.maintainer,
                }),
            });
        }
        findings
    }
}

impl Default for SquatAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for SquatAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        // No registry context means no scan-time knowledge of who publishes
        // what. Guessing from the PKGBUILD alone would produce exactly the
        // false accusations this analyzer is built to avoid.
        let Some(reg) = &context.registry else {
            return Ok(Vec::new());
        };
        let Some(name) = context.package_name() else {
            return Ok(Vec::new());
        };
        let now = chrono::Utc::now().timestamp();
        let mut findings = self.analyze_with(name, reg, &context.file_path, now);
        findings.extend(self.check_owned_namespaces(
            name,
            reg,
            &context.config.owned_namespaces,
            &context.file_path,
        ));
        Ok(findings)
    }

    fn name(&self) -> &str {
        "squat"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OwnedNamespace, VariantBase};
    use std::path::Path;

    const NOW: i64 = 1_780_000_000; // fixed clock so tests never drift

    fn days_ago(d: i64) -> i64 {
        NOW - d * 86_400
    }

    fn reg() -> RegistryContext {
        RegistryContext {
            maintainer: Some("someone".into()),
            num_votes: Some(0),
            popularity: Some(0.0),
            out_of_date: None,
            first_submitted: Some(days_ago(3)),
            last_modified: Some(days_ago(1)),
            official_names: vec![
                "python-requests".into(),
                "openssl".into(),
                "binutils".into(),
                "firefox".into(),
            ],
            variant_base: None,
        }
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    #[test]
    fn cyrillic_name_is_critical_regardless_of_standing() {
        let a = SquatAnalyzer::new();
        let mut r = reg();
        // Even a long-established, popular package cannot innocently have a
        // Cyrillic character in its name.
        r.first_submitted = Some(days_ago(4000));
        r.num_votes = Some(9000);
        let f = a.analyze_with("firefоx", &r, Path::new("PKGBUILD"), NOW);
        assert!(ids(&f).contains(&"SQUAT-001"), "got {:?}", ids(&f));
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn separator_swap_on_an_official_name_is_flagged() {
        let a = SquatAnalyzer::new();
        let f = a.analyze_with("python_requests", &reg(), Path::new("PKGBUILD"), NOW);
        assert!(ids(&f).contains(&"SQUAT-001"), "got {:?}", ids(&f));
    }

    #[test]
    fn one_keystroke_from_a_high_value_target_is_flagged_when_new() {
        let a = SquatAnalyzer::new();
        let f = a.analyze_with("openss1", &reg(), Path::new("PKGBUILD"), NOW);
        assert!(ids(&f).contains(&"SQUAT-002"), "got {:?}", ids(&f));
    }

    #[test]
    fn an_established_package_is_not_accused_over_its_name() {
        // The `bibutils`/`binutils` case: genuinely one keyboard-adjacent
        // character apart, genuinely a real package. Standing must silence it.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.first_submitted = Some(days_ago(3000));
        r.num_votes = Some(400);
        let f = a.analyze_with("bibutils", &r, Path::new("PKGBUILD"), NOW);
        assert!(
            !ids(&f).contains(&"SQUAT-002"),
            "an established package must not be accused: {:?}",
            ids(&f)
        );
    }

    #[test]
    fn age_alone_confers_standing() {
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.first_submitted = Some(days_ago(400));
        r.num_votes = Some(0);
        let f = a.analyze_with("openss1", &r, Path::new("PKGBUILD"), NOW);
        assert!(!ids(&f).contains(&"SQUAT-002"));
    }

    #[test]
    fn votes_alone_confer_standing() {
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.first_submitted = Some(days_ago(2));
        r.num_votes = Some(500);
        let f = a.analyze_with("openss1", &r, Path::new("PKGBUILD"), NOW);
        assert!(!ids(&f).contains(&"SQUAT-002"));
    }

    #[test]
    fn variant_in_different_hands_is_reported_as_low_context_only() {
        // 42.5% of real AUR build variants are in different hands from their
        // base and are legitimate. This must be a note, not an accusation --
        // Low severity, no CWE, and phrased so a reader is not misled into
        // thinking the scanner found evidence of anything.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = Some("someone-else".into());
        r.variant_base = Some(VariantBase {
            name: "aur-scanner".into(),
            maintainer: Some("kiefstudio".into()),
            official: false,
            num_votes: Some(120),
        });
        let f = a.analyze_with("aur-scanner-bin", &r, Path::new("PKGBUILD"), NOW);
        let finding = f
            .iter()
            .find(|x| x.id == "SQUAT-003")
            .expect("must note it");
        assert_eq!(
            finding.severity,
            Severity::Low,
            "a 42%-common shape must never be reported above Low"
        );
        assert!(finding.cwe_id.is_none());
        assert!(finding.description.contains("usually legitimate"));
    }

    #[test]
    fn owned_namespace_violation_is_critical() {
        // The case that started this, stated as fact rather than suspicion:
        // we publish `aur-scanner`, we declared that, and someone else
        // published `aur-scanner-bin`.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = Some("not-kief-studio".into());
        let owned = vec![OwnedNamespace {
            prefix: "aur-scanner".into(),
            maintainers: vec!["KiefStudio".into()],
        }];
        let f = a.check_owned_namespaces("aur-scanner-bin", &r, &owned, Path::new("PKGBUILD"));
        assert_eq!(ids(&f), vec!["SQUAT-004"]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].description.contains("not-kief-studio"));
    }

    #[test]
    fn owned_namespace_allows_the_declared_maintainer() {
        let a = SquatAnalyzer::new();
        let mut r = reg();
        // Case-insensitive: AUR account names are displayed inconsistently.
        r.maintainer = Some("kiefstudio".into());
        let owned = vec![OwnedNamespace {
            prefix: "aur-scanner".into(),
            maintainers: vec!["KiefStudio".into()],
        }];
        for name in ["aur-scanner", "aur-scanner-bin", "aur-scanner-git"] {
            let f = a.check_owned_namespaces(name, &r, &owned, Path::new("PKGBUILD"));
            assert!(f.is_empty(), "{name} is ours and authorised: {:?}", ids(&f));
        }
    }

    #[test]
    fn owned_namespace_flags_an_orphaned_package_in_our_namespace() {
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = None;
        let owned = vec![OwnedNamespace {
            prefix: "aur-scanner".into(),
            maintainers: vec!["KiefStudio".into()],
        }];
        let f = a.check_owned_namespaces("aur-scanner-bin", &r, &owned, Path::new("PKGBUILD"));
        assert_eq!(ids(&f), vec!["SQUAT-004"]);
    }

    #[test]
    fn owned_namespace_does_not_match_a_merely_similar_prefix() {
        // `aur-scannerfoo` is a different name, not a variant inside the
        // namespace. Only an exact match or a `-`-separated suffix counts.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = Some("stranger".into());
        let owned = vec![OwnedNamespace {
            prefix: "aur-scanner".into(),
            maintainers: vec!["KiefStudio".into()],
        }];
        for name in ["aur-scannerfoo", "aur-scan", "totally-different"] {
            let f = a.check_owned_namespaces(name, &r, &owned, Path::new("PKGBUILD"));
            assert!(
                f.is_empty(),
                "{name} is outside the namespace: {:?}",
                ids(&f)
            );
        }
    }

    #[test]
    fn no_owned_namespaces_configured_means_no_such_findings() {
        // Nothing is on by default.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = Some("stranger".into());
        let f = a.check_owned_namespaces("aur-scanner-bin", &r, &[], Path::new("PKGBUILD"));
        assert!(f.is_empty());
    }

    #[test]
    fn variant_by_the_same_maintainer_is_not_flagged() {
        // The normal, overwhelmingly common case: upstream ships their own
        // `-bin`. This must stay silent or the rule is unusable.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = Some("kiefstudio".into());
        r.variant_base = Some(VariantBase {
            name: "aur-scanner".into(),
            maintainer: Some("kiefstudio".into()),
            official: false,
            num_votes: Some(120),
        });
        let f = a.analyze_with("aur-scanner-bin", &r, Path::new("PKGBUILD"), NOW);
        assert!(!ids(&f).contains(&"SQUAT-003"), "got {:?}", ids(&f));
    }

    #[test]
    fn a_variant_of_an_official_package_never_reaches_this_analyzer() {
        // `registry::resolve_variant_base` refuses to build a `VariantBase` for
        // an official package, because an AUR account is never the same hands
        // as the Arch maintainers and 4,997 legitimate packages have this shape.
        // Nothing here should depend on `official`, and this test documents
        // that the case is handled upstream rather than by severity tuning.
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.maintainer = Some("stranger".into());
        r.variant_base = None; // what registry resolution actually produces
        let f = a.analyze_with("firefox-bin", &r, Path::new("PKGBUILD"), NOW);
        assert!(
            !ids(&f).contains(&"SQUAT-003"),
            "a git/bin build of a repo package is what the AUR is for: {:?}",
            ids(&f)
        );
    }

    #[test]
    fn established_variant_is_still_flagged_when_hands_differ() {
        // Standing does NOT clear a variant claim. A squatted `-bin` that has
        // been sitting there for two years accumulating installs is worse, not
        // better -- unlike a near-miss name, there is no innocent reading of
        // "different person publishing your binary build".
        let a = SquatAnalyzer::new();
        let mut r = reg();
        r.first_submitted = Some(days_ago(900));
        r.num_votes = Some(300);
        r.maintainer = Some("stranger".into());
        r.variant_base = Some(VariantBase {
            name: "aur-scanner".into(),
            maintainer: Some("kiefstudio".into()),
            official: false,
            num_votes: Some(120),
        });
        let f = a.analyze_with("aur-scanner-bin", &r, Path::new("PKGBUILD"), NOW);
        assert!(ids(&f).contains(&"SQUAT-003"));
    }

    #[test]
    fn ordinary_package_produces_nothing() {
        let a = SquatAnalyzer::new();
        let f = a.analyze_with("my-little-tool", &reg(), Path::new("PKGBUILD"), NOW);
        assert!(f.is_empty(), "got {:?}", ids(&f));
    }

    #[tokio::test]
    async fn no_registry_context_means_no_findings() {
        // A bare `aur-scan scan ./dir` has no idea who publishes anything.
        // Guessing is worse than silence.
        use crate::parser::{PkgbuildParser, StaticParser};
        use crate::types::ScanConfig;
        let parsed = StaticParser::new()
            .parse("pkgname=firefоx\npkgver=1\npkgrel=1\n")
            .unwrap();
        let ctx = AnalysisContext {
            pkgbuild: parsed,
            install_script: None,
            side_scripts: vec![],
            config: ScanConfig::default(),
            file_path: "PKGBUILD".into(),
            registry: None,
        };
        let f = SquatAnalyzer::new().analyze(&ctx).await.unwrap();
        assert!(f.is_empty());
    }
}
