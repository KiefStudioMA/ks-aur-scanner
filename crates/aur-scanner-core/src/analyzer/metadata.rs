//! Packaging-metadata analyzer.
//!
//! The parser extracts `provides`/`conflicts`/`replaces`/`epoch`/`backup`/
//! `install`/`validpgpkeys`, but until now no analyzer reasoned over them. These
//! fields encode supply-chain attacks the regex/text rules cannot express because
//! they need the *parsed structure*, not a line:
//!
//! * dependency confusion — `provides=` a core package name (DEP-001);
//! * forced displacement — `replaces=`/`conflicts=` a core/security package
//!   (META-003);
//! * stealth force-upgrade — `epoch>=1` to outrank the official package
//!   (META-004);
//! * persistent config tamper — `backup=` of a security-sensitive file
//!   (META-006);
//! * out-of-package install scriptlet — `install=` with a path/`..`/odd name
//!   (META-005);
//! * signature theatre — `validpgpkeys=` declared but nothing is verified against
//!   it (META-002).
//!
//! FP discipline is load-bearing: a legitimate `<core>-git`/`<core>-bin` alternate
//! provides/replaces its base package by design, so the core-name checks are gated
//! on "the package is NOT an alternate of that name" (and on a curated core/
//! security set, never "any repo package").

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;

/// Curated set of Arch core/base + security packages. `provides=`-ing one is
/// dependency confusion; `replaces=`/`conflicts=`-ing one is forced displacement
/// of a trusted (often security-critical) package. Deliberately NOT "any repo
/// package": the bar is a name a normal AUR package would never legitimately
/// claim unless it is that package's own `-git`/`-bin` alternate.
const TRUSTED_PKGS: &[&str] = &[
    // core system (NB: `sh` is intentionally absent — every shell legitimately
    // `provides=('sh')`, so it would false-positive)
    "bash",
    "coreutils",
    "glibc",
    "gcc-libs",
    "systemd",
    "systemd-libs",
    "util-linux",
    "shadow",
    "filesystem",
    "pacman",
    "sudo",
    "doas",
    "openssh",
    "gnupg",
    "pam",
    "grep",
    "sed",
    "gawk",
    "tar",
    "gzip",
    "xz",
    "zstd",
    "findutils",
    "which",
    "less",
    "procps-ng",
    "psmisc",
    "iproute2",
    "iputils",
    "e2fsprogs",
    "krb5",
    "curl",
    "wget",
    "openssl",
    "ca-certificates",
    "ca-certificates-mozilla",
    "zlib",
    "readline",
    "ncurses",
    "dbus",
    "polkit",
    "systemd-sysvcompat",
    "linux",
    "linux-firmware",
    "mkinitcpio",
    "grub",
    "pacman-mirrorlist",
    "archlinux-keyring",
    // security tooling (replacing/conflicting these = defense evasion)
    "apparmor",
    "firejail",
    "ufw",
    "nftables",
    "iptables",
    "audit",
    "usbguard",
    "fail2ban",
    "clamav",
    "firewalld",
    "opensnitch",
    "selinux",
    "tomb",
];

/// Sensitive file prefixes (relative to `/`): a `backup=` entry under one of
/// these turns a "config" file into a persistent root-level tamper surface.
const SENSITIVE_BACKUP: &[&str] = &[
    "etc/sudoers",
    "etc/ssh/",
    "etc/pam.d/",
    "etc/ld.so.preload",
    "etc/ld.so.conf",
    "etc/profile",
    "etc/shadow",
    "etc/passwd",
    "etc/group",
    "etc/gshadow",
    "etc/crontab",
    "etc/cron.d/",
    "etc/polkit-1/",
    "etc/systemd/system/",
    "etc/modprobe.d/",
    "etc/sysctl.d/",
    "etc/security/",
    "root/.ssh/",
    "etc/skel/",
];

/// Alternate-package affixes: a `foo-git`/`foo-bin` package legitimately
/// provides/replaces `foo`. Stripping these (and a leading `lib`) yields the
/// "stem" used to recognise that a provides/replaces is the package's own base.
const ALT_SUFFIXES: &[&str] = &[
    "-git",
    "-bin",
    "-svn",
    "-hg",
    "-bzr",
    "-cvs",
    "-nightly",
    "-beta",
    "-rc",
    "-dev",
    "-devel",
    "-debug",
    "-legacy",
    "-lts",
    "-stable",
    "-unstable",
];

/// Strip a dependency/version constraint and soname to the bare package name:
/// `bash>=5.0` -> `bash`, `libfoo.so=1` -> `libfoo.so`(then handled), `pkg:desc`
/// -> `pkg`. Splits at the first constraint/soname/description separator.
fn bare_name(dep: &str) -> &str {
    let dep = dep.trim().trim_matches(|c| c == '\'' || c == '"');
    dep.split(['=', '<', '>', ':']).next().unwrap_or(dep).trim()
}

/// The "stem" of a package name with an alternate affix removed, e.g.
/// `firefox-git` -> `firefox`. Returns the input unchanged when no affix matches.
fn pkgname_stem(name: &str) -> &str {
    for suf in ALT_SUFFIXES {
        if let Some(stem) = name.strip_suffix(suf) {
            if !stem.is_empty() {
                return stem;
            }
        }
    }
    name
}

/// Whether one of the package's own names is (an alternate/variant of) `target`
/// — i.e. this package legitimately IS `target` (e.g. `bash`, `bash-git`,
/// `sudo-selinux`, `openssh-hpn`), so a `provides`/`replaces` of `target` is
/// expected, not an attack. The dependency-confusion signal is precisely the
/// OPPOSITE: a package whose name has NO relationship to the core name it claims.
/// Matched on dash-delimited components (not arbitrary substrings) to stay
/// precise for short names. `target` is at least 3 chars (callers gate on the
/// curated set), so the component checks do not over-trigger.
fn is_own_alternate(pkgnames: &[String], target: &str) -> bool {
    pkgnames.iter().any(|p| {
        p == target
            || pkgname_stem(p) == target
            || p.starts_with(&format!("{target}-"))
            || p.ends_with(&format!("-{target}"))
            || pkgname_stem(p).starts_with(&format!("{target}-"))
    })
}

/// Analyzer over parsed packaging metadata.
pub struct MetadataAnalyzer;

impl MetadataAnalyzer {
    /// Create a new metadata analyzer.
    pub fn new() -> Self {
        Self
    }
}

impl Default for MetadataAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn finding(
        &self,
        ctx: &AnalysisContext,
        id: &str,
        severity: Severity,
        category: Category,
        title: String,
        description: String,
        recommendation: &str,
        cwe: Option<&str>,
        snippet: Option<String>,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            severity,
            category,
            title,
            description,
            location: Location {
                file: ctx.file_path.clone(),
                line: None,
                column: None,
                snippet,
            },
            recommendation: recommendation.to_string(),
            cwe_id: cwe.map(String::from),
            metadata: serde_json::json!({}),
        }
    }
}

#[async_trait]
impl SecurityAnalyzer for MetadataAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let pkg = &context.pkgbuild;
        let mut findings = Vec::new();

        // Does the package provide/replace/conflict a curated trusted package it
        // is not itself an alternate of? Computed once; drives META-003/DEP-001
        // and escalates META-004.
        let mut displaced_trusted: Vec<String> = Vec::new(); // replaces/conflicts
        let mut shadowed_trusted: Vec<String> = Vec::new(); // provides

        for entry in pkg.replaces.iter().chain(pkg.conflicts.iter()) {
            let name = bare_name(entry);
            if TRUSTED_PKGS.contains(&name)
                && !is_own_alternate(&pkg.pkgname, name)
                && !displaced_trusted.iter().any(|n| n == name)
            {
                displaced_trusted.push(name.to_string());
            }
        }
        for entry in &pkg.provides {
            let name = bare_name(entry);
            if TRUSTED_PKGS.contains(&name)
                && !is_own_alternate(&pkg.pkgname, name)
                && !shadowed_trusted.iter().any(|n| n == name)
            {
                shadowed_trusted.push(name.to_string());
            }
        }

        // META-003 — replaces/conflicts of a trusted package (forced displacement).
        if !displaced_trusted.is_empty() {
            findings.push(self.finding(
                context,
                "META-003",
                Severity::High,
                Category::SuspiciousMetadata,
                "Replaces/conflicts a core or security package".to_string(),
                format!(
                    "The package declares replaces=/conflicts= of trusted package(s): {}. \
                     This forces pacman to displace the official (often security-critical) \
                     package with this AUR build. Only that package's own -git/-bin alternate \
                     should do this.",
                    displaced_trusted.join(", ")
                ),
                "Remove the replaces/conflicts unless this package is the legitimate provider; \
                 report the package to the AUR maintainers.",
                Some("CWE-1357"),
                Some(format!(
                    "replaces/conflicts: {}",
                    displaced_trusted.join(", ")
                )),
            ));
        }

        // DEP-001 — provides a trusted package name (dependency confusion).
        if !shadowed_trusted.is_empty() {
            findings.push(self.finding(
                context,
                "DEP-001",
                Severity::High,
                Category::SuspiciousMetadata,
                "Provides a core package name (dependency confusion)".to_string(),
                format!(
                    "The package declares provides= of trusted package name(s): {}. A package \
                     that is not that package's own alternate can satisfy a dependency in its \
                     place and be pulled in transparently.",
                    shadowed_trusted.join(", ")
                ),
                "Remove the provides unless this is the legitimate provider; this is a \
                 dependency-confusion vector.",
                Some("CWE-427"),
                Some(format!("provides: {}", shadowed_trusted.join(", "))),
            ));
        }

        // META-004 — epoch>=1 (stealth force-upgrade over the repo package).
        if let Some(ep) = &pkg.epoch {
            if ep.trim().parse::<u64>().map(|n| n >= 1).unwrap_or(false) {
                let escalate = !displaced_trusted.is_empty() || !shadowed_trusted.is_empty();
                findings.push(self.finding(
                    context,
                    "META-004",
                    if escalate {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                    Category::SuspiciousMetadata,
                    "epoch set (forces an upgrade over the repo version)".to_string(),
                    format!(
                        "epoch={} makes this package outrank the official package's version \
                         regardless of pkgver{}. epoch is legitimate for genuine versioning \
                         resets but, combined with provides/replaces of a trusted name, is a \
                         stealth force-upgrade.",
                        ep.trim(),
                        if escalate {
                            " — and this package also provides/replaces a trusted name"
                        } else {
                            ""
                        }
                    ),
                    "Confirm the epoch bump is a real upstream versioning reset, not a way to \
                     supersede the official package.",
                    None,
                    Some(format!("epoch={}", ep.trim())),
                ));
            }
        }

        // META-005 — install= scriptlet outside the package.
        if let Some(install) = &pkg.install {
            let v = install.trim();
            let outside = v.contains('/') || v.contains("..") || !v.ends_with(".install");
            if outside && !v.is_empty() {
                findings.push(self.finding(
                    context,
                    "META-005",
                    Severity::Medium,
                    Category::SuspiciousMetadata,
                    "install= points outside the package".to_string(),
                    format!(
                        "install={v} is not a plain `<name>.install` file in the package \
                         directory (it contains a path, `..`, or a non-.install name). makepkg \
                         runs this scriptlet as part of the package; an out-of-tree path is a \
                         way to run an unexpected file."
                    ),
                    "Use a plain `<pkgname>.install` file shipped alongside the PKGBUILD.",
                    Some("CWE-426"),
                    Some(format!("install={v}")),
                ));
            }
        }

        // META-006 — backup= of a security-sensitive file.
        let sensitive: Vec<String> = pkg
            .backup
            .iter()
            .map(|b| b.trim().trim_start_matches('/').to_string())
            .filter(|b| SENSITIVE_BACKUP.iter().any(|p| b.starts_with(p)))
            .collect();
        if !sensitive.is_empty() {
            findings.push(self.finding(
                context,
                "META-006",
                Severity::Medium,
                Category::SuspiciousMetadata,
                "backup= of a security-sensitive file".to_string(),
                format!(
                    "backup= lists security-sensitive path(s): {}. A package that ships and \
                     marks such a file as a backup config can persistently alter authentication, \
                     the dynamic linker, or privilege rules.",
                    sensitive.join(", ")
                ),
                "Packages should not own or back up files under sudoers/ssh/pam.d/ld.so/etc.; \
                 review what content is installed there.",
                Some("CWE-426"),
                Some(format!("backup: {}", sensitive.join(", "))),
            ));
        }

        // META-002 — validpgpkeys declared but never used to verify anything.
        if !pkg.validpgpkeys.is_empty() {
            let verifies = pkg.source.iter().any(|s| {
                let u = s.url.to_lowercase();
                let frag = s.fragment.as_deref().unwrap_or("").to_lowercase();
                let fname = s.filename.as_deref().unwrap_or("").to_lowercase();
                frag.contains("signed")
                    || u.contains("?signed")
                    || u.ends_with(".sig")
                    || u.ends_with(".asc")
                    || u.ends_with(".sign")
                    || fname.ends_with(".sig")
                    || fname.ends_with(".asc")
            });
            if !verifies {
                findings.push(
                    self.finding(
                        context,
                        "META-002",
                        Severity::Low,
                        Category::SuspiciousMetadata,
                        "validpgpkeys declared but no signature is verified".to_string(),
                        "validpgpkeys= lists trusted signing key(s) but no source carries a \
                     detached signature (.sig/.asc) or a ?signed VCS fragment, so the declared \
                     key verifies nothing — signature theatre that can lull a reviewer."
                            .to_string(),
                        "Either verify a signed source against the key, or remove the unused \
                     validpgpkeys.",
                        Some("CWE-347"),
                        None,
                    ),
                );
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "metadata"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn ctx(src: &str) -> AnalysisContext {
        let pkgbuild = StaticParser::new().parse(src).unwrap();
        AnalysisContext {
            pkgbuild,
            install_script: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        }
    }

    async fn ids(src: &str) -> Vec<String> {
        MetadataAnalyzer::new()
            .analyze(&ctx(src))
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.id)
            .collect()
    }

    #[tokio::test]
    async fn dep001_and_meta003_fire_on_core_names() {
        let got = ids(
            "pkgname=evil\npkgver=1\npkgrel=1\nprovides=('bash')\nreplaces=('sudo')\nconflicts=('openssh')\n",
        )
        .await;
        assert!(
            got.contains(&"DEP-001".to_string()),
            "provides bash -> DEP-001: {got:?}"
        );
        assert!(
            got.contains(&"META-003".to_string()),
            "replaces sudo -> META-003: {got:?}"
        );
    }

    #[tokio::test]
    async fn legit_alternate_does_not_fire() {
        // bash-git providing/conflicting bash is the normal alternate pattern.
        let got = ids(
            "pkgname=bash-git\npkgver=1\npkgrel=1\nprovides=('bash')\nconflicts=('bash')\nreplaces=('bash')\n",
        )
        .await;
        assert!(
            !got.contains(&"DEP-001".to_string()),
            "alternate must not fire DEP-001: {got:?}"
        );
        assert!(
            !got.contains(&"META-003".to_string()),
            "alternate must not fire META-003: {got:?}"
        );
    }

    #[tokio::test]
    async fn legit_variant_packages_do_not_fire() {
        // Real Arch variant packages provide/replace a core name without a
        // -git/-bin affix; the dash-component match must recognise them.
        for src in [
            "pkgname=sudo-selinux\npkgver=1\npkgrel=1\nprovides=('sudo')\nconflicts=('sudo')\nreplaces=('sudo')\n",
            "pkgname=openssh-hpn\npkgver=1\npkgrel=1\nprovides=('openssh')\nconflicts=('openssh')\n",
            "pkgname=xz-utils\npkgver=1\npkgrel=1\nprovides=('xz')\n",
        ] {
            let got = ids(src).await;
            assert!(!got.contains(&"DEP-001".to_string()), "variant must not fire DEP-001: {src} -> {got:?}");
            assert!(!got.contains(&"META-003".to_string()), "variant must not fire META-003: {src} -> {got:?}");
        }
        // ...but an UNRELATED name claiming a core provide is the attack.
        let evil = ids("pkgname=totally-legit-app\npkgver=1\npkgrel=1\nprovides=('xz')\n").await;
        assert!(
            evil.contains(&"DEP-001".to_string()),
            "unrelated provides xz -> DEP-001: {evil:?}"
        );
    }

    #[tokio::test]
    async fn provides_of_non_core_is_clean() {
        // Providing a normal (non-core) virtual package is routine.
        let got =
            ids("pkgname=myapp\npkgver=1\npkgrel=1\nprovides=('libmyapp.so' 'myapp-thing')\n")
                .await;
        assert!(
            !got.contains(&"DEP-001".to_string()),
            "non-core provides must be clean: {got:?}"
        );
    }

    #[tokio::test]
    async fn epoch_low_then_escalates_with_core_shadow() {
        let low = ids("pkgname=app\npkgver=1\npkgrel=1\nepoch=1\n").await;
        assert!(low.contains(&"META-004".to_string()));
        // epoch + provides core -> the same finding escalates (still META-004).
        let esc = ids("pkgname=app\npkgver=1\npkgrel=1\nepoch=2\nprovides=('glibc')\n").await;
        assert!(esc.contains(&"META-004".to_string()) && esc.contains(&"DEP-001".to_string()));
        // epoch=0 / absent is clean.
        assert!(!ids("pkgname=app\npkgver=1\npkgrel=1\nepoch=0\n")
            .await
            .contains(&"META-004".to_string()));
    }

    #[tokio::test]
    async fn meta005_install_outside_package() {
        assert!(
            ids("pkgname=a\npkgver=1\npkgrel=1\ninstall=../../etc/evil\n")
                .await
                .contains(&"META-005".to_string())
        );
        assert!(ids("pkgname=a\npkgver=1\npkgrel=1\ninstall=/opt/x.sh\n")
            .await
            .contains(&"META-005".to_string()));
        // a plain <name>.install is clean.
        assert!(!ids("pkgname=a\npkgver=1\npkgrel=1\ninstall=a.install\n")
            .await
            .contains(&"META-005".to_string()));
    }

    #[tokio::test]
    async fn meta006_sensitive_backup() {
        assert!(
            ids("pkgname=a\npkgver=1\npkgrel=1\nbackup=('etc/sudoers.d/a')\n")
                .await
                .contains(&"META-006".to_string())
        );
        assert!(
            ids("pkgname=a\npkgver=1\npkgrel=1\nbackup=('etc/ssh/sshd_config')\n")
                .await
                .contains(&"META-006".to_string())
        );
        // an ordinary app config is clean.
        assert!(
            !ids("pkgname=a\npkgver=1\npkgrel=1\nbackup=('etc/myapp/myapp.conf')\n")
                .await
                .contains(&"META-006".to_string())
        );
    }

    #[tokio::test]
    async fn meta002_validpgpkeys_unused_vs_used() {
        // declared key, no signed source -> META-002
        let unused = ids(
            "pkgname=a\npkgver=1\npkgrel=1\nvalidpgpkeys=('ABCDEF0123456789')\nsource=('https://x/a.tar.gz')\n",
        )
        .await;
        assert!(
            unused.contains(&"META-002".to_string()),
            "unused key -> META-002: {unused:?}"
        );
        // declared key with a .sig source -> not signature theatre
        let used = ids(
            "pkgname=a\npkgver=1\npkgrel=1\nvalidpgpkeys=('ABCDEF0123456789')\nsource=('https://x/a.tar.gz' 'https://x/a.tar.gz.sig')\n",
        )
        .await;
        assert!(
            !used.contains(&"META-002".to_string()),
            "signed source -> no META-002: {used:?}"
        );
    }
}
