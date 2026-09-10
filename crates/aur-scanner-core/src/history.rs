//! What a package looked like the last time we scanned it.
//!
//! A PKGBUILD that was clean last week and is clean today is not the same thing
//! as a PKGBUILD that was clean last week and grew a `curl | sh` today. Both
//! score identically on a single scan; only the second is an incident. Every
//! AUR supply-chain campaign on record -- the 2018 xeactor hijack, the June 2026
//! Atomic Arch wave -- worked by *changing* packages people had already decided
//! to trust, so the change itself is the signal.
//!
//! This module records a small fingerprint of each scanned package and diffs the
//! next scan against it. It deliberately stores a summary, not the file: the
//! point is to answer "what is different, and does the difference matter",
//! and keeping full copies of every PKGBUILD ever scanned is a liability with
//! no matching benefit.
//!
//! Absence of history is never a finding. The first scan of a package is
//! silent -- there is nothing to compare it to, and a tool that complains about
//! its own cold cache is noise.

use crate::types::{Category, Finding, Location, ScanResult, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// The stored fingerprint of one package as of one scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageRecord {
    /// Package name.
    pub package: String,
    /// `pkgver-pkgrel` at the time of the scan.
    pub version: String,
    /// When the scan happened.
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    /// Maintainer as the registry reported it; `None` means orphaned.
    #[serde(default)]
    pub maintainer: Option<String>,
    /// Hash of the PKGBUILD bytes.
    pub pkgbuild_hash: String,
    /// Hash of the concatenated install scriptlets and ALPM hooks, if any.
    #[serde(default)]
    pub scripts_hash: Option<String>,
    /// Upstream origins the sources point at (`host/owner/repo`), deduped.
    #[serde(default)]
    pub source_origins: BTreeSet<String>,
    /// Finding IDs raised by that scan.
    #[serde(default)]
    pub finding_ids: BTreeSet<String>,
    /// PKGBUILD function names present (`build`, `package`, `prepare`, ...).
    #[serde(default)]
    pub functions: BTreeSet<String>,
}

impl PackageRecord {
    /// Build a record from a completed scan.
    pub fn from_scan(
        result: &ScanResult,
        pkgbuild: &crate::parser::ParsedPkgbuild,
        maintainer: Option<String>,
    ) -> Self {
        let pkgbuild_hash = blake3::hash(pkgbuild.raw_content.as_bytes())
            .to_hex()
            .to_string();

        PackageRecord {
            package: result.package_name.clone(),
            version: result.package_version.clone(),
            scanned_at: result.timestamp,
            maintainer,
            pkgbuild_hash,
            scripts_hash: None,
            // ONLY remote sources. A local `source=()` entry (a patch file, a
            // .service unit) is shipped in the package directory and has no
            // upstream, but `origin_of` will happily parse `0001-fix.patch` as
            // a scheme-less host because it contains dots. Recording those made
            // adding a patch file -- the most routine change an AUR maintainer
            // makes -- emit `DIFF-003 High: now fetches from 0001-fix.patch`,
            // which is false, unreadable, and enough to trip the `--fail-on
            // high` the shell integration uses.
            source_origins: pkgbuild
                .source
                .iter()
                .filter(|s| s.protocol.is_remote())
                .filter_map(|s| crate::neturl::origin_of(&s.url))
                .collect(),
            finding_ids: result.findings.iter().map(|f| f.id.clone()).collect(),
            functions: pkgbuild.functions.keys().cloned().collect(),
        }
    }

    /// Attach the hash of every package-side script (install scriptlet, ALPM
    /// hooks). Separate from the PKGBUILD hash because a payload moving into an
    /// install hook is a distinct event worth naming.
    pub fn with_scripts(mut self, scripts: &[String]) -> Self {
        if !scripts.is_empty() {
            let mut hasher = blake3::Hasher::new();
            for s in scripts {
                hasher.update(s.as_bytes());
                hasher.update(b"\0");
            }
            self.scripts_hash = Some(hasher.finalize().to_hex().to_string());
        }
        self
    }
}

/// On-disk store of package records.
///
/// One JSON file per package under a directory the user owns. Read failures and
/// corrupt files are treated as "no history": a damaged cache must degrade to
/// the first-scan behaviour, never to an error or a false alarm.
pub struct History {
    dir: PathBuf,
}

impl History {
    /// Open (and create) the history directory.
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        // The history says which packages this user scanned and when. That is
        // nobody else's business on a shared machine.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(History { dir })
    }

    /// The default history directory (`$XDG_CACHE_HOME/aur-scan/history`).
    pub fn default_dir() -> PathBuf {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .unwrap_or_else(std::env::temp_dir);
        base.join("aur-scan").join("history")
    }

    /// Path for one package's record. The name is validated by the caller
    /// before it ever reaches here; this additionally refuses anything that is
    /// not a plain file name so a hostile package name cannot escape the dir.
    fn path_for(&self, package: &str) -> Option<PathBuf> {
        if package.is_empty()
            || package.contains('/')
            || package.contains('\\')
            || package.contains("..")
        {
            warn!("refusing to use history path for suspicious package name {package:?}");
            return None;
        }
        Some(self.dir.join(format!("{package}.json")))
    }

    /// The stored record for a package, or `None` if we have never scanned it
    /// (or the stored file is unreadable/corrupt).
    pub fn get(&self, package: &str) -> Option<PackageRecord> {
        let path = self.path_for(package)?;
        let bytes = std::fs::read(&path).ok()?;
        match serde_json::from_slice::<PackageRecord>(&bytes) {
            Ok(r) => Some(r),
            Err(e) => {
                debug!("discarding corrupt history for {package}: {e}");
                None
            }
        }
    }

    /// Store a record, replacing any previous one. Written to a temp file and
    /// renamed so an interrupted write cannot leave a truncated record behind.
    pub fn put(&self, record: &PackageRecord) -> std::io::Result<()> {
        let Some(path) = self.path_for(&record.package) else {
            return Ok(());
        };
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)
    }

    /// Every package we have a record for.
    pub fn packages(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                (p.extension()? == "json").then(|| p.file_stem()?.to_str().map(String::from))?
            })
            .collect();
        names.sort();
        names
    }

    /// Forget one package's history.
    pub fn forget(&self, package: &str) -> std::io::Result<()> {
        let Some(path) = self.path_for(package) else {
            return Ok(());
        };
        match std::fs::remove_file(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// The directory in use.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// What changed between two records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Version string changed.
    pub version: Option<(String, String)>,
    /// Maintainer changed (old, new). Either side may be `None` = orphaned.
    pub maintainer: Option<(Option<String>, Option<String>)>,
    /// The PKGBUILD bytes changed.
    pub pkgbuild_changed: bool,
    /// Install/ALPM scripts changed, were added, or were removed.
    pub scripts_changed: bool,
    /// Scripts appeared where there previously were none.
    pub scripts_added: bool,
    /// Upstream origins that are present now and were not before.
    pub origins_added: Vec<String>,
    /// Upstream origins that were present before and are gone now.
    pub origins_removed: Vec<String>,
    /// Finding IDs raised now that were not raised before.
    pub findings_added: Vec<String>,
    /// Finding IDs raised before that are no longer raised.
    pub findings_removed: Vec<String>,
    /// PKGBUILD functions that appeared.
    pub functions_added: Vec<String>,
}

impl Changes {
    /// Whether anything at all differs.
    pub fn is_empty(&self) -> bool {
        self.version.is_none()
            && self.maintainer.is_none()
            && !self.pkgbuild_changed
            && !self.scripts_changed
            && self.origins_added.is_empty()
            && self.origins_removed.is_empty()
            && self.findings_added.is_empty()
            && self.findings_removed.is_empty()
            && self.functions_added.is_empty()
    }
}

/// Compare a previous record against the current one.
pub fn compare(before: &PackageRecord, after: &PackageRecord) -> Changes {
    let diff = |a: &BTreeSet<String>, b: &BTreeSet<String>| -> Vec<String> {
        b.difference(a).cloned().collect()
    };

    Changes {
        version: (before.version != after.version)
            .then(|| (before.version.clone(), after.version.clone())),
        maintainer: (before.maintainer != after.maintainer)
            .then(|| (before.maintainer.clone(), after.maintainer.clone())),
        pkgbuild_changed: before.pkgbuild_hash != after.pkgbuild_hash,
        scripts_changed: before.scripts_hash != after.scripts_hash,
        scripts_added: before.scripts_hash.is_none() && after.scripts_hash.is_some(),
        origins_added: diff(&before.source_origins, &after.source_origins),
        origins_removed: diff(&after.source_origins, &before.source_origins),
        findings_added: diff(&before.finding_ids, &after.finding_ids),
        findings_removed: diff(&after.finding_ids, &before.finding_ids),
        functions_added: diff(&before.functions, &after.functions),
    }
}

/// Split a set of findings into those newly raised since `before` and the rest.
pub fn newly_raised<'a>(before: &PackageRecord, findings: &'a [Finding]) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| !before.finding_ids.contains(&f.id))
        .collect()
}

/// The most severe severity among a set of findings, if any.
pub fn peak_severity(findings: &[&Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).min()
}

/// Turn a comparison into findings.
///
/// These describe *movement*, and are deliberately scoped to movement that a
/// reader could act on. A version bump on its own is not reported: packages
/// update constantly and a tool that says so every time is a tool people mute.
/// What is reported is risk that appeared, ownership that moved, upstream that
/// moved, and an install-time execution path that did not previously exist.
pub fn findings_for_changes(
    before: &PackageRecord,
    after: &PackageRecord,
    changes: &Changes,
    current_findings: &[Finding],
    file: &Path,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let loc = |file: &Path| Location {
        file: file.to_path_buf(),
        line: None,
        column: None,
        snippet: None,
    };
    let since = before.scanned_at.format("%Y-%m-%d");

    // DIFF-001 -- risk that is new since the last time this package was
    // approved. Severity tracks the worst new finding: a package that has
    // always had a SKIP checksum is not news, one that just grew a curl|sh is.
    let new_findings = newly_raised(before, current_findings);
    if let Some(peak) = peak_severity(&new_findings) {
        let ids: Vec<String> = new_findings.iter().map(|f| f.id.clone()).collect();
        let titles: Vec<String> = new_findings
            .iter()
            .map(|f| format!("{} ({})", f.id, f.title))
            .collect();
        out.push(Finding {
            id: "DIFF-001".to_string(),
            severity: peak,
            category: Category::SuspiciousMetadata,
            title: format!("{} new finding(s) since {since}", new_findings.len()),
            description: format!(
                "This package raised {} finding(s) that it did not raise when it was last \
                 scanned on {since} at version {}. It is now version {}. New risk in a package \
                 you already reviewed is how supply-chain compromise actually presents: {}.",
                new_findings.len(),
                before.version,
                after.version,
                titles.join("; ")
            ),
            location: loc(file),
            recommendation: "Review the new findings specifically -- these are the changes since \
                             you last looked at this package."
                .to_string(),
            cwe_id: None,
            metadata: serde_json::json!({
                "new_finding_ids": ids,
                "previous_version": before.version,
                "current_version": after.version,
                "previously_scanned": before.scanned_at,
            }),
        });
    }

    // DIFF-002 -- ownership moved.
    //
    // Adoption of an orphan is called out at High and separately from an
    // ordinary handover: it is the exact mechanism of both the 2018 xeactor
    // hijack and the June 2026 Atomic Arch campaign, where abandoned packages
    // were picked up specifically in order to modify them.
    if let Some((old, new)) = &changes.maintainer {
        let (severity, title, description) = match (old, new) {
            (None, Some(new_m)) => (
                Severity::High,
                "Orphaned package has been adopted".to_string(),
                format!(
                    "'{}' was orphaned when it was last scanned on {since} and is now maintained \
                     by '{new_m}'. Adopting an abandoned package is the documented entry point \
                     for the 2018 xeactor hijack and the 2026 Atomic Arch campaign -- the new \
                     maintainer inherits every existing install.",
                    after.package
                ),
            ),
            (Some(old_m), None) => (
                Severity::Medium,
                "Package has been orphaned".to_string(),
                format!(
                    "'{}' was maintained by '{old_m}' on {since} and is now orphaned. Nobody is \
                     responsible for it, and it can be adopted by anyone.",
                    after.package
                ),
            ),
            (Some(old_m), Some(new_m)) => (
                Severity::Medium,
                "Maintainer changed".to_string(),
                format!(
                    "'{}' was maintained by '{old_m}' on {since} and is now maintained by \
                     '{new_m}'. Handovers are normal; this is worth a look alongside what else \
                     changed in the same window.",
                    after.package
                ),
            ),
            (None, None) => unreachable!("compare() only sets this when the values differ"),
        };
        out.push(Finding {
            id: "DIFF-002".to_string(),
            severity,
            category: Category::SuspiciousMetadata,
            title,
            description,
            location: loc(file),
            recommendation: "Confirm the handover is legitimate before installing an update."
                .to_string(),
            cwe_id: None,
            metadata: serde_json::json!({
                "previous_maintainer": old,
                "current_maintainer": new,
                "previously_scanned": before.scanned_at,
            }),
        });
    }

    // DIFF-003 -- the package now fetches from somewhere it did not before.
    //
    // Compared at host/owner/repo, so a new tag or release tarball under the
    // same project is NOT a change. A new owner for the same repo name is the
    // fork-impersonation pattern.
    if !changes.origins_added.is_empty() {
        out.push(Finding {
            id: "DIFF-003".to_string(),
            severity: Severity::High,
            category: Category::NetworkSecurity,
            title: "Package fetches from a new upstream".to_string(),
            description: format!(
                "'{}' now fetches from {} which it did not use when last scanned on {since}{}. \
                 Source URLs are compared at host/owner/repo, so ordinary version bumps do not \
                 appear here -- upstream itself moved.",
                after.package,
                changes.origins_added.join(", "),
                if changes.origins_removed.is_empty() {
                    String::new()
                } else {
                    format!(" (no longer using {})", changes.origins_removed.join(", "))
                }
            ),
            location: loc(file),
            recommendation: "Verify the new upstream is the project's real home and not a fork \
                             impersonating it."
                .to_string(),
            cwe_id: Some("CWE-494".to_string()),
            metadata: serde_json::json!({
                "origins_added": changes.origins_added,
                "origins_removed": changes.origins_removed,
                "previously_scanned": before.scanned_at,
            }),
        });
    }

    // DIFF-004 -- an install-time execution path appeared where there was none.
    //
    // Install scriptlets and ALPM hooks run as root at install time. A package
    // that never had one growing one is the Atomic Arch delivery path exactly,
    // and it is invisible to a severity-only comparison because the scriptlet
    // may be perfectly clean on the day it appears.
    if changes.scripts_added {
        out.push(Finding {
            id: "DIFF-004".to_string(),
            severity: Severity::High,
            category: Category::Persistence,
            title: "Package gained an install script".to_string(),
            description: format!(
                "'{}' had no install scriptlet or ALPM hook when it was last scanned on {since}, \
                 and now has one. Install scripts run as root at install time; acquiring one is \
                 a change in what the package is able to do to the system, whatever the script \
                 currently contains.",
                after.package
            ),
            location: loc(file),
            recommendation: "Read the new install script in full before installing.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            metadata: serde_json::json!({ "previously_scanned": before.scanned_at }),
        });
    } else if changes.scripts_changed {
        out.push(Finding {
            id: "DIFF-004".to_string(),
            severity: Severity::Medium,
            category: Category::Persistence,
            title: "Install script changed".to_string(),
            description: format!(
                "The install scriptlet or ALPM hook of '{}' differs from the one seen on {since}. \
                 This code runs as root at install time.",
                after.package
            ),
            location: loc(file),
            recommendation: "Read the changed install script before installing.".to_string(),
            cwe_id: None,
            metadata: serde_json::json!({ "previously_scanned": before.scanned_at }),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str) -> PackageRecord {
        PackageRecord {
            package: name.into(),
            version: "1.0-1".into(),
            scanned_at: chrono::Utc::now(),
            maintainer: Some("alice".into()),
            pkgbuild_hash: "aaaa".into(),
            scripts_hash: None,
            source_origins: ["github.com/alice/tool".to_string()].into_iter().collect(),
            finding_ids: ["CHK-004".to_string()].into_iter().collect(),
            functions: ["build".to_string()].into_iter().collect(),
        }
    }

    fn finding(id: &str, sev: Severity) -> Finding {
        Finding {
            id: id.into(),
            severity: sev,
            category: Category::MaliciousCode,
            title: format!("{id} title"),
            description: String::new(),
            location: Location {
                file: "PKGBUILD".into(),
                line: None,
                column: None,
                snippet: None,
            },
            recommendation: String::new(),
            cwe_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    fn diff_findings(
        before: &PackageRecord,
        after: &PackageRecord,
        current: &[Finding],
    ) -> Vec<Finding> {
        let c = compare(before, after);
        findings_for_changes(before, after, &c, current, Path::new("PKGBUILD"))
    }

    fn ids_of(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    #[test]
    fn an_unchanged_package_produces_no_diff_findings() {
        let a = rec("tool");
        let current = vec![finding("CHK-004", Severity::Medium)];
        assert!(diff_findings(&a, &a.clone(), &current).is_empty());
    }

    #[test]
    fn a_plain_version_bump_alone_is_not_reported() {
        // Packages update constantly. A tool that says so every time gets muted.
        let before = rec("tool");
        let mut after = before.clone();
        after.version = "1.1-1".into();
        after.pkgbuild_hash = "bbbb".into();
        let current = vec![finding("CHK-004", Severity::Medium)];
        let f = diff_findings(&before, &after, &current);
        assert!(
            f.is_empty(),
            "a version bump with no new risk must be silent: {:?}",
            ids_of(&f)
        );
    }

    #[test]
    fn new_risk_since_last_scan_is_diff001_at_the_new_severity() {
        let before = rec("tool");
        let mut after = before.clone();
        after.finding_ids.insert("DLE-001".into());
        let current = vec![
            finding("CHK-004", Severity::Medium),
            finding("DLE-001", Severity::Critical),
        ];
        let f = diff_findings(&before, &after, &current);
        let d = f.iter().find(|x| x.id == "DIFF-001").expect("must fire");
        assert_eq!(
            d.severity,
            Severity::Critical,
            "severity tracks the new finding"
        );
        assert!(d.description.contains("DLE-001"));
        // The pre-existing CHK-004 must not be described as new.
        let ids = d.metadata["new_finding_ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "DLE-001");
    }

    #[test]
    fn a_resolved_finding_does_not_raise_diff001() {
        let before = rec("tool");
        let mut after = before.clone();
        after.finding_ids.clear();
        let f = diff_findings(&before, &after, &[]);
        assert!(!ids_of(&f).contains(&"DIFF-001"));
    }

    #[test]
    fn adoption_of_an_orphan_is_high() {
        // The xeactor / Atomic Arch mechanism.
        let mut before = rec("tool");
        before.maintainer = None;
        let mut after = before.clone();
        after.maintainer = Some("mallory".into());
        let f = diff_findings(&before, &after, &[]);
        let d = f.iter().find(|x| x.id == "DIFF-002").expect("must fire");
        assert_eq!(d.severity, Severity::High);
        assert!(d.title.contains("adopted"));
    }

    #[test]
    fn an_ordinary_handover_is_medium_not_high() {
        let before = rec("tool");
        let mut after = before.clone();
        after.maintainer = Some("bob".into());
        let f = diff_findings(&before, &after, &[]);
        let d = f.iter().find(|x| x.id == "DIFF-002").unwrap();
        assert_eq!(d.severity, Severity::Medium);
        assert!(d.description.contains("alice"));
        assert!(d.description.contains("bob"));
    }

    #[test]
    fn a_package_becoming_orphaned_is_reported() {
        let before = rec("tool");
        let mut after = before.clone();
        after.maintainer = None;
        let f = diff_findings(&before, &after, &[]);
        let d = f.iter().find(|x| x.id == "DIFF-002").unwrap();
        assert!(d.title.contains("orphaned"));
    }

    #[test]
    fn a_new_upstream_origin_is_diff003() {
        let before = rec("tool");
        let mut after = before.clone();
        after.source_origins.insert("cdn.evil.example/x".into());
        let f = diff_findings(&before, &after, &[]);
        let d = f.iter().find(|x| x.id == "DIFF-003").expect("must fire");
        assert_eq!(d.severity, Severity::High);
        assert!(d.description.contains("cdn.evil.example/x"));
    }

    #[test]
    fn gaining_an_install_script_is_high_changing_one_is_medium() {
        let before = rec("tool");

        let mut gained = before.clone();
        gained.scripts_hash = Some("bbbb".into());
        let f = diff_findings(&before, &gained, &[]);
        let d = f.iter().find(|x| x.id == "DIFF-004").expect("must fire");
        assert_eq!(
            d.severity,
            Severity::High,
            "acquiring one is the bigger event"
        );
        assert!(d.title.contains("gained"));

        let mut had = before.clone();
        had.scripts_hash = Some("bbbb".into());
        let mut changed = had.clone();
        changed.scripts_hash = Some("cccc".into());
        let f2 = diff_findings(&had, &changed, &[]);
        let d2 = f2.iter().find(|x| x.id == "DIFF-004").unwrap();
        assert_eq!(d2.severity, Severity::Medium);
    }

    #[test]
    fn a_compromise_shaped_change_raises_everything_relevant() {
        // Orphan adopted, upstream moved, install script appeared, new critical
        // finding -- all at once, which is what a real hijack looks like.
        let mut before = rec("tool");
        before.maintainer = None;
        let mut after = before.clone();
        after.maintainer = Some("mallory".into());
        after.source_origins.insert("cdn.evil.example/p".into());
        after.scripts_hash = Some("bbbb".into());
        after.finding_ids.insert("DLE-001".into());
        let current = vec![
            finding("CHK-004", Severity::Medium),
            finding("DLE-001", Severity::Critical),
        ];
        let f = diff_findings(&before, &after, &current);
        let ids = ids_of(&f);
        for want in ["DIFF-001", "DIFF-002", "DIFF-003", "DIFF-004"] {
            assert!(ids.contains(&want), "missing {want}: {ids:?}");
        }
    }

    /// Build a record the way a real scan does, from parsed PKGBUILD text.
    fn record_from_source(pkgbuild_src: &str) -> PackageRecord {
        use crate::parser::{PkgbuildParser, StaticParser};
        let parsed = StaticParser::new().parse(pkgbuild_src).unwrap();
        let result = ScanResult {
            package_name: "tool".into(),
            package_version: parsed.pkgver.clone(),
            findings: vec![],
            scanned_files: vec![],
            timestamp: chrono::Utc::now(),
            scan_duration_ms: 0,
        };
        PackageRecord::from_scan(&result, &parsed, Some("alice".into()))
    }

    #[test]
    fn local_source_files_are_not_upstream_origins() {
        // Regression: adding a patch file or a .service unit to source=() is
        // the most routine change an AUR maintainer makes. `origin_of` parses
        // `0001-fix-build.patch` as a scheme-less host because it has dots, so
        // recording every source made this emit
        //   DIFF-003 High: 'tool' now fetches from 0001-fix-build.patch
        // -- false, unreadable, and enough to trip the `--fail-on high` the
        // shell integration uses. Only remote protocols are origins.
        let before = record_from_source(
            "pkgname=tool\npkgver=1.0\npkgrel=1\nsource=(\"https://github.com/alice/tool/archive/v1.0.tar.gz\")\n",
        );
        let after = record_from_source(
            "pkgname=tool\npkgver=1.1\npkgrel=1\nsource=(\"https://github.com/alice/tool/archive/v1.1.tar.gz\"\n        \"0001-fix-build.patch\"\n        \"tool.service\")\n",
        );

        assert_eq!(
            before.source_origins,
            ["github.com/alice/tool".to_string()].into_iter().collect(),
            "only the remote source is an origin"
        );
        assert_eq!(
            after.source_origins,
            ["github.com/alice/tool".to_string()].into_iter().collect(),
            "local files must not appear as origins: {:?}",
            after.source_origins
        );

        let changes = compare(&before, &after);
        assert!(
            changes.origins_added.is_empty(),
            "adding local files must not read as a new upstream: {:?}",
            changes.origins_added
        );
        let findings = findings_for_changes(&before, &after, &changes, &[], Path::new("PKGBUILD"));
        assert!(
            !findings.iter().any(|f| f.id == "DIFF-003"),
            "adding a patch file must not fire DIFF-003: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_genuinely_new_remote_source_is_still_an_origin() {
        // The guard above must not silence the real signal.
        let before = record_from_source(
            "pkgname=tool\npkgver=1.0\npkgrel=1\nsource=(\"https://github.com/alice/tool/archive/v1.0.tar.gz\")\n",
        );
        let after = record_from_source(
            "pkgname=tool\npkgver=1.1\npkgrel=1\nsource=(\"https://github.com/alice/tool/archive/v1.1.tar.gz\"\n        \"https://cdn.evil.example/payload.bin\")\n",
        );
        let changes = compare(&before, &after);
        assert_eq!(changes.origins_added, vec!["cdn.evil.example/payload.bin"]);
        let findings = findings_for_changes(&before, &after, &changes, &[], Path::new("PKGBUILD"));
        assert!(findings.iter().any(|f| f.id == "DIFF-003"));
    }

    #[test]
    fn identical_records_show_no_changes() {
        let a = rec("tool");
        assert!(compare(&a, &a.clone()).is_empty());
    }

    #[test]
    fn detects_a_maintainer_change() {
        let before = rec("tool");
        let mut after = before.clone();
        after.maintainer = Some("mallory".into());
        let c = compare(&before, &after);
        assert_eq!(
            c.maintainer,
            Some((Some("alice".into()), Some("mallory".into())))
        );
        assert!(!c.is_empty());
    }

    #[test]
    fn detects_adoption_of_an_orphan() {
        // The Atomic Arch pattern: orphaned package acquires a maintainer.
        let mut before = rec("tool");
        before.maintainer = None;
        let mut after = before.clone();
        after.maintainer = Some("mallory".into());
        let c = compare(&before, &after);
        assert_eq!(c.maintainer, Some((None, Some("mallory".into()))));
    }

    #[test]
    fn detects_a_new_source_origin() {
        let before = rec("tool");
        let mut after = before.clone();
        after
            .source_origins
            .insert("cdn.evil.example/payload".into());
        let c = compare(&before, &after);
        assert_eq!(c.origins_added, vec!["cdn.evil.example/payload"]);
        assert!(c.origins_removed.is_empty());
    }

    #[test]
    fn detects_a_newly_raised_finding() {
        let before = rec("tool");
        let mut after = before.clone();
        after.finding_ids.insert("DLE-001".into());
        let c = compare(&before, &after);
        assert_eq!(c.findings_added, vec!["DLE-001"]);
        // The pre-existing one is not re-reported as new.
        assert!(!c.findings_added.contains(&"CHK-004".to_string()));
    }

    #[test]
    fn detects_a_resolved_finding() {
        let before = rec("tool");
        let mut after = before.clone();
        after.finding_ids.clear();
        let c = compare(&before, &after);
        assert_eq!(c.findings_removed, vec!["CHK-004"]);
    }

    #[test]
    fn detects_an_install_script_appearing() {
        // A package that never had an install scriptlet growing one is the
        // Atomic Arch delivery path exactly.
        let before = rec("tool");
        let mut after = before.clone();
        after.scripts_hash = Some("bbbb".into());
        let c = compare(&before, &after);
        assert!(c.scripts_changed);
        assert!(c.scripts_added);
    }

    #[test]
    fn detects_a_new_build_function() {
        let before = rec("tool");
        let mut after = before.clone();
        after.functions.insert("package".into());
        let c = compare(&before, &after);
        assert_eq!(c.functions_added, vec!["package"]);
    }

    #[test]
    fn newly_raised_filters_out_known_findings() {
        use crate::types::{Category, Location};
        let before = rec("tool");
        let mk = |id: &str, sev: Severity| Finding {
            id: id.into(),
            severity: sev,
            category: Category::MaliciousCode,
            title: String::new(),
            description: String::new(),
            location: Location {
                file: "PKGBUILD".into(),
                line: None,
                column: None,
                snippet: None,
            },
            recommendation: String::new(),
            cwe_id: None,
            metadata: serde_json::Value::Null,
        };
        let findings = vec![
            mk("CHK-004", Severity::Medium),
            mk("DLE-001", Severity::Critical),
        ];
        let new = newly_raised(&before, &findings);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].id, "DLE-001");
        assert_eq!(peak_severity(&new), Some(Severity::Critical));
    }

    #[test]
    fn store_round_trips_a_record() {
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-{}", std::process::id()));
        let h = History::open(dir.clone()).unwrap();
        let r = rec("round-trip-tool");
        assert!(h.get("round-trip-tool").is_none(), "starts empty");
        h.put(&r).unwrap();
        assert_eq!(h.get("round-trip-tool").as_ref(), Some(&r));
        assert!(h.packages().contains(&"round-trip-tool".to_string()));
        h.forget("round-trip-tool").unwrap();
        assert!(h.get("round-trip-tool").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_record_reads_as_no_history() {
        // A damaged cache must behave like a first scan, not raise an error and
        // not invent a change.
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-bad-{}", std::process::id()));
        let h = History::open(dir.clone()).unwrap();
        std::fs::write(dir.join("busted.json"), b"{not json").unwrap();
        assert!(h.get("busted").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_traversal_in_a_package_name_is_refused() {
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-trav-{}", std::process::id()));
        let h = History::open(dir.clone()).unwrap();
        for bad in ["../../etc/passwd", "a/b", "..", ""] {
            assert!(h.path_for(bad).is_none(), "{bad:?} must be refused");
            assert!(h.get(bad).is_none());
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
