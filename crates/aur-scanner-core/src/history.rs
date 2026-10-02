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
    /// What produced `finding_ids`: scanner version plus the reporting
    /// threshold.
    ///
    /// `finding_ids` is not a property of the package alone -- the engine
    /// filters by `min_severity` and by whichever rules are loaded. Without
    /// this, raising the threshold, dropping in a rules.d file, or simply
    /// UPGRADING the scanner makes previously-absent IDs look like new risk,
    /// and DIFF-001 announces "N new finding(s) since <date>" about a package
    /// whose bytes never changed. After a 2.1 -> 2.2 upgrade that fires for
    /// every package in the store at once.
    ///
    /// `None` on records written before this field existed, which is treated
    /// the same as a mismatch.
    #[serde(default)]
    pub analysis_fingerprint: Option<String>,
}

/// Identify the analysis inputs that determine which findings a scan produces.
pub fn analysis_fingerprint(min_severity: crate::types::Severity) -> String {
    format!("v{}/{:?}", crate::VERSION, min_severity)
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
            analysis_fingerprint: None,
        }
    }

    /// Record which analysis inputs produced `finding_ids`.
    pub fn with_fingerprint(mut self, fingerprint: String) -> Self {
        self.analysis_fingerprint = Some(fingerprint);
        self
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

/// The effective user id, for building a per-user fallback path.
#[cfg(unix)]
fn users_uid() -> u32 {
    // SAFETY: geteuid() is always successful and has no preconditions.
    unsafe { libc_geteuid() }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

#[cfg(not(unix))]
fn users_uid() -> u32 {
    0
}

/// Which namespace a record belongs to.
///
/// Records are keyed by package NAME, and for a `--local` directory that name
/// is whatever the PKGBUILD declares about itself. Without separation, scanning
/// a local directory that declares `pkgname=firefox` overwrites the baseline
/// for the real AUR `firefox` -- and because the `DIFF-*` codes are pure deltas
/// against the stored record, a poisoned baseline does not raise a false alarm,
/// it *silences* the next real change.
///
/// Refusing to record local scans was the first fix and was wrong: it broke the
/// documented `aur-scan check --local ./pkg` workflow, where re-scanning your
/// own package directory and seeing what changed is the entire point. Separate
/// namespaces keep both properties -- local scans diff against local scans, and
/// can never touch an AUR package's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Identity came from the AUR: the name is authoritative.
    Aur,
    /// Identity is self-declared by a directory on disk.
    Local,
}

impl Scope {
    fn subdir(self) -> Option<&'static str> {
        match self {
            Scope::Aur => None,
            Scope::Local => Some("local"),
        }
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
    /// Records for packages whose identity came from the AUR.
    pub const AUR: Scope = Scope::Aur;
    /// Records for packages whose identity is self-declared by a directory.
    pub const LOCAL: Scope = Scope::Local;

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
            // Last resort: a PER-USER subdirectory of the temp dir, never the
            // shared temp dir itself. /tmp is world-writable, so a fixed path
            // there can be pre-created (or symlinked) by another local user,
            // who then controls the baseline this scanner diffs against -- and
            // a poisoned baseline silences the next real change rather than
            // raising a false alarm.
            .unwrap_or_else(|| {
                let uid = users_uid();
                std::env::temp_dir().join(format!("aur-scan-{uid}"))
            });
        base.join("aur-scan").join("history")
    }

    /// Path for one package's record. The name is validated by the caller
    /// before it ever reaches here; this additionally refuses anything that is
    /// not a plain file name so a hostile package name cannot escape the dir.
    fn path_for(&self, package: &str, scope: Scope) -> Option<PathBuf> {
        if package.is_empty()
            || package.contains('/')
            || package.contains('\\')
            || package.contains("..")
        {
            warn!("refusing to use history path for suspicious package name {package:?}");
            return None;
        }
        let base = match scope.subdir() {
            Some(sub) => self.dir.join(sub),
            None => self.dir.clone(),
        };
        Some(base.join(format!("{package}.json")))
    }

    /// The stored record for a package, or `None` if we have never scanned it
    /// (or the stored file is unreadable/corrupt).
    pub fn get(&self, package: &str, scope: Scope) -> Option<PackageRecord> {
        let path = self.path_for(package, scope)?;
        let bytes = std::fs::read(&path).ok()?;
        match serde_json::from_slice::<PackageRecord>(&bytes) {
            Ok(r) => Some(r),
            Err(e) => {
                debug!("discarding corrupt history for {package}: {e}");
                None
            }
        }
    }

    /// Store a record, replacing any previous one.
    ///
    /// Written to a **process-private** temp file and renamed, so that neither
    /// an interrupted write nor a concurrent one can publish a partial record.
    ///
    /// The temp name carries a pid and a per-call counter deliberately. A fixed
    /// `<pkg>.json.tmp` is
    /// shared by every process scanning that package, and `fs::write` truncates
    /// in place: two concurrent scans interleave their bytes and whichever
    /// renames last publishes the mixture. That fails quietly in the worst
    /// direction — `get()` swallows the unparseable result as "no history", so
    /// change detection silently switches off for that package with nothing
    /// above a `debug!` to say so. The pacman hook and an interactive
    /// `aur-scan check` can easily overlap, and a dependency tree writes a
    /// record for every transitive node.
    ///
    /// Permissions are set on the temp file *before* the content is written, so
    /// there is no window in which a complete record sits at the default mode.
    pub fn put(&self, record: &PackageRecord, scope: Scope) -> std::io::Result<()> {
        let Some(path) = self.path_for(&record.package, scope) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        // Unique per CALL, not merely per process: a pid alone still collides
        // between threads or concurrent async tasks inside one process, which
        // the race test below demonstrates. pid disambiguates across processes,
        // the counter across everything within one.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("json.tmp.{}.{seq}", std::process::id()));
        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Create with restrictive permissions from the outset rather than
        // chmod-ing after the bytes are already on disk.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let write_result = opts.open(&tmp).and_then(|mut f| {
            use std::io::Write;
            f.write_all(&json)?;
            f.sync_all()
        });
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        // Atomic publish. If this fails, drop the temp file rather than leaving
        // per-pid litter in the cache directory.
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Drop records that are old enough to be useless, and cap the total count.
    ///
    /// A record is a few hundred bytes, so this is not about disk. It is about
    /// the store being a permanent, ever-growing list of every AUR package this
    /// user has ever looked at, kept indefinitely with no way to age out. That
    /// is a privacy liability that grows on its own, and nothing was ever
    /// removing anything.
    ///
    /// Two bounds, both generous, because deleting a baseline costs real
    /// security value -- the next scan of that package silently becomes a first
    /// scan:
    ///
    /// * **Age.** A record older than `max_age_days` describes a package the
    ///   user has not touched in a long time; diffing against it would mostly
    ///   report the intervening year of ordinary updates.
    /// * **Count.** Past `max_records`, the oldest are dropped first, so an
    ///   unbounded dependency closure cannot grow the store forever.
    ///
    /// Returns how many records were removed. Every failure is ignored: pruning
    /// is housekeeping and must never interfere with a scan.
    pub fn prune(&self, max_age_days: u64, max_records: usize) -> usize {
        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for dir in [self.dir.clone(), self.dir.join("local")] {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                let modified = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                entries.push((modified, p));
            }
        }

        let mut removed = 0usize;
        let cutoff = std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(
            max_age_days.saturating_mul(86_400),
        ));

        // Oldest first, so the count cap drops the least useful records.
        entries.sort_by_key(|(t, _)| *t);

        let over_by = entries.len().saturating_sub(max_records);
        for (i, (modified, path)) in entries.iter().enumerate() {
            let too_old = cutoff.is_some_and(|c| *modified < c);
            let over_cap = i < over_by;
            if (too_old || over_cap) && std::fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            debug!("pruned {removed} history record(s)");
        }
        removed
    }

    /// Default bounds: a year of history, and 5,000 records.
    ///
    /// 5,000 is far above any real dependency closure -- the whole AUR is
    /// ~119,000 packages and a heavy user installs a few hundred -- so the count
    /// cap is a runaway backstop, not a working limit. The age cap is what
    /// actually keeps the store from being a permanent record.
    pub const DEFAULT_MAX_AGE_DAYS: u64 = 365;
    pub const DEFAULT_MAX_RECORDS: usize = 5_000;

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
    pub fn forget(&self, package: &str, scope: Scope) -> std::io::Result<()> {
        let Some(path) = self.path_for(package, scope) else {
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

    // Only diff FINDINGS when both sides were produced by the same analysis
    // inputs. A scanner upgrade or a threshold change alters which IDs appear
    // without the package changing at all, and reporting that as "new risk"
    // would be a false statement of fact in the one output users act on.
    //
    // The structural signals below (ownership, upstream, scripts) are
    // properties of the PACKAGE, not of the ruleset, so they stay comparable.
    let comparable_findings = before.analysis_fingerprint.is_some()
        && before.analysis_fingerprint == after.analysis_fingerprint;

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
        findings_added: if comparable_findings {
            diff(&before.finding_ids, &after.finding_ids)
        } else {
            Vec::new()
        },
        findings_removed: if comparable_findings {
            diff(&after.finding_ids, &before.finding_ids)
        } else {
            Vec::new()
        },
        functions_added: diff(&before.functions, &after.functions),
    }
}

/// Split a set of findings into those newly raised since `before` and the rest.
pub fn newly_raised<'a>(
    before: &PackageRecord,
    after: &PackageRecord,
    findings: &'a [Finding],
) -> Vec<&'a Finding> {
    // Same rule as `compare`: without matching analysis inputs there is no
    // meaningful "new since last time".
    if before.analysis_fingerprint.is_none()
        || before.analysis_fingerprint != after.analysis_fingerprint
    {
        return Vec::new();
    }
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
    let new_findings = newly_raised(before, after, current_findings);
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
    } else if changes.scripts_changed && after.scripts_hash.is_none() {
        // Removed, not changed. Saying "runs as root" about a script that no
        // longer exists is simply wrong, and this is the safe direction of
        // travel -- worth noting, not worth alarming about.
        out.push(Finding {
            id: "DIFF-004".to_string(),
            severity: Severity::Low,
            category: Category::Persistence,
            title: "Install script removed".to_string(),
            description: format!(
                "'{}' had an install scriptlet or ALPM hook on {since} and no longer does. \
                 Losing an install-time execution path is the safe direction; noted because it \
                 is a change to what the package can do.",
                after.package
            ),
            location: loc(file),
            recommendation: "No action needed; noted for completeness.".to_string(),
            cwe_id: None,
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
            // Same inputs on both sides, so findings are comparable by default
            // in these tests; the mismatch case is covered explicitly below.
            analysis_fingerprint: Some("test-fp".to_string()),
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
        // The identity is the HOST here: `payload.bin` names a release artifact,
        // not a project, and including it would make every version bump on a
        // self-hosted tarball look like an upstream move.
        assert_eq!(changes.origins_added, vec!["cdn.evil.example"]);
        let findings = findings_for_changes(&before, &after, &changes, &[], Path::new("PKGBUILD"));
        assert!(findings.iter().any(|f| f.id == "DIFF-003"));
    }

    #[test]
    fn a_scanner_upgrade_does_not_fabricate_new_findings() {
        // finding_ids depends on the ruleset and the reporting threshold, not
        // just on the package. Upgrading the scanner (which adds codes) or
        // changing min_severity must not make a byte-identical package report
        // "N new finding(s) since <date>" -- that would fire for every recorded
        // package at once on the first run after an upgrade.
        let mut before = rec("tool");
        before.analysis_fingerprint = Some("v2.1.0/Low".into());
        let mut after = before.clone();
        after.analysis_fingerprint = Some("v2.2.0/Low".into());
        after.finding_ids.insert("SQUAT-001".into());

        let c = compare(&before, &after);
        assert!(
            c.findings_added.is_empty(),
            "a different ruleset makes the findings delta meaningless: {:?}",
            c.findings_added
        );
        assert!(c.findings_removed.is_empty());

        // But structural signals are properties of the PACKAGE, so they survive.
        let mut moved = after.clone();
        moved.maintainer = Some("mallory".into());
        moved.source_origins.insert("cdn.evil.example".into());
        let c2 = compare(&before, &moved);
        assert!(
            c2.maintainer.is_some(),
            "ownership change must still report"
        );
        assert_eq!(c2.origins_added, vec!["cdn.evil.example"]);
    }

    #[test]
    fn a_record_with_no_fingerprint_is_not_findings_comparable() {
        // Records written before the field existed.
        let mut before = rec("tool");
        before.analysis_fingerprint = None;
        let mut after = before.clone();
        after.analysis_fingerprint = Some("v2.2.0/Low".into());
        after.finding_ids.insert("DLE-001".into());
        assert!(compare(&before, &after).findings_added.is_empty());
    }

    #[test]
    fn matching_fingerprints_still_report_real_new_risk() {
        let before = rec("tool");
        let mut after = before.clone();
        after.finding_ids.insert("DLE-001".into());
        assert_eq!(compare(&before, &after).findings_added, vec!["DLE-001"]);
    }

    #[test]
    fn a_removed_install_script_is_not_reported_as_changed() {
        // "the install script changed ... this code runs as root" is simply
        // false when the script is gone, and removal is the safe direction.
        let mut before = rec("tool");
        before.scripts_hash = Some("aaaa".into());
        let mut after = before.clone();
        after.scripts_hash = None;
        let c = compare(&before, &after);
        let f = findings_for_changes(&before, &after, &c, &[], Path::new("PKGBUILD"));
        let d = f.iter().find(|x| x.id == "DIFF-004").expect("must note it");
        assert_eq!(d.severity, Severity::Low);
        assert!(d.title.contains("removed"), "{}", d.title);
        assert!(!d.description.contains("runs as root"), "{}", d.description);
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
        let new = newly_raised(&before, &before, &findings);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].id, "DLE-001");
        assert_eq!(peak_severity(&new), Some(Severity::Critical));
    }

    #[test]
    fn store_round_trips_a_record() {
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-{}", std::process::id()));
        let h = History::open(dir.clone()).unwrap();
        let r = rec("round-trip-tool");
        assert!(
            h.get("round-trip-tool", Scope::Aur).is_none(),
            "starts empty"
        );
        h.put(&r, Scope::Aur).unwrap();
        assert_eq!(h.get("round-trip-tool", Scope::Aur).as_ref(), Some(&r));
        assert!(h.packages().contains(&"round-trip-tool".to_string()));
        h.forget("round-trip-tool", Scope::Aur).unwrap();
        assert!(h.get("round-trip-tool", Scope::Aur).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_writers_never_publish_a_mixed_record() {
        // Two writers with different-sized payloads racing on the same package.
        // With a shared temp name they interleave and publish a mixture, which
        // `get()` then swallows as "no history" -- change detection silently
        // off. Each writer must own its own temp file.
        use std::sync::Arc;
        let dir = std::env::temp_dir().join(format!(
            "aur-scan-hist-race-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let h = Arc::new(History::open(dir.clone()).unwrap());

        let mut small = rec("racer");
        small.version = "1.0-1".into();
        let mut big = rec("racer");
        big.version = "2.0-1".into();
        // Make the payloads very different lengths so a torn write would not
        // accidentally still parse.
        for i in 0..200 {
            big.finding_ids.insert(format!("PAD-{i:03}"));
        }

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let h = Arc::clone(&h);
                let r = if i % 2 == 0 {
                    small.clone()
                } else {
                    big.clone()
                };
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        h.put(&r, Scope::Aur).unwrap();
                    }
                })
            })
            .collect();
        for t in handles {
            t.join().unwrap();
        }

        // Whoever won, the published record must be one of the two INTACT
        // records, never a blend and never unreadable.
        let got = h
            .get("racer", Scope::Aur)
            .expect("a readable record must survive");
        assert!(
            got == small || got == big,
            "published record is neither writer's input -- torn write"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_enforces_the_count_cap_oldest_first() {
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = History::open(dir.clone()).unwrap();

        // Write 10 records with increasing mtimes.
        for i in 0..10 {
            let mut r = rec(&format!("pkg{i:02}"));
            r.version = format!("{i}.0-1");
            h.put(&r, Scope::Aur).unwrap();
            // Force a distinguishable mtime ordering without sleeping.
            let path = dir.join(format!("pkg{i:02}.json"));
            let t = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_700_000_000 + i * 60);
            let f = std::fs::File::options().write(true).open(&path).unwrap();
            f.set_modified(t).unwrap();
        }
        assert_eq!(h.packages().len(), 10);

        // Keep 4. The six oldest go.
        let removed = h.prune(u64::MAX, 4);
        assert_eq!(removed, 6, "should drop exactly the overage");
        let left = h.packages();
        assert_eq!(left.len(), 4);
        assert!(
            left.contains(&"pkg09".to_string()) && left.contains(&"pkg06".to_string()),
            "the NEWEST records must survive, got {left:?}"
        );
        assert!(
            !left.contains(&"pkg00".to_string()),
            "the oldest must be dropped first"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_drops_records_past_the_age_cap() {
        let dir =
            std::env::temp_dir().join(format!("aur-scan-hist-prune-age-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = History::open(dir.clone()).unwrap();

        h.put(&rec("ancient"), Scope::Aur).unwrap();
        let old_path = dir.join("ancient.json");
        let f = std::fs::File::options()
            .write(true)
            .open(&old_path)
            .unwrap();
        f.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();

        h.put(&rec("fresh"), Scope::Aur).unwrap();

        let removed = h.prune(30, usize::MAX);
        assert_eq!(removed, 1);
        assert!(h.get("ancient", Scope::Aur).is_none());
        assert!(
            h.get("fresh", Scope::Aur).is_some(),
            "a recent record must survive"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_covers_the_local_namespace_too() {
        let dir =
            std::env::temp_dir().join(format!("aur-scan-hist-prune-loc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = History::open(dir.clone()).unwrap();
        h.put(&rec("localpkg"), Scope::Local).unwrap();
        let p = dir.join("local").join("localpkg.json");
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(h.prune(30, usize::MAX), 1, "local records must age out too");
        assert!(h.get("localpkg", Scope::Local).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_with_default_bounds_keeps_a_normal_working_set() {
        // The bounds must not delete a baseline anyone is actually using: a
        // heavy user has a few hundred AUR packages, far under the cap.
        let dir =
            std::env::temp_dir().join(format!("aur-scan-hist-prune-def-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = History::open(dir.clone()).unwrap();
        for i in 0..300 {
            h.put(&rec(&format!("p{i:04}")), Scope::Aur).unwrap();
        }
        let removed = h.prune(History::DEFAULT_MAX_AGE_DAYS, History::DEFAULT_MAX_RECORDS);
        assert_eq!(removed, 0, "300 fresh records must all survive");
        assert_eq!(h.packages().len(), 300);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_local_scan_cannot_overwrite_an_aur_packages_record() {
        // The poisoning case: a directory declaring `pkgname=firefox` must not
        // touch the real firefox baseline. Refusing to record local scans was
        // the first attempt and broke `check --local`, which exists precisely
        // to re-scan your own directory and see what changed.
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = History::open(dir.clone()).unwrap();

        let mut real = rec("firefox");
        real.maintainer = Some("arch".into());
        real.source_origins = ["github.com/mozilla/firefox".to_string()]
            .into_iter()
            .collect();
        h.put(&real, Scope::Aur).unwrap();

        let mut impostor = rec("firefox");
        impostor.maintainer = Some("mallory".into());
        impostor.source_origins = ["cdn.evil.example/x".to_string()].into_iter().collect();
        h.put(&impostor, Scope::Local).unwrap();

        assert_eq!(
            h.get("firefox", Scope::Aur).as_ref(),
            Some(&real),
            "the AUR record must be untouched by a local scan of the same name"
        );
        assert_eq!(
            h.get("firefox", Scope::Local).as_ref(),
            Some(&impostor),
            "the local scan still gets its own history, so --local diffing works"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_record_reads_as_no_history() {
        // A damaged cache must behave like a first scan, not raise an error and
        // not invent a change.
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-bad-{}", std::process::id()));
        let h = History::open(dir.clone()).unwrap();
        std::fs::write(dir.join("busted.json"), b"{not json").unwrap();
        assert!(h.get("busted", Scope::Aur).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_traversal_in_a_package_name_is_refused() {
        let dir = std::env::temp_dir().join(format!("aur-scan-hist-trav-{}", std::process::id()));
        let h = History::open(dir.clone()).unwrap();
        for bad in ["../../etc/passwd", "a/b", "..", ""] {
            assert!(
                h.path_for(bad, Scope::Aur).is_none(),
                "{bad:?} must be refused"
            );
            assert!(h.get(bad, Scope::Aur).is_none());
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
