//! Full dependency-tree resolution for AUR packages.
//!
//! `paru -S foo` builds not just `foo` but its entire AUR dependency closure,
//! and a hijacked package is often a *dependency* rather than the thing you
//! asked for. To detect problems before install we must resolve and scan the
//! whole tree, not the named package alone.
//!
//! AUR dependencies are resolved recursively via the RPC `info` endpoint
//! (batched per level). A name the AUR does not return is classified by asking
//! pacman: if the sync databases (or an installed package) satisfy it, it is a
//! trusted repo leaf; otherwise AUR packages that `provides` it are expanded and
//! scanned; otherwise it is *unresolved* and fails the gate. Nothing is trusted
//! merely for being absent from the AUR.
//!
//! SAFETY INVARIANT: resolution follows ONLY static, declared package metadata
//! (`depends`/`makedepends`/...). It must never fetch a `source=` artifact,
//! follow a URL found in a PKGBUILD, or execute anything -- doing so would make
//! the scanner the execution vector for the very payload it is looking for.
//! When a package fetches/runs code from an external source at build time, that
//! is an *opaque boundary*: it is flagged (see the `remote_exec` analyzer and
//! the `aur-scan:opaque` SBOM marker) and NOT expanded. A truthful, bounded
//! SBOM that says "this runs code from <url>, we stop here" is correct; a
//! "complete" SBOM built by chasing attacker-controlled code is dangerous.

use crate::aur::{AurPackageInfo, PackageInfoSource};
use crate::error::{Result, ScanError};
use crate::validate::is_valid_package_name;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Most AUR providers we will expand for one virtual dependency. A name that
/// hundreds of packages provide is not something a build should silently pick
/// from; past this the tree is reported truncated (fail closed).
pub const MAX_PROVIDERS: usize = 10;

/// Why a package is in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DepKind {
    /// Explicitly requested by the user.
    Root,
    /// Runtime dependency (`depends`).
    Runtime,
    /// Build-time dependency (`makedepends`).
    Make,
    /// Test dependency (`checkdepends`).
    Check,
    /// Optional dependency (`optdepends`).
    Optional,
}

/// Where a package comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PackageSource {
    /// Resolved in the AUR (untrusted; must be scanned).
    Aur,
    /// Satisfied by the official sync databases (signed, trusted), or by an
    /// already-installed package. Confirmed by pacman, never assumed.
    Repo,
    /// A virtual name that no repo satisfies but one or more AUR packages
    /// `provides`. Not scanned itself; its providers (its `depends`) are.
    Provided,
    /// Neither a repo nor the AUR (by name or by provides) could be shown to
    /// satisfy it. Unreviewable, so it fails the gate. This is the default so a
    /// forgotten classification can never read as "trusted".
    #[default]
    Unresolved,
}

/// A node in the dependency graph.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PackageNode {
    /// Package name (constraint-stripped).
    pub name: String,
    /// Version, when known.
    pub version: Option<String>,
    /// Origin classification.
    pub source: PackageSource,
    /// AUR package base (for fetching the PKGBUILD).
    pub package_base: Option<String>,
    /// Maintainer, when known (`None` + AUR = orphaned).
    pub maintainer: Option<String>,
    /// Whether the package is orphaned (a hijack risk factor).
    pub orphaned: bool,
    /// Resolved child dependency names. For a [`PackageSource::Provided`] node
    /// these are the AUR packages that provide it.
    pub depends: Vec<String>,
    /// The reasons this node is present (deduped, sorted).
    pub kinds: Vec<DepKind>,
    /// Shortest depth from a root.
    pub depth: usize,
    /// Raw `provides` entries of an AUR package (may carry `=version`).
    pub provides: Vec<String>,
    /// Sync repository that satisfied a [`PackageSource::Repo`] node, if known.
    pub repository: Option<String>,
    /// A virtual dependency with several candidate AUR providers: all are
    /// scanned, and the helper's eventual choice is not known to us.
    pub ambiguous: bool,
    /// Why a [`PackageSource::Unresolved`] node is unresolved, or a note about
    /// how a repo node was satisfied.
    pub note: Option<String>,
}

/// A resolved dependency graph.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DependencyGraph {
    /// The user-requested roots.
    pub roots: Vec<String>,
    /// All nodes keyed by name (sorted for stable output).
    pub nodes: BTreeMap<String, PackageNode>,
    /// Names that hit the depth/size cap and were not expanded further. Any
    /// entry here means part of the tree was NOT scanned.
    pub truncated: Vec<String>,
    /// Informational notices (unsatisfied version constraints, ambiguity).
    pub notes: Vec<String>,
}

impl DependencyGraph {
    /// All AUR nodes (the set that must be scanned), in stable order.
    pub fn aur_packages(&self) -> Vec<&PackageNode> {
        self.nodes
            .values()
            .filter(|n| n.source == PackageSource::Aur)
            .collect()
    }

    /// Count of AUR vs non-AUR nodes.
    pub fn counts(&self) -> (usize, usize) {
        let aur = self
            .nodes
            .values()
            .filter(|n| n.source == PackageSource::Aur)
            .count();
        (aur, self.nodes.len() - aur)
    }

    /// Nodes nothing could vouch for (not in a repo, not in the AUR).
    pub fn unresolved(&self) -> Vec<&PackageNode> {
        self.nodes
            .values()
            .filter(|n| n.source == PackageSource::Unresolved)
            .collect()
    }

    /// Virtual dependencies with several possible AUR providers.
    pub fn ambiguous(&self) -> Vec<&PackageNode> {
        self.nodes.values().filter(|n| n.ambiguous).collect()
    }

    /// Human-readable reasons the tree is NOT fully reviewed. Empty means every
    /// node was classified and nothing was cut off. Callers must fail closed on a
    /// non-empty result: an unresolved or truncated node is an unscanned package.
    pub fn blocking_issues(&self) -> Vec<String> {
        let mut out = Vec::new();
        for n in self.unresolved() {
            out.push(format!(
                "unresolved dependency {:?}: {}",
                n.name,
                n.note
                    .as_deref()
                    .unwrap_or("not in the official repos or the AUR")
            ));
        }
        for t in &self.truncated {
            out.push(format!(
                "dependency tree truncated at {t:?} (depth/size cap): deeper packages were not scanned"
            ));
        }
        out
    }
}

/// Options controlling which dependency classes are followed.
#[derive(Debug, Clone)]
pub struct ResolveOptions {
    /// Follow `makedepends` (default true: they run during the build).
    pub include_make: bool,
    /// Follow `checkdepends` (default true).
    pub include_check: bool,
    /// Follow `optdepends` (default false: not pulled by default).
    pub include_optional: bool,
    /// Maximum recursion depth (safety bound).
    pub max_depth: usize,
    /// Maximum number of nodes (safety bound).
    pub max_nodes: usize,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            include_make: true,
            include_check: true,
            include_optional: false,
            max_depth: 16,
            max_nodes: 2000,
        }
    }
}

// --- version constraints ----------------------------------------------------

/// Comparison operator of a dependency version constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintOp {
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `=`
    Eq,
    /// `>=`
    Ge,
    /// `>`
    Gt,
}

impl ConstraintOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Eq => "=",
            Self::Ge => ">=",
            Self::Gt => ">",
        }
    }
}

/// A parsed `name<op>version` constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionConstraint {
    /// Operator.
    pub op: ConstraintOp,
    /// Required version (`[epoch:]ver[-rel]`).
    pub version: String,
}

impl VersionConstraint {
    /// Whether `have` satisfies this constraint (pacman `vercmp` semantics).
    pub fn satisfied_by(&self, have: &str) -> bool {
        let ord = vercmp(have, &self.version);
        match self.op {
            ConstraintOp::Lt => ord == Ordering::Less,
            ConstraintOp::Le => ord != Ordering::Greater,
            ConstraintOp::Eq => ord == Ordering::Equal,
            ConstraintOp::Ge => ord != Ordering::Less,
            ConstraintOp::Gt => ord == Ordering::Greater,
        }
    }

    /// `name<op>version`, safe to hand to pacman as one argv element.
    pub fn spec_for(&self, name: &str) -> String {
        format!("{name}{}{}", self.op.as_str(), self.version)
    }
}

impl std::fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.op.as_str(), self.version)
    }
}

/// Split a dependency specifier into its package name and optional version
/// constraint. Removes optdepends descriptions (`baz: text`). A constraint with
/// characters outside a conservative version alphabet is dropped (and so never
/// reaches a subprocess).
pub fn split_dep(spec: &str) -> (&str, Option<VersionConstraint>) {
    let spec = spec.trim();
    let end = spec.find(['<', '>', '=', ':']).unwrap_or(spec.len());
    let name = spec[..end].trim();
    let rest = &spec[end..];
    if rest.is_empty() || rest.starts_with(':') {
        return (name, None);
    }
    // Drop a trailing optdepends description ("foo>=1: why").
    let rest = rest.split(": ").next().unwrap_or(rest).trim();
    let (op, ver) = if let Some(v) = rest.strip_prefix("<=") {
        (ConstraintOp::Le, v)
    } else if let Some(v) = rest.strip_prefix(">=") {
        (ConstraintOp::Ge, v)
    } else if let Some(v) = rest.strip_prefix('<') {
        (ConstraintOp::Lt, v)
    } else if let Some(v) = rest.strip_prefix('>') {
        (ConstraintOp::Gt, v)
    } else if let Some(v) = rest.strip_prefix('=') {
        (ConstraintOp::Eq, v)
    } else {
        return (name, None);
    };
    let ver = ver.trim();
    let ok = !ver.is_empty()
        && ver.len() <= 128
        && ver
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | ':' | '-'));
    if ok {
        (
            name,
            Some(VersionConstraint {
                op,
                version: ver.to_string(),
            }),
        )
    } else {
        (name, None)
    }
}

/// Strip a dependency specifier down to its package name: removes version
/// constraints (`foo>=1.2`, `bar=3`) and optdepends descriptions (`baz: text`).
pub fn dep_name(spec: &str) -> &str {
    split_dep(spec).0
}

/// libalpm's `rpmvercmp` on a single version segment (no epoch/release).
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let (si, sj) = (i, j);
        while i < a.len() && !a[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        // Different separator runs: the longer one is newer.
        if i - si != j - sj {
            return if i - si < j - sj {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let (s1, s2) = (i, j);
        let isnum = a[i].is_ascii_digit();
        if isnum {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        let (seg1, seg2) = (&a[s1..i], &b[s2..j]);
        if seg2.is_empty() {
            // Segments of different kinds: numeric is newer than alpha.
            return if isnum {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let ord = if isnum {
            let t1 = trim_zeros(seg1);
            let t2 = trim_zeros(seg2);
            t1.len().cmp(&t2.len()).then_with(|| t1.cmp(t2))
        } else {
            seg1.cmp(seg2)
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    let rest_a = i < a.len();
    let rest_b = j < b.len();
    if !rest_a && !rest_b {
        return Ordering::Equal;
    }
    // Whatever remains: an alpha tail is older than nothing, a numeric one newer.
    if (!rest_a && !b[j].is_ascii_alphabetic()) || (rest_a && a[i].is_ascii_alphabetic()) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn trim_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|c| **c == b'0').count();
    &s[n..]
}

/// Split `[epoch:]version[-release]`.
fn parse_evr(v: &str) -> (&str, &str, Option<&str>) {
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()) => (e, r),
        _ => ("0", v),
    };
    match rest.rsplit_once('-') {
        Some((ver, rel)) => (epoch, ver, Some(rel)),
        None => (epoch, rest, None),
    }
}

/// Compare two Arch package versions the way `vercmp` does (epoch, then
/// version, then release only when both sides carry one).
pub fn vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (e1, v1, r1) = parse_evr(a);
    let (e2, v2, r2) = parse_evr(b);
    let mut ord = rpmvercmp(e1, e2);
    if ord == Ordering::Equal {
        ord = rpmvercmp(v1, v2);
    }
    if ord == Ordering::Equal {
        if let (Some(r1), Some(r2)) = (r1, r2) {
            ord = rpmvercmp(r1, r2);
        }
    }
    ord
}

// --- repo lookup ------------------------------------------------------------

/// What the local pacman knows about a dependency specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoAnswer {
    /// A sync database satisfies it (names, provides and versions resolved).
    Sync {
        /// Repository (`core`, `extra`, ...).
        repository: String,
        /// The concrete package that satisfies it.
        package: String,
    },
    /// Not in a sync database, but an installed package satisfies it.
    Installed,
    /// Neither.
    NotFound,
}

/// Asks the system package manager whether a dependency is satisfied by an
/// official source. A trait so resolution is testable without pacman.
#[async_trait::async_trait]
pub trait RepoLookup: Send + Sync {
    /// Look up `spec` (`name` or `name<op>version`, already validated).
    async fn lookup(&self, spec: &str) -> Result<RepoAnswer>;
}

/// [`RepoLookup`] backed by read-only `pacman` queries (`-Sp`, `-T`).
pub struct PacmanRepo;

#[async_trait::async_trait]
impl RepoLookup for PacmanRepo {
    async fn lookup(&self, spec: &str) -> Result<RepoAnswer> {
        // `spec` is only ever built from a validated package name plus a
        // constraint from the conservative version alphabet; `--` still stops it
        // from being read as an option.
        let sync = tokio::process::Command::new("pacman")
            .args(["-Sp", "--noconfirm", "--print-format", "%r/%n", "--", spec])
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(ScanError::Io)?;
        if sync.status.success() {
            let out = String::from_utf8_lossy(&sync.stdout);
            if let Some((repo, pkg)) = out
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .and_then(|l| l.split_once('/'))
            {
                return Ok(RepoAnswer::Sync {
                    repository: repo.to_string(),
                    package: pkg.to_string(),
                });
            }
        }
        let installed = tokio::process::Command::new("pacman")
            .args(["-T", "--", spec])
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(ScanError::Io)?;
        if installed.status.success() {
            return Ok(RepoAnswer::Installed);
        }
        Ok(RepoAnswer::NotFound)
    }
}

// --- resolution -------------------------------------------------------------

struct Edge {
    from: String,
    to: String,
    constraint: Option<VersionConstraint>,
}

/// Resolve the full dependency closure of `roots`, classifying non-AUR names
/// with the system `pacman`.
pub async fn resolve(
    source: &dyn PackageInfoSource,
    roots: &[String],
    opts: &ResolveOptions,
) -> Result<DependencyGraph> {
    resolve_with(source, &PacmanRepo, roots, opts).await
}

/// Resolve the full dependency closure of `roots`.
///
/// A name the AUR does not return is NOT assumed to be an official package. It is
/// trusted as `Repo` only when `repo` confirms a sync database (or an installed
/// package) satisfies it; otherwise AUR packages that `provide` it are expanded
/// and scanned; otherwise it is `Unresolved` and fails the gate.
pub async fn resolve_with(
    source: &dyn PackageInfoSource,
    repo: &dyn RepoLookup,
    roots: &[String],
    opts: &ResolveOptions,
) -> Result<DependencyGraph> {
    let roots: Vec<String> = roots.iter().map(|r| dep_name(r).to_string()).collect();
    let mut nodes: BTreeMap<String, PackageNode> = BTreeMap::new();
    let mut kinds_seen: BTreeMap<String, BTreeSet<DepKind>> = BTreeMap::new();
    let mut truncated: Vec<String> = Vec::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut edges: Vec<Edge> = Vec::new();

    // Queue of (name, kind, depth). Roots first.
    let mut queue: VecDeque<(String, DepKind, usize)> = VecDeque::new();
    for r in &roots {
        queue.push_back((r.clone(), DepKind::Root, 0));
    }

    // Process level by level so we can batch RPC calls.
    while !queue.is_empty() {
        let frontier: Vec<(String, DepKind, usize)> = queue.drain(..).collect();

        // Record kind for every frontier item; collect the not-yet-resolved names.
        let mut to_query: Vec<String> = Vec::new();
        for (name, kind, _depth) in &frontier {
            kinds_seen.entry(name.clone()).or_default().insert(*kind);
            if visited.insert(name.clone()) {
                to_query.push(name.clone());
            }
        }
        if to_query.is_empty() {
            continue;
        }

        let query_refs: Vec<&str> = to_query.iter().map(|s| s.as_str()).collect();
        let infos = source.info_batch(&query_refs).await?;
        let found: BTreeMap<String, AurPackageInfo> =
            infos.into_iter().map(|i| (i.name.clone(), i)).collect();

        for (name, _kind, depth) in &frontier {
            if nodes.contains_key(name) {
                continue;
            }
            // Only build a node for names we actually queried this round.
            if !to_query.contains(name) {
                continue;
            }

            if let Some(info) = found.get(name) {
                // AUR package: record and expand.
                let mut child_specs: Vec<String> = info.depends.clone();
                if opts.include_make {
                    child_specs.extend(info.make_depends.clone());
                }
                if opts.include_check {
                    child_specs.extend(info.check_depends.clone());
                }
                if opts.include_optional {
                    child_specs.extend(info.opt_depends.clone());
                }
                let mut children: Vec<String> = Vec::new();
                for spec in &child_specs {
                    let (c, constraint) = split_dep(spec);
                    if c.is_empty() {
                        continue;
                    }
                    // Drop dependency names that are not legal package
                    // identifiers. These come from an attacker-controlled
                    // PKGBUILD and would otherwise flow into network URLs,
                    // filesystem paths and subprocess arguments.
                    if !is_valid_package_name(c) {
                        tracing::warn!("ignoring illegal dependency name {c:?} of {name}");
                        continue;
                    }
                    edges.push(Edge {
                        from: name.clone(),
                        to: c.to_string(),
                        constraint,
                    });
                    children.push(c.to_string());
                }
                children.sort();
                children.dedup();

                let orphaned = info.maintainer.is_none();
                nodes.insert(
                    name.clone(),
                    PackageNode {
                        name: name.clone(),
                        version: Some(info.version.clone()),
                        source: PackageSource::Aur,
                        package_base: Some(info.package_base.clone()),
                        maintainer: info.maintainer.clone(),
                        orphaned,
                        depends: children.clone(),
                        depth: *depth,
                        provides: info.provides.clone(),
                        ..Default::default()
                    },
                );

                // Enqueue children unless we have hit a cap.
                if *depth < opts.max_depth && nodes.len() < opts.max_nodes {
                    for c in children {
                        if !visited.contains(&c) {
                            queue.push_back((c, DepKind::Runtime, depth + 1));
                        }
                    }
                } else if opts.max_depth > 0 && !children.is_empty() {
                    // Only a *cap* hit is a truncation; max_depth == 0 is the
                    // explicit --no-deps "roots only" opt-out.
                    truncated.push(name.clone());
                }
            } else {
                // Not an AUR package by name. NEVER assume it is official.
                let mut wanted: Vec<VersionConstraint> = edges
                    .iter()
                    .filter(|e| &e.to == name)
                    .filter_map(|e| e.constraint.clone())
                    .collect();
                wanted.dedup();
                let (node, enqueue) =
                    classify_non_aur(name, *depth, &wanted, source, repo, &mut truncated).await?;
                for p in enqueue {
                    if !visited.contains(&p) {
                        queue.push_back((p, DepKind::Runtime, depth + 1));
                    }
                }
                nodes.insert(name.clone(), node);
            }
        }
    }

    // A virtual node is only as good as the providers that really declare it.
    let provided: Vec<String> = nodes
        .values()
        .filter(|n| n.source == PackageSource::Provided)
        .map(|n| n.name.clone())
        .collect();
    for vname in provided {
        let keep: Vec<String> = nodes[&vname]
            .depends
            .iter()
            .filter(|p| {
                nodes.get(*p).is_some_and(|pn| {
                    pn.source == PackageSource::Aur
                        && pn.provides.iter().any(|pr| dep_name(pr) == vname)
                })
            })
            .cloned()
            .collect();
        let node = nodes.get_mut(&vname).expect("collected from nodes");
        if keep.is_empty() {
            node.source = PackageSource::Unresolved;
            node.depends.clear();
            node.note = Some(
                "AUR search listed candidates but none declare it in provides=; \
                 not in the official repos either"
                    .to_string(),
            );
        } else {
            node.ambiguous = keep.len() > 1;
            node.depends = keep;
        }
    }

    // Attach the (deduped, sorted) reasons each node is present.
    for (name, node) in nodes.iter_mut() {
        if let Some(set) = kinds_seen.get(name) {
            node.kinds = set.iter().copied().collect();
        }
    }

    // Version constraints: recorded and checked against what the AUR offers.
    let mut notes: Vec<String> = Vec::new();
    for e in &edges {
        let Some(c) = &e.constraint else { continue };
        let Some(target) = nodes.get(&e.to) else {
            continue;
        };
        match target.source {
            PackageSource::Aur => {
                if let Some(v) = target.version.as_deref().filter(|v| !v.is_empty()) {
                    if !c.satisfied_by(v) {
                        notes.push(format!(
                            "{} requires {}{c} but the AUR version is {v}",
                            e.from, e.to
                        ));
                    }
                }
            }
            PackageSource::Provided => {
                let ok = target.depends.iter().filter_map(|p| nodes.get(p)).any(|p| {
                    p.provides.iter().any(|pr| {
                        let (n, pc) = split_dep(pr);
                        n == e.to
                            && pc
                                .filter(|pc| pc.op == ConstraintOp::Eq)
                                .is_some_and(|pc| c.satisfied_by(&pc.version))
                    })
                });
                if !ok {
                    notes.push(format!(
                        "{} requires {}{c} but no AUR provider declares a matching provides= version",
                        e.from, e.to
                    ));
                }
            }
            _ => {}
        }
    }
    for n in nodes.values().filter(|n| n.ambiguous) {
        notes.push(format!(
            "{} is provided by several AUR packages ({}); all are scanned, but which one is installed is not determined",
            n.name,
            n.depends.join(", ")
        ));
    }
    notes.sort();
    notes.dedup();

    truncated.sort();
    truncated.dedup();
    Ok(DependencyGraph {
        roots,
        nodes,
        truncated,
        notes,
    })
}

/// Classify a name the AUR did not return by name. Returns the node and any AUR
/// provider names to expand next.
async fn classify_non_aur(
    name: &str,
    depth: usize,
    wanted: &[VersionConstraint],
    source: &dyn PackageInfoSource,
    repo: &dyn RepoLookup,
    truncated: &mut Vec<String>,
) -> Result<(PackageNode, Vec<String>)> {
    let base = PackageNode {
        name: name.to_string(),
        depth,
        ..Default::default()
    };
    let unresolved = |why: String| PackageNode {
        source: PackageSource::Unresolved,
        note: Some(why),
        ..base.clone()
    };

    // Every constraint on this name must hold, so ask pacman about each one.
    let mut specs: Vec<String> = vec![name.to_string()];
    specs.extend(wanted.iter().map(|c| c.spec_for(name)));

    let mut sync: Option<(String, String)> = None;
    let mut all_sync = true;
    let mut all_satisfied = true;
    for spec in &specs {
        match repo.lookup(spec).await {
            Ok(RepoAnswer::Sync {
                repository,
                package,
            }) => {
                if sync.is_none() {
                    sync = Some((repository, package));
                }
            }
            Ok(RepoAnswer::Installed) => all_sync = false,
            Ok(RepoAnswer::NotFound) => {
                all_sync = false;
                all_satisfied = false;
            }
            Err(e) => {
                // pacman itself failed: we cannot vouch for anything.
                return Ok((
                    unresolved(format!("could not ask pacman about it ({e})")),
                    Vec::new(),
                ));
            }
        }
    }
    if all_sync {
        if let Some((repository, package)) = sync {
            let note = (package != name).then(|| format!("satisfied by {package}"));
            return Ok((
                PackageNode {
                    source: PackageSource::Repo,
                    repository: Some(repository),
                    note,
                    ..base
                },
                Vec::new(),
            ));
        }
    }
    if all_satisfied {
        // Every query was answered by a sync db or an installed package, and not
        // all by sync: an already-installed package covers it (nothing is built).
        return Ok((
            PackageNode {
                source: PackageSource::Repo,
                note: Some("satisfied by an already-installed package".to_string()),
                ..base
            },
            Vec::new(),
        ));
    }

    // Not an official package: is it a virtual name some AUR package provides?
    let mut candidates: Vec<String> = source
        .find_providers(name)
        .await?
        .into_iter()
        .filter(|c| c != name && is_valid_package_name(c))
        .collect();
    candidates.sort();
    candidates.dedup();
    if candidates.is_empty() {
        return Ok((
            unresolved("not in the official repos (pacman) and no AUR package provides it".into()),
            Vec::new(),
        ));
    }
    if candidates.len() > MAX_PROVIDERS {
        truncated.push(name.to_string());
        candidates.truncate(MAX_PROVIDERS);
    }
    Ok((
        PackageNode {
            source: PackageSource::Provided,
            depends: candidates.clone(),
            ambiguous: candidates.len() > 1,
            ..base
        },
        candidates,
    ))
}

/// AUR dependencies of `node`, looking through virtual (provided) nodes. Build
/// ordering must follow these, not just `node.depends`.
pub fn aur_dependencies<'g>(graph: &'g DependencyGraph, node: &'g PackageNode) -> Vec<&'g str> {
    let mut out: Vec<&str> = Vec::new();
    for dep in &node.depends {
        match graph.nodes.get(dep) {
            Some(n) if n.source == PackageSource::Aur => out.push(n.name.as_str()),
            Some(n) if n.source == PackageSource::Provided => {
                for p in &n.depends {
                    if graph
                        .nodes
                        .get(p)
                        .is_some_and(|pn| pn.source == PackageSource::Aur)
                    {
                        out.push(p.as_str());
                    }
                }
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Order the AUR packages so every package's AUR dependencies come before it
/// (repo/leaf nodes are excluded). Used to build a tree in a valid order with
/// `makepkg`. Cycles -- which AUR make/check deps can form -- are broken
/// deterministically by appending the remaining nodes in name order.
pub fn topo_order(graph: &DependencyGraph) -> Vec<String> {
    let aur: BTreeSet<&str> = graph
        .nodes
        .values()
        .filter(|n| n.source == PackageSource::Aur)
        .map(|n| n.name.as_str())
        .collect();

    // indeg[n] = number of n's dependencies that are themselves AUR packages.
    let mut indeg: BTreeMap<&str, usize> = aur.iter().map(|n| (*n, 0usize)).collect();
    // dependents[d] = AUR packages that depend on d.
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in graph
        .nodes
        .values()
        .filter(|n| aur.contains(n.name.as_str()))
    {
        for dep in aur_dependencies(graph, node) {
            if aur.contains(dep) {
                dependents.entry(dep).or_default().push(node.name.as_str());
                *indeg.get_mut(node.name.as_str()).unwrap() += 1;
            }
        }
    }

    // Kahn's algorithm, processing ready nodes in name order for determinism.
    let mut ready: Vec<&str> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(n, _)| *n)
        .collect();
    ready.sort();
    let mut order: Vec<String> = Vec::new();
    let mut i = 0;
    while i < ready.len() {
        let n = ready[i];
        i += 1;
        order.push(n.to_string());
        if let Some(deps) = dependents.get(n) {
            let mut newly = Vec::new();
            for &m in deps {
                let e = indeg.get_mut(m).unwrap();
                *e -= 1;
                if *e == 0 {
                    newly.push(m);
                }
            }
            newly.sort();
            ready.extend(newly);
        }
    }

    // Any nodes left were in a cycle; append in name order so we still try.
    if order.len() < aur.len() {
        let mut rest: Vec<&str> = aur
            .iter()
            .copied()
            .filter(|n| !order.iter().any(|o| o == n))
            .collect();
        rest.sort();
        order.extend(rest.into_iter().map(String::from));
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn info(name: &str, deps: &[&str], make: &[&str], maintainer: Option<&str>) -> AurPackageInfo {
        AurPackageInfo {
            name: name.to_string(),
            version: "1.0-1".to_string(),
            package_base: name.to_string(),
            maintainer: maintainer.map(String::from),
            depends: deps.iter().map(|s| s.to_string()).collect(),
            make_depends: make.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    struct FakeSource {
        db: HashMap<String, AurPackageInfo>,
    }

    #[async_trait::async_trait]
    impl PackageInfoSource for FakeSource {
        async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>> {
            Ok(names
                .iter()
                .filter_map(|n| self.db.get(*n).cloned())
                .collect())
        }

        async fn find_providers(&self, name: &str) -> Result<Vec<String>> {
            Ok(self
                .db
                .values()
                .filter(|i| i.provides.iter().any(|p| dep_name(p) == name))
                .map(|i| i.name.clone())
                .collect())
        }
    }

    /// Hermetic pacman: knows a fixed set of sync names (with optional
    /// provides/versions encoded as plain specs) and installed names.
    #[derive(Default)]
    struct FakeRepo {
        sync: HashMap<String, (&'static str, String)>,
        installed: Vec<&'static str>,
        fail: bool,
        queries: std::sync::Mutex<Vec<String>>,
    }

    impl FakeRepo {
        fn with(names: &[&'static str]) -> Self {
            let mut r = FakeRepo::default();
            for n in names {
                r.sync.insert(n.to_string(), ("extra", n.to_string()));
            }
            r
        }
    }

    #[async_trait::async_trait]
    impl RepoLookup for FakeRepo {
        async fn lookup(&self, spec: &str) -> Result<RepoAnswer> {
            self.queries.lock().unwrap().push(spec.to_string());
            if self.fail {
                return Err(ScanError::Io(std::io::Error::other("no pacman")));
            }
            let (name, _) = split_dep(spec);
            if let Some((repo, pkg)) = self.sync.get(name) {
                return Ok(RepoAnswer::Sync {
                    repository: repo.to_string(),
                    package: pkg.clone(),
                });
            }
            if self.installed.contains(&name) {
                return Ok(RepoAnswer::Installed);
            }
            Ok(RepoAnswer::NotFound)
        }
    }

    fn src(infos: Vec<AurPackageInfo>) -> FakeSource {
        FakeSource {
            db: infos.into_iter().map(|i| (i.name.clone(), i)).collect(),
        }
    }

    #[test]
    fn dep_name_strips_constraints_and_descriptions() {
        assert_eq!(dep_name("foo>=1.2"), "foo");
        assert_eq!(dep_name("bar=3"), "bar");
        assert_eq!(dep_name("baz: optional thing"), "baz");
        assert_eq!(dep_name("  qux  "), "qux");
        assert_eq!(dep_name("zlib<2"), "zlib");
        assert_eq!(dep_name("epoch>=1:2.0-1"), "epoch");
    }

    #[test]
    fn split_dep_keeps_the_constraint() {
        let (n, c) = split_dep("foo>=1:2.0-1");
        assert_eq!(n, "foo");
        assert_eq!(c.unwrap().to_string(), ">=1:2.0-1");
        let (n, c) = split_dep("bar: why");
        assert_eq!((n, c), ("bar", None));
        // Shell metacharacters never survive into a constraint.
        assert_eq!(split_dep("x>=1;rm -rf").1, None);
    }

    #[test]
    fn vercmp_matches_pacman() {
        use std::cmp::Ordering::*;
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0", "1.1", Less),
            ("1.10", "1.9", Greater),
            ("1.0a", "1.0", Less),
            ("1.0", "1.0a", Greater),
            ("1:1.0", "2.0", Greater),
            ("1.0-1", "1.0-2", Less),
            ("1.0-1", "1.0", Equal), // release compared only if both have one
            ("1.0rc1", "1.0", Less),
            ("2.0", "1.99", Greater),
            ("1.001", "1.1", Equal),
        ] {
            assert_eq!(vercmp(a, b), want, "vercmp({a}, {b})");
        }
    }

    #[test]
    fn constraint_satisfaction() {
        let c = |s: &str| split_dep(s).1.unwrap();
        assert!(c("foo>=1.2").satisfied_by("1.2-1"));
        assert!(c("foo>=1.2").satisfied_by("1.10-3"));
        assert!(!c("foo>=2").satisfied_by("1.9-1"));
        assert!(c("foo<2").satisfied_by("1.9-1"));
        assert!(c("foo=1.0").satisfied_by("1.0-5"));
        assert!(!c("foo>1.0").satisfied_by("1.0-5"));
    }

    #[tokio::test]
    async fn resolves_transitive_aur_tree_and_marks_repo_leaves() {
        let source = src(vec![
            info("foo", &["mid>=1", "glibc"], &["cmake"], Some("alice")),
            info("mid", &["deep"], &[], None), // orphaned AUR dep
            info("deep", &[], &[], Some("bob")),
        ]);
        let repo = FakeRepo::with(&["glibc", "cmake"]);
        let graph = resolve_with(
            &source,
            &repo,
            &["foo".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();

        assert!(graph.nodes.contains_key("foo"));
        assert!(graph.nodes.contains_key("mid"));
        assert!(graph.nodes.contains_key("deep"));
        assert_eq!(graph.nodes["glibc"].source, PackageSource::Repo);
        assert_eq!(graph.nodes["glibc"].repository.as_deref(), Some("extra"));
        assert_eq!(graph.nodes["cmake"].source, PackageSource::Repo);
        assert!(graph.nodes["mid"].orphaned);
        let (aur, repo_n) = graph.counts();
        assert_eq!(aur, 3);
        assert!(repo_n >= 2);
        assert!(graph.blocking_issues().is_empty());
    }

    #[tokio::test]
    async fn nonexistent_name_is_unresolved_not_trusted_repo() {
        // Regression: any name the AUR RPC did not return used to be labelled
        // "[repo] (official, trusted)" without asking pacman.
        let source = src(vec![]);
        let repo = FakeRepo::default();
        let graph = resolve_with(
            &source,
            &repo,
            &["zz-nonexistent-pkg-xyz".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            graph.nodes["zz-nonexistent-pkg-xyz"].source,
            PackageSource::Unresolved
        );
        assert!(!graph.blocking_issues().is_empty());
        assert_eq!(graph.unresolved().len(), 1);
    }

    #[tokio::test]
    async fn pacman_failure_fails_closed() {
        let source = src(vec![info("foo", &["glibc"], &[], Some("a"))]);
        let repo = FakeRepo {
            fail: true,
            ..Default::default()
        };
        let graph = resolve_with(
            &source,
            &repo,
            &["foo".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(graph.nodes["glibc"].source, PackageSource::Unresolved);
        assert!(!graph.blocking_issues().is_empty());
    }

    #[tokio::test]
    async fn aur_only_provides_becomes_scanned_aur_node() {
        // `sh-virtual` is only provided by an AUR -git package. It must be
        // scanned, not waved through as a trusted repo leaf.
        let mut prov = info("thing-git", &["libz"], &[], Some("eve"));
        prov.provides = vec!["thing=2.0".into()];
        let source = src(vec![info("app", &["thing>=1"], &[], Some("a")), prov]);
        let repo = FakeRepo::with(&["libz"]);
        let graph = resolve_with(
            &source,
            &repo,
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(graph.nodes["thing"].source, PackageSource::Provided);
        assert_eq!(graph.nodes["thing"].depends, vec!["thing-git"]);
        assert!(!graph.nodes["thing"].ambiguous);
        assert_eq!(graph.nodes["thing-git"].source, PackageSource::Aur);
        let scan_set: Vec<&str> = graph
            .aur_packages()
            .iter()
            .map(|n| n.name.as_str())
            .collect();
        assert!(scan_set.contains(&"thing-git"));
        assert!(graph.blocking_issues().is_empty());
        // 2.0 satisfies >=1: no constraint notice.
        assert!(graph.notes.is_empty(), "{:?}", graph.notes);
        // Build order sees through the virtual node.
        assert_eq!(topo_order(&graph), vec!["thing-git", "app"]);
    }

    #[tokio::test]
    async fn several_providers_are_all_scanned_and_marked_ambiguous() {
        let mut p1 = info("prov-a", &[], &[], Some("x"));
        p1.provides = vec!["virt".into()];
        let mut p2 = info("prov-b", &[], &[], Some("y"));
        p2.provides = vec!["virt".into()];
        let source = src(vec![info("app", &["virt"], &[], Some("a")), p1, p2]);
        let graph = resolve_with(
            &source,
            &FakeRepo::default(),
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        let v = &graph.nodes["virt"];
        assert!(v.ambiguous);
        assert_eq!(v.depends, vec!["prov-a", "prov-b"]);
        assert_eq!(graph.aur_packages().len(), 3);
        assert!(graph.notes.iter().any(|n| n.contains("several AUR")));
        assert_eq!(graph.ambiguous().len(), 1);
    }

    #[tokio::test]
    async fn provider_that_does_not_actually_provide_is_dropped() {
        // A search hit whose own provides= does not list the name is not trusted.
        struct LyingSource(FakeSource);
        #[async_trait::async_trait]
        impl PackageInfoSource for LyingSource {
            async fn info_batch(&self, n: &[&str]) -> Result<Vec<AurPackageInfo>> {
                self.0.info_batch(n).await
            }
            async fn find_providers(&self, _n: &str) -> Result<Vec<String>> {
                Ok(vec!["liar".into()])
            }
        }
        let source = LyingSource(src(vec![
            info("app", &["virt"], &[], Some("a")),
            info("liar", &[], &[], Some("x")),
        ]));
        let graph = resolve_with(
            &source,
            &FakeRepo::default(),
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(graph.nodes["virt"].source, PackageSource::Unresolved);
        assert!(!graph.blocking_issues().is_empty());
    }

    #[tokio::test]
    async fn already_installed_satisfier_is_noted_repo() {
        let source = src(vec![info("app", &["local-thing"], &[], Some("a"))]);
        let repo = FakeRepo {
            installed: vec!["local-thing"],
            ..Default::default()
        };
        let graph = resolve_with(
            &source,
            &repo,
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        let n = &graph.nodes["local-thing"];
        assert_eq!(n.source, PackageSource::Repo);
        assert!(n.note.as_deref().unwrap().contains("installed"));
    }

    #[tokio::test]
    async fn version_constraint_is_recorded_and_checked_against_aur() {
        let source = src(vec![
            info("app", &["lib>=2.0"], &[], Some("a")),
            info("lib", &[], &[], Some("b")), // version 1.0-1
        ]);
        let graph = resolve_with(
            &source,
            &FakeRepo::default(),
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(graph.notes.len(), 1, "{:?}", graph.notes);
        assert!(graph.notes[0].contains("app requires lib>=2.0"));
        assert!(graph.notes[0].contains("1.0-1"));
    }

    #[tokio::test]
    async fn repo_constraint_is_passed_to_pacman() {
        let source = src(vec![info("app", &["glibc>=2.39"], &[], Some("a"))]);
        let repo = FakeRepo::with(&["glibc"]);
        resolve_with(
            &source,
            &repo,
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        let q = repo.queries.lock().unwrap();
        assert!(q.contains(&"glibc>=2.39".to_string()), "{q:?}");
    }

    #[tokio::test]
    async fn depth_cap_is_reported_as_truncation() {
        let source = src(vec![
            info("a", &["b"], &[], Some("x")),
            info("b", &["c"], &[], Some("x")),
            info("c", &[], &[], Some("x")),
        ]);
        let opts = ResolveOptions {
            max_depth: 1,
            ..Default::default()
        };
        let graph = resolve_with(&source, &FakeRepo::default(), &["a".to_string()], &opts)
            .await
            .unwrap();
        assert_eq!(graph.truncated, vec!["b"]);
        assert!(graph
            .blocking_issues()
            .iter()
            .any(|m| m.contains("truncated")));
    }

    #[tokio::test]
    async fn no_deps_mode_is_not_a_truncation() {
        let source = src(vec![info("a", &["b"], &[], Some("x"))]);
        let opts = ResolveOptions {
            max_depth: 0,
            ..Default::default()
        };
        let graph = resolve_with(&source, &FakeRepo::default(), &["a".to_string()], &opts)
            .await
            .unwrap();
        assert!(graph.truncated.is_empty());
    }

    #[tokio::test]
    async fn topo_order_places_deps_before_dependents() {
        // app -> lib -> base ; all AUR. glibc is repo (excluded).
        let source = src(vec![
            info("app", &["lib", "glibc"], &[], Some("a")),
            info("lib", &["base"], &[], Some("a")),
            info("base", &[], &[], Some("a")),
        ]);
        let graph = resolve_with(
            &source,
            &FakeRepo::with(&["glibc"]),
            &["app".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        let order = topo_order(&graph);
        assert_eq!(order, vec!["base", "lib", "app"]);
        assert!(!order.iter().any(|n| n == "glibc")); // repo leaf excluded
    }

    #[tokio::test]
    async fn handles_cycles_without_hanging() {
        let source = src(vec![
            info("a", &["b"], &[], Some("x")),
            info("b", &["a"], &[], Some("x")),
        ]);
        let graph = resolve_with(
            &source,
            &FakeRepo::default(),
            &["a".to_string()],
            &ResolveOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(graph.aur_packages().len(), 2);
    }
}
