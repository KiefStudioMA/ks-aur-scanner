//! Full dependency-tree resolution for AUR packages.
//!
//! `paru -S foo` builds not just `foo` but its entire AUR dependency closure,
//! and a hijacked package is often a *dependency* rather than the thing you
//! asked for. To detect problems before install we must resolve and scan the
//! whole tree, not the named package alone.
//!
//! AUR dependencies are resolved recursively via the RPC `info` endpoint
//! (batched per level). Dependencies that are not AUR packages are official
//! repository packages (signed, out of scope for AUR tampering) and become
//! leaves -- still recorded so the SBOM is complete.
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
use crate::error::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageSource {
    /// Resolved in the AUR (untrusted; must be scanned).
    Aur,
    /// Not in the AUR: an official repository or virtual package (trusted).
    Repo,
}

/// A node in the dependency graph.
#[derive(Debug, Clone, Serialize)]
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
    /// Resolved child dependency names.
    pub depends: Vec<String>,
    /// The reasons this node is present (deduped, sorted).
    pub kinds: Vec<DepKind>,
    /// Shortest depth from a root.
    pub depth: usize,
}

/// A resolved dependency graph.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyGraph {
    /// The user-requested roots.
    pub roots: Vec<String>,
    /// All nodes keyed by name (sorted for stable output).
    pub nodes: BTreeMap<String, PackageNode>,
    /// Names that hit the depth/size cap and were not expanded further.
    pub truncated: Vec<String>,
}

impl DependencyGraph {
    /// All AUR nodes (the set that must be scanned), in stable order.
    pub fn aur_packages(&self) -> Vec<&PackageNode> {
        self.nodes
            .values()
            .filter(|n| n.source == PackageSource::Aur)
            .collect()
    }

    /// Count of AUR vs repo nodes.
    pub fn counts(&self) -> (usize, usize) {
        let aur = self
            .nodes
            .values()
            .filter(|n| n.source == PackageSource::Aur)
            .count();
        (aur, self.nodes.len() - aur)
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

/// Strip a dependency specifier down to its package name: removes version
/// constraints (`foo>=1.2`, `bar=3`) and optdepends descriptions (`baz: text`).
pub fn dep_name(spec: &str) -> &str {
    let spec = spec.trim();
    // optdepends "name: description"
    let spec = spec.split(':').next().unwrap_or(spec).trim();
    // version constraint: first of < > = chars
    let end = spec.find(['<', '>', '=']).unwrap_or(spec.len());
    spec[..end].trim()
}

/// Resolve the full dependency closure of `roots`.
pub async fn resolve(
    source: &dyn PackageInfoSource,
    roots: &[String],
    opts: &ResolveOptions,
) -> Result<DependencyGraph> {
    let roots: Vec<String> = roots.iter().map(|r| dep_name(r).to_string()).collect();
    let mut nodes: BTreeMap<String, PackageNode> = BTreeMap::new();
    let mut kinds_seen: BTreeMap<String, BTreeSet<DepKind>> = BTreeMap::new();
    let mut truncated: Vec<String> = Vec::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();

    // Queue of (name, kind, depth). Roots first.
    let mut queue: VecDeque<(String, DepKind, usize)> = VecDeque::new();
    for r in &roots {
        queue.push_back((r.clone(), DepKind::Root, 0));
    }

    // Process level by level so we can batch RPC calls.
    while !queue.is_empty() {
        // Drain the current frontier.
        let mut frontier: Vec<(String, DepKind, usize)> = Vec::new();
        while let Some(item) = queue.pop_front() {
            frontier.push(item);
        }

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
                let mut children: Vec<String> = child_specs
                    .iter()
                    .map(|s| dep_name(s).to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if opts.include_optional {
                    children.extend(info.opt_depends.iter().map(|s| dep_name(s).to_string()));
                }
                // Drop dependency names that are not legal package identifiers.
                // These come from an attacker-controlled PKGBUILD and would
                // otherwise flow into network URLs and filesystem paths; a name
                // that is not installable can never be a real build dependency.
                children.retain(|c| {
                    let ok = crate::validate::is_valid_package_name(c);
                    if !ok {
                        tracing::warn!("ignoring illegal dependency name {c:?} of {name}");
                    }
                    ok
                });
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
                        kinds: Vec::new(), // filled at the end
                        depth: *depth,
                    },
                );

                // Enqueue children unless we have hit a cap.
                if *depth < opts.max_depth && nodes.len() < opts.max_nodes {
                    let child_kind = DepKind::Runtime;
                    for c in children {
                        if !visited.contains(&c) {
                            queue.push_back((c, child_kind, depth + 1));
                        }
                    }
                } else if opts.max_depth > 0 && !children.is_empty() {
                    // Only a *cap* hit is noteworthy; max_depth == 0 is the
                    // intentional --no-deps "roots only" mode.
                    truncated.push(name.clone());
                }
            } else {
                // Not in AUR -> official repo / virtual: a trusted leaf.
                nodes.insert(
                    name.clone(),
                    PackageNode {
                        name: name.clone(),
                        version: None,
                        source: PackageSource::Repo,
                        package_base: None,
                        maintainer: None,
                        orphaned: false,
                        depends: Vec::new(),
                        kinds: Vec::new(),
                        depth: *depth,
                    },
                );
            }
        }
    }

    // Attach the (deduped, sorted) reasons each node is present.
    for (name, node) in nodes.iter_mut() {
        if let Some(set) = kinds_seen.get(name) {
            node.kinds = set.iter().copied().collect();
        }
    }

    truncated.sort();
    truncated.dedup();
    Ok(DependencyGraph {
        roots,
        nodes,
        truncated,
    })
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
        for dep in &node.depends {
            if aur.contains(dep.as_str()) {
                dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(node.name.as_str());
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
        db: std::collections::HashMap<String, AurPackageInfo>,
    }

    #[async_trait::async_trait]
    impl PackageInfoSource for FakeSource {
        async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>> {
            Ok(names
                .iter()
                .filter_map(|n| self.db.get(*n).cloned())
                .collect())
        }
    }

    #[test]
    fn dep_name_strips_constraints_and_descriptions() {
        assert_eq!(dep_name("foo>=1.2"), "foo");
        assert_eq!(dep_name("bar=3"), "bar");
        assert_eq!(dep_name("baz: optional thing"), "baz");
        assert_eq!(dep_name("  qux  "), "qux");
        assert_eq!(dep_name("zlib<2"), "zlib");
    }

    #[tokio::test]
    async fn resolves_transitive_aur_tree_and_marks_repo_leaves() {
        // foo -(dep)-> mid -(dep)-> deep(AUR), and foo -(make)-> glibc(repo)
        let mut db = std::collections::HashMap::new();
        for i in [
            info("foo", &["mid>=1", "glibc"], &["cmake"], Some("alice")),
            info("mid", &["deep"], &[], None), // orphaned AUR dep
            info("deep", &[], &[], Some("bob")),
        ] {
            db.insert(i.name.clone(), i);
        }
        let source = FakeSource { db };
        let graph = resolve(&source, &["foo".to_string()], &ResolveOptions::default())
            .await
            .unwrap();

        // AUR closure
        assert!(graph.nodes.contains_key("foo"));
        assert!(graph.nodes.contains_key("mid"));
        assert!(graph.nodes.contains_key("deep"));
        // repo / virtual leaves recorded but not AUR
        assert_eq!(graph.nodes["glibc"].source, PackageSource::Repo);
        assert_eq!(graph.nodes["cmake"].source, PackageSource::Repo);
        // orphan flagged
        assert!(graph.nodes["mid"].orphaned);
        // scan set = AUR only
        let (aur, repo) = graph.counts();
        assert_eq!(aur, 3);
        assert!(repo >= 2);
    }

    #[tokio::test]
    async fn topo_order_places_deps_before_dependents() {
        let mut db = std::collections::HashMap::new();
        // app -> lib -> base ; all AUR. glibc is repo (excluded).
        db.insert("app".into(), info("app", &["lib", "glibc"], &[], Some("a")));
        db.insert("lib".into(), info("lib", &["base"], &[], Some("a")));
        db.insert("base".into(), info("base", &[], &[], Some("a")));
        let source = FakeSource { db };
        let graph = resolve(&source, &["app".to_string()], &ResolveOptions::default())
            .await
            .unwrap();
        let order = topo_order(&graph);
        assert_eq!(order, vec!["base", "lib", "app"]);
        assert!(!order.iter().any(|n| n == "glibc")); // repo leaf excluded
    }

    #[tokio::test]
    async fn handles_cycles_without_hanging() {
        let mut db = std::collections::HashMap::new();
        db.insert("a".into(), info("a", &["b"], &[], Some("x")));
        db.insert("b".into(), info("b", &["a"], &[], Some("x")));
        let source = FakeSource { db };
        let graph = resolve(&source, &["a".to_string()], &ResolveOptions::default())
            .await
            .unwrap();
        assert_eq!(graph.aur_packages().len(), 2);
    }
}
