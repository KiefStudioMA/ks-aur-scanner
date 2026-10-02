//! SBOM generation from a resolved dependency graph.
//!
//! Produces a CycloneDX 1.5 JSON document (the security-oriented SBOM standard)
//! and a human-readable dependency tree, so a user can review the full set of
//! packages -- and any findings against them -- *before* installing.

use crate::depgraph::{DependencyGraph, PackageNode, PackageSource};
use crate::types::Finding;
use serde::Serialize;
use std::collections::BTreeMap;

/// Per-package scan summary attached to an SBOM component.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ComponentScan {
    /// Findings by id with severity label, for review.
    pub findings: Vec<(String, String)>,
    /// Count of critical findings.
    pub critical: usize,
    /// Count of high findings.
    pub high: usize,
    /// Whether this package fetches/executes code from outside any package,
    /// making the SBOM necessarily incomplete past this node.
    pub opaque: bool,
    /// External URLs this package pulls code from, if any were extracted.
    pub remote_urls: Vec<String>,
}

impl ComponentScan {
    /// Build a summary from a slice of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        use crate::types::Severity;
        let mut s = ComponentScan::default();
        for f in findings {
            s.findings.push((f.id.clone(), f.severity.to_string()));
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                _ => {}
            }
            // An opaque boundary: the package runs code fetched at build/install
            // time, so the dependency tree cannot be completed past it.
            if f.metadata
                .get("opaque_boundary")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                s.opaque = true;
            }
            if let Some(urls) = f.metadata.get("remote_urls").and_then(|v| v.as_array()) {
                for u in urls {
                    if let Some(u) = u.as_str() {
                        s.opaque = true;
                        if !s.remote_urls.iter().any(|e| e == u) {
                            s.remote_urls.push(u.to_string());
                        }
                    }
                }
            }
        }
        s
    }
}

/// Current timestamp as an ISO-8601/RFC-3339 string for SBOM metadata.
pub fn now_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// A UUID-shaped serial number derived from the current time and process id.
/// Not a cryptographic UUIDv4, but unique enough to identify one SBOM document.
pub fn new_serial() -> String {
    use sha2::{Digest, Sha256};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let d = h.finalize();
    let hex: String = d.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Percent-encode a purl name/version/qualifier value: everything outside the
/// RFC 3986 unreserved set is escaped (so an epoch `1:2.0` becomes `1%3A2.0` and
/// `c++` becomes `c%2B%2B`).
fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Package URL for a node, or `None` when the node is not a concrete package
/// (an unresolved or virtual name has no honest purl). The `repository`
/// qualifier is only emitted when known: `aur` for AUR packages, the real sync
/// repo name for repo packages.
fn purl(n: &PackageNode) -> Option<String> {
    let repo = match n.source {
        PackageSource::Aur => Some("aur"),
        PackageSource::Repo => n.repository.as_deref(),
        PackageSource::Provided | PackageSource::Unresolved => return None,
    };
    let mut p = format!("pkg:alpm/arch/{}", purl_encode(&n.name));
    if let Some(v) = &n.version {
        p.push('@');
        p.push_str(&purl_encode(v));
    }
    if let Some(r) = repo {
        p.push_str("?repository=");
        p.push_str(&purl_encode(r));
    }
    Some(p)
}

fn component_json(
    n: &PackageNode,
    scans: &BTreeMap<String, ComponentScan>,
    ty: &str,
) -> serde_json::Value {
    let mut properties = vec![
        serde_json::json!({"name": "aur-scan:source", "value": match n.source {
            PackageSource::Aur => "aur",
            PackageSource::Repo => "repo",
            PackageSource::Provided => "provided",
            PackageSource::Unresolved => "unresolved",
        }}),
        serde_json::json!({"name": "aur-scan:depth", "value": n.depth.to_string()}),
    ];
    if n.orphaned {
        properties.push(serde_json::json!({"name": "aur-scan:orphaned", "value": "true"}));
    }
    if n.ambiguous {
        properties.push(serde_json::json!({"name": "aur-scan:ambiguous", "value": "true"}));
    }
    if let Some(note) = &n.note {
        properties.push(serde_json::json!({"name": "aur-scan:note", "value": note}));
    }
    if let Some(m) = &n.maintainer {
        properties.push(serde_json::json!({"name": "aur-scan:maintainer", "value": m}));
    }
    if let Some(scan) = scans.get(&n.name) {
        properties.push(serde_json::json!({
            "name": "aur-scan:findings",
            "value": format!("{} critical, {} high", scan.critical, scan.high)
        }));
        for (id, sev) in &scan.findings {
            properties.push(serde_json::json!({
                "name": "aur-scan:finding", "value": format!("{id} ({sev})")
            }));
        }
        // Mark the opaque boundary: the SBOM is incomplete past a node
        // that fetches/executes external code, by design.
        if scan.opaque {
            properties.push(serde_json::json!({
                "name": "aur-scan:opaque",
                "value": "true (fetches/executes external code; SBOM incomplete past this node)"
            }));
            for url in &scan.remote_urls {
                properties.push(serde_json::json!({
                    "name": "aur-scan:remote-source", "value": url
                }));
            }
        }
    }

    let mut component = serde_json::json!({
        "type": ty,
        "bom-ref": n.name,
        "name": n.name,
        "properties": properties,
    });
    if let Some(p) = purl(n) {
        component["purl"] = serde_json::json!(p);
    }
    if let Some(v) = &n.version {
        component["version"] = serde_json::json!(v);
    }
    component
}

/// Build a CycloneDX 1.5 SBOM document. `scans` maps package name to its scan
/// summary; `serial`/`timestamp` are supplied by the caller (kept out of here
/// so the function stays deterministic and testable).
///
/// Structure: the first requested root is `metadata.component` and is NOT
/// repeated in `components` (bom-refs must be unique across the document); every
/// other node is a component. `dependsOn` lists only refs that exist in the
/// document, so a `--no-deps`/truncated tree never dangles.
pub fn to_cyclonedx(
    graph: &DependencyGraph,
    scans: &BTreeMap<String, ComponentScan>,
    tool_version: &str,
    serial: &str,
    timestamp: &str,
) -> serde_json::Value {
    let primary: Option<&str> = graph.roots.first().map(|r| r.as_str());
    let metadata_component = primary.map(|r| match graph.nodes.get(r) {
        Some(n) => component_json(n, scans, "application"),
        None => serde_json::json!({"type": "application", "bom-ref": r, "name": r}),
    });

    let components: Vec<serde_json::Value> = graph
        .nodes
        .values()
        .filter(|n| Some(n.name.as_str()) != primary)
        .map(|n| component_json(n, scans, "library"))
        .collect();

    // Every ref that exists in the document.
    let mut refs: std::collections::BTreeSet<&str> =
        graph.nodes.keys().map(|k| k.as_str()).collect();
    if let Some(p) = primary {
        refs.insert(p);
    }

    let dependencies: Vec<serde_json::Value> = graph
        .nodes
        .values()
        .filter_map(|n| {
            let deps: Vec<&String> = n
                .depends
                .iter()
                .filter(|d| refs.contains(d.as_str()))
                .collect();
            (!deps.is_empty()).then(|| serde_json::json!({ "ref": n.name, "dependsOn": deps }))
        })
        .collect();

    // Findings expressed as CycloneDX vulnerabilities, keyed by finding id and
    // pointing at the affected component.
    let mut vulnerabilities: Vec<serde_json::Value> = Vec::new();
    for (pkg, scan) in scans {
        for (id, sev) in &scan.findings {
            vulnerabilities.push(serde_json::json!({
                "id": id,
                "source": {"name": "aur-scan"},
                "ratings": [{"severity": sev.to_lowercase()}],
                "affects": [{"ref": pkg}],
            }));
        }
    }

    let mut metadata = serde_json::json!({
        "timestamp": timestamp,
        "tools": [{"vendor": "Kief Studio", "name": "aur-scan", "version": tool_version}],
    });
    if let Some(c) = metadata_component {
        metadata["component"] = c;
    }

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
    })
}

/// Render the dependency graph as a reviewable text tree.
pub fn render_tree(graph: &DependencyGraph, scans: &BTreeMap<String, ComponentScan>) -> String {
    let mut out = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for root in &graph.roots {
        render_node(graph, scans, root, "", None, &mut seen, &mut out);
    }
    out
}

/// `last` is `None` for a root (no connector), else whether this is the last
/// sibling. `prefix` grows by one column group per level.
#[allow(clippy::too_many_arguments)]
fn render_node(
    graph: &DependencyGraph,
    scans: &BTreeMap<String, ComponentScan>,
    name: &str,
    prefix: &str,
    last: Option<bool>,
    seen: &mut std::collections::BTreeSet<String>,
    out: &mut String,
) {
    let connector = match last {
        None => "",
        Some(true) => "└─ ",
        Some(false) => "├─ ",
    };

    let node = graph.nodes.get(name);
    let tag = match node.map(|n| n.source) {
        Some(PackageSource::Aur) => "[AUR]",
        Some(PackageSource::Repo) => "[repo]",
        Some(PackageSource::Provided) => "[AUR virtual]",
        Some(PackageSource::Unresolved) => "[UNRESOLVED]",
        None => "[not scanned]",
    };
    let mut annot = String::new();
    if let Some(n) = node {
        if n.orphaned {
            annot.push_str(" ORPHAN");
        }
        if n.ambiguous {
            annot.push_str(" AMBIGUOUS (several providers; all scanned)");
        }
        if n.source == PackageSource::Unresolved {
            annot.push_str(&format!(
                " !! {}",
                n.note.as_deref().unwrap_or("could not be resolved")
            ));
        }
    }
    if let Some(scan) = scans.get(name) {
        if scan.critical > 0 || scan.high > 0 {
            annot.push_str(&format!(" !! {}C/{}H", scan.critical, scan.high));
        }
        if scan.opaque {
            let urls = if scan.remote_urls.is_empty() {
                "an external source".to_string()
            } else {
                scan.remote_urls.join(", ")
            };
            annot.push_str(&format!(" ⚠ OPAQUE: runs code from {urls}"));
        }
    }

    // Avoid infinite recursion on cycles / shared deps: a repeat is shown once
    // more, marked, and not expanded again.
    let first_visit = seen.insert(name.to_string());
    if !first_visit && node.is_some_and(|n| !n.depends.is_empty()) {
        annot.push_str(" (*)");
    }
    out.push_str(&format!("{prefix}{connector}{tag} {name}{annot}\n"));
    if !first_visit {
        return;
    }
    if let Some(node) = node {
        let child_prefix = match last {
            None => String::new(),
            Some(true) => format!("{prefix}   "),
            Some(false) => format!("{prefix}│  "),
        };
        let n = node.depends.len();
        for (i, child) in node.depends.iter().enumerate() {
            render_node(
                graph,
                scans,
                child,
                &child_prefix,
                Some(i + 1 == n),
                seen,
                out,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::depgraph::{PackageNode, PackageSource};

    fn node(name: &str, source: PackageSource, deps: &[&str]) -> PackageNode {
        PackageNode {
            name: name.to_string(),
            version: Some("1.0".to_string()),
            source,
            package_base: Some(name.to_string()),
            depends: deps.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn graph() -> DependencyGraph {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "foo".into(),
            node("foo", PackageSource::Aur, &["bar", "glibc"]),
        );
        nodes.insert("bar".into(), node("bar", PackageSource::Aur, &[]));
        let mut glibc = node("glibc", PackageSource::Repo, &[]);
        glibc.repository = Some("core".into());
        nodes.insert("glibc".into(), glibc);
        DependencyGraph {
            roots: vec!["foo".into()],
            nodes,
            ..Default::default()
        }
    }

    /// Every bom-ref in the document (metadata + components), asserting uniqueness.
    fn all_refs(bom: &serde_json::Value) -> std::collections::BTreeSet<String> {
        let mut refs = std::collections::BTreeSet::new();
        let mut add = |c: &serde_json::Value| {
            let r = c["bom-ref"].as_str().unwrap().to_string();
            assert!(refs.insert(r.clone()), "duplicate bom-ref {r}");
        };
        if let Some(c) = bom["metadata"].get("component") {
            add(c);
        }
        for c in bom["components"].as_array().unwrap() {
            add(c);
        }
        refs
    }

    fn assert_refs_consistent(bom: &serde_json::Value) {
        let refs = all_refs(bom);
        for d in bom["dependencies"].as_array().unwrap() {
            assert!(
                refs.contains(d["ref"].as_str().unwrap()),
                "dangling ref {d}"
            );
            for t in d["dependsOn"].as_array().unwrap() {
                assert!(
                    refs.contains(t.as_str().unwrap()),
                    "dangling dependsOn {t} in {d}"
                );
            }
        }
        for v in bom["vulnerabilities"].as_array().unwrap() {
            for a in v["affects"].as_array().unwrap() {
                assert!(refs.contains(a["ref"].as_str().unwrap()));
            }
        }
    }

    #[test]
    fn cyclonedx_is_wellformed() {
        let g = graph();
        let scans = BTreeMap::new();
        let bom = to_cyclonedx(&g, &scans, "0.1.1", "abc", "2026-06-13T00:00:00Z");
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.5");
        // Root lives in metadata.component only; 2 other nodes are components.
        assert_eq!(bom["metadata"]["component"]["bom-ref"], "foo");
        assert_eq!(bom["components"].as_array().unwrap().len(), 2);
        assert!(bom["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["ref"] == "foo"));
        assert_refs_consistent(&bom);
    }

    #[test]
    fn bom_refs_unique_and_depends_on_never_dangle_with_no_deps() {
        // --no-deps: only the root was resolved, but it still lists children.
        let mut g = graph();
        g.nodes.retain(|k, _| k == "foo");
        let bom = to_cyclonedx(&g, &BTreeMap::new(), "0.1.1", "abc", "t");
        assert_eq!(bom["components"].as_array().unwrap().len(), 0);
        assert_refs_consistent(&bom);
        // Nothing resolvable remains to depend on: no dangling edge is emitted.
        assert!(bom["dependencies"].as_array().unwrap().is_empty());
    }

    #[test]
    fn purl_encodes_epoch_and_only_claims_known_repos() {
        let mut g = graph();
        g.nodes.get_mut("bar").unwrap().version = Some("1:2.0-3".into());
        let mut ghost = node("zz-ghost", PackageSource::Unresolved, &[]);
        ghost.version = None;
        g.nodes.insert("zz-ghost".into(), ghost);
        g.nodes.insert(
            "c++".into(),
            node("c++", PackageSource::Repo, &[]), // repo unknown
        );
        let bom = to_cyclonedx(&g, &BTreeMap::new(), "0.1.1", "abc", "t");
        let comps = bom["components"].as_array().unwrap();
        let by = |n: &str| comps.iter().find(|c| c["name"] == n).unwrap();
        assert_eq!(
            by("bar")["purl"],
            "pkg:alpm/arch/bar@1%3A2.0-3?repository=aur"
        );
        assert_eq!(
            by("glibc")["purl"],
            "pkg:alpm/arch/glibc@1.0?repository=core"
        );
        // Unknown repo: no qualifier. Unresolved: no purl at all.
        assert_eq!(by("c++")["purl"], "pkg:alpm/arch/c%2B%2B@1.0");
        assert!(by("zz-ghost").get("purl").is_none());
    }

    #[test]
    fn cyclonedx_records_findings_as_vulnerabilities() {
        let g = graph();
        let mut scans = BTreeMap::new();
        scans.insert(
            "foo".to_string(),
            ComponentScan {
                findings: vec![("ATOMIC-001".into(), "CRITICAL".into())],
                critical: 1,
                ..Default::default()
            },
        );
        let bom = to_cyclonedx(&g, &scans, "0.1.1", "abc", "t");
        let vulns = bom["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "ATOMIC-001");
        assert_eq!(vulns[0]["affects"][0]["ref"], "foo");
    }

    #[test]
    fn tree_marks_aur_and_findings() {
        let g = graph();
        let mut scans = BTreeMap::new();
        scans.insert(
            "foo".to_string(),
            ComponentScan {
                findings: vec![],
                critical: 2,
                high: 1,
                ..Default::default()
            },
        );
        let tree = render_tree(&g, &scans);
        assert!(tree.contains("[AUR] foo"));
        assert!(tree.contains("!! 2C/1H"));
        assert!(tree.contains("[repo] glibc"));
    }

    #[test]
    fn tree_is_nested_with_connectors() {
        // app -> lib -> base, app -> tool
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "app".into(),
            node("app", PackageSource::Aur, &["lib", "tool"]),
        );
        nodes.insert("lib".into(), node("lib", PackageSource::Aur, &["base"]));
        nodes.insert("base".into(), node("base", PackageSource::Aur, &[]));
        nodes.insert("tool".into(), node("tool", PackageSource::Aur, &[]));
        let g = DependencyGraph {
            roots: vec!["app".into()],
            nodes,
            ..Default::default()
        };
        let tree = render_tree(&g, &BTreeMap::new());
        let expected = "[AUR] app\n├─ [AUR] lib\n│  └─ [AUR] base\n└─ [AUR] tool\n";
        assert_eq!(tree, expected);
    }

    #[test]
    fn tree_shows_unresolved_loudly() {
        let mut g = graph();
        let mut ghost = node("ghost", PackageSource::Unresolved, &[]);
        ghost.note = Some("no such package".into());
        g.nodes.insert("ghost".into(), ghost);
        g.nodes.get_mut("foo").unwrap().depends.push("ghost".into());
        let tree = render_tree(&g, &BTreeMap::new());
        assert!(tree.contains("[UNRESOLVED] ghost"), "{tree}");
        assert!(tree.contains("no such package"), "{tree}");
    }

    #[test]
    fn opaque_boundary_is_surfaced_in_tree_and_sbom() {
        let mut g = graph();
        // Make the opaque package a non-root so it is in components[].
        g.nodes.get_mut("bar").unwrap().depends = vec![];
        let mut scans = BTreeMap::new();
        scans.insert(
            "bar".to_string(),
            ComponentScan {
                findings: vec![("EXEC-REMOTE".into(), "CRITICAL".into())],
                critical: 1,
                opaque: true,
                remote_urls: vec!["https://evil.example/x.sh".into()],
                ..Default::default()
            },
        );
        let tree = render_tree(&g, &scans);
        assert!(tree.contains("OPAQUE: runs code from https://evil.example/x.sh"));

        let bom = to_cyclonedx(&g, &scans, "0.1.1", "s", "t");
        let bar = bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "bar")
            .unwrap();
        let props = bar["properties"].as_array().unwrap();
        assert!(props.iter().any(|p| p["name"] == "aur-scan:opaque"));
        assert!(props
            .iter()
            .any(|p| p["name"] == "aur-scan:remote-source"
                && p["value"] == "https://evil.example/x.sh"));
    }
}
