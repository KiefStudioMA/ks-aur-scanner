//! SBOM generation from a resolved dependency graph.
//!
//! Produces a CycloneDX 1.5 JSON document (the security-oriented SBOM standard)
//! and a human-readable dependency tree, so a user can review the full set of
//! packages -- and any findings against them -- *before* installing.

use crate::depgraph::{DependencyGraph, PackageSource};
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

fn purl(name: &str, version: Option<&str>, source: PackageSource) -> String {
    let repo = match source {
        PackageSource::Aur => "aur",
        PackageSource::Repo => "repo",
    };
    match version {
        Some(v) => format!("pkg:alpm/arch/{name}@{v}?repository={repo}"),
        None => format!("pkg:alpm/arch/{name}?repository={repo}"),
    }
}

/// Build a CycloneDX 1.5 SBOM document. `scans` maps package name to its scan
/// summary; `serial`/`timestamp` are supplied by the caller (kept out of here
/// so the function stays deterministic and testable).
pub fn to_cyclonedx(
    graph: &DependencyGraph,
    scans: &BTreeMap<String, ComponentScan>,
    tool_version: &str,
    serial: &str,
    timestamp: &str,
) -> serde_json::Value {
    let components: Vec<serde_json::Value> = graph
        .nodes
        .values()
        .map(|n| {
            let mut properties = vec![
                serde_json::json!({"name": "aur-scan:source", "value": match n.source {
                    PackageSource::Aur => "aur",
                    PackageSource::Repo => "repo",
                }}),
                serde_json::json!({"name": "aur-scan:depth", "value": n.depth.to_string()}),
            ];
            if n.orphaned {
                properties.push(serde_json::json!({"name": "aur-scan:orphaned", "value": "true"}));
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
                "type": "library",
                "bom-ref": n.name,
                "name": n.name,
                "purl": purl(&n.name, n.version.as_deref(), n.source),
                "properties": properties,
            });
            if let Some(v) = &n.version {
                component["version"] = serde_json::json!(v);
            }
            component
        })
        .collect();

    let dependencies: Vec<serde_json::Value> = graph
        .nodes
        .values()
        .filter(|n| !n.depends.is_empty())
        .map(|n| serde_json::json!({ "ref": n.name, "dependsOn": n.depends }))
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

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "Kief Studio", "name": "aur-scan", "version": tool_version}],
            "component": graph.roots.first().map(|r| serde_json::json!({
                "type": "application",
                "bom-ref": r,
                "name": r,
            })),
        },
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
        render_node(graph, scans, root, "", true, &mut seen, &mut out);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn render_node(
    graph: &DependencyGraph,
    scans: &BTreeMap<String, ComponentScan>,
    name: &str,
    prefix: &str,
    last: bool,
    seen: &mut std::collections::BTreeSet<String>,
    out: &mut String,
) {
    let connector = if prefix.is_empty() {
        ""
    } else if last {
        "└─ "
    } else {
        "├─ "
    };

    let node = graph.nodes.get(name);
    let tag = match node.map(|n| n.source) {
        Some(PackageSource::Aur) => "[AUR]",
        Some(PackageSource::Repo) => "[repo]",
        None => "[not scanned]",
    };
    let mut annot = String::new();
    if node.map(|n| n.orphaned).unwrap_or(false) {
        annot.push_str(" ORPHAN");
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

    out.push_str(&format!("{prefix}{connector}{tag} {name}{annot}\n"));

    // Avoid infinite recursion on cycles / shared deps.
    if !seen.insert(name.to_string()) {
        return;
    }
    if let Some(node) = node {
        let child_prefix = if prefix.is_empty() {
            String::new()
        } else if last {
            format!("{prefix}   ")
        } else {
            format!("{prefix}│  ")
        };
        let n = node.depends.len();
        for (i, child) in node.depends.iter().enumerate() {
            render_node(graph, scans, child, &child_prefix, i + 1 == n, seen, out);
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
            maintainer: None,
            orphaned: false,
            depends: deps.iter().map(|s| s.to_string()).collect(),
            kinds: vec![],
            depth: 0,
        }
    }

    fn graph() -> DependencyGraph {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "foo".into(),
            node("foo", PackageSource::Aur, &["bar", "glibc"]),
        );
        nodes.insert("bar".into(), node("bar", PackageSource::Aur, &[]));
        nodes.insert("glibc".into(), node("glibc", PackageSource::Repo, &[]));
        DependencyGraph {
            roots: vec!["foo".into()],
            nodes,
            truncated: vec![],
        }
    }

    #[test]
    fn cyclonedx_is_wellformed() {
        let g = graph();
        let scans = BTreeMap::new();
        let bom = to_cyclonedx(&g, &scans, "0.1.1", "abc", "2026-06-13T00:00:00Z");
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.5");
        assert_eq!(bom["components"].as_array().unwrap().len(), 3);
        // dependencies edge for foo present
        assert!(bom["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["ref"] == "foo"));
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
    fn opaque_boundary_is_surfaced_in_tree_and_sbom() {
        let g = graph();
        let mut scans = BTreeMap::new();
        scans.insert(
            "foo".to_string(),
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
        let foo = bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "foo")
            .unwrap();
        let props = foo["properties"].as_array().unwrap();
        assert!(props.iter().any(|p| p["name"] == "aur-scan:opaque"));
        assert!(props
            .iter()
            .any(|p| p["name"] == "aur-scan:remote-source"
                && p["value"] == "https://evil.example/x.sh"));
    }
}
