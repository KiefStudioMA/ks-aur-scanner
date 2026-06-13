//! Flags language package managers (npm, pip, cargo, go, ...) that can execute
//! arbitrary registry code while fetching dependencies.
//!
//! - `PKGMGR-001` (Critical): in an install script — runs as root during the
//!   pacman transaction. This is the June 2026 `npm install atomic-lockfile` vector.
//! - `PKGMGR-002` (High): in a build function for a language unrelated to the
//!   package's declared makedepends (e.g. `npm` in a Rust package).
//! - `PKGMGR-003` (Info): in a build function for the package's own language.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::parser::ParsedPkgbuild;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

struct PkgManager {
    bin: &'static str,
    ecosystem: &'static str,
    /// Risky subcommands; empty means any invocation qualifies (e.g. npx).
    subcommands: &'static [&'static str],
}

const PACKAGE_MANAGERS: &[PkgManager] = &[
    // JavaScript / TypeScript
    PkgManager { bin: "npm", ecosystem: "javascript", subcommands: &["install", "ci", "i", "add", "rebuild", "exec", "run", "update"] },
    PkgManager { bin: "pnpm", ecosystem: "javascript", subcommands: &["install", "i", "add", "dlx", "rebuild", "exec", "run", "update"] },
    PkgManager { bin: "yarn", ecosystem: "javascript", subcommands: &["install", "add", "dlx", "run"] },
    PkgManager { bin: "bun", ecosystem: "javascript", subcommands: &["install", "add", "x", "create", "run"] },
    PkgManager { bin: "deno", ecosystem: "javascript", subcommands: &["install", "cache", "add", "run"] },
    // Runner-style binaries that execute a package directly.
    PkgManager { bin: "npx", ecosystem: "javascript", subcommands: &[] },
    PkgManager { bin: "bunx", ecosystem: "javascript", subcommands: &[] },
    PkgManager { bin: "pnpx", ecosystem: "javascript", subcommands: &[] },
    // Python
    PkgManager { bin: "pip", ecosystem: "python", subcommands: &["install"] },
    PkgManager { bin: "pip3", ecosystem: "python", subcommands: &["install"] },
    PkgManager { bin: "pipx", ecosystem: "python", subcommands: &["install", "run"] },
    PkgManager { bin: "poetry", ecosystem: "python", subcommands: &["install", "add"] },
    PkgManager { bin: "pdm", ecosystem: "python", subcommands: &["install", "add", "sync"] },
    PkgManager { bin: "uv", ecosystem: "python", subcommands: &["pip", "add", "sync", "run"] },
    // Rust
    PkgManager { bin: "cargo", ecosystem: "rust", subcommands: &["install", "build", "run", "test", "b"] },
    // Go
    PkgManager { bin: "go", ecosystem: "go", subcommands: &["install", "get", "build", "run", "generate"] },
    // Ruby
    PkgManager { bin: "gem", ecosystem: "ruby", subcommands: &["install"] },
    PkgManager { bin: "bundle", ecosystem: "ruby", subcommands: &["install"] },
    // PHP
    PkgManager { bin: "composer", ecosystem: "php", subcommands: &["install", "require", "update"] },
];

lazy_static! {
    /// One compiled regex per package manager, paired with its index.
    static ref PM_REGEXES: Vec<Regex> = PACKAGE_MANAGERS
        .iter()
        .map(|pm| {
            let pattern = if pm.subcommands.is_empty() {
                format!(r"\b{}\b", regex::escape(pm.bin))
            } else {
                // <bin> [optional -flags ...] <subcommand>
                let subs = pm
                    .subcommands
                    .iter()
                    .map(|s| regex::escape(s))
                    .collect::<Vec<_>>()
                    .join("|");
                format!(r"\b{}\s+(?:[-+][\w-]+\s+)*({})\b", regex::escape(pm.bin), subs)
            };
            Regex::new(&pattern).expect("valid package-manager regex")
        })
        .collect();
}

/// Human-readable note about how a given ecosystem can execute code.
fn ecosystem_risk(ecosystem: &str) -> &'static str {
    match ecosystem {
        "javascript" => "npm/pnpm/yarn/bun can run arbitrary pre/post-install lifecycle scripts from the registry while resolving dependencies",
        "python" => "installing a source distribution runs the project's build backend (e.g. setup.py), which can execute arbitrary code",
        "rust" => "cargo compiles dependency build scripts (build.rs) and procedural macros, which run arbitrary code at build time",
        "go" => "go can fetch remote modules and execute code via cgo or go:generate",
        "ruby" => "gem/bundler build native extensions (extconf.rb) from dependencies, which run arbitrary code",
        "php" => "composer can execute plugin and script hooks defined by dependencies",
        _ => "it can download and execute code from a remote package registry",
    }
}

/// Analyzer for language package-manager invocations.
pub struct PackageManagerAnalyzer;

impl PackageManagerAnalyzer {
    /// Create a new package-manager analyzer
    pub fn new() -> Self {
        Self
    }

    /// Infer the package's build ecosystem(s) from its declared makedepends.
    fn infer_ecosystems(pkgbuild: &ParsedPkgbuild) -> HashSet<&'static str> {
        let mut set = HashSet::new();
        let deps = pkgbuild
            .makedepends
            .iter()
            .chain(pkgbuild.depends.iter())
            .chain(pkgbuild.checkdepends.iter());

        for dep in deps {
            // Strip version constraints / provides syntax: python>=3.8 -> python
            let name = dep
                .split(['>', '<', '=', ':'])
                .next()
                .unwrap_or(dep)
                .trim()
                .to_lowercase();

            if name == "nodejs"
                || name.starts_with("nodejs")
                || name == "node"
                || name.starts_with("electron")
                || matches!(name.as_str(), "npm" | "pnpm" | "yarn" | "bun" | "deno")
            {
                set.insert("javascript");
            }
            if name == "python" || name.starts_with("python") || name.starts_with("pypy") {
                set.insert("python");
            }
            if name.starts_with("rust") || name == "cargo" {
                set.insert("rust");
            }
            if name == "go" || name == "golang" || name.starts_with("golang") || name.starts_with("go-")
            {
                set.insert("go");
            }
            if name == "ruby" || name.starts_with("ruby") {
                set.insert("ruby");
            }
            if name == "php" || name.starts_with("php") || name == "composer" {
                set.insert("php");
            }
        }

        set
    }

    /// Scan a block of content, returning (line_offset_within_block, matched_text, pm_index)
    /// for each package-manager invocation found on a non-comment line.
    fn scan(content: &str) -> Vec<(usize, String, usize)> {
        let mut hits = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            for (pm_idx, re) in PM_REGEXES.iter().enumerate() {
                if let Some(m) = re.find(line) {
                    hits.push((line_idx, m.as_str().trim().to_string(), pm_idx));
                }
            }
        }
        hits
    }
}

impl Default for PackageManagerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for PackageManagerAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let inferred = Self::infer_ecosystems(&context.pkgbuild);

        // In an install script, any package-manager invocation is critical.
        if let Some(ref script) = context.install_script {
            for (line_idx, matched, pm_idx) in Self::scan(&script.content) {
                let pm = &PACKAGE_MANAGERS[pm_idx];
                findings.push(Finding {
                    id: "PKGMGR-001".to_string(),
                    severity: Severity::Critical,
                    category: Category::MaliciousCode,
                    title: "Language package manager invoked in install script".to_string(),
                    description: format!(
                        "The install script runs '{}' ({}). Install scripts execute as root \
                         during the pacman transaction; invoking a language package manager here \
                         downloads and builds dependencies from a remote registry, and {}. This is \
                         the technique used in the June 2026 AUR supply-chain attack \
                         (npm install atomic-lockfile / bun install js-digest).",
                        matched,
                        pm.ecosystem,
                        ecosystem_risk(pm.ecosystem),
                    ),
                    location: Location {
                        file: script.path.clone(),
                        line: Some(line_idx + 1),
                        column: None,
                        snippet: Some(matched.clone()),
                    },
                    recommendation:
                        "Install scripts must never fetch or build packages. Vendor all \
                         dependencies at build time and remove this call."
                            .to_string(),
                    cwe_id: Some("CWE-94".to_string()),
                    metadata: serde_json::json!({
                        "binary": pm.bin,
                        "ecosystem": pm.ecosystem,
                        "matched_text": matched,
                        "in_install_script": true,
                    }),
                });
            }
        }

        // In build functions, cross-ecosystem use is High, same-ecosystem is Info.
        for (func_name, func) in &context.pkgbuild.functions {
            let is_build_phase = matches!(func_name.as_str(), "build" | "prepare" | "check")
                || func_name == "package"
                || func_name.starts_with("package_");
            if !is_build_phase {
                continue;
            }

            for (line_idx, matched, pm_idx) in Self::scan(&func.content) {
                let pm = &PACKAGE_MANAGERS[pm_idx];
                let line = Some(func.line_start + line_idx);

                // Without an inferred language we can't call anything "unrelated".
                let cross_language = !inferred.is_empty() && !inferred.contains(pm.ecosystem);

                if cross_language {
                    let mut langs: Vec<&str> = inferred.iter().copied().collect();
                    langs.sort_unstable();
                    findings.push(Finding {
                        id: "PKGMGR-002".to_string(),
                        severity: Severity::High,
                        category: Category::MaliciousCode,
                        title: "Cross-ecosystem package manager in build function".to_string(),
                        description: format!(
                            "Function '{}' invokes '{}' ({}), but the package's declared build \
                             dependencies indicate a {} project. Pulling in an unrelated \
                             language's package manager is a supply-chain red flag: {}.",
                            func_name,
                            matched,
                            pm.ecosystem,
                            langs.join("/"),
                            ecosystem_risk(pm.ecosystem),
                        ),
                        location: Location {
                            file: context.file_path.clone(),
                            line,
                            column: None,
                            snippet: Some(matched.clone()),
                        },
                        recommendation: format!(
                            "Verify why a {} package manager is needed. Prefer Arch packages or \
                             vendored, checksummed sources over fetching from {} registries at \
                             build time. If legitimate, declare the toolchain in makedepends.",
                            pm.ecosystem, pm.ecosystem,
                        ),
                        cwe_id: Some("CWE-829".to_string()),
                        metadata: serde_json::json!({
                            "binary": pm.bin,
                            "ecosystem": pm.ecosystem,
                            "matched_text": matched,
                            "function": func_name,
                            "inferred_ecosystems": langs,
                        }),
                    });
                } else {
                    findings.push(Finding {
                        id: "PKGMGR-003".to_string(),
                        severity: Severity::Info,
                        category: Category::Dependencies,
                        title: "Package manager fetches dependencies at build time".to_string(),
                        description: format!(
                            "Function '{}' invokes '{}' ({}); {}. Confirm dependencies are pinned \
                             and integrity-checked.",
                            func_name,
                            matched,
                            pm.ecosystem,
                            ecosystem_risk(pm.ecosystem),
                        ),
                        location: Location {
                            file: context.file_path.clone(),
                            line,
                            column: None,
                            snippet: Some(matched.clone()),
                        },
                        recommendation:
                            "Prefer offline/vendored builds (e.g. --offline, --frozen-lockfile, \
                             --ignore-scripts) so the build cannot execute unreviewed remote code."
                                .to_string(),
                        cwe_id: Some("CWE-829".to_string()),
                        metadata: serde_json::json!({
                            "binary": pm.bin,
                            "ecosystem": pm.ecosystem,
                            "matched_text": matched,
                            "function": func_name,
                        }),
                    });
                }
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "package_manager"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{ParsedInstallScript, PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn ctx(pkgbuild: &str, install: Option<&str>) -> AnalysisContext {
        let parser = StaticParser::new();
        let install_script = install.map(|c| ParsedInstallScript {
            content: c.to_string(),
            path: PathBuf::from("pkg.install"),
            hooks: crate::parser::parse_install_hooks(c),
        });
        AnalysisContext {
            pkgbuild: parser.parse(pkgbuild).unwrap(),
            install_script,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        }
    }

    #[tokio::test]
    async fn test_npm_in_install_script_is_critical() {
        let analyzer = PackageManagerAnalyzer::new();
        let install = "post_install() {\n    npm install atomic-lockfile\n}\n";
        let findings = analyzer
            .analyze(&ctx("pkgname=t\npkgver=1\npkgrel=1\n", Some(install)))
            .await
            .unwrap();
        let f = findings.iter().find(|f| f.id == "PKGMGR-001").unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_cross_language_npm_in_rust_build_is_high() {
        let analyzer = PackageManagerAnalyzer::new();
        let pkgbuild = "pkgname=t\npkgver=1\npkgrel=1\nmakedepends=('rust' 'cargo')\nbuild() {\n    npm install\n}\n";
        let findings = analyzer.analyze(&ctx(pkgbuild, None)).await.unwrap();
        let f = findings.iter().find(|f| f.id == "PKGMGR-002").unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[tokio::test]
    async fn test_same_language_cargo_in_rust_build_is_info_only() {
        // False-positive guard: a normal Rust package must not raise High/Critical.
        let analyzer = PackageManagerAnalyzer::new();
        let pkgbuild = "pkgname=t\npkgver=1\npkgrel=1\nmakedepends=('rust')\nbuild() {\n    cargo build --release --frozen\n}\n";
        let findings = analyzer.analyze(&ctx(pkgbuild, None)).await.unwrap();
        assert!(!findings.iter().any(|f| f.severity <= Severity::Medium));
        assert!(findings.iter().any(|f| f.id == "PKGMGR-003"));
    }

    #[tokio::test]
    async fn test_same_language_npm_in_node_build_is_info() {
        let analyzer = PackageManagerAnalyzer::new();
        let pkgbuild = "pkgname=t\npkgver=1\npkgrel=1\nmakedepends=('npm' 'nodejs')\nbuild() {\n    npm install\n}\n";
        let findings = analyzer.analyze(&ctx(pkgbuild, None)).await.unwrap();
        assert!(!findings.iter().any(|f| f.id == "PKGMGR-002"));
        assert!(findings.iter().any(|f| f.id == "PKGMGR-003"));
    }

    #[tokio::test]
    async fn test_no_package_manager_no_findings() {
        let analyzer = PackageManagerAnalyzer::new();
        let pkgbuild = "pkgname=t\npkgver=1\npkgrel=1\nmakedepends=('cmake')\nbuild() {\n    make\n}\n";
        let findings = analyzer.analyze(&ctx(pkgbuild, None)).await.unwrap();
        assert!(findings.is_empty());
    }
}
