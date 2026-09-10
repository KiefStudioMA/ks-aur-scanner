//! Prebuilt binaries shipped inside a package directory.
//!
//! Everything here is static: [`crate::elf`] parses bytes and nothing is ever
//! executed, mapped executable, or handed to the dynamic loader. See that
//! module for why `ldd` in particular is off-limits.
//!
//! # What is actually suspicious
//!
//! Not "the package contains a binary" — a `-bin` package downloading a
//! prebuilt tarball is its entire reason to exist. The signal is an executable
//! **committed into the AUR repository itself**, because that repository is
//! supposed to hold a build recipe, not an artifact. That is precisely the
//! shape reported in issue #29: a `validator` ELF sitting beside the PKGBUILD,
//! run with `sudo` during `build()`.
//!
//! # What is deliberately NOT a finding
//!
//! Capability symbols on their own. Measured against real system binaries,
//! `/usr/bin/ssh` imports `socket`, `connect`, `getaddrinfo`, `execl`, `fork`,
//! `popen`, `system` and `dlopen`; `/bin/bash` imports nearly the same set.
//! "This binary can open a socket and run a command" describes a large fraction
//! of legitimate software, so it is reported as *context on an
//! already-suspicious binary*, never as a reason to flag one.

use super::SecurityAnalyzer;
use crate::elf::{self, ElfInfo};
use crate::error::Result;
use crate::types::{AnalysisContext, BinaryArtifact, Category, Finding, Location, Severity};
use async_trait::async_trait;

/// Shannon entropy above which a section looks compressed or encrypted rather
/// than compiled.
///
/// Calibrated against real files rather than guessed: ordinary system binaries
/// measure 6.0–6.9 bits/byte (`ls` 6.02, `bash` 6.32, `libcrypto` 6.52, with the
/// highest single section at 6.86), gzip output measures 7.99, and random bytes
/// 8.00. 7.5 sits in the empty space between the two populations.
const PACKED_ENTROPY: f64 = 7.5;

/// Symbols that indicate outbound network capability.
const NETWORK_SYMBOLS: &[&str] = &[
    "socket",
    "connect",
    "getaddrinfo",
    "gethostbyname",
    "inet_addr",
    "inet_pton",
    "sendto",
    "recvfrom",
    "SSL_connect",
    "curl_easy_perform",
];

/// Symbols that indicate running other programs, or manipulating processes.
const EXEC_SYMBOLS: &[&str] = &[
    "system",
    "popen",
    "execve",
    "execl",
    "execlp",
    "execvp",
    "fork",
    "posix_spawn",
    "ptrace",
    "memfd_create",
    "dlopen",
];

/// Analyzer for prebuilt binaries in a package directory.
pub struct BinaryAnalyzer;

impl BinaryAnalyzer {
    /// Create a new binary analyzer.
    pub fn new() -> Self {
        Self
    }

    /// Capability summary for a parsed ELF, used as evidence on a finding.
    fn capabilities(info: &ElfInfo) -> (Vec<String>, Vec<String>) {
        let net: Vec<String> = info
            .imports
            .iter()
            .filter(|s| NETWORK_SYMBOLS.contains(&s.as_str()))
            .cloned()
            .collect();
        let exec: Vec<String> = info
            .imports
            .iter()
            .filter(|s| EXEC_SYMBOLS.contains(&s.as_str()))
            .cloned()
            .collect();
        (net, exec)
    }

    /// A short phrase describing what the binary can do, or `None`.
    fn capability_note(info: &ElfInfo) -> Option<String> {
        let (net, exec) = Self::capabilities(info);
        match (net.is_empty(), exec.is_empty()) {
            (true, true) => None,
            (false, true) => Some(format!("links network calls ({})", net.join(", "))),
            (true, false) => Some(format!("runs other programs ({})", exec.join(", "))),
            (false, false) => Some(format!(
                "both opens network connections ({}) and runs other programs ({})",
                net.join(", "),
                exec.join(", ")
            )),
        }
    }

    /// A run path is dangerous when it is relative, or points somewhere any
    /// local user can write. Both let an attacker place a library that the
    /// binary will load in preference to the system one.
    fn hazardous_run_path(p: &str) -> Option<&'static str> {
        let lower = p.to_ascii_lowercase();

        // `$ORIGIN` is the normal, safe idiom: it resolves against the
        // BINARY's own directory, so `$ORIGIN/../lib` is just "the lib
        // directory next to my bin directory" and is what every relocatable
        // install uses. Judge it on how far it climbs, not on containing `..`
        // at all -- from /usr/bin, three levels up reaches the filesystem root
        // and can then descend into somewhere writable.
        if lower.starts_with("$origin") {
            let ups = lower.matches("..").count();
            return if ups > 2 {
                Some("a $ORIGIN path that climbs far enough to leave the install tree")
            } else {
                None
            };
        }

        if lower.starts_with("/tmp")
            || lower.starts_with("/var/tmp")
            || lower.starts_with("/dev/shm")
        {
            return Some("a world-writable directory");
        }
        // A bare relative path resolves against the CURRENT working directory
        // at run time, which the caller controls rather than the packager.
        if !lower.starts_with('/') {
            return Some("a relative path resolved against the working directory");
        }
        if lower.contains("..") {
            return Some("a path that escapes its own directory");
        }
        None
    }

    fn analyze_artifact(
        &self,
        art: &BinaryArtifact,
        ctx: &AnalysisContext,
        findings: &mut Vec<Finding>,
    ) {
        let name = art
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let loc = || Location {
            file: art.path.clone(),
            line: None,
            column: None,
            snippet: Some(name.clone()),
        };

        let info = elf::parse(&art.head);
        let cap = info.as_ref().and_then(Self::capability_note);
        let cap_clause = cap
            .as_deref()
            .map(|c| format!(" It {c}."))
            .unwrap_or_default();

        // Where is this file referenced?
        let run_in_build = ctx
            .pkgbuild
            .functions
            .iter()
            .filter(|(fname, _)| fname.as_str() != "package")
            .any(|(_, body)| body.content.contains(&name));
        let installed = ctx
            .pkgbuild
            .functions
            .iter()
            .filter(|(fname, _)| fname.starts_with("package"))
            .any(|(_, body)| body.content.contains(&name));

        // BIN-002 -- executed during the build.
        //
        // The build runs as your user, before anything is installed, and a
        // committed binary has no upstream anyone can review. Combined with
        // PRIV-001 (sudo in build) this is exactly the openconnect-sso report.
        if run_in_build {
            findings.push(Finding {
                id: "BIN-002".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousCode,
                title: format!("Prebuilt binary '{name}' is executed during the build"),
                description: format!(
                    "'{name}' is an {} committed alongside the PKGBUILD, and a build function \
                     references it. Building a package should compile source, not run an opaque \
                     executable that shipped with the recipe -- there is no upstream for a \
                     reviewer to compare it against.{cap_clause}",
                    art.format
                ),
                location: loc(),
                recommendation: "Do not build this package. A build step that runs a bundled \
                                 binary is running code nobody has reviewed."
                    .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({
                    "file": name,
                    "format": art.format,
                    "size_bytes": art.size,
                    "network_symbols": info.as_ref().map(|i| Self::capabilities(i).0),
                    "exec_symbols": info.as_ref().map(|i| Self::capabilities(i).1),
                }),
            });
        } else {
            // BIN-001 -- present but not run during the build.
            //
            // Lower, because a package legitimately ships an icon or a small
            // helper it installs. Still worth naming: an AUR repository holds a
            // build recipe, and an executable in it is an artifact nobody
            // fetched from a declared source.
            let (sev, why) = if installed {
                (
                    Severity::Medium,
                    "It is installed by package(), so it will land on the system.",
                )
            } else {
                (
                    Severity::High,
                    "It is NOT installed by package() and NOT used by the build, so nothing in \
                     this PKGBUILD explains why it is here.",
                )
            };
            findings.push(Finding {
                id: "BIN-001".to_string(),
                severity: sev,
                category: Category::SuspiciousMetadata,
                title: format!("Prebuilt binary '{name}' committed in the package directory"),
                description: format!(
                    "'{name}' is an {} shipped inside the package directory rather than fetched \
                     from a declared source. {why}{cap_clause}",
                    art.format
                ),
                location: loc(),
                recommendation: "Confirm why a compiled artifact ships with the build recipe, \
                                 and where it came from."
                    .to_string(),
                cwe_id: Some("CWE-494".to_string()),
                metadata: serde_json::json!({
                    "file": name,
                    "format": art.format,
                    "size_bytes": art.size,
                    "installed_by_package": installed,
                    "used_by_build": run_in_build,
                }),
            });
        }

        let Some(info) = info else {
            return;
        };

        // BIN-003 -- an eBPF object.
        //
        // eBPF runs in the kernel. The June 2026 Atomic Arch campaign shipped an
        // eBPF rootkit (`scales.bpf.c`) exactly this way, and there is no
        // ordinary reason for a package to carry one as a prebuilt blob.
        if info.machine == elf::EM_BPF
            || info
                .sections
                .iter()
                .any(|s| s.starts_with(".bpf") || s == ".BTF")
        {
            findings.push(Finding {
                id: "BIN-003".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousCode,
                title: format!("'{name}' is a prebuilt eBPF object"),
                description: format!(
                    "'{name}' is an eBPF object shipped as a compiled blob. eBPF programs run \
                     IN THE KERNEL, and this one arrives with no source for anyone to read. The \
                     June 2026 Atomic Arch campaign delivered an eBPF rootkit through AUR \
                     packages in this form."
                ),
                location: loc(),
                recommendation: "Do not install. Obtain the eBPF source and build it, or use a \
                                 package that does."
                    .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({
                    "file": name,
                    "machine": info.machine,
                    "sections": info.sections,
                }),
            });
        }

        // BIN-004 -- a run path an attacker can win.
        for rp in &info.run_paths {
            if let Some(why) = Self::hazardous_run_path(rp) {
                findings.push(Finding {
                    id: "BIN-004".to_string(),
                    severity: Severity::High,
                    category: Category::PrivilegeEscalation,
                    title: format!("'{name}' searches for libraries in an unsafe location"),
                    description: format!(
                        "'{name}' carries a run path of '{rp}', which is {why}. A library placed \
                         there is loaded in preference to the system copy, so whoever can write \
                         to that location controls what this binary executes."
                    ),
                    location: loc(),
                    recommendation: "Do not install a binary whose library search path can be \
                                     written by others."
                        .to_string(),
                    cwe_id: Some("CWE-426".to_string()),
                    metadata: serde_json::json!({ "file": name, "run_path": rp, "reason": why }),
                });
            }
        }

        // BIN-005 -- a section that looks compressed or encrypted.
        if info.max_section_entropy >= PACKED_ENTROPY {
            let section = info.max_entropy_section.clone().unwrap_or_default();
            findings.push(Finding {
                id: "BIN-005".to_string(),
                severity: Severity::Medium,
                category: Category::Obfuscation,
                title: format!("'{name}' contains a packed or encrypted section"),
                description: format!(
                    "Section '{section}' of '{name}' measures {:.2} bits/byte of entropy. \
                     Ordinary compiled code measures around 6.0-6.9; compressed data measures \
                     ~8.0. Content this dense is packed or encrypted, which prevents any static \
                     review of what the binary actually contains.",
                    info.max_section_entropy
                ),
                location: loc(),
                recommendation: "Treat a packed binary in a source package as unreviewable."
                    .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({
                    "file": name,
                    "section": section,
                    "entropy": info.max_section_entropy,
                }),
            });
        }
    }
}

impl Default for BinaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for BinaryAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for art in &context.local_binaries {
            self.analyze_artifact(art, context, &mut findings);
        }
        Ok(findings)
    }

    fn name(&self) -> &str {
        "binary"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn elf_header(e_type: u16, machine: u16) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(elf::ELF_MAGIC);
        v[4] = 2;
        v[5] = 1;
        v[6] = 1;
        v[16..18].copy_from_slice(&e_type.to_le_bytes());
        v[18..20].copy_from_slice(&machine.to_le_bytes());
        v
    }

    fn ctx_with(pkgbuild: &str, arts: Vec<BinaryArtifact>) -> AnalysisContext {
        AnalysisContext {
            pkgbuild: StaticParser::new().parse(pkgbuild).unwrap(),
            install_script: None,
            side_scripts: vec![],
            local_binaries: arts,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
            registry: None,
        }
    }

    fn artifact(name: &str, head: Vec<u8>) -> BinaryArtifact {
        BinaryArtifact {
            path: PathBuf::from(name),
            format: "ELF",
            size: head.len() as u64,
            head,
        }
    }

    async fn run(pkgbuild: &str, arts: Vec<BinaryArtifact>) -> Vec<Finding> {
        BinaryAnalyzer::new()
            .analyze(&ctx_with(pkgbuild, arts))
            .await
            .unwrap()
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    #[tokio::test]
    async fn a_binary_executed_during_build_is_critical() {
        // Issue #29: a `validator` ELF committed beside the PKGBUILD and run
        // during build().
        let f = run(
            "pkgname=t\npkgver=1\npkgrel=1\nbuild() {\n  sudo ./validator --check\n  make\n}\n",
            vec![artifact("validator", elf_header(2, 62))],
        )
        .await;
        let b = f.iter().find(|x| x.id == "BIN-002").expect("must fire");
        assert_eq!(b.severity, Severity::Critical);
        assert!(b.description.contains("validator"));
    }

    #[tokio::test]
    async fn an_unexplained_binary_is_high_and_an_installed_one_is_medium() {
        // Nothing in the PKGBUILD references it at all.
        let f = run(
            "pkgname=t\npkgver=1\npkgrel=1\nbuild() {\n  make\n}\n",
            vec![artifact("splitter", elf_header(2, 62))],
        )
        .await;
        let b = f.iter().find(|x| x.id == "BIN-001").unwrap();
        assert_eq!(b.severity, Severity::High);
        assert!(
            b.description
                .contains("nothing in this PKGBUILD explains why it is here")
                || b.description.contains("NOT installed")
        );

        // Installed by package() -- still noted, but explicable.
        let f2 = run(
            "pkgname=t\npkgver=1\npkgrel=1\npackage() {\n  install -Dm755 helper \"$pkgdir/usr/bin/helper\"\n}\n",
            vec![artifact("helper", elf_header(2, 62))],
        )
        .await;
        let b2 = f2.iter().find(|x| x.id == "BIN-001").unwrap();
        assert_eq!(b2.severity, Severity::Medium);
    }

    #[tokio::test]
    async fn an_ebpf_object_is_critical() {
        let f = run(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            vec![artifact("scales.bpf.o", elf_header(1, elf::EM_BPF))],
        )
        .await;
        assert!(ids(&f).contains(&"BIN-003"), "got {:?}", ids(&f));
        let b = f.iter().find(|x| x.id == "BIN-003").unwrap();
        assert_eq!(b.severity, Severity::Critical);
        assert!(b.description.contains("KERNEL"));
    }

    #[tokio::test]
    async fn capability_symbols_alone_are_not_a_finding() {
        // /usr/bin/ssh imports socket, connect, execve, fork, dlopen and
        // popen; so does bash. Reporting that as suspicious would flag a large
        // fraction of legitimate software. It is context, never a cause.
        let info = ElfInfo {
            imports: vec![
                "socket".into(),
                "connect".into(),
                "execve".into(),
                "dlopen".into(),
            ],
            ..Default::default()
        };
        let note = BinaryAnalyzer::capability_note(&info).expect("summarised as context");
        assert!(note.contains("network"));
        assert!(note.contains("runs other programs"));

        // No artifact at all -> no findings, regardless of capabilities.
        let f = run("pkgname=t\npkgver=1\npkgrel=1\n", vec![]).await;
        assert!(f.is_empty());
    }

    #[test]
    fn hazardous_run_paths_are_recognised_and_normal_ones_are_not() {
        for bad in ["/tmp/lib", "/var/tmp", "/dev/shm/x", "../lib", "lib"] {
            assert!(
                BinaryAnalyzer::hazardous_run_path(bad).is_some(),
                "{bad} should be flagged"
            );
        }
        // `$ORIGIN/../lib` is the standard relocatable-install idiom and must
        // not be flagged; climbing far enough to leave the tree is different.
        assert!(
            BinaryAnalyzer::hazardous_run_path("$ORIGIN/../../../../tmp").is_some(),
            "excessive $ORIGIN traversal should be flagged"
        );
        for ok in ["/usr/lib", "$ORIGIN/../lib", "$ORIGIN/lib", "/opt/app/lib"] {
            assert!(
                BinaryAnalyzer::hazardous_run_path(ok).is_none(),
                "{ok} is a normal run path"
            );
        }
    }

    #[tokio::test]
    async fn a_package_with_no_binaries_produces_nothing() {
        let f = run(
            "pkgname=t\npkgver=1\npkgrel=1\nbuild() { make; }\npackage() { make install; }\n",
            vec![],
        )
        .await;
        assert!(f.is_empty());
    }

    #[tokio::test]
    async fn an_unparseable_blob_still_reports_its_presence() {
        // Truncated/corrupt ELF: we cannot read its structure, but "a binary is
        // committed here" is still true and still worth saying.
        let f = run(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            vec![artifact("broken", b"\x7fELF\x02\x01".to_vec())],
        )
        .await;
        assert!(ids(&f).contains(&"BIN-001"), "got {:?}", ids(&f));
    }
}
