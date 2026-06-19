//! Binary payload analyzer for prebuilt (`-bin`) packages.
//!
//! A PKGBUILD scanner never opens the prebuilt binary that a `-bin` package
//! ships in `source=`, yet that binary *is* the payload for campaigns like
//! CHAOS RAT and Atomic Arch. This analyzer closes that blind spot without ever
//! executing anything: it only reads bytes and parses headers.
//!
//! Two tiers, cheapest first:
//!  * **Reputation** (always on, no download): the PKGBUILD already declares
//!    `sha256sums`, so we look that hash up in the local IOC database
//!    (`BIN-HASH`) and, *only if a VirusTotal key is already present in the
//!    environment*, query VirusTotal by hash (`BIN-VT`). No key is ever
//!    required or embedded.
//!  * **Structure** (only if the artifact bytes are already on disk next to the
//!    PKGBUILD): parse the ELF with `goblin` and flag eBPF objects (`BIN-EBPF`),
//!    suspicious imports (`BIN-IMPORT`), packers / high entropy (`BIN-PACKED`),
//!    and embedded known-C2 domains (`BIN-STRING`).

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::threat_intel::IocDatabase;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Cap on bytes read from a local artifact (real payloads are well under this;
/// the cap bounds memory against a hostile multi-GB file).
const MAX_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;

/// ELF `e_machine` value for eBPF.
const EM_BPF: u16 = 247;

/// Whole-file Shannon entropy above which an ELF is treated as packed/encrypted.
const PACKED_ENTROPY: f64 = 7.2;

/// Imported symbols that are genuinely rare in ordinary software and strongly
/// associated with anti-debugging, process injection, and rootkits.
///
/// This list is deliberately narrow. Common symbols that also appear in benign
/// binaries (dlopen, mprotect, syscall, setuid/setgid, prctl, memfd_create) are
/// excluded on purpose: firing on those would flag bash and most Rust/Go
/// binaries, eroding trust in every other finding.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "ptrace",            // anti-debugging / debugger-evasion
    "process_vm_readv",  // reading another process's memory
    "process_vm_writev", // writing another process's memory
    "bpf",               // raw bpf(2) syscall (pairs with eBPF payloads)
];

/// Extensions that indicate a shipped binary artifact rather than source.
const BINARY_EXTS: &[&str] = &[
    ".appimage",
    ".elf",
    ".bin",
    ".run",
    ".so",
    ".deb",
    ".pkg.tar.zst",
    ".pkg.tar.xz",
];

/// Analyzer that inspects prebuilt binary artifacts referenced from `source=`.
pub struct BinaryPayloadAnalyzer {
    db: Arc<IocDatabase>,
    /// VirusTotal API key picked up from the environment, if any. When absent,
    /// the VT stage is silently skipped — a key is never required.
    vt_key: Option<String>,
}

impl BinaryPayloadAnalyzer {
    /// Create an analyzer backed by the given IOC database. A VirusTotal key is
    /// auto-detected from `VT_API_KEY` / `VIRUSTOTAL_API_KEY`; none is required.
    pub fn new(db: Arc<IocDatabase>) -> Self {
        let vt_key = std::env::var("VT_API_KEY")
            .or_else(|_| std::env::var("VIRUSTOTAL_API_KEY"))
            .ok()
            .filter(|k| !k.trim().is_empty());
        Self { db, vt_key }
    }
}

#[async_trait]
impl SecurityAnalyzer for BinaryPayloadAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let dir = context.file_path.parent().unwrap_or_else(|| Path::new("."));
        let pkg_is_bin = context.pkgbuild.pkgname.iter().any(|n| n.ends_with("-bin"));
        let sha256s = &context.pkgbuild.checksums.sha256sums;

        for (idx, src) in context.pkgbuild.source.iter().enumerate() {
            let name = artifact_name(src);
            if !is_binary_artifact(&name, pkg_is_bin) {
                continue;
            }

            // --- Tier A: reputation from the declared hash (no bytes needed) ---
            let declared = sha256s
                .get(idx)
                .and_then(|o| o.clone())
                .map(|h| h.to_lowercase());
            if let Some(hash) = &declared {
                if let Some(f) = self.reputation(context, &name, hash).await {
                    findings.push(f);
                    continue; // definitively bad; skip further work
                }
            }

            // --- Tier B: structural inspection of locally available bytes ---
            let Some(path) = resolve_local(dir, src, &name) else {
                continue;
            };
            let Some(bytes) = read_capped(&path) else {
                continue;
            };
            if !is_elf(&bytes) {
                continue; // ELF-only in v1 (no decompression dependency)
            }

            // If the PKGBUILD declared no usable hash (e.g. sha256sums=SKIP, very
            // common for -bin packages), hash the local bytes ourselves so the
            // reputation check still applies.
            if declared.is_none() {
                let computed = sha256_hex(&bytes);
                if let Some(f) = self.reputation(context, &name, &computed).await {
                    findings.push(f);
                    continue;
                }
            }

            findings.extend(self.inspect_elf(&path, &bytes));
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "binary"
    }
}

impl BinaryPayloadAnalyzer {
    /// Reputation check for a single hash: local IOC database first, then
    /// VirusTotal (only if a key is present). Returns a finding if known-bad.
    async fn reputation(&self, ctx: &AnalysisContext, name: &str, hash: &str) -> Option<Finding> {
        if let Some(campaign) = self.db.match_sha256(hash) {
            return Some(self.hash_finding(ctx, name, hash, campaign));
        }
        if let Some(key) = &self.vt_key {
            if let Some(mal) = vt_lookup(key, hash).await {
                if mal > 0 {
                    return Some(self.vt_finding(ctx, name, hash, mal));
                }
            }
        }
        None
    }

    fn hash_finding(
        &self,
        ctx: &AnalysisContext,
        name: &str,
        hash: &str,
        campaign: &str,
    ) -> Finding {
        let suffix = self
            .db
            .campaign(campaign)
            .map(|c| format!(" (campaign: {})", c.name))
            .unwrap_or_default();
        Finding {
            id: "BIN-HASH".into(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            title: format!("Source artifact hash is a known payload: {name}"),
            description: format!(
                "The declared sha256 of '{name}' matches a known-malicious payload hash in the \
                 IOC database{suffix}. The prebuilt binary itself is the malware."
            ),
            location: loc(&ctx.file_path, Some(format!("sha256: {hash}"))),
            recommendation: "Do NOT build/install. This artifact is a known payload.".into(),
            cwe_id: Some("CWE-506".into()),
            metadata: serde_json::json!({ "artifact": name, "sha256": hash, "campaign": campaign }),
        }
    }

    fn vt_finding(&self, ctx: &AnalysisContext, name: &str, hash: &str, mal: u64) -> Finding {
        Finding {
            id: "BIN-VT".into(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            title: format!("VirusTotal flags source artifact: {name}"),
            description: format!(
                "VirusTotal reports {mal} engine(s) detecting the declared sha256 of '{name}' as \
                 malicious."
            ),
            location: loc(&ctx.file_path, Some(format!("sha256: {hash}"))),
            recommendation: "Do NOT build/install; review the VirusTotal report for this hash."
                .into(),
            cwe_id: Some("CWE-506".into()),
            metadata: serde_json::json!({ "artifact": name, "sha256": hash, "vt_malicious": mal }),
        }
    }

    /// Structural checks on an ELF artifact.
    fn inspect_elf(&self, path: &Path, bytes: &[u8]) -> Vec<Finding> {
        let mut out = Vec::new();
        let report = ElfReport::of(bytes);

        if report.is_ebpf {
            out.push(Finding {
                id: "BIN-EBPF".into(),
                severity: Severity::High,
                category: Category::Persistence,
                title: "Prebuilt binary contains eBPF objects".into(),
                description:
                    "The shipped binary embeds eBPF bytecode (EM_BPF machine or .bpf/.BTF \
                     sections). eBPF can hook syscalls and hide processes/files — the Atomic Arch \
                     payload shipped an eBPF rootkit (scales.bpf.c)."
                        .into(),
                location: loc(path, None),
                recommendation:
                    "Verify the package legitimately needs eBPF; treat as a rootkit otherwise."
                        .into(),
                cwe_id: Some("CWE-506".into()),
                metadata: serde_json::json!({ "sections": report.bpf_sections }),
            });
        }

        if !report.suspicious_imports.is_empty() {
            out.push(Finding {
                id: "BIN-IMPORT".into(),
                severity: Severity::Medium,
                category: Category::MaliciousCode,
                title: "Prebuilt binary imports high-risk syscalls".into(),
                description: format!(
                    "The shipped binary imports unusual symbols ({}). These are typical of \
                     anti-debugging, code injection, and rootkit behavior.",
                    report.suspicious_imports.join(", ")
                ),
                location: loc(path, None),
                recommendation:
                    "Review why these are needed; cross-check against upstream sources.".into(),
                cwe_id: Some("CWE-506".into()),
                metadata: serde_json::json!({ "imports": report.suspicious_imports }),
            });
        }

        if report.packed {
            out.push(Finding {
                id: "BIN-PACKED".into(),
                severity: Severity::High,
                category: Category::Obfuscation,
                title: "Prebuilt binary appears packed/obfuscated".into(),
                description: format!(
                    "The shipped binary shows packer indicators ({}). Packing hides the real code \
                     from inspection and is common in malware droppers.",
                    report.packer_reason
                ),
                location: loc(path, None),
                recommendation: "Unpack and review, or obtain a build from reviewable source.".into(),
                cwe_id: Some("CWE-506".into()),
                metadata: serde_json::json!({ "reason": report.packer_reason, "entropy": report.entropy }),
            });
        }

        for domain in self.db.domains.keys() {
            if contains_ascii_ci(bytes, domain.as_bytes()) {
                out.push(Finding {
                    id: "BIN-STRING".into(),
                    severity: Severity::Critical,
                    category: Category::DataExfiltration,
                    title: format!("Prebuilt binary embeds known C2 domain: {domain}"),
                    description: format!(
                        "The shipped binary contains the string '{domain}', a known C2/exfil \
                         indicator from the IOC database."
                    ),
                    location: loc(path, Some(domain.clone())),
                    recommendation: "Do NOT build/install; the binary references known-malicious infrastructure.".into(),
                    cwe_id: Some("CWE-506".into()),
                    metadata: serde_json::json!({ "domain": domain }),
                });
            }
        }

        out
    }
}

/// Structural summary of an ELF, extracted without executing it.
#[derive(Default)]
struct ElfReport {
    is_ebpf: bool,
    bpf_sections: Vec<String>,
    suspicious_imports: Vec<String>,
    packed: bool,
    packer_reason: String,
    entropy: f64,
}

impl ElfReport {
    fn of(bytes: &[u8]) -> Self {
        let mut r = ElfReport {
            entropy: shannon_entropy(bytes),
            ..Default::default()
        };

        if let Ok(elf) = goblin::elf::Elf::parse(bytes) {
            if elf.header.e_machine == EM_BPF {
                r.is_ebpf = true;
            }
            for sh in &elf.section_headers {
                if let Some(sname) = elf.shdr_strtab.get_at(sh.sh_name) {
                    let lc = sname.to_ascii_lowercase();
                    if lc.contains("bpf") || lc == ".btf" || lc.starts_with(".btf") {
                        r.is_ebpf = true;
                        r.bpf_sections.push(sname.to_string());
                    }
                    if sname.starts_with("UPX") || sname == ".UPX" {
                        r.packed = true;
                        r.packer_reason = format!("packer section '{sname}'");
                    }
                }
            }
            // Imports can appear in the dynamic symbol table (.dynsym, the usual
            // case for a linked binary) or the static one (.symtab, kept in
            // unstripped/relocatable objects). Check both.
            let note = |name: &str, r: &mut ElfReport| {
                if SUSPICIOUS_IMPORTS.contains(&name)
                    && !r.suspicious_imports.iter().any(|e| e == name)
                {
                    r.suspicious_imports.push(name.to_string());
                }
            };
            for sym in elf.dynsyms.iter().filter(|s| s.is_import()) {
                if let Some(n) = elf.dynstrtab.get_at(sym.st_name) {
                    note(n, &mut r);
                }
            }
            for sym in elf.syms.iter().filter(|s| s.is_import()) {
                if let Some(n) = elf.strtab.get_at(sym.st_name) {
                    note(n, &mut r);
                }
            }
        }

        if !r.packed && r.entropy > PACKED_ENTROPY {
            r.packed = true;
            r.packer_reason = format!("high entropy {:.2} bits/byte", r.entropy);
        }
        r
    }
}

/// Query VirusTotal v3 for a file hash. Returns the malicious-engine count, or
/// `None` on any error / unknown hash (the scan must never fail because of VT).
async fn vt_lookup(api_key: &str, sha256: &str) -> Option<u64> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .ok()?;
    let resp = client
        .get(format!("https://www.virustotal.com/api/v3/files/{sha256}"))
        .header("x-apikey", api_key)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None; // 404 = VT has never seen it
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    json.pointer("/data/attributes/last_analysis_stats/malicious")
        .and_then(|v| v.as_u64())
}

/// The on-disk / URL file name of a source entry.
fn artifact_name(src: &crate::parser::SourceEntry) -> String {
    if let Some(f) = &src.filename {
        return f.clone();
    }
    let url = src.url.split(['#', '?']).next().unwrap_or(&src.url);
    url.rsplit('/').next().unwrap_or(url).to_string()
}

/// Whether a source looks like a shipped binary worth inspecting.
fn is_binary_artifact(name: &str, pkg_is_bin: bool) -> bool {
    let lc = name.to_ascii_lowercase();
    if BINARY_EXTS.iter().any(|e| lc.ends_with(e)) {
        return true;
    }
    // For -bin packages, generic archives usually carry the prebuilt binary.
    pkg_is_bin
        && [".tar.gz", ".tgz", ".tar", ".zip", ".tar.xz", ".tar.zst"]
            .iter()
            .any(|e| lc.ends_with(e))
}

/// Resolve a source entry to a local file (co-located with the PKGBUILD or a
/// `file://`/relative local source). Returns `None` if not present on disk.
fn resolve_local(dir: &Path, src: &crate::parser::SourceEntry, name: &str) -> Option<PathBuf> {
    use crate::parser::Protocol;
    if src.protocol == Protocol::File {
        let raw = src.url.strip_prefix("file://").unwrap_or(&src.url);
        let p = Path::new(raw);
        let cand = if p.is_absolute() {
            p.to_path_buf()
        } else {
            dir.join(raw)
        };
        if cand.is_file() {
            return Some(cand);
        }
    }
    let co = dir.join(name);
    co.is_file().then_some(co)
}

fn read_capped(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(MAX_ARTIFACT_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == b"\x7fELF"
}

/// Lowercase hex sha256 of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Shannon entropy in bits per byte (0..=8).
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Case-insensitive ASCII substring search over raw bytes.
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn loc(file: &Path, snippet: Option<String>) -> Location {
    Location {
        file: file.to_path_buf(),
        line: None,
        column: None,
        snippet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7, 7, 7, 7]), 0.0); // single symbol
                                                         // 0..=255 once each -> maximal 8 bits/byte.
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn artifact_classification() {
        assert!(is_binary_artifact("app.AppImage", false));
        assert!(is_binary_artifact("payload.run", false));
        assert!(!is_binary_artifact("src-1.0.tar.gz", false));
        // generic archive only counts for -bin packages
        assert!(is_binary_artifact("foo-1.0.tar.gz", true));
    }

    #[test]
    fn ascii_ci_search() {
        assert!(contains_ascii_ci(
            b"junk\x00EvIl.Example\x00",
            b"evil.example"
        ));
        assert!(!contains_ascii_ci(b"nothing here", b"evil.example"));
    }

    #[test]
    fn suspicious_imports_detected_in_synthetic_list() {
        let names = ["printf", "ptrace", "malloc", "process_vm_readv"];
        let hits: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| SUSPICIOUS_IMPORTS.contains(n))
            .collect();
        assert_eq!(hits, vec!["ptrace", "process_vm_readv"]);
    }

    #[test]
    fn benign_imports_do_not_trigger() {
        // Symbols that appear in ordinary binaries (bash imports dlopen/
        // memfd_create; a normal Rust binary imports mprotect/setuid/syscall)
        // must NOT be flagged, or BIN-IMPORT becomes noise.
        let benign = [
            "dlopen",
            "memfd_create",
            "mprotect",
            "syscall",
            "setuid",
            "setgid",
            "prctl",
            "malloc",
            "__libc_start_main",
        ];
        assert!(benign.iter().all(|n| !SUSPICIOUS_IMPORTS.contains(n)));
    }

    /// A hand-built 64-byte ELF64 header with `e_machine = EM_BPF` and no
    /// section/program headers — enough for goblin to read the machine type.
    fn minimal_bpf_elf() -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(b"\x7fELF");
        h[4] = 2; // ELFCLASS64
        h[5] = 1; // little-endian
        h[6] = 1; // EV_CURRENT
        h[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type = ET_REL
        h[18..20].copy_from_slice(&EM_BPF.to_le_bytes()); // e_machine = BPF
        h[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        h[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
                                                         // e_phoff/e_shoff = 0, e_phnum/e_shnum = 0 -> nothing else to parse
        h
    }

    #[test]
    fn detects_ebpf_machine() {
        let elf = minimal_bpf_elf();
        assert!(is_elf(&elf));
        let report = ElfReport::of(&elf);
        assert!(report.is_ebpf, "EM_BPF machine must be detected as eBPF");
    }

    #[test]
    fn real_elf_parses_without_ebpf() {
        // The test binary itself is a normal ELF: parses, not eBPF.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(bytes) = read_capped(&exe) {
                if is_elf(&bytes) {
                    let report = ElfReport::of(&bytes);
                    assert!(!report.is_ebpf);
                }
            }
        }
    }

    #[tokio::test]
    async fn flags_known_payload_hash_offline() {
        use crate::parser::{PkgbuildParser, StaticParser};
        use crate::types::ScanConfig;
        // Build an IOC db with a known-bad hash, then a PKGBUILD declaring it.
        let mut db = IocDatabase::embedded();
        let bad = "a".repeat(64);
        db.sha256.insert(bad.clone(), "atomic-arch-2026-06".into());

        let pkgbuild = StaticParser::new()
            .parse(&format!(
                "pkgname=evil-bin\npkgver=1\npkgrel=1\nsource=(\"https://x.test/evil.AppImage\")\nsha256sums=('{bad}')\n"
            ))
            .unwrap();
        let ctx = AnalysisContext {
            pkgbuild,
            install_script: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        };
        let analyzer = BinaryPayloadAnalyzer::new(Arc::new(db));
        let findings = analyzer.analyze(&ctx).await.unwrap();
        assert!(findings
            .iter()
            .any(|f| f.id == "BIN-HASH" && f.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn ignores_non_binary_sources() {
        use crate::parser::{PkgbuildParser, StaticParser};
        use crate::types::ScanConfig;
        let pkgbuild = StaticParser::new()
            .parse("pkgname=lib\npkgver=1\npkgrel=1\nsource=(\"https://x.test/src-1.0.tar.gz\")\nsha256sums=('SKIP')\n")
            .unwrap();
        let ctx = AnalysisContext {
            pkgbuild,
            install_script: None,
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
        };
        let analyzer = BinaryPayloadAnalyzer::new(Arc::new(IocDatabase::embedded()));
        assert!(analyzer.analyze(&ctx).await.unwrap().is_empty());
    }

    // ---- ELF builders (deterministic, no toolchain needed) ----

    fn write_ehdr(out: &mut [u8], machine: u16, shoff: usize, shnum: u16, shstrndx: u16) {
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // little-endian
        out[6] = 1; // EV_CURRENT
        out[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type = ET_REL
        out[18..20].copy_from_slice(&machine.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
        out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        out[60..62].copy_from_slice(&shnum.to_le_bytes()); // e_shnum
        out[62..64].copy_from_slice(&shstrndx.to_le_bytes()); // e_shstrndx
    }

    fn shdr(
        name: u32,
        typ: u32,
        off: usize,
        size: usize,
        link: u32,
        info: u32,
        ent: u64,
    ) -> [u8; 64] {
        let mut s = [0u8; 64];
        s[0..4].copy_from_slice(&name.to_le_bytes()); // sh_name
        s[4..8].copy_from_slice(&typ.to_le_bytes()); // sh_type
        s[24..32].copy_from_slice(&(off as u64).to_le_bytes()); // sh_offset
        s[32..40].copy_from_slice(&(size as u64).to_le_bytes()); // sh_size
        s[40..44].copy_from_slice(&link.to_le_bytes()); // sh_link
        s[44..48].copy_from_slice(&info.to_le_bytes()); // sh_info
        s[56..64].copy_from_slice(&ent.to_le_bytes()); // sh_entsize
        s
    }

    /// Relocatable ELF64 carrying one global+undefined symbol in `.symtab`
    /// (an "import" by goblin's definition).
    fn elf_with_symbol(symname: &str) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let name_off = strtab.len() as u32;
        strtab.extend_from_slice(symname.as_bytes());
        strtab.push(0);

        let mut symtab = vec![0u8; 24]; // null symbol
        let mut sym = [0u8; 24];
        sym[0..4].copy_from_slice(&name_off.to_le_bytes()); // st_name
        sym[4] = (1 << 4) | 2; // st_info = STB_GLOBAL<<4 | STT_FUNC; st_shndx/value/size = 0
        symtab.extend_from_slice(&sym);

        let mut shstr = vec![0u8];
        let n_symtab = shstr.len() as u32;
        shstr.extend_from_slice(b".symtab\0");
        let n_strtab = shstr.len() as u32;
        shstr.extend_from_slice(b".strtab\0");
        let n_shstr = shstr.len() as u32;
        shstr.extend_from_slice(b".shstrtab\0");

        let off_symtab = 64;
        let off_strtab = off_symtab + symtab.len();
        let off_shstr = off_strtab + strtab.len();
        let sht = (off_shstr + shstr.len() + 7) & !7;

        let mut out = vec![0u8; sht + 4 * 64];
        write_ehdr(&mut out, 62 /* EM_X86_64 */, sht, 4, 3);
        out[off_symtab..off_symtab + symtab.len()].copy_from_slice(&symtab);
        out[off_strtab..off_strtab + strtab.len()].copy_from_slice(&strtab);
        out[off_shstr..off_shstr + shstr.len()].copy_from_slice(&shstr);
        out[sht + 64..sht + 128].copy_from_slice(&shdr(
            n_symtab,
            2,
            off_symtab,
            symtab.len(),
            2,
            1,
            24,
        ));
        out[sht + 128..sht + 192].copy_from_slice(&shdr(
            n_strtab,
            3,
            off_strtab,
            strtab.len(),
            0,
            0,
            0,
        ));
        out[sht + 192..sht + 256].copy_from_slice(&shdr(
            n_shstr,
            3,
            off_shstr,
            shstr.len(),
            0,
            0,
            0,
        ));
        out
    }

    /// Minimal ELF64 with a single named (empty) section, for section-name checks.
    fn elf_with_named_section(name: &str) -> Vec<u8> {
        let mut shstr = vec![0u8];
        let n_sec = shstr.len() as u32;
        shstr.extend_from_slice(name.as_bytes());
        shstr.push(0);
        let n_shstr = shstr.len() as u32;
        shstr.extend_from_slice(b".shstrtab\0");

        let off_shstr = 64;
        let sht = (off_shstr + shstr.len() + 7) & !7;

        let mut out = vec![0u8; sht + 3 * 64];
        write_ehdr(&mut out, 62, sht, 3, 2);
        out[off_shstr..off_shstr + shstr.len()].copy_from_slice(&shstr);
        out[sht + 64..sht + 128]
            .copy_from_slice(&shdr(n_sec, 1 /* PROGBITS */, 0, 0, 0, 0, 0));
        out[sht + 128..sht + 192].copy_from_slice(&shdr(
            n_shstr,
            3,
            off_shstr,
            shstr.len(),
            0,
            0,
            0,
        ));
        out
    }

    // ---- BIN-IMPORT (both ways, through goblin) ----

    #[test]
    fn ptrace_import_detected_via_symtab() {
        let report = ElfReport::of(&elf_with_symbol("ptrace"));
        assert!(report.suspicious_imports.iter().any(|s| s == "ptrace"));
    }

    #[test]
    fn benign_symbol_with_same_structure_not_flagged() {
        // Same ELF layout, benign name -> proves it's the name, not the shape.
        let report = ElfReport::of(&elf_with_symbol("printf"));
        assert!(report.suspicious_imports.is_empty());
    }

    // ---- BIN-EBPF (section-name path + end-to-end) ----

    #[test]
    fn btf_section_detected_as_ebpf() {
        let report = ElfReport::of(&elf_with_named_section(".BTF"));
        assert!(report.is_ebpf);
    }

    #[tokio::test]
    async fn ebpf_artifact_flagged_end_to_end() {
        use crate::parser::{PkgbuildParser, StaticParser};
        use crate::types::ScanConfig;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("payload.elf"), minimal_bpf_elf()).unwrap();
        let pkgbuild = StaticParser::new()
            .parse("pkgname=x-bin\npkgver=1\npkgrel=1\nsource=(\"payload.elf\")\nsha256sums=('SKIP')\n")
            .unwrap();
        let ctx = AnalysisContext {
            pkgbuild,
            install_script: None,
            config: ScanConfig::default(),
            file_path: dir.path().join("PKGBUILD"),
        };
        let analyzer = BinaryPayloadAnalyzer::new(Arc::new(IocDatabase::embedded()));
        let findings = analyzer.analyze(&ctx).await.unwrap();
        assert!(findings.iter().any(|f| f.id == "BIN-EBPF"));
    }

    // ---- BIN-PACKED (both ways: section name, high entropy, clean) ----

    #[test]
    fn upx_section_flagged_as_packed() {
        let report = ElfReport::of(&elf_with_named_section("UPX1"));
        assert!(report.packed);
    }

    #[test]
    fn high_entropy_elf_flagged_as_packed() {
        let mut bytes = vec![0u8; 64];
        write_ehdr(&mut bytes, 62, 0, 0, 0);
        for _ in 0..64 {
            bytes.extend(0u8..=255); // uniform -> entropy ~8 bits/byte
        }
        let report = ElfReport::of(&bytes);
        assert!(report.packed && report.entropy > PACKED_ENTROPY);
    }

    #[test]
    fn low_entropy_elf_not_packed() {
        let mut bytes = vec![0u8; 8192]; // mostly zeros
        write_ehdr(&mut bytes, 62, 0, 0, 0);
        let report = ElfReport::of(&bytes);
        assert!(!report.packed, "entropy was {:.2}", report.entropy);
    }

    // ---- BIN-STRING (embedded C2 domain, both ways) ----

    #[test]
    fn embedded_c2_domain_flagged() {
        let mut db = IocDatabase::embedded();
        db.domains
            .insert("evil.example".into(), "atomic-arch-2026-06".into());
        let analyzer = BinaryPayloadAnalyzer {
            db: Arc::new(db),
            vt_key: None,
        };

        let mut hit = elf_with_named_section(".text");
        hit.extend_from_slice(b"\x00...c2 host: evil.example/beacon...\x00");
        let f = analyzer.inspect_elf(Path::new("payload.elf"), &hit);
        assert!(f.iter().any(|x| x.id == "BIN-STRING"));

        // Same binary without the domain -> no BIN-STRING.
        let clean = elf_with_named_section(".text");
        let f2 = analyzer.inspect_elf(Path::new("payload.elf"), &clean);
        assert!(!f2.iter().any(|x| x.id == "BIN-STRING"));
    }
}
