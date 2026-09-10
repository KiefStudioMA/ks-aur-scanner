//! A minimal, read-only ELF reader.
//!
//! # Why this is still static analysis
//!
//! Static analysis is about **read versus execute**, not text versus binary.
//! Parsing an ELF header is exactly as static as parsing a line of a PKGBUILD:
//! bytes come in, structure comes out, nothing is ever handed to a loader.
//!
//! The line is easy to cross by accident, though, and the classic way is `ldd`.
//! On glibc `/usr/bin/ldd` is a shell script whose `try_trace` runs
//! `output=$(eval $add_env '"$@"' ...)` — it **executes the target** through the
//! dynamic loader to discover its dependencies. Calling it on a hostile
//! `-bin` payload runs that payload as the user. The same hazard applies to
//! anything that maps the file executable, or shells out to a helper that might.
//!
//! So this module reads `DT_NEEDED` out of the `.dynamic` section itself rather
//! than asking the system, and the crate never invokes `ldd`, `objdump`, or
//! `file` on package content.
//!
//! # Scope
//!
//! Deliberately partial. It parses only what the analyzers use — header,
//! section table, `.dynstr`, `.dynsym` names, and the `.dynamic` entries for
//! linked libraries and run paths — rather than pulling in a general object-file
//! library. In a tool whose whole pitch is supply-chain caution, a bounded
//! hand-written parser we can read end to end is worth more than breadth we do
//! not use.
//!
//! # Robustness
//!
//! Input is attacker-controlled by definition. Every read goes through
//! `.get(..)`; there is no indexing, no `unwrap` on slice access, and no
//! `unsafe`. A truncated, lying, or hostile file yields `None` or a partial
//! [`ElfInfo`] — never a panic, and never an out-of-bounds read.

/// What we can learn about an ELF without running it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ElfInfo {
    /// 32- or 64-bit.
    pub bits: u8,
    /// Machine architecture, as the raw `e_machine` value.
    pub machine: u16,
    /// Human-readable architecture name, when recognised.
    pub arch: Option<&'static str>,
    /// Object type: executable, shared object, relocatable.
    pub kind: ElfKind,
    /// Shared libraries named by `DT_NEEDED`.
    pub needed: Vec<String>,
    /// `DT_RPATH` / `DT_RUNPATH`, which control where libraries are searched.
    pub run_paths: Vec<String>,
    /// Dynamic symbol names the object imports (undefined symbols).
    pub imports: Vec<String>,
    /// Section names present.
    pub sections: Vec<String>,
    /// The highest Shannon entropy of any sizeable section, in bits per byte.
    /// Above ~7.2 suggests compressed or encrypted content.
    pub max_section_entropy: f64,
    /// Name of the section with that entropy.
    pub max_entropy_section: Option<String>,
    /// Whether a symbol table is present (an unstripped binary).
    pub has_symtab: bool,
}

/// ELF object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ElfKind {
    /// `ET_REL` — a relocatable object. eBPF programs are shipped like this.
    Relocatable,
    /// `ET_EXEC` — a fixed-address executable.
    Executable,
    /// `ET_DYN` — a shared object or PIE executable.
    SharedObject,
    /// Anything else, or unstated.
    #[default]
    Other,
}

/// The four magic bytes that start every ELF file.
pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// `EM_BPF`. An eBPF object in a package is worth naming on its own: the June
/// 2026 Atomic Arch campaign shipped an eBPF rootkit (`scales.bpf.c`) this way,
/// and eBPF runs in the kernel.
pub const EM_BPF: u16 = 247;

/// Whether a byte slice starts with the ELF magic. Cheap enough to run over
/// every file in a package directory.
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&ELF_MAGIC[..])
}

/// Recognise other executable formats, so "this is a prebuilt binary" does not
/// silently mean "ELF only".
pub fn executable_format(bytes: &[u8]) -> Option<&'static str> {
    match bytes.get(..4) {
        Some(b"\x7fELF") => Some("ELF"),
        Some([0x4D, 0x5A, ..]) => Some("PE/COFF"), // MZ
        Some([0xCA, 0xFE, 0xBA, 0xBE]) => Some("Mach-O universal"),
        Some([0xCF, 0xFA, 0xED, 0xFE]) | Some([0xCE, 0xFA, 0xED, 0xFE]) => Some("Mach-O"),
        Some([0x23, 0x21, ..]) => Some("script (shebang)"), // #!
        _ => None,
    }
}

/// Read a little- or big-endian integer from `bytes` at `off`, or `None` if it
/// would run past the end.
fn read_u16(bytes: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = bytes.get(off..off + 2)?;
    let arr = [b[0], b[1]];
    Some(if le {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    })
}

fn read_u32(bytes: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = bytes.get(off..off + 4)?;
    let arr = [b[0], b[1], b[2], b[3]];
    Some(if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn read_u64(bytes: &[u8], off: usize, le: bool) -> Option<u64> {
    let b = bytes.get(off..off + 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Some(if le {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

/// Read a 32- or 64-bit address-sized value.
fn read_addr(bytes: &[u8], off: usize, le: bool, is64: bool) -> Option<u64> {
    if is64 {
        read_u64(bytes, off, le)
    } else {
        read_u32(bytes, off, le).map(u64::from)
    }
}

/// A NUL-terminated string starting at `off` within `table`.
fn cstr_at(table: &[u8], off: usize) -> Option<String> {
    let rest = table.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let s = rest.get(..end)?;
    // Names are ASCII in practice; anything else is suspicious in its own right
    // but must not make the parse fail.
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Shannon entropy of a byte slice, in bits per byte (0.0 to 8.0).
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Architecture name for a raw `e_machine`, for the ones that matter on Arch.
fn machine_name(m: u16) -> Option<&'static str> {
    Some(match m {
        3 => "x86",
        40 => "ARM",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        EM_BPF => "eBPF",
        _ => return None,
    })
}

/// Sections below this size are not worth an entropy reading -- short sections
/// trivially score high and would be a false-positive machine.
const MIN_ENTROPY_SECTION_BYTES: usize = 4096;

/// Parse what we need from an ELF image.
///
/// Returns `None` only when the input is not an ELF at all or the header itself
/// is unreadable. Beyond that the parse is best-effort: a file that lies about
/// its own section table yields an [`ElfInfo`] with fewer fields populated
/// rather than an error, because "this binary has a malformed section table" is
/// itself worth reporting and is not a reason to stop looking at it.
pub fn parse(bytes: &[u8]) -> Option<ElfInfo> {
    if !is_elf(bytes) {
        return None;
    }
    let class = *bytes.get(4)?;
    let is64 = match class {
        1 => false,
        2 => true,
        _ => return None,
    };
    let le = match *bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };

    let e_type = read_u16(bytes, 16, le)?;
    let machine = read_u16(bytes, 18, le)?;

    let mut info = ElfInfo {
        bits: if is64 { 64 } else { 32 },
        machine,
        arch: machine_name(machine),
        kind: match e_type {
            1 => ElfKind::Relocatable,
            2 => ElfKind::Executable,
            3 => ElfKind::SharedObject,
            _ => ElfKind::Other,
        },
        ..Default::default()
    };

    // Section header table: offset, entry size, count, and the index of the
    // section-name string table.
    let (shoff_at, shentsize_at, shnum_at, shstrndx_at) = if is64 {
        (40usize, 58usize, 60usize, 62usize)
    } else {
        (32usize, 46usize, 48usize, 50usize)
    };
    let shoff = read_addr(bytes, shoff_at, le, is64)? as usize;
    let shentsize = read_u16(bytes, shentsize_at, le)? as usize;
    let shnum = read_u16(bytes, shnum_at, le)? as usize;
    let shstrndx = read_u16(bytes, shstrndx_at, le)? as usize;

    // A file may legitimately have no sections (fully stripped, or a core file).
    if shoff == 0 || shentsize == 0 || shnum == 0 {
        return Some(info);
    }
    // Refuse an implausible section count rather than allocating for it. A real
    // object has tens of sections; this is a claimed value from a hostile file.
    if shnum > 4096 {
        return Some(info);
    }

    // Locate each section: (name_off, sh_type, offset, size).
    let mut raw: Vec<(u32, u32, usize, usize)> = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let base = shoff.checked_add(i.checked_mul(shentsize)?)?;
        let name_off = read_u32(bytes, base, le)?;
        let sh_type = read_u32(bytes, base + 4, le)?;
        let (off_at, size_at) = if is64 { (24, 32) } else { (16, 20) };
        let offset = read_addr(bytes, base + off_at, le, is64)? as usize;
        let size = read_addr(bytes, base + size_at, le, is64)? as usize;
        raw.push((name_off, sh_type, offset, size));
    }

    // The section-name string table.
    let shstr: Vec<u8> = raw
        .get(shstrndx)
        .and_then(|&(_, _, off, size)| bytes.get(off..off.checked_add(size)?))
        .map(|s| s.to_vec())
        .unwrap_or_default();

    let mut dynamic: Option<(usize, usize)> = None;
    let mut dynstr: Option<(usize, usize)> = None;
    let mut dynsym: Option<(usize, usize)> = None;

    for &(name_off, sh_type, off, size) in &raw {
        let name = cstr_at(&shstr, name_off as usize).unwrap_or_default();
        if !name.is_empty() {
            info.sections.push(name.clone());
        }
        // SHT_SYMTAB = 2 -- an unstripped binary.
        if sh_type == 2 {
            info.has_symtab = true;
        }
        match name.as_str() {
            ".dynamic" => dynamic = Some((off, size)),
            ".dynstr" => dynstr = Some((off, size)),
            ".dynsym" => dynsym = Some((off, size)),
            _ => {}
        }
        // Entropy over sizeable sections that actually occupy file space.
        // SHT_NOBITS = 8 has no bytes on disk.
        if sh_type != 8 && size >= MIN_ENTROPY_SECTION_BYTES {
            if let Some(data) = bytes.get(off..off.saturating_add(size)) {
                let e = entropy(data);
                if e > info.max_section_entropy {
                    info.max_section_entropy = e;
                    info.max_entropy_section = Some(name.clone());
                }
            }
        }
    }

    let dynstr_table: Vec<u8> = dynstr
        .and_then(|(off, size)| bytes.get(off..off.checked_add(size)?))
        .map(|s| s.to_vec())
        .unwrap_or_default();

    // .dynamic entries: (tag, value) pairs, address-sized.
    if let Some((off, size)) = dynamic {
        let entry = if is64 { 16 } else { 8 };
        let count = size / entry;
        for i in 0..count.min(4096) {
            let base = match off.checked_add(i.saturating_mul(entry)) {
                Some(b) => b,
                None => break,
            };
            let Some(tag) = read_addr(bytes, base, le, is64) else {
                break;
            };
            let Some(val) = read_addr(bytes, base + entry / 2, le, is64) else {
                break;
            };
            match tag {
                0 => break, // DT_NULL
                1 => {
                    // DT_NEEDED
                    if let Some(s) = cstr_at(&dynstr_table, val as usize) {
                        if !s.is_empty() {
                            info.needed.push(s);
                        }
                    }
                }
                15 | 29 => {
                    // DT_RPATH (15) / DT_RUNPATH (29)
                    if let Some(s) = cstr_at(&dynstr_table, val as usize) {
                        if !s.is_empty() {
                            info.run_paths.push(s);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Imported symbol NAMES from .dynsym. We only need the names, so the entry
    // layout is read for its st_name field and its section index (st_shndx == 0
    // means undefined, i.e. imported).
    if let Some((off, size)) = dynsym {
        let entry = if is64 { 24 } else { 16 };
        let count = size / entry;
        for i in 0..count.min(65536) {
            let Some(base) = off.checked_add(i.checked_mul(entry)?) else {
                break;
            };
            let Some(st_name) = read_u32(bytes, base, le) else {
                break;
            };
            // st_shndx sits at a different offset per class.
            let shndx_at = if is64 { base + 6 } else { base + 14 };
            let Some(st_shndx) = read_u16(bytes, shndx_at, le) else {
                break;
            };
            if st_shndx != 0 {
                continue; // defined here, not imported
            }
            if let Some(s) = cstr_at(&dynstr_table, st_name as usize) {
                if !s.is_empty() {
                    info.imports.push(s);
                }
            }
        }
    }

    info.needed.sort();
    info.needed.dedup();
    info.run_paths.sort();
    info.run_paths.dedup();
    info.imports.sort();
    info.imports.dedup();
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally valid 64-bit LE ELF header.
    fn header(e_type: u16, machine: u16) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(ELF_MAGIC);
        v[4] = 2; // 64-bit
        v[5] = 1; // little-endian
        v[6] = 1; // version
        v[16..18].copy_from_slice(&e_type.to_le_bytes());
        v[18..20].copy_from_slice(&machine.to_le_bytes());
        v
    }

    #[test]
    fn detects_elf_magic_and_other_formats() {
        assert!(is_elf(b"\x7fELFrest"));
        assert!(!is_elf(b"#!/bin/sh"));
        assert_eq!(executable_format(b"\x7fELF...."), Some("ELF"));
        assert_eq!(executable_format(b"MZ\x90\x00"), Some("PE/COFF"));
        assert_eq!(executable_format(b"#!/bin/sh"), Some("script (shebang)"));
        assert_eq!(executable_format(b"plain text"), None);
    }

    #[test]
    fn parses_a_header_without_sections() {
        let info = parse(&header(2, 62)).expect("valid header must parse");
        assert_eq!(info.bits, 64);
        assert_eq!(info.arch, Some("x86-64"));
        assert_eq!(info.kind, ElfKind::Executable);
        assert!(info.needed.is_empty());
    }

    #[test]
    fn recognises_an_ebpf_object() {
        // The Atomic Arch campaign shipped an eBPF rootkit; eBPF runs in-kernel.
        let info = parse(&header(1, EM_BPF)).expect("parse");
        assert_eq!(info.arch, Some("eBPF"));
        assert_eq!(info.kind, ElfKind::Relocatable);
    }

    #[test]
    fn rejects_non_elf_input() {
        assert!(parse(b"not an elf at all").is_none());
        assert!(parse(b"").is_none());
        assert!(parse(b"\x7fELF").is_none(), "truncated before class byte");
    }

    #[test]
    fn hostile_input_never_panics() {
        // Every read goes through .get(); this pins that. Truncations at every
        // length, plus headers that lie about their own section table.
        let full = header(2, 62);
        for n in 0..full.len() {
            let _ = parse(&full[..n]);
        }

        let mut lying = header(2, 62);
        // Absurd section count, offset and entry size.
        lying[40..48].copy_from_slice(&u64::MAX.to_le_bytes()); // e_shoff
        lying[58..60].copy_from_slice(&u16::MAX.to_le_bytes()); // e_shentsize
        lying[60..62].copy_from_slice(&u16::MAX.to_le_bytes()); // e_shnum
        lying[62..64].copy_from_slice(&u16::MAX.to_le_bytes()); // e_shstrndx
        let _ = parse(&lying);

        // Section table pointing just past the end.
        let mut oob = header(2, 62);
        oob[40..48].copy_from_slice(&64u64.to_le_bytes());
        oob[58..60].copy_from_slice(&64u16.to_le_bytes());
        oob[60..62].copy_from_slice(&8u16.to_le_bytes());
        let _ = parse(&oob);

        // Random-ish bytes with a valid magic.
        let mut noise = vec![0u8; 512];
        noise[..4].copy_from_slice(ELF_MAGIC);
        noise[4] = 2;
        noise[5] = 1;
        for (i, b) in noise.iter_mut().enumerate().skip(16) {
            *b = (i.wrapping_mul(31) % 251) as u8;
        }
        let _ = parse(&noise);
    }

    #[test]
    fn rejects_an_implausible_class_or_endianness() {
        let mut bad = header(2, 62);
        bad[4] = 9; // not 32/64-bit
        assert!(parse(&bad).is_none());
        let mut bad2 = header(2, 62);
        bad2[5] = 9; // not LE/BE
        assert!(parse(&bad2).is_none());
    }

    #[test]
    fn entropy_ranges_are_sane() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 1000]), 0.0, "one repeated byte carries none");
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(
            entropy(&uniform) > 7.9,
            "a uniform byte distribution is near maximal"
        );
        let texty: Vec<u8> = b"the quick brown fox "
            .iter()
            .cycle()
            .take(4096)
            .copied()
            .collect();
        assert!(entropy(&texty) < 5.0, "english-ish text is low entropy");
    }

    #[test]
    fn cstr_reads_are_bounded() {
        let table = b"abc\0def\0";
        assert_eq!(cstr_at(table, 0).as_deref(), Some("abc"));
        assert_eq!(cstr_at(table, 4).as_deref(), Some("def"));
        // Past the end is None, not a panic.
        assert_eq!(cstr_at(table, 999), None);
        // Unterminated tail still reads to the end.
        assert_eq!(cstr_at(b"tail", 0).as_deref(), Some("tail"));
    }
}
