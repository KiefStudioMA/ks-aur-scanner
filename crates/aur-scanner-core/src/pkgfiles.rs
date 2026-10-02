//! Reading the files that ship beside a PKGBUILD, without ever failing open.
//!
//! The PKGBUILD is only part of what makepkg runs: the `.install` scriptlet,
//! ALPM `.hook` files, local `source=()` entries and sidecar scripts all execute
//! (or are installed) too. Every one of those used to be read with
//! `read_to_string` behind a size check, and ANY read failure was logged and the
//! file treated as absent -- so a single non-UTF-8 byte, or padding past the
//! size cap, made a package with a `curl | bash` scriptlet scan clean.
//!
//! The rules here:
//!
//! * A file is decoded lossily. Bytes can no longer hide content.
//! * Reads are bounded by `take(cap)`, not by trusting `metadata().len()`.
//! * Symlinks and non-regular files (FIFO, device) are never followed or
//!   opened. A FIFO would hang the scan; `/dev/zero` would exhaust memory; a
//!   link to `/etc/hostname` would leak host files into reports.
//! * Anything declared or shipped that cannot be fully analyzed produces a
//!   Critical [`SCAN-001`](crate::types::UNANALYZABLE_CODE) finding. It is never
//!   silently dropped.

use crate::parser::{self, ParsedInstallScript, ParsedPkgbuild};
use crate::types::{Category, FileType, Finding, Location, Severity, UNANALYZABLE_CODE};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use tracing::debug;

/// Maximum size of a file the scanner will read into memory. Real PKGBUILDs
/// and install scripts are a few KB; anything past this is abnormal and a
/// memory-exhaustion risk from a hostile repository.
pub const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Total bytes the scanner will hold for the files beside one PKGBUILD. Each
/// file is individually capped; this bounds a directory of many of them.
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// How many undeclared script-like files are loaded from one directory.
const MAX_DISCOVERED_FILES: usize = 512;

/// Extensions of files that run or get installed as scripts/units.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "dash", "py", "pl", "rb", "js", "lua", "php", "service", "timer",
    "socket", "path",
];

/// Names that are never treated as sidecars.
const IGNORED_NAMES: &[&str] = &["PKGBUILD", ".SRCINFO", ".gitignore", ".git", ".AURINFO"];

/// Entries in the package directory that are never read as package content.
/// Everything else -- dotfiles included -- is a candidate, because anything in
/// the directory is reachable from the build via `$startdir`.
const NEVER_SCANNED: &[&str] = &["PKGBUILD", ".SRCINFO", ".git"];

/// How much of a file is sampled to decide whether it is text.
const TEXT_SAMPLE_BYTES: usize = 8 * 1024;

/// A file read, possibly truncated at the cap.
#[derive(Debug)]
pub struct CappedRead {
    /// Lossily decoded text.
    pub content: String,
    /// The file was longer than the cap; `content` is only its prefix.
    pub truncated: bool,
    /// Size on disk at open time.
    pub size: u64,
}

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// Open `path` only if it is a plain regular file: not a symlink, not a FIFO,
/// socket or device. Checked with `symlink_metadata` first (never opens a FIFO)
/// and re-checked on the open handle.
fn open_regular(path: &Path) -> std::io::Result<File> {
    let meta = std::fs::symlink_metadata(path)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(err(describe_symlink(path)));
    }
    if !ft.is_file() {
        return Err(err(
            "not a regular file (FIFO, socket, device or directory)",
        ));
    }
    let f = File::open(path)?;
    let opened = f.metadata()?;
    if !opened.is_file() {
        return Err(err("not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
            return Err(err("file changed while it was being opened"));
        }
    }
    Ok(f)
}

/// "symlink to <target>" -- the target path only, never its contents.
fn describe_symlink(path: &Path) -> String {
    match std::fs::read_link(path) {
        Ok(t) => format!(
            "is a symlink to '{}'; links are never followed, and a link pointing outside the package directory is itself suspicious",
            t.display()
        ),
        Err(_) => "is a symlink; links are never followed".to_string(),
    }
}

/// Read up to [`MAX_SCAN_FILE_BYTES`] of a regular file, decoding lossily.
pub fn read_capped_lossy(path: &Path) -> std::io::Result<CappedRead> {
    let f = open_regular(path)?;
    let size = f.metadata()?.len();
    let mut buf = Vec::new();
    // One byte past the cap tells us the file is longer than it, regardless of
    // what the metadata claimed.
    f.take(MAX_SCAN_FILE_BYTES + 1).read_to_end(&mut buf)?;
    let truncated = buf.len() as u64 > MAX_SCAN_FILE_BYTES;
    if truncated {
        buf.truncate(MAX_SCAN_FILE_BYTES as usize);
    }
    Ok(CappedRead {
        content: String::from_utf8_lossy(&buf).into_owned(),
        truncated,
        size,
    })
}

/// Read a text file for analysis, refusing files larger than the cap.
///
/// Public so every caller that touches package-controlled files -- including the
/// CLI's history and diff paths -- shares one reader. Invalid UTF-8 is decoded
/// lossily rather than failing; symlinks and non-regular files are refused.
pub fn read_text_capped(path: &Path) -> crate::Result<String> {
    let r = read_capped_lossy(path)?;
    if r.truncated {
        tracing::warn!(
            "refusing to read {} ({} bytes > {} cap): possible resource-exhaustion attempt",
            path.display(),
            r.size,
            MAX_SCAN_FILE_BYTES
        );
        return Err(crate::ScanError::Io(err(format!(
            "file too large to scan safely: {} bytes",
            r.size
        ))));
    }
    Ok(r.content)
}

/// Build the Critical "could not be analyzed" finding for `path`.
pub fn unanalyzable_finding(path: &Path, reason: &str) -> Finding {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    Finding {
        id: UNANALYZABLE_CODE.to_string(),
        severity: Severity::Critical,
        category: Category::Configuration,
        title: format!("Package file could not be analyzed: {name}"),
        description: format!(
            "'{}' {reason}. Content that was not analyzed cannot be reported clean; a payload \
             can hide behind exactly this.",
            path.display()
        ),
        location: Location {
            file: path.to_path_buf(),
            line: None,
            column: None,
            snippet: None,
        },
        recommendation: "Do not install. Inspect the file by hand; a legitimate package has no \
                         reason to ship an oversized, unreadable, or symlinked script."
            .to_string(),
        cwe_id: Some("CWE-693".to_string()),
        metadata: serde_json::json!({ "path": path.display().to_string(), "reason": reason }),
    }
}

/// Everything found beside the PKGBUILD.
#[derive(Debug, Default)]
pub struct PackageFiles {
    /// The primary install scriptlet (first declared, else first `*.install`).
    pub install: Option<ParsedInstallScript>,
    /// Every other scriptlet, hook, local source and sidecar script.
    pub side: Vec<ParsedInstallScript>,
    /// `SCAN-001` findings for anything that could not be fully analyzed.
    pub findings: Vec<Finding>,
}

/// Result of expanding PKGBUILD variables in a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    /// The expanded text. Any variable that could not be resolved is replaced by
    /// [`WILDCARD`].
    pub text: String,
    /// Every variable resolved.
    pub complete: bool,
}

/// Stands in for an unresolvable `$var` so the name can be glob-matched.
pub const WILDCARD: char = '\u{1}';

fn lookup_var(pkg: &ParsedPkgbuild, name: &str) -> Option<String> {
    let v = match name {
        "pkgname" => pkg.pkgname.first().cloned(),
        "pkgbase" => pkg
            .variables
            .get("pkgbase")
            .cloned()
            .or_else(|| pkg.pkgname.first().cloned()),
        "pkgver" => Some(pkg.pkgver.clone()).filter(|s| !s.is_empty()),
        "pkgrel" => Some(pkg.pkgrel.clone()).filter(|s| !s.is_empty()),
        "epoch" => pkg.epoch.clone(),
        "url" => pkg.url.clone(),
        other => pkg
            .variables
            .get(other)
            .filter(|s| !s.starts_with('['))
            .cloned(),
    }?;
    Some(v.trim_matches(['"', '\'']).to_string())
}

/// Expand `$name` / `${name}` using the PKGBUILD's own top-level variables.
/// Static only: nothing is executed. Parameter-expansion operators
/// (`${x%.*}`, `${x//a/b}`) are not evaluated and count as unresolved.
pub fn expand_vars(value: &str, pkg: &ParsedPkgbuild) -> Expanded {
    expand_depth(value.trim().trim_matches(['"', '\'']), pkg, 4)
}

fn expand_depth(s: &str, pkg: &ParsedPkgbuild, depth: u8) -> Expanded {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut complete = true;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // `${...}` or `$name`
        let (name, next, braced_plain) = if chars.get(i + 1) == Some(&'{') {
            match chars[i + 2..].iter().position(|&c| c == '}') {
                Some(rel) => {
                    let inner: String = chars[i + 2..i + 2 + rel].iter().collect();
                    let plain = !inner.is_empty()
                        && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    (inner, i + 2 + rel + 1, plain)
                }
                None => (String::new(), chars.len(), false),
            }
        } else {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let n: String = chars[i + 1..j].iter().collect();
            let plain = !n.is_empty();
            (n, j.max(i + 1), plain)
        };
        let resolved = if braced_plain && depth > 0 {
            lookup_var(pkg, &name).map(|v| expand_depth(&v, pkg, depth - 1))
        } else {
            None
        };
        match resolved {
            Some(e) if e.complete => out.push_str(&e.text),
            _ => {
                out.push(WILDCARD);
                complete = false;
            }
        }
        i = next.max(i + 1);
    }
    Expanded {
        text: out,
        complete,
    }
}

/// Glob match where [`WILDCARD`] matches any run of characters.
fn wildcard_match(pat: &[char], name: &[char]) -> bool {
    match pat.split_first() {
        None => name.is_empty(),
        Some((&WILDCARD, rest)) => (0..=name.len()).any(|k| wildcard_match(rest, &name[k..])),
        Some((&c, rest)) => name.first() == Some(&c) && wildcard_match(rest, &name[1..]),
    }
}

/// The filename makepkg uses for a local `source=()` entry: a `name::` rename if
/// present, otherwise the basename of the path (directories are dropped, so
/// `scripts/helper.sh` is `helper.sh` in the package directory).
fn local_source_name(entry: &parser::SourceEntry, pkg: &ParsedPkgbuild) -> Option<Expanded> {
    if let Some(f) = &entry.filename {
        return Some(expand_vars(f, pkg));
    }
    let url = expand_vars(&entry.url, pkg);
    // Variables may expand to a remote URL (`$_baseurl/x.tar.gz`).
    if url.complete && parser::Protocol::from_url(&url.text).is_remote() {
        return None;
    }
    let no_frag = url.text.split(['#', '?']).next().unwrap_or_default();
    let base = no_frag.rsplit('/').next().unwrap_or_default();
    Some(Expanded {
        text: base.to_string(),
        complete: url.complete,
    })
}

/// A plain single filename: no separators, not `.`/`..`, no NUL.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

fn is_script_name(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SCRIPT_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Join a declared relative path onto `dir`, refusing anything that could
/// leave it: absolute paths, `..`, and any symlinked intermediate directory.
fn safe_join(dir: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel_path = Path::new(rel);
    let mut cur = dir.to_path_buf();
    let comps: Vec<Component> = rel_path.components().collect();
    if comps.is_empty() {
        return Err("is empty".into());
    }
    for (idx, c) in comps.iter().enumerate() {
        match c {
            Component::Normal(n) => {
                cur.push(n);
                if idx + 1 < comps.len() {
                    match std::fs::symlink_metadata(&cur) {
                        Ok(m) if m.is_dir() => {}
                        Ok(_) => return Err("passes through a non-directory or symlink".into()),
                        Err(_) => return Err("is missing".into()),
                    }
                }
            }
            Component::CurDir => {}
            _ => return Err("escapes the package directory (absolute or '..')".into()),
        }
    }
    Ok(cur)
}

struct Collector {
    findings: Vec<Finding>,
    seen: HashSet<PathBuf>,
    budget: u64,
    discovered: usize,
}

impl Collector {
    /// Load one file as a script. `strip_binary` skips files that look like
    /// binary blobs (declared patches/archives) instead of scripts.
    fn load(
        &mut self,
        path: &Path,
        file_type: FileType,
        require_script_like: bool,
    ) -> Option<ParsedInstallScript> {
        if !self.seen.insert(path.to_path_buf()) {
            return None;
        }
        // A directory is not a file to analyze (and is not an evasion).
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            return None;
        }
        let read = match read_capped_lossy(path) {
            Ok(r) => r,
            Err(e) => {
                self.findings.push(unanalyzable_finding(
                    path,
                    &format!("could not be read: {e}"),
                ));
                return None;
            }
        };
        let held = read.content.len() as u64;
        if held > self.budget {
            self.findings.push(unanalyzable_finding(
                path,
                "was not read because the package directory exceeds the total scan size budget",
            ));
            return None;
        }
        self.budget -= held;
        if read.truncated {
            self.findings.push(unanalyzable_finding(
                path,
                &format!(
                    "is {} bytes, larger than the {} byte scan cap; only its first {} bytes were analyzed",
                    read.size, MAX_SCAN_FILE_BYTES, MAX_SCAN_FILE_BYTES
                ),
            ));
        }
        let mut content = read.content;
        // bash discards NUL bytes, so `cu\0rl` runs as `curl`. Strip them rather
        // than letting one defeat every pattern -- or, worse, skipping the file
        // as "binary".
        if content.contains('\0') {
            content = content.replace('\0', "");
            if require_script_like {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !(is_script_name(&name) || content.starts_with("#!")) {
                    debug!("skipping binary local source {}", path.display());
                    return None;
                }
            }
        }
        Some(ParsedInstallScript {
            hooks: parser::parse_install_hooks(&content),
            content,
            path: path.to_path_buf(),
            file_type,
        })
    }

    /// Whether `path` exists at all (without following a final symlink).
    fn exists(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }
}

/// Does the file start with `#!`? Regular files only; two bytes.
fn has_shebang(path: &Path) -> bool {
    let Ok(mut f) = open_regular(path) else {
        return false;
    };
    let mut b = [0u8; 2];
    f.read_exact(&mut b).is_ok() && &b == b"#!"
}

/// Whether the first 8 KiB of a regular file look like text: no NUL bytes, or,
/// when there are some (bash discards NULs, so `cu\0rl` still runs), mostly
/// printable once decoded lossily. Binaries (ELF, archives, images) fail this and
/// are left to the `BIN-*` checks. Unreadable files count as not text; they are
/// reported separately.
fn looks_like_text(path: &Path) -> bool {
    let Ok(f) = open_regular(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if f.take(TEXT_SAMPLE_BYTES as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    if buf.is_empty() || !buf.contains(&0) {
        return true;
    }
    let decoded = String::from_utf8_lossy(&buf);
    let (mut total, mut printable) = (0usize, 0usize);
    for c in decoded.chars().filter(|&c| c != '\0') {
        total += 1;
        if c != '\u{FFFD}' && (!c.is_control() || matches!(c, '\t' | '\n' | '\r')) {
            printable += 1;
        }
    }
    total > 0 && printable * 100 >= total * 85
}

/// Paths the package text reaches through `$startdir` / `$srcdir` (braced or
/// not), with known variables expanded. `$srcdir` is tried both as the package
/// directory and as its `src/` subdirectory.
fn startdir_references(text: &str, pkg: &ParsedPkgbuild) -> Vec<String> {
    lazy_static::lazy_static! {
        static ref REF: regex::Regex = regex::Regex::new(
            r#"\$(?:\{(startdir|srcdir)\}|(startdir|srcdir))/([^\s"'`;|&)<>(]+)"#
        ).unwrap();
    }
    let mut out = Vec::new();
    for c in REF.captures_iter(text) {
        let rest = &c[3];
        let ex = expand_vars(rest, pkg);
        if !ex.complete {
            continue;
        }
        let rel = ex.text.trim_end_matches('/').to_string();
        if rel.is_empty() {
            continue;
        }
        if c.get(1)
            .or_else(|| c.get(2))
            .is_some_and(|m| m.as_str() == "srcdir")
        {
            out.push(format!("src/{rel}"));
        }
        out.push(rel);
    }
    out
}

/// Collect and read everything the package ships beside its PKGBUILD.
pub fn collect(dir: &Path, pkg: &ParsedPkgbuild) -> PackageFiles {
    let mut c = Collector {
        findings: Vec::new(),
        seen: HashSet::new(),
        budget: MAX_TOTAL_BYTES,
        discovered: 0,
    };
    let mut out = PackageFiles::default();

    // Directory listing, without following symlinks.
    let mut entries: Vec<(String, PathBuf, std::fs::FileType)> = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            for e in rd.flatten() {
                if let Ok(ft) = std::fs::symlink_metadata(e.path()).map(|m| m.file_type()) {
                    entries.push((e.file_name().to_string_lossy().into_owned(), e.path(), ft));
                }
            }
        }
        Err(e) => c.findings.push(unanalyzable_finding(
            dir,
            &format!("package directory could not be listed: {e}"),
        )),
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut installs: Vec<ParsedInstallScript> = Vec::new();

    // 1. Declared install= values (global and per split package).
    let mut declared: Vec<&String> = pkg.installs.iter().collect();
    if let Some(i) = &pkg.install {
        if !pkg.installs.contains(i) {
            declared.push(i);
        }
    }
    for value in declared {
        let ex = expand_vars(value, pkg);
        if !ex.complete {
            // Unresolvable name: the `*.install` sweep below still reads every
            // install file in the directory.
            debug!("install= value {value:?} not statically resolvable");
            continue;
        }
        match safe_join(dir, &ex.text) {
            Ok(p) => match std::fs::symlink_metadata(&p) {
                Err(_) => c.findings.push(unanalyzable_finding(
                    &p,
                    "is declared by install= but does not exist; makepkg would refuse it, and the declared scriptlet could not be reviewed",
                )),
                Ok(m) if m.is_dir() => c.findings.push(unanalyzable_finding(
                    &p,
                    "is declared by install= but is a directory, not a scriptlet; makepkg would refuse it, and the declared scriptlet could not be reviewed",
                )),
                Ok(_) => {
                    if let Some(s) = c.load(&p, FileType::InstallScript, false) {
                        installs.push(s);
                    }
                }
            },
            Err(reason) => c.findings.push(unanalyzable_finding(
                &dir.join(&ex.text),
                &format!("is declared by install= but {reason}"),
            )),
        }
    }

    // 2. Every `*.install` in the directory, declared or not. makepkg only
    //    honours the declared one, but reading them all means a split package's
    //    per-package scriptlet or a decoy cannot hide a payload.
    for (name, path, _) in &entries {
        let ext_install = Path::new(name).extension().and_then(|e| e.to_str()) == Some("install");
        if !ext_install {
            continue;
        }
        if let Some(s) = c.load(path, FileType::InstallScript, false) {
            installs.push(s);
        }
    }

    // 3. ALPM hooks.
    for (name, path, _) in &entries {
        if Path::new(name).extension().and_then(|e| e.to_str()) == Some("hook") {
            if let Some(s) = c.load(path, FileType::InstallScript, false) {
                out.side.push(s);
            }
        }
    }

    // 4. Local source=() entries, by makepkg's own naming rules.
    for entry in &pkg.source {
        if entry.protocol.is_remote() {
            continue;
        }
        let Some(ex) = local_source_name(entry, pkg) else {
            continue;
        };
        if ex.complete {
            if !is_plain_name(&ex.text) {
                debug!(
                    "not reading local source {:?}: not a plain filename",
                    ex.text
                );
                continue;
            }
            let p = dir.join(&ex.text);
            if Collector::exists(&p) {
                if let Some(s) = c.load(&p, FileType::SourceFile, true) {
                    out.side.push(s);
                }
            }
        } else {
            // Partly unresolvable (`${pkgver//./_}.patch`): read every file in
            // the directory the pattern could name.
            let pat: Vec<char> = ex.text.chars().collect();
            if pat.iter().all(|&ch| ch == WILDCARD) {
                // Nothing to anchor on; matching everything would just re-read
                // the whole directory as "sources".
                continue;
            }
            for (name, path, ft) in &entries {
                if ft.is_dir() || IGNORED_NAMES.contains(&name.as_str()) {
                    continue;
                }
                let n: Vec<char> = name.chars().collect();
                if wildcard_match(&pat, &n) {
                    if let Some(s) = c.load(path, FileType::SourceFile, true) {
                        out.side.push(s);
                    }
                }
            }
        }
    }

    // 5. Every other file in the directory. makepkg can reach any of them via
    //    `$startdir` (`bash "$startdir/build.cfg"`, `. "$startdir/.cfg"`), and a
    //    name or extension says nothing about what a shell will do with the
    //    content, so dotfiles and extension-less files are read too. Binaries
    //    (NUL-heavy, non-printable) are left to the BIN-* checks. Links, FIFOs
    //    and the like are never opened; they are reported when a script-like
    //    name or the package's own text points at them.
    let mut all_text = pkg.raw_content.clone();
    for s in installs.iter().chain(out.side.iter()) {
        all_text.push('\n');
        all_text.push_str(&s.content);
    }
    for (name, path, ft) in &entries {
        if NEVER_SCANNED.contains(&name.as_str()) || c.seen.contains(path) || ft.is_dir() {
            continue;
        }
        let wanted = if ft.is_file() {
            is_script_name(name) || has_shebang(path) || looks_like_text(path)
        } else {
            is_script_name(name) || all_text.contains(name.as_str())
        };
        if !wanted {
            continue;
        }
        if c.discovered >= MAX_DISCOVERED_FILES {
            c.findings.push(unanalyzable_finding(
                path,
                "was not read because the package directory holds too many files",
            ));
            continue;
        }
        c.discovered += 1;
        if let Some(s) = c.load(path, FileType::SourceFile, false) {
            out.side.push(s);
        }
    }

    // 6. Paths the package reaches through `$startdir` / `$srcdir` that live
    //    below the top level (`$startdir/conf/build.cfg`). Followed to a fixed
    //    point: a file read here can name the next one.
    let mut queue: Vec<String> = vec![pkg.raw_content.clone()];
    queue.extend(installs.iter().map(|s| s.content.clone()));
    queue.extend(out.side.iter().map(|s| s.content.clone()));
    while let Some(text) = queue.pop() {
        for rel in startdir_references(&text, pkg) {
            let Ok(p) = safe_join(dir, &rel) else {
                continue;
            };
            if c.seen.contains(&p) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_dir() || (ft.is_file() && !looks_like_text(&p) && !has_shebang(&p)) {
                continue;
            }
            if c.discovered >= MAX_DISCOVERED_FILES {
                c.findings.push(unanalyzable_finding(
                    &p,
                    "was not read because the package directory holds too many files",
                ));
                continue;
            }
            c.discovered += 1;
            if let Some(s) = c.load(&p, FileType::SourceFile, false) {
                queue.push(s.content.clone());
                out.side.push(s);
            }
        }
    }

    // The first install scriptlet is the primary one; the rest are side scripts.
    let mut it = installs.into_iter();
    out.install = it.next();
    out.side.splice(0..0, it);
    out.findings = c.findings;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(text: &str) -> ParsedPkgbuild {
        use crate::parser::PkgbuildParser;
        parser::StaticParser::new().parse(text).unwrap()
    }

    #[test]
    fn expands_simple_and_nested_vars() {
        let p = pkg("pkgname=foo\npkgver=1.2\npkgrel=1\n_base=bar-$pkgver\n");
        assert_eq!(
            expand_vars("${pkgname}-helper.sh", &p).text,
            "foo-helper.sh"
        );
        assert_eq!(expand_vars("$_base.patch", &p).text, "bar-1.2.patch");
        let e = expand_vars("${pkgver//./_}.patch", &p);
        assert!(!e.complete);
        assert!(e.text.contains(WILDCARD));
    }

    #[test]
    fn wildcard_matches_unresolved_segment() {
        let pat: Vec<char> = format!("v{WILDCARD}.patch").chars().collect();
        assert!(wildcard_match(
            &pat,
            &"v1_2.patch".chars().collect::<Vec<_>>()
        ));
        assert!(!wildcard_match(
            &pat,
            &"v1_2.txt".chars().collect::<Vec<_>>()
        ));
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let d = tempfile::tempdir().unwrap();
        assert!(safe_join(d.path(), "../x").is_err());
        assert!(safe_join(d.path(), "/etc/passwd").is_err());
        assert!(safe_join(d.path(), "a.install").is_ok());
    }
}
