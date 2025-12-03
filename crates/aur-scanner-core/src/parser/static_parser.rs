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

    // Array patterns
    static ref ARRAY_SINGLE: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)=\((.*)\)$"#).unwrap();
    static ref ARRAY_START: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)=\($"#).unwrap();
    // Multi-line array that starts with content on first line
    static ref ARRAY_MULTILINE_START: Regex = Regex::new(r#"^([a-zA-Z_][a-zA-Z0-9_]*)=\((.+)$"#).unwrap();

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

    /// Extract function body starting from a line
    fn extract_function(&self, lines: &[&str], start_idx: usize) -> Option<(String, usize)> {
        let mut brace_count = 0;
        let mut in_function = false;
        let mut body_lines = Vec::new();
        let mut end_idx = start_idx;

        for (i, line) in lines.iter().enumerate().skip(start_idx) {
            let trimmed = line.trim();

            // Count braces (simplified - doesn't handle strings/comments)
            for ch in trimmed.chars() {
                match ch {
                    '{' => {
                        brace_count += 1;
                        in_function = true;
                    }
                    '}' => brace_count -= 1,
                    _ => {}
                }
            }

            if in_function {
                body_lines.push(*line);
                if brace_count == 0 {
                    end_idx = i;
                    break;
                }
            } else if trimmed.ends_with('{') {
                body_lines.push(*line);
                brace_count = 1;
                in_function = true;
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

        // Collect multi-line arrays
        let mut pending_array: Option<(String, String)> = None;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || COMMENT.is_match(trimmed) {
                i += 1;
                continue;
            }

            // Handle multi-line array continuation
            if let Some((name, ref mut collected)) = pending_array.as_mut() {
                collected.push(' ');
                collected.push_str(trimmed.trim_end_matches(')'));

                if trimmed.ends_with(')') {
                    let elements = self.parse_array_elements(collected);
                    self.assign_array(&mut pkgbuild, name, elements);
                    pending_array = None;
                }
                i += 1;
                continue;
            }

            // Check for array start (multi-line, empty first line)
            if let Some(caps) = ARRAY_START.captures(trimmed) {
                let name = caps.get(1).unwrap().as_str().to_string();
                pending_array = Some((name, String::new()));
                i += 1;
                continue;
            }

            // Check for multi-line array with content on first line
            if let Some(caps) = ARRAY_MULTILINE_START.captures(trimmed) {
                let name = caps.get(1).unwrap().as_str().to_string();
                let first_content = caps.get(2).unwrap().as_str();
                // Check if it actually ends with ) - could be single line
                if first_content.ends_with(')') {
                    let content = first_content.trim_end_matches(')');
                    let elements = self.parse_array_elements(content);
                    self.assign_array(&mut pkgbuild, &name, elements);
                } else {
                    pending_array = Some((name, first_content.to_string()));
                }
                i += 1;
                continue;
            }

            // Check for single-line array
            if let Some(caps) = ARRAY_SINGLE.captures(trimmed) {
                let name = caps.get(1).unwrap().as_str();
                let content = caps.get(2).unwrap().as_str();
                let elements = self.parse_array_elements(content);
                self.assign_array(&mut pkgbuild, name, elements);
                i += 1;
                continue;
            }

            // Check for function definition
            if let Some(caps) = FUNC_START.captures(trimmed) {
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
            if let Some(caps) = VAR_QUOTED.captures(trimmed) {
                let name = caps.get(1).unwrap().as_str();
                let value = caps.get(2).unwrap().as_str();
                self.assign_variable(&mut pkgbuild, name, value);
                i += 1;
                continue;
            }

            // Check for simple variable assignment
            if let Some(caps) = VAR_SIMPLE.captures(trimmed) {
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
    fn assign_array(&self, pkgbuild: &mut ParsedPkgbuild, name: &str, elements: Vec<String>) {
        match name {
            "pkgname" => pkgbuild.pkgname = elements,
            "arch" => pkgbuild.arch = elements,
            "license" => pkgbuild.license = elements,
            "depends" => pkgbuild.depends = elements,
            "makedepends" => pkgbuild.makedepends = elements,
            "checkdepends" => pkgbuild.checkdepends = elements,
            "optdepends" => pkgbuild.optdepends = elements,
            "provides" => pkgbuild.provides = elements,
            "conflicts" => pkgbuild.conflicts = elements,
            "replaces" => pkgbuild.replaces = elements,
            "backup" => pkgbuild.backup = elements,
            "options" => pkgbuild.options = elements,
            "source" => {
                pkgbuild.source = elements.iter().map(|s| SourceEntry::parse(s)).collect();
            }
            "md5sums" => pkgbuild.checksums.md5sums = self.parse_checksums(&elements),
            "sha1sums" => pkgbuild.checksums.sha1sums = self.parse_checksums(&elements),
            "sha256sums" => pkgbuild.checksums.sha256sums = self.parse_checksums(&elements),
            "sha512sums" => pkgbuild.checksums.sha512sums = self.parse_checksums(&elements),
            "b2sums" => pkgbuild.checksums.b2sums = self.parse_checksums(&elements),
            _ => {
                // Store as JSON array in variables
                pkgbuild
                    .variables
                    .insert(name.to_string(), serde_json::to_string(&elements).unwrap());
            }
        }
    }
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
    fn test_strict_mode_missing_fields() {
        let parser = StaticParser::strict();
        let result = parser.parse("pkgdesc='test'");
        assert!(matches!(result, Err(ParseError::MissingField(_))));
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
