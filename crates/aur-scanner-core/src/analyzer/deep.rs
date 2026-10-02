//! Cross-line "deep" analysis.
//!
//! The rule engine matches a single line at a time, so it misses obfuscation
//! that is split across lines -- decode a payload on one line, execute it on
//! another. This analyzer reasons over the whole file (PKGBUILD + install
//! script together) to catch decode->execute flows and large embedded blobs.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::informational_lines_with;
use crate::textutil::{deobfuscate_text, logical_lines, SHELLS, SHELL_LAUNCHER, SHELL_PATH};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

lazy_static! {
    /// A decoding/decompression operation that produces executable text.
    /// `(?i)` so `BASE64`/`XXD`/`OpenSSL` case variants cannot evade the decode
    /// step (audit HI-6) -- these are all command names, none case-canonical.
    static ref DECODE: Regex = Regex::new(
        r"(?i)base64\s+(-d|--decode|-[a-zA-Z]*d)|xxd\s+-r|\bbase32\s+-d|openssl\s+enc\s+.*-d|(gunzip|zcat|xz\s+-d|\bunzip)\b|\btr\s+.*\|"
    ).unwrap();
    /// Hex-escaped payloads (several escapes, not an isolated byte). Intentionally
    /// case-sensitive: a bash ANSI-C escape is lowercase `\x`; the hex digits
    /// already accept both cases via the `[0-9a-fA-F]` class.
    static ref HEX_BLOB: Regex = Regex::new(r"(\\x[0-9a-fA-F]{2}){4,}").unwrap();
    /// A sink that executes dynamically-produced text. Shell sinks come from the
    /// shared `SHELLS` constant so `dash`/`zsh`/`ksh -c`/here-strings are covered
    /// like `sh`/`bash` (defect #6). `(?i)` so `BASH`/`EVAL`/`SH -c` case variants
    /// cannot evade the exec sink (audit HI-6).
    static ref EXEC_SINK: Regex = Regex::new(&format!(
        r"(?i)\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b|\beval\b|{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s+-c\b|{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s*<<<|source\s+/dev/stdin|/dev/stdin"
    )).unwrap();
    /// A long base64-looking blob in a single assignment/string. Intentionally
    /// case-sensitive: this matches the canonical Base64 ALPHABET, not a keyword,
    /// so it must not be folded to case-insensitive.
    static ref LONG_B64: Regex = Regex::new(r"[A-Za-z0-9+/]{200,}={0,2}").unwrap();
}

/// Analyzer for cross-line obfuscation and decode->execute flows.
pub struct DeepAnalyzer;

impl DeepAnalyzer {
    /// Create a new deep analyzer.
    pub fn new() -> Self {
        Self
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn analyze_text(&self, text: &str, file: &std::path::Path) -> Vec<Finding> {
        let local = crate::rules::ShadowSet::from_text(text).names();
        self.analyze_text_with(text, file, &local)
    }

    fn analyze_text_with(
        &self,
        text: &str,
        file: &std::path::Path,
        shadowed: &HashSet<String>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Strip comment lines AND printed/informational lines (a non-redirected
        // heredoc body or a pure `echo`/`msg "..."` print) using the shared
        // rule-engine pre-filter, so a package that merely DOCUMENTS a
        // `base64 -d | sh` example does not raise DEEP-001. Work on logical lines
        // so a backslash-continued decode/exec is still seen as one command.
        let lines = logical_lines(text);
        let line_strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
        let informational = informational_lines_with(&line_strs, shadowed);
        let code: String = lines
            .iter()
            .enumerate()
            .filter(|(i, (_, l))| !l.trim_start().starts_with('#') && !informational[*i])
            .map(|(_, (_, l))| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        // Also scan a de-obfuscated variant so a quote-split / ANSI-C-escaped
        // `base64 -d` or `| sh` cannot hide the decode->execute flow (defect
        // #6c). Line count is preserved; the extra scan is skipped when nothing
        // decoded.
        let decoded = deobfuscate_text(&code);
        let differs = decoded != code;
        let hit = |re: &Regex| re.is_match(&code) || (differs && re.is_match(&decoded));
        let has_decode = hit(&DECODE) || hit(&HEX_BLOB);
        let has_sink = hit(&EXEC_SINK);

        if has_decode && has_sink {
            findings.push(Finding {
                id: "DEEP-001".to_string(),
                severity: Severity::Critical,
                category: Category::Obfuscation,
                title: "Decode-and-execute flow".to_string(),
                description:
                    "The file both decodes/decompresses data and dynamically executes shell input. \
                     Together these form a decode->execute payload, even when split across lines."
                        .to_string(),
                location: Location {
                    file: file.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation:
                    "Decode the payload manually and review it. Legitimate builds do not decode \
                     and then execute generated shell code."
                        .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({ "multiline": true }),
            });
        }

        // DEEP-003 -- Unicode bidirectional control characters (Trojan Source,
        // CVE-2021-42574).
        //
        // These reorder how text DISPLAYS without changing how it executes, so a
        // reviewer reading the PKGBUILD in a terminal or on the AUR web page can
        // see something different from what makepkg runs. There is no legitimate
        // reason for a bidi override in shell source: real right-to-left text in
        // a comment or a message needs no explicit override, because terminals
        // and browsers apply the Unicode bidi algorithm on their own.
        //
        // Scanned over the RAW text, not the informational-filtered code: the
        // whole point is that a reviewer cannot trust which lines are comments.
        let bidi: Vec<char> = text
            .chars()
            .filter(|c| {
                matches!(
                    c,
                    // Explicit directional overrides and embeddings.
                    '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
                    // Isolates.
                    | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
                    // Deprecated but still honoured marks.
                    | '\u{200E}' | '\u{200F}' | '\u{061C}'
                )
            })
            .collect();
        if !bidi.is_empty() {
            let names: Vec<String> = {
                let mut seen: Vec<char> = Vec::new();
                for c in &bidi {
                    if !seen.contains(c) {
                        seen.push(*c);
                    }
                }
                seen.iter()
                    .map(|c| format!("U+{:04X}", *c as u32))
                    .collect()
            };
            findings.push(Finding {
                id: "DEEP-003".to_string(),
                severity: Severity::Critical,
                category: Category::Obfuscation,
                title: "Unicode bidirectional control characters".to_string(),
                description: format!(
                    "The file contains {} Unicode bidi control character(s) ({}). These change \
                     how the text is DISPLAYED without changing what is executed, so the code a \
                     reviewer reads can differ from the code that runs (Trojan Source, \
                     CVE-2021-42574). Shell source has no legitimate use for an explicit \
                     directional override.",
                    bidi.len(),
                    names.join(", ")
                ),
                location: Location {
                    file: file.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Strip the bidi characters and re-read the file before trusting \
                                 any review of it."
                    .to_string(),
                cwe_id: Some("CWE-94".to_string()),
                metadata: serde_json::json!({
                    "bidi_count": bidi.len(),
                    "codepoints": names,
                }),
            });
        }

        if let Some(m) = LONG_B64.find(&code) {
            findings.push(Finding {
                id: "DEEP-002".to_string(),
                severity: Severity::High,
                category: Category::Obfuscation,
                title: "Large embedded encoded blob".to_string(),
                description: format!(
                    "A {}-character base64-like blob is embedded in the package. Large encoded \
                     blobs are a common way to smuggle binaries or scripts past review.",
                    m.as_str().len()
                ),
                location: Location {
                    file: file.to_path_buf(),
                    line: None,
                    column: None,
                    snippet: None,
                },
                recommendation: "Decode and review the blob; verify it is legitimate data."
                    .to_string(),
                cwe_id: Some("CWE-506".to_string()),
                metadata: serde_json::json!({ "blob_len": m.as_str().len() }),
            });
        }

        findings
    }
}

impl Default for DeepAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for DeepAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        // Analyze PKGBUILD and install script together: a decode in one and an
        // exec in the other is still a single payload.
        let mut combined = context.pkgbuild.raw_content.clone();
        // One anchor for the combined text, because the analysis is deliberately
        // cross-file: a decode in the PKGBUILD and the exec in the .install is
        // one payload, and pinning it to either file alone would misreport it.
        //
        // Assigned ONCE. Reassigning inside the loop made every finding point at
        // the LAST side script, so with several scriptlets the reported file was
        // whichever one happened to be discovered last -- not where the reader
        // should start.
        let mut anchor = context.file_path.clone();
        let pkgbuild_is_empty = context.pkgbuild.raw_content.trim().is_empty();
        let mut anchored_to_script = false;
        for script in context.all_scripts() {
            combined.push('\n');
            combined.push_str(&script.content);
            // Only when the PKGBUILD body is empty is a side script the better
            // starting point, and then it is the FIRST one.
            if pkgbuild_is_empty && !anchored_to_script {
                anchor = script.path.clone();
                anchored_to_script = true;
            }
        }
        let shadow = context.shadowed_printers();
        let shadowed = shadow.names();
        let mut findings = self.analyze_text_with(&combined, &anchor, &shadowed);
        // Calls to a redefined printer, replaced by what they execute.
        if let Some(inlined) = shadow.inline_calls(&combined) {
            for f in self.analyze_text_with(&inlined, &anchor, &shadowed) {
                if !findings
                    .iter()
                    .any(|e| e.id == f.id && e.location.line == f.location.line)
                {
                    findings.push(f);
                }
            }
        }
        // A message function that runs its arguments is a finding in itself,
        // whether or not the call site shows what it will run.
        for def in shadow.executing() {
            findings.push(Finding {
                id: "OBF-012".to_string(),
                severity: Severity::Critical,
                category: Category::Obfuscation,
                title: format!("Message function '{}' redefined to execute its arguments", def.name),
                description: format!(
                    "'{}' is normally a printer, but this package redefines it so that it runs what it is given. Every call that looks like a status message is then a command.",
                    def.name
                ),
                location: Location {
                    file: def.file.clone(),
                    line: Some(def.line),
                    column: None,
                    snippet: None,
                },
                recommendation: "Do not install. A legitimate package has no reason to make a message helper run its arguments.".to_string(),
                cwe_id: Some("CWE-94".to_string()),
                metadata: serde_json::json!({ "function": def.name, "alias": def.alias }),
            });
        }
        Ok(findings)
    }

    fn name(&self) -> &str {
        "deep"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn flags_multiline_decode_then_exec() {
        let a = DeepAnalyzer::new();
        let text = "payload=$(echo aGVsbG8= | base64 -d)\n# ... later ...\neval \"$payload\"";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        assert!(findings.iter().any(|f| f.id == "DEEP-001"));
    }

    #[test]
    fn flags_obfuscated_decode_then_exec() {
        // Defect #6c: a quote-split `base64 -d` and a `| dash` sink, neither of
        // which the raw regexes match, must still form DEEP-001 after de-obf.
        let a = DeepAnalyzer::new();
        let text = "p=$(echo aGVsbG8= | \"ba\"\"se64\" -d)\neval \"$p\" | da\\sh";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        assert!(
            findings.iter().any(|f| f.id == "DEEP-001"),
            "obfuscated decode->exec must trip DEEP-001: {findings:?}"
        );
    }

    #[test]
    fn documented_decode_exec_in_heredoc_not_flagged() {
        // Task 4050a: a `base64 -d | sh` example that only appears in a printed
        // (non-redirected) heredoc is documentation, not a payload — no DEEP-001.
        let a = DeepAnalyzer::new();
        let text = "post_install() {\n  cat <<EOF\n  example: echo data | base64 -d | sh\nEOF\n}";
        let findings = a.analyze_text(text, Path::new("test.install"));
        assert!(
            !findings.iter().any(|f| f.id == "DEEP-001"),
            "documented decode|exec in a printed heredoc must not fire DEEP-001: {findings:?}"
        );
    }

    #[test]
    fn case_variation_decode_then_exec_still_flags() {
        // Audit HI-6: `BASE64 -d` into `EVAL`/`SH` (upper/mixed case) must still
        // form DEEP-001 — DECODE and EXEC_SINK are `(?i)`.
        let a = DeepAnalyzer::new();
        let text = "p=$(echo aGVsbG8= | BASE64 -d)\nEVAL \"$p\"";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        assert!(
            findings.iter().any(|f| f.id == "DEEP-001"),
            "case-variant decode->exec must trip DEEP-001: {findings:?}"
        );
    }

    #[test]
    fn flags_bidi_control_characters() {
        // Trojan Source: what a reviewer sees is not what runs.
        let a = DeepAnalyzer::new();
        let text = "build() {\n  echo \"\u{202E}hctap ylppa\u{202C}\"\n  make\n}";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        let f = findings
            .iter()
            .find(|f| f.id == "DEEP-003")
            .expect("bidi must be flagged");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.description.contains("U+202E"), "{}", f.description);
    }

    #[test]
    fn flags_bidi_even_inside_a_comment() {
        // The attack hides code as a comment (or vice versa), so the
        // informational-line filter must not be what decides here.
        let a = DeepAnalyzer::new();
        let text = "build() {\n  # \u{2066}safe\u{2069}\n  make\n}";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        assert!(findings.iter().any(|f| f.id == "DEEP-003"));
    }

    #[test]
    fn ordinary_non_ascii_text_is_not_bidi() {
        // Accented characters, CJK, emoji in a pkgdesc are all fine. Only
        // explicit DIRECTIONAL CONTROLS are the signal.
        let a = DeepAnalyzer::new();
        for text in [
            "pkgdesc=\"Herramienta de configuración\"",
            "pkgdesc=\"日本語のツール\"",
            "# maintainer: Renée Müller <r@example.com>",
            "pkgdesc=\"مرحبا\"",
        ] {
            let findings = a.analyze_text(text, Path::new("PKGBUILD"));
            assert!(
                !findings.iter().any(|f| f.id == "DEEP-003"),
                "false positive on ordinary text: {text}"
            );
        }
    }

    #[test]
    fn clean_build_no_findings() {
        let a = DeepAnalyzer::new();
        let text = "build() {\n  make\n}\npackage() {\n  make DESTDIR=\"$pkgdir\" install\n}";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_large_encoded_blob() {
        let a = DeepAnalyzer::new();
        let blob = "A".repeat(240);
        let text = format!("data={blob}");
        let findings = a.analyze_text(&text, Path::new("PKGBUILD"));
        assert!(findings.iter().any(|f| f.id == "DEEP-002"));
    }

    #[test]
    fn decode_without_exec_is_not_deep001() {
        // base64 decode alone (e.g. decoding a real data file) must not trip
        // DEEP-001 without an execution sink.
        let a = DeepAnalyzer::new();
        let text = "install -Dm644 <(echo Zm9v | base64 -d) \"$pkgdir/etc/foo\"";
        let findings = a.analyze_text(text, Path::new("PKGBUILD"));
        assert!(!findings.iter().any(|f| f.id == "DEEP-001"));
    }
}
