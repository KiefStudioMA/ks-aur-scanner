//! Cross-line "deep" analysis.
//!
//! The rule engine matches a single line at a time, so it misses obfuscation
//! that is split across lines -- decode a payload on one line, execute it on
//! another. This analyzer reasons over the whole file (PKGBUILD + install
//! script together) to catch decode->execute flows and large embedded blobs.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::informational_lines;
use crate::textutil::{deobfuscate_text, logical_lines, SHELLS, SHELL_LAUNCHER, SHELL_PATH};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// A decoding/decompression operation that produces executable text.
    static ref DECODE: Regex = Regex::new(
        r"base64\s+(-d|--decode|-[a-zA-Z]*d)|xxd\s+-r|\bbase32\s+-d|openssl\s+enc\s+.*-d|(gunzip|zcat|xz\s+-d|\bunzip)\b|\btr\s+.*\|"
    ).unwrap();
    /// Hex-escaped payloads (several escapes, not an isolated byte).
    static ref HEX_BLOB: Regex = Regex::new(r"(\\x[0-9a-fA-F]{2}){4,}").unwrap();
    /// A sink that executes dynamically-produced text. Shell sinks come from the
    /// shared `SHELLS` constant so `dash`/`zsh`/`ksh -c`/here-strings are covered
    /// like `sh`/`bash` (defect #6).
    static ref EXEC_SINK: Regex = Regex::new(&format!(
        r"\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b|\beval\b|{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s+-c\b|{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s*<<<|source\s+/dev/stdin|/dev/stdin"
    )).unwrap();
    /// A long base64-looking blob in a single assignment/string.
    static ref LONG_B64: Regex = Regex::new(r"[A-Za-z0-9+/]{200,}={0,2}").unwrap();
}

/// Analyzer for cross-line obfuscation and decode->execute flows.
pub struct DeepAnalyzer;

impl DeepAnalyzer {
    /// Create a new deep analyzer.
    pub fn new() -> Self {
        Self
    }

    fn analyze_text(&self, text: &str, file: &std::path::Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Strip comment lines AND printed/informational lines (a non-redirected
        // heredoc body or a pure `echo`/`msg "..."` print) using the shared
        // rule-engine pre-filter, so a package that merely DOCUMENTS a
        // `base64 -d | sh` example does not raise DEEP-001. Work on logical lines
        // so a backslash-continued decode/exec is still seen as one command.
        let lines = logical_lines(text);
        let line_strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
        let informational = informational_lines(&line_strs);
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
        let mut anchor = context.file_path.clone();
        if let Some(install) = &context.install_script {
            combined.push('\n');
            combined.push_str(&install.content);
            // Prefer the install script as the anchor if the PKGBUILD body is empty.
            if context.pkgbuild.raw_content.trim().is_empty() {
                anchor = install.path.clone();
            }
        }
        Ok(self.analyze_text(&combined, &anchor))
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
