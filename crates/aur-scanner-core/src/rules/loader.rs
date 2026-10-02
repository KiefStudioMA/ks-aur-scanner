//! Rule file loader

use super::{warn_rule, CompiledPattern, Rule};
use crate::error::{Result, ScanError};
use crate::types::FileType;
use std::collections::HashSet;
use std::path::Path;
use tracing::debug;

/// Loader for rule definition files
pub struct RuleLoader;

impl RuleLoader {
    /// Create a new rule loader
    pub fn new() -> Self {
        Self
    }

    /// Load rules from a TOML file
    pub fn load_from_file(&self, path: &Path) -> Result<Vec<Rule>> {
        let content = std::fs::read_to_string(path)?;
        self.parse_toml(&content, path)
    }

    /// Rule files in `dir`, sorted by name so load order (and therefore which
    /// of two colliding ids wins) is deterministic rather than filesystem order.
    fn toml_files(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
        if !dir.exists() {
            return Err(ScanError::Config(format!(
                "Rules directory does not exist: {}",
                dir.display()
            )));
        }
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    /// Load all rules from a directory, unvetted (parse only). Prefer
    /// [`Self::load_vetted_from_directory`] for anything that will be matched.
    pub fn load_from_directory(&self, dir: &Path) -> Result<Vec<Rule>> {
        let mut all_rules = Vec::new();
        for path in Self::toml_files(dir)? {
            debug!("Loading rules from: {}", path.display());
            match self.load_from_file(&path) {
                Ok(rules) => {
                    debug!("Loaded {} rules from {}", rules.len(), path.display());
                    all_rules.extend(rules);
                }
                Err(e) => warn_rule(&format!("skipping rule file {}: {}", path.display(), e)),
            }
        }
        Ok(all_rules)
    }

    /// Load a directory and keep only rules that will really run.
    ///
    /// A file that does not parse (bad TOML, unknown key such as `patern`) is
    /// skipped on its own. A rule is dropped, with a stderr warning, when its id
    /// is already in `reserved` (a built-in, an analyzer code, or an earlier
    /// rule -- the first definition always wins, so a community rule can never
    /// replace or lower a built-in), when it has no patterns, or when a pattern
    /// does not compile. Accepted ids are added to `reserved`. Disabled rules
    /// are vetted but not returned.
    pub fn load_vetted_from_directory(
        &self,
        dir: &Path,
        reserved: &mut HashSet<String>,
    ) -> Result<Vec<Rule>> {
        let mut accepted = Vec::new();
        for path in Self::toml_files(dir)? {
            let rules = match self.load_from_file(&path) {
                Ok(r) => r,
                Err(e) => {
                    warn_rule(&format!("skipping rule file {}: {}", path.display(), e));
                    continue;
                }
            };
            for rule in rules {
                if !is_valid_rule_id(&rule.id) {
                    warn_rule(&format!(
                        "rejecting rule {:?} from {}: the id must look like CATEGORY-001 (letters and digits, upper case, at least one '-')",
                        rule.id,
                        path.display()
                    ));
                    continue;
                }
                if reserved.contains(&rule.id) {
                    warn_rule(&format!(
                        "rejecting rule {} from {}: the id is already used by a built-in or earlier rule \
                         (community rules can never replace or lower an existing detection)",
                        rule.id,
                        path.display()
                    ));
                    continue;
                }
                if rule.patterns.is_empty() {
                    warn_rule(&format!(
                        "rejecting rule {} from {}: it has no patterns and could never fire",
                        rule.id,
                        path.display()
                    ));
                    continue;
                }
                let mut ok = true;
                for p in &rule.patterns {
                    if let Err(e) = CompiledPattern::compile(p, rule.case_sensitive) {
                        warn_rule(&format!(
                            "rejecting rule {} from {}: pattern does not compile: {e}",
                            rule.id,
                            path.display()
                        ));
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    continue;
                }
                reserved.insert(rule.id.clone());
                if rule.enabled {
                    accepted.push(rule);
                }
            }
        }
        Ok(accepted)
    }

    /// Parse TOML content into rules
    fn parse_toml(&self, content: &str, path: &Path) -> Result<Vec<Rule>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RulesFile {
            #[serde(default)]
            rule: Vec<Rule>,
        }

        let file: RulesFile = toml::from_str(content)
            .map_err(|e| ScanError::Config(format!("Failed to parse {}: {}", path.display(), e)))?;

        // A community rule that omits `file_types` would otherwise deserialize to
        // an empty list, load, count toward the catalog, and never fire (audit
        // LOW). Default it to the standard scanned file types so it actually runs,
        // and warn so the author can pin it explicitly.
        let mut rules = file.rule;
        for rule in &mut rules {
            // Ids are compared case- and whitespace-insensitively against the
            // built-ins, so `shell-001` or `"SHELL-001 "` cannot load beside
            // `SHELL-001`.
            rule.id = normalize_rule_id(&rule.id);
            if rule.file_types.is_empty() {
                warn_rule(&format!(
                    "rule {} in {} declares no file_types; defaulting to [Pkgbuild, InstallScript] so it is not silently inert",
                    rule.id,
                    path.display()
                ));
                rule.file_types = vec![FileType::Pkgbuild, FileType::InstallScript];
            }
        }
        Ok(rules)
    }
}

/// Trim and upper-case a community rule id.
pub(crate) fn normalize_rule_id(id: &str) -> String {
    id.trim().to_ascii_uppercase()
}

/// `^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`, checked by hand (ASCII only).
pub(crate) fn is_valid_rule_id(id: &str) -> bool {
    let mut parts = id.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    let mut fc = first.chars();
    if !fc.next().is_some_and(|c| c.is_ascii_uppercase())
        || !fc.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }
    let mut n = 0;
    for p in parts {
        n += 1;
        if p.is_empty()
            || !p
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return false;
        }
    }
    n >= 1
}

impl Default for RuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_toml() {
        let toml = r#"
[[rule]]
id = "TEST-001"
name = "Test Rule"
description = "A test rule"
severity = "high"
category = "command_injection"
file_types = ["pkgbuild"]
recommendation = "Fix it"

[[rule.patterns]]
type = "regex"
pattern = "test.*pattern"
"#;

        let loader = RuleLoader::new();
        let rules = loader.parse_toml(toml, Path::new("test.toml")).unwrap();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "TEST-001");
        assert_eq!(rules[0].patterns.len(), 1);
    }

    #[test]
    fn rule_without_file_types_defaults_to_scanned_types() {
        // audit LOW: a community rule that omits `file_types` must not load inert.
        let toml = r#"
[[rule]]
id = "TEST-002"
name = "No file types"
description = "omits file_types"
severity = "high"
category = "command_injection"
recommendation = "Fix it"

[[rule.patterns]]
type = "regex"
pattern = "x"
"#;
        let loader = RuleLoader::new();
        let rules = loader.parse_toml(toml, Path::new("test.toml")).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].file_types,
            vec![FileType::Pkgbuild, FileType::InstallScript],
            "a rule omitting file_types must default to the scanned types, not stay inert"
        );
    }

    fn rule_toml(id: &str) -> String {
        format!(
            "[[rule]]\nid = \"{id}\"\nname = \"n\"\ndescription = \"d\"\nseverity = \"low\"\ncategory = \"command_injection\"\nfile_types = [\"pkgbuild\"]\nrecommendation = \"r\"\n\n[[rule.patterns]]\ntype = \"regex\"\npattern = \"x\"\n"
        )
    }

    fn vet(id: &str) -> Vec<Rule> {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("r.toml"), rule_toml(id)).unwrap();
        let mut reserved: HashSet<String> = ["SHELL-001".to_string()].into();
        RuleLoader::new()
            .load_vetted_from_directory(d.path(), &mut reserved)
            .unwrap()
    }

    #[test]
    fn community_ids_are_normalised_before_the_collision_check() {
        // Case and whitespace variants of a built-in id are collisions.
        assert!(vet("shell-001").is_empty());
        assert!(vet("SHELL-001 ").is_empty());
        assert!(vet(" Shell-001").is_empty());
        // Closest benign form: a distinct id still loads, normalised.
        let ok = vet(" mine-001 ");
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].id, "MINE-001");
    }

    #[test]
    fn malformed_community_ids_are_rejected() {
        for bad in [
            "NODASH", "A--1", "-A-1", "A-", "1A-001", "A B-001", "A_B-001", "",
        ] {
            assert!(vet(bad).is_empty(), "{bad:?} should be rejected");
        }
        for good in ["A-1", "ABC-001", "A1-B2-C3"] {
            assert_eq!(vet(good).len(), 1, "{good:?} should load");
        }
    }
}
