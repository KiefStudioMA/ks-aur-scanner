//! Rule file loader

use super::Rule;
use crate::error::{Result, ScanError};
use std::path::Path;
use tracing::{debug, warn};

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

    /// Load all rules from a directory
    pub fn load_from_directory(&self, dir: &Path) -> Result<Vec<Rule>> {
        let mut all_rules = Vec::new();

        if !dir.exists() {
            return Err(ScanError::Config(format!(
                "Rules directory does not exist: {}",
                dir.display()
            )));
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                debug!("Loading rules from: {}", path.display());
                match self.load_from_file(&path) {
                    Ok(rules) => {
                        debug!("Loaded {} rules from {}", rules.len(), path.display());
                        all_rules.extend(rules);
                    }
                    Err(e) => {
                        warn!("Failed to load rules from {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(all_rules)
    }

    /// Parse TOML content into rules
    fn parse_toml(&self, content: &str, path: &Path) -> Result<Vec<Rule>> {
        #[derive(serde::Deserialize)]
        struct RulesFile {
            #[serde(default)]
            rule: Vec<Rule>,
        }

        let file: RulesFile = toml::from_str(content).map_err(|e| {
            ScanError::Config(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        Ok(file.rule)
    }
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
}
