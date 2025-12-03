//! PKGBUILD parsing module
//!
//! Provides static analysis of PKGBUILD files without executing bash code.

mod static_parser;

pub use static_parser::StaticParser;

use crate::error::ParseError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Trait for PKGBUILD parsers
pub trait PkgbuildParser: Send + Sync {
    /// Parse PKGBUILD content from a string
    fn parse(&self, content: &str) -> Result<ParsedPkgbuild, ParseError>;

    /// Parse PKGBUILD from a file path
    fn parse_file(&self, path: &std::path::Path) -> Result<ParsedPkgbuild, ParseError> {
        let content = std::fs::read_to_string(path)?;
        self.parse(&content)
    }
}

/// Parsed representation of a PKGBUILD file
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsedPkgbuild {
    /// Package name(s) - can be multiple for split packages
    pub pkgname: Vec<String>,
    /// Package version
    pub pkgver: String,
    /// Package release number
    pub pkgrel: String,
    /// Epoch (optional)
    pub epoch: Option<String>,
    /// Package description
    pub pkgdesc: Option<String>,
    /// Architectures
    pub arch: Vec<String>,
    /// Upstream URL
    pub url: Option<String>,
    /// License(s)
    pub license: Vec<String>,
    /// Runtime dependencies
    pub depends: Vec<String>,
    /// Build dependencies
    pub makedepends: Vec<String>,
    /// Check dependencies
    pub checkdepends: Vec<String>,
    /// Optional dependencies
    pub optdepends: Vec<String>,
    /// Packages this provides
    pub provides: Vec<String>,
    /// Packages this conflicts with
    pub conflicts: Vec<String>,
    /// Packages this replaces
    pub replaces: Vec<String>,
    /// Source files/URLs
    pub source: Vec<SourceEntry>,
    /// Checksums
    pub checksums: Checksums,
    /// Install script name
    pub install: Option<String>,
    /// Changelog file
    pub changelog: Option<String>,
    /// Backup files
    pub backup: Vec<String>,
    /// Package options
    pub options: Vec<String>,
    /// Custom variables found in the PKGBUILD
    pub variables: HashMap<String, String>,
    /// Functions defined in the PKGBUILD
    pub functions: HashMap<String, FunctionBody>,
    /// Raw content of the PKGBUILD
    pub raw_content: String,
}

/// A source entry (URL or file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntry {
    /// The URL or filename
    pub url: String,
    /// Renamed filename (if using ::)
    pub filename: Option<String>,
    /// Protocol used
    pub protocol: Protocol,
    /// Fragment (for VCS sources)
    pub fragment: Option<String>,
}

impl SourceEntry {
    /// Parse a source string into a SourceEntry
    pub fn parse(source: &str) -> Self {
        let (filename, url) = if source.contains("::") {
            let parts: Vec<&str> = source.splitn(2, "::").collect();
            (Some(parts[0].to_string()), parts[1].to_string())
        } else {
            (None, source.to_string())
        };

        let protocol = Protocol::from_url(&url);

        let fragment = if url.contains('#') {
            url.split('#').nth(1).map(String::from)
        } else {
            None
        };

        Self {
            url,
            filename,
            protocol,
            fragment,
        }
    }
}

/// Protocol used for source download
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTPS (secure)
    Https,
    /// HTTP (insecure)
    Http,
    /// FTP over TLS
    Ftps,
    /// FTP (insecure)
    Ftp,
    /// Git repository
    Git,
    /// Subversion
    Svn,
    /// Mercurial
    Hg,
    /// Bazaar
    Bzr,
    /// Local file
    File,
    /// Unknown protocol
    Unknown(String),
}

impl Protocol {
    /// Determine protocol from URL
    pub fn from_url(url: &str) -> Self {
        let url_lower = url.to_lowercase();

        // Check for VCS prefixes (git+https://, svn+https://, etc.)
        if url_lower.starts_with("git+") || url_lower.starts_with("git://") {
            return Protocol::Git;
        }
        if url_lower.starts_with("svn+") || url_lower.starts_with("svn://") {
            return Protocol::Svn;
        }
        if url_lower.starts_with("hg+") || url_lower.starts_with("hg://") {
            return Protocol::Hg;
        }
        if url_lower.starts_with("bzr+") || url_lower.starts_with("bzr://") {
            return Protocol::Bzr;
        }

        // Standard protocols
        if url_lower.starts_with("https://") {
            Protocol::Https
        } else if url_lower.starts_with("http://") {
            Protocol::Http
        } else if url_lower.starts_with("ftps://") {
            Protocol::Ftps
        } else if url_lower.starts_with("ftp://") {
            Protocol::Ftp
        } else if url_lower.starts_with("file://") || !url.contains("://") {
            Protocol::File
        } else {
            let proto = url.split("://").next().unwrap_or("unknown");
            Protocol::Unknown(proto.to_string())
        }
    }

    /// Check if this protocol is secure
    pub fn is_secure(&self) -> bool {
        matches!(
            self,
            Protocol::Https | Protocol::Ftps | Protocol::Git | Protocol::File
        )
    }
}

/// Checksums for source files
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checksums {
    /// MD5 sums (weak, deprecated)
    pub md5sums: Vec<Option<String>>,
    /// SHA1 sums (weak)
    pub sha1sums: Vec<Option<String>>,
    /// SHA256 sums (recommended)
    pub sha256sums: Vec<Option<String>>,
    /// SHA512 sums (strong)
    pub sha512sums: Vec<Option<String>>,
    /// BLAKE2 sums (strong)
    pub b2sums: Vec<Option<String>>,
}

impl Checksums {
    /// Check if any checksums are present
    pub fn has_any(&self) -> bool {
        !self.md5sums.is_empty()
            || !self.sha1sums.is_empty()
            || !self.sha256sums.is_empty()
            || !self.sha512sums.is_empty()
            || !self.b2sums.is_empty()
    }

    /// Check if only weak checksums are used
    pub fn only_weak(&self) -> bool {
        (self.sha256sums.is_empty() && self.sha512sums.is_empty() && self.b2sums.is_empty())
            && (!self.md5sums.is_empty() || !self.sha1sums.is_empty())
    }

    /// Get the strongest checksum type available
    pub fn strongest_type(&self) -> Option<&'static str> {
        if !self.b2sums.is_empty() {
            Some("b2sums")
        } else if !self.sha512sums.is_empty() {
            Some("sha512sums")
        } else if !self.sha256sums.is_empty() {
            Some("sha256sums")
        } else if !self.sha1sums.is_empty() {
            Some("sha1sums")
        } else if !self.md5sums.is_empty() {
            Some("md5sums")
        } else {
            None
        }
    }
}

/// A bash function body from the PKGBUILD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBody {
    /// Function name (e.g., "build", "package")
    pub name: String,
    /// Content of the function
    pub content: String,
    /// Starting line number (1-indexed)
    pub line_start: usize,
    /// Ending line number (1-indexed)
    pub line_end: usize,
}

/// Parsed .install script
#[derive(Debug, Clone)]
pub struct ParsedInstallScript {
    /// Raw content
    pub content: String,
    /// Path to the script
    pub path: PathBuf,
    /// Detected hooks
    pub hooks: Vec<InstallHook>,
}

/// Hook defined in an install script
#[derive(Debug, Clone)]
pub struct InstallHook {
    /// Hook name (pre_install, post_install, etc.)
    pub name: String,
    /// Hook content
    pub content: String,
    /// Starting line
    pub line_start: usize,
}

/// Parse install script hooks
pub fn parse_install_hooks(content: &str) -> Vec<InstallHook> {
    let mut hooks = Vec::new();
    let hook_names = [
        "pre_install",
        "post_install",
        "pre_upgrade",
        "post_upgrade",
        "pre_remove",
        "post_remove",
    ];

    for (line_num, line) in content.lines().enumerate() {
        for hook_name in &hook_names {
            if line.trim().starts_with(&format!("{}()", hook_name))
                || line.trim().starts_with(&format!("{} ()", hook_name))
            {
                // Find the function body
                let remaining = &content[content
                    .lines()
                    .take(line_num)
                    .map(|l| l.len() + 1)
                    .sum::<usize>()..];
                if let Some(body) = extract_function_body(remaining) {
                    hooks.push(InstallHook {
                        name: hook_name.to_string(),
                        content: body,
                        line_start: line_num + 1,
                    });
                }
            }
        }
    }

    hooks
}

/// Extract function body from content starting at function definition
fn extract_function_body(content: &str) -> Option<String> {
    let mut brace_count = 0;
    let mut in_function = false;
    let mut body = String::new();

    for ch in content.chars() {
        if ch == '{' {
            brace_count += 1;
            in_function = true;
        } else if ch == '}' {
            brace_count -= 1;
        }

        if in_function {
            body.push(ch);
            if brace_count == 0 {
                return Some(body);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_entry_parse() {
        let entry = SourceEntry::parse("https://example.com/file.tar.gz");
        assert_eq!(entry.protocol, Protocol::Https);
        assert!(entry.filename.is_none());

        let entry = SourceEntry::parse("myfile.tar.gz::https://example.com/file.tar.gz");
        assert_eq!(entry.filename, Some("myfile.tar.gz".to_string()));
        assert_eq!(entry.protocol, Protocol::Https);
    }

    #[test]
    fn test_protocol_detection() {
        assert_eq!(Protocol::from_url("https://example.com"), Protocol::Https);
        assert_eq!(Protocol::from_url("http://example.com"), Protocol::Http);
        assert_eq!(
            Protocol::from_url("git+https://github.com/repo"),
            Protocol::Git
        );
        assert_eq!(Protocol::from_url("local-file.tar.gz"), Protocol::File);
    }

    #[test]
    fn test_protocol_security() {
        assert!(Protocol::Https.is_secure());
        assert!(!Protocol::Http.is_secure());
        assert!(!Protocol::Ftp.is_secure());
    }
}
