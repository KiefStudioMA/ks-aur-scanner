//! Error types for the AUR security scanner

use thiserror::Error;

/// Main error type for scanning operations
#[derive(Error, Debug)]
pub enum ScanError {
    /// Failed to parse PKGBUILD
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Cache error
    #[error("Cache error: {0}")]
    Cache(String),

    /// Timeout
    #[error("Operation timed out after {0}s")]
    Timeout(u64),

    /// Invalid configuration
    #[error("Configuration error: {0}")]
    Config(String),

    /// Rule error
    #[error("Rule error: {0}")]
    Rule(String),

    /// Feature not supported
    #[error("Not supported: {0}")]
    NotSupported(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// TOML parsing error
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Regex error
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
}

/// Errors specific to PKGBUILD parsing
#[derive(Error, Debug)]
pub enum ParseError {
    /// Invalid syntax
    #[error("Syntax error at line {line}: {message}")]
    Syntax { line: usize, message: String },

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid value
    #[error("Invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },

    /// IO error during parsing
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Empty content
    #[error("Empty or invalid PKGBUILD content")]
    EmptyContent,
}

/// Result type alias for scanner operations
pub type Result<T> = std::result::Result<T, ScanError>;

impl From<reqwest::Error> for ScanError {
    fn from(e: reqwest::Error) -> Self {
        ScanError::Network(e.to_string())
    }
}
