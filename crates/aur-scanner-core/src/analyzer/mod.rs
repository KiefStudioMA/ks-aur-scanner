//! Security analyzers for PKGBUILD analysis

mod blocklist;
mod checksum;
mod pattern;
mod pkgmanager;
mod privilege;
mod source;

pub use blocklist::BlocklistAnalyzer;
pub use checksum::ChecksumAnalyzer;
pub use pattern::PatternAnalyzer;
pub use pkgmanager::PackageManagerAnalyzer;
pub use privilege::PrivilegeAnalyzer;
pub use source::SourceAnalyzer;

use crate::error::Result;
use crate::types::{AnalysisContext, Finding};
use async_trait::async_trait;

/// Trait for security analyzers
#[async_trait]
pub trait SecurityAnalyzer: Send + Sync {
    /// Analyze the given context and return findings
    async fn analyze(&self, context: &AnalysisContext) -> Result<Vec<Finding>>;

    /// Get the analyzer name
    fn name(&self) -> &str;

    /// Get the analyzer version
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}
