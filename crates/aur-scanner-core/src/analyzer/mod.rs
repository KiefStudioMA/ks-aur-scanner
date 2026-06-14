//! Security analyzers for PKGBUILD analysis

mod binary;
mod checksum;
mod deep;
mod ioc;
mod pattern;
mod privilege;
mod remote_exec;
mod source;

pub use binary::BinaryPayloadAnalyzer;
pub use checksum::ChecksumAnalyzer;
pub use deep::DeepAnalyzer;
pub use ioc::IocAnalyzer;
pub use pattern::PatternAnalyzer;
pub use privilege::PrivilegeAnalyzer;
pub use remote_exec::RemoteExecAnalyzer;
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
