//! AUR Security Scanner CLI
//!
//! Command-line interface for scanning AUR packages for security issues.

mod commands;
mod output;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use aur_scanner_core::Severity;

#[derive(Parser)]
#[command(name = "aur-scan")]
#[command(author = "Kief Studio")]
#[command(version)]
#[command(about = "Security scanner for AUR packages", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Minimum severity to report
    #[arg(short, long, global = true, value_enum)]
    severity: Option<SeverityArg>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Quiet mode (only show findings)
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a PKGBUILD file or directory
    Scan {
        /// Path to PKGBUILD or directory containing it
        path: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Exit with non-zero code if findings at or above this severity
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,

        /// Include informational findings
        #[arg(long)]
        include_info: bool,
    },

    /// Check an AUR package BEFORE installation (fetches from AUR)
    Check {
        /// Package name(s) to check
        #[arg(required = true)]
        packages: Vec<String>,

        /// Skip interactive prompt (don't ask to proceed)
        #[arg(long)]
        no_confirm: bool,

        /// Exit with non-zero code if findings at or above this severity
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,
    },

    /// Scan all installed AUR packages on the system
    System {
        /// Re-fetch PKGBUILDs from AUR (instead of using cache)
        #[arg(long)]
        rescan: bool,

        /// Custom cache directory for PKGBUILDs
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },

    /// List available detection rules
    Rules {
        /// Show only rules of this severity
        #[arg(short, long, value_enum)]
        severity: Option<SeverityArg>,

        /// Show rule details
        #[arg(short, long)]
        details: bool,
    },

    /// Explain a detection code in detail
    Explain {
        /// Detection code to explain (e.g., DLE-001, PERSIST-001)
        code: String,
    },

    /// List all detection codes with brief descriptions
    Codes {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
    },

    /// Check scanner version and configuration
    Version,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging - default to warn to keep output clean
    let filter = if cli.verbose {
        "aur_scanner=debug,aur_scanner_core=debug"
    } else if cli.quiet {
        "aur_scanner=error"
    } else {
        "aur_scanner=warn,aur_scanner_core=warn"
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)))
        .with_target(false)
        .without_time()
        .init();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            fail_on,
            include_info,
        } => {
            commands::scan::run(
                path,
                format,
                output,
                fail_on.map(Into::into),
                cli.severity.map(Into::into),
                include_info,
            )
            .await
        }
        Commands::Check {
            packages,
            no_confirm,
            fail_on,
        } => {
            commands::check::run(
                packages,
                cli.severity.map(Into::into),
                !no_confirm, // interactive = !no_confirm
                fail_on.map(Into::into),
            )
            .await
        }
        Commands::System { rescan, cache_dir } => {
            commands::system::run(
                cli.severity.map(Into::into),
                rescan,
                cache_dir,
            )
            .await
        }
        Commands::Rules { severity, details } => {
            commands::rules::run(severity.map(Into::into), details)
        }
        Commands::Explain { code } => {
            commands::explain::run(&code)
        }
        Commands::Codes { category } => {
            commands::codes::run(category.as_deref())
        }
        Commands::Version => {
            commands::version::run();
            Ok(())
        }
    }
}
