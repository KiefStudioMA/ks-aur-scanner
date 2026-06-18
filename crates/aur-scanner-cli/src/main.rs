//! AUR Security Scanner CLI
//!
//! Command-line interface for scanning AUR packages for security issues.

mod commands;
mod output;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use aur_scanner_core::{ScanConfig, Severity};

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

    /// Disable colored output (also honored: the NO_COLOR environment variable)
    #[arg(long, global = true)]
    no_color: bool,
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
        /// Package name(s) to check (optional if --local dirs are given)
        packages: Vec<String>,

        /// Skip interactive prompt (don't ask to proceed)
        #[arg(long)]
        no_confirm: bool,

        /// Exit with non-zero code if findings at or above this severity
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,

        /// Do not resolve and scan the AUR dependency tree (named packages only)
        #[arg(long)]
        no_deps: bool,

        /// Also follow optional dependencies when resolving the tree
        #[arg(long)]
        include_optional: bool,

        /// Write a CycloneDX SBOM of the full dependency tree to this path
        #[arg(long, value_name = "FILE")]
        sbom: Option<PathBuf>,

        /// Scan these already-fetched package dir(s) from disk (race-free, the
        /// exact bytes that will be built). Repeatable. Remaining AUR deps are
        /// fetched from the AUR unless they are also provided here.
        #[arg(long, value_name = "DIR")]
        local: Vec<PathBuf>,
    },

    /// Race-free install: scan the exact bytes, then build them in dep order
    Install {
        /// Package name(s) to install
        #[arg(required = true)]
        packages: Vec<String>,

        /// Gate threshold: findings at or above this severity block the build
        #[arg(long, value_enum, default_value = "critical")]
        gate: SeverityArg,

        /// Also follow optional dependencies
        #[arg(long)]
        include_optional: bool,

        /// Pass --noconfirm to makepkg and skip the build prompt
        #[arg(long)]
        noconfirm: bool,

        /// Build even if the scan gate trips (deliberate override)
        #[arg(long)]
        force: bool,

        /// Workspace dir for clones/builds (default ~/.cache/aur-scan/build)
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,

        /// Write a CycloneDX SBOM to this path
        #[arg(long, value_name = "FILE")]
        sbom: Option<PathBuf>,

        /// Keep the build directories after a successful install
        /// (default: clean them up)
        #[arg(long)]
        keep_build: bool,
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

        /// Output format: text, markdown, json
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Show or query the IOC (indicator of compromise) database
    Ioc {
        /// Check whether a name/value matches a known indicator
        #[arg(long, value_name = "NAME")]
        check: Option<String>,
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

    // Color: the `colored` crate already auto-disables on a non-terminal and
    // honors NO_COLOR/CLICOLOR_FORCE. Force it off explicitly when `--no-color`
    // is given or NO_COLOR is set, so the switch is deterministic regardless of
    // where output goes.
    if cli.no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    // Initialize logging - default to warn to keep output clean
    let filter = if cli.verbose {
        "aur_scanner=debug,aur_scanner_core=debug"
    } else if cli.quiet {
        "aur_scanner=error"
    } else {
        "aur_scanner=warn,aur_scanner_core=warn"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_target(false)
        .without_time()
        .init();

    // Load the optional -c/--config file once. A present-but-unreadable or
    // malformed config is a hard error rather than being silently ignored, so
    // the flag can never appear to work while doing nothing.
    let file_config: Option<ScanConfig> = match cli.config.as_ref() {
        Some(path) => Some(
            ScanConfig::from_toml_file(path)
                .with_context(|| format!("failed to load config file {}", path.display()))?,
        ),
        None => None,
    };

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
                cli.quiet,
                file_config.unwrap_or_default(),
            )
            .await
        }
        Commands::Check {
            packages,
            no_confirm,
            fail_on,
            no_deps,
            include_optional,
            sbom,
            local,
        } => {
            commands::check::run(commands::check::CheckArgs {
                package_names: packages,
                min_severity: cli.severity.map(Into::into),
                interactive: !no_confirm,
                fail_on: fail_on.map(Into::into),
                resolve_deps: !no_deps,
                include_optional,
                sbom_path: sbom,
                local_dirs: local,
            })
            .await
        }
        Commands::Install {
            packages,
            gate,
            include_optional,
            noconfirm,
            force,
            workspace,
            sbom,
            keep_build,
        } => {
            commands::install::run(commands::install::InstallArgs {
                package_names: packages,
                fail_on: gate.into(),
                include_optional,
                noconfirm,
                force,
                workspace,
                sbom_path: sbom,
                keep_build,
            })
            .await
        }
        Commands::System { rescan, cache_dir } => {
            commands::system::run(
                cli.severity.map(Into::into),
                rescan,
                cache_dir,
                file_config.unwrap_or_default(),
            )
            .await
        }
        Commands::Rules { severity, details } => {
            commands::rules::run(severity.map(Into::into), details)
        }
        Commands::Explain { code } => commands::explain::run(&code),
        Commands::Codes { category, format } => {
            // Honor a config-supplied custom rules dir so `codes` lists rules the
            // scan engine would actually load.
            let extra_dirs: Vec<PathBuf> =
                file_config.and_then(|c| c.rules_path).into_iter().collect();
            commands::codes::run(category.as_deref(), &format, &extra_dirs)
        }
        Commands::Ioc { check } => commands::ioc::run(check.as_deref()),
        Commands::Version => {
            commands::version::run();
            Ok(())
        }
    }
}
