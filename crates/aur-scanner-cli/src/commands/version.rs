//! Version command implementation

use super::banner;
use aur_scanner_core::ScanConfig;
use colored::Colorize;

/// Run the version command.
///
/// Reports the resolved configuration and, critically, whether it actually
/// LOADS. Every scanning path treats a present-but-invalid config as a hard
/// error and the pacman hook exits non-zero on one, which aborts the whole
/// transaction. That is the correct fail-closed posture for a security gate, but
/// it means a stale or mistyped key in `/etc/aur-scanner/config.toml` first
/// announces itself by breaking `pacman -Syu`. This gives an operator a way to
/// find out on purpose instead.
///
/// Returns the process exit code: non-zero when the config is present and
/// broken, so it is usable as a pre-upgrade check in a script.
pub fn run(config_path: Option<&std::path::Path>) -> i32 {
    banner::print_banner();

    println!("{}", "Components:".white().bold());
    println!("  CLI:     v{}", env!("CARGO_PKG_VERSION"));
    println!("  Core:    v{}", aur_scanner_core::VERSION);
    println!();

    println!("{}", "Capabilities:".white().bold());
    println!("  {} Static PKGBUILD analysis", "-".dimmed());
    println!("  {} Pattern-based malware detection", "-".dimmed());
    println!("  {} Install script scanning", "-".dimmed());
    println!("  {} Source URL verification", "-".dimmed());
    println!("  {} Checksum validation", "-".dimmed());
    println!("  {} Privilege escalation detection", "-".dimmed());
    println!("  {} AUR package pre-check", "-".dimmed());
    println!("  {} System-wide AUR audit", "-".dimmed());
    println!();

    // Configuration health.
    println!("{}", "Configuration:".white().bold());
    let mut exit = 0;
    match ScanConfig::resolve(config_path) {
        Ok((config, Some(path))) => {
            println!("  {} {}", "loaded:".dimmed(), path.display());
            println!("  {} {:?}", "min severity:".dimmed(), config.min_severity);
            println!(
                "  {} {}",
                "threat intel:".dimmed(),
                if config.enable_threat_intel {
                    "enabled".yellow().to_string()
                } else {
                    "off (default)".to_string()
                }
            );
            println!(
                "  {} {}",
                "owned namespaces:".dimmed(),
                if config.owned_namespaces.is_empty() {
                    "none declared".to_string()
                } else {
                    config
                        .owned_namespaces
                        .iter()
                        .map(|n| n.prefix.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            println!("  {}", "config is valid".green());
        }
        Ok((_, None)) => {
            println!(
                "  {}",
                "no config file found; using built-in defaults".dimmed()
            );
        }
        Err(e) => {
            println!("  {} {}", "INVALID:".red().bold(), e);
            println!(
                "  {}",
                "Every scan path treats this as a hard error, and the pacman hook \
                 will abort transactions until it is fixed."
                    .red()
            );
            exit = 2;
        }
    }
    println!();

    println!("{}", "Integration:".white().bold());
    println!("  {} Shell functions (bash/zsh)", "-".dimmed());
    println!("  {} Wrapper binary (paru/yay)", "-".dimmed());
    println!("  {} Pacman hook", "-".dimmed());
    println!();

    println!(
        "{} https://github.com/KiefStudioMA/ks-aur-scanner",
        "Repository:".dimmed()
    );
    println!("{} https://kief.studio", "Website:".dimmed());
    println!();
    exit
}
