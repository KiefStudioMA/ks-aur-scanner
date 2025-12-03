//! Version command implementation

use colored::Colorize;
use super::banner;

/// Run the version command
pub fn run() {
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

    println!("{}", "Integration:".white().bold());
    println!("  {} Shell functions (bash/zsh)", "-".dimmed());
    println!("  {} Wrapper binary (paru/yay)", "-".dimmed());
    println!("  {} Pacman hook", "-".dimmed());
    println!();

    println!("{} https://github.com/KiefStudioMA/ks-aur-scanner", "Repository:".dimmed());
    println!("{} https://kief.studio", "Website:".dimmed());
    println!();
}
