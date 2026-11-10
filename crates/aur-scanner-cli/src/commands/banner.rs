//! CLI banner and branding
//!
//! The banner `version` prints and the header the other commands print.

use colored::Colorize;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Print the main banner
pub fn print_banner() {
    println!();
    println!("{}", "║ ║╔═╝  ╔═║║ ║╔═║  ╔═╝╔═╝╔═║╔═ ╔═ ╔═╝╔═║".cyan());
    println!("{}", "╔╝ ══║═╝╔═║║ ║╔╔╝═╝══║║  ╔═║║ ║║ ║╔═╝╔╔╝".cyan());
    println!("{}", "╝ ╝══╝  ╝ ╝══╝╝ ╝  ══╝══╝╝ ╝╝ ╝╝ ╝══╝╝ ╝".cyan());
    println!();
    println!(
        "  {} v{}  |  https://kief.studio",
        "Kief Studio".white().bold(),
        VERSION
    );
    println!();
}

/// Print a compact header for subcommands
pub fn print_header(title: &str) {
    println!();
    println!(
        "{} {}",
        "AUR Security Scanner".cyan().bold(),
        format!("| {}", title).dimmed()
    );
    println!("{}", "=".repeat(60).dimmed());
}
