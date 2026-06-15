//! CLI banner and branding
//!
//! Provides consistent branding and UI utilities across all CLI commands.

#![allow(dead_code)]

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

/// Print a section divider
pub fn print_divider() {
    println!("{}", "-".repeat(60).dimmed());
}

/// Print a box around text
pub fn print_box(lines: &[&str]) {
    let max_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let width = max_len + 4;

    println!("{}", format!("+{}+", "-".repeat(width - 2)).dimmed());
    for line in lines {
        println!(
            "{} {:<width$} {}",
            "|".dimmed(),
            line,
            "|".dimmed(),
            width = max_len
        );
    }
    println!("{}", format!("+{}+", "-".repeat(width - 2)).dimmed());
}

/// Print a severity badge
pub fn severity_badge(severity: &aur_scanner_core::Severity) -> String {
    use aur_scanner_core::Severity;
    match severity {
        Severity::Critical => format!("{}", " CRITICAL ".on_red().white().bold()),
        Severity::High => format!("{}", " HIGH ".on_yellow().black().bold()),
        Severity::Medium => format!("{}", " MEDIUM ".on_cyan().black()),
        Severity::Low => format!("{}", " LOW ".on_white().black()),
        Severity::Info => format!("{}", " INFO ".dimmed()),
    }
}

/// Print status indicators
pub fn status_ok() -> String {
    format!("{}", "[OK]".green().bold())
}

pub fn status_warn() -> String {
    format!("{}", "[WARN]".yellow().bold())
}

pub fn status_fail() -> String {
    format!("{}", "[FAIL]".red().bold())
}

/// Print a progress indicator
pub fn progress(current: usize, total: usize, item: &str) {
    let pct = (current * 100).checked_div(total).unwrap_or(0);
    print!(
        "\r{} [{}/{}] {}...",
        format!("{}%", pct).cyan(),
        current,
        total,
        item
    );
    use std::io::Write;
    std::io::stdout().flush().ok();
}

/// Clear the current line (for progress updates)
pub fn clear_line() {
    print!("\r{}\r", " ".repeat(80));
    use std::io::Write;
    std::io::stdout().flush().ok();
}
