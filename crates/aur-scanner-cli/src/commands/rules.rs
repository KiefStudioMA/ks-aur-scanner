//! Rules command implementation

use anyhow::Result;
use aur_scanner_core::{rules::RuleEngine, Severity};
use colored::Colorize;

/// Run the rules command
pub fn run(severity_filter: Option<Severity>, details: bool) -> Result<()> {
    let engine = RuleEngine::default();

    println!();
    println!("{}", "Available Detection Rules".bold().underline());
    println!();

    // Get all rules from built-in set
    let builtin_rules = get_builtin_rule_info();

    for (id, name, severity, description) in builtin_rules {
        // Filter by severity if specified
        if let Some(filter) = &severity_filter {
            if &severity != filter {
                continue;
            }
        }

        let severity_str = format_severity(&severity);
        println!("{} [{}] {}", id.bold(), severity_str, name);

        if details {
            println!("    {}", description.dimmed());
            println!();
        }
    }

    println!();
    println!("Total rules loaded: {}", engine.rule_count());

    Ok(())
}

fn format_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MEDIUM".cyan().to_string(),
        Severity::Low => "LOW".to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}

fn get_builtin_rule_info() -> Vec<(&'static str, &'static str, Severity, &'static str)> {
    vec![
        ("DLE-001", "Curl pipe to shell", Severity::Critical, "Downloading and executing remote scripts via curl | bash"),
        ("DLE-002", "Wget pipe to shell", Severity::Critical, "Downloading and executing remote scripts via wget | sh"),
        ("SHELL-001", "Bash reverse shell", Severity::Critical, "Pattern indicates a bash reverse shell connection"),
        ("SHELL-002", "Netcat reverse shell", Severity::Critical, "Netcat with execute flag indicates reverse shell"),
        ("CRED-001", "SSH key access", Severity::Critical, "Accessing SSH private keys during build/install"),
        ("CRED-002", "GPG key access", Severity::Critical, "Accessing GPG keyring during build/install"),
        ("PRIV-001", "Sudo in build function", Severity::Critical, "Build functions should never require sudo"),
        ("BROWSER-001", "Browser profile access", Severity::Critical, "Accessing browser profiles may indicate credential theft"),
        ("CRYPTO-001", "Mining pool connection", Severity::Critical, "Connection to cryptocurrency mining pools"),
        ("EXFIL-001", "Data exfiltration pattern", Severity::Critical, "Sending data to external servers"),
        ("OBF-001", "Base64 decoding", Severity::High, "Base64 decoding may hide malicious payloads"),
        ("OBF-002", "Eval usage", Severity::High, "Eval can execute obfuscated malicious code"),
        ("URL-001", "Raw IP in URL", Severity::High, "URLs with raw IP addresses are suspicious"),
        ("PERSIST-001", "Systemd service creation", Severity::High, "Creating systemd services outside of package()"),
        ("PERSIST-002", "Cron job creation", Severity::High, "Creating cron jobs for persistence"),
        ("SRC-001", "Insecure source protocol", Severity::Medium, "Source downloaded over insecure HTTP"),
        ("SRC-002", "Suspicious source domain", Severity::High, "Source from suspicious or untrusted domain"),
        ("SRC-003", "Raw IP in source URL", Severity::High, "Source URL contains raw IP address"),
        ("SRC-004", "URL shortener in source", Severity::High, "Source uses URL shortener hiding destination"),
        ("CHK-001", "No checksums", Severity::High, "Package has sources but no checksums"),
        ("CHK-002", "MD5 checksums", Severity::Medium, "MD5 is cryptographically broken"),
        ("CHK-003", "SHA1 checksums", Severity::Medium, "SHA1 is cryptographically weak"),
        ("CHK-004", "SKIP checksums", Severity::Medium, "Some sources use SKIP instead of real checksums"),
        ("CHK-005", "All SKIP checksums", Severity::High, "All sources use SKIP - no integrity verification"),
        ("PRIV-002", "SUID bit setting", Severity::Critical, "Setting SUID/SGID bits on files"),
        ("PRIV-003", "Sudoers modification", Severity::Critical, "Modifying sudoers file"),
        ("PRIV-004", "Capabilities setting", Severity::Medium, "Setting file capabilities"),
        ("PRIV-005", "Kernel module operations", Severity::High, "Kernel module loading or manipulation"),
    ]
}
