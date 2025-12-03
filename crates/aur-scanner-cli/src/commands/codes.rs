//! List all detection codes with descriptions

use anyhow::Result;
use colored::Colorize;

/// Detection code categories with all codes
pub fn get_all_codes() -> Vec<CodeEntry> {
    vec![
        // Download and Execute
        CodeEntry::new("DLE-001", "Critical", "Curl pipe to shell", "Download & Execute",
            "Detects curl piped to bash/sh, a classic malware pattern. Used in 2018 xeactor attack.",
            "Download scripts first, inspect them, then execute manually."),
        CodeEntry::new("DLE-002", "Critical", "Wget pipe to shell", "Download & Execute",
            "Detects wget piped to bash/sh. Same risk as curl piping.",
            "Download scripts first, inspect them, then execute manually."),
        CodeEntry::new("DLE-003", "Critical", "Curl output executed", "Download & Execute",
            "Downloads a file then executes it in a separate step.",
            "Review any downloaded content before execution."),

        // Pastebin Downloads
        CodeEntry::new("PASTE-001", "Critical", "Pastebin download", "Paste Sites",
            "Downloads from paste sites (pastebin.com, ptpb.pw, etc.). Major malware indicator. Used in 2018 xeactor attack via ptpb.pw.",
            "Never trust code from paste sites. Report immediately."),

        // Reverse Shells
        CodeEntry::new("SHELL-001", "Critical", "Bash reverse shell", "Reverse Shell",
            "Uses /dev/tcp for outbound shell connection. Classic bash reverse shell technique.",
            "Remove immediately. This is definitive malware."),
        CodeEntry::new("SHELL-002", "Critical", "Netcat reverse shell", "Reverse Shell",
            "Uses netcat with -e or -c flag for remote shell access.",
            "Remove immediately. This is definitive malware."),
        CodeEntry::new("SHELL-003", "Critical", "Python reverse shell", "Reverse Shell",
            "Python socket connection pattern indicative of reverse shell.",
            "Remove immediately. This is definitive malware."),
        CodeEntry::new("SHELL-004", "Critical", "Socat shell", "Reverse Shell",
            "Socat with EXEC or TCP for potential shell access.",
            "Review socat usage carefully."),

        // Credential Theft
        CodeEntry::new("CRED-001", "Critical", "SSH key access", "Credential Theft",
            "Accesses ~/.ssh/ directory containing private keys.",
            "Packages should never access SSH keys."),
        CodeEntry::new("CRED-002", "Critical", "GPG key access", "Credential Theft",
            "Accesses ~/.gnupg/ directory containing GPG keys.",
            "Packages should never access GPG keys."),
        CodeEntry::new("CRED-003", "Critical", "Password file access", "Credential Theft",
            "Accesses password files, credential stores, or cloud credentials.",
            "Report immediately. Likely credential theft."),

        // Browser Data Theft
        CodeEntry::new("BROWSER-001", "Critical", "Browser profile access", "Browser Theft",
            "Accesses browser profile directories. May steal passwords, cookies, history.",
            "Packages should never access browser data."),
        CodeEntry::new("BROWSER-002", "Critical", "Browser database access", "Browser Theft",
            "Accesses browser SQLite files (logins.json, Login Data, cookies.sqlite).",
            "Definitive credential theft indicator."),

        // Privilege Escalation
        CodeEntry::new("PRIV-001", "Critical", "Sudo in build", "Privilege Escalation",
            "Uses sudo in PKGBUILD build/package functions. Never required.",
            "Remove sudo. makepkg handles permissions correctly."),
        CodeEntry::new("PRIV-002", "Critical", "SUID/SGID bit", "Privilege Escalation",
            "Sets SUID or SGID bits on files. Can enable privilege escalation.",
            "Review carefully. SUID should be rare."),
        CodeEntry::new("PRIV-003", "Critical", "Sudoers modification", "Privilege Escalation",
            "Modifies /etc/sudoers for permanent privilege escalation.",
            "Never acceptable. Report immediately."),

        // Install Script Execution (CHAOS RAT)
        CodeEntry::new("INSTALL-001", "Critical", "Python in install script", "Install Abuse",
            "Executes Python in post_install. Used in July 2025 CHAOS RAT attack.",
            "Install scripts should not run Python."),
        CodeEntry::new("INSTALL-002", "High", "Binary execution in install", "Install Abuse",
            "Executes binaries from /opt or package directories during install.",
            "Review carefully. May be legitimate."),
        CodeEntry::new("INSTALL-003", "Critical", "Network in install script", "Install Abuse",
            "Makes network connections (curl/wget) in install scripts.",
            "Install scripts should never download content."),

        // Persistence Mechanisms
        CodeEntry::new("PERSIST-001", "Critical", "Systemd service creation", "Persistence",
            "Creates systemd services in install scripts. Enables boot persistence. Used in 2018 xeactor and 2025 CHAOS RAT.",
            "Services should be user-enabled, not automatic."),
        CodeEntry::new("PERSIST-002", "Critical", "Systemd timer creation", "Persistence",
            "Creates systemd timers for periodic execution. Used in 2018 xeactor attack (360 second intervals).",
            "Timers should be user-controlled."),
        CodeEntry::new("PERSIST-003", "High", "Cron job creation", "Persistence",
            "Creates cron jobs for scheduled execution.",
            "Cron jobs should be user-managed."),
        CodeEntry::new("PERSIST-004", "Critical", "rc.local modification", "Persistence",
            "Modifies /etc/rc.local for boot persistence.",
            "Packages should never modify boot scripts."),
        CodeEntry::new("PERSIST-005", "High", "XDG autostart creation", "Persistence",
            "Creates autostart entries in .config/autostart/.",
            "Autostart should be user-controlled."),
        CodeEntry::new("PERSIST-006", "Critical", "Systemd masquerading", "Persistence",
            "Binary named like systemd component (e.g., systemd-initd). Used in CHAOS RAT attack.",
            "Verify this is a legitimate systemd component."),

        // Cryptomining
        CodeEntry::new("CRYPTO-001", "Critical", "Mining pool connection", "Cryptomining",
            "Connects to cryptocurrency mining pools (stratum+tcp://).",
            "Definitive cryptomining. Remove immediately."),
        CodeEntry::new("CRYPTO-002", "Critical", "Miner binary", "Cryptomining",
            "Contains known miner executables (xmrig, cgminer, cpuminer, etc.).",
            "Remove immediately."),
        CodeEntry::new("CRYPTO-003", "Critical", "Wallet address", "Cryptomining",
            "Contains cryptocurrency wallet addresses (Monero, Bitcoin).",
            "Wallet addresses in packages are highly suspicious."),

        // Data Exfiltration
        CodeEntry::new("EXFIL-001", "Critical", "Curl POST exfiltration", "Data Exfiltration",
            "Sends data via curl POST/data flags.",
            "Build/install should not send data externally."),
        CodeEntry::new("EXFIL-002", "Critical", "Netcat data transfer", "Data Exfiltration",
            "Uses netcat to transfer data externally.",
            "Netcat piping is suspicious in build scripts."),
        CodeEntry::new("EXFIL-003", "Critical", "Discord/Telegram webhook", "Data Exfiltration",
            "Uses Discord or Telegram webhooks for C2 or data exfiltration.",
            "Webhook URLs in packages are malicious."),

        // Obfuscation
        CodeEntry::new("OBF-001", "High", "Base64 decoding", "Obfuscation",
            "Decodes base64 content, potentially hiding malicious payloads.",
            "Decode and review base64 content manually."),
        CodeEntry::new("OBF-002", "High", "Eval usage", "Obfuscation",
            "Uses eval to execute potentially obfuscated code.",
            "Avoid eval; use direct commands."),
        CodeEntry::new("OBF-003", "High", "Hex-encoded payload", "Obfuscation",
            "Contains hex-encoded content (\\xNN or xxd).",
            "Decode and review content."),
        CodeEntry::new("OBF-004", "Medium", "String concatenation", "Obfuscation",
            "Uses excessive variable concatenation to hide commands.",
            "Review concatenated strings carefully."),
        CodeEntry::new("OBF-005", "High", "Gzip decode execution", "Obfuscation",
            "Decompresses and executes payloads via gzip piping.",
            "Decompress and review before execution."),

        // Suspicious URLs
        CodeEntry::new("URL-001", "High", "Raw IP in URL", "Network Security",
            "Uses raw IP addresses instead of domain names. C2 indicator.",
            "Use domain names from trusted sources."),
        CodeEntry::new("URL-002", "High", "URL shortener", "Network Security",
            "Uses URL shorteners (bit.ly, tinyurl) to hide destinations.",
            "Always use full URLs from trusted sources."),
        CodeEntry::new("URL-003", "High", "Dynamic DNS domain", "Network Security",
            "Uses dynamic DNS domains (duckdns, no-ip) common for malware C2.",
            "Dynamic DNS in packages is suspicious."),
        CodeEntry::new("SRC-001", "Medium", "Non-standard git source", "Network Security",
            "Git source from non-standard hosting (not GitHub, GitLab, etc.).",
            "Verify git sources are trusted."),

        // Checksums
        CodeEntry::new("CHKSUM-001", "Medium", "MD5 checksum", "Cryptography",
            "Uses cryptographically broken MD5 for integrity.",
            "Use sha256sums or stronger."),
        CodeEntry::new("CHKSUM-002", "Medium", "SHA1 checksum", "Cryptography",
            "Uses weak SHA1 for integrity verification.",
            "Use sha256sums or stronger."),
        CodeEntry::new("CHK-001", "High", "No checksums", "Cryptography",
            "Package has no checksum verification.",
            "Always provide checksums for sources."),
        CodeEntry::new("CHK-005", "High", "All SKIP checksums", "Cryptography",
            "All sources use SKIP, no integrity verification.",
            "Provide real checksums for non-git sources."),

        // Hidden Files/Paths
        CodeEntry::new("HIDDEN-001", "High", "Hidden file creation", "Suspicious Paths",
            "Creates hidden files in user home directory.",
            "Packages should not create hidden files in ~."),
        CodeEntry::new("HIDDEN-002", "High", "Tmp execution", "Suspicious Paths",
            "Executes files from /tmp. CHAOS RAT placed binary in /tmp.",
            "Packages should not execute from /tmp."),
        CodeEntry::new("HIDDEN-003", "High", "Non-standard binary path", "Suspicious Paths",
            "Places binaries in /usr/local/share or ~/.local/share. Used by CHAOS RAT.",
            "Binaries should be in standard locations."),

        // Environment
        CodeEntry::new("ENV-001", "Critical", "LD_PRELOAD manipulation", "Environment",
            "Manipulates LD_PRELOAD for library injection.",
            "LD_PRELOAD manipulation is extremely suspicious."),
        CodeEntry::new("ENV-002", "High", "PATH manipulation", "Environment",
            "Modifies PATH environment variable in install scripts.",
            "PATH manipulation is suspicious."),
        CodeEntry::new("ENV-003", "Critical", "Shell config modification", "Environment",
            "Modifies .bashrc, .profile, or other shell configs for persistence.",
            "Packages should not modify shell configuration."),

        // Metadata
        CodeEntry::new("META-001", "Low", "Provides impersonation", "Metadata",
            "Package 'provides' another package, may be impersonating. CHAOS RAT used this technique.",
            "Verify this is a legitimate alternative package."),
    ]
}

pub struct CodeEntry {
    pub code: &'static str,
    pub severity: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
}

impl CodeEntry {
    pub fn new(
        code: &'static str,
        severity: &'static str,
        name: &'static str,
        category: &'static str,
        description: &'static str,
        recommendation: &'static str,
    ) -> Self {
        Self { code, severity, name, category, description, recommendation }
    }
}

pub fn run(category: Option<&str>) -> Result<()> {
    let codes = get_all_codes();

    println!("{}", "AUR Security Scanner - Detection Codes".bold());
    println!("{}", "=".repeat(60));
    println!();

    // Get unique categories
    let mut categories: Vec<&str> = codes.iter().map(|c| c.category).collect();
    categories.sort();
    categories.dedup();

    // Filter by category if specified
    let filter_cat = category.map(|c| c.to_lowercase());

    for cat in categories {
        if let Some(ref filter) = filter_cat {
            if !cat.to_lowercase().contains(filter) {
                continue;
            }
        }

        println!("{}", format!("[{}]", cat).cyan().bold());
        println!();

        for entry in codes.iter().filter(|e| e.category == cat) {
            let severity_colored = match entry.severity {
                "Critical" => entry.severity.red().bold(),
                "High" => entry.severity.yellow(),
                "Medium" => entry.severity.blue(),
                "Low" => entry.severity.white(),
                _ => entry.severity.normal(),
            };

            println!("  {} [{}] {}",
                entry.code.green().bold(),
                severity_colored,
                entry.name);
        }
        println!();
    }

    println!("{}", "Use 'aur-scan explain <CODE>' for detailed information.".dimmed());

    Ok(())
}
