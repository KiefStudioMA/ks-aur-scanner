# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.0-rc3] - 2026-06-15

Security-hardening release: an adversarial pre-ship review of the rc2 code closed
six real defects across the gate, parser, and detection layers, plus an
exhaustive expansion of shell/interpreter download-exec coverage. **Release
candidate.**

### Gate — fail closed
- The AUR-membership classifier no longer treats a network/lookup error as
  "not an AUR package" (which could let an install proceed unscanned); an
  indeterminate result now fails closed and is scanned. The `install` consent
  prompt requires a TTY — a piped `y` no longer counts as consent.

### Parser — no silent evasion, no panic
- Closed a quote-state desync between the array terminator and the inline-comment
  stripper that could silently drop a crafted `source=()`/`sha256sums=()`
  continuation line, hiding a source from every analyzer. An unterminated array is
  now flushed to the analyzers (and warned), never dropped.
- Fixed a panic on a CRLF + multibyte `.install` (byte offset could land
  mid-codepoint).

### Detection
- The privilege analyzer now shares the informational-line filter, so a printed
  `sudo`/`setcap`/`sudoers` message or heredoc no longer raises a Critical finding.
- The printed-message filter is now **quote-aware**: a `;`/`|`/`&`/`>` *inside* a
  quoted `echo`/`msg` string is literal text, so a benign note like
  `echo "config lives in ~/.config; ..."` no longer trips `HIDDEN-001`. An
  unquoted chain (`echo x; touch ~/.evilrc`) and in-string command substitution
  (`"$(curl …)"`) are still scanned.
- De-obfuscation now decodes 2-char quote-splitting and backslash escapes, catches
  `dash` and other shells the old alternation missed, and runs in the deep /
  remote-exec / IOC analyzers too.
- **Exhaustive download-exec sink coverage** — every common shell and interpreter
  reachable via `curl | …`, `<(curl)`, `-c/-e/-r "$(curl)"`, here-strings, path
  prefixes (`/bin/sh`), launchers (`busybox`/`env`/…), and double-launchers
  (24 shells + 20+ interpreters). `npx`/`bunx` lifecycle runners (`ATOMIC-002`).
  New `EXEC-006` (`sqlite3 .shell/.system/.import`) and `EXEC-007`
  (`make -f -` / `make -f /dev/stdin`).
- `HIDDEN-002`/`INSTALL-002` now require an execution context (no longer fire on
  `TMPDIR=/tmp/…`, `mktemp -d /tmp/…`, `./configure`).

### Pacman hook
- The privilege-drop decision/guard logic is now test-covered: it refuses a uid-0
  *or* gid-0 drop target, refuses a symlinked/non-regular PKGBUILD, and fails
  closed on a scan error or a critical finding.

## [1.1.0-rc2] - 2026-06-14

Proactive detection expansion, driven by a live obfuscated AUR campaign and an
adversarial gap analysis of the catalog. **Release candidate.**

### Anti-evasion (the multiplier)

- **De-obfuscation pass.** A new wave hid a `bun add <js-payload>` in a
  `post_install` hook using ANSI-C quoting (`$'\x63'`) and adjacent-quote
  word-splitting (`"b"'u''n'`), which evaded the targeted rules — rc1 caught it
  only as a generic high "hex payload." The scanner now **decodes** ANSI-C
  escapes and **collapses** quote-splitting, and runs *every* rule against the
  decoded text. The whole catalog now resists this evasion at once: that sample
  is correctly flagged **critical** (`ATOMIC-002`, package-manager-in-install-hook).
- `OBF-006` flags the quote-splitting technique itself; `OBF-007/008/011` add
  printf-assembly, base32/16 decode, and interpreter here-strings.

### Detection — +28 rules across six threat classes (catalog 72 → 106)

- **Reverse/bind shells:** `SHELL-005..011` — perl, php, ruby/lua/awk, node,
  openssl `s_client`, `mkfifo` backpipe, busybox-nc/telnet/ncat-ssl.
- **Exfiltration:** `EXFIL-004` (DNS), `EXFIL-006/007` (curl/wget upload),
  `EXFIL-008` (Slack/Teams webhooks), `EXFIL-009` (file-drop/tunnel hosts),
  `CRED-004/005/008` (cloud/CI creds, keyrings/wallets, env dump).
- **Auth/system tampering:** `PRIV-007/008` (privileged account, password),
  `TAMPER-001/002/005/011/013/017` (auth-db write, doas/NOPASSWD, PAM, pacman
  `SigLevel=Never`, disabling security controls, CA trust anchor).
- **Supply-chain trust:** `TRUST-001/002` (pacman-key / gpg import),
  `DEP-003` (index/registry override), `SRC-009` (obfuscated IP in URL).
- **RCE:** `EXEC-002` (`sh -c "$(curl)"`), `EXEC-005` (detached `setsid`/`nohup`).

### Other

- `aur-scan install` now tidies its own build directory after a successful
  install (`--keep-build` to retain).
- Packaging: `options=('!debug' '!strip')` — the release binaries are already
  stripped by cargo, so makepkg's split-debug + re-strip passes were redundant
  (and produced an empty `-debug` package + `gdb-add-index`/libfakeroot noise).
- The fail-closed wrapper and the privilege-dropping pacman hook gained unit
  tests for their deny/refuse/validation paths.

## [1.1.0-rc1] - 2026-06-13

Security-hardening release resolving a full security & quality audit of the
scanner. **Release candidate** — see "Behavior changes" below before upgrading
automation, and the validation checklist in the PR before promoting to stable.

### ⚠️ Behavior changes (read before upgrading)

- **The scanner now fails *closed*.** The `paru`/`yay` wrapper and the pacman
  hook previously continued past a fetch/scan error, a timeout, or a
  non-interactive prompt; they now **deny** in those cases. If you drive
  `paru`/`yay` from a script, cron, or CI (no TTY), an install that cannot be
  fully analyzed will be refused rather than silently proceeding. This is
  intentional — a security gate that fails open is not a gate.
- **`scan --format json` / `--format sarif` now emit only the machine document
  on stdout.** The human-readable summary moved to **stderr**, so
  `aur-scan scan --format json | jq` works. If you were scraping the summary
  text out of stdout, read stderr instead (or use the JSON fields).

### Security

- **Input validation chokepoint** for package names/bases: illegal identifiers
  are rejected before they can become URL path segments or filesystem paths,
  closing a path-traversal vector (`package_base` → `remove_dir_all`) and
  request-injection into the AUR RPC.
- **Network hardening:** redirects refused, HTTPS-only enforced, response bodies
  size-capped (streaming), and all RPC URLs percent-encoded.
- **Pacman hook drops root** (supplementary groups → gid → uid, verified
  irreversible) before reading user cache files, validates names, and refuses
  symlinked PKGBUILDs.
- **Detection-evasion fixes:** backslash-newline line-continuation splicing;
  quote- and comment-aware brace scanning (no more `echo "}"` / `# }`
  truncation); broadened reverse-shell (`/dev/(tcp|udp)/<host>`) and bare
  crypto-address detection; checksum SKIP-laundering across all hash arrays.
- Dependency advisory **RUSTSEC-2026-0007** resolved (`bytes` → 1.11.1).

### Added

- `SRC-007`: warns when a VCS source is not pinned to a commit (Low — a
  reproducibility nudge, since branch-tracking is normal for `-git` packages).
- `Severity::is_at_least()` gate helper with an order-pinning test.
- CLI integration test suite that runs the real binary against the PKGBUILD
  fixtures (JSON/SARIF validity, detection matrix, catalog coverage, exit codes).
- CI (format, clippy-as-error, full tests, release build) and `cargo-deny`
  supply-chain gating, plus a weekly advisory scan.
- The rolling `-git` package now verifies the signed HEAD commit at build time.

### Fixed

- **False positive:** a printed `note "...~/.config/..."` message in an install
  script no longer trips `HIDDEN-001` (it mentions a path; it does not write
  one) — observed on `google-chrome` and `visual-studio-code-bin`.
- `scan` machine-format output no longer corrupted by the summary footer.
- Parser: `source+=(...)` appends are no longer dropped; inline comments are
  handled quote-aware (a `#commit=` fragment in a quoted value is preserved);
  single-line function bodies are captured.
- Cache writes are atomic (`0600`) in an owner-only (`0700`) directory, entries
  are key-bound, and a corrupt entry is a miss rather than trusted data.
- Provenance store distinguishes an absent baseline from a corrupt one (the
  latter is preserved as `.corrupt` and warned, not silently reset).
- Removed a panicking `AurClient::default()` and a response `unwrap`.

### Notes

- The `--locked` updates to the tagged-package PKGBUILDs live in their own AUR
  repositories and are released separately.

## [1.0.3]

See the project history prior to the introduction of this changelog.

[1.1.0-rc1]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v1.1.0-rc1
