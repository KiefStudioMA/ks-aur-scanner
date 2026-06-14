# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

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
