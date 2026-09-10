# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Fixes from an external review of the release candidate. All eight items were
reproduced against the branch before being changed, and the two regex findings
were settled with fixture tests rather than by reading.

### Security

- **The pacman hook no longer reads a user-writable config as root.** It
  resolves its configuration before it can drop privileges — `/etc` may be
  root-readable only — and it had moved off its hardcoded `/etc` path onto the
  CLI's search order, which puts `$XDG_CONFIG_HOME`/`~/.config` *first*. A root
  process was therefore taking its security configuration from a file any
  unprivileged user can write, about fifteen lines before the drop. The
  cheapest exploit is not escalation but denial of service: because a malformed
  security config is deliberately a hard error, a hostile `build()` could drop
  broken TOML in `~/.config/aur-scanner/` and wedge every subsequent pacman
  transaction — something that previously required write access to `/etc`.
  Config lookups are now privilege-aware (`ScanConfig::resolve_for_privilege`):
  as root, `/etc` and nothing else.

### Fixed

- **`ATOMIC-004` missed the natural form of a sudo shim.** Both patterns
  required either a literal `~`/`/home/<user>` prefix or the token `sudo`
  *before* the destination directory. Real commands put the file name last, so
  `cp payload /usr/local/bin/sudo` and
  `install -Dm755 stealer "$HOME/.local/bin/sudo"` matched neither — on a
  Critical rule the hook fails closed on. The rule now anchors on the PATH
  directory instead of on how the home directory was spelled.
- **`PERSIST-003` was narrowed past its goal.** Suppressing `rm` (issue #21)
  left it matching an enumerated verb list, so `echo '...' | crontab -` — the
  standard non-interactive install — plus `crontab -u root -`, a redirect from
  anything other than `echo`/`printf`/`cat`, `ln -s`, and `sed -i` insertion
  all passed clean. Now matched, with every pattern bounded to a single command
  so cleaning up a stale cron entry still stays silent.
- **A pre-existing `PERSIST-003` false positive**, found while measuring the
  above against 503 live AUR PKGBUILDs: `crontab` followed by `\s+` matched
  across a newline and into prose, firing on `python-python-crontab` twice over
  (`pkgname=...-crontab` plus the next line, and `pkgdesc="Crontab module
  for python"`). Arguments now share a line with their command, and a
  bare-word argument must end it. The rule fires on 1 of 503 — `dcron-git`,
  which does install cron files.
- **An empty `XDG_CONFIG_HOME` no longer disables the user config path.**
  Written as an `else if` against the same `if let`, `XDG_CONFIG_HOME=` counted
  as set and dropped `~/.config` entirely — the issue #25 symptom that search
  order exists to prevent.
- **A malformed config no longer disables the commands that diagnose it.**
  Config resolution had moved ahead of the command match, so a bad file
  hard-failed `explain`, `rules`, `ioc` and `codes` as well. Those read nothing
  but the built-in rule table; they now run first. `codes` reads `rules_path`,
  so it degrades to the built-in list with a warning that says so. Every
  scanning path still hard-fails.
- **`scanned_files` now lists every file that was read** — the `.hook`
  scriptlets, the side scripts pulled in from `source=()`, and the committed
  binaries. A SARIF consumer reads it as the manifest of what was examined, and
  a finding could point at a file the same report said was never scanned.
- **`DeepAnalyzer` findings anchor to the first file, not the last.** The
  anchor was reassigned every loop iteration, so with several scriptlets every
  finding pointed at whichever was discovered last.

### Changed

- The repository accepts **merge commits only**; squash and rebase are
  disabled. Release tags are signed against a PR head, and a squash or rebase
  merge would orphan the tag it was verified from.

## [2.2.0-rc.1] - 2026-09-10

Change detection, name impersonation, ownership signals, and static binary
analysis.

**This is a release candidate, and it is a large one.** The detection surface
grew from 118 codes to 133 and every scanning path was rewired, so it wants soak
time rather than going straight to stable. Install `aur-scanner-rc` to test it.

Every threshold below was set by measuring against the live data -- all 15,436
official package names and all 119,170 AUR packages -- not by intuition. Two
rules were deleted outright once measured, and one was demoted from High to an
informational note.

### Added

- **`aur-scan diff <old> <new>`** — compare two package directories and report
  findings that appeared, findings that were resolved, and structural changes
  (upstream moved, install script added, new functions) that a severity count
  hides. Stateless, so it is safe in CI. `--fail-on` trips only on **newly
  added** findings, so a package with long-standing Mediums can still be
  approved.
- **Automatic change detection** on `check` and `install` (`DIFF-001..004`):
  new findings since the last scan, ownership moved, upstream moved, install
  script added. Silent on a first scan and on a plain version bump. Source URLs
  compare at `host/owner/repo`, so new tags and release tarballs do not read as
  an upstream change.
- **Name impersonation** (`SQUAT-001..004`). Rendering collision — confusable
  glyphs or a separator swap — measured at **zero** false positives across the
  official corpus, reported Critical. One-keystroke substitution restricted to a
  curated high-value list and gated on registry standing. Edit-distance matching
  was implemented, measured at 23,662 false positives for two-character edits and
  2,039 for one-character insert/delete, and **removed** — those kinds are
  absent, not tuned down.
- **`[[owned_namespaces]]`** — declare the package-name prefixes you publish and
  the accounts allowed to publish them. The AUR reserves no variant namespace, so
  owning `foo` does not reserve `foo-bin`. 42.5% of real AUR build variants have
  a different maintainer than their base and are legitimate, so the scanner will
  not accuse anyone on that basis; declaring your own names turns the ambiguous
  case into a Critical with no false positives by construction. Empty by default.
- **Ownership signals** (`OWN-001..004`) — orphaned (11.9% of the AUR, so Low),
  orphaned *and* out-of-date (4.2%, Medium), stale out-of-date flag, and a new
  package with no community validation that runs build or install code. Zero
  votes is 50% of the AUR and is never reported on its own.
- **`aur-scan completions <shell>`** for bash, zsh and fish, installed by the
  packages. Generated from the command tree so they cannot drift. Deliberately
  exempt from config loading: a typo in `config.toml` is a hard error everywhere
  else and must not break a shell setup at package-install time.
- **`PERM-001`/`PERM-002`** world-writable permission rules, shipped as a
  community TOML file so they double as a worked example (issue #8).
- A clean-room VM acceptance suite (`tests/vm-acceptance.sh`) that installs the
  built package and exercises the installed binaries, every documented command,
  and all four shell integrations in their real interpreters.

### Fixed

- **`SHELL-002` false positive** — the netcat rule matched the `nc` at the *end*
  of `MEGAsync`, reporting `git -C MEGAsync -c protocol.file.allow=...` as a
  Critical reverse shell (issue #32). Command-position anchoring via a shared
  `CMD_START`, and the flag search is bounded to the command itself so a benign
  `-c` on a later command in the same line cannot complete the match.
- **`CHK-004`/`CHK-005` named their sources** — a bare count was unactionable;
  the reporter could not tell a detached signature from a tarball (issue #31).
  Now named in the description and exposed as structured metadata with positional
  indices.
- **Registry context reached only `check`.** `install`, the AUR-helper wrapper,
  `system`, and the pacman hook all scanned with a strictly smaller analyzer set,
  so `SQUAT-*`, `OWN-*`, `DIFF-*` and the operator's own `[[owned_namespaces]]`
  were inert on every path that gates an installation. The convenience overload
  that defaulted to no registry has been removed; the choice is now a required
  `Registry` argument.
- **`AUR_SCAN_MODE=install` was the weaker mode** despite being documented as
  stronger: it routed to the one command with no registry context *and* raised
  the blocking threshold from High to Critical. The integrations now pass
  `--gate "$AUR_SCAN_SEVERITY"` so the configured threshold governs both modes.
- **`DIFF-003` fired on adding a patch file.** Local `source=()` entries were
  recorded as upstream origins, so a routine `0001-fix-build.patch` produced
  `now fetches from 0001-fix-build.patch` at High — enough to trip the
  `--fail-on high` the shell integration uses.
- **Scan history could be poisoned.** The record is keyed on the name a PKGBUILD
  declares about itself, so `check --local ./fork` declaring `pkgname=firefox`
  overwrote the real baseline — and because `DIFF-*` are pure deltas, a poisoned
  baseline *silences* the next real change. Shadowing local dirs are no longer
  recorded.
- **Concurrent scans could corrupt a history record.** The temp file used a fixed
  name shared by every writer; a torn write was then swallowed as "no history",
  silently disabling change detection for that package.
- **`SQUAT-001` emitted High from one of its two code paths** while the catalog,
  the README and every `--fail-on critical` gate treated it as Critical.
- **Non-ASCII detection no longer depends on a hand-written table.** AUR names
  are ASCII by policy, so any non-ASCII glyph is anomalous; the confusable table
  now only explains a name rather than deciding about one.
- **Shell integrations wrote their banner to stdout.** These are sourced from a
  shell rc, so that breaks `scp`, `rsync`, and `ssh host cmd`, all of which read
  the remote shell's stdout as protocol data.
- **The packages installed only `example.toml`** from `rules.d/`, so any other
  rule file shipped would silently not exist on user systems.
- **Config keys are now validated everywhere**, including inside
  `[threat_intel]` and `[cache]`. A mistyped `virustotal_apikey` previously did
  nothing at all, which is the exact failure mode issue #25 was about.


### Added (since the section above was first drafted)

- **Static binary analysis** (`BIN-001`..`BIN-005`). A hand-written, bounds-checked
  ELF reader — no new dependency in a supply-chain tool — parses the header,
  section table, `DT_NEEDED`, `DT_RPATH`/`RUNPATH`, imported symbol names and
  section entropy. Nothing is executed. `ldd` is specifically off-limits and the
  acceptance suite asserts it: on glibc it is a shell script that
  `eval`-executes its target through the loader, so calling it on a hostile
  `-bin` payload runs that payload.
- **`SRC-010`** — a source that fetches the same repository name under a
  *different owner* than the declared `url=`. `SRC-008` structurally could not
  see this: it compares forge hosts and skips VCS sources.
- **`DEEP-003`** — Unicode bidi controls (Trojan Source, CVE-2021-42574), which
  make the code a reviewer reads differ from the code that runs.
- **`ESCAPE-001`** — extraction or installation outside `$srcdir`/`$pkgdir`.
- **Local `source=()` files are now read.** A payload in a build-fix `.patch`, or
  a sidecar script the PKGBUILD sources, was previously invisible.
- **`aur-scan version` validates the configuration** and exits 2 if it is broken,
  so an operator can check before upgrading rather than finding out when the
  pacman hook aborts a transaction.

### Fixed (since the section above was first drafted)

- **`aur-scan check --no-confirm` exited 0 on a Critical finding.** The gate was
  only ever evaluated when `--fail-on` was passed, and the shell integrations
  invoke `check --severity <sev> --no-confirm` with no `--fail-on` — `--severity`
  is a display floor, not a gate. With `AUR_SCAN_INTERACTIVE=0` the primary
  documented protection was a no-op. Both sides fixed.
- **Registry context reached only `check`.** `install`, the AUR-helper wrapper,
  `system` and the hook all ran a strictly smaller analyzer set, so `SQUAT-*`,
  `OWN-*`, `DIFF-*` and `[[owned_namespaces]]` were inert on every path that
  gates an installation. The convenience overload that defaulted to no registry
  is gone; the choice is now a required argument.
- **`AUR_SCAN_MODE=install` was the weaker mode** while documented as stronger.
- **Two false-positive classes in `DIFF-003`**: local patch files recorded as
  upstream origins, and version-in-path URLs where a routine bump looked like an
  upstream move.
- **Scan history** — poisoning via a `--local` directory's self-declared name,
  a torn-write race between concurrent scans, unbounded growth, a
  world-writable fallback path, discarding computed findings when the store
  could not be written, and reporting "orphaned" when a lookup had merely
  failed.
- **`SQUAT-001` emitted High from one of its two paths** while the catalog and
  every `--fail-on critical` gate treated it as Critical.
- **Non-ASCII detection no longer depends on a hand-written table** — AUR names
  are ASCII by policy, so any non-ASCII glyph is anomalous.
- **Terminal escape injection.** Findings quote package-controlled text; printed
  raw, an escape sequence let the scanned file drive the reviewer's display.
- **Config keys are validated inside every table**, including `[threat_intel]`
  and `[cache]`.

### Notes for testers

Known gaps, named rather than hidden: decompression bombs and hostile
`makedepends` are not detected, and VirusTotal lookups still key off the
PKGBUILD's declared `sha256sums` rather than hashing a committed binary.

Thresholds in this release were set by measuring against the live corpus — all
15,436 official package names and all 119,170 AUR packages — not by intuition.
Two rules were deleted outright after measurement and one was demoted from High
to an informational note. If you see a false positive, that number is wrong and
we want the report.


## [2.1.0] - 2026-09-10

Promotes `2.1.0-rc.2` unchanged. No detection, rule, or behaviour differences
**between rc.2 and this tag** — the RC soaked for six weeks and the code is the
code that was tested, so the tag is a promotion rather than a new build.

Everything under 2.1.0-rc.1 and 2.1.0-rc.2 below is part of this release.

### Security

- `Cargo.lock` carries `anyhow` 1.0.104, which is past **RUSTSEC-2026-0190**
  (unsoundness in `Error::downcast_mut()`, fixed in 1.0.103). `main` still held
  1.0.100 until this release merged, which is why the weekly cargo-deny
  advisories job had been failing.

  The window was longer than first recorded here. The last green *scheduled*
  run on `main` was **2026-06-29**; it then failed every week from 2026-07-06
  through 2026-09-07 — ten consecutive weekly failures, about ten weeks. The
  earlier "failing since 2026-08-03" note read the second visible streak in a
  truncated run list as the start; the green runs dated 2026-07-28 in between
  were all `push` events on release branches and tags, never `main`.

### Changed

- `actions/checkout@v5` across CI and the advisories workflow (Node 24 Actions
  runtime); `main` was still on `@v4` and warning about the Node 20 deprecation.

## [2.1.0-rc.2] - 2026-07-28

Same candidate as 2.1.0-rc.1 plus packaging/CI hygiene. The `v2.1.0-rc.1` tag is
**immutable** (repo rules block tag deletion/move); this RC re-points testers at
the clean tip.

### Changed

- Repo-wide `cargo fmt --all`; CI rustfmt is now a hard gate (was non-blocking).
- CI/audit workflows: `actions/checkout@v4` → `@v5` (Node 24 Actions runtime).
- `aur-scanner-rc` tracks `v2.1.0-rc.2`.

No detection/rule behaviour changes vs 2.1.0-rc.1.

## [2.1.0-rc.1] - 2026-07-28

Release candidate focused on correctness and Atomic Arch coverage depth. External
pull requests are treated as untrusted input: only reimplemented, adversarially
tested changes land. The pacman hook remains fail-closed on Critical findings
in multi-package transactions (PR #23's soft-continue default is not accepted).

### Added

- **Configurable text output via an `[output]` config table.** Each finding's
  rendered fields are user-controllable: `line`, `snippet`, `recommendation`,
  and `cwe`. Rich by default; mistyped keys are hard errors
  (`deny_unknown_fields`). Display-only — never changes findings, exit codes, or
  gates. `check` compact output now shows `file:line` (discussion #16).
- **Default config discovery.** Without `-c`, the CLI and hook load the first
  existing path among `$XDG_CONFIG_HOME/aur-scanner/config.toml` (or
  `~/.config/...`) and `/etc/aur-scanner/config.toml`. A present-but-malformed
  file is a hard error. Fixes threat-intel appearing dead when keys lived only
  in the system config (issue #25). `check` now applies the full config (not
  only the display table).
- **ALPM `*.hook` side-script scanning.** Package-dir `.hook` files are read as
  text and analyzed with the install-scriptlet rule surface (Atomic Arch wave 4
  delivery path). Never executed.
- **ATOMIC-004** — `~/.local/bin/sudo` (and similar) credential-stealer shim
  detection.
- **ATOMIC-001** expanded with wave-3 package names (`nextfile-js`,
  `ansi-colors-nextfile-js`).
- **ENV-003** expanded to fish/zsh/profile.d startup paths (still subject to the
  pure-printer / heredoc informational filter).

### Fixed

- **`aur-scan-wrap` / plugin / `install` config discovery** — those paths used
  built-in `ScanConfig::default()` only, so XDG/`/etc` settings (including
  threat-intel) never applied when scanning through the wrapper. They now share
  `ScanConfig::resolve` via `Scanner::with_system_config()` (same contract as the
  CLI and hook). Pure built-in defaults remain available for unit tests.
- **SRC-004 false positive on `raw.githubusercontent.com`** — shortener match is
  host-label-boundary via `neturl`, not a substring (issue #22; `t.co` inside
  `githubusercontent.com`).
- **CHK-006 false positive on commented-out sources** — `#` after an unquoted
  `(` is a shell comment, matching bash (`source=(#"old"` …) (issue #24).
- **PRIV-002 false positive on clearing SUID** — symbolic modes that *remove*
  the bit (`u-s`, `g-s`, `-s`) no longer fire; only set forms (`u+s`, `=s`,
  octal 2–7xxx) do (issue #21).
- **ENV-003 / HIDDEN-001 on printed install messages** — path-prefixed pure
  printers (`/bin/cat <<EOF`) are recognized so documentation heredocs that
  mention `~/.bashrc` do not fire (issue #15).
- **PERSIST-003 on cron removal** — requires a write/install verb (or
  `crontab -e` / file install); `rm /etc/cron.d/...` and `crontab -l`/`-r` do
  not fire (issue #21).
- **`aur-scanner-git` prepare()** — GitHub merge commits signed by GitHub's key
  fall back to verifying the first parent against `validpgpkeys` (issue #20).

### Security

- Hook multi-package policy: **unchanged fail-closed**. A Critical finding still
  aborts the entire transaction. Soft-skip of the offending package only is not
  the default; it would let a malicious package ride alongside clean ones.
- `anyhow` bumped past RUSTSEC-2026-0190 (unsound `downcast_mut`).

### Deferred (not this RC)

- Offline analysis of prebuilt `-bin` artifacts (planned follow-up; opt-in threat
  intel already covers declared hashes when enabled).

## [2.0.0] - 2026-06-17

Major release: optional, opt-in threat-intelligence lookups (VirusTotal +
URLhaus), an active verdict cache, broader AUR-helper coverage (cache discovery
+ shell wrappers + a Nushell integration), and a global `--no-color` flag. The
default scan is unchanged — fully offline and static; threat intelligence stays
off until you enable it and supply your own keys.

### Added — opt-in threat intelligence

- **VirusTotal & URLhaus lookups, wired in for real.** The previously inert
  provider stubs are now working: with `enable_threat_intel` set and a key
  supplied (config or `VT_API_KEY`/`VIRUSTOTAL_API_KEY`/`URLHAUS_AUTH_KEY`), a new
  networked analyzer checks each declared `sha256sums` against VirusTotal and each
  `source=` URL against abuse.ch/URLhaus, emitting `TI-VT-001` / `TI-URLHAUS-001`
  on a malicious verdict. **Off by default** — a default scan stays fully
  offline/static. Only data already public in the PKGBUILD (hashes, source URLs)
  is ever transmitted; every lookup fails open so a provider outage never blocks a
  scan. All third-party network code is isolated in a single auditable file
  (`threat_intel/remote.rs`). URLhaus requires the now-mandatory abuse.ch
  `Auth-Key`.

  The VirusTotal-by-hash approach is credited to **@SuitablyMysterious**, whose
  `vt_lookup` in [PR #9](https://github.com/KiefStudioMA/ks-aur-scanner/pull/9)
  was the reference implementation.

- **Verdict caching is now active.** The hardened, MAC-authenticated `DiskCache`
  (owner-only dir, per-user keyed integrity) — previously built but unwired — now
  caches threat-intel verdicts, so repeat lookups respect VirusTotal's 4-req/min
  public quota. Gated by `CacheConfig`; lookups are also capped per scan.

### Added — broader AUR helper coverage

- **`system` audit and the pacman hook now cover every maintained AUR helper.**
  Cache discovery spans yay, paru, pikaur, aura, pakku, trizen, aurutils, rua, and
  pat-aur — at each helper's real PKGBUILD location (e.g. pikaur's
  `~/.local/share/pikaur/aur_repos`, rua's `~/.config/rua/pkg`, trizen's
  `~/.cache/trizen/sources`), with XDG `*_HOME` overrides honored.
- **Shell integration wraps more helpers** ([#6](https://github.com/KiefStudioMA/ks-aur-scanner/issues/6); diagnosis from [@nikoraasu](https://github.com/nikoraasu) in [#12](https://github.com/KiefStudioMA/ks-aur-scanner/issues/12)).
  `pikaur`, `trizen`, and `pakku` join `paru`/`yay` as pre-build gates (they share
  pacman's `-S`/`-Syu` grammar); helpers with a different model (`aura -A`, and the
  subcommand tools aurutils/rua/pat-aur) are covered by the pacman hook instead.
- **Nushell integration** (`install/integration.nu`, [#5](https://github.com/KiefStudioMA/ks-aur-scanner/issues/5)) — routes
  helper installs through the `aur-scan-wrap` gate; honors `AUR_SCAN_ENABLED=0` and
  provides `<helper>-unsafe` bypasses. Verified on nushell 0.113.
- **pacman hook** now sets `NeedsTargets`, so the transaction's package names reach
  the hook (it reads targets from stdin to locate each PKGBUILD).

### Changed

- Added a global `--no-color` flag; colored output also honors the `NO_COLOR`
  environment variable and auto-disables when not writing to a terminal.

## [1.1.0] - 2026-06-15

Stable promotion of the 1.1.0 release-candidate line, plus a second hardening
wave that closes the residual evasion classes surfaced by an adversarial
self-audit. **Stable.**

### Detection — evasion classes closed

- **Variable-indirection (taint pass).** A fetch/exec hidden behind a shell
  variable (`dl=curl; $dl …`, a `$(printf …)`-assembled command name) is now
  resolved and matched in addition to the raw and de-obfuscated forms — it used to
  evade every rule. Resolution only ever adds a finding, never suppresses one.
- **Case-insensitive analyzers.** The structural analyzers (privilege, remote-exec,
  deep, source) match command/shell/interpreter tokens case-insensitively, so a
  cased-up payload no longer slips a finding. Canonical-casing tokens (env-var
  NAMEs, the `R` interpreter, base64/hex alphabets) stay case-sensitive to avoid
  false positives.
- **Host-aware URL/IOC matching.** Domain and source-host checks parse the real URL
  authority instead of a naive substring, closing a `github.com\@evil.tld` /
  defanged-host evasion and a path-segment-as-host false positive.
- **Supply-chain & packaging-metadata analyzer.** New structural checks over
  `provides`/`replaces`/`epoch`/`backup`/`install`/`validpgpkeys`/checksums
  (dependency confusion, core-package displacement, signature theatre, sensitive
  `backup=`, malformed hashes).
- The printed-message filter is quote-aware: a `;` inside a quoted `echo` no longer
  trips `HIDDEN-001`.

### Hardening

- **Cache verdicts are authenticated** with a per-user keyed MAC — a local writer
  can no longer flip a malicious verdict to benign; a MAC failure is a miss, not
  trusted data.
- The `makepkg` build environment is allowlisted (a poisoned `PATH`/`LD_*`/`GIT_*`
  cannot redirect trusted helpers); `--force` can never override an *unscannable*
  package; a `--local` scan only attributes a cached verdict to a node whose name
  provably matches.
- A community rule that omits `file_types` now defaults to the scanned types
  instead of loading inert.

### Quality

- A **self-adversarial evasion fuzzer** runs as a release gate: every malicious
  fixture is mutated through a library of semantics-preserving evasion transforms
  and the gate must still block each variant — a slip fails the build.

### Credits

The install-hook package-manager detection (`ATOMIC-002`) and the de-obfuscation
pass this release hardens were prompted by community threat reports:
[@LunarEclipse363](https://github.com/LunarEclipse363)
([#2](https://github.com/KiefStudioMA/ks-aur-scanner/issues/2) — the
orphaned-package takeover that pulled the `atomic-lockfile` infostealer through an
install hook) and [@zebulon2](https://github.com/zebulon2)
([#10](https://github.com/KiefStudioMA/ks-aur-scanner/issues/10) — the obfuscated
`bun add` (`nextfile-js`) variant the de-obfuscation pass now sees through).

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

[2.2.0-rc.1]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v2.2.0-rc.1
[2.1.0]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v2.1.0
[2.1.0-rc.2]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v2.1.0-rc.2
[2.1.0-rc.1]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v2.1.0-rc.1
[2.0.0]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v2.0.0
[1.1.0-rc1]: https://github.com/KiefStudioMA/ks-aur-scanner/releases/tag/v1.1.0-rc1
