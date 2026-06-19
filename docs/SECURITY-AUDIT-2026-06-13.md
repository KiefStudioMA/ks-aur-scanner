# aur-scanner — Security & Quality Audit

Date: 2026-06-13 (remediation completed across 1.1.0-rc1 … rc3)
Scope: full repository — Rust core/cli/hook/plugin, shell integrations, PKGBUILDs/packaging, the pacman hook, and repo hygiene.
Method: focused manual review across four areas (detection engine, fetch/network/provenance, execution/decision paths, packaging/supply-chain) plus `cargo clippy --all-targets --all-features` and `cargo audit`.

## Threat model

The scanner sits between a user and an untrusted AUR package. Its inputs —
PKGBUILDs, `.install` scripts, AUR RPC responses, package names, dependency
names, cache contents, and community rule files — are **attacker-controlled**.
The two failure classes that matter most are **detection bypass** (malware slips
past a rule) and **fail-open** (the gate proceeds when it cannot fully analyze a
package). The design goal is that the gate fails *closed*, and that no
destructive or trust-bearing action is taken before analysis completes.

## Security properties upheld

These are load-bearing invariants the audit verified and that the project
commits to preserving:

- The static parser is **genuinely static** — no `bash`, `makepkg`, or any
  process execution in the parse/analyze path. Hostile input is never executed.
- Repository cloning is hardened (no file-protocol, no hooks, no symlinks, no
  submodule recursion, no terminal prompts).
- The CLI `install` path is **race-free**: a package is cloned once, scanned in
  place, and built from the same tree — no re-fetch between scan and build.
- Every external command is invoked via an argument vector — **no shell
  interpolation** anywhere.
- File reads are size-capped; network responses are size-capped, HTTPS-only,
  with redirects refused; package/base names are validated against a strict
  charset before they can become paths or request parameters.
- Tagged AUR packages use signed-tag verification; the pacman hook drops root
  privileges before reading user-controlled files and fails closed.
- Dependency tree is mainstream and pinned (`Cargo.lock` committed); `cargo
  audit` advisories are tracked and resolved.

## Remediation summary

The audit drove the 1.1.0 hardening line. All findings rated **Critical** and
the **High**-severity items were remediated and shipped across `1.1.0-rc1`
through `1.1.0-rc3`, each with regression tests. Remaining lower-severity
hardening items are tracked privately and addressed on a rolling basis.

Consistent with coordinated-disclosure practice, this document does not
enumerate specific detection weaknesses or evasion techniques. If you believe
you have found a missed payload, an evasion, or any false negative, please
report it privately through a GitHub Security Advisory (see
[SECURITY.md](../SECURITY.md)) rather than a public issue or pull request — false
negatives are treated as security-grade: we fix and release first, then
disclose, and we credit reporters.

## Tooling baseline

- `cargo clippy --all-targets --all-features`: clean.
- `cargo audit`: tracked; advisories resolved on the shipping line.
- CI runs format, clippy-as-error, the full test suite, a release build, and
  supply-chain (advisory/license) gating.
