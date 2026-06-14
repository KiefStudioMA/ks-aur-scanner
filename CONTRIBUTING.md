# Contributing to aur-scan

Thanks for helping. A lot of people now build AUR packages behind this tool, and
it shouldn't rest on one maintainer — contributions are genuinely wanted. This
file is the bar. It exists so the project can grow **without** getting less
safe, because a security tool that drifts is worse than none.

## The non-negotiables

These are not style preferences. A PR that breaks one of these will be asked to
change, no matter how useful the rest of it is.

1. **Static-only is a hard invariant.** The scanner reads PKGBUILDs and install
   scripts. It must **never** execute, `source`, `eval`, or fetch-and-run a
   package it inspects, and it must not add a code path that could. The only
   subprocesses allowed are the existing hardened `git clone` and read-only
   `pacman` queries. If your change runs *anything* from the analyzed package,
   it will be rejected.
2. **No detection without a catalog entry.** Every finding code the tool can emit
   must be in the authoritative catalog (`crates/aur-scanner-core/src/catalog/`)
   and pass the uniqueness/coverage tests. No orphan codes.
3. **No weakening existing checks.** Don't loosen, disable, or "simplify" a
   security check to make code shorter or a build faster. If a rule is wrong,
   fix it precisely (see the 1.0.2 `chmod 755` false-positive fix for the shape
   of a good correction: narrow the pattern, add regression tests both ways).
4. **Tests, clippy, fmt — all green.**
   - `cargo test --all` passes
   - `cargo clippy --all` produces **no warnings**
   - `cargo fmt --all` applied
   - New behaviour ships with new tests. Detection/false-positive fixes ship with
     a test that fails before your change and passes after.

## How to add a detection rule

You have two paths:

- **Community rule (no Rust):** add a TOML rule to `install/rules.d/` following
  `example.toml`. These load from `rules.d/` at runtime and are the easiest way
  to extend coverage. Give it a unique `id` and a clear `severity`.
- **Built-in rule:** add it to the relevant analyzer plus a catalog entry, with
  tests. Run `cargo test` — the catalog audit tests will tell you if the code is
  missing or duplicated.

Either way: prefer **precise** patterns. A rule that fires on `chmod 755` erodes
trust in every other finding. Test it against both the malicious case and a
benign look-alike.

## Workflow

1. Fork, branch from `main`.
2. Make the change. Keep it focused — one concern per PR.
3. `cargo fmt --all && cargo clippy --all && cargo test --all`.
4. Open a PR. Fill in the checklist (it's short and it's about the invariants above).
5. A maintainer reviews. Expect questions on anything touching the static-only
   boundary or the catalog.

### About signed commits on `main`

`main` is protected by a branch ruleset: **commits must be GPG-signed**, and
force-push/deletion are blocked. You don't have to sign the commits on your fork
— when your PR is accepted it's landed as a **signed commit that preserves you
as the author** (the maintainer signs the merge). If you *do* sign your own
commits ([GitHub guide](https://docs.github.com/authentication/managing-commit-signature-verification)),
even better. Either way your authorship is kept and you're credited in the
release notes and the README contributors list.

## Reporting security issues

Do **not** use public issues or PRs for vulnerabilities — see
[SECURITY.md](SECURITY.md). A false negative (something the scanner should flag
but doesn't, or a scan that silently fails yet says "clean") is security-grade.

## Code of conduct

Participation is covered by our [Code of Conduct](CODE_OF_CONDUCT.md). Be decent.
