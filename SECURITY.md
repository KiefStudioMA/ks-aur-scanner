# Security Policy

`aur-scan` is a security tool, so we hold it to a higher bar than most projects —
both in what it does and in how it is built and shipped.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security problem.**

- Email **security@kief.studio**, or
- Use GitHub's **Security → Report a vulnerability** (private advisory) on this repo.

Include enough to reproduce: affected version (`aur-scan --version`), the PKGBUILD
or input involved, and the behaviour you observed vs. expected. If you have a fix,
a private patch is welcome.

We aim to acknowledge within **72 hours** and to ship a fix or mitigation as fast
as the severity warrants. We'll credit you in the release notes unless you ask us
not to.

### What counts as a security issue here

Because of what this tool is, these are treated as security-grade:

- A **false negative** — a malicious pattern the scanner should flag but doesn't,
  or any path where a scan silently fails yet reports "clean."
- Anything that makes the scanner **execute, source, or fetch-and-run** a package
  it is only supposed to read (a breach of the static-only invariant).
- Tampering with the **build/release supply chain** (signing, packaging, tags).

Ordinary false positives are bugs, not vulnerabilities — file those as normal
issues.

## Supported versions

We support the **latest released version**. The AUR is rolling; please update
before reporting (`paru -S aur-scanner-git` / re-build the tagged package).

## Threat model (what this tool does and does not do)

- **Static analysis only.** `aur-scan` parses PKGBUILDs and install scripts with
  pure pattern/AST analysis. It does **not** run `makepkg`, source the PKGBUILD,
  evaluate shell, or execute the package. The only subprocesses it spawns are a
  hardened `git clone` (no hooks/submodules, protocol-restricted) to fetch a
  PKGBUILD, and read-only `pacman` queries. **The scan cannot compromise the
  machine doing the scanning** — that property is non-negotiable.
- **Opaque boundary.** When a package fetches and runs code from an external
  source, the scanner flags it and stops — it does **not** follow the URL or
  resolve that chain. It tells you "this runs code from `<url>`," which is the
  thing you actually needed to know.
- **Not a guarantee.** Static analysis cannot catch every novel or obfuscated
  attack. Sandboxed dynamic analysis is intentionally out of scope — running the
  thing is exactly what we refuse to do. Treat findings as defense-in-depth and
  still review PKGBUILDs for critical systems.

## Supply-chain hardening

- Release tags are **GPG-signed**; verify with `git verify-tag v<version>`.
- The tagged AUR packages build from the signed tag and verify it
  (`validpgpkeys`) rather than trusting a GitHub tarball hash.
- `main` and `v*` tags are protected by a branch ruleset: **signed commits
  required, no force-push, no deletion.**
- Signing key fingerprint: `25631EAE3F43999050B7D7021132BF893C33FB51`
  (`gpg --recv-keys 25631EAE3F43999050B7D7021132BF893C33FB51`).
