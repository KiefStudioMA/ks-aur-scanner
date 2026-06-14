<!--
Thanks for contributing! Keep PRs focused — one concern each.
Read CONTRIBUTING.md if you haven't. The checklist below is about the
invariants that keep this a trustworthy security tool, not busywork.
-->

## What this changes

<!-- A sentence or two. Link any issue with "Fixes #123". -->

## Type

- [ ] Bug fix
- [ ] New / improved detection rule
- [ ] False-positive fix
- [ ] Integration (shell / AUR helper)
- [ ] Docs / tests
- [ ] Other:

## Checklist

- [ ] `cargo test --all` passes
- [ ] `cargo clippy --all` is **warning-free**
- [ ] `cargo fmt --all` applied
- [ ] New behaviour has tests (a fix has a test that fails before, passes after)

### Security invariants (required — see CONTRIBUTING.md)

- [ ] **Static-only preserved:** this change does not execute, `source`, `eval`,
      or fetch-and-run any package the scanner inspects, and adds no path that could.
- [ ] **No weakened checks:** no existing security check was loosened, disabled,
      or removed to simplify code or speed things up.
- [ ] If it adds/*changes a detection code*: the code is in the catalog and the
      uniqueness/coverage tests pass.
- [ ] If it's a new rule: tested against both the malicious case **and** a benign
      look-alike (no `chmod 755`-style false positives).

> Found a security vulnerability (incl. a false negative)? **Don't** open a public
> PR — see [SECURITY.md](../SECURITY.md).
