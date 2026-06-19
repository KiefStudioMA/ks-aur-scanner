# Documentation dataset (audited)

This directory is the **single source of truth** for the example output shown in
the [aur-scanner.kief.studio](https://aur-scanner.kief.studio) documentation.

- `capture.sh` runs the real `aur-scan` binary against the repo's own
  `tests/fixtures/` and the detection catalog, and records the actual
  **stdout (`.out`) / stderr (`.err`) / exit code (`.exit`)** of every
  invocation into `dataset/`.
- Nothing under `dataset/` is hand-edited. To refresh it:

  ```bash
  cargo build --release --all
  docs/examples/capture.sh
  ```

The harness discovers fixtures and detection codes from the tool itself (it never
references an input or code that doesn't exist), stages into a temp dir, validates
(JSON parses, malicious fixtures don't come back clean, `--fail-on high` gates),
and only then atomically replaces `dataset/`. A failed run leaves the previous
dataset untouched.

`dataset/meta.txt` records the binary version and git commit the snapshot was
generated from. The `timestamp` and `scan_duration_ms` fields in JSON scans are
runtime values and vary between runs.

## Layout

```
dataset/
  meta.txt                     version + commit provenance
  scan/<fixture>/{text,json,sarif}.{out,err,exit}
  scan/<fixture>/fail-on-high.exit      the CI gate, as an exit code
  codes/{text,json,markdown}.out        the detection catalog
  explain/<CODE>.out                    per-code detail
  help/<subcommand>.out                 CLI reference
  sbom/clean-example-package.cdx.json   CycloneDX SBOM (best-effort; needs net)
  version.out
```
