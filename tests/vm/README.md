# Clean-room acceptance testing

The unit and CLI test suites run in the developer's environment, which is
already set up correctly. That is exactly the environment least likely to catch
a packaging bug.

Three real defects in this repository were found only by installing the built
package on a machine that had never seen it:

* All three PKGBUILDs installed only `example.toml` from `rules.d/`, so any
  other rule file we shipped silently did not exist on user systems.
* Every shell integration file wrote its `AUR_SCAN_VERBOSE` banner to stdout.
  These are sourced from a shell rc, so that breaks `scp`, `rsync`, and
  `ssh host cmd`, all of which read the remote shell's stdout as protocol data.
* `ScanConfig` accepted unknown keys, so a mistyped `enable_threat_intel`
  silently did nothing.

None of these are visible from `cargo test`.

## Running it

`vm-acceptance.sh` runs inside a throwaway Arch VM against a copy of the
working tree at `~/src`. It builds, runs `makepkg -si`, and then exercises the
**installed** binaries: every documented command, every output format, the
shell integrations and completions in their real interpreters, the detection
fixtures, and a live AUR lookup.

Provision a VM from the official Arch cloud image with
`cloud-init-user-data.yaml`, which installs the toolchain plus every shell the
project ships a file for (bash, zsh, fish, nushell, dash) — a missing shell
makes its checks silently not run, which reports a pass the suite did not earn.

```bash
# On the host, from the repo root
rsync -a --exclude target/ --exclude .git/ ./ tester@VM:src/
scp tests/vm-acceptance.sh tester@VM:~/
ssh tester@VM './vm-acceptance.sh'
```

The script is idempotent: it removes any previously installed `aur-scanner`
first, so an interrupted transaction from an earlier run cannot masquerade as a
packaging bug on the next one.
