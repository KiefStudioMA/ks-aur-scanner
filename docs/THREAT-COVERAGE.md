# aur-scan Threat Coverage

aur-scan organizes its detections around six adversary vectors — **obfuscation /
encoding**, **RCE / payload delivery** (incl. makepkg/VCS/.SRCINFO),
**persistence**, **privilege escalation / system tampering**, **exfiltration /
C2 / credential theft**, and **supply-chain / metadata** — implemented as regex
pattern rules (run through a de-obfuscation pass so the catalog sees through
common encoding) plus structural analyzers for the checks that need parsed
metadata or `$pkgdir`-awareness.

The authoritative, machine-readable list of detection codes is **`aur-scan
codes`** (also published on the
[Detection Codes](https://aur-scanner.kief.studio/detection-codes/) page), and
the pipeline is documented in
[How it works](https://aur-scanner.kief.studio/how-it-works/).

## Reporting a gap or a false negative

Detailed coverage status, the per-vector gap analysis, and any **unfixed**
detection weaknesses are tracked **privately** and are deliberately **not**
published here — a public list of what the scanner does not yet catch is itself
an evasion roadmap.

If you've found a missed payload, an evasion, or any false negative, please
**report it privately** through a GitHub Security Advisory (see
[SECURITY.md](../SECURITY.md)) — **not** a public issue or pull request. False
negatives are treated as security-grade: we fix and release first, then disclose.
Contributors are credited.
