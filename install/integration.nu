# AUR Security Scanner - Nushell integration
#
# Source this from your Nushell config (config.nu):
#   source /usr/share/aur-scan/integration.nu
# or for a manual install:
#   source /path/to/integration.nu
#
# Unlike the bash/zsh/fish integrations (which re-implement the operation
# classifier in the shell), the Nushell integration delegates to the wrapper
# binary `aur-scan-wrap`, which classifies the helper invocation, scans the
# PKGBUILD(s), and only then hands off to the real helper. Read-only operations
# (-Q, -Ss, etc.) pass straight through. This keeps a single, audited gate.
#
# Verified on Nushell 0.113 (uses `def --wrapped`). Override before sourcing:
#   $env.AUR_SCAN_ENABLED = "0"   # disable scanning entirely
#   $env.AUR_SCAN_VERBOSE = "1"   # print a banner when this file loads

# Route one helper invocation through the scanner's wrapper gate. Honors
# AUR_SCAN_ENABLED=0 as a bypass, and degrades to running the helper directly
# (with a warning) if the wrapper binary isn't installed.
def _aur_scan_gate [helper: string, ...rest] {
    if (($env.AUR_SCAN_ENABLED? | default "1") == "0") {
        ^$helper ...$rest
    } else if (which aur-scan-wrap | is-empty) {
        print -e "aur-scan: aur-scan-wrap not found in PATH; running without scanning."
        ^$helper ...$rest
    } else {
        ^aur-scan-wrap $helper ...$rest
    }
}

# Wrap the helpers that share pacman's -S/-Syu grammar. `--wrapped` passes
# pacman-style flags through to the rest argument untouched.
def --wrapped paru   [...rest] { _aur_scan_gate paru ...$rest }
def --wrapped yay    [...rest] { _aur_scan_gate yay ...$rest }
def --wrapped pikaur [...rest] { _aur_scan_gate pikaur ...$rest }
def --wrapped trizen [...rest] { _aur_scan_gate trizen ...$rest }
def --wrapped pakku  [...rest] { _aur_scan_gate pakku ...$rest }

# Bypass commands: run a helper once without scanning.
def --wrapped paru-unsafe   [...rest] { ^paru ...$rest }
def --wrapped yay-unsafe    [...rest] { ^yay ...$rest }
def --wrapped pikaur-unsafe [...rest] { ^pikaur ...$rest }
def --wrapped trizen-unsafe [...rest] { ^trizen ...$rest }
def --wrapped pakku-unsafe  [...rest] { ^pakku ...$rest }

# Scan all installed AUR packages.
def aur-scan-system [...rest] { ^aur-scan system ...$rest }

if (($env.AUR_SCAN_VERBOSE? | default "0") == "1") {
    print "AUR Security Scanner: Nushell integration loaded."
    print "  - paru, yay, pikaur, trizen, pakku route installs through aur-scan-wrap"
    print "  - use '<helper>-unsafe' or set $env.AUR_SCAN_ENABLED = \"0\" to bypass"
}
