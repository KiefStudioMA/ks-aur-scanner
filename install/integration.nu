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

# Settings are plain environment variables, read by the wrapper itself, so they
# behave exactly as in the other shells:
#   $env.AUR_SCAN_SEVERITY = "high"        # gate threshold (critical|high|medium|low|info)
#   $env.AUR_SCAN_INTERACTIVE = "0"        # never prompt; deny findings
#   $env.AUR_SCAN_MODE = "install"         # race-free `aur-scan install` for named installs
#   $env.AUR_SCAN_SCAN_UPGRADES = "0"      # skip scanning the AUR update set on -Syu
#   $env.AUR_SCAN_SCAN_GETPKGBUILD = "1"   # also scan `-G` downloads
# Set them with `$env.NAME = "value"` (strings) so they reach the wrapper.

# Route one helper invocation through the scanner's wrapper gate. Honors
# AUR_SCAN_ENABLED=0 as a bypass. If the wrapper binary isn't installed it
# REFUSES (running the helper unscanned would be a silent fail-open); use
# `<helper>-unsafe` to bypass on purpose.
def _aur_scan_gate [helper: string, ...rest] {
    if (($env.AUR_SCAN_ENABLED? | default "1") == "0") {
        ^$helper ...$rest
    } else if (which aur-scan-wrap | is-empty) {
        error make --unspanned { msg: $"aur-scan: aur-scan-wrap not found in PATH; refusing to run ($helper) unscanned. Install it, or use ($helper)-unsafe to bypass." }
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
    # `print -e` writes to stderr. Never stdout: this file is sourced from
    # config.nu, and stdout during shell init breaks scp/rsync/`ssh host cmd`.
    print -e "AUR Security Scanner: Nushell integration loaded."
    print -e "  - paru, yay, pikaur, trizen, pakku route installs through aur-scan-wrap"
    print -e "  - use '<helper>-unsafe' or set $env.AUR_SCAN_ENABLED = \"0\" to bypass"
}
