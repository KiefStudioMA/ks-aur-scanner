#!/usr/bin/env fish
# AUR Security Scanner - Fish Shell Integration
#
# Source this file in your ~/.config/fish/config.fish:
#   source /usr/share/aur-scan/integration.fish
#
# Or for manual installation:
#   source /path/to/integration.fish

# Configuration (can be overridden before sourcing)
if not set -q AUR_SCAN_ENABLED
    set -g AUR_SCAN_ENABLED 1
end
if not set -q AUR_SCAN_SEVERITY
    set -g AUR_SCAN_SEVERITY high
end
if not set -q AUR_SCAN_INTERACTIVE
    set -g AUR_SCAN_INTERACTIVE 1
end
# Print the load-time banner. Off by default so sourcing this file produces no
# console output during shell init.
if not set -q AUR_SCAN_VERBOSE
    set -g AUR_SCAN_VERBOSE 0
end

# Check if aur-scan is available
if not command -q aur-scan
    echo "Warning: aur-scan not found in PATH. AUR security scanning disabled." >&2
    return 0
end

# Classify a pacman/helper invocation by its OPERATION (not by substring
# sniffing, which could let an unrelated flag silently disable scanning). Sets
# the global _AUR_SCAN_INSTALL=1 when the invocation could build/install
# packages, and fills _AUR_SCAN_PKGS with the package operands. Bias: scan
# whenever an install is possible (fail toward scanning, never silently skip).
function _aur_scan_classify
    set -g _AUR_SCAN_IS_INSTALL 0
    set -g _AUR_SCAN_IS_UPGRADE 0
    set -g _AUR_SCAN_IS_GETPKGBUILD 0
    set -g _AUR_SCAN_PKGS
    set -l op ""
    set -l mods ""
    set -l eoo 0
    for a in $argv
        if test "$eoo" = "1"
            set -a _AUR_SCAN_PKGS $a
            continue
        end
        switch $a
            case '--'
                set eoo 1
            case '--sync'
                set op "$op"S
            case '--upgrade'
                set op "$op"U
            case '--query'
                set op "$op"Q
            case '--remove'
                set op "$op"R
            case '--getpkgbuild'
                set op "$op"G
            case '--show'
                set op "$op"P
            case '--sysupgrade'
                set mods "$mods"u
            case '--search'
                set mods "$mods"s
            case '--info'
                set mods "$mods"i
            case '--files'
                set op "$op"F
            case '--database'
                set op "$op"D
            case '--deptest'
                set op "$op"T
            case '--*'
                # other long option: ignored
            case '-*'
                set -l rest (string sub -s 2 -- $a)
                for c in (string split '' -- $rest)
                    if string match -qr '[A-Z]' -- $c
                        set op "$op$c"
                    else
                        set mods "$mods$c"
                    end
                end
            case '*'
                set -a _AUR_SCAN_PKGS $a
        end
    end

    set -l is_sync 0
    set -l is_upfile 0
    set -l is_getpkgbuild 0
    set -l sysupgrade 0
    set -l non_install 0
    set -l readonly_sync 0
    string match -q '*S*' -- $op; and set is_sync 1
    string match -q '*U*' -- $op; and set is_upfile 1
    string match -q '*G*' -- $op; and set is_getpkgbuild 1
    string match -q '*u*' -- $mods; and set sysupgrade 1
    # Never-install ops: pacman's QRFDTV plus -P (--show). -G handled below.
    string match -qr '[QRFDTVP]' -- $op; and set non_install 1
    # Read-only sync sub-operations: search/info/list/groups/clean/print.
    string match -qr '[silgcp]' -- $mods; and set readonly_sync 1

    # -G/--getpkgbuild only downloads a PKGBUILD to inspect -- scanned on opt-in.
    if test "$is_getpkgbuild" = "1"
        if test (count $_AUR_SCAN_PKGS) -gt 0
            set -g _AUR_SCAN_IS_GETPKGBUILD 1
        end
        return
    end
    # Passthrough: a non-install op that is not also a sync/upgrade, or a
    # read-only sync sub-op (search/info/list/...).
    if test "$non_install" = "1" -a "$is_sync" = "0" -a "$is_upfile" = "0"
        return
    end
    if test "$is_sync" = "1" -a "$readonly_sync" = "1"
        return
    end
    # System upgrade: -Syu/-Su, or the helper default (no op + no operands, e.g.
    # bare `yay`). Packages aren't named, so the gate scans the AUR update set.
    if test "$is_sync" = "1" -a "$sysupgrade" = "1"
        set -g _AUR_SCAN_IS_UPGRADE 1
    else if test -z "$op" -a (count $_AUR_SCAN_PKGS) -eq 0
        set -g _AUR_SCAN_IS_UPGRADE 1
    end
    # Named install: operands that are not a read-only op (covers -S pkg, bare
    # `helper pkg`, yay -Y pkg). The pacman hook backstops the -Y menu selection.
    if test (count $_AUR_SCAN_PKGS) -gt 0 -a "$readonly_sync" = "0"
        set -g _AUR_SCAN_IS_INSTALL 1
    end
end

# Shared gate: scan the operands, then hand off to the real helper. $argv[1] is
# the helper name; the rest are its original arguments.
function _aur_scan_gate
    set -l helper $argv[1]
    set -e argv[1]
    if test "$AUR_SCAN_ENABLED" != "1"
        command $helper $argv
        return
    end

    _aur_scan_classify $argv

    # Race-free mode applies to a NAMED install that is NOT also a system upgrade
    # (a `-Syu pkg` must still let the helper do the upgrade).
    if test "$_AUR_SCAN_IS_INSTALL" = "1" -a "$_AUR_SCAN_IS_UPGRADE" = "0" -a "$AUR_SCAN_MODE" = "install"
        aur-scan install $_AUR_SCAN_PKGS
        return $status
    end

    # Assemble the packages to pre-scan from the classified action(s) and the
    # user's coverage settings (secure-by-default).
    set -l to_scan
    if test "$_AUR_SCAN_IS_INSTALL" = "1"
        set -a to_scan $_AUR_SCAN_PKGS
    end
    # -G/--getpkgbuild: opt-in (default off) -- only fetches a PKGBUILD to review.
    if test "$_AUR_SCAN_IS_GETPKGBUILD" = "1" -a "$AUR_SCAN_SCAN_GETPKGBUILD" = "1"
        set -a to_scan $_AUR_SCAN_PKGS
    end
    # System upgrade: scan each AUR package with a pending update (default on;
    # set AUR_SCAN_SCAN_UPGRADES=0 to disable).
    if test "$_AUR_SCAN_IS_UPGRADE" = "1" -a "$AUR_SCAN_SCAN_UPGRADES" != "0"
        set -l upd (command $helper -Quaq 2>/dev/null)
        if test (count $upd) -gt 0
            set -a to_scan $upd
        end
    end

    if test (count $to_scan) -gt 0
        # De-duplicate, preserving order.
        set to_scan (printf '%s\n' $to_scan | awk 'NF && !seen[$0]++')
        echo "AUR Security Scanner: pre-checking "(count $to_scan)" package(s)..."
        set -l scan_args --severity $AUR_SCAN_SEVERITY
        if test "$AUR_SCAN_INTERACTIVE" != "1"
            set -a scan_args --no-confirm
        end
        if not aur-scan check $scan_args $to_scan
            echo "Scan failed or user aborted. Not proceeding with $helper."
            return 1
        end
    end

    command $helper $argv
end

function paru --wraps='paru'
    _aur_scan_gate paru $argv
end

function yay --wraps='yay'
    _aur_scan_gate yay $argv
end

function pikaur --wraps='pikaur'
    _aur_scan_gate pikaur $argv
end

function trizen --wraps='trizen'
    _aur_scan_gate trizen $argv
end

function pakku --wraps='pakku'
    _aur_scan_gate pakku $argv
end

# These helpers share pacman's -S/-Syu grammar, so the classifier is correct for
# them. aura (installs via -A) and the subcommand-grammar tools (aurutils, rua,
# pat-aur) are intentionally not wrapped — use the pacman hook to cover them.

# Convenience abbreviations to temporarily disable scanning
abbr --add paru-unsafe 'AUR_SCAN_ENABLED=0 paru'
abbr --add yay-unsafe 'AUR_SCAN_ENABLED=0 yay'
abbr --add pikaur-unsafe 'AUR_SCAN_ENABLED=0 pikaur'
abbr --add trizen-unsafe 'AUR_SCAN_ENABLED=0 trizen'
abbr --add pakku-unsafe 'AUR_SCAN_ENABLED=0 pakku'

# Function to scan all installed AUR packages
function aur-scan-system
    aur-scan system $argv
end

if test "$AUR_SCAN_VERBOSE" = "1"
    echo "AUR Security Scanner: Shell integration loaded."
    echo "  - paru, yay, pikaur, trizen, pakku auto-scan before installing AUR packages"
    echo "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)"
    echo "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper"
    echo "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning"
    echo "  - Set AUR_SCAN_ENABLED=0 to disable globally"
end
