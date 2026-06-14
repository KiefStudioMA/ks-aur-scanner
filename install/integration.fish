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
    set -g _AUR_SCAN_INSTALL 0
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
    set -l is_up 0
    set -l non_install 0
    set -l readonly_sync 0
    string match -q '*S*' -- $op; and set is_sync 1
    string match -q '*U*' -- $op; and set is_up 1
    string match -qr '[QRFDTV]' -- $op; and set non_install 1
    # Read-only sync sub-operations: search/info/list/groups/clean/print.
    string match -qr '[silgcp]' -- $mods; and set readonly_sync 1

    if test "$non_install" = "1" -a "$is_sync" = "0" -a "$is_up" = "0"
        return
    end
    if test "$is_sync" = "1" -a "$readonly_sync" = "1"
        return
    end
    if test \( "$is_sync" = "1" -o "$is_up" = "1" \) -a (count $_AUR_SCAN_PKGS) -gt 0
        set -g _AUR_SCAN_INSTALL 1
        return
    end
    # No recognized operation but bare operands present (helpers treat as install).
    if test -z "$op" -a (count $_AUR_SCAN_PKGS) -gt 0
        set -g _AUR_SCAN_INSTALL 1
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
    if test "$_AUR_SCAN_INSTALL" = "1"
        # Race-free mode: scan the exact bytes, then build them in dep order.
        if test "$AUR_SCAN_MODE" = "install"
            aur-scan install $_AUR_SCAN_PKGS
            return $status
        end

        echo "AUR Security Scanner: Pre-checking packages..."
        set -l scan_args --severity $AUR_SCAN_SEVERITY
        if test "$AUR_SCAN_INTERACTIVE" != "1"
            set -a scan_args --no-confirm
        end
        if not aur-scan check $scan_args $_AUR_SCAN_PKGS
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

# Convenience abbreviations to temporarily disable scanning
abbr --add paru-unsafe 'AUR_SCAN_ENABLED=0 paru'
abbr --add yay-unsafe 'AUR_SCAN_ENABLED=0 yay'

# Function to scan all installed AUR packages
function aur-scan-system
    aur-scan system $argv
end

if test "$AUR_SCAN_VERBOSE" = "1"
    echo "AUR Security Scanner: Shell integration loaded."
    echo "  - paru and yay auto-scan before installing AUR packages"
    echo "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)"
    echo "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper"
    echo "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning"
    echo "  - Set AUR_SCAN_ENABLED=0 to disable globally"
end
