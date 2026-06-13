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

# Check if aur-scan is available
if not command -q aur-scan
    echo "Warning: aur-scan not found in PATH. AUR security scanning disabled." >&2
    return 0
end

# Wrapper function for paru
function paru --wraps='paru'
    if test "$AUR_SCAN_ENABLED" != "1"
        command paru $argv
        return
    end

    # Check if this is an install operation
    set -l is_sync 0
    set -l packages

    for arg in $argv
        switch $arg
            case '-S*' '--sync'
                set is_sync 1
            case '-Q*' '--query'
                set is_sync 0
                break
            case '-s*' '--search'
                set is_sync 0
                break
            case '-*'
                # skip flags
            case '*'
                set -a packages $arg
        end
    end

    if test "$is_sync" = "1" -a (count $packages) -gt 0
        # Race-free mode: scan the exact bytes, then build them in dep order
        # (replaces the helper for the named AUR packages). Opt in with
        # AUR_SCAN_MODE=install.
        if test "$AUR_SCAN_MODE" = "install"
            aur-scan install $packages
            return $status
        end

        echo "AUR Security Scanner: Pre-checking packages..."

        set -l scan_args --severity $AUR_SCAN_SEVERITY
        if test "$AUR_SCAN_INTERACTIVE" != "1"
            set -a scan_args --no-confirm
        end

        if not aur-scan check $scan_args $packages
            echo "Scan failed or user aborted. Not proceeding with paru."
            return 1
        end
    end

    command paru $argv
end

# Wrapper function for yay
function yay --wraps='yay'
    if test "$AUR_SCAN_ENABLED" != "1"
        command yay $argv
        return
    end

    # Check if this is an install operation
    set -l is_sync 0
    set -l packages

    for arg in $argv
        switch $arg
            case '-S*' '--sync'
                set is_sync 1
            case '-Q*' '--query'
                set is_sync 0
                break
            case '-s*' '--search'
                set is_sync 0
                break
            case '-*'
                # skip flags
            case '*'
                set -a packages $arg
        end
    end

    if test "$is_sync" = "1" -a (count $packages) -gt 0
        # Race-free mode: scan the exact bytes, then build them in dep order
        # (replaces the helper for the named AUR packages). Opt in with
        # AUR_SCAN_MODE=install.
        if test "$AUR_SCAN_MODE" = "install"
            aur-scan install $packages
            return $status
        end

        echo "AUR Security Scanner: Pre-checking packages..."

        set -l scan_args --severity $AUR_SCAN_SEVERITY
        if test "$AUR_SCAN_INTERACTIVE" != "1"
            set -a scan_args --no-confirm
        end

        if not aur-scan check $scan_args $packages
            echo "Scan failed or user aborted. Not proceeding with yay."
            return 1
        end
    end

    command yay $argv
end

# Convenience abbreviations to temporarily disable scanning
abbr --add paru-unsafe 'AUR_SCAN_ENABLED=0 paru'
abbr --add yay-unsafe 'AUR_SCAN_ENABLED=0 yay'

# Function to scan all installed AUR packages
function aur-scan-system
    aur-scan system $argv
end

echo "AUR Security Scanner: Shell integration loaded."
echo "  - paru and yay auto-scan before installing AUR packages"
echo "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)"
echo "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper"
echo "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning"
echo "  - Set AUR_SCAN_ENABLED=0 to disable globally"
