#!/bin/bash
# AUR Security Scanner - Bash Integration
#
# Source this file in your ~/.bashrc:
#   source /usr/share/aur-scan/integration.bash
#
# Or for manual installation:
#   source /path/to/integration.bash

# Configuration (can be overridden before sourcing)
: "${AUR_SCAN_ENABLED:=1}"
: "${AUR_SCAN_SEVERITY:=high}"
: "${AUR_SCAN_INTERACTIVE:=1}"

# Check if aur-scan is available
if ! command -v aur-scan &> /dev/null; then
    echo "Warning: aur-scan not found in PATH. AUR security scanning disabled." >&2
    return 0 2>/dev/null || exit 0
fi

# Wrapper function for paru
paru() {
    if [[ "$AUR_SCAN_ENABLED" != "1" ]]; then
        command paru "$@"
        return
    fi

    # Check if this is an install operation
    local is_sync=0
    local packages=()

    for arg in "$@"; do
        case "$arg" in
            -S*|--sync) is_sync=1 ;;
            -Q*|--query) is_sync=0; break ;;
            -s*|--search) is_sync=0; break ;;
            -*) ;;
            *) packages+=("$arg") ;;
        esac
    done

    if [[ "$is_sync" == "1" ]] && [[ ${#packages[@]} -gt 0 ]]; then
        echo "AUR Security Scanner: Pre-checking packages..."

        local scan_args=("--severity" "$AUR_SCAN_SEVERITY")
        [[ "$AUR_SCAN_INTERACTIVE" != "1" ]] && scan_args+=("--no-confirm")

        if ! aur-scan check "${scan_args[@]}" "${packages[@]}"; then
            echo "Scan failed or user aborted. Not proceeding with paru."
            return 1
        fi
    fi

    command paru "$@"
}

# Wrapper function for yay
yay() {
    if [[ "$AUR_SCAN_ENABLED" != "1" ]]; then
        command yay "$@"
        return
    fi

    # Check if this is an install operation
    local is_sync=0
    local packages=()

    for arg in "$@"; do
        case "$arg" in
            -S*|--sync) is_sync=1 ;;
            -Q*|--query) is_sync=0; break ;;
            -s*|--search) is_sync=0; break ;;
            -*) ;;
            *) packages+=("$arg") ;;
        esac
    done

    if [[ "$is_sync" == "1" ]] && [[ ${#packages[@]} -gt 0 ]]; then
        echo "AUR Security Scanner: Pre-checking packages..."

        local scan_args=("--severity" "$AUR_SCAN_SEVERITY")
        [[ "$AUR_SCAN_INTERACTIVE" != "1" ]] && scan_args+=("--no-confirm")

        if ! aur-scan check "${scan_args[@]}" "${packages[@]}"; then
            echo "Scan failed or user aborted. Not proceeding with yay."
            return 1
        fi
    fi

    command yay "$@"
}

# Convenience alias to temporarily disable scanning
alias paru-unsafe='AUR_SCAN_ENABLED=0 paru'
alias yay-unsafe='AUR_SCAN_ENABLED=0 yay'

# Function to scan all installed AUR packages
aur-scan-system() {
    aur-scan system "$@"
}

echo "AUR Security Scanner: Shell integration loaded."
echo "  - paru and yay will auto-scan before installing AUR packages"
echo "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning"
echo "  - Set AUR_SCAN_ENABLED=0 to disable globally"
