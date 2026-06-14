#!/bin/zsh
# AUR Security Scanner - Zsh Integration
#
# Source this file in your ~/.zshrc:
#   source /usr/share/aur-scan/integration.zsh
#
# Or for manual installation:
#   source /path/to/integration.zsh

# Configuration (can be overridden before sourcing)
: "${AUR_SCAN_ENABLED:=1}"
: "${AUR_SCAN_SEVERITY:=high}"
: "${AUR_SCAN_INTERACTIVE:=1}"
# Print the load-time banner. Off by default so sourcing this file produces no
# console output during shell init (which Powerlevel10k instant prompt flags).
: "${AUR_SCAN_VERBOSE:=0}"

# Check if aur-scan is available
if ! command -v aur-scan &> /dev/null; then
    print -P "%F{yellow}Warning: aur-scan not found in PATH. AUR security scanning disabled.%f" >&2
    return 0
fi

# Classify a pacman/helper invocation by its OPERATION (not by substring
# sniffing, which could let an unrelated flag silently disable scanning). Sets
# _AUR_SCAN_INSTALL=1 when the invocation could build/install packages, and
# fills the _AUR_SCAN_PKGS array with the package operands. Bias: scan whenever
# an install is possible (fail toward scanning, never silently skip).
_aur_scan_classify() {
    _AUR_SCAN_INSTALL=0
    _AUR_SCAN_PKGS=()
    local op="" mods="" eoo=0 a rest i c
    for a in "$@"; do
        if [[ "$eoo" == "1" ]]; then _AUR_SCAN_PKGS+=("$a"); continue; fi
        case "$a" in
            --) eoo=1 ;;
            --sync) op="${op}S" ;;
            --upgrade) op="${op}U" ;;
            --query) op="${op}Q" ;;
            --remove) op="${op}R" ;;
            --search) mods="${mods}s" ;;
            --info) mods="${mods}i" ;;
            --files) op="${op}F" ;;
            --database) op="${op}D" ;;
            --deptest) op="${op}T" ;;
            --*) ;;  # other long option: ignored
            -*)
                rest="${a#-}"
                for (( i=0; i<${#rest}; i++ )); do
                    c="${rest:$i:1}"
                    case "$c" in
                        [A-Z]) op="${op}${c}" ;;
                        *)     mods="${mods}${c}" ;;
                    esac
                done
                ;;
            *) _AUR_SCAN_PKGS+=("$a") ;;
        esac
    done

    local is_sync=0 is_up=0 non_install=0 readonly_sync=0
    [[ "$op" == *S* ]] && is_sync=1
    [[ "$op" == *U* ]] && is_up=1
    [[ "$op" == *[QRFDTV]* ]] && non_install=1
    # Read-only sync sub-operations: search/info/list/groups/clean/print.
    [[ "$mods" == *[silgcp]* ]] && readonly_sync=1

    if [[ "$non_install" == "1" && "$is_sync" == "0" && "$is_up" == "0" ]]; then return; fi
    if [[ "$is_sync" == "1" && "$readonly_sync" == "1" ]]; then return; fi
    if [[ ( "$is_sync" == "1" || "$is_up" == "1" ) && ${#_AUR_SCAN_PKGS[@]} -gt 0 ]]; then
        _AUR_SCAN_INSTALL=1; return
    fi
    # No recognized operation but bare operands present (helpers treat as install).
    if [[ -z "$op" && ${#_AUR_SCAN_PKGS[@]} -gt 0 ]]; then
        _AUR_SCAN_INSTALL=1
    fi
}

# Shared gate: scan the operands, then hand off to the real helper. $1 is the
# helper name; the rest are its original arguments.
_aur_scan_gate() {
    local helper="$1"; shift
    if [[ "$AUR_SCAN_ENABLED" != "1" ]]; then
        command "$helper" "$@"
        return
    fi

    local -a _AUR_SCAN_PKGS
    _aur_scan_classify "$@"
    if [[ "$_AUR_SCAN_INSTALL" == "1" ]]; then
        # Race-free mode: scan the exact bytes, then build them in dep order.
        if [[ "${AUR_SCAN_MODE:-gate}" == "install" ]]; then
            aur-scan install "${_AUR_SCAN_PKGS[@]}"
            return $?
        fi

        print -P "%F{cyan}AUR Security Scanner:%f Pre-checking packages..."
        local -a scan_args
        scan_args=("--severity" "$AUR_SCAN_SEVERITY")
        [[ "$AUR_SCAN_INTERACTIVE" != "1" ]] && scan_args+=("--no-confirm")
        if ! aur-scan check "${scan_args[@]}" "${_AUR_SCAN_PKGS[@]}"; then
            print -P "%F{yellow}Scan failed or user aborted. Not proceeding with $helper.%f"
            return 1
        fi
    fi

    command "$helper" "$@"
}

paru() { _aur_scan_gate paru "$@"; }
yay()  { _aur_scan_gate yay "$@"; }

# Convenience alias to temporarily disable scanning
alias paru-unsafe='AUR_SCAN_ENABLED=0 paru'
alias yay-unsafe='AUR_SCAN_ENABLED=0 yay'

# Function to scan all installed AUR packages
aur-scan-system() {
    aur-scan system "$@"
}

if [[ "$AUR_SCAN_VERBOSE" == "1" ]]; then
    print -P "%F{green}AUR Security Scanner:%f Shell integration loaded."
    print -P "  - paru and yay auto-scan before installing AUR packages"
    print -P "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)"
    print -P "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper"
    print -P "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning"
    print -P "  - Set AUR_SCAN_ENABLED=0 to disable globally"
fi
