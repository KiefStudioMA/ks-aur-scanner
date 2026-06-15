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
# sniffing, which could let an unrelated flag silently disable scanning). From
# the operation it sets: _AUR_SCAN_IS_INSTALL (named operands are scanned),
# _AUR_SCAN_IS_UPGRADE (a system upgrade -- the gate scans the AUR update set),
# and _AUR_SCAN_IS_GETPKGBUILD (a `-G` fetch -- scanned only on opt-in); it fills
# _AUR_SCAN_PKGS with the operands. Bias: scan whenever an install is possible.
_aur_scan_classify() {
    _AUR_SCAN_IS_INSTALL=0
    _AUR_SCAN_IS_UPGRADE=0
    _AUR_SCAN_IS_GETPKGBUILD=0
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
            --getpkgbuild) op="${op}G" ;;
            --show) op="${op}P" ;;
            --search) mods="${mods}s" ;;
            --info) mods="${mods}i" ;;
            --files) op="${op}F" ;;
            --database) op="${op}D" ;;
            --deptest) op="${op}T" ;;
            --sysupgrade) mods="${mods}u" ;;
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

    local is_sync=0 is_upfile=0 is_getpkgbuild=0 sysupgrade=0 non_install=0 readonly_sync=0
    [[ "$op" == *S* ]] && is_sync=1
    [[ "$op" == *U* ]] && is_upfile=1       # -U: install a local package file
    [[ "$op" == *G* ]] && is_getpkgbuild=1  # -G/--getpkgbuild: download a PKGBUILD only
    [[ "$mods" == *u* ]] && sysupgrade=1    # the 'u' of -Syu/-Su: system upgrade
    # Never-install operations: pacman's query/remove/files/database/deptest/
    # version, plus -P (--show, print stats). -G is handled on its own below.
    [[ "$op" == *[QRFDTVP]* ]] && non_install=1
    # Read-only sync sub-operations: search/info/list/groups/clean/print.
    [[ "$mods" == *[silgcp]* ]] && readonly_sync=1

    # -G/--getpkgbuild only downloads a PKGBUILD to inspect -- not an install.
    # Recorded separately so the gate scans it ONLY on opt-in (AUR_SCAN_SCAN_GETPKGBUILD=1).
    if [[ "$is_getpkgbuild" == "1" ]]; then
        [[ ${#_AUR_SCAN_PKGS[@]} -gt 0 ]] && _AUR_SCAN_IS_GETPKGBUILD=1
        return
    fi
    # Passthrough: a non-install op that is not also a sync/upgrade, or a
    # read-only sync sub-op.
    if [[ "$non_install" == "1" && "$is_sync" == "0" && "$is_upfile" == "0" ]]; then return; fi
    if [[ "$is_sync" == "1" && "$readonly_sync" == "1" ]]; then return; fi

    # System upgrade: -Syu/-Su, or the helper's default (no operation and no
    # operands -- e.g. bare `yay` == `yay -Syu`). The upgraded packages are not
    # named, so the gate enumerates the AUR update set itself.
    if [[ ( "$is_sync" == "1" && "$sysupgrade" == "1" ) || ( -z "$op" && ${#_AUR_SCAN_PKGS[@]} -eq 0 ) ]]; then
        _AUR_SCAN_IS_UPGRADE=1
    fi
    # Named install: operands that are not a read-only op. Covers `-S pkg`, bare
    # `helper pkg`, and yay's `-Y pkg` (its default search-and-install, #12). NB:
    # in yay's interactive `-Y` menu the operand is a search term and the package
    # finally chosen may differ -- the opt-in pacman hook is the backstop.
    if [[ ${#_AUR_SCAN_PKGS[@]} -gt 0 && "$readonly_sync" == "0" ]]; then
        _AUR_SCAN_IS_INSTALL=1
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

    # Race-free mode applies to a NAMED install that is NOT also a system upgrade
    # (a `-Syu pkg` must still let the helper do the upgrade).
    if [[ "$_AUR_SCAN_IS_INSTALL" == "1" && "$_AUR_SCAN_IS_UPGRADE" == "0" && "${AUR_SCAN_MODE:-gate}" == "install" ]]; then
        aur-scan install "${_AUR_SCAN_PKGS[@]}"
        return $?
    fi

    # Assemble the packages to pre-scan from the classified action(s) and the
    # user's coverage settings (secure-by-default). `-aU` keeps the list unique.
    local -aU _to_scan
    [[ "$_AUR_SCAN_IS_INSTALL" == "1" ]] && _to_scan+=("${_AUR_SCAN_PKGS[@]}")
    # -G/--getpkgbuild: opt-in (default off) -- it only fetches a PKGBUILD to review.
    if [[ "$_AUR_SCAN_IS_GETPKGBUILD" == "1" && "${AUR_SCAN_SCAN_GETPKGBUILD:-0}" == "1" ]]; then
        _to_scan+=("${_AUR_SCAN_PKGS[@]}")
    fi
    # System upgrade: scan each AUR package with a pending update (default on).
    if [[ "$_AUR_SCAN_IS_UPGRADE" == "1" && "${AUR_SCAN_SCAN_UPGRADES:-1}" == "1" ]]; then
        local -a _upd
        _upd=(${(f)"$(command "$helper" -Quaq 2>/dev/null)"})
        (( ${#_upd[@]} )) && _to_scan+=("${_upd[@]}")
    fi

    if (( ${#_to_scan[@]} )); then
        print -P "%F{cyan}AUR Security Scanner:%f pre-checking ${#_to_scan[@]} package(s)..."
        local -a scan_args
        scan_args=("--severity" "$AUR_SCAN_SEVERITY")
        [[ "$AUR_SCAN_INTERACTIVE" != "1" ]] && scan_args+=("--no-confirm")
        if ! aur-scan check "${scan_args[@]}" "${_to_scan[@]}"; then
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
