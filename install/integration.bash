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
# Print the load-time banner. Off by default so sourcing this file produces no
# console output during shell init.
: "${AUR_SCAN_VERBOSE:=0}"

# aur-scan missing: do NOT silently run unscanned. The gate refuses at call
# time (see _aur_scan_gate); use `paru-unsafe` / `yay-unsafe` to bypass on purpose.
if ! command -v aur-scan &> /dev/null; then
    echo "Warning: aur-scan not found in PATH. Installs through paru/yay/... will be REFUSED until it is installed (use <helper>-unsafe to bypass)." >&2
fi

# A legal Arch/AUR package identifier (mirrors aur-scanner-core's validator).
_aur_scan_valid_name() {
    local re='^[A-Za-z0-9@_+][A-Za-z0-9@._+-]*$'
    [[ ${#1} -le 256 && "$1" =~ $re ]]
}

# Classify a pacman/helper invocation by its OPERATION (not by substring
# sniffing, which could let an unrelated flag silently disable scanning). It
# fills, fail-closed:
#   _AUR_SCAN_NAMES        AUR names that would be built (`aur/x` -> x; `core/x` dropped)
#   _AUR_SCAN_IS_UPGRADE   a system upgrade (the gate scans the AUR update set)
#   _AUR_SCAN_IS_GETPKGBUILD / _AUR_SCAN_PKGS   a `-G` fetch (scanned only on opt-in)
#   _AUR_SCAN_LOCAL        local build dirs (`-B dir`, `-Ui`, `-U dir`) to scan
#   _AUR_SCAN_NOTICES      prebuilt-package installs that cannot be pre-scanned
#   _AUR_SCAN_BLOCK        reasons the invocation must be refused (cannot be validated)
#   _AUR_SCAN_MENU         the helper will show a search menu and install the pick
#                          (`paru <term>`, `yay <term>`, `yay -Y <term>`, `-S --interactive`);
#                          the pick is made AFTER the gate, so it is refused unless
#                          AUR_SCAN_ALLOW_MENU=1. Neither paru nor yay auto-selects an
#                          exact name: the menu is always shown.
# Bias: scan whenever an install is possible; refuse what cannot be scanned.
_aur_scan_classify() {
    _AUR_SCAN_IS_UPGRADE=0
    _AUR_SCAN_IS_GETPKGBUILD=0
    _AUR_SCAN_PKGS=()
    _AUR_SCAN_NAMES=()
    _AUR_SCAN_LOCAL=()
    _AUR_SCAN_NOTICES=()
    _AUR_SCAN_BLOCK=()
    _AUR_SCAN_MENU=0
    local op="" mods="" longs=" " eoo=0 skip=0 a rest i c
    for a in "$@"; do
        if [[ "$skip" == "1" ]]; then skip=0; continue; fi
        if [[ "$eoo" == "1" ]]; then _AUR_SCAN_PKGS+=("$a"); continue; fi
        case "$a" in
            --) eoo=1 ;;
            --sync) op="${op}S" ;;
            --upgrade) op="${op}U" ;;
            --query) op="${op}Q" ;;
            --remove) op="${op}R" ;;
            --getpkgbuild) op="${op}G" ;;
            --show) op="${op}P" ;;
            --build) op="${op}B" ;;
            --version) op="${op}V" ;;
            --yay) op="${op}Y" ;;
            --files) op="${op}F" ;;
            --database) op="${op}D" ;;
            --deptest) op="${op}T" ;;
            --sysupgrade) mods="${mods}u" ;;
            --search) mods="${mods}s" ;;
            --info|--install) mods="${mods}i" ;;
            --list) mods="${mods}l" ;;
            --groups) mods="${mods}g" ;;
            --clean) mods="${mods}c" ;;
            --print) mods="${mods}p" ;;
            # Long options that take the NEXT argument as their value (only ones
            # that ALWAYS do: a boolean flag listed here would swallow an operand).
            --root|--dbpath|--cachedir|--logfile|--gpgdir|--hookdir|--arch|--color|--config|--sysroot|--ignore|--ignoregroup|--assume-installed|--overwrite|--print-format|--ask|--aururl|--aurrpcurl|--clonedir|--builddir|--makepkg|--makepkgconf|--pacman|--pacman-conf|--pacmanconf|--git|--gitflags|--sudo|--sudoflags|--asp|--bat|--batflags|--fm|--fmflags|--editor|--editorflags|--mflags|--gpg|--gpgflags|--answerclean|--answerdiff|--answeredit|--answerupgrade|--searchby|--sortby|--completioninterval|--requestsplitn|--mode|--limit|--develsuffixes|--develfile|--ignoredevel|--chrootflags|--chrootpkgs|--rootchrootpkgs|--pkgctl)
                longs="${longs}${a} "; skip=1 ;;
            --*) longs="${longs}${a%%=*} " ;;  # other long option
            -*)
                rest="${a#-}"
                for (( i=0; i<${#rest}; i++ )); do
                    c="${rest:$i:1}"
                    case "$c" in
                        # getopt: -b <dbpath> / -r <root> take a value: the rest of
                        # this argument (-Sb/db) or, ending the group, the NEXT one.
                        [br]) (( i == ${#rest} - 1 )) && skip=1; break ;;
                        [A-Z]) op="${op}${c}" ;;
                        *)     mods="${mods}${c}" ;;
                    esac
                done
                ;;
            *) _AUR_SCAN_PKGS+=("$a") ;;
        esac
    done

    local is_sync=0 is_upfile=0 sysupgrade=0 non_install=0 readonly_sync=0 npk=${#_AUR_SCAN_PKGS[@]}
    [[ "$op" == *S* ]] && is_sync=1
    [[ "$op" == *U* ]] && is_upfile=1       # -U: install a local package file
    [[ "$mods" == *u* ]] && sysupgrade=1    # the 'u' of -Syu/-Su: system upgrade
    # Never-install operations: pacman's query/remove/files/database/deptest/
    # version, plus -P (--show, print stats).
    [[ "$op" == *[QRFDTVP]* ]] && non_install=1
    # Read-only sync sub-operations: search/info/list/groups/clean/print.
    [[ "$mods" == *[silgcp]* ]] && readonly_sync=1

    # Help prints usage and installs nothing, but ONLY when there is nothing to
    # install: `paru -S evil --help` must still be classified as an install.
    if [[ ( "$mods" == *h* || "$longs" == *" --help "* ) && $npk -eq 0 ]]; then return; fi

    # -G/--getpkgbuild only downloads a PKGBUILD to inspect -- not an install.
    # Scanned ONLY on opt-in (AUR_SCAN_SCAN_GETPKGBUILD=1).
    if [[ "$op" == *G* ]]; then
        [[ $npk -gt 0 ]] && _AUR_SCAN_IS_GETPKGBUILD=1
        return
    fi
    # -B (paru): build local PKGBUILD directories; each one is scanned.
    if [[ "$op" == *B* ]]; then
        local -a _dirs=("${_AUR_SCAN_PKGS[@]}")
        [[ $npk -eq 0 ]] && _dirs=(".")
        local d
        for d in "${_dirs[@]}"; do
            if [[ -d "$d" ]]; then _AUR_SCAN_LOCAL+=("$d")
            else _AUR_SCAN_BLOCK+=("-B operand '$d' is not a directory; cannot scan it"); fi
        done
        return
    fi
    # Passthrough: a non-install op that is not also a sync/upgrade, a read-only
    # sync sub-op, or a help/version-style invocation.
    if [[ "$non_install" == "1" && "$is_sync" == "0" && "$is_upfile" == "0" ]]; then return; fi
    if [[ "$is_sync" == "1" && "$readonly_sync" == "1" ]]; then return; fi
    # A report flag (--stats, --gendb, ...) is read-only only when no install,
    # upgrade or build operation and no operand is present; otherwise the
    # invocation is classified exactly as if the flag were absent.
    local report_re=' --(gendb|stats|news|order|comments) '
    if [[ "$longs" =~ $report_re && $npk -eq 0 && "$sysupgrade" == "0" && "$is_upfile" == "0" ]]; then return; fi

    # -U / -Ui: install a local file, or build a local PKGBUILD directory.
    if [[ "$is_upfile" == "1" && "$is_sync" == "0" ]]; then
        local o
        if [[ $npk -eq 0 ]]; then
            [[ "$mods" == *i* ]] && _AUR_SCAN_LOCAL+=(".")
            return
        fi
        for o in "${_AUR_SCAN_PKGS[@]}"; do
            if [[ -d "$o" ]]; then _AUR_SCAN_LOCAL+=("$o")
            elif [[ "${o##*/}" == "PKGBUILD" ]]; then
                if [[ "$o" == */* ]]; then _AUR_SCAN_LOCAL+=("${o%/*}"); else _AUR_SCAN_LOCAL+=("."); fi
            else
                _AUR_SCAN_NOTICES+=("$o: prebuilt package/URL installed as-is; aur-scan cannot pre-scan it")
            fi
        done
        return
    fi

    # Search-menu installs: bare `helper <term>` (paru: interactive search; yay:
    # op -Y), `yay -Y <term>` (its -s/-i/-l/-g/-p do not stop the menu; only
    # --gendb and -c do) and `-S --interactive`. The installed set is picked
    # after this gate runs, so it cannot be scanned.
    local yay_menu=0
    if [[ "$op" == *Y* && "$is_sync" == "0" && "$is_upfile" == "0" && $npk -gt 0 \
       && "$mods" != *c* && "$longs" != *" --gendb "* ]]; then
        yay_menu=1; _AUR_SCAN_MENU=1
    elif [[ -z "$op" && $npk -gt 0 && "$readonly_sync" == "0" ]]; then
        _AUR_SCAN_MENU=1
    elif [[ "$is_sync" == "1" && "$longs" == *" --interactive "* && "$readonly_sync" == "0" ]]; then
        _AUR_SCAN_MENU=1
    fi

    # System upgrade: -Syu/-Su/-Sua, yay -Yu, or the helper's default (no
    # operation and no operands -- e.g. bare `paru` == `paru -Syu`). The upgraded
    # packages are not named, so the gate enumerates the AUR update set itself.
    if [[ ( "$is_sync" == "1" && "$sysupgrade" == "1" ) || ( "$op" == *Y* && "$sysupgrade" == "1" ) \
       || ( -z "$op" && $npk -eq 0 ) \
       || ( "$op" == "Y" && -z "$mods" && $npk -eq 0 && "$longs" == " " ) ]]; then
        _AUR_SCAN_IS_UPGRADE=1
    fi
    # Named install: operands of a non-read-only invocation. Covers `-S pkg`, bare
    # `helper pkg`, and yay's `-Y pkg` (#12). `aur/x` scans x; `core/x` (another
    # repo) needs no scan; anything that is not a legal name is REFUSED.
    if [[ $npk -gt 0 && ( "$readonly_sync" == "0" || "$yay_menu" == "1" ) ]]; then
        local p repo name
        for p in "${_AUR_SCAN_PKGS[@]}"; do
            name="$p"; repo=""
            if [[ "$p" == */* ]]; then repo="${p%%/*}"; name="${p#*/}"; fi
            if ! _aur_scan_valid_name "$name"; then
                _AUR_SCAN_BLOCK+=("package operand '$p' is not a valid package name; refusing to install what cannot be scanned")
            elif [[ -n "$repo" && "$repo" != "aur" ]]; then
                # explicit non-AUR repository (must look like a repo name)
                [[ "$repo" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || \
                    _AUR_SCAN_BLOCK+=("package operand '$p' has an invalid repository prefix")
            else
                _AUR_SCAN_NAMES+=("$name")
            fi
        done
    fi
}

# List the AUR packages with a pending update into _AUR_SCAN_UPDATES. Returns 1
# when the list cannot be trusted (helper failed, e.g. network down): that must
# BLOCK, never read as "no updates". pacman-style helpers exit 1 with no output
# when nothing is pending, so exactly that shape is accepted as empty.
_aur_scan_updates() {
    local helper="$1" errf out err rc line
    _AUR_SCAN_UPDATES=()
    errf=$(mktemp) || { echo "AUR Security Scanner: cannot create a temp file; refusing." >&2; return 1; }
    out=$(command "$helper" -Quaq 2>"$errf"); rc=$?
    err=$(<"$errf"); rm -f "$errf"
    if (( rc != 0 )); then
        if ! { (( rc == 1 )) && [[ -z "${out//[[:space:]]/}" && -z "${err//[[:space:]]/}" ]]; }; then
            echo "AUR Security Scanner: '$helper -Quaq' failed (${err%%$'\n'*}); cannot list pending AUR updates." >&2
            return 1
        fi
    fi
    while IFS= read -r line; do
        line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        if ! _aur_scan_valid_name "$line"; then
            echo "AUR Security Scanner: unexpected update entry '$line'; refusing." >&2
            return 1
        fi
        _AUR_SCAN_UPDATES+=("$line")
    done <<< "$out"
    return 0
}

# Shared gate: scan what would be built, then hand off to the real helper. $1 is
# the helper name; the rest are its original arguments. Fail-closed throughout.
_aur_scan_gate() {
    local helper="$1"; shift
    if [[ "$AUR_SCAN_ENABLED" != "1" ]]; then
        command "$helper" "$@"
        return
    fi

    _aur_scan_classify "$@"

    if [[ ${#_AUR_SCAN_BLOCK[@]} -gt 0 ]]; then
        local _r
        for _r in "${_AUR_SCAN_BLOCK[@]}"; do echo "AUR Security Scanner: BLOCKED: $_r" >&2; done
        echo "Not proceeding with $helper. Use ${helper}-unsafe to bypass deliberately." >&2
        return 1
    fi
    if [[ "$_AUR_SCAN_MENU" == "1" && "${AUR_SCAN_ALLOW_MENU:-0}" != "1" ]]; then
        echo "AUR Security Scanner: BLOCKED: menu-mode install: the helper lets you pick packages from a search menu AFTER this scan, so the packages you pick would not be scanned. Name the exact package instead ('-S <name>'), or set AUR_SCAN_ALLOW_MENU=1 to accept the old behaviour (the search term is scanned as a package name; rely on the pacman hook for the final pick)." >&2
        echo "Nothing was installed. Use ${helper}-unsafe to bypass deliberately." >&2
        return 1
    fi
    local _n
    for _n in "${_AUR_SCAN_NOTICES[@]}"; do echo "AUR Security Scanner: notice: $_n" >&2; done

    # Assemble the packages to pre-scan from the classified action(s) and the
    # user's coverage settings (secure-by-default).
    local -a _to_scan=("${_AUR_SCAN_NAMES[@]}")
    # -G/--getpkgbuild: opt-in (default off) -- it only fetches a PKGBUILD to review.
    if [[ "$_AUR_SCAN_IS_GETPKGBUILD" == "1" && "${AUR_SCAN_SCAN_GETPKGBUILD:-0}" == "1" ]]; then
        _to_scan+=("${_AUR_SCAN_PKGS[@]}")
    fi
    local _want_upd=0
    [[ "$_AUR_SCAN_IS_UPGRADE" == "1" && "${AUR_SCAN_SCAN_UPGRADES:-1}" != "0" ]] && _want_upd=1

    if [[ ${#_to_scan[@]} -gt 0 || ${#_AUR_SCAN_LOCAL[@]} -gt 0 || "$_want_upd" == "1" ]]; then
        if ! command -v aur-scan &> /dev/null; then
            echo "AUR Security Scanner: aur-scan not found in PATH; refusing to run $helper unscanned. Install it, or use ${helper}-unsafe to bypass." >&2
            return 1
        fi
    fi

    # Race-free mode applies to a NAMED install that is NOT also a system upgrade
    # or local build (a `-Syu pkg` must still let the helper do the upgrade):
    # scan the exact bytes and build them in dependency order via `aur-scan install`.
    if [[ ${#_AUR_SCAN_NAMES[@]} -gt 0 && "$_AUR_SCAN_IS_UPGRADE" == "0" && ${#_AUR_SCAN_LOCAL[@]} -eq 0 \
       && "${AUR_SCAN_MODE:-gate}" == "install" ]]; then
        aur-scan install --gate "$AUR_SCAN_SEVERITY" "${_AUR_SCAN_NAMES[@]}"
        return $?
    fi

    # System upgrade: scan each AUR package with a pending update (default on). A
    # hijacked update is the primary AUR threat, so this is on by default. If the
    # list cannot be obtained the upgrade is BLOCKED, not waved through.
    if [[ "$_want_upd" == "1" ]]; then
        if ! _aur_scan_updates "$helper"; then
            echo "Not proceeding with $helper (cannot enumerate AUR updates)." >&2
            return 1
        fi
        _to_scan+=("${_AUR_SCAN_UPDATES[@]}")
    fi

    if [[ ${#_to_scan[@]} -gt 0 || ${#_AUR_SCAN_LOCAL[@]} -gt 0 ]]; then
        # De-duplicate, preserving order.
        local -A _seen=(); local -a _uniq=(); local _p
        for _p in "${_to_scan[@]}"; do
            [[ -n "$_p" && -z "${_seen[$_p]:-}" ]] && { _uniq+=("$_p"); _seen[$_p]=1; }
        done
        echo "AUR Security Scanner: pre-checking ${#_uniq[@]} package(s), ${#_AUR_SCAN_LOCAL[@]} local dir(s)..."
        local scan_args=("--severity" "$AUR_SCAN_SEVERITY" "--fail-on" "$AUR_SCAN_SEVERITY")
        # No TTY (pipe/cron/CI) cannot answer a prompt: deny rather than guess.
        if [[ "$AUR_SCAN_INTERACTIVE" != "1" || ! -t 0 ]]; then
            scan_args+=("--no-confirm")
        fi
        local _d
        for _d in "${_AUR_SCAN_LOCAL[@]}"; do scan_args+=("--local" "$_d"); done
        if ! aur-scan check "${scan_args[@]}" "${_uniq[@]}"; then
            echo "Scan failed or user aborted. Not proceeding with $helper."
            return 1
        fi
    fi

    command "$helper" "$@"
}

paru()   { _aur_scan_gate paru "$@"; }
yay()    { _aur_scan_gate yay "$@"; }
pikaur() { _aur_scan_gate pikaur "$@"; }
trizen() { _aur_scan_gate trizen "$@"; }
pakku()  { _aur_scan_gate pakku "$@"; }

# These helpers are wrapped because they share pacman's flag grammar for AUR
# installs (-S/-Syu), so the operation classifier above is correct for them.
# Other helpers are NOT wrapped blindly — aura installs the AUR via a *different*
# operation (`aura -A`, and `-Ad` lists deps where `d` is pacman's --nodeps), and
# aurutils/rua/pat-aur use a subcommand model (`aur sync …`, `rua install …`,
# `pat-aur b:…`); a wrong assumption would silently skip a scan or falsely block a
# read-only command. To cover those, any helper the wrapper can't see, or yay's
# interactive `-Y` menu (the package is chosen after the wrapper runs), enable the
# opt-in pacman hook — it fires on the actually-installed package regardless of helper.

# Run a helper once WITHOUT scanning (also the escape hatch when aur-scan is
# missing). Functions, not aliases, so they work in scripts too.
paru-unsafe()   { AUR_SCAN_ENABLED=0 paru "$@"; }
yay-unsafe()    { AUR_SCAN_ENABLED=0 yay "$@"; }
pikaur-unsafe() { AUR_SCAN_ENABLED=0 pikaur "$@"; }
trizen-unsafe() { AUR_SCAN_ENABLED=0 trizen "$@"; }
pakku-unsafe()  { AUR_SCAN_ENABLED=0 pakku "$@"; }

# Function to scan all installed AUR packages
aur-scan-system() {
    aur-scan system "$@"
}

if [[ "$AUR_SCAN_VERBOSE" == "1" ]]; then
    echo "AUR Security Scanner: Shell integration loaded." >&2
    echo "  - paru, yay, pikaur, trizen, pakku auto-scan before installing AUR packages" >&2
    echo "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)" >&2
    echo "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper" >&2
    echo "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning" >&2
    echo "  - Set AUR_SCAN_ENABLED=0 to disable globally" >&2
fi
