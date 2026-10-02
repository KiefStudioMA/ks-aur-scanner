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

# aur-scan missing: do NOT silently run unscanned. The gate refuses at call
# time (see _aur_scan_gate); use `paru-unsafe` / `yay-unsafe` to bypass on purpose.
if not command -q aur-scan
    echo "Warning: aur-scan not found in PATH. Installs through paru/yay/... will be REFUSED until it is installed (use <helper>-unsafe to bypass)." >&2
end

# A legal Arch/AUR package identifier (mirrors aur-scanner-core's validator).
function _aur_scan_valid_name
    test (string length -- $argv[1]) -le 256
    and string match -qr '^[A-Za-z0-9@_+][A-Za-z0-9@._+-]*$' -- $argv[1]
end

# Options that change WHICH AUR packages are upgradeable (or where the list
# comes from). They are copied onto the `<helper> -Quaq` enumeration so the
# scanned update set is the set the real run will build. Mirrors
# UPDATE_FLAG_OPTS in aur-scan-wrap (a test keeps them in step). --repo/--mode/
# --aur are not forwarded: -Quaq already asks for the AUR side and widening can
# only over-scan; --rebuild/--redownload/--noconfirm do not change the set.
function _aur_scan_fwd_opt
    contains -- $argv[1] --aururl --aurrpcurl --config --ignore --ignoregroup --assume-installed --arch --dbpath --root --sysroot --pacman --pacman-conf --pacmanconf --develsuffixes --develfile --ignoredevel --nodevel
end

# Classify a pacman/helper invocation by its OPERATION (not by substring
# sniffing, which could let an unrelated flag silently disable scanning). It
# fills, fail-closed:
#   _AUR_SCAN_NAMES        AUR names that would be built (`aur/x` -> x; `core/x` dropped)
#   _AUR_SCAN_IS_UPGRADE   a system upgrade (the gate scans the AUR update set)
#   _AUR_SCAN_IS_GETPKGBUILD / _AUR_SCAN_PKGS   a `-G` fetch (scanned only on opt-in)
#   _AUR_SCAN_LOCAL        local build dirs (`-B dir`, `-Ui`, `-U dir`) to scan
#   _AUR_SCAN_NOTICES      prebuilt-package installs that cannot be pre-scanned
#   _AUR_SCAN_BLOCK        reasons the invocation must be refused (cannot be validated)
#   _AUR_SCAN_UPD_FLAGS    user flags to copy onto the `<helper> -Quaq` update listing
#   _AUR_SCAN_DEVEL        `--devel` is in effect: VCS updates cannot be listed reliably,
#                          so installed foreign -git/-svn/-hg/-bzr packages are scanned too
#   _AUR_SCAN_MENU         the helper will show a search menu and install the pick
#                          (`paru <term>`, `yay <term>`, `yay -Y <term>`, `-S --interactive`);
#                          the pick is made AFTER the gate, so it is refused unless
#                          AUR_SCAN_ALLOW_MENU=1. Neither paru nor yay auto-selects an
#                          exact name: the menu is always shown.
# Bias: scan whenever an install is possible; refuse what cannot be scanned.
function _aur_scan_classify
    set -g _AUR_SCAN_IS_UPGRADE 0
    set -g _AUR_SCAN_IS_GETPKGBUILD 0
    set -g _AUR_SCAN_PKGS
    set -g _AUR_SCAN_NAMES
    set -g _AUR_SCAN_LOCAL
    set -g _AUR_SCAN_NOTICES
    set -g _AUR_SCAN_BLOCK
    set -g _AUR_SCAN_MENU 0
    set -g _AUR_SCAN_UPD_FLAGS
    set -g _AUR_SCAN_DEVEL 0
    set -l fwd_next 0
    set -l op ""
    set -l mods ""
    set -l longs " "
    set -l eoo 0
    set -l skip 0
    for a in $argv
        if test "$skip" = "1"
            set skip 0
            if test "$fwd_next" = "1"
                set fwd_next 0
                set -a _AUR_SCAN_UPD_FLAGS $a
            end
            continue
        end
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
            case '--build'
                set op "$op"B
            case '--version'
                set op "$op"V
            case '--yay'
                set op "$op"Y
            case '--files'
                set op "$op"F
            case '--database'
                set op "$op"D
            case '--deptest'
                set op "$op"T
            case '--sysupgrade'
                set mods "$mods"u
            case '--search'
                set mods "$mods"s
            case '--info' '--install'
                set mods "$mods"i
            case '--list'
                set mods "$mods"l
            case '--groups'
                set mods "$mods"g
            case '--clean'
                set mods "$mods"c
            case '--print'
                set mods "$mods"p
            case '--devel'
                set -g _AUR_SCAN_DEVEL 1
                set longs "$longs--devel "
            case '--nodevel'
                set -g _AUR_SCAN_DEVEL 0
                set -a _AUR_SCAN_UPD_FLAGS $a
                set longs "$longs--nodevel "
            # Long options that take the NEXT argument as their value (only ones
            # that ALWAYS do: a boolean flag listed here would swallow an operand).
            case '--root' '--dbpath' '--cachedir' '--logfile' '--gpgdir' '--hookdir' '--arch' '--color' '--config' '--sysroot' '--ignore' '--ignoregroup' '--assume-installed' '--overwrite' '--print-format' '--ask' '--aururl' '--aurrpcurl' '--clonedir' '--builddir' '--makepkg' '--makepkgconf' '--pacman' '--pacman-conf' '--pacmanconf' '--git' '--gitflags' '--sudo' '--sudoflags' '--asp' '--bat' '--batflags' '--fm' '--fmflags' '--editor' '--editorflags' '--mflags' '--gpg' '--gpgflags' '--answerclean' '--answerdiff' '--answeredit' '--answerupgrade' '--searchby' '--sortby' '--completioninterval' '--requestsplitn' '--mode' '--limit' '--develsuffixes' '--develfile' '--ignoredevel' '--chrootflags' '--chrootpkgs' '--rootchrootpkgs' '--pkgctl'
                set longs "$longs$a "
                set skip 1
                if _aur_scan_fwd_opt $a
                    set -a _AUR_SCAN_UPD_FLAGS $a
                    set fwd_next 1
                end
            case '--*'
                # other long option (strip any =value)
                set -l oname (string replace -r '=.*' '' -- $a)
                set longs "$longs$oname "
                if _aur_scan_fwd_opt $oname
                    set -a _AUR_SCAN_UPD_FLAGS $a
                end
            case '-*'
                set -l rest (string sub -s 2 -- $a)
                set -l chars (string split '' -- $rest)
                for i in (seq (count $chars))
                    set -l c $chars[$i]
                    # getopt: -b <dbpath> / -r <root> take a value: the rest of
                    # this argument (-Sb/db) or, ending the group, the NEXT one.
                    if string match -qr '^[br]$' -- $c
                        set -l long_flag --dbpath
                        test "$c" = r; and set long_flag --root
                        if test $i -eq (count $chars)
                            set skip 1
                            set fwd_next 1
                            set -a _AUR_SCAN_UPD_FLAGS $long_flag
                        else
                            set -l restv (string join '' -- $chars[(math $i + 1)..-1])
                            set -a _AUR_SCAN_UPD_FLAGS "$long_flag=$restv"
                        end
                        break
                    end
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

    set -l npk (count $_AUR_SCAN_PKGS)
    set -l is_sync 0
    set -l is_upfile 0
    set -l sysupgrade 0
    set -l non_install 0
    set -l readonly_sync 0
    string match -q '*S*' -- $op; and set is_sync 1
    string match -q '*U*' -- $op; and set is_upfile 1
    string match -q '*u*' -- $mods; and set sysupgrade 1
    # Never-install ops: pacman's QRFDTV plus -P (--show).
    string match -qr '[QRFDTVP]' -- $op; and set non_install 1
    # Read-only sync sub-operations: search/info/list/groups/clean/print.
    string match -qr '[silgcp]' -- $mods; and set readonly_sync 1

    # Help prints usage and installs nothing, but ONLY when there is nothing to
    # install: `paru -S evil --help` must still be classified as an install.
    if test $npk -eq 0
        if string match -q '*h*' -- $mods; or string match -q '* --help *' -- $longs
            return
        end
    end

    # -G/--getpkgbuild only downloads a PKGBUILD to inspect -- not an install.
    # Scanned ONLY on opt-in (AUR_SCAN_SCAN_GETPKGBUILD=1).
    if string match -q '*G*' -- $op
        if test $npk -gt 0
            set -g _AUR_SCAN_IS_GETPKGBUILD 1
        end
        return
    end
    # -B (paru): build local PKGBUILD directories; each one is scanned.
    if string match -q '*B*' -- $op
        set -l dirs $_AUR_SCAN_PKGS
        if test $npk -eq 0
            set dirs .
        end
        for d in $dirs
            if test -d "$d"
                set -a _AUR_SCAN_LOCAL $d
            else
                set -a _AUR_SCAN_BLOCK "-B operand '$d' is not a directory; cannot scan it"
            end
        end
        return
    end
    # Passthrough: a non-install op that is not also a sync/upgrade, a read-only
    # sync sub-op, or a help/version-style invocation.
    if test "$non_install" = "1" -a "$is_sync" = "0" -a "$is_upfile" = "0"
        return
    end
    if test "$is_sync" = "1" -a "$readonly_sync" = "1"
        return
    end
    # A report flag (--stats, --gendb, ...) is read-only only when no install,
    # upgrade or build operation and no operand is present; otherwise the
    # invocation is classified exactly as if the flag were absent.
    if string match -qr ' --(gendb|stats|news|order|comments) ' -- $longs
        and test $npk -eq 0 -a "$sysupgrade" = "0" -a "$is_upfile" = "0"
        return
    end

    # -U / -Ui: install a local file, or build a local PKGBUILD directory.
    if test "$is_upfile" = "1" -a "$is_sync" = "0"
        if test $npk -eq 0
            if string match -q '*i*' -- $mods
                set -a _AUR_SCAN_LOCAL .
            end
            return
        end
        for o in $_AUR_SCAN_PKGS
            if test -d "$o"
                set -a _AUR_SCAN_LOCAL $o
            else if test (string replace -r '.*/' '' -- $o) = PKGBUILD
                if string match -q '*/*' -- $o
                    set -a _AUR_SCAN_LOCAL (string replace -r '/[^/]*$' '' -- $o)
                else
                    set -a _AUR_SCAN_LOCAL .
                end
            else
                set -a _AUR_SCAN_NOTICES "$o: prebuilt package/URL installed as-is; aur-scan cannot pre-scan it"
            end
        end
        return
    end

    # Search-menu installs: bare `helper <term>` (paru: interactive search; yay:
    # op -Y), `yay -Y <term>` (its -s/-i/-l/-g/-p do not stop the menu; only
    # --gendb and -c do) and `-S --interactive`. The installed set is picked
    # after this gate runs, so it cannot be scanned.
    set -l yay_menu 0
    if string match -q '*Y*' -- $op; and test "$is_sync" = "0" -a "$is_upfile" = "0" -a $npk -gt 0
        and not string match -q '*c*' -- $mods
        and not string match -q '* --gendb *' -- $longs
        set yay_menu 1
        set -g _AUR_SCAN_MENU 1
    else if test -z "$op" -a $npk -gt 0 -a "$readonly_sync" = "0"
        set -g _AUR_SCAN_MENU 1
    else if test "$is_sync" = "1" -a "$readonly_sync" = "0"; and string match -q '* --interactive *' -- $longs
        set -g _AUR_SCAN_MENU 1
    end

    # System upgrade: -Syu/-Su/-Sua, yay -Yu, or the helper's default (no
    # operation and no operands -- e.g. bare `paru` == `paru -Syu`). The upgraded
    # packages are not named, so the gate enumerates the AUR update set itself.
    if test "$is_sync" = "1" -a "$sysupgrade" = "1"
        set -g _AUR_SCAN_IS_UPGRADE 1
    else if string match -q '*Y*' -- $op; and test "$sysupgrade" = "1"
        set -g _AUR_SCAN_IS_UPGRADE 1
    else if test -z "$op" -a $npk -eq 0
        set -g _AUR_SCAN_IS_UPGRADE 1
    else if test "$op" = "Y" -a -z "$mods" -a $npk -eq 0 -a "$longs" = " "
        set -g _AUR_SCAN_IS_UPGRADE 1
    end
    # Named install: operands of a non-read-only invocation. Covers `-S pkg`, bare
    # `helper pkg`, and yay's `-Y pkg` (#12). `aur/x` scans x; `core/x` (another
    # repo) needs no scan; anything that is not a legal name is REFUSED.
    if test $npk -gt 0; and test "$readonly_sync" = "0" -o "$yay_menu" = "1"
        for p in $_AUR_SCAN_PKGS
            set -l repo ""
            set -l name $p
            if string match -q '*/*' -- $p
                set repo (string replace -r '/.*' '' -- $p)
                set name (string replace -r '^[^/]*/' '' -- $p)
            end
            if not _aur_scan_valid_name $name
                set -a _AUR_SCAN_BLOCK "package operand '$p' is not a valid package name; refusing to install what cannot be scanned"
            else if test -n "$repo" -a "$repo" != "aur"
                # explicit non-AUR repository (must look like a repo name)
                if not string match -qr '^[A-Za-z0-9][A-Za-z0-9._+-]*$' -- $repo
                    set -a _AUR_SCAN_BLOCK "package operand '$p' has an invalid repository prefix"
                end
            else
                set -a _AUR_SCAN_NAMES $name
            end
        end
    end
end

# List the AUR packages with a pending update into _AUR_SCAN_UPDATES. Returns 1
# when the list cannot be trusted (helper failed, e.g. network down): that must
# BLOCK, never read as "no updates". pacman-style helpers exit 1 with no output
# when nothing is pending, so exactly that shape is accepted as empty.
function _aur_scan_updates
    set -g _AUR_SCAN_UPDATES
    set -l helper $argv[1]
    set -l errf (mktemp)
    or begin
        echo "AUR Security Scanner: cannot create a temp file; refusing." >&2
        return 1
    end
    set -l out (command $helper -Quaq $_AUR_SCAN_UPD_FLAGS 2>$errf)
    set -l rc $status
    set -l err (cat $errf)
    rm -f $errf
    set -l outj (string join '' -- $out | string trim)
    set -l errj (string join '' -- $err | string trim)
    if test $rc -ne 0
        if not test $rc -eq 1 -a -z "$outj" -a -z "$errj"
            echo "AUR Security Scanner: '$helper -Quaq' failed ($err[1]); cannot list pending AUR updates." >&2
            return 1
        end
    end
    for line in $out
        set line (string trim -- $line)
        test -z "$line"; and continue
        if not _aur_scan_valid_name $line
            echo "AUR Security Scanner: unexpected update entry '$line'; refusing." >&2
            return 1
        end
        set -a _AUR_SCAN_UPDATES $line
    end
    return 0
end

# `--devel`: `-Quaq` cannot list VCS updates reliably, so list the installed
# foreign VCS packages (`pacman -Qmq`, -git/-svn/-hg/-bzr) into _AUR_SCAN_VCS and
# scan them too. Returns 1 (BLOCK) when pacman cannot be queried.
function _aur_scan_vcs_installed
    set -g _AUR_SCAN_VCS
    set -l pflags
    set -l skipn 0
    for a in $_AUR_SCAN_UPD_FLAGS
        if test "$skipn" = "1"
            set -a pflags $a
            set skipn 0
            continue
        end
        switch $a
            case '--dbpath' '--root' '--sysroot'
                set -a pflags $a
                set skipn 1
            case '--dbpath=*' '--root=*' '--sysroot=*'
                set -a pflags $a
        end
    end
    set -l errf (mktemp)
    or begin
        echo "AUR Security Scanner: cannot create a temp file; refusing." >&2
        return 1
    end
    set -l out (command pacman -Qmq $pflags 2>$errf)
    set -l rc $status
    set -l err (cat $errf)
    rm -f $errf
    set -l outj (string join '' -- $out | string trim)
    set -l errj (string join '' -- $err | string trim)
    if test $rc -ne 0
        if not test $rc -eq 1 -a -z "$outj" -a -z "$errj"
            echo "AUR Security Scanner: 'pacman -Qmq' failed ($err[1]); cannot list installed VCS packages." >&2
            return 1
        end
    end
    for line in $out
        set line (string trim -- $line)
        test -z "$line"; and continue
        if not _aur_scan_valid_name $line
            echo "AUR Security Scanner: unexpected package entry '$line'; refusing." >&2
            return 1
        end
        if string match -qr -- '-(git|svn|hg|bzr)$' $line
            set -a _AUR_SCAN_VCS $line
        end
    end
    return 0
end

# Shared gate: scan what would be built, then hand off to the real helper.
# $argv[1] is the helper name; the rest are its original arguments. Fail-closed
# throughout.
function _aur_scan_gate
    set -l helper $argv[1]
    set -e argv[1]
    if test "$AUR_SCAN_ENABLED" != "1"
        command $helper $argv
        return
    end

    _aur_scan_classify $argv

    if test (count $_AUR_SCAN_BLOCK) -gt 0
        for r in $_AUR_SCAN_BLOCK
            echo "AUR Security Scanner: BLOCKED: $r" >&2
        end
        echo "Not proceeding with $helper. Use $helper-unsafe to bypass deliberately." >&2
        return 1
    end
    if test "$_AUR_SCAN_MENU" = "1" -a "$AUR_SCAN_ALLOW_MENU" != "1"
        echo "AUR Security Scanner: BLOCKED: menu-mode install: the helper lets you pick packages from a search menu AFTER this scan, so the packages you pick would not be scanned. Name the exact package instead ('-S <name>'), or set AUR_SCAN_ALLOW_MENU=1 to accept the old behaviour (the search term is scanned as a package name; rely on the pacman hook for the final pick)." >&2
        echo "Nothing was installed. Use $helper-unsafe to bypass deliberately." >&2
        return 1
    end
    for n in $_AUR_SCAN_NOTICES
        echo "AUR Security Scanner: notice: $n" >&2
    end

    # Assemble the packages to pre-scan from the classified action(s) and the
    # user's coverage settings (secure-by-default).
    set -l to_scan $_AUR_SCAN_NAMES
    # -G/--getpkgbuild: opt-in (default off) -- only fetches a PKGBUILD to review.
    if test "$_AUR_SCAN_IS_GETPKGBUILD" = "1" -a "$AUR_SCAN_SCAN_GETPKGBUILD" = "1"
        set -a to_scan $_AUR_SCAN_PKGS
    end
    set -l want_upd 0
    if test "$_AUR_SCAN_IS_UPGRADE" = "1" -a "$AUR_SCAN_SCAN_UPGRADES" != "0"
        set want_upd 1
    end

    if test (count $to_scan) -gt 0 -o (count $_AUR_SCAN_LOCAL) -gt 0 -o "$want_upd" = "1"
        if not command -q aur-scan
            echo "AUR Security Scanner: aur-scan not found in PATH; refusing to run $helper unscanned. Install it, or use $helper-unsafe to bypass." >&2
            return 1
        end
    end

    # Race-free mode applies to a NAMED install that is NOT also a system upgrade
    # or local build (a `-Syu pkg` must still let the helper do the upgrade).
    if test (count $_AUR_SCAN_NAMES) -gt 0 -a "$_AUR_SCAN_IS_UPGRADE" = "0" -a (count $_AUR_SCAN_LOCAL) -eq 0 -a "$AUR_SCAN_MODE" = "install"
        aur-scan install --gate $AUR_SCAN_SEVERITY $_AUR_SCAN_NAMES
        return $status
    end

    # System upgrade: scan each AUR package with a pending update (default on;
    # set AUR_SCAN_SCAN_UPGRADES=0 to disable). If the list cannot be obtained
    # the upgrade is BLOCKED, not waved through.
    if test "$want_upd" = "1"
        if not _aur_scan_updates $helper
            echo "Not proceeding with $helper (cannot enumerate AUR updates)." >&2
            return 1
        end
        set -a to_scan $_AUR_SCAN_UPDATES
        if test "$_AUR_SCAN_DEVEL" = "1"
            if not _aur_scan_vcs_installed
                echo "Not proceeding with $helper (--devel: cannot list installed VCS packages)." >&2
                return 1
            end
            set -a to_scan $_AUR_SCAN_VCS
        end
    end

    if test (count $to_scan) -gt 0 -o (count $_AUR_SCAN_LOCAL) -gt 0
        # De-duplicate, preserving order.
        set to_scan (printf '%s\n' $to_scan | awk 'NF && !seen[$0]++')
        echo "AUR Security Scanner: pre-checking "(count $to_scan)" package(s), "(count $_AUR_SCAN_LOCAL)" local dir(s)..."
        set -l scan_args --severity $AUR_SCAN_SEVERITY --fail-on $AUR_SCAN_SEVERITY
        # No TTY (pipe/cron/CI) cannot answer a prompt: deny rather than guess.
        if test "$AUR_SCAN_INTERACTIVE" != "1"; or not isatty stdin
            set -a scan_args --no-confirm
        end
        for d in $_AUR_SCAN_LOCAL
            set -a scan_args --local $d
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

# Run a helper once WITHOUT scanning (also the escape hatch when aur-scan is
# missing). Real functions, not abbreviations: abbreviations only expand when
# typed interactively, so they did nothing in scripts and `fish -c`.
function paru-unsafe --wraps='paru'
    command paru $argv
end

function yay-unsafe --wraps='yay'
    command yay $argv
end

function pikaur-unsafe --wraps='pikaur'
    command pikaur $argv
end

function trizen-unsafe --wraps='trizen'
    command trizen $argv
end

function pakku-unsafe --wraps='pakku'
    command pakku $argv
end

# Function to scan all installed AUR packages
function aur-scan-system
    aur-scan system $argv
end

if test "$AUR_SCAN_VERBOSE" = "1"
    echo "AUR Security Scanner: Shell integration loaded." >&2
    echo "  - paru, yay, pikaur, trizen, pakku auto-scan before installing AUR packages" >&2
    echo "  - AUR_SCAN_MODE=install : race-free (scan the exact bytes, then build)" >&2
    echo "  - AUR_SCAN_MODE=gate (default) : scan, then hand off to the helper" >&2
    echo "  - Use 'paru-unsafe' or 'yay-unsafe' to bypass scanning" >&2
    echo "  - Set AUR_SCAN_ENABLED=0 to disable globally" >&2
end
