#!/usr/bin/env bash
#
# capture.sh — generate the audited documentation dataset.
#
# Runs the REAL aur-scan binary against the repo's own test fixtures and the
# detection catalog, and records the actual stdout / stderr / exit code of every
# invocation into docs/examples/dataset/. Those files are the single source of
# truth the documentation quotes from — nothing in the docs is hand-typed output.
#
# Design (data-pipeline discipline):
#   * Inputs are the committed fixtures under tests/fixtures/ — never mutated.
#   * Everything is captured into a STAGING dir first, validated, and only then
#     atomically swapped in. A failed/empty run never overwrites a good dataset.
#   * Fixtures and detection codes are DISCOVERED from the tool, not hardcoded,
#     so the dataset can never reference an input or code that doesn't exist.
#   * Re-runnable and idempotent (modulo the runtime timestamp/duration fields).
#
# Usage:  docs/examples/capture.sh        (run from anywhere in the repo)
#
set -euo pipefail

# --- locate repo root + binary ------------------------------------------------
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
BIN="$REPO/target/release/aur-scan"
FIXTURES="$REPO/tests/fixtures"
OUT="$REPO/docs/examples/dataset"

[ -x "$BIN" ] || { echo "ERROR: $BIN not found. Run: cargo build --release --all" >&2; exit 1; }
[ -d "$FIXTURES" ] || { echo "ERROR: fixtures dir $FIXTURES missing" >&2; exit 1; }

VERSION="$("$BIN" --version | awk '{print $NF}')"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/aur-scan-dataset.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT

echo ">> aur-scan $VERSION — capturing into staging $STAGING"

# Run a command, capturing stdout/.out, stderr/.err and exit/.exit. Never aborts
# the script on a non-zero exit (a non-zero exit is itself data we record).
capture() {  # capture <dest-prefix> <cmd...>
    local dest="$1"; shift
    mkdir -p "$(dirname "$dest")"
    set +e
    "$@" >"$dest.out" 2>"$dest.err"
    echo "$?" >"$dest.exit"
    set -e
}

# --- meta ---------------------------------------------------------------------
mkdir -p "$STAGING"
{
    echo "tool: aur-scan"
    echo "version: $VERSION"
    echo "git_commit: $(git rev-parse HEAD)"
    echo "git_branch: $(git rev-parse --abbrev-ref HEAD)"
    echo "generated_by: docs/examples/capture.sh"
    echo "note: timestamp and scan_duration_ms in JSON are runtime values and vary per run."
} >"$STAGING/meta.txt"

# --- 1. scan every fixture in every format ------------------------------------
# Discover fixtures: any directory that contains a PKGBUILD.
echo ">> scanning fixtures"
while IFS= read -r pkgdir; do
    rel="${pkgdir#"$FIXTURES"/}"          # e.g. malicious/curl-bash
    slug="${rel//\//-}"                    # e.g. malicious-curl-bash
    for fmt in text json sarif; do
        capture "$STAGING/scan/$slug/$fmt" "$BIN" scan "$pkgdir" --format "$fmt"
    done
    # the documented CI gate, recorded as its own exit-code artifact
    capture "$STAGING/scan/$slug/fail-on-high" "$BIN" scan "$pkgdir" --fail-on high
done < <(find "$FIXTURES" -name PKGBUILD -printf '%h\n' | sort -u)

# --- 2. detection catalog -----------------------------------------------------
echo ">> catalog: codes"
capture "$STAGING/codes/text"     "$BIN" codes
capture "$STAGING/codes/json"     "$BIN" codes --format json
capture "$STAGING/codes/markdown" "$BIN" codes --format markdown

# --- 3. explain — only codes that actually exist in the catalog ---------------
echo ">> catalog: explain"
# Pull the real code IDs out of the catalog we just captured.
mapfile -t ALL_CODES < <(grep -oE '\b[A-Z]+-[0-9]+\b|\bEXEC-REMOTE\b|\bIOC-[0-9]+\b' \
                         "$STAGING/codes/text.out" | sort -u)
# Representative set the docs reference; intersect with what exists.
WANT=(DLE-001 PASTE-001 EXEC-REMOTE SHELL-001 CRED-001 INSTALL-004 \
      PERSIST-001 PERSIST-002 CRYPTO-001 CRYPTO-003 ATOMIC-001 ATOMIC-002 ATOMIC-003)
for code in "${WANT[@]}"; do
    if printf '%s\n' "${ALL_CODES[@]}" | grep -qx "$code"; then
        capture "$STAGING/explain/$code" "$BIN" explain "$code"
    else
        echo "   (skip explain $code — not in catalog)"
    fi
done

# --- 3b. SBOM (best-effort) ---------------------------------------------------
# `check --local --sbom` resolves the dependency tree, which may use the AUR RPC.
# If it can't (offline), we just skip it rather than fail the whole capture.
echo ">> SBOM (best-effort)"
mkdir -p "$STAGING/sbom"
if timeout 60 "$BIN" check --local "$FIXTURES/clean/example-package" --no-confirm \
        --sbom "$STAGING/sbom/clean-example-package.cdx.json" \
        >"$STAGING/sbom/clean-example-package.sbom.txt" 2>&1 \
        && [ -s "$STAGING/sbom/clean-example-package.cdx.json" ]; then
    echo "   captured SBOM (CycloneDX $(python3 -c "import json;print(json.load(open('$STAGING/sbom/clean-example-package.cdx.json'))['specVersion'])" 2>/dev/null))"
else
    echo "   skipped (no network / dep resolution unavailable)"
    echo "SBOM generation needs dependency resolution (AUR RPC); not captured offline." \
        >"$STAGING/sbom/SKIPPED.txt"
fi

# --- 4. help for every subcommand + version -----------------------------------
echo ">> help + version"
capture "$STAGING/help/aur-scan" "$BIN" --help
for sub in scan check install system rules explain codes ioc version; do
    capture "$STAGING/help/$sub" "$BIN" "$sub" --help
done
capture "$STAGING/version" "$BIN" --version

# --- 5b. canonicalize paths ---------------------------------------------------
# The scanner echoes the (absolute) path it was given into every finding's
# `file` field. Strip the absolute repo + staging prefixes so the committed
# dataset is byte-identical regardless of WHERE it was generated (no
# /home/<user> leak; no churn between the repo root and a .mycelium clone).
echo ">> canonicalizing paths (repo-relative)"
# Order matters: the staging temp dir and the repo root are stripped to a
# relative form first; anything else under the maintainer's $HOME (e.g. a
# ~/.cache path an SBOM run might emit) falls back to a "~/"-relative form so
# the username never lands in the committed dataset.
find "$STAGING" -type f \( -name '*.out' -o -name '*.err' -o -name '*.json' -o -name '*.txt' \) \
    -exec sed -i \
        -e "s#${STAGING}/#staging/#g" \
        -e "s#${REPO}/##g" \
        -e "s#${HOME:-/__no_home__}/#~/#g" {} +

# --- 5. validate before swap --------------------------------------------------
echo ">> validating"
fail=0
need_nonempty() { [ -s "$1" ] || { echo "   EMPTY: ${1#$STAGING/}" >&2; fail=1; }; }
valid_json()   { python3 -c "import json,sys; json.load(open('$1'))" 2>/dev/null \
                 || { echo "   BAD JSON: ${1#$STAGING/}" >&2; fail=1; }; }

# Every scanned fixture must have produced text + parseable json + sarif.
while IFS= read -r pkgdir; do
    rel="${pkgdir#"$FIXTURES"/}"; slug="${rel//\//-}"
    need_nonempty "$STAGING/scan/$slug/text.out"
    need_nonempty "$STAGING/scan/$slug/json.out"; valid_json "$STAGING/scan/$slug/json.out"
    valid_json "$STAGING/scan/$slug/sarif.out"
done < <(find "$FIXTURES" -name PKGBUILD -printf '%h\n' | sort -u)
need_nonempty "$STAGING/codes/text.out"; valid_json "$STAGING/codes/json.out"

# Privacy guard (fail closed): the maintainer's absolute home must never survive
# canonicalization into the committed dataset. If it does, keep the existing
# dataset rather than swap in a leaky one.
if grep -rIlF "${HOME:-/__no_home__}/" "$STAGING" >/dev/null 2>&1; then
    echo "   LEAK: maintainer home path survived canonicalization:" >&2
    grep -rIlF "${HOME:-/__no_home__}/" "$STAGING" | sed "s#^$STAGING/#     #" >&2
    fail=1
fi

# A malicious fixture must NOT come back clean (catches a silently-broken binary).
if grep -qiE 'No (security )?(issues|findings)' "$STAGING/scan/malicious-curl-bash/text.out" 2>/dev/null; then
    echo "   SUSPECT: malicious-curl-bash reported clean" >&2; fail=1
fi
[ "$(cat "$STAGING/scan/malicious-curl-bash/fail-on-high.exit" 2>/dev/null)" = "1" ] \
    || { echo "   SUSPECT: --fail-on high did not gate the curl-bash fixture" >&2; fail=1; }

[ "$fail" -eq 0 ] || { echo ">> VALIDATION FAILED — keeping existing dataset, discarding staging" >&2; exit 1; }

# --- 6. atomic swap -----------------------------------------------------------
rm -rf "$OUT"
mkdir -p "$(dirname "$OUT")"
cp -a "$STAGING" "$OUT"
echo ">> dataset written to ${OUT#$REPO/}  ($(find "$OUT" -type f | wc -l) files)"
