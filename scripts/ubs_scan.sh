#!/usr/bin/env bash
# =============================================================================
# scripts/ubs_scan.sh — the `ubs` step of scripts/check.sh (fa-0hs4.2)
#
# The bug scanner as a STATIC scan: it compiles nothing (`--no-cargo`); the
# compiler, clippy, test and deny verdicts are check.sh's own steps, so this
# step never launches a bare cargo.
#
# One scan per package directory (crates/<name>, tools/<name>), not one
# whole-project scan: on 2026-10-29 (b4fff298b) ubs v5.5.3 left the whole
# project partially analyzed ("ast-grep: output exceeds 16777216 bytes",
# exit 2), and that cap has no override. Every package scan completes.
#
# Test code is out of scope (`.ubsignore` plus `--exclude-tests`). The step's
# contract since fa-lbh (2026-10-10) is that a test `panic!` is not critical
# while a production `panic!` is; the scanner then rated integration-test
# panics as warnings. v5.5.3 rates every `panic!` critical and cannot tell
# that a `tests.rs` or `#[path]` module compiles only under cfg(test).
#
# Each directory reports one line: PASS needs a complete scan (status ok)
# with 0 critical findings; critical findings are FAIL (their scanner report
# follows); a partial or unreadable scan is UNRUN. Exit 0 only when every
# directory passed and at least one file was scanned.
#
# Usage: bash scripts/ubs_scan.sh [--root <repo>]
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
source "$ROOT/scripts/lib/gate_verdict.sh"

scan_root="$ROOT"
if [ "${1:-}" = "--root" ] && [ -n "${2:-}" ]; then
  scan_root="$(cd "$2" && pwd)" || exit 2
fi
cd "$scan_root" || exit 2
gate_init "ubs"

if ! command -v ubs >/dev/null 2>&1; then
  gate_unrun "ubs is not installed"
  gate_verdict
fi

# Package directories holding tracked Rust; a file outside crates/ and tools/
# is scanned under its top-level directory, a root-level file on its own.
mapfile -t TARGETS < <(git ls-files --cached --others --exclude-standard -- '*.rs' \
  | awk -F/ '($1 == "crates" || $1 == "tools") && NF > 2 { print $1 "/" $2; next }
             NF > 1 { print $1; next }
             { print }' | sort -u)
if [ "${#TARGETS[@]}" -eq 0 ]; then
  gate_unrun "no tracked Rust files; nothing was checked"
  gate_verdict
fi

UBS_ARGS=(--only=rust --no-cargo --no-color --exclude-tests --ignore-file="$scan_root/.ubsignore")
scanned=0
for target in "${TARGETS[@]}"; do
  out="$(ubs "${UBS_ARGS[@]}" --format=jsonl "$target" 2>&1)"
  rc=$?
  read -r status files critical < <(printf '%s\n' "$out" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        t = json.loads(line)
    except ValueError:
        continue
    if isinstance(t, dict) and t.get("type") == "totals":
        ok = t.get("status") == "ok" and not t.get("failed_modules")
        print("ok" if ok else (t.get("status") or "unknown"), int(t.get("files", 0)), int(t.get("critical", 0)))
        break
else:
    print("no-totals 0 0")
')
  if [ "${critical:-0}" -gt 0 ]; then
    gate_fail "ubs $target — $critical critical finding(s) (exit $rc)"
    NO_COLOR=1 ubs "${UBS_ARGS[@]}" "$target" 2>&1 | grep -E -A12 'CRITICAL' | sed 's/^/  /'
  elif [ "${status:-}" != "ok" ] || [ "$rc" -ne 0 ]; then
    gate_unrun "ubs $target — scan did not complete (status ${status:-none}, exit $rc); nothing here is a verdict"
    printf '%s\n' "$out" | tail -n 5 | sed 's/^/  /'
  elif [ "${files:-0}" -eq 0 ]; then
    echo "ubs $target: no file in scope (test code only)"
  else
    scanned=$((scanned + files))
    gate_pass "ubs $target ($files files, 0 critical)"
  fi
done
if [ "$scanned" -eq 0 ] && [ "$GATE_FAIL" -eq 0 ] && [ "$GATE_UNRUN" -eq 0 ]; then
  gate_unrun "no file was in scope in any package; nothing was checked"
fi
gate_verdict
