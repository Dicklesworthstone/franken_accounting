#!/usr/bin/env bash
# =============================================================================
# scripts/conformance_mutation.sh — the fa-conformance mutation run (bead fa-zy1)
#
# Usage: scripts/conformance_mutation.sh
#
# crates/fa-conformance/tests/substrate.rs asserts each relied-upon substrate
# behavior through `relied_upon`, which inverts its expectation when
# FA_CONFORMANCE_INVERT names the test. For every `#[test]` in that file this
# gate runs the suite with that one test inverted and requires that exactly
# that test fails: a test whose inversion still passes asserts nothing, and one
# whose inversion fails a sibling is not independent.
#
# The runtime switch travels through RCH_ENV_ALLOWLIST. Every command uses
# the same job count and profile as check.sh; no accounting predicate or
# timeout changes. A missing switch leaves the inverted suite green and fails.
#
# Verdicts (scripts/lib/gate_verdict.sh):
#   PASS  inverting the test failed exactly that test
#   FAIL  the inversion left the suite green, or failed another test
#   UNRUN the suite did not run (build failure, offloader refusal)
#
# No-claim boundary: proves each test discriminates its own assertion at the
# pinned revision; it does not prove the assertion covers the whole behavior.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

gate_init "conformance-mutation"

SUITE="$ROOT/crates/fa-conformance/tests/substrate.rs"
[ -r "$SUITE" ] || gate_abort_unrun "conformance-mutation — no suite at $SUITE"
command -v rch >/dev/null 2>&1 || gate_abort_unrun "conformance-mutation — rch is unavailable"
command -v python3 >/dev/null 2>&1 || gate_abort_unrun "conformance-mutation — python3 is unavailable"

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fa-conformance-mutation.XXXXXX")" \
  || gate_abort_unrun "conformance-mutation — cannot create a log directory"

jobs="${CHECK_JOBS:-2}"
read -r -a config_args <<<"${CHECK_TEST_CONFIG---config profile.dev.debug=false --config profile.test.debug=false}"
allowlist="${RCH_ENV_ALLOWLIST:-}"
allowlist="${allowlist:+$allowlist,}FA_CONFORMANCE_INVERT"
inventory="$LOG_DIR/tests.txt"

run_suite() {
  local log="$1" inverse="$2"
  shift 2
  FA_CONFORMANCE_INVERT="$inverse" RCH_ENV_ALLOWLIST="$allowlist" \
    RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
    rch exec -- cargo test -j "$jobs" "${config_args[@]}" --locked \
      -p fa-conformance --test substrate --no-fail-fast "$@" >"$log" 2>&1
}

# Classify actual complete harness output, including qualified test names.
# A transcript without matching remote completion is UNRUN, never evidence.
classify_run() {
  python3 - "$1" "$2" "$3" "$4" "$inventory" <<'PY'
import collections
import pathlib
import re
import sys

log_path, command_rc, phase, inverse, inventory_path = sys.argv[1:]
command_rc = int(command_rc)
text = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(log_path).read_text(errors="replace"))

def refuse(detail, code):
    print(f"conformance transcript: {detail}; log={log_path}")
    raise SystemExit(code)

remote = re.findall(r"Remote command finished: exit=(-?\d+)\b", text)
if len(remote) != 1 or int(remote[0]) != command_rc:
    refuse("missing or inconsistent remote completion", 2)

if phase == "list":
    if command_rc != 0:
        refuse("compiled test discovery did not complete", 2)
    names = re.findall(r"^([\w:]+): test$", text, re.MULTILINE)
    summary = re.findall(r"^(\d+) tests?, (\d+) benchmarks?$", text, re.MULTILINE)
    if (not names or len(set(names)) != len(names)
            or any(not re.fullmatch(r"\w+(?:::\w+)*", name) for name in names)
            or summary != [(str(len(names)), "0")]):
        refuse("empty, duplicated or incomplete compiled test inventory", 2)
    with pathlib.Path(inventory_path).open("x") as output:
        output.write("\n".join(names) + "\n")
    print(f"conformance inventory: {len(names)} compiled tests")
    raise SystemExit(0)

names = pathlib.Path(inventory_path).read_text().splitlines()
summaries = re.findall(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out;",
    text, re.MULTILINE,
)
if command_rc not in (0, 101) or len(summaries) != 1:
    refuse("the native suite did not produce one complete result", 2)
results = re.findall(
    r"^test ([\w:]+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)(?:,.*)?$",
    text, re.MULTILINE,
)
if collections.Counter(name for name, _ in results) != collections.Counter(names):
    refuse("executed names differ from the complete compiled inventory", 1)
failed = sorted(name for name, status in results if status == "FAILED")
expected_failed = [] if phase == "baseline" else [inverse]
kind, *counts = summaries[0]
expected_counts = [len(names) - len(expected_failed), len(expected_failed), 0, 0, 0]
expected_rc = 0 if phase == "baseline" else 101
expected_kind = "ok" if phase == "baseline" else "FAILED"
if (failed != expected_failed or list(map(int, counts)) != expected_counts
        or kind != expected_kind or command_rc != expected_rc
        or any(status == "ignored" for _, status in results)):
    refuse(f"expected failures {expected_failed}, observed {failed}; summary={summaries[0]}", 1)
print(f"conformance transcript: complete {phase}, tests={len(names)}, failures={failed}")
PY
}

list_log="$LOG_DIR/list.log"
run_suite "$list_log" "" -- --list
rc=$?
classify_run "$list_log" "$rc" list ""
classified=$?
[ "$classified" -eq 0 ] || gate_abort_unrun "conformance-mutation — compiled discovery is incomplete (log $list_log)"
mapfile -t TESTS <"$inventory"

baseline_log="$LOG_DIR/baseline.log"
run_suite "$baseline_log" ""
rc=$?
classify_run "$baseline_log" "$rc" baseline ""
classified=$?
case "$classified" in
  0) gate_pass "baseline — all ${#TESTS[@]} compiled tests passed" ;;
  1) gate_fail "baseline — the suite is not green (log $baseline_log)" ;;
  *) gate_unrun "baseline — the suite did not complete (log $baseline_log)" ;;
esac
if [ "$classified" -ne 0 ]; then
  gate_verdict
  rc=$?
  exit "$rc"
fi

for t in "${TESTS[@]}"; do
  log="$LOG_DIR/$t.log"
  run_suite "$log" "$t"
  rc=$?
  classify_run "$log" "$rc" mutation "$t"
  classified=$?
  case "$classified" in
    0) gate_pass "$t — inverted, and exactly it failed; all other tests passed" ;;
    1) gate_fail "$t — inversion did not fail exactly this test (log $log)" ;;
    *) gate_unrun "$t — the suite did not complete (exit $rc; log $log)" ;;
  esac
done

gate_verdict
