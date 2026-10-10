#!/usr/bin/env bash
# =============================================================================
# scripts/tests/invariants_negative.sh — planted negatives for the
# `invariants` gate (bead fa-37f)
#
# Usage: scripts/tests/invariants_negative.sh <invariants.toml> <test-transcript> <workdir>
#
# A gate that cannot fail is not a gate. This self-test runs
# scripts/invariants_check.sh against the same transcript the real step
# judged:
#   0. positive control: the real registry passes;
#   1. a scratch copy whose first live checker is renamed must fail, with a
#      FAIL line naming the renamed checker (a checker that no longer exists);
#   2. a missing transcript must be UNRUN, never PASS (the third state).
# Scratch copies and their transcripts stay in <workdir> for inspection.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

if [ "$#" -ne 3 ]; then
  printf 'FAIL invariants_negative.sh: usage: invariants_negative.sh <invariants.toml> <test-transcript> <workdir>\n'
  exit 1
fi
REGISTRY="$1"
TRANSCRIPT="$2"
WORK="$3"

gate_init "invariants-negative"
mkdir -p "$WORK" || gate_abort_unrun "invariants-negative — cannot create $WORK"
CHECK="$ROOT/scripts/invariants_check.sh"

# run_case <name> <registry> <transcript> -> sets RC and OUT
run_case() {
  OUT="$WORK/$1.transcript"
  bash "$CHECK" "$2" "$3" >"$OUT" 2>"$WORK/$1.stderr"
  RC=$?
}

run_case positive "$REGISTRY" "$TRANSCRIPT"
if [ "$RC" -eq 2 ] && grep -q '^UNRUN ' "$OUT"; then
  gate_abort_unrun "invariants-negative — the positive control did not run ($(grep -m1 '^UNRUN ' "$OUT" | cut -c7-))"
elif [ "$RC" -eq 0 ]; then
  gate_pass "invariants-negative — positive control: the real registry passes over this transcript"
else
  gate_fail "invariants-negative — positive control: the real registry fails (exit $RC); see $OUT"
fi

# 1. Rename the first live checker in a scratch copy.
SUFFIX="_renamed_by_invariants_negative"
awk -v suffix="$SUFFIX" '
  !done && /^checkers = \["/ { sub(/", |"\]$/, suffix "&"); done = 1 }
  { print }
' "$REGISTRY" >"$WORK/renamed.toml"
RENAMED="$(grep -m1 "$SUFFIX" "$WORK/renamed.toml" | sed -E 's/^checkers = \["([^"]+)".*/\1/')"
if [ -z "$RENAMED" ]; then
  gate_fail "invariants-negative — could not plant: no live checker line was found"
else
  run_case renamed "$WORK/renamed.toml" "$TRANSCRIPT"
  line="$(grep '^FAIL ' "$OUT" | grep -F -- "$RENAMED" | head -n 1)"
  if [ "$RC" -eq 1 ] && [ -n "$line" ]; then
    gate_pass "invariants-negative — planted rename is caught: ${line#FAIL }"
  else
    gate_fail "invariants-negative — planted rename of \`$RENAMED\` was not caught (exit $RC); see $OUT"
  fi
fi

# 2. No transcript: the third state, never a pass.
run_case no-transcript "$REGISTRY" "$WORK/no-such-transcript.log"
if [ "$RC" -eq 2 ] && grep -q '^UNRUN ' "$OUT"; then
  gate_pass "invariants-negative — a missing transcript is UNRUN, not PASS"
else
  gate_fail "invariants-negative — a missing transcript gave exit $RC; see $OUT"
fi

gate_verdict
