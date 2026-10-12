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
# The switch travels as cargo `--config env.…` as well as in the environment,
# so it reaches a remotely executed test binary (rch); if it does not arrive,
# the inverted test passes and this gate reports FAIL, never a false PASS.
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
mapfile -t TESTS < <(awk '/^#\[test\]$/ { want = 1; next } want && /^fn [a-z0-9_]+\(\)/ { sub(/^fn /, ""); sub(/\(.*/, ""); print; want = 0 }' "$SUITE")
[ "${#TESTS[@]}" -gt 0 ] || gate_abort_unrun "conformance-mutation — no #[test] fns found in $SUITE"

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fa-conformance-mutation.XXXXXX")" \
  || gate_abort_unrun "conformance-mutation — cannot create a log directory"

for t in "${TESTS[@]}"; do
  log="$LOG_DIR/$t.log"
  FA_CONFORMANCE_INVERT="$t" cargo test --locked -p fa-conformance --test substrate --no-fail-fast \
    --config "env.FA_CONFORMANCE_INVERT.value=\"$t\"" >"$log" 2>&1
  rc=$?
  failed="$(sed 's/\x1b\[[0-9;]*m//g' "$log" | sed -nE 's/^test ([a-z0-9_]+) \.\.\. FAILED$/\1/p' | sort -u | tr '\n' ' ')"
  ran="$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -c '^test result:' || true)"
  if [ "$ran" -eq 0 ]; then
    gate_unrun "$t — the suite did not run (exit $rc; log $log)"
  elif [ "$rc" -eq 0 ]; then
    gate_fail "$t — inverting it left the suite green: the test does not discriminate (log $log)"
  elif [ "$failed" = "$t " ]; then
    gate_pass "$t — inverted, and exactly it failed"
  else
    gate_fail "$t — inverted, but the failures were: ${failed:-none named} (exit $rc; log $log)"
  fi
done

gate_verdict
