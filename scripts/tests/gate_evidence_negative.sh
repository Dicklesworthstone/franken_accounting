#!/usr/bin/env bash
# =============================================================================
# scripts/tests/gate_evidence_negative.sh — planted negatives for gate
# evidence hardening (bead fa-czx)
#
# Usage: scripts/tests/gate_evidence_negative.sh <repo-root> <workdir>
#
# Verifies that the gate evidence checks and compiling-step guards cannot
# silently pass on incomplete or weakened evidence:
#   0. positive control: matching listed/executed tests with completion markers
#      and intact assert/negative counts -> PASS (exit 0);
#   1. stub rch / log exiting 0 without `Remote command finished: exit=0` ->
#      UNRUN (exit 2);
#   2. stub test run executing zero tests (`0 passed`) -> UNRUN (exit 2);
#   3. stub test run dropping one listed test -> FAIL (exit 1);
#   4. commit removing an `assert` (or negative test) without a
#      `Weakened-tests:` / `Retired-tests:` trailer -> FAIL (exit 1), and with
#      the matching trailer -> PASS (exit 0).
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

if [ "$#" -ne 2 ]; then
  printf 'FAIL gate_evidence_negative.sh: usage: gate_evidence_negative.sh <repo-root> <workdir>\n'
  exit 1
fi

REPO_ROOT="$1"
WORK="$2"

gate_init "gate-evidence-negative"
mkdir -p "$WORK" || gate_abort_unrun "gate-evidence-negative — cannot create $WORK"

CHECK="$ROOT/scripts/gate_evidence_check.sh"

# Build a small synthetic crate fixture for baseline/ratchet tests.
BASE_TREE="$WORK/base_tree"
CURR_TREE="$WORK/curr_tree"
mkdir -p "$BASE_TREE/crates/fa-sample/src" "$CURR_TREE/crates/fa-sample/src"

cat >"$BASE_TREE/crates/fa-sample/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn refuses_bad_input() {
        let res: Result<u32, &'static str> = Err("FA-REF-001");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "FA-REF-001");
    }

    #[test]
    fn computes_exact_balance() {
        assert_eq!(2 + 2, 4);
    }
}
RS
cp "$BASE_TREE/crates/fa-sample/src/lib.rs" "$CURR_TREE/crates/fa-sample/src/lib.rs"

cat >"$WORK/valid-list.log" <<'LOG'
alpha::computes_exact_balance: test
alpha::refuses_bad_input: test
alpha::retains_lineage: test

3 tests, 0 benchmarks
Remote command finished: exit=0
LOG

cat >"$WORK/valid-test.log" <<'LOG'
running 3 tests
test alpha::computes_exact_balance ... ok
test alpha::refuses_bad_input ... ok
test alpha::retains_lineage ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

Remote command finished: exit=0
LOG

: >"$WORK/empty-msg.txt"

run_case() {
  local name="$1"; shift
  OUT="$WORK/$name.transcript"
  bash "$CHECK" "$@" >"$OUT" 2>"$WORK/$name.stderr"
  RC=$?
}

# 0. Positive control.
run_case positive "$CURR_TREE" "$WORK/valid-list.log" "$WORK/valid-test.log" "$WORK/case-positive" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/empty-msg.txt"
if [ "$RC" -eq 0 ] && [ -s "$WORK/case-positive/test-inventory.txt" ] && [ -s "$WORK/case-positive/evidence-ratchet.tsv" ]; then
  gate_pass "gate-evidence-negative — positive control passes and writes inventory + ratchet witnesses"
else
  gate_fail "gate-evidence-negative — positive control failed (exit $RC); see $OUT"
fi

# 1. Stub exiting 0 without `Remote command finished: exit=0` -> UNRUN.
cat >"$WORK/no-remote-finish.log" <<'LOG'
running 3 tests
test alpha::computes_exact_balance ... ok
test alpha::refuses_bad_input ... ok
test alpha::retains_lineage ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
LOG

run_case no-remote-finish "$CURR_TREE" "$WORK/valid-list.log" "$WORK/no-remote-finish.log" "$WORK/case-no-remote" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/empty-msg.txt"
if [ "$RC" -eq 2 ] && grep -q '^UNRUN ' "$OUT" && grep -Fq 'Remote command finished: exit=0' "$OUT"; then
  gate_pass "gate-evidence-negative — planted missing 'Remote command finished: exit=0' produces UNRUN"
else
  gate_fail "gate-evidence-negative — missing 'Remote command finished: exit=0' gave exit $RC (expected UNRUN exit 2); see $OUT"
fi

# 2. Stub that "runs" zero tests -> UNRUN.
cat >"$WORK/zero-tests.log" <<'LOG'
running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

Remote command finished: exit=0
LOG

run_case zero-tests "$CURR_TREE" "$WORK/valid-list.log" "$WORK/zero-tests.log" "$WORK/case-zero-tests" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/empty-msg.txt"
if [ "$RC" -eq 2 ] && grep -q '^UNRUN ' "$OUT"; then
  gate_pass "gate-evidence-negative — planted zero-executed-tests log produces UNRUN"
else
  gate_fail "gate-evidence-negative — zero-executed-tests log gave exit $RC (expected UNRUN exit 2); see $OUT"
fi

# 3. Stub that drops one listed test -> FAIL.
cat >"$WORK/dropped-one.log" <<'LOG'
running 2 tests
test alpha::computes_exact_balance ... ok
test alpha::refuses_bad_input ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

Remote command finished: exit=0
LOG

run_case dropped-one "$CURR_TREE" "$WORK/valid-list.log" "$WORK/dropped-one.log" "$WORK/case-dropped-one" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/empty-msg.txt"
if [ "$RC" -eq 1 ] && grep -q '^FAIL ' "$OUT" && grep -Fq 'alpha::retains_lineage' "$OUT"; then
  gate_pass "gate-evidence-negative — planted dropped listed test 'alpha::retains_lineage' produces FAIL"
else
  gate_fail "gate-evidence-negative — dropped listed test gave exit $RC (expected FAIL exit 1); see $OUT"
fi

# 4. Commit removing an assert without a `Weakened-tests:` trailer -> FAIL;
#    with `Weakened-tests:` trailer -> PASS.
WEAK_TREE="$WORK/weak_tree"
mkdir -p "$WEAK_TREE/crates/fa-sample/src"
cat >"$WEAK_TREE/crates/fa-sample/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn refuses_bad_input() {
        let res: Result<u32, &'static str> = Err("FA-REF-001");
        assert!(res.is_err());
    }

    #[test]
    fn computes_exact_balance() {
        assert_eq!(2 + 2, 4);
    }
}
RS

run_case weakened-no-trailer "$WEAK_TREE" "$WORK/valid-list.log" "$WORK/valid-test.log" "$WORK/case-weakened-no-trailer" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/empty-msg.txt"
if [ "$RC" -eq 1 ] && grep -q '^FAIL ' "$OUT" && grep -Fq 'fa-sample' "$OUT" && grep -Fq 'assert_sites' "$OUT"; then
  gate_pass "gate-evidence-negative — planted removed assert without Weakened-tests: trailer produces FAIL"
else
  gate_fail "gate-evidence-negative — removed assert without trailer gave exit $RC (expected FAIL exit 1); see $OUT"
fi

cat >"$WORK/weakened-trailer-msg.txt" <<'MSG'
refactor(sample): consolidate duplicate error assertion

Weakened-tests: fa-sample::refuses_bad_input (consolidated duplicate assert)
MSG

run_case weakened-with-trailer "$WEAK_TREE" "$WORK/valid-list.log" "$WORK/valid-test.log" "$WORK/case-weakened-with-trailer" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/weakened-trailer-msg.txt"
if [ "$RC" -eq 0 ]; then
  gate_pass "gate-evidence-negative — removed assert accompanied by Weakened-tests: trailer passes"
else
  gate_fail "gate-evidence-negative — removed assert with Weakened-tests: trailer gave exit $RC (expected 0); see $OUT"
fi

# 5. Commit removing a #[test] without a `Retired-tests:` trailer -> FAIL;
#    with `Retired-tests:` trailer -> PASS.
RETIRED_TREE="$WORK/retired_tree"
mkdir -p "$RETIRED_TREE/crates/fa-sample/src"
cat >"$RETIRED_TREE/crates/fa-sample/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn refuses_bad_input() {
        let res: Result<u32, &'static str> = Err("FA-REF-001");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "FA-REF-001");
        assert_eq!(2 + 2, 4);
    }
}
RS

run_case retired-no-trailer "$RETIRED_TREE" "$WORK/valid-list.log" "$WORK/valid-test.log" "$WORK/case-retired-no-trailer" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/empty-msg.txt"
if [ "$RC" -eq 1 ] && grep -q '^FAIL ' "$OUT" && grep -Fq 'fa-sample::computes_exact_balance' "$OUT"; then
  gate_pass "gate-evidence-negative — planted removed test without Retired-tests: trailer produces FAIL"
else
  gate_fail "gate-evidence-negative — removed test without trailer gave exit $RC (expected FAIL exit 1); see $OUT"
fi

cat >"$WORK/retired-trailer-msg.txt" <<'MSG'
refactor(sample): fold computes_exact_balance into refuses_bad_input

Retired-tests: fa-sample::computes_exact_balance
MSG

run_case retired-with-trailer "$RETIRED_TREE" "$WORK/valid-list.log" "$WORK/valid-test.log" "$WORK/case-retired-with-trailer" \
  --base-root "$BASE_TREE" --commit-msg-file "$WORK/retired-trailer-msg.txt"
if [ "$RC" -eq 0 ]; then
  gate_pass "gate-evidence-negative — removed test accompanied by Retired-tests: trailer passes"
else
  gate_fail "gate-evidence-negative — removed test with Retired-tests: trailer gave exit $RC (expected 0); see $OUT"
fi

# 6. Direct check of `cargo_build` in scripts/check.sh against a stub `rch` on PATH:
#    (a) stub `rch` exits 0 without `Remote command finished: exit=0` -> UNRUN;
#    (b) stub `rch` exits 0 with `Remote command finished: exit=0` and `0 passed` -> UNRUN.
STUB_BIN="$WORK/stub-bin"
mkdir -p "$STUB_BIN" "$WORK/stub-logs"
sed -n '/^cargo_build()/,/^}/p' "$ROOT/scripts/check.sh" >"$WORK/cargo_build_fn.sh"

cat >"$STUB_BIN/rch" <<'SH'
#!/usr/bin/env bash
printf '    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.01s\n'
exit 0
SH
chmod +x "$STUB_BIN/rch"

bash -c '
  set -u
  . "$1/scripts/lib/gate_verdict.sh"
  LOG_DIR="$2"
  CHECK_JOBS=1
  . "$3"
  gate_init "stub-check"
  PATH="$4:$PATH" cargo_build "check" check --workspace
  gate_verdict
' _ "$ROOT" "$WORK/stub-logs" "$WORK/cargo_build_fn.sh" "$STUB_BIN" \
  >"$WORK/stub-rch-no-finish.out" 2>"$WORK/stub-rch-no-finish.err"
STUB_RC=$?
if [ "$STUB_RC" -eq 2 ] && grep -q '^UNRUN ' "$WORK/stub-rch-no-finish.out"; then
  gate_pass "gate-evidence-negative — check.sh cargo_build classifies stub rch without 'Remote command finished: exit=0' as UNRUN"
else
  gate_fail "gate-evidence-negative — check.sh cargo_build stub rch without completion marker gave exit $STUB_RC; see $WORK/stub-rch-no-finish.out"
fi

cat >"$STUB_BIN/rch" <<'SH'
#!/usr/bin/env bash
printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\nRemote command finished: exit=0\n'
exit 0
SH
chmod +x "$STUB_BIN/rch"

bash -c '
  set -u
  . "$1/scripts/lib/gate_verdict.sh"
  LOG_DIR="$2"
  CHECK_JOBS=1
  . "$3"
  gate_init "stub-test"
  PATH="$4:$PATH" cargo_build "test" test --workspace
  gate_verdict
' _ "$ROOT" "$WORK/stub-logs" "$WORK/cargo_build_fn.sh" "$STUB_BIN" \
  >"$WORK/stub-rch-zero-tests.out" 2>"$WORK/stub-rch-zero-tests.err"
STUB_RC=$?
if [ "$STUB_RC" -eq 2 ] && grep -q '^UNRUN ' "$WORK/stub-rch-zero-tests.out"; then
  gate_pass "gate-evidence-negative — check.sh cargo_build classifies stub rch with zero passed tests as UNRUN"
else
  gate_fail "gate-evidence-negative — check.sh cargo_build stub rch with zero passed tests gave exit $STUB_RC; see $WORK/stub-rch-zero-tests.out"
fi

# Also verify real workspace source scan succeeds.
if [ -d "$REPO_ROOT/crates" ]; then
  run_case workspace-source "$REPO_ROOT" "$WORK/valid-list.log" "$WORK/valid-test.log" "$WORK/case-workspace"
  if [ "$RC" -eq 0 ] && [ -s "$WORK/case-workspace/evidence-ratchet.tsv" ]; then
    gate_pass "gate-evidence-negative — real workspace source inventory and ratchet scan succeeds"
  else
    gate_fail "gate-evidence-negative — real workspace source scan failed (exit $RC); see $OUT"
  fi
fi

gate_verdict
