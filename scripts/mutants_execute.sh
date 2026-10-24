#!/usr/bin/env bash
# =============================================================================
# scripts/mutants_execute.sh — execute the named kernel-law mutations
#
# Usage: scripts/mutants_execute.sh [--results <file>] [MUT-id ...]
#
# registries/mutants.toml names each mutation: its file, the exact `find`
# text, the replacement, and the tests that must kill it. `xtask mutants`
# only anchors that ledger (each `find` occurs exactly once). This gate
# executes it. For each mutant (every row, or the ids named) it:
# - applies the replacement in this worktree;
# - runs every killed_by test alone (`cargo test ... -- --exact <name>`);
# - restores the file before the next mutant, and on interruption.
#
# Verdicts (scripts/lib/gate_verdict.sh), one per mutant:
#   PASS  every killed_by test failed with the mutation applied
#   FAIL  the mutant survived: a killed_by test passed or matched no test, or
#         the mutated tree does not compile (the row tests nothing), or the
#         `find` text no longer occurs exactly once
#   UNRUN a test did not execute (offloader refusal), a killed_by test
#         already fails on the unmutated tree (it cannot judge a mutant), or
#         the mutated file has uncommitted changes and was left alone
#
# Every killed_by test first runs once on the unmutated tree (cached per
# test): a kill counts only for a test that passes there.
#
# --results <file> records one `<MUT-id> KILLED|SURVIVED|UNRUN` line per
# mutant, which `xtask mutants --results <file>` judges.
#
# Run it in a dedicated worktree: the gate edits tracked files while it
# runs. No-claim boundary: a kill proves the named tests notice this one
# mutation at this revision; it does not prove they cover the law.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

gate_init "mutants-execute"

RESULTS=""
if [ "${1:-}" = "--results" ]; then
  RESULTS="${2:-}"
  [ -n "$RESULTS" ] || gate_abort_unrun "mutants-execute — --results needs a file"
  shift 2
  : > "$RESULTS" || gate_abort_unrun "mutants-execute — cannot write $RESULTS"
fi
LEDGER=(python3 -B "$ROOT/scripts/mutants_ledger.py" "$ROOT")
if [ "$#" -gt 0 ]; then
  IDS=("$@")
else
  mapfile -t IDS < <("${LEDGER[@]}" ids)
fi
[ "${#IDS[@]}" -gt 0 ] || gate_abort_unrun "mutants-execute — no mutants in registries/mutants.toml"

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fa-mutants.XXXXXX")" \
  || gate_abort_unrun "mutants-execute — cannot create a log directory"

ACTIVE=""
restore_active() {
  if [ -n "$ACTIVE" ]; then
    "${LEDGER[@]}" restore "$ACTIVE" "$LOG_DIR/$ACTIVE.orig" \
      || gate_diag "mutants-execute: restore $ACTIVE by hand from $LOG_DIR/$ACTIVE.orig"
    ACTIVE=""
  fi
}
trap restore_active EXIT
trap 'restore_active; exit 130' INT TERM

record() {
  if [ -n "$RESULTS" ]; then
    printf '%s %s\n' "$1" "$2" >> "$RESULTS"
  fi
}

# The unmutated verdict of each killed_by test, run once and cached: green,
# red or unrun (did not execute). Sets BASE_STATE; call it directly, not in a
# command substitution, so the cache survives.
declare -A BASELINE
BASE_STATE=""
BASE_RUNS=0
baseline() {
  local line="$1" args log rc plain
  if [ -z "${BASELINE[$line]:-}" ]; then
    IFS=$'\t' read -r -a args <<< "$line"
    BASE_RUNS=$((BASE_RUNS + 1))
    log="$LOG_DIR/baseline-$BASE_RUNS.log"
    cargo test --locked "${args[@]}" > "$log" 2>&1
    rc=$?
    plain="$(sed 's/\x1b\[[0-9;]*m//g' "$log")"
    if [ "$rc" -eq 0 ] && grep -qE '^test result: ok\. [1-9][0-9]* passed' <<< "$plain"; then
      BASELINE[$line]=green
    elif [ "$rc" -ne 0 ] && gate_env_failure_class "$log" > /dev/null; then
      BASELINE[$line]=unrun
    else
      BASELINE[$line]="red (log $log)"
    fi
  fi
  BASE_STATE="${BASELINE[$line]}"
}

for id in "${IDS[@]}"; do
  if ! file="$("${LEDGER[@]}" file "$id")"; then
    gate_fail "$id — no such row in registries/mutants.toml"
    continue
  fi
  if ! git -C "$ROOT" diff --quiet HEAD -- "$file"; then
    gate_unrun "$id — $file has uncommitted changes, so it was not mutated"
    record "$id" UNRUN
    continue
  fi
  mapfile -t TESTS < <("${LEDGER[@]}" tests "$id")
  unjudged=""
  for line in "${TESTS[@]}"; do
    baseline "$line"
    if [ "$BASE_STATE" != green ]; then
      unjudged="$unjudged ${line//$'\t'/ } [$BASE_STATE]"
    fi
  done
  if [ -n "$unjudged" ]; then
    gate_unrun "$id — a killed_by test is not green unmutated, so it cannot judge the mutant:$unjudged"
    record "$id" UNRUN
    continue
  fi
  if ! "${LEDGER[@]}" apply "$id" "$LOG_DIR/$id.orig"; then
    gate_fail "$id — its find text does not occur exactly once in $file"
    record "$id" SURVIVED
    continue
  fi
  ACTIVE="$id"
  n=0
  killed=0
  stillborn=""
  survived=""
  unrun=""
  for line in "${TESTS[@]}"; do
    n=$((n + 1))
    IFS=$'\t' read -r -a args <<< "$line"
    log="$LOG_DIR/$id-$n.log"
    cargo test --locked "${args[@]}" > "$log" 2>&1
    rc=$?
    plain="$(sed 's/\x1b\[[0-9;]*m//g' "$log")"
    if grep -q '^test result: FAILED' <<< "$plain"; then
      killed=$((killed + 1))
    elif grep -qE '^test result: ok\. [1-9][0-9]* passed' <<< "$plain"; then
      survived="$survived ${args[*]}"
    elif grep -qE '^test result: ok\. 0 passed' <<< "$plain"; then
      survived="$survived ${args[*]} (matched no test)"
    elif [ "$rc" -ne 0 ] && class="$(gate_env_failure_class "$log")"; then
      unrun="$unrun ${args[*]} ($class)"
    elif grep -q 'could not compile' <<< "$plain"; then
      stillborn="$log"
    else
      unrun="$unrun ${args[*]} (exit $rc, no test result)"
    fi
  done
  restore_active
  if [ -n "$unrun" ]; then
    gate_unrun "$id — did not execute:$unrun (logs $LOG_DIR)"
    record "$id" UNRUN
  elif [ -n "$stillborn" ]; then
    gate_fail "$id — the mutated tree does not compile, so the row tests nothing (log $stillborn)"
    record "$id" SURVIVED
  elif [ -n "$survived" ]; then
    gate_fail "$id — survived:$survived (logs $LOG_DIR)"
    record "$id" SURVIVED
  else
    gate_pass "$id — killed by all $n of its tests"
    record "$id" KILLED
  fi
done

gate_verdict
