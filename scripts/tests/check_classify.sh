#!/usr/bin/env bash
# =============================================================================
# scripts/tests/check_classify.sh — Unit and step-harness tests for check.sh
# offloader-failure classification (bead fa-j1fc)
# =============================================================================
# Verifies that check.sh classifies rch offloader failures as UNRUN regardless
# of exit code (1, 100, 101, 103) when "Remote command finished" is absent, and
# classifies executed remote failures ("Remote command finished: exit=...") and
# non-rch local command failures as FAIL.
#
# Acceptance test entry points:
#   scripts/tests/check_classify.sh::ssh_timeout_exit1_is_unrun
# =============================================================================

set -uo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../lib/gate_verdict.sh
. "$SOURCE_ROOT/scripts/lib/gate_verdict.sh"
gate_init "check-classify"

base="${TMPDIR:-/tmp}/fa-check-classify-$$-${RANDOM:-0}"
mkdir -p "$base/bin" "$base/logs"

# Extract the real helpers (hash_file, extract_worker, record_step_verdict,
# try_reuse_step, is_rch_offloader_unrun) and run_step/cargo_build from check.sh.
harness="$base/check_harness.sh"
cat > "$harness" <<'HDR'
set -u
LOG_DIR="${CHECK_LOG_DIR:-/tmp}"
STEP_MANIFEST="${CHECK_STEP_MANIFEST:-/dev/null}"
: >"$STEP_MANIFEST"
CHECK_TREE_HASH="0123456789abcdef0123456789abcdef01234567"
CHECK_TOOLCHAIN="rustc 1.100.0-nightly"
HDR
sed -n '/^hash_file() {/,/^gate_init /{ /^gate_init /!p; }' "$SOURCE_ROOT/scripts/check.sh" >> "$harness"
sed -n '/^run_step() {/,/^run_gate() {/{ /^run_gate() {/!p; }' "$SOURCE_ROOT/scripts/check.sh" >> "$harness"

# Helper that runs a single step through check.sh's actual run_step or cargo_build
# in a subshell and echoes the recorded status from step-verdicts.jsonl.
invoke_run_step() {
  local rc="$1" log_body="$2"
  local step_dir="$base/run-$$-${RANDOM:-0}"
  mkdir -p "$step_dir/bin"
  cat > "$step_dir/bin/fake-tool" <<EOF
#!/usr/bin/env bash
cat <<'LOGEOF'
$log_body
LOGEOF
exit $rc
EOF
  chmod +x "$step_dir/bin/fake-tool"
  (
    export PATH="$step_dir/bin:$PATH"
    export CHECK_LOG_DIR="$step_dir/logs"
    export CHECK_STEP_MANIFEST="$step_dir/step-verdicts.jsonl"
    mkdir -p "$CHECK_LOG_DIR"
    # shellcheck source=../lib/gate_verdict.sh
    . "$SOURCE_ROOT/scripts/lib/gate_verdict.sh"
    gate_init "inner"
    # shellcheck disable=SC1090
    . "$harness"
    run_step "probe-step" fake-tool
  ) > "$step_dir/stdout.log" 2> "$step_dir/stderr.log" || true
  python3 - "$step_dir/step-verdicts.jsonl" "$step_dir/stdout.log" <<'PY'
import json, pathlib, sys
manifest = pathlib.Path(sys.argv[1])
stdout = pathlib.Path(sys.argv[2]).read_text()
rec = json.loads(manifest.read_text().splitlines()[0])
status = rec["status"]
if status == "UNRUN" and not stdout.startswith("UNRUN probe-step"):
    print(f"MISMATCH:{status}:{stdout.strip()}")
elif status == "FAIL" and not stdout.startswith("FAIL probe-step"):
    print(f"MISMATCH:{status}:{stdout.strip()}")
elif status == "PASS" and not stdout.startswith("PASS probe-step"):
    print(f"MISMATCH:{status}:{stdout.strip()}")
else:
    print(status)
PY
}

invoke_cargo_build() {
  local rc="$1" sub="$2" log_body="$3"
  local step_dir="$base/cargo-$$-${RANDOM:-0}"
  mkdir -p "$step_dir/bin"
  cat > "$step_dir/bin/rch" <<EOF
#!/usr/bin/env bash
cat <<'LOGEOF'
$log_body
LOGEOF
exit $rc
EOF
  chmod +x "$step_dir/bin/rch"
  (
    export PATH="$step_dir/bin:$PATH"
    export CHECK_LOG_DIR="$step_dir/logs"
    export CHECK_STEP_MANIFEST="$step_dir/step-verdicts.jsonl"
    mkdir -p "$CHECK_LOG_DIR"
    # shellcheck source=../lib/gate_verdict.sh
    . "$SOURCE_ROOT/scripts/lib/gate_verdict.sh"
    gate_init "inner"
    # shellcheck disable=SC1090
    . "$harness"
    cargo_build "probe-cargo" "$sub" --workspace
  ) > "$step_dir/stdout.log" 2> "$step_dir/stderr.log" || true
  python3 - "$step_dir/step-verdicts.jsonl" "$step_dir/stdout.log" <<'PY'
import json, pathlib, sys
manifest = pathlib.Path(sys.argv[1])
stdout = pathlib.Path(sys.argv[2]).read_text()
rec = json.loads(manifest.read_text().splitlines()[0])
status = rec["status"]
if status == "UNRUN" and not stdout.startswith("UNRUN probe-cargo"):
    print(f"MISMATCH:{status}:{stdout.strip()}")
elif status == "FAIL" and not stdout.startswith("FAIL probe-cargo"):
    print(f"MISMATCH:{status}:{stdout.strip()}")
elif status == "PASS" and not stdout.startswith("PASS probe-cargo"):
    print(f"MISMATCH:{status}:{stdout.strip()}")
else:
    print(status)
PY
}

# 1. Planted negative (acceptance test): a log containing "[RCH-E104] SSH command timed out"
#    with exit 1 classifies UNRUN, not FAIL, in both run_step and cargo_build.
ssh_timeout_exit1_is_unrun() {
  local log_text="[RCH-E104] SSH command timed out (no local fallback)"
  local step_verdict cargo_verdict
  step_verdict="$(invoke_run_step 1 "$log_text")"
  if [ "$step_verdict" != "UNRUN" ]; then
    gate_fail "ssh_timeout_exit1_is_unrun — run_step classified exit 1 + '$log_text' as $step_verdict, expected UNRUN"
    return 1
  fi
  cargo_verdict="$(invoke_cargo_build 1 clippy "$log_text")"
  if [ "$cargo_verdict" != "UNRUN" ]; then
    gate_fail "ssh_timeout_exit1_is_unrun — cargo_build classified exit 1 + '$log_text' as $cargo_verdict, expected UNRUN"
    return 1
  fi
  gate_pass "ssh_timeout_exit1_is_unrun (exit 1 with '[RCH-E104] SSH command timed out' classifies UNRUN in run_step and cargo_build)"
  return 0
}

# 2. Classifier table test: every rch failure marker x exit code (1, 100, 101, 103) -> UNRUN,
#    and executed failures / local failures -> FAIL.
classifier_table_covers_rch_markers_and_exit_codes() {
  # shellcheck disable=SC1090
  . "$harness"

  local -a unrun_markers=(
    "[RCH-E104] SSH command timed out (no local fallback)"
    "2026-10-25T00:00:00Z ERROR rch::hook: SSH command timed out after 1800s"
    "[RCH] no admissible workers available; refusing local fallback"
    "rch::fleet: no admissible workers in pool"
    "[RCH] remote command completion unconfirmed"
    "RCH_SCOPED_COMPLETION_UNCONFIRMED: lost SSH stream"
    "rch::transfer: Connection timed out while syncing"
  )
  local marker rc f cases=0
  for marker in "${unrun_markers[@]}"; do
    for rc in 1 100 101 103; do
      cases=$((cases + 1))
      f="$base/logs/unrun-$cases.log"
      printf '%s\n' "$marker" > "$f"
      if ! is_rch_offloader_unrun "$rc" "$f"; then
        gate_fail "classifier_table — marker '$marker' with exit $rc classified FAIL, expected UNRUN"
        return 1
      fi
    done
  done

  # Executed remote failures (containing "Remote command finished") must classify as FAIL
  # for exit codes 1, 100, 101 (while exit 103 remains rch refusal UNRUN).
  local -a fail_logs=(
    "Selected worker: hz2 at ubuntu@178.104.77.29
error[E0432]: unresolved import \`foo\`
Remote command finished: exit=101 in 1200ms"
    "Selected worker: vmi1149989 at root@212.90.121.76
test foo::bar ... FAILED
test result: FAILED. 0 passed; 1 failed
Remote command finished: exit=1 in 900ms"
    "Diff in /data/projects/franken_accounting/src/lib.rs:1"
  )
  for marker in "${fail_logs[@]}"; do
    for rc in 1 101; do
      cases=$((cases + 1))
      f="$base/logs/fail-$cases.log"
      printf '%s\n' "$marker" > "$f"
      if is_rch_offloader_unrun "$rc" "$f"; then
        gate_fail "classifier_table — executed failure log with exit $rc classified UNRUN, expected FAIL: $marker"
        return 1
      fi
    done
  done

  # Also verify end-to-end cargo_build for no admissible workers (exit 101) and completion unconfirmed (exit 1)
  local v1 v2 v3
  v1="$(invoke_cargo_build 101 check "rch: no admissible workers")"
  [ "$v1" = "UNRUN" ] || { gate_fail "classifier_table — no admissible workers exit 101 got $v1"; return 1; }
  v2="$(invoke_cargo_build 1 test "[RCH] completion unconfirmed")"
  [ "$v2" = "UNRUN" ] || { gate_fail "classifier_table — completion unconfirmed exit 1 got $v2"; return 1; }
  v3="$(invoke_cargo_build 101 check "error[E0432]: bad\nRemote command finished: exit=101")"
  [ "$v3" = "FAIL" ] || { gate_fail "classifier_table — Remote command finished exit 101 got $v3"; return 1; }

  gate_pass "classifier_table_covers_rch_markers_and_exit_codes ($cases marker x exit-code cases + cargo_build end-to-end verified)"
  return 0
}

# 3. The split `test` step (fa-0hs4.2): check.sh's real cargo_test_jobs over a
#    fixed three-job list and a fake rch whose answer per job comes from the
#    scenario. Prints "<status> <alpha attempts> <job headers in test.log>".
invoke_test_jobs() {
  local scenario="$1"
  local step_dir="$base/jobs-$scenario"
  mkdir -p "$step_dir/bin" "$step_dir/state"
  cat > "$step_dir/bin/rch" <<'EOF'
#!/usr/bin/env bash
# Fake `rch exec -- cargo test -j N --no-fail-fast <job args>`.
args="$*"
key="$(printf '%s' "$args" | tr -c 'A-Za-z0-9' '_')"
attempt=$(( $(cat "$FAKE_STATE/$key" 2>/dev/null || echo 0) + 1 ))
echo "$attempt" > "$FAKE_STATE/$key"
printf '%s|%s\n' "${RCH_TEST_TIMEOUT_SEC:-fleet}" "$args" >> "$FAKE_STATE/budgets"
ran() { printf 'Selected worker: w1 at u@h\nrunning %s test%s\n' "$1" "$([ "$1" = 1 ] || echo s)"; }
pass() { ran 1; printf 'test %s ... ok\n\ntest result: ok. 1 passed; 0 failed\nRemote command finished: exit=0 in 9ms\n' "$1"; exit 0; }
case "$FAKE_SCENARIO:$args" in
  fail-first:*-p\ alpha*)
    ran 1; printf 'test a ... FAILED\n\ntest result: FAILED. 0 passed; 1 failed\nRemote command finished: exit=101 in 9ms\n'; exit 101 ;;
  refused-once:*-p\ alpha*)
    [ "$attempt" -ge 2 ] && pass a
    printf '[RCH] no admissible workers available; refusing local fallback\n'; exit 103 ;;
  refused-always:*-p\ alpha*)
    printf '[RCH] no admissible workers available; refusing local fallback\n'; exit 103 ;;
  cap-kill:*-p\ alpha*)
    ran 1; printf 'Remote command finished: exit=137 in 1800000ms\n'; exit 137 ;;
  stale:*--exact\ slow*)
    ran 0; printf '\ntest result: ok. 0 passed; 0 failed; 1 filtered out\nRemote command finished: exit=0 in 9ms\n'; exit 0 ;;
  *-p\ alpha*) pass a ;;
  *--exact\ slow*) pass slow ;;
  *) pass x ;;
esac
EOF
  chmod +x "$step_dir/bin/rch"
  (
    export PATH="$step_dir/bin:$PATH" FAKE_STATE="$step_dir/state" FAKE_SCENARIO="$scenario"
    export CHECK_LOG_DIR="$step_dir/logs" CHECK_ISOLATED_TIMEOUT_SEC=4321
    unset RCH_TEST_TIMEOUT_SEC
    export CHECK_STEP_MANIFEST="$step_dir/step-verdicts.jsonl"
    mkdir -p "$CHECK_LOG_DIR"
    # shellcheck source=../lib/gate_verdict.sh
    . "$SOURCE_ROOT/scripts/lib/gate_verdict.sh"
    gate_init "inner"
    # shellcheck disable=SC1090
    . "$harness"
    list_test_jobs() {
      printf 'alpha\t-p alpha\nbeta.test.x\t-p beta --test x -- --exact --skip slow\n'
      printf 'beta.test.x.isolated.slow\t-p beta --test x -- --exact slow\n'
    }
    cargo_test_jobs
  ) > "$step_dir/stdout.log" 2> "$step_dir/stderr.log" || true
  local status alpha headers
  status="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline())["status"])' "$step_dir/step-verdicts.jsonl" 2>/dev/null)"
  [ -n "$status" ] && grep -q "^$status test" "$step_dir/stdout.log" || status="MISMATCH:${status:-none}:$(head -c 200 "$step_dir/stdout.log")"
  alpha="$(cat "$step_dir/state/"*alpha* 2>/dev/null || echo 0)"
  headers="$(grep -c '^==== test job .* (exit ' "$step_dir/logs/test.log" 2>/dev/null)"
  printf '%s %s %s\n' "$status" "$alpha" "${headers:-0}"
}

split_test_jobs_compose_one_step() {
  local got expect scenario
  for scenario in pass fail-first refused-once refused-always cap-kill stale; do
    got="$(invoke_test_jobs "$scenario")"
    case "$scenario" in
      # Every job ran once and its output is in the one step log.
      pass) expect="PASS 1 3" ;;
      # A red job fails the step and never hides the jobs after it.
      fail-first) expect="FAIL 1 3" ;;
      # A command the offloader never ran is retried; the retry decides.
      refused-once) expect="PASS 2 3" ;;
      refused-always) expect="UNRUN 3 3" ;;
      # A cap kill executed: a failure, never retried.
      cap-kill) expect="FAIL 1 3" ;;
      # An isolated test that matches nothing fails, so the list cannot rot.
      stale) expect="FAIL 1 3" ;;
    esac
    if [ "$got" != "$expect" ]; then
      gate_fail "split_test_jobs_compose_one_step — scenario $scenario: got '$got', expected '$expect' (status, alpha attempts, job headers)"
      return 1
    fi
  done
  # Only the isolated command carries its own budget; the others keep the
  # fleet's cap.
  local budgets
  budgets="$(cut -d' ' -f1 "$base/jobs-pass/state/budgets" | tr '\n' ' ')"
  if [ "$budgets" != "fleet|exec fleet|exec 4321|exec " ] \
    || ! grep -q '^4321|.* -- --exact slow$' "$base/jobs-pass/state/budgets"; then
    gate_fail "split_test_jobs_compose_one_step — rch test budgets per command: '$budgets' (want fleet, fleet, then 4321 for the isolated job)"
    return 1
  fi
  gate_pass "split_test_jobs_compose_one_step (pass, fail-first, refused-once, refused-always, cap-kill, stale; isolated budget)"
}

# 4. The real job list covers every workspace package, and every TEST_ISOLATED
#    entry names a target of a split package (otherwise list_test_jobs exits 1).
split_test_job_list_covers_the_workspace() {
  local list="$base/jobs.tsv" missing
  # shellcheck disable=SC1090,SC2034  # list_test_jobs reads ROOT.
  if ! (ROOT="$SOURCE_ROOT"; . "$harness"; list_test_jobs) >"$list" 2>"$base/jobs.err"; then
    gate_fail "split_test_job_list_covers_the_workspace — list_test_jobs failed: $(head -c 300 "$base/jobs.err")"
    return 1
  fi
  missing="$(python3 - "$SOURCE_ROOT" "$list" <<'PY'
import glob, os, sys, tomllib
root, listed = sys.argv[1], open(sys.argv[2]).read()
packages = []
for pattern in tomllib.load(open(os.path.join(root, "Cargo.toml"), "rb"))["workspace"]["members"]:
    for d in glob.glob(os.path.join(root, pattern)):
        packages.append(tomllib.load(open(os.path.join(d, "Cargo.toml"), "rb"))["package"]["name"])
print(" ".join(p for p in packages if f"\t-p {p}\n" not in listed and f"\t-p {p} " not in listed))
PY
)"
  if [ -n "$missing" ] || ! grep -q '\.isolated\.' "$list"; then
    gate_fail "split_test_job_list_covers_the_workspace — packages without a job: ${missing:-none}; isolated jobs: $(grep -c '\.isolated\.' "$list")"
    return 1
  fi
  gate_pass "split_test_job_list_covers_the_workspace ($(wc -l <"$list" | tr -d ' ') jobs)"
}

ssh_timeout_exit1_is_unrun
classifier_table_covers_rch_markers_and_exit_codes
split_test_jobs_compose_one_step
split_test_job_list_covers_the_workspace

gate_verdict
