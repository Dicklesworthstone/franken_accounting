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
# Inside a real proof, local_proof.sh exports CHECK_STEP_MANIFEST and
# CHECK_LOG_DIR for check.sh. The harness below truncates $STEP_MANIFEST and
# records into it, so an inherited value would erase the real proof's step
# records. Every case starts from this selftest's own files instead.
export CHECK_LOG_DIR="$base/logs"
export CHECK_STEP_MANIFEST="$base/step-verdicts.jsonl"
unset CHECK_RESUME_FROM

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
sed -n '/^run_gate() {/,/^}/p' "$SOURCE_ROOT/scripts/check.sh" >> "$harness"

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

# 5. The proof summary (fa-0hs4.2): check.sh's exit hook prints exactly what
#    local_proof_verify.sh requires of a transcript, one `ALL GATES GREEN` for
#    a green run and `QUALITY GATE RED` on stdout and stderr for anything else.
check_summary_matches_the_proof_verifier() {
  local case rc pass fail unrun want out
  if ! grep -qx 'gate_init "check.sh" check_summary' "$SOURCE_ROOT/scripts/check.sh"; then
    gate_fail "check_summary_matches_the_proof_verifier — check.sh does not register check_summary as its exit hook"
    return 1
  fi
  for case in "0 3 0 0 green" "1 3 1 0 red" "2 3 0 1 red" "0 3 0 1 red" "0 0 0 0 red"; do
    read -r rc pass fail unrun want <<<"$case"
    out="$base/summary-$rc-$pass-$fail-$unrun"
    # shellcheck disable=SC1090,SC2034  # check_summary reads the GATE_* tallies.
    (. "$harness"; GATE_PASS=$pass GATE_FAIL=$fail GATE_UNRUN=$unrun; check_summary "$rc") \
      >"$out.out" 2>"$out.err"
    if [ "$want" = green ]; then
      [ "$(cat "$out.out")" = "ALL GATES GREEN" ] && [ ! -s "$out.err" ] && continue
    else
      [ "$(cat "$out.out")" = "QUALITY GATE RED" ] && [ "$(cat "$out.err")" = "QUALITY GATE RED" ] && continue
    fi
    gate_fail "check_summary_matches_the_proof_verifier — exit $rc with $pass/$fail/$unrun passed/failed/unrun: stdout '$(cat "$out.out")', stderr '$(cat "$out.err")' (want $want)"
    return 1
  done
  gate_pass "check_summary_matches_the_proof_verifier (green, failed, unrun, unrun under exit 0, no assertions)"
}

# The ubs step scans each package directory (scripts/ubs_scan.sh). A fake
# scanner answers per directory: a complete clean scan is PASS, a critical
# finding FAIL, a partial or crashed scan UNRUN, and no file in scope anywhere
# is UNRUN; every scan carries the test-scope flags.
ubs_scan_classifies_each_package_scan() {
  local repo="$base/ubs-repo" bin="$base/ubs-bin" case a b want_rc want rc
  # shellcheck disable=SC2016  # the literal check.sh line, not an expansion.
  if ! grep -qF 'run_gate "ubs" "$ROOT/scripts/ubs_scan.sh"' "$SOURCE_ROOT/scripts/check.sh"; then
    gate_fail "ubs_scan_classifies_each_package_scan — check.sh does not run scripts/ubs_scan.sh as its ubs step"
    return 1
  fi
  mkdir -p "$repo/scripts/lib" "$repo/crates/a/src" "$repo/crates/b/src" "$bin"
  cp "$SOURCE_ROOT/scripts/ubs_scan.sh" "$repo/scripts/"
  cp "$SOURCE_ROOT/scripts/lib/gate_verdict.sh" "$repo/scripts/lib/"
  printf 'pub fn a() {}\n' > "$repo/crates/a/src/lib.rs"
  printf 'pub fn b() {}\n' > "$repo/crates/b/src/lib.rs"
  : > "$repo/.ubsignore"
  git -C "$repo" init -q && git -C "$repo" add -A
  cat > "$bin/ubs" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_UBS_ARGS"
target="${!#}"
mode=ok
case "$target" in crates/a) mode="$FAKE_UBS_A" ;; crates/b) mode="$FAKE_UBS_B" ;; esac
case " $* " in *" --format=jsonl "*) ;; *) printf '  CRITICAL (1 found)\n    fake finding in %s\n' "$target"; exit 1 ;; esac
case "$mode" in
  ok) printf '{"type":"totals","status":"ok","failed_modules":[],"files":3,"critical":0}\n'; exit 0 ;;
  empty) printf '{"type":"totals","status":"ok","failed_modules":[],"files":0,"critical":0}\n'; exit 0 ;;
  crit) printf '{"type":"totals","status":"ok","failed_modules":[],"files":3,"critical":2}\n'; exit 1 ;;
  partial) printf '{"type":"totals","status":"partial","failed_modules":["rust"],"files":3,"critical":0}\n'; exit 2 ;;
  crash) printf 'Segmentation fault\n'; exit 139 ;;
esac
EOF
  chmod +x "$bin/ubs"
  for case in "ok ok 0 PASS.ubs.crates/b" "crit ok 1 FAIL.ubs.crates/a" "ok partial 2 UNRUN.ubs.crates/b" \
    "crash ok 2 UNRUN.ubs.crates/a" "empty empty 2 UNRUN.no.file.was.in.scope"; do
    read -r a b want_rc want <<<"$case"
    : > "$base/ubs-args"
    PATH="$bin:$PATH" FAKE_UBS_A="$a" FAKE_UBS_B="$b" FAKE_UBS_ARGS="$base/ubs-args" \
      bash "$repo/scripts/ubs_scan.sh" --root "$repo" > "$base/ubs-$a-$b.out" 2>&1
    rc=$?
    if [ "$rc" -ne "$want_rc" ] || ! grep -Eq "^${want//./ }" "$base/ubs-$a-$b.out"; then
      gate_fail "ubs_scan_classifies_each_package_scan — a=$a b=$b: exit $rc (want $want_rc), want a line '${want//./ }': $(tr '\n' '|' < "$base/ubs-$a-$b.out")"
      return 1
    fi
    if grep -F -- '--format=jsonl' "$base/ubs-args" | grep -vqF -- "--no-cargo --no-color --exclude-tests --ignore-file=$repo/.ubsignore"; then
      gate_fail "ubs_scan_classifies_each_package_scan — a scan ran without the test-scope flags: $(tr '\n' '|' < "$base/ubs-args")"
      return 1
    fi
  done
  gate_pass "ubs_scan_classifies_each_package_scan (clean, critical, partial, crashed, nothing in scope)"
}

# run_gate runs a gate script with this run's step manifest read-only, and a
# script that changes the manifest anyway fails its own step: no gate script
# can erase the records of the steps before it.
run_gate_protects_the_step_manifest() {
  local dir="$base/run-gate"
  mkdir -p "$dir/logs"
  cat > "$dir/truncate.sh" <<'EOF'
#!/usr/bin/env bash
: > "$CHECK_STEP_MANIFEST" 2>/dev/null
exit 0
EOF
  cat > "$dir/append.sh" <<'EOF'
#!/usr/bin/env bash
chmod u+w "$CHECK_STEP_MANIFEST"
printf '{}\n' >> "$CHECK_STEP_MANIFEST"
exit 0
EOF
  (
    export CHECK_LOG_DIR="$dir/logs" CHECK_STEP_MANIFEST="$dir/step-verdicts.jsonl"
    # shellcheck source=../lib/gate_verdict.sh
    . "$SOURCE_ROOT/scripts/lib/gate_verdict.sh"
    gate_init "inner"
    # shellcheck disable=SC1090
    . "$harness"
    printf '{"step":"earlier","status":"PASS"}\n' >> "$STEP_MANIFEST"
    run_gate "truncating-script" "$dir/truncate.sh"
    run_gate "appending-script" "$dir/append.sh"
  ) > "$dir/stdout.log" 2>&1
  if ! head -n 1 "$dir/step-verdicts.jsonl" | grep -Fq '"step":"earlier"'; then
    gate_fail "run_gate_protects_the_step_manifest — an earlier step record was erased: $(head -c 200 "$dir/step-verdicts.jsonl")"
    return 1
  fi
  if ! grep -q "^FAIL appending-script changed this run's step manifest" "$dir/stdout.log"; then
    gate_fail "run_gate_protects_the_step_manifest — a script that changed the manifest did not fail its step: $(tr '\n' '|' < "$dir/stdout.log")"
    return 1
  fi
  gate_pass "run_gate_protects_the_step_manifest (truncation blocked, earlier record kept; a changed manifest fails the step)"
}

ssh_timeout_exit1_is_unrun
classifier_table_covers_rch_markers_and_exit_codes
split_test_jobs_compose_one_step
split_test_job_list_covers_the_workspace
check_summary_matches_the_proof_verifier
ubs_scan_classifies_each_package_scan
run_gate_protects_the_step_manifest

gate_verdict
