#!/usr/bin/env bash
# =============================================================================
# scripts/owner_watch.sh — Owner-line compile watch (bead fa-qu8v)
# =============================================================================
# Polls `git ls-remote <remote> <ref>` (default: origin refs/heads/main).
# For each new tip T not yet noted under `refs/notes/owner-watch`:
#   a. Checks T out into ONE permanent warm worktree
#      (`/data/projects/franken_accounting-watch`, reused so the rch pool stays warm).
#   b. Runs `cargo clippy --workspace --all-targets --keep-going -- -D warnings`
#      then `cargo test --workspace --no-fail-fast` through `rch` with
#      `RCH_REQUIRE_REMOTE=1`, classifying PASS/FAIL/UNRUN (an rch refusal is
#      UNRUN, never FAIL/RED).
#   c. Writes a git note on T under `refs/notes/owner-watch` and pushes the
#      notes ref.
#   d. On RED (FAIL): creates (or updates if one is already open for the same
#      first-error signature) a P0 repair bead "main red at <T>: <first error>"
#      with the de-ANSI'd error block, introducing commit, and tracker drift.
#   e. Never edits code, never pushes to main/staging, never resets developer state.
#
# Usage:
#   bash scripts/owner_watch.sh [--once] [--remote NAME|URL] [--ref REF]
#                               [--worktree DIR] [--log-file FILE] [--no-push] [--force]
#   bash scripts/owner_watch.sh --loop [--interval-secs 300] ...
#   bash scripts/owner_watch.sh --status [--remote NAME|URL] [--ref REF]
#   bash scripts/owner_watch.sh --self-test
# =============================================================================

set -uo pipefail

NOTES_REF="owner-watch"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/owner_watch.sh [--once] [--remote NAME|URL] [--ref REF]
                              [--worktree DIR] [--log-file FILE] [--no-push] [--force]
  bash scripts/owner_watch.sh --loop [--interval-secs N]
  bash scripts/owner_watch.sh --status [--remote NAME|URL] [--ref REF]
  bash scripts/owner_watch.sh --self-test
USAGE
}

die() {
  printf 'owner-watch: %s\n' "$*" >&2
  exit 2
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [ -f "$root/scripts/gate_workers.conf" ]; then
  # shellcheck source=gate_workers.conf
  . "$root/scripts/gate_workers.conf"
fi

mode="once"
remote="origin"
watched_ref="refs/heads/main"
worktree="${FA_WATCH_WORKTREE:-/data/projects/franken_accounting-watch}"
log_file="${FA_WATCH_LOG:-${TMPDIR:-/tmp}/fa-owner-watch.log}"
interval_secs=300
push_notes=1
force_eval=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --once) mode="once"; shift ;;
    --loop) mode="loop"; shift ;;
    --status) mode="status"; shift ;;
    --self-test) mode="selftest"; shift ;;
    --remote) [ "$#" -ge 2 ] || die "--remote needs a value"; remote="$2"; shift 2 ;;
    --ref) [ "$#" -ge 2 ] || die "--ref needs a value"; watched_ref="$2"; shift 2 ;;
    --worktree) [ "$#" -ge 2 ] || die "--worktree needs a value"; worktree="$2"; shift 2 ;;
    --log-file) [ "$#" -ge 2 ] || die "--log-file needs a value"; log_file="$2"; shift 2 ;;
    --interval-secs) [ "$#" -ge 2 ] || die "--interval-secs needs a value"; interval_secs="$2"; shift 2 ;;
    --no-push) push_notes=0; shift ;;
    --force) force_eval=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ "$mode" = "selftest" ]; then
  exec bash "$root/scripts/tests/owner_watch_selftest.sh"
fi

RCH_BIN="${FA_RCH_BIN:-rch}"
BR_BIN="${FA_BR_BIN:-br}"
CHECK_JOBS="${CHECK_JOBS:-2}"

de_ansi() {
  sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g'
}

extract_worker() {
  local f="$1" w=""
  if [ -f "$f" ]; then
    w="$(sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' "$f" | tail -n 1)"
  fi
  printf '%s\n' "${w:-unknown}"
}

classify_rch_step() {
  local rc="$1" log="$2" kind="$3"
  if [ "$rc" -eq 0 ]; then
    if ! grep -Fq 'Remote command finished: exit=0' "$log"; then
      printf 'UNRUN\n'
      return
    fi
    if [ "$kind" = "clippy" ] && ! grep -Eq '^[[:space:]]*Finished ' "$log"; then
      printf 'UNRUN\n'
      return
    fi
    if [ "$kind" = "test" ] && ! grep -Eq '^test result: ok\. ' "$log"; then
      printf 'UNRUN\n'
      return
    fi
    printf 'PASS\n'
    return
  fi
  local executed=0
  grep -Fq 'Remote command finished' "$log" && executed=1
  if [ "$rc" -eq 103 ] \
    || { [ "$executed" -eq 0 ] && { [ "$rc" -eq 100 ] || grep -Eiq '(\[RCH(-E[0-9]+)?\]|rch::).*(SSH command timed out|refusing local fallback|no local fallback|no admissible worker|completion unconfirmed|RCH_SCOPED_COMPLETION_UNCONFIRMED|Connection timed out|Connection refused|Broken pipe)|\[RCH-E[0-9]+\]|SSH command timed out|no admissible workers?|refusing local fallback|completion unconfirmed|RCH_SCOPED_COMPLETION_UNCONFIRMED' "$log"; }; }; then
    printf 'UNRUN\n'
  else
    printf 'FAIL\n'
  fi
}

print_status() {
  local remote_url tip note verdict recorded
  if ! remote_url="$(git -C "$root" remote get-url "$remote" 2>/dev/null)"; then
    remote_url="$remote"
  fi
  git -C "$root" fetch --quiet "$remote_url" \
    "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" 2>/dev/null || true
  tip="$(git -C "$root" ls-remote "$remote_url" "$watched_ref" 2>/dev/null | awk 'NR==1 {print $1}')"
  if [ -z "$tip" ]; then
    tip="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
  fi
  note="$(git -C "$root" notes --ref="$NOTES_REF" show "$tip" 2>/dev/null || true)"
  if [ -z "$note" ]; then
    printf 'main@%s: UNRUN since unrecorded\n' "${tip:0:8}"
    return 0
  fi
  verdict="$(sed -n 's/^verdict=//p' <<< "$note" | head -n 1)"
  recorded="$(sed -n 's/^recorded_utc=//p' <<< "$note" | head -n 1)"
  printf 'main@%s: %s since %s\n' "${tip:0:8}" "${verdict:-UNRUN}" "${recorded:-unknown}"
}

if [ "$mode" = "status" ]; then
  print_status
  exit 0
fi

evaluate_once() {
  local remote_url tip
  if ! remote_url="$(git -C "$root" remote get-url "$remote" 2>/dev/null)"; then
    remote_url="$remote"
  fi

  tip="$(git -C "$root" ls-remote "$remote_url" "$watched_ref" 2>/dev/null | awk 'NR==1 {print $1}')"
  [ -n "$tip" ] || die "could not resolve $watched_ref on $remote_url"

  # Ensure the permanent warm watch worktree exists and fetches latest commits + notes
  if [ ! -d "$worktree/.git" ] && [ ! -f "$worktree/.git" ]; then
    mkdir -p "$(dirname "$worktree")"
    git clone --quiet --reference-if-able "$root" --dissociate "$remote_url" "$worktree" \
      || die "cannot initialize warm watch worktree at $worktree"
  fi
  git -C "$worktree" fetch --quiet "$remote_url" \
    "+$watched_ref:refs/remotes/watch/target" \
    "+refs/heads/*:refs/remotes/watch/*" \
    "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" 2>/dev/null \
    || git -C "$worktree" fetch --quiet "$remote_url" "+$watched_ref:refs/remotes/watch/target" \
    || die "cannot fetch $watched_ref into $worktree"

  local existing_note
  existing_note="$(git -C "$worktree" notes --ref="$NOTES_REF" show "$tip" 2>/dev/null || true)"
  if [ -n "$existing_note" ] && [ "$force_eval" -eq 0 ]; then
    local prev_verdict
    prev_verdict="$(sed -n 's/^verdict=//p' <<< "$existing_note" | head -n 1)"
    if [ "$prev_verdict" = "GREEN" ] || [ "$prev_verdict" = "RED" ]; then
      printf 'owner-watch: tip %s already noted (%s); skipping\n' "${tip:0:12}" "$prev_verdict"
      return 0
    fi
  fi

  git -C "$worktree" checkout --quiet --detach "$tip" || die "cannot checkout $tip in $worktree"
  local tree_sha
  tree_sha="$(git -C "$worktree" rev-parse "${tip}^{tree}")"

  local run_dir="${TMPDIR:-/tmp}/fa-owner-watch-${tip:0:12}-$$"
  mkdir -p "$run_dir"
  mkdir -p "$(dirname "$log_file")"

  # Step 1: clippy --keep-going
  local clippy_log="$run_dir/clippy.log"
  local clippy_rc=0
  local ts_clippy
  ts_clippy="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    clippy_rc=103
    printf '[RCH] rch binary not found; refusing local fallback\n' > "$clippy_log"
  else
    (
      cd "$worktree"
      RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_WORKER="${FA_GATE_PRIMARY_WORKER:-hz2}" \
        "$RCH_BIN" exec -- cargo clippy -j "$CHECK_JOBS" --workspace --all-targets --keep-going -- -D warnings
    ) > "$clippy_log" 2>&1 || clippy_rc=$?
  fi
  local clippy_verdict clippy_worker
  clippy_verdict="$(classify_rch_step "$clippy_rc" "$clippy_log" "clippy")"
  clippy_worker="$(extract_worker "$clippy_log")"
  printf '=== %s tip=%s step=clippy verdict=%s rc=%s worker=%s\n' \
    "$ts_clippy" "$tip" "$clippy_verdict" "$clippy_rc" "$clippy_worker" >> "$log_file"

  # Step 2: test --no-fail-fast (runs when clippy is PASS, or skipped if clippy is FAIL/UNRUN)
  local test_log="$run_dir/test.log"
  local test_rc=0
  local test_verdict="UNRUN"
  local test_worker="$clippy_worker"
  local ts_test
  ts_test="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$clippy_verdict" = "PASS" ]; then
    (
      cd "$worktree"
      RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_WORKER="${FA_GATE_PRIMARY_WORKER:-hz2}" \
        "$RCH_BIN" exec -- cargo test -j "$CHECK_JOBS" --workspace --no-fail-fast
    ) > "$test_log" 2>&1 || test_rc=$?
    test_verdict="$(classify_rch_step "$test_rc" "$test_log" "test")"
    test_worker="$(extract_worker "$test_log")"
    printf '=== %s tip=%s step=test verdict=%s rc=%s worker=%s\n' \
      "$ts_test" "$tip" "$test_verdict" "$test_rc" "$test_worker" >> "$log_file"
  fi

  local overall_verdict="UNRUN"
  if [ "$clippy_verdict" = "FAIL" ] || [ "$test_verdict" = "FAIL" ]; then
    overall_verdict="RED"
  elif [ "$clippy_verdict" = "PASS" ] && [ "$test_verdict" = "PASS" ]; then
    overall_verdict="GREEN"
  else
    overall_verdict="UNRUN"
  fi

  local test_passed=0 test_failed=0
  if [ -f "$test_log" ]; then
    test_passed="$(awk '/^test result:/ { for (i = 1; i <= NF; i++) if ($i == "passed;") sum += $(i - 1) } END { print sum + 0 }' "$test_log")"
    test_failed="$(awk '/^test result:/ { for (i = 1; i <= NF; i++) if ($i == "failed;") sum += $(i - 1) } END { print sum + 0 }' "$test_log")"
  fi

  local first_error=""
  local error_block=""
  if [ "$overall_verdict" = "RED" ]; then
    local fail_log="$clippy_log"
    [ "$clippy_verdict" = "FAIL" ] || fail_log="$test_log"
    first_error="$(de_ansi < "$fail_log" | grep -E '^(error(\[E[0-9]+\])?:|thread .* panicked at|FAILED)' | head -n 1 || true)"
    [ -n "$first_error" ] || first_error="compile or test failure (exit ${clippy_rc}/${test_rc})"
    error_block="$(de_ansi < "$fail_log" | grep -E -A 6 '^(error(\[E[0-9]+\])?:|thread .* panicked at)' | head -n 30 || true)"
  fi

  # Tracker drift check over the last 10 commits on the watched ref
  local no_bead_commits
  no_bead_commits="$(git -C "$worktree" log -n 10 --format='%h %s' "$tip" 2>/dev/null \
    | grep -Ev 'fa-[a-z0-9]+' | head -n 5 | tr '\n' ';' || true)"

  # Gate capacity & disk headroom summary from scripts/gate_health.sh (fa-abhg)
  local gate_health_summary=""
  if [ -r "$ROOT/scripts/gate_health.sh" ]; then
    gate_health_summary="$(bash "$ROOT/scripts/gate_health.sh" --repo "$worktree" 2>/dev/null \
      | sed -n 's/^GATE_HEALTH_SUMMARY=//p' | tail -n 1 || true)"
  fi

  local recorded_utc
  recorded_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local note_text
  note_text="$(
    printf 'owner-watch v1\n'
    printf 'verdict=%s\n' "$overall_verdict"
    printf 'commit=%s\n' "$tip"
    printf 'tree=%s\n' "$tree_sha"
    printf 'recorded_utc=%s\n' "$recorded_utc"
    printf 'worker=%s\n' "$test_worker"
    printf 'steps=clippy:%s,test:%s\n' "$clippy_verdict" "$test_verdict"
    printf 'test_totals=passed:%s,failed:%s\n' "$test_passed" "$test_failed"
    [ -n "$gate_health_summary" ] && printf 'gate_health=%s\n' "$gate_health_summary"
    [ -n "$first_error" ] && printf 'first_error=%s\n' "$first_error"
    [ -n "$no_bead_commits" ] && printf 'tracker_drift_no_bead=%s\n' "$no_bead_commits"
  )"

  git -C "$worktree" -c user.name="fa owner-watch" -c user.email="owner-watch@localhost" \
    notes --ref="$NOTES_REF" add -f -m "$note_text" "$tip"
  local note_id
  note_id="$(git -C "$worktree" notes --ref="$NOTES_REF" list "$tip" 2>/dev/null | awk '{print $1}' || echo none)"
  if [ "$push_notes" -eq 1 ]; then
    git -C "$worktree" push --quiet "$remote_url" "refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" 2>/dev/null || true
  fi

  if [ "$overall_verdict" = "RED" ]; then
    local short_tip="${tip:0:8}"
    local bead_title="main red at ${short_tip}: ${first_error}"
    local intro_commit
    intro_commit="$(git -C "$worktree" log -n 1 --format='%h %s (%an)' "$tip" 2>/dev/null || echo "$short_tip")"
    local bead_desc
    bead_desc="$(
      printf 'Automated owner_watch.sh RED report at %s\n' "$recorded_utc"
      printf 'Commit: %s (tree %s)\n' "$tip" "$tree_sha"
      printf 'Introducing commit candidate: %s\n' "$intro_commit"
      printf 'Steps: clippy=%s (rc=%s), test=%s (rc=%s) on worker %s\n\n' \
        "$clippy_verdict" "$clippy_rc" "$test_verdict" "$test_rc" "$test_worker"
      printf 'De-ANSI compiler/test error output:\n%s\n' "$error_block"
    )"
    if command -v "$BR_BIN" >/dev/null 2>&1; then
      "$BR_BIN" create --title "$bead_title" --priority 0 --type bug --description "$bead_desc" >/dev/null 2>&1 || true
    fi
  fi

  printf 'OWNER_WATCH_%s commit=%s tree=%s note_id=%s clippy=%s test=%s worker=%s\n' \
    "$overall_verdict" "$tip" "$tree_sha" "${note_id:-none}" "$clippy_verdict" "$test_verdict" "$test_worker"
  case "$overall_verdict" in
    GREEN) return 0 ;;
    RED) return 1 ;;
    UNRUN) return 2 ;;
  esac
}

if [ "$mode" = "once" ]; then
  evaluate_once
  exit $?
fi

while true; do
  evaluate_once || true
  sleep "$interval_secs"
done
