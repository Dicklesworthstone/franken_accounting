#!/usr/bin/env bash
# =============================================================================
# scripts/tier0.sh — Tier 0: the tree is formatted and every target type-checks
# (bead fa-1qk0). .github/workflows/tier0.yml is the same two steps as a
# hosted recipe for manual dispatch. Tier 0 says nothing about test results.
# =============================================================================
# Verdict contract (scripts/lib/gate_verdict.sh):
#   1. `cargo fmt --all --check`
#   2. `rch exec -- cargo check --workspace --all-targets` with the same
#      completion-marker rules as scripts/check.sh (`Remote command finished:
#      exit=0` + `Finished `).
#   3. Availability (WHAT 5): when the `rch` fleet refuses to execute due to
#      disk/capacity pressure ("no admissible workers", exit 103, or exit 100
#      / refusing local fallback / completion unconfirmed with no remote
#      execution), `tier0.sh` falls back to the local lane on the gate host
#      (`RCH_CARGO_WRAPPER_BYPASS=1 cargo check ...`) unless
#      `TIER0_DISABLE_LOCAL_FALLBACK=1` is set (which reports `UNRUN`).
#      Every run records the tree hash, toolchain, lane (`remote` or `local`),
#      host fingerprint, step verdicts, and durations, and writes a git note
#      under `refs/notes/fa-tier0` on a clean PASS tree.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEFAULT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

usage() {
  cat <<'USAGE'
Usage: bash scripts/tier0.sh [--repository DIR] [--log-dir DIR]
                             [--publish-note] [--push-note] [--remote NAME|URL]
                             [--no-note] [--require-clean]
USAGE
}

repo="$DEFAULT_ROOT"
log_dir="${TIER0_LOG_DIR:-}"
publish_note="${TIER0_PUBLISH_NOTE:-1}"
push_note=0
remote="origin"
require_clean=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      if [ "$#" -lt 2 ]; then
        printf 'FAIL tier0: --repository requires a path\n'
        exit 2
      fi
      repo="$2"
      shift 2
      ;;
    --log-dir)
      if [ "$#" -lt 2 ]; then
        printf 'FAIL tier0: --log-dir requires a path\n'
        exit 2
      fi
      log_dir="$2"
      shift 2
      ;;
    --publish-note)
      publish_note=1
      shift
      ;;
    --push-note)
      publish_note=1
      push_note=1
      shift
      ;;
    --remote)
      if [ "$#" -lt 2 ]; then
        printf 'FAIL tier0: --remote requires a name or URL\n'
        exit 2
      fi
      remote="$2"
      shift 2
      ;;
    --no-note)
      publish_note=0
      push_note=0
      shift
      ;;
    --require-clean)
      require_clean=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'FAIL tier0: unknown argument %s\n' "$1"
      exit 2
      ;;
  esac
done

if [ ! -d "$repo" ]; then
  printf 'FAIL tier0: repository directory does not exist: %s\n' "$repo"
  exit 2
fi
cd "$repo" || exit 2

if [ -r "$SCRIPT_DIR/lib/gate_verdict.sh" ]; then
  # shellcheck source=lib/gate_verdict.sh
  . "$SCRIPT_DIR/lib/gate_verdict.sh"
elif [ -r "$repo/scripts/lib/gate_verdict.sh" ]; then
  # shellcheck source=lib/gate_verdict.sh
  . "$repo/scripts/lib/gate_verdict.sh"
else
  printf 'FAIL tier0: scripts/lib/gate_verdict.sh not found\n'
  exit 2
fi

gate_init "tier0"

if [ -z "$log_dir" ]; then
  log_dir="$(mktemp -d "${TMPDIR:-/tmp}/fa-tier0.XXXXXX")"
else
  mkdir -p "$log_dir"
fi
STEP_MANIFEST="$log_dir/step-verdicts.jsonl"
: > "$STEP_MANIFEST"

CARGO_BIN="${FA_CARGO_BIN:-cargo}"
RCH_BIN="${FA_RCH_BIN:-rch}"
TIER0_JOBS="${TIER0_JOBS:-2}"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
base_tree="$(git rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)"
tree="$base_tree"
dirty=0
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  dirty=1
  tree="${base_tree}+dirty"
fi

if [ "$require_clean" -eq 1 ] && [ "$dirty" -eq 1 ]; then
  gate_fail "worktree tier0 FAIL step=worktree tree=$tree — working tree has uncommitted tracked changes"
  gate_verdict
  exit $?
fi

toolchain="$(rustc --version 2>/dev/null || "$CARGO_BIN" --version 2>/dev/null || echo unavailable)"
toolchain_id="$(printf '%s' "$toolchain" | tr ' \t' '__')"
host_name="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown-host)"
host_arch="$(uname -s 2>/dev/null || echo unknown)-$(uname -m 2>/dev/null || echo unknown)"
host_fp="${TIER0_HOST_FINGERPRINT:-${host_name}:${host_arch}}"

hash_file() {
  local f="$1"
  if [ ! -f "$f" ]; then
    printf 'none\n'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    printf 'unavailable\n'
  fi
}

extract_worker() {
  local f="$1"
  local w=""
  if [ -f "$f" ]; then
    w="$(sed -n 's/.*Selected worker: \([^ ]*\) at .*/\1/p' "$f" | tail -n 1)"
    if [ -z "$w" ]; then
      w="$(sed -n 's/^\[RCH\] remote \([^ ]*\) (.*/\1/p' "$f" | tail -n 1)"
    fi
    if [ -z "$w" ] && grep -q '^\[RCH\]' "$f"; then
      w="unassigned"
    fi
  fi
  printf '%s\n' "${w:-local}"
}

record_step_verdict() {
  local step="$1" status="$2" lane="$3" worker="$4" started="$5" finished="$6" duration="$7" log_file="$8"
  local log_digest
  log_digest="$(hash_file "$log_file")"
  printf '{"step":"%s","status":"%s","tree_hash":"%s","commit":"%s","toolchain":"%s","lane":"%s","host":"%s","worker":"%s","started":"%s","finished":"%s","duration_secs":%s,"log_digest":"%s"}\n' \
    "$step" "$status" "$tree" "$commit" "$toolchain" "$lane" "$host_fp" "$worker" "$started" "$finished" "${duration:-0}" "$log_digest" \
    >> "$STEP_MANIFEST"
}

gate_diag "tier0: commit=$commit tree=$tree toolchain=\"$toolchain\" host=$host_fp log_dir=$log_dir"

# -----------------------------------------------------------------------------
# Step 1: cargo fmt --all --check
# -----------------------------------------------------------------------------
fmt_log="$log_dir/fmt.log"
fmt_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fmt_t0="$(date +%s)"
fmt_dur=0
fmt_status="PASS"

if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  fmt_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  record_step_verdict "fmt" "UNRUN" "local" "local" "$fmt_started" "$fmt_finished" 0 "$fmt_log"
  gate_unrun "fmt tier0 UNRUN step=fmt tree=$tree lane=local host=$host_fp toolchain=$toolchain_id duration=0s — $CARGO_BIN is not installed; log: $fmt_log"
  fmt_status="UNRUN"
else
  "$CARGO_BIN" fmt --all --check >"$fmt_log" 2>&1
  fmt_rc=$?
  fmt_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fmt_t1="$(date +%s)"
  fmt_dur=$((fmt_t1 - fmt_t0))
  if [ "$fmt_rc" -eq 0 ]; then
    record_step_verdict "fmt" "PASS" "local" "local" "$fmt_started" "$fmt_finished" "$fmt_dur" "$fmt_log"
    gate_pass "fmt tier0 PASS step=fmt tree=$tree lane=local host=$host_fp toolchain=$toolchain_id duration=${fmt_dur}s"
    fmt_status="PASS"
  else
    record_step_verdict "fmt" "FAIL" "local" "local" "$fmt_started" "$fmt_finished" "$fmt_dur" "$fmt_log"
    gate_fail "fmt tier0 FAIL step=fmt exit=$fmt_rc tree=$tree lane=local host=$host_fp toolchain=$toolchain_id duration=${fmt_dur}s; log: $fmt_log"
    gate_diag "---- fmt: last 40 lines of $fmt_log"
    tail -n 40 "$fmt_log" >&2
    fmt_status="FAIL"
  fi
fi

# -----------------------------------------------------------------------------
# Step 2: cargo check --workspace --all-targets (remote via rch, local fallback)
# -----------------------------------------------------------------------------
check_log="$log_dir/check.log"
check_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check_t0="$(date +%s)"
check_dur=0
check_lane="remote"
check_worker="local"
check_status="UNRUN"
remote_refused=0
remote_reason=""
check_rc=0

if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  check_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  record_step_verdict "check" "UNRUN" "none" "none" "$check_started" "$check_finished" 0 "$check_log"
  gate_unrun "check tier0 UNRUN step=check tree=$tree lane=none host=$host_fp toolchain=$toolchain_id duration=0s — $CARGO_BIN is not installed; log: $check_log"
else
  if [ "${TIER0_FORCE_LOCAL:-0}" = "1" ]; then
    remote_refused=1
    remote_reason="TIER0_FORCE_LOCAL=1"
  elif command -v "$RCH_BIN" >/dev/null 2>&1; then
    RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
      "$RCH_BIN" exec -- "$CARGO_BIN" check -j "$TIER0_JOBS" --workspace --all-targets >"$check_log" 2>&1
    check_rc=$?
    check_worker="$(extract_worker "$check_log")"
    if [ "$check_rc" -eq 0 ]; then
      if grep -Fq 'Remote command finished: exit=0' "$check_log" \
        && grep -Eq '^[[:space:]]*Finished ' "$check_log"; then
        check_lane="remote"
        check_status="PASS"
      else
        remote_refused=1
        remote_reason="remote exit 0 without 'Remote command finished: exit=0' and 'Finished' completion markers"
      fi
    else
      executed=0
      grep -q 'Remote command finished' "$check_log" && executed=1
      if [ "$check_rc" -eq 103 ] \
        || { [ "$executed" -eq 0 ] && { [ "$check_rc" -eq 100 ] || grep -Eq '(\[RCH\].*(refusing local fallback|completion unconfirmed|no admissible worker)|no admissible workers|workers critical|disk pressure)' "$check_log"; }; }; then
        remote_refused=1
        remote_reason="rch offloader did not execute command (exit $check_rc)"
      else
        check_lane="remote"
        check_status="FAIL"
      fi
    fi
  else
    remote_refused=1
    remote_reason="$RCH_BIN is not installed"
  fi

  if [ "$remote_refused" -eq 1 ]; then
    if [ "${TIER0_DISABLE_LOCAL_FALLBACK:-0}" = "1" ]; then
      check_lane="remote-refused"
      check_worker="none"
      check_status="UNRUN"
    else
      gate_diag "tier0: remote lane unavailable ($remote_reason); running local lane on $host_fp"
      if [ -f "$check_log" ] && [ -s "$check_log" ]; then
        cp "$check_log" "$check_log.remote" 2>/dev/null || true
        printf '\n=== tier0 local-lane fallback on %s (%s) ===\n' "$host_fp" "$remote_reason" >>"$check_log"
      else
        : > "$check_log"
      fi
      RCH_CARGO_WRAPPER_BYPASS=1 \
        "$CARGO_BIN" check -j "$TIER0_JOBS" --workspace --all-targets >>"$check_log" 2>&1
      check_rc=$?
      check_lane="local"
      check_worker="local"
      if [ "$check_rc" -eq 0 ]; then
        if grep -Eq '^[[:space:]]*Finished ' "$check_log"; then
          check_status="PASS"
        else
          check_status="UNRUN"
          remote_reason="local lane exited 0 without cargo 'Finished' completion marker"
        fi
      else
        check_status="FAIL"
      fi
    fi
  fi

  check_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  check_t1="$(date +%s)"
  check_dur=$((check_t1 - check_t0))
  record_step_verdict "check" "$check_status" "$check_lane" "$check_worker" "$check_started" "$check_finished" "$check_dur" "$check_log"

  case "$check_status" in
    PASS)
      gate_pass "check tier0 PASS step=check tree=$tree lane=$check_lane host=$host_fp worker=$check_worker toolchain=$toolchain_id duration=${check_dur}s"
      ;;
    UNRUN)
      gate_unrun "check tier0 UNRUN step=check exit=$check_rc tree=$tree lane=$check_lane host=$host_fp toolchain=$toolchain_id duration=${check_dur}s — $remote_reason; log: $check_log"
      ;;
    *)
      gate_fail "check tier0 FAIL step=check exit=$check_rc tree=$tree lane=$check_lane host=$host_fp worker=$check_worker toolchain=$toolchain_id duration=${check_dur}s; log: $check_log"
      gate_diag "---- check: last 40 lines of $check_log"
      tail -n 40 "$check_log" >&2
      ;;
  esac
fi

# -----------------------------------------------------------------------------
# Summary file and git note under refs/notes/fa-tier0
# -----------------------------------------------------------------------------
overall_verdict="red"
if [ "$fmt_status" = "PASS" ] && [ "$check_status" = "PASS" ]; then
  if gate_check_tree_stable; then
    overall_verdict="pass"
  else
    overall_verdict="void"
  fi
elif [ "$fmt_status" = "UNRUN" ] || [ "$check_status" = "UNRUN" ]; then
  overall_verdict="unrun"
fi

{
  printf 'tier0 v1\n'
  printf 'verdict=%s\n' "$overall_verdict"
  printf 'commit=%s\n' "$commit"
  printf 'tree=%s\n' "$tree"
  printf 'lane=%s\n' "$check_lane"
  printf 'host=%s\n' "$host_fp"
  printf 'worker=%s\n' "$check_worker"
  printf 'toolchain=%s\n' "$toolchain"
  printf 'fmt_status=%s\n' "$fmt_status"
  printf 'fmt_seconds=%s\n' "$fmt_dur"
  printf 'check_status=%s\n' "$check_status"
  printf 'check_seconds=%s\n' "$check_dur"
  printf 'log_dir=%s\n' "$log_dir"
  printf 'recorded_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$log_dir/tier0-summary.txt"

if [ "$overall_verdict" = "pass" ] && [ "$dirty" -eq 0 ] && [ "$publish_note" -eq 1 ]; then
  git notes --ref=fa-tier0 add -f -F "$log_dir/tier0-summary.txt" "$commit" >/dev/null 2>&1 || true
  if [ "$push_note" -eq 1 ]; then
    # Another publisher moves the remote notes ref, and a plain push of ours
    # is then refused as non-fast-forward. Merge the remote notes (keeping
    # this run's note only where both name this commit) and retry; a note
    # that still cannot be published is reported, never silently local.
    note_pushed=0
    for _ in 1 2 3; do
      if git push --quiet "$remote" "refs/notes/fa-tier0:refs/notes/fa-tier0" >/dev/null 2>&1; then
        note_pushed=1
        break
      fi
      git fetch --quiet "$remote" "+refs/notes/fa-tier0:refs/notes/fa-tier0-remote" >/dev/null 2>&1 || true
      git notes --ref=fa-tier0 merge -q -s ours refs/notes/fa-tier0-remote >/dev/null 2>&1 || true
    done
    [ "$note_pushed" -eq 1 ] \
      || gate_diag "tier0: the $overall_verdict note for $commit is recorded locally but was not published to $remote"
  fi
fi

gate_verdict
