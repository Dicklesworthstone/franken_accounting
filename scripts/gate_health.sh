#!/usr/bin/env bash
# =============================================================================
# scripts/gate_health.sh — Designated gate worker capacity & disk health check
# (bead fa-abhg)
#
# Reports designated-worker slot/disk metadata and repository-wide recorded
# PASS note timestamps and timings under the gate_verdict.sh contract.
# Dispatch-time admission guards remain authoritative for actual capacity.
#
# Usage:
#   bash scripts/gate_health.sh [options]
#
# Options:
#   --status-json <path>         Read rch status JSON from file instead of live CLI
#   --repo <path>                Git repository to inspect for tier-0/tier-1 notes
#   --workers <csv>              Comma-separated worker IDs (default: FA_GATE_WORKERS)
#   --min-free-gb <float>        Minimum free disk GB per worker (default: 15.0)
#   --min-free-pct <float>       Minimum free disk % per worker (default: 2.5)
#   --min-admissible-slots <int> Minimum metadata slot estimate across pool (default: 1)
#   --janitor-plan               Print target-pool disk budget & age-sweep policy
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Hooks export repository-local Git variables that override even `git -C`.
# This helper always inspects its explicit repository, never that caller state.
git_local_env="$(git rev-parse --local-env-vars)"
git_env_rc=$?
if [ "$git_env_rc" -ne 0 ]; then
  printf 'UNRUN gate-health-git-context: could not inspect Git environment (rc=%s)\n' "$git_env_rc"
  printf 'FAIL gate-health-git-context: repository isolation did not run\n'
  exit 2
fi
while IFS= read -r git_variable; do
  [ -z "$git_variable" ] || unset "$git_variable"
done <<<"$git_local_env"
# shellcheck source=lib/gate_verdict.sh
source "$ROOT/scripts/lib/gate_verdict.sh"
if [ -r "$ROOT/scripts/gate_workers.conf" ]; then
  # shellcheck source=gate_workers.conf
  source "$ROOT/scripts/gate_workers.conf"
fi

STATUS_JSON_FILE=""
REPO_PATH="$ROOT"
WORKERS_CSV="${FA_GATE_WORKERS:-hz2,vmi1152480}"
MIN_FREE_GB="${FA_GATE_MIN_FREE_GB:-15.0}"
MIN_FREE_PCT="${FA_GATE_MIN_FREE_PCT:-2.5}"
MIN_ADMISSIBLE_SLOTS="${FA_GATE_MIN_ADMISSIBLE_SLOTS:-1}"
PRINT_JANITOR_PLAN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --status-json | --repo | --workers | --min-free-gb | --min-free-pct | --min-admissible-slots)
      if [ "$#" -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
        printf 'FAIL gate-health-usage: %s requires a value\n' "$1"
        exit 2
      fi
      ;;
  esac
  case "$1" in
    --status-json)
      STATUS_JSON_FILE="${2:-}"
      shift 2
      ;;
    --repo)
      REPO_PATH="${2:-}"
      shift 2
      ;;
    --workers)
      WORKERS_CSV="${2:-}"
      shift 2
      ;;
    --min-free-gb)
      MIN_FREE_GB="${2:-}"
      shift 2
      ;;
    --min-free-pct)
      MIN_FREE_PCT="${2:-}"
      shift 2
      ;;
    --min-admissible-slots)
      MIN_ADMISSIBLE_SLOTS="${2:-}"
      shift 2
      ;;
    --janitor-plan)
      PRINT_JANITOR_PLAN=1
      shift
      ;;
    -h | --help)
      sed -n '2,23p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      printf 'FAIL gate-health-usage: unknown option: %s\n' "$1"
      exit 2
      ;;
  esac
done

if [ "$PRINT_JANITOR_PLAN" -eq 1 ]; then
  cat <<EOF
GATE_DISK_BUDGET_POLICY
canonical_gate_worktree=${FA_GATE_WORKTREE:-/data/projects/franken_accounting-gate}
watch_worktree=${FA_WATCH_WORKTREE:-/data/projects/franken_accounting-watch}
designated_workers=${WORKERS_CSV}
min_free_gb=${MIN_FREE_GB}
min_free_pct=${MIN_FREE_PCT}
pool_retention_policy=retain canonical gate and watch pools; sweep ad-hoc .rch-target-* pools older than 7 days via cargo clean --offline when disk_free_gb < ${MIN_FREE_GB}
EOF
fi

gate_init "gate-health"

TMP_STATUS=""
cleanup() {
  if [ -n "$TMP_STATUS" ] && [ -f "$TMP_STATUS" ]; then
    rm -f "$TMP_STATUS"
  fi
}
trap cleanup EXIT

if [ -n "$STATUS_JSON_FILE" ]; then
  if [ ! -r "$STATUS_JSON_FILE" ]; then
    gate_unrun "rch-status" "status JSON file not readable: $STATUS_JSON_FILE"
    gate_verdict
    exit $?
  fi
else
  if ! command -v rch >/dev/null 2>&1; then
    gate_unrun "rch-status" "rch binary not found in PATH"
    gate_verdict
    exit $?
  fi
  TMP_STATUS="$(mktemp "${TMPDIR:-/tmp}/fa-gate-health-status.XXXXXX")"
  rch status --json >"$TMP_STATUS"
  rc=$?
  if [ "$rc" -ne 0 ] || [ ! -s "$TMP_STATUS" ]; then
    gate_unrun "rch-status" "rch status --json failed (rc=$rc)"
    gate_verdict
    exit $?
  fi
  STATUS_JSON_FILE="$TMP_STATUS"
fi

EVAL_OUT="$(python3 - "$STATUS_JSON_FILE" "$REPO_PATH" "$WORKERS_CSV" "$MIN_FREE_GB" "$MIN_FREE_PCT" "$MIN_ADMISSIBLE_SLOTS" <<'PY'
import json
from datetime import datetime
import math
import re
import subprocess
import sys

status_file, repo_path, workers_csv, min_gb_s, min_pct_s, min_slots_s = sys.argv[1:7]
designated = list(dict.fromkeys(w.strip() for w in workers_csv.split(",") if w.strip()))

def finite_number(value, label, maximum=None):
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite nonnegative number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{label} must be a finite nonnegative number") from exc
    if not math.isfinite(number) or number < 0 or (maximum is not None and number > maximum):
        raise ValueError(f"{label} is outside its finite nonnegative domain")
    return number

def slot_count(value, label):
    if type(value) is int:
        number = value
    elif isinstance(value, str) and re.fullmatch(r"\+?[0-9]+", value.strip(), re.ASCII):
        number = int(value)
    else:
        raise ValueError(f"{label} must be a nonnegative whole slot count")
    if number < 0:
        raise ValueError(f"{label} must be a nonnegative whole slot count")
    return number

try:
    min_gb = finite_number(min_gb_s, "minimum free GB")
    min_pct = finite_number(min_pct_s, "minimum free percentage", 100)
    min_slots = slot_count(min_slots_s, "minimum slots")
    if not designated:
        raise ValueError("at least one worker ID is required")
except ValueError as exc:
    print(f"UNRUN\tgate-health-arguments\t{exc}")
    sys.exit(0)

def git_out(args):
    p = subprocess.run(["git", "-C", repo_path] + args, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""

def latest_pass_note(ref, time_field):
    # Git lists notes by object ID, not execution time. These are recorded
    # metadata summaries, not independent verification of their proof bundles.
    latest = None
    for row in git_out(["notes", f"--ref={ref}", "list"]).splitlines():
        parts = row.split()
        if len(parts) != 2:
            continue
        commit = parts[1]
        body = git_out(["notes", f"--ref={ref}", "show", commit])
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        if fields.get("verdict", "").lower() != "pass":
            continue
        if fields.get("check_exit", "0") != "0" or fields.get("tree_stable", "true") != "true":
            continue
        stamp = fields.get(time_field, "")
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None or (latest is not None and (when, commit) <= latest[:2]):
            continue
        duration = None
        try:
            if "duration_ms" in fields:
                duration = int(fields["duration_ms"])
            elif time_field == "recorded_utc":
                seconds = [int(fields[key]) for key in ("fmt_seconds", "check_seconds")]
                if all(value >= 0 for value in seconds):
                    duration = sum(seconds) * 1000
            else:
                steps = [json.loads(line.split("=", 1)[1]) for line in body.splitlines()
                         if line.startswith("step_verdict=")]
                if steps and all(isinstance(step, dict)
                                 and type(step.get("duration_ms")) is int
                                 and step["duration_ms"] >= 0 for step in steps):
                    duration = sum(step["duration_ms"] for step in steps)
        except (KeyError, TypeError, ValueError):
            pass
        if duration is not None and duration < 0:
            duration = None
        latest = (when, commit, stamp, duration)
    return (latest[1][:12], latest[2], latest[3]) if latest else ("none", "none", None)

def duration_text(value):
    return "unknown" if value is None else f"{value}ms"

def invalid_json_constant(value):
    raise ValueError(f"nonfinite JSON number {value}")

try:
    with open(status_file, "r", encoding="utf-8") as stream:
        raw = json.load(stream, parse_constant=invalid_json_constant)
except Exception as exc:
    print(f"UNRUN\trch-status\tinvalid status JSON: {exc}")
    sys.exit(0)

workers_list = (
    raw.get("data", {}).get("daemon", {}).get("workers")
    or raw.get("workers")
    or []
)
by_id = {w.get("id"): w for w in workers_list if isinstance(w, dict) and w.get("id")}

# Validate every selected worker before emitting any PASS. Missing telemetry
# cannot become a full disk or an extra slot through defaults or truncation.
metrics = {}
invalid_metrics = False
for wid in designated:
    w = by_id.get(wid)
    if w is None:
        continue
    try:
        used = slot_count(w.get("used_slots"), "used slots")
        total = slot_count(w.get("total_slots"), "total slots")
        if used > total:
            raise ValueError("used slots exceed total slots")
        free_value = w.get("pressure_disk_free_gb")
        if free_value is None:
            free_value = w.get("disk_free_gb")
        free_gb = finite_number(free_value, "free disk GB")
        ratio = w.get("pressure_disk_free_ratio")
        if ratio is not None:
            free_pct = finite_number(ratio, "free disk ratio", 1) * 100
        elif w.get("pressure_disk_total_gb") is not None:
            total_gb = finite_number(w["pressure_disk_total_gb"], "total disk GB")
            if total_gb == 0:
                raise ValueError("total disk GB cannot establish a percentage")
            free_pct = finite_number(free_gb / total_gb * 100, "free disk percentage", 100)
        else:
            free_pct = finite_number(w.get("disk_free_pct"), "free disk percentage", 100)
        metrics[wid] = (used, total, free_gb, free_pct)
    except ValueError as exc:
        print(f"UNRUN\tworker-{wid}-metrics\t{exc}")
        invalid_metrics = True
if invalid_metrics:
    sys.exit(0)

last_tier0_commit, last_tier0_utc, last_tier0_ms = latest_pass_note("refs/notes/fa-tier0", "recorded_utc")
last_tier1_commit, last_tier1_utc, last_tier1_ms = latest_pass_note("refs/notes/fa-verdict", "finished_utc")

estimated_slots = 0
summary_workers = []

for wid in designated:
    w = by_id.get(wid)
    if w is None:
        print(f"FAIL\tworker-{wid}\tdesignated worker {wid} missing from rch status")
        continue
    status = str(w.get("status", "unknown"))
    circuit = str(w.get("circuit_state", "unknown"))
    used_slots, total_slots, free_gb, free_pct = metrics[wid]
    free_slots = total_slots - used_slots
    pressure = str(w.get("pressure_state", "unknown"))

    print(
        f"LOG\tGATE_HEALTH_WORKER worker={wid} status={status} circuit={circuit} "
        f"slots={free_slots}/{total_slots} pressure={pressure} "
        f"disk_free_gb={free_gb:.1f} disk_free_pct={free_pct:.1f}% "
        f"last_tier0_duration={duration_text(last_tier0_ms)} last_tier1_duration={duration_text(last_tier1_ms)}"
    )

    worker_ok = True
    if free_gb < min_gb or free_pct < min_pct:
        print(
            f"FAIL\tworker-{wid}-disk\tworker {wid} below disk threshold "
            f"(free={free_gb:.1f}GB / {free_pct:.1f}%, min={min_gb:.1f}GB / {min_pct:.1f}%, pressure={pressure})"
        )
        worker_ok = False
    if pressure == "critical":
        print(
            f"FAIL\tworker-{wid}-pressure\tworker {wid} under critical pressure "
            f"(pressure={pressure}, free_disk={free_gb:.1f}GB / {free_pct:.1f}%)"
        )
        worker_ok = False
    if status != "healthy" or circuit != "closed":
        print(
            f"FAIL\tworker-{wid}-health\tworker {wid} not healthy/closed "
            f"(status={status}, circuit={circuit})"
        )
        worker_ok = False

    if worker_ok:
        estimated_slots += free_slots
        print(
            f"PASS\tworker-{wid}\tslots={free_slots}/{total_slots} "
            f"disk_free={free_gb:.1f}GB ({free_pct:.1f}%) pressure={pressure}"
        )

    summary_workers.append({
        "worker": wid,
        "status": status,
        "circuit": circuit,
        "free_slots": free_slots,
        "total_slots": total_slots,
        "pressure_state": pressure,
        "disk_free_gb": round(free_gb, 2),
        "disk_free_pct": round(free_pct, 2),
        "metadata_healthy": worker_ok,
    })

if estimated_slots < min_slots:
    print(
        f"FAIL\tgate-capacity\testimated_admissible_slots={estimated_slots} below min_admissible_slots={min_slots} "
        f"across designated workers ({','.join(designated)})"
    )
else:
    print(
        f"PASS\tgate-capacity\testimated_admissible_slots={estimated_slots} (min={min_slots}); "
        f"worker metadata only, dispatch admission guards remain authoritative; "
        f"last_tier0={last_tier0_commit}@{last_tier0_utc}({duration_text(last_tier0_ms)}) "
        f"last_tier1={last_tier1_commit}@{last_tier1_utc}({duration_text(last_tier1_ms)})"
    )

summary = {
    "designated_workers": designated,
    "estimated_admissible_slots": estimated_slots,
    "capacity_basis": "worker_status_metadata",
    "admission_checked": False,
    "history_scope": "repository_recorded_pass_metadata",
    "min_free_gb": min_gb,
    "min_free_pct": min_pct,
    "last_tier0_commit": last_tier0_commit,
    "last_tier0_utc": last_tier0_utc,
    "last_tier0_duration_ms": last_tier0_ms,
    "last_tier1_commit": last_tier1_commit,
    "last_tier1_utc": last_tier1_utc,
    "last_tier1_duration_ms": last_tier1_ms,
    "workers": summary_workers,
}
print("LOG\tGATE_HEALTH_SUMMARY=" + json.dumps(summary, separators=(",", ":"), sort_keys=True, allow_nan=False))
PY
)"
eval_rc=$?
if [ "$eval_rc" -ne 0 ]; then
  while IFS= read -r diagnostic; do
    printf 'GATE_HEALTH_EVALUATOR_DIAGNOSTIC %s\n' "$diagnostic"
  done <<<"$EVAL_OUT"
  gate_unrun "health-evaluator" "metadata evaluation failed (rc=$eval_rc); partial output is not a verdict"
  gate_verdict
  exit $?
fi

while IFS=$'\t' read -r kind step detail; do
  [ -z "$kind" ] && continue
  case "$kind" in
    LOG)
      printf '%s\n' "$step"
      ;;
    PASS)
      gate_pass "$step" "$detail"
      ;;
    FAIL)
      gate_fail "$step" "$detail"
      ;;
    UNRUN)
      gate_unrun "$step" "$detail"
      ;;
  esac
done <<<"$EVAL_OUT"

gate_verdict
