#!/usr/bin/env bash
# =============================================================================
# scripts/gate_health.sh — Designated gate worker capacity & disk health check
# (bead fa-abhg)
#
# Reports admissible slots, disk headroom (GB and %), and last successful
# tier-0 / tier-1 durations for the designated gate workers in
# scripts/gate_workers.conf under the substrate gate_verdict.sh contract.
#
# Usage:
#   bash scripts/gate_health.sh [options]
#
# Options:
#   --status-json <path>         Read rch status JSON from file instead of live CLI
#   --repo <path>                Git repository to inspect for tier-0/tier-1 notes
#   --workers <csv>              Comma-separated worker IDs (default: FA_GATE_WORKERS)
#   --min-free-gb <float>        Minimum free disk GB per worker (default: 15.0)
#   --min-free-pct <float>       Minimum free disk % per worker (default: 5.0)
#   --min-admissible-slots <int> Minimum admissible slots across pool (default: 1)
#   --janitor-plan               Print target-pool disk budget & age-sweep policy
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
      printf 'gate_health.sh: unknown option: %s\n' "$1" >&2
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
  rch status --json >"$TMP_STATUS" 2>/dev/null
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
import subprocess
import sys

status_file, repo_path, workers_csv, min_gb_s, min_pct_s, min_slots_s = sys.argv[1:7]
min_gb = float(min_gb_s)
min_pct = float(min_pct_s)
min_slots = int(min_slots_s)
designated = [w.strip() for w in workers_csv.split(",") if w.strip()]

def git_out(args):
    p = subprocess.run(["git", "-C", repo_path] + args, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""

# Inspect latest tier-0 and tier-1 notes in repo_path
last_tier0_commit = "none"
last_tier0_utc = "none"
last_tier0_ms = 0
t0_list = git_out(["notes", "--ref=refs/notes/fa-tier0", "list"])
if t0_list:
    last_line = t0_list.splitlines()[-1].split()
    if len(last_line) == 2:
        last_tier0_commit = last_line[1][:12]
        body = git_out(["notes", "--ref=refs/notes/fa-tier0", "show", last_line[1]])
        for line in body.splitlines():
            if line.startswith("recorded_utc="):
                last_tier0_utc = line.split("=", 1)[1]
            elif line.startswith("duration_ms="):
                try:
                    last_tier0_ms = int(line.split("=", 1)[1])
                except ValueError:
                    pass

last_tier1_commit = "none"
last_tier1_utc = "none"
last_tier1_ms = 0
t1_list = git_out(["notes", "--ref=refs/notes/fa-verdict", "list"])
if t1_list:
    last_line = t1_list.splitlines()[-1].split()
    if len(last_line) == 2:
        last_tier1_commit = last_line[1][:12]
        body = git_out(["notes", "--ref=refs/notes/fa-verdict", "show", last_line[1]])
        total_ms = 0
        for line in body.splitlines():
            if line.startswith("finished_utc="):
                last_tier1_utc = line.split("=", 1)[1]
            elif line.startswith("step_verdict="):
                try:
                    sv = json.loads(line.split("=", 1)[1])
                    total_ms += int(sv.get("duration_ms", 0))
                except Exception:
                    pass
        last_tier1_ms = total_ms

try:
    raw = json.load(open(status_file, "r", encoding="utf-8"))
except Exception as exc:
    print(f"UNRUN\trch-status\tinvalid status JSON: {exc}")
    sys.exit(0)

workers_list = (
    raw.get("data", {}).get("daemon", {}).get("workers")
    or raw.get("workers")
    or []
)
by_id = {w.get("id"): w for w in workers_list if isinstance(w, dict) and w.get("id")}

admissible_slots = 0
summary_workers = []

for wid in designated:
    w = by_id.get(wid)
    if w is None:
        print(f"FAIL\tworker-{wid}\tdesignated worker {wid} missing from rch status")
        continue
    status = str(w.get("status", "unknown"))
    circuit = str(w.get("circuit_state", "unknown"))
    used_slots = int(w.get("used_slots") or 0)
    total_slots = int(w.get("total_slots") or 0)
    free_slots = max(0, total_slots - used_slots)
    pressure = str(w.get("pressure_state", "unknown"))
    free_gb_val = w.get("pressure_disk_free_gb")
    if free_gb_val is None:
        free_gb_val = w.get("disk_free_gb", 0.0)
    free_gb = float(free_gb_val or 0.0)
    ratio_val = w.get("pressure_disk_free_ratio")
    if ratio_val is not None:
        free_pct = float(ratio_val) * 100.0
    elif w.get("pressure_disk_total_gb"):
        total_gb = float(w.get("pressure_disk_total_gb") or 1.0)
        free_pct = (free_gb / total_gb) * 100.0 if total_gb > 0 else 0.0
    else:
        free_pct = float(w.get("disk_free_pct", 100.0))

    print(
        f"LOG\tGATE_HEALTH_WORKER worker={wid} status={status} circuit={circuit} "
        f"slots={free_slots}/{total_slots} pressure={pressure} "
        f"disk_free_gb={free_gb:.1f} disk_free_pct={free_pct:.1f}% "
        f"last_tier0_ms={last_tier0_ms} last_tier1_ms={last_tier1_ms}"
    )

    worker_ok = True
    if free_gb < min_gb or free_pct < min_pct or pressure == "critical":
        print(
            f"FAIL\tworker-{wid}-disk\tworker {wid} below disk threshold "
            f"(free={free_gb:.1f}GB / {free_pct:.1f}%, min={min_gb:.1f}GB / {min_pct:.1f}%, pressure={pressure})"
        )
        worker_ok = False
    if status != "healthy" or circuit != "closed":
        print(
            f"FAIL\tworker-{wid}-health\tworker {wid} not healthy/closed "
            f"(status={status}, circuit={circuit})"
        )
        worker_ok = False

    if worker_ok:
        admissible_slots += free_slots
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
        "admissible": worker_ok,
    })

if admissible_slots < min_slots:
    print(
        f"FAIL\tgate-capacity\tadmissible_slots={admissible_slots} below min_admissible_slots={min_slots} "
        f"across designated workers ({','.join(designated)})"
    )
else:
    print(
        f"PASS\tgate-capacity\tadmissible_slots={admissible_slots} (min={min_slots}) "
        f"last_tier0={last_tier0_commit}@{last_tier0_utc}({last_tier0_ms}ms) "
        f"last_tier1={last_tier1_commit}@{last_tier1_utc}({last_tier1_ms}ms)"
    )

summary = {
    "designated_workers": designated,
    "admissible_slots": admissible_slots,
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
print("LOG\tGATE_HEALTH_SUMMARY=" + json.dumps(summary, separators=(",", ":"), sort_keys=True))
PY
)"

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
