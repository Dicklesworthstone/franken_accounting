#!/usr/bin/env bash
# =============================================================================
# scripts/tests/gate_health_selftest.sh — Self-test for scripts/gate_health.sh
# (bead fa-abhg)
#
# Acceptance test cases:
#   - scripts/tests/gate_health_selftest.sh::healthy_workers_pass
#   - scripts/tests/gate_health_selftest.sh::low_disk_is_fail
#   - scripts/tests/gate_health_selftest.sh::insufficient_slots_is_fail
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Isolate every synthetic repository before any fixture or source snapshot:
# hook-local Git variables otherwise redirect `git -C` into the caller's repo.
git_local_env="$(git rev-parse --local-env-vars)"
git_env_rc=$?
if [ "$git_env_rc" -ne 0 ]; then
  printf 'UNRUN gate-health-selftest-git-context: could not inspect Git environment (rc=%s)\n' "$git_env_rc"
  printf 'FAIL gate-health-selftest-git-context: fixture isolation did not run\n'
  exit 2
fi
while IFS= read -r git_variable; do
  [ -z "$git_variable" ] || unset "$git_variable"
done <<<"$git_local_env"
# shellcheck source=../lib/gate_verdict.sh
source "$ROOT/scripts/lib/gate_verdict.sh"

GATE_HEALTH="$ROOT/scripts/gate_health.sh"
gate_init "gate-health-selftest"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fa-gate-health-selftest.XXXXXX")"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Case 1: healthy_workers_pass
# -----------------------------------------------------------------------------
cat >"$WORK_DIR/healthy.json" <<'EOF'
{
  "api_version": "1.0",
  "data": {
    "daemon": {
      "workers": [
        {
          "id": "hz2",
          "status": "healthy",
          "circuit_state": "closed",
          "used_slots": 1,
          "total_slots": 4,
          "pressure_state": "normal",
          "pressure_disk_free_gb": 120.5,
          "pressure_disk_total_gb": 500.0,
          "pressure_disk_free_ratio": 0.241
        },
        {
          "id": "vmi1152480",
          "status": "healthy",
          "circuit_state": "closed",
          "used_slots": 0,
          "total_slots": 3,
          "pressure_state": "warning",
          "pressure_disk_free_gb": 28.8,
          "pressure_disk_total_gb": 200.0,
          "pressure_disk_free_ratio": 0.144
        }
      ]
    }
  }
}
EOF

out_healthy="$(bash "$GATE_HEALTH" --status-json "$WORK_DIR/healthy.json" --workers "hz2,vmi1152480" --min-free-gb 15.0 --min-free-pct 5.0 2>&1)"
rc_healthy=$?
if [ "$rc_healthy" -eq 0 ] \
  && grep -q '^PASS worker-hz2 ' <<<"$out_healthy" \
  && grep -q '^PASS worker-vmi1152480 ' <<<"$out_healthy" \
  && grep -q '^PASS gate-capacity ' <<<"$out_healthy" \
  && grep -q '^GATE_HEALTH_SUMMARY=' <<<"$out_healthy"; then
  gate_pass "healthy_workers_pass" "healthy designated workers pass with slots and disk headroom logged"
else
  gate_fail "healthy_workers_pass" "rc=$rc_healthy out=$out_healthy"
fi

# -----------------------------------------------------------------------------
# Case 2: low_disk_is_fail
# -----------------------------------------------------------------------------
cat >"$WORK_DIR/low_disk.json" <<'EOF'
{
  "api_version": "1.0",
  "data": {
    "daemon": {
      "workers": [
        {
          "id": "hz2",
          "status": "healthy",
          "circuit_state": "closed",
          "used_slots": 0,
          "total_slots": 4,
          "pressure_state": "normal",
          "pressure_disk_free_gb": 80.0,
          "pressure_disk_total_gb": 400.0,
          "pressure_disk_free_ratio": 0.20
        },
        {
          "id": "vmi1152480",
          "status": "healthy",
          "circuit_state": "closed",
          "used_slots": 0,
          "total_slots": 3,
          "pressure_state": "critical",
          "pressure_disk_free_gb": 4.2,
          "pressure_disk_total_gb": 200.0,
          "pressure_disk_free_ratio": 0.021
        }
      ]
    }
  }
}
EOF

out_low_disk="$(bash "$GATE_HEALTH" --status-json "$WORK_DIR/low_disk.json" --workers "hz2,vmi1152480" --min-free-gb 15.0 --min-free-pct 5.0 2>&1)"
rc_low_disk=$?
if [ "$rc_low_disk" -ne 0 ] && grep -q '^FAIL worker-vmi1152480-disk ' <<<"$out_low_disk"; then
  gate_pass "low_disk_is_fail" "below-threshold disk on vmi1152480 emitted anchored FAIL line and exited non-zero (rc=$rc_low_disk)"
else
  gate_fail "low_disk_is_fail" "expected non-zero exit and FAIL worker-vmi1152480-disk (rc=$rc_low_disk out=$out_low_disk)"
fi

# -----------------------------------------------------------------------------
# Case 3: insufficient_slots_is_fail
# -----------------------------------------------------------------------------
cat >"$WORK_DIR/busy.json" <<'EOF'
{
  "api_version": "1.0",
  "data": {
    "daemon": {
      "workers": [
        {
          "id": "hz2",
          "status": "healthy",
          "circuit_state": "closed",
          "used_slots": 4,
          "total_slots": 4,
          "pressure_state": "normal",
          "pressure_disk_free_gb": 80.0,
          "pressure_disk_total_gb": 400.0,
          "pressure_disk_free_ratio": 0.20
        },
        {
          "id": "vmi1152480",
          "status": "unreachable",
          "circuit_state": "open",
          "used_slots": 0,
          "total_slots": 3,
          "pressure_state": "telemetry_gap",
          "pressure_disk_free_gb": 40.0,
          "pressure_disk_total_gb": 200.0,
          "pressure_disk_free_ratio": 0.20
        }
      ]
    }
  }
}
EOF

out_busy="$(bash "$GATE_HEALTH" --status-json "$WORK_DIR/busy.json" --workers "hz2,vmi1152480" --min-admissible-slots 1 2>&1)"
rc_busy=$?
if [ "$rc_busy" -ne 0 ] \
  && grep -q '^FAIL worker-vmi1152480-health ' <<<"$out_busy" \
  && grep -q '^FAIL gate-capacity ' <<<"$out_busy"; then
  gate_pass "insufficient_slots_is_fail" "0 admissible slots and unreachable worker emitted FAIL lines (rc=$rc_busy)"
else
  gate_fail "insufficient_slots_is_fail" "expected FAIL gate-capacity (rc=$rc_busy out=$out_busy)"
fi

# Real Git notes, with object order deliberately different from time order.
# These are isolated metadata controls, not repository verification proofs.
python3 - "$WORK_DIR" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])

def git(repo, *args, **kwargs):
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=Gate health test",
         "-c", "user.email=gate-health@example.invalid", *args],
        check=True, stdout=subprocess.PIPE, text=True, **kwargs).stdout.strip()

def fixture(name):
    repo = root / name
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    tree = git(repo, "mktree", input="")
    commits = sorted(git(repo, "commit-tree", tree, "-m", f"Synthetic note control {n}")
                     for n in range(3))
    return repo, commits

def note(repo, ref, commit, body):
    git(repo, "notes", f"--ref={ref}", "add", "-m", body, commit)

def expected(name, **fields):
    with (root / f"{name}.expected.json").open("x") as stream:
        json.dump(fields, stream)

repo, (latest, older, _) = fixture("history_chronology")
note(repo, "fa-tier0", older,
     "verdict=pass\nrecorded_utc=2026-10-26T10:00:00Z\nduration_ms=9000")
note(repo, "fa-tier0", latest,
     "verdict=pass\nrecorded_utc=2026-11-10T10:00:00Z\nfmt_seconds=8\ncheck_seconds=19")
note(repo, "fa-verdict", older,
     'verdict=pass\nfinished_utc=2026-10-26T11:00:00Z\nstep_verdict={"duration_ms":9000}')
note(repo, "fa-verdict", latest,
     'verdict=pass\nfinished_utc=2026-11-10T11:00:00Z\n'
     'step_verdict={"duration_ms":500}\nstep_verdict={"duration_ms":1200}')
expected("history_chronology", last_tier0_commit=latest[:12],
         last_tier0_utc="2026-11-10T10:00:00Z", last_tier0_duration_ms=27000,
         last_tier1_commit=latest[:12], last_tier1_utc="2026-11-10T11:00:00Z",
         last_tier1_duration_ms=1700, capacity_basis="worker_status_metadata", admission_checked=False,
         estimated_admissible_slots=6, history_scope="repository_recorded_pass_metadata")

repo, (passed, _, red) = fixture("red_is_not_success")
for ref, stamp in (("fa-tier0", "recorded_utc"), ("fa-verdict", "finished_utc")):
    note(repo, ref, passed, f"verdict=pass\n{stamp}=2026-11-10T12:00:00Z\nduration_ms=42")
    note(repo, ref, red, f"verdict=red\n{stamp}=2026-11-10T13:00:00Z\nduration_ms=1")
expected("red_is_not_success", last_tier0_commit=passed[:12], last_tier1_commit=passed[:12],
         last_tier0_utc="2026-11-10T12:00:00Z", last_tier1_utc="2026-11-10T12:00:00Z")

repo, (passed, _, _) = fixture("current_duration")
note(repo, "fa-tier0", passed,
     "verdict=pass\nrecorded_utc=2026-11-10T12:00:00Z\nfmt_seconds=8\ncheck_seconds=19")
note(repo, "fa-verdict", passed,
     'verdict=pass\nfinished_utc=2026-11-10T12:00:00Z\n'
     'step_verdict={"duration_ms":500}\nstep_verdict={"duration_ms":1200}')
expected("current_duration", last_tier0_duration_ms=27000, last_tier1_duration_ms=1700)

repo, (passed, _, _) = fixture("legacy_duration")
note(repo, "fa-tier0", passed,
     "verdict=pass\nrecorded_utc=2026-11-10T12:00:00Z\nduration_ms=123456")
note(repo, "fa-verdict", passed,
     'verdict=pass\nfinished_utc=2026-11-10T12:00:00Z\nstep_verdict={"duration_ms":30}')
expected("legacy_duration", last_tier0_duration_ms=123456, last_tier1_duration_ms=30)

repo, (passed, _, _) = fixture("unknown_duration")
note(repo, "fa-tier0", passed, "verdict=pass\nrecorded_utc=2026-11-10T12:00:00Z")
note(repo, "fa-verdict", passed, "verdict=pass\nfinished_utc=2026-11-10T12:00:00Z")
expected("unknown_duration", last_tier0_commit=passed[:12], last_tier1_commit=passed[:12],
         last_tier0_duration_ms=None, last_tier1_duration_ms=None)

repo, (passed, _, _) = fixture("zero_duration")
note(repo, "fa-tier0", passed,
     "verdict=pass\nrecorded_utc=2026-11-10T12:00:00Z\nfmt_seconds=0\ncheck_seconds=0")
note(repo, "fa-verdict", passed,
     'verdict=pass\nfinished_utc=2026-11-10T12:00:00Z\nstep_verdict={"duration_ms":0}')
expected("zero_duration", last_tier0_duration_ms=0, last_tier1_duration_ms=0)

repo, (red, _, _) = fixture("only_red_history")
note(repo, "fa-tier0", red, "verdict=red\nrecorded_utc=2026-11-10T12:00:00Z")
note(repo, "fa-verdict", red, "verdict=red\nfinished_utc=2026-11-10T12:00:00Z")
expected("only_red_history", last_tier0_commit="none", last_tier1_commit="none",
         last_tier0_utc="none", last_tier1_utc="none",
         last_tier0_duration_ms=None, last_tier1_duration_ms=None)
PY
rc_note_setup=$?
if [ "$rc_note_setup" -ne 0 ]; then
  gate_fail "note_fixture_setup" "isolated Git note setup failed (rc=$rc_note_setup)"
  gate_verdict
  exit $?
fi

for note_case in history_chronology red_is_not_success current_duration legacy_duration unknown_duration zero_duration only_red_history; do
  out_note="$(bash "$GATE_HEALTH" --status-json "$WORK_DIR/healthy.json" --repo "$WORK_DIR/$note_case" --workers "hz2,vmi1152480" 2>&1)"
  rc_note=$?
  python3 - "$out_note" "$WORK_DIR/$note_case.expected.json" <<'PY'
import json
from pathlib import Path
import sys

prefix = "GATE_HEALTH_SUMMARY="
rows = [line[len(prefix):] for line in sys.argv[1].splitlines() if line.startswith(prefix)]
assert len(rows) == 1, "expected one gate-health metadata summary"
actual = json.loads(rows[0])
expected = json.loads(Path(sys.argv[2]).read_text())
assert "admissible_slots" not in actual, "slot estimate must not retain an unqualified admission alias"
assert all("metadata_healthy" in row and "admissible" not in row for row in actual["workers"])
for key, value in expected.items():
    assert key in actual and actual[key] == value, f"{key}: expected {value!r}, got {actual.get(key)!r}"
PY
  rc_note_summary=$?
  if [ "$rc_note" -eq 0 ] && [ "$rc_note_summary" -eq 0 ]; then
    gate_pass "$note_case" "recorded PASS metadata matches independent history and timing controls"
  else
    gate_fail "$note_case" "health_rc=$rc_note summary_rc=$rc_note_summary out=$out_note"
  fi
done

python3 - "$GATE_HEALTH" "$WORK_DIR" <<'PY'
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

helper, directory = sys.argv[1:]
root = Path(directory)
healthy = json.loads((root / "healthy.json").read_text())
failures = []

def check(name, argv, expected, marker, timeout=5, stdout_only=False, env=None):
    try:
        result = subprocess.run(["bash", helper, *argv], capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        print(f"CONTROL {name}: timed out")
        failures.append(name)
        return
    print(f"CONTROL {name}: exit={result.returncode}, expected={expected}")
    transcript = result.stdout if stdout_only else result.stdout + result.stderr
    if result.returncode != expected or marker not in transcript:
        failures.append(name)
        for stream in (result.stdout, result.stderr):
            for line in stream.splitlines():
                print(f"DETAIL {name}: {line}")

bad_metrics = (
    ("second-worker-integer", {"used_slots": "not-an-integer"}),
    ("negative-slots", {"used_slots": -1}),
    ("fractional-slots", {"used_slots": 0.5}),
    ("boolean-slots", {"total_slots": True}),
    ("inconsistent-slots", {"used_slots": 4}),
    ("nan-disk-string", {"pressure_disk_free_gb": "NaN"}),
    ("nan-disk-number", {"pressure_disk_free_gb": float("nan")}),
    ("infinite-disk", {"pressure_disk_free_gb": float("inf")}),
    ("negative-disk", {"pressure_disk_free_gb": -1}),
    ("invalid-ratio", {"pressure_disk_free_ratio": 1.5}),
    ("missing-percentage", {"pressure_disk_free_ratio": None, "pressure_disk_total_gb": None}),
)
for name, changes in bad_metrics:
    status = copy.deepcopy(healthy)
    status["data"]["daemon"]["workers"][1].update(changes)
    path = root / f"{name}.json"
    path.write_text(json.dumps(status))
    check(name, ["--status-json", str(path), "--repo", str(root / "history_chronology")], 2, "UNRUN ")

base = ["--status-json", str(root / "healthy.json"), "--repo", str(root / "history_chronology")]
for option, value in (("--min-free-gb", "NaN"), ("--min-free-gb", "Infinity"),
                      ("--min-free-gb", "-1"), ("--min-free-pct", "NaN"),
                      ("--min-free-pct", "101"), ("--min-admissible-slots", "-1"),
                      ("--min-admissible-slots", "1.5")):
    check(f"threshold-{option}-{value}", [*base, option, value], 2, "UNRUN ")
for option in ("--status-json", "--repo", "--workers", "--min-free-gb", "--min-free-pct", "--min-admissible-slots"):
    check(f"missing-{option}", [*base, option], 2, "FAIL gate-health-usage:", timeout=2, stdout_only=True)
check("next-option-is-not-a-value", [*base, "--workers", "--janitor-plan"], 2,
      "FAIL gate-health-usage:", stdout_only=True)
check("empty-value", [*base, "--workers", ""], 2, "FAIL gate-health-usage:", stdout_only=True)
check("unknown-option", [*base, "--not-an-option"], 2, "FAIL gate-health-usage:", stdout_only=True)
check("duplicate-worker-not-capacity", [*base, "--workers", "hz2,hz2", "--min-admissible-slots", "5"],
      1, "FAIL gate-capacity ")
check("valid-scientific-threshold", [*base, "--min-free-gb", "1e1"], 0, "PASS gate-capacity ")
for name in ("percentage-from-total", "explicit-percentage"):
    status = copy.deepcopy(healthy)
    worker = status["data"]["daemon"]["workers"][1]
    del worker["pressure_disk_free_ratio"]
    if name == "explicit-percentage":
        del worker["pressure_disk_total_gb"]
        worker["disk_free_pct"] = 14.4
    path = root / f"{name}.json"
    path.write_text(json.dumps(status))
    check(name, ["--status-json", str(path), "--repo", str(root / "history_chronology")],
          0, "PASS gate-capacity ")
foreign_git = os.environ.copy()
foreign_git.update(GIT_DIR=str(root / "only_red_history" / ".git"),
                   GIT_WORK_TREE=str(root / "only_red_history"),
                   GIT_INDEX_FILE=str(root / "only_red_history" / ".git" / "redirected-index"))
history = json.loads((root / "history_chronology.expected.json").read_text())
check("explicit-repo-ignores-inherited-git-context", base, 0,
      f"last_tier0={history['last_tier0_commit']}@{history['last_tier0_utc']}", env=foreign_git)

pressure_status = copy.deepcopy(healthy)
pressure_worker = pressure_status["data"]["daemon"]["workers"][0]
pressure_worker["id"] = "hz2"
pressure_worker["pressure_disk_free_gb"] = 80.3
pressure_worker["pressure_disk_total_gb"] = 320.0
pressure_worker["pressure_disk_free_ratio"] = 0.2509
pressure_worker["pressure_state"] = "critical"
pressure_path = root / "critical-pressure-ample-disk.json"
pressure_path.write_text(json.dumps(pressure_status))
pressure_res = subprocess.run(
    ["bash", helper, "--status-json", str(pressure_path), "--repo", str(root / "history_chronology")],
    capture_output=True, text=True, timeout=5
)
pressure_transcript = pressure_res.stdout + pressure_res.stderr
print(f"CONTROL critical-pressure-ample-disk: exit={pressure_res.returncode}, expected=1")
if (
    pressure_res.returncode != 1
    or "FAIL worker-hz2-pressure" not in pressure_transcript
    or "under critical pressure" not in pressure_transcript
    or "FAIL worker-hz2-disk" in pressure_transcript
):
    failures.append("critical-pressure-ample-disk")
    for line in pressure_transcript.splitlines():
        print(f"DETAIL critical-pressure-ample-disk: {line}")

if failures:
    print(f"CONTROL_FAILURES {failures}")
    raise SystemExit(1)
PY
rc_input_controls=$?
if [ "$rc_input_controls" -eq 0 ]; then
  gate_pass "input_validation" "malformed metrics, thresholds and missing values refuse without partial green or hangs"
  gate_pass "gate_health_selftest::critical_memory_pressure_with_ample_disk_reports_pressure_not_disk_floor" "critical pressure with 80.3 GB free disk reports worker-hz2-pressure, never worker-hz2-disk"
else
  gate_fail "input_validation" "input controls failed (rc=$rc_input_controls)"
fi

cd "$ROOT" || exit 1
gate_verdict
