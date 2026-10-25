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

cd "$ROOT" || exit 1
gate_verdict
