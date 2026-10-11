#!/usr/bin/env bash
# =============================================================================
# scripts/tests/topology_negative.sh — planted negatives for the `topology`
# gate (bead fa-37f)
#
# Usage: scripts/tests/topology_negative.sh <workspace_topology.toml> <cargo-metadata.json> <workdir>
#
# A gate that cannot fail is not a gate. This self-test runs
# scripts/topology_check.sh on the real registry (positive control: it must
# pass) and on scratch copies with one planted defect each (it must fail with
# a FAIL line naming the defect):
#   1. a present crate whose row was removed (a crate added without a row);
#   2. a row moved to a higher layer, so a lower crate's edge into it goes up;
#   3. an allowlist narrowed so a real edge breaks it.
# Scratch copies and their transcripts stay in <workdir> for inspection.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

if [ "$#" -ne 3 ]; then
  printf 'FAIL topology_negative.sh: usage: topology_negative.sh <workspace_topology.toml> <cargo-metadata.json> <workdir>\n'
  exit 1
fi
REGISTRY="$1"
META="$2"
WORK="$3"

gate_init "topology-negative"
mkdir -p "$WORK" || gate_abort_unrun "topology-negative — cannot create $WORK"
CHECK="$ROOT/scripts/topology_check.sh"

# run_case <name> <registry> -> sets RC and OUT (the case's stdout transcript)
run_case() {
  OUT="$WORK/$1.transcript"
  bash "$CHECK" "$2" "$META" >"$OUT" 2>"$WORK/$1.stderr"
  RC=$?
}

run_case positive "$REGISTRY"
if [ "$RC" -eq 2 ] && grep -q '^UNRUN ' "$OUT"; then
  gate_abort_unrun "topology-negative — the positive control did not run ($(grep -m1 '^UNRUN ' "$OUT" | cut -c7-))"
elif [ "$RC" -eq 0 ]; then
  gate_pass "topology-negative — positive control: the real registry passes"
else
  gate_fail "topology-negative — positive control: the real registry fails (exit $RC); see $OUT"
fi

# expect_fail <case> <needle...>: the planted copy must exit 1 with a FAIL line
# containing every needle.
expect_fail() {
  local name="$1"; shift
  local line
  line="$(grep '^FAIL ' "$OUT" | grep -F -- "$1" | head -n 1)"
  for needle in "$@"; do
    [ -n "$line" ] && ! grep -qF -- "$needle" <<<"$line" && line=""
  done
  if [ "$RC" -eq 1 ] && [ -n "$line" ]; then
    gate_pass "topology-negative — planted $name is caught: ${line#FAIL }"
  else
    gate_fail "topology-negative — planted $name was not caught (exit $RC); see $OUT"
  fi
}

# 1. fa-verify exists but its row is gone.
awk 'BEGIN { RS = ""; ORS = "\n\n" } !/name = "fa-verify"/' "$REGISTRY" >"$WORK/no-row.toml"
if grep -q 'name = "fa-verify"' "$WORK/no-row.toml"; then
  gate_fail "topology-negative — could not plant: the fa-verify row is still present"
else
  run_case no-row "$WORK/no-row.toml"
  expect_fail "crate without a row" "crate \`fa-verify\` has no topology row"
fi

# 2. fa-registry moved to the surface layer: fa-money's normal edge goes up.
awk 'BEGIN { RS = ""; ORS = "\n\n" } /name = "fa-registry"/ { sub(/layer = "foundation"/, "layer = \"surface\"") } { print }' \
  "$REGISTRY" >"$WORK/upward.toml"
run_case upward "$WORK/upward.toml"
expect_fail "upward edge" "fa-registry" "up the layer order"

# 3. fa-reference may no longer depend on fa-registry.
sed 's/^allowlist = \["fa-time", "fa-registry"\]$/allowlist = ["fa-time"]/' "$REGISTRY" >"$WORK/allowlist.toml"
if cmp -s "$REGISTRY" "$WORK/allowlist.toml"; then
  gate_fail "topology-negative — could not plant: fa-reference's allowlist line was not found"
else
  run_case allowlist "$WORK/allowlist.toml"
  expect_fail "allowlist breach" "fa-reference" "allowlist"
fi

# fa-087: preserve the gate's literal-signature boundary with independent
# positive and planted-negative source fixtures. No fixture is compiled here;
# the facade's positive/compile_fail doctests run in the workspace test gate.
cat >"$WORK/facade-safe.rs" <<'RUST'
pub fn read_document_for(capability: &Capability) -> Document { body() }
pub async fn read_document_for_async(
    capability: &fa_journal::Capability,
) -> Outcome<fa_journal::DocumentRead> { body() }
pub fn document_commitment() -> Option<[u8; 32]> { body() }
pub(crate) fn verification_only() -> DocumentRecord { body() }
RUST
OUT="$WORK/facade-safe.transcript"
bash "$CHECK" --facade-bytes "$WORK/facade-safe.rs" >"$OUT" 2>"$WORK/facade-safe.stderr"
RC=$?
if [ "$RC" -eq 0 ]; then
  gate_pass "facade-bytes — capability-gated, commitment-only and private controls pass"
else
  gate_fail "facade-bytes — positive signature controls failed (exit $RC); see $OUT"
fi

cat >"$WORK/facade-raw.rs" <<'RUST'
pub fn leaked_document() -> Option<fa_journal::Document> { body() }
RUST
cat >"$WORK/facade-record.rs" <<'RUST'
pub async fn leaked_inline_record(
    oid: &Oid,
) -> Result<Option<fa_journal::DocumentRecord>, Error> { body() }
RUST
for case in facade-raw facade-record; do
  OUT="$WORK/$case.transcript"
  bash "$CHECK" --facade-bytes "$WORK/$case.rs" >"$OUT" 2>"$WORK/$case.stderr"
  RC=$?
  expect_fail "$case byte return" "facade-bytes" "without Capability"
done

gate_verdict
