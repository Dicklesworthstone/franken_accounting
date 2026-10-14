#!/usr/bin/env bash
# =============================================================================
# scripts/topology_check.sh — the workspace obeys registries/
# workspace_topology.toml (bead fa-37f)
#
# Usage: scripts/topology_check.sh <workspace_topology.toml> <cargo-metadata.json>
#   (the JSON is `cargo metadata --no-deps --format-version 1` of the tree)
#   or: scripts/topology_check.sh --facade-bytes <source.rs> [<source.rs>...]
#
# Plan §18.1: a crate may depend only on its own or lower layers; fa-reference
# and fa-verify have registered allowlists; no crate exists without its row.
# This gate judges the actual graph:
#   - every crate under crates/ (a workspace member or a directory with a
#     Cargo.toml) has a row with `planned = false`;
#   - every `planned = false` row names a crate that exists;
#   - every first-party normal or build edge goes to the same or a lower
#     layer; a dev (test-only) edge may also reach the verification layer;
#   - a crate with an allowlist depends, through any edge, only on what it
#     lists.
# fa-registry's tests validate the registry itself and pin it to plan §18.1.
#
# Verdicts, per scripts/lib/gate_verdict.sh: PASS per present crate whose
# edges are all lawful; FAIL per violation; UNRUN when jq or the metadata is
# missing.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

# fa-087: a literal document-byte return type on a public facade signature
# must take a Capability. This narrow source guard complements the compiler's
# pinned missing-method doctests; it is not a Rust type/alias analysis.
check_facade_bytes() {
  local file bad
  for file in "$@"; do
    if [ ! -r "$file" ]; then
      gate_unrun "facade-bytes — cannot read $file"
      continue
    fi
    bad="$(awk '
      /^[[:space:]]*pub[[:space:]]+(async[[:space:]]+|const[[:space:]]+)?fn[[:space:]]/ {
        signature = $0; start = NR; collecting = 1
      }
      collecting && NR != start { signature = signature " " $0 }
      collecting && /[;{]/ {
        sub(/[;{].*$/, "", signature)
        returns = signature; sub(/^.*->[[:space:]]*/, "", returns)
        args = signature; sub(/->[[:space:]]*.*/, "", args)
        if (signature ~ /->/ && returns ~ /(^|[^[:alnum:]_])(Document|DocumentRead|DocumentRecord|Storage)([^[:alnum:]_]|$)/ && args !~ /(^|[^[:alnum:]_])Capability([^[:alnum:]_]|$)/)
          print start ": " signature
        collecting = 0
      }
    ' "$file")" || {
      gate_unrun "facade-bytes — could not inspect $file"
      continue
    }
    if [ -n "$bad" ]; then
      gate_fail "facade-bytes — $file exposes a document-byte type without Capability: $bad"
    else
      gate_pass "facade-bytes — $file has no ungated literal document-byte return type"
    fi
  done
}

if [ "${1:-}" = "--facade-bytes" ]; then
  shift
  gate_init "facade-bytes"
  [ "$#" -gt 0 ] || gate_abort_unrun "facade-bytes — no source files provided"
  check_facade_bytes "$@"
  gate_verdict
  exit $?
fi

if [ "$#" -ne 2 ]; then
  printf 'FAIL topology_check.sh: usage: topology_check.sh <workspace_topology.toml> <cargo-metadata.json>\n'
  exit 1
fi
REGISTRY="$1"
META="$2"

gate_init "topology"

command -v jq >/dev/null 2>&1 || gate_abort_unrun "topology — jq is not installed; the cargo graph was not read"
[ -r "$REGISTRY" ] || gate_abort_unrun "topology — no registry at $REGISTRY"
[ -s "$META" ] || gate_abort_unrun "topology — no cargo metadata at $META"

# The registry: the layer order, then one TSV row per crate:
# name, layer, planned, allowlist (`*` when absent, else comma-joined).
LAYERS="$(sed -nE 's/^layers = \[(.*)\]$/\1/p' "$REGISTRY" | tr -d '" ' | tr ',' '\n')"
[ -n "$LAYERS" ] || gate_abort_unrun "topology — $REGISTRY declares no layers"
ROWS="$(awk '
  function str(line) { sub(/^[a-z_]+ = "/, "", line); sub(/"$/, "", line); return line }
  function flush() { if (in_row) print name "\t" layer "\t" planned "\t" allow }
  /^\[\[crate\]\]/ { flush(); in_row = 1; name = ""; layer = ""; planned = ""; allow = "*"; next }
  /^\[/ { flush(); in_row = 0; next }
  in_row && /^name = / { name = str($0) }
  in_row && /^layer = / { layer = str($0) }
  in_row && /^planned = / { planned = $3 }
  in_row && /^allowlist = / { line = $0; sub(/^allowlist = \[/, "", line); sub(/\]$/, "", line); gsub(/[" ]/, "", line); allow = line }
  END { flush() }
' "$REGISTRY")"

declare -A RANK LAYER_OF PLANNED ALLOW
rank=0
while read -r layer; do
  [ -n "$layer" ] || continue
  RANK["$layer"]=$rank
  rank=$((rank + 1))
done <<<"$LAYERS"
while IFS=$'\t' read -r name layer planned allow; do
  [ -n "$name" ] || continue
  LAYER_OF["$name"]="$layer"
  PLANNED["$name"]="$planned"
  ALLOW["$name"]="$allow"
done <<<"$ROWS"

# The crates that exist: workspace members, plus any directory under crates/
# with a Cargo.toml (a crate not yet added to the workspace still needs a row).
MEMBERS="$(jq -r '.workspace_members as $ws | .packages[] | select(.id as $id | $ws | index($id)) | .name' "$META")" \
  || gate_abort_unrun "topology — $META is not cargo metadata"
DIRS="$(for manifest in "$ROOT"/crates/*/Cargo.toml "$ROOT"/tools/*/Cargo.toml; do
  [ -f "$manifest" ] && awk '/^\[package\]/ { p = 1; next } /^\[/ { p = 0 } p && /^name = / { gsub(/"/, "", $3); print $3; exit }' "$manifest"
done)"
PRESENT="$(printf '%s\n%s\n' "$MEMBERS" "$DIRS" | awk 'NF && !seen[$0]++')"
[ -n "$PRESENT" ] || gate_abort_unrun "topology — no crate found in $META or under crates/"
declare -A IS_PRESENT
while read -r crate; do IS_PRESENT["$crate"]=1; done <<<"$PRESENT"

# First-party edges: path dependencies of members, as "from to kind".
EDGES="$(jq -r '.workspace_members as $ws | .packages[] | select(.id as $id | $ws | index($id)) | .name as $p
  | .dependencies[] | select(.path != null) | "\($p) \(.name) \(.kind // "normal")"' "$META")"

while read -r crate; do
  [ -n "$crate" ] || continue
  layer="${LAYER_OF[$crate]:-}"
  if [ -z "$layer" ]; then
    gate_fail "topology — crate \`$crate\` has no topology row (add it to $REGISTRY with its §18.1 layer)"
    continue
  fi
  if [ "${PLANNED[$crate]}" != "false" ]; then
    gate_fail "topology — crate \`$crate\` exists but its row says planned = ${PLANNED[$crate]}"
    continue
  fi
  bad=0
  edges=0
  while read -r from to kind; do
    [ "$from" = "$crate" ] || continue
    edges=$((edges + 1))
    to_layer="${LAYER_OF[$to]:-}"
    if [ -z "$to_layer" ]; then
      gate_fail "topology — \`$crate\` depends on \`$to\` ($kind), which has no topology row"
      bad=1
      continue
    fi
    allow="${ALLOW[$crate]}"
    if [ "$allow" != "*" ] && ! tr ',' '\n' <<<"$allow" | grep -qxF "$to"; then
      gate_fail "topology — \`$crate\` -> \`$to\` ($kind) breaks $crate's allowlist [$allow]"
      bad=1
      continue
    fi
    if [ "${RANK[$to_layer]}" -gt "${RANK[$layer]}" ] \
      && ! { [ "$kind" = "dev" ] && [ "$to_layer" = "verification" ]; }; then
      gate_fail "topology — \`$crate\` ($layer) -> \`$to\` ($to_layer) is a $kind edge up the layer order"
      bad=1
    fi
  done <<<"$EDGES"
  [ "$bad" -eq 0 ] && gate_pass "topology — $crate ($layer): $edges first-party edges within the order"
done <<<"$PRESENT"

while IFS=$'\t' read -r name _ planned _; do
  [ -n "$name" ] || continue
  if [ "$planned" = "false" ] && [ -z "${IS_PRESENT[$name]:-}" ]; then
    gate_fail "topology — row \`$name\` says planned = false but no such crate exists"
  fi
done <<<"$ROWS"

check_facade_bytes "$ROOT/crates/fa/src/book.rs" "$ROOT/crates/fa/src/async_book.rs"

gate_verdict
