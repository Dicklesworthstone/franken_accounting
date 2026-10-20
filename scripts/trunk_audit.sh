#!/usr/bin/env bash
# =============================================================================
# scripts/trunk_audit.sh — Trunk verdict note audit (bead fa-7dx)
# =============================================================================
# Lists trunk commits since `--since <rev>` (default: HEAD, so a zero-range
# check succeeds unless an explicit adoption point is supplied) that lack a
# green verdict note (`verdicts`, `fa-verdict`, `merge-train`, or `owner-watch`)
# bound to their exact tree hash.
#
# Usage:
#   bash scripts/trunk_audit.sh [--repository DIR] [--since REV] [--head REV]
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"
gate_init "trunk-audit"

repo="$ROOT"
since_rev=""
head_rev="HEAD"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      [ "$#" -ge 2 ] || gate_abort_unrun "trunk-audit — --repository requires a path"
      repo="$2"
      shift 2
      ;;
    --since)
      [ "$#" -ge 2 ] || gate_abort_unrun "trunk-audit — --since requires a revision"
      since_rev="$2"
      shift 2
      ;;
    --head)
      [ "$#" -ge 2 ] || gate_abort_unrun "trunk-audit — --head requires a revision"
      head_rev="$2"
      shift 2
      ;;
    *)
      gate_abort_unrun "trunk-audit — unknown argument: $1"
      ;;
  esac
done

head_sha="$(git -C "$repo" rev-parse --verify "${head_rev}^{commit}" 2>/dev/null)" \
  || gate_abort_unrun "trunk-audit — cannot resolve head revision $head_rev in $repo"

if [ -z "$since_rev" ]; then
  since_sha="$head_sha"
else
  since_sha="$(git -C "$repo" rev-parse --verify "${since_rev}^{commit}" 2>/dev/null)" \
    || gate_abort_unrun "trunk-audit — cannot resolve --since $since_rev in $repo"
fi

has_verdict_note() {
  local sha="$1" tree_sha="$2" ref note
  for ref in verdicts fa-verdict merge-train owner-watch; do
    note="$(git -C "$repo" notes --ref="$ref" show "$sha" 2>/dev/null || true)"
    [ -n "$note" ] || continue
    if grep -Eqx 'verdict=(pass|GREEN)' <<< "$note" \
      && grep -Fxq "tree=$tree_sha" <<< "$note"; then
      return 0
    fi
  done
  return 1
}

missing=0
checked=0
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  checked=$((checked + 1))
  tree_sha="$(git -C "$repo" rev-parse "${sha}^{tree}")"
  if has_verdict_note "$sha" "$tree_sha"; then
    gate_pass "trunk-audit commit ${sha:0:12} (tree ${tree_sha:0:12}) has green verdict note"
  else
    gate_fail "trunk-audit commit ${sha:0:12} (tree ${tree_sha:0:12}) lacks a green verdict note"
    missing=$((missing + 1))
  fi
done < <(git -C "$repo" rev-list --first-parent --reverse "${since_sha}..${head_sha}")

if [ "$checked" -eq 0 ]; then
  gate_pass "trunk-audit range ${since_sha:0:12}..${head_sha:0:12} has 0 unverified commits"
fi

gate_verdict
