#!/usr/bin/env bash
# =============================================================================
# scripts/crate_verdicts.sh — Content-addressed per-crate verdicts CLI & note
# publisher (bead fa-xrl)
# =============================================================================
# Usage:
#   bash scripts/crate_verdicts.sh [--repo DIR] [--store FILE] [--output FILE]
#                                  [--publish-note] [--self-test]
# =============================================================================

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$root"
store="${TMPDIR:-/tmp}/fa-crate-verdicts-store.json"
output="${TMPDIR:-/tmp}/fa-crate-verdicts-manifest.json"
publish_note=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --store) store="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --publish-note) publish_note=1; shift ;;
    --self-test) exec bash "$root/scripts/tests/crate_verdicts_selftest.sh" ;;
    *) printf 'crate-verdicts: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done

python3 -B "$root/scripts/crate_verdicts.py" --repo "$repo" --store "$store" --output "$output"

if [ "$publish_note" -eq 1 ]; then
  head_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" notes --ref=crate-verdicts add -f -F "$output" "$head_sha" 2>/dev/null || true
fi
