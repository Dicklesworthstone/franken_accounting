#!/usr/bin/env bash
# =============================================================================
# scripts/crate_verdicts.sh — Candidate input fingerprints, never unproved
# verification verdicts (bead fa-xrl).
# =============================================================================
# Usage:
#   bash scripts/crate_verdicts.sh [--repo DIR] [--output FILE]
#                                  [--publish-note] [--self-test]
# =============================================================================

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$root"
output=""
publish_note=0
self_test=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --publish-note) publish_note=1; shift ;;
    --self-test) self_test=1; shift ;;
    *) printf 'crate-verdicts: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done

if [ "$publish_note" -eq 1 ]; then
  printf 'UNRUN crate-verdicts: input fingerprints cannot be published as execution verdicts; use scripts/local_proof.sh\n' >&2
  exit 2
fi

if [ "$self_test" -eq 1 ]; then
  exec bash "$root/scripts/tests/crate_verdicts_selftest.sh"
fi

if [ -z "$output" ]; then
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/fa-crate-inputs.XXXXXX")"
  output="$output_dir/manifest.json"
fi
python3 -B "$root/scripts/crate_verdicts.py" --repo "$repo" --output "$output"
