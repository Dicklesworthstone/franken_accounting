#!/usr/bin/env bash
# =============================================================================
# close_bead.sh — close a bead only when bound to a verified PASS manifest
# whose tree contains the bead's landing commit (bead fa-u7u).
# =============================================================================
# Usage:
#   bash scripts/close_bead.sh <bead-id> --manifest <proof-dir-or-manifest> \
#       [--commit <landing-commit>] [--repository <repo>] --reason <reason>
# =============================================================================

set -euo pipefail

fail() {
  printf 'close-bead: REFUSED — %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
Usage: bash scripts/close_bead.sh <bead-id> --manifest <proof-dir|manifest.txt>
                                  [--commit <landing-commit>] [--repository <dir>]
                                  --reason <reason>
USAGE
}

[ "$#" -ge 1 ] || { usage >&2; exit 2; }
bead_id=""
manifest_arg=""
landing_commit=""
repo_dir=""
reason=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      [ "$#" -ge 2 ] || fail "--manifest requires a path"
      manifest_arg="$2"
      shift 2
      ;;
    --commit)
      [ "$#" -ge 2 ] || fail "--commit requires a commit SHA"
      landing_commit="$2"
      shift 2
      ;;
    --repository)
      [ "$#" -ge 2 ] || fail "--repository requires a directory"
      repo_dir="$2"
      shift 2
      ;;
    --reason)
      [ "$#" -ge 2 ] || fail "--reason requires text"
      reason="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      fail "unknown flag: $1"
      ;;
    *)
      [ -z "$bead_id" ] || fail "only one bead id may be supplied"
      bead_id="$1"
      shift
      ;;
  esac
done

[ -n "$bead_id" ] || fail "missing <bead-id>"
[ -n "$manifest_arg" ] || fail "missing --manifest (cannot close $bead_id without citing a verdict manifest)"
[ -n "$reason" ] || fail "missing --reason"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [ -z "$repo_dir" ]; then
  repo_dir="$root"
fi

if [ -d "$manifest_arg" ]; then
  proof_dir="$manifest_arg"
  manifest_file="$proof_dir/manifest.txt"
elif [ -f "$manifest_arg" ]; then
  manifest_file="$manifest_arg"
  proof_dir="$(dirname "$manifest_arg")"
else
  fail "manifest path does not exist: $manifest_arg"
fi

[ -f "$manifest_file" ] || fail "manifest file not found: $manifest_file"

# Verify proof bundle integrity and exact-tree binding against the repository
bash "$root/scripts/local_proof_verify.sh" --repository "$repo_dir" "$proof_dir" >/dev/null \
  || fail "proof bundle at $proof_dir failed local_proof_verify.sh against $repo_dir"

verdict="$(awk -F= '$1 == "verdict" { print $2 }' "$manifest_file")"
stable="$(awk -F= '$1 == "tree_stable" { print $2 }' "$manifest_file")"
manifest_commit="$(awk -F= '$1 == "commit" { print $2 }' "$manifest_file")"
manifest_tree="$(awk -F= '$1 == "tree" { print $2 }' "$manifest_file")"

[ "$verdict" = "pass" ] || fail "manifest verdict is '$verdict', expected 'pass'"
[ "$stable" = "true" ] || fail "manifest tree_stable is '$stable', expected 'true'"

if [ -z "$landing_commit" ]; then
  landing_commit="$(git -C "$repo_dir" log -n 1 --format='%H' --grep="$bead_id" "$manifest_commit" 2>/dev/null || true)"
  [ -n "$landing_commit" ] || fail "no commit mentioning $bead_id is reachable from manifest commit $manifest_commit (supply --commit explicitly if commit message does not mention $bead_id)"
else
  landing_commit="$(git -C "$repo_dir" rev-parse --verify "${landing_commit}^{commit}" 2>/dev/null)" \
    || fail "landing commit $landing_commit does not exist in $repo_dir"
fi

# Verify that the manifest's commit contains the bead's landing commit (tree A cannot close a bead landed in tree B)
if ! git -C "$repo_dir" merge-base --is-ancestor "$landing_commit" "$manifest_commit" 2>/dev/null; then
  fail "manifest commit ${manifest_commit:0:12} (tree ${manifest_tree:0:12}) does not contain landing commit ${landing_commit:0:12} for $bead_id"
fi

# Also ensure that if landing_commit == manifest_commit or ancestor, the manifest tree matches the repository tree
actual_manifest_tree="$(git -C "$repo_dir" rev-parse "${manifest_commit}^{tree}")"
[ "$actual_manifest_tree" = "$manifest_tree" ] \
  || fail "manifest tree $manifest_tree does not match commit tree $actual_manifest_tree"

cited_reason="${reason} [manifest: commit=${manifest_commit:0:12} tree=${manifest_tree:0:12}]"
if [ "${FA_CLOSE_BEAD_DRY_RUN:-0}" = "1" ]; then
  printf 'CLOSE_BEAD_VERIFIED bead=%s commit=%s tree=%s landing=%s\n' \
    "$bead_id" "$manifest_commit" "$manifest_tree" "$landing_commit"
  exit 0
fi

"${FA_BR_BIN:-br}" close "$bead_id" --reason "$cited_reason"
printf 'CLOSE_BEAD_OK bead=%s commit=%s tree=%s landing=%s\n' \
  "$bead_id" "$manifest_commit" "$manifest_tree" "$landing_commit"
