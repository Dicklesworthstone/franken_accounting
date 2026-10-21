#!/usr/bin/env bash
# =============================================================================
# scripts/tier0.sh — Tier 0: the tree is formatted and every target type-checks
# (bead fa-1qk0). .github/workflows/tier0.yml is the same two steps as a
# hosted recipe for manual dispatch. Tier 0 says nothing about test results.
# =============================================================================
# Usage: bash scripts/tier0.sh
# Prints one verdict line, `tier0 PASS tree=<hash>` or `tier0 FAIL step=<step>
# tree=<hash>`, and exits 0 only on PASS. The tree hash is of HEAD; a dirty
# working tree is named, since its verdict is not HEAD's.
# =============================================================================

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root" || exit 2

tree="$(git rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)"
if [ -n "$(git status --porcelain --untracked-files=no -- crates registries Cargo.toml Cargo.lock 2>/dev/null)" ]; then
  tree="$tree+dirty"
fi

if ! cargo fmt --all --check; then
  printf 'tier0 FAIL step=fmt tree=%s\n' "$tree"
  exit 1
fi

check=(cargo check --workspace --all-targets)
if command -v rch >/dev/null 2>&1; then
  check=(rch exec -- "${check[@]}")
fi
if ! "${check[@]}"; then
  printf 'tier0 FAIL step=check tree=%s\n' "$tree"
  exit 1
fi

printf 'tier0 PASS tree=%s\n' "$tree"
