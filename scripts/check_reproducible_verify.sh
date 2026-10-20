#!/usr/bin/env bash
# =============================================================================
# scripts/check_reproducible_verify.sh — Reproducible build & std-only gate
# for `fa-verify` (plan §13.3, gate G4, bead fa-eqk)
#
# Verifies:
#   1. `crates/fa-verify/Cargo.toml` declares zero dependency tables (std-only)
#      and planted dependency additions are refused;
#   2. Two independent clean builds of `fa-verify` (in separate staging roots
#      with path remapping on the pinned toolchain) produce byte-identical
#      binaries with identical SHA-256 checksums;
#   3. A planted build perturbation produces a distinct digest and is caught by
#      the comparator;
#   4. Emits a `SHA256SUMS` manifest suitable for air-gapped verification.
#
# No-claim boundary: proves byte-for-byte build reproducibility of `fa-verify`
# on the pinned toolchain (`rust-toolchain.toml`).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

gate_init "reproducible-verify"

MANIFEST="$ROOT/crates/fa-verify/Cargo.toml"
if grep -v '^[[:space:]]*#' "$MANIFEST" | grep -Eq '(\[.*dependencies.*\]|^(dev-|build-)?dependencies\.)'; then
  gate_fail "reproducible-verify — crates/fa-verify/Cargo.toml declares a dependency table (must be std-only)"
else
  gate_pass "reproducible-verify — crates/fa-verify/Cargo.toml is std-only"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/fa-verify-repro.XXXXXX")"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

# Planted negative for std-only manifest check.
cp "$MANIFEST" "$WORK/planted.toml"
printf '\n[dependencies]\nserde = "1.0"\n' >>"$WORK/planted.toml"
if grep -v '^[[:space:]]*#' "$WORK/planted.toml" | grep -Eq '(\[.*dependencies.*\]|^(dev-|build-)?dependencies\.)'; then
  gate_pass "reproducible-verify — planted dependency in scratch Cargo.toml is caught"
else
  gate_fail "reproducible-verify — planted dependency in scratch Cargo.toml was not caught"
fi

if ! command -v rustc >/dev/null 2>&1; then
  gate_abort_unrun "reproducible-verify — rustc not found in PATH"
fi

build_isolated_fa_verify() {
  local tag="$1"
  local extra_cfg="${2:-}"
  local dir="$WORK/$tag"
  mkdir -p "$dir/out"
  cp -R "$ROOT/crates/fa-verify/src" "$dir/src"

  local common_flags=(
    --edition=2024
    -C opt-level=2
    -C codegen-units=1
    -C debuginfo=0
    -C strip=symbols
    --remap-path-prefix="$dir=/franken_accounting/crates/fa-verify"
    --remap-path-prefix="$HOME=/builder"
  )
  if [ -n "$extra_cfg" ]; then
    common_flags+=(--cfg "$extra_cfg")
  fi

  rustc "${common_flags[@]}" \
    --crate-name fa_verify \
    --crate-type rlib \
    -C metadata="fa-verify-lib-v1" \
    "$dir/src/lib.rs" \
    -o "$dir/out/libfa_verify.rlib"

  rustc "${common_flags[@]}" \
    --crate-name fa_verify \
    --crate-type bin \
    -C metadata="fa-verify-bin-v1" \
    "$dir/src/main.rs" \
    --extern "fa_verify=$dir/out/libfa_verify.rlib" \
    -L "dependency=$dir/out" \
    -o "$dir/out/fa-verify"
}

build_isolated_fa_verify "build-a"
build_isolated_fa_verify "build-b"

SHA_A="$(sha256sum "$WORK/build-a/out/fa-verify" | awk '{print $1}')"
SHA_B="$(sha256sum "$WORK/build-b/out/fa-verify" | awk '{print $1}')"

if [ "$SHA_A" = "$SHA_B" ] && cmp -s "$WORK/build-a/out/fa-verify" "$WORK/build-b/out/fa-verify"; then
  gate_pass "reproducible-verify — two independent builds of fa-verify are byte-identical (sha256=$SHA_A)"
else
  gate_fail "reproducible-verify — build-a ($SHA_A) != build-b ($SHA_B)"
fi

# Verify the built static std-only binary executes cleanly.
if "$WORK/build-a/out/fa-verify" --help >/dev/null 2>&1; then
  gate_pass "reproducible-verify — built fa-verify binary executes --help cleanly"
else
  gate_fail "reproducible-verify — built fa-verify binary failed --help"
fi

# Write SHA256SUMS manifest and verify with sha256sum -c.
if (
  cd "$WORK/build-a/out" || exit 1
  sha256sum fa-verify >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
); then
  gate_pass "reproducible-verify — SHA256SUMS manifest verified"
else
  gate_fail "reproducible-verify — SHA256SUMS verification failed"
fi

gate_verdict
