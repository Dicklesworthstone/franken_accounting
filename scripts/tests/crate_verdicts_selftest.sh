#!/usr/bin/env bash
# Self-test for content-addressed per-crate verdicts and Merkle root composition (bead fa-xrl).
#
# Verifies:
#   1. Cold run populates the verdict store (0 reused) and computes a deterministic Merkle root.
#   2. Planted change in a leaf crate (`crate-leaf`) reuses >= 50% of crate verdicts (3/4 = 75%).
#   3. Composed Merkle root with reused leaves equals a cold full run on the exact same tree byte-for-byte.
#   4. Planted change in `registries/units.toml` invalidates 100% of crates (0 reused).
#   5. Planted undeclared external `include_str!("../../../outside.txt")` fails closed (not reused).

set -euo pipefail

fail() {
  printf 'crate-verdicts-selftest: FAIL %s\n' "$*" >&2
  exit 1
}
ok() {
  printf 'ok  %s\n' "$*"
}

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
base="${TMPDIR:-/tmp}/fa-crate-verdicts-selftest-$$-${RANDOM:-0}"
repo="$base/workspace"
store="$base/store.json"
mkdir -p "$repo/registries" "$repo/crates/crate-core/src" "$repo/crates/crate-mid/src" \
  "$repo/crates/crate-leaf-a/src" "$repo/crates/crate-leaf-b/src"

cat > "$repo/Cargo.toml" <<'TOML'
[workspace]
members = [
  "crates/crate-core",
  "crates/crate-mid",
  "crates/crate-leaf-a",
  "crates/crate-leaf-b",
]
TOML
printf 'lock-v1\n' > "$repo/Cargo.lock"
printf 'nightly-2026-08-31\n' > "$repo/rust-toolchain.toml"
printf 'stack-v1\n' > "$repo/franken-stack.lock"
printf 'deny-v1\n' > "$repo/deny.toml"
printf 'units-v1\n' > "$repo/registries/units.toml"

cat > "$repo/crates/crate-core/Cargo.toml" <<'TOML'
[package]
name = "crate-core"
version = "0.1.0"
TOML
printf 'pub fn core_fn() {}\n' > "$repo/crates/crate-core/src/lib.rs"

cat > "$repo/crates/crate-mid/Cargo.toml" <<'TOML'
[package]
name = "crate-mid"
version = "0.1.0"
[dependencies]
crate-core = { path = "../crate-core" }
TOML
printf 'pub fn mid_fn() {}\n' > "$repo/crates/crate-mid/src/lib.rs"

cat > "$repo/crates/crate-leaf-a/Cargo.toml" <<'TOML'
[package]
name = "crate-leaf-a"
version = "0.1.0"
[dependencies]
crate-mid = { path = "../crate-mid" }
TOML
printf 'pub fn leaf_a() {}\n' > "$repo/crates/crate-leaf-a/src/lib.rs"

cat > "$repo/crates/crate-leaf-b/Cargo.toml" <<'TOML'
[package]
name = "crate-leaf-b"
version = "0.1.0"
[dependencies]
crate-core = { path = "../crate-core" }
TOML
printf 'pub fn leaf_b() {}\n' > "$repo/crates/crate-leaf-b/src/lib.rs"

cd "$repo"
git init -q -b main
git config user.name "Test"
git config user.email "test@example.invalid"
git add .
git commit -q -m "initial workspace"

# 1. Cold run: 0/4 reused
out1="$(python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" --store "$store" --output "$base/m1.json")"
grep -Fq "reused=0/4 ratio=0.0000" <<< "$out1" || fail "1: expected 0/4 reused on cold run ($out1)"
ok "1 cold run computes input closures for 4 crates (0/4 reused)"

# 2. Planted change in leaf crate `crate-leaf-a` -> crate-core, crate-mid, crate-leaf-b reused (3/4 = 75% >= 50%)
printf 'pub fn leaf_a_v2() {}\n' >> "$repo/crates/crate-leaf-a/src/lib.rs"
git commit -q -am "edit leaf-a"
out2="$(python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" --store "$store" --output "$base/m2-incremental.json")"
grep -Fq "reused=3/4 ratio=0.7500" <<< "$out2" || fail "2: expected 3/4 (75%) reused after leaf change ($out2)"
ok "2 leaf crate edit reuses 3/4 (75% >= 50%) of crate verdicts"

# 3. Composed Merkle root with reused leaves equals a cold full run on the same tree
python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" --store "$base/empty-store.json" --output "$base/m2-cold.json" --no-update-store >/dev/null
root_inc="$(jq -r '.merkle_root' "$base/m2-incremental.json")"
root_cold="$(jq -r '.merkle_root' "$base/m2-cold.json")"
[ "$root_inc" = "$root_cold" ] || fail "3: incremental Merkle root ($root_inc) != cold Merkle root ($root_cold)"
ok "3 composed Merkle root ($root_inc) equals cold full run on the same tree"

# 4. Planted registry change in `registries/units.toml` -> conservative invalidation (0/4 reused)
printf 'units-v2\n' >> "$repo/registries/units.toml"
git commit -q -am "edit registries/units.toml"
out4="$(python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" --store "$store" --output "$base/m4-reg.json")"
grep -Fq "reused=0/4 ratio=0.0000" <<< "$out4" || fail "4: expected 0/4 reused after registry edit ($out4)"
ok "4 planted registry change invalidates all crates (0/4 reused)"

# 5. Undeclared external include_str! outside crate and registries fails closed (not reused)
printf 'const EXT: &str = include_str!("../../../outside.txt");\n' >> "$repo/crates/crate-leaf-b/src/lib.rs"
git commit -q -am "undeclared include"
python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" --store "$store" --output "$base/m5a.json" >/dev/null
out5b="$(python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" --store "$store" --output "$base/m5b.json")"
# crate-leaf-b has undeclared_external_read=true so only 3/4 are reused even on identical tree
grep -Fq "reused=3/4 ratio=0.7500" <<< "$out5b" || fail "5: undeclared external include should fail closed ($out5b)"
ok "5 undeclared external include_str! fails closed and is never cached/reused"

printf 'crate-verdicts-selftest: all 5 scenarios passed (fixtures retained at %s)\n' "$base"
