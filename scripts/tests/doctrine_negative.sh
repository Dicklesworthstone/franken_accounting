#!/usr/bin/env bash
# =============================================================================
# scripts/tests/doctrine_negative.sh — planted negatives for `doctrine`
# (bead fa-598p)
#
# Usage: scripts/tests/doctrine_negative.sh [<foundations-dir> [<workdir>]]
#
# Runs scripts/doctrine_check.sh on the real workspace (positive control) and
# on six isolated scratch fixtures, each planting one constitutional violation
# and asserting a FAIL line naming the violation and `<file>:<line>`:
#   1. planted `execute_gql` / `BoundPlan` reference;
#   2. planted `f64` in an amount crate (`crates/fa-money/src/lib.rs`);
#   3. planted `std::thread::spawn` in production `src/`;
#   4. planted `#[derive(Serialize, Deserialize)]` on a first-party type;
#   5. planted missing `#![forbid(unsafe_code)]` at a crate root;
#   6. planted duplicate `fnx-classes` package ID in a posture closure.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/gate_verdict.sh
. "$ROOT/scripts/lib/gate_verdict.sh"

if [ "$#" -gt 2 ]; then
  printf 'FAIL doctrine_negative.sh: usage: doctrine_negative.sh [<foundations-dir> [<workdir>]]\n'
  exit 1
fi

FOUNDATIONS_DIR="${1:-}"
WORK="${2:-$(mktemp -d "${TMPDIR:-/tmp}/fa-doctrine-neg.XXXXXX")}"

gate_init "doctrine-negative"
mkdir -p "$WORK" || gate_abort_unrun "doctrine-negative — cannot create $WORK"
CHECK="$ROOT/scripts/doctrine_check.sh"

# run_case <name> <target_root> <foundations_dir> -> sets RC and OUT
run_case() {
  local name="$1" target="$2" fdir="${3:-}"
  OUT="$WORK/$name.transcript"
  if [ -n "$fdir" ]; then
    bash "$CHECK" "$target" "$fdir" >"$OUT" 2>"$WORK/$name.stderr"
  else
    bash "$CHECK" "$target" >"$OUT" 2>"$WORK/$name.stderr"
  fi
  RC=$?
}

# expect_fail <case_label> <needle...>
expect_fail() {
  local label="$1"; shift
  local line
  line="$(grep '^FAIL ' "$OUT" | grep -F -- "$1" | head -n 1)"
  for needle in "$@"; do
    [ -n "$line" ] && ! grep -qF -- "$needle" <<<"$line" && line=""
  done
  if [ "$RC" -eq 1 ] && [ -n "$line" ]; then
    gate_pass "doctrine-negative — planted $label is caught: ${line#FAIL }"
  else
    gate_fail "doctrine-negative — planted $label was not caught (exit $RC); see $OUT"
  fi
}

# Build a minimal valid scratch workspace root in $1 with clean crate roots and Cargo.lock
make_clean_tree() {
  local dst="$1"
  mkdir -p \
    "$dst/crates/fa-money/src" \
    "$dst/crates/fa-model/src" \
    "$dst/crates/fa-journal/src" \
    "$dst/crates/fa-verify/src" \
    "$dst/tools/registry-check/src" \
    "$dst/foundations"
  for c in fa-money fa-model fa-journal fa-verify; do
    cat >"$dst/crates/$c/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
pub fn clean() -> i128 { 0 }
RS
  done
  cat >"$dst/tools/registry-check/src/main.rs" <<'RS'
#![forbid(unsafe_code)]
fn main() {}
RS
  for p in fa fa-cli fad fa-mcp; do
    cat >"$dst/foundations/$p.tree" <<EOF
$p v0.0.1 ($dst/crates/$p)|default
fnx-classes v0.1.0 (https://github.com/Dicklesworthstone/franken_networkx?rev=9d710b1c#9d710b1c)|
EOF
  done
}

# 0. Positive control on the real workspace
run_case positive "$ROOT" "$FOUNDATIONS_DIR"
if [ "$RC" -eq 2 ] && grep -q '^UNRUN ' "$OUT"; then
  gate_abort_unrun "doctrine-negative — positive control did not run ($(grep -m1 '^UNRUN ' "$OUT" | cut -c7-))"
elif [ "$RC" -eq 0 ]; then
  gate_pass "doctrine-negative — positive control: real workspace passes all 6 checks"
else
  gate_fail "doctrine-negative — positive control: real workspace failed (exit $RC); see $OUT"
fi

# 1. Planted execute_gql / BoundPlan reference
CASE1="$WORK/case1-gql"
make_clean_tree "$CASE1"
cat >>"$CASE1/crates/fa-journal/src/lib.rs" <<'RS'
pub fn bad_query() { let _ = execute_gql("MATCH (n) RETURN n"); }
RS
run_case case1-gql "$CASE1" "$CASE1/foundations"
expect_fail "execute_gql reference" "no-raw-gql" "crates/fa-journal/src/lib.rs:3:" "execute_gql"

# 2. Planted f64 in amount crate
CASE2="$WORK/case2-float"
make_clean_tree "$CASE2"
cat >>"$CASE2/crates/fa-money/src/lib.rs" <<'RS'
pub fn bad_amount(x: i128) -> f64 { x as f64 }
RS
run_case case2-float "$CASE2" "$CASE2/foundations"
expect_fail "float in amount crate" "no-float-in-amount-crates" "crates/fa-money/src/lib.rs:3:" "f64"

# 3. Planted std::thread::spawn in production src/
CASE3="$WORK/case3-thread"
make_clean_tree "$CASE3"
cat >>"$CASE3/crates/fa-journal/src/lib.rs" <<'RS'
pub fn bad_bg() { let _ = std::thread::spawn(|| {}); }
RS
run_case case3-thread "$CASE3" "$CASE3/foundations"
expect_fail "detached thread spawn" "no-detached-threads" "crates/fa-journal/src/lib.rs:3:" "thread::spawn"

# 4. Planted #[derive(Serialize, Deserialize)] on first-party type
CASE4="$WORK/case4-serde"
make_clean_tree "$CASE4"
cat >>"$CASE4/crates/fa-model/src/lib.rs" <<'RS'
#[derive(Clone, Serialize, Deserialize)]
pub enum BadDurableEnum { A, B }
RS
run_case case4-serde "$CASE4" "$CASE4/foundations"
expect_fail "serde derive on durable type" "no-serde-durable-derive" "crates/fa-model/src/lib.rs:3:" "Serialize"

# 5. Planted missing #![forbid(unsafe_code)] at crate root
CASE5="$WORK/case5-unsafe"
make_clean_tree "$CASE5"
cat >"$CASE5/crates/fa-verify/src/lib.rs" <<'RS'
pub fn missing_forbid() -> u32 { 1 }
RS
run_case case5-unsafe "$CASE5" "$CASE5/foundations"
expect_fail "missing forbid(unsafe_code)" "forbid-unsafe-crate-roots" "crates/fa-verify/src/lib.rs:1:" "forbid(unsafe_code)"

# 6. Planted duplicate fnx-classes package ID in a posture closure
CASE6="$WORK/case6-fnx"
make_clean_tree "$CASE6"
cat >>"$CASE6/foundations/fa-mcp.tree" <<'EOF'
fnx-classes v0.2.0 (registry+https://github.com/rust-lang/crates.io-index)|default
EOF
run_case case6-fnx "$CASE6" "$CASE6/foundations"
expect_fail "duplicate fnx-classes package ID" "single-fnx-classes" "fa-mcp.tree:" "requires 1 fnx-classes package ID, found 2"

gate_verdict
