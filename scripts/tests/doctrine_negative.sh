#!/usr/bin/env bash
# =============================================================================
# scripts/tests/doctrine_negative.sh — planted negatives for `doctrine`
# (bead fa-598p)
#
# Usage: scripts/tests/doctrine_negative.sh [<foundations-dir> [<workdir>]]
#
# Runs scripts/doctrine_check.sh on the real workspace (positive control) and
# on isolated scratch fixtures, each planting one constitutional violation
# and asserting a FAIL line naming the violation and `<file>:<line>`:
#   1. planted `execute_gql` / `BoundPlan` reference;
#   2. planted `f64` in an amount crate (`crates/fa-money/src/lib.rs`);
#   3. planted `std::thread::spawn` in production `src/`;
#   4. planted `#[derive(Serialize, Deserialize)]` on a first-party type;
#   5. planted missing `#![forbid(unsafe_code)]` at a crate root;
#   6. planted duplicate `fnx-classes` package ID in a posture closure;
#   7. direct full-book scans, including production siblings after test items.
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
  gate_pass "doctrine-negative — positive control: real workspace passes all 7 checks"
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

# 7. Planted uninstrumented substrate scan in a metered crate
CASE7="$WORK/case7-scan"
make_clean_tree "$CASE7"
mkdir -p "$CASE7/crates/fa-notary/src"
cat >"$CASE7/crates/fa-notary/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
pub fn scan(db: &Db, seq: u64) { let _ = db.vertices_at(seq); }
RS
run_case case7-scan "$CASE7" "$CASE7/foundations"
expect_fail "uninstrumented substrate scan" "metered-substrate-scans" "crates/fa-notary/src/lib.rs:2:" "fa_journal::op_witness"

# Test-only attributes apply to a single item. Start with a clean file that
# uses the metered wrapper in production and literal scans in test code.
SIBLINGS="$WORK/case7-siblings"
make_clean_tree "$SIBLINGS"
mkdir -p "$SIBLINGS/crates/fa-notary/src"
cat >"$SIBLINGS/crates/fa-notary/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
#[cfg(test)]
use crate::fixtures;
#[cfg(test)]
#[allow(dead_code)]
/// The literal comparison exercises the storage read directly.
mod checks { fn literal(db: &Db) { assert!(db.vertices().is_ok()); } }
pub fn scan(db: &Db, seq: u64) { let _ = fa_journal::op_witness::vertices_at(db, seq); }
RS
run_case case7-siblings-clean "$SIBLINGS" "$SIBLINGS/foundations"
if [ "$RC" -eq 0 ]; then
  gate_pass "doctrine-negative — test-only scan and metered production sibling accepted"
else
  gate_fail "doctrine-negative — valid metered production sibling failed (exit $RC); see $OUT"
fi

# The production call occurs inside an ordinary Rust macro and crosses a line.
cat >>"$SIBLINGS/crates/fa-notary/src/lib.rs" <<'RS'
pub fn unmetered(db: &Db) { assert!(db
    .edges_at(42).is_ok()); }
#[cfg(not(test))]
pub fn production_only(db: &Db) { let _ = db /* live handle */ .vertices(); }
RS
run_case case7-siblings-raw "$SIBLINGS" "$SIBLINGS/foundations"
expect_fail "production macro scan after test items" ".edges_at()" "metered-substrate-scans" "crates/fa-notary/src/lib.rs:10:"
expect_fail "production-only method call after test items" ".vertices()" "metered-substrate-scans" "crates/fa-notary/src/lib.rs:12:"

# Only the central wrappers may issue raw reads. UFCS on the substrate,
# including an explicitly renamed import, must obey the same contract.
BOUNDARY="$WORK/case7-boundary"
make_clean_tree "$BOUNDARY"
mkdir -p "$BOUNDARY/crates/fa-journal/src/live"
mkdir -p "$BOUNDARY/crates/fa/src/tests"
cat >"$BOUNDARY/crates/fa/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
#[cfg(test)]
mod fixture;
mod tests { pub mod live; }
RS
cat >"$BOUNDARY/crates/fa/src/fixture.rs" <<'RS'
#![cfg(test)]
pub fn independent(db: &Db) { db.vertices(); }
RS
cat >"$BOUNDARY/crates/fa/src/tests/live.rs" <<'RS'
use fgdb::Database;
pub fn live(db: &Database<V>) { fa_journal::op_witness::vertices(db); }
RS
cat >"$BOUNDARY/crates/fa-journal/src/lib.rs" <<'RS'
#![forbid(unsafe_code)]
pub mod op_witness {
    pub fn vertices(db: &Db) { let rows = db.vertices(); record_vertex_scan(rows.len()); }
    pub fn txn_vertices(txn: &Txn, db: &Db) { let rows = txn.vertices(db); record_vertex_scan(rows.len()); }
}
#[cfg(test)]
mod tests;
mod live { pub mod tests; }
RS
cat >"$BOUNDARY/crates/fa-journal/src/live/tests.rs" <<'RS'
use fgdb::{Database as Store, WriteTxn};
use fgdb as graph;
pub fn counted(db: &Store) { crate::op_witness::vertices(db); }
pub fn unrelated(local: &LocalGraph) { LocalGraph::vertices(local); }
#[test]
fn literal_oracle() { Store::vertices_at(db, at); }
RS
run_case case7-boundary-clean "$BOUNDARY" "$BOUNDARY/foundations"
if [ "$RC" -eq 0 ]; then
  gate_pass "doctrine-negative — central wrappers, independent test and unrelated UFCS accepted"
else
  gate_fail "doctrine-negative — legitimate boundary or independent test rejected (exit $RC); see $OUT"
fi
cat >>"$BOUNDARY/crates/fa-journal/src/lib.rs" <<'RS'
pub fn outside(db: &Db) { db.vertices(); }
RS
cat >>"$BOUNDARY/crates/fa/src/tests/live.rs" <<'RS'
pub fn scan(txn: &fgdb::WriteTxn, db: &Database<V>) { txn.vertices::<V>(db); }
pub fn callback(db: &Database<V>) { let scan = Database::<V>::vertices_at; scan(db, at); }
RS
cat >>"$BOUNDARY/crates/fa-journal/src/live/tests.rs" <<'RS'
pub fn renamed(db: &Store) { Store::edges_at(db, at); }
pub fn txn(txn: &WriteTxn, db: &Store) { WriteTxn::vertices(txn, db); }
pub fn generic(db: &Store) { <fgdb::Database<V>>::vertices_at(db, at); }
pub fn expression(db: &Store) { assert!(graph::Database::edges(db).is_ok()); }
mod op_witness { pub fn vertices(db: &Db) { let _ = db.vertices(); } }
RS
run_case case7-boundary-raw "$BOUNDARY" "$BOUNDARY/foundations"
expect_fail "scan outside the central module" "crates/fa-journal/src/lib.rs:9:" ".vertices()"
expect_fail "renamed substrate UFCS in production tests.rs" "crates/fa-journal/src/live/tests.rs:7:" ".edges_at()"
expect_fail "transactional UFCS" "crates/fa-journal/src/live/tests.rs:8:" ".vertices()"
expect_fail "qualified generic substrate UFCS" "crates/fa-journal/src/live/tests.rs:9:" ".vertices_at()"
expect_fail "macro call with crate alias" "crates/fa-journal/src/live/tests.rs:10:" ".edges()"
expect_fail "imitated central wrapper" "crates/fa-journal/src/live/tests.rs:11:" ".vertices()"
expect_fail "generic transaction read in a facade tests directory" "crates/fa/src/tests/live.rs:3:" ".vertices()"
expect_fail "facade UFCS function pointer" "crates/fa/src/tests/live.rs:4:" ".vertices_at()"

gate_verdict
