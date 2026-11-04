#!/usr/bin/env bash
# Input-fingerprint and false-verdict controls (bead fa-xrl).
#
# Verifies:
#   Input changes and undeclared includes are detected, while unexecuted checks,
#   invalid Rust, forged stores and publication requests cannot become PASS.
#   These are metadata tests; no Rust compilation or real proof reuse is claimed.

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
mkdir -p "$repo/scripts" "$repo/registries" "$repo/crates/crate-core/src" "$repo/crates/crate-mid/src" \
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
cat > "$repo/scripts/check.sh" <<'CHECK'
#!/usr/bin/env bash
# CANONICAL_STEPS: check, test
printf 'unexpected execution\n' > checks-ran
CHECK

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

run_unrun() {
  local manifest="$1" rc
  if python3 -B "$source_root/scripts/crate_verdicts.py" \
    --repo "$repo" --output "$manifest" > "$manifest.log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  [ "$rc" -eq 2 ] || fail "expected UNRUN exit2, got $rc; log: $manifest.log"
  python3 -B - "$manifest" <<'PY'
import json
import sys
from pathlib import Path

m = json.loads(Path(sys.argv[1]).read_text())
assert m["schema"] == "fa:crate-verdicts-manifest:v2"
assert m["scope"] == "input_fingerprints_only"
assert m["status"] == "UNRUN" and m["checks_executed"] is False
assert m["total_crates"] == 4 and m["reused_crates"] == 0
assert all(c["status"] == "UNRUN" and c["reused"] is False for c in m["crates"])
assert m["workspace_steps"] == [
    {"step": "check", "status": "UNRUN"},
    {"step": "test", "status": "UNRUN"},
]
assert len(m["fingerprint_root"]) == 64
PY
  [ ! -e "$repo/checks-ran" ] || fail "input collection ran an unrequested check"
}

# 1. Fingerprints cannot assert that unexecuted checks passed.
run_unrun "$base/m1.json"
ok "1 four crate fingerprints and two planned checks remain UNRUN"

# 2. Preserve the leaf-change dependency test, without calling matching inputs proofs.
printf 'pub fn leaf_a_v2() {}\n' >> "$repo/crates/crate-leaf-a/src/lib.rs"
git commit -q -am "edit leaf-a"
run_unrun "$base/m2.json"
python3 -B - "$base/m1.json" "$base/m2.json" <<'PY'
import json
import sys
from pathlib import Path

a, b = [json.loads(Path(p).read_text()) for p in sys.argv[1:]]
before = {c["crate"]: c["input_hash"] for c in a["crates"]}
after = {c["crate"]: c["input_hash"] for c in b["crates"]}
assert {name for name in before if before[name] != after[name]} == {"crate-leaf-a"}
assert a["fingerprint_root"] != b["fingerprint_root"]
PY
ok "2 a leaf edit changes only its candidate input hash, with zero verdict reuse"

# 3. Deterministic input collection is not cold-run execution equivalence.
run_unrun "$base/m2-again.json"
cmp "$base/m2.json" "$base/m2-again.json" || fail "3 identical inputs produced different metadata"
ok "3 identical inputs produce byte-identical fingerprint metadata"

# 4. A registry edit still invalidates every candidate input fingerprint.
printf 'units-v2\n' >> "$repo/registries/units.toml"
git commit -q -am "edit registries/units.toml"
run_unrun "$base/m4.json"
python3 -B - "$base/m2.json" "$base/m4.json" <<'PY'
import json
import sys
from pathlib import Path

a, b = [json.loads(Path(p).read_text()) for p in sys.argv[1:]]
assert a["global_invalidation_digest"] != b["global_invalidation_digest"]
before = {c["crate"]: c["input_hash"] for c in a["crates"]}
assert all(before[c["crate"]] != c["input_hash"] for c in b["crates"])
PY
ok "4 a registry edit changes every candidate input hash"

# 5. Keep the explicit external-input diagnostic.
printf 'const EXT: &str = include_str!("../../../outside.txt");\n' >> "$repo/crates/crate-leaf-b/src/lib.rs"
git commit -q -am "undeclared include"
run_unrun "$base/m5.json"
python3 -B - "$base/m5.json" <<'PY'
import json
import sys
from pathlib import Path

m = json.loads(Path(sys.argv[1]).read_text())
leaf = next(c for c in m["crates"] if c["crate"] == "crate-leaf-b")
assert leaf["undeclared_external_read"] is True and leaf["undeclared_reasons"]
assert leaf["status"] == "UNRUN"
PY
ok "5 an undeclared external include is reported without a verdict"

# 6. Deliberately broken Rust still cannot receive a fabricated PASS.
printf 'this is not Rust\n' >> "$repo/crates/crate-core/src/lib.rs"
git commit -q -am "broken Rust negative control"
run_unrun "$base/m6.json"
ok "6 invalid Rust and an unexecuted compiler remain UNRUN"

# 7. A self-asserted legacy PASS store is rejected and preserved.
printf '{"forged":{"status":"PASS","tree_hash":"invented"}}\n' > "$base/forged-store.json"
before="$(sha256sum "$base/forged-store.json")"
if python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" \
  --store "$base/forged-store.json" --output "$base/forged-output.json" > "$base/forged.log" 2>&1; then
  rc=0
else
  rc=$?
fi
[ "$rc" -eq 2 ] || fail "7 a legacy store was accepted (exit $rc)"
[ "$before" = "$(sha256sum "$base/forged-store.json")" ] || fail "7 legacy evidence was overwritten"
[ ! -e "$base/forged-output.json" ] || fail "7 a legacy store produced a verdict"
ok "7 forged legacy PASS data cannot authorize reuse and stays intact"

# 8. Publishing input hashes as execution notes is refused before any note write.
notes_before="$(git for-each-ref refs/notes/crate-verdicts)"
if TMPDIR="$base" bash "$source_root/scripts/crate_verdicts.sh" --repo "$repo" \
  --output "$base/published.json" --publish-note > "$base/publish.log" 2>&1; then
  rc=0
else
  rc=$?
fi
[ "$rc" -eq 2 ] || fail "8 unproved publication was accepted (exit $rc)"
[ "$notes_before" = "$(git for-each-ref refs/notes/crate-verdicts)" ] || fail "8 a verdict note was published"
[ ! -e "$base/published.json" ] || fail "8 publication produced an unproved verdict"
# An instrumented child makes an early --self-test exec observable without
# recursively running this suite if the wrapper regresses. Use the actual
# wrapper, with only its child replaced; no accounting behavior is simulated.
wrapper_fixture="$base/wrapper-control/scripts"
mkdir -p "$wrapper_fixture/tests"
cp "$source_root/scripts/crate_verdicts.sh" "$wrapper_fixture/crate_verdicts.sh"
cat > "$wrapper_fixture/tests/crate_verdicts_selftest.sh" <<'CHILD'
#!/usr/bin/env bash
: > "${FA_CRATE_CHILD_MARKER:?}"
exit 97
CHILD
for order in self-first publish-first; do
  if [ "$order" = self-first ]; then
    flags=(--self-test --publish-note)
  else
    flags=(--publish-note --self-test)
  fi
  marker="$base/child-$order"
  if FA_CRATE_CHILD_MARKER="$marker" bash "$wrapper_fixture/crate_verdicts.sh" \
    "${flags[@]}" > "$base/flags-$order.log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  [ "$rc" -eq 2 ] || fail "8 combined flags did not refuse (order $order, exit $rc)"
  [ ! -e "$marker" ] || fail "8 publication request started a child (order $order)"
done
ok "8 unproved note publication is refused"

# 9. Retained reports cannot be overwritten by another invocation.
before="$(sha256sum "$base/m1.json")"
if python3 -B "$source_root/scripts/crate_verdicts.py" --repo "$repo" \
  --output "$base/m1.json" > "$base/overwrite.log" 2>&1; then
  rc=0
else
  rc=$?
fi
[ "$rc" -eq 2 ] || fail "9 an existing report was overwritten (exit $rc)"
[ "$before" = "$(sha256sum "$base/m1.json")" ] || fail "9 retained report bytes changed"
ok "9 existing reports are preserved"

printf 'crate-verdicts-selftest: all 9 metadata and false-verdict controls passed (fixtures retained at %s)\n' "$base"
