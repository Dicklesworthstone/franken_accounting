#!/usr/bin/env bash
# =============================================================================
# scripts/tests/tier0_selftest.sh — Mutation-sensitive self-test for Tier 0
# (bead fa-1qk0)
# =============================================================================
# Acceptance tests:
#   - scripts/tests/tier0_selftest.sh::folds_two_green_trains_and_updates_main
#   - scripts/tests/tier0_selftest.sh::refuses_test_target_syntax_error
#   - scripts/tests/tier0_selftest.sh::refuses_lib_type_error
#   - scripts/tests/tier0_selftest.sh::pre_push_requires_tier0_note
#   - scripts/tests/tier0_selftest.sh::falls_back_to_local_lane_on_rch_refusal
#   - scripts/tests/tier0_selftest.sh::unrun_refuses_to_fold_without_ejecting
# =============================================================================

set -uo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../lib/gate_verdict.sh
. "$SOURCE_ROOT/scripts/lib/gate_verdict.sh"
gate_init "tier0-selftest"

base="${TMPDIR:-/tmp}/fa-tier0-selftest-$$-${RANDOM:-0}"
mkdir -p "$base/bin"
remote="$base/remote.git"
dev="$base/dev"
op="$base/operator"
work="$base/work"

# Controlled rch shim: delegates to real cargo check in the throwaway workspace
# while emitting RCH remote markers, or simulates the 2026-10-20 disk-pressure
# capacity refusal when FAKE_RCH_MODE=refuse.
cat > "$base/bin/rch" <<'RCH_STUB'
#!/usr/bin/env bash
set -uo pipefail
if [ "${FAKE_RCH_MODE:-remote}" = "refuse" ]; then
  printf '[RCH] remote required; refusing local fallback: no admissible workers (3 workers critical, disk pressure)\n' >&2
  exit 103
fi
if [ "${1:-}" = "exec" ] && [ "${2:-}" = "--" ]; then
  shift 2
fi
printf '[RCH] Selected worker: hz2 at 10.0.0.2\n'
RCH_CARGO_WRAPPER_BYPASS=1 "$@"
rc=$?
printf 'Remote command finished: exit=%s\n' "$rc"
exit "$rc"
RCH_STUB
chmod +x "$base/bin/rch"

export FA_RCH_BIN="$base/bin/rch"
export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$base/target"
export TIER0_JOBS=2

setup_fixture_repo() {
  git init -q --bare -b main "$remote"
  git clone -q "$remote" "$dev" 2>/dev/null
  cd "$dev" || gate_die "tier0-selftest: cannot cd into $dev"
  git config user.name "Tier0 Dev"
  git config user.email "dev@example.invalid"

  mkdir -p scripts/lib scripts/hooks crates/fa/src crates/fa-mcp/src crates/fa-mcp/tests
  cp "$SOURCE_ROOT/scripts/tier0.sh" scripts/tier0.sh
  cp "$SOURCE_ROOT/scripts/merge_train.sh" scripts/merge_train.sh
  cp "$SOURCE_ROOT/scripts/install-hooks.sh" scripts/install-hooks.sh
  cp "$SOURCE_ROOT/scripts/hooks/pre-push" scripts/hooks/pre-push
  cp "$SOURCE_ROOT/scripts/gate_workers.conf" scripts/gate_workers.conf
  cp "$SOURCE_ROOT/scripts/lib/gate_verdict.sh" scripts/lib/gate_verdict.sh
  chmod +x scripts/*.sh scripts/hooks/pre-push

  cat > Cargo.toml <<'TOML'
[workspace]
resolver = "2"
members = ["crates/fa", "crates/fa-mcp"]

[workspace.lints.rust]
unsafe_code = "forbid"
TOML

  cat > crates/fa/Cargo.toml <<'TOML'
[package]
name = "fa"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
TOML

  cat > crates/fa/src/lib.rs <<'RS'
#![forbid(unsafe_code)]

pub mod book {
    pub struct AsyncBook {
        context: u64,
    }

    impl AsyncBook {
        #[must_use]
        pub const fn new(context: u64) -> Self {
            Self { context }
        }

        #[must_use]
        pub const fn context(&self) -> u64 {
            self.context
        }
    }
}
RS

  cat > crates/fa-mcp/Cargo.toml <<'TOML'
[package]
name = "fa-mcp"
version = "0.1.0"
edition = "2024"

[dependencies]
fa = { path = "../fa" }

[lints]
workspace = true
TOML

  cat > crates/fa-mcp/src/lib.rs <<'RS'
#![forbid(unsafe_code)]

#[must_use]
pub const fn mcp_ready() -> bool {
    true
}
RS

  cat > crates/fa-mcp/tests/e2e_stdio.rs <<'RS'
#[test]
fn inline_fx_rates_keep_agent_provenance() {
    let book = fa::book::AsyncBook::new(42);
    assert_eq!(book.context(), 42);
    assert!(fa_mcp::mcp_ready());
}
RS

  cargo fmt --all
  git add .
  git commit -q -m "initial green workspace"
  bash scripts/tier0.sh --publish-note > "$base/init-tier0.out" 2>"$base/init-tier0.err" \
    || gate_die "tier0-selftest: initial fixture failed tier0 ($(cat "$base/init-tier0.out" "$base/init-tier0.err"))"
  git push -q origin main
  git push -q origin refs/notes/fa-tier0:refs/notes/fa-tier0

  git clone -q "$remote" "$op" 2>/dev/null
  git -C "$op" config user.name "Tier0 Train"
  git -C "$op" config user.email "train@example.invalid"
  cd "$SOURCE_ROOT" || gate_die "tier0-selftest: cannot cd back to $SOURCE_ROOT"
}

remote_main() {
  git --git-dir="$remote" rev-parse refs/heads/main
}

remote_tier0_note() {
  git --git-dir="$remote" notes --ref=fa-tier0 show "$1" 2>/dev/null || true
}

remote_train_note() {
  git --git-dir="$remote" notes --ref=merge-train show "$1" 2>/dev/null || true
}

delete_remote_trains() {
  local ref
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    git --git-dir="$remote" update-ref -d "$ref"
  done < <(git --git-dir="$remote" for-each-ref --format='%(refname)' 'refs/heads/train/')
}

# 1. Positive: folding two green trains passes tier0, names both steps PASS,
#    updates main, and records a refs/notes/fa-tier0 PASS note for the merged tree.
folds_two_green_trains_and_updates_main() {
  local base_main
  base_main="$(remote_main)"
  delete_remote_trains

  git -C "$dev" fetch -q origin main
  git -C "$dev" checkout -q -B train-green-1 "$base_main"
  cat > "$dev/crates/fa/src/fx.rs" <<'RS'
#[must_use]
pub const fn spot_mantissa(units: i128, rate_ppm: i128) -> i128 {
    units * rate_ppm
}
RS
  cat >> "$dev/crates/fa/src/lib.rs" <<'RS'

pub mod fx;
RS
  (cd "$dev" && cargo fmt --all)
  git -C "$dev" add crates/fa/src/fx.rs crates/fa/src/lib.rs
  git -C "$dev" commit -q -m "feat(fa): add fx helper (fa-1qk0)"
  git -C "$dev" push -q origin HEAD:refs/heads/train/fa-1qk0-agent1

  git -C "$dev" checkout -q -B train-green-2 "$base_main"
  cat >> "$dev/crates/fa-mcp/tests/e2e_stdio.rs" <<'RS'

#[test]
fn stdio_health_check_compiles() {
    assert!(fa_mcp::mcp_ready());
}
RS
  (cd "$dev" && cargo fmt --all)
  git -C "$dev" add crates/fa-mcp/tests/e2e_stdio.rs
  git -C "$dev" commit -q -m "test(fa-mcp): add stdio health test (fa-1qk0)"
  git -C "$dev" push -q origin HEAD:refs/heads/train/fa-1qk0-agent2

  local rc=0
  (cd "$op" && bash scripts/merge_train.sh fold --work "$work") > "$base/fold-green.out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    gate_fail "folds_two_green_trains_and_updates_main — merge_train fold exited $rc ($(cat "$base/fold-green.out"))"
    return 1
  fi

  local new_main new_tree t0_note t0_log
  new_main="$(remote_main)"
  if [ "$new_main" = "$base_main" ]; then
    gate_fail "folds_two_green_trains_and_updates_main — main did not advance"
    return 1
  fi
  new_tree="$(git --git-dir="$remote" rev-parse "${new_main}^{tree}")"
  t0_note="$(remote_tier0_note "$new_main")"
  if ! grep -Fxq "verdict=pass" <<< "$t0_note" || ! grep -Fxq "tree=$new_tree" <<< "$t0_note"; then
    gate_fail "folds_two_green_trains_and_updates_main — promoted main tip lacks refs/notes/fa-tier0 pass note for tree $new_tree ($t0_note)"
    return 1
  fi

  t0_log="$(sed -n 's/^merge-train: TIER0 PASS .*; transcript: //p' "$base/fold-green.out" | tail -n 1)"
  if [ -z "$t0_log" ] || [ ! -f "$t0_log" ]; then
    gate_fail "folds_two_green_trains_and_updates_main — missing tier0 transcript path in output"
    return 1
  fi
  if ! grep -Eq '^PASS fmt tier0 PASS step=fmt tree=' "$t0_log" \
    || ! grep -Eq '^PASS check tier0 PASS step=check tree=.* lane=remote host=.* toolchain=.* duration=[0-9]+s$' "$t0_log"; then
    gate_fail "folds_two_green_trains_and_updates_main — tier0 transcript did not name both fmt and check PASS with metadata ($(cat "$t0_log"))"
    return 1
  fi

  delete_remote_trains
  gate_pass "folds_two_green_trains_and_updates_main (promoted ${new_main:0:12}, tree ${new_tree:0:12}, both fmt and check PASS)"
  return 0
}

# 2. Planted negative: replay 11df0f1 (syntax error spliced into crates/fa-mcp/tests/e2e_stdio.rs).
#    Only `--all-targets` compiles tests/e2e_stdio.rs; tier0 must fail and main must not move.
refuses_test_target_syntax_error() {
  local before_main bad_sha
  before_main="$(remote_main)"
  delete_remote_trains

  git -C "$dev" fetch -q origin main
  git -C "$dev" checkout -q -B train-splice "$before_main"
  # Replay 11df0f1: splice a second #[test] into the middle of inline_fx_rates_keep_agent_provenance
  # while keeping valid indentation so rustfmt would not even fix the broken syntax.
  cat > "$dev/crates/fa-mcp/tests/e2e_stdio.rs" <<'RS'
#[test]
fn inline_fx_rates_keep_agent_provenance() {
    let book = fa::book::AsyncBook::new(42);
#[test]
fn spliced_audit_cluster_test_breaks_parse() {
    assert_eq!(book.context(), 42);
}
RS
  git -C "$dev" add crates/fa-mcp/tests/e2e_stdio.rs
  git -C "$dev" commit -q -m "test(fa-mcp): replay 11df0f1 spliced test target syntax error"
  bad_sha="$(git -C "$dev" rev-parse HEAD)"
  git -C "$dev" push -q origin HEAD:refs/heads/train/fa-1qk0-splice

  local rc=0
  (cd "$op" && bash scripts/merge_train.sh fold --work "$work") > "$base/splice.out" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    gate_fail "refuses_test_target_syntax_error — merge_train fold succeeded on spliced test target syntax error"
    return 1
  fi
  if [ "$(remote_main)" != "$before_main" ]; then
    gate_fail "refuses_test_target_syntax_error — main moved on a test-target syntax error"
    return 1
  fi
  local note
  note="$(remote_train_note "$bad_sha")"
  if ! grep -Fxq "verdict=red" <<< "$note"; then
    gate_fail "refuses_test_target_syntax_error — rejected candidate lacks verdict=red note ($note)"
    return 1
  fi

  delete_remote_trains
  gate_pass "refuses_test_target_syntax_error (replay 11df0f1 splice refused, exit=$rc, main unchanged at ${before_main:0:12})"
  return 0
}

# 3. Planted negative: replay 9c34c53 (E0616 private field `AsyncBook::context` accessed
#    from crates/fa/src/fx_revaluation.rs). Formatted cleanly so `fmt` passes and `check` fails.
refuses_lib_type_error() {
  local before_main bad_sha
  before_main="$(remote_main)"
  delete_remote_trains

  git -C "$dev" fetch -q origin main
  git -C "$dev" checkout -q -B train-e0616 "$before_main"
  cat > "$dev/crates/fa/src/fx_revaluation.rs" <<'RS'
use crate::book::AsyncBook;

#[must_use]
pub const fn leak_private_context(book: &AsyncBook) -> u64 {
    book.context
}
RS
  cat >> "$dev/crates/fa/src/lib.rs" <<'RS'

pub mod fx_revaluation;
RS
  (cd "$dev" && cargo fmt --all)
  git -C "$dev" add crates/fa/src/fx_revaluation.rs crates/fa/src/lib.rs
  git -C "$dev" commit -q -m "feat(fa): replay 9c34c53 private field AsyncBook::context"
  bad_sha="$(git -C "$dev" rev-parse HEAD)"
  git -C "$dev" push -q origin HEAD:refs/heads/train/fa-1qk0-e0616

  local rc=0
  (cd "$op" && bash scripts/merge_train.sh fold --work "$work") > "$base/e0616.out" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    gate_fail "refuses_lib_type_error — merge_train fold succeeded on E0616 private field error"
    return 1
  fi
  if [ "$(remote_main)" != "$before_main" ]; then
    gate_fail "refuses_lib_type_error — main moved on E0616 lib type error"
    return 1
  fi
  local t0_log
  t0_log="$(sed -n 's/^merge-train: TIER0 RED .*; transcript: //p' "$base/e0616.out" | tail -n 1)"
  if [ -z "$t0_log" ] || ! grep -Eq '^PASS fmt ' "$t0_log" || ! grep -Eq '^FAIL check tier0 FAIL step=check' "$t0_log"; then
    gate_fail "refuses_lib_type_error — tier0 transcript did not record PASS fmt + FAIL check ($(cat "${t0_log:-/dev/null}"))"
    return 1
  fi

  delete_remote_trains
  gate_pass "refuses_lib_type_error (replay 9c34c53 E0616 refused on step=check after PASS fmt, main unchanged)"
  return 0
}

# 4. Planted negative + positive: pre-push hook installed by scripts/install-hooks.sh
#    refuses a push to main without a refs/notes/fa-tier0 PASS note for that exact tree,
#    refuses a stale tree note, and allows the push once tier0.sh records PASS for the tree.
pre_push_requires_tier0_note() {
  local before_main
  before_main="$(remote_main)"

  bash "$SOURCE_ROOT/scripts/install-hooks.sh" --repository "$dev" >/dev/null
  git -C "$dev" fetch -q origin main
  git -C "$dev" checkout -q -B main "$before_main"
  cat >> "$dev/crates/fa/src/lib.rs" <<'RS'

#[must_use]
pub const fn tier0_hook_probe() -> u32 {
    7
}
RS
  (cd "$dev" && cargo fmt --all)
  git -C "$dev" add crates/fa/src/lib.rs
  git -C "$dev" commit -q -m "feat(fa): direct main push probe (fa-1qk0)"
  local probe_sha probe_tree
  probe_sha="$(git -C "$dev" rev-parse HEAD)"
  probe_tree="$(git -C "$dev" rev-parse 'HEAD^{tree}')"

  # (a) Push without any tier0 note -> must be refused even without --strict
  if git -C "$dev" push -q origin main 2>"$base/prepush-missing.err"; then
    gate_fail "pre_push_requires_tier0_note — push to main succeeded without a refs/notes/fa-tier0 note"
    return 1
  fi
  if ! grep -Fq "refs/notes/fa-tier0" "$base/prepush-missing.err"; then
    gate_fail "pre_push_requires_tier0_note — refusal message did not name refs/notes/fa-tier0 ($(cat "$base/prepush-missing.err"))"
    return 1
  fi
  if [ "$(remote_main)" != "$before_main" ]; then
    gate_fail "pre_push_requires_tier0_note — remote main moved on refused push"
    return 1
  fi

  # (b) Push with a tier0 note for a different tree hash -> must still be refused
  git -C "$dev" notes --ref=fa-tier0 add -f \
    -m "$(printf 'tier0 v1\nverdict=pass\ncommit=%s\ntree=0000000000000000000000000000000000000000\n' "$probe_sha")" \
    "$probe_sha"
  if git -C "$dev" push -q origin main 2>"$base/prepush-stale.err"; then
    gate_fail "pre_push_requires_tier0_note — push to main succeeded with a mismatched tree hash in refs/notes/fa-tier0"
    return 1
  fi

  # (c) Run tier0.sh --publish-note -> records exact tree PASS note -> push succeeds
  if ! (cd "$dev" && bash scripts/tier0.sh --publish-note >"$base/prepush-tier0.out" 2>"$base/prepush-tier0.err"); then
    gate_fail "pre_push_requires_tier0_note — tier0.sh failed on valid probe commit ($(cat "$base/prepush-tier0.out" "$base/prepush-tier0.err"))"
    return 1
  fi
  if ! git -C "$dev" push -q origin main 2>"$base/prepush-ok.err"; then
    gate_fail "pre_push_requires_tier0_note — push to main failed after tier0.sh recorded PASS note ($(cat "$base/prepush-ok.err"))"
    return 1
  fi
  git -C "$dev" push -q origin +refs/notes/fa-tier0:refs/notes/fa-tier0
  if [ "$(remote_main)" != "$probe_sha" ]; then
    gate_fail "pre_push_requires_tier0_note — remote main did not advance to $probe_sha"
    return 1
  fi

  gate_pass "pre_push_requires_tier0_note (refused missing/stale tier0 note, allowed after tier0 PASS for tree ${probe_tree:0:12})"
  return 0
}

# 5. Availability (WHAT 5): when the rch fleet refuses due to disk/capacity pressure,
#    tier0.sh falls back to the local lane on the gate host and records lane=local + host fingerprint.
falls_back_to_local_lane_on_rch_refusal() {
  local rc=0
  (
    cd "$dev"
    FAKE_RCH_MODE=refuse TIER0_HOST_FINGERPRINT="gate-host-01:Linux-x86_64" \
      bash scripts/tier0.sh --publish-note --log-dir "$base/local-fallback-logs"
  ) > "$base/local-fallback.out" 2>"$base/local-fallback.err" || rc=$?

  if [ "$rc" -ne 0 ]; then
    gate_fail "falls_back_to_local_lane_on_rch_refusal — tier0.sh exited $rc under rch refusal ($(cat "$base/local-fallback.out" "$base/local-fallback.err"))"
    return 1
  fi
  if ! grep -Eq '^PASS check tier0 PASS step=check tree=.* lane=local host=gate-host-01:Linux-x86_64 worker=local ' "$base/local-fallback.out"; then
    gate_fail "falls_back_to_local_lane_on_rch_refusal — transcript did not record lane=local and host fingerprint ($(cat "$base/local-fallback.out"))"
    return 1
  fi
  local head_sha note
  head_sha="$(git -C "$dev" rev-parse HEAD)"
  note="$(git -C "$dev" notes --ref=fa-tier0 show "$head_sha" 2>/dev/null || true)"
  if ! grep -Fxq "lane=local" <<< "$note" || ! grep -Fxq "host=gate-host-01:Linux-x86_64" <<< "$note"; then
    gate_fail "falls_back_to_local_lane_on_rch_refusal — refs/notes/fa-tier0 did not record lane=local and host fingerprint ($note)"
    return 1
  fi

  gate_pass "falls_back_to_local_lane_on_rch_refusal (rch exit 103 -> local lane fallback PASS with lane=local and host fingerprint)"
  return 0
}

# 6. UNRUN handling (WHAT 2): when tier0 reports UNRUN (e.g. rch refused and local fallback disabled),
#    merge_train.sh refuses to fold ("do not fold yet", EX_UNRUN=7) without ejecting the candidate.
unrun_refuses_to_fold_without_ejecting() {
  local before_main cand_sha
  before_main="$(remote_main)"
  delete_remote_trains

  git -C "$dev" fetch -q origin main
  git -C "$dev" checkout -q -B train-unrun "$before_main"
  cat >> "$dev/crates/fa/src/lib.rs" <<'RS'

#[must_use]
pub const fn unrun_probe() -> u32 {
    99
}
RS
  (cd "$dev" && cargo fmt --all)
  git -C "$dev" add crates/fa/src/lib.rs
  git -C "$dev" commit -q -m "feat(fa): unrun fold probe (fa-1qk0)"
  cand_sha="$(git -C "$dev" rev-parse HEAD)"
  git -C "$dev" push -q origin HEAD:refs/heads/train/fa-1qk0-unrun

  local rc=0
  (
    cd "$op"
    FAKE_RCH_MODE=refuse TIER0_DISABLE_LOCAL_FALLBACK=1 \
      bash scripts/merge_train.sh fold --work "$work"
  ) > "$base/unrun-fold.out" 2>&1 || rc=$?

  if [ "$rc" -ne 7 ]; then
    gate_fail "unrun_refuses_to_fold_without_ejecting — expected exit 7 (EX_UNRUN), got $rc ($(cat "$base/unrun-fold.out"))"
    return 1
  fi
  if [ "$(remote_main)" != "$before_main" ]; then
    gate_fail "unrun_refuses_to_fold_without_ejecting — main moved on UNRUN"
    return 1
  fi
  if ! grep -Fq "do not fold yet; no candidate ejected" "$base/unrun-fold.out"; then
    gate_fail "unrun_refuses_to_fold_without_ejecting — missing 'do not fold yet; no candidate ejected' message ($(cat "$base/unrun-fold.out"))"
    return 1
  fi
  if [ -n "$(remote_train_note "$cand_sha")" ]; then
    gate_fail "unrun_refuses_to_fold_without_ejecting — candidate should not be marked red on UNRUN"
    return 1
  fi

  delete_remote_trains
  gate_pass "unrun_refuses_to_fold_without_ejecting (UNRUN -> exit 7 'do not fold yet', main unchanged, candidate not ejected)"
  return 0
}

setup_fixture_repo

if [ "$#" -gt 0 ]; then
  for fn in "$@"; do
    case "$fn" in
      folds_two_green_trains_and_updates_main|\
      refuses_test_target_syntax_error|\
      refuses_lib_type_error|\
      pre_push_requires_tier0_note|\
      falls_back_to_local_lane_on_rch_refusal|\
      unrun_refuses_to_fold_without_ejecting)
        "$fn"
        ;;
      *)
        gate_die "tier0-selftest: unknown test function $fn"
        ;;
    esac
  done
else
  folds_two_green_trains_and_updates_main
  refuses_test_target_syntax_error
  refuses_lib_type_error
  pre_push_requires_tier0_note
  falls_back_to_local_lane_on_rch_refusal
  unrun_refuses_to_fold_without_ejecting
fi

gate_verdict
