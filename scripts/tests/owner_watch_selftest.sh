#!/usr/bin/env bash
# =============================================================================
# scripts/tests/owner_watch_selftest.sh — Self-test for scripts/owner_watch.sh
# (beads fa-qu8v, fa-j1fc)
# =============================================================================
# Creates a temporary bare repo and stub `rch` + `br` binaries covering:
#   1. GREEN commit (stub rch exits 0 with completion markers) -> GREEN note with test totals, no bead created.
#   2. red_tip_files_p0: RED commit (stub rch exits 101 with rustc error[E0432]) -> RED note + P0 repair bead created with exact de-ANSI error and commit.
#   3. UNRUN commits (stub rch exits 103 refusing local fallback, and exit 1 with "[RCH-E104] SSH command timed out") -> UNRUN note, NO bead created.
#   4. --status prints "main@<short_sha>: GREEN|RED|UNRUN since <time>".
#
# Acceptance test entry points:
#   scripts/tests/owner_watch_selftest.sh::red_tip_files_p0
# =============================================================================

set -uo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../lib/gate_verdict.sh
. "$source_root/scripts/lib/gate_verdict.sh"
gate_init "owner-watch-selftest"

fail() {
  # The EXIT trap samples the tree from the current directory: from inside
  # a fixture clone it would report the source tree as moved.
  cd "$source_root" 2>/dev/null || true
  gate_fail "$*"
  exit 1
}

base="${TMPDIR:-/tmp}/fa-owner-watch-selftest-$$-${RANDOM:-0}"
mkdir -p "$base/bin"
remote="$base/remote.git"
dev="$base/dev"
watch_wt="$base/watch-worktree"
watch_log="$base/watch.log"
beads_log="$base/created-beads.log"
: > "$beads_log"

cat > "$base/bin/stub-rch" <<'RCH'
#!/usr/bin/env bash
set -eu
mode="${STUB_RCH_MODE:-green}"
echo "  2026-10-20T00:00:00Z INFO rch::hook: Selected worker: hz2 at ubuntu@178.104.77.29"
case "$mode" in
  green)
    if [[ "$*" == *"clippy"* ]]; then
      echo "    Checking fa v0.0.1"
      echo "    Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 1.00s"
      echo "  2026-10-20T00:00:01Z INFO rch: Remote command finished: exit=0 in 1000ms"
      exit 0
    else
      echo "running 12 tests"
      echo "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
      echo "  2026-10-20T00:00:02Z INFO rch: Remote command finished: exit=0 in 1000ms"
      exit 0
    fi
    ;;
  red)
    printf '\x1b[31merror[E0432]\x1b[0m: unresolved import `missing::Symbol`\n'
    echo "  --> crates/fa/src/lib.rs:10:5"
    echo "error: could not compile \`fa\` (lib) due to 1 previous error"
    echo "  2026-10-20T00:00:01Z INFO rch: Remote command finished: exit=101 in 1000ms"
    exit 101
    ;;
  unrun)
    echo "[RCH] remote required; refusing local fallback (no admissible worker)"
    exit 103
    ;;
  ssh-timeout)
    echo "[RCH-E104] SSH command timed out (no local fallback)"
    exit 1
    ;;
  *)
    exit 99
    ;;
esac
RCH

cat > "$base/bin/stub-br" <<'BR'
#!/usr/bin/env bash
set -eu
printf 'BR_CALLED %s\n' "$*" >> "$STUB_BEADS_LOG"
BR
chmod +x "$base/bin/stub-rch" "$base/bin/stub-br"

git init -q --bare -b main "$remote"
git clone -q "$remote" "$dev" 2>/dev/null
cd "$dev" || fail "cannot cd into $dev"
git config user.name "Owner"
git config user.email "owner@users.noreply.github.com"
printf 'fn main() {}\n' > lib.rs
git add lib.rs
git commit -q -m "feat: initial green commit (fa-100)"
git push -q origin main
green_sha="$(git rev-parse HEAD)"

export FA_RCH_BIN="$base/bin/stub-rch"
export FA_BR_BIN="$base/bin/stub-br"
export STUB_BEADS_LOG="$beads_log"

# 1. Evaluate GREEN commit
green_tip_records_green_note() {
  STUB_RCH_MODE=green bash "$source_root/scripts/owner_watch.sh" --once \
    --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null
  local green_note status_line
  green_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$green_sha")"
  grep -Fxq 'verdict=GREEN' <<< "$green_note" || fail "1: expected verdict=GREEN in note"
  grep -Fxq 'test_totals=passed:12,failed:0' <<< "$green_note" || fail "1: expected test_totals in note"
  [ ! -s "$beads_log" ] || fail "1: GREEN run should not create any bead"
  grep -Eq "=== .* tip=$green_sha step=clippy verdict=PASS rc=0 worker=hz2" "$watch_log" \
    || fail "1: missing clippy log entry in watch.log"
  status_line="$(bash "$source_root/scripts/owner_watch.sh" --status --remote "$remote" --ref refs/heads/main)"
  grep -Eq "^main@${green_sha:0:8}: GREEN since " <<< "$status_line" \
    || fail "1: unexpected --status output: $status_line"
  gate_pass "green_tip_records_green_note (GREEN note with test totals, status line, and no bead)"
}

# 2. Acceptance test: planted red tip on a scratch remote files a P0 bead with the de-ANSI'd compiler error
red_tip_files_p0() {
  printf 'use missing::Symbol;\n' >> lib.rs
  git commit -q -am "feat: planted compile error without bead id"
  git push -q origin main
  local red_sha red_rc red_note
  red_sha="$(git rev-parse HEAD)"
  red_rc=0
  STUB_RCH_MODE=red bash "$source_root/scripts/owner_watch.sh" --once \
    --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null || red_rc=$?
  [ "$red_rc" -eq 1 ] || fail "2: expected exit 1 on RED commit, got $red_rc"
  red_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$red_sha")"
  grep -Fxq 'verdict=RED' <<< "$red_note" || fail "2: expected verdict=RED in note"
  grep -Fq 'first_error=error[E0432]: unresolved import `missing::Symbol`' <<< "$red_note" \
    || fail "2: expected de-ANSI first_error in note"
  grep -Fq 'tracker_drift_no_bead=' <<< "$red_note" \
    || fail "2: expected tracker_drift_no_bead in note"
  grep -Fq "main red at ${red_sha:0:8}: error[E0432]: unresolved import \`missing::Symbol\`" "$beads_log" \
    || fail "2: expected P0 repair bead creation in beads_log"
  if grep -Fq $'\x1b[' "$beads_log"; then
    fail "2: P0 bead description contains raw ANSI escape codes"
  fi
  gate_pass "red_tip_files_p0 (planted RED commit produces RED note on remote and files P0 bead with de-ANSI compiler error)"
}

# 3. Push commits when rch refuses offload (exit 103) or times out over SSH (exit 1) -> UNRUN note, NO new bead
unrun_tip_files_no_bead() {
  printf '// comment\n' >> lib.rs
  git commit -q -am "chore: third commit (fa-101)"
  git push -q origin main
  local unrun_sha bead_count_before unrun_rc unrun_note bead_count_after
  unrun_sha="$(git rev-parse HEAD)"
  bead_count_before="$(wc -l < "$beads_log" | tr -d ' ')"
  unrun_rc=0
  STUB_RCH_MODE=unrun bash "$source_root/scripts/owner_watch.sh" --once \
    --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null || unrun_rc=$?
  [ "$unrun_rc" -eq 2 ] || fail "3a: expected exit 2 on UNRUN commit, got $unrun_rc"
  unrun_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$unrun_sha")"
  grep -Fxq 'verdict=UNRUN' <<< "$unrun_note" || fail "3a: expected verdict=UNRUN in note"

  printf '// timeout probe\n' >> lib.rs
  git commit -q -am "chore: fourth commit (fa-102)"
  git push -q origin main
  local timeout_sha timeout_rc timeout_note
  timeout_sha="$(git rev-parse HEAD)"
  timeout_rc=0
  STUB_RCH_MODE=ssh-timeout bash "$source_root/scripts/owner_watch.sh" --once \
    --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null || timeout_rc=$?
  [ "$timeout_rc" -eq 2 ] || fail "3b: expected exit 2 on SSH timeout commit, got $timeout_rc"
  timeout_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$timeout_sha")"
  grep -Fxq 'verdict=UNRUN' <<< "$timeout_note" || fail "3b: expected verdict=UNRUN in note on SSH timeout"

  bead_count_after="$(wc -l < "$beads_log" | tr -d ' ')"
  [ "$bead_count_before" = "$bead_count_after" ] || fail "3: UNRUN must never file a RED bead"
  gate_pass "unrun_tip_files_no_bead (rch exit 103 and '[RCH-E104] SSH command timed out' exit 1 produce UNRUN notes and file no bead)"
}

green_tip_records_green_note
red_tip_files_p0
unrun_tip_files_no_bead

cd "$source_root" || fail "cannot cd back to $source_root"
gate_verdict
