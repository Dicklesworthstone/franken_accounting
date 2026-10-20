#!/usr/bin/env bash
# Self-test for scripts/owner_watch.sh (bead fa-qu8v).
#
# Creates a temporary bare repo and stub `rch` + `br` binaries covering:
#   1. GREEN commit (stub rch exits 0 with completion markers) -> GREEN note with test totals, no bead created.
#   2. RED commit (stub rch exits 101 with rustc error[E0432]) -> RED note + P0 repair bead created with exact error and commit.
#   3. UNRUN commit (stub rch exits 103 refusing local fallback) -> UNRUN note, NO bead created.
#   4. --status prints "main@<short_sha>: GREEN|RED|UNRUN since <time>".

set -euo pipefail

fail() {
  printf 'owner-watch-selftest: FAIL %s\n' "$*" >&2
  exit 1
}
ok() {
  printf 'ok  %s\n' "$*"
}

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
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
cd "$dev"
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
STUB_RCH_MODE=green bash "$source_root/scripts/owner_watch.sh" --once \
  --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null
green_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$green_sha")"
grep -Fxq 'verdict=GREEN' <<< "$green_note" || fail "1: expected verdict=GREEN in note"
grep -Fxq 'test_totals=passed:12,failed:0' <<< "$green_note" || fail "1: expected test_totals in note"
[ ! -s "$beads_log" ] || fail "1: GREEN run should not create any bead"
grep -Eq "=== .* tip=$green_sha step=clippy verdict=PASS rc=0 worker=hz2" "$watch_log" \
  || fail "1: missing clippy log entry in watch.log"
status_line="$(bash "$source_root/scripts/owner_watch.sh" --status --remote "$remote" --ref refs/heads/main)"
grep -Eq "^main@${green_sha:0:8}: GREEN since " <<< "$status_line" \
  || fail "1: unexpected --status output: $status_line"
ok "1 GREEN commit produces GREEN note with test totals, status line, and no bead"

# 2. Push a commit with a planted compile error -> RED note + P0 bead created
printf 'use missing::Symbol;\n' >> lib.rs
git commit -q -am "feat: planted compile error without bead id"
git push -q origin main
red_sha="$(git rev-parse HEAD)"
set +e
STUB_RCH_MODE=red bash "$source_root/scripts/owner_watch.sh" --once \
  --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null
red_rc=$?
set -e
[ "$red_rc" -eq 1 ] || fail "2: expected exit 1 on RED commit, got $red_rc"
red_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$red_sha")"
grep -Fxq 'verdict=RED' <<< "$red_note" || fail "2: expected verdict=RED in note"
grep -Fq 'first_error=error[E0432]: unresolved import `missing::Symbol`' <<< "$red_note" \
  || fail "2: expected de-ANSI first_error in note"
grep -Fq 'tracker_drift_no_bead=' <<< "$red_note" \
  || fail "2: expected tracker_drift_no_bead in note"
grep -Fq "main red at ${red_sha:0:8}: error[E0432]: unresolved import \`missing::Symbol\`" "$beads_log" \
  || fail "2: expected P0 repair bead creation in beads_log"
ok "2 RED commit produces RED note, tracker drift report, and P0 repair bead with exact de-ANSI error"

# 3. Push another commit when rch refuses offload (exit 103) -> UNRUN note, NO new bead
printf '// comment\n' >> lib.rs
git commit -q -am "chore: third commit (fa-101)"
git push -q origin main
unrun_sha="$(git rev-parse HEAD)"
bead_count_before="$(wc -l < "$beads_log" | tr -d ' ')"
set +e
STUB_RCH_MODE=unrun bash "$source_root/scripts/owner_watch.sh" --once \
  --remote "$remote" --ref refs/heads/main --worktree "$watch_wt" --log-file "$watch_log" >/dev/null
unrun_rc=$?
set -e
[ "$unrun_rc" -eq 2 ] || fail "3: expected exit 2 on UNRUN commit, got $unrun_rc"
unrun_note="$(git --git-dir="$remote" notes --ref=owner-watch show "$unrun_sha")"
grep -Fxq 'verdict=UNRUN' <<< "$unrun_note" || fail "3: expected verdict=UNRUN in note"
bead_count_after="$(wc -l < "$beads_log" | tr -d ' ')"
[ "$bead_count_before" = "$bead_count_after" ] || fail "3: UNRUN must never file a RED bead"
ok "3 rch refusal (exit 103) produces UNRUN note and files no bead"

printf 'owner-watch-selftest: all 3 scenarios passed (fixtures retained at %s)\n' "$base"
