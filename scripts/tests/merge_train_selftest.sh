#!/usr/bin/env bash
# =============================================================================
# scripts/tests/merge_train_selftest.sh — Mutation-sensitive controls for
# scripts/merge_train.sh, local_proof.sh, and local_proof_verify.sh
# (beads fa-u7u, fa-aj8, fa-j1fc)
# =============================================================================
# Builds a throwaway bare remote with a fake scripts/tier0.sh and scripts/check.sh
# and drives the real merge_train.sh, local_proof.sh, and local_proof_verify.sh
# through every verdict (run + fold -> tier0 -> check -> local_proof -> note push),
# JSON transcript emission, README Verified-at maintenance, and remote
# refs/notes/fa-verdict verification. No Rust is compiled.
#
# Acceptance test entry points:
#   scripts/tests/merge_train_selftest.sh::red_candidate_leaves_main_and_publishes_red_note
# =============================================================================

set -uo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../lib/gate_verdict.sh
. "$source_root/scripts/lib/gate_verdict.sh"
gate_init "merge-train-selftest"

fail() {
  gate_fail "$*"
  exit 1
}

base="${TMPDIR:-/tmp}/fa-merge-train-selftest-$$-${RANDOM:-0}"
mkdir -p "$base"
remote="$base/remote.git"
dev="$base/dev"
op="$base/operator"
work="$base/work"
canonical_gate="$base/canonical-gate"
counter="$base/check-runs.txt"
: > "$counter"
export FAKE_CHECK_COUNTER="$counter"
export RCH_CARGO_WRAPPER_BYPASS=1

git init -q --bare -b main "$remote"
git clone -q "$remote" "$dev" 2>/dev/null
cd "$dev" || fail "cannot cd into $dev"
git config user.name "Self-Test Dev"
git config user.email "dev@example.invalid"
mkdir -p scripts
cp "$source_root/scripts/merge_train.sh" scripts/merge_train.sh
cp "$source_root/scripts/local_proof.sh" scripts/local_proof.sh
cp "$source_root/scripts/local_proof_verify.sh" scripts/local_proof_verify.sh
cp "$source_root/scripts/gate_workers.conf" scripts/gate_workers.conf

cat > scripts/tier0.sh <<'TIER0'
#!/usr/bin/env bash
set -eu
log_dir=""
publish_note=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --log-dir) log_dir="$2"; shift 2 ;;
    --publish-note) publish_note=1; shift ;;
    *) shift ;;
  esac
done
[ -n "$log_dir" ] && mkdir -p "$log_dir"
head_sha="$(git rev-parse HEAD)"
tree_sha="$(git rev-parse 'HEAD^{tree}')"
if [ "$publish_note" -eq 1 ]; then
  git notes --ref=fa-tier0 add -f -m "$(printf 'tier0 v1\nverdict=pass\ncommit=%s\ntree=%s\n' "$head_sha" "$tree_sha")" "$head_sha" 2>/dev/null || true
fi
printf 'PASS fmt (fake tier0)\n'
printf 'PASS check (fake tier0)\n'
printf 'tier0: 2 passed, 0 failed, 0 unrun\n'
printf 'ALL GATES GREEN\n'
TIER0

cat > scripts/check.sh <<'CHECK'
#!/usr/bin/env bash
# CANONICAL_STEPS: test-list, test
set -eu
printf 'run\n' >> "${FAKE_CHECK_COUNTER:-/dev/null}"
tree_hash="$(git rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)"
toolchain="$(rustc --version 2>/dev/null || echo unavailable)"
log_dir="${CHECK_LOG_DIR:-/tmp}"
manifest="${CHECK_STEP_MANIFEST:-/dev/null}"
# A step record carries the real time it ran: local_proof_verify.sh refuses
# a step that started before its proof (7f075b7d2).
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$log_dir"
printf '  sample::test_one: test\n  sample::test_two: test\nRemote command finished: exit=0\n[RCH] remote hz2 (1s)\n' > "$log_dir/test-list.log"
list_digest="$(sha256sum "$log_dir/test-list.log" | awk '{print $1}')"
if [ -e RED ]; then
  printf 'test sample::test_one ... FAILED\ntest result: FAILED. 0 passed; 1 failed\nRemote command finished: exit=101\n[RCH] remote hz2 (1s)\n' > "$log_dir/test.log"
  test_digest="$(sha256sum "$log_dir/test.log" | awk '{print $1}')"
  {
    printf '{"step":"test-list","status":"PASS","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
      "$tree_hash" "$toolchain" "$now" "$now" "$list_digest"
    printf '{"step":"test","status":"FAIL","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
      "$tree_hash" "$toolchain" "$now" "$now" "$test_digest"
  } > "$manifest"
  printf 'PASS test-list\n'
  printf 'FAIL fake gate: RED is tracked\n'
  printf 'QUALITY GATE RED\n'
  printf 'QUALITY GATE RED\n' >&2
  exit 7
fi
printf 'test sample::test_one ... ok\ntest sample::test_two ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored\nRemote command finished: exit=0\n[RCH] remote hz2 (1s)\n' > "$log_dir/test.log"
test_digest="$(sha256sum "$log_dir/test.log" | awk '{print $1}')"
{
  printf '{"step":"test-list","status":"PASS","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
    "$tree_hash" "$toolchain" "$now" "$now" "$list_digest"
  printf '{"step":"test","status":"PASS","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
    "$tree_hash" "$toolchain" "$now" "$now" "$test_digest"
} > "$manifest"
printf 'PASS test-list\n'
printf 'PASS test\n'
printf 'ALL GATES GREEN\n'
CHECK
chmod +x scripts/*.sh
printf 'base\n' > README.txt
printf '# FrankenAccounting\n\n> Verified at 000000000000 (2026-10-20): UNRUN\n' > README.md
git add .
git commit -q -m initial
git push -q origin main
initial_main="$(git rev-parse HEAD)"

git clone -q "$remote" "$op"
git -C "$op" config user.name "Self-Test Train"
git -C "$op" config user.email "train@example.invalid"

remote_main() { git --git-dir="$remote" rev-parse refs/heads/main; }
runs() { wc -l < "$counter" | tr -d ' '; }
train() {
  local rc=0
  (cd "$op" && bash scripts/merge_train.sh "$@" --work "$work") > "$base/last.out" 2>&1 || rc=$?
  printf '%s' "$rc"
}
note_of() { git --git-dir="$remote" notes --ref=merge-train show "$1" 2>/dev/null || true; }
verdict_note_of() { git --git-dir="$remote" notes --ref=fa-verdict show "$1" 2>/dev/null || true; }
has_note() { local obj="$1"; shift; local n; n="$(note_of "$obj")"; grep "$@" <<< "$n"; }

# 0. dry-run prints canonical gate path, designated workers, and expected warmth (fa-aj8).
rc="$(train dry-run --canonical-worktree "$canonical_gate")"
[ "$rc" = 0 ] || fail "scenario 0: dry-run exit $rc"
grep -Fxq "gate_worktree=$canonical_gate" "$base/last.out" || fail "scenario 0: missing gate_worktree"
grep -Fxq "designated_workers=hz2,vmi1152480" "$base/last.out" || fail "scenario 0: missing designated_workers"
grep -Fxq "expected_warmth=false" "$base/last.out" || fail "scenario 0: expected cold before init"
gate_pass "0 dry-run prints canonical gate path, designated workers, and warmth"

# 1. No staging branch.
rc="$(train run)"
[ "$rc" = 0 ] || fail "scenario 1: exit $rc, expected 0 ($(cat "$base/last.out"))"
grep -q '^merge-train: NOTHING' "$base/last.out" || fail "scenario 1: no NOTHING line"
[ "$(remote_main)" = "$initial_main" ] || fail "scenario 1: main moved"
gate_pass "1 no staging branch -> NOTHING, main unchanged"

# 2. A good staging commit is promoted through a --no-ff train merge using canonical gate worktree,
#    publishes refs/notes/fa-verdict to remote, and local_proof_verify.sh validates the pushed note.
cd "$dev" || fail "cannot cd into $dev"
git checkout -q -b staging
printf 'feature\n' > feature.txt
git add feature.txt
git -c user.email=35050222+bot@users.noreply.github.com commit -q -m "feat: good change"
git push -q origin staging
good_staging="$(git rev-parse HEAD)"
rc="$(train run --canonical-worktree "$canonical_gate")"
[ "$rc" = 0 ] || fail "scenario 2: exit $rc ($(cat "$base/last.out"))"
grep -q '^merge-train: PROMOTED' "$base/last.out" || fail "scenario 2: no PROMOTED line"
grep -q '^merge-train: VERDICT-NOTE note_id=' "$base/last.out" || fail "scenario 2: no VERDICT-NOTE summary line"
promoted="$(remote_main)"
parents="$(git --git-dir="$remote" rev-list --parents -n1 "$promoted")"
[ "$parents" = "$promoted $initial_main $good_staging" ] \
  || fail "scenario 2: main tip is not a --no-ff merge of (old main, staging): $parents"
has_note "$promoted" -qx 'verdict=pass' || fail "scenario 2: no pass note on the promoted merge"
has_note "$promoted" -qx 'check_exit=0' || fail "scenario 2: pass note lacks check_exit=0"
[ -n "$(git ls-remote "$remote" 'refs/notes/fa-verdict')" ] \
  || fail "scenario 2: git ls-remote origin refs/notes/fa-verdict is empty"
bash "$source_root/scripts/local_proof_verify.sh" --repository "$remote" --note "$promoted" >/dev/null \
  || fail "scenario 2: local_proof_verify.sh failed on remote refs/notes/fa-verdict note for promoted main"
grep -Eq "Verified at ${promoted:0:12} \([0-9]{4}-[0-9]{2}-[0-9]{2}\): PASS" "$op/README.md" \
  || fail "scenario 2: operator README.md was not updated with Verified at ...: PASS ($(cat "$op/README.md"))"
[ -f "$work/last-verdict.json" ] || fail "scenario 2: missing JSON transcript $work/last-verdict.json"
python3 - "$work/last-verdict.json" "$promoted" <<'PY' || fail "scenario 2: JSON transcript schema check failed"
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert doc["candidate"] == sys.argv[2]
assert len(doc["tree_hash"]) == 40
assert doc["toolchain"]
assert len(doc["note_id"]) == 40
assert len(doc["steps"]) == 2
for s in doc["steps"]:
    assert set(s) >= {"name", "verdict", "duration_ms", "witness"}
    assert s["verdict"] == "PASS"
    assert "log_digest" in s["witness"]
PY
[ "$(runs)" = 1 ] || fail "scenario 2: expected exactly 1 check run, saw $(runs)"
rc="$(train dry-run --canonical-worktree "$canonical_gate")"
grep -Fxq "expected_warmth=true" "$base/last.out" || fail "scenario 2: expected warm after canonical gate init"
gate_pass "2 good staging -> PROMOTED with refs/notes/fa-verdict validated by local_proof_verify.sh and JSON transcript"

# 2b. update-readme writes PASS only from a full-scope PASS note (fa-ygj2).
readme_before="$(cat "$op/README.md")"
rc="$(train update-readme --commit "$initial_main" --status PASS)"
[ "$rc" != 0 ] || fail "2b: update-readme wrote PASS for a commit with no verdict note"
[ "$(cat "$op/README.md")" = "$readme_before" ] || fail "2b: a refused PASS changed the README"
git -C "$op" fetch -q origin main "+refs/notes/fa-verdict:refs/notes/fa-verdict"
rc="$(train update-readme --commit "$promoted" --status PASS --date 2026-10-21)"
[ "$rc" = 0 ] || fail "2b: update-readme refused the full-scope PASS note ($(cat "$base/last.out"))"
grep -Fq "Verified at ${promoted:0:12} (2026-10-21): PASS" "$op/README.md" \
  || fail "2b: update-readme did not write the full-scope PASS ($(cat "$op/README.md"))"
gate_pass "2b update-readme refuses PASS without a full-scope note and writes it from one"

# 3. A red staging commit is refused; main does not move; refs/notes/fa-verdict records RED.
cd "$dev" || fail "cannot cd into $dev"
printf 'boom\n' > RED
git add RED
git commit -q -m "feat: breaks the gate"
git push -q origin staging
red_staging="$(git rev-parse HEAD)"
rc="$(train run --canonical-worktree "$canonical_gate")"
[ "$rc" = 1 ] || fail "scenario 3: exit $rc, expected 1 ($(cat "$base/last.out"))"
grep -q '^merge-train: RED' "$base/last.out" || fail "scenario 3: no RED line"
[ "$(remote_main)" = "$promoted" ] || fail "scenario 3: main moved on a red proof"
has_note "$red_staging" -qx 'verdict=red' || fail "scenario 3: no red note on the staging tip"
has_note "$red_staging" -qx 'warm=true' || fail "scenario 3: red note did not record warm=true on second canonical run"
has_note "$red_staging" -q '^fail: FAIL fake gate: RED is tracked$' \
  || fail "scenario 3: red note lacks the FAIL transcript line"
# The fa-verdict note stays on the merge candidate the proof checked (not the
# staging tip, whose own tree was never checked); the remote holds it.
red_cand="$(note_of "$red_staging" | sed -n 's/^candidate=//p')"
[ -n "$red_cand" ] || fail "scenario 3: the red merge-train note names no candidate"
[ "$(git --git-dir="$remote" rev-parse --verify -q "refs/merge-train/rejected/$red_cand")" = "$red_cand" ] \
  || fail "scenario 3: the rejected candidate $red_cand is not published on the remote"
grep -Fxq 'verdict=red' <<< "$(verdict_note_of "$red_cand")" \
  || fail "scenario 3: refs/notes/fa-verdict lacks verdict=red for the rejected candidate"
[ -z "$(verdict_note_of "$red_staging")" ] \
  || fail "scenario 3: a proof of the merge candidate was attributed to the staging tip"
bash "$source_root/scripts/local_proof_verify.sh" --repository "$remote" --note "$red_cand" >/dev/null \
  || fail "scenario 3: local_proof_verify.sh failed on remote refs/notes/fa-verdict RED note"
[ "$(runs)" = 2 ] || fail "scenario 3: expected 2 check runs, saw $(runs)"
gate_pass "3 red staging -> RED, main unchanged, verified red note on the published candidate, merge-train note on the tip"

# 4. The same pair is not re-proved.
rc="$(train run --canonical-worktree "$canonical_gate")"
[ "$rc" = 1 ] || fail "scenario 4: exit $rc, expected 1"
grep -q '^merge-train: BOUNCED-ALREADY' "$base/last.out" || fail "scenario 4: no BOUNCED-ALREADY line"
[ "$(runs)" = 2 ] || fail "scenario 4: the check was re-run ($(runs) runs)"
gate_pass "4 unchanged bounced pair -> BOUNCED-ALREADY without re-proving"

# 5. A direct push to main (the violation audit must catch), plus a conflicting staging edit.
direct="$base/direct"
git clone -q "$remote" "$direct"
cd "$direct" || fail "cannot cd into $direct"
printf 'main version\n' > README.txt
git -c user.name=Bot -c user.email=35050222+bot@users.noreply.github.com commit -q -am "feat: pushed straight to main"
git push -q origin main
direct_commit="$(git rev-parse HEAD)"
cd "$dev" || fail "cannot cd into $dev"
git rm -q RED
printf 'staging version\n' > README.txt
git commit -q -am "fix: remove RED, edit README"
git push -q origin staging
conflict_staging="$(git rev-parse HEAD)"
rc="$(train run)"
[ "$rc" = 3 ] || fail "scenario 5: exit $rc, expected 3 ($(cat "$base/last.out"))"
grep -q '^merge-train: CONFLICT' "$base/last.out" || fail "scenario 5: no CONFLICT line"
[ "$(remote_main)" = "$direct_commit" ] || fail "scenario 5: main moved on a conflict"
has_note "$conflict_staging" -qx 'conflict=README.txt' || fail "scenario 5: conflict note lacks the file"
gate_pass "5 conflicting staging -> CONFLICT note naming README.txt"

# 6. Audit catches the direct push and counts the train merge as proven.
rc="$(train audit --since "$initial_main")"
[ "$rc" = 1 ] || fail "scenario 6: audit exit $rc, expected 1 ($(cat "$base/last.out"))"
grep -q "^VIOLATION first-parent ${direct_commit:0:12}" "$base/last.out" \
  || fail "scenario 6: audit did not name the direct push ($(cat "$base/last.out"))"
grep -q 'proven=1 unproven=1 violations=1' "$base/last.out" \
  || fail "scenario 6: unexpected audit tally ($(tail -1 "$base/last.out"))"
gate_pass "6 audit -> VIOLATION for the direct toolchain-less push; train merge counted proven"

# 7. Repair staging by merging main into it; --no-push proves without moving main, then a real run promotes.
cd "$dev" || fail "cannot cd into $dev"
git fetch -q origin
if git merge -q --no-edit origin/main >/dev/null 2>&1; then
  fail "scenario 7: fixture expected a conflict to resolve"
fi
printf 'resolved\n' > README.txt
git add README.txt
git commit -q -m "merge main into staging; resolve README"
git push -q origin staging
before="$(remote_main)"
rc="$(train run --no-push)"
[ "$rc" = 0 ] || fail "scenario 7a: exit $rc ($(cat "$base/last.out"))"
grep -q '^merge-train: PASS (--no-push)' "$base/last.out" || fail "scenario 7a: no PASS (--no-push) line"
[ "$(remote_main)" = "$before" ] || fail "scenario 7a: --no-push moved main"
rc="$(train run)"
[ "$rc" = 0 ] || fail "scenario 7b: exit $rc ($(cat "$base/last.out"))"
grep -q '^merge-train: PROMOTED' "$base/last.out" || fail "scenario 7b: no PROMOTED line"
[ "$(git --git-dir="$remote" show "$(remote_main)":README.txt)" = resolved ] \
  || fail "scenario 7b: promoted tree lacks the resolution"
gate_pass "7 --no-push proves without moving main; the real run promotes"

# 8. Acceptance test (fa-j1fc): fold -> tier0 -> check -> local_proof -> note push
#    with a green candidate (promotes and publishes verified PASS fa-verdict note)
#    followed by a planted-red candidate (leaves main unchanged and publishes RED fa-verdict note).
red_candidate_leaves_main_and_publishes_red_note() {
  cd "$dev" || fail "cannot cd into $dev"
  git fetch -q origin main
  local base_main fold_green_sha promoted_fold red_cand_sha fold_rc
  base_main="$(remote_main)"

  # 8a. Green train candidate via `fold`
  git checkout -q -B train-fold-green "$base_main"
  printf 'fold green\n' > fold_green.txt
  git add fold_green.txt
  git commit -q -m "feat: green fold candidate (fa-j1fc)"
  fold_green_sha="$(git rev-parse HEAD)"
  git push -q origin HEAD:refs/heads/train/fa-j1fc-green

  fold_rc="$(train fold)"
  [ "$fold_rc" = 0 ] || fail "8a: fold green exited $fold_rc ($(cat "$base/last.out"))"
  promoted_fold="$(remote_main)"
  [ "$promoted_fold" != "$base_main" ] || fail "8a: main did not advance on green fold"
  has_note "$fold_green_sha" -qx 'verdict=pass' || fail "8a: fold_green_sha lacks pass note"
  bash "$source_root/scripts/local_proof_verify.sh" --repository "$remote" --note "$promoted_fold" >/dev/null \
    || fail "8a: local_proof_verify.sh failed on promoted fold main tip $promoted_fold"
  grep -Fq "not product correctness beyond them" <<< "$(verdict_note_of "$promoted_fold")" \
    || fail "8a: PASS note lacks no-claim boundary"
  git --git-dir="$remote" update-ref -d refs/heads/train/fa-j1fc-green

  # 8b. Planted-red train candidate whose tier-1 tests fail (tier0 passes, check.sh fails)
  git fetch -q origin main
  git checkout -q -B train-fold-red "$promoted_fold"
  printf 'planted red\n' > RED
  git add RED
  git commit -q -m "feat: planted red fold candidate (fa-j1fc)"
  red_cand_sha="$(git rev-parse HEAD)"
  git push -q origin HEAD:refs/heads/train/fa-j1fc-red

  fold_rc="$(train fold)"
  [ "$fold_rc" = 1 ] || fail "8b: expected exit 1 on planted-red fold candidate, got $fold_rc ($(cat "$base/last.out"))"
  [ "$(remote_main)" = "$promoted_fold" ] || fail "8b: main moved on planted-red fold candidate"
  # As in scenario 3: the RED note stays on the stacked merge the proof checked.
  local red_merge
  red_merge="$(note_of "$red_cand_sha" | sed -n 's/^candidate=//p')"
  [ -n "$red_merge" ] || fail "8b: the ejected ref's merge-train note names no candidate"
  [ "$(git --git-dir="$remote" rev-parse --verify -q "refs/merge-train/rejected/$red_merge")" = "$red_merge" ] \
    || fail "8b: the rejected merge $red_merge is not published on the remote"
  grep -Fxq 'verdict=red' <<< "$(verdict_note_of "$red_merge")" \
    || fail "8b: planted-red candidate lacks verdict=red in remote refs/notes/fa-verdict"
  bash "$source_root/scripts/local_proof_verify.sh" --repository "$remote" --note "$red_merge" >/dev/null \
    || fail "8b: local_proof_verify.sh failed on remote RED note for $red_merge"

  gate_pass "red_candidate_leaves_main_and_publishes_red_note (fold E2E green promotes with verified fa-verdict note; planted-red leaves main unchanged and publishes verified RED fa-verdict note)"
}

red_candidate_leaves_main_and_publishes_red_note

# 9. A PASS over fewer steps than check.sh declares is promoted, but the
#    README names its scope and update-readme will not call it PASS (fa-ygj2).
cd "$dev" || fail "cannot cd into $dev"
git fetch -q origin
git checkout -q -B staging origin/main
sed -i 's/^# CANONICAL_STEPS: test-list, test$/# CANONICAL_STEPS: fmt, test-list, test/' scripts/check.sh
grep -qx '# CANONICAL_STEPS: fmt, test-list, test' scripts/check.sh || fail "scenario 9: fixture header not rewritten"
git commit -q -am "gate: declare a step this check does not run"
git push -q origin staging
rc="$(train run --canonical-worktree "$canonical_gate")"
[ "$rc" = 0 ] || fail "scenario 9: exit $rc ($(cat "$base/last.out"))"
grep -q '^merge-train: PROMOTED' "$base/last.out" || fail "scenario 9: no PROMOTED line"
partial="$(remote_main)"
grep -Fq "Verified at ${partial:0:12} " "$op/README.md" || fail "scenario 9: README not updated for $partial"
grep -Eq "Verified at ${partial:0:12} \([0-9]{4}-[0-9]{2}-[0-9]{2}\): PASS \(partial scope\)" "$op/README.md" \
  || fail "scenario 9: a partial-scope PASS was written as a full PASS ($(cat "$op/README.md"))"
git -C "$op" fetch -q origin main "+refs/notes/fa-verdict:refs/notes/fa-verdict"
rc="$(train update-readme --commit "$partial" --status PASS)"
[ "$rc" != 0 ] || fail "scenario 9: update-readme wrote PASS from a partial-scope note"
gate_pass "9 partial-scope PASS -> promoted, README says PASS (partial scope), update-readme refuses PASS"

cd "$source_root" || fail "cannot cd back to $source_root"
gate_verdict
