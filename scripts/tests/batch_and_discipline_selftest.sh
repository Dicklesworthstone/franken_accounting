#!/usr/bin/env bash
# Self-test for fa-7dx (pre-push hook, trunk_audit, stale_claims, claim-before-code)
# and fa-cat (merge_train batching, binary-search bisection on 5 candidates with #3 red,
# decision card with pinned fallback N=1, and UNRUN non-ejection).

set -euo pipefail

fail() {
  printf 'batch-and-discipline-selftest: FAIL %s\n' "$*" >&2
  exit 1
}
ok() {
  printf 'ok  %s\n' "$*"
}

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
base="${TMPDIR:-/tmp}/fa-batch-discipline-selftest-$$-${RANDOM:-0}"
mkdir -p "$base"
remote="$base/remote.git"
dev="$base/dev"
op="$base/operator"
work="$base/work"
counter="$base/check-runs.txt"
: > "$counter"
export FAKE_CHECK_COUNTER="$counter"
export RCH_CARGO_WRAPPER_BYPASS=1

git init -q --bare -b main "$remote"
git clone -q "$remote" "$dev" 2>/dev/null
cd "$dev"
git config user.name "AgentA"
git config user.email "agenta@example.invalid"
mkdir -p scripts/lib .beads
cp "$source_root/scripts/merge_train.sh" scripts/merge_train.sh
cp "$source_root/scripts/local_proof.sh" scripts/local_proof.sh
cp "$source_root/scripts/local_proof_verify.sh" scripts/local_proof_verify.sh
cp "$source_root/scripts/gate_workers.conf" scripts/gate_workers.conf
cp "$source_root/scripts/trunk_audit.sh" scripts/trunk_audit.sh
cp "$source_root/scripts/stale_claims.sh" scripts/stale_claims.sh
cp "$source_root/scripts/lib/gate_verdict.sh" scripts/lib/gate_verdict.sh

cat > .beads/issues.jsonl <<'JSONL'
{"id":"fa-c1","status":"in_progress","assignee":"AgentA","updated_at":"2026-10-19T00:00:00Z"}
{"id":"fa-c2","status":"in_progress","assignee":"AgentA","updated_at":"2026-10-19T00:00:00Z"}
{"id":"fa-c3","status":"in_progress","assignee":"AgentA","updated_at":"2026-10-19T00:00:00Z"}
{"id":"fa-c4","status":"in_progress","assignee":"AgentB","updated_at":"2026-10-19T00:00:00Z"}
{"id":"fa-c5","status":"in_progress","assignee":"AgentB","updated_at":"2026-10-19T00:00:00Z"}
{"id":"fa-stolen","status":"in_progress","assignee":"RealOwner","updated_at":"2026-10-19T00:00:00Z"}
JSONL

cat > scripts/check.sh <<'CHECK'
#!/usr/bin/env bash
set -eu
printf 'run\n' >> "${FAKE_CHECK_COUNTER:-/dev/null}"
if [ "${FAKE_CHECK_FORCE_UNRUN:-0}" = "1" ]; then
  printf 'UNRUN fake-gate — offloader busy\n'
  printf 'FAIL fake-gate — offloader busy\n'
  printf 'check.sh: 0 passed, 0 failed, 1 unrun\n'
  printf 'QUALITY GATE RED\n'
  printf 'QUALITY GATE RED\n' >&2
  exit 2
fi
if [ -e RED ]; then
  printf 'RED fake gate: RED is present\n'
  printf 'FAIL fake gate: RED is present\n'
  printf 'check.sh: 0 passed, 1 failed, 0 unrun\n'
  printf 'QUALITY GATE RED\n'
  printf 'QUALITY GATE RED\n' >&2
  exit 7
fi
printf 'PASS fake gate\n'
printf 'check.sh: 1 passed, 0 failed, 0 unrun\n'
printf 'ALL GATES GREEN\n'
CHECK
chmod +x scripts/*.sh
git add .
git commit -q -m "initial (fa-c1)"
git push -q origin main
initial_main="$(git rev-parse HEAD)"

# 1. Test stale_claims.sh: AgentA holds 3 in_progress (>2 limit), and fa-c2..fa-stolen have no recent commit
stale_out="$(bash scripts/stale_claims.sh --repository "$dev" --hours 24 --wip-limit 2)"
grep -Fq "WIP_LIMIT_EXCEEDED agent=AgentA count=3 limit=2" <<< "$stale_out" \
  || fail "1: stale_claims did not detect WIP limit violation for AgentA"
grep -Fq "STALE_CLAIM id=fa-stolen assignee=RealOwner" <<< "$stale_out" \
  || fail "1: stale_claims did not detect stale claim on fa-stolen"
ok "1 stale_claims.sh detects stale claims and WIP > 2 limit"

# 2. Test pre-push hook installation and enforcement (fa-7dx)
bash "$source_root/scripts/install-hooks.sh" --repository "$dev" --strict >/dev/null
printf 'unverified\n' > unverified.txt
git add unverified.txt
git commit -q -m "feat: unverified commit (fa-c1)"
unv_sha="$(git rev-parse HEAD)"
unv_tree="$(git rev-parse 'HEAD^{tree}')"
if git push -q origin main 2>"$base/push.err"; then
  fail "2: pre-push hook allowed push to main without verdict note"
fi
grep -Fq "has no green verdict note for its exact tree" "$base/push.err" \
  || fail "2: pre-push hook did not print actionable refusal message"
# Pushing to refs/heads/train/* is always allowed without a note
git push -q origin HEAD:refs/heads/train/fa-c1-AgentA
# Adding a tier0 PASS note and green verdict note for the exact tree allows pushing to main
git notes --ref=fa-tier0 add -f -m "$(printf 'tier0 v1\nverdict=pass\ntree=%s\n' "$unv_tree")" "$unv_sha"
git notes --ref=verdicts add -f -m "$(printf 'verdict=pass\ntree=%s\n' "$unv_tree")" "$unv_sha"
git push -q origin main
# Remove the train ref we just used so queue is clean for batch tests
git --git-dir="$remote" update-ref -d refs/heads/train/fa-c1-AgentA
base_main="$(git rev-parse HEAD)"
ok "2 pre-push hook refuses unverified push to main, allows refs/heads/train/*, and allows noted push"

# 3. Test trunk_audit.sh (fa-7dx): initial_main..base_main has a green verdict note -> PASS
bash scripts/trunk_audit.sh --repository "$dev" --since "$initial_main" --head "$base_main" >/dev/null
ok "3 trunk_audit.sh passes when trunk commits carry green verdict notes"

# 4. Test claim-before-code refusal in merge_train.sh (fa-7dx)
git clone -q "$remote" "$op"
git -C "$op" config user.name "TrainOp"
git -C "$op" config user.email "train@example.invalid"

git checkout -q -B cand-stolen "$base_main"
printf 'stolen work\n' > stolen.txt
git add stolen.txt
git -c user.name="Intruder" commit -q -m "feat: touch fa-stolen assigned to RealOwner"
git push -q origin HEAD:refs/heads/train/fa-stolen-Intruder
set +e
(cd "$op" && bash scripts/merge_train.sh run-batch --check-claims --work "$work") > "$base/claim.out" 2>&1
claim_rc=$?
set -e
[ "$claim_rc" -eq 6 ] || fail "4: expected exit 6 (EX_CLAIM) when only candidate fails claim check, got $claim_rc ($(cat "$base/claim.out"))"
grep -Fq "CLAIM-CONFLICT" "$base/claim.out" || fail "4: missing CLAIM-CONFLICT message"
git --git-dir="$remote" update-ref -d refs/heads/train/fa-stolen-Intruder
ok "4 merge_train.sh refuses candidate naming a bead assigned to another agent"

# 5. Test 5 queued candidates where candidate 3 is RED -> bisects (<= 3 extra gates), ejects #3, lands 1,2,4,5 (fa-cat)
: > "$counter"
for i in 1 2 3 4 5; do
  git -C "$dev" checkout -q -B "cand-$i" "$base_main"
  printf 'candidate %s\n' "$i" > "$dev/cand_${i}.txt"
  git -C "$dev" add "cand_${i}.txt"
  if [ "$i" -eq 3 ]; then
    printf 'broken\n' > "$dev/RED"
    git -C "$dev" add RED
  fi
  agent="AgentA"
  [ "$i" -ge 4 ] && agent="AgentB"
  git -C "$dev" -c user.name="$agent" commit -q -m "feat: candidate $i (fa-c$i)"
  git -C "$dev" push -q origin "HEAD:refs/heads/train/fa-c${i}-${agent}"
done

# First verify that an infra UNRUN does NOT eject any candidate
set +e
(cd "$op" && FAKE_CHECK_FORCE_UNRUN=1 bash scripts/merge_train.sh run-batch --check-claims --work "$work") > "$base/unrun.out" 2>&1
unrun_rc=$?
set -e
[ "$unrun_rc" -eq 7 ] || fail "5a: expected exit 7 (EX_UNRUN), got $unrun_rc ($(cat "$base/unrun.out"))"
grep -Fq "no candidate ejected" "$base/unrun.out" || fail "5a: UNRUN should not eject any candidate"
ok "5a infrastructure UNRUN retries and never ejects a candidate"

# Now run the real batch with candidate 3 RED
: > "$counter"
(cd "$op" && bash scripts/merge_train.sh run-batch --check-claims --work "$work") > "$base/batch.out" 2>&1
grep -Fq "DECISION-CARD: queue=5" "$base/batch.out" || fail "5b: missing DECISION-CARD log"
grep -Fq "EJECTED refs/heads/train/fa-c3-AgentA" "$base/batch.out" || fail "5b: candidate 3 was not ejected"
grep -Fq "PROMOTED-BATCH: 4 candidate(s)" "$base/batch.out" || fail "5b: remaining 4 candidates were not promoted"

total_gates="$(wc -l < "$counter" | tr -d ' ')"
# Initial stack gate (1) + <= 3 bisect gates + 1 clean remainder gate = <= 5 gates total
[ "$total_gates" -le 5 ] || fail "5b: expected <= 5 total gates (<= 3 bisect gates), saw $total_gates"

# Verify remote main contains cand_1, cand_2, cand_4, cand_5 and NOT cand_3 or RED
new_main="$(git --git-dir="$remote" rev-parse refs/heads/main)"
for i in 1 2 4 5; do
  git --git-dir="$remote" cat-file -e "${new_main}:cand_${i}.txt" 2>/dev/null \
    || fail "5b: cand_${i}.txt missing from promoted main"
done
if git --git-dir="$remote" cat-file -e "${new_main}:cand_3.txt" 2>/dev/null; then
  fail "5b: ejected cand_3.txt should not be on promoted main"
fi
ok "5b 5 candidates with #3 RED -> #3 ejected via bisection and 1,2,4,5 promoted in $total_gates total gates"

printf 'batch-and-discipline-selftest: all scenarios passed (fixtures retained at %s)\n' "$base"
