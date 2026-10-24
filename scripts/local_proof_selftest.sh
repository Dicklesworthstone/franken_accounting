#!/usr/bin/env bash
# Retained mutation-sensitive controls for local proof production, verification,
# split-run union, git notes, and bead-close tree attribution (bead fa-u7u).

set -euo pipefail

fail() {
  printf 'local-proof-selftest: %s\n' "$*" >&2
  exit 1
}

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
run_id="$$-${RANDOM:-0}"
base="${TMPDIR:-/tmp}/fa-local-proof-selftest-$run_id"
fixture="$base/repository"
mkdir -p "$fixture/scripts/lib"
cp "$source_root/scripts/local_proof.sh" "$fixture/scripts/local_proof.sh"
cp "$source_root/scripts/local_proof_verify.sh" "$fixture/scripts/local_proof_verify.sh"
cp "$source_root/scripts/close_bead.sh" "$fixture/scripts/close_bead.sh"
cp "$source_root/scripts/lib/gate_verdict.sh" "$fixture/scripts/lib/gate_verdict.sh"

cat > "$fixture/scripts/check.sh" <<'CHECK'
#!/usr/bin/env bash
set -eu
if [ -n "${FAKE_PROOF_CHECK_MARKER:-}" ]; then
  printf 'ran\n' > "$FAKE_PROOF_CHECK_MARKER"
fi
tree_hash="$(git rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)"
toolchain="$(rustc --version 2>/dev/null || echo unavailable)"
ROOT="$PWD"
LOG_DIR="$CHECK_LOG_DIR"
STEP_MANIFEST="$CHECK_STEP_MANIFEST"
CHECK_TREE_HASH="$tree_hash"
CHECK_TOOLCHAIN="$toolchain"
: >"$STEP_MANIFEST"
. scripts/lib/gate_verdict.sh
CHECK
# Exercise the actual producer helpers, not a stdout-based imitation of reuse.
sed -n '/^hash_file() {/,/^gate_init /{ /^gate_init /!p; }' \
  "$source_root/scripts/check.sh" >> "$fixture/scripts/check.sh"
cat >> "$fixture/scripts/check.sh" <<'CHECK'

emit_step() {
  local step="$1" status="$2"
  printf 'fixture gate %s %s\n' "$step" "$status" >"$LOG_DIR/$step.log"
  if [ "${FAKE_PROOF_MODE:-}" = compile-controls ]; then
    case "$step" in
      check) printf '    Finished dev profile\n' >>"$LOG_DIR/$step.log" ;;
      test-list) printf 'sample::one: test\nsample::two: test\n' >>"$LOG_DIR/$step.log" ;;
      test) printf 'test sample::one ... ok\ntest sample::two ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored\n' >>"$LOG_DIR/$step.log" ;;
    esac
    printf 'Remote command finished: exit=0\n' >>"$LOG_DIR/$step.log"
  fi
  record_step_verdict "$step" "$status" "2026-10-20T00:00:00Z" "2026-10-20T00:00:01Z" 1 "$LOG_DIR/$step.log"
}

case "${FAKE_PROOF_MODE:-pass}" in
  compile-controls)
    for step in check test-list test; do
      emit_step "$step" PASS
      printf 'PASS %s\n' "$step"
    done
    printf 'ALL GATES GREEN\n'
    ;;
  pass)
    emit_step "fake-step-1" "PASS"
    printf 'PASS fake-step-1\n'
    printf 'ALL GATES GREEN\n'
    ;;
  split-1)
    emit_step "fake-step-1" "PASS"
    printf 'PASS fake-step-1\n'
    emit_step "fake-step-2" "UNRUN"
    printf 'UNRUN fake-step-2 — worker busy\n'
    printf 'FAIL check.sh: 1 gate(s) did not run\n'
    printf 'QUALITY GATE RED\n'
    printf 'QUALITY GATE RED\n' >&2
    exit 2
    ;;
  split-2)
    if [ "${FAKE_PROOF_COPY_FAILURE:-0}" = 1 ]; then
      mkdir "$LOG_DIR/fake-step-1.log"
    fi
    if try_reuse_step "fake-step-1" "$LOG_DIR/fake-step-1.log"; then
      :
    else
      exit 98
    fi
    emit_step "fake-step-2" "PASS"
    printf 'PASS fake-step-2\n'
    printf 'ALL GATES GREEN\n'
    ;;
  red)
    emit_step "fake-step-1" "FAIL"
    printf 'RED fake gate\n'
    printf 'FAIL fake gate\n'
    printf 'QUALITY GATE RED\n'
    printf 'QUALITY GATE RED\n' >&2
    exit "${FAKE_PROOF_RED_EXIT:-7}"
    ;;
  move)
    emit_step "fake-step-1" "PASS"
    printf 'changed\n' >> tracked.txt
    printf 'PASS fake-step-1\n'
    printf 'ALL GATES GREEN\n'
    ;;
  *) exit 99 ;;
esac
CHECK
chmod +x "$fixture/scripts/"*.sh

rehash() {
  local proof="$1"
  (
    cd "$proof"
    : > SHA256SUMS
    while IFS= read -r file; do
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" >> SHA256SUMS
      else
        shasum -a 256 "$file" >> SHA256SUMS
      fi
    done < <(find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort)
  )
}

expect_red() {
  local proof="$1" reason="$2"
  if bash scripts/local_proof_verify.sh --repository "$fixture" "$proof" >/dev/null 2>&1; then
    fail "verifier accepted $reason"
  fi
}

make_v1_proof() {
  local source="$1" target="$2"
  mkdir "$target"
  local file
  for file in command.txt tools.txt commit-before.txt commit-after.txt \
      status-before.txt status-after.txt check.stdout.log check.stderr.log \
      check-exit.txt; do
    cp "$source/$file" "$target/$file"
  done
  awk -F= '
    $1 == "format_version" { print "format_version=1"; next }
    $1 == "tree" || $1 == "check_script_path" || $1 == "check_script_blob" { next }
    { print }
  ' "$source/manifest.txt" > "$target/manifest.txt"
  rehash "$target"
}

cd "$fixture"
git init -q -b main
git config user.name "Local Proof Self-Test"
git config user.email "local-proof-selftest@example.invalid"
printf 'stable\n' > tracked.txt
git add .
git commit -q -m "initial (fa-test-1)"
commit_a="$(git rev-parse HEAD)"

# Dirty worktree refusal
printf 'untracked\n' > dirty.tmp
if FAKE_PROOF_MODE=pass bash scripts/local_proof.sh --output "$base/dirty-attempt" >/dev/null 2>&1; then
  fail "producer accepted a dirty worktree"
fi
git checkout -q -- .
# Move dirty.tmp outside repository rather than deleting
mv dirty.tmp "$base/dirty-moved.tmp"

pass_proof="$base/pass"
FAKE_PROOF_MODE=pass bash scripts/local_proof.sh --output "$pass_proof" --publish-note >/dev/null
bash scripts/local_proof_verify.sh --repository "$fixture" "$pass_proof" >/dev/null
grep -Fxq 'format_version=3' "$pass_proof/manifest.txt" || fail "producer did not emit v3"
git notes --ref=fa-verdict show "$commit_a" | grep -Fxq 'verdict=pass' \
  || fail "--publish-note did not record refs/notes/fa-verdict on commit"

# Split-run positive: Run 1 has 1 PASS + 1 UNRUN; Run 2 resumes from Run 1 and completes fake-step-2 -> PASS
split1_proof="$base/split-1"
set +e
FAKE_PROOF_MODE=split-1 bash scripts/local_proof.sh --output "$split1_proof" >/dev/null
split1_rc=$?
set -e
[ "$split1_rc" -eq 2 ] || fail "split-1 did not exit 2 on UNRUN"
bash scripts/local_proof_verify.sh --repository "$fixture" "$split1_proof" >/dev/null

split2_proof="$base/split-2"
FAKE_PROOF_MODE=split-2 bash scripts/local_proof.sh --output "$split2_proof" --resume-from "$split1_proof" >/dev/null
bash scripts/local_proof_verify.sh --repository "$fixture" "$split2_proof" >/dev/null
bash scripts/local_proof_verify.sh "$split2_proof" >/dev/null
grep -Fxq 'verdict=pass' "$split2_proof/manifest.txt" || fail "split-run union did not produce verdict=pass"
grep -Fq 'PASS fake-step-1 (reused from verified split-run' "$split2_proof/check.stdout.log" \
  || fail "split-run union did not reuse fake-step-1"
python3 -B - "$split1_proof" "$split2_proof" <<'PY'
import hashlib, json, pathlib, sys
prior, current = map(pathlib.Path, sys.argv[1:])
before = json.loads((prior / 'step-verdicts.jsonl').read_text().splitlines()[0])
after = json.loads((current / 'step-verdicts.jsonl').read_text().splitlines()[0])
assert {k: v for k, v in after.items() if k != 'reused_from'} == before
assert after['reused_from']['proof'] == hashlib.sha256((prior / 'SHA256SUMS').read_bytes()).hexdigest()
assert (current / 'steps/fake-step-1.log').read_bytes() == (prior / 'steps/fake-step-1.log').read_bytes()
PY

v1_proof="$base/v1-pass"
make_v1_proof "$pass_proof" "$v1_proof"
bash scripts/local_proof_verify.sh --repository "$fixture" "$v1_proof" >/dev/null
if FAKE_PROOF_MODE=pass bash scripts/local_proof.sh --output "$base/legacy-resume" --resume-from "$v1_proof" \
    >"$base/legacy-resume.stdout" 2>"$base/legacy-resume.stderr"; then
  fail "producer reused legacy proof without retained evidence"
fi
v2_proof="$base/v2-pass"
make_v1_proof "$pass_proof" "$v2_proof"
for file in tree-before.txt tree-after.txt check-script-blob.txt; do
  cp "$pass_proof/$file" "$v2_proof/$file"
done
sed 's/^format_version=3$/format_version=2/' "$pass_proof/manifest.txt" >"$v2_proof/manifest.txt"
rehash "$v2_proof"
bash scripts/local_proof_verify.sh --repository "$fixture" "$v2_proof" >/dev/null
if FAKE_PROOF_MODE=pass bash scripts/local_proof.sh --output "$base/legacy-v2-resume" --resume-from "$v2_proof" \
    >"$base/legacy-v2-resume.stdout" 2>"$base/legacy-v2-resume.stderr"; then
  fail "producer reused v2 proof without retained evidence"
fi

# These are synthetic compiler transcripts testing the evidence validator,
# never evidence that Rust ran. Rehash outer sums and step digests so the
# marker/inventory controls, rather than only checksum mismatch, must reject.
compile_proof="$base/compile-controls"
FAKE_PROOF_MODE=compile-controls bash scripts/local_proof.sh --output "$compile_proof" >/dev/null
for mutation in completion inventory duplicate-key uncertain; do
  altered="$base/compile-$mutation"
  cp -R "$compile_proof" "$altered"
  python3 -B - "$altered" "$mutation" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
records = [json.loads(line) for line in (root / 'step-verdicts.jsonl').read_text().splitlines()]
path = root / ('steps/check.log' if mutation == 'completion' else 'steps/test.log')
text = path.read_text()
if mutation == 'completion': text = text.replace('Remote command finished: exit=0', 'remote command status unknown')
if mutation == 'inventory': text = text.replace('test sample::two ... ok\n', '')
if mutation == 'uncertain': text += 'RCH_SCOPED_COMPLETION_UNCONFIRMED\n'
path.write_text(text)
for record in records:
    record['log_digest'] = hashlib.sha256((root / 'steps' / (record['step'] + '.log')).read_bytes()).hexdigest()
lines = [json.dumps(record, separators=(',', ':')) for record in records]
if mutation == 'duplicate-key': lines[0] = lines[0].replace('"status":"PASS"', '"status":"FAIL","status":"PASS"')
(root / 'step-verdicts.jsonl').write_text('\n'.join(lines) + '\n')
tools = [line for line in (root / 'tools.txt').read_text().splitlines() if not line.startswith('step_verdict=')]
(root / 'tools.txt').write_text('\n'.join(tools + ['step_verdict=' + line for line in lines]) + '\n')
PY
  rehash "$altered"
  if [ "$mutation" = uncertain ]; then
    if bash scripts/local_proof_verify.sh --repository "$fixture" --for-resume "$altered" \
        >"$base/uncertain.stdout" 2>"$base/uncertain.stderr"; then
      fail "resume accepted an uncertain completion for automatic retry"
    fi
  else
    expect_red "$altered" "rehashed $mutation compiler evidence"
  fi
done
if FAKE_PROOF_MODE=split-2 FAKE_PROOF_COPY_FAILURE=1 \
    bash scripts/local_proof.sh --output "$base/copy-failure" --resume-from "$split1_proof" \
    >"$base/copy-failure.stdout" 2>"$base/copy-failure.stderr"; then
  fail "producer ignored reused-log copy failure"
fi
grep -Fq 'evidence copy failed; command was not retried' "$base/copy-failure/check.stdout.log" \
  || fail "copy failure was not explicit"
[ ! -e "$base/copy-failure/steps/fake-step-2.log" ] || fail "producer continued after reused-log copy failure"

# Admission must reject before invoking even a replacement check.sh. Both raw
# checksum corruption and rehashed semantic lies are tested in real processes.
for mutation in tools log missing-log sums toolchain duplicate malformed stdout-only wrong-tree wrong-script; do
  prior="$base/resume-$mutation"
  cp -R "$split1_proof" "$prior"
  python3 -B - "$prior" "$mutation" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
records = (root / 'step-verdicts.jsonl').read_text().splitlines()
if mutation == 'tools':
    with (root / 'tools.txt').open('a') as file: file.write('tampered=true\n')
elif mutation == 'log':
    with (root / 'steps/fake-step-1.log').open('a') as file: file.write('tampered\n')
elif mutation == 'missing-log':
    (root / 'steps/fake-step-1.log').rename(root / 'steps/retained-missing-log')
elif mutation == 'sums':
    with (root / 'SHA256SUMS').open('a') as file: file.write('bad checksum\n')
elif mutation == 'toolchain':
    altered = []
    for line in records:
        record = json.loads(line)
        record['toolchain'] = 'rustc wrong-toolchain'
        altered.append(json.dumps(record, separators=(',', ':')))
    (root / 'step-verdicts.jsonl').write_text('\n'.join(altered) + '\n')
    tools = (root / 'tools.txt').read_text().splitlines()
    tools = ['rustc=rustc wrong-toolchain' if line.startswith('rustc=') else line for line in tools if not line.startswith('step_verdict=')]
    (root / 'tools.txt').write_text('\n'.join(tools + ['step_verdict=' + line for line in altered]) + '\n')
elif mutation == 'duplicate':
    with (root / 'step-verdicts.jsonl').open('a') as file: file.write(records[0] + '\n')
elif mutation == 'malformed':
    with (root / 'step-verdicts.jsonl').open('a') as file: file.write('{broken\n')
elif mutation == 'stdout-only':
    (root / 'step-verdicts.jsonl').write_text('\n'.join(records[1:]) + '\n')
    tools = (root / 'tools.txt').read_text().splitlines()
    (root / 'tools.txt').write_text('\n'.join(line for line in tools if not line.startswith('step_verdict=' + records[0])) + '\n')
elif mutation in ('wrong-tree', 'wrong-script'):
    key, file = ('tree', 'tree-before.txt') if mutation == 'wrong-tree' else ('check_script_blob', 'check-script-blob.txt')
    lines = (root / 'manifest.txt').read_text().splitlines()
    (root / 'manifest.txt').write_text('\n'.join(key + '=' + '0' * 40 if line.startswith(key + '=') else line for line in lines) + '\n')
    (root / file).write_text('0' * 40 + '\n')
PY
  case "$mutation" in tools|log|sums) ;; *) rehash "$prior" ;; esac
  marker="$base/resume-ran-$mutation"
  if FAKE_PROOF_MODE=pass FAKE_PROOF_CHECK_MARKER="$marker" \
      bash scripts/local_proof.sh --output "$base/resume-output-$mutation" --resume-from "$prior" \
      >"$base/resume-$mutation.stdout" 2>"$base/resume-$mutation.stderr"; then
    fail "producer accepted resume mutation $mutation"
  fi
  [ ! -e "$marker" ] || fail "producer ran check after rejected $mutation evidence"
done

# Final independent verification rejects changed reused logs and changed origin
# identity even when the outer checksum manifest is regenerated by an attacker.
for mutation in reused-log provenance; do
  altered="$base/$mutation"
  cp -R "$split2_proof" "$altered"
  if [ "$mutation" = reused-log ]; then
    printf 'changed reused log\n' >>"$altered/steps/fake-step-1.log"
  else
    python3 -B - "$altered" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
records = [json.loads(line) for line in (root / 'step-verdicts.jsonl').read_text().splitlines()]
records[0]['worker'] = 'invented-worker'
lines = [json.dumps(record, separators=(',', ':')) for record in records]
(root / 'step-verdicts.jsonl').write_text('\n'.join(lines) + '\n')
tools = [line for line in (root / 'tools.txt').read_text().splitlines() if not line.startswith('step_verdict=')]
(root / 'tools.txt').write_text('\n'.join(tools + ['step_verdict=' + line for line in lines]) + '\n')
PY
  fi
  rehash "$altered"
  expect_red "$altered" "$mutation in a reused proof"
done

red_proof="$base/red"
set +e
FAKE_PROOF_MODE=red bash scripts/local_proof.sh --output "$red_proof" >/dev/null
red_exit=$?
set -e
[ "$red_exit" -eq 7 ] || fail "red proof did not preserve check exit 7"
bash scripts/local_proof_verify.sh --repository "$fixture" "$red_proof" >/dev/null

# Split-run negative: a FAIL recorded in red_proof blocks --resume-from
if FAKE_PROOF_MODE=pass bash scripts/local_proof.sh --output "$base/split-from-fail" --resume-from "$red_proof" >/dev/null 2>&1; then
  fail "producer allowed --resume-from a proof containing a FAIL step"
fi

# Bead-close tree attribution: manifest for commit_a (tree A) can close fa-test-1,
# but CANNOT close fa-test-2 landed in commit_b (tree B)
FA_CLOSE_BEAD_DRY_RUN=1 bash scripts/close_bead.sh fa-test-1 \
  --manifest "$pass_proof" --repository "$fixture" --reason "landed in commit A" >/dev/null

printf 'second tree\n' >> tracked.txt
git add tracked.txt
git commit -q -m "second change (fa-test-2)"
commit_b="$(git rev-parse HEAD)"
if FA_CLOSE_BEAD_DRY_RUN=1 bash scripts/close_bead.sh fa-test-2 \
    --manifest "$pass_proof" --commit "$commit_b" --repository "$fixture" --reason "wrong tree" >/dev/null 2>&1; then
  fail "close_bead.sh accepted a manifest from tree A for a bead landed in tree B"
fi

move_proof="$base/move"
set +e
FAKE_PROOF_MODE=move bash scripts/local_proof.sh --output "$move_proof" >/dev/null
move_exit=$?
set -e
[ "$move_exit" -eq 125 ] || fail "moving tree did not produce void exit 125"
bash scripts/local_proof_verify.sh --repository "$fixture" "$move_proof" >/dev/null

git add tracked.txt
git commit -q -m stabilize-after-movement

# Exercise producer infrastructure failures without compiling or running Rust.
fault_bin="$base/fault-bin"
mkdir "$fault_bin"
LOCAL_PROOF_REAL_GIT="$(command -v git)"
LOCAL_PROOF_REAL_MKDIR="$(command -v mkdir)"
LOCAL_PROOF_REAL_FIND="$(command -v find)"
LOCAL_PROOF_REAL_SORT="$(command -v sort)"
LOCAL_PROOF_REAL_HASH="$(command -v sha256sum || command -v shasum)"
export LOCAL_PROOF_REAL_GIT LOCAL_PROOF_REAL_MKDIR LOCAL_PROOF_REAL_FIND
export LOCAL_PROOF_REAL_SORT LOCAL_PROOF_REAL_HASH

cat > "$fault_bin/git" <<'SHIM'
#!/usr/bin/env bash
set -eu
if [ "${1:-}" = status ]; then
  case "${FAKE_PROOF_FAULT:-}" in
    before-status)
      if [ ! -e "$FAKE_PROOF_CHECK_MARKER" ]; then
        printf 'injected status capture failure\n' >&2
        exit 69
      fi
      ;;
    after-status)
      if [ -e "$FAKE_PROOF_CHECK_MARKER" ]; then
        printf 'injected status capture failure\n' >&2
        exit 69
      fi
      ;;
  esac
fi
exec "$LOCAL_PROOF_REAL_GIT" "$@"
SHIM
cat > "$fault_bin/mkdir" <<'SHIM'
#!/usr/bin/env bash
set -eu
if [ "${FAKE_PROOF_FAULT:-}" = output-claim ]; then
  "$LOCAL_PROOF_REAL_MKDIR" "$@"
  printf 'other-writer-evidence\n' > "$1/manifest.txt"
  printf 'injected output claim failure\n' >&2
  exit 73
fi
exec "$LOCAL_PROOF_REAL_MKDIR" "$@"
SHIM
cat > "$fault_bin/find" <<'SHIM'
#!/usr/bin/env bash
set -eu
if [ "${FAKE_PROOF_FAULT:-}" = inventory-find ]; then
  printf './command.txt\n'
  printf 'injected inventory find failure\n' >&2
  exit 74
fi
exec "$LOCAL_PROOF_REAL_FIND" "$@"
SHIM
cat > "$fault_bin/sort" <<'SHIM'
#!/usr/bin/env bash
set -eu
if [ "${FAKE_PROOF_FAULT:-}" = inventory-sort ]; then
  "$LOCAL_PROOF_REAL_SORT" "$@"
  printf 'injected inventory sort failure\n' >&2
  exit 75
fi
exec "$LOCAL_PROOF_REAL_SORT" "$@"
SHIM
cat > "$fault_bin/$(basename "$LOCAL_PROOF_REAL_HASH")" <<'SHIM'
#!/usr/bin/env bash
set -eu
if [ "${FAKE_PROOF_FAULT:-}" = checksum ]; then
  printf 'injected checksum failure\n' >&2
  exit 76
fi
exec "$LOCAL_PROOF_REAL_HASH" "$@"
SHIM
chmod +x "$fault_bin/"*

expect_producer_abort() {
  local fault="$1" check_ran="$2" diagnostic="$3"
  local proof="$base/fault-$fault" marker="$base/ran-$fault"
  if PATH="$fault_bin:$PATH" FAKE_PROOF_MODE=pass \
      FAKE_PROOF_FAULT="$fault" FAKE_PROOF_CHECK_MARKER="$marker" \
      bash scripts/local_proof.sh --output "$proof" \
      > "$base/$fault.stdout" 2> "$base/$fault.stderr"; then
    fail "producer accepted $fault infrastructure failure"
  fi
  if grep -Eq '^LOCAL_PROOF_(PASS|RED|VOID)$' "$base/$fault.stdout"; then
    fail "producer published a completed proof after $fault"
  fi
  grep -Fq "$diagnostic" "$base/$fault.stderr" \
    || fail "producer lost $fault tool diagnostics"
  if [ "$check_ran" = yes ]; then
    [ -f "$marker" ] || fail "$fault control did not reach check.sh"
  else
    [ ! -e "$marker" ] || fail "producer ran check.sh after $fault"
  fi
  if [ "$fault" = output-claim ]; then
    [ "$(cat "$proof/manifest.txt")" = other-writer-evidence ] \
      || fail "producer overwrote another writer's proof"
    [ ! -e "$proof/commit-before.txt" ] \
      || fail "producer wrote evidence without claiming the directory"
  fi
}

expect_producer_abort before-status no 'injected status capture failure'
expect_producer_abort after-status yes 'injected status capture failure'
expect_producer_abort output-claim no 'injected output claim failure'
expect_producer_abort inventory-find yes 'injected inventory find failure'
expect_producer_abort inventory-sort yes 'injected inventory sort failure'
expect_producer_abort checksum yes 'injected checksum failure'

for code in 125 255; do
  boundary_proof="$base/red-$code"
  if FAKE_PROOF_MODE=red FAKE_PROOF_RED_EXIT="$code" \
      bash scripts/local_proof.sh --output "$boundary_proof" >/dev/null; then
    fail "producer accepted check exit $code"
  else
    boundary_exit=$?
  fi
  [ "$boundary_exit" -eq "$code" ] || fail "producer changed check exit $code"
  grep -Fxq 'verdict=red' "$boundary_proof/manifest.txt" \
    || fail "stable check exit $code was not RED"
  bash scripts/local_proof_verify.sh --repository "$fixture" "$boundary_proof" >/dev/null
done

checksum_tamper="$base/checksum-tamper"
cp -R "$pass_proof" "$checksum_tamper"
printf 'tamper\n' >> "$checksum_tamper/check.stdout.log"
expect_red "$checksum_tamper" "a checksum-invalid proof"

inventory_tamper="$base/inventory-tamper"
cp -R "$pass_proof" "$inventory_tamper"
printf 'extra\n' > "$inventory_tamper/undeclared.txt"
rehash "$inventory_tamper"
expect_red "$inventory_tamper" "a checksum-consistent extra file"

manifest_tamper="$base/manifest-tamper"
cp -R "$pass_proof" "$manifest_tamper"
printf 'commit=%s\n' "$(git rev-parse HEAD)" >> "$manifest_tamper/manifest.txt"
rehash "$manifest_tamper"
expect_red "$manifest_tamper" "a checksum-consistent duplicate manifest key"

tree_tamper="$base/tree-tamper"
cp -R "$pass_proof" "$tree_tamper"
awk -F= '$1 == "tree" { print "tree=0000000000000000000000000000000000000000"; next } { print }' \
  "$pass_proof/manifest.txt" > "$tree_tamper/manifest.txt"
printf '%040d\n' 0 > "$tree_tamper/tree-before.txt"
rehash "$tree_tamper"
expect_red "$tree_tamper" "a checksum-consistent false source tree"

red_contract_tamper="$base/red-contract-tamper"
cp -R "$red_proof" "$red_contract_tamper"
printf 'RED fake gate\nFAIL fake gate\n' > "$red_contract_tamper/check.stdout.log"
: > "$red_contract_tamper/check.stderr.log"
rehash "$red_contract_tamper"
expect_red "$red_contract_tamper" "a red proof without the check.sh reporting contract"

v1_red_proof="$base/v1-red"
make_v1_proof "$red_proof" "$v1_red_proof"
bash scripts/local_proof_verify.sh --repository "$fixture" "$v1_red_proof" >/dev/null
for version in 1 2; do
  if [ "$version" -eq 1 ]; then status_source="$v1_red_proof"; else status_source="$red_proof"; fi
  for code in 00 007 256 999 18446744073709551616; do
    status_tamper="$base/status-v$version-$code"
    cp -R "$status_source" "$status_tamper"
    awk -F= -v code="$code" '
      $1 == "check_exit" { print "check_exit=" code; next }
      { print }
    ' "$status_source/manifest.txt" > "$status_tamper/manifest.txt"
    printf '%s\n' "$code" > "$status_tamper/check-exit.txt"
    rehash "$status_tamper"
    expect_red "$status_tamper" "format-v$version shell status $code"
  done
done

for field in commit-after tree-after; do
  for kind in empty nonhex multiline; do
    snapshot_tamper="$base/$field-$kind"
    cp -R "$move_proof" "$snapshot_tamper"
    case "$kind" in
      empty) printf '' > "$snapshot_tamper/$field.txt" ;;
      nonhex) printf 'not-a-git-object\n' > "$snapshot_tamper/$field.txt" ;;
      multiline)
        cat "$move_proof/$field.txt" > "$snapshot_tamper/$field.txt"
        printf 'extra-line\n' >> "$snapshot_tamper/$field.txt"
        ;;
    esac
    rehash "$snapshot_tamper"
    expect_red "$snapshot_tamper" "a void proof with $kind $field"
  done
done

printf 'PASS local-proof v3 semantic controls (verified partial reuse, retained provenance, legacy verification, git notes, and bead-close attribution)\n'
printf 'fixture=%s\n' "$fixture"
printf 'pass_proof=%s\n' "$pass_proof"
printf 'split2_proof=%s\n' "$split2_proof"
printf 'v1_proof=%s\n' "$v1_proof"
printf 'red_proof=%s\n' "$red_proof"
printf 'void_proof=%s\n' "$move_proof"
printf 'tamper_root=%s\n' "$base"
