#!/usr/bin/env bash
# =============================================================================
# scripts/tests/close_bead_selftest.sh — Unit and E2E self-tests for
# scripts/close_bead.sh (bead fa-8jcr)
# =============================================================================
# Acceptance test entry points:
#   scripts/tests/close_bead_selftest.sh::refuses_missing_test
#   scripts/tests/close_bead_selftest.sh::refuses_failed_test
#   scripts/tests/close_bead_selftest.sh::refuses_verdict_without_landing_commit
#   scripts/tests/close_bead_selftest.sh::closes_with_cited_note
#   scripts/tests/close_bead_selftest.sh::unbound_resumed_steps_cannot_authorize_closure
# =============================================================================

set -uo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../lib/gate_verdict.sh
. "$source_root/scripts/lib/gate_verdict.sh"
gate_init "close-bead-selftest"

fail() {
  cd "$source_root" 2>/dev/null || true
  gate_fail "$*"
  exit 1
}

base="${TMPDIR:-/tmp}/fa-close-bead-selftest-$$-${RANDOM:-0}"
mkdir -p "$base/bin" "$base/blocks"
fixture="$base/repo"
mkdir -p "$fixture/scripts/lib" "$fixture/.beads" "$fixture/docs" "$fixture/crates/fa/src"

cp "$source_root/scripts/close_bead.sh" "$fixture/scripts/close_bead.sh"
cp "$source_root/scripts/local_proof.sh" "$fixture/scripts/local_proof.sh"
cp "$source_root/scripts/local_proof_verify.sh" "$fixture/scripts/local_proof_verify.sh"
cp "$source_root/scripts/lib/gate_verdict.sh" "$fixture/scripts/lib/gate_verdict.sh"
chmod +x "$fixture/scripts/"*.sh

# Stub br binary that updates .beads/issues.jsonl on `br close` and logs `br create`
cat > "$base/bin/stub-br" <<'BR'
#!/usr/bin/env bash
set -eu
sub="${1:-}"
shift || true
if [ "$sub" = "close" ]; then
  bid="$1"
  shift
  reason=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --reason) reason="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  python3 - "$STUB_BEADS_JSONL" "$bid" "$reason" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
bid, reason = sys.argv[2:4]
rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
for r in rows:
    if r.get("id") == bid:
        r["status"] = "closed"
        r["close_reason"] = reason
        r["closed_at"] = "2026-10-25T00:00:00Z"
path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
PY
  exit 0
elif [ "$sub" = "create" ]; then
  printf 'BR_CREATE %s\n' "$*" >> "$STUB_BR_CREATED"
  exit 0
fi
exit 0
BR
chmod +x "$base/bin/stub-br"
export FA_BR_BIN="$base/bin/stub-br"
export STUB_BEADS_JSONL="$fixture/.beads/issues.jsonl"
export STUB_BR_CREATED="$base/br-created.log"
: > "$STUB_BR_CREATED"

# Synthetic check.sh that produces test-list.log and test.log
cat > "$fixture/scripts/check.sh" <<'CHECK'
#!/usr/bin/env bash
# CANONICAL_STEPS: test-list, test
set -eu
tree_hash="$(git rev-parse 'HEAD^{tree}')"
toolchain="$(rustc --version 2>/dev/null || echo 'rustc 1.100.0-nightly')"
log_dir="$CHECK_LOG_DIR"
manifest="$CHECK_STEP_MANIFEST"
stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$log_dir"
: > "$manifest"

if [ "${FAKE_CHECK_MODE:-pass}" = "split-1" ]; then
  printf '  fa_journal::retention::tests::floor_enforced: test\nRemote command finished: exit=0\n[RCH] remote hz2 (1s)\n' > "$log_dir/test-list.log"
  d1="$(sha256sum "$log_dir/test-list.log" | awk '{print $1}')"
  printf '{"step":"test-list","status":"PASS","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
    "$tree_hash" "$toolchain" "$stamp" "$stamp" "$d1" >> "$manifest"
  printf '  [RCH] worker busy; refusing local fallback\n' > "$log_dir/test.log"
  d2="$(sha256sum "$log_dir/test.log" | awk '{print $1}')"
  printf '{"step":"test","status":"UNRUN","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
    "$tree_hash" "$toolchain" "$stamp" "$stamp" "$d2" >> "$manifest"
  printf 'PASS test-list\nUNRUN test\nFAIL check.sh: 1 gate(s) did not run\nQUALITY GATE RED\n'
  printf 'QUALITY GATE RED\n' >&2
  exit 2
fi

printf '  fa_journal::retention::tests::floor_enforced: test\n  fa_journal::retention::tests::cadence_checked: test\n  carried::posts_balance: test\nRemote command finished: exit=0\n[RCH] remote hz2 (1s)\n' > "$log_dir/test-list.log"
d_list="$(sha256sum "$log_dir/test-list.log" | awk '{print $1}')"

cat > "$log_dir/test.log" <<'EOF'
test fa_journal::retention::tests::floor_enforced ... ok
test fa_journal::retention::tests::cadence_checked ... ok
PASS scripts/tests/close_bead_selftest.sh::closes_with_cited_note
test result: ok. 2 passed; 0 failed; 0 ignored
     Running tests/ledger.rs (target/debug/deps/ledger-0123456789abcdef)

running 1 test
test carried::posts_balance ... ok
test result: ok. 1 passed; 0 failed; 0 ignored
Remote command finished: exit=0
[RCH] remote hz2 (1s)
EOF
d_test="$(sha256sum "$log_dir/test.log" | awk '{print $1}')"

{
  printf '{"step":"test-list","status":"PASS","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
    "$tree_hash" "$toolchain" "$stamp" "$stamp" "$d_list"
  printf '{"step":"test","status":"PASS","tree_hash":"%s","toolchain":"%s","worker":"hz2","started":"%s","finished":"%s","duration_secs":0,"log_digest":"%s"}\n' \
    "$tree_hash" "$toolchain" "$stamp" "$stamp" "$d_test"
} > "$manifest"
printf 'PASS test-list\nPASS test\nALL GATES GREEN\n'
CHECK
chmod +x "$fixture/scripts/check.sh"

# Seed .beads/issues.jsonl in fixture
python3 - "$STUB_BEADS_JSONL" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
beads = [
    {
        "id": "fa-good",
        "status": "in_progress",
        "description": "Implement retention floor.\n\n```acceptance-tests\n# retention unit tests\nfa-journal::retention::tests::floor_enforced\n\nfa-journal::retention::tests::cadence_checked\n```\n",
    },
    {
        "id": "fa-missing-test",
        "status": "in_progress",
        "description": "Bead naming nonexistent test.\n\n```acceptance-tests\nfa-journal::retention::tests::floor_enforced\nfa-journal::retention::tests::does_not_exist\n```\n",
    },
    {
        "id": "fa-failed-test",
        "status": "in_progress",
        "description": "Bead naming a test that failed.\n\n```acceptance-tests\nfa-journal::retention::tests::cadence_checked\n```\n",
    },
    {
        "id": "fa-unlanded",
        "status": "in_progress",
        "description": "Bead landed on another branch.\n\n```acceptance-tests\nfa-journal::retention::tests::floor_enforced\n```\n",
    },
    {
        "id": "fa-doc-only",
        "status": "in_progress",
        "description": "Doc bead.\n\n```acceptance-tests\nnone: pure documentation update\n```\n",
    },
    {
        "id": "fa-code-loophole",
        "status": "in_progress",
        "description": "Code bead trying none loophole.\n\n```acceptance-tests\nnone: trying to skip tests on crates/ edit\n```\n",
    },
    {"id": "fa-no-block", "status": "in_progress", "description": "Code without an acceptance block"},
    {
        "id": "fa-binary-qualified",
        "status": "in_progress",
        "description": "Integration test named with its binary.\n\n```acceptance-tests\nfa-journal::ledger::carried::posts_balance\n```\n",
    },
    {
        "id": "fa-wrong-binary",
        "status": "in_progress",
        "description": "Integration test named with another binary.\n\n```acceptance-tests\nfa-journal::other::carried::posts_balance\n```\n",
    },
]
path.write_text("\n".join(json.dumps(b) for b in beads) + "\n")
PY

cd "$fixture" || fail "cannot cd into $fixture"
git init -q -b main
git config user.name "Close Bead Self-Test"
git config user.email "close-bead@example.invalid"
printf 'pub fn init() {}\n' > crates/fa/src/lib.rs
git add .
git commit -q -m "feat: initial implementation (fa-good, fa-missing-test, fa-failed-test, fa-code-loophole, fa-no-block, fa-binary-qualified, fa-wrong-binary)"

printf '# Guide\n' > docs/guide.md
git add docs/guide.md
git commit -q -m "docs: add guide (fa-doc-only)"
main_commit="$(git rev-parse HEAD)"

# Produce a PASS proof and publish refs/notes/fa-verdict on main_commit
pass_proof="$base/pass-proof"
FAKE_CHECK_MODE=pass bash scripts/local_proof.sh --output "$pass_proof" --publish-note >/dev/null
note_id="$(git notes --ref=fa-verdict list "$main_commit" | awk '{print $1}')"
[ -n "$note_id" ] || fail "setup: missing fa-verdict note on $main_commit"

# Unit tests for acceptance-tests parser (fences, comments, blank lines, duplicate names)
parser_unit_tests() {
  local out
  out="$(bash scripts/close_bead.sh --parse-block fa-good --repository "$fixture")"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d=={"kind":"tests","items":["fa-journal::retention::tests::floor_enforced","fa-journal::retention::tests::cadence_checked"]}' "$out" \
    || fail "parser_unit_tests: failed to parse fa-good block ($out)"

  printf '```acceptance-tests\nfoo::bar\nfoo::bar\n```\n' > "$base/blocks/dup.md"
  if bash scripts/close_bead.sh --parse-block "$base/blocks/dup.md" --repository "$fixture" 2>/dev/null; then
    fail "parser_unit_tests: accepted duplicate test names"
  fi

  printf '```acceptance-tests\n# only comments\n\n```\n' > "$base/blocks/empty.md"
  if bash scripts/close_bead.sh --parse-block "$base/blocks/empty.md" --repository "$fixture" 2>/dev/null; then
    fail "parser_unit_tests: accepted empty acceptance-tests block"
  fi
  gate_pass "parser_unit_tests (fences, comments, blank lines, duplicate and empty rejection verified)"
}

# 1. Acceptance test: positive — a bead whose listed tests are in a PASS verdict closes and its close_reason cites the note
closes_with_cited_note() {
  local out
  out="$(bash scripts/close_bead.sh fa-good --verdict "$note_id" --repository "$fixture" --reason "all retention tests green" 2>&1)" \
    || fail "closes_with_cited_note: close_bead.sh failed ($out)"
  grep -Fq "CLOSE_BEAD_OK bead=fa-good note_id=$note_id" <<< "$out" \
    || fail "closes_with_cited_note: missing CLOSE_BEAD_OK output ($out)"
  grep -Fq 'decision=ALLOW' <<< "$out" \
    || fail "closes_with_cited_note: missing decision=ALLOW log ($out)"
  python3 - "$STUB_BEADS_JSONL" "${note_id:0:12}" <<'PY' || fail "closes_with_cited_note: close_reason in issues.jsonl did not cite verdict note"
import json, pathlib, sys
rows = {r["id"]: r for r in map(json.loads, pathlib.Path(sys.argv[1]).read_text().splitlines())}
assert rows["fa-good"]["status"] == "closed"
assert f"verdict_note: {sys.argv[2]}" in rows["fa-good"]["close_reason"]
PY
  git add .beads/issues.jsonl
  git commit -q -m "chore(beads): close fa-good"
  gate_pass "closes_with_cited_note (bead fa-good closed with verdict_note=${note_id:0:12} cited in close_reason)"
}

# 1b. cargo prints an integration test without its binary; an acceptance line
# naming the binary that ran it matches, one naming another binary does not.
matches_integration_tests_by_their_binary() {
  local out rc=0
  out="$(bash scripts/close_bead.sh fa-wrong-binary --verdict "$note_id" --repository "$fixture" --reason "should fail" 2>&1)" || rc=$?
  [ "$rc" -ne 0 ] || fail "matches_integration_tests_by_their_binary: a line naming another binary closed ($out)"
  grep -Fq "missing from verdict" <<< "$out" \
    || fail "matches_integration_tests_by_their_binary: expected a missing-test refusal for the wrong binary ($out)"
  out="$(bash scripts/close_bead.sh fa-binary-qualified --verdict "$note_id" --repository "$fixture" --reason "ledger test green" 2>&1)" \
    || fail "matches_integration_tests_by_their_binary: the binary-qualified line was refused ($out)"
  grep -Fq "CLOSE_BEAD_OK bead=fa-binary-qualified" <<< "$out" \
    || fail "matches_integration_tests_by_their_binary: missing CLOSE_BEAD_OK ($out)"
  git add .beads/issues.jsonl
  git commit -q -m "chore(beads): close fa-binary-qualified"
  gate_pass "matches_integration_tests_by_their_binary (crate::<bin>::<path> closes from a Running tests/<bin>.rs section; another binary is refused)"
}

# 2. Acceptance test: planted negative — a bead naming a test that does not exist is refused
refuses_missing_test() {
  local out rc=0
  out="$(bash scripts/close_bead.sh fa-missing-test --verdict "$note_id" --repository "$fixture" --reason "should fail" 2>&1)" || rc=$?
  [ "$rc" -ne 0 ] || fail "refuses_missing_test: close_bead.sh accepted a bead with a missing test"
  grep -Fq "missing from verdict" <<< "$out" \
    || fail "refuses_missing_test: expected missing-test refusal diagnostic ($out)"
  grep -Fq "does_not_exist" <<< "$out" \
    || fail "refuses_missing_test: refusal did not name does_not_exist ($out)"
  python3 - "$STUB_BEADS_JSONL" <<'PY' || fail "refuses_missing_test: bead status changed after refusal"
import json, pathlib, sys
rows = {r["id"]: r for r in map(json.loads, pathlib.Path(sys.argv[1]).read_text().splitlines())}
assert rows["fa-missing-test"]["status"] == "in_progress"
PY
  gate_pass "refuses_missing_test (bead naming nonexistent test refused with exact miss list)"
}

# 3. Acceptance test: planted negative — a bead whose test failed in the verdict is refused
refuses_failed_test() {
  local orig_note
  orig_note="$(git notes --ref=fa-verdict show "$main_commit")"

  python3 - "$main_commit" <<'PY'
import json, subprocess, sys
commit = sys.argv[1]
note = subprocess.check_output(["git", "notes", "--ref=fa-verdict", "show", commit], text=True)
out = []
for line in note.splitlines():
    if line.startswith("step_verdict="):
        rec = json.loads(line.removeprefix("step_verdict="))
        if rec.get("step") == "test":
            w = rec.get("witness", {})
            w["passed_test_names"] = [t for t in w.get("passed_test_names", []) if "cadence_checked" not in t]
            w["failed_test_names"] = ["fa_journal::retention::tests::cadence_checked"]
            rec["witness"] = w
        out.append("step_verdict=" + json.dumps(rec, separators=(",", ":")))
    else:
        out.append(line)
subprocess.run(["git", "notes", "--ref=fa-verdict", "add", "-f", "-m", "\n".join(out) + "\n", commit], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
PY

  local out rc=0
  out="$(bash scripts/close_bead.sh fa-failed-test --verdict "$main_commit" --repository "$fixture" --reason "should fail" 2>&1)" || rc=$?
  printf '%s\n' "$orig_note" | git notes --ref=fa-verdict add -f -F - "$main_commit" 2>/dev/null
  [ "$rc" -ne 0 ] || fail "refuses_failed_test: close_bead.sh accepted a bead whose test FAILED in the verdict ($out)"
  grep -Eq 'FAILED in verdict|note test witness differs from retained log' <<< "$out" \
    || fail "refuses_failed_test: neither failure admission nor retained-result binding refused the forged metadata ($out)"
  gate_pass "refuses_failed_test (forged failure metadata cannot override the retained executed result)"
}

# 4. Acceptance test: planted negative — a verdict on a tree lacking the landing commit is refused
refuses_verdict_without_landing_commit() {
  local current_branch
  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  git checkout -q -b side-branch "$main_commit"
  printf 'pub fn side() {}\n' >> crates/fa/src/lib.rs
  git add crates/fa/src/lib.rs
  git commit -q -m "feat: side branch work (fa-unlanded)"
  local side_sha
  side_sha="$(git rev-parse HEAD)"
  git checkout -q "$current_branch"

  local out rc=0
  out="$(bash scripts/close_bead.sh fa-unlanded --verdict "$pass_proof" --commit "$side_sha" --repository "$fixture" --reason "wrong tree" 2>&1)" || rc=$?
  [ "$rc" -ne 0 ] || fail "refuses_verdict_without_landing_commit: accepted verdict lacking landing commit"
  grep -Fq "does not contain landing commit" <<< "$out" \
    || fail "refuses_verdict_without_landing_commit: unexpected error ($out)"
  gate_pass "refuses_verdict_without_landing_commit (verdict on tree lacking landing commit refused)"
}

# 5. Companion integration test (fa-hlnd.1 / fa-8jcr): tampered reused evidence in a split-run proof
#    is rejected by both local_proof_verify.sh and close_bead.sh.
unbound_resumed_steps_cannot_authorize_closure() {
  local split1="$base/split1"
  set +e
  FAKE_CHECK_MODE=split-1 bash scripts/local_proof.sh --output "$split1" >/dev/null 2>&1
  set -e
  local tampered_source="$base/split1-tampered"
  cp -R "$split1" "$tampered_source"
  printf 'tampered log line\n' >> "$tampered_source/steps/test-list.log"
  if bash scripts/local_proof.sh --output "$base/split2-from-tampered" --resume-from "$tampered_source" >/dev/null 2>&1; then
    fail "unbound_resumed_steps_cannot_authorize_closure: local_proof.sh admitted tampered source proof"
  fi

  local forged="$base/forged-final"
  cp -R "$pass_proof" "$forged"
  printf 'test fa_journal::retention::tests::invented ... ok\n' >> "$forged/steps/test.log"
  (
    cd "$forged"
    : > SHA256SUMS
    while IFS= read -r f; do
      sha256sum "$f" >> SHA256SUMS
    done < <(find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort)
  )
  if bash scripts/local_proof_verify.sh --repository "$fixture" "$forged" >/dev/null 2>&1; then
    fail "tampered_reused_evidence_cannot_form_a_valid_final_manifest: verifier accepted forged step log"
  fi
  if bash scripts/close_bead.sh fa-good --verdict "$forged" --repository "$fixture" --reason "forged" >/dev/null 2>&1; then
    fail "unbound_resumed_steps_cannot_authorize_closure: close_bead.sh accepted forged proof bundle"
  fi
  gate_pass "unbound_resumed_steps_cannot_authorize_closure (tampered split-run and forged step logs rejected by local_proof_verify and close_bead)"
}

# 6. Process-closure loophole protection, closure-debt metric, and 30-day regression runner
process_closure_and_regression_checks() {
  bash scripts/close_bead.sh fa-doc-only --verdict "$pass_proof" --repository "$fixture" --reason "docs landed" >/dev/null 2>&1 \
    || fail "process_closure: doc-only bead with none: block should succeed"
  git add .beads/issues.jsonl
  git commit -q -m "chore(beads): close fa-doc-only"

  if bash scripts/close_bead.sh fa-code-loophole --verdict "$pass_proof" --repository "$fixture" --reason "loophole" >/dev/null 2>&1; then
    fail "process_closure: code bead touching crates/ was allowed to use none: loophole"
  fi

  local debt_json
  debt_json="$(bash scripts/close_bead.sh --closure-debt --verdict "$pass_proof" --repository "$fixture" --json)"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["closed_total"]==3 and d["verdict_cited_closures"]==2 and d["process_closures"]==1 and d["closure_debt_count"]==0, d' "$debt_json" \
    || fail "process_closure: unexpected closure-debt report ($debt_json)"

  bash scripts/close_bead.sh --regression-check --days 30 --verdict "$pass_proof" --repository "$fixture" >/dev/null \
    || fail "regression_check: failed on healthy pass_proof"

  gate_pass "process_closure_and_regression_checks (none: loophole blocked on code commits, closure-debt=0, 30-day regression check green)"
}

# These are producer-generated synthetic proofs, not evidence that Rust ran.
# Every negative invokes the real closure command in dry-run mode and retains
# stdout/stderr plus the untouched fixture graph. Old admission must lose here.
retained_evidence_refusal() {
  local mutation="$1" label="$2" target_bead="${3:-fa-good}"
  local altered="$base/note-$mutation" original_note out rc=0
  original_note="$(git notes --ref=fa-verdict show "$main_commit")"
  cp -R "$pass_proof" "$altered"
  cp "$STUB_BEADS_JSONL" "$altered.graph-before"
  python3 -B - "$altered" "$mutation" "$main_commit" <<'PY' || fail "cannot plant $mutation"
import hashlib, json, pathlib, subprocess, sys
root, mutation, commit = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
note = subprocess.check_output(["git", "notes", "--ref=fa-verdict", "show", commit], text=True)
fields, summaries = {}, []
for line in note.splitlines():
    key, value = line.split("=", 1)
    if key == "step_verdict": summaries.append(json.loads(value))
    else: fields[key] = value
records = [json.loads(line) for line in (root / "step-verdicts.jsonl").read_text().splitlines()]
fields["proof_dir"] = str(root)
if mutation == "step-tree":
    records[0]["tree_hash"] = summaries[0]["tree_hash"] = "0" * 40
elif mutation == "before-commit":
    fields["started_utc"] = "2000-01-01T00:00:00Z"
    manifest = (root / "manifest.txt").read_text().splitlines()
    (root / "manifest.txt").write_text("\n".join("started_utc=" + fields["started_utc"]
        if line.startswith("started_utc=") else line for line in manifest) + "\n")
elif mutation == "step-before-run":
    for key in ("started", "finished"):
        records[0][key] = summaries[0][key] = "2000-01-01T00:00:00Z"
elif mutation == "outside-test":
    with (root / "steps/test-list.log").open("a") as log:
        log.write("test fa_journal::retention::tests::does_not_exist ... ok\n")
    summaries[0]["witness"]["passed_test_names"] = ["fa_journal::retention::tests::does_not_exist"]
elif mutation == "without-test":
    records = records[:1]
    summaries = summaries[:1]
    summaries[0]["witness"]["passed_test_names"] = [
        "fa_journal::retention::tests::floor_enforced", "fa_journal::retention::tests::cadence_checked"]
    (root / "check.stdout.log").write_text("PASS test-list\nALL GATES GREEN\n")
elif mutation == "missing-proof":
    fields["proof_dir"] = str(root / "not-retained")
elif mutation == "checksum-identity":
    fields["proof_sums_sha256"] = "0" * 64
elif mutation == "direct-test-name":
    fields["passed_test"] = "fa_journal::retention::tests::does_not_exist"
elif mutation == "failed-log":
    log = root / "steps/test.log"
    log.write_text(log.read_text().replace("cadence_checked ... ok", "cadence_checked ... FAILED")
        .replace("2 passed; 0 failed", "1 passed; 1 failed"))
    summaries[1]["witness"]["passed_test_names"].remove("fa_journal::retention::tests::cadence_checked")
    summaries[1]["witness"]["failed_test_names"] = ["fa_journal::retention::tests::cadence_checked"]
elif mutation != "mutated-log":
    raise ValueError(mutation)
for record, summary in zip(records, summaries):
    digest = hashlib.sha256((root / "steps" / (record["step"] + ".log")).read_bytes()).hexdigest()
    record["log_digest"] = summary["log_digest"] = summary["witness"]["log_digest"] = digest
lines = [json.dumps(record, separators=(",", ":")) for record in records]
(root / "step-verdicts.jsonl").write_text("\n".join(lines) + "\n")
tools = [line for line in (root / "tools.txt").read_text().splitlines() if not line.startswith("step_verdict=")]
(root / "tools.txt").write_text("\n".join(tools + ["step_verdict=" + line for line in lines]) + "\n")
sums = []
for path in sorted(root.rglob("*")):
    if path.is_file() and path.name != "SHA256SUMS":
        sums.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  ./" + path.relative_to(root).as_posix())
(root / "SHA256SUMS").write_text("\n".join(sums) + "\n")
if mutation != "checksum-identity":
    fields["proof_sums_sha256"] = hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest()
if mutation == "mutated-log":
    with (root / "steps/test.log").open("a") as log: log.write("changed byte\n")
body = "\n".join([key + "=" + value for key, value in fields.items()]
    + ["step_verdict=" + json.dumps(summary, separators=(",", ":")) for summary in summaries]) + "\n"
subprocess.run(["git", "notes", "--ref=fa-verdict", "add", "-f", "-F", "-", commit], input=body, text=True, check=True)
PY
  FA_CLOSE_BEAD_DRY_RUN=1 bash scripts/close_bead.sh "$target_bead" --verdict "$main_commit" \
    --repository "$fixture" --reason "synthetic $mutation control" \
    >"$altered.stdout" 2>"$altered.stderr"
  rc=$?
  printf '%s\n' "$original_note" | git notes --ref=fa-verdict add -f -F - "$main_commit" 2>/dev/null \
    || fail "could not restore original fixture note"
  cmp "$STUB_BEADS_JSONL" "$altered.graph-before" || fail "$label: refusal changed the fixture graph"
  if [ "$rc" -eq 0 ]; then
    gate_fail "$label: original defect admitted $mutation (logs $altered.stdout and .stderr)"
  else
    out="$(cat "$altered.stderr")"
    case "$out" in
      *local-proof-verify:*|*"failed local_proof_verify.sh"*)
        gate_pass "$label (synthetic $mutation refused exit=$rc; graph unchanged)" ;;
      *"FAILED in verdict"*)
        [ "$mutation" = failed-log ] || fail "$label: unrelated failed-test refusal ($out)"
        gate_pass "$label (retained failed test refused exit=$rc; graph unchanged)" ;;
      *) fail "$label: unrelated failure ($out)" ;;
    esac
  fi
}

refuses_note_whose_step_tree_differs_from_commit_tree() {
  retained_evidence_refusal step-tree close_bead_selftest::refuses_note_whose_step_tree_differs_from_commit_tree
}
refuses_note_started_before_its_commit() {
  retained_evidence_refusal before-commit close_bead_selftest::refuses_note_started_before_its_commit
}
refuses_test_names_reported_outside_the_test_step() {
  retained_evidence_refusal outside-test close_bead_selftest::refuses_test_names_reported_outside_the_test_step fa-missing-test
}
refuses_note_without_test_step_for_code_bead() {
  retained_evidence_refusal without-test close_bead_selftest::refuses_note_without_test_step_for_code_bead
}
refuses_bundle_with_mutated_step_log() {
  retained_evidence_refusal mutated-log close_bead_selftest::refuses_bundle_with_mutated_step_log
}
accepts_genuine_full_scope_bundle_with_scraped_test_name() {
  local relocated="$base/relocated-proof"
  cp -R "$pass_proof" "$relocated"
  bash scripts/local_proof_verify.sh --repository "$fixture" --note "$main_commit" "$relocated" \
    >"$base/relocated.stdout" 2>"$base/relocated.stderr" \
    || fail "relocated producer-generated fixture failed verification"
  FA_CLOSE_BEAD_DRY_RUN=1 bash scripts/close_bead.sh fa-good --verdict "$note_id" \
    --repository "$fixture" --reason "scraped fixture tests" >"$base/scraped.stdout" 2>"$base/scraped.stderr" \
    || fail "producer-generated full-scope fixture could not authorize its actual test names"
  gate_pass "close_bead_selftest::accepts_genuine_full_scope_bundle_with_scraped_test_name (producer-generated synthetic fixture; no Rust execution)"
}

refuses_manifest_without_acceptance_block() {
  local out rc=0
  FA_CLOSE_BEAD_DRY_RUN=1 bash scripts/close_bead.sh fa-no-block --manifest "$pass_proof" \
    --repository "$fixture" --reason "manifest cannot bypass acceptance" \
    >"$base/no-block.stdout" 2>"$base/no-block.stderr" || rc=$?
  if [ "$rc" -eq 0 ]; then
    gate_fail "refuses_manifest_without_acceptance_block: manifest bypassed named acceptance"
  else
    out="$(cat "$base/no-block.stderr")"
    case "$out" in
      *"lacks an"*"acceptance-tests"*) gate_pass "refuses_manifest_without_acceptance_block (manifest alias still requires named acceptance)" ;;
      *) fail "refuses_manifest_without_acceptance_block: unrelated refusal ($out)" ;;
    esac
  fi
}

parser_unit_tests
closes_with_cited_note
matches_integration_tests_by_their_binary
refuses_note_whose_step_tree_differs_from_commit_tree
refuses_note_started_before_its_commit
refuses_test_names_reported_outside_the_test_step
refuses_note_without_test_step_for_code_bead
refuses_bundle_with_mutated_step_log
retained_evidence_refusal missing-proof refuses_note_without_retained_proof
retained_evidence_refusal checksum-identity refuses_note_with_copied_checksum_identity
retained_evidence_refusal step-before-run refuses_step_started_before_its_proof
retained_evidence_refusal direct-test-name refuses_unbound_direct_test_names fa-missing-test
retained_evidence_refusal failed-log refuses_retained_failed_test fa-failed-test
accepts_genuine_full_scope_bundle_with_scraped_test_name
refuses_manifest_without_acceptance_block
refuses_missing_test
refuses_failed_test
refuses_verdict_without_landing_commit
unbound_resumed_steps_cannot_authorize_closure
process_closure_and_regression_checks

cd "$source_root" || fail "cannot cd back to $source_root"
gate_verdict
