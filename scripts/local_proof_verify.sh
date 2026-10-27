#!/usr/bin/env bash
# Independently verify a local proof bundle without rerunning its commands (bead fa-u7u).
#
# This authenticates format and internal consistency, not the identity of the
# bundle's producer. With --repository it additionally binds the named commit,
# tree, and check-script blob to an independently supplied Git object database.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/local_proof_verify.sh [--repository DIR] [--for-resume|--for-close] [PROOF_DIR]
       bash scripts/local_proof_verify.sh [--repository DIR] [--for-close] --note COMMIT_OR_REF [PROOF_DIR]

Options:
  --repository DIR  Require DIR's Git object database to contain the proof's
                    commit, tree, and exact tracked scripts/check.sh blob.
  --note REV        Verify a published refs/notes/fa-verdict note for REV in
                    --repository DIR (defaults to current repository), bound
                    to its retained proof_dir or an explicitly supplied copy.
  --for-close       Require a retained v3 full canonical gate and executed tests.
  --for-resume      Require v3, a stable tree matching DIR's current tree,
                    identical check script/toolchain, and zero FAIL records.
  -h, --help        Show this help.

Verification never reruns check.sh. It proves strict format, checksums,
exact-tree attribution, verdict/exit consistency, and the reporting contract.
USAGE
}

fail() {
  printf 'local-proof-verify: %s\n' "$*" >&2
  exit 1
}

repository=""
proof_arg=""
note_arg=""
for_resume=0
for_close=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      [ "$#" -ge 2 ] || fail "--repository requires a directory"
      repository="$2"
      shift 2
      ;;
    --note)
      [ "$#" -ge 2 ] || fail "--note requires a commit or ref"
      note_arg="$2"
      shift 2
      ;;
    --for-resume) for_resume=1; shift ;;
    --for-close) for_close=1; shift ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*) fail "unknown argument: $1" ;;
    *)
      [ -z "$proof_arg" ] || fail "only one proof directory or commit may be supplied"
      proof_arg="$1"
      shift
      ;;
  esac
done
[ -n "$proof_arg" ] || [ -n "$note_arg" ] || { usage >&2; exit 2; }
[ "$for_resume" -eq 0 ] || [ "$for_close" -eq 0 ] || fail "choose --for-resume or --for-close"

if [ -n "$repository" ]; then
  [ -d "$repository" ] || fail "not a repository directory: $repository"
  repository="$(cd "$repository" && pwd -P)"
  git -C "$repository" rev-parse --git-dir >/dev/null 2>&1 \
    || fail "--repository is not a Git worktree or repository"
fi

# If --note REV is supplied, or if --repository DIR is supplied and PROOF_DIR is
# not a directory on disk but resolves to a commit in DIR, verify the published
# refs/notes/fa-verdict note for that commit.
if [ -z "$note_arg" ] && [ -n "$proof_arg" ] && [ ! -d "$proof_arg" ] && [ -n "$repository" ] && [ "$for_resume" -eq 0 ]; then
  if git -C "$repository" rev-parse --verify --quiet "${proof_arg}^{commit}" >/dev/null 2>&1; then
    note_arg="$proof_arg"
    proof_arg=""
  fi
fi

if [ -n "$note_arg" ]; then
  [ "$for_resume" -eq 0 ] || fail "--for-resume requires a retained proof directory"
  repo_for_note="${repository:-$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)}"
  git -C "$repo_for_note" rev-parse --git-dir >/dev/null 2>&1 \
    || fail "--note requires a Git repository (--repository DIR)"
  target_commit="$(git -C "$repo_for_note" rev-parse --verify --quiet "${note_arg}^{commit}" 2>/dev/null)" \
    || fail "commit $note_arg does not exist in $repo_for_note"
  target_tree="$(git -C "$repo_for_note" rev-parse --verify "${target_commit}^{tree}")"
  target_script_blob="$(git -C "$repo_for_note" rev-parse --verify "${target_commit}:scripts/check.sh" 2>/dev/null || echo "")"
  note_blob="$(git -C "$repo_for_note" notes --ref=fa-verdict list "$target_commit" 2>/dev/null | awk '{print $1}' || true)"
  [ -n "$note_blob" ] || fail "missing refs/notes/fa-verdict note for $target_commit"
  note_text="$(git -C "$repo_for_note" notes --ref=fa-verdict show "$target_commit" 2>/dev/null)" \
    || fail "cannot read refs/notes/fa-verdict note for $target_commit"

  python3 -B - "$target_commit" "$target_tree" "$target_script_blob" "$note_blob" "$note_text" \
    "$repo_for_note" "$proof_arg" "${BASH_SOURCE[0]}" "$for_close" <<'PY' || exit 1
import hashlib
import json
import pathlib
import re
import subprocess
import sys

target_commit, target_tree, target_script_blob, note_blob, note_text = sys.argv[1:6]
repository, proof_override, verifier, for_close = sys.argv[6:10]

def require(cond, msg):
    if not cond:
        print(f"local-proof-verify: {msg}", file=sys.stderr)
        sys.exit(1)

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key}")
        result[key] = value
    return result

kv = {}
steps = []
for raw in note_text.splitlines():
    if not raw.strip():
        continue
    require("=" in raw, f"malformed note line: {raw}")
    k, v = raw.split("=", 1)
    if k == "step_verdict":
        steps.append(json.loads(v, object_pairs_hook=strict_object))
    else:
        require(k not in kv, f"duplicate note key: {k}")
        kv[k] = v

require(kv.get("format_version") == "3", "note format_version must be 3")
require(kv.get("commit") == target_commit, f"note commit {kv.get('commit')} != {target_commit}")
require(kv.get("tree") == target_tree, f"note tree {kv.get('tree')} != {target_tree}")
require(kv.get("check_script_path") == "scripts/check.sh", "unexpected check_script_path in note")
if target_script_blob:
    require(kv.get("check_script_blob") == target_script_blob, "note check_script_blob mismatch")
require(kv.get("tree_stable") in ("true", "false"), "invalid tree_stable in note")
verdict = kv.get("verdict")
require(verdict in ("pass", "red", "void"), f"invalid verdict in note: {verdict}")
check_exit = int(kv.get("check_exit", "-1"))
require(0 <= check_exit <= 255, "invalid check_exit in note")
auth = kv.get("authority", "")
require(auth.startswith("check.sh exit code") and "not product correctness beyond them" in auth,
        "note authority lacks no-claim boundary")
require("not product correctness beyond them" in kv.get("no_claim_boundary", ""),
        "note lacks no_claim_boundary")
toolchain = kv.get("toolchain", "")
require(bool(toolchain), "note lacks toolchain")
require(bool(re.fullmatch(r"[0-9a-f]{64}", kv.get("proof_sums_sha256", ""))), "note lacks valid proof_sums_sha256")
inv_digest = kv.get("test_inventory_digest", "")
require(inv_digest == "none" or bool(re.fullmatch(r"[0-9a-f]{64}", inv_digest)), "invalid test_inventory_digest in note")
require(bool(steps), "note contains zero step_verdict records")
require("passed_test" not in kv and "failed_test" not in kv,
        "unbound test-name fields cannot authorize a note")

for rec in steps:
    name = rec.get("step", "")
    require(bool(name), "step_verdict missing step name")
    require(rec.get("status") in ("PASS", "FAIL", "UNRUN"), f"{name}: invalid step status")
    require(rec.get("tree_hash") == target_tree, f"{name}: step tree_hash mismatch")
    require(rec.get("toolchain") == toolchain, f"{name}: step toolchain mismatch")
    require(isinstance(rec.get("duration_ms"), int) and rec["duration_ms"] >= 0, f"{name}: invalid duration_ms")
    witness = rec.get("witness")
    require(isinstance(witness, dict) and witness.get("log_digest") == rec.get("log_digest"),
            f"{name}: missing or mismatched step work witness")
    if name == "test-list" and rec["status"] == "PASS":
        require(bool(re.fullmatch(r"[0-9a-f]{64}", inv_digest)), "test-list PASS requires hex test_inventory_digest")

if verdict == "pass":
    require(kv["tree_stable"] == "true" and check_exit == 0, "pass note must be stable with exit 0")
    require(all(r["status"] == "PASS" for r in steps), "pass note has non-PASS step")
elif verdict == "red":
    require(kv["tree_stable"] == "true" and check_exit != 0, "red note must be stable with nonzero exit")
    require(any(r["status"] in ("FAIL", "UNRUN") for r in steps), "red note lacks failing/unrun step")

proof = pathlib.Path(proof_override or kv.get("proof_dir", ""))
require(bool(proof_override or kv.get("proof_dir")), "note requires a retained v3 proof directory")
require(proof.is_dir(), f"retained proof directory is unavailable: {proof}")
proof = proof.resolve()
command = ["bash", verifier, "--repository", repository]
if for_close == "1":
    command.append("--for-close")
command.append(str(proof))
checked = subprocess.run(command, text=True, capture_output=True)
if checked.returncode:
    print(checked.stdout, end="")
    print(checked.stderr, end="", file=sys.stderr)
    require(False, "note's retained proof failed verification")
checked_fields = dict(line.split("=", 1) for line in checked.stdout.splitlines() if "=" in line)
if "scope" in kv:
    require(kv["scope"] == checked_fields["scope"], "note/retained scope mismatch")
manifest = dict(line.split("=", 1) for line in (proof / "manifest.txt").read_text().splitlines())
require(manifest.get("format_version") == "3", "notes require retained v3 step logs")
require(all(kv.get(key) == value for key, value in manifest.items()), "note/retained manifest mismatch")
require(hashlib.sha256((proof / "SHA256SUMS").read_bytes()).hexdigest() == kv["proof_sums_sha256"],
        "note/retained proof checksum identity mismatch")
records = [json.loads(line, object_pairs_hook=strict_object)
           for line in (proof / "step-verdicts.jsonl").read_text().splitlines()]
require(len(steps) == len(records), "note/retained step inventory mismatch")
tools = (proof / "tools.txt").read_text().splitlines()
require([line.removeprefix("rustc=") for line in tools if line.startswith("rustc=")] == [toolchain],
        "note/retained toolchain mismatch")
listed_log = proof / "steps/test-list.log"
listed = sorted(re.findall(r"^\s*(.+): test$", listed_log.read_text(), re.M)) if listed_log.is_file() else []
actual_inventory = (hashlib.sha256(("\n".join(listed) + "\n").encode()).hexdigest() if listed else
                    hashlib.sha256(listed_log.read_bytes()).hexdigest() if listed_log.is_file() else "none")
require(inv_digest == actual_inventory, "note/retained test inventory mismatch")
for rec, origin in zip(steps, records):
    name = origin["step"]
    require({key: value for key, value in rec.items() if key not in {"witness", "duration_ms"}} == origin,
            f"{name}: note/retained execution provenance mismatch")
    require(rec["duration_ms"] == origin["duration_secs"] * 1000, f"{name}: note duration mismatch")
    log = proof / "steps" / (name + ".log")
    passed, failed = [], []
    actual_witness = {"log_digest": origin["log_digest"], "worker": origin["worker"]}
    if log.is_file():
        text = log.read_text(errors="replace")
        if name == "test-list":
            actual_witness["listed_tests"] = len(re.findall(r"^\s*(.+): test$", text, re.M))
            actual_witness["test_inventory_digest"] = actual_inventory
        elif name in {"test", "robot-schema", "registry-check"}:
            actual_witness["passed_tests"] = sum(map(int, re.findall(r"^test result: ok\. (\d+) passed;", text, re.M)))
        elif name in {"check", "clippy"}:
            actual_witness["finished_targets"] = len(re.findall(r"^\s*Finished ", text, re.M))
        evidence = re.findall(r"^\s*evidence artifact_id=(\S+) .* verdict=PASS$", text, re.M)
        if evidence:
            actual_witness["evidence_artifacts"] = evidence
        for match in re.finditer(r"^test\s+(\S+)(?: - should panic)?\s+\.\.\.\s+(ok|FAILED)$", text if name == "test" else "", re.M):
            (passed if match[2] == "ok" else failed).append(match[1])
        for match in re.finditer(r"^(PASS|FAIL|ok)\s+([A-Za-z0-9_.:/-]+)", text, re.M):
            (failed if match[1] == "FAIL" else passed).append(match[2])
    if passed:
        actual_witness["passed_test_names"] = passed
    if failed:
        actual_witness["failed_test_names"] = failed
    require(rec["witness"] == actual_witness,
            f"{name}: note test witness differs from retained log")
print(checked.stdout, end="")
print(f"note_id={note_blob}")
PY
  exit 0
fi

proof="$proof_arg"
[ -d "$proof" ] || fail "not a directory: $proof"
proof="$(cd "$proof" && pwd -P)"

base_files=(
  manifest.txt SHA256SUMS command.txt tools.txt
  commit-before.txt commit-after.txt status-before.txt status-after.txt
  check.stdout.log check.stderr.log check-exit.txt
)
for file in "${base_files[@]}"; do
  [ -f "$proof/$file" ] || fail "missing required file: $file"
done
symlink="$(find "$proof" -type l -print -quit)"
[ -z "$symlink" ] || fail "proof contains a symlink: $symlink"

manifest_value() {
  local key="$1"
  awk -F= -v key="$key" '
    $1 == key {
      count += 1
      if (count == 1) { sub(/^[^=]*=/, ""); value=$0 }
    }
    END { if (count != 1) exit 1; print value }
  ' "$proof/manifest.txt"
}

format_version="$(manifest_value format_version)" \
  || fail "manifest must contain exactly one format_version"
case "$format_version" in 1|2|3) ;; *) fail "unsupported format_version: $format_version" ;; esac
if [ "$for_close" -eq 1 ]; then
  [ "$format_version" = 3 ] || fail "closure requires retained v3 step evidence"
  [ -n "$repository" ] || fail "--for-close requires --repository"
fi
if [ "$for_resume" -eq 1 ]; then
  [ "$format_version" = 3 ] || fail "resume requires v3 retained step evidence; legacy proof verification is unchanged"
  [ -n "$repository" ] || fail "--for-resume requires --repository"
fi
keys_v1=(authority check_exit commit finished_utc format_version ref repository started_utc tree_stable verdict)
keys_v2=(authority check_exit check_script_blob check_script_path commit finished_utc format_version ref repository started_utc tree tree_stable verdict)
actual_keys="$(awk -F= 'NF >= 2 && length($1) > 0 { print $1; next } { exit 2 }' \
  "$proof/manifest.txt" | LC_ALL=C sort)" \
  || fail "manifest contains a blank or malformed line"
if [ "$format_version" = 1 ]; then
  expected_keys="$(printf '%s\n' "${keys_v1[@]}" | LC_ALL=C sort)"
else
  expected_keys="$(printf '%s\n' "${keys_v2[@]}" | LC_ALL=C sort)"
fi
[ "$actual_keys" = "$expected_keys" ] \
  || fail "manifest key inventory is not exact for format v$format_version"

commit="$(manifest_value commit)" || fail "manifest lacks commit"
printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$' || fail "invalid manifest commit"
check_exit="$(manifest_value check_exit)" || fail "manifest lacks check_exit"
[[ "$check_exit" =~ ^(0|[1-9][0-9]{0,2})$ ]] && [ "$check_exit" -le 255 ] \
  || fail "check_exit must be a canonical shell status in 0..255"
stable="$(manifest_value tree_stable)" || fail "manifest lacks tree_stable"
case "$stable" in true|false) ;; *) fail "tree_stable must be true or false" ;; esac
verdict="$(manifest_value verdict)" || fail "manifest lacks verdict"
case "$verdict" in pass|red|void) ;; *) fail "unknown verdict: $verdict" ;; esac
authority="$(manifest_value authority)" || fail "manifest lacks authority"
case "$authority" in check.sh\ exit\ code*) ;; *) fail "manifest authority boundary is invalid" ;; esac
[ -n "$(manifest_value started_utc)" ] || fail "started_utc is empty"
[ -n "$(manifest_value finished_utc)" ] || fail "finished_utc is empty"

expected_files=(
  ./SHA256SUMS ./check-exit.txt ./check.stderr.log ./check.stdout.log
  ./command.txt ./commit-after.txt ./commit-before.txt ./manifest.txt
  ./status-after.txt ./status-before.txt ./tools.txt
)
if [ "$format_version" != 1 ]; then
  expected_files+=(./check-script-blob.txt ./tree-after.txt ./tree-before.txt)
  for file in check-script-blob.txt tree-after.txt tree-before.txt; do
    [ -f "$proof/$file" ] || fail "format v2 proof lacks $file"
  done
fi
if [ "$format_version" = 3 ]; then
  expected_files+=(./step-verdicts.jsonl)
  # Only step evidence and checksum-addressed source bundles extend the base
  # inventory. Every byte, including nested proof sums, is covered below.
  while IFS= read -r file; do
    case "$file" in ./steps/*|./sources/*) expected_files+=("$file") ;; esac
  done <<< "$(cd "$proof" && find . -type f -print | LC_ALL=C sort)"
fi
expected_inventory="$(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)"
actual_inventory="$(cd "$proof" && find . -type f -print | LC_ALL=C sort)"
[ "$actual_inventory" = "$expected_inventory" ] \
  || fail "proof regular-file inventory is not exact"

declared_files="$(sed -E 's/^[0-9a-fA-F]{64}[[:space:]]+//' "$proof/SHA256SUMS" | LC_ALL=C sort)"
actual_without_sums="$(cd "$proof" && find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort)"
[ "$declared_files" = "$actual_without_sums" ] \
  || fail "SHA256SUMS does not name the exact checksum-covered inventory"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$proof" && sha256sum -c SHA256SUMS >/dev/null) || fail "SHA-256 verification failed"
elif command -v shasum >/dev/null 2>&1; then
  (cd "$proof" && shasum -a 256 -c SHA256SUMS >/dev/null) || fail "SHA-256 verification failed"
else
  fail "sha256sum or shasum is required"
fi

[ "$(cat "$proof/command.txt")" = "bash scripts/check.sh" ] || fail "unexpected proof command"
[ "$(cat "$proof/commit-before.txt")" = "$commit" ] || fail "manifest/before-commit mismatch"
recorded_exit="$(cat "$proof/check-exit.txt")"
[ "$recorded_exit" = "$check_exit" ] || fail "manifest/check-exit file mismatch"
if grep -q '[^[:space:]]' "$proof/status-before.txt"; then
  fail "proof did not start from a clean worktree"
fi

before_commit="$(cat "$proof/commit-before.txt")"
after_commit="$(cat "$proof/commit-after.txt")"
[[ "$after_commit" =~ ^[0-9a-f]{40}$ ]] || fail "invalid after-commit object ID"
before_status="$(cat "$proof/status-before.txt")"
after_status="$(cat "$proof/status-after.txt")"
if [ "$format_version" != 1 ]; then
  tree="$(manifest_value tree)" || fail "manifest lacks tree"
  printf '%s\n' "$tree" | grep -Eq '^[0-9a-f]{40}$' || fail "invalid manifest tree"
  path="$(manifest_value check_script_path)" || fail "manifest lacks check_script_path"
  [ "$path" = scripts/check.sh ] || fail "unexpected check_script_path: $path"
  script_blob="$(manifest_value check_script_blob)" || fail "manifest lacks check_script_blob"
  printf '%s\n' "$script_blob" | grep -Eq '^[0-9a-f]{40}$' || fail "invalid check_script_blob"
  [ "$(cat "$proof/tree-before.txt")" = "$tree" ] || fail "manifest/before-tree mismatch"
  [ "$(cat "$proof/check-script-blob.txt")" = "$script_blob" ] || fail "manifest/check-script-blob mismatch"
  before_tree="$(cat "$proof/tree-before.txt")"
  after_tree="$(cat "$proof/tree-after.txt")"
  [[ "$after_tree" =~ ^[0-9a-f]{40}$ ]] || fail "invalid after-tree object ID"
else
  tree=""
  path="scripts/check.sh"
  script_blob=""
  before_tree="legacy"
  after_tree="legacy"
fi

observed_stable=false
if [ "$before_commit" = "$after_commit" ] \
  && [ "$before_tree" = "$after_tree" ] \
  && [ "$before_status" = "$after_status" ]; then
  observed_stable=true
fi
[ "$observed_stable" = "$stable" ] || fail "tree_stable disagrees with captured state"
if [ "$stable" = true ]; then
  if grep -q '[^[:space:]]' "$proof/status-after.txt"; then
    fail "stable proof ended dirty"
  fi
fi

if [ -n "$repository" ]; then
  git -C "$repository" cat-file -e "${commit}^{commit}" 2>/dev/null \
    || fail "repository does not contain proof commit $commit"
  repository_tree="$(git -C "$repository" rev-parse "${commit}^{tree}")"
  if [ -n "$tree" ] && [ "$repository_tree" != "$tree" ]; then
    fail "repository tree $repository_tree disagrees with proof tree $tree"
  fi
  if [ -n "$script_blob" ]; then
    repository_blob="$(git -C "$repository" rev-parse "${commit}:${path}")" \
      || fail "repository commit lacks $path"
    [ "$repository_blob" = "$script_blob" ] \
      || fail "repository $path blob disagrees with proof"
  fi
fi

if [ "$for_close" -eq 1 ]; then
  [ "$verdict" = pass ] && [ "$stable" = true ] || fail "closure requires a stable PASS proof"
fi

case "$verdict" in
  pass)
    [ "$stable" = true ] || fail "pass proof is not tree-stable"
    [ "$check_exit" -eq 0 ] || fail "pass proof has nonzero check exit"
    [ "$(grep -Ec '^ALL GATES GREEN([[:space:]]|$)' "$proof/check.stdout.log")" -eq 1 ] \
      || fail "pass proof must contain exactly one anchored green summary"
    if grep -Eq '^(RED|UNRUN|FAIL|QUALITY GATE RED)([[:space:]]|$)' "$proof/check.stdout.log"; then
      fail "pass proof contains an anchored non-pass verdict"
    fi
    ;;
  red)
    [ "$stable" = true ] || fail "red proof is not tree-stable"
    [ "$check_exit" -ne 0 ] || fail "red proof has zero check exit"
    grep -Fxq 'QUALITY GATE RED' "$proof/check.stdout.log" \
      || fail "red proof lacks QUALITY GATE RED on stdout"
    grep -Fxq 'QUALITY GATE RED' "$proof/check.stderr.log" \
      || fail "red proof lacks QUALITY GATE RED on stderr"
    grep -Eq '^(RED|UNRUN|FAIL)([[:space:]]|$)' "$proof/check.stdout.log" \
      || fail "red proof lacks an anchored failing gate verdict"
    if grep -Eq '^ALL GATES GREEN([[:space:]]|$)' "$proof/check.stdout.log"; then
      fail "red proof contains a green summary"
    fi
    ;;
  void)
    [ "$stable" = false ] || fail "void proof claims a stable tree"
    ;;
esac

proof_scope="historical"
if [ "$format_version" = 3 ]; then
  command -v python3 >/dev/null 2>&1 || fail "v3 step verification requires python3"
  step_validation="$(python3 -B - "$proof" "$tree" "$script_blob" "$verdict" "$for_resume" \
      "$repository" "$commit" "$for_close" <<'PY'
import collections
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
tree, script_blob, verdict, for_resume, repository, commit, for_close = sys.argv[2:]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key}")
        result[key] = value
    return result

def records_at(directory):
    lines = (directory / "step-verdicts.jsonl").read_text().splitlines()
    require(bool(lines), "empty step record inventory")
    records = [json.loads(line, object_pairs_hook=strict_object) for line in lines]
    require(all(isinstance(record, dict) for record in records), "non-object step record")
    names = [record.get("step") for record in records]
    require(all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                and name not in (".", "..") for name in names), "invalid step name")
    require(len(set(names)) == len(names), "duplicate step record")
    return {record["step"]: record for record in records}

try:
    records = records_at(root)
    manifest = dict(line.split("=", 1) for line in (root / "manifest.txt").read_text().splitlines())
    run_started = datetime.datetime.strptime(manifest["started_utc"], "%Y-%m-%dT%H:%M:%SZ")
    run_finished = datetime.datetime.strptime(manifest["finished_utc"], "%Y-%m-%dT%H:%M:%SZ")
    require(run_finished >= run_started, "reversed proof execution times")
    canonical = []
    if repository:
        committed = int(subprocess.check_output(["git", "-C", repository, "show", "-s", "--format=%ct", commit], text=True).strip())
        committed_at = datetime.datetime.fromtimestamp(committed, datetime.timezone.utc).replace(tzinfo=None)
        require(run_started >= committed_at, "proof started before its commit")
        script = subprocess.check_output(["git", "-C", repository, "show", f"{commit}:scripts/check.sh"], text=True)
        headers = re.findall(r"^# CANONICAL_STEPS: (.+)$", script, re.M)
        if len(headers) == 1:
            canonical = [name.strip() for name in headers[0].split(",")]
            require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in canonical)
                    and len(set(canonical)) == len(canonical), "invalid canonical step inventory")
    full_scope = bool(canonical) and set(canonical) == set(records)
    if for_close == "1":
        require(full_scope, "closure requires the full canonical step inventory, including test")
        require(records.get("test", {}).get("status") == "PASS"
                and records.get("test-list", {}).get("status") == "PASS",
                "closure requires executed tests and their inventory")
    tools = (root / "tools.txt").read_text().splitlines()
    toolchains = [line.removeprefix("rustc=") for line in tools if line.startswith("rustc=")]
    require(len(toolchains) == 1 and toolchains[0].startswith("rustc "), "missing or ambiguous Rust toolchain")
    embedded = [json.loads(line.removeprefix("step_verdict="), object_pairs_hook=strict_object)
                for line in tools if line.startswith("step_verdict=")]
    require(embedded == list(records.values()), "tools/step record inventory mismatch")
    stdout = (root / "check.stdout.log").read_text()
    pass_labels = re.findall(r"^PASS ([A-Za-z0-9_.-]+)(?=\s|$)", stdout, re.M)
    expected_pass = [name for name, record in records.items() if record.get("status") == "PASS"]
    require(collections.Counter(pass_labels) == collections.Counter(expected_pass), "stdout/step PASS inventory mismatch")
    unrun_labels = re.findall(r"^UNRUN ([A-Za-z0-9_.-]+)(?=\s|$)", stdout, re.M)
    expected_unrun = [name for name, record in records.items() if record.get("status") == "UNRUN"]
    require(collections.Counter(unrun_labels) == collections.Counter(expected_unrun), "stdout/step UNRUN inventory mismatch")
    if verdict == "pass":
        require(all(record.get("status") == "PASS" for record in records.values()), "pass proof has non-PASS steps")
    if for_resume == "1":
        require(all(record.get("status") != "FAIL" for record in records.values()), "resume proof contains a FAIL step")
        require(not re.search(r"^RED(?:\s|$)|^[\w-]+: \d+ passed, [1-9]\d* failed,", stdout, re.M), "resume proof contains an executed failure")
    offered_sources = [line.removeprefix("resume_source=") for line in tools if line.startswith("resume_source=")]
    require(len(offered_sources) <= 1 and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in offered_sources), "invalid resume source identity")
    source_ids = set(offered_sources)
    required_keys = {"step", "status", "tree_hash", "toolchain", "worker", "started", "finished", "duration_secs", "log_digest"}
    for name, record in records.items():
        require(set(record) in (required_keys, required_keys | {"reused_from"}), f"{name}: unexpected record fields")
        require(record["status"] in ("PASS", "FAIL", "UNRUN"), f"{name}: invalid status")
        require(record["tree_hash"] == tree and record["toolchain"] == toolchains[0], f"{name}: tree/toolchain mismatch")
        require(isinstance(record["worker"], str) and bool(record["worker"]), f"{name}: missing execution worker")
        require(type(record["duration_secs"]) is int and record["duration_secs"] >= 0, f"{name}: invalid duration")
        started = datetime.datetime.strptime(record["started"], "%Y-%m-%dT%H:%M:%SZ")
        finished = datetime.datetime.strptime(record["finished"], "%Y-%m-%dT%H:%M:%SZ")
        require(finished >= started, f"{name}: reversed execution times")
        require(finished <= run_finished, f"{name}: step finished after its proof")
        if "reused_from" not in record:
            require(started >= run_started, f"{name}: step started before its proof")
        log = root / "steps" / (name + ".log")
        if record["log_digest"] == "none":
            require(record["status"] != "PASS" and not log.exists(), f"{name}: missing PASS log or unbound log")
        else:
            require(isinstance(record["log_digest"], str) and re.fullmatch(r"[0-9a-f]{64}", record["log_digest"]), f"{name}: invalid log digest")
            require(log.is_file(), f"{name}: missing step log")
            require(hashlib.sha256(log.read_bytes()).hexdigest() == record["log_digest"], f"{name}: step log digest mismatch")
        if for_resume == "1" and log.is_file():
            require(not re.search(r"RCH_SCOPED_COMPLETION_UNCONFIRMED|completion unconfirmed", log.read_text()), f"{name}: uncertain completion requires reconciliation before resume")
        if record["status"] == "PASS" and name in {"check", "clippy", "test-list", "test", "robot-schema", "registry-check", "fuzz-smoke", "bench-smoke", "reachability"}:
            text = log.read_text()
            require("Remote command finished: exit=0" in text, f"{name}: missing remote completion")
            require(not re.search(r"Remote command finished: exit=[1-9]\d*|^test result: FAILED|^test .+ \.\.\. FAILED$", text, re.M), f"{name}: contradictory failed execution")
            workers = re.findall(r"Selected worker: (\S+) at |^\[RCH\] remote (\S+) \(", text, re.M)
            require(any(record["worker"] in pair for pair in workers), f"{name}: execution worker is not witnessed by the log")
            if name in {"check", "clippy"}:
                require(re.search(r"^\s*Finished ", text, re.M), f"{name}: missing compile completion")
            if name == "test-list":
                require(re.search(r": test$", text, re.M), "test-list: no tests listed")
            if name in {"test", "robot-schema", "registry-check"}:
                require(sum(map(int, re.findall(r"^test result: ok\. (\d+) passed;", text, re.M))) > 0, f"{name}: zero executed tests")
        if "reused_from" in record:
            source = record["reused_from"]
            require(isinstance(source, dict) and set(source) == {"proof", "step"}, f"{name}: malformed source reference")
            require(isinstance(source["proof"], str) and re.fullmatch(r"[0-9a-f]{64}", source["proof"]), f"{name}: invalid source digest")
            require(source["step"] == name and record["status"] == "PASS", f"{name}: invalid reused step")
            require(source["proof"] in offered_sources, f"{name}: source differs from admitted resume proof")
            source_ids.add(source["proof"])
            prior = root / "sources" / source["proof"]
            require(hashlib.sha256((prior / "SHA256SUMS").read_bytes()).hexdigest() == source["proof"], f"{name}: source proof checksum identity mismatch")
            prior_manifest = (prior / "manifest.txt").read_text().splitlines()
            require("format_version=3" in prior_manifest and "tree_stable=true" in prior_manifest
                    and f"tree={tree}" in prior_manifest and f"check_script_blob={script_blob}" in prior_manifest, f"{name}: incompatible source proof")
            prior_records = records_at(prior)
            require(all(item.get("status") != "FAIL" for item in prior_records.values()), f"{name}: source proof has FAIL")
            origin = prior_records.get(name)
            require(origin is not None and {k: v for k, v in origin.items() if k != "reused_from"}
                    == {k: v for k, v in record.items() if k != "reused_from"}, f"{name}: execution provenance changed")
    if records.get("test", {}).get("status") == "PASS":
        require(records.get("test-list", {}).get("status") == "PASS", "test PASS lacks an inventory witness")
        listed = collections.Counter(re.findall(r"^\s*(.+): test$", (root / "steps/test-list.log").read_text(), re.M))
        executed = collections.Counter(re.findall(r"^test (\S+)(?: - should panic)? \.\.\. (?:ok|ignored(?:, [^\n]*)?)$", (root / "steps/test.log").read_text(), re.M))
        require(bool(listed) and listed == executed, "listed/executed test inventories differ")
    sources_dir = root / "sources"
    actual_sources = {path.name for path in sources_dir.iterdir()} if sources_dir.exists() else set()
    require(actual_sources == source_ids, "unreferenced or missing retained source proof")
    print("scope=" + ("full" if full_scope else "partial"))
    for source_id in sorted(source_ids):
        print("source=" + source_id)
except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
    print(f"local-proof-verify: {error}", file=sys.stderr)
    sys.exit(1)
PY
)" || fail "v3 step evidence is invalid"
  proof_scope="$(awk -F= '$1 == "scope" { print $2 }' <<< "$step_validation")"
  source_ids="$(awk -F= '$1 == "source" { print $2 }' <<< "$step_validation")"
  depth="${FA_PROOF_VERIFY_DEPTH:-0}"
  [[ "$depth" =~ ^[0-9]+$ ]] && [ "$depth" -lt 16 ] || fail "source proof nesting exceeds 16"
  while IFS= read -r source_id; do
    [ -n "$source_id" ] || continue
    if [ -n "$repository" ]; then
      FA_PROOF_VERIFY_DEPTH="$((depth + 1))" bash "${BASH_SOURCE[0]}" --repository "$repository" "$proof/sources/$source_id" \
        >/dev/null || fail "retained source proof failed independent verification: $source_id"
    else
      FA_PROOF_VERIFY_DEPTH="$((depth + 1))" bash "${BASH_SOURCE[0]}" "$proof/sources/$source_id" \
        >/dev/null || fail "retained source proof failed independent verification: $source_id"
    fi
  done <<< "$source_ids"
fi

if [ "$for_resume" -eq 1 ]; then
  [ "$stable" = true ] || fail "resume proof was not tree-stable"
  [ "$(git -C "$repository" rev-parse 'HEAD^{tree}')" = "$tree" ] || fail "resume tree differs from current tree"
  [ "$(git -C "$repository" rev-parse HEAD:scripts/check.sh)" = "$script_blob" ] || fail "resume check script differs from current script"
  current_toolchain="$(cd "$repository" && rustc --version)" || fail "cannot determine current toolchain"
  [ "$(grep '^rustc=' "$proof/tools.txt")" = "rustc=$current_toolchain" ] || fail "resume toolchain differs from current toolchain"
fi

printf 'LOCAL_PROOF_VERIFIED\n'
printf 'path=%s\n' "$proof"
printf 'commit=%s\n' "$commit"
printf 'tree=%s\n' "${tree:-legacy-unrecorded}"
printf 'check_script_blob=%s\n' "${script_blob:-legacy-unrecorded}"
printf 'check_exit=%s\n' "$check_exit"
printf 'tree_stable=%s\n' "$stable"
printf 'verdict=%s\n' "$verdict"
printf 'scope=%s\n' "$proof_scope"
