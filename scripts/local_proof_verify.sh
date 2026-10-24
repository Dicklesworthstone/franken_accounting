#!/usr/bin/env bash
# Independently verify a local proof bundle without rerunning its commands (bead fa-u7u).
#
# This authenticates format and internal consistency, not the identity of the
# bundle's producer. With --repository it additionally binds the named commit,
# tree, and check-script blob to an independently supplied Git object database.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/local_proof_verify.sh [--repository DIR] [--for-resume] PROOF_DIR

Options:
  --repository DIR  Require DIR's Git object database to contain the proof's
                    commit, tree, and exact tracked scripts/check.sh blob.
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
for_resume=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository)
      [ "$#" -ge 2 ] || fail "--repository requires a directory"
      repository="$2"
      shift 2
      ;;
    --for-resume) for_resume=1; shift ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*) fail "unknown argument: $1" ;;
    *)
      [ -z "$proof_arg" ] || fail "only one proof directory may be supplied"
      proof_arg="$1"
      shift
      ;;
  esac
done
[ -n "$proof_arg" ] || { usage >&2; exit 2; }

proof="$proof_arg"
[ -d "$proof" ] || fail "not a directory: $proof"
proof="$(cd "$proof" && pwd -P)"
if [ -n "$repository" ]; then
  [ -d "$repository" ] || fail "not a repository directory: $repository"
  repository="$(cd "$repository" && pwd -P)"
  git -C "$repository" rev-parse --git-dir >/dev/null 2>&1 \
    || fail "--repository is not a Git worktree or repository"
fi

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

if [ "$format_version" = 3 ]; then
  command -v python3 >/dev/null 2>&1 || fail "v3 step verification requires python3"
  source_ids="$(python3 -B - "$proof" "$tree" "$script_blob" "$verdict" "$for_resume" <<'PY'
import collections
import datetime
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
tree, script_blob, verdict, for_resume = sys.argv[2:]

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
        executed = collections.Counter(re.findall(r"^test (.+) \.\.\. (?:ok|ignored)$", (root / "steps/test.log").read_text(), re.M))
        require(bool(listed) and not (listed - executed), "listed tests missing from execution")
    sources_dir = root / "sources"
    actual_sources = {path.name for path in sources_dir.iterdir()} if sources_dir.exists() else set()
    require(actual_sources == source_ids, "unreferenced or missing retained source proof")
    for source_id in sorted(source_ids):
        print(source_id)
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f"local-proof-verify: {error}", file=sys.stderr)
    sys.exit(1)
PY
)" || fail "v3 step evidence is invalid"
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
