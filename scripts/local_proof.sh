#!/usr/bin/env bash
# Capture one exact-tree local `scripts/check.sh` run as immutable evidence (beads fa-u7u, fa-aj8).
#
# This wrapper does not reinterpret product failures. `check.sh`'s exit code is
# authoritative when the tree remains stable; any HEAD, committed-tree, or
# worktree movement voids the run. Output directories are never removed or
# overwritten.
#
# Supports `--resume-from PRIOR_PROOF_DIR` for split-run union on the exact
# same tree and toolchain (refusing if the prior run recorded any FAIL step),
# and `--publish-note` to attach the verdict manifest under `refs/notes/fa-verdict`.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/local_proof.sh [--output DIR] [--resume-from PRIOR_DIR]
                                   [--publish-note] [--push-note]

Run the repository-authoritative `bash scripts/check.sh`, preserve stdout and
stderr separately, and write a checksum-bound format-v3 manifest naming the
exact commit, source tree, and tracked check-script blob. DIR must be outside
the repository and must not exist. V3 retains step logs and source proofs for
independent verification; legacy v1/v2 proofs remain readable but cannot resume.
USAGE
}

fail() {
  printf 'local-proof: %s\n' "$*" >&2
  exit 2
}

output=""
resume_from=""
publish_note=0
push_note=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || fail "--output requires a directory"
      output="$2"
      shift 2
      ;;
    --resume-from)
      [ "$#" -ge 2 ] || fail "--resume-from requires a directory"
      resume_from="$2"
      shift 2
      ;;
    --publish-note)
      publish_note=1
      shift
      ;;
    --push-note)
      publish_note=1
      push_note=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

command -v git >/dev/null 2>&1 || fail "git is required"
if command -v sha256sum >/dev/null 2>&1; then
  hash_command=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash_command=(shasum -a 256)
else
  fail "sha256sum or shasum is required"
fi
root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "not inside a Git worktree"
cd "$root"
[ -f scripts/check.sh ] || fail "scripts/check.sh is missing"

if [ -f scripts/gate_workers.conf ]; then
  # shellcheck source=gate_workers.conf
  . scripts/gate_workers.conf
fi

before_commit="$(git rev-parse --verify HEAD)"
before_tree="$(git rev-parse --verify "${before_commit}^{tree}")"
check_script_path="scripts/check.sh"
check_script_blob="$(git rev-parse --verify "${before_commit}:${check_script_path}")" \
  || fail "$check_script_path is not tracked by $before_commit"
short_sha="$(printf '%s' "$before_commit" | cut -c1-12)"
ref_name="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || printf 'detached')"
before_status="$(git status --porcelain=v1 --untracked-files=all)" \
  || fail "could not capture the initial worktree state"
[ -z "$before_status" ] || {
  printf '%s\n' "$before_status" >&2
  fail "proof runs require a clean worktree"
}

if [ -n "$resume_from" ]; then
  [ -d "$resume_from" ] || fail "--resume-from directory does not exist: $resume_from"
  resume_from="$(cd "$resume_from" && pwd -P)"
  bash scripts/local_proof_verify.sh --repository "$root" --for-resume "$resume_from" \
    || fail "--resume-from proof is not admissible; no commands executed"
fi
# An inherited variable must not bypass the explicit admission above.
unset CHECK_RESUME_FROM

if [ -z "$output" ]; then
  output="${TMPDIR:-/tmp}/fa-local-proof-${short_sha}-$$"
fi
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
parent="$(dirname "$output")"
[ -d "$parent" ] || fail "output parent does not exist: $parent"
parent="$(cd "$parent" && pwd -P)"
output="$parent/$(basename "$output")"
case "$output" in "$root"|"$root"/*) fail "output must be outside the repository worktree" ;; esac
[ ! -e "$output" ] && [ ! -L "$output" ] || fail "output already exists: $output"
# mkdir is the exclusive claim, not the preceding advisory existence check.
# Never write into another producer's directory if that claim fails.
mkdir "$output" || fail "could not claim output directory: $output"
if [ -n "$resume_from" ]; then
  source_id="$("${hash_command[@]}" "$resume_from/SHA256SUMS" | awk '{print $1}')"
  mkdir "$output/sources"
  cp -R "$resume_from" "$output/sources/$source_id" \
    || fail "could not retain the source proof; no commands executed"
  bash scripts/local_proof_verify.sh --repository "$root" --for-resume "$output/sources/$source_id" \
    || fail "retained source proof changed during copy; no commands executed"
  export CHECK_RESUME_FROM="$output/sources/$source_id"
fi

printf '%s\n' "$before_commit" > "$output/commit-before.txt"
printf '%s\n' "$before_tree" > "$output/tree-before.txt"
printf '%s\n' "$check_script_blob" > "$output/check-script-blob.txt"
printf '%s' "$before_status" > "$output/status-before.txt"
printf 'bash scripts/check.sh\n' > "$output/command.txt"

pool_warm="false"
if [ "$root" = "${FA_GATE_WORKTREE:-/data/projects/franken_accounting-gate}" ] || [ -d "$root/target" ]; then
  pool_warm="true"
fi

{
  printf 'git=%s\n' "$(git --version 2>&1)"
  printf 'uname=%s\n' "$(uname -a 2>&1)"
  if command -v rustc >/dev/null 2>&1; then printf 'rustc=%s\n' "$(rustc --version 2>&1)"; else printf 'rustc=unavailable\n'; fi
  if command -v cargo >/dev/null 2>&1; then printf 'cargo=%s\n' "$(cargo --version 2>&1)"; else printf 'cargo=unavailable\n'; fi
  if command -v br >/dev/null 2>&1; then printf 'br=%s\n' "$(br --version 2>&1)"; else printf 'br=unavailable\n'; fi
  printf 'worktree=%s\n' "$root"
  printf 'designated_workers=%s\n' "${FA_GATE_WORKERS:-hz2,vmi1152480}"
  printf 'warm=%s\n' "$pool_warm"
  if [ -n "$resume_from" ]; then printf 'resume_source=%s\n' "$source_id"; fi
} > "$output/tools.txt"

export CHECK_LOG_DIR="$output/steps"
mkdir "$CHECK_LOG_DIR"
export CHECK_STEP_MANIFEST="$output/step-verdicts.jsonl"

started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
t0_epoch="$(date +%s)"
if bash scripts/check.sh > "$output/check.stdout.log" 2> "$output/check.stderr.log"; then
  check_exit=0
else
  check_exit=$?
fi
finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
t1_epoch="$(date +%s)"
printf 'wall_seconds=%s\n' "$((t1_epoch - t0_epoch))" >> "$output/tools.txt"
if [ -f "$CHECK_STEP_MANIFEST" ]; then
  while IFS= read -r step_line; do
    [ -n "$step_line" ] && printf 'step_verdict=%s\n' "$step_line" >> "$output/tools.txt"
  done < "$CHECK_STEP_MANIFEST"
fi

after_commit="$(git rev-parse --verify HEAD)"
after_tree="$(git rev-parse --verify "${after_commit}^{tree}")"
after_status="$(git status --porcelain=v1 --untracked-files=all)" \
  || fail "could not capture the final worktree state"
printf '%s\n' "$after_commit" > "$output/commit-after.txt"
printf '%s\n' "$after_tree" > "$output/tree-after.txt"
printf '%s' "$after_status" > "$output/status-after.txt"
printf '%s\n' "$check_exit" > "$output/check-exit.txt"

stable=true
if [ "$before_commit" != "$after_commit" ] \
  || [ "$before_tree" != "$after_tree" ] \
  || [ "$before_status" != "$after_status" ]; then
  stable=false
fi

if [ "$stable" != true ]; then
  verdict=void
  wrapper_exit=125
elif [ "$check_exit" -eq 0 ]; then
  verdict=pass
  wrapper_exit=0
else
  verdict=red
  wrapper_exit="$check_exit"
  if [ "$wrapper_exit" -eq 0 ]; then wrapper_exit=1; fi
fi

{
  printf 'format_version=3\n'
  printf 'repository=%s\n' "$(basename "$root")"
  printf 'commit=%s\n' "$before_commit"
  printf 'tree=%s\n' "$before_tree"
  printf 'ref=%s\n' "$ref_name"
  printf 'check_script_path=%s\n' "$check_script_path"
  printf 'check_script_blob=%s\n' "$check_script_blob"
  printf 'started_utc=%s\n' "$started_utc"
  printf 'finished_utc=%s\n' "$finished_utc"
  printf 'check_exit=%s\n' "$check_exit"
  printf 'tree_stable=%s\n' "$stable"
  printf 'verdict=%s\n' "$verdict"
  printf 'authority=check.sh exit code on the exact stable tree; void when HEAD, committed tree, or worktree state moves; a PASS note proves the named steps passed on that tree, not product correctness beyond them\n'
} > "$output/manifest.txt"

(
  cd "$output"
  # Process substitution hides find/sort failures from the consuming loop.
  # Capture the complete inventory synchronously before publishing checksums.
  inventory="$(find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort)" \
    || fail "could not enumerate proof inventory"
  [ -n "$inventory" ] || fail "proof inventory is empty"
  : > SHA256SUMS
  while IFS= read -r file; do
    "${hash_command[@]}" "$file" >> SHA256SUMS \
      || fail "could not checksum proof file: $file"
  done <<< "$inventory"
)

# A successful check exit cannot publish a proof whose own retained evidence
# fails verification. Keep the incomplete bundle for diagnosis on failure.
bash scripts/local_proof_verify.sh --repository "$root" "$output" \
  || fail "produced proof failed independent verification"

note_id=""
if [ "$publish_note" -eq 1 ]; then
  note_body="$(python3 -B - "$output" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
manifest_text = (root / "manifest.txt").read_text()
tools_lines = (root / "tools.txt").read_text().splitlines()
toolchain = next((l.removeprefix("rustc=") for l in tools_lines if l.startswith("rustc=")), "unavailable")
sums_sha256 = hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest()

test_list_log = root / "steps" / "test-list.log"
if test_list_log.is_file():
    listed = sorted(re.findall(r"^\s*(.+): test$", test_list_log.read_text(errors="replace"), re.M))
    if listed:
        test_inv_digest = hashlib.sha256(("\n".join(listed) + "\n").encode("utf-8")).hexdigest()
    else:
        test_inv_digest = hashlib.sha256(test_list_log.read_bytes()).hexdigest()
else:
    test_inv_digest = "none"

out = [manifest_text.rstrip("\n")]
out.append("no_claim_boundary=a PASS note proves the named steps passed on that tree, not product correctness beyond them")
out.append(f"toolchain={toolchain}")
out.append(f"proof_sums_sha256={sums_sha256}")
out.append(f"test_inventory_digest={test_inv_digest}")

step_file = root / "step-verdicts.jsonl"
if step_file.is_file():
    for line in step_file.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        step_name = rec["step"]
        dur_secs = int(rec.get("duration_secs", 0))
        rec["duration_ms"] = dur_secs * 1000
        log_path = root / "steps" / f"{step_name}.log"
        witness = {
            "log_digest": rec.get("log_digest", "none"),
            "worker": rec.get("worker", "local"),
        }
        if log_path.is_file():
            text = log_path.read_text(errors="replace")
            if step_name == "test-list":
                witness["listed_tests"] = len(re.findall(r"^\s*(.+): test$", text, re.M))
                witness["test_inventory_digest"] = test_inv_digest
            elif step_name in ("test", "robot-schema", "registry-check"):
                witness["passed_tests"] = sum(map(int, re.findall(r"^test result: ok\. (\d+) passed;", text, re.M)))
            elif step_name in ("check", "clippy"):
                witness["finished_targets"] = len(re.findall(r"^\s*Finished ", text, re.M))
            ev_ids = re.findall(r"^\s*evidence artifact_id=(\S+) .* verdict=PASS$", text, re.M)
            if ev_ids:
                witness["evidence_artifacts"] = ev_ids
            passed_names = []
            failed_names = []
            for m in re.finditer(r"^test\s+(\S+)\s+\.\.\.\s+(ok|FAILED)$", text, re.M):
                if m.group(2) == "ok":
                    passed_names.append(m.group(1))
                else:
                    failed_names.append(m.group(1))
            for m in re.finditer(r"^(PASS|FAIL|ok)\s+([A-Za-z0-9_.:/-]+)", text, re.M):
                if m.group(1) == "FAIL":
                    failed_names.append(m.group(2))
                else:
                    passed_names.append(m.group(2))
            if passed_names:
                witness["passed_test_names"] = passed_names
            if failed_names:
                witness["failed_test_names"] = failed_names
        rec["witness"] = witness
        out.append("step_verdict=" + json.dumps(rec, separators=(",", ":")))

print("\n".join(out))
PY
)"
  printf '%s\n' "$note_body" | git notes --ref=fa-verdict add -f -F - "$before_commit" 2>/dev/null || true
  note_id="$(git notes --ref=fa-verdict list "$before_commit" 2>/dev/null | awk '{print $1}' || true)"
  if [ "$push_note" -eq 1 ]; then
    git push origin refs/notes/fa-verdict:refs/notes/fa-verdict 2>/dev/null || true
  fi
fi

case "$verdict" in
  pass) printf 'LOCAL_PROOF_PASS\n' ;;
  red) printf 'LOCAL_PROOF_RED\n' ;;
  void) printf 'LOCAL_PROOF_VOID\n' ;;
esac
printf 'path=%s\n' "$output"
printf 'commit=%s\n' "$before_commit"
printf 'tree=%s\n' "$before_tree"
printf 'check_script_blob=%s\n' "$check_script_blob"
printf 'check_exit=%s\n' "$check_exit"
printf 'tree_stable=%s\n' "$stable"
printf 'verdict=%s\n' "$verdict"
if [ -n "$note_id" ]; then
  printf 'note_id=%s\n' "$note_id"
fi
exit "$wrapper_exit"
