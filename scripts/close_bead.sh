#!/usr/bin/env bash
# =============================================================================
# scripts/close_bead.sh — Evidence-bound bead closure, acceptance-tests parser,
# closure-debt metric, and 30-day closure-regression runner (beads fa-u7u, fa-8jcr)
# =============================================================================
# Usage:
#   bash scripts/close_bead.sh <bead-id> --verdict <note-id|commit|proof-dir>
#       [--commit <landing-commit>] [--repository <dir>] [--no-tests "<reason>"]
#       --reason <reason>
#   bash scripts/close_bead.sh <bead-id> --manifest <proof-dir|manifest.txt>
#       [--commit <landing-commit>] [--repository <dir>] --reason <reason>
#   bash scripts/close_bead.sh --parse-block <file-or-bead-id> [--repository <dir>]
#   bash scripts/close_bead.sh --closure-debt [--repository <dir>] [--verdict <dir|note>] [--json]
#   bash scripts/close_bead.sh --regression-check [--days 30] [--repository <dir>] [--verdict <dir|note>]
# =============================================================================

set -euo pipefail

fail() {
  printf 'close-bead: REFUSED — %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/close_bead.sh <bead-id> --verdict <note-id|commit|proof-dir>
                             [--commit <landing-commit>] [--repository <dir>]
                             [--no-tests "<reason>"] --reason <reason>
  bash scripts/close_bead.sh <bead-id> --manifest <proof-dir|manifest.txt>
                             [--commit <landing-commit>] [--repository <dir>]
                             --reason <reason>
  bash scripts/close_bead.sh --parse-block <bead-id|file> [--repository <dir>]
  bash scripts/close_bead.sh --closure-debt [--repository <dir>] [--verdict <dir|note>] [--json]
  bash scripts/close_bead.sh --regression-check [--days 30] [--repository <dir>] [--verdict <dir|note>]
USAGE
}

[ "$#" -ge 1 ] || { usage >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
bead_id=""
verdict_arg=""
manifest_arg=""
landing_commit=""
repo_dir=""
reason=""
no_tests_reason=""
mode="close"
parse_target=""
days=30
json_out=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --verdict)
      [ "$#" -ge 2 ] || fail "--verdict requires a note id, commit, or proof directory"
      verdict_arg="$2"
      shift 2
      ;;
    --manifest)
      [ "$#" -ge 2 ] || fail "--manifest requires a path"
      manifest_arg="$2"
      shift 2
      ;;
    --commit)
      [ "$#" -ge 2 ] || fail "--commit requires a commit SHA"
      landing_commit="$2"
      shift 2
      ;;
    --repository)
      [ "$#" -ge 2 ] || fail "--repository requires a directory"
      repo_dir="$2"
      shift 2
      ;;
    --reason)
      [ "$#" -ge 2 ] || fail "--reason requires text"
      reason="$2"
      shift 2
      ;;
    --no-tests)
      [ "$#" -ge 2 ] || fail "--no-tests requires a reason string"
      no_tests_reason="$2"
      shift 2
      ;;
    --parse-block)
      [ "$#" -ge 2 ] || fail "--parse-block requires a bead id or file"
      mode="parse-block"
      parse_target="$2"
      shift 2
      ;;
    --closure-debt)
      mode="closure-debt"
      shift
      ;;
    --regression-check)
      mode="regression-check"
      shift
      ;;
    --days)
      [ "$#" -ge 2 ] || fail "--days requires an integer"
      days="$2"
      shift 2
      ;;
    --json)
      json_out=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      fail "unknown flag: $1"
      ;;
    *)
      [ -z "$bead_id" ] || fail "only one bead id may be supplied"
      bead_id="$1"
      shift
      ;;
  esac
done

if [ -z "$repo_dir" ]; then
  repo_dir="$root"
fi
repo_dir="$(cd "$repo_dir" && pwd -P)"

# Python helper module embedded for acceptance-tests parsing, inventory extraction,
# closure-debt calculation, and 30-day regression checking.
run_py_helper() {
  FA_CLOSE_VERIFIER="$root/scripts/local_proof_verify.sh" python3 -B - "$@" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

cmd = sys.argv[1]

def die(msg):
    print(f"close-bead: REFUSED — {msg}", file=sys.stderr)
    sys.exit(2)

def parse_acceptance_block(text):
    """
    Extracts the ```acceptance-tests ... ``` fenced block from markdown text.
    Returns (kind, items) where:
      - kind == "missing": block absent
      - kind == "none": items == [reason_str]
      - kind == "tests": items == [test_1, test_2, ...]
    Raises ValueError on malformed fences, empty block, invalid test names, or duplicates.
    """
    lines = text.splitlines()
    in_block = False
    block_Count = 0
    collected = []
    for line in lines:
        stripped = line.strip()
        if not in_block:
            if re.match(r"^`{3,}acceptance-tests\s*$", stripped):
                in_block = True
                block_Count += 1
                if block_Count > 1:
                    raise ValueError("multiple acceptance-tests blocks found")
        else:
            if re.match(r"^`{3,}\s*$", stripped):
                in_block = False
                continue
            collected.append(stripped)
    if in_block:
        raise ValueError("unclosed acceptance-tests fenced block")
    if block_Count == 0:
        return ("missing", [])

    entries = []
    for raw in collected:
        if not raw or raw.startswith("#"):
            continue
        entries.append(raw)
    if not entries:
        raise ValueError("acceptance-tests block is empty")

    if len(entries) == 1 and entries[0].startswith("none:"):
        reason = entries[0][5:].strip()
        if not reason:
            raise ValueError("`none:` in acceptance-tests requires a non-empty reason")
        return ("none", [reason])

    seen = set()
    for item in entries:
        if item.startswith("none:"):
            raise ValueError("`none: <reason>` cannot be combined with test names")
        if "::" not in item or any(ch.isspace() for ch in item):
            raise ValueError(f"invalid acceptance test identifier `{item}` (expected crate::module::test_fn or script::case)")
        if item in seen:
            raise ValueError(f"duplicate acceptance test `{item}`")
        seen.add(item)
    return ("tests", entries)

def load_beads(repo):
    jsonl = pathlib.Path(repo) / ".beads" / "issues.jsonl"
    if not jsonl.is_file():
        return {}
    beads = {}
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "id" in row:
            beads[row["id"]] = row
    return beads

def load_verdict_inventory(repo, verdict_spec, for_close=False):
    """
    Loads passed and failed test inventories from either a proof directory,
    a manifest.txt path, or a git note under refs/notes/fa-verdict.
    Returns dict:
      {
        "commit": str,
        "tree": str,
        "verdict": str,
        "stable": str,
        "note_id": str,
        "passed": set[str],
        "failed": set[str],
      }
    """
    passed = set()
    failed = set()
    p = pathlib.Path(verdict_spec) if verdict_spec else None
    if p and p.exists():
        proof_dir = p if p.is_dir() else p.parent
        command = ["bash", os.environ["FA_CLOSE_VERIFIER"], "--repository", repo]
        if for_close:
            command.append("--for-close")
        command.append(str(proof_dir))
        checked = subprocess.run(command, text=True, capture_output=True)
        if checked.returncode:
            print(checked.stdout, end="", file=sys.stderr)
            print(checked.stderr, end="", file=sys.stderr)
            die("verdict inventory has no verified full-scope retained evidence")
        checked_fields = dict(line.split("=", 1) for line in checked.stdout.splitlines() if "=" in line)
        if checked_fields.get("scope") != "full":
            die("verdict inventory requires full-scope retained v3 evidence")
        manifest_file = proof_dir / "manifest.txt"
        if not manifest_file.is_file():
            die(f"manifest file not found: {manifest_file}")
        kv = {}
        for line in manifest_file.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k] = v
        commit = kv.get("commit", "")
        tree = kv.get("tree", "")
        verdict = kv.get("verdict", "")
        stable = kv.get("tree_stable", "")
        note_id = hashlib.sha256((proof_dir / "SHA256SUMS").read_bytes()).hexdigest()[:40]
        records = [json.loads(line) for line in (proof_dir / "step-verdicts.jsonl").read_text().splitlines()]
        # Only declared, checksum-bound step logs can supply executed cases.
        for record in records:
            if record["log_digest"] == "none":
                continue
            step_stem = record["step"]
            lf = proof_dir / "steps" / (step_stem + ".log")
            text = lf.read_text(encoding="utf-8", errors="replace")
            if step_stem == "test":
                for m in re.finditer(r"^test\s+(\S+)(?: - should panic)?\s+\.\.\.\s+(ok|FAILED)$", text, re.M):
                    (passed if m.group(2) == "ok" else failed).add(m.group(1))
            for m in re.finditer(r"^(PASS|FAIL|ok)\s+([A-Za-z0-9_.:/-]+)", text, re.M):
                kind, cname = m.group(1), m.group(2)
                target_Set = failed if kind == "FAIL" else passed
                # Script cases stay qualified by their owning step. A PASS
                # in check-classify cannot impersonate a workspace Rust test.
                target_Set.add(f"{step_stem}::{cname}")
                target_Set.add(f"{step_stem.replace('-', '_')}::{cname}")
        return {
            "commit": commit,
            "tree": tree,
            "verdict": verdict,
            "stable": stable,
            "note_id": note_id,
            "passed": passed,
            "failed": failed,
        }

    # Otherwise resolve via git notes --ref=fa-verdict in repo
    target = verdict_spec or "HEAD"
    note_text = ""
    note_id = ""
    commit = ""
    # Check if target is a note blob SHA in refs/notes/fa-verdict
    try:
        listing = subprocess.check_output(
            ["git", "-C", repo, "notes", "--ref=fa-verdict", "list"],
            text=True, stderr=subprocess.DEVNULL
        ).splitlines()
        for entry in listing:
            parts = entry.split()
            if len(parts) == 2 and (parts[0].startswith(target) or parts[1].startswith(target)):
                note_id, commit = parts[0], parts[1]
                break
    except Exception:
        pass
    if not commit:
        try:
            commit = subprocess.check_output(
                ["git", "-C", repo, "rev-parse", "--verify", f"{target}^{{commit}}"],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            out = subprocess.check_output(
                ["git", "-C", repo, "notes", "--ref=fa-verdict", "list", commit],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            if out:
                note_id = out.split()[0]
        except Exception:
            die(f"cannot resolve verdict reference `{target}` in {repo}")
    if not note_id:
        die(f"no refs/notes/fa-verdict note found for `{target}` in {repo}")
    command = ["bash", os.environ["FA_CLOSE_VERIFIER"], "--repository", repo]
    if for_close:
        command.append("--for-close")
    command.extend(["--note", commit])
    checked = subprocess.run(command, text=True, capture_output=True)
    if checked.returncode:
        print(checked.stdout, end="", file=sys.stderr)
        print(checked.stderr, end="", file=sys.stderr)
        die("note has no verified full-scope retained evidence")
    fields = dict(line.split("=", 1) for line in checked.stdout.splitlines() if "=" in line)
    inventory = load_verdict_inventory(repo, fields["path"], for_close)
    inventory["note_id"] = fields["note_id"]
    return inventory

def matches_inventory(test_id, inv_set):
    if test_id in inv_set:
        return True
    # Normalize crate-name hyphens to underscores and allow suffix matching after crate::
    norm = test_id.replace("-", "_")
    if norm in inv_set:
        return True
    if "::" in test_id:
        prefix, rest = test_id.split("::", 1)
        if rest in inv_set:
            return True
        # e.g. scripts/tests/close_bead_selftest.sh::closes_with_cited_note -> closes_with_cited_note
        stem = pathlib.Path(prefix).stem
        if f"{stem}::{rest}" in inv_set or rest in inv_set:
            return True
    return False

if cmd == "parse-block":
    repo, target = sys.argv[2], sys.argv[3]
    p = pathlib.Path(target)
    if p.is_file():
        text = p.read_text(encoding="utf-8")
    else:
        beads = load_beads(repo)
        if target not in beads:
            die(f"bead `{target}` not found in {repo}/.beads/issues.jsonl")
        text = beads[target].get("description", "")
    try:
        kind, items = parse_acceptance_block(text)
    except ValueError as err:
        die(str(err))
    print(json.dumps({"kind": kind, "items": items}))
    sys.exit(0)

if cmd == "closure-debt":
    repo, verdict_spec, as_json = sys.argv[2], sys.argv[3], int(sys.argv[4])
    beads = load_beads(repo)
    inv = None
    if verdict_spec:
        try:
            inv = load_verdict_inventory(repo, verdict_spec)
        except SystemExit:
            inv = None
    else:
        try:
            inv = load_verdict_inventory(repo, "HEAD")
        except SystemExit:
            inv = None

    closed_total = 0
    verdict_cited = 0
    process_closures = 0
    debt_beads = []
    for bid, row in sorted(beads.items()):
        if row.get("status") != "closed":
            continue
        closed_total += 1
        close_reason = row.get("close_reason", "") or ""
        desc = row.get("description", "") or ""
        try:
            kind, items = parse_acceptance_block(desc)
        except ValueError:
            kind, items = ("invalid", [])
        if kind == "none" or "[process-closure:" in close_reason:
            process_closures += 1
            continue
        has_citation = any(tok in close_reason for tok in ("[verdict_note:", "[manifest:", "note_id="))
        if has_citation:
            verdict_cited += 1
        if kind == "tests":
            if inv is None or any(not matches_inventory(t, inv["passed"]) or matches_inventory(t, inv["failed"]) for t in items):
                debt_beads.append(bid)
        elif not has_citation:
            debt_beads.append(bid)

    report = {
        "closed_total": closed_total,
        "verdict_cited_closures": verdict_cited,
        "process_closures": process_closures,
        "closure_debt_count": len(debt_beads),
        "closure_debt_beads": debt_beads,
    }
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"closed_total={closed_total}")
        print(f"verdict_cited_closures={verdict_cited}")
        print(f"process_closures={process_closures}")
        print(f"closure_debt_count={len(debt_beads)}")
    sys.exit(0)

if cmd == "regression-check":
    repo, days_str, verdict_spec, br_bin = sys.argv[2:6]
    days = int(days_str)
    beads = load_beads(repo)
    inv = load_verdict_inventory(repo, verdict_spec) if verdict_spec else load_verdict_inventory(repo, "HEAD")
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    regressions = []
    checked = 0
    for bid, row in sorted(beads.items()):
        if row.get("status") != "closed":
            continue
        closed_at_str = row.get("closed_at") or row.get("updated_at") or ""
        if closed_at_str:
            try:
                dt = datetime.datetime.fromisoformat(closed_at_str.replace("Z", "+00:00"))
                if dt < cutoff:
                    continue
            except Exception:
                pass
        desc = row.get("description", "") or ""
        try:
            kind, items = parse_acceptance_block(desc)
        except ValueError:
            continue
        if kind != "tests":
            continue
        checked += 1
        for t in items:
            if matches_inventory(t, inv["failed"]) or not matches_inventory(t, inv["passed"]):
                regressions.append((bid, t))
    if regressions:
        for bid, t in regressions:
            title = f"closure regression in {bid}: {t}"
            desc = f"Automated 30-day closure-regression check found acceptance test `{t}` for closed bead `{bid}` missing or failing in verdict {inv['note_id']} (commit {inv['commit']})."
            print(f"CLOSURE_REGRESSION bead={bid} test={t} verdict_note={inv['note_id']}")
            try:
                subprocess.run([br_bin, "create", "--title", title, "--priority", "0", "--type", "bug", "--description", desc],
                               check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        sys.exit(1)
    print(f"CLOSURE_REGRESSION_OK checked_beads={checked} days={days} verdict_note={inv['note_id']}")
    sys.exit(0)

if cmd == "verify-close":
    repo, bead_id, verdict_spec, landing_commit, no_tests_reason, require_block = sys.argv[2:8]
    inv = load_verdict_inventory(repo, verdict_spec, for_close=True)
    beads = load_beads(repo)
    row = beads.get(bead_id)

    kind = "missing"
    items = []
    if row is not None:
        try:
            kind, items = parse_acceptance_block(row.get("description", "") or "")
        except ValueError as err:
            die(f"bead {bead_id}: {err}")

    if no_tests_reason:
        if kind == "tests":
            die(f"bead {bead_id} declares acceptance-tests {items}; cannot override with --no-tests")
        kind = "none"
        items = [no_tests_reason]

    if kind == "missing" and require_block == "1":
        die(f"bead {bead_id} lacks an ```acceptance-tests``` fenced block (or --no-tests reason for pure doc/process beads)")

    if kind == "none":
        reason_text = items[0]
        # Verify landing_commit does not touch crates/ or scripts/
        changed = subprocess.check_output(
            ["git", "-C", repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", landing_commit],
            text=True
        ).splitlines()
        code_paths = [p for p in changed if p.startswith("crates/") or p.startswith("scripts/")]
        if code_paths:
            die(f"bead {bead_id} landing commit {landing_commit[:12]} touches code paths ({', '.join(code_paths[:3])}); `none:` / `--no-tests` is restricted to pure doc/process beads")
        print(f"CLOSE_BEAD_LOG bead={bead_id} landing={landing_commit} verdict_commit={inv['commit']} tree={inv['tree']} note_id={inv['note_id']} mode=process_closure reason={json.dumps(reason_text)} decision=ALLOW", file=sys.stderr)
        print(json.dumps({
            "decision": "ALLOW",
            "mode": "process",
            "process_reason": reason_text,
            "commit": inv["commit"],
            "tree": inv["tree"],
            "note_id": inv["note_id"],
        }))
        sys.exit(0)

    if kind == "tests":
        hits = []
        misses = []
        failed_hits = []
        for t in items:
            if matches_inventory(t, inv["failed"]):
                failed_hits.append(t)
            elif matches_inventory(t, inv["passed"]):
                hits.append(t)
            else:
                misses.append(t)
        decision = "ALLOW" if (not misses and not failed_hits) else "REFUSE"
        print(
            f"CLOSE_BEAD_LOG bead={bead_id} landing={landing_commit} verdict_commit={inv['commit']} tree={inv['tree']} note_id={inv['note_id']} "
            f"parsed_tests={json.dumps(items)} hits={json.dumps(hits)} misses={json.dumps(misses)} failed={json.dumps(failed_hits)} decision={decision}",
            file=sys.stderr
        )
        if failed_hits:
            die(f"acceptance test(s) FAILED in verdict {inv['note_id'][:12]}: {', '.join(failed_hits)}")
        if misses:
            die(f"acceptance test(s) missing from verdict {inv['note_id'][:12]} inventory: {', '.join(misses)}")

    print(json.dumps({
        "decision": "ALLOW",
        "mode": "tests" if kind == "tests" else "legacy-manifest",
        "tests": items,
        "commit": inv["commit"],
        "tree": inv["tree"],
        "note_id": inv["note_id"],
    }))
    sys.exit(0)
PY
}

if [ "$mode" = "parse-block" ]; then
  run_py_helper parse-block "$repo_dir" "$parse_target"
  exit 0
fi

if [ "$mode" = "closure-debt" ]; then
  run_py_helper closure-debt "$repo_dir" "${verdict_arg:-$manifest_arg}" "$json_out"
  exit 0
fi

if [ "$mode" = "regression-check" ]; then
  run_py_helper regression-check "$repo_dir" "$days" "${verdict_arg:-$manifest_arg}" "${FA_BR_BIN:-br}"
  exit 0
fi

[ -n "$bead_id" ] || fail "missing <bead-id>"
[ -n "$verdict_arg" ] || [ -n "$manifest_arg" ] || fail "missing --verdict or --manifest (cannot close $bead_id without citing a verdict)"
[ -n "$reason" ] || fail "missing --reason"

spec="${verdict_arg:-$manifest_arg}"
require_block=1

# 1. Verify retained evidence; this does not authenticate the producer's identity.
if [ -d "$spec" ] || [ -f "$spec" ]; then
  if [ -d "$spec" ]; then
    proof_dir="$spec"
    manifest_file="$proof_dir/manifest.txt"
  else
    manifest_file="$spec"
    proof_dir="$(dirname "$spec")"
  fi
  [ -f "$manifest_file" ] || fail "manifest file not found: $manifest_file"
  bash "$root/scripts/local_proof_verify.sh" --repository "$repo_dir" --for-close "$proof_dir" >/dev/null \
    || fail "proof bundle at $proof_dir failed local_proof_verify.sh against $repo_dir"
  verdict="$(awk -F= '$1 == "verdict" { print $2 }' "$manifest_file")"
  stable="$(awk -F= '$1 == "tree_stable" { print $2 }' "$manifest_file")"
  manifest_commit="$(awk -F= '$1 == "commit" { print $2 }' "$manifest_file")"
  manifest_tree="$(awk -F= '$1 == "tree" { print $2 }' "$manifest_file")"
  verify_spec="$proof_dir"
else
  # Resolve note id or commit in repo_dir and verify with local_proof_verify.sh --note
  resolved_commit="$(python3 -B - "$repo_dir" "$spec" <<'PY'
import subprocess, sys
repo, target = sys.argv[1:3]
try:
    listing = subprocess.check_output(["git", "-C", repo, "notes", "--ref=fa-verdict", "list"], text=True, stderr=subprocess.DEVNULL).splitlines()
    for line in listing:
        parts = line.split()
        if len(parts) == 2 and (parts[0].startswith(target) or parts[1].startswith(target)):
            print(parts[1])
            sys.exit(0)
except Exception:
    pass
try:
    c = subprocess.check_output(["git", "-C", repo, "rev-parse", "--verify", f"{target}^{{commit}}"], text=True, stderr=subprocess.DEVNULL).strip()
    print(c)
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
)" || fail "cannot resolve --verdict $spec in $repo_dir"
  verify_out="$(bash "$root/scripts/local_proof_verify.sh" --repository "$repo_dir" --for-close --note "$resolved_commit")" \
    || fail "verdict note for $spec ($resolved_commit) failed local_proof_verify.sh against $repo_dir"
  verdict="$(awk -F= '$1 == "verdict" { print $2 }' <<< "$verify_out")"
  stable="$(awk -F= '$1 == "tree_stable" { print $2 }' <<< "$verify_out")"
  manifest_commit="$(awk -F= '$1 == "commit" { print $2 }' <<< "$verify_out")"
  manifest_tree="$(awk -F= '$1 == "tree" { print $2 }' <<< "$verify_out")"
  verify_spec="$spec"
fi

[ "$verdict" = "pass" ] || fail "verdict is '$verdict', expected 'pass'"
[ "$stable" = "true" ] || fail "tree_stable is '$stable', expected 'true'"

# 2. Resolve and verify landing commit ancestry in the verdict's commit
if [ -z "$landing_commit" ]; then
  landing_commit="$(git -C "$repo_dir" log -n 1 --format='%H' --grep="$bead_id" "$manifest_commit" 2>/dev/null || true)"
  [ -n "$landing_commit" ] || fail "no commit mentioning $bead_id is reachable from verdict commit $manifest_commit (supply --commit explicitly if commit message does not mention $bead_id)"
else
  landing_commit="$(git -C "$repo_dir" rev-parse --verify "${landing_commit}^{commit}" 2>/dev/null)" \
    || fail "landing commit $landing_commit does not exist in $repo_dir"
fi

if ! git -C "$repo_dir" merge-base --is-ancestor "$landing_commit" "$manifest_commit" 2>/dev/null; then
  fail "verdict commit ${manifest_commit:0:12} (tree ${manifest_tree:0:12}) does not contain landing commit ${landing_commit:0:12} for $bead_id"
fi

actual_manifest_tree="$(git -C "$repo_dir" rev-parse "${manifest_commit}^{tree}")"
[ "$actual_manifest_tree" = "$manifest_tree" ] \
  || fail "verdict tree $manifest_tree does not match commit tree $actual_manifest_tree"

# 3. Verify acceptance-tests block against the verdict's test inventory
decision_json="$(run_py_helper verify-close "$repo_dir" "$bead_id" "$verify_spec" "$landing_commit" "$no_tests_reason" "$require_block")" \
  || exit $?

note_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["note_id"])' "$decision_json")"
close_mode="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["mode"])' "$decision_json")"

if [ "$close_mode" = "process" ]; then
  proc_reason="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["process_reason"])' "$decision_json")"
  cited_reason="${reason} [process-closure: ${proc_reason}] [verdict_note: ${note_id:0:12} commit=${manifest_commit:0:12} tree=${manifest_tree:0:12}]"
else
  cited_reason="${reason} [verdict_note: ${note_id:0:12} commit=${manifest_commit:0:12} tree=${manifest_tree:0:12}]"
fi

if [ "${FA_CLOSE_BEAD_DRY_RUN:-0}" = "1" ]; then
  printf 'CLOSE_BEAD_VERIFIED bead=%s note_id=%s commit=%s tree=%s landing=%s\n' \
    "$bead_id" "$note_id" "$manifest_commit" "$manifest_tree" "$landing_commit"
  exit 0
fi

"${FA_BR_BIN:-br}" close "$bead_id" --reason "$cited_reason"
printf 'CLOSE_BEAD_OK bead=%s note_id=%s commit=%s tree=%s landing=%s\n' \
  "$bead_id" "$note_id" "$manifest_commit" "$manifest_tree" "$landing_commit"
