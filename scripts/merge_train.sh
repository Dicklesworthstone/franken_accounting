#!/usr/bin/env bash
# =============================================================================
# merge_train.sh — the verified landing queue from `staging` / `refs/heads/train/*`
# to `main` (beads fa-u7u, fa-aj8, fa-7dx, fa-cat, fa-1qk0)
# =============================================================================
# Supports:
#   - `run`: single staging branch promotion (substrate-compatible) or `--batch`
#            queue processing over `refs/heads/train/<bead>-<agent>`.
#   - `run-batch`: batched queue gating with binary-search bisection on RED,
#                  UNRUN non-ejection, claim-before-code enforcement (fa-7dx),
#                  and a replayable batch-size decision card with pinned fallback N=1 (fa-cat).
#   - `fold`: folds queued `refs/heads/train/*` (or explicit train refs) onto `main`
#             gated by `scripts/tier0.sh` (fmt + `cargo check --workspace --all-targets`),
#             refusing to update `main` on anything but PASS; UNRUN means "do not fold yet"
#             and never ejects a candidate (fa-1qk0).
#   - `dry-run`: prints canonical warm gate path, designated workers, and warmth (fa-aj8).
#   - `audit`: audits first-parent commits on `main` since `--since REV`.
# =============================================================================

set -uo pipefail

EX_NOTHING=0
EX_RED=1
EX_USAGE=2
EX_CONFLICT=3
EX_STALE=4
EX_UNVERIFIABLE=5
EX_CLAIM=6
EX_UNRUN=7
EX_VOID=125
NOTES_REF=merge-train
TIER0_NOTES_REF=fa-tier0

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/merge_train.sh run       [--remote NAME|URL] [--main BRANCH] [--staging BRANCH]
                                        [--work DIR] [--canonical-worktree DIR] [--no-push]
                                        [--dry-run] [--check-claims] [--batch] [--tier0-only]
  bash scripts/merge_train.sh run-batch [--remote NAME|URL] [--main BRANCH] [--work DIR]
                                        [--canonical-worktree DIR] [--max-batch N]
                                        [--check-claims] [--no-push] [--tier0-only]
  bash scripts/merge_train.sh fold      [--remote NAME|URL] [--main BRANCH] [--work DIR]
                                        [--canonical-worktree DIR] [--max-batch N]
                                        [--check-claims] [--no-push] [REF...]
  bash scripts/merge_train.sh dry-run   [--canonical-worktree DIR]
  bash scripts/merge_train.sh audit     --since REV [--remote NAME|URL] [--main BRANCH]
                                        [--work DIR] [--author-pattern ERE] [--strict]
USAGE
}

die() {
  printf 'merge-train: %s\n' "$*" >&2
  exit "$EX_USAGE"
}

say() {
  printf 'merge-train: %s\n' "$*"
}

[ "$#" -ge 1 ] || { usage >&2; exit "$EX_USAGE"; }
command="$1"
shift
case "$command" in
  run|run-batch|fold|audit|dry-run) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit "$EX_USAGE" ;;
esac

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)"
if [ -f "$root/scripts/gate_workers.conf" ]; then
  # shellcheck source=gate_workers.conf
  . "$root/scripts/gate_workers.conf"
fi

remote="origin"
main_branch="main"
staging_branch="staging"
work="${TMPDIR:-/tmp}/fa-merge-train"
canonical_worktree=""
push=1
dry_run=0
check_claims="${FA_MERGE_TRAIN_CHECK_CLAIMS:-0}"
batch_mode=0
tier0_only=0
max_batch=8
declare -a explicit_refs=()
if [ "$command" = "dry-run" ]; then
  dry_run=1
elif [ "$command" = "run-batch" ]; then
  batch_mode=1
elif [ "$command" = "fold" ]; then
  batch_mode=1
  tier0_only=1
fi
since=""
author_pattern='users\.noreply\.github\.com'
strict=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --remote) [ "$#" -ge 2 ] || die "--remote needs a value"; remote="$2"; shift 2 ;;
    --main) [ "$#" -ge 2 ] || die "--main needs a value"; main_branch="$2"; shift 2 ;;
    --staging) [ "$#" -ge 2 ] || die "--staging needs a value"; staging_branch="$2"; shift 2 ;;
    --work) [ "$#" -ge 2 ] || die "--work needs a value"; work="$2"; shift 2 ;;
    --canonical-worktree) [ "$#" -ge 2 ] || die "--canonical-worktree needs a value"; canonical_worktree="$2"; shift 2 ;;
    --max-batch) [ "$#" -ge 2 ] || die "--max-batch needs a value"; max_batch="$2"; shift 2 ;;
    --no-push) push=0; shift ;;
    --dry-run) dry_run=1; shift ;;
    --check-claims) check_claims=1; shift ;;
    --batch) batch_mode=1; shift ;;
    --tier0-only) tier0_only=1; shift ;;
    --since) [ "$#" -ge 2 ] || die "--since needs a value"; since="$2"; shift 2 ;;
    --author-pattern) [ "$#" -ge 2 ] || die "--author-pattern needs a value"; author_pattern="$2"; shift 2 ;;
    --strict) strict=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*)
      die "unknown argument: $1"
      ;;
    *)
      if [ "$command" = "fold" ]; then
        explicit_refs+=("$1")
        shift
      else
        die "unknown argument: $1"
      fi
      ;;
  esac
done

effective_gate_worktree="${canonical_worktree:-${FA_GATE_WORKTREE:-/data/projects/franken_accounting-gate}}"
expected_warmth="false"
if [ -d "$effective_gate_worktree/.git" ] || [ -f "$effective_gate_worktree/.git" ]; then
  expected_warmth="true"
fi

if [ "$dry_run" -eq 1 ]; then
  say "DRY-RUN canonical warm gate configuration (fa-aj8)"
  printf 'gate_worktree=%s\n' "$effective_gate_worktree"
  printf 'designated_workers=%s\n' "${FA_GATE_WORKERS:-hz2,vmi1152480}"
  printf 'primary_worker=%s\n' "${FA_GATE_PRIMARY_WORKER:-hz2}"
  printf 'fallback_worker=%s\n' "${FA_GATE_FALLBACK_WORKER:-vmi1152480}"
  printf 'expected_warmth=%s\n' "$expected_warmth"
  exit 0
fi

command -v git >/dev/null 2>&1 || die "git is required"
root="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run from inside the repository"
if remote_url="$(git -C "$root" remote get-url "$remote" 2>/dev/null)"; then
  :
else
  remote_url="$remote"
fi
case "$work" in /*) ;; *) work="$PWD/$work" ;; esac
case "$work" in "$root"|"$root"/*) die "--work must be outside the repository worktree" ;; esac
mkdir -p "$work/candidates" "$work/proofs" "$work/cards" || die "cannot create $work"

train_name="$(git -C "$root" config user.name 2>/dev/null || true)"
train_email="$(git -C "$root" config user.email 2>/dev/null || true)"
[ -n "$train_name" ] || train_name="fa merge-train"
[ -n "$train_email" ] || train_email="merge-train@localhost"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mirror="$work/mirror.git"

refresh_mirror() {
  if [ ! -d "$mirror" ]; then
    git clone --quiet --bare --reference-if-able "$root" --dissociate "$remote_url" "$mirror" \
      || die "cannot create mirror of $remote_url"
  fi
  git -C "$mirror" fetch --quiet --prune "$remote_url" \
    "+refs/heads/*:refs/heads/*" \
    "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" \
    "+refs/notes/$TIER0_NOTES_REF:refs/notes/$TIER0_NOTES_REF" 2>/dev/null \
    || git -C "$mirror" fetch --quiet --prune "$remote_url" \
      "+refs/heads/*:refs/heads/*" "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" 2>/dev/null \
    || git -C "$mirror" fetch --quiet --prune "$remote_url" "+refs/heads/*:refs/heads/*" \
    || die "cannot fetch $remote_url"
}

gitc() {
  git -c user.name="$train_name" -c user.email="$train_email" "$@"
}

publish_note() {
  local clone="$1" object="$2" body="$3" attempt
  gitc -C "$clone" notes --ref="$NOTES_REF" append -m "$body" "$object" \
    || { say "WARNING: could not write the note locally"; return 1; }
  [ "$push" -eq 1 ] || { say "--no-push: note written locally only"; return 0; }
  for attempt in 1 2 3; do
    if git -C "$clone" push --quiet "$remote_url" \
        "refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" 2>/dev/null; then
      return 0
    fi
    git -C "$clone" fetch --quiet "$remote_url" \
      "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF-remote" 2>/dev/null || true
    gitc -C "$clone" notes --ref="$NOTES_REF" merge -q -s cat_sort_uniq \
      "$NOTES_REF-remote" 2>/dev/null || true
    say "note push rejected (attempt $attempt); merged remote notes and retrying"
  done
  say "WARNING: could not publish the note after 3 attempts"
  return 1
}

publish_tier0_note() {
  local clone="$1" object="$2" tree_sha="$3" attempt existing
  existing="$(git -C "$clone" notes --ref="$TIER0_NOTES_REF" show "$object" 2>/dev/null || true)"
  if [ -z "$existing" ]; then
    gitc -C "$clone" notes --ref="$TIER0_NOTES_REF" add -f -m "$(printf 'tier0 v1\nverdict=pass\ncommit=%s\ntree=%s\nhost=%s\nrecorded_utc=%s\n' \
      "$object" "$tree_sha" "$(hostname 2>/dev/null || echo unknown)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$object" >/dev/null 2>&1 || true
  fi
  [ "$push" -eq 1 ] || return 0
  for attempt in 1 2 3; do
    if git -C "$clone" push --quiet "$remote_url" \
        "refs/notes/$TIER0_NOTES_REF:refs/notes/$TIER0_NOTES_REF" 2>/dev/null; then
      return 0
    fi
    git -C "$clone" fetch --quiet "$remote_url" \
      "+refs/notes/$TIER0_NOTES_REF:refs/notes/$TIER0_NOTES_REF-remote" 2>/dev/null || true
    gitc -C "$clone" notes --ref="$TIER0_NOTES_REF" merge -q -s cat_sort_uniq \
      "$TIER0_NOTES_REF-remote" 2>/dev/null || true
  done
  return 0
}

note_body() {
  local verdict="$1"
  shift
  printf 'merge-train v1\nverdict=%s\nrecorded_utc=%s\nhost=%s\n' \
    "$verdict" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname 2>/dev/null || echo unknown)"
  local kv
  for kv in "$@"; do printf '%s\n' "$kv"; done
}

# verify_candidate_claims <repo> <base_sha> <cand_sha> [expected_agent]
# Refuses if any commit in base_sha..cand_sha mentions a bead ID whose assignee
# in .beads/issues.jsonl is someone other than the commit author or expected_agent (fa-7dx).
verify_candidate_claims() {
  local repo="$1" base_sha="$2" cand_sha="$3" expected_agent="${4:-}"
  [ "$check_claims" -eq 1 ] || return 0
  local jsonl_blob
  jsonl_blob="$(git -C "$repo" show "${base_sha}:.beads/issues.jsonl" 2>/dev/null || true)"
  [ -n "$jsonl_blob" ] || return 0

  python3 - "$jsonl_blob" "$repo" "$base_sha" "$cand_sha" "$expected_agent" <<'PY'
import json
import re
import subprocess
import sys

jsonl_text, repo, base_sha, cand_sha, expected_agent = sys.argv[1:6]
assignees = {}
for line in jsonl_text.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except Exception:
        continue
    bid = row.get("id")
    assignee = row.get("assignee")
    if bid and assignee:
        assignees[bid] = assignee

log_out = subprocess.check_output(
    ["git", "-C", repo, "log", "--format=%H%x09%an%x09%s %b", f"{base_sha}..{cand_sha}"],
    text=True,
)
for entry in log_out.splitlines():
    parts = entry.split("\t", 2)
    if len(parts) < 3:
        continue
    commit_sha, author_name, msg = parts
    actor = expected_agent or author_name
    for bead_id in re.findall(r"\bfa-[a-z0-9]+\b", msg):
        owner = assignees.get(bead_id)
        if owner and owner != actor and owner != author_name:
            print(f"CLAIM-CONFLICT: commit {commit_sha[:12]} names {bead_id} assigned to {owner}, not {actor}")
            sys.exit(1)
sys.exit(0)
PY
}

# emit_batch_decision_card <queue_len> <card_file>
# Computes optimal batch size N minimizing expected gate cost per landed candidate
# C(N) = G * [1 + (1 - (1-p)^N) * ceil(log2 N)] / (N * (1-p))
# with pinned fallback N=1 when posterior is wide or FA_TRAIN_PINNED_FALLBACK=1 (fa-cat).
emit_batch_decision_card() {
  local queue_len="$1" card_file="$2" max_n="$3"
  python3 - "$queue_len" "$card_file" "$max_n" "${FA_TRAIN_PINNED_FALLBACK:-0}" <<'PY'
import json
import math
import sys

queue_len = int(sys.argv[1])
card_file = sys.argv[2]
max_n = int(sys.argv[3])
force_fallback = int(sys.argv[4]) == 1

# Beta(alpha=1, beta=19) prior (~5% failure rate)
alpha, beta = 1.0, 19.0
p = alpha / (alpha + beta)
g_minutes = 15.0

candidates = []
limit = max(1, min(queue_len, max_n))
best_n = 1
best_cost = None

for n in range(1, limit + 1):
    ceil_log2 = 0 if n <= 1 else int(math.ceil(math.log2(n)))
    prob_all_green = (1.0 - p) ** n
    expected_gates = 1.0 + (1.0 - prob_all_green) * ceil_log2
    expected_landed = max(0.01, n * (1.0 - p))
    cost_per_landed = g_minutes * expected_gates / expected_landed
    candidates.append({
        "batch_size": n,
        "expected_gates": round(expected_gates, 4),
        "cost_minutes_per_landed": round(cost_per_landed, 4),
    })
    if best_cost is None or cost_per_landed < best_cost:
        best_cost = cost_per_landed
        best_n = n

chosen = 1 if force_fallback else best_n
c1 = candidates[0]["cost_minutes_per_landed"]
cn = candidates[chosen - 1]["cost_minutes_per_landed"]

card = {
    "schema": "fa:decision-card:merge-train-batch:v1",
    "policy_epoch": 1,
    "state_space": {
        "queue_length": queue_len,
        "beta_alpha": alpha,
        "beta_beta": beta,
        "p_fail_posterior_mean": round(p, 4),
    },
    "candidate_actions": candidates,
    "chosen_action": {"batch_size": chosen},
    "expected_benefit_minutes_per_candidate": round(c1 - cn, 4),
    "pinned_fallback": {"batch_size": 1},
    "fallback_active": force_fallback,
}
with open(card_file, "w", encoding="utf-8") as f:
    json.dump(card, f, indent=2, sort_keys=True)
print(chosen)
PY
}

# tier0_in_cand <cand_dir> <label_tag> -> sets TIER0_LAST_VERDICT (PASS|RED|UNRUN), TIER0_LAST_FAIL_LINE
TIER0_LAST_VERDICT=""
TIER0_LAST_FAIL_LINE=""
TIER0_COUNT=0

tier0_in_cand() {
  local cand="$1" tag="$2"
  TIER0_COUNT=$((TIER0_COUNT + 1))
  local cand_sha
  cand_sha="$(git -C "$cand" rev-parse HEAD)"
  local t0_dir="$work/proofs/$stamp-tier0-${tag}-${TIER0_COUNT}-${cand_sha:0:12}"
  local t0_log="$t0_dir.stdout.log"
  local t0_err="$t0_dir.stderr.log"
  mkdir -p "$t0_dir"
  : "${CARGO_TARGET_DIR:=$work/target}"
  : "${RCH_WORKER:=${FA_GATE_PRIMARY_WORKER:-hz2}}"
  export CARGO_TARGET_DIR RCH_WORKER

  local t0_rc=0
  (cd "$cand" && bash scripts/tier0.sh --publish-note --log-dir "$t0_dir") >"$t0_log" 2>"$t0_err" || t0_rc=$?
  TIER0_LAST_FAIL_LINE=""

  if [ "$t0_rc" -eq 0 ] \
    && grep -Eq '^PASS fmt([[:space:]]|$)' "$t0_log" \
    && grep -Eq '^PASS check([[:space:]]|$)' "$t0_log" \
    && ! grep -Eq '^(FAIL|UNRUN|RED)([[:space:]]|$)' "$t0_log"; then
    TIER0_LAST_VERDICT="PASS"
    say "TIER0 PASS on ${cand_sha:0:12} ($tag); transcript: $t0_log"
    return 0
  fi

  if [ "$t0_rc" -eq 2 ] \
    && grep -Eq '^UNRUN([[:space:]]|$)' "$t0_log" \
    && ! grep -Eq '^RED([[:space:]]|$)|: [0-9]+ passed, [1-9][0-9]* failed,' "$t0_log"; then
    TIER0_LAST_VERDICT="UNRUN"
    say "TIER0 UNRUN on ${cand_sha:0:12} ($tag): do not fold yet; transcript: $t0_log"
    return 2
  fi

  TIER0_LAST_VERDICT="RED"
  TIER0_LAST_FAIL_LINE="$(grep -a '^FAIL ' "$t0_log" 2>/dev/null | head -n 1 || true)"
  say "TIER0 RED on ${cand_sha:0:12} ($tag): ${TIER0_LAST_FAIL_LINE:-tier0 failed}; transcript: $t0_log"
  return 1
}

# gate_tree_in_cand <cand_dir> <label_tag> -> sets GATE_LAST_VERDICT (PASS|RED|UNRUN|VOID), GATE_LAST_FAIL_LINE
GATE_LAST_VERDICT=""
GATE_LAST_FAIL_LINE=""
GATE_COUNT=0

gate_tree_in_cand() {
  local cand="$1" tag="$2"
  GATE_COUNT=$((GATE_COUNT + 1))
  GATE_LAST_FAIL_LINE=""

  if [ -f "$cand/scripts/tier0.sh" ]; then
    tier0_in_cand "$cand" "$tag"
    if [ "$TIER0_LAST_VERDICT" = "UNRUN" ]; then
      GATE_LAST_VERDICT="UNRUN"
      return 2
    fi
    if [ "$TIER0_LAST_VERDICT" != "PASS" ]; then
      GATE_LAST_VERDICT="RED"
      GATE_LAST_FAIL_LINE="$TIER0_LAST_FAIL_LINE"
      return 1
    fi
    if [ "$tier0_only" -eq 1 ] || [ ! -f "$cand/scripts/local_proof.sh" ]; then
      GATE_LAST_VERDICT="PASS"
      return 0
    fi
  elif [ "$tier0_only" -eq 1 ]; then
    GATE_LAST_VERDICT="RED"
    GATE_LAST_FAIL_LINE="FAIL tier0: scripts/tier0.sh missing in candidate tree"
    return 1
  fi

  local cand_sha
  cand_sha="$(git -C "$cand" rev-parse HEAD)"
  local proof="$work/proofs/$stamp-${tag}-${GATE_COUNT}-${cand_sha:0:12}"
  local log="$work/proofs/$stamp-${tag}-${GATE_COUNT}-${cand_sha:0:12}.train.log"
  : "${RCH_CARGO_WRAPPER_BYPASS:=1}"
  : "${CARGO_TARGET_DIR:=$work/target}"
  : "${RCH_WORKER:=${FA_GATE_PRIMARY_WORKER:-hz2}}"
  export RCH_CARGO_WRAPPER_BYPASS CARGO_TARGET_DIR RCH_WORKER

  local proof_rc=0
  (cd "$cand" && bash scripts/local_proof.sh --output "$proof") > "$log" 2>&1 || proof_rc=$?
  GATE_LAST_FAIL_LINE=""

  if [ ! -f "$proof/manifest.txt" ]; then
    GATE_LAST_VERDICT="VOID"
    return 1
  fi
  local verdict
  verdict="$(sed -n 's/^verdict=//p' "$proof/manifest.txt")"
  if [ "$verdict" = "pass" ] && [ "$proof_rc" -eq 0 ]; then
    GATE_LAST_VERDICT="PASS"
    return 0
  fi
  if [ "$verdict" = "void" ]; then
    GATE_LAST_VERDICT="VOID"
    return 1
  fi
  # Distinguish infrastructure UNRUN (no RED line and no non-UNRUN FAIL line) from product RED
  if grep -Eq '^UNRUN([[:space:]]|$)' "$proof/check.stdout.log" 2>/dev/null \
    && ! grep -Eq '^RED([[:space:]]|$)|: [0-9]+ passed, [1-9][0-9]* failed,' "$proof/check.stdout.log" 2>/dev/null; then
    GATE_LAST_VERDICT="UNRUN"
    return 2
  fi
  GATE_LAST_VERDICT="RED"
  GATE_LAST_FAIL_LINE="$(grep -a '^FAIL ' "$proof/check.stdout.log" 2>/dev/null | head -n 1 || true)"
  return 1
}

run_batch_train() {
  refresh_mirror
  local main_sha
  main_sha="$(git -C "$mirror" rev-parse --verify --quiet "refs/heads/$main_branch^{commit}")" \
    || die "remote has no $main_branch branch"

  local -a raw_refs=()
  if [ "${#explicit_refs[@]}" -gt 0 ]; then
    local raw_arg norm_ref
    for raw_arg in "${explicit_refs[@]}"; do
      case "$raw_arg" in
        refs/heads/*) norm_ref="$raw_arg" ;;
        origin/*) norm_ref="refs/heads/${raw_arg#origin/}" ;;
        *) norm_ref="refs/heads/$raw_arg" ;;
      esac
      git -C "$mirror" rev-parse --verify --quiet "${norm_ref}^{commit}" >/dev/null \
        || die "remote has no branch $norm_ref"
      raw_refs+=("$norm_ref")
    done
  else
    while IFS= read -r ref; do
      [ -n "$ref" ] && raw_refs+=("$ref")
    done < <(git -C "$mirror" for-each-ref --format='%(refname)' 'refs/heads/train/' | LC_ALL=C sort)
  fi

  if [ "${#raw_refs[@]}" -eq 0 ]; then
    say "NOTHING: no queued refs under refs/heads/train/*"
    return "$EX_NOTHING"
  fi

  local cand
  if [ -n "$canonical_worktree" ]; then
    cand="$canonical_worktree"
    if [ ! -d "$cand/.git" ] && [ ! -f "$cand/.git" ]; then
      git clone --quiet --local "$mirror" "$cand" || die "cannot initialize canonical gate worktree $cand"
    else
      git -C "$cand" fetch --quiet "$mirror" "+refs/heads/*:refs/remotes/origin/*" || die "cannot fetch mirror into $cand"
    fi
  else
    cand="$work/candidates/$stamp-batch-$$"
    git clone --quiet --local "$mirror" "$cand" || die "cannot clone candidate"
  fi
  git -C "$cand" fetch --quiet "$remote_url" \
    "+refs/heads/*:refs/remotes/origin/*" \
    "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" \
    "+refs/notes/$TIER0_NOTES_REF:refs/notes/$TIER0_NOTES_REF" 2>/dev/null || true

  # Filter eligible candidates (not already ancestor of main, and passing claim-before-code)
  local -a active_refs=()
  local -a active_shas=()
  local ref sha short_name expected_agent claim_err
  for ref in "${raw_refs[@]}"; do
    sha="$(git -C "$mirror" rev-parse --verify "$ref^{commit}")"
    if git -C "$mirror" merge-base --is-ancestor "$sha" "$main_sha"; then
      continue
    fi
    short_name="${ref#refs/heads/train/}"
    expected_agent="${short_name##*-}"
    if ! claim_err="$(verify_candidate_claims "$mirror" "$main_sha" "$sha" "$expected_agent" 2>&1)"; then
      say "EJECTED $ref ($claim_err)"
      publish_note "$cand" "$sha" "$(note_body claim-conflict "main=$main_sha" "ref=$ref" "fail: $claim_err")"
      continue
    fi
    active_refs+=("$ref")
    active_shas+=("$sha")
  done

  if [ "${#active_refs[@]}" -eq 0 ]; then
    say "NOTHING: all queued candidates were already landed or rejected by claim check"
    return "$EX_CLAIM"
  fi

  local card_file="$work/cards/decision-card-$stamp.json"
  local chosen_n
  chosen_n="$(emit_batch_decision_card "${#active_refs[@]}" "$card_file" "$max_batch")"
  say "DECISION-CARD: queue=${#active_refs[@]} chosen_batch_size=$chosen_n card=$card_file"

  # Slice active_refs to chosen_n (or full queue if max_batch >= queue)
  local -a batch_refs=("${active_refs[@]:0:$chosen_n}")
  local -a batch_shas=("${active_shas[@]:0:$chosen_n}")

  while [ "${#batch_refs[@]}" -gt 0 ]; do
    git -C "$cand" checkout --quiet --detach "$main_sha" || die "cannot checkout $main_sha"
    local -a stacked_refs=()
    local -a stacked_shas=()
    local -a stacked_merges=()
    local idx
    for idx in "${!batch_refs[@]}"; do
      ref="${batch_refs[$idx]}"
      sha="${batch_shas[$idx]}"
      if ! gitc -C "$cand" merge --quiet --no-ff --no-edit \
          -m "merge-train: stack $ref (${sha:0:12})" "$sha" >/dev/null 2>&1; then
        git -C "$cand" merge --abort >/dev/null 2>&1 || true
        say "EJECTED $ref (merge conflict)"
        publish_note "$cand" "$sha" "$(note_body conflict "main=$main_sha" "ref=$ref")"
        continue
      fi
      stacked_refs+=("$ref")
      stacked_shas+=("$sha")
      stacked_merges+=("$(git -C "$cand" rev-parse HEAD)")
    done

    if [ "${#stacked_refs[@]}" -eq 0 ]; then
      say "RED: all candidates in batch failed to stack"
      return "$EX_CONFLICT"
    fi

    local count="${#stacked_refs[@]}"
    say "GATING stack of $count candidate(s): ${stacked_refs[*]}"
    gate_tree_in_cand "$cand" "stack"
    if [ "$GATE_LAST_VERDICT" = "UNRUN" ]; then
      say "UNRUN: infrastructure offloader did not run stack; retrying once without ejecting any candidate"
      gate_tree_in_cand "$cand" "stack-retry"
      if [ "$GATE_LAST_VERDICT" = "UNRUN" ]; then
        say "UNRUN: stack remained UNRUN; do not fold yet; no candidate ejected"
        return "$EX_UNRUN"
      fi
    fi

    if [ "$GATE_LAST_VERDICT" = "PASS" ]; then
      local tip_sha="${stacked_merges[$((count - 1))]}"
      local tip_tree
      tip_tree="$(git -C "$cand" rev-parse "${tip_sha}^{tree}")"
      publish_tier0_note "$cand" "$tip_sha" "$tip_tree"
      if [ "$push" -eq 1 ]; then
        git -C "$cand" push --quiet "$remote_url" "$tip_sha:refs/heads/$main_branch" \
          || { say "STALE: $main_branch moved during batch proof"; return "$EX_STALE"; }
        if git -C "$mirror" rev-parse --verify --quiet "refs/heads/$staging_branch^{commit}" >/dev/null; then
          git -C "$cand" push --quiet "$remote_url" "$tip_sha:refs/heads/$staging_branch" 2>/dev/null || true
        fi
      fi
      for idx in "${!stacked_refs[@]}"; do
        ref="${stacked_refs[$idx]}"
        sha="${stacked_shas[$idx]}"
        publish_note "$cand" "$sha" "$(note_body pass "main=$main_sha" "ref=$ref" "batch_tip=$tip_sha" "tree=$tip_tree")"
      done
      publish_note "$cand" "$tip_sha" "$(note_body pass "main=$main_sha" "batch_size=$count" "tree=$tip_tree")"
      say "PROMOTED-BATCH: $count candidate(s) (${stacked_refs[*]}) -> $main_branch ${tip_sha:0:12} (gates=$GATE_COUNT)"
      return "$EX_NOTHING"
    fi

    # Binary search bisection over stacked_merges[0..count-1] to find the first failing candidate
    local lo=0
    local hi=$((count - 1))
    local bad_fail_line="$GATE_LAST_FAIL_LINE"
    while [ "$lo" -lt "$hi" ]; do
      local mid=$(( (lo + hi) / 2 ))
      local mid_merge="${stacked_merges[$mid]}"
      git -C "$cand" checkout --quiet --detach "$mid_merge"
      say "BISECT testing prefix 0..$mid (${stacked_refs[$mid]})"
      gate_tree_in_cand "$cand" "bisect-$mid"
      if [ "$GATE_LAST_VERDICT" = "UNRUN" ]; then
        say "UNRUN during bisection; do not fold yet; no candidate ejected"
        return "$EX_UNRUN"
      fi
      if [ "$GATE_LAST_VERDICT" = "PASS" ]; then
        lo=$((mid + 1))
      else
        hi="$mid"
        [ -n "$GATE_LAST_FAIL_LINE" ] && bad_fail_line="$GATE_LAST_FAIL_LINE"
      fi
    done

    local bad_ref="${stacked_refs[$lo]}"
    local bad_sha="${stacked_shas[$lo]}"
    say "EJECTED $bad_ref (${bad_sha:0:12}) after bisection: ${bad_fail_line:-gate failed}"
    publish_note "$cand" "$bad_sha" "$(note_body red "main=$main_sha" "ref=$bad_ref" "fail: ${bad_fail_line:-gate failed}")"

    # Rebuild batch_refs and batch_shas without bad_ref and loop to gate the healthy remainder
    local -a next_refs=()
    local -a next_shas=()
    for idx in "${!stacked_refs[@]}"; do
      if [ "$idx" -ne "$lo" ]; then
        next_refs+=("${stacked_refs[$idx]}")
        next_shas+=("${stacked_shas[$idx]}")
      fi
    done
    batch_refs=("${next_refs[@]}")
    batch_shas=("${next_shas[@]}")
  done

  say "RED: all candidates in batch were ejected"
  return "$EX_RED"
}

run_train() {
  refresh_mirror
  if [ "$batch_mode" -eq 1 ]; then
    run_batch_train
    return $?
  fi
  local main_sha staging_sha
  main_sha="$(git -C "$mirror" rev-parse --verify --quiet "refs/heads/$main_branch^{commit}")" \
    || die "remote has no $main_branch branch"
  if ! staging_sha="$(git -C "$mirror" rev-parse --verify --quiet "refs/heads/$staging_branch^{commit}")"; then
    say "NOTHING: remote has no $staging_branch branch"
    return "$EX_NOTHING"
  fi
  if git -C "$mirror" merge-base --is-ancestor "$staging_sha" "$main_sha"; then
    say "NOTHING: $staging_branch ${staging_sha:0:12} is already contained in $main_branch ${main_sha:0:12}"
    return "$EX_NOTHING"
  fi

  local claim_err
  if ! claim_err="$(verify_candidate_claims "$mirror" "$main_sha" "$staging_sha" "" 2>&1)"; then
    say "CLAIM-CONFLICT: $claim_err"
    return "$EX_CLAIM"
  fi

  local prior
  prior="$(git -C "$mirror" notes --ref="$NOTES_REF" show "$staging_sha" 2>/dev/null || true)"
  if [ -n "$prior" ] && grep -qx "main=$main_sha" <<< "$prior" \
      && grep -Eqx 'verdict=(red|conflict)' <<< "$prior"; then
    say "BOUNCED-ALREADY: $staging_branch ${staging_sha:0:12} was already refused against $main_branch ${main_sha:0:12}; push a fix to $staging_branch"
    grep -E '^(verdict|fail|conflict)' <<< "$prior" | sed 's/^/    /'
    if grep -qx 'verdict=conflict' <<< "$prior"; then return "$EX_CONFLICT"; fi
    return "$EX_RED"
  fi

  local cand warm_flag="false"
  if [ -n "$canonical_worktree" ]; then
    cand="$canonical_worktree"
    if [ ! -d "$cand/.git" ] && [ ! -f "$cand/.git" ]; then
      git clone --quiet --local "$mirror" "$cand" || die "cannot initialize canonical gate worktree $cand"
      warm_flag="false"
    else
      git -C "$cand" fetch --quiet "$mirror" "+refs/heads/*:refs/remotes/origin/*" || die "cannot fetch mirror into $cand"
      warm_flag="true"
    fi
  else
    cand="$work/candidates/$stamp-$$"
    git clone --quiet --local "$mirror" "$cand" || die "cannot clone candidate"
  fi
  git -C "$cand" fetch --quiet "$remote_url" \
    "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" \
    "+refs/notes/$TIER0_NOTES_REF:refs/notes/$TIER0_NOTES_REF" 2>/dev/null || true
  git -C "$cand" checkout --quiet --detach "$main_sha" || die "cannot check out $main_sha"
  say "candidate: $cand (warm=$warm_flag)"
  say "merging $staging_branch ${staging_sha:0:12} into $main_branch ${main_sha:0:12} (--no-ff)"
  if ! gitc -C "$cand" merge --quiet --no-ff --no-edit \
      -m "merge-train: promote $staging_branch ${staging_sha:0:12} onto $main_branch ${main_sha:0:12}" \
      "$staging_sha" >/dev/null 2>&1; then
    local conflicts
    conflicts="$(git -C "$cand" diff --name-only --diff-filter=U)"
    git -C "$cand" merge --abort >/dev/null 2>&1 || true
    say "CONFLICT: $staging_branch does not merge cleanly onto $main_branch"
    printf '%s\n' "$conflicts" | sed 's/^/    /'
    local -a kv=("main=$main_sha" "staging=$staging_sha")
    local f
    while IFS= read -r f; do [ -n "$f" ] && kv+=("conflict=$f"); done <<< "$conflicts"
    publish_note "$cand" "$staging_sha" "$(note_body conflict "${kv[@]}")"
    return "$EX_CONFLICT"
  fi
  local cand_sha cand_tree
  cand_sha="$(git -C "$cand" rev-parse HEAD)"
  cand_tree="$(git -C "$cand" rev-parse 'HEAD^{tree}')"

  # Unskippable Tier-0 gate before any promotion (bead fa-1qk0)
  if [ -f "$cand/scripts/tier0.sh" ]; then
    tier0_in_cand "$cand" "staging"
    if [ "$TIER0_LAST_VERDICT" = "UNRUN" ]; then
      say "UNRUN: tier0 did not run on ${cand_sha:0:12}; do not fold yet; nothing promoted"
      return "$EX_UNRUN"
    fi
    if [ "$TIER0_LAST_VERDICT" != "PASS" ]; then
      say "RED: tier0 failed on ${cand_sha:0:12}; $staging_branch bounced"
      printf '    %s\n' "${TIER0_LAST_FAIL_LINE:-FAIL tier0}"
      publish_note "$cand" "$staging_sha" "$(note_body red "main=$main_sha" "staging=$staging_sha" "candidate=$cand_sha" "tree=$cand_tree" "warm=$warm_flag" "fail: ${TIER0_LAST_FAIL_LINE:-FAIL tier0}")"
      return "$EX_RED"
    fi
    if [ "$tier0_only" -eq 1 ] || [ ! -f "$cand/scripts/local_proof.sh" ]; then
      publish_tier0_note "$cand" "$cand_sha" "$cand_tree"
      if [ "$push" -eq 0 ]; then
        say "PASS (--no-push): ${cand_sha:0:12} would be promoted to $main_branch"
        publish_note "$cand" "$cand_sha" "$(note_body pass "main=$main_sha" "staging=$staging_sha" "candidate=$cand_sha" "tree=$cand_tree" "warm=$warm_flag" "check_exit=0")"
        return "$EX_NOTHING"
      fi
      if ! git -C "$cand" push --quiet "$remote_url" "$cand_sha:refs/heads/$main_branch" 2>/dev/null; then
        say "STALE: $main_branch moved during tier0; nothing promoted (rerun the train)"
        return "$EX_STALE"
      fi
      say "PROMOTED: $main_branch ${main_sha:0:12} -> ${cand_sha:0:12}"
      publish_note "$cand" "$cand_sha" "$(note_body pass "main=$main_sha" "staging=$staging_sha" "candidate=$cand_sha" "tree=$cand_tree" "warm=$warm_flag" "check_exit=0")"
      return "$EX_NOTHING"
    fi
  elif [ "$tier0_only" -eq 1 ]; then
    say "RED: scripts/tier0.sh missing on ${cand_sha:0:12}"
    return "$EX_RED"
  fi

  local proof="$work/proofs/$stamp-${cand_sha:0:12}"
  local log="$work/proofs/$stamp-${cand_sha:0:12}.train.log"
  say "proving ${cand_sha:0:12} (tree ${cand_tree:0:12}); transcript: $log"
  : "${RCH_CARGO_WRAPPER_BYPASS:=1}"
  : "${CARGO_TARGET_DIR:=$work/target}"
  : "${RCH_WORKER:=${FA_GATE_PRIMARY_WORKER:-hz2}}"
  export RCH_CARGO_WRAPPER_BYPASS CARGO_TARGET_DIR RCH_WORKER
  local proof_rc=0
  (cd "$cand" && bash scripts/local_proof.sh --output "$proof") > "$log" 2>&1 || proof_rc=$?
  say "local_proof.sh exited $proof_rc"

  local base_kv=("main=$main_sha" "staging=$staging_sha" "candidate=$cand_sha" "tree=$cand_tree" "proof=$proof" "warm=$warm_flag" "worker=${RCH_WORKER}")
  if [ ! -f "$proof/manifest.txt" ] \
      || ! bash "$cand/scripts/local_proof_verify.sh" --repository "$cand" "$proof" >> "$log" 2>&1; then
    say "UNVERIFIABLE: the proof bundle did not verify; nothing promoted"
    publish_note "$cand" "$staging_sha" "$(note_body unverifiable "${base_kv[@]}" "local_proof_exit=$proof_rc")"
    return "$EX_UNVERIFIABLE"
  fi
  local verdict check_exit stable proved_commit wall_secs
  verdict="$(sed -n 's/^verdict=//p' "$proof/manifest.txt")"
  check_exit="$(sed -n 's/^check_exit=//p' "$proof/manifest.txt")"
  stable="$(sed -n 's/^tree_stable=//p' "$proof/manifest.txt")"
  proved_commit="$(sed -n 's/^commit=//p' "$proof/manifest.txt")"
  wall_secs="$(sed -n 's/^wall_seconds=//p' "$proof/tools.txt" 2>/dev/null || echo 0)"
  base_kv+=("check_exit=$check_exit" "tree_stable=$stable" "wall_seconds=${wall_secs:-0}"
    "started_utc=$(sed -n 's/^started_utc=//p' "$proof/manifest.txt")"
    "finished_utc=$(sed -n 's/^finished_utc=//p' "$proof/manifest.txt")")

  if [ "$verdict" = pass ] && [ "$check_exit" = 0 ] && [ "$stable" = true ] \
      && [ "$proved_commit" = "$cand_sha" ]; then
    publish_tier0_note "$cand" "$cand_sha" "$cand_tree"
    if [ "$push" -eq 0 ]; then
      say "PASS (--no-push): ${cand_sha:0:12} would be promoted to $main_branch"
      publish_note "$cand" "$cand_sha" "$(note_body pass "${base_kv[@]}")"
      return "$EX_NOTHING"
    fi
    if ! git -C "$cand" push --quiet "$remote_url" "$cand_sha:refs/heads/$main_branch" 2>>"$log"; then
      say "STALE: $main_branch moved during the proof; nothing promoted (rerun the train)"
      return "$EX_STALE"
    fi
    say "PROMOTED: $main_branch ${main_sha:0:12} -> ${cand_sha:0:12}"
    publish_note "$cand" "$cand_sha" "$(note_body pass "${base_kv[@]}")"
    return "$EX_NOTHING"
  fi

  local fails
  fails="$(grep -a '^FAIL ' "$proof/check.stdout.log" 2>/dev/null | head -n 40)"
  local -a fail_kv=()
  local line
  while IFS= read -r line; do [ -n "$line" ] && fail_kv+=("fail: $line"); done <<< "$fails"
  if [ "$verdict" = void ]; then
    say "VOID: the tree moved during the proof; nothing promoted"
    publish_note "$cand" "$staging_sha" "$(note_body void "${base_kv[@]}")"
    return "$EX_VOID"
  fi
  say "RED: check.sh exited $check_exit on ${cand_sha:0:12}; $staging_branch bounced"
  printf '%s\n' "$fails" | sed 's/^/    /'
  publish_note "$cand" "$staging_sha" "$(note_body red "${base_kv[@]}" "${fail_kv[@]}")"
  return "$EX_RED"
}

audit_train() {
  [ -n "$since" ] || die "audit requires --since REV (the adoption point)"
  refresh_mirror
  local since_sha main_sha
  since_sha="$(git -C "$mirror" rev-parse --verify --quiet "$since^{commit}")" \
    || die "cannot resolve --since $since in the mirror"
  main_sha="$(git -C "$mirror" rev-parse --verify --quiet "refs/heads/$main_branch^{commit}")" \
    || die "remote has no $main_branch branch"
  git -C "$mirror" merge-base --is-ancestor "$since_sha" "$main_sha" \
    || die "--since $since is not an ancestor of $main_branch"

  local proven=0 unproven=0 violations=0 m note offenders
  while IFS= read -r m; do
    [ -n "$m" ] || continue
    note="$(git -C "$mirror" notes --ref="$NOTES_REF" show "$m" 2>/dev/null || true)"
    if grep -qx 'verdict=pass' <<< "$note"; then
      proven=$((proven + 1))
      continue
    fi
    unproven=$((unproven + 1))
    offenders="$(git -C "$mirror" log --format='%h%x09%ae%x09%s' "$m^1..$m" 2>/dev/null \
      | MT_AUTHOR_PATTERN="$author_pattern" awk -F '\t' '$2 ~ ENVIRON["MT_AUTHOR_PATTERN"]')"
    if [ -n "$offenders" ]; then
      violations=$((violations + $(printf '%s\n' "$offenders" | wc -l)))
      printf 'VIOLATION first-parent %s carries unproven commits by the toolchain-less identity:\n' "${m:0:12}"
      printf '%s\n' "$offenders" | sed 's/^/    /'
    elif [ "$strict" -eq 1 ]; then
      violations=$((violations + 1))
      printf 'VIOLATION first-parent %s has no pass note (--strict)\n' "${m:0:12}"
    else
      printf 'UNPROVEN first-parent %s %s\n' "${m:0:12}" \
        "$(git -C "$mirror" log -1 --format='%ae %s' "$m")"
    fi
  done < <(git -C "$mirror" rev-list --first-parent --reverse "$since_sha..$main_sha")

  printf 'audit: %s..%s first-parent commits: proven=%d unproven=%d violations=%d\n' \
    "${since_sha:0:12}" "${main_sha:0:12}" "$proven" "$unproven" "$violations"
  [ "$violations" -eq 0 ] || return 1
  return 0
}

case "$command" in
  run|run-batch|fold) run_train; exit $? ;;
  audit) audit_train; exit $? ;;
esac
