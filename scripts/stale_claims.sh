#!/usr/bin/env bash
# =============================================================================
# scripts/stale_claims.sh — Stale claim & WIP limit report (bead fa-7dx)
# =============================================================================
# Reports:
#   1. `in_progress` beads with no git commit mentioning their ID in the last
#      `--hours` (default 24h).
#   2. Agents holding more than `--wip-limit` (default 2) `in_progress` beads.
#
# Usage:
#   bash scripts/stale_claims.sh [--repository DIR] [--hours 24] [--wip-limit 2] [--json]
# =============================================================================

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
hours=24
wip_limit=2
json_mode=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repository) repo="$2"; shift 2 ;;
    --hours) hours="$2"; shift 2 ;;
    --wip-limit) wip_limit="$2"; shift 2 ;;
    --json) json_mode=1; shift ;;
    *) printf 'stale-claims: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done

jsonl="$repo/.beads/issues.jsonl"
[ -f "$jsonl" ] || { printf 'stale-claims: missing %s\n' "$jsonl" >&2; exit 2; }

recent_commits="$(git -C "$repo" log --since="${hours} hours ago" --format='%s %b' 2>/dev/null || true)"

python3 - "$jsonl" "$wip_limit" "$hours" "$json_mode" "$recent_commits" <<'PY'
import json
import sys
from collections import defaultdict

jsonl_path = sys.argv[1]
wip_limit = int(sys.argv[2])
hours = int(sys.argv[3])
json_mode = int(sys.argv[4]) == 1
recent_commits = sys.argv[5]

in_progress = []
by_agent = defaultdict(list)

with open(jsonl_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if row.get("status") == "in_progress":
            bid = row.get("id", "")
            assignee = row.get("assignee") or row.get("owner") or "unassigned"
            in_progress.append((bid, assignee, row.get("updated_at", "")))
            by_agent[assignee].append(bid)

stale = []
for bid, assignee, updated_at in in_progress:
    if bid and bid not in recent_commits:
        stale.append({"id": bid, "assignee": assignee, "updated_at": updated_at})

wip_violations = []
for agent, bids in sorted(by_agent.items()):
    if len(bids) > wip_limit:
        wip_violations.append({"agent": agent, "count": len(bids), "beads": sorted(bids)})

if json_mode:
    print(json.dumps({
        "hours": hours,
        "wip_limit": wip_limit,
        "stale_claims": stale,
        "wip_violations": wip_violations,
    }))
else:
    for item in stale:
        print(f"STALE_CLAIM id={item['id']} assignee={item['assignee']} updated_at={item['updated_at']} (no commit in {hours}h)")
    for v in wip_violations:
        beads_csv = ",".join(v["beads"])
        print(f"WIP_LIMIT_EXCEEDED agent={v['agent']} count={v['count']} limit={wip_limit} beads={beads_csv}")
    print(f"SUMMARY in_progress={len(in_progress)} stale_claims={len(stale)} wip_violations={len(wip_violations)}")
PY
