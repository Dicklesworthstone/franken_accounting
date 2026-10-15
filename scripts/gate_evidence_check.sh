#!/usr/bin/env bash
# =============================================================================
# scripts/gate_evidence_check.sh — positive completion markers, test-inventory
# witness, and per-crate evidence ratchet (bead fa-czx)
#
# Usage:
#   scripts/gate_evidence_check.sh <repo-root> <test-list.log> <test.log> <workdir> \
#     [--base-root <dir>] [--commit-msg-file <file>]
#
# Enforces three honesty properties over the gate's test execution and the
# working tree:
#   1. Positive completion markers: both <test-list.log> and <test.log> must
#      contain `Remote command finished: exit=0`; <test-list.log> must list at
#      least one `: test` entry; <test.log> must contain at least one
#      `test result: ok.` line and a positive total of passed tests. Missing
#      completion markers are UNRUN (retryable), never PASS.
#   2. Test-inventory witness: every test listed in <test-list.log> must appear
#      as an executed (`ok` or `ignored`) test line in <test.log>, and the
#      counts must match (no silent skips or dropped test binaries). In
#      addition, no source `#[test]` function present in the baseline tree may
#      disappear without being named in a `Retired-tests:` trailer on the
#      landing commit.
#   3. Per-crate evidence ratchet: for every crate in `crates/`, the count of
#      planted negative tests and the count of `assert` sites (`assert!`,
#      `assert_eq!`, `assert_ne!`, `matches!`) must not decrease relative to
#      the baseline tree (`--base-root` or `HEAD~1`) unless the commit message
#      carries a `Weakened-tests:` or `Retired-tests:` trailer naming the crate
#      or test.
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_DEFAULT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$REPO_ROOT_DEFAULT/scripts/lib/gate_verdict.sh"

if [ "$#" -lt 4 ]; then
  printf 'FAIL gate_evidence_check.sh: usage: gate_evidence_check.sh <repo-root> <test-list.log> <test.log> <workdir> [--base-root <dir>] [--commit-msg-file <file>]\n'
  exit 1
fi

ROOT="$1"
LIST_LOG="$2"
TEST_LOG="$3"
WORK="$4"
shift 4

BASE_ROOT=""
COMMIT_MSG_FILE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-root)
      BASE_ROOT="${2:-}"
      shift 2
      ;;
    --commit-msg-file)
      COMMIT_MSG_FILE="${2:-}"
      shift 2
      ;;
    *)
      printf 'FAIL gate_evidence_check.sh: unknown argument %s\n' "$1"
      exit 1
      ;;
  esac
done

gate_init "gate-evidence"
mkdir -p "$WORK" || gate_abort_unrun "gate-evidence — cannot create workdir $WORK"

# ---- 1. Positive completion markers on test-list.log and test.log -----------
if [ ! -r "$LIST_LOG" ]; then
  gate_abort_unrun "gate-evidence — test-list log is missing or unreadable; log: $LIST_LOG"
fi
if [ ! -r "$TEST_LOG" ]; then
  gate_abort_unrun "gate-evidence — test log is missing or unreadable; log: $TEST_LOG"
fi

if ! grep -Fq 'Remote command finished: exit=0' "$LIST_LOG"; then
  gate_abort_unrun "gate-evidence — test-list log lacks 'Remote command finished: exit=0' completion marker; log: $LIST_LOG"
fi
if ! grep -Fq 'Remote command finished: exit=0' "$TEST_LOG"; then
  gate_abort_unrun "gate-evidence — test log lacks 'Remote command finished: exit=0' completion marker; log: $TEST_LOG"
fi

awk '/: test$/ { line = $0; sub(/: test$/, "", line); sub(/^[[:space:]]+/, "", line); if (line != "") print line }' "$LIST_LOG" \
  | LC_ALL=C sort >"$WORK/listed-tests.txt"
LISTED_COUNT="$(wc -l <"$WORK/listed-tests.txt" | tr -d ' ')"
if [ "${LISTED_COUNT:-0}" -le 0 ]; then
  gate_abort_unrun "gate-evidence — test-list log contains zero listed tests; log: $LIST_LOG"
fi

PASSED_TOTAL="$(awk '/^test result: ok\./ { for (i = 1; i <= NF; i++) if ($i == "passed;") sum += $(i - 1) } END { print sum + 0 }' "$TEST_LOG")"
if ! grep -Eq '^test result: ok\. ' "$TEST_LOG" || [ "${PASSED_TOTAL:-0}" -le 0 ]; then
  gate_abort_unrun "gate-evidence — test log has no positive 'test result: ok. N passed' completion marker (passed=${PASSED_TOTAL:-0}); log: $TEST_LOG"
fi

gate_pass "gate-evidence — positive completion markers present ($LISTED_COUNT listed, $PASSED_TOTAL passed)"

# ---- 2. Executed vs listed test-inventory witness ---------------------------
awk '/^test .+ \.\.\. (ok|ignored)$/ { line = $0; sub(/^test /, "", line); sub(/ \.\.\. (ok|ignored)$/, "", line); if (line != "") print line }' "$TEST_LOG" \
  | LC_ALL=C sort >"$WORK/executed-tests.txt"
EXECUTED_COUNT="$(wc -l <"$WORK/executed-tests.txt" | tr -d ' ')"

LC_ALL=C comm -23 "$WORK/listed-tests.txt" "$WORK/executed-tests.txt" >"$WORK/dropped-tests.txt"
DROPPED_COUNT="$(wc -l <"$WORK/dropped-tests.txt" | tr -d ' ')"

if [ "${DROPPED_COUNT:-0}" -gt 0 ] || [ "$EXECUTED_COUNT" -lt "$LISTED_COUNT" ]; then
  FIRST_DROPPED="$(head -n 1 "$WORK/dropped-tests.txt")"
  gate_fail "gate-evidence — test-inventory mismatch: listed $LISTED_COUNT tests but executed $EXECUTED_COUNT ($DROPPED_COUNT listed test(s) dropped, first: ${FIRST_DROPPED:-count-mismatch}); witness: $WORK/dropped-tests.txt"
else
  cp "$WORK/listed-tests.txt" "$WORK/test-inventory.txt"
  gate_pass "gate-evidence — test-inventory witness verified ($EXECUTED_COUNT/$LISTED_COUNT listed tests executed; witness: $WORK/test-inventory.txt)"
fi

# ---- 3. Source test-inventory & per-crate evidence ratchet ------------------
COMMIT_MSG_PATH="$WORK/commit-message.txt"
if [ -n "$COMMIT_MSG_FILE" ]; then
  if [ ! -r "$COMMIT_MSG_FILE" ]; then
    gate_abort_unrun "gate-evidence — commit message file is unreadable: $COMMIT_MSG_FILE"
  fi
  cp "$COMMIT_MSG_FILE" "$COMMIT_MSG_PATH"
elif git -C "$ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
  git -C "$ROOT" log -1 --format=%B >"$COMMIT_MSG_PATH" 2>/dev/null || : >"$COMMIT_MSG_PATH"
else
  : >"$COMMIT_MSG_PATH"
fi

# Extract baseline tree if not explicitly supplied and HEAD~1 exists in git.
if [ -z "$BASE_ROOT" ] && git -C "$ROOT" rev-parse --verify HEAD~1 >/dev/null 2>&1; then
  BASE_ROOT="$WORK/base-tree"
  mkdir -p "$BASE_ROOT"
  if ! git -C "$ROOT" archive HEAD~1 -- crates tools 2>/dev/null | tar -x -C "$BASE_ROOT" 2>/dev/null; then
    BASE_ROOT=""
  fi
fi

python3 -B - "$ROOT" "$BASE_ROOT" "$COMMIT_MSG_PATH" "$WORK" <<'PY' >"$WORK/ratchet.out" 2>"$WORK/ratchet.err"
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
base_arg = sys.argv[2]
base_root = pathlib.Path(base_arg) if base_arg else None
commit_msg = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8", errors="replace")
work = pathlib.Path(sys.argv[4])

TEST_ATTR_RE = re.compile(r"#\[(?:[\w:]+::)?test(?:\([^\)]*\))?\]")
FN_RE = re.compile(r"\bfn\s+([A-Za-z0-9_]+)\s*\(")
ASSERT_RE = re.compile(r"\b(?:assert|assert_eq|assert_ne|matches)!\s*\(")
NEG_NAME_RE = re.compile(
    r"(?:^|_)(?:negative|refuse|refuses|refused|forbid|forbidden|reject|rejected|"
    r"invalid|corrupt|tamper|drift|untrusted|unauthenticated|unauthorized|"
    r"conflict|cycle|overflow|missing|unknown|mismatch|fail|fails|failed|"
    r"cannot|never|without|wrong|bad|duplicate|stale|expired)(?:_|$)"
)
NEG_BODY_RE = re.compile(r"(?:expect_err\s*\(|is_err\s*\(|FA-REF-[0-9]{3})")


def trailers(prefix: str) -> str:
    vals = []
    for line in commit_msg.splitlines():
        if line.lower().startswith(prefix.lower()):
            vals.append(line.split(":", 1)[1].strip())
    return " ".join(vals)


retired_trailer = trailers("Retired-tests:")
weakened_trailer = trailers("Weakened-tests:") + " " + retired_trailer


def scan_tree(tree_root: pathlib.Path):
    crates_dir = tree_root / "crates"
    tests_set = set()
    crate_stats = {}
    if not crates_dir.is_dir():
        return tests_set, crate_stats
    for crate_dir in sorted(p for p in crates_dir.iterdir() if p.is_dir()):
        crate = crate_dir.name
        assert_sites = 0
        neg_tests = 0
        test_count = 0
        for rs in sorted(crate_dir.rglob("*.rs")):
            text = rs.read_text(encoding="utf-8", errors="replace")
            assert_sites += len(ASSERT_RE.findall(text))
            lines = text.splitlines()
            i = 0
            while i < len(lines):
                if TEST_ATTR_RE.search(lines[i]):
                    j = i + 1
                    fn_name = None
                    while j < len(lines) and j <= i + 8:
                        m = FN_RE.search(lines[j])
                        if m:
                            fn_name = m.group(1)
                            break
                        j += 1
                    if fn_name:
                        tests_set.add(f"{crate}::{fn_name}")
                        test_count += 1
                        snippet = "\n".join(lines[j : min(len(lines), j + 60)])
                        if NEG_NAME_RE.search(fn_name) or NEG_BODY_RE.search(snippet):
                            neg_tests += 1
                        i = j + 1
                        continue
                i += 1
        crate_stats[crate] = {
            "tests": test_count,
            "negative_tests": neg_tests,
            "assert_sites": assert_sites,
        }
    return tests_set, crate_stats


curr_tests, curr_stats = scan_tree(root)
(work / "source-test-inventory.txt").write_text(
    "".join(f"{t}\n" for t in sorted(curr_tests)),
    encoding="utf-8",
)
with (work / "evidence-ratchet.tsv").open("w", encoding="utf-8") as fh:
    fh.write("crate\ttests\tnegative_tests\tassert_sites\n")
    for crate, st in sorted(curr_stats.items()):
        fh.write(
            f"{crate}\t{st['tests']}\t{st['negative_tests']}\t{st['assert_sites']}\n"
        )

failures = []
if base_root and (base_root / "crates").is_dir():
    base_tests, base_stats = scan_tree(base_root)
    for removed in sorted(base_tests - curr_tests):
        short_name = removed.split("::", 1)[1]
        crate_name = removed.split("::", 1)[0]
        if (
            removed not in retired_trailer
            and short_name not in retired_trailer
            and crate_name not in retired_trailer
        ):
            failures.append(
                f"source test `{removed}` was removed without a `Retired-tests:` trailer naming it"
            )
    for crate, bst in sorted(base_stats.items()):
        cst = curr_stats.get(
            crate, {"tests": 0, "negative_tests": 0, "assert_sites": 0}
        )
        for metric in ("negative_tests", "assert_sites"):
            if cst[metric] < bst[metric]:
                if crate not in weakened_trailer and "all" not in weakened_trailer:
                    failures.append(
                        f"crate `{crate}` {metric} decreased from {bst[metric]} to {cst[metric]} without a `Weakened-tests:` trailer naming `{crate}`"
                    )

if failures:
    for f in failures:
        print(f"FAIL\t{f}")
    sys.exit(1)
else:
    total_neg = sum(v["negative_tests"] for v in curr_stats.values())
    total_asserts = sum(v["assert_sites"] for v in curr_stats.values())
    print(
        f"PASS\t{len(curr_stats)} crates, {len(curr_tests)} source tests, {total_neg} negative tests, {total_asserts} assert sites"
    )
    sys.exit(0)
PY
RATCHET_RC=$?

if [ "$RATCHET_RC" -eq 0 ]; then
  SUMMARY="$(awk -F'\t' '$1 == "PASS" { print $2 }' "$WORK/ratchet.out")"
  gate_pass "gate-evidence — evidence ratchet & source inventory ($SUMMARY; manifest: $WORK/evidence-ratchet.tsv)"
else
  while IFS=$'\t' read -r tag detail; do
    if [ "$tag" = "FAIL" ]; then
      gate_fail "gate-evidence — $detail"
    fi
  done <"$WORK/ratchet.out"
  if [ ! -s "$WORK/ratchet.out" ]; then
    gate_fail "gate-evidence — ratchet analyzer failed (exit $RATCHET_RC); see $WORK/ratchet.err"
  fi
fi

gate_verdict
