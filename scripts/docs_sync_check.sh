#!/usr/bin/env bash
# =============================================================================
# scripts/docs_sync_check.sh — G0 README/AGENTS synchronization check (fa-vz7e)
#
# Verifies under scripts/lib/gate_verdict.sh:
#   (a) Every FA-* marker in README.md and AGENTS.md resolves against registries/*.toml
#   (b) Every present-tense `fa ` command above `## TL;DR` in README.md exists in verbs.toml
#   (c) README.md status line (`> **Status (YYYY-MM-DD):`) carries a date within 7 days
#       of the latest verdict note / Verified-at line
#   (d) AGENTS.md's check-sh-steps list equals scripts/check.sh's CANONICAL_STEPS header
#       and every step is invoked in scripts/check.sh
#
# Logs every mismatch with file:line on both sides.
# A default repository check also runs --self-test; fixtures are retained.
# =============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
source "$ROOT/scripts/lib/gate_verdict.sh"

TARGET_ROOT="${1:-$ROOT}"
if [ "$TARGET_ROOT" = --self-test ]; then
  gate_init "docs-sync-selftest"
else
  gate_init "docs-sync"
fi

if ! command -v python3 >/dev/null 2>&1; then
  gate_unrun "docs-sync" "python3 is not installed"
  gate_verdict
  exit $?
fi

if [ "$TARGET_ROOT" = --self-test ]; then
  python3 - "$ROOT" <<'PY'
import pathlib
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1])
base = pathlib.Path(tempfile.mkdtemp(prefix="fa-docs-sync-selftest-"))
registry = '''[global]
flags = ["--token", "--book"]
switches = ["--json"]
flag_aliases = ["--robot=--json"]
[[verb]]
name = "period"
subcommands = ["close"]
'''
cases = [
    ("plain", "fa period close FY2026-P03", 0, "PASS readme-commands"),
    ("registered-prefix", 'fa --token "controller token" --book ./book --json period close FY2026-P03', 0, "PASS readme-commands"),
    ("inline-alias-prefix", "fa --token=controller.token --robot period close FY2026-P03", 0, "PASS readme-commands"),
    ("inline-comment", "fa period close FY2026-P03 # the document's range", 0, "PASS readme-commands"),
    ("quoted-hash", 'fa --token "controller#1 token" period close FY2026-P03', 0, "PASS readme-commands"),
    ("broken-quote", 'fa --token "broken period close', 1, "malformed command"),
    ("unknown-prefix", "fa --invented t period close", 1, "unregistered verb `--invented`"),
    ("missing-value", "fa --token", 1, "needs a value"),
    ("unknown-verb", "fa --token t invented", 1, "unregistered verb `invented`"),
    ("unknown-subcommand", "fa --token t period teleport", 1, "missing valid subcommand"),
    ("evaluator-failure", "fa period close FY2026-P03", 1, "Python evaluation failed"),
    ("missing-files", "", 2, "missing required file"),
]
failures = 0
for name, command, expected, diagnostic in cases:
    fixture = base / name
    fixture.mkdir()
    if name != "missing-files":
        (fixture / "registries").mkdir()
        (fixture / "scripts").mkdir()
        (fixture / "registries/verbs.toml").write_text(registry)
        (fixture / "scripts/check.sh").write_text("# CANONICAL_STEPS: fmt\n")
        (fixture / "AGENTS.md").write_text("<!-- check-sh-steps: fmt -->\n")
        date = "2026-99-99" if name == "evaluator-failure" else "2026-10-25"
        (fixture / "README.md").write_text(f"> **Status ({date}):** fixture\n```bash\n{command}\n```\n## TL;DR\n")
    result = subprocess.run(["bash", str(source / "scripts/docs_sync_check.sh"), str(fixture)],
                            cwd=source, text=True, capture_output=True)
    (base / (name + ".stdout")).write_text(result.stdout)
    (base / (name + ".stderr")).write_text(result.stderr)
    if result.returncode == expected and diagnostic in result.stdout + result.stderr:
        print(f"PASS docs_sync_selftest::{name} exit={result.returncode}")
    else:
        failures += 1
        print(f"FAIL docs_sync_selftest::{name} expected={expected} actual={result.returncode}; logs={base}")
print(f"fixtures={base}")
print(f"cases={len(cases)} failures={failures}")
sys.exit(1 if failures else 0)
PY
  selftest_rc=$?
  if [ "$selftest_rc" -eq 0 ]; then
    gate_pass "docs-sync-selftest" "all registry-prefix and evaluator-failure controls executed"
  else
    gate_fail "docs-sync-selftest" "controls failed (exit $selftest_rc)"
  fi
  gate_verdict
  exit $?
fi

if [ "$#" -eq 0 ]; then
  bash "$ROOT/scripts/docs_sync_check.sh" --self-test
  selftest_rc=$?
  if [ "$selftest_rc" -ne 0 ]; then
    gate_fail "docs-sync-selftest" "controls failed (exit $selftest_rc)"
  fi
fi

EVAL_LINES="$(python3 - "$TARGET_ROOT" <<'PY'
import datetime
import pathlib
import re
import shlex
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
readme_path = root / "README.md"
agents_path = root / "AGENTS.md"
check_sh_path = root / "scripts" / "check.sh"
reg_dir = root / "registries"

for p in (readme_path, agents_path, check_sh_path, reg_dir / "verbs.toml"):
    if not p.is_file():
        print(f"UNRUN\tdocs-sync\tmissing required file {p}")
        sys.exit(0)

readme_text = readme_path.read_text(encoding="utf-8")
agents_text = agents_path.read_text(encoding="utf-8")
check_sh_text = check_sh_path.read_text(encoding="utf-8")

# (a) Collect all FA-* markers across registries/*.toml
known_markers = set()
for tf in reg_dir.glob("*.toml"):
    tcontent = tf.read_text(encoding="utf-8")
    for m in re.finditer(r'"(FA-[A-Z]+-[0-9]{2,}[A-Za-z0-9_-]*)"', tcontent):
        known_markers.add(m.group(1))

prefixes = (
    "FA-CON-", "FA-INV-", "FA-EVID-", "FA-CAL-", "FA-CFG-", "FA-REF-",
    "FA-THR-", "FA-TB-", "FA-TV-", "FA-PROOF-", "FA-MODEL-", "FA-SLO-", "FA-ART-",
)
marker_re = re.compile(r"\b(FA-[A-Z]+-[0-9]{2,})\b")

marker_mismatches = []
marker_count = 0
for rel_name, doc_text in (("README.md", readme_text), ("AGENTS.md", agents_text)):
    for lineno, line in enumerate(doc_text.splitlines(), 1):
        for m in marker_re.finditer(line):
            tok = m.group(1)
            if any(tok.startswith(p) for p in prefixes):
                marker_count += 1
                if tok not in known_markers:
                    marker_mismatches.append(f"{rel_name}:{lineno}: unresolved marker `{tok}` (not in registries/*.toml)")

if marker_mismatches:
    for msg in marker_mismatches:
        print(f"LOG\tDOCS_SYNC_MISMATCH {msg}")
    print(f"FAIL\tmarkers-resolve\t{marker_mismatches[0]}")
else:
    print(f"PASS\tmarkers-resolve\tall {marker_count} FA-* markers in README.md and AGENTS.md resolve")

# (b) Every `fa ` command in fenced shell blocks above `## TL;DR` in README.md exists in verbs.toml
verbs_text = (reg_dir / "verbs.toml").read_text(encoding="utf-8")
global_match = re.search(r"^\[global\]\s*\n(.*?)(?=^\[|\Z)", verbs_text, re.M | re.S)
global_text = global_match.group(1) if global_match else ""
def global_values(field):
    match = re.search(r"^" + field + r"\s*=\s*\[([^\]]*)\]", global_text, re.M)
    return re.findall(r'"([^"]+)"', match.group(1)) if match else []
global_flags = set(global_values("flags"))
global_switches = set(global_values("switches"))
flag_aliases = dict(value.split("=", 1) for value in global_values("flag_aliases"))
verb_subs = {}
for block in verbs_text.split("[[verb]]")[1:]:
    nm = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.M)
    subs_m = re.search(r'^\s*subcommands\s*=\s*\[([^\]]*)\]', block, re.M)
    if nm:
        vname = nm.group(1)
        subs = re.findall(r'"([^"]+)"', subs_m.group(1)) if subs_m else []
        verb_subs[vname] = set(subs)

aliases = {}
for block in verbs_text.split("[[alias]]")[1:]:
    fr = re.search(r'^\s*from\s*=\s*\[([^\]]*)\]', block, re.M)
    to = re.search(r'^\s*to\s*=\s*\[([^\]]*)\]', block, re.M)
    if fr and to:
        from_words = tuple(re.findall(r'"([^"]+)"', fr.group(1)))
        to_words = re.findall(r'"([^"]+)"', to.group(1))
        if from_words:
            aliases[from_words] = to_words

above_tldr = readme_text.split("\n## TL;DR\n")[0]
in_fence = None
pending = ""
pending_line = 0
cmd_mismatches = []
cmd_count = 0

for lineno, raw in enumerate(above_tldr.splitlines(), 1):
    if raw.startswith("```"):
        lang = raw[3:].strip()
        if in_fence is None:
            in_fence = lang in ("", "bash", "sh", "shell", "console")
        else:
            in_fence = None
        pending = ""
        continue
    if in_fence is not True:
        continue
    part = raw.strip()
    if not part or part.startswith("#"):
        continue
    if not pending:
        pending_line = lineno
        joined = part
    else:
        joined = f"{pending} {part}"
    if joined.endswith(chr(92)):
        pending = joined[:-1].rstrip()
        continue
    pending = ""
    if not joined.startswith("fa "):
        continue
    cmd_count += 1
    try:
        words = shlex.split(joined, comments=True)[1:]
    except ValueError as error:
        cmd_mismatches.append(f"README.md:{pending_line}: malformed command `{joined}`: {error}")
        continue
    # The same registry defines global prefixes accepted by the real CLI.
    # Consume only registered options; an unknown prefix still fails below.
    while words:
        name, equals, _value = words[0].partition("=")
        name = flag_aliases.get(name, name)
        if name in global_flags:
            if not equals and len(words) < 2:
                cmd_mismatches.append(f"README.md:{pending_line}: global flag `{name}` needs a value")
                words = []
                break
            words = words[1 if equals else 2:]
        elif name in global_switches:
            if equals:
                cmd_mismatches.append(f"README.md:{pending_line}: global switch `{name}` takes no value")
                words = []
                break
            words = words[1:]
        else:
            break
    if not words:
        continue
    # Expand alias (2-word then 1-word)
    if len(words) >= 2 and (words[0], words[1]) in aliases:
        words = aliases[(words[0], words[1])] + words[2:]
    elif (words[0],) in aliases:
        words = aliases[(words[0],)] + words[1:]
    vname = words[0]
    if vname not in verb_subs:
        cmd_mismatches.append(
            f"README.md:{pending_line}: command `{joined}` uses unregistered verb `{vname}` (not in registries/verbs.toml:1)"
        )
        continue
    subs = verb_subs[vname]
    if subs and (len(words) < 2 or words[1] not in subs):
        cmd_mismatches.append(
            f"README.md:{pending_line}: command `{joined}` missing valid subcommand for `{vname}` (expected one of {sorted(subs)} in registries/verbs.toml:1)"
        )

if cmd_mismatches:
    for msg in cmd_mismatches:
        print(f"LOG\tDOCS_SYNC_MISMATCH {msg}")
    print(f"FAIL\treadme-commands\t{cmd_mismatches[0]}")
else:
    print(f"PASS\treadme-commands\tall {cmd_count} present-tense `fa` commands above `## TL;DR` resolve against verbs.toml")

# (c) README status line date within 7 days of last verdict note / Verified-at line
status_line_no = 0
status_date_str = ""
verified_line_no = 0
verified_date_str = ""
for lineno, line in enumerate(readme_text.splitlines(), 1):
    m_st = re.search(r"\*\*Status\s*\((\d{4}-\d{2}-\d{2})\):", line)
    if m_st and not status_date_str:
        status_line_no = lineno
        status_date_str = m_st.group(1)
    m_vf = re.search(r"Verified at [0-9a-f]+\s*\((\d{4}-\d{2}-\d{2})\):", line)
    if m_vf and not verified_date_str:
        verified_line_no = lineno
        verified_date_str = m_vf.group(1)

if not status_date_str:
    print("LOG\tDOCS_SYNC_MISMATCH README.md:1: missing `> **Status (YYYY-MM-DD):` line")
    print("FAIL\treadme-status-date\tREADME.md:1: missing `> **Status (YYYY-MM-DD):` status line")
else:
    status_dt = datetime.date.fromisoformat(status_date_str)
    ref_dt = datetime.date.fromisoformat(verified_date_str) if verified_date_str else status_dt
    ref_loc = f"README.md:{verified_line_no}" if verified_line_no else "refs/notes/fa-verdict"
    # Also check latest refs/notes/fa-verdict note date if git repo is available
    p = subprocess.run(["git", "-C", str(root), "notes", "--ref=refs/notes/fa-verdict", "list"], capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip():
        last_commit = p.stdout.strip().splitlines()[-1].split()[-1]
        p2 = subprocess.run(["git", "-C", str(root), "notes", "--ref=refs/notes/fa-verdict", "show", last_commit], capture_output=True, text=True)
        if p2.returncode == 0:
            m_utc = re.search(r"^finished_utc=(\d{4}-\d{2}-\d{2})", p2.stdout, re.M)
            if m_utc:
                ref_dt = datetime.date.fromisoformat(m_utc.group(1))
                ref_loc = f"refs/notes/fa-verdict({last_commit[:12]})"
    delta_days = abs((ref_dt - status_dt).days)
    if delta_days > 7:
        msg = f"README.md:{status_line_no}: Status date {status_date_str} is {delta_days} days from verdict date {ref_dt.isoformat()} ({ref_loc}); max allowed is 7 days"
        print(f"LOG\tDOCS_SYNC_MISMATCH {msg}")
        print(f"FAIL\treadme-status-date\t{msg}")
    else:
        print(f"PASS\treadme-status-date\tREADME.md:{status_line_no} status date {status_date_str} is within 7 days of {ref_dt.isoformat()} ({delta_days}d)")

# (d) AGENTS.md list of check.sh steps equals scripts/check.sh CANONICAL_STEPS header
agents_steps_line = 0
agents_steps = []
for lineno, line in enumerate(agents_text.splitlines(), 1):
    m = re.search(r"<!--\s*check-sh-steps:\s*(.*?)-->", line)
    if m:
        agents_steps_line = lineno
        agents_steps = [s.strip() for s in m.group(1).split(",") if s.strip()]
        break

check_steps_line = 0
check_steps = []
for lineno, line in enumerate(check_sh_text.splitlines(), 1):
    m = re.match(r"^#\s*CANONICAL_STEPS:\s*(.+)$", line)
    if m:
        check_steps_line = lineno
        check_steps = [s.strip() for s in m.group(1).split(",") if s.strip()]
        break

if not agents_steps or not check_steps:
    msg = f"AGENTS.md:{agents_steps_line} or scripts/check.sh:{check_steps_line} missing canonical step list"
    print(f"LOG\tDOCS_SYNC_MISMATCH {msg}")
    print(f"FAIL\tcheck-steps-sync\t{msg}")
elif agents_steps != check_steps:
    msg = (
        f"AGENTS.md:{agents_steps_line} step list {agents_steps} != "
        f"scripts/check.sh:{check_steps_line} CANONICAL_STEPS {check_steps}"
    )
    print(f"LOG\tDOCS_SYNC_MISMATCH {msg}")
    print(f"FAIL\tcheck-steps-sync\t{msg}")
else:
    print(
        f"PASS\tcheck-steps-sync\tAGENTS.md:{agents_steps_line} and scripts/check.sh:{check_steps_line} agree on all {len(check_steps)} steps"
    )
PY
)"
eval_rc=$?
if [ "$eval_rc" -ne 0 ]; then
  gate_fail "docs-sync" "Python evaluation failed (exit $eval_rc); no complete evaluation"
  gate_verdict
  exit $?
fi

while IFS=$'\t' read -r kind step detail; do
  [ -z "$kind" ] && continue
  case "$kind" in
    LOG)
      printf '%s\n' "$step"
      ;;
    PASS)
      gate_pass "$step" "$detail"
      ;;
    FAIL)
      gate_fail "$step" "$detail"
      ;;
    UNRUN)
      gate_unrun "$step" "$detail"
      ;;
  esac
done <<< "$EVAL_LINES"

cd "$ROOT" || exit 1
gate_verdict
