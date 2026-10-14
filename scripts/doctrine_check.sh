#!/usr/bin/env bash
# =============================================================================
# scripts/doctrine_check.sh — Constitutional engineering doctrine lint gate
# (bead fa-598p; AGENTS.md doctrines 1, 2, 4, 9; plan §0.4 decision 10, §18.4)
#
# Usage: scripts/doctrine_check.sh [<workspace-root> [<foundations-receipts-dir>]]
#
# Enforces six mechanical prohibitions across the workspace:
#   1. no-raw-gql: no `execute_gql*` or `BoundPlan` calls/references.
#   2. no-float-in-amount-crates: no `f32`/`f64`/`as f32`/`as f64` in
#      amount/ledger/verification crates (`fa-money`, `fa-model`, `fa-journal`,
#      `fa-registers`, `fa-statements`, `fa-lantern`, `fa-verify`,
#      `fa-palimpsest`, `fa-escrow`, `fa-docket`, `fa-steward`, `fa-notary`,
#      `fa-intents`, `fa-policy`).
#   3. no-detached-threads: no `std::thread::spawn` or `thread::Builder` in
#      production source files (`crates/*/src/**/*.rs`, `tools/*/src/**/*.rs`).
#   4. no-serde-durable-derive: no `#[derive(...Serialize|Deserialize...)]` on
#      first-party types (`crates/**/*.rs`, `tools/**/*.rs`).
#   5. forbid-unsafe-crate-roots: every crate root (`src/lib.rs`, `src/main.rs`,
#      `src/bin/*.rs`) carries `#![forbid(unsafe_code)]`.
#   6. single-fnx-classes: every shipped posture (`fa`, `fa-cli`, `fad`,
#      `fa-mcp`) resolves `fnx-classes` to a single package ID.
#
# Every source violation reports `<relative-file>:<line>` in its `FAIL` line.
# =============================================================================
set -u

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/gate_verdict.sh
. "$SCRIPT_ROOT/scripts/lib/gate_verdict.sh"

gate_init "doctrine"

if [ "$#" -gt 2 ]; then
  printf 'FAIL doctrine_check.sh: usage: doctrine_check.sh [<workspace-root> [<foundations-receipts-dir>]]\n'
  exit 1
fi

TARGET_ROOT="${1:-$SCRIPT_ROOT}"
FOUNDATIONS_DIR="${2:-}"

command -v python3 >/dev/null 2>&1 || gate_abort_unrun "doctrine — python3 is not installed"
[ -d "$TARGET_ROOT/crates" ] || gate_abort_unrun "doctrine — workspace root $TARGET_ROOT has no crates/ directory"

VERDICT_LINES="$(python3 -B - "$TARGET_ROOT" "$FOUNDATIONS_DIR" <<'PY' 2>&1
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
foundations_arg = sys.argv[2]
foundations_dir = Path(foundations_arg).resolve() if foundations_arg else None

passes = []
fails = []
unruns = []


def strip_line_comment(line: str) -> str:
    idx = line.find("//")
    return line if idx < 0 else line[:idx]


def iter_rs_files(subdirs):
    for sub in subdirs:
        base = root / sub
        if base.is_dir():
            yield from sorted(base.rglob("*.rs"))


all_rs = list(iter_rs_files(["crates", "tools"]))
if not all_rs:
    print("UNRUN doctrine — no Rust source files under crates/ or tools/")
    sys.exit(2)

# 1. no-raw-gql: no execute_gql* or BoundPlan references
gql_re = re.compile(r"\b(execute_gql\w*|BoundPlan)\b")
gql_hits = []
for path in all_rs:
    rel = path.relative_to(root)
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        code = strip_line_comment(raw)
        m = gql_re.search(code)
        if m:
            gql_hits.append(f"{rel}:{lineno}: forbidden `{m.group(1)}` reference")
if gql_hits:
    for hit in gql_hits:
        fails.append(f"no-raw-gql — {hit}")
else:
    passes.append(f"no-raw-gql — 0 execute_gql*/BoundPlan references across {len(all_rs)} Rust files")

# 2. no-float-in-amount-crates: no f32/f64/as f32/as f64 in amount & domain crates
amount_crates = [
    "fa-money",
    "fa-model",
    "fa-journal",
    "fa-registers",
    "fa-statements",
    "fa-lantern",
    "fa-verify",
    "fa-palimpsest",
    "fa-escrow",
    "fa-docket",
    "fa-steward",
    "fa-notary",
    "fa-intents",
    "fa-policy",
]
float_re = re.compile(r"\b(f32|f64)\b")
float_hits = []
amount_files = 0
for crate in amount_crates:
    crate_dir = root / "crates" / crate
    if not crate_dir.is_dir():
        continue
    for path in sorted(crate_dir.rglob("*.rs")):
        amount_files += 1
        rel = path.relative_to(root)
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "doctrine-allow: non-amount-float" in raw:
                continue
            code = strip_line_comment(raw)
            m = float_re.search(code)
            if m:
                float_hits.append(f"{rel}:{lineno}: forbidden float token `{m.group(1)}` in {crate}")
if float_hits:
    for hit in float_hits:
        fails.append(f"no-float-in-amount-crates — {hit}")
else:
    passes.append(
        f"no-float-in-amount-crates — 0 f32/f64 tokens across {amount_files} files in {len(amount_crates)} crates"
    )

# 3. no-detached-threads: no std::thread::spawn or thread::Builder in production src/
thread_re = re.compile(r"\bthread::(spawn|Builder)\b")
thread_hits = []
prod_files = []
for sub in ["crates", "tools"]:
    base = root / sub
    if base.is_dir():
        for crate_dir in sorted(base.iterdir()):
            src_dir = crate_dir / "src"
            if src_dir.is_dir():
                prod_files.extend(sorted(src_dir.rglob("*.rs")))
for path in prod_files:
    rel = path.relative_to(root)
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        code = strip_line_comment(raw)
        m = thread_re.search(code)
        if m:
            thread_hits.append(f"{rel}:{lineno}: forbidden detached thread `{m.group(0)}` outside asupersync region")
if thread_hits:
    for hit in thread_hits:
        fails.append(f"no-detached-threads — {hit}")
else:
    passes.append(f"no-detached-threads — 0 detached thread spawns across {len(prod_files)} production source files")

# 4. no-serde-durable-derive: no #[derive(...Serialize|Deserialize...)]
serde_re = re.compile(r"#\[derive\([^\]]*?\b(Serialize|Deserialize)\b[^\]]*\)\]")
serde_hits = []
for path in all_rs:
    rel = path.relative_to(root)
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        code = strip_line_comment(raw)
        m = serde_re.search(code)
        if m:
            serde_hits.append(f"{rel}:{lineno}: forbidden serde derive `{m.group(1)}` on first-party type")
if serde_hits:
    for hit in serde_hits:
        fails.append(f"no-serde-durable-derive — {hit}")
else:
    passes.append(f"no-serde-durable-derive — 0 serde Serialize/Deserialize derives across {len(all_rs)} Rust files")

# 5. forbid-unsafe-crate-roots: every crate root has #![forbid(unsafe_code)]
crate_roots = []
for sub in ["crates", "tools"]:
    base = root / sub
    if not base.is_dir():
        continue
    for crate_dir in sorted(base.iterdir()):
        src_dir = crate_dir / "src"
        if not src_dir.is_dir():
            continue
        for root_name in ["lib.rs", "main.rs"]:
            candidate = src_dir / root_name
            if candidate.is_file():
                crate_roots.append(candidate)
        bin_dir = src_dir / "bin"
        if bin_dir.is_dir():
            crate_roots.extend(sorted(bin_dir.glob("*.rs")))

unsafe_hits = []
for path in crate_roots:
    rel = path.relative_to(root)
    found_forbid = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        code = strip_line_comment(raw).strip()
        if code == "#![forbid(unsafe_code)]":
            found_forbid = True
            break
    if not found_forbid:
        unsafe_hits.append(f"{rel}:1: missing `#![forbid(unsafe_code)]` at crate root")
if unsafe_hits:
    for hit in unsafe_hits:
        fails.append(f"forbid-unsafe-crate-roots — {hit}")
else:
    passes.append(f"forbid-unsafe-crate-roots — all {len(crate_roots)} crate roots carry #![forbid(unsafe_code)]")

# 6. single-fnx-classes: single package ID for fnx-classes per shipped posture
postures = ["fa", "fa-cli", "fad", "fa-mcp"]
fnx_hits = []
if foundations_dir and foundations_dir.is_dir():
    for posture in postures:
        tree_file = foundations_dir / f"{posture}.tree"
        if not tree_file.is_file():
            fnx_hits.append(f"{tree_file}:1: missing posture tree receipt for {posture}")
            continue
        fnx_packages = set()
        fnx_lines = {}
        for lineno, raw in enumerate(tree_file.read_text(encoding="utf-8").splitlines(), 1):
            if not raw or raw == "[build-dependencies]":
                continue
            line = raw.removesuffix(" (*)")
            pkg = line.split("|", 1)[0].strip()
            if pkg.startswith("fnx-classes "):
                fnx_packages.add(pkg)
                fnx_lines.setdefault(pkg, lineno)
        if len(fnx_packages) != 1:
            first_line = min(fnx_lines.values()) if fnx_lines else 1
            fnx_hits.append(
                f"{tree_file}:{first_line}: posture `{posture}` requires 1 fnx-classes package ID, found {len(fnx_packages)}: {sorted(fnx_packages)}"
            )
else:
    lock_path = root / "Cargo.lock"
    if not lock_path.is_file():
        unruns.append("single-fnx-classes — neither foundations receipts nor Cargo.lock available")
    else:
        import tomllib
        lock_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        fnx_pkgs = [
            f"{p['name']} v{p['version']} ({p.get('source', 'local')})"
            for p in lock_data.get("package", [])
            if p.get("name") == "fnx-classes"
        ]
        if len(fnx_pkgs) != 1:
            fnx_hits.append(
                f"Cargo.lock:1: workspace requires 1 fnx-classes package ID, found {len(fnx_pkgs)}: {fnx_pkgs}"
            )

if fnx_hits:
    for hit in fnx_hits:
        fails.append(f"single-fnx-classes — {hit}")
elif not unruns:
    passes.append("single-fnx-classes — every shipped posture resolves fnx-classes to a single package ID")

for u in unruns:
    print(f"UNRUN::{u}")
for p in passes:
    print(f"PASS::{p}")
for f in fails:
    print(f"FAIL::{f}")
PY
)"
PY_RC=$?
if [ "$PY_RC" -eq 2 ]; then
  gate_abort_unrun "${VERDICT_LINES#UNRUN }"
fi

while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "$line" in
    UNRUN::*) gate_unrun "${line#UNRUN::}" ;;
    PASS::*) gate_pass "${line#PASS::}" ;;
    FAIL::*) gate_fail "${line#FAIL::}" ;;
    *) gate_fail "doctrine — unexpected output: $line" ;;
  esac
done <<<"$VERDICT_LINES"

gate_verdict
