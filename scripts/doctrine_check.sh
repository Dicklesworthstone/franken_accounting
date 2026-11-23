#!/usr/bin/env bash
# =============================================================================
# scripts/doctrine_check.sh — Constitutional engineering doctrine lint gate
# (bead fa-598p; AGENTS.md doctrines 1, 2, 4, 9; plan §0.4 decision 10, §18.4)
#
# Usage: scripts/doctrine_check.sh [<workspace-root> [<foundations-receipts-dir>]]
#
# Enforces seven mechanical prohibitions across the workspace:
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
#   7. metered-substrate-scans: whole-table and relation scans in metered production
#      paths must go through the counted wrappers in `fa_journal::op_witness`.
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
import json
import re
import shutil
import subprocess
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
    "fa-oracles",
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

# 7. metered-substrate-scans: no direct whole-table or relation-scoped scans
# bypassing fa_journal::op_witness in metered kernel/register/notary/lantern paths
# (bead fa-0hs4.27).
metered_files = []
for sub in [
    "crates/fa/src",
    "crates/fa-journal/src",
    "crates/fa-notary/src",
    "crates/fa-registers/src",
    "crates/fa-lantern/src",
]:
    base = root / sub
    if base.is_dir():
        for p in sorted(base.rglob("*.rs")):
            if sub not in ("crates/fa/src", "crates/fa-journal/src") and (p.name == "tests.rs" or "tests" in p.relative_to(base).parts):
                continue
            metered_files.append(p)

# Rust outer attributes are siblings of the item they decorate. Search back
# through other attributes and comments only. Crossing a completed item
# would let an earlier test-only import excuse later production code.
scan_rule = r"""
id: unmetered-scan
language: Rust
severity: hint
rule:
  regex: '^(r#)?((vertices|edges)(_at)?|edges_by_relation_at)$'
  any:
    - kind: field_identifier
      inside:
        kind: field_expression
        field: field
        has: { field: value, pattern: '$RECEIVER' }
        any:
          - inside: { kind: call_expression, field: function }
          - inside:
              kind: generic_function
              field: function
              inside: { kind: call_expression, field: function }
    - kind: identifier
      inside:
        kind: scoped_identifier
        field: name
        has: { field: path, pattern: '$OWNER' }
    # Macro argument tokens have no field_expression until Rust expands them.
    - kind: identifier
      inside: { kind: token_tree }
      follows: { regex: '^\.$', stopBy: { not: { matches: comment } } }
      precedes: { kind: token_tree, regex: '^\(', stopBy: { not: { matches: comment } } }
    - kind: identifier
      inside: { kind: token_tree }
      follows:
        regex: '^::$'
        follows:
          kind: identifier
          pattern: '$MACRO_TYPE'
          any:
            - follows:
                regex: '^::$'
                follows: { kind: identifier, pattern: '$MACRO_CRATE' }
            - regex: '.'
      precedes: { kind: token_tree, regex: '^\(' }
  all:
    - any:
        - inside:
            stopBy: { kind: function_item }
            kind: function_item
            has: { field: name, pattern: '$BOUNDARY_FN' }
            inside:
              kind: declaration_list
              inside:
                kind: mod_item
                has: { field: name, regex: '^op_witness$' }
                inside: { kind: source_file }
        - regex: '.'
  not:
    inside:
      stopBy: end
      any:
        - kind: source_file
          has: { kind: inner_attribute_item, pattern: '#![cfg(test)]' }
        - follows:
            any: [{ pattern: '#[cfg(test)]' }, { pattern: '#[test]' }]
            stopBy:
              not:
                any: [{ kind: attribute_item }, { matches: comment }]
utils:
  comment:
    any: [{ kind: line_comment }, { kind: block_comment }]
---
id: substrate-scan-import
language: Rust
severity: hint
rule:
  kind: identifier
  inside: { kind: use_declaration, stopBy: end }
  any:
    - regex: '^fgdb$'
      inside:
        kind: use_as_clause
        field: path
        has: { field: alias, pattern: '$CRATE_ALIAS' }
    - regex: '^(Database|WriteTxn)$'
      all:
        - any:
            - inside:
                kind: scoped_identifier
                field: name
                has: { field: path, regex: '^(::)?fgdb$' }
            - inside:
                kind: scoped_use_list
                stopBy: { kind: scoped_use_list }
                has: { field: path, regex: '^(::)?fgdb$' }
        - any:
            - inside:
                kind: use_as_clause
                stopBy: { kind: use_declaration }
                has: { field: alias, pattern: '$TYPE_ALIAS' }
            - regex: '.'
"""
central_reads = {
    "vertices": ("db", "vertices"),
    "vertices_at": ("db", "vertices_at"),
    "snapshot_vertices_at": ("db", "vertices_at"),
    "txn_vertices": ("txn", "vertices"),
    "edges": ("db", "edges"),
    "edges_at": ("db", "edges_at"),
    "edges_by_relation_at": ("db", "edges_by_relation_at"),
}
scan_words = re.compile(r"\b(?:(?:vertices|edges)(?:_at)?|edges_by_relation_at)\b")
candidates = [str(p.relative_to(root)) for p in metered_files if scan_words.search(p.read_text(encoding="utf-8"))]
scan_complete = True
matches = []
if candidates:
    if shutil.which("ast-grep") is None:
        unruns.append("metered-substrate-scans — ast-grep is required to distinguish Rust production and test items")
        scan_complete = False
    else:
        result = subprocess.run(
            ["ast-grep", "scan", "--inline-rules", scan_rule, "--json=compact", "--", *candidates],
            cwd=root, capture_output=True, text=True,
        )
        if result.returncode:
            unruns.append(f"metered-substrate-scans — ast-grep exited {result.returncode}: {result.stderr.strip()}")
            scan_complete = False
        else:
            matches = json.loads(result.stdout)
crate_aliases = {}
type_aliases = {}
for match in matches:
    if match["ruleId"] != "substrate-scan-import":
        continue
    captures = match.get("metaVariables", {}).get("single", {})
    path = match["file"]
    if "CRATE_ALIAS" in captures:
        crate_aliases.setdefault(path, set()).add(captures["CRATE_ALIAS"]["text"])
    else:
        name = captures.get("TYPE_ALIAS", {}).get("text", match["text"])
        type_aliases.setdefault(path, set()).add(name)

def substrate_owner(owner, path):
    # UFCS accepts Database::<V>::method and <fgdb::Database<V>>::method.
    owner = "".join(owner.split())
    if owner.startswith("<") and owner.endswith(">"):
        owner = owner[1:-1]
    owner = owner.split("<", 1)[0].removeprefix("::").removesuffix("::")
    namespace, _, typename = owner.rpartition("::")
    if namespace:
        return (namespace == "fgdb" or namespace in crate_aliases.get(path, ())) and typename in ("Database", "WriteTxn")
    return typename in type_aliases.get(path, ())

exempted = set()
violations = []
calls = (m for m in matches if m["ruleId"] == "unmetered-scan")
for match in sorted(calls, key=lambda m: (m["file"], m["range"]["byteOffset"]["start"])):
    captures = match.get("metaVariables", {}).get("single", {})
    owner = captures.get("OWNER", {}).get("text")
    if "MACRO_TYPE" in captures:
        namespace = captures.get("MACRO_CRATE", {}).get("text")
        owner = (namespace + "::" if namespace else "") + captures["MACRO_TYPE"]["text"]
    if owner is not None and not substrate_owner(owner, match["file"]):
        continue
    fn = captures.get("BOUNDARY_FN", {}).get("text")
    receiver = captures.get("RECEIVER", {}).get("text")
    if (match["file"] == "crates/fa-journal/src/lib.rs" and fn in central_reads
            and central_reads[fn] == (receiver, match["text"]) and fn not in exempted):
        exempted.add(fn)
        continue
    violations.append(match)
    line = match["range"]["start"]["line"] + 1
    fails.append(
        f"metered-substrate-scans — {match['file']}:{line}: uninstrumented direct substrate scan "
        f"`.{match['text']}()`; route through `fa_journal::op_witness`"
    )
if scan_complete and not violations:
    passes.append(
        f"metered-substrate-scans — 0 uninstrumented substrate scans across {len(metered_files)} metered production files"
    )

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
