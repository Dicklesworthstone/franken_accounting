#!/usr/bin/env python3
"""Candidate per-crate input fingerprints, without execution verdicts (fa-xrl).

Computes candidate hashes over the workspace inputs currently enumerated:
  input_hash = H(
      "fa:crate-input-closure:v1",
      global_invalidation_inputs(Cargo.toml, Cargo.lock, rust-toolchain.toml,
                                 franken-stack.lock, deny.toml, registries/*.toml),
      transitive_workspace_crate_trees(crate),
      declared_external_includes(crate),
  )

Rules:
- Any change to Cargo.lock, rust-toolchain.toml, franken-stack.lock, deny.toml,
  or any registries/*.toml changes `global_invalidation_digest` and every
  candidate crate fingerprint.
- Any build.rs or include_str!/include_bytes! reading a path outside the crate's
  own directory or `registries/` is flagged `undeclared_external_read=True` and
  reported as an undeclared input. This scan is not a complete input manifest.
- These fingerprints do not authenticate execution, feature sets, test-target
  inventories, or every external input. No result is a verification verdict.
- Earlier versions invented PASS for fresh inputs and trusted unauthenticated
  JSON stores. They must not authorize reuse. Until actual execution evidence is
  bound and verified, every status is UNRUN and the command exits 2. Existing
  stores and notes are left untouched.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path


GLOBAL_FILES = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "franken-stack.lock",
    "deny.toml",
]

INCLUDE_RE = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)')


def sha256_domain(domain: bytes, parts: list[bytes]) -> str:
    h = hashlib.sha256()
    h.update(domain)
    h.update(b"\x00")
    for p in parts:
        h.update(len(p).to_bytes(8, "little"))
        h.update(p)
    return h.hexdigest()


def git_tree_hash(repo: Path, rev: str = "HEAD") -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", f"{rev}^{{tree}}"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).strip()
    except Exception:
        return "unknown"


def hash_file_bytes(path: Path) -> bytes:
    if not path.is_file():
        return b"MISSING"
    return hashlib.sha256(path.read_bytes()).digest()


def hash_directory_tree(root: Path) -> str:
    entries: list[bytes] = []
    if not root.exists():
        return sha256_domain(b"fa:dir-tree:v1", [])
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ("target", ".git"))
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if fpath.is_symlink() or not fpath.is_file():
                continue
            rel = fpath.relative_to(root).as_posix().encode("utf-8")
            fhash = hashlib.sha256(fpath.read_bytes()).hexdigest().encode("ascii")
            entries.append(rel + b":" + fhash)
    return sha256_domain(b"fa:dir-tree:v1", entries)


def compute_global_invalidation_digest(repo: Path) -> str:
    parts: list[bytes] = []
    for rel in GLOBAL_FILES:
        p = repo / rel
        parts.append(rel.encode("utf-8") + b":" + hash_file_bytes(p))
    reg_dir = repo / "registries"
    if reg_dir.is_dir():
        for dirpath, dirnames, filenames in os.walk(reg_dir):
            dirnames[:] = sorted(dirnames)
            for fname in sorted(filenames):
                if fname.endswith(".toml") or fname.endswith(".jsonl"):
                    fpath = Path(dirpath) / fname
                    rel = fpath.relative_to(repo).as_posix()
                    parts.append(rel.encode("utf-8") + b":" + hash_file_bytes(fpath))
    return sha256_domain(b"fa:global-inputs:v1", parts)


def discover_workspace_crates(repo: Path) -> dict[str, dict]:
    root_toml_path = repo / "Cargo.toml"
    data = tomllib.loads(root_toml_path.read_text(encoding="utf-8"))
    members = data.get("workspace", {}).get("members", [])
    crates: dict[str, dict] = {}
    for member in sorted(members):
        crate_dir = repo / member
        manifest_path = crate_dir / "Cargo.toml"
        if not manifest_path.is_file():
            continue
        c_toml = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        pkg_name = c_toml.get("package", {}).get("name", Path(member).name)
        deps: set[str] = set()
        for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
            for dep_name in c_toml.get(sec, {}).keys():
                deps.add(dep_name)
        crates[pkg_name] = {
            "name": pkg_name,
            "rel_path": member,
            "dir": crate_dir,
            "raw_deps": sorted(deps),
        }
    # Filter raw_deps to workspace-internal crates only
    ws_names = set(crates.keys())
    for info in crates.values():
        info["ws_deps"] = sorted(d for d in info["raw_deps"] if d in ws_names and d != info["name"])
    return crates


def transitive_ws_closure(crates: dict[str, dict], start: str) -> list[str]:
    visited: set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur in visited or cur not in crates:
            continue
        visited.add(cur)
        for dep in crates[cur]["ws_deps"]:
            if dep not in visited:
                stack.append(dep)
    return sorted(visited)


def inspect_external_reads(repo: Path, crate_dir: Path) -> tuple[bool, list[str]]:
    """Scan crate .rs files and build.rs for external reads outside crate_dir and registries/."""
    undeclared = False
    reasons: list[str] = []
    if (crate_dir / "build.rs").is_file():
        undeclared = True
        reasons.append("build.rs present without input manifest")
    reg_root = (repo / "registries").resolve()
    crate_root = crate_dir.resolve()
    for dirpath, dirnames, filenames in os.walk(crate_dir):
        dirnames[:] = sorted(d for d in dirnames if d != "target")
        for fname in sorted(filenames):
            if not fname.endswith(".rs"):
                continue
            fpath = Path(dirpath) / fname
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for m in INCLUDE_RE.finditer(text):
                raw_target = m.group(1)
                resolved = (fpath.parent / raw_target).resolve()
                in_crate = resolved == crate_root or crate_root in resolved.parents
                in_reg = resolved == reg_root or reg_root in resolved.parents
                if not (in_crate or in_reg):
                    undeclared = True
                    reasons.append(f"undeclared external include: {raw_target}")
    return undeclared, reasons


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256_domain(b"fa:input-fingerprint-merkle-empty:v1", [])
    layer = [bytes.fromhex(x) for x in leaves]
    while len(layer) > 1:
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                combined = sha256_domain(b"fa:input-fingerprint-merkle-node:v1", [layer[i], layer[i + 1]])
            else:
                combined = sha256_domain(b"fa:input-fingerprint-merkle-odd:v1", [layer[i]])
            next_layer.append(bytes.fromhex(combined))
        layer = next_layer
    return layer[0].hex()


def evaluate_workspace(repo: Path) -> dict:
    tree_sha = git_tree_hash(repo)
    global_digest = compute_global_invalidation_digest(repo)
    crates = discover_workspace_crates(repo)

    per_crate_tree_hashes: dict[str, str] = {}
    for name, info in sorted(crates.items()):
        per_crate_tree_hashes[name] = hash_directory_tree(info["dir"])

    crate_records: list[dict] = []
    for name in sorted(crates.keys()):
        info = crates[name]
        closure = transitive_ws_closure(crates, name)
        undeclared, undeclared_reasons = inspect_external_reads(repo, info["dir"])
        closure_parts = [
            b"global:" + global_digest.encode("ascii"),
            b"crate:" + name.encode("utf-8"),
        ]
        for dep_name in closure:
            closure_parts.append(
                dep_name.encode("utf-8") + b"=" + per_crate_tree_hashes[dep_name].encode("ascii")
            )
        input_hash = sha256_domain(b"fa:crate-input-fingerprint:v1", closure_parts)

        # Hashing inputs is not evidence that any check executed. In particular,
        # a cache's self-asserted PASS cannot establish a verdict for this hash.
        leaf_digest = sha256_domain(
            b"fa:crate-input-fingerprint-leaf:v1",
            [
                name.encode("utf-8"),
                input_hash.encode("ascii"),
            ],
        )
        crate_records.append({
            "crate": name,
            "rel_path": info["rel_path"],
            "transitive_closure": closure,
            "input_hash": input_hash,
            "status": "UNRUN",
            "reused": False,
            "reused_from_tree": None,
            "undeclared_external_read": undeclared,
            "undeclared_reasons": undeclared_reasons,
            "leaf_digest": leaf_digest,
        })

    # Report the actual planned step names, without inventing their outcomes.
    workspace_steps: list[dict] = []
    check_script = repo / "scripts/check.sh"
    if check_script.is_file():
        for line in check_script.read_text(encoding="utf-8").splitlines():
            if line.startswith("# CANONICAL_STEPS:"):
                workspace_steps = [
                    {"step": name.strip(), "status": "UNRUN"}
                    for name in line.split(":", 1)[1].split(",")
                    if name.strip()
                ]
                break
    ws_leaves: list[str] = []
    for step in sorted(workspace_steps, key=lambda s: s["step"]):
        ws_leaf = sha256_domain(
            b"fa:planned-ws-step-leaf:v1",
            [
                step["step"].encode("utf-8"),
                step["status"].encode("ascii"),
                tree_sha.encode("ascii"),
            ],
        )
        ws_leaves.append(ws_leaf)

    all_leaves = ws_leaves + [c["leaf_digest"] for c in crate_records]
    root_hash = merkle_root(all_leaves)
    total_crates = len(crate_records)
    return {
        "schema": "fa:crate-verdicts-manifest:v2",
        "scope": "input_fingerprints_only",
        "status": "UNRUN",
        "checks_executed": False,
        "tree_hash": tree_sha,
        "global_invalidation_digest": global_digest,
        "total_crates": total_crates,
        "reused_crates": 0,
        "fingerprint_root": root_hash,
        "workspace_steps": workspace_steps,
        "crates": crate_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute candidate input fingerprints; no checks run and no verdict is reused (fa-xrl)"
    )
    parser.add_argument("--repo", default=".", help="Workspace repository root")
    parser.add_argument("--output", required=True, help="Output manifest JSON path")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    out_path = Path(args.output).resolve()

    manifest = evaluate_workspace(repo)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out_path.open("x", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
    except FileExistsError:
        print("UNRUN crate-verdicts: output already exists; choose an unused path", file=sys.stderr)
        return 2
    print(
        f"UNRUN crate-verdicts input_fingerprints_only crates={manifest['total_crates']} "
        f"fingerprint_root={manifest['fingerprint_root']}; no checks executed or verdicts reused"
    )
    print(f"output={json.dumps(str(out_path))}")
    print("fix_hint=run bash scripts/local_proof.sh for execution-bound verification")
    return 2


if __name__ == "__main__":
    sys.exit(main())
