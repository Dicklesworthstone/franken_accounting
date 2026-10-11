#!/usr/bin/env python3
"""Planted defects + actual Cargo feature-isolation probe; no compilation.

Usage: foundation_negative.py <real-receipts-dir> <new-output-dir>
All specimens and transcripts are retained. No gate or source is weakened.
"""

import copy
import importlib.util
import json
import subprocess
import sys
import tomllib
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("foundation_check", ROOT / "scripts/foundation_check.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def main():
    if len(sys.argv) != 3:
        print("FAIL foundation-negative — usage: foundation_negative.py <receipts> <new-output-dir>")
        return 1
    receipts, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    policy = tomllib.loads((ROOT / "franken-stack.lock").read_text())
    locked = tomllib.loads((ROOT / "Cargo.lock").read_text())
    metadata = json.loads((receipts / "metadata.json").read_text())
    trees = {p: (receipts / (p + ".tree")).read_text() for p in policy["production_gate"]["postures"]}
    passed = 0
    failed = 0

    def verdict(name, good, detail):
        nonlocal passed, failed
        if good:
            passed += 1
            print(f"PASS foundation-negative — {name}: {detail}")
        else:
            failed += 1
            print(f"FAIL foundation-negative — {name}: {detail}")

    def case(name, meta, variants, needle):
        directory = output / name
        directory.mkdir()
        (directory / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
        for p, tree in variants.items():
            (directory / (p + ".tree")).write_text(tree)
        try:
            errors, _ = CHECK.check(policy, meta, locked, variants)
        except CHECK.Invalid as error:
            errors = [str(error)]
        (directory / "verdict.txt").write_text("\n".join(errors) + "\n")
        good = not errors if needle is None else any(needle in e for e in errors)
        verdict(name, good, "real graph passes" if needle is None and good else str(errors))

    case("positive", metadata, trees, None)
    for name in ("asupersync", "fgdb-types"):
        meta, variants = copy.deepcopy(metadata), dict(trees)
        original = next(p for p in meta["packages"] if p["name"] == name)
        duplicate = copy.deepcopy(original)
        duplicate["source"] = "registry+https://github.com/rust-lang/crates.io-index"
        duplicate["id"] = duplicate["source"] + "#" + name + "@" + duplicate["version"]
        meta["packages"].append(duplicate)
        meta["resolve"]["nodes"].append({"id": duplicate["id"], "deps": [], "features": []})
        variants["fa"] += CHECK.display(duplicate) + "|\n"
        case("duplicate-" + name, meta, variants, f"fa: {name} requires one package ID, found 2")

    meta, variants = copy.deepcopy(metadata), dict(trees)
    package = next(p for p in meta["packages"] if p["name"] == "fgdb-types")
    previous = CHECK.display(package)
    origin, _ = package["source"].rsplit("#", 1)
    package["source"] = origin + "#" + "a" * 40
    for posture in variants:
        variants[posture] = variants[posture].replace(previous + "|", CHECK.display(package) + "|")
    case("source-pin-drift", meta, variants, "fgdb-types: source pin drift")

    variants = dict(trees)
    runtime = next(p for p in metadata["packages"] if p["name"] == "asupersync")
    variants["fa"] = variants["fa"].replace(CHECK.display(runtime) + "|", CHECK.display(runtime) + "|tls", 1)
    case("embedded-feature-drift", metadata, variants, "fa: asupersync feature drift")

    variants = dict(trees)
    mcp = next(p for p in metadata["packages"] if p["name"] == "fastmcp-rust")
    variants["fa"] += CHECK.display(mcp) + "|\n"
    case("mcp-confinement", metadata, variants, "violates foundation posture confinement")

    variants = dict(trees)
    sim = next(p for p in metadata["packages"] if p["name"] == "fgdb-sim")
    variants["fa"] += CHECK.display(sim) + "|\n"
    case("dev-package-leak", metadata, variants, "test-only package fgdb-sim")
    variants = dict(trees)
    variants["fa"] = ""
    case("empty-tree", metadata, variants, "missing/wrong tree root")
    variants = dict(trees)
    variants["fa"] += "unexpected Cargo output\n"
    case("malformed-tree", metadata, variants, "expected package|features")

    # A real resolver-3 workspace: another selected member and dev features
    # must not leak into client; host build features stay a separate occurrence.
    fixture = output / "cargo-feature-isolation"
    fixture.mkdir()
    (fixture / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["client", "other", "dep"]\n')
    common = 'dep = { path = "../dep", default-features = false, features = ["%s"] }\n'
    manifests = {
        "dep": '[features]\nbase = []\ndev = []\nother = []\nbuild = []\n',
        "client": '[dependencies]\n' + common % "base" + '[dev-dependencies]\n' + common % "dev" + '[build-dependencies]\n' + common % "build",
        "other": '[dependencies]\n' + common % "other",
    }
    for name, dependencies in manifests.items():
        directory = fixture / name
        (directory / "src").mkdir(parents=True)
        (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.0.1"\nedition = "2024"\n' + dependencies)
        (directory / "src/lib.rs").write_text("// Resolver fixture only; never compiled.\n")
    (fixture / "client/build.rs").write_text("fn main() {}\n")

    def cargo(label, *args):
        result = subprocess.run(["cargo", *args], cwd=fixture, text=True, capture_output=True,
                                check=False, timeout=60)
        (fixture / (label + ".stdout")).write_text(result.stdout)
        (fixture / (label + ".stderr")).write_text(result.stderr)
        if result.returncode:
            raise CHECK.Invalid(f"Cargo probe {label} did not resolve (exit {result.returncode}); see {fixture}")
        return result.stdout

    # metadata creates this fixture's lock; subsequent tree commands are locked.
    resolved = json.loads(cargo("metadata", "metadata", "--offline", "--format-version", "1"))
    package_map = {p["id"]: p for p in resolved["packages"]}
    for posture, edge_kinds, expected in [
        ("client", "normal,build", {frozenset({"base"}), frozenset({"build"})}),
        ("other", "normal,build", {frozenset({"other"})}),
        ("client", "normal,build,dev", {frozenset({"base", "dev"}), frozenset({"build"})}),
    ]:
        label = posture + "-" + edge_kinds.replace(",", "-")
        text = cargo(label, "tree", "--locked", "--offline", "-p", posture, "--edges", edge_kinds,
                     "--prefix", "none", "--color", "never", "--format", "{p}|{f}")
        actual = {frozenset(features) for pid, features in CHECK.read_tree(text, package_map, posture)
                  if package_map[pid]["name"] == "dep"}
        verdict(label, actual == expected, f"observed feature contexts {sorted(map(sorted, actual))}")
    print(f"foundation-negative: {passed} passed, {failed} failed, 0 unrun")
    return int(bool(failed))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL foundation-negative — incomplete evidence: {error}")
        print("foundation-negative: 0 passed, 1 failed, 0 unrun")
        sys.exit(1)
