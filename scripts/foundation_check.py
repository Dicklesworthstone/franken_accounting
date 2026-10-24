#!/usr/bin/env python3
"""Check resolved foundation identities and per-posture production features.

Metadata supplies opaque package IDs/source revisions, NEVER posture features:
its resolve.nodes features can unify other workspace members and dev edges.
Separate cargo tree -p POSTURE -e normal,build outputs supply feature contexts.
Host/build occurrences of one package may have different feature sets; judge
each, not a fabricated union. This is a current-host/default-feature resolution
gate, not a compiler unit graph or a claim about other targets/configurations.
See https://doc.rust-lang.org/cargo/commands/cargo-tree.html#feature-unification.
Only Python's standard library is used. Inputs/receipts are retained by caller.
"""

import fnmatch
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class Invalid(ValueError):
    """Malformed/ambiguous evidence must never yield a green empty graph."""


def repository(source):
    """Cargo considers a trailing .git equivalent for these admitted URLs."""
    return source.split("?", 1)[0].split("#", 1)[0].removesuffix(".git")


def display(package):
    """Cargo tree's {p}; exact-match to metadata, never infer an ID by name."""
    text = package["name"] + " v" + package["version"]
    if any("proc-macro" in t["kind"] for t in package["targets"]):
        text += " (proc-macro)"
    source = package["source"]
    if source is None:
        text += " (" + str(Path(package["manifest_path"]).parent) + ")"
    elif source.startswith("git+"):
        origin, commit = source.removeprefix("git+").rsplit("#", 1)
        text += " (" + origin + "#" + commit[:8] + ")"
    elif source != "registry+https://github.com/rust-lang/crates.io-index":
        # Fail closed for other registries until their display is supported.
        raise Invalid("unsupported registry source: " + source)
    return text


def read_tree(text, packages, posture):
    rendered = {}
    for p in packages.values():
        rendered.setdefault(display(p), []).append(p["id"])
    nodes = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw or raw == "[build-dependencies]":
            continue
        line = raw.removesuffix(" (*)")
        if line.count("|") != 1:
            raise Invalid(f"{posture} tree line {number}: expected package|features")
        name, feature_text = line.split("|")
        ids = rendered.get(name, [])
        if len(ids) != 1:
            raise Invalid(f"{posture}: tree package {name!r} matches {len(ids)} metadata IDs")
        features = feature_text.split(",") if feature_text else []
        if any(not re.fullmatch(r"[A-Za-z0-9_+./-]+", f) for f in features):
            raise Invalid(f"{posture}: malformed feature list {feature_text!r}")
        nodes.append((ids[0], set(features)))
    if not nodes or packages[nodes[0][0]]["name"] != posture:
        raise Invalid(f"{posture}: missing/wrong tree root")
    return nodes


def check(policy, metadata, cargo_lock, trees, license_policy):
    failures = []
    successes = []
    packages = {p["id"]: p for p in metadata["packages"]}
    if not packages or len(packages) != len(metadata["packages"]):
        raise Invalid("empty metadata or duplicate package IDs")
    members = set(metadata["workspace_members"])
    if not members or not members <= packages.keys() or metadata.get("resolve") is None:
        raise Invalid("metadata has no complete workspace/resolution")
    resolved_ids = [n["id"] for n in metadata["resolve"]["nodes"]]
    if not members <= set(resolved_ids) or len(resolved_ids) != len(set(resolved_ids)):
        raise Invalid("metadata has incomplete/duplicate resolution nodes")
    # cargo-deny verifies each clarification's actual license bytes. Check the
    # other direction here: a new first-party member must not silently lack
    # the exact-name policy for our inherited license and its existing rider.
    clarifications = license_policy["licenses"].get("clarify", [])
    exceptions = license_policy["licenses"].get("exceptions", [])
    for pid in sorted(members):
        member = packages[pid]
        identity = member["name"] + "@" + member["version"]
        matching = [row for row in clarifications if row["crate"] == identity]
        if len(matching) != 1:
            failures.append(f"{identity}: requires exactly one first-party license clarification, found {len(matching)}")
        elif matching[0]["expression"] != "LicenseRef-MIT-OpenAI-Anthropic-Rider":
            failures.append(f"{identity}: clarification must preserve the existing license and rider")
        admitted = [row for row in exceptions if row["crate"] == identity]
        if len(admitted) != 1 or admitted[0]["allow"] != ["LicenseRef-MIT-OpenAI-Anthropic-Rider"]:
            failures.append(f"{identity}: requires one exact exception for the existing license and rider")
    rules = policy["production_gate"]
    postures = rules["postures"]
    if set(trees) != set(postures) or len(postures) != len(set(postures)):
        raise Invalid("posture evidence does not match production_gate.postures")
    # A policy edit cannot accidentally omit one of the four promised postures.
    if set(postures) != {"fa", "fa-cli", "fad", "fa-mcp"}:
        raise Invalid("production gate must cover fa/fa-cli/fad/fa-mcp")
    if set(rules["required_singletons"]) != {"asupersync", "fgdb-types", "fnx-classes"}:
        raise Invalid("production gate must require all three shared type identities")
    foundations = policy["foundation"]
    lock_packages = cargo_lock["package"]
    owners = {}
    for pid, p in packages.items():
        matches = [f for f in foundations if any(
            fnmatch.fnmatchcase(p["name"], pattern) for pattern in f["package_patterns"]
        )]
        if not matches:
            # Every resolved git package needs a recorded foundation pin,
            # including a new suite project reached transitively. Adding an
            # eligible owner project adds its row; this is not a project cap.
            if p["source"] and p["source"].startswith("git+"):
                failures.append(f"unregistered foundation package {pid}")
            continue
        if len(matches) != 1:
            raise Invalid(f"{pid}: overlapping foundation policies")
        f = matches[0]
        owners[pid] = f
        source = p["source"]
        if source is None or repository(source) != repository(f["source"]):
            failures.append(f"{p['name']}: wrong foundation source {source!r}; expected {f['source']}")
        elif f["source"].startswith("git+"):
            parsed = urlsplit(source.removeprefix("git+"))
            if parse_qs(parsed.query) != {"rev": [f["rev"]]} or parsed.fragment != f["rev"]:
                failures.append(f"{p['name']}: source pin drift: {source}; expected rev {f['rev']}")
        wanted_version = re.match(r"=?([0-9]+\.[0-9]+\.[0-9]+)(?:$| )", f["version"])
        if not wanted_version:
            raise Invalid(f"{f['name']}: no exact version in foundation row")
        if p["version"] != wanted_version[1]:
            failures.append(f"{p['name']}: version {p['version']} differs from {wanted_version[1]}")
        locked = [x for x in lock_packages if (x["name"], x["version"], x.get("source"))
                  == (p["name"], p["version"], source)]
        if len(locked) != 1:
            failures.append(f"{p['name']}: resolved identity has no unique Cargo.lock entry")
        elif source and source.startswith("registry+"):
            checksum = locked[0].get("checksum", "")
            if not re.fullmatch(r"[0-9a-f]{64}", checksum):
                failures.append(f"{p['name']}: missing registry checksum")
            if p["name"] == f["name"] and checksum != f.get("checksum"):
                failures.append(f"{p['name']}: stack-lock checksum drift")
    # Preserve the direct-dependency boundary, checking resolved identity rather
    # than accepting any package named fa-* or any git source named fgdb-*.
    for node in metadata["resolve"]["nodes"]:
        if node["id"] not in members:
            continue
        for edge in node["deps"]:
            if not any(kind["kind"] in (None, "build") for kind in edge["dep_kinds"]):
                continue
            if edge["pkg"] not in members and edge["pkg"] not in owners:
                failures.append(f"direct dependency outside admitted foundations: {node['id']} -> {edge['pkg']}")
    for posture in postures:
        nodes = read_tree(trees[posture], packages, posture)
        ids = {pid for pid, _ in nodes}
        if not ids <= set(resolved_ids):
            failures.append(f"{posture}: tree contains IDs absent from metadata's resolution")
        if nodes[0][0] not in members:
            raise Invalid(f"{posture}: root is not a workspace member")
        for name in rules["required_singletons"]:
            found = sorted(pid for pid in ids if packages[pid]["name"] == name)
            if len(found) != 1:
                failures.append(f"{posture}: {name} requires one package ID, found {len(found)}: {found}")
        for pid, enabled in nodes:
            p = packages[pid]
            if p["name"] in rules["forbidden_packages"]:
                failures.append(f"{posture}: test-only package {p['name']} in production closure")
            if pid not in owners:
                continue
            f = owners[pid]
            if posture not in f["production_postures"]:
                failures.append(f"{posture}: {p['name']} violates foundation posture confinement")
            overrides = [r for r in policy.get("production_feature", [])
                         if p["name"] in r["packages"] and posture in r["postures"]]
            if len(overrides) > 1:
                raise Invalid(f"{posture}/{p['name']}: overlapping feature policies")
            allowed = set(overrides[0]["allowed"] if overrides else f["production_features"])
            if enabled - allowed:
                failures.append(f"{posture}: {p['name']} feature drift: {sorted(enabled - allowed)}; allowed {sorted(allowed)}")
        successes.append(f"{posture}: {len(ids & owners.keys())} foundation IDs checked; single shared type identities; production feature ceilings checked")
    return list(dict.fromkeys(failures)), successes


def main():
    if len(sys.argv) != 3:
        print("FAIL foundations: usage: foundation_check.py <repo-root> <receipts-dir>")
        return 1
    root, work = map(Path, sys.argv[1:])
    try:
        policy = tomllib.loads((root / "franken-stack.lock").read_text())
        metadata = json.loads((work / "metadata.json").read_text())
        cargo_lock = tomllib.loads((root / "Cargo.lock").read_text())
        license_policy = tomllib.loads((root / "deny.toml").read_text())
        trees = {p: (work / (p + ".tree")).read_text() for p in policy["production_gate"]["postures"]}
        failures, successes = check(policy, metadata, cargo_lock, trees, license_policy)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL foundations — invalid/incomplete evidence: {error}")
        print("foundations: 0 passed, 1 failed, 0 unrun")
        return 1
    if failures:
        for failure in failures:
            print("FAIL foundations — " + failure)
    else:
        for success in successes:
            print("PASS foundations — " + success)
    print(f"foundations: {0 if failures else len(successes)} passed, {len(failures)} failed, 0 unrun")
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
