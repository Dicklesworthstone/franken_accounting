#!/usr/bin/env python3
"""Qualify G1 from a completed, independently verified exact-revision proof.

Run after scripts/local_proof.sh, never from inside the proof being evaluated:
    python3 -B scripts/g1_release_check.py --proof /path/to/proof --json

The existing format-v3 verifier remains the authority for proof integrity and
full-gate execution. This consumer adds the G1-specific acceptance inventory and
the fixed 50-seed campaign witness. It does not run Rust, rewrite the scoreboard,
close beads, publish a release, or authenticate the identity of a proof producer.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts/local_proof_verify.sh"
SCOREBOARD_TEST = (
    "fa-cli", "scoreboard",
    "vision_workflows_and_gate_criteria_match_declared_scoreboard_in_both_directions",
)
CRASH_TESTS = (
    ("fa", "lib", "book::tests::a_post_crashed_at_every_commit_point_is_whole_or_absent_after_reopen"),
    ("fa", "lib", "book::tests::a_batch_crashed_at_every_commit_point_is_all_or_none_after_reopen"),
)
HISTORY_TESTS = (
    ("fa-registers", "differential", "multi_seed_campaign_tier1"),
    ("fa-registers", "differential", "planted_mutation_found_and_shrunk"),
    ("fa-registers", "differential", "serial_replay_refuses_a_history_the_reference_would_not_admit"),
)
G1_IDS = tuple(f"G1-{n:02}" for n in range(1, 8))
JOB = re.compile(r"^==== test job ([A-Za-z0-9_.-]+): cargo test (.+) \(exit ([0-9]+)\)$")
RUN = re.compile(r"^\s*Running\s+(?:(unittests)\s+)?(\S+)\s+\(([^)]+)\)\s*$")
TEST = re.compile(
    r"^test (\S+)( - should panic)? \.\.\. (ok|FAILED|ignored(?:, .*?)?)$"
)
COHORT = re.compile(
    r"^G1-05 tier1: seed_from=(\d+) seed_count=(\d+) histories=(\d+) "
    r"steps_per_history=(\d+) race_histories=(\d+) races=(\d+) "
    r"coverage_cells=(\d+) serial_replayed=(\d+)$"
)


class QualificationError(ValueError):
    """Missing or contradictory evidence; never a qualifying verdict."""


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    require(result.returncode == 0,
            f"command failed ({result.returncode}): {' '.join(map(str, command))}\n"
            + result.stderr.strip())
    return result.stdout


def git(repository, *args):
    return run(["git", "-C", str(repository), *args]).strip()


def fields(text):
    result = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        require(name not in result, f"duplicate field {name}")
        result[name] = value
    return result


def strict_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"duplicate JSON field {name}")
        result[name] = value
    return result


def checksum_inventory(raw):
    inventory = {}
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](\./.+)", line)
        require(match is not None, "malformed proof checksum inventory")
        digest, path = match.groups()
        require(path not in inventory, f"duplicate proof checksum path {path}")
        inventory[path] = digest.lower()
    return inventory


def read_bound(proof, relative, inventory):
    """Return one byte snapshot only after checking its verified checksum."""
    key = "./" + relative
    require(key in inventory, f"unbound proof file {relative}")
    data = (proof / relative).read_bytes()
    require(hashlib.sha256(data).hexdigest() == inventory[key],
            f"proof file changed after verification: {relative}")
    return data


def package_from_args(arguments):
    args = shlex.split(arguments)
    packages = []
    for index, arg in enumerate(args):
        if arg in ("-p", "--package"):
            require(index + 1 < len(args), "test job has an incomplete package argument")
            packages.append(args[index + 1])
        elif arg.startswith("--package="):
            packages.append(arg.partition("=")[2])
    require(len(packages) == 1 and re.fullmatch(r"[A-Za-z0-9_-]+", packages[0]),
            "test job lacks one explicit package")
    return packages[0]


def test_sections(text):
    """Keep package, target, and completed RCH job provenance together.

    Unqualified names and arbitrary PASS lines cannot impersonate Rust tests.
    An earlier unrun offloader attempt contributes no acceptance evidence.
    """
    jobs = []
    current = None
    for line in text.splitlines():
        if line.startswith("==== test job "):
            current = None
            match = JOB.fullmatch(line)
            if match:
                label, arguments, status = match.groups()
                package = package_from_args(arguments)
                require(label == package or label.startswith(package + "."),
                        "test job label/package mismatch")
                current = {"package": package, "label": label, "status": int(status), "lines": []}
                jobs.append(current)
        elif current is not None:
            current["lines"].append(line)
    require(jobs, "test transcript has no package-qualified completed jobs")

    sections = []
    for job in jobs:
        joined = "\n".join(job["lines"])
        completions = re.findall(r"Remote command finished: exit=([0-9]+)", joined)
        require(job["status"] == 0 and completions and set(completions) == {"0"},
                f"{job['label']}: missing successful remote completion")
        section = None
        for line in job["lines"]:
            match = RUN.fullmatch(line)
            if match:
                unit, path, _ = match.groups()
                target = None
                if unit and (path == "src/lib.rs" or path.endswith("/src/lib.rs")):
                    target = "lib"
                elif not unit:
                    named = re.search(r"(?:^|/)tests/([A-Za-z0-9_-]+)(?:\.rs|/main\.rs)$", path)
                    if named:
                        target = named.group(1)
                section = {"package": job["package"], "target": target, "job": job["label"],
                           "tests": [], "lines": []}
                sections.append(section)
                continue
            if re.match(r"^\s*Doc-tests\s", line):
                section = None
            if section is not None:
                section["lines"].append(line)
                match = TEST.fullmatch(line)
                if match:
                    name, should_panic, outcome = match.groups()
                    section["tests"].append((name, outcome, bool(should_panic)))
    return sections


def qualified(selector):
    return "::".join(selector)


def require_test(sections, selector):
    package, target, name = selector
    found = [
        (section, outcome, should_panic)
        for section in sections
        if (section["package"], section["target"]) == (package, target)
        for test, outcome, should_panic in section["tests"] if test == name
    ]
    require(len(found) == 1, f"{qualified(selector)}: expected one executed acceptance test")
    section, outcome, should_panic = found[0]
    require(outcome == "ok" and not should_panic,
            f"{qualified(selector)}: acceptance test did not pass normally ({outcome})")
    return section


def require_cohort(section):
    candidates = [line for line in section["lines"] if line.startswith("G1-05 tier1:")]
    require(len(candidates) == 1, "G1-05 requires one retained tier-1 campaign witness")
    match = COHORT.fullmatch(candidates[0])
    require(match is not None, "G1-05 campaign witness is malformed")
    values = tuple(map(int, match.groups()))
    require(values[:6] == (1, 50, 50, 640, 50, 2000),
            "G1-05 requires canonical 50 histories, 50 race histories, and 2000 races")
    require(values[6] > 0 and values[7] > 0,
            "G1-05 campaign lacks coverage or serial-replay evidence")
    return dict(zip(("seed_from", "seed_count", "histories", "steps_per_history",
                     "race_histories", "races", "coverage_cells", "serial_replayed"), values))


def g1_rows(repository, commit):
    source = git(repository, "show", f"{commit}:registries/scoreboard.toml")
    rows = [row for row in tomllib.loads(source).get("gate_criterion", [])
            if row.get("gate") == "G1"]
    require([row.get("id") for row in rows] == list(G1_IDS),
            "candidate scoreboard must contain exactly the seven ordered G1 criteria")
    for row in rows:
        criterion = row.get("id")
        require(isinstance(row.get("criterion"), str) and row["criterion"].strip(),
                f"{criterion}: missing criterion")
        if criterion not in ("G1-04", "G1-05"):
            require(row.get("expected") == "works" and row.get("expected_exit") == 0,
                    f"{criterion}: the candidate no longer declares this criterion working")
    for index, text, evidence in (
        (3, "idempotency and batches under crash", "lab-campaign"),
        (4, "the reference differential over model-generated histories", "differential"),
    ):
        row = rows[index]
        require(row["criterion"] == text and row.get("evidence_class") == evidence
                and row.get("probe_kind") == evidence,
                f"{row['id']}: criterion text or evidence class changed")
    return rows


def qualify(repository, proof, revision=None):
    repository, proof = Path(repository).resolve(), Path(proof).resolve()
    selected = revision or "HEAD"
    commit = git(repository, "rev-parse", "--verify", "--end-of-options", selected + "^{commit}")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid selected commit")
    tree = git(repository, "rev-parse", "--verify", commit + "^{tree}")
    if revision is None:
        require(not git(repository, "status", "--porcelain=v1", "--untracked-files=all"),
                "current-revision qualification requires a clean worktree; "
                "use --revision only to assess an explicitly named committed revision")

    sums = (proof / "SHA256SUMS").read_bytes()
    verified = run(["bash", str(VERIFIER), "--repository", str(repository),
                    "--for-close", str(proof)])
    require(verified.splitlines().count("LOCAL_PROOF_VERIFIED") == 1,
            "local proof verifier did not return its positive completion")
    verdict = fields(verified)
    require(verdict.get("scope") == "full" and verdict.get("verdict") == "pass"
            and verdict.get("tree_stable") == "true" and verdict.get("check_exit") == "0",
            "G1 qualification requires a stable full-gate PASS")
    require(verdict.get("commit") == commit and verdict.get("tree") == tree,
            "proof does not qualify the independently selected revision")
    require((proof / "SHA256SUMS").read_bytes() == sums,
            "proof checksum inventory changed during verification")
    inventory = checksum_inventory(sums)
    manifest = fields(read_bound(proof, "manifest.txt", inventory).decode("utf-8"))
    require(manifest.get("format_version") == "3" and manifest.get("commit") == commit
            and manifest.get("tree") == tree, "verified manifest identity changed")
    records = [json.loads(line, object_pairs_hook=strict_object)
               for line in read_bound(proof, "step-verdicts.jsonl", inventory).decode("utf-8").splitlines()]
    test = [record for record in records if record.get("step") == "test"]
    require(len(test) == 1 and test[0].get("status") == "PASS", "missing executed test step")
    log = read_bound(proof, "steps/test.log", inventory)
    require(hashlib.sha256(log).hexdigest() == test[0].get("log_digest"),
            "test log differs from its verified step")
    sections = test_sections(log.decode("utf-8"))
    require_test(sections, SCOREBOARD_TEST)
    for selector in (*CRASH_TESTS, *HISTORY_TESTS):
        require_test(sections, selector)
    cohort = require_cohort(require_test(sections, HISTORY_TESTS[0]))
    rows = g1_rows(repository, commit)
    require(git(repository, "rev-parse", "--verify", "--end-of-options",
                selected + "^{commit}") == commit, "selected revision moved during qualification")
    if revision is None:
        require(not git(repository, "status", "--porcelain=v1", "--untracked-files=all"),
                "worktree changed during qualification")
    return {
        "gate": "G1",
        "verdict": "PASS",
        "commit": commit,
        "tree": tree,
        "proof": str(proof),
        "proof_sums_sha256": hashlib.sha256(sums).hexdigest(),
        "criteria": [
            {"id": row["id"], "criterion": row["criterion"], "verdict": "PASS",
             "tests": [qualified(test) for test in (
                 CRASH_TESTS if row["id"] == "G1-04" else
                 HISTORY_TESTS if row["id"] == "G1-05" else (SCOREBOARD_TEST,)
             )]} for row in rows
        ],
        "history_campaign": cohort,
        "scope": "G1 on the named committed revision; no G2-G4, full fa-nl7/fa-2ihd "
                 "bead closure, or proof-producer identity claim",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--proof", type=Path, required=True, help="completed retained v3 proof directory")
    parser.add_argument("--revision", help="explicit committed revision; defaults to clean HEAD")
    parser.add_argument("--json", action="store_true", help="emit the qualification report as JSON")
    args = parser.parse_args(argv)
    try:
        report = qualify(args.repository, args.proof, args.revision)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        if args.json:
            print(json.dumps({"gate": "G1", "verdict": "UNMET", "reason": str(error)}, sort_keys=True))
        else:
            print(f"G1 UNMET: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"G1 PASS commit={report['commit']} tree={report['tree']}")
        for row in report["criteria"]:
            print(f"PASS {row['id']} {row['criterion']}")
        print(f"proof_sums_sha256={report['proof_sums_sha256']}")
        print(report["scope"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

