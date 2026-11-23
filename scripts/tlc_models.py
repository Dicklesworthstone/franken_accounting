#!/usr/bin/env python3
"""Execute the bounded accounting models and retain TLC's search or counterexample."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

MODELS = Path(__file__).resolve().parents[1] / "formal" / "tla"

# Each guard is removed from a private copy of its action. The original
# configuration, including every invariant and the deadlock check, still runs.
CONTROLS = {
    "CloseDagUnderCrashes": (r"Prereqs(t) \subseteq completedTasks", "DagOrderRespected"),
    "DraftPromotionMovingTrunk": ('draftApprovedBy = "human_approver"', "AgentNeverPromotesToTrunk"),
    "MergeTrain": (r"c \notin RedCandidates", "LandedCandidatesWereGatedGreen"),
    "RestatementLifecycle": ("p # preparer", "DualControlEnforced"),
    "TwoPhaseWithExpiry": (None, "SingleResolutionPerHold"),
}
HOLD_CONTROL = "TwoPhaseMissingIdentityGuard"
COUNTS = re.compile(r"^(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue\.$", re.M)
DEPTH = re.compile(r"^The depth of the complete state graph search is (\d+)\.$", re.M)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(jar, directory, model, negative):
    guard, invariant = CONTROLS[model]
    module = HOLD_CONTROL if negative and guard is None else model
    case = directory / (model + ("-negative" if negative else "-positive"))
    case.mkdir()
    source = case / (module + ".tla")
    shutil.copyfile(MODELS / source.name, source)
    base_hash = sha256(MODELS / (model + ".tla"))
    if negative and guard is None:
        shutil.copyfile(MODELS / (model + ".tla"), case / (model + ".tla"))
    elif negative:
        text = source.read_text()
        original = "  /\\ " + guard + "\n"
        if text.count(original) != 1:
            raise ValueError(f"{model} expected one action guard {guard!r}")
        source.write_text(text.replace(original, "  /\\ TRUE\n"))

    config = case / (module + ".cfg")
    shutil.copyfile(MODELS / config.name, config)
    command = ["java", "-Xmx384m", "-XX:+UseSerialGC", "-cp", str(jar), "tlc2.TLC",
               "-workers", "1", "-seed", "20261122", "-config", config.name, source.name]
    log = case / "tlc.log"
    with log.open("xb") as stream:
        run = subprocess.run(command, cwd=case, stdout=stream, stderr=subprocess.STDOUT,
                             timeout=120, check=False)
    output = log.read_text()
    counts = COUNTS.search(output)
    if not counts:
        raise ValueError(f"{module} did not report its state counts (exit {run.returncode}, {log})")
    generated, distinct, queued = map(int, counts.groups())
    if not 0 < distinct <= generated:
        raise ValueError(f"{module} returned inconsistent state counts in {log}")
    record = dict(module=module, base_spec_sha256=base_hash, spec_sha256=sha256(source),
                  cfg_sha256=sha256(config), log_sha256=sha256(log), command=command,
                  tlc_version=output.splitlines()[0], exit_code=run.returncode,
                  states_generated=generated, distinct_states=distinct, states_left=queued)
    if negative:
        violation = re.findall(r"^Error: Invariant (\w+) is violated\.$", output, re.M)
        trace = re.findall(r"^State (\d+): <", output, re.M)
        if run.returncode != 12 or violation != [invariant] or len(trace) < 2:
            raise ValueError(f"{module} did not produce a counterexample to {invariant} ({log})")
        record.update(result="counterexample", invariant=invariant, trace_states=len(trace))
    else:
        depth = DEPTH.search(output)
        complete = "Model checking completed. No error has been found." in output
        if run.returncode or queued or not complete or not depth or int(depth[1]) < 1:
            raise ValueError(f"{module} did not exhaust its bounded state space ({log})")
        record.update(result="pass", depth=int(depth[1]))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-only", action="store_true")
    args = parser.parse_args()
    jar = Path(os.environ.get("TLA2TOOLS_JAR", "")).expanduser().resolve()
    if not jar.is_file() or not shutil.which("java"):
        print("UNRUN tlc-models requires Java and TLA2TOOLS_JAR pointing to tla2tools.jar")
        print("FAIL tlc-models could not start the model checker")
        return 3
    configs = {p.stem for p in MODELS.glob("*.cfg")}
    sources = {p.stem for p in MODELS.glob("*.tla")}
    if configs != set(CONTROLS) | {HOLD_CONTROL} or configs != sources:
        raise ValueError("each TLA module must have a configuration and belong to the campaign")
    parent = Path(os.environ.get("CHECK_LOG_DIR", tempfile.gettempdir()))
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="fa-tlc-", dir=parent))
    print(f"TLC transcripts and counts in {output}", flush=True)
    results = []
    for model in CONTROLS:
        for negative in ([True] if args.negative_only else [False, True]):
            results.append(execute(jar, output, model, negative))
    summary = {"scope": "bounded TLA+ specifications", "jar_sha256": sha256(jar), "runs": results}
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS scripts/tests/tlc_selftest.sh::planted_variants_fail ({len(CONTROLS)} named counterexamples)")
    if not args.negative_only:
        print(f"PASS scripts/check.sh::tlc-models ({len(CONTROLS)} complete state spaces)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"FAIL tlc-models {error}")
        sys.exit(1)
