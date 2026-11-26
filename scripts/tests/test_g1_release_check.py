"""G1 consumer controls over real Git objects and synthetic v3 proof bundles.

The production proof verifier runs in every end-to-end case. Synthetic Cargo
logs exercise its transport/qualification contract; they never establish a
native accounting, crash, differential, or release PASS. Fixtures are retained
under the temporary directory for inspection.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import g1_release_check as g1


WITNESS = (
    "G1-05 tier1: seed_from=1 seed_count=50 histories=50 steps_per_history=640 "
    "race_histories=50 races=2000 coverage_cells=147 serial_replayed=6000"
)


def section(package, target, names, *, label=None, witness=None):
    label = label or f"{package}.{'lib' if target == 'lib' else 'test.' + target}"
    selector = "--lib" if target == "lib" else f"--test {target}"
    path = "unittests src/lib.rs" if target == "lib" else f"tests/{target}.rs"
    lines = [
        f"==== test job {label}: cargo test -p {package} {selector} (exit 0)",
        f"     Running {path} (target/debug/deps/{package.replace('-', '_')}-0123456789abcdef)",
        f"running {len(names)} test" + ("s" if len(names) != 1 else ""),
    ]
    if witness is not None:
        lines.append(witness)
    lines.extend(f"test {name} ... ok" for name in names)
    lines.extend([
        f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        "Remote command finished: exit=0",
        "[RCH] remote fixture-worker (1s)",
    ])
    return "\n".join(lines) + "\n"


def passing_log():
    return (
        section("fa", "lib", [selector[2] for selector in g1.CRASH_TESTS])
        + section("fa-registers", "differential", [g1.HISTORY_TESTS[0][2]],
                  label="fa-registers.test.differential.isolated.multi_seed_campaign_tier1",
                  witness=WITNESS)
        + section("fa-registers", "differential", [selector[2] for selector in g1.HISTORY_TESTS[1:]])
        + section("fa-cli", "scoreboard", [g1.SCOREBOARD_TEST[2]])
    )


class ProofFixture:
    def __init__(self):
        self.base = Path(tempfile.mkdtemp(prefix="fa-g1-consumer-tests-"))
        self.repo = self.base / "repository"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "registries").mkdir()
        self.check = self.repo / "scripts/check.sh"
        self.check.write_text("#!/bin/sh\n# CANONICAL_STEPS: test-list, test\nexit 93\n")
        self.scoreboard = self.repo / "registries/scoreboard.toml"
        self.scoreboard.write_bytes((ROOT / "registries/scoreboard.toml").read_bytes())
        self.git("init", "-q", "-b", "main")
        self.commit_all("synthetic proof consumer fixture")
        self.next_proof = 0

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), *args],
                                text=True, capture_output=True, check=True)
        return result.stdout.strip()

    def commit_all(self, message):
        self.git("add", ".")
        self.git("-c", "user.name=G1 proof fixture", "-c", "user.email=g1-fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-q", "-m", message)
        self.commit = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.script_blob = self.git("rev-parse", "HEAD:scripts/check.sh")

    def proof(self, log=None, *, partial=False, verdict="pass", version=3):
        self.next_proof += 1
        proof = self.base / f"proof-{self.next_proof}"
        (proof / "steps").mkdir(parents=True)
        text = passing_log() if log is None else log
        listed = re.findall(r"^test (\S+)(?: - should panic)? \.\.\. (?:ok|FAILED|ignored(?:, .*?)?)$",
                            text, re.M)
        logs = {
            "test-list": "".join(f"{name}: test\n" for name in listed)
                         + "Remote command finished: exit=0\n[RCH] remote fixture-worker (1s)\n",
            "test": text,
        }
        epoch = int(self.git("show", "-s", "--format=%ct", self.commit))
        stamp = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        records = []
        for name, data in logs.items():
            (proof / "steps" / f"{name}.log").write_text(data)
            if partial and name == "test-list":
                continue
            records.append({
                "step": name, "status": "UNRUN" if verdict == "red" and name == "test" else "PASS",
                "tree_hash": self.tree, "toolchain": "rustc 1.100.0-fixture",
                "worker": "fixture-worker", "started": stamp, "finished": stamp,
                "duration_secs": 0, "log_digest": hashlib.sha256(data.encode()).hexdigest(),
            })
        records_text = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in records)
        (proof / "step-verdicts.jsonl").write_text(records_text)
        tools = "rustc=rustc 1.100.0-fixture\n" + "".join(
            "step_verdict=" + json.dumps(row, separators=(",", ":")) + "\n" for row in records
        )
        (proof / "tools.txt").write_text(tools)
        exit_code = 0 if verdict == "pass" else 2
        manifest = {
            "format_version": str(version), "repository": "repository", "commit": self.commit,
            "tree": self.tree, "ref": "main", "check_script_path": "scripts/check.sh",
            "check_script_blob": self.script_blob, "started_utc": stamp, "finished_utc": stamp,
            "check_exit": str(exit_code), "tree_stable": "true", "verdict": verdict,
            "authority": "check.sh exit code on the exact stable tree; not product correctness beyond them",
        }
        (proof / "manifest.txt").write_text("".join(f"{key}={value}\n" for key, value in manifest.items()))
        fixed = {
            "command.txt": "bash scripts/check.sh\n",
            "commit-before.txt": self.commit + "\n", "commit-after.txt": self.commit + "\n",
            "tree-before.txt": self.tree + "\n", "tree-after.txt": self.tree + "\n",
            "check-script-blob.txt": self.script_blob + "\n",
            "status-before.txt": "", "status-after.txt": "",
            "check-exit.txt": str(exit_code) + "\n",
            "check.stdout.log": "".join(f"{row['status']} {row['step']}\n" for row in records)
                                + ("ALL GATES GREEN\n" if verdict == "pass" else "QUALITY GATE RED\n"),
            "check.stderr.log": "" if verdict == "pass" else "QUALITY GATE RED\n",
        }
        for name, data in fixed.items():
            (proof / name).write_text(data)
        self.rehash(proof)
        return proof

    @staticmethod
    def rehash(proof):
        entries = []
        for path in sorted(proof.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                entries.append(hashlib.sha256(path.read_bytes()).hexdigest()
                               + "  ./" + path.relative_to(proof).as_posix() + "\n")
        (proof / "SHA256SUMS").write_text("".join(entries))


class G1QualificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ProofFixture()

    def qualify(self, proof, revision=None):
        return g1.qualify(self.fixture.repo, proof, revision)

    def test_complete_verified_candidate_qualifies_without_rewriting_the_scoreboard(self):
        original = self.fixture.scoreboard.read_bytes()
        proof = self.fixture.proof()
        report = self.qualify(proof)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["commit"], self.fixture.commit)
        self.assertEqual(report["tree"], self.fixture.tree)
        self.assertEqual([row["id"] for row in report["criteria"]], list(g1.G1_IDS))
        self.assertEqual(report["history_campaign"]["seed_count"], 50)
        self.assertEqual(report["history_campaign"]["races"], 2000)
        self.assertEqual(self.fixture.scoreboard.read_bytes(), original)
        self.assertEqual(self.fixture.git("status", "--porcelain"), "")

    def test_show_output_retains_the_campaign_witness_after_the_test_result(self):
        name = g1.HISTORY_TESTS[0][2]
        captured = section("fa-registers", "differential", [name])
        captured = captured.replace(
            f"test {name} ... ok\n",
            f"test {name} ... ok\nsuccesses:\n\n---- {name} stdout ----\n{WITNESS}\n\n"
            f"successes:\n    {name}\n\n",
        )
        text = (section("fa", "lib", [selector[2] for selector in g1.CRASH_TESTS])
                + captured
                + section("fa-registers", "differential", [selector[2] for selector in g1.HISTORY_TESTS[1:]])
                + section("fa-cli", "scoreboard", [g1.SCOREBOARD_TEST[2]]))
        self.assertEqual(self.qualify(self.fixture.proof(text))["verdict"], "PASS")

    def test_missing_acceptance_or_negative_control_cannot_be_replaced_by_a_pass_claim(self):
        for selector in (*g1.CRASH_TESTS, *g1.HISTORY_TESTS, g1.SCOREBOARD_TEST):
            with self.subTest(test=selector):
                text = passing_log().replace(f"test {selector[2]} ... ok\n",
                                             f"PASS {g1.qualified(selector)}\n")
                with self.assertRaisesRegex(g1.QualificationError, "expected one executed acceptance"):
                    self.qualify(self.fixture.proof(text))

    def test_ignored_or_should_panic_acceptance_is_not_a_release_pass(self):
        name = g1.HISTORY_TESTS[0][2]
        for replacement in (f"test {name} ... ignored", f"test {name} - should panic ... ok"):
            with self.subTest(outcome=replacement):
                text = passing_log().replace(f"test {name} ... ok", replacement)
                with self.assertRaisesRegex(g1.QualificationError, "did not pass normally"):
                    self.qualify(self.fixture.proof(text))

    def test_wrong_package_or_target_cannot_supply_identically_named_tests(self):
        for text in (
            passing_log().replace("fa-registers", "other-crate"),
            passing_log().replace("tests/differential.rs", "tests/impostor.rs"),
        ):
            with self.subTest(transcript=text[:80]):
                with self.assertRaisesRegex(g1.QualificationError, "expected one executed acceptance"):
                    self.qualify(self.fixture.proof(text))

    def test_package_free_test_inventory_cannot_authorize_g1(self):
        text = "\n".join(line for line in passing_log().splitlines()
                         if not line.startswith("==== test job ")) + "\n"
        with self.assertRaisesRegex(g1.QualificationError, "no package-qualified completed jobs"):
            self.qualify(self.fixture.proof(text))

    def test_another_jobs_remote_completion_cannot_hide_an_incomplete_campaign(self):
        prefix, campaign = passing_log().split(
            "==== test job fa-registers.test.differential.isolated.multi_seed_campaign_tier1", 1)
        for changed in (campaign.replace("Remote command finished: exit=0\n", "", 1),
                        campaign.replace("(exit 0)", "(exit 101)", 1)):
            with self.subTest(transcript=changed[:100]):
                text = prefix + "==== test job fa-registers.test.differential.isolated.multi_seed_campaign_tier1" + changed
                with self.assertRaisesRegex(g1.QualificationError, "missing successful remote completion"):
                    self.qualify(self.fixture.proof(text))

    def test_duplicate_test_successes_are_ambiguous(self):
        name = g1.HISTORY_TESTS[0][2]
        text = passing_log().replace(f"test {name} ... ok\n", f"test {name} ... ok\ntest {name} ... ok\n")
        with self.assertRaisesRegex(g1.QualificationError, "expected one executed acceptance"):
            self.qualify(self.fixture.proof(text))

    def test_missing_or_duplicate_campaign_witness_is_not_a_pass(self):
        for replacement in ("", WITNESS + "\n" + WITNESS):
            with self.subTest(witness=replacement):
                with self.assertRaisesRegex(g1.QualificationError, "one retained tier-1 campaign witness"):
                    self.qualify(self.fixture.proof(passing_log().replace(WITNESS, replacement)))

    def test_insufficient_or_shifted_cohort_and_empty_coverage_are_rejected(self):
        for before, after in (
            ("seed_from=1", "seed_from=2"), ("seed_count=50", "seed_count=8"),
            ("histories=50", "histories=49"), ("steps_per_history=640", "steps_per_history=0"),
            ("race_histories=50", "race_histories=8"), ("races=2000", "races=320"),
            ("coverage_cells=147", "coverage_cells=0"), ("serial_replayed=6000", "serial_replayed=0"),
        ):
            with self.subTest(change=after):
                with self.assertRaises(g1.QualificationError):
                    self.qualify(self.fixture.proof(passing_log().replace(before, after)))

    def test_campaign_witness_from_another_target_does_not_qualify_fixed_fifty(self):
        text = passing_log().replace(WITNESS + "\n", "").replace(
            f"test {g1.SCOREBOARD_TEST[2]} ... ok", WITNESS + "\n" + f"test {g1.SCOREBOARD_TEST[2]} ... ok"
        )
        with self.assertRaisesRegex(g1.QualificationError, "one retained tier-1 campaign witness"):
            self.qualify(self.fixture.proof(text))

    def test_old_proof_requires_explicit_matching_revision(self):
        proof = self.fixture.proof()
        original = self.fixture.commit
        (self.fixture.repo / "later.txt").write_text("a later source tree\n")
        self.fixture.commit_all("later source tree")
        with self.assertRaisesRegex(g1.QualificationError, "independently selected revision"):
            self.qualify(proof)
        self.assertEqual(self.qualify(proof, original)["commit"], original)

    def test_dirty_default_revision_is_not_qualified(self):
        proof = self.fixture.proof()
        self.fixture.check.write_text(self.fixture.check.read_text() + "# changed\n")
        with self.assertRaisesRegex(g1.QualificationError, "clean worktree"):
            self.qualify(proof)

    def test_tampered_log_is_rejected_by_the_real_proof_verifier(self):
        proof = self.fixture.proof()
        log = proof / "steps/test.log"
        log.write_text(log.read_text() + "unbound bytes\n")
        with self.assertRaisesRegex(g1.QualificationError, "SHA-256 verification failed"):
            self.qualify(proof)

    def test_unrun_partial_and_legacy_proofs_cannot_qualify(self):
        for kwargs in ({"verdict": "red"}, {"partial": True}, {"version": 2}):
            with self.subTest(proof=kwargs):
                with self.assertRaises(g1.QualificationError):
                    self.qualify(self.fixture.proof(**kwargs))

    def test_other_g1_regressions_remain_blocking_even_with_both_campaigns(self):
        self.fixture.scoreboard.write_text(self.fixture.scoreboard.read_text().replace(
            'argv = ["g1_genesis_clauses_live"]\nexpected = "works"',
            'argv = ["g1_genesis_clauses_live"]\nexpected = "absent"', 1))
        self.fixture.commit_all("synthetic regression in another G1 criterion")
        with self.assertRaisesRegex(g1.QualificationError, "no longer declares this criterion working"):
            self.qualify(self.fixture.proof())

    def test_bound_snapshot_refuses_a_file_changed_after_checksum_validation(self):
        proof = self.fixture.proof()
        inventory = g1.checksum_inventory((proof / "SHA256SUMS").read_bytes())
        (proof / "steps/test.log").write_text("changed after verification\n")
        with self.assertRaisesRegex(g1.QualificationError, "changed after verification"):
            g1.read_bound(proof, "steps/test.log", inventory)


if __name__ == "__main__":
    unittest.main()
