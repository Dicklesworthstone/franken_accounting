"""Adversarial controls for the live harness's independently checked results."""
from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_live


EXPECTED = {
    "source_system": "test-source",
    "accounts": [
        {"account": "published-type", "debit_minor": "10500", "credit_minor": "500", "signed_minor": "10000"},
        {"account": "published-payment-offset", "debit_minor": "500", "credit_minor": "10500", "signed_minor": "-10000"},
    ],
    "entry_count": 1,
    "leg_count": 4,
}


def report() -> dict:
    return {"event": "trial_balance", "data": {"rows": [
        {"code": "published-type", "debits": "105.00 GBP", "credits": "5.00 GBP", "net": "100.00 GBP"},
        {"code": "published-payment-offset", "debits": "5.00 GBP", "credits": "105.00 GBP", "net": "-100.00 GBP"},
    ]}}


def approval_events(principal: str, *, retry: bool = False) -> list[dict]:
    """Explicit unit fixtures, never reported as native execution evidence."""
    offset = run_live.REVIEWERS.index(principal) * 2
    return [{"event": "approved", "book": "c" * 32,
             "authority": {"principal": principal}, "coordinate": {"known_at": 50 + offset + index},
             "data": {"approved_digest": proposal, "approval_vid": f"{offset + index + 1:032x}",
                      "recorded_at": 50 + offset + index, "security_policy_epoch": None if retry else 0,
                      "already_recorded": retry}}
            for index, proposal in enumerate(["a" * 64, "b" * 64])]


EVIDENCE_DOCUMENTS = {"a" * 64: "1" * 64, "b" * 64: "2" * 64}
EVIDENCE_ENTRIES = [f"{index:032x}" for index in (1, 2)]
EVIDENCE_STAGED_AT = dict(zip(EVIDENCE_ENTRIES, (50, 51), strict=True))


def evidence_events(*, retry: bool = False) -> list[dict]:
    """Constructed transport fixtures, separate from native corpus receipts."""
    citations = [{"document_oid": oid, "doc_commit": commitment, "role": "Source"}
                 for oid, commitment in EVIDENCE_DOCUMENTS.items()]
    return [{"event": "evidence_attached", "book": "c" * 32,
             "authority": {"principal": "operator"}, "coordinate": {"known_at": 200 if retry else 70 + index},
             "data": {"entry": entry, "supplement_vid": f"{100 + index:032x}",
                      "entry_digest": f"{300 + index:064x}", "body_digest": f"{400 + index:064x}",
                      "recorded_at": 70 + index, "already_recorded": retry,
                      "documents": copy.deepcopy(citations)}}
            for index, entry in enumerate(EVIDENCE_ENTRIES)]


class LiveOracleControls(unittest.TestCase):
    @staticmethod
    def native_fixture(root: Path, *, daemon: bool = False):
        paths = [root / name for name in ("fa", "fa-verify", "fad")]
        for path in paths:
            path.write_bytes(("test executable bytes: " + path.name).encode())
            path.chmod(0o755)
        out = root / "execution"
        out.mkdir()
        return run_live.Native(paths[0], paths[1], out, 10, paths[2] if daemon else None)

    def test_initial_executable_hash_is_retained_and_replacement_prevents_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            original = native.fa.read_bytes()
            self.assertEqual(native.identities["fa"]["sha256"], hashlib.sha256(original).hexdigest())
            native.fa.write_bytes(b"different executable")
            with mock.patch.object(run_live.subprocess, "run") as execute:
                with self.assertRaisesRegex(run_live.CheckError, "executable changed"):
                    native.execute(["book", "info"])
                execute.assert_not_called()
            self.assertEqual(native.calls, 0)
            self.assertFalse((native.out / "commands.jsonl").exists())
            self.assertEqual(native.identities["fa"]["sha256"], hashlib.sha256(original).hexdigest())

    def test_replacement_during_command_retains_completed_output_but_refuses_success(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            stdout = b'{"event":"book_info","data":{}}\n'
            def replace_during_command(*args, **kwargs):
                native.fa.write_bytes(b"replacement installed while native command ran")
                return run_live.subprocess.CompletedProcess(args[0], 0, stdout, b"")
            with mock.patch.object(run_live.subprocess, "run", side_effect=replace_during_command):
                with self.assertRaisesRegex(run_live.CheckError, "executable changed"):
                    native.execute(["book", "info"])
            records = [json.loads(line) for line in (native.out / "commands.jsonl").read_text().splitlines()]
            self.assertEqual([record["state"] for record in records], ["started", "completed"])
            self.assertEqual(records[-1]["exit"], 0)
            self.assertEqual((native.out / "transcript" / "00001.stdout.jsonl").read_bytes(), stdout)

    def test_changed_fa_does_not_prevent_cleanup_with_unchanged_fad(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory), daemon=True)
            native.fa.write_bytes(b"replacement fa")
            completed = run_live.subprocess.CompletedProcess([], 0, b'{"event":"fad_stopped"}\n', b"")
            with mock.patch.object(run_live.subprocess, "run", return_value=completed) as execute:
                self.assertEqual(native.execute(["stop"], daemon_control=True), [{"event": "fad_stopped"}])
                self.assertEqual(execute.call_args.args[0][0], str(native.fad))
            with self.assertRaisesRegex(run_live.CheckError, "executable changed"):
                native.check_executables()

    def test_timeout_keeps_exact_stdin_and_partial_receipts_without_confirming_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            request = b'{"chunks":[{"index":0,"approvals":["A:exact-reference"]}]}\n'
            partial = b'{"event":"migration_import_progress","data":{"completed_count":1}}\n'
            timeout = run_live.subprocess.TimeoutExpired("fa", 10, output=partial, stderr=b"interrupted\n")
            with mock.patch.object(run_live.subprocess, "run", side_effect=timeout):
                with self.assertRaisesRegex(run_live.CheckError, "timed out"):
                    native.execute(["migrate", "import", "--action", "stage", "--intent", "-"], request_bytes=request)
            records = [json.loads(line) for line in (native.out / "commands.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["state"], "started")
            self.assertEqual((native.out / records[0]["stdin_path"]).read_bytes(), request)
            self.assertEqual(records[0]["stdin_sha256"], hashlib.sha256(request).hexdigest())
            self.assertEqual((native.out / "transcript" / "00001.stdout.jsonl").read_bytes(), partial)
            self.assertEqual((native.out / "transcript" / "00001.stderr.txt").read_bytes(), b"interrupted\n")

    def test_final_identity_check_prevents_pass_and_records_original_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fa, verifier = root / "fa", root / "fa-verify"
            for path in (fa, verifier):
                path.write_bytes(("initial " + path.name).encode())
                path.chmod(0o755)
            initial = hashlib.sha256(verifier.read_bytes()).hexdigest()
            out = root / "execution"
            def complete_then_replace(native, *_):
                verifier.write_bytes(b"new verifier installed before result publication")
                return {"status": "PASS", "checks": []}
            arguments = ["run_live.py", "--prepared", str(root), "--dataset", "fixture", "--out", str(out),
                         "--fa", str(fa), "--fa-verify", str(verifier)]
            with (mock.patch.object(sys, "argv", arguments),
                  mock.patch.object(run_live, "verify_prepared", return_value=({}, {})),
                  mock.patch.object(run_live, "run", side_effect=complete_then_replace),
                  mock.patch.object(sys, "stdout", io.StringIO())):
                self.assertEqual(run_live.main(), 1)
            result = json.loads((out / "result.json").read_bytes())
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("executable changed", result["executable_identity_error"])
            self.assertEqual(result["fa_verify_sha256"], initial)
            self.assertNotIn("executable_identity_guards", result["checks"])

    def test_initial_identity_failure_records_no_native_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fa"
            executable.write_bytes(b"fixture")
            executable.chmod(0o755)
            out = root / "execution"
            arguments = ["run_live.py", "--prepared", str(root), "--dataset", "fixture", "--out", str(out),
                         "--fa", str(executable), "--fa-verify", str(executable)]
            with (mock.patch.object(sys, "argv", arguments),
                  mock.patch.object(run_live, "verify_prepared", return_value=({}, {})),
                  mock.patch.object(run_live, "executable_identity", side_effect=run_live.CheckError("unstable initial executable")),
                  mock.patch.object(run_live, "run") as run,
                  mock.patch.object(sys, "stdout", io.StringIO())):
                self.assertEqual(run_live.main(), 1)
                run.assert_not_called()
            result = json.loads((out / "result.json").read_bytes())
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["native_calls"], 0)
            self.assertIn("may have committed", result["boundary"])

    def test_group_size_must_be_an_integer_before_any_execution(self):
        for invalid in (True, 1.0, 0, 4097):
            with self.subTest(size=invalid), self.assertRaisesRegex(run_live.CheckError, "must be an integer"):
                run_live.Native(Path("fa"), Path("verify"), Path("unused"), 10, stage_group_size=invalid)

    def test_approval_group_receipts_bind_every_digest_reviewer_book_and_publication(self):
        proposals = ["a" * 64, "b" * 64]
        principal = run_live.REVIEWERS[0]
        good = approval_events(principal)
        parameters = dict(principal=principal, book_id="c" * 32, previous={})
        self.assertEqual(run_live.check_approval_group(good, proposals, **parameters),
                         [event["data"] for event in good])
        mutations = [
            lambda events: events.pop(),
            lambda events: events.append(copy.deepcopy(events[0])),
            lambda events: events.reverse(),
            lambda events: events[1].update(event="unrelated"),
            lambda events: events[1].update(book="d" * 32),
            lambda events: events[1]["authority"].update(principal=run_live.REVIEWERS[1]),
            lambda events: events[1].update(authority=None),
            lambda events: events[1]["data"].update(approved_digest="d" * 64),
            lambda events: events[1]["data"].update(approval_vid=events[0]["data"]["approval_vid"]),
            lambda events: events[1]["data"].update(approval_vid="not-a-native-id"),
            lambda events: events[1]["data"].update(recorded_at=50),
            lambda events: events[1]["data"].update(recorded_at=True),
            lambda events: events[1]["data"].update(recorded_at=0),
            lambda events: events[1]["data"].update(security_policy_epoch=True),
            lambda events: events[1]["data"].update(security_policy_epoch=-1),
            lambda events: events[1]["data"].update(already_recorded=0),
            lambda events: events[1]["data"].update(already_recorded=True),
            lambda events: events[1]["coordinate"].update(known_at=50),
            lambda events: events[1]["coordinate"].update(known_at=True),
        ]
        for index, mutate in enumerate(mutations):
            wrong = copy.deepcopy(good)
            mutate(wrong)
            with self.subTest(mutation=index), self.assertRaises(run_live.CheckError):
                run_live.check_approval_group(wrong, proposals, **parameters)
        # A second reviewer must not reuse the first reviewer's native receipt.
        parameters["previous"] = {(principal, event["data"]["approved_digest"]): event["data"] for event in good}
        parameters["principal"] = run_live.REVIEWERS[1]
        second = approval_events(run_live.REVIEWERS[1])
        run_live.check_approval_group(second, proposals, **parameters)
        second[0]["data"]["approval_vid"] = good[0]["data"]["approval_vid"]
        with self.assertRaisesRegex(run_live.CheckError, "share a native identity"):
            run_live.check_approval_group(second, proposals, **parameters)

    def test_approval_group_retries_require_original_ids_sequences_and_retry_envelopes(self):
        principal = run_live.REVIEWERS[0]
        original = approval_events(principal)
        previous = {(principal, event["data"]["approved_digest"]): event["data"] for event in original}
        retry = approval_events(principal, retry=True)
        for event in retry:
            event["coordinate"]["known_at"] = 120  # Current head, original receipt sequence.
        proposals = ["a" * 64, "b" * 64]
        parameters = dict(principal=principal, book_id="c" * 32, previous=previous)
        run_live.check_approval_group(retry, proposals, **parameters)
        mutations = [
            lambda data: data.update(approval_vid="d" * 32),
            lambda data: data.update(recorded_at=49),
            lambda data: data.update(already_recorded=False),
            lambda data: data.update(security_policy_epoch=0),
            lambda data: data.pop("security_policy_epoch"),
        ]
        for index, mutate in enumerate(mutations):
            wrong = copy.deepcopy(retry)
            mutate(wrong[1]["data"])
            with self.subTest(mutation=index), self.assertRaises(run_live.CheckError):
                run_live.check_approval_group(wrong, proposals, **parameters)

    def test_two_approval_calls_preserve_exact_stdin_tokens_pairs_and_retry_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            native.batch_approvals, native.book_id = True, "c" * 32
            native.reviewer_tokens = [native.out / f"{principal}.token" for principal in run_live.REVIEWERS]
            proposals = ["a" * 64, "b" * 64]
            expected = [[f"{1:032x}", f"{3:032x}"], [f"{2:032x}", f"{4:032x}"]]
            observations = []
            def execute(command, **kwargs):
                token = Path(command[command.index("--token") + 1])
                index = native.reviewer_tokens.index(token)
                principal = run_live.REVIEWERS[index]
                retry = len(observations) >= 2
                observations.append((command, kwargs["input"]))
                stdout = ("".join(json.dumps(event) + "\n" for event in approval_events(principal, retry=retry))).encode()
                return run_live.subprocess.CompletedProcess(command, 0, stdout, b"")
            with mock.patch.object(run_live.subprocess, "run", side_effect=execute):
                self.assertEqual(native.approval_group(proposals), expected)
                self.assertEqual(native.approval_group(proposals), expected)
            self.assertEqual(native.approval_group_requests, 4)
            self.assertEqual(len(native.approval_receipts), 4)
            request = run_live.json_bytes(proposals)
            for command, forwarded in observations:
                self.assertEqual(forwarded, request)
                self.assertIn("--proposals", command)
                self.assertEqual(command[command.index("--proposals") + 1], "-")
                self.assertNotIn("--as", command)
                self.assertNotIn("--proposal", command)
            starts = [json.loads(line) for line in (native.out / "commands.jsonl").read_text().splitlines()
                      if json.loads(line)["state"] == "started"]
            self.assertEqual(len(starts), 4)
            for record in starts:
                self.assertEqual(record["stdin_sha256"], run_live.digest(request))
                self.assertEqual((native.out / record["stdin_path"]).read_bytes(), request)

    def test_partial_approval_failure_keeps_actual_prefix_and_never_approves_second_reviewer(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            native.batch_approvals, native.book_id = True, "c" * 32
            native.reviewer_tokens = [native.out / f"{principal}.token" for principal in run_live.REVIEWERS]
            prefix = json.dumps(approval_events(run_live.REVIEWERS[0])[0]).encode() + b"\n"
            stdout = prefix + b'{"event":"error","data":{"message":"capability expired"}}\n'
            completed = run_live.subprocess.CompletedProcess([], 6, stdout, b"authority refusal\n")
            with mock.patch.object(run_live.subprocess, "run", return_value=completed) as execute:
                with self.assertRaisesRegex(run_live.CheckError, "exited 6"):
                    native.approval_group(["a" * 64, "b" * 64])
                execute.assert_called_once()
            self.assertEqual(native.approval_receipts, {})
            self.assertEqual(native.approval_group_requests, 1)
            self.assertEqual((native.out / "transcript/00001.stdout.jsonl").read_bytes(), stdout)
            records = [json.loads(line) for line in (native.out / "commands.jsonl").read_text().splitlines()]
            self.assertEqual(records[-1]["exit"], 6)
            self.assertEqual(json.loads((native.out / records[0]["stdin_path"]).read_bytes()), ["a" * 64, "b" * 64])

    def test_second_reviewer_failure_and_expired_retry_never_use_cached_approvals_as_success(self):
        for fail_on_retry in (False, True):
            with self.subTest(retry=fail_on_retry), tempfile.TemporaryDirectory() as directory:
                native = self.native_fixture(Path(directory))
                native.batch_approvals, native.book_id = True, "c" * 32
                native.reviewer_tokens = [native.out / f"{principal}.token" for principal in run_live.REVIEWERS]
                calls = []
                def execute(command, **kwargs):
                    calls.append(command)
                    index = native.reviewer_tokens.index(Path(command[command.index("--token") + 1]))
                    refuse = len(calls) == (3 if fail_on_retry else 2)
                    events = approval_events(run_live.REVIEWERS[index])
                    stdout = ("".join(json.dumps(event) + "\n" for event in events[:1 if refuse else 2])).encode()
                    if refuse:
                        stdout += b'{"event":"error","data":{"message":"authority revoked"}}\n'
                    return run_live.subprocess.CompletedProcess(command, 6 if refuse else 0, stdout, b"")
                with mock.patch.object(run_live.subprocess, "run", side_effect=execute):
                    if fail_on_retry:
                        native.approval_group(["a" * 64, "b" * 64])
                    with self.assertRaisesRegex(run_live.CheckError, "exited 6"):
                        native.approval_group(["a" * 64, "b" * 64])
                self.assertEqual(len(calls), 3 if fail_on_retry else 2)
                self.assertEqual(len(native.approval_receipts), 4 if fail_on_retry else 2)
                retained = native.out / "transcript" / f"{len(calls):05d}.stdout.jsonl"
                self.assertIn(b'"authority revoked"', retained.read_bytes())
                self.assertTrue(all("--proposals" in command and "--token" in command
                                    and "--as" not in command and "--grant" not in command for command in calls))

    def test_batch_run_transposes_checked_reviewer_receipts_into_exact_native_stage_selection(self):
        for via_daemon in (False, True):
            with self.subTest(daemon=via_daemon), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                native = self.native_fixture(root, daemon=via_daemon)
                native.batch_approvals, native.stage_group_size = True, 2
                prepared = root / "prepared"
                prepared.mkdir()
                for name in ("raw.csv", "legacy.csv", "receipt.json", "provenance.jsonl",
                             "records.jsonl", "expected_tb.json", "columns.toml"):
                    (prepared / name).write_bytes(f"retained {name}\n".encode())
                (prepared / "account_map.json").write_text("{}", encoding="utf-8")
                expected = {**EXPECTED, "period_start": "2025-12-01", "entry_count": 2,
                            "entries": [{"entry_id": "first"}, {"entry_id": "second"}]}
                chunks = [{"entry_vid": "first", "proposal_digest": "a" * 64, "leg_count": 2},
                          {"entry_vid": "second", "proposal_digest": "b" * 64, "leg_count": 2}]
                real_one = native.one
                def setup_or_stage(args, **kwargs):
                    if args[:2] == ["book", "create"]:
                        return {"book": "c" * 32, "data": {"book_id": "c" * 32}}
                    if args[:2] == ["document", "read"]:
                        Path(args[args.index("--out") + 1]).write_bytes((prepared / args[2]).read_bytes())
                        return {"data": {"view": "full"}}
                    if args[:2] == ["migrate", "open"]:
                        return {"data": {"run_vid": "run"}}
                    if args[:4] == ["migrate", "import", "--action", "prepare"]:
                        return {"data": {"mode": "FullDetail", "sole_opening_source": True,
                                         "chunks": chunks, "package_oid": "package", "already_recorded": True}}
                    if args[:4] == ["migrate", "import", "--action", "stage"]:
                        return real_one(args, **kwargs)
                    if args[0] == "tb":
                        return {"data": {"rows": []}}
                    return {"data": {}}
                def start_bulk():
                    native.reviewer_tokens = [native.out / f"{principal}.token" for principal in run_live.REVIEWERS]
                    if via_daemon:
                        native.daemon = mock.Mock()
                        native.daemon.poll.return_value = None
                observed = []
                def execute(command, **kwargs):
                    observed.append((command, kwargs["input"]))
                    if "--proposals" in command:
                        index = native.reviewer_tokens.index(Path(command[command.index("--token") + 1]))
                        events = approval_events(run_live.REVIEWERS[index], retry=len(observed) > 2)
                        stdout = ("".join(json.dumps(event) + "\n" for event in events)).encode()
                        return run_live.subprocess.CompletedProcess(command, 0, stdout, b"")
                    # Stop at the actual stage transport after its exact request
                    # has been written. This remains a constructed unit case.
                    return run_live.subprocess.CompletedProcess(command, 6, b'{"event":"error"}\n', b"stage boundary\n")
                with (
                    mock.patch.object(native, "one", side_effect=setup_or_stage),
                    mock.patch.object(native, "document", side_effect=lambda path, *_: path.name),
                    mock.patch.object(native, "head", return_value=200),
                    mock.patch.object(native, "start_bulk", side_effect=start_bulk),
                    mock.patch.object(run_live.subprocess, "run", side_effect=execute),
                    self.assertRaisesRegex(run_live.CheckError, "exited 6"),
                ):
                    run_live.run(native, prepared, "fixture", expected)
                self.assertEqual(len(observed), 5)  # A/B, exact A/B retry, stage.
                for command, request in observed[:4]:
                    self.assertEqual(request, run_live.json_bytes(["a" * 64, "b" * 64]))
                    self.assertEqual("--via" in command, via_daemon)
                    self.assertEqual(command[command.index("--proposals") + 1], "-")
                    self.assertNotIn("--as", command)
                selection = {"chunks": [{"index": 0, "approvals": [f"{1:032x}", f"{3:032x}"]},
                                         {"index": 1, "approvals": [f"{2:032x}", f"{4:032x}"]}]}
                self.assertEqual(json.loads(observed[-1][1]), selection)
                self.assertEqual((native.out / "stage-00000.json").read_bytes(), observed[-1][1])

    def test_bad_approval_selection_or_missing_independent_tokens_refuses_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            native.batch_approvals, native.book_id = True, "c" * 32
            native.reviewer_tokens = [native.out / "first.token", native.out / "second.token"]
            invalid = [[], ["a" * 64] * 2, ["a" * 64, "not-a-digest"], ["a" * 64, 12],
                       [f"{index:064x}" for index in range(4097)]]
            with mock.patch.object(run_live.subprocess, "run") as execute:
                for proposals in invalid:
                    with self.subTest(size=len(proposals)), self.assertRaises(run_live.CheckError):
                        native.approval_group(proposals)
                native.reviewer_tokens = [native.out / "first.token"] * 2
                with self.assertRaisesRegex(run_live.CheckError, "separately issued"):
                    native.approval_group(["a" * 64])
                execute.assert_not_called()
            self.assertEqual(native.calls, 0)

    def test_direct_batch_mode_issues_two_restricted_native_tokens_without_starting_daemon(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            native.batch_approvals = True
            with mock.patch.object(native, "one", return_value={}) as issue:
                native.start_bulk()
            self.assertEqual(issue.call_count, 2)
            self.assertIsNone(native.daemon)
            self.assertEqual(len(set(native.reviewer_tokens)), 2)
            for principal, call in zip(run_live.REVIEWERS, issue.call_args_list, strict=True):
                args = call.args[0]
                self.assertEqual(args[:2], ["capability", "issue"])
                self.assertEqual(args[args.index("--holder") + 1], principal)
                self.assertEqual([args[index + 1] for index, value in enumerate(args) if value == "--op"],
                                 ["read", "approve"])
            with self.assertRaisesRegex(run_live.CheckError, "already been issued"):
                native.start_bulk()

    def test_evidence_group_binds_every_entry_to_exact_source_commitments_and_roles(self):
        good = evidence_events()
        parameters = dict(documents=EVIDENCE_DOCUMENTS, book_id="c" * 32, principal="operator",
                          staged_at=EVIDENCE_STAGED_AT, previous={})
        self.assertEqual(run_live.check_evidence_group(good, EVIDENCE_ENTRIES, **parameters),
                         [event["data"] for event in good])
        mutations = [
            lambda events: events.pop(),
            lambda events: events.append(copy.deepcopy(events[0])),
            lambda events: events.reverse(),
            lambda events: events[1].update(event="unrelated"),
            lambda events: events[1].update(book="d" * 32),
            lambda events: events[1]["authority"].update(principal="other"),
            lambda events: events[1]["data"].update(entry="9" * 32),
            lambda events: events[1]["data"].update(supplement_vid=events[0]["data"]["supplement_vid"]),
            lambda events: events[1]["data"].update(supplement_vid="malformed"),
            lambda events: events[1]["data"].update(recorded_at=True),
            lambda events: events[1]["data"].update(recorded_at=50),
            lambda events: events[1]["data"].update(recorded_at=70),
            lambda events: (events[1]["data"].update(recorded_at=65), events[1]["coordinate"].update(known_at=65)),
            lambda events: events[1]["data"].update(body_digest=None),
            lambda events: events[1]["data"].update(entry_digest="unknown"),
            lambda events: events[1]["data"].update(already_recorded=0),
            lambda events: events[1]["data"].update(already_recorded=True),
            lambda events: events[1]["coordinate"].update(known_at=70),
            lambda events: events[1]["coordinate"].update(known_at=200),
            lambda events: events[1]["data"]["documents"].pop(),
            lambda events: events[1]["data"]["documents"].append(copy.deepcopy(events[1]["data"]["documents"][0])),
            lambda events: events[1]["data"]["documents"][1].update(document_oid="e" * 64),
            lambda events: events[1]["data"]["documents"][1].update(doc_commit="f" * 64),
            lambda events: events[1]["data"]["documents"][1].update(role="Review"),
            lambda events: events[1]["data"]["documents"][1].update(doc_commit=None),
            lambda events: events[1]["data"]["documents"].__setitem__(1, copy.deepcopy(events[1]["data"]["documents"][0])),
        ]
        for index, mutate in enumerate(mutations):
            wrong = copy.deepcopy(good)
            mutate(wrong)
            with self.subTest(mutation=index), self.assertRaises(run_live.CheckError):
                run_live.check_evidence_group(wrong, EVIDENCE_ENTRIES, **parameters)
        later_stage = {EVIDENCE_ENTRIES[0]: 50, EVIDENCE_ENTRIES[1]: 70}
        with self.assertRaisesRegex(run_live.CheckError, "complete staged group"):
            run_live.check_evidence_group(good, EVIDENCE_ENTRIES, **{**parameters, "staged_at": later_stage})

    def test_evidence_retries_keep_original_supplement_and_source_commitments_at_later_head(self):
        original = evidence_events()
        previous = {event["data"]["entry"]: event["data"] for event in original}
        retry = evidence_events(retry=True)
        parameters = dict(documents=EVIDENCE_DOCUMENTS, book_id="c" * 32, principal="operator",
                          staged_at=EVIDENCE_STAGED_AT, previous=previous)
        run_live.check_evidence_group(retry, EVIDENCE_ENTRIES, **parameters)
        mutations = [
            lambda data: data.update(supplement_vid="d" * 32),
            lambda data: data.update(recorded_at=150),
            lambda data: data.update(entry_digest="e" * 64),
            lambda data: data.update(body_digest="f" * 64),
            lambda data: data.update(already_recorded=False),
        ]
        for index, mutate in enumerate(mutations):
            wrong = copy.deepcopy(retry)
            mutate(wrong[1]["data"])
            with self.subTest(mutation=index), self.assertRaises(run_live.CheckError):
                run_live.check_evidence_group(wrong, EVIDENCE_ENTRIES, **parameters)

    def test_evidence_group_uses_one_retained_stdin_request_and_reexecutes_exact_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            native.batch_evidence, native.book_id, native.owner_principal = True, "c" * 32, "operator"
            native.document_commitments = EVIDENCE_DOCUMENTS.copy()
            observed = []
            def execute(command, **kwargs):
                retry = bool(observed)
                observed.append((command, kwargs["input"]))
                stdout = ("".join(json.dumps(event) + "\n" for event in evidence_events(retry=retry))).encode()
                return run_live.subprocess.CompletedProcess(command, 0, stdout, b"")
            with mock.patch.object(run_live.subprocess, "run", side_effect=execute):
                for _ in range(2):
                    native.attach_sources(EVIDENCE_ENTRIES, list(EVIDENCE_DOCUMENTS), staged_at=EVIDENCE_STAGED_AT)
            self.assertEqual(native.evidence_group_requests, 2)
            self.assertEqual(len(native.evidence_receipts), 2)
            request = run_live.json_bytes(EVIDENCE_ENTRIES)
            for command, forwarded in observed:
                self.assertEqual(forwarded, request)
                self.assertEqual(command[command.index("--entries") + 1], "-")
                self.assertEqual([command[index + 1] for index, value in enumerate(command) if value == "--evidence"],
                                 list(EVIDENCE_DOCUMENTS))
            records = [json.loads(line) for line in (native.out / "commands.jsonl").read_text().splitlines()]
            for record in (record for record in records if record["state"] == "started"):
                self.assertEqual(record["stdin_sha256"], run_live.digest(request))
                self.assertEqual((native.out / record["stdin_path"]).read_bytes(), request)

    def test_evidence_prefix_refusal_or_invalid_last_receipt_is_retained_without_accepting_group(self):
        for refused in (False, True):
            with self.subTest(refusal=refused), tempfile.TemporaryDirectory() as directory:
                native = self.native_fixture(Path(directory))
                native.batch_evidence, native.book_id, native.owner_principal = True, "c" * 32, "operator"
                native.document_commitments = EVIDENCE_DOCUMENTS.copy()
                events = evidence_events()
                if refused:
                    events[1] = {"event": "error", "data": {"message": "post capability expired"}}
                else:
                    events[1]["data"]["documents"][1]["doc_commit"] = "f" * 64
                stdout = ("".join(json.dumps(event) + "\n" for event in events)).encode()
                completed = run_live.subprocess.CompletedProcess([], 6 if refused else 0, stdout, b"")
                with mock.patch.object(run_live.subprocess, "run", return_value=completed) as execute:
                    with self.assertRaises(run_live.CheckError):
                        native.attach_sources(EVIDENCE_ENTRIES, list(EVIDENCE_DOCUMENTS), staged_at=EVIDENCE_STAGED_AT)
                    execute.assert_called_once()
                self.assertEqual(native.evidence_receipts, {})
                self.assertEqual((native.out / "transcript/00001.stdout.jsonl").read_bytes(), stdout)

    def test_evidence_groups_require_complete_staging_and_uploaded_document_bindings_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            native.batch_evidence, native.book_id, native.owner_principal = True, "c" * 32, "operator"
            native.document_commitments = EVIDENCE_DOCUMENTS.copy()
            invalid = [([], list(EVIDENCE_DOCUMENTS), {}),
                       (EVIDENCE_ENTRIES * 2, list(EVIDENCE_DOCUMENTS), EVIDENCE_STAGED_AT),
                       (EVIDENCE_ENTRIES, ["e" * 64], EVIDENCE_STAGED_AT),
                       (EVIDENCE_ENTRIES, list(EVIDENCE_DOCUMENTS) * 2, EVIDENCE_STAGED_AT),
                       (EVIDENCE_ENTRIES, list(EVIDENCE_DOCUMENTS), {EVIDENCE_ENTRIES[0]: 50}),
                       (EVIDENCE_ENTRIES, list(EVIDENCE_DOCUMENTS), {key: True for key in EVIDENCE_ENTRIES})]
            many_entries = [f"{index:032x}" for index in range(4096)]
            documents = [f"{index:064x}" for index in range(5)]
            native.document_commitments.update({oid: "f" * 64 for oid in documents})
            invalid.append((many_entries, documents, {entry: index + 1 for index, entry in enumerate(many_entries)}))
            with mock.patch.object(run_live.subprocess, "run") as execute:
                for entries, documents, staged_at in invalid:
                    with self.subTest(entries=len(entries), documents=len(documents)), self.assertRaises(run_live.CheckError):
                        native.attach_sources(entries, documents, staged_at=staged_at)
                execute.assert_not_called()
            self.assertEqual(native.calls, 0)

    def test_default_evidence_path_keeps_legacy_individual_attachment_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            native = self.native_fixture(Path(directory))
            with mock.patch.object(native, "one", return_value={}) as attach:
                native.attach_sources(EVIDENCE_ENTRIES, list(EVIDENCE_DOCUMENTS), staged_at=EVIDENCE_STAGED_AT)
            self.assertEqual(attach.call_count, 2)
            for entry, call in zip(EVIDENCE_ENTRIES, attach.call_args_list, strict=True):
                self.assertEqual(call.args[0], ["document", "attach", entry, "--evidence", "a" * 64,
                                               "--evidence", "b" * 64])
            self.assertEqual(native.evidence_group_requests, 0)

    def test_group_selection_reaches_daemon_as_retained_stdin_and_failure_keeps_receipts(self):
        # Replace only the book setup and native subprocess. Exercise the actual
        # run loop, Native.one and Native.execute at the new transport boundary.
        # fad has no files root, so sending the saved selection's host path would
        # refuse before any stage operation; stdin must carry those exact bytes.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared, out = root / "prepared", root / "execution"
            prepared.mkdir()
            out.mkdir()
            for name in ("raw.csv", "legacy.csv", "receipt.json", "provenance.jsonl",
                         "records.jsonl", "expected_tb.json", "columns.toml"):
                (prepared / name).write_bytes(f"retained {name}\n".encode())
            (prepared / "account_map.json").write_text("{}", encoding="utf-8")
            expected = {**EXPECTED, "period_start": "2025-12-01", "entry_count": 2,
                        "entries": [{"entry_id": "first"}, {"entry_id": "second"}]}
            chunks = [{"entry_vid": "first", "proposal_digest": "a" * 64, "leg_count": 2},
                      {"entry_vid": "second", "proposal_digest": "b" * 64, "leg_count": 2}]
            for name in ("fa", "fa-verify", "fad"):
                (root / name).write_bytes(("test executable bytes: " + name).encode())
            native = run_live.Native(root / "fa", root / "fa-verify", out, 10,
                                     root / "fad", stage_group_size=2)
            daemon = mock.Mock()
            daemon.poll.return_value = None
            real_one = native.one

            def setup_or_stage(args, **kwargs):
                if args[:2] == ["document", "read"]:
                    Path(args[args.index("--out") + 1]).write_bytes((prepared / args[2]).read_bytes())
                    return {"data": {"view": "full"}}
                if args[:2] == ["migrate", "open"]:
                    return {"data": {"run_vid": "run"}}
                if args[:4] == ["migrate", "import", "--action", "prepare"]:
                    return {"data": {"mode": "FullDetail", "sole_opening_source": True,
                                     "chunks": chunks, "package_oid": "package", "already_recorded": True}}
                if args[:4] == ["migrate", "import", "--action", "stage"]:
                    return real_one(args, **kwargs)
                if args[0] == "tb":
                    return {"data": {"rows": []}}
                return {"data": {}}

            approvals = [["1" * 32, "2" * 32], ["3" * 32, "4" * 32]]
            progress = (json.dumps({"event": "migration_import_progress", "data": {
                "atomic": False, "selected_count": 2, "completed_count": 1,
                "chunks": [{"chunk_index": 0, "entry_vid": "first", "recorded_at": 42}],
            }}) + "\n").encode()
            refusal = b'{"event":"error","data":{"message":"second chunk refused"}}\n'
            stdout = progress + refusal
            completed = run_live.subprocess.CompletedProcess([], 6, stdout, b"native refusal\n")
            with (
                mock.patch.object(native, "one", side_effect=setup_or_stage),
                mock.patch.object(native, "document", side_effect=lambda path, *_: path.name),
                mock.patch.object(native, "head", return_value=41),
                mock.patch.object(native, "approvals", side_effect=approvals),
                mock.patch.object(native, "start_bulk", side_effect=lambda: setattr(native, "daemon", daemon)),
                mock.patch.object(run_live.subprocess, "run", return_value=completed) as execute,
                self.assertRaisesRegex(run_live.CheckError, "exited 6"),
            ):
                run_live.run(native, prepared, "fixture", expected)

            execute.assert_called_once()
            command = execute.call_args.args[0]
            self.assertEqual(command[command.index("--via") + 1], "fad")
            self.assertEqual(command[command.index("--intent") + 1], "-")
            saved = out / "stage-00000.json"
            self.assertNotIn(str(saved), command)
            request_bytes = saved.read_bytes()
            self.assertEqual(execute.call_args.kwargs["input"], request_bytes)
            self.assertEqual(json.loads(request_bytes), {"chunks": [
                {"index": index, "approvals": approved} for index, approved in enumerate(approvals)
            ]})
            calls = [json.loads(line) for line in (out / "commands.jsonl").read_text().splitlines()]
            self.assertEqual(calls[0]["stdin_sha256"], run_live.digest(request_bytes))
            self.assertEqual(calls[0]["stdin_bytes"], len(request_bytes))
            self.assertEqual((out / calls[0]["stdin_path"]).read_bytes(), request_bytes)
            self.assertEqual(calls[1]["exit"], 6)
            self.assertEqual((out / "transcript" / "00001.stdout.jsonl").read_bytes(), stdout)
            self.assertEqual((out / "transcript" / "00001.stderr.txt").read_bytes(), b"native refusal\n")

    def test_group_receipts_bind_exact_proposals_and_separate_publications(self):
        chunks = [{"entry_vid": "first", "proposal_digest": "approved-first"},
                  {"entry_vid": "second", "proposal_digest": "approved-second"}]
        good = {"event": "migration_import_group_staged", "data": {
            "package_oid": "package", "run_vid": "run", "atomic": False,
            "selected_count": 2, "completed_count": 2, "recorded_count": 5,
            "chunk_count": 5, "run_state": "Open", "ready_to_finalize": True,
            "chunks": [{"chunk_index": 3 + index, **chunk, "recorded_at": 91 + index,
                        "already_recorded": False} for index, chunk in enumerate(chunks)],
        }}
        parameters = dict(start=3, total=5, package="D:package", run_vid="run")
        self.assertEqual(len(run_live.check_staged_group(good, chunks, **parameters)), 2)
        mutations = [
            lambda data: data.update(package_oid="other"),
            lambda data: data.update(run_vid="other"),
            lambda data: data.update(atomic=True),
            lambda data: data.update(recorded_count=4),
            lambda data: data.update(completed_count=1),
            lambda data: data.update(ready_to_finalize=False),
            lambda data: data["chunks"].reverse(),
            lambda data: data["chunks"][1].update(proposal_digest="unapproved"),
            lambda data: data["chunks"][1].update(entry_vid="first"),
            lambda data: data["chunks"][1].update(recorded_at=91),
            lambda data: data["chunks"][1].update(recorded_at=True),
            lambda data: data["chunks"][1].update(already_recorded=True),
        ]
        for index, mutate in enumerate(mutations):
            wrong = copy.deepcopy(good)
            mutate(wrong["data"])
            with self.subTest(mutation=index), self.assertRaises(run_live.CheckError):
                run_live.check_staged_group(wrong, chunks, **parameters)
        retried = copy.deepcopy(good)
        for receipt in retried["data"]["chunks"]:
            receipt["already_recorded"] = True
        self.assertEqual(run_live.check_staged_group(retried, chunks, already_recorded=True, **parameters),
                         retried["data"]["chunks"])

    def test_gross_movements_are_checked_even_when_every_net_is_unchanged(self):
        good = report()
        run_live.check_tb(good, EXPECTED)
        wrong = copy.deepcopy(good)
        # Omitting an equal debit and credit preserves every account's net.
        wrong["data"]["rows"][0]["debits"] = "100.00 GBP"
        wrong["data"]["rows"][0]["credits"] = "0.00 GBP"
        with self.assertRaisesRegex(run_live.CheckError, "differs from source"):
            run_live.check_tb(wrong, EXPECTED)

    def test_account_and_duplicate_row_checks_cannot_be_replaced_by_balance_flag(self):
        wrong = report()
        wrong["data"]["balanced"] = True
        wrong["data"]["rows"][0]["code"] = "different-category"
        with self.assertRaisesRegex(run_live.CheckError, "differs from source"):
            run_live.check_tb(wrong, EXPECTED)
        wrong = report()
        wrong["data"]["rows"].append(copy.deepcopy(wrong["data"]["rows"][0]))
        with self.assertRaisesRegex(run_live.CheckError, "duplicate native"):
            run_live.check_tb(wrong, EXPECTED)

    def test_staged_rows_must_be_invisible_even_when_balanced(self):
        with self.assertRaisesRegex(run_live.CheckError, "differs from source"):
            run_live.check_tb(report(), EXPECTED, invisible=True)
        run_live.check_tb({"data": {"rows": []}}, EXPECTED, invisible=True)

    def test_pending_amounts_are_not_posted_source_activity(self):
        wrong = report()
        wrong["data"]["rows"][0]["credits_pending"] = "0.01 GBP"
        with self.assertRaisesRegex(run_live.CheckError, "unexpected pending"):
            run_live.check_tb(wrong, EXPECTED)

    def test_native_amounts_have_one_explicit_currency_and_exact_scale(self):
        self.assertEqual(run_live.money("-12345678901234567890.09 GBP"), -1234567890123456789009)
        for malformed in [1.0, "1.00 USD", "1e2 GBP", "1.000 GBP", "NaN GBP", "1.00", " 1.00 GBP"]:
            with self.subTest(malformed=malformed), self.assertRaises(run_live.CheckError):
                run_live.money(malformed)

    def test_every_exported_source_row_must_survive_not_only_aggregate_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = io.StringIO(newline="")
            writer = csv.writer(source, lineterminator="\n")
            writer.writerow(["entry_id", "effective_date", "account_code", "side", "amount", "currency", "description", "memo"])
            memo = 'source_row=hash:1; quoted "supplier", detail\n# second physical line\r\n'
            source_rows = [
                ["original", "2025-03-10", "published-type", "D", "105.00", "GBP", "model", memo],
                ["original", "2025-03-10", "published-payment-offset", "C", "105.00", "GBP", "model", memo],
                ["original", "2025-03-10", "published-type", "C", "5.00", "GBP", "model", "source_row=hash:2"],
                ["original", "2025-03-10", "published-payment-offset", "D", "5.00", "GBP", "model", "source_row=hash:2"],
            ]
            writer.writerows(source_rows)
            (root / "legacy.csv").write_bytes(source.getvalue().encode())

            def exported(rows, name):
                output = io.StringIO(newline="")
                output.write("# fa_csv_gl_v1|metadata\n")
                writer = csv.writer(output, lineterminator="\n")
                writer.writerow(["entry_id", "line_no", "effective_date", "recorded_seq", "entry_class", "account_code", "side",
                                 "amount", "currency", "unit_scale", "description", "migrated_from", "memo"])
                for index, row in enumerate(rows, 1):
                    _, day, account, side, amount, currency, description, line_memo = row
                    writer.writerow(["native-vid", index, day, "99", "12", account, side, amount, currency, "2", description, "test-source:original", line_memo])
                path = root / name
                path.write_bytes(output.getvalue().encode())
                return path

            good = exported(source_rows, "good.csv")
            self.assertEqual(run_live.check_export(good, root, EXPECTED), {"entries": 1, "legs": 4})
            wrong = copy.deepcopy(source_rows)
            wrong[0][-1] = wrong[1][-1] = "source_row=hash:3"
            with self.assertRaisesRegex(run_live.CheckError, "lost, duplicated or changed"):
                run_live.check_export(exported(wrong, "wrong-identity.csv"), root, EXPECTED)
            wrong = copy.deepcopy(source_rows)
            wrong[0][1] = wrong[1][1] = "2025-03-11"
            with self.assertRaisesRegex(run_live.CheckError, "lost, duplicated or changed"):
                run_live.check_export(exported(wrong, "wrong-date.csv"), root, EXPECTED)
            wrong_lineage = root / "wrong-lineage.csv"
            wrong_lineage.write_bytes(good.read_bytes().replace(b"test-source:original", b"test-source:wrong-journal"))
            with self.assertRaisesRegex(run_live.CheckError, "lost, duplicated or changed"):
                run_live.check_export(wrong_lineage, root, EXPECTED)

    def test_prepare_event_contract_refuses_missing_or_ambiguous_native_result(self):
        for events in [[], [{"event": "another_event"}], [{"event": "report_certificate"}] * 2]:
            with self.assertRaises(run_live.CheckError):
                run_live.event_named(events, "report_certificate")


if __name__ == "__main__":
    unittest.main()
