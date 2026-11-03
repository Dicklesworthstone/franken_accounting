"""Adversarial controls for the live harness's independently checked results."""
from __future__ import annotations

import copy
import csv
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


class LiveOracleControls(unittest.TestCase):
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
