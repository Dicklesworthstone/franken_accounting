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
