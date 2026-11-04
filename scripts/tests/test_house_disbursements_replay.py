"""Negative controls for the House native replay's independent comparisons."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import house_disbursements_replay as replay


class HouseReplayControls(unittest.TestCase):
    def source_rows(self):
        # Deliberately small test data; never presented as publisher evidence.
        return [
            {"entry_id": "scope:1", "effective_date": "2026-06-30", "account_code": account,
             "side": side, "amount": "123.45", "currency": "USD", "description": "Analysis entry",
             "memo": "source_row=original-row-17; transaction_date=; date_policy=quarter-end"}
            for account, side in (("expense-1", "D"), ("offset", "C"))
        ]

    def write_source(self, directory, rows=None):
        rows = rows or self.source_rows()
        with (directory / "legacy.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def export(self, rows=None):
        return [{"entry_id": "native-id-1", "line_no": str(index), "entry_class": "12",
                 "effective_date": row["effective_date"], "account_code": row["account_code"],
                 "side": row["side"], "amount": row["amount"], "currency": "USD", "unit_scale": "2",
                 "description": row["description"], "memo": row["memo"],
                 "migrated_from": "house-test:" + row["entry_id"], "dimension_set_v1": ""}
                for index, row in enumerate(rows or self.source_rows(), 1)]

    def write_export(self, directory, rows):
        path = directory / "native.csv"
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        return path

    def expected(self):
        return {"source_system": "house-test", "entry_count": 1, "leg_count": 2}

    def trial_balance(self, rows):
        return {"event": "trial_balance", "book": "test-book",
                "coordinate": {"effective": "period:FY2026-P06", "known_at": 17, "branch": "trunk"},
                "data": {"periods": ["FY2026-P06"], "effective_through": "2026-06-30",
                         "known_at": 17, "mode": "stock", "activity": False,
                         "dimension": None, "balanced": True, "rows": rows}}

    def test_full_dated_lineage_matches_and_offsetting_twin_does_not(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.write_source(directory)
            rows = self.export()
            path = self.write_export(directory, rows)
            self.assertEqual(replay.check_export(path, directory, self.expected()), {"entries": 1, "legs": 2})
            for row in rows:
                row["amount"] = "123.46"
            path = self.write_export(directory, rows)
            with self.assertRaisesRegex(replay.live.CheckError, "dated source legs"):
                replay.check_export(path, directory, self.expected())

    def test_changed_missing_date_lineage_or_dropped_repeat_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.write_source(directory)
            for field, value in (("memo", "transaction_date=2026-06-30"),
                                 ("effective_date", "2026-05-31"),
                                 ("migrated_from", "house-test:another-row")):
                rows = self.export()
                rows[0][field] = value
                with self.subTest(field=field), self.assertRaises(replay.live.CheckError):
                    replay.check_export(self.write_export(directory, rows), directory, self.expected())
            with self.assertRaises(replay.live.CheckError):
                replay.check_export(self.write_export(directory, self.export()[:1]), directory, self.expected())
            with self.assertRaises(replay.live.CheckError):
                replay.check_export(self.write_export(directory, self.export() * 2), directory, self.expected())

    def test_export_refuses_unexpected_currency_or_attribution(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.write_source(directory)
            for field, value in (("currency", "GBP"), ("entry_class", "0"),
                                 ("dimension_set_v1", "3:" + "1" * 32)):
                rows = self.export()
                rows[0][field] = value
                with self.subTest(field=field), self.assertRaises(replay.live.CheckError):
                    replay.check_export(self.write_export(directory, rows), directory, self.expected())

    def test_zero_net_activity_cannot_disappear_from_trial_balance(self):
        control = {"period": "FY2026-P06", "at_date": "2026-06-30", "accounts": [
            {"account": "expense-1", "debit_minor": "12345", "credit_minor": "12345", "signed_minor": "0"},
        ]}
        event = self.trial_balance([{"code": "expense-1", "debits": "123.45 USD", "credits": "123.45 USD",
                                    "net": "0.00 USD", "debits_pending": "0.00 USD", "credits_pending": "0.00 USD"}])
        self.assertEqual(replay.check_tb(event, control, known_at=17, book_id="test-book")["cells"], 1)
        with self.assertRaisesRegex(replay.live.CheckError, "gross/net"):
            replay.check_tb(self.trial_balance([]), control, known_at=17, book_id="test-book")
        event["data"]["rows"][0]["debits_pending"] = "0.01 USD"
        with self.assertRaisesRegex(replay.live.CheckError, "pending"):
            replay.check_tb(event, control, known_at=17, book_id="test-book")

    def test_identical_amounts_cannot_hide_a_stale_period_or_historical_prefix(self):
        control = {"period": "FY2026-P06", "at_date": "2026-06-30", "accounts": []}
        event = self.trial_balance([])
        replay.check_tb(event, control, known_at=17, book_id="test-book", invisible=True)
        mutations = [("periods", ["FY2026-P07"]), ("effective_through", "2026-07-31"),
                     ("known_at", 18), ("mode", "flow"), ("activity", True),
                     ("dimension", {"program": "unexpected"}), ("balanced", False)]
        for field, value in mutations:
            changed = json.loads(json.dumps(event))
            changed["data"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(replay.live.CheckError, "requested book"):
                replay.check_tb(changed, control, known_at=17, book_id="test-book", invisible=True)
        for field, value in (("known_at", 18), ("effective", "period:FY2026-P07"), ("branch", "other")):
            changed = json.loads(json.dumps(event))
            changed["coordinate"][field] = value
            with self.subTest(coordinate=field), self.assertRaises(replay.live.CheckError):
                replay.check_tb(changed, control, known_at=17, book_id="test-book", invisible=True)
        with self.assertRaises(replay.live.CheckError):
            replay.check_tb(event, control, known_at=17, book_id="another-book", invisible=True)

    def test_balanced_native_negative_keeps_source_and_changes_one_real_pair(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.write_source(directory)
            original = (directory / "legacy.csv").read_bytes()
            changed = list(csv.DictReader(io.StringIO(replay.monetary_twin(directory).decode())))
            self.assertEqual([row["amount"] for row in changed], ["123.46", "123.46"])
            self.assertEqual([row["side"] for row in changed], ["D", "C"])
            self.assertEqual((directory / "legacy.csv").read_bytes(), original)
            self.assertEqual([row["memo"] for row in changed], [row["memo"] for row in self.source_rows()])


if __name__ == "__main__":
    unittest.main()
