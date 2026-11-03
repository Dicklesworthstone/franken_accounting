"""Source/comparator tests, never a substitute for a native Square One run.

Native-shaped reports and receipt identities below are expressly test-only.
Their amounts are folded directly from the pinned source's printed literals.
"""

from contextlib import redirect_stderr
from copy import deepcopy
import csv
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_replay as replay
import blmis_square_one as source
import blmis_square_one_replay as runner
import public_ledger as ledger


def raw_cents(text):
    if text == "-":
        return 0
    sign = -1 if text.startswith("(") else 1
    return sign * int(Decimal(text.strip("()").replace(",", "")) * 100)


def native_shaped_fixture(rows):
    """A comparator fixture with fake IDs, not an executed accounting result."""
    running = debit = credit = 0
    lines, posted = [], {}
    for row in rows:
        amount = raw_cents(row["deposits_literal"])
        if row["withdrawals_literal"] not in ("*", "* [1]"):
            amount += raw_cents(row["withdrawals_literal"])
        running += amount
        if not amount:
            continue
        identity = hashlib.sha256(("test-only:" + row["row_id"]).encode()).hexdigest()
        receipt = {"vid": identity[:32], "entry_digest": identity, "recorded_at": 100 + len(lines)}
        posted[row["row_id"]] = receipt
        debit += max(-amount, 0)
        credit += max(amount, 0)
        lines.append({"account": source.PRINCIPAL_ACCOUNT, "unit": "USD", "entry_digest": identity,
                      "leg_index": 0, "recorded_at": receipt["recorded_at"], "effective_date": row["date"],
                      "class": "Original", "debits": f"{source.money(max(-amount, 0))} USD",
                      "credits": f"{source.money(max(amount, 0))} USD",
                      "running_balance": f"{source.money(-running)} USD"})
    data = {"label": runner.LABEL, "effective_from": rows[0]["date"], "effective_through": rows[-1]["date"],
            "known_at": 500, "lines": lines,
            "cells": [{"account": source.PRINCIPAL_ACCOUNT, "unit": "USD", "opening": "0.00 USD",
                       "line_count": len(lines), "debits": f"{source.money(debit)} USD",
                       "credits": f"{source.money(credit)} USD", "net_change": f"{source.money(-running)} USD",
                       "closing": f"{source.money(-running)} USD"}]}
    return data, posted


class SquareOneReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.metadata = source.load_fixture()
        cls.observations = runner.source_observations(cls.rows)
        cls.report, cls.posted = native_shaped_fixture(cls.rows)

    def test_independent_source_fold_retains_all_rows_and_published_disagreements(self):
        observations = self.observations
        self.assertEqual(len(observations), 1050)
        self.assertEqual(sum(row["star"] for row in observations), 709)
        self.assertEqual(sum(row["principal_movement_cents"] != 0 for row in observations), 340)
        self.assertEqual(sum(row["principal_movement_cents"] == 0 for row in observations), 710)
        self.assertEqual(observations[-1]["source_principal_cents"], 224442500)
        self.assertEqual(observations[-1]["printed_principal_cents"], 224442800)
        gaps = runner.gap_map(observations)
        self.assertEqual(len(gaps), 1010)
        self.assertEqual(max(map(abs, gaps.values())), 300)
        self.assertEqual(observations[-1]["source_minus_printed_cents"], -300)
        self.assertEqual(sum(row["reported_cents"] for row in observations if row["star"]), -40960700)

    def test_star_is_not_a_numeric_zero_and_unknown_or_missing_values_refuse(self):
        for literal in ("*", "* [1]", "", "1.00", "1,00", "NaN", "1e6", "(1,000", "00"):
            with self.subTest(literal=literal), self.assertRaises(ledger.ReplayError):
                runner.literal_cents(literal)
        self.assertEqual(runner.literal_cents("(0)"), 0)
        self.assertEqual(runner.literal_cents("(1,000)"), -100000)

    def test_missing_footnote_or_reintroduced_starred_cash_is_refused(self):
        index = next(i for i, row in enumerate(self.rows) if row["star"])
        rows = deepcopy(self.rows)
        rows[index]["footnote_premises"] = []
        with self.assertRaisesRegex(ledger.ReplayError, "footnote"):
            runner.source_observations(rows)
        rows = deepcopy(self.rows)
        for key in ("withdrawals_cents", "cash_movement_cents", "principal_movement_cents"):
            rows[index][key] = rows[index]["reported_cents"]
        with self.assertRaisesRegex(ledger.ReplayError, "independent literals"):
            runner.source_observations(rows)

    def test_positive_withholding_cancellations_keep_their_printed_sign(self):
        cancellations = [row for row in self.rows if row["description"].startswith("CXL ")]
        self.assertEqual(len(cancellations), 3)
        self.assertTrue(all(row["withdrawals_cents"] > 0 for row in cancellations))
        rows = deepcopy(self.rows)
        index = self.rows.index(cancellations[0])
        for key in ("withdrawals_cents", "cash_movement_cents", "principal_movement_cents"):
            rows[index][key] *= -1
        with self.assertRaisesRegex(ledger.ReplayError, "independent literals"):
            runner.source_observations(rows)

    def test_native_comparison_checks_1050_observations_and_reports_1010_gaps(self):
        comparison = runner.compare_native_observations(self.report, self.rows, self.posted, self.observations)
        self.assertEqual(comparison["source_rows"], 1050)
        self.assertEqual(comparison["native_lines"], 340)
        self.assertEqual(comparison["zero_principal_observations"], 710)
        self.assertEqual(comparison["printed_rows_off"], 1010)
        self.assertEqual(comparison["closing_gap_cents"], -300)
        self.assertTrue(comparison["native_matches_source_movements_exactly"])
        self.assertFalse(comparison["all_printed_balances_equal"])

    def test_one_cent_error_fails_even_inside_the_three_dollar_source_gap(self):
        data = deepcopy(self.report)
        discrepant_digests = {self.posted[row["source_row_id"]]["entry_digest"]
                              for row in self.observations
                              if row["source_minus_printed_cents"] and row["source_row_id"] in self.posted}
        index = next(i for i, line in enumerate(data["lines"])
                     if line["entry_digest"] in discrepant_digests)
        data["lines"][index]["running_balance"] = source.money(replay.usd(data["lines"][index]["running_balance"]) + 1) + " USD"
        with self.assertRaisesRegex(ledger.ReplayError, "running principal"):
            runner.compare_native_observations(data, self.rows, self.posted, self.observations)

    def test_altered_gap_map_cannot_hide_a_native_error(self):
        observations = deepcopy(self.observations)
        observations[-1]["source_minus_printed_cents"] += 1
        with self.assertRaisesRegex(ledger.ReplayError, "altered source oracle"):
            runner.compare_native_observations(self.report, self.rows, self.posted, observations)

    def test_missing_repeated_reordered_and_wrong_scope_native_lines_are_refused(self):
        cases = []
        data = deepcopy(self.report)
        data["lines"].pop()
        cases.append(data)
        data = deepcopy(self.report)
        data["lines"][1] = deepcopy(data["lines"][0])
        cases.append(data)
        data = deepcopy(self.report)
        data["lines"][0], data["lines"][1] = data["lines"][1], data["lines"][0]
        cases.append(data)
        data = deepcopy(self.report)
        data["label"] = replay.LABEL
        cases.append(data)
        data = deepcopy(self.report)
        data["known_at"] = 101
        cases.append(data)
        for index, data in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ledger.ReplayError):
                runner.compare_native_observations(data, self.rows, self.posted, self.observations)

    def test_zero_observation_is_checked_and_never_becomes_a_posting(self):
        monetary_ids = set(self.posted)
        self.assertEqual(len(monetary_ids), 340)
        self.assertTrue(all(row["row_id"] not in monetary_ids for row in self.rows if row["star"]))
        zero = next(i for i, row in enumerate(self.rows) if row["principal_movement_cents"] == 0)
        rows = deepcopy(self.rows)
        rows[zero]["printed_balance_cents"] += 100
        with self.assertRaisesRegex(ledger.ReplayError, "independent literals"):
            runner.compare_native_observations(self.report, rows, self.posted, self.observations)

    def test_prepared_annual_controls_and_680_legs_match_independent_source(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            source.prepare(package)
            controls = json.loads((package / "controls.json").read_text())
            self.assertEqual(controls, runner.annual_source_controls(self.observations))
            self.assertEqual(len(controls), 10)
            entries = replay.normalized_entries(package / "legacy.csv", self.rows, source_id=source.SOURCE_ID)
            self.assertEqual(len(entries), 340)
            self.assertEqual(sum(len(entry["legs"]) for entry in entries), 680)
            self.assertTrue(all(entry["legs"][0]["party"] == source.PRINCIPAL_ACCOUNT for entry in entries))
            with self.assertRaisesRegex(ledger.ReplayError, "differs from source"):
                replay.normalized_entries(package / "legacy.csv", self.rows)

    def test_cross_case_memo_and_extra_posting_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            source.prepare(package)
            with (package / "legacy.csv").open(newline="") as stream:
                records = list(csv.DictReader(stream))
            changed = deepcopy(records)
            changed[0]["memo"] = changed[0]["memo"].replace(source.SOURCE_ID, "SRC-BLM-001")
            for name, rows in (("wrong-citation.csv", changed), ("extra-row.csv", records + [records[0]])):
                path = package / name
                path.write_bytes(source.csv_bytes(source.LEGACY_COLUMNS, rows))
                with self.assertRaises(ledger.ReplayError):
                    replay.normalized_entries(path, self.rows, source_id=source.SOURCE_ID)

    def test_missing_binary_is_unrun_without_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "untouched"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = runner.main(["run", "--out", str(output), "--fa", str(output / "missing"),
                                      "--fa-verify", str(output / "also-missing")])
            self.assertEqual(status, 4)
            self.assertEqual(json.loads(stderr.getvalue())["status"], "UNRUN")
            self.assertFalse(output.exists())

    def test_existing_evidence_directory_is_never_overwritten_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            sentinel = output / "keep.txt"
            sentinel.write_text("original evidence")
            with mock.patch.object(runner, "run_native", side_effect=source.SourceError("destination exists")), \
                    redirect_stderr(io.StringIO()):
                status = runner.main(["run", "--out", str(output), "--fa", sys.executable,
                                      "--fa-verify", sys.executable])
            self.assertEqual(status, 1)
            self.assertEqual(sentinel.read_text(), "original evidence")
            self.assertFalse((output / "failure.json").exists())


if __name__ == "__main__":
    unittest.main()
