"""Literal/source oracle tests; fake native identities are comparator fixtures only.

Successful tests do not claim that native binaries executed. The complete
runtime driver must independently finish before it emits a PASS report.
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
import blmis_magnify as source
import blmis_magnify_replay as runner
import blmis_replay as replay
import public_ledger as ledger


def raw_cents(text):
    if text == "-":
        return 0
    sign = -1 if text.startswith("(") else 1
    return sign * int(Decimal(text.strip("()").replace(",", "")) * 100)


def native_shaped_fixture(rows):
    """Independent raw-literal amounts, deliberately synthetic report identities."""
    account = rows[0]["account"]
    running = debit = credit = 0
    lines, posted = [], {}
    for row in rows:
        amount = raw_cents(row["deposits_literal"])
        if row["withdrawals_literal"] not in ("*", "* [4]"):
            amount += raw_cents(row["withdrawals_literal"])
        amount += raw_cents(row["transfers_in_literal"]) + raw_cents(row["transfers_out_literal"])
        running += amount
        if not amount:
            continue
        identity = hashlib.sha256(("test-only:" + row["row_id"]).encode()).hexdigest()
        receipt = {"vid": identity[:32], "entry_digest": identity, "recorded_at": 100 + len(lines)}
        posted[row["row_id"]] = receipt
        debit += max(-amount, 0)
        credit += max(amount, 0)
        lines.append({"account": f"BLMIS-{account}", "unit": "USD", "entry_digest": identity,
                      "leg_index": 0, "recorded_at": receipt["recorded_at"], "effective_date": row["date"],
                      "class": "Original", "debits": f"{source.money(max(-amount, 0))} USD",
                      "credits": f"{source.money(max(amount, 0))} USD",
                      "running_balance": f"{source.money(-running)} USD"})
    data = {"label": runner.label(account), "effective_from": rows[0]["date"], "effective_through": rows[-1]["date"],
            "known_at": 10000, "lines": lines,
            "cells": [{"account": f"BLMIS-{account}", "unit": "USD", "opening": "0.00 USD",
                       "line_count": len(lines), "debits": f"{source.money(debit)} USD",
                       "credits": f"{source.money(credit)} USD", "net_change": f"{source.money(-running)} USD",
                       "closing": f"{source.money(-running)} USD"}]}
    return data, posted


class MagnifyReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows, cls.metadata = source.load_fixture()
        cls.rows = source.computation_order(rows)
        cls.observations = runner.source_observations(cls.rows)
        cls.accounts = replay.grouped_accounts(cls.rows)
        cls.reports, cls.posted, cls.comparisons = {}, {}, {}
        for account, selected in cls.accounts.items():
            cls.reports[account], cls.posted[account] = native_shaped_fixture(selected)
            observations = [row for row in cls.observations if row["account"] == account]
            cls.comparisons[account] = runner.compare_native_observations(
                cls.reports[account], selected, cls.posted[account], observations)

    def test_complete_six_account_population_retains_stars_and_literal_zero_types(self):
        observations = self.observations
        self.assertEqual(len(observations), 2364)
        self.assertEqual({row["account"] for row in observations}, set(source.ACCOUNTS))
        self.assertEqual(sum(row["star"] for row in observations), 717)
        self.assertEqual(sum(row["principal_movement_cents"] != 0 for row in observations), 1586)
        self.assertEqual(sum(row["principal_movement_cents"] == 0 for row in observations), 778)
        transfers = [row for row in observations if row["transfer_credit_role"] == "oracle_output"]
        self.assertEqual(len(transfers), 58)
        self.assertEqual(sum(row["principal_movement_cents"] == 0 for row in transfers), 55)
        self.assertEqual(sum(row["principal_movement_cents"] == 0 and not row["star"]
                             and row["transfer_credit_role"] == "not_applicable" for row in observations), 6)
        self.assertEqual(sum(row["reported_cents"] for row in observations if row["star"]), -68275700)
        self.assertEqual(sum(row["withdrawals_cents"] > 0 for row in self.rows), 43)

    def test_all_printed_discrepancies_are_reported_without_a_tolerance(self):
        expected = {"1FN024": (342, 327, 330, 4200, -4200), "1FN025": (58, 45, 0, 0, 0),
                    "1FN037": (1927, 1179, 1920, 1800, 1600), "1FN073": (6, 6, 2, 100, 100),
                    "1FN097": (4, 4, 0, 0, 0), "1FR051": (27, 25, 0, 0, 0)}
        keys = ("source_rows", "native_lines", "printed_rows_off", "maximum_printed_gap_cents", "closing_gap_cents")
        for account, values in expected.items():
            with self.subTest(account=account):
                self.assertEqual(tuple(self.comparisons[account][key] for key in keys), values)
                self.assertTrue(self.comparisons[account]["native_matches_source_movements_exactly"])

    def test_unknown_blank_and_star_literals_are_not_numeric_zero(self):
        for text in ("*", "* [4]", "", "1.00", "1,00", "NaN", "1e6", "(1,000", "00", "5 [1]"):
            with self.subTest(text=text), self.assertRaises(ledger.ReplayError):
                runner.literal_cents(text)
        self.assertEqual(runner.literal_cents("(0)"), 0)
        self.assertEqual(runner.literal_cents("(1,000)"), -100000)
        self.assertEqual(runner.reported_cents("(3,000,000) [1]"), (-300000000, "[1]"))
        for text in ("5 [5]", "5[1]", "5 [1] [2]", "* [4]"):
            with self.subTest(text=text), self.assertRaises(ledger.ReplayError):
                runner.reported_cents(text)

    def test_tax_premises_are_scoped_to_correct_account_and_marker(self):
        index = next(i for i, row in enumerate(self.rows) if row["star"])
        for field, value in (("footnote_premises", []),
                             ("footnote_premises", ["SRC-BLM-006:1FN024:footnote:4"]),
                             ("withdrawal_marker", "[1]"), ("star", 1)):
            rows = deepcopy(self.rows)
            rows[index][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ledger.ReplayError, "footnote"):
                runner.source_observations(rows)

    def test_tax_cash_reintroduction_and_corrective_sign_reversal_fail(self):
        for index in (next(i for i, row in enumerate(self.rows) if row["star"]),
                      next(i for i, row in enumerate(self.rows) if row["withdrawals_cents"] > 0)):
            rows = deepcopy(self.rows)
            value = rows[index]["reported_cents"] if rows[index]["star"] else -rows[index]["withdrawals_cents"]
            for field in ("withdrawals_cents", "cash_movement_cents", "principal_movement_cents"):
                rows[index][field] = value
            with self.subTest(index=index), self.assertRaisesRegex(ledger.ReplayError, "independent literals"):
                runner.source_observations(rows)

    def test_duplicate_wrong_source_and_reordered_same_day_rows_fail(self):
        rows = deepcopy(self.rows)
        rows[0]["row_id"] = rows[0]["row_id"].replace("SRC-BLM-006", "SRC-BLM-001")
        cases = [rows, self.rows + [self.rows[-1]]]
        index = next(i for i in range(len(self.rows) - 1) if self.rows[i]["date"] == self.rows[i + 1]["date"])
        rows = deepcopy(self.rows)
        rows[index], rows[index + 1] = rows[index + 1], rows[index]
        cases.append(rows)
        for index, rows in enumerate(cases):
            with self.subTest(index=index), self.assertRaisesRegex(ledger.ReplayError, "computation order"):
                runner.source_observations(rows)

    def test_transfer_oracle_status_and_partial_literal_description_are_retained(self):
        partial = next(row for row in self.rows if row["row_id"] == source.PARTIAL_DESCRIPTION_ROW)
        self.assertEqual(partial["description"], "(1FN024)")
        self.assertEqual(partial["reported_cents"], 500000000)
        observed = next(row for row in self.observations if row["source_row_id"] == source.PARTIAL_DESCRIPTION_ROW)
        self.assertEqual(observed["transfer_credit_role"], "oracle_output")
        self.assertEqual(observed["principal_movement_cents"], 0)
        rows = deepcopy(self.rows)
        index = self.rows.index(partial)
        rows[index]["transfer_credit_role"] = "independently_reproduced"
        with self.assertRaisesRegex(ledger.ReplayError, "relabeled"):
            runner.source_observations(rows)

    def test_one_cent_native_error_fails_inside_a_published_forty_two_dollar_gap(self):
        account = "1FN024"
        data = deepcopy(self.reports[account])
        data["lines"][-1]["running_balance"] = source.money(replay.usd(data["lines"][-1]["running_balance"]) + 1) + " USD"
        observations = [row for row in self.observations if row["account"] == account]
        with self.assertRaisesRegex(ledger.ReplayError, "running principal"):
            runner.compare_native_observations(data, self.accounts[account], self.posted[account], observations)

    def test_altered_gap_or_omitted_zero_observation_cannot_hide_a_native_error(self):
        account = "1FN037"
        observations = deepcopy([row for row in self.observations if row["account"] == account])
        observations[-1]["source_minus_printed_cents"] += 1
        omitted = [row for row in self.observations if row["account"] == account]
        del omitted[next(i for i, row in enumerate(omitted) if row["star"])]
        for changed in (observations, omitted):
            with self.assertRaisesRegex(ledger.ReplayError, "altered source oracle"):
                runner.compare_native_observations(self.reports[account], self.accounts[account],
                                                   self.posted[account], changed)

    def test_missing_repeated_reordered_or_wrong_scope_native_lines_fail(self):
        account = "1FN025"
        original = self.reports[account]
        cases = []
        data = deepcopy(original)
        data["lines"].pop()
        cases.append(data)
        data = deepcopy(original)
        data["lines"][1] = deepcopy(data["lines"][0])
        cases.append(data)
        data = deepcopy(original)
        data["lines"][0], data["lines"][1] = data["lines"][1], data["lines"][0]
        cases.append(data)
        for field, value in (("label", runner.label("1FN024")), ("known_at", 101), ("known_at", True)):
            data = deepcopy(original)
            data[field] = value
            cases.append(data)
        observations = [row for row in self.observations if row["account"] == account]
        for index, changed in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ledger.ReplayError):
                runner.compare_native_observations(changed, self.accounts[account], self.posted[account], observations)

    def test_native_zero_carry_is_compared_without_a_fictitious_posting(self):
        account = "1FN037"
        self.assertEqual(len(self.posted[account]), 1179)
        self.assertTrue(all(row["row_id"] not in self.posted[account] for row in self.accounts[account] if row["star"]))
        selected = deepcopy(self.accounts[account])
        index = next(i for i, row in enumerate(selected) if row["star"])
        selected[index]["printed_balance_cents"] += 100
        observations = [row for row in self.observations if row["account"] == account]
        with self.assertRaisesRegex(ledger.ReplayError, "independent literals"):
            runner.compare_native_observations(self.reports[account], selected, self.posted[account], observations)

    def test_native_transfer_event_gap_is_34_dollars_not_later_42_dollars(self):
        scope = runner.transfer_scope(self.comparisons)
        self.assertFalse(scope["independent_credit_reproduction"])
        self.assertEqual(scope["transfer_oracle_observations"], 58)
        self.assertEqual(scope["zero_principal_transfer_observations"], 55)
        pair = scope["paired_source_credit"]
        self.assertEqual(pair["source_credited_principal_cents"], 281666100)
        self.assertEqual(pair["native_origin_principal_before_cents"], 281662700)
        self.assertEqual(pair["native_origin_principal_after_cents"], -3400)
        self.assertEqual(pair["source_credit_minus_native_available_cents"], 3400)
        self.assertEqual(self.comparisons["1FN024"]["closing_gap_cents"], -4200)
        self.assertFalse(scope["external_origin"]["origin_history_present"])
        self.assertEqual(scope["external_origin"]["source_credited_principal_cents"], 68200)
        changed = deepcopy(self.comparisons)
        origin = next(row for row in changed["1FN024"]["observations"] if row["source_row_id"] == runner.OUTWARD_TRANSFER)
        origin["native_principal_cents"] = 0
        with self.assertRaisesRegex(ledger.ReplayError, "transfer-event arithmetic"):
            runner.transfer_scope(changed)

    def test_all_91_printed_controls_and_3172_normalized_legs_match_independent_source(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            source.prepare(package)
            controls = json.loads((package / "controls.json").read_text())
            self.assertEqual(controls, runner.annual_source_controls(self.observations))
            self.assertEqual(sum(map(len, controls.values())), 91)
            entries = replay.normalized_entries(package / "legacy.csv", self.rows, source_id=source.SOURCE_ID)
            self.assertEqual(len(entries), 1586)
            self.assertEqual(sum(len(entry["legs"]) for entry in entries), 3172)
            self.assertEqual({entry["legs"][0]["party"] for entry in entries}, {f"BLMIS-{a}" for a in source.ACCOUNTS})
            self.assertEqual([entry["idempotency_key"] for entry in entries],
                             [row["row_id"] for row in self.rows if row["principal_movement_cents"]])
            with self.assertRaisesRegex(ledger.ReplayError, "differs from source"):
                replay.normalized_entries(package / "legacy.csv", self.rows)

    def test_annual_book_controls_are_cumulative_across_account_lifetimes(self):
        self.assertTrue(all(value == 0 for value in runner.cumulative_cells(self.observations, "1982-12-31").values()))
        early = runner.cumulative_cells(self.observations, "1983-12-31")
        self.assertNotEqual(early["BLMIS-1FN024"], 0)
        self.assertEqual(early["BLMIS-1FN037"], 0)
        old = runner.cumulative_cells(self.observations, "1999-12-31")
        final = runner.cumulative_cells(self.observations, "2008-12-31")
        self.assertEqual(old["BLMIS-1FN097"], final["BLMIS-1FN097"])
        self.assertEqual(final["BLMIS-1FN097"], 32179000)
        self.assertEqual(final["BLMIS-TRANSFER"], 68200)
        for year in range(1983, 2009):
            self.assertEqual(sum(runner.cumulative_cells(self.observations, f"{year}-12-31").values()), 0)

    def test_cross_case_memo_and_extra_csv_leg_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            source.prepare(package)
            with (package / "legacy.csv").open(newline="") as stream:
                records = list(csv.DictReader(stream))
            changed = deepcopy(records)
            changed[0]["memo"] = changed[0]["memo"].replace(source.SOURCE_ID, "SRC-BLM-005")
            for name, records in (("wrong-source.csv", changed), ("extra-leg.csv", records + [records[0]])):
                path = package / name
                path.write_bytes(source.csv_bytes(source.LEGACY_COLUMNS, records))
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
