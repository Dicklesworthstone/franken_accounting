#!/usr/bin/env python3
"""Offline source and normalization tests for every Magnify Exhibit B row."""

from __future__ import annotations

from collections import Counter
import copy
import csv
from decimal import Decimal, InvalidOperation
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_magnify as source


def printed_cents(literal: str) -> int:
    """Independent Decimal reader; stars and absent cells are not numbers."""
    numeric = re.sub(r" \[[1-4]\]$", "", literal)
    if numeric == "-":
        return 0
    if numeric.startswith("("):
        return -int(Decimal(numeric[1:-1].replace(",", "")) * 100)
    return int(Decimal(numeric.replace(",", "")) * 100)


class MagnifySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.metadata = source.load_fixture()
        cls.raw_rows = list(csv.DictReader(io.StringIO((source.FIXTURE_DIR / "rows.csv").read_text())))

    def directory(self):
        # Keep negative-test evidence; no source or diagnostic cleanup.
        return Path(tempfile.mkdtemp(prefix="fa-magnify-source-"))

    def minimal_layout(self, body, *, columns=11):
        lines = [
            "10-05279-smb Doc 150-1 10/30/17 Doc 143-2 09/29/17 Exhibit B",
            "BLMIS ACCOUNT NO. 1FN024 SOURCE ROLE",
            " ".join(f"Column {i}" for i in range(1, columns + 1)),
            "Transaction Amount",
            "Reported in Cash Cash Transfers of Transfers of Balance of Two Year Six Year Full History",
            "Date Transaction Description Customer Statement Deposits Withdrawals Principal In Principal Out Principal Transfers Transfers Transfers",
            body, "Page 1 of 8 - 1FN024", "",
        ]
        return "\n".join(lines) + "\f" * 51

    def test_complete_source_population_and_code_owned_pins(self):
        self.assertEqual(Counter(row["account"] for row in self.rows),
                         {"1FN024": 342, "1FN025": 58, "1FN037": 1927, "1FN073": 6, "1FN097": 4, "1FR051": 27})
        self.assertEqual(len(self.rows), 2364)
        self.assertEqual(min(row["date"] for row in self.rows), "1983-07-11")
        self.assertEqual(max(row["date"] for row in self.rows), "2008-12-03")
        self.assertEqual(source.digest((source.FIXTURE_DIR / "rows.csv").read_bytes()),
                         "f10a7bc474512a0f4db4b457d4865a4ff7909053f28f24e3dfa023afb60cf697")
        self.assertEqual(source.digest((source.FIXTURE_DIR / "source.json").read_bytes()),
                         "7350a15658dfc63da0386f8b17ca19acc09c454938df5abf94ca78e96e89fc80")

    def test_mixed_layouts_keep_absence_distinct_from_a_printed_dash(self):
        for row in self.rows:
            if row["account"] == "1FN037":
                self.assertEqual(row["source_column_count"], 12)
                self.assertNotEqual(row["ninety_day_literal"], "")
                self.assertIsInstance(row["ninety_day_cents"], int)
            else:
                self.assertEqual(row["source_column_count"], 11)
                self.assertEqual(row["ninety_day_literal"], "")
                self.assertIsNone(row["ninety_day_cents"])
        row = {**self.raw_rows[0], "ninety_day_literal": "-"}
        with self.assertRaisesRegex(source.SourceError, "invented ninety-day"):
            source.row_values(row)
        row = {**self.raw_rows[0], "source_column_count": "12"}
        with self.assertRaisesRegex(source.SourceError, "layout attribution"):
            source.row_values(row)

    def test_independent_decimal_fold_matches_every_exact_and_discrepant_cell(self):
        actual = source.diagnostics(self.rows, self.metadata)["accounts"]
        expected_summary = {
            "1FN024": (330, 4200, -4200, -728341900), "1FN025": (0, 0, 0, -474582200),
            "1FN037": (1920, 1800, 1600, -12367316900), "1FN073": (2, 100, 100, -103109700),
            "1FN097": (0, 0, 0, -32179000), "1FR051": (0, 0, 0, -1123001900),
        }
        for account in source.ACCOUNTS:
            running = 0
            gaps = []
            selected = [row for row in self.raw_rows if row["account"] == account]
            for row in selected:
                incoming = printed_cents(row["deposits_literal"])
                withdrawal = 0 if row["withdrawals_literal"].startswith("*") else printed_cents(row["withdrawals_literal"])
                running += incoming + withdrawal + printed_cents(row["transfers_in_literal"]) + printed_cents(row["transfers_out_literal"])
                difference = running - printed_cents(row["printed_balance_literal"])
                if difference:
                    gaps.append({"row_id": row["row_id"], "gap_cents": difference})
            self.assertEqual(gaps, actual[account]["row_differences"])
            self.assertEqual((actual[account]["rows_off"], actual[account]["maximum_gap_cents"],
                              actual[account]["closing_gap_cents"], running), expected_summary[account])

    def test_footers_are_independent_controls_and_not_balance_inputs(self):
        report = source.diagnostics(self.rows, self.metadata)["accounts"]
        self.assertEqual(report["1FN024"]["footer_gaps_cents"],
                         {"withdrawals": -4100, "full_history": -4100, "printed_balance": -4200})
        self.assertEqual(report["1FN037"]["footer_gaps_cents"],
                         {"withdrawals": 1600, "full_history": 1600, "printed_balance": 1600})
        self.assertEqual(report["1FN073"]["footer_gaps_cents"], {"printed_balance": 100})
        for account in ("1FN025", "1FN097", "1FR051"):
            self.assertEqual(report[account]["footer_gaps_cents"], {})
        changed = copy.deepcopy(self.metadata)
        changed["accounts"]["1FN024"]["footer"]["cells"]["withdrawals"] = "(7,603,548)"
        mutated = source.verify_rows(self.rows, changed)["accounts"]["1FN024"]
        self.assertEqual(mutated["footer_gaps_cents"]["withdrawals"], -4200)
        self.assertEqual(mutated["row_differences"], report["1FN024"]["row_differences"])

    def test_all_stars_retain_reported_amounts_and_their_local_footnote(self):
        stars = [row for row in self.rows if row["star"]]
        self.assertEqual(len(stars), 717)
        self.assertEqual(sum(row["withdrawals_literal"] == "* [4]" for row in stars), 511)
        self.assertEqual(sum(row["withdrawals_literal"] == "*" for row in stars), 206)
        self.assertEqual(sum(printed_cents(row["reported_literal"]) for row in stars), -68275700)
        self.assertTrue(all(row["account"] == "1FN037" and row["principal_movement_cents"] == 0 for row in stars))
        self.assertTrue(all(row["footnote_premises"] == ["SRC-BLM-006:1FN037:footnote:4"] for row in stars))
        with self.assertRaises(InvalidOperation):
            printed_cents("*")

    def test_source_zero_observations_are_not_discarded(self):
        zero = [row for row in self.rows if row["principal_movement_cents"] == 0]
        self.assertEqual(len(zero), 778)
        self.assertEqual(sum(row["star"] for row in zero), 717)
        self.assertEqual(sum(row["transfer_credit_role"] == "oracle_output" for row in zero), 55)
        numeric = [row for row in zero if not row["star"] and row["transfer_credit_role"] == "not_applicable"]
        self.assertEqual(len(numeric), 6)
        self.assertTrue(all(row["reported_literal"] == row["withdrawals_literal"] == "(0)" for row in numeric))

    def test_all_transfer_credits_are_oracle_inputs_and_descriptions_remain_exact(self):
        transfers = [row for row in self.rows if row["transfer_credit_role"] == "oracle_output"]
        self.assertEqual(len(transfers), 58)
        self.assertEqual(sum(row["description"].startswith("TRANS ") for row in transfers), 57)
        incomplete = next(row for row in transfers if row["row_id"] == source.PARTIAL_DESCRIPTION_ROW)
        self.assertEqual(incomplete["description"], "(1FN024)")
        self.assertEqual(incomplete["date"], "1997-01-02")
        self.assertEqual(incomplete["reported_cents"], 500000000)
        self.assertEqual(incomplete["principal_movement_cents"], 0)
        self.assertEqual(incomplete["footnote_premises"], ["SRC-BLM-006:1FN037:footnote:2"])
        self.assertEqual(Counter(row["account"] for row in transfers),
                         {"1FN024": 17, "1FN025": 13, "1FN037": 26, "1FR051": 2})
        changed = copy.deepcopy(self.rows)
        next(row for row in changed if row["transfer_credit_role"] == "oracle_output")["transfer_credit_role"] = "derived"
        with self.assertRaisesRegex(source.SourceError, "source-oracle"):
            source.verify_rows(changed, self.metadata)

    def test_transfer_principal_does_not_claim_to_recompute_rounded_origin(self):
        origin = [row for row in self.rows if row["account"] == "1FN024"]
        i = next(i for i, row in enumerate(origin) if row["date"] == "1989-03-17")
        transfer = origin[i]
        remaining = sum(row["principal_movement_cents"] for row in origin[:i])
        self.assertEqual(remaining, 281662700)
        self.assertEqual(transfer["transfers_out_cents"], -281666100)
        self.assertEqual(remaining + transfer["transfers_out_cents"], -3400)
        self.assertEqual(transfer["printed_balance_literal"], "-")

    def test_positive_withdrawal_corrections_and_returns_keep_their_sign(self):
        positive = [row for row in self.rows if row["withdrawals_cents"] > 0]
        self.assertEqual(len(positive), 43)
        self.assertEqual(Counter(row["account"] for row in positive),
                         {"1FN024": 9, "1FN025": 19, "1FN037": 14, "1FR051": 1})
        self.assertTrue(all(row["cash_movement_cents"] == row["reported_cents"] > 0 for row in positive))
        self.assertTrue(any(row["description"] == "RETURNED CHECK WIRE 5/21/98" for row in positive))
        self.assertTrue(any(row["description"] == "CHECK WIRE RETURNED 1/21/00" for row in positive))

    def test_account_scoped_footnotes_and_footer_annotations_are_distinct(self):
        self.assertEqual(self.metadata["accounts"]["1FN024"]["footnotes"]["[4]"]["role"], "other_recipients")
        self.assertEqual(self.metadata["accounts"]["1FN037"]["footnotes"]["[4]"]["role"], "withholding_refunds")
        for account, marker in (("1FN024", "[4]"), ("1FN025", "[2]"), ("1FR051", "[2]")):
            annotations = self.metadata["accounts"][account]["footer"]["markers"]
            self.assertEqual({item["field"] for item in annotations}, {"withdrawals", "full_history"})
            self.assertEqual({item["marker"] for item in annotations}, {marker})
        altered = copy.deepcopy(self.metadata)
        altered["accounts"]["1FN037"]["footnotes"]["[4]"] = altered["accounts"]["1FN024"]["footnotes"]["[4]"]
        with self.assertRaisesRegex(source.SourceError, "footnote premise"):
            source.verify_rows(self.rows, altered)

    def test_missing_star_or_transfer_premise_is_refused(self):
        for select in (lambda row: row["star"], lambda row: bool(row["reported_marker"])):
            changed = copy.deepcopy(self.rows)
            next(row for row in changed if select(row))["footnote_premises"] = []
            with self.assertRaisesRegex(source.SourceError, "footnote premises"):
                source.verify_rows(changed, self.metadata)
        metadata = copy.deepcopy(self.metadata)
        metadata["accounts"]["1FN037"]["footnotes"].pop("[4]")
        with self.assertRaisesRegex(source.SourceError, "footnote census"):
            source.verify_rows(self.rows, metadata)

    def test_removed_star_and_changed_marker_location_are_refused(self):
        rows = copy.deepcopy(self.raw_rows)
        row = next(row for row in rows if row["withdrawals_literal"].startswith("*") and row["reported_literal"] == "(0)")
        row.update(withdrawals_literal="(0)", withdrawal_marker="", marker_source_line="", marker_raw_line_sha256="")
        with self.assertRaisesRegex(source.SourceError, "717"):
            source.verify_rows([source.row_values(row) for row in rows], self.metadata)
        row = copy.deepcopy(next(row for row in self.raw_rows if row["withdrawals_literal"] == "*"))
        row["marker_source_line"] = str(int(row["source_line"]) - 2)
        with self.assertRaisesRegex(source.SourceError, "marker attribution"):
            source.row_values(row)

    def test_changed_printed_balance_is_a_diagnostic_not_an_extraction_failure(self):
        raw = copy.deepcopy(self.raw_rows)
        raw[0]["printed_balance_literal"] = "3,136,151"
        changed = source.verify_rows([source.row_values(row) for row in raw], self.metadata)
        report = changed["accounts"]["1FN024"]
        self.assertEqual(report["rows_off"], 331)
        self.assertEqual(report["row_differences"][0], {"row_id": self.rows[0]["row_id"], "gap_cents": -100})
        self.assertEqual(report["closing_gap_cents"], -4200)

    def test_one_dollar_movement_changes_only_its_accounts_running_fold(self):
        raw = copy.deepcopy(self.raw_rows)
        raw[0]["reported_literal"] = raw[0]["deposits_literal"] = "3,136,151"
        changed = source.verify_rows([source.row_values(row) for row in raw], self.metadata)["accounts"]
        original = source.diagnostics(self.rows, self.metadata)["accounts"]
        self.assertEqual(changed["1FN024"]["closing_gap_cents"], -4100)
        for account in set(source.ACCOUNTS) - {"1FN024"}:
            self.assertEqual(changed[account], original[account])

    def test_dropped_duplicated_or_reordered_source_rows_are_refused(self):
        for rows in (self.rows[:-1], [self.rows[0], *self.rows[1:-1], self.rows[0]],
                     [self.rows[1], self.rows[0], *self.rows[2:]]):
            with self.assertRaises(source.SourceError):
                source.verify_rows(rows, self.metadata)

    def test_changed_rows_cannot_be_blessed_by_a_caller_checksum(self):
        directory = self.directory()
        raw = (source.FIXTURE_DIR / "rows.csv").read_bytes().replace(b"3,136,150", b"3,136,151", 1)
        (directory / "rows.csv").write_bytes(raw)
        (directory / "source.json").write_bytes((source.FIXTURE_DIR / "source.json").read_bytes())
        (directory / "checksums.json").write_text(json.dumps({"rows.csv": source.digest(raw)}))
        with self.assertRaisesRegex(source.SourceError, "rows SHA-256"):
            source.load_fixture(directory)

    def test_changed_metadata_is_refused_by_its_separate_pin(self):
        directory = self.directory()
        (directory / "rows.csv").write_bytes((source.FIXTURE_DIR / "rows.csv").read_bytes())
        metadata = copy.deepcopy(self.metadata)
        metadata["accounts"]["1FN024"]["footer"]["cells"]["printed_balance"] = "(7,283,419)"
        (directory / "source.json").write_bytes(source.json_bytes(metadata))
        with self.assertRaisesRegex(source.SourceError, "metadata SHA-256"):
            source.load_fixture(directory)

    def test_unknown_layout_extra_column_and_unknown_description_are_refused(self):
        raw = self.raw_rows[0]
        cells = [raw["date_literal"], raw["description"], *(raw[f"{field}_literal"] for field in source.value_fields("1FN024"))]
        with self.assertRaisesRegex(source.SourceError, "unknown declared layout"):
            source.parse_layout(self.minimal_layout("  ".join(cells), columns=12))
        with self.assertRaisesRegex(source.SourceError, "wrong cell count"):
            source.parse_layout(self.minimal_layout("  ".join([*cells, "123"])))
        with self.assertRaisesRegex(source.SourceError, "unrecognized Magnify"):
            source.row_values({**raw, "description": "UNMAPPED TRANSACTION"})

    def test_incomplete_description_is_not_generalized_or_fabricated(self):
        row = next(row for row in self.raw_rows if row["row_id"] == source.PARTIAL_DESCRIPTION_ROW)
        changed = {**self.raw_rows[0], "description": "(1FN024)"}
        with self.assertRaisesRegex(source.SourceError, "reviewed source location"):
            source.row_values(changed)
        self.assertEqual(source.row_values(row)["transaction_kind"], "transfer_annotation_only")

    def test_normalized_package_accounts_for_every_observation_and_exact_leg(self):
        manifest, payloads = source.package_payloads(source.FIXTURE_DIR)
        self.assertEqual((manifest["source_rows"], manifest["source_accounts"], manifest["monetary_rows"], manifest["normalized_legs"]),
                         (2364, 6, 1586, 3172))
        normalized = list(csv.DictReader(io.StringIO(payloads["legacy.csv"].decode())))
        by_id = {}
        for row in normalized:
            by_id.setdefault(row["entry_id"], []).append(row)
        for row in self.rows:
            legs = by_id.get(row["row_id"], [])
            if row["principal_movement_cents"] == 0:
                self.assertEqual(legs, [])
                continue
            self.assertEqual(len(legs), 2)
            self.assertEqual(sum(Decimal(leg["signed_amount"]) for leg in legs), 0)
            principal = next(leg for leg in legs if leg["account_code"] == f"BLMIS-{row['account']}")
            raw = next(item for item in self.raw_rows if item["row_id"] == row["row_id"])
            movement = sum(printed_cents(raw[f"{field}_literal"]) for field in ("deposits", "withdrawals", "transfers_in", "transfers_out"))
            self.assertEqual(int(Decimal(principal["signed_amount"]) * 100), -movement)
            self.assertTrue(all(leg["source_row"] == row["row_id"] and leg["effective_date"] == row["date"] for leg in legs))
        observations = json.loads(payloads["observations.json"])
        self.assertEqual(len(observations), 2364)
        self.assertEqual(sum(row["posted"] for row in observations), 1586)
        self.assertEqual(sum(row["star"] for row in observations), 717)
        self.assertEqual(len(manifest["zero_principal_rows"]), 778)
        self.assertEqual(len(json.loads(payloads["chart.json"])["accounts"]), 8)

    def test_global_posting_order_preserves_each_accounts_source_same_day_order(self):
        ordered = source.computation_order(self.rows)
        self.assertEqual([row["date"] for row in ordered], sorted(row["date"] for row in ordered))
        for account in source.ACCOUNTS:
            self.assertEqual([row["row_id"] for row in ordered if row["account"] == account],
                             [row["row_id"] for row in self.rows if row["account"] == account])
        self.assertNotEqual(ordered, self.rows)

    def test_annual_controls_retain_printed_values_without_adjusting_them(self):
        _, payloads = source.package_payloads(source.FIXTURE_DIR)
        controls = json.loads(payloads["controls.json"])
        for account in source.ACCOUNTS:
            selected = [row for row in self.raw_rows if row["account"] == account]
            decoded = [row for row in self.rows if row["account"] == account]
            for control in controls[account]:
                row = next(row for row in reversed(decoded) if row["date"] <= control["at_date"])
                raw = next(raw for raw in selected if raw["row_id"] == row["row_id"])
                self.assertEqual(control["printed_balance_cents"], printed_cents(raw["printed_balance_literal"]))
                self.assertEqual(control["source_fold_minus_printed_cents"],
                                 control["source_fold_cents"] - control["printed_balance_cents"])
        self.assertEqual(controls["1FN024"][-1]["source_fold_minus_printed_cents"], -4200)

    def test_wrong_original_refuses_before_extracting_or_creating_package(self):
        directory = self.directory()
        pdf = directory / "wrong.pdf"
        pdf.write_bytes(b"%PDF-not-the-source")
        with patch.object(source.subprocess, "run") as extractor:
            with self.assertRaisesRegex(source.SourceError, "byte count"):
                source.prepare_pdf(directory / "package", pdf)
            extractor.assert_not_called()
        self.assertFalse((directory / "package").exists())

    def test_missing_extractor_is_unrun_without_fixture_fallback(self):
        with patch.object(source, "verify_pdf", return_value=b"verified full original"), \
             patch.object(source.subprocess, "run", side_effect=FileNotFoundError("pdftotext")), \
             patch.object(source, "load_fixture") as retained, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            result = source.main(["extract", "--pdf", "pinned.pdf", "--out", str(self.directory() / "extracted")])
            self.assertEqual(result, 4)
            self.assertTrue(stderr.getvalue().startswith("UNRUN "))
            retained.assert_not_called()

    def test_offline_prepare_is_deterministic_and_preserves_existing_outputs(self):
        directory = self.directory()
        with patch.object(source.request, "build_opener", side_effect=AssertionError("unexpected network")), \
             patch.object(source.subprocess, "run", side_effect=AssertionError("unexpected extractor")):
            first = source.prepare(directory / "first")
            second = source.prepare(directory / "second")
        self.assertEqual(first, second)
        self.assertNotIn("source_extraction", first)
        self.assertEqual({p.name: p.read_bytes() for p in (directory / "first").iterdir()},
                         {p.name: p.read_bytes() for p in (directory / "second").iterdir()})
        with patch.object(source, "verify_pdf") as read:
            with self.assertRaisesRegex(source.SourceError, "already exists"):
                source.prepare_pdf(directory / "first", Path("source.pdf"))
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
