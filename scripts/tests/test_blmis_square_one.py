#!/usr/bin/env python3
"""Offline source/normalization controls for the complete Square One account."""

from __future__ import annotations

import copy
import csv
from decimal import Decimal
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_square_one as source


def printed_cents(literal: str) -> int:
    """Independent decimal reader for this source's displayed whole dollars."""
    if literal == "-":
        return 0
    if literal.startswith("("):
        return int(-Decimal(literal[1:-1].replace(",", "")) * Decimal(100))
    return int(Decimal(literal.replace(",", "")) * Decimal(100))


class SquareOneSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.metadata = source.load_fixture()
        cls.raw_rows = list(csv.DictReader(io.StringIO((source.FIXTURE_DIR / "rows.csv").read_text())))

    def retain_directory(self) -> Path:
        # Retain negative-test evidence; do not delete repository/session files.
        return Path(tempfile.mkdtemp(prefix="fa-square-one-source-"))

    def first_page_layout(self, body: str) -> str:
        page = "\n".join([
            "10-04330-smb Doc 167-2 Filed 12/21/18 Exhibit B", "Pg 2 of 20",
            "BLMIS ACCOUNT NO. 1FR048 - SOURCE ROLE", *source.HEADER_LINES,
            body, "Page 1 of 19 - 1FR048", "",
        ])
        return page + "\f" * 19

    def test_complete_source_census_and_raw_identity(self):
        self.assertEqual(len(self.rows), 1050)
        self.assertEqual(self.rows[0]["date"], "1999-02-01")
        self.assertEqual(self.rows[-1]["date"], "2008-12-03")
        self.assertEqual(sum(row["star"] for row in self.rows), 709)
        self.assertEqual(sum(row["withdrawals_literal"] == "* [1]" for row in self.rows), 37)
        self.assertEqual(sum(row["withdrawals_literal"] == "*" for row in self.rows), 672)
        self.assertEqual(sum(row["principal_movement_cents"] != 0 for row in self.rows), 340)
        self.assertEqual({row["account"] for row in self.rows}, {"1FR048"})
        self.assertEqual({row["exhibit"] for row in self.rows}, {"B"})
        self.assertEqual(source.digest((source.FIXTURE_DIR / "rows.csv").read_bytes()),
                         "0b3d9666f7a55926333b53241d51e30a3ce4e3b417da7f072c4fcfc3d4a34afd")
        self.assertEqual(source.digest((source.FIXTURE_DIR / "source.json").read_bytes()),
                         "56b89c945d4b463c9929f8470a3625e58024adaeba67f656735399f892cf9284")

    def test_independent_decimal_fold_keeps_every_printed_discrepancy(self):
        running = 0
        expected = []
        for row in self.raw_rows:
            incoming = printed_cents(row["deposits_literal"])
            withdrawal = row["withdrawals_literal"]
            if withdrawal.startswith("*"):
                self.assertEqual(row["withdrawal_marker"], "[1]")
                self.assertEqual(self.metadata["footnotes"]["[1]"]["fact_id"], source.FOOTNOTE_ID)
                outgoing = 0
            else:
                outgoing = printed_cents(withdrawal)
            running += incoming + outgoing
            gap = running - printed_cents(row["printed_balance_literal"])
            if gap:
                expected.append({"row_id": row["row_id"], "gap_cents": gap})
        report = source.diagnostics(self.rows, self.metadata)
        self.assertEqual(report["row_differences"], expected)
        self.assertEqual((running, len(expected), report["maximum_gap_cents"]), (224442500, 1010, 300))
        self.assertEqual(report["closing_gap_cents"], -300)
        self.assertEqual(report["printed_closing_balance_cents"], 224442800)
        self.assertEqual(expected[0], {"row_id": "SRC-BLM-005:1FR048:p60:l17", "gap_cents": -100})
        self.assertEqual(report["footer_gaps_cents"], {
            "withdrawals": -300, "six_year": -100, "full_history": -300, "printed_balance": -300,
        })

    def test_star_amounts_remain_reported_evidence_with_required_premise(self):
        starred = [row for row in self.rows if row["star"]]
        self.assertEqual(sum(printed_cents(row["reported_literal"]) for row in starred), -40960700)
        self.assertTrue(all(row["withdrawals_cents"] == row["principal_movement_cents"] == 0 for row in starred))
        self.assertTrue(all(row["principal_rule"] == "withholding_refund_exclusion" for row in starred))
        self.assertTrue(all(row["footnote_premises"] == [source.FOOTNOTE_ID] for row in starred))
        self.assertTrue(all(row["withdrawals_literal"] in ("*", "* [1]") for row in starred))
        self.assertEqual(source.diagnostics(self.rows, self.metadata)["excluded_reported_cents"], -40960700)

    def test_numeric_zero_is_preserved_separately_from_a_star(self):
        unstarred_zero = [row for row in self.rows if not row["star"] and row["principal_movement_cents"] == 0]
        self.assertEqual(len(unstarred_zero), 1)
        row = unstarred_zero[0]
        self.assertEqual((row["row_id"], row["date"], row["reported_literal"], row["withdrawals_literal"]),
                         ("SRC-BLM-005:1FR048:p60:l23", "1999-05-05", "(0)", "(0)"))
        self.assertEqual(row["footnote_premises"], [])

    def test_positive_cancellations_remain_positive_in_withdrawal_column(self):
        cancellations = [row for row in self.rows if row["transaction_kind"] == "tax_withholding_cancellation"]
        self.assertEqual([(row["date"], row["withdrawals_cents"]) for row in cancellations],
                         [("2006-04-28", 16400), ("2006-08-07", 18000), ("2007-07-17", 21200)])
        self.assertTrue(all(row["deposits_cents"] == 0 and row["principal_movement_cents"] > 0 for row in cancellations))
        bad = next(copy.deepcopy(row) for row in self.raw_rows if row["description"].startswith("CXL"))
        bad["description"] = "W/H TAX DIV SLB"
        with self.assertRaisesRegex(source.SourceError, "positive withdrawal"):
            source.row_values(bad)

    def test_missing_or_changed_footnote_is_refused(self):
        for footnotes in ({}, {"[1]": {"fact_id": source.FOOTNOTE_ID, "normalized_text_sha256": "0" * 64}}):
            metadata = copy.deepcopy(self.metadata)
            metadata["footnotes"] = footnotes
            with self.assertRaisesRegex(source.SourceError, "StarPremiseMissing"):
                source.verify_rows(self.rows, metadata)
        changed = copy.deepcopy(self.rows)
        next(row for row in changed if row["star"])["footnote_premises"] = []
        with self.assertRaisesRegex(source.SourceError, "StarPremiseMissing"):
            source.verify_rows(changed, self.metadata)

    def test_removed_star_marker_fails_the_complete_census(self):
        raw = copy.deepcopy(self.raw_rows)
        row = next(row for row in raw if row["withdrawals_literal"].startswith("*") and row["reported_literal"] == "(0)")
        row.update(withdrawals_literal="(0)", withdrawal_marker="", marker_source_line="", marker_raw_line_sha256="")
        with self.assertRaisesRegex(source.SourceError, "709 source cells"):
            source.verify_rows([source.row_values(item) for item in raw], self.metadata)

    def test_marker_attribution_and_unknown_star_semantics_are_refused(self):
        original = next(row for row in self.raw_rows if row["withdrawals_literal"] == "*")
        for field, value in (("marker_source_line", str(int(original["source_line"]) - 2)),
                             ("withdrawal_marker", "[2]"), ("withdrawals_literal", "* [2]")):
            row = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(source.SourceError):
                source.row_values(row)

    def test_dropped_duplicated_and_reordered_observations_are_refused(self):
        cases = [self.rows[:-1], [self.rows[0], *self.rows[1:-1], self.rows[0]],
                 [self.rows[1], self.rows[0], *self.rows[2:]]]
        for rows in cases:
            with self.subTest(rows=len(rows)), self.assertRaises(source.SourceError):
                source.verify_rows(rows, self.metadata)

    def test_printed_balance_mutation_is_reported_not_repaired(self):
        changed = copy.deepcopy(self.raw_rows)
        changed[0]["printed_balance_literal"] = "2,000,001"
        report = source.verify_rows([source.row_values(row) for row in changed], self.metadata)
        self.assertEqual(report["row_differences"][0], {"row_id": self.rows[0]["row_id"], "gap_cents": -100})
        self.assertEqual(report["rows_off"], 1011)
        self.assertEqual(report["source_closing_balance_cents"], 224442500)

    def test_movement_mutation_changes_the_independent_running_diagnostic(self):
        changed = copy.deepcopy(self.raw_rows)
        changed[0]["reported_literal"] = changed[0]["deposits_literal"] = "2,000,001"
        report = source.verify_rows([source.row_values(row) for row in changed], self.metadata)
        baseline = {row["row_id"]: row["gap_cents"] for row in source.diagnostics(self.rows, self.metadata)["row_differences"]}
        actual = {row["row_id"]: row["gap_cents"] for row in report["row_differences"]}
        for row in self.rows:
            self.assertEqual(actual.get(row["row_id"], 0), baseline.get(row["row_id"], 0) + 100)
        self.assertEqual(report["closing_gap_cents"], -200)

    def test_footer_mutation_is_a_separate_source_diagnostic(self):
        metadata = copy.deepcopy(self.metadata)
        metadata["footer"]["cells"]["withdrawals"] = "(25,852,736)"
        report = source.verify_rows(self.rows, metadata)
        self.assertEqual(report["rows_off"], 1010)
        self.assertEqual(report["footer_gaps_cents"]["withdrawals"], -400)

    def test_changed_rows_and_self_supplied_pin_sidecars_are_refused(self):
        directory = self.retain_directory()
        changed = (source.FIXTURE_DIR / "rows.csv").read_bytes().replace(b"2,000,000", b"2,000,001", 1)
        (directory / "rows.csv").write_bytes(changed)
        (directory / "source.json").write_bytes((source.FIXTURE_DIR / "source.json").read_bytes())
        (directory / "checksums.json").write_text(json.dumps({"rows.csv": source.digest(changed)}))
        with self.assertRaisesRegex(source.SourceError, "rows SHA-256"):
            source.load_fixture(directory)

    def test_changed_metadata_is_refused_by_its_code_owned_pin(self):
        directory = self.retain_directory()
        (directory / "rows.csv").write_bytes((source.FIXTURE_DIR / "rows.csv").read_bytes())
        metadata = copy.deepcopy(self.metadata)
        metadata["footer"]["cells"]["printed_balance"] = "2,244,425"
        (directory / "source.json").write_bytes(source.json_bytes(metadata))
        with self.assertRaisesRegex(source.SourceError, "metadata SHA-256"):
            source.load_fixture(directory)

    def test_unknown_header_and_extra_column_fail_before_arithmetic(self):
        cells = [self.raw_rows[0]["date_literal"], self.raw_rows[0]["description"],
                 *(self.raw_rows[0][f"{field}_literal"] for field in source.VALUE_FIELDS)]
        layout = self.first_page_layout("  ".join(cells))
        with self.assertRaisesRegex(source.SourceError, "unexpected declared headers"):
            source.parse_layout(layout.replace("Transfers Out Principal", "Transfer Out Principal"))
        with self.assertRaisesRegex(source.SourceError, "expected twelve cells"):
            source.parse_layout(self.first_page_layout("  ".join([*cells, "123"])))

    def test_missing_adjacent_star_marker_and_orphan_marker_are_refused(self):
        row = next(row for row in self.raw_rows if row["withdrawals_literal"] == "*")
        cells = [row["date_literal"], row["description"], *(row[f"{field}_literal"] for field in source.VALUE_FIELDS)]
        with self.assertRaisesRegex(source.SourceError, "star lacks adjacent footnote marker"):
            source.parse_layout(self.first_page_layout("  ".join(cells)))
        with self.assertRaisesRegex(source.SourceError, "unattributed footnote marker"):
            source.parse_layout(self.first_page_layout("[1]"))

    def test_unknown_description_is_refused_without_name_passthrough(self):
        changed = {**self.raw_rows[0], "description": "UNMAPPED PRIVATE PERSON"}
        with self.assertRaisesRegex(source.SourceError, "unrecognized Square One transaction description") as caught:
            source.row_values(changed)
        self.assertNotIn(changed["description"], str(caught.exception))

    def test_wrong_pdf_is_refused_before_extraction(self):
        path = self.retain_directory() / "wrong.pdf"
        path.write_bytes(b"%PDF-not-the-source")
        with patch.object(source.subprocess, "run") as extractor:
            with self.assertRaisesRegex(source.SourceError, "PDF byte count"):
                source.extract_pdf(path)
            extractor.assert_not_called()

    def test_unavailable_extractor_reports_unrun_without_retained_fallback(self):
        with patch.object(source, "verify_pdf", return_value=b"verified source bytes"), \
             patch.object(source.subprocess, "run", side_effect=FileNotFoundError("pdftotext")), \
             patch.object(source, "load_fixture") as retained, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            result = source.main(["extract", "--pdf", "pinned.pdf", "--out", str(self.retain_directory() / "extract")])
            self.assertEqual(result, 4)
            self.assertTrue(stderr.getvalue().startswith("UNRUN "))
            retained.assert_not_called()

    def test_normalized_package_preserves_all_observations_and_exact_legs(self):
        manifest, payloads = source.package_payloads(source.FIXTURE_DIR)
        self.assertEqual((manifest["source_rows"], manifest["monetary_rows"], manifest["normalized_legs"]), (1050, 340, 680))
        normalized = list(csv.DictReader(io.StringIO(payloads["legacy.csv"].decode())))
        by_id = {}
        for row in normalized:
            by_id.setdefault(row["entry_id"], []).append(row)
        source_by_id = {row["row_id"]: row for row in self.rows}
        self.assertEqual(len(by_id), 340)
        for row_id, legs in by_id.items():
            original = source_by_id[row_id]
            self.assertEqual(len(legs), 2)
            self.assertEqual(sum(Decimal(leg["signed_amount"]) for leg in legs), 0)
            self.assertEqual({leg["account_code"] for leg in legs}, {source.PRINCIPAL_ACCOUNT, source.CASH_ACCOUNT})
            self.assertTrue(all(leg["effective_date"] == original["date"] and leg["source_row"] == row_id for leg in legs))
            cash = next(leg for leg in legs if leg["account_code"] == source.CASH_ACCOUNT)
            self.assertEqual(int(Decimal(cash["signed_amount"]) * 100), printed_cents(original["reported_literal"]))
        observations = json.loads(payloads["observations.json"])
        self.assertEqual(len(observations), 1050)
        self.assertEqual(sum(row["posted"] for row in observations), 340)
        self.assertEqual(sum(row["star"] for row in observations), 709)
        self.assertEqual(observations[-1]["source_fold_minus_printed_cents"], -300)
        self.assertEqual(observations[-1]["printed_balance_cents"], 224442800)
        self.assertEqual(len(manifest["zero_principal_rows"]), 710)

    def test_annual_controls_are_the_printed_cells_with_separate_source_fold(self):
        _, payloads = source.package_payloads(source.FIXTURE_DIR)
        controls = json.loads(payloads["controls.json"])
        self.assertEqual(len(controls), 10)
        for control in controls:
            row = next(row for row in reversed(self.rows) if row["date"] <= control["at_date"])
            self.assertEqual(control["source_row_id"], row["row_id"])
            self.assertEqual(control["printed_balance_cents"], printed_cents(row["printed_balance_literal"]))
            self.assertEqual(control["source_fold_minus_printed_cents"],
                             control["source_fold_cents"] - control["printed_balance_cents"])
        self.assertEqual(controls[-1]["printed_balance_cents"], 224442800)
        self.assertEqual(controls[-1]["source_fold_cents"], 224442500)

    def test_offline_prepare_is_deterministic_and_makes_no_pdf_claim(self):
        root = self.retain_directory()
        with patch.object(source.request, "build_opener", side_effect=AssertionError("unexpected network")), \
             patch.object(source.subprocess, "run", side_effect=AssertionError("unexpected extractor")):
            first = source.prepare(root / "first")
            second = source.prepare(root / "second")
        self.assertNotIn("source_extraction", first)
        self.assertEqual(first, second)
        self.assertEqual({path.name: path.read_bytes() for path in (root / "first").iterdir()},
                         {path.name: path.read_bytes() for path in (root / "second").iterdir()})

    def test_existing_output_is_preserved_before_pdf_or_network_access(self):
        root = self.retain_directory()
        sentinel = root / "existing.txt"
        sentinel.write_text("retain this evidence")
        with patch.object(source, "verify_pdf") as verify, patch.object(source, "fetch") as fetch:
            with self.assertRaisesRegex(source.SourceError, "already exists"):
                source.prepare_pdf(root, Path("source.pdf"))
            verify.assert_not_called()
            fetch.assert_not_called()
        self.assertEqual(sentinel.read_text(), "retain this evidence")


if __name__ == "__main__":
    unittest.main()
