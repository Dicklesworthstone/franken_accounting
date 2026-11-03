"""Offline checks over every retained factual Glantz B-2 account row.

The independent Decimal fold reads the source literals directly; it does not
consume normalized legs or the production helper's integer amount parser.
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
import blmis_source as source


def decimal_cents(literal):
    value = literal.split(" [", 1)[0]
    if value == "-":
        return 0
    negative = value.startswith("(")
    value = value.strip("()").replace(",", "")
    cents = int(Decimal(value) * Decimal(100))
    return -cents if negative else cents


def retained_rows():
    with (source.FIXTURE_DIR / "rows.csv").open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, strict=True))


def test_layout():
    """Minimal author-created page furniture around the retained factual cells.

    This is parser fault injection, not the original extraction or source proof.
    Live reproduction must use extract --pdf against the pinned original PDF.
    """
    originals = retained_rows()
    pages = []
    for index, page in enumerate(source.PDF_PAGES):
        lines = [
            f"Exhibit B-2  Pg {index + 5} of 14  Filed 01/22/18",
            f"BLMIS ACCOUNT NO. {source.ACCOUNT} - role-labelled test heading",
            "  ".join(f"Column {number}" for number in range(1, 10)),
            "Date  Description  Customer Statement  Deposits  Withdrawals  Principal In  Principal Out  Fictitious Profits",
        ]
        for row in originals:
            if int(row["pdf_page"]) == page:
                cells = [row["date_literal"], row["description"]] + [row[f"{key}_literal"] for key in source.VALUE_FIELDS]
                lines.append("   ".join(cells))
        if index == 2:
            # Independently transcribed from the PDF's printed footer, not folded.
            lines.extend([
                "Total: $ 10,439,983 $ (16,924,380) $ 537,366 $ (4,000,000) $ (9,947,031) $ (7,700,000)",
                "[1]", "Synthetic footnote one for parser structure.", "",
                "[2]", "Synthetic footnote two for parser structure.", "",
            ])
        lines.append(f"Page {index + 1} of 3 - {source.ACCOUNT}")
        pages.append("\n".join(lines) + "\n")
    return "\f".join(pages) + "\f"


class BlmisSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.metadata = source.load_fixture()
        cls.raw_rows = retained_rows()

    def test_complete_pinned_population_and_original_document_identity(self):
        self.assertEqual(source.SOURCE_BYTES, 389586)
        self.assertEqual(source.SOURCE_SHA256,
                         "751a8a55bf02b022076af39c8637086630090b41164f70e2a04184c0d003dec1")
        self.assertEqual(len(self.rows), 75)
        self.assertEqual([sum(row["pdf_page"] == p for row in self.rows) for p in (31, 32, 33)], [35, 35, 5])
        self.assertEqual(self.rows[0]["date"], "1992-12-07")
        self.assertEqual(self.rows[-1]["date"], "2008-10-30")
        self.assertEqual(len({row["row_id"] for row in self.rows}), 75)
        for row in self.rows:
            self.assertEqual(row["exhibit_page"], row["pdf_page"] - 26)
            self.assertEqual(row["source_line"], row["page_row"] + 15)

    def test_independent_decimal_fold_matches_every_printed_balance_and_footer(self):
        running = 0
        totals = {field: 0 for field in ("deposits", "withdrawals", "transfers_in", "transfers_out", "two_year")}
        for row in self.raw_rows:
            for field in totals:
                totals[field] += decimal_cents(row[f"{field}_literal"])
            running += sum(decimal_cents(row[f"{field}_literal"]) for field in (
                "deposits", "withdrawals", "transfers_in", "transfers_out"))
            self.assertEqual(running, decimal_cents(row["printed_balance_literal"]), row["row_id"])
        # These values are the printed footer cells, not normalized output goldens.
        self.assertEqual(totals, {"deposits": 1043998300, "withdrawals": -1692438000,
                                 "transfers_in": 53736600, "transfers_out": -400000000,
                                 "two_year": -770000000})
        self.assertEqual(running, -994703100)
        for field, total in {**totals, "printed_balance": running}.items():
            self.assertEqual(total, decimal_cents(self.metadata["footer"]["cells"][field]))

    def test_reported_transfers_and_trustee_principal_remain_separate(self):
        transfers = [row for row in self.rows if row["description"].startswith("TRANS ")]
        self.assertEqual([row["reported_cents"] for row in transfers], [-400000000, 127042200, 20000000])
        self.assertEqual([row["principal_movement_cents"] for row in transfers], [-400000000, 53736600, 0])
        self.assertEqual([row["footnotes"] for row in transfers], [[], [1], [2]])
        self.assertEqual([row["transfer_credit_role"] for row in transfers], ["oracle_output"] * 3)
        self.assertEqual(transfers[0]["description"], "TRANS TO 1Z314330 (1ZB143)")
        zero = transfers[-1]
        self.assertEqual(zero["row_id"], "SRC-BLM-001:1ZA192:p32:l43")
        preceding = self.rows[self.rows.index(zero) - 1]
        self.assertEqual(zero["printed_balance_cents"], preceding["printed_balance_cents"])

    def test_money_parser_refuses_missing_fractional_and_ambiguous_cells(self):
        for literal in ("", "1.00", "1,00", "1,234.5", "1e6", "NaN", "(1,000", "(1,000) [3]", " -", "1,000*", "00"):
            with self.subTest(literal=literal), self.assertRaises(source.SourceError):
                source.amount_cents(literal, allow_footnote=True)
        self.assertEqual(source.amount_cents("(4,000,000)"), (-400000000, []))
        self.assertEqual(source.amount_cents("-"), (0, []))
        with self.assertRaisesRegex(source.SourceError, "footnote"):
            source.amount_cents("1,270,422 [1]")

    def test_printed_balance_selection_keeps_last_same_day_and_carries_source_date(self):
        selected = source.last_printed_balance(self.rows, "1992-12-07")
        self.assertEqual(selected["printed_balance_cents"], 153500000)
        self.assertEqual(selected["source_row_id"], self.rows[2]["row_id"])
        gap_year = source.last_printed_balance(self.rows, "1995-12-31")
        self.assertEqual(gap_year["printed_balance_cents"], 95500000)
        self.assertEqual(gap_year["source_date"], "1994-01-05")
        with self.assertRaisesRegex(source.SourceError, "no published balance"):
            source.last_printed_balance(self.rows, "1992-12-06")

    def test_one_dollar_movement_and_same_day_reordering_fail_printed_controls(self):
        rows = deepcopy(self.rows)
        rows[0]["principal_movement_cents"] += 100
        report = source.diagnostics(rows, self.metadata)
        self.assertEqual(report["rows_off"], 75)
        self.assertEqual(report["closing_gap_cents"], 100)
        with self.assertRaisesRegex(source.SourceError, "printed controls"):
            source.verify_rows(rows, self.metadata)
        rows = deepcopy(self.rows)
        rows[0], rows[1] = rows[1], rows[0]
        with self.assertRaisesRegex(source.SourceError, "row order"):
            source.verify_rows(rows, self.metadata)

    def test_arithmetic_disagreements_remain_diagnostics_during_extraction(self):
        layout = test_layout().replace("383,000   -\n", "383,001   -\n", 1)
        raw, metadata = source.parse_layout(layout)
        rows = [source.row_values(row) for row in raw]
        report = source.diagnostics(rows, metadata)
        self.assertEqual(report["rows_off"], 1)
        self.assertEqual(report["maximum_gap_cents"], 100)
        self.assertEqual(report["closing_gap_cents"], 0)
        with self.assertRaisesRegex(source.SourceError, "printed controls"):
            source.verify_rows(rows, metadata)
        raw, metadata = source.parse_layout(test_layout().replace("$ 10,439,983", "$ 10,439,984"))
        report = source.diagnostics([source.row_values(row) for row in raw], metadata)
        self.assertEqual(report["footer_gaps_cents"], {"deposits": -100})

    def test_missing_row_extra_column_wrong_account_and_layout_are_refused(self):
        layout = test_layout()
        raw, _ = source.parse_layout(layout)
        self.assertEqual(len(raw), 75)
        lines = layout.splitlines(keepends=True)
        missing = "".join(line for line in lines if not line.startswith("1/4/1993"))
        with self.assertRaisesRegex(source.SourceError, "incomplete account"):
            source.parse_layout(missing)
        extra = layout.replace("383,000   -\n", "383,000   -   100\n", 1)
        with self.assertRaisesRegex(source.SourceError, "nine cells"):
            source.parse_layout(extra)
        for changed in (layout.replace("Column 9", "Column 10", 1),
                        layout.replace("ACCOUNT NO. 1ZA192", "ACCOUNT NO. 1ZA193", 1),
                        layout.replace("Customer Statement", "Unrecognized Balance", 1)):
            with self.assertRaises(source.SourceError):
                source.parse_layout(changed)

    def test_fixture_tampering_cannot_be_blessed_by_a_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            raw = (source.FIXTURE_DIR / "rows.csv").read_bytes()
            changed = raw.replace(b'"383,000"', b'"383,001"', 1)
            self.assertNotEqual(raw, changed)
            (target / "rows.csv").write_bytes(changed)
            metadata = deepcopy(self.metadata)
            metadata["rows_sha256"] = hashlib.sha256(changed).hexdigest()
            (target / "source.json").write_bytes(source.json_bytes(metadata))
            with self.assertRaisesRegex(source.SourceError, "source rows SHA-256"):
                source.load_fixture(target)
            (target / "rows.csv").write_bytes(raw)
            with self.assertRaisesRegex(source.SourceError, "metadata SHA-256"):
                source.load_fixture(target)

    def test_prepare_accounts_for_every_row_and_never_posts_printed_balances(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "package"
            manifest = source.prepare(output)
            self.assertEqual((manifest["source_rows"], manifest["monetary_rows"], manifest["normalized_legs"]), (75, 74, 148))
            with (output / "legacy.csv").open(newline="") as stream:
                legs = list(csv.DictReader(stream))
            mapped = {item["source_row_id"] for item in manifest["row_mapping"]}
            zero = set(manifest["zero_principal_rows"])
            self.assertFalse(mapped & zero)
            self.assertEqual(mapped | zero, {row["row_id"] for row in self.rows})
            self.assertEqual([row["source_row_id"] for row in manifest["row_mapping"]],
                             [row["row_id"] for row in self.rows if row["principal_movement_cents"]])
            for raw in self.raw_rows:
                selected = [leg for leg in legs if leg["entry_id"] == raw["row_id"]]
                source_movement = sum(decimal_cents(raw[f"{field}_literal"]) for field in (
                    "deposits", "withdrawals", "transfers_in", "transfers_out"))
                if not source_movement:
                    self.assertFalse(selected)
                    continue
                self.assertEqual(len(selected), 2)
                self.assertEqual(sum(Decimal(leg["signed_amount"]) for leg in selected), 0)
                principal = next(leg for leg in selected if leg["account_code"] == source.PRINCIPAL_ACCOUNT)
                self.assertEqual(int(Decimal(principal["signed_amount"]) * 100), -source_movement)
                self.assertEqual(principal["description"], raw["description"])
            controls = json.loads((output / "controls.json").read_bytes())
            self.assertEqual(len(controls), 17)
            self.assertEqual(controls[-1]["printed_balance_cents"], -994703100)
            for control in controls:
                original = next(row for row in self.raw_rows if row["row_id"] == control["source_row_id"])
                self.assertEqual(control["printed_balance_cents"], decimal_cents(original["printed_balance_literal"]))
            before = (output / "legacy.csv").read_bytes()
            with self.assertRaisesRegex(source.SourceError, "destination already exists"):
                source.prepare(output)
            self.assertEqual((output / "legacy.csv").read_bytes(), before)

    def test_prepare_is_byte_identical_on_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "one", Path(tmp) / "two"
            source.prepare(first)
            source.prepare(second)
            self.assertEqual(sorted(path.name for path in first.iterdir()), sorted(path.name for path in second.iterdir()))
            for path in first.iterdir():
                self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())

    def test_download_verifies_bytes_before_creating_output_and_preserves_destinations(self):
        class Response(io.BytesIO):
            status = 200

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "source.pdf"
            opener = mock.Mock()
            opener.open.return_value = Response(b"not the pinned document")
            with mock.patch.object(source.request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(source.SourceError, "download differs"):
                    source.fetch(output)
                self.assertFalse(output.exists())
            output.write_bytes(b"existing evidence")
            with mock.patch.object(source.request, "build_opener") as build:
                with self.assertRaisesRegex(source.SourceError, "already exists"):
                    source.fetch(output)
                build.assert_not_called()
            self.assertEqual(output.read_bytes(), b"existing evidence")

    def test_missing_extractor_is_unrun_and_wrong_pdf_fails_before_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wrong.pdf"
            path.write_bytes(b"%PDF-wrong")
            with mock.patch.object(source.subprocess, "run") as run:
                with self.assertRaisesRegex(source.SourceError, "byte count"):
                    source.extract_pdf(path)
                run.assert_not_called()
            with mock.patch.object(source, "verify_pdf", return_value=b"checked"), \
                    mock.patch.object(source.subprocess, "run", side_effect=FileNotFoundError("pdftotext")):
                with self.assertRaises(source.EnvironmentError):
                    source.extract_pdf(path)
            stderr = io.StringIO()
            with mock.patch.object(source, "extract_pdf", side_effect=source.EnvironmentError("missing pdftotext")), redirect_stderr(stderr):
                self.assertEqual(source.main(["extract", "--pdf", str(path), "--output", str(Path(tmp) / "unused")]), 4)
            self.assertIn("UNRUN", stderr.getvalue())

    def test_download_redirect_refuses_nonpublisher_and_plain_http(self):
        handler = source.PinnedRedirect()
        req = source.request.Request(source.SOURCE_URL)
        for url in ("http://www.madofftrustee.com/document.pdf", "https://example.com/document.pdf",
                    "https://www.madofftrustee.com:8443/document.pdf", "https://user@www.madofftrustee.com/document.pdf"):
            with self.subTest(url=url), self.assertRaises(source.SourceError):
                handler.redirect_request(req, None, 302, "Found", {}, url)


if __name__ == "__main__":
    unittest.main()
