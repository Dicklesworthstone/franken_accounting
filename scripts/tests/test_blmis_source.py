"""Offline checks over every retained factual Glantz B-2 account row.

The independent Decimal fold reads the source literals directly; it does not
consume normalized legs or the production helper's integer amount parser.
"""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import csv
from decimal import Decimal
import hashlib
import io
import json
import os
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

    def test_pdf_preparation_uses_this_extraction_and_preserves_its_entire_lineage(self):
        # This is an orchestration contract with an explicitly mocked extractor,
        # not proof of a live PDF extraction. Real acquisition is run separately.
        original_pdf = b"%PDF-unit-only-input"
        raw = (source.FIXTURE_DIR / "rows.csv").read_bytes()
        metadata = (source.FIXTURE_DIR / "source.json").read_bytes()
        layout = b"unit-only extractor output, not source evidence\n"

        def extraction(path, *, layout_out):
            self.assertEqual(path.read_bytes(), original_pdf)
            layout_out.write_bytes(layout)
            return raw, metadata

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "from-pdf"
            supplied = Path(tmp) / "input.pdf"
            supplied.write_bytes(original_pdf)
            with mock.patch.object(source, "verify_pdf", return_value=original_pdf), \
                    mock.patch.object(source, "extract_pdf", side_effect=extraction) as extract, \
                    mock.patch.object(source, "load_fixture", wraps=source.load_fixture) as load:
                manifest = source.prepare_pdf(output, supplied)
            extract.assert_called_once_with(output / "source.pdf", layout_out=output / "extracted-source/layout.txt")
            load.assert_called_once_with(output / "extracted-source")
            self.assertEqual((output / "source.pdf").read_bytes(), original_pdf)
            self.assertEqual((output / "extracted-source/layout.txt").read_bytes(), layout)
            self.assertEqual((output / "extracted-source/rows.csv").read_bytes(), raw)
            self.assertEqual((output / "extracted-source/source.json").read_bytes(), metadata)
            self.assertEqual((output / "rows.csv").read_bytes(), raw)
            self.assertEqual((output / "source.json").read_bytes(), metadata)
            self.assertEqual(manifest["normalized_legs"], 148)
            receipt = json.loads((output / "extraction.json").read_bytes())
            self.assertEqual(receipt, manifest["source_extraction"])
            self.assertEqual(receipt["mode"], "original_pdf_extracted_this_run")
            self.assertEqual(receipt["command"], ["pdftotext", "-layout", "-f", "31", "-l", "33",
                                                   str(output / "source.pdf"), "-"])
            self.assertEqual(json.loads((output / "manifest.json").read_bytes()), manifest)
            for name, pin in manifest["outputs"].items():
                content = (output / name).read_bytes()
                self.assertEqual(len(content), pin["bytes"], name)
                self.assertEqual(hashlib.sha256(content).hexdigest(), pin["sha256"], name)

    def test_pdf_preparation_downloads_then_extracts_before_any_normalization(self):
        observed = []
        raw = (source.FIXTURE_DIR / "rows.csv").read_bytes()
        metadata = (source.FIXTURE_DIR / "source.json").read_bytes()
        normalize = source.package_payloads

        def download(path):
            observed.append("download")
            path.write_bytes(b"%PDF-unit-only-downloaded-input")

        def extraction(path, *, layout_out):
            observed.append("extract")
            self.assertEqual(path.read_bytes(), b"%PDF-unit-only-downloaded-input")
            layout_out.write_bytes(b"unit-only extraction\n")
            return raw, metadata

        def normalized(directory):
            observed.append("normalize")
            return normalize(directory)

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(source, "fetch", side_effect=download), \
                mock.patch.object(source, "extract_pdf", side_effect=extraction), \
                mock.patch.object(source, "package_payloads", side_effect=normalized):
            manifest = source.prepare_pdf(Path(tmp) / "downloaded")
            self.assertEqual(manifest["source_rows"], 75)
        self.assertEqual(observed, ["download", "extract", "normalize"])

    def test_pdf_extraction_drift_preserves_diagnostic_text_but_creates_no_accounting_inputs(self):
        layout = test_layout().encode()
        result = mock.Mock(returncode=0, stdout=layout)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "drift"
            with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-unit-only-input"), \
                    mock.patch.object(source.subprocess, "run", return_value=result), \
                    mock.patch.object(source, "package_payloads") as normalize:
                with self.assertRaisesRegex(source.SourceError, "extraction differs"):
                    source.prepare_pdf(output, Path(tmp) / "provided.pdf")
            normalize.assert_not_called()
            self.assertEqual((output / "extracted-source/layout.txt").read_bytes(), layout)
            self.assertTrue((output / "source.pdf").is_file())
            for name in ("legacy.csv", "chart.json", "manifest.json", "extraction.json", "book",
                         "extracted-source/rows.csv", "extracted-source/source.json"):
                self.assertFalse((output / name).exists(), name)

    def test_returned_extraction_rows_are_reauthenticated_before_normalization(self):
        raw = (source.FIXTURE_DIR / "rows.csv").read_bytes() + b"\n"
        metadata = (source.FIXTURE_DIR / "source.json").read_bytes()

        def extraction(path, *, layout_out):
            layout_out.write_bytes(b"unit-only extraction\n")
            return raw, metadata

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "changed-returned-rows"
            with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-unit-only-input"), \
                    mock.patch.object(source, "extract_pdf", side_effect=extraction):
                with self.assertRaisesRegex(source.SourceError, "source rows SHA-256"):
                    source.prepare_pdf(output, Path(tmp) / "provided.pdf")
            self.assertEqual((output / "extracted-source/rows.csv").read_bytes(), raw)
            self.assertFalse((output / "legacy.csv").exists())
            self.assertFalse((output / "manifest.json").exists())

    def test_pdf_preparation_refuses_missing_extractor_with_actionable_unrun(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "no-extractor"
            error = io.StringIO()
            with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-unit-only-input"), \
                    mock.patch.object(source.subprocess, "run", side_effect=FileNotFoundError("pdftotext")), \
                    mock.patch.object(source, "package_payloads") as normalize, \
                    redirect_stdout(io.StringIO()), redirect_stderr(error):
                status = source.main(["prepare-pdf", "--pdf", str(Path(tmp) / "provided.pdf"),
                                      "--output", str(output)])
            self.assertEqual(status, 4)
            self.assertIn("UNRUN", error.getvalue())
            self.assertIn("install Poppler", error.getvalue())
            self.assertIn("cannot substitute retained rows", error.getvalue())
            normalize.assert_not_called()
            self.assertTrue((output / "source.pdf").is_file())
            self.assertFalse((output / "legacy.csv").exists())

    def test_offline_preparation_is_explicit_and_never_claims_pdf_extraction(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(source, "fetch") as fetch, \
                mock.patch.object(source, "extract_pdf") as extract:
            output = Path(tmp) / "offline"
            manifest = source.prepare(output)
            self.assertNotIn("source_extraction", manifest)
            self.assertFalse((output / "source.pdf").exists())
            self.assertFalse((output / "extraction.json").exists())
            fetch.assert_not_called()
            extract.assert_not_called()

    def test_download_redirect_refuses_nonpublisher_and_plain_http(self):
        handler = source.PinnedRedirect()
        req = source.request.Request(source.SOURCE_URL)
        for url in ("http://www.madofftrustee.com/document.pdf", "https://example.com/document.pdf",
                    "https://www.madofftrustee.com:8443/document.pdf", "https://user@www.madofftrustee.com/document.pdf"):
            with self.subTest(url=url), self.assertRaises(source.SourceError):
                handler.redirect_request(req, None, 302, "Found", {}, url)


def glantz_b2_raw_rows():
    """Project the real retained B-2 records into the additive six-account schema."""
    result = []
    for original in retained_rows():
        row = dict(original)
        marker = next((item for item in ("[1]", "[2]") if row["reported_literal"].endswith(" " + item)), "")
        row.update(exhibit="B-2", reported_marker=marker,
                   marker_source_line=row["source_line"] if marker else "",
                   marker_raw_line_sha256=row["raw_line_sha256"] if marker else "")
        result.append(row)
    return result


def authored_glantz_row(account="1T0026", page=27, line=25, **changes):
    """Small author-created decoder input, never claimed as original PDF evidence."""
    row = {field: "-" for field in (f"{name}_literal" for name in source.VALUE_FIELDS)}
    row.update(row_id=f"SRC-BLM-001:{account}:p{page}:l{line}",
               account=account, pdf_page=str(page), exhibit_page=str(page - 26),
               page_row="1", source_line=str(line), date_literal="1/2/2000",
               description="CHECK", reported_literal="100", deposits_literal="100",
               printed_balance_literal="100",
               raw_line_sha256=hashlib.sha256(b"author-created decoder test row").hexdigest(),
               exhibit=source.GLANTZ_ACCOUNTS[account]["exhibit"],
               reported_marker="", marker_source_line="", marker_raw_line_sha256="")
    row.update(changes)
    return row


def authored_glantz_layout():
    """Author-created layout fault injection; it cannot satisfy original PDF pins.

    Counts and page furniture exercise completeness checks. Invented amounts,
    headings and note bodies are explicitly unrelated to the trustee evidence.
    """
    pages = []
    for account, spec in source.GLANTZ_ACCOUNTS.items():
        for page_index, (page, count) in enumerate(zip(spec["pdf_pages"], spec["rows_per_page"])):
            lines = [
                f"Exhibit {spec['exhibit']}  Pg {page - 26} of 14  Filed 01/22/18",
                f"BLMIS ACCOUNT NO. {account} - author-created test heading",
                "  ".join(f"Column {number}" for number in range(1, 10)),
                "Date  Description  Customer Statement  Deposits  Withdrawals  Principal In  Principal Out  Fictitious Profits",
            ]
            for index in range(count):
                if page == 27 and index == 0:
                    lines.append("                   [1]")
                    cells = ["1/2/2000", "TRANS FROM EXTERNAL (EXTERNAL)", "100", "-", "-", "50", "-", "50", "-"]
                else:
                    cells = ["1/2/2000", "CHECK", "100", "100", "-", "-", "-", "100", "-"]
                lines.append("   ".join(cells))
            if page_index == len(spec["pdf_pages"]) - 1:
                lines.append("Total: $ - $ - $ - $ - $ - $ -")
                for marker in source.GLANTZ_NOTE_MEANINGS[account]:
                    if marker == "*":
                        lines.append("* Author-created recipient note.")
                    else:
                        lines.extend([marker, "Author-created explanatory note.", ""])
            lines.append(f"Page {page_index + 1} of {len(spec['pdf_pages'])} - {account}")
            pages.append("\n".join(lines) + "\n")
    return "\f".join(pages) + "\f"


class GlantzCompleteSourceUnitTests(unittest.TestCase):
    def test_additive_decoder_preserves_every_existing_real_b2_field(self):
        original = retained_rows()
        extended = glantz_b2_raw_rows()
        self.assertEqual(source.csv_bytes(source.ROW_COLUMNS, [
            {key: row[key] for key in source.ROW_COLUMNS} for row in extended
        ]), (source.FIXTURE_DIR / "rows.csv").read_bytes())
        for raw, additional in zip(original, extended):
            decoded = source.glantz_row_values(additional)
            self.assertEqual({key: decoded[key] for key in source.row_values(raw)}, source.row_values(raw))
        self.assertEqual(sum(row["reported_marker"] != "" for row in extended), 2)

    def test_detached_marker_keeps_its_own_source_line_and_is_not_fabricated_inline(self):
        raw = authored_glantz_row(
            description="TRANS FROM EXTERNAL (EXTERNAL)", reported_literal="100",
            deposits_literal="-", transfers_in_literal="50", printed_balance_literal="50",
            reported_marker="[1]", marker_source_line="24",
            marker_raw_line_sha256=hashlib.sha256(b"author-created detached marker").hexdigest())
        row = source.glantz_row_values(raw)
        self.assertEqual(row["reported_literal"], "100")
        self.assertEqual((row["reported_cents"], row["principal_movement_cents"]), (10000, 5000))
        self.assertEqual(row["marker_source_line"], 24)
        self.assertNotEqual(row["marker_raw_line_sha256"], row["raw_line_sha256"])
        self.assertEqual(row["transfer_credit_role"], "oracle_output")
        for changes in ({"marker_source_line": "23"},
                        {"reported_marker": ""},
                        {"marker_raw_line_sha256": ""},
                        {"reported_literal": "100 [1]"}):
            with self.subTest(changes=changes), self.assertRaises(source.SourceError):
                source.glantz_row_values({**raw, **changes})
        with self.assertRaisesRegex(source.SourceError, "undeclared detached"):
            source.glantz_row_values(authored_glantz_row(
                account="1ZA192", page=31, line=28,
                description="TRANS FROM EXTERNAL (EXTERNAL)", reported_literal="100",
                deposits_literal="-", transfers_in_literal="50",
                reported_marker="[1]", marker_source_line="27",
                marker_raw_line_sha256=raw["marker_raw_line_sha256"]))

    def test_account_scoped_marker_and_recipient_asterisk_do_not_change_principal(self):
        outgoing = authored_glantz_row(
            account="1ZB143", page=37, line=23,
            description="TRANS TO 1ZA19230 (1ZA192)", reported_literal="(200,000) [1]",
            deposits_literal="-", printed_balance_literal="(4,854,688)",
            reported_marker="[1]", marker_source_line="23")
        outgoing["marker_raw_line_sha256"] = outgoing["raw_line_sha256"]
        decoded = source.glantz_row_values(outgoing)
        self.assertEqual(decoded["principal_movement_cents"], 0)
        self.assertEqual(decoded["reported_cents"], -20000000)
        self.assertIn("outward", source.GLANTZ_NOTE_MEANINGS["1ZB143"]["[1]"])
        self.assertIn("originating", source.GLANTZ_NOTE_MEANINGS["1T0026"]["[1]"])
        cash = authored_glantz_row(
            account="1ZR176", page=40, line=32, date_literal="1/3/2008",
            reported_literal="(265,000) *", deposits_literal="-",
            withdrawals_literal="(265,000)", printed_balance_literal="(2,317,965)",
            reported_marker="*", marker_source_line="32")
        cash["marker_raw_line_sha256"] = cash["raw_line_sha256"]
        decoded = source.glantz_row_values(cash)
        self.assertEqual(decoded["principal_movement_cents"], -26500000)
        self.assertEqual(decoded["footnotes"], [])
        self.assertEqual(decoded["transfer_credit_role"], "not_applicable")
        with self.assertRaises(source.SourceError):
            source.glantz_row_values({**cash, "reported_marker": "[1]", "reported_literal": "(265,000) [1]"})

    def test_stop_payment_preserves_positive_withdrawal_and_rejects_cash_reclassification(self):
        raw = authored_glantz_row(
            account="1ZB010", page=35, line=39, date_literal="10/17/2006",
            description="STOP PAYMENT", reported_literal="25,000", deposits_literal="-",
            withdrawals_literal="25,000", printed_balance_literal="(97,500)")
        row = source.glantz_row_values(raw)
        self.assertEqual(row["cash_movement_cents"], 2500000)
        self.assertEqual(row["withdrawals_cents"], 2500000)
        self.assertEqual(row["deposits_cents"], 0)
        for changes in ({"description": "CHECK"},
                        {"deposits_literal": "25,000", "withdrawals_literal": "-"},
                        {"reported_literal": "(25,000)", "withdrawals_literal": "(25,000)"}):
            with self.subTest(changes=changes), self.assertRaises(source.SourceError):
                source.glantz_row_values({**raw, **changes})

    def test_computation_order_is_one_named_interpretation_without_mutating_display_order(self):
        check = source.glantz_row_values(authored_glantz_row(
            account="1ZB010", page=35, line=38, date_literal="10/17/2006",
            reported_literal="(25,000)", deposits_literal="-",
            withdrawals_literal="(25,000)", printed_balance_literal="(122,500)"))
        stop = source.glantz_row_values(authored_glantz_row(
            account="1ZB010", page=35, line=39, date_literal="10/17/2006",
            description="STOP PAYMENT", reported_literal="25,000", deposits_literal="-",
            withdrawals_literal="25,000", printed_balance_literal="(97,500)"))
        displayed = [check, stop]
        before = deepcopy(displayed)
        self.assertEqual(source.glantz_computation_order(displayed), [stop, check])
        self.assertEqual(displayed, before)
        unrelated = [source.glantz_row_values(row) for row in glantz_b2_raw_rows()]
        self.assertEqual(source.glantz_computation_order(unrelated), unrelated)
        for altered in ([check], [stop, check], [check, check, stop],
                        [check, {**stop, "date": "2006-10-18"}],
                        [check, {**stop, "principal_movement_cents": 2500001}]):
            with self.subTest(altered=altered), self.assertRaises(source.SourceError):
                source.glantz_computation_order(altered)

    def test_only_reviewed_transfer_pairs_are_compared_and_reported_alias_is_preserved(self):
        # These are minimal authored objects around independently transcribed
        # comparison cells. They are not a substitute for a complete source run.
        rows = [
            {"row_id": "SRC-BLM-001:1ZA192:p31:l20", "account": "1ZA192", "printed_balance_cents": 485500000},
            {"row_id": "SRC-BLM-001:1ZA192:p31:l21", "account": "1ZA192", "date": "1993-10-20",
             "description": "TRANS TO 1Z314330 (1ZB143)", "reported_cents": -400000000,
             "transfer_movement_cents": -400000000},
            {"row_id": "SRC-BLM-001:1ZA192:p32:l43", "account": "1ZA192", "date": "2005-12-23",
             "description": "TRANS FROM 1ZB14330 (1ZB143)", "reported_cents": 20000000,
             "transfer_movement_cents": 0},
            {"row_id": "SRC-BLM-001:1ZB143:p36:l16", "account": "1ZB143", "date": "1993-10-20",
             "description": "TRANS FROM 1ZA19230 (1ZA192)", "reported_cents": 400000000,
             "transfer_movement_cents": 400000000},
            {"row_id": "SRC-BLM-001:1ZB143:p37:l22", "account": "1ZB143", "printed_balance_cents": -485468800},
            {"row_id": "SRC-BLM-001:1ZB143:p37:l23", "account": "1ZB143", "date": "2005-12-23",
             "description": "TRANS TO 1ZA19230 (1ZA192)", "reported_cents": -20000000,
             "transfer_movement_cents": 0},
        ]
        pairs = source.glantz_transfer_pairs(rows)
        self.assertEqual([pair["recomputed_credit_cents"] for pair in pairs], [400000000, 0])
        self.assertTrue(all(pair["agrees_with_both_printed_credits"] for pair in pairs))
        self.assertEqual(rows[1]["description"], "TRANS TO 1Z314330 (1ZB143)")
        changed = deepcopy(rows)
        changed[0]["printed_balance_cents"] = 100
        comparison = source.glantz_transfer_pairs(changed)
        self.assertFalse(comparison[0]["agrees_with_both_printed_credits"])
        self.assertEqual(comparison[0]["recomputed_credit_cents"], 100)
        for altered in (rows[:-1], rows + [rows[0]],
                        [({**row, "description": "TRANS TO 1Z314330 (OTHER)"} if i == 1 else row) for i, row in enumerate(rows)],
                        [({**row, "reported_cents": -400000001} if i == 1 else row) for i, row in enumerate(rows)]):
            with self.subTest(altered=altered), self.assertRaises(source.SourceError):
                source.glantz_transfer_pairs(altered)

    def test_complete_layout_requires_every_declared_page_row_and_original_column_shape(self):
        layout = authored_glantz_layout()
        raw, metadata = source.parse_glantz_layout(layout)
        self.assertEqual(len(raw), 379)
        self.assertEqual([metadata["accounts"][account]["row_count"] for account in source.GLANTZ_ACCOUNTS],
                         [117, 75, 61, 51, 57, 18])
        first = source.glantz_row_values(raw[0])
        self.assertEqual(first["source_line"], 6)
        self.assertEqual(first["marker_source_line"], 5)
        self.assertEqual(first["reported_literal"], "100")
        # Authored furniture cannot be accepted as the reviewed source population.
        with self.assertRaises(source.SourceError):
            source.verify_glantz_rows([source.glantz_row_values(row) for row in raw], metadata)
        mutations = [
            layout.replace("   CHECK   100   100   -   -   -   100   -\n",
                           "   CHECK   100   100   -   -   -   100   -   999\n", 1),
            layout.replace("1/2/2000   CHECK   100   100   -   -   -   100   -\n", "", 1),
            layout.replace("BLMIS ACCOUNT NO. 1T0026 -", "BLMIS ACCOUNT NO. UNKNOWN -", 1),
            layout.replace("Column 9", "Column 10", 1),
            layout.replace("                   [1]\n", "                   [1]\n\n", 1),
            layout.rsplit("\f", 2)[0] + "\f",
        ]
        for changed in mutations:
            self.assertNotEqual(changed, layout)
            with self.subTest(prefix=changed[:100]), self.assertRaises(source.SourceError):
                source.parse_glantz_layout(changed)

    def test_verified_pdf_is_passed_as_bytes_and_actual_failed_layout_survives(self):
        layout = b"author-created invalid extraction\n"
        result = mock.Mock(returncode=0, stdout=layout)
        with tempfile.TemporaryDirectory() as tmp:
            retained = Path(tmp) / "layout.txt"
            with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-author-created-unit-input"), \
                    mock.patch.object(source.subprocess, "run", return_value=result) as run:
                with self.assertRaises(source.SourceError):
                    source.extract_glantz_pdf(Path(tmp) / "input.pdf", layout_out=retained)
            self.assertEqual(retained.read_bytes(), layout)
            self.assertEqual(run.call_args.args[0],
                             ["pdftotext", "-layout", "-f", "27", "-l", "40", "-", "-"])
            self.assertEqual(run.call_args.kwargs["input"], b"%PDF-author-created-unit-input")
        with mock.patch.object(source, "verify_pdf", side_effect=source.SourceError("bad original")), \
                mock.patch.object(source.subprocess, "run") as run:
            with self.assertRaisesRegex(source.SourceError, "bad original"):
                source.extract_glantz_pdf(Path("not-used.pdf"))
            run.assert_not_called()

    def test_preparation_owns_destination_only_after_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "existing"
            existing.mkdir()
            sentinel = existing / "sentinel"
            sentinel.write_bytes(b"previous evidence")
            callback = mock.Mock()
            with mock.patch.object(source, "fetch") as fetch:
                with self.assertRaisesRegex(source.SourceError, "already exists"):
                    source.prepare_glantz(existing, on_created=callback)
                fetch.assert_not_called()
            callback.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"previous evidence")
            fresh = Path(tmp) / "racing-destination"
            with mock.patch.object(source.Path, "mkdir", side_effect=FileExistsError("another writer won")), \
                    mock.patch.object(source, "fetch") as fetch:
                with self.assertRaises(FileExistsError):
                    source.prepare_glantz(fresh, on_created=callback)
                fetch.assert_not_called()
            callback.assert_not_called()

    def test_missing_extractor_leaves_verified_original_and_never_normalizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "unavailable"
            ownership = []
            with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-author-created-unit-input"), \
                    mock.patch.object(source.subprocess, "run", side_effect=FileNotFoundError("pdftotext")), \
                    mock.patch.object(source, "_glantz_payloads") as normalize:
                with self.assertRaisesRegex(source.EnvironmentError, "cannot substitute retained rows"):
                    source.prepare_glantz(output, Path(tmp) / "input.pdf",
                                          on_created=lambda: ownership.append(output.is_dir()))
            self.assertEqual(ownership, [True])
            self.assertEqual((output / "source.pdf").read_bytes(), b"%PDF-author-created-unit-input")
            normalize.assert_not_called()
            self.assertFalse((output / "legacy.csv").exists())
            self.assertFalse((output / "manifest.json").exists())

    def test_unprepared_full_source_returns_explicit_unrun_and_default_b2_stays_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            with self.assertRaisesRegex(source.EnvironmentError, "prepare --account all"):
                source.load_glantz_fixture(missing)
            error = io.StringIO()
            with redirect_stderr(error), redirect_stdout(io.StringIO()):
                status = source.main(["verify", "--account", "all", "--source-dir", str(missing)])
            self.assertEqual(status, 4)
            self.assertIn("UNRUN", error.getvalue())
            with mock.patch.object(source, "fetch") as fetch, \
                    mock.patch.object(source, "_extract_glantz_pdf") as extract, \
                    redirect_stdout(io.StringIO()):
                status = source.main(["prepare", "--output", str(Path(tmp) / "old-default")])
            self.assertEqual(status, 0)
            fetch.assert_not_called()
            extract.assert_not_called()


@unittest.skipUnless(os.environ.get("FA_BLMIS_GLANTZ_PDF"),
                     "UNRUN: set FA_BLMIS_GLANTZ_PDF to the pinned original PDF and install Poppler")
class GlantzOriginalPdfTests(unittest.TestCase):
    """Real complete-source checks, never replaced with synthetic passing rows."""

    @classmethod
    def setUpClass(cls):
        cls.pdf = Path(os.environ["FA_BLMIS_GLANTZ_PDF"])
        cls.original = source.verify_pdf(cls.pdf)
        try:
            cls.raw, cls.meta_raw, cls.layout = source._extract_glantz_pdf(cls.pdf)
        except source.EnvironmentError as exc:
            raise unittest.SkipTest(f"UNRUN: {exc}") from exc
        cls.literal_rows = list(csv.DictReader(io.StringIO(cls.raw.decode(), newline=""), strict=True))
        cls.rows = [source.glantz_row_values(row) for row in cls.literal_rows]
        cls.metadata = json.loads(cls.meta_raw)

    def test_all_source_pages_observations_and_existing_b2_bytes_are_retained(self):
        self.assertEqual(len(self.original), 389586)
        self.assertEqual(hashlib.sha256(self.original).hexdigest(),
                         "751a8a55bf02b022076af39c8637086630090b41164f70e2a04184c0d003dec1")
        self.assertEqual(len(self.rows), 379)
        self.assertEqual(len({row["row_id"] for row in self.rows}), 379)
        self.assertEqual([sum(row["account"] == account for row in self.rows) for account in
                          ("1T0026", "1ZA192", "1ZB010", "1ZB143", "1ZR010", "1ZR176")],
                         [117, 75, 61, 51, 57, 18])
        self.assertEqual(sum(row["principal_movement_cents"] != 0 for row in self.rows), 372)
        self.assertEqual(sum(row["description"].startswith("TRANS ") for row in self.rows), 17)
        self.assertEqual(sum(bool(row["reported_marker"]) for row in self.rows), 12)
        self.assertEqual(sum(bool(row["reported_marker"]) and row["marker_source_line"] != row["source_line"]
                             for row in self.rows), 6)
        projection = [{key: row[key] for key in source.ROW_COLUMNS}
                      for row in self.literal_rows if row["account"] == "1ZA192"]
        self.assertEqual(source.csv_bytes(source.ROW_COLUMNS, projection),
                         (source.FIXTURE_DIR / "rows.csv").read_bytes())

    def test_independent_decimal_fold_preserves_exact_printed_discrepancies(self):
        printed_footers = {
            "1T0026": (1820800000, -2796643100, 259626600, -21200000, -737416500, -675000000),
            "1ZA192": (1043998300, -1692438000, 53736600, -400000000, -994703100, -770000000),
            "1ZB010": (122000000, -152750000, 0, -20000000, -50750000, -38500000),
            "1ZB143": (117853200, -2208822000, 400000000, -4500000, -1695468800, -1150000000),
            "1ZR010": (597918400, -930717300, 0, 0, -332798900, -332798900),
            "1ZR176": (205001400, -486797900, 0, 0, -281796500, -76500000),
        }
        expected_local = {
            "1ZR010": [(38, 23, -100), (38, 36, -100), (38, 41, -100), (38, 44, -100),
                       (38, 47, -100), (39, 22, -100), (39, 26, -100), (39, 29, -100), (39, 33, -100)],
            "1ZR176": [(40, 21, 100), (40, 33, -100)],
        }
        for account, expected_footer in printed_footers.items():
            raw_rows = [row for row in self.literal_rows if row["account"] == account]
            if account == "1ZB010":
                # Explicit, independently transcribed display interpretation.
                positions = {row["row_id"]: i for i, row in enumerate(raw_rows)}
                check = positions["SRC-BLM-001:1ZB010:p35:l38"]
                stop = positions["SRC-BLM-001:1ZB010:p35:l39"]
                self.assertEqual(stop, check + 1)
                raw_rows[check], raw_rows[stop] = raw_rows[stop], raw_rows[check]
            totals = {field: 0 for field in ("deposits", "withdrawals", "transfers_in", "transfers_out", "two_year")}
            running, prior_printed, gaps, local = 0, 0, [], []
            for row in raw_rows:
                cells = {field: decimal_cents(row[f"{field}_literal"]) for field in totals}
                for field, amount in cells.items():
                    totals[field] += amount
                movement = sum(cells[field] for field in ("deposits", "withdrawals", "transfers_in", "transfers_out"))
                printed = decimal_cents(row["printed_balance_literal"])
                local_gap = printed - prior_printed - movement
                if local_gap:
                    local.append((int(row["pdf_page"]), int(row["source_line"]), local_gap))
                running += movement
                gaps.append(running - printed)
                prior_printed = printed
            actual_footer = tuple(decimal_cents(self.metadata["accounts"][account]["footer"]["cells"][field])
                                  for field in ("deposits", "withdrawals", "transfers_in", "transfers_out",
                                                "printed_balance", "two_year"))
            self.assertEqual(actual_footer, expected_footer, account)
            self.assertEqual(local, expected_local.get(account, []), account)
            movement_footer = tuple(totals[field] for field in ("deposits", "withdrawals", "transfers_in", "transfers_out"))
            expected_movements = list(expected_footer[:4])
            if account == "1ZR010":
                expected_movements[0] += 900
            self.assertEqual(movement_footer, tuple(expected_movements), account)
            self.assertEqual(totals["two_year"], expected_footer[5], account)
            self.assertEqual(running - expected_footer[4], 900 if account == "1ZR010" else 0, account)
            self.assertEqual(sum(gap != 0 for gap in gaps), {"1ZR010": 50, "1ZR176": 12}.get(account, 0), account)
            self.assertEqual(max(map(abs, gaps)), {"1ZR010": 900, "1ZR176": 100}.get(account, 0), account)
        stopped = [row for row in self.literal_rows if row["account"] == "1ZB010"]
        cash = [decimal_cents(row["deposits_literal"]) + decimal_cents(row["withdrawals_literal"]) for row in stopped]
        self.assertEqual(sum(max(0, amount) for amount in cash), 124500000)
        self.assertEqual(sum(max(0, -amount) for amount in cash), 155250000)

    def test_known_source_signature_refuses_changed_values_without_balancing_plugs(self):
        report = source.verify_glantz_rows(self.rows, self.metadata)
        self.assertEqual(report["accounts"]["1ZR176"]["computation_order"]["printed_closing_balance_cents"], -281796500)
        self.assertEqual([pair["recomputed_credit_cents"] for pair in report["transfer_pairs"]], [400000000, 0])
        self.assertEqual(len(report["unpaired_transfer_rows"]), 13)
        changed = deepcopy(self.rows)
        changed[0]["principal_movement_cents"] += 100
        with self.assertRaisesRegex(source.SourceError, "discrepancies differ"):
            source.verify_glantz_rows(changed, self.metadata)
        changed = deepcopy(self.metadata)
        changed["accounts"]["1ZR010"]["footer"]["cells"]["deposits"] = "5,979,193"
        with self.assertRaisesRegex(source.SourceError, "footer literals differ"):
            source.verify_glantz_rows(self.rows, changed)
        changed = deepcopy(self.rows)
        next(row for row in changed if row["reported_marker"])["reported_marker"] = ""
        with self.assertRaisesRegex(source.SourceError, "marker locations differ"):
            source.verify_glantz_rows(changed, self.metadata)

    def test_live_package_reextracts_every_byte_and_rejects_forged_sidecar_and_leg(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / "one", Path(tmp) / "two"
            manifest = source.prepare_glantz(one, self.pdf)
            repeated = source.prepare_glantz(two, self.pdf)
            self.assertEqual(manifest, repeated)
            self.assertEqual((manifest["source_rows"], manifest["monetary_rows"], manifest["normalized_legs"]), (379, 372, 744))
            for name in (*manifest["outputs"], "manifest.json"):
                self.assertEqual((one / name).read_bytes(), (two / name).read_bytes(), name)
            rows, metadata = source.load_glantz_fixture(one)
            self.assertEqual(rows, self.rows)
            self.assertEqual(metadata, self.metadata)
            normalized = list(csv.DictReader(io.StringIO((one / "legacy.csv").read_text(), newline="")))
            self.assertEqual(len(normalized), 744)
            by_id = {row["row_id"]: row for row in self.rows}
            for entry in manifest["row_mapping"]:
                legs = [row for row in normalized if row["entry_id"] == entry["entry_id"]]
                self.assertEqual(len(legs), 2)
                self.assertEqual(sum(Decimal(row["signed_amount"]) for row in legs), Decimal(0))
                original = by_id[entry["source_row_id"]]
                principal = next(row for row in legs if row["account_code"] == "BLMIS-" + original["account"])
                self.assertEqual(int(Decimal(principal["signed_amount"]) * 100), -original["principal_movement_cents"])
            source_bytes = (one / "rows.csv").read_bytes()
            changed = source_bytes.replace(b'"18,208,000"', b'"18,208,001"', 1)
            if changed == source_bytes:
                changed = source_bytes + b"\n"
            (one / "rows.csv").write_bytes(changed)
            forged = deepcopy(manifest)
            forged["source_rows_sha256"] = hashlib.sha256(changed).hexdigest()
            forged["outputs"]["rows.csv"] = {"bytes": len(changed), "sha256": hashlib.sha256(changed).hexdigest()}
            (one / "manifest.json").write_bytes(source.json_bytes(forged))
            with self.assertRaisesRegex(source.SourceError, "rows.csv differs"):
                source.load_glantz_fixture(one)
            legacy = (two / "legacy.csv").read_bytes() + b"\n"
            (two / "legacy.csv").write_bytes(legacy)
            forged = deepcopy(repeated)
            forged["outputs"]["legacy.csv"] = {"bytes": len(legacy), "sha256": hashlib.sha256(legacy).hexdigest()}
            (two / "manifest.json").write_bytes(source.json_bytes(forged))
            with self.assertRaisesRegex(source.SourceError, "legacy.csv differs"):
                source.load_glantz_fixture(two)


if __name__ == "__main__":
    unittest.main()
