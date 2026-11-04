"""Independent synthetic controls for the House adapter, not real-corpus claims.

Real source bytes are acquired by the explicit helper invocation. This small
fixture includes printed totals, two office sections, duplicated original rows,
reused document IDs, credits, offsetting gross activity, and undated payroll.
"""

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
import house_disbursements as house


ORGANIZATION = "SYNTHETIC HOUSE EXAMPLE"


def csv_bytes(headers, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def fixture():
    """All published controls below are literal, hand-calculated expectations."""
    rows = []

    def activity(program, category, amount, date, stream, document="DUP"):
        row = dict.fromkeys(house.DETAIL_HEADERS, "")
        row.update({"ORGANIZATION": ORGANIZATION, "FISCAL YEAR OR LEGISLATIVE YEAR": "FY2026",
                    "ORGANIZATION CODE": "00123", "PROGRAM": program, "PROGRAM CODE": "0007",
                    "SORT SUBTOTAL DESCRIPTION": category, "BUDGET OBJECT CLASS": "25",
                    "SORT SEQUENCE": "DETAIL", "TRANSACTION DATE": date, "DATA SOURCE": stream,
                    "DOCUMENT": document, "VENDOR NAME": 'Example, "Vendor"', "VENDOR ID": "0001",
                    "PERFORM START DT": "1-Apr-26", "PERFORM END DT": "30-Jun-26",
                    "DESCRIPTION": "Synthetic original record", "BUDGET OBJECT CODE": "2501", "AMOUNT": amount})
        rows.append(row)

    def subtotal(program, category, description, amount, *, office=False):
        row = dict.fromkeys(house.DETAIL_HEADERS, "   ")
        row.update({"ORGANIZATION": ORGANIZATION, "FISCAL YEAR OR LEGISLATIVE YEAR": "FY2026",
                    "ORGANIZATION CODE": "00123", "PROGRAM": program, "PROGRAM CODE": "",
                    "SORT SUBTOTAL DESCRIPTION": category,
                    "SORT SEQUENCE": "GRAND TOTAL FOR ORGANIZATION" if office else "SUBTOTAL",
                    "DESCRIPTION": description, "AMOUNT": amount})
        rows.append(row)

    activity("OPERATIONS", "OTHER SERVICES", "100.25", "5-Apr-26", "AP")
    activity("OPERATIONS", "OTHER SERVICES", "-20.25", "5-Apr-26", "AR")
    rows.append(copy.deepcopy(rows[0]))  # exact duplicate original, retained
    subtotal("OPERATIONS", "OTHER SERVICES", "OTHER SERVICES TOTALS:", "180.25")
    activity("OPERATIONS", "TRAVEL", "10", "15-May-26", "AP", "OFFSET")
    activity("OPERATIONS", "TRAVEL", "-10", "15-May-26", "AP", "OFFSET")
    subtotal("OPERATIONS", "TRAVEL", "TRAVEL TOTALS:", "0")
    subtotal("OPERATIONS", "TRAVEL", "OPERATIONS TOTALS:", "180.25")
    activity("PAYROLL", "PERSONNEL COMPENSATION", "2000", "", "GL", " ")
    activity("PAYROLL", "BENEFITS", "0.00", "6-Jun-26", "GL", "ZERO")
    subtotal("PAYROLL", "PERSONNEL COMPENSATION", "PERSONNEL COMPENSATION TOTALS:", "2000")
    subtotal("PAYROLL", "BENEFITS", "BENEFITS TOTALS:", "0")
    subtotal("PAYROLL", "BENEFITS", "PAYROLL TOTALS:", "2000")
    subtotal("PAYROLL", "BENEFITS", "OFFICE TOTALS: ", "2180.25", office=True)
    activity("GRANTS", "OTHER SERVICES", "30.1", "1-Jun-26", "GL", "DUP")
    subtotal("GRANTS", "OTHER SERVICES", "OTHER SERVICES TOTALS:", "30.1")
    subtotal("GRANTS", "OTHER SERVICES", "GRANTS TOTALS:", "30.1")
    subtotal("GRANTS", "OTHER SERVICES", "OFFICE TOTALS: ", "30.1", office=True)
    summaries = [
        [ORGANIZATION, "OPERATIONS", "OTHER SERVICES", "400.25", "180.25"],
        [ORGANIZATION, "OPERATIONS", "TRAVEL", "100", "0"],
        [ORGANIZATION, "OPERATIONS", "OPERATIONS TOTALS:", "500.25", "180.25"],
        [ORGANIZATION, "PAYROLL", "PERSONNEL COMPENSATION", "6000", "2000"],
        [ORGANIZATION, "PAYROLL", "BENEFITS", "20", "0"],
        [ORGANIZATION, "PAYROLL", "PAYROLL TOTALS:", "6020", "2000"],
        [ORGANIZATION, "EMPTY", "OTHER SERVICES", "3", "0"],
        [ORGANIZATION, "EMPTY", "EMPTY TOTALS:", "3", "0"],
        [ORGANIZATION, "EMPTY", "OFFICE TOTALS:", "6523.25", "2180.25"],
        [ORGANIZATION, "GRANTS", "OTHER SERVICES", "30.1", "30.1"],
        [ORGANIZATION, "GRANTS", "GRANTS TOTALS:", "30.1", "30.1"],
        [ORGANIZATION, "GRANTS", "OFFICE TOTALS:", "30.1", "30.1"],
    ]
    detail = csv_bytes([*house.DETAIL_HEADERS[:-1], "AMOUNT" + " " * 64],
                       [[row[key] for key in house.DETAIL_HEADERS] for row in rows])
    summary = csv_bytes([*house.SUMMARY_HEADERS[:-1], "QTD AMOUNT" + " " * 196], summaries)
    spec = copy.deepcopy(house.load_spec())
    spec["id"] = "synthetic-house-test"
    spec["default_organization"] = ORGANIZATION
    spec["controls"] = {
        "record_count": 18, "detail_rows": 8, "subtotal_rows": 8, "office_total_rows": 2,
        "summary_rows": 12, "organization_count": 1, "positive_rows": 5, "negative_rows": 2,
        "zero_rows": 1, "positive_minor": "224060", "negative_minor": "-3025", "net_minor": "221035",
        "duplicate_detail_rows": 1, "missing_transaction_dates": 1, "outside_quarter_transaction_dates": 0,
        "unparsed_service_dates": 0, "data_sources": {"AP": 4, "AR": 1, "GL": 3},
    }
    return repin(spec, detail, summary), detail, summary


def repin(spec, detail, summary):
    changed = copy.deepcopy(spec)
    for name, value in (("detail", detail), ("summary", summary)):
        changed[name].update(byte_length=len(value), sha256=house.sha256(value))
    return changed


def records(data):
    return [json.loads(line) for line in data.splitlines()]


def bundle(spec, detail, summary):
    return house.build_bundle(detail, summary, ORGANIZATION, spec=spec)


class LiteralTests(unittest.TestCase):
    def test_exact_published_decimal_styles_and_wide_values(self):
        for text, expected in [("0", 0), ("0.0", 0), ("-0.00", 0), ("15", 1500),
                               ("15.7", 1570), ("-20.25", -2025),
                               ("9007199254740993.99", 900719925474099399)]:
            with self.subTest(text=text):
                self.assertEqual(house.parse_minor(text), expected)
                self.assertEqual(house.reference_minor(text), expected)

    def test_subcent_nonfinite_rounded_or_ambiguous_literals_refuse(self):
        for text in ["1.001", "NaN", "Infinity", "1e3", "1,000.00", " 1", "1 ",
                     "+1", "01", "(1)", "1.", ".25", "-", "", "1" * 65, str(1 << 127)]:
            with self.subTest(text=text):
                with self.assertRaises(house.DataError):
                    house.parse_minor(text)

    def test_calendar_and_century_policy_are_explicit(self):
        self.assertEqual(house.source_date("1-Apr-26"), "2026-04-01")
        self.assertEqual(house.source_date("01-Apr-26"), "2026-04-01")
        self.assertEqual(house.source_date("2-May-36"), "2036-05-02")
        self.assertIsNone(house.source_date("   "))
        for text in ["31-Apr-26", "29-Feb-25", "1-APR-26", "14-MAR-0026", "2026-04-01"]:
            with self.subTest(text=text):
                with self.assertRaises(house.DataError):
                    house.source_date(text)

    def test_service_date_defect_is_explicit_and_never_repaired(self):
        diagnostic = house.service_date("14-MAR-0026")
        self.assertEqual(diagnostic["literal"], "14-MAR-0026")
        self.assertEqual(diagnostic["status"], "unparsed_as_published")
        self.assertIsNone(diagnostic["parsed_iso"])


class SourceTests(unittest.TestCase):
    def test_pinned_manifest_has_full_publication_population(self):
        spec = house.load_spec()
        self.assertEqual(spec["detail"]["byte_length"], 26169448)
        self.assertEqual(spec["summary"]["byte_length"], 621267)
        self.assertEqual(spec["controls"]["detail_rows"], 123701)
        self.assertEqual(spec["controls"]["net_minor"], "45744956364")
        self.assertEqual(spec["controls"]["unparsed_service_dates"], 2)
        self.assertEqual(spec["controls"]["outside_quarter_transaction_dates"], 3)

    def test_both_original_files_are_authenticated_before_transform(self):
        spec, detail, summary = fixture()
        for changed_detail, changed_summary, kind in [
            (detail.replace(b"100.25", b"100.26", 1), summary, "detail"),
            (detail, summary.replace(b"180.25", b"180.26", 1), "summary"),
        ]:
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(house.DataError, kind + " source SHA-256 mismatch"):
                    bundle(spec, changed_detail, changed_summary)

    def test_repinning_source_does_not_hide_dropped_equal_offset_rows(self):
        spec, detail, summary = fixture()
        parsed = list(csv.reader(io.StringIO(detail.decode(), newline="")))
        # Drop +10 and -10 from the real source shape. Every NET subtotal is
        # unchanged, but independently pinned census and gross activity fail.
        shortened = csv_bytes(parsed[0], [row for index, row in enumerate(parsed[1:], 1) if index not in (5, 6)])
        with self.assertRaisesRegex(house.DataError, "full source census"):
            bundle(repin(spec, shortened, summary), shortened, summary)

    def test_header_width_unknown_row_class_and_encoding_are_refused(self):
        spec, detail, summary = fixture()
        for changed, message in [
            (detail.replace(b"VENDOR ID", b"SUPPLIER ID", 1), "header drift"),
            (detail.replace(b"SYNTHETIC HOUSE EXAMPLE,FY2026", b"FY2026", 1), "field count"),
            (detail.replace(b",DETAIL,", b",UNKNOWN,", 1), "row kind"),
            (detail.replace(b"Synthetic original", b"Synthetic \xfforiginal", 1), "encoding"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(house.DataError, message):
                    bundle(repin(spec, changed, summary), changed, summary)

    def test_out_of_quarter_transaction_date_is_never_shifted(self):
        spec, _, _ = fixture()
        fields = {"TRANSACTION DATE": "19-Dec-24", "DATA SOURCE": "AP"}
        with self.assertRaisesRegex(house.DataError, "outside the quarter"):
            house.effective_date(fields, spec)
        with self.assertRaisesRegex(house.DataError, "undated GL"):
            house.effective_date({"TRANSACTION DATE": "", "DATA SOURCE": "AP"}, spec)

    def test_whole_source_date_defect_is_reported_but_selected_accounting_date_refuses(self):
        spec, detail, summary = fixture()
        changed = detail.replace(b"1-Jun-26,GL,DUP", b"INVALID,GL,DUP", 1)
        altered_spec = repin(spec, changed, summary)
        observed = house.profile(changed, summary, spec=altered_spec)
        self.assertEqual(observed["organizations"][0]["publisher_controls"], "PASS")
        self.assertEqual(observed["organizations"][0]["date_policy"], "REFUSED")
        diagnostic = observed["source_date_diagnostics"][0]
        self.assertEqual(diagnostic["record_ordinal"], 15)
        self.assertEqual(diagnostic["literal"], "INVALID")
        self.assertEqual(diagnostic["classification"], "unparsed_transaction_date")
        with self.assertRaisesRegex(house.DataError, "invalid published date"):
            bundle(altered_spec, changed, summary)

    def test_fetch_is_bounded_and_source_checked(self):
        spec, detail, _ = fixture()
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.geturl.return_value = spec["detail"]["url"]
        response.read.return_value = detail
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch.object(house.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(house.acquire_source("detail", spec), detail)
        response.read.assert_called_once_with(spec["detail"]["max_bytes"] + 1)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 45)
        response.read.return_value = detail + b"x"
        with mock.patch.object(house.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(house.DataError, "byte count"):
                house.acquire_source("detail", spec)

    def test_redirect_cannot_leave_the_publisher_or_downgrade_https(self):
        for url in ["http://www.house.gov/data", "https://other.example/data", "https://www.house.gov.evil.test/data",
                    "https://user:secret@www.house.gov/data", "https://www.house.gov:444/data", "file:///data"]:
            with self.subTest(url=url):
                with self.assertRaises(house.DataError):
                    house.house_url(url)


class ReconciliationTests(unittest.TestCase):
    def test_all_source_and_summary_control_rows_survive_without_posting(self):
        spec, detail, summary = fixture()
        result = bundle(spec, detail, summary)
        saved = records(result["records.jsonl"])
        summaries = records(result["summary-records.jsonl"])
        provenance = records(result["provenance.jsonl"])
        self.assertEqual(len(saved), 18)
        self.assertEqual(len(summaries), 12)
        self.assertEqual(len(provenance), 18)
        self.assertEqual(result["raw-detail.csv"], detail)
        self.assertEqual(result["raw-summary.csv"], summary)
        self.assertEqual(sum(row["disposition"] == "posted" for row in saved), 7)
        self.assertEqual(sum(row["disposition"] == "unposted_zero" for row in saved), 1)
        self.assertTrue(all(row["entry_id"] is None for row in provenance if row["control_kind"] != "detail"))
        self.assertEqual({row["publication_section"] for row in saved}, {1, 2})
        self.assertEqual(len(json.loads(result["controls.json"])["checks"]), 12)

    def test_original_duplicate_rows_and_reused_document_ids_keep_distinct_identities(self):
        spec, detail, summary = fixture()
        result = bundle(spec, detail, summary)
        saved = records(result["records.jsonl"])
        self.assertEqual(saved[0]["raw_fields"], saved[2]["raw_fields"])
        self.assertEqual(saved[0]["record_sha256"], saved[2]["record_sha256"])
        self.assertNotEqual(saved[0]["row_id"], saved[2]["row_id"])
        self.assertEqual(len({row["row_id"] for row in saved}), 18)
        self.assertEqual(saved[0]["raw_fields"]["DOCUMENT"], saved[14]["raw_fields"]["DOCUMENT"])
        expected = json.loads(result["expected_tb.json"])
        self.assertEqual(expected["source_stats"]["duplicate_detail_rows"], 1)
        self.assertEqual((expected["entry_count"], expected["leg_count"]), (4, 14))

    def test_blank_transaction_date_preserves_service_dates_and_declares_analysis_assignment(self):
        spec, detail, summary = fixture()
        row = records(bundle(spec, detail, summary)["records.jsonl"])[8]
        self.assertEqual(row["raw_fields"]["TRANSACTION DATE"], "")
        self.assertEqual(row["raw_fields"]["PERFORM START DT"], "1-Apr-26")
        self.assertEqual(row["effective_date"], "2026-06-30")
        self.assertEqual(row["date_policy"], "undated_gl_quarter_end")
        self.assertEqual(row["service_period_start"], {"literal": "1-Apr-26", "parsed_iso": "2026-04-01", "status": "parsed"})

    def test_inline_one_cent_subtotal_mutation_fails_even_with_new_source_hash(self):
        spec, detail, summary = fixture()
        changed = detail.replace(b"OTHER SERVICES TOTALS:,   ,180.25", b"OTHER SERVICES TOTALS:,   ,180.26", 1)
        self.assertNotEqual(changed, detail)
        with self.assertRaisesRegex(house.DataError, "inline category subtotal discrepancy"):
            bundle(repin(spec, changed, summary), changed, summary)

    def test_summary_one_cent_control_mutation_fails_even_with_new_source_hash(self):
        spec, detail, summary = fixture()
        changed = summary.replace(b"400.25,180.25", b"400.25,180.26", 1)
        with self.assertRaisesRegex(house.DataError, "independent summary category discrepancy"):
            bundle(repin(spec, detail, changed), detail, changed)

    def test_summary_ytd_never_substitutes_for_the_quarter(self):
        spec, detail, summary = fixture()
        result = bundle(spec, detail, summary)
        controls = json.loads(result["controls.json"])
        self.assertEqual(controls["qtd_net_minor"], "221035")
        original = records(result["summary-records.jsonl"])[0]
        self.assertEqual(original["raw_fields"]["YTD AMOUNT"], "400.25")
        self.assertEqual(original["raw_fields"]["QTD AMOUNT"], "180.25")

    def test_duplicate_summary_key_in_one_section_is_ambiguous_not_deduplicated(self):
        spec, detail, summary = fixture()
        parsed = list(csv.reader(io.StringIO(summary.decode(), newline="")))
        changed = csv_bytes(parsed[0], [parsed[1], *parsed[1:]])
        altered_spec = repin(spec, detail, changed)
        altered_spec["controls"]["summary_rows"] = 13
        with self.assertRaisesRegex(house.DataError, "ambiguous repeated category control"):
            bundle(altered_spec, detail, changed)

    def test_repeated_labels_across_office_sections_are_separate_controls(self):
        spec, detail, summary = fixture()
        detail = detail.replace(b"GRANTS", b"OPERATIONS")
        summary = summary.replace(b"GRANTS", b"OPERATIONS")
        result = bundle(repin(spec, detail, summary), detail, summary)
        controls = json.loads(result["controls.json"])
        repeated = [row for row in controls["checks"] if row["kind"] == "category"
                    and row["program"] == "OPERATIONS" and row["category"] == "OTHER SERVICES"]
        self.assertEqual([row["publication_section"] for row in repeated], [1, 2])
        self.assertEqual([row["summary_qtd_minor"] for row in repeated], ["18025", "3010"])
        expected = json.loads(result["expected_tb.json"])
        account = house.expense_account("OPERATIONS", "OTHER SERVICES")
        cell = next(row for row in expected["accounts"] if row["account"] == account)
        self.assertEqual(cell["signed_minor"], "21035")

    def test_cumulative_gross_controls_keep_net_zero_activity_and_summary_only_zero_accounts(self):
        spec, detail, summary = fixture()
        expected = json.loads(bundle(spec, detail, summary)["expected_tb.json"])
        travel = house.expense_account("OPERATIONS", "TRAVEL")
        empty = house.expense_account("EMPTY", "OTHER SERVICES")
        controls = expected["controls"]
        self.assertEqual([row["period"] for row in controls], [f"FY2026-P{month:02}" for month in range(4, 13)])
        may = next(row for row in controls[1]["accounts"] if row["account"] == travel)
        self.assertEqual((may["debit_minor"], may["credit_minor"], may["signed_minor"]), ("1000", "1000", "0"))
        june = {row["account"]: row for row in controls[2]["accounts"]}
        self.assertEqual(june[empty]["debit_minor"], "0")
        self.assertEqual(june[house.OFFSET_ACCOUNT]["signed_minor"], "-221035")
        self.assertTrue(all(row["accounts"] == controls[2]["accounts"] for row in controls[3:]))
        self.assertTrue(all(row["carry_only"] for row in controls[3:]))
        self.assertTrue(all(row["net_control_basis"] == "independent_published_summary_qtd" for row in controls[2:]))
        self.assertEqual(expected["unit"], "USD")
        self.assertEqual(expected["opening_date"], "2027-01-01")

    def test_profile_preserves_refusals_instead_of_filtering_organizations(self):
        spec, detail, summary = fixture()
        changed = summary.replace(b"400.25,180.25", b"400.25,180.26", 1)
        observed = house.profile(detail, changed, spec=repin(spec, detail, changed))
        self.assertEqual(len(observed["organizations"]), 1)
        self.assertEqual(observed["organizations"][0]["publisher_controls"], "REFUSED")
        self.assertIn("independent summary category discrepancy", observed["organizations"][0]["reason"])
        self.assertEqual(observed["native_validation"], "UNRUN")


class PreparedIntegrityTests(unittest.TestCase):
    def test_exclusive_write_exact_retry_and_independent_regeneration(self):
        spec, detail, summary = fixture()
        files = bundle(spec, detail, summary)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "prepared"
            house.write_bundle(path, files)
            house.write_bundle(path, files)
            self.assertEqual(house.verify_prepared(path, ORGANIZATION, spec=spec), json.loads(files["expected_tb.json"]))
            changed = {**files, "legacy.csv": files["legacy.csv"].replace(b"2026-04-05", b"2026-04-06", 1)}
            with self.assertRaisesRegex(house.DataError, "overwrite"):
                house.write_bundle(path, changed)
            self.assertEqual((path / "legacy.csv").read_bytes(), files["legacy.csv"])

    def test_changed_date_or_repeated_row_identity_in_prepared_files_is_rejected(self):
        spec, detail, summary = fixture()
        files = bundle(spec, detail, summary)
        for name in ("legacy.csv", "provenance.jsonl"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "prepared"
                house.write_bundle(path, files)
                if name == "legacy.csv":
                    changed = files[name].replace(b"2026-04-05", b"2026-04-06", 1)
                else:
                    values = records(files[name])
                    values[2]["row_id"] = values[0]["row_id"]
                    changed = house.jsonl_bytes(values)
                (path / name).write_bytes(changed)
                with self.assertRaisesRegex(house.DataError, "pinned-source regeneration"):
                    house.verify_prepared(path, ORGANIZATION, spec=spec)

    def test_removing_one_pair_of_balanced_legs_is_rejected_despite_unchanged_balance(self):
        spec, detail, summary = fixture()
        files = bundle(spec, detail, summary)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "prepared"
            house.write_bundle(path, files)
            rows = list(csv.reader(io.StringIO(files["legacy.csv"].decode(), newline="")))
            (path / "legacy.csv").write_bytes(csv_bytes(rows[0], rows[3:]))
            with self.assertRaisesRegex(house.DataError, "pinned-source regeneration"):
                house.verify_prepared(path, ORGANIZATION, spec=spec)


if __name__ == "__main__":
    unittest.main()
