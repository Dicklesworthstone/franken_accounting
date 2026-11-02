"""Negative controls for the real public-ledger source boundary (stdlib only)."""

import csv
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import public_ledger_source as source


def record(**changes):
    row = dict.fromkeys(source.HEADERS, " ")
    row.update({
        "BUSINESS_UNIT": "03900", "OCP_AGNCY_NAME": "A public agency",
        "LEDGER": "ACTUALS", "FISCAL_YEAR": "2024", "ACCOUNTING_PERIOD": "10",
        "FUND_CODE": "1000", "CLASS_FLD": "8315A", "ACCOUNT": "101000",
        "ACCTDESCR": "Cash", source.AMOUNT_COLUMN: "1.23",
    })
    row.update(changes)
    return row


def csv_bytes(rows, *, headers=source.HEADERS):
    text = io.StringIO(newline="")
    writer = csv.writer(text)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([row[h] for h in headers])
    return text.getvalue().encode("cp1252")


class SourceParsingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ledger.csv"

    def write(self, rows, **kwargs):
        self.path.write_bytes(csv_bytes(rows, **kwargs))
        return self.path

    def test_exact_amounts_and_subcent_refusal(self):
        for text, mills in [("0", 0), ("-0.008", -8), ("+3.41", 3410),
                            ("3449445.312", 3449445312), ("1.230", 1230),
                            ("123456789012345678901234567890.12", 123456789012345678901234567890120)]:
            self.assertEqual(source.amount_mills(text), mills)
        self.assertEqual(source.amount_cents("-123.450"), -12345)
        with self.assertRaisesRegex(source.SourceError, "subcent"):
            source.amount_cents("0.001")
        for text in ["1e3", "NaN", "1,000.00", " 1.00", "1.0001", "1.", "", "∞", "１２"]:
            with self.subTest(text=text), self.assertRaises(source.SourceError):
                source.amount_mills(text)

    def test_cp1252_quoted_multiline_and_identifiers_are_lossless(self):
        first = record(PROJDESCR='A quoted "project", with\na second line – retained')
        rows = list(source.iter_rows(self.write([first, record()])))
        self.assertEqual([n for n, _ in rows], [1, 2])
        self.assertEqual(rows[0][1], first)
        self.assertEqual(rows[0][1]["BUSINESS_UNIT"], "03900")
        self.assertEqual(rows[0][1]["CLASS_FLD"], "8315A")
        self.assertEqual(rows[0][1]["DEPTID"], " ")

    def test_schema_drift_ragged_records_and_bad_encoding_refuse(self):
        self.write([record()], headers=source.HEADERS[:-1])
        with self.assertRaisesRegex(source.SourceError, "header"):
            list(source.iter_rows(self.path))
        self.write([record()])
        with self.path.open("ab") as output:
            output.write(b"only,two\r\n")
        with self.assertRaisesRegex(source.SourceError, "record 2 has 2 columns"):
            list(source.iter_rows(self.path))
        self.path.write_bytes(csv_bytes([record()]) + b"\x81")
        with self.assertRaisesRegex(source.SourceError, "decode"):
            list(source.iter_rows(self.path))

    def test_truncated_quoted_record_and_nul_refuse(self):
        self.path.write_bytes(csv_bytes([]) + b'"unterminated')
        with self.assertRaisesRegex(source.SourceError, "decode"):
            list(source.iter_rows(self.path))
        self.write([record(PROJDESCR="bad\x00description")])
        with self.assertRaisesRegex(source.SourceError, "NUL"):
            list(source.iter_rows(self.path))

    def test_complete_agency_keeps_zero_rows_and_source_ordinal_mapping(self):
        debit = record()
        credit = record(ACCOUNT="431000", ACCTDESCR="Revenue", **{source.AMOUNT_COLUMN: "-1.23"})
        zero = record(CLASS_FLD="90000", **{source.AMOUNT_COLUMN: "0"})
        result = source.prepare_agency(self.write([debit, credit, zero]), "03900", source_records=[10, 20, 40])
        self.assertEqual([r["source_record"] for r in result["rows"]], [10, 20, 40])
        self.assertEqual(result["summary"]["zero_rows"], 1)
        self.assertEqual(result["summary"]["rows"], 3)
        self.assertEqual(result["summary"]["group_count"], 2)
        self.assertEqual(result["groups"][1]["rows"][0]["amount_mills"], 0)
        self.assertEqual(result["headers"], list(source.HEADERS))

    def test_noncontiguous_rows_are_all_selected_without_other_agency(self):
        self.write([record(), record(BUSINESS_UNIT="01000"), record(**{source.AMOUNT_COLUMN: "-1.23"})])
        result = source.prepare_agency(self.path, "03900")
        self.assertEqual([r["source_record"] for r in result["rows"]], [1, 3])
        self.assertEqual(result["summary"]["source_rows_scanned"], 3)

    def test_global_balance_cannot_hide_unbalanced_funds_or_periods(self):
        for change in [{"CLASS_FLD": "90000"}, {"FUND_CODE": "2000"}, {"ACCOUNTING_PERIOD": "11"}]:
            with self.subTest(change=change):
                self.write([record(), record(**change, **{source.AMOUNT_COLUMN: "-1.23"})])
                observed = source.read_agency(self.path, "03900")
                self.assertEqual(observed["summary"]["net_mills"], 0)
                with self.assertRaisesRegex(source.SourceError, "complete agency import is refused"):
                    source.prepare_agency(self.path, "03900")

    def test_balanced_subcent_rows_still_refuse_cent_import(self):
        self.write([record(**{source.AMOUNT_COLUMN: "0.004"}), record(**{source.AMOUNT_COLUMN: "-0.004"})])
        with self.assertRaisesRegex(source.SourceError, "subcent"):
            source.prepare_agency(self.path, "03900")
        profile = source.profile_source(self.path, verify=False)
        self.assertFalse(profile["verified_source"])
        self.assertEqual(profile["summary"]["net_mills"], 0)
        self.assertEqual(profile["summary"]["subcent_rows"], 2)
        self.assertEqual([r["amount_mills"] for r in profile["subcent_diagnostics"]], [4, -4])

    def test_profile_reports_imbalance_without_repair(self):
        self.write([record(), record(ACCOUNTING_PERIOD="11", **{source.AMOUNT_COLUMN: "-1.22"})])
        profile = source.profile_source(self.path, verify=False)
        self.assertEqual(profile["summary"]["net_mills"], 10)
        self.assertEqual(profile["summary"]["unbalanced_agency_period_count"], 2)
        self.assertEqual(profile["summary"]["positive_mills"], 1230)
        self.assertEqual(profile["summary"]["negative_mills"], -1220)
        with self.assertRaisesRegex(source.SourceError, "source pin mismatch"):
            source.profile_source(self.path)

    def test_ambiguous_metadata_and_source_map_fail_closed(self):
        for change in [{"ACCOUNTING_PERIOD": "13"}, {"ACCOUNT": "1e5"}, {"LEDGER": "BUDGET"}]:
            with self.subTest(change=change), self.assertRaises(source.SourceError):
                source.read_agency(self.write([record(**change)]), "03900")
        self.write([record(), record()])
        for mapping in [[1], [1, 2, 3], [2, 1], [1, 1], [0, 2], [True, 2]]:
            with self.subTest(mapping=mapping), self.assertRaises(source.SourceError):
                source.read_agency(self.path, "03900", source_records=mapping)
        with self.assertRaisesRegex(source.SourceError, "no rows"):
            source.read_agency(self.path, "99900")
        with self.assertRaisesRegex(source.SourceError, "five-digit"):
            source.read_agency(self.path, "3900")
        self.write([record(), record(ACCTDESCR="Different cash name")])
        with self.assertRaisesRegex(source.SourceError, "conflicting descriptions"):
            source.read_agency(self.path, "03900")


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "download.csv"
        self.body = csv_bytes([record()])
        for name, value in [("SOURCE_SIZE_BYTES", len(self.body)),
                            ("SOURCE_SHA256", hashlib.sha256(self.body).hexdigest())]:
            patch = mock.patch.object(source, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def response(self, body):
        stream = io.BytesIO(body)
        stream.headers = {}
        stream.geturl = lambda: source.SOURCE_URL
        return stream

    def test_verified_download_and_cache_use_honest_user_agent(self):
        with mock.patch.object(source.urllib.request, "urlopen", return_value=self.response(self.body)) as fetch:
            self.assertEqual(source.fetch_source(self.path), self.path)
            request = fetch.call_args.args[0]
            self.assertEqual(request.get_header("User-agent"), source.USER_AGENT)
            self.assertEqual(source.fetch_source(self.path), self.path)
            self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.path.read_bytes(), self.body)

    def test_truncated_oversized_or_changed_downloads_never_publish(self):
        for body in [self.body[:-1], self.body + b"x", bytes([self.body[0] ^ 1]) + self.body[1:]]:
            with self.subTest(size=len(body)):
                with mock.patch.object(source.urllib.request, "urlopen", return_value=self.response(body)):
                    with self.assertRaises(source.SourceError):
                        source.fetch_source(self.path)
                self.assertFalse(self.path.exists())
                self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_existing_mismatched_file_is_preserved(self):
        self.path.write_bytes(b"unrelated existing data")
        with mock.patch.object(source.urllib.request, "urlopen") as fetch:
            with self.assertRaisesRegex(source.SourceError, "pin mismatch"):
                source.fetch_source(self.path)
            fetch.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b"unrelated existing data")

    def test_destination_created_during_download_is_never_overwritten(self):
        response = self.response(self.body)
        original_read = response.read

        def read_and_create_destination(size):
            self.path.write_bytes(b"another writer's data")
            return original_read(size)

        response.read = read_and_create_destination
        with mock.patch.object(source.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(source.SourceError, "download failed"):
                source.fetch_source(self.path)
        self.assertEqual(self.path.read_bytes(), b"another writer's data")
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])


if __name__ == "__main__":
    unittest.main()
