"""Offline adapter tests; full government-source replay is an explicit invocation.

The little fixtures here exercise malformed inputs and accounting edge cases.
They are labeled synthetic and never advertised as real-world test coverage.
"""

import copy
import csv
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "public_spend.py"
SPEC = importlib.util.spec_from_file_location("public_spend", MODULE_PATH)
public_spend = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = public_spend
SPEC.loader.exec_module(public_spend)


HEADERS = ["Department family", "Entity", "Date", "Expense type", "Expense area",
           "Supplier", "Transaction number", "Amount", "Description", "Supplier Postcode"]


def fixture():
    """Synthetic controls manually calculated independently of adapter code."""
    rows = [
        ["EXAMPLE", "EXAMPLE", "01/03/2025", "Travel", "North", "Café, Ltd", "P1", "100.25", 'Rail "return"', "X1"],
        ["EXAMPLE", "EXAMPLE", "01/03/2025", "Travel", "North", "Café, Ltd", "P1", "-20.25", "Credit", "X1"],
        ["EXAMPLE", "EXAMPLE", "02/03/2025", "Travel", "South", "Café, Ltd", "P2", "0.00", "Zero source value", "X1"],
        ["EXAMPLE", "EXAMPLE", "01/03/2025", "Travel", "North", "Café, Ltd", "P1", "100.25", 'Rail "return"', "X1"],
        ["EXAMPLE", "EXAMPLE", "02/03/2025", "IT", "South", "IT Ltd", "P2", "12.30", "Software", "X2"],
        ["EXAMPLE", "EXAMPLE", "03/03/2025", "IT", "South", "IT Ltd", "P3", "0.10", "Support", "X2"],
    ]
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(HEADERS)
    writer.writerows(rows)
    raw = buffer.getvalue().encode("cp1252")
    spec = copy.deepcopy(public_spend.load_sources()["hmrc-2025-03"])
    spec.update(id="synthetic-test", sha256=public_spend.sha256(raw), byte_length=len(raw))
    spec["controls"] = {
        "row_count": 6, "positive_rows": 4, "negative_rows": 1, "zero_rows": 1,
        "positive_minor": "21290", "negative_minor": "-2025", "net_minor": "19265",
        "min_minor": "-2025", "max_minor": "10025", "duplicate_rows": 1,
        "transaction_count": 3, "split_transaction_count": 2, "max_transaction_rows": 3,
        "expense_type_count": 2, "expense_area_count": 2, "supplier_count": 2, "date_count": 3,
    }
    return spec, raw


def repin(spec, raw):
    return {**spec, "byte_length": len(raw), "sha256": public_spend.sha256(raw)}


def jsonl(raw):
    return [json.loads(line) for line in raw.splitlines()]


class AmountTests(unittest.TestCase):
    def test_decimal_amounts_and_pence_are_exact(self):
        self.assertEqual(public_spend.parse_amount("0.01", "decimal"), 1)
        self.assertEqual(public_spend.parse_amount("-31280.00", "decimal"), -3128000)
        self.assertEqual(public_spend.parse_amount("9007199254740993.99", "decimal"), 900719925474099399)

    def test_whole_pound_source_values_and_negative_credits(self):
        for text, minor in [("£14,966,428", 1496642800), ("-£1", -100), ("£0", 0), ("£1234", 123400)]:
            with self.subTest(text=text):
                self.assertEqual(public_spend.parse_amount(text, "sterling_whole_pounds"), minor)

    def test_malformed_amounts_are_never_rounded_or_silently_cleaned(self):
        for text in ["1.001", "1", "1e3", "NaN", "1,234.00", "+1.00", " 1.00", "1.00 ", "01.00", "(1.00)"]:
            with self.subTest(text=text):
                with self.assertRaises(public_spend.DataError):
                    public_spend.parse_amount(text, "decimal")
        for text in ["£1,23", "£1,234,56", "£01", "£1.00", "£-1", "GBP 1", "£ 1", "£1e2"]:
            with self.subTest(text=text):
                with self.assertRaises(public_spend.DataError):
                    public_spend.parse_amount(text, "sterling_whole_pounds")

    def test_i128_overflow_is_refused(self):
        with self.assertRaisesRegex(public_spend.DataError, "i128"):
            public_spend.parse_amount(f"{1 << 127}.00", "decimal")


class SourceTests(unittest.TestCase):
    def test_manifest_contains_complete_locked_real_source_controls(self):
        sources = public_spend.load_sources()
        self.assertEqual(sources["hmrc-2025-03"]["controls"]["row_count"], 1430)
        self.assertEqual(sources["dwp-2025-01"]["controls"]["row_count"], 13099)
        self.assertEqual(sources["hmrc-2025-03"]["controls"]["net_minor"], "28574458415")
        self.assertEqual(sources["dwp-2025-01"]["controls"]["net_minor"], "30776409400")

    def test_source_mutation_is_rejected_before_parsing(self):
        spec, raw = fixture()
        changed = raw.replace(b"100.25", b"100.26", 1)
        with self.assertRaisesRegex(public_spend.DataError, "SHA-256"):
            public_spend.build_bundle(spec, changed)

    def test_header_width_encoding_and_date_drift_are_refused(self):
        spec, raw = fixture()
        mutations = [
            (raw.replace(b"Expense type", b"Expense kind", 1), "header drift"),
            (raw.replace(b"EXAMPLE,EXAMPLE", b"EXAMPLE", 1), "fields"),
            (raw.replace(b"Caf\xe9", b"Caf\x81", 1), "encoding"),
            (raw.replace(b"01/03/2025", b"31/02/2025", 1), "invalid calendar date"),
            (raw.replace(b"01/03/2025", b"01/04/2025", 1), "outside declared source period"),
        ]
        for changed, message in mutations:
            with self.subTest(message=message):
                with self.assertRaisesRegex(public_spend.DataError, message):
                    public_spend.decode_records(repin(spec, changed), changed)

    def test_new_source_pin_does_not_bypass_independent_control_totals(self):
        spec, raw = fixture()
        changed = raw.replace(b"100.25", b"100.26", 1)
        with self.assertRaisesRegex(public_spend.DataError, "independent source controls"):
            public_spend.build_bundle(repin(spec, changed), changed)

    def test_network_read_is_bounded_and_hash_checked(self):
        spec, raw = fixture()
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.geturl.return_value = spec["url"]
        response.read.return_value = raw
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch.object(public_spend.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(public_spend.acquire_source(spec), raw)
        response.read.assert_called_once_with(spec["max_bytes"] + 1)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 30)
        self.assertEqual(opener.open.call_args.args[0].get_header("User-agent"), public_spend.USER_AGENT)

    def test_insecure_source_or_redirect_is_refused(self):
        for url in ["http://example.com/source.csv", "https://user:secret@example.com/source.csv", "file:///tmp/data"]:
            with self.subTest(url=url):
                with self.assertRaises(public_spend.DataError):
                    public_spend.https_url(url)


class BundleTests(unittest.TestCase):
    def test_every_source_record_duplicate_and_zero_survives(self):
        spec, raw = fixture()
        bundle = public_spend.build_bundle(spec, raw)
        records = jsonl(bundle["records.jsonl"])
        provenance = jsonl(bundle["provenance.jsonl"])
        self.assertEqual(len(records), 6)
        self.assertEqual(len({row["row_id"] for row in records}), 6)
        self.assertEqual(records[0]["raw_fields"], records[3]["raw_fields"])
        self.assertNotEqual(records[0]["row_id"], records[3]["row_id"])
        self.assertEqual(records[0]["supplier"], "Café, Ltd")
        self.assertEqual(records[0]["raw_fields"]["Description"], 'Rail "return"')
        self.assertEqual(provenance[2]["disposition"], "unposted_zero")
        self.assertIsNone(provenance[2]["entry_id"])
        self.assertEqual(bundle["raw.csv"], raw)

    def test_generated_gl_folds_to_independent_signed_category_totals(self):
        spec, raw = fixture()
        bundle = public_spend.build_bundle(spec, raw)
        rows = list(csv.DictReader(io.StringIO(bundle["legacy.csv"].decode())))
        balances = {}
        groups = {}
        for row in rows:
            amount = public_spend.parse_amount(row["amount"], "decimal")
            signed = amount if row["side"] == "D" else -amount
            balances[row["account_code"]] = balances.get(row["account_code"], 0) + signed
            groups[row["entry_id"]] = groups.get(row["entry_id"], 0) + signed
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(value == 0 for value in groups.values()))
        self.assertEqual(balances[public_spend.expense_account("Travel")], 18025)
        self.assertEqual(balances[public_spend.expense_account("IT")], 1240)
        self.assertEqual(balances[public_spend.OFFSET_ACCOUNT], -19265)
        expected = json.loads(bundle["expected_tb.json"])
        self.assertEqual(balances, {row["account"]: int(row["signed_minor"]) for row in expected["accounts"]})
        self.assertEqual(expected["entry_count"], 3)
        self.assertEqual(expected["leg_count"], 10)
        self.assertEqual(expected["posted_row_count"], 5)
        self.assertEqual(expected["zero_row_count"], 1)
        chart = json.loads(bundle["chart.json"])
        offset = next(row for row in chart["accounts"] if row["code"] == public_spend.OFFSET_ACCOUNT)
        self.assertEqual(offset["type"], "Equity")
        self.assertNotIn("roles", offset)

    def test_each_leg_maps_back_to_its_original_record(self):
        spec, raw = fixture()
        bundle = public_spend.build_bundle(spec, raw)
        legs = list(csv.DictReader(io.StringIO(bundle["legacy.csv"].decode())))
        for row in jsonl(bundle["provenance.jsonl"]):
            linked = [leg for leg in legs if leg["memo"] == "source_row=" + row["row_id"]]
            self.assertEqual(len(linked), 0 if row["disposition"] == "unposted_zero" else 2)
            if linked:
                self.assertEqual({leg["entry_id"] for leg in linked}, {row["entry_id"]})

    def test_all_dimensions_conserve_the_original_signed_amounts(self):
        spec, raw = fixture()
        bundle = public_spend.build_bundle(spec, raw)
        dimensions = json.loads(bundle["dimensions.json"])
        for name, rows in dimensions.items():
            with self.subTest(name=name):
                self.assertEqual(sum(row["row_count"] for row in rows), 6)
                self.assertEqual(sum(int(row["signed_minor"]) for row in rows), 19265)
                self.assertEqual(sum(int(row["positive_minor"]) for row in rows), 21290)
                self.assertEqual(sum(int(row["negative_minor"]) for row in rows), -2025)

    def test_date_chunking_preserves_all_originals_and_bounded_journals(self):
        spec, raw = fixture()
        # Change only the bound, so the same independently pinned corpus must
        # still retain every record and total with more generated journal ids.
        with mock.patch.object(public_spend, "MAX_ROWS_PER_ENTRY", 2):
            bundle = public_spend.build_bundle(spec, raw)
        expected = json.loads(bundle["expected_tb.json"])
        self.assertEqual(expected["entry_count"], 4)
        self.assertEqual(expected["leg_count"], 10)
        self.assertTrue(all(len(entry["source_row_ids"]) <= 2 for entry in expected["entries"]))

    def test_determinism_and_non_destructive_idempotent_output(self):
        spec, raw = fixture()
        bundle = public_spend.build_bundle(spec, raw)
        self.assertEqual(bundle, public_spend.build_bundle(spec, raw))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "prepared"
            public_spend.write_bundle(output, bundle)
            public_spend.write_bundle(output, bundle)
            altered = {**bundle, "legacy.csv": b"changed"}
            with self.assertRaisesRegex(public_spend.DataError, "refusing to overwrite"):
                public_spend.write_bundle(output, altered)
            self.assertEqual((output / "legacy.csv").read_bytes(), bundle["legacy.csv"])

    def test_receipt_binds_every_generated_file_and_original_source(self):
        spec, raw = fixture()
        bundle = public_spend.build_bundle(spec, raw)
        receipt = json.loads(bundle["receipt.json"])
        self.assertEqual(set(receipt["files"]), set(bundle) - {"receipt.json"})
        for name, binding in receipt["files"].items():
            self.assertEqual(binding["sha256"], public_spend.sha256(bundle[name]))
            self.assertEqual(binding["bytes"], len(bundle[name]))
        self.assertIn("not the publisher's", receipt["model_boundary"])


if __name__ == "__main__":
    unittest.main()
