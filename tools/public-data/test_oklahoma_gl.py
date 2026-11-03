"""Offline source integrity, arithmetic and no-overwrite tests for Oklahoma intake."""
from __future__ import annotations

import copy
import csv
from decimal import Decimal
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("oklahoma_gl", HERE / "oklahoma_gl.py")
assert SPEC is not None and SPEC.loader is not None
gl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gl)


class OklahomaPublicDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = gl.DATA_DIR / "source.csv"
        cls.raw = cls.source.read_bytes()
        cls.index = gl.read_index()
        _, cls.selected = gl.collect(io.BytesIO(cls.raw), "fixture", cls.index)

    def scratch(self) -> Path:
        # Preserve test products for inspection; do not delete workspace data.
        return Path(tempfile.mkdtemp(prefix="fa-oklahoma-test-"))

    def test_complete_source_population_and_literal_monetary_controls(self):
        outputs = gl.artifacts(self.source)
        manifest = json.loads(outputs["manifest.json"])
        self.assertEqual(manifest["selection_rows"], 312)
        self.assertEqual(manifest["normalized_legs"], 306)
        self.assertEqual(manifest["zero_rows_retained"], 6)
        self.assertEqual(manifest["reconstructed_entries"], 104)
        self.assertEqual(manifest["source_rows"], 373357)
        self.assertEqual(manifest["source_bytes"], 113856733)
        self.assertEqual(
            [p["debit_cents"] for p in manifest["period_totals"]],
            [2301421504, 780628575, 777711423],
        )
        self.assertEqual(
            [p["credit_cents"] for p in manifest["period_totals"]],
            [2301421504, 780628575, 777711423],
        )
        expected = [
            {"101000": "-8237688.62", "416101": "-7347513.21",
             "548110": "15666701.83", "548130": "-81500.00"},
            {"101000": "6890277.39", "416101": "-7348281.57",
             "548110": "421504.18", "548130": "36500.00"},
            {"101000": "6913177.99", "416101": "-7202457.66",
             "548110": "264279.67", "548130": "25000.00"},
        ]
        self.assertEqual([p["account_nets"] for p in manifest["period_totals"]], expected)
        self.assertEqual([p["rows"] for p in manifest["period_totals"]], [144, 86, 82])
        self.assertEqual([p["nonzero_rows"] for p in manifest["period_totals"]], [138, 86, 82])
        self.assertEqual([p["date"] for p in manifest["period_totals"]],
                         ["2024-04-30", "2024-05-31", "2024-06-30"])

    def test_independent_decimal_fold_matches_every_normalized_leg(self):
        source = csv.DictReader(io.StringIO(self.raw.decode("cp1252"), newline=""))
        expected = {}
        for row in source:
            key = (row["ACCOUNTING_PERIOD"], row["ACCOUNT"])
            expected[key] = expected.get(key, Decimal(0)) + Decimal(row["SUM(L.POSTED_TOTAL_AMT)"])
        outputs = gl.artifacts(self.source)
        normalized = csv.DictReader(io.StringIO(outputs["legacy.csv"].decode(), newline=""))
        observed = {}
        group_sums = {}
        for row in normalized:
            source_period = str(int(row["effective_date"][5:7]) + 6)
            key = (source_period, row["account"])
            amount = Decimal(row["amount"])
            self.assertNotEqual(amount, 0)
            observed[key] = observed.get(key, Decimal(0)) + amount
            group_sums[row["entry_id"]] = group_sums.get(row["entry_id"], Decimal(0)) + amount
        self.assertEqual(observed, expected)
        self.assertEqual(len(group_sums), 104)
        self.assertEqual(set(group_sums.values()), {Decimal(0)})

    def test_all_source_fields_zeros_and_original_row_identities_survive(self):
        outputs = gl.artifacts(self.source)
        self.assertEqual(outputs["source.csv"], self.raw)
        manifest = json.loads(outputs["manifest.json"])
        self.assertEqual(manifest["rows"], self.index)
        source_rows = list(csv.reader(io.StringIO(outputs["source.csv"].decode(), newline="")))
        self.assertEqual(len(source_rows), 313)
        self.assertTrue(all(len(row) == 36 for row in source_rows))
        normalized = list(csv.DictReader(io.StringIO(outputs["legacy.csv"].decode(), newline="")))
        valid_records = {
            str(item["position"]["source_record"])
            for item in self.selected if Decimal(item["fields"][gl.AMOUNT_COLUMN]) != 0
        }
        self.assertEqual({r["source_record"] for r in normalized}, valid_records)
        self.assertEqual(len(valid_records), len(normalized))
        for row in normalized:
            self.assertEqual(row["memo"], "source_record=" + row["source_record"])
        self.assertEqual(
            {item["fields"]["CLASS_FLD"] for item in self.selected},
            {r["entry_id"].split(":")[-1] for r in normalized},
        )

    def test_artifacts_are_deterministic_and_output_hashes_bind_content(self):
        first, second = gl.artifacts(self.source), gl.artifacts(self.source)
        self.assertEqual(first, second)
        manifest = json.loads(first["manifest.json"])
        for name, control in manifest["outputs"].items():
            self.assertEqual(hashlib.sha256(first[name]).hexdigest(), control["sha256"])
            self.assertEqual(len(first[name]), control["bytes"])

    def test_column_map_contains_only_the_native_column_declaration(self):
        # Account mappings belong to the native import intent. Embedding a
        # second table here causes native preparation to refuse before any
        # source rows or independently declared monetary controls are checked.
        outputs = gl.artifacts(self.source)
        declaration = tomllib.loads(outputs["column_map.toml"].decode("utf-8"))
        self.assertEqual(declaration, {"columns": {
            "source_system": gl.SOURCE_SYSTEM,
            "default_unit": "USD",
            "entry_id_column": "entry_id",
            "effective_date_column": "effective_date",
            "account_column": "account",
            "signed_amount_column": "amount",
            "unit_column": "currency",
            "description_column": "description",
            "memo_column": "memo",
        }})

    def test_tampered_source_fails_before_any_output_is_written(self):
        folder = self.scratch()
        source = folder / "tampered.csv"
        data = self.raw.replace(b"4157.4", b"4157.5", 1)
        self.assertNotEqual(data, self.raw)
        source.write_bytes(data)
        with self.assertRaisesRegex(gl.DataError, "SHA-256"):
            gl.prepare(source, folder / "output")
        self.assertFalse((folder / "output").exists())

    def test_source_schema_and_row_width_drift_are_refused(self):
        bad_header = self.raw.replace(b'"LEDGER"', b'"JOURNAL"', 1)
        with self.assertRaisesRegex(gl.DataError, "schema drift"):
            gl.collect(io.BytesIO(bad_header), "fixture", self.index)
        lines = self.raw.splitlines(keepends=True)
        lines[1] = lines[1].rstrip(b"\r\n") + b',"extra"\r\n'
        with self.assertRaisesRegex(gl.DataError, "expected 36 fields"):
            gl.collect(io.BytesIO(b"".join(lines)), "fixture", self.index)

    def test_missing_or_duplicate_source_records_cannot_be_accepted(self):
        lines = self.raw.splitlines(keepends=True)
        for data in (b"".join(lines[:-1]), b"".join(lines + [lines[-1]])):
            with self.assertRaises(gl.DataError):
                gl.collect(io.BytesIO(data), "fixture", self.index)

    def test_a_one_cent_change_is_unbalanced_without_a_plug(self):
        altered = copy.deepcopy(self.selected)
        altered[0]["fields"][gl.AMOUNT_COLUMN] = "4157.41"
        with self.assertRaisesRegex(gl.DataError, "unbalanced source group"):
            gl.analyze(altered)

    def test_balanced_groups_cannot_hide_fractional_cents(self):
        altered = copy.deepcopy(self.selected)
        altered[0]["fields"][gl.AMOUNT_COLUMN] = "4157.401"
        with self.assertRaisesRegex(gl.DataError, "fractional cents"):
            gl.analyze(altered)

    def test_duplicate_chartfield_scope_is_refused_even_with_different_amount(self):
        altered = copy.deepcopy(self.selected)
        extra = copy.deepcopy(altered[0])
        extra["fields"][gl.AMOUNT_COLUMN] = "0"
        altered.append(extra)
        with self.assertRaisesRegex(gl.DataError, "duplicate chartfield scope"):
            gl.analyze(altered)

    def test_scope_and_account_classification_are_explicit(self):
        for field, value, message in [
            ("BUSINESS_UNIT", "90001", "business unit"),
            ("LEDGER", "BUDGET", "ledger"),
            ("FUND_CODE", "1000", "fund"),
            ("FISCAL_YEAR", "2025", "scope"),
            ("ACCOUNTING_PERIOD", "13", "scope"),
            ("ACCOUNT", "999999", "unmapped"),
            ("ACCTDESCR", "Different cash", "renamed"),
        ]:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.selected)
                altered[0]["fields"][field] = value
                with self.assertRaisesRegex(gl.DataError, message):
                    gl.analyze(altered)

    def test_exact_parser_has_no_float_or_silent_rounding_path(self):
        for text, expected in [("4157.4", 415740), ("-0.01", -1),
                               ("120", 12000), ("0.000", 0),
                               ("123456789012345678901234567890.12", 12345678901234567890123456789012)]:
            self.assertEqual(gl.cents(text), expected)
        for text in ["1e2", "NaN", "Infinity", "1,000.00", " 1", "1.001", "9" * 64]:
            with self.subTest(amount=text), self.assertRaises(gl.DataError):
                gl.cents(text)

    def test_record_reads_are_bounded_and_encoding_is_not_lossy(self):
        class Bounded(io.BytesIO):
            def readline(self, size=-1):
                if size != gl.MAX_RECORD_BYTES + 1:
                    raise AssertionError("unbounded physical-line read")
                return super().readline(size)
        lines = gl.RawLines(Bounded(b"\x96\r\n"))
        self.assertEqual(next(lines), "\u2013\r\n")
        self.assertEqual(b"".join(lines.parts), b"\x96\r\n")
        with self.assertRaisesRegex(gl.DataError, "Windows-1252"):
            next(gl.RawLines(Bounded(b"\x81")))
        with self.assertRaisesRegex(gl.DataError, "budget"):
            next(gl.RawLines(Bounded(b"x" * (gl.MAX_RECORD_BYTES + 1))))

    def test_index_tampering_is_refused(self):
        folder = self.scratch()
        path = folder / "index.csv"
        path.write_bytes((gl.DATA_DIR / "source_rows.csv").read_bytes() + b"\n")
        with self.assertRaisesRegex(gl.DataError, "index SHA-256"):
            gl.read_index(path)

    def test_existing_outputs_are_never_overwritten(self):
        folder = self.scratch()
        output = folder / "existing"
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_text("preserve me")
        with self.assertRaisesRegex(gl.DataError, "already exists"):
            gl.prepare(self.source, output)
        self.assertEqual(sentinel.read_text(), "preserve me")
        with self.assertRaisesRegex(gl.DataError, "already exists"):
            gl.fetch(sentinel)
        self.assertEqual(sentinel.read_text(), "preserve me")

    def test_prepare_creates_a_complete_new_package(self):
        folder = self.scratch() / "prepared"
        manifest = gl.prepare(self.source, folder)
        self.assertEqual(manifest["normalized_legs"], 306)
        self.assertEqual({p.name for p in folder.iterdir()},
                         {"source.csv", "legacy.csv", "chart.json", "column_map.toml", "manifest.json"})
        # Native migrate import receives account_map separately in its intent;
        # a second mapping in column_map is refused even when it is identical.
        columns = tomllib.loads((folder / "column_map.toml").read_text(encoding="utf-8"))
        self.assertEqual(set(columns), {"columns"})
        self.assertEqual(columns["columns"], {
            "source_system": "oklahoma-omes-period-activity-v1",
            "default_unit": "USD",
            "entry_id_column": "entry_id",
            "effective_date_column": "effective_date",
            "account_column": "account",
            "signed_amount_column": "amount",
            "unit_column": "currency",
            "description_column": "description",
            "memo_column": "memo",
        })

    def test_network_redirect_policy_stays_on_public_https_source_hosts(self):
        redirect = gl.PublicRedirect()
        for url in ["http://data.ok.gov/file", "https://example.com/file",
                    "https://localhost/file", "file:///etc/passwd"]:
            with self.subTest(url=url), self.assertRaises(gl.DataError):
                redirect.redirect_request(None, None, 302, "", {}, url)


if __name__ == "__main__":
    unittest.main()
