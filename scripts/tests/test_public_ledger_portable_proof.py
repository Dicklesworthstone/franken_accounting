"""Portable selection and source-control contracts using a real public bundle.

The committed university bundle was produced by an actual native replay. These
tests inspect its framing and compare its output with an independent Decimal
fold of the original CSV. They do not execute fa-verify and do not establish a
new native or cryptographic PASS. Synthetic metadata below is protocol-test
input, never an authenticated report.
"""

from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import base64
import csv
import datetime as dt
from decimal import Decimal
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import public_ledger_portable_proof as portable


def nonzero(cells):
    return {key: amount for key, amount in cells.items() if amount}


class PortableSelectionTests(unittest.TestCase):
    @staticmethod
    def row(dimension, code):
        return {
            dimension: code, "period": "FY2024-P12",
            "certificate_oid": hashlib.sha256(f"protocol fixture:{dimension}:{code}".encode()).hexdigest(),
            "account_nets": {"101000": 100},
            "gross_cents": {"101000:debit": 150, "101000:credit": 50},
        }

    def report(self, dimension="project", codes=("007", "7", "Alpha", "alpha")):
        return {
            "dimension_certificates": {dimension: [self.row(dimension, code) for code in codes]},
            "dimension_value_counts": {dimension: len(codes)},
        }

    def test_canonical_bound_and_unbound_modes_inherit_and_accept_only_matching_requests(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                retained = {"bind_source": True} if enabled else {}
                report = {"bind_source": enabled}
                for requested in (None, enabled):
                    self.assertEqual(portable.source_binding_mode(report, retained, requested),
                                     (enabled, "canonical_recovery_pins"))
                with self.assertRaisesRegex(ValueError, "differs from the completed replay"):
                    portable.source_binding_mode(report, retained, not enabled)

    def test_binding_contract_contradictions_and_noncanonical_pins_refuse(self):
        for report, retained in (
            ({"bind_source": True}, {}), ({"bind_source": False}, {"bind_source": True}),
            ({}, {"bind_source": True}), ({"bind_source": 1}, {"bind_source": True}),
            ({"bind_source": "true"}, {"bind_source": True}),
            ({"bind_source": False}, {"bind_source": False}),
            ({"bind_source": True}, {"bind_source": 1}),
        ):
            with self.subTest(report=report, retained=retained):
                with self.assertRaises(ValueError):
                    portable.source_binding_mode(report, retained, None)

    def test_legacy_companion_binding_requires_explicit_selection_without_rewriting_metadata(self):
        report, retained = {}, {"format": "fa-public-ledger-recovery-v1"}
        self.assertEqual(portable.source_binding_mode(report, retained, True),
                         (True, "legacy_explicit_selection"))
        self.assertEqual(portable.source_binding_mode(report, retained, False),
                         (False, "legacy_explicit_selection"))
        self.assertEqual(portable.source_binding_mode(report, retained, None),
                         (False, "legacy_unbound_default"))
        self.assertEqual(report, {})
        self.assertEqual(retained, {"format": "fa-public-ledger-recovery-v1"})

    def test_exact_dimension_selection_preserves_leading_zeroes_and_case(self):
        report = self.report()
        self.assertEqual(portable.select_dimension_report(report, "project", None)["project"], "007")
        for code in ("007", "7", "Alpha", "alpha"):
            with self.subTest(code=code):
                selected = portable.select_dimension_report(report, "project", code)
                self.assertEqual(selected["project"], code)
                self.assertEqual(selected["certificate_oid"], self.row("project", code)["certificate_oid"])
        for code in ("07", "ALPHA", " Alpha", "alpha ", 7):
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    portable.select_dimension_report(report, "project", code)

    def test_empty_or_missing_project_population_never_falls_back_to_department(self):
        report = self.report("department", ("1000001",))
        for present in (False, True):
            with self.subTest(present=present):
                if present:
                    report["dimension_certificates"]["project"] = []
                    report["dimension_value_counts"]["project"] = 0
                with self.assertRaisesRegex(ValueError, "no retained project reports"):
                    portable.select_dimension_report(report, "project", None)
        with self.assertRaisesRegex(ValueError, "unsupported source dimension"):
            portable.select_dimension_report(report, "imagined_dimension", None)

    def test_duplicate_codes_and_incorrect_or_boolean_population_counts_refuse(self):
        for change in ("duplicate", "missing_count", "wrong_count", "boolean_count"):
            with self.subTest(change=change):
                report = self.report("fund", ("01000", "02000"))
                if change == "duplicate":
                    report["dimension_certificates"]["fund"][1]["fund"] = "01000"
                elif change == "missing_count":
                    report["dimension_value_counts"].pop("fund")
                else:
                    report["dimension_value_counts"]["fund"] = True if change == "boolean_count" else 1
                with self.assertRaises(ValueError):
                    portable.select_dimension_report(report, "fund", None)

    def test_malformed_retained_report_metadata_refuses_before_a_certificate_is_selected(self):
        for change in ("nonobject", "blank_code", "padded_code", "numeric_code", "certificate",
                       "uppercase_certificate", "period", "float_net", "boolean_net", "negative_gross"):
            with self.subTest(change=change):
                report = self.report("fund", ("01000",))
                row = report["dimension_certificates"]["fund"][0]
                if change == "nonobject":
                    report["dimension_certificates"]["fund"][0] = []
                elif change in ("blank_code", "padded_code", "numeric_code"):
                    row["fund"] = {"blank_code": "", "padded_code": " 01000", "numeric_code": 1000}[change]
                elif change in ("certificate", "uppercase_certificate"):
                    row["certificate_oid"] = "invalid" if change == "certificate" else "A" * 64
                elif change == "period":
                    row["period"] = "FY24-P12"
                elif change == "negative_gross":
                    row["gross_cents"]["101000:debit"] = -1
                else:
                    row["account_nets"]["101000"] = 1.5 if change == "float_net" else True
                with self.assertRaises(ValueError):
                    portable.select_dimension_report(report, "fund", None)


class OriginalBookAdmissionTests(unittest.TestCase):
    """No native command is run by these identity-admission regressions."""

    def setUp(self):
        self.original = {"book_id": "a" * 32, "base_unit": "USD", "calendar": "fiscal", "entities": []}
        self.report = {"recovery": {"book_id": self.original["book_id"], "attempt": "attempts/000002"}}

    def test_original_book_identity_matches_the_report_and_exact_native_scope(self):
        actual = {**self.original, "head": 300, "name": "a descriptive label"}
        self.assertEqual(portable.original_book_identity(self.original, self.report, native=actual), self.original)
        for field, value in (("book_id", "b" * 32), ("base_unit", "EUR"),
                             ("calendar", "a-different-calendar"), ("entities", ["foreign"])):
            with self.subTest(field=field):
                changed = {**actual, field: value}
                with self.assertRaisesRegex(ValueError, "original recovery book"):
                    portable.original_book_identity(self.original, self.report, native=changed)
        changed_report = {"recovery": {"book_id": "b" * 32}}
        with self.assertRaisesRegex(ValueError, "completed report book identity differs"):
            portable.original_book_identity(self.original, changed_report)

    def test_incomplete_or_noncanonical_original_book_facts_refuse(self):
        cases = [
            {key: value for key, value in self.original.items() if key != "calendar"},
            {**self.original, "unexpected": True}, {**self.original, "book_id": "A" * 32},
            {**self.original, "base_unit": "EUR"}, {**self.original, "entities": ["foreign"]},
            {**self.original, "calendar": None}, {**self.original, "calendar": " fiscal"},
        ]
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    portable.original_book_identity(changed, self.report)

    def test_changed_completion_report_cannot_adopt_another_book_before_any_native_command(self):
        def fact(value):
            canonical = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
            return json.dumps({"sha256": hashlib.sha256(canonical).hexdigest(), "value": value})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, output = root / "run", root / "proof"
            (run / "recovery").mkdir(parents=True)
            (run / "report.json").write_text(json.dumps({"status": "PASS", "recovery": {"book_id": "b" * 32}}))
            (run / "recovery/pins.json").write_text(fact({"format": "fa-public-ledger-recovery-v1"}))
            (run / "recovery/book.json").write_text(fact(self.original))
            before = {path.relative_to(run): path.read_bytes() for path in run.rglob("*") if path.is_file()}
            with mock.patch.object(portable.subprocess, "run") as execute, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
                result = portable.main(["--run", str(run), "--out", str(output),
                                        "--fa", "/unobserved-fa", "--fa-verify", "/unobserved-verifier"])
            self.assertEqual(result, 1)
            self.assertIn("completed report book identity differs", errors.getvalue())
            execute.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual({path.relative_to(run): path.read_bytes()
                              for path in run.rglob("*") if path.is_file()}, before)


class PinnedUniversityProofParsingTests(unittest.TestCase):
    """Actual committed wire and independent source arithmetic; no verifier run."""

    @classmethod
    def setUpClass(cls):
        example = ROOT / "examples/public_ledger/university_source_bound"
        cls.public = json.loads((example / "manifest.json").read_text())
        packed = (example / "report.fab.gz").read_bytes()
        specification = next(value for value in cls.public["files"] if value["name"] == "report.fab")
        assert hashlib.sha256(packed).hexdigest() == specification["gzip_sha256"]
        cls.bundle = gzip.decompress(packed)
        assert len(cls.bundle) == specification["bytes"]
        assert hashlib.sha256(cls.bundle).hexdigest() == specification["sha256"]
        raw = (ROOT / "crates/fa-oracles/fixtures/public_ledger/omes-fy2024-q4-66000.csv").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == cls.public["source"]["fixture_sha256"]
        rows = list(csv.DictReader(io.StringIO(raw.decode("cp1252"), newline="")))
        assert len(rows) == 1055
        cls.periods = ("FY2024-P10", "FY2024-P11", "FY2024-P12")
        activity = {period: {} for period in cls.periods}
        departments, monetary_rows = set(), 0
        for row in rows:
            assert row["BUSINESS_UNIT"] == "66000" and row["LEDGER"] == "ACTUALS"
            assert row["FISCAL_YEAR"] == "2024"
            period = f"FY2024-P{int(row['ACCOUNTING_PERIOD']):02}"
            assert period in activity
            amount = Decimal(row["SUM(L.POSTED_TOTAL_AMT)"]) * Decimal(100)
            assert amount.is_finite() and amount == amount.to_integral_value()
            cents = int(amount)
            monetary_rows += cents != 0
            code, account = row["DEPTID"].strip(), row["ACCOUNT"]
            if code:
                departments.add(code)
            cells = activity[period].setdefault(code, {"account_nets": {}, "gross_cents": {}})
            cells["account_nets"][account] = cells["account_nets"].get(account, 0) + cents
            if cents:
                key = account + (":debit" if cents > 0 else ":credit")
                cells["gross_cents"][key] = cells["gross_cents"].get(key, 0) + abs(cents)
        assert monetary_rows == 1051
        cls.manifest = {
            "format": "fa-public-ledger-replay-v1", "agency": "66000",
            "source_sha256": cls.public["source"]["statewide_csv_sha256"],
            "source_rows": len(rows), "monetary_rows": monetary_rows,
            "dimensions": {"department": [{"code": code} for code in sorted(departments)]},
            "dimension_activity": {"department": activity},
        }
        cls.report = {key: cls.manifest[key] for key in ("agency", "source_sha256", "source_rows", "monetary_rows")}
        cls.selected = {"department": "1000001", "period": "FY2024-P12",
                        "certificate_oid": cls.public["expected_certificate"]}
        for name in ("account_nets", "gross_cents"):
            total = defaultdict(int)
            for period in cls.periods:
                for key, amount in activity[period].get("1000001", {}).get(name, {}).items():
                    total[key] += amount
            cls.selected[name] = dict(total)
        cls.closure = portable.inspect(cls.bundle, source_bound=True, require_fragments=True)
        # Locate the actual canonical output blob without reusing Reader or
        # reconstructing a producer-shaped fixture. The short output-format
        # label is a different blob; only the actual report has a longer body.
        domain = b"fa:dimension-trial-balance:v1"
        candidates = []
        offset = cls.bundle.find(domain)
        while offset >= 0:
            if offset >= 4:
                size = struct.unpack_from("<I", cls.bundle, offset - 4)[0]
                if len(domain) < size <= len(cls.bundle) - offset:
                    candidates.append(cls.bundle[offset:offset + size])
            offset = cls.bundle.find(domain, offset + len(domain))
        assert len(candidates) == 1
        cls.output = candidates[0]

    def test_actual_university_bundle_cells_match_independent_decimal_source_fold(self):
        closure = self.closure
        self.assertEqual(closure["certificate_digest"], self.public["expected_certificate"])
        self.assertEqual(closure["dimension"], "department")
        self.assertEqual(closure["dimension_value"], "1000001")
        self.assertEqual(closure["known_at"], 270)
        self.assertEqual(closure["native_input_count"], 12)
        self.assertEqual(closure["migration_run_bodies"], 9)
        self.assertEqual(closure["migration_source_witnesses"], 9)
        self.assertEqual(closure["additive_input_labels"], [
            "MigrationRunFragment", "MigrationSource", "MigrationSourceFragment", "EntryFragment",
        ])
        decoded = portable.inspect_output(self.output)
        self.assertEqual(decoded, closure["output"])
        for name in ("account_nets", "gross_cents"):
            self.assertEqual(nonzero(decoded[name]), nonzero(self.selected[name]))
        selected = portable.original_source_control(self.manifest, self.report, self.selected, "department")
        self.assertIsNot(selected, self.selected)
        result = portable.reconcile_source_output(closure, selected, "department")
        self.assertEqual(result["status"], "PASS")  # Arithmetic comparison only.
        self.assertEqual(result["effective_through"], "2024-06-30")
        self.assertEqual(result["nonzero_cells_compared"], {
            name: len(nonzero(self.selected[name])) for name in ("account_nets", "gross_cents")
        })

    def test_equal_debit_and_credit_increase_keeps_net_but_refuses_source_gross_comparison(self):
        altered = deepcopy(self.closure)
        code = next(iter(altered["output"]["account_nets"]))
        for side in ("debit", "credit"):
            key = f"{code}:{side}"
            altered["output"]["gross_cents"][key] = altered["output"]["gross_cents"].get(key, 0) + 1
        self.assertEqual(altered["output"]["account_nets"], self.closure["output"]["account_nets"])
        with self.assertRaisesRegex(ValueError, "gross_cents differ"):
            portable.reconcile_source_output(altered, self.selected, "department")

    def test_a_matching_period_label_and_cells_cannot_hide_the_wrong_non_null_cutoff(self):
        expected = (dt.date(2024, 6, 30) - dt.date(1970, 1, 1)).days
        self.assertEqual(self.closure["output"]["effective_through"], expected)
        for day in (expected - 1, expected + 1, 0, True):
            with self.subTest(day=day):
                altered = deepcopy(self.closure)
                altered["output"]["effective_through"] = day
                with self.assertRaisesRegex(ValueError, "stock selection differs"):
                    portable.reconcile_source_output(altered, self.selected, "department")

    def test_wrong_dimension_scope_period_snapshot_or_activity_selection_refuses(self):
        for change in ("dimension", "code", "multiple_values", "outer_period", "inner_period",
                       "outer_snapshot", "inner_snapshot", "activity", "no_effective_date", "net"):
            with self.subTest(change=change):
                altered = deepcopy(self.closure)
                output = altered["output"]
                if change == "dimension":
                    altered["dimension"] = "fund"
                elif change == "code":
                    output["value"] = "01000001"
                elif change == "multiple_values":
                    output["values"].append("7999999")
                elif change in ("outer_period", "inner_period"):
                    (altered if change == "outer_period" else output)["selected" if change == "outer_period" else "periods"] = ["FY2024-P11"]
                elif change in ("outer_snapshot", "inner_snapshot"):
                    (altered if change == "outer_snapshot" else output)["known_at"] += 1
                elif change == "activity":
                    output["activity"] = True
                elif change == "no_effective_date":
                    output["effective_through"] = None
                else:
                    code = next(iter(output["account_nets"]))
                    output["account_nets"][code] += 1
                with self.assertRaises(ValueError):
                    portable.reconcile_source_output(altered, self.selected, "department")

    def test_real_bundle_and_output_truncation_and_trailing_framing_refuse(self):
        for value, decode in (
            (self.bundle, lambda wire: portable.inspect(wire, source_bound=True, require_fragments=True)),
            (self.output, portable.inspect_output),
        ):
            for position in (0, 1, 4, 24, len(value) // 2, len(value) - 1):
                with self.subTest(bytes=len(value), truncated_at=position):
                    with self.assertRaises(ValueError):
                        decode(value[:position])
            with self.assertRaisesRegex(ValueError, "trailing framing"):
                decode(value + b"unexpected")
        with self.assertRaisesRegex(ValueError, "source profile differs"):
            portable.inspect(self.bundle, source_bound=False, require_fragments=True)

    def write_public_files(self, out):
        example = ROOT / "examples/public_ledger/university_source_bound"
        for name in portable.PUBLIC_FILES:
            raw = gzip.decompress((example / f"{name}.gz").read_bytes())
            specification = next(item for item in self.public["files"] if item["name"] == name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), specification["sha256"])
            (out / name).write_bytes(raw)

    def test_proof_snapshot_refuses_changes_to_each_submitted_public_artifact(self):
        # This exercises the byte-stability guard only, without a mock or real
        # verifier verdict. Native acceptance remains the separate CLI step.
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.write_public_files(out)
            submitted = portable.proof_file_snapshot(out)
            self.assertEqual(portable.proof_file_snapshot(out, expected=submitted), submitted)
            for name in portable.PUBLIC_FILES:
                with self.subTest(name=name):
                    path = out / name
                    original = path.read_bytes()
                    changed = original[:-1] + bytes([original[-1] ^ 1])
                    self.assertEqual(len(changed), len(original))
                    path.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError, "bytes submitted for native verification"):
                        portable.proof_file_snapshot(out, expected=submitted)
                    with self.assertRaisesRegex(ValueError, "native-verified proof files"):
                        portable.public_example(out, self.public["trusted_fixture_public_key"],
                                                self.public["expected_certificate"], True,
                                                verified_files=submitted)
                    path.write_bytes(original)
            self.assertEqual(portable.proof_file_snapshot(out, expected=submitted), submitted)

    def test_public_emission_compresses_exactly_the_submitted_proof_bytes_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.write_public_files(out)
            submitted = portable.proof_file_snapshot(out)
            manifest, encoded = portable.public_example(
                out, self.public["trusted_fixture_public_key"], self.public["expected_certificate"], True,
                verified_files=submitted,
            )
            self.assertEqual(manifest["status"], "READY")
            self.assertEqual({name for name, _ in encoded}, set(portable.PUBLIC_FILES))
            for item in manifest["files"]:
                packed = base64.b64decode(dict(encoded)[item["name"]], validate=True)
                raw = gzip.decompress(packed)
                self.assertEqual({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                                 submitted[item["name"]])
                self.assertEqual(item["bytes"], submitted[item["name"]]["bytes"])
                self.assertEqual(item["sha256"], submitted[item["name"]]["sha256"])
                self.assertEqual(item["gzip_sha256"], hashlib.sha256(packed).hexdigest())
            self.assertEqual(portable.proof_file_snapshot(out, expected=submitted), submitted)

    def test_mutable_report_cells_cannot_replace_pinned_original_source_controls(self):
        for change in ("net", "same_net_gross"):
            with self.subTest(change=change):
                selected = deepcopy(self.selected)
                code = next(iter(selected["account_nets"]))
                if change == "net":
                    selected["account_nets"][code] += 1
                else:
                    for side in ("debit", "credit"):
                        key = f"{code}:{side}"
                        selected["gross_cents"][key] = selected["gross_cents"].get(key, 0) + 1
                with self.assertRaisesRegex(ValueError, "pinned original-source controls"):
                    portable.original_source_control(self.manifest, self.report, selected, "department")

    def test_source_profile_identity_period_coverage_and_unique_value_are_required(self):
        for change in ("format", "agency", "source_sha256", "source_rows", "monetary_rows",
                       "missing_period", "extra_period", "missing_value", "duplicate_value", "bad_period"):
            with self.subTest(change=change):
                manifest, report, selected = deepcopy(self.manifest), deepcopy(self.report), deepcopy(self.selected)
                if change == "format":
                    manifest["format"] = "unknown"
                elif change in ("agency", "source_sha256", "source_rows", "monetary_rows"):
                    report[change] = "foreign" if isinstance(report[change], str) else report[change] + 1
                elif change == "missing_period":
                    manifest["dimension_activity"]["department"].pop("FY2024-P10")
                elif change == "extra_period":
                    manifest["dimension_activity"]["department"]["FY2024-P09"] = {}
                elif change == "missing_value":
                    manifest["dimensions"]["department"] = []
                elif change == "duplicate_value":
                    manifest["dimensions"]["department"].append({"code": "1000001"})
                else:
                    selected["period"] = "FY2024-P09"
                with self.assertRaises(ValueError):
                    portable.original_source_control(manifest, report, selected, "department")

    def test_original_source_control_sums_only_through_the_selected_period(self):
        selected = deepcopy(self.selected)
        selected["period"] = "FY2024-P10"
        april = self.manifest["dimension_activity"]["department"]["FY2024-P10"]["1000001"]
        selected.update(deepcopy(april))
        observed = portable.original_source_control(self.manifest, self.report, selected, "department")
        self.assertEqual(observed["account_nets"], april["account_nets"])
        self.assertEqual(observed["gross_cents"], april["gross_cents"])
        self.assertNotEqual(nonzero(observed["gross_cents"]), nonzero(self.selected["gross_cents"]))


if __name__ == "__main__":
    unittest.main()
