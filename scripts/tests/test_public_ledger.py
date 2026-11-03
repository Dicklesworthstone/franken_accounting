"""Offline reconciliation against authentic, pinned OMES agency extracts.

Decimal is deliberately used only in this independent test oracle. Production
normalization uses integer parsing, so their arithmetic implementations differ.
"""

from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import csv
from decimal import Decimal, localcontext
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import public_ledger as replay
import public_ledger_source as source


PINNED = {
    "20400": {
        "sha256": "020b4591235d3aa6fdaed89924b6c7bd59792ca49b528df11ee4c54bca900341",
        "rows": 125, "accounts": 43, "zero_rows": 4,
        "positive_cents": {"10": 7025554, "11": 8910103, "12": 10143723},
    },
    "31500": {
        "sha256": "2d60b56cd29ef0e426054cd6107962286b2ad92b1633d29d91bb32a139cd4249",
        "rows": 137, "accounts": 51, "zero_rows": 6,
        "positive_cents": {"10": 8101289584, "11": 11732456136, "12": 6432209691},
    },
    "66000": {
        "sha256": "d8a7eb93c8e45f5a190d96d9bb07bed0230a2db994f4881474e33f26701cb537",
        "rows": 1055, "accounts": 223, "zero_rows": 4,
        "positive_cents": {"10": 1894043633, "11": 2720307270, "12": 1994217923},
    },
}
DATES = {"10": "2024-04-30", "11": "2024-05-31", "12": "2024-06-30"}


def cents(text):
    with localcontext() as context:
        context.prec = 100
        result = Decimal(text) * 100
        if result != result.to_integral_exact():
            raise AssertionError(f"test oracle encountered noncent amount {text!r}")
        return int(result)


def read_csv(path, encoding):
    with path.open(encoding=encoding, newline="") as stream:
        return list(csv.DictReader(stream, strict=True))


def native_package(case, run):
    """Native-shaped proposal output built from the original CSV, not mapping.

    This deliberately uses Decimal for the amounts and original record order.
    It is an offline assertion fixture, not a replacement for running fa.
    """
    chunks = []
    for index, entry_id in enumerate(run["entry_ids"]):
        _, agency, year, period, ledger, fund, funding = entry_id.split(":")
        selected = [row for row in case["originals"] if (
            row["BUSINESS_UNIT"], row["FISCAL_YEAR"], row["ACCOUNTING_PERIOD"],
            row["LEDGER"], row["FUND_CODE"], row["CLASS_FLD"],
        ) == (agency, year, period, ledger, fund, funding)
            and cents(row[source.AMOUNT_COLUMN]) != 0]
        legs = []
        for ordinal, row in enumerate(selected):
            amount = Decimal(row[source.AMOUNT_COLUMN])
            legs.append({"index": ordinal, "account": row["ACCOUNT"],
                         "side": "credit" if amount.is_signed() else "debit",
                         "amount": f"{abs(amount):.2f} USD"})
        chunks.append({"index": index, "effective_date": DATES[period],
                       "document_date": DATES[period],
                       "effective_period": f"FY{year}-P{int(period):02}",
                       "counts_after_finalize": True, "leg_count": len(legs),
                       "legs": legs})
    return {"row_count": sum(len(chunk["legs"]) for chunk in chunks),
            "chunk_count": len(chunks), "chunks": chunks}


class PinnedAgencyNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = {}
        for agency in PINNED:
            fixture = replay.FIXTURES / f"omes-fy2024-q4-{agency}.csv"
            provenance = json.loads(fixture.with_suffix(".json").read_text(encoding="utf-8"))
            out = Path(cls.directory.name) / agency
            manifest = replay.normalize(fixture, agency, out)
            originals = read_csv(fixture, "cp1252")
            source_rows = {
                position["record_index"]: row
                for position, row in zip(provenance["source_records"], originals, strict=True)
            }
            normalized = [
                (run, row)
                for run in manifest["runs"]
                for row in read_csv(out / run["source"], "utf-8")
            ]
            cls.cases[agency] = {
                "fixture": fixture, "provenance": provenance, "out": out,
                "manifest": manifest, "originals": originals,
                "source_rows": source_rows, "normalized": normalized,
            }

    def test_original_byte_extracts_match_independently_pinned_distribution_slices(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                raw = case["fixture"].read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), PINNED[agency]["sha256"])
                self.assertEqual(raw, (case["out"] / "original-agency.csv").read_bytes())
                self.assertEqual(case["provenance"]["subset_sha256"], PINNED[agency]["sha256"])
                self.assertEqual(case["provenance"]["source_sha256"], source.SOURCE_SHA256)
                self.assertEqual(case["manifest"]["original_selection_sha256"], PINNED[agency]["sha256"])
                self.assertEqual(len(raw), case["provenance"]["subset_bytes"])
                self.assertEqual(len(case["originals"]), PINNED[agency]["rows"])

    def test_every_original_record_is_accounted_for_once_including_zeros(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                manifest, original = case["manifest"], case["source_rows"]
                mapped = [row["source_record"] for row in manifest["row_mapping"]]
                expected_zeros = sorted(n for n, r in original.items() if cents(r[source.AMOUNT_COLUMN]) == 0)
                self.assertEqual(len(set(mapped)), len(mapped))
                self.assertEqual(manifest["zero_rows"], expected_zeros)
                self.assertEqual(len(expected_zeros), PINNED[agency]["zero_rows"])
                self.assertFalse(set(mapped) & set(expected_zeros))
                self.assertEqual(set(mapped) | set(expected_zeros), set(original))
                self.assertEqual(manifest["source_rows"], PINNED[agency]["rows"])
                self.assertEqual(manifest["monetary_rows"], PINNED[agency]["rows"] - PINNED[agency]["zero_rows"])
                normalized_ordinals = [int(row["source_record"]) for _, row in case["normalized"]]
                self.assertEqual(sorted(normalized_ordinals), sorted(mapped))

    def test_each_normalized_leg_preserves_original_account_sign_amount_and_all_fields(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                expected_columns = {f"original_{name}" for name in source.HEADERS}
                mapping = {row["source_record"]: row for row in case["manifest"]["row_mapping"]}
                for run, normalized in case["normalized"]:
                    ordinal = int(normalized["source_record"])
                    original = case["source_rows"][ordinal]
                    self.assertEqual({k for k in normalized if k.startswith("original_")}, expected_columns)
                    restored = {name: normalized[f"original_{name}"] for name in source.HEADERS}
                    self.assertEqual(restored, original, f"agency {agency}, source record {ordinal}")
                    expected = cents(original[source.AMOUNT_COLUMN])
                    self.assertNotEqual(expected, 0)
                    self.assertEqual(cents(normalized["signed_amount"]), expected)
                    self.assertEqual(normalized["account_code"], original["ACCOUNT"])
                    self.assertEqual(normalized["effective_date"], DATES[original["ACCOUNTING_PERIOD"]])
                    self.assertEqual(mapping[ordinal]["cents"], expected)
                    self.assertEqual(mapping[ordinal]["account"], original["ACCOUNT"])
                    self.assertEqual(mapping[ordinal]["entry_id"], normalized["entry_id"])
                    self.assertEqual(mapping[ordinal]["run"], run["name"])
                    expected_id = ":".join([
                        "OK", agency, original["FISCAL_YEAR"], original["ACCOUNTING_PERIOD"],
                        original["LEDGER"], original["FUND_CODE"], original["CLASS_FLD"],
                    ])
                    self.assertEqual(normalized["entry_id"], expected_id)

    def test_every_natural_group_balances_and_no_row_is_split_into_synthetic_legs(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                groups = defaultdict(list)
                for run, row in case["normalized"]:
                    groups[row["entry_id"]].append(row)
                for entry_id, rows in groups.items():
                    self.assertGreaterEqual(len(rows), 2, entry_id)
                    self.assertEqual(sum(cents(r["signed_amount"]) for r in rows), 0, entry_id)
                    matching = [r for r in case["manifest"]["row_mapping"] if r["entry_id"] == entry_id]
                    self.assertEqual([r["leg"] for r in matching], list(range(1, len(rows) + 1)))
                declared = [entry_id for run in case["manifest"]["runs"] for entry_id in run["entry_ids"]]
                self.assertEqual(sorted(declared), sorted(groups))
                for run in case["manifest"]["runs"]:
                    self.assertEqual(hashlib.sha256((case["out"] / run["source"]).read_bytes()).hexdigest(), run["sha256"])

    def test_period_gross_totals_equal_independent_pinned_source_observations(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                gross = defaultdict(lambda: {"positive": 0, "negative": 0})
                for _, row in case["normalized"]:
                    period = row["original_ACCOUNTING_PERIOD"]
                    amount = cents(row["signed_amount"])
                    gross[period]["positive" if amount > 0 else "negative"] += amount
                for observed in case["provenance"]["periods"]:
                    period = observed["period"]
                    expected = PINNED[agency]["positive_cents"][period]
                    self.assertEqual(gross[period]["positive"], expected)
                    self.assertEqual(gross[period]["negative"], -expected)
                    self.assertEqual(cents(observed["positive"]), expected)
                    self.assertEqual(cents(observed["negative"]), -expected)

    def test_each_account_period_oracle_matches_independent_provenance(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                expected = {p: {} for p in replay.PERIODS}
                for row in case["provenance"]["account_totals"]:
                    expected[f"FY2024-P{row['period']}"][row["account"]] = cents(row["net"])
                self.assertEqual(case["manifest"]["activity_cents"], expected)
                for run in case["manifest"]["runs"]:
                    actual = {p: defaultdict(int) for p in replay.PERIODS}
                    for current_run, row in case["normalized"]:
                        if current_run["name"] == run["name"]:
                            period = f"FY2024-P{row['original_ACCOUNTING_PERIOD']}"
                            actual[period][row["account_code"]] += cents(row["signed_amount"])
                    self.assertEqual(run["activity_cents"], {p: dict(v) for p, v in actual.items()})

    def test_gross_oracle_matches_decimal_fold_of_every_original_account_and_period(self):
        for agency, case in self.cases.items():
            with self.subTest(agency=agency):
                expected = {period: defaultdict(int) for period in replay.PERIODS}
                for row in case["originals"]:
                    value = cents(row[source.AMOUNT_COLUMN])
                    period = f"FY2024-P{row['ACCOUNTING_PERIOD']}"
                    side = "credit" if value < 0 else "debit"
                    expected[period][f"{row['ACCOUNT']}:{side}"] += abs(value)
                expected = {period: dict(cells) for period, cells in expected.items()}
                self.assertEqual(case["manifest"]["activity_gross_cents"], expected)
                rows = [{"fields": row} for row in case["originals"]]
                self.assertEqual(replay.gross_oracle(rows), expected)
                for period, cells in expected.items():
                    debit = sum(value for key, value in cells.items() if key.endswith(":debit"))
                    credit = sum(value for key, value in cells.items() if key.endswith(":credit"))
                    self.assertEqual(debit, PINNED[agency]["positive_cents"][period[-2:]])
                    self.assertEqual(credit, debit)

    def test_native_leg_assertion_accepts_exact_original_rows_for_every_complete_fixture(self):
        for agency, case in self.cases.items():
            for run in case["manifest"]["runs"]:
                with self.subTest(agency=agency, run=run["name"]):
                    replay.verify_prepared_legs(case["manifest"], run, native_package(case, run))

    def test_native_leg_assertion_rejects_same_account_opposing_mutations_that_preserve_net(self):
        case = self.cases["31500"]
        run = next(run for run in case["manifest"]["runs"] if run["key"][2] == "8315A")
        package = native_package(case, run)
        before = deepcopy(package)
        legs = package["chunks"][0]["legs"]
        debit = next(leg for leg in legs if leg["account"] == "101000" and leg["side"] == "debit")
        credit = next(leg for leg in legs if leg["account"] == "101000" and leg["side"] == "credit")
        for leg in (debit, credit):
            amount = Decimal(leg["amount"].removesuffix(" USD")) + Decimal("0.01")
            leg["amount"] = f"{amount:.2f} USD"

        def net_by_account(current):
            result = defaultdict(int)
            for chunk in current["chunks"]:
                for leg in chunk["legs"]:
                    amount = cents(leg["amount"].removesuffix(" USD"))
                    result[leg["account"]] += amount if leg["side"] == "debit" else -amount
            return dict(result)

        self.assertEqual(net_by_account(package), net_by_account(before))
        self.assertEqual(package["row_count"], before["row_count"])
        with self.assertRaisesRegex(replay.ReplayError, "differs from original source record"):
            replay.verify_prepared_legs(case["manifest"], run, package)

    def test_native_leg_assertion_rejects_substitution_drop_duplicate_and_reorder(self):
        case = self.cases["31500"]
        run = case["manifest"]["runs"][0]
        original = native_package(case, run)
        for mutation in ("account", "side", "drop", "duplicate", "swap"):
            with self.subTest(mutation=mutation):
                package = deepcopy(original)
                chunk = package["chunks"][0]
                legs = chunk["legs"]
                if mutation == "account":
                    legs[0]["account"] = next(leg["account"] for leg in legs
                                              if leg["account"] != legs[0]["account"])
                elif mutation == "side":
                    legs[0]["side"] = "credit" if legs[0]["side"] == "debit" else "debit"
                elif mutation == "drop":
                    legs.pop()
                    chunk["leg_count"] -= 1
                elif mutation == "duplicate":
                    legs[1] = deepcopy(legs[0])
                    legs[1]["index"] = 1
                else:
                    legs[0], legs[1] = legs[1], legs[0]
                    # Keep native indices consistent, so this actually tests
                    # original row order rather than an invalid index alone.
                    legs[0]["index"], legs[1]["index"] = 0, 1
                with self.assertRaises(replay.ReplayError):
                    replay.verify_prepared_legs(case["manifest"], run, package)

    def test_native_leg_assertion_rejects_wrong_scope_dates_and_counts(self):
        case = self.cases["31500"]
        run = case["manifest"]["runs"][0]
        original = native_package(case, run)
        changes = [
            ("effective_date", "2024-04-29"),
            ("document_date", "2024-04-29"),
            ("effective_period", "FY2024-P11"),
            ("counts_after_finalize", False),
            ("index", 1),
            ("leg_count", original["chunks"][0]["leg_count"] + 1),
        ]
        for field, changed in changes:
            with self.subTest(field=field):
                package = deepcopy(original)
                package["chunks"][0][field] = changed
                with self.assertRaises(replay.ReplayError):
                    replay.verify_prepared_legs(case["manifest"], run, package)
        for field in ("row_count", "chunk_count"):
            with self.subTest(field=field):
                package = deepcopy(original)
                package[field] += 1
                with self.assertRaises(replay.ReplayError):
                    replay.verify_prepared_legs(case["manifest"], run, package)
        package = deepcopy(original)
        package["chunks"].pop()
        with self.assertRaisesRegex(replay.ReplayError, "omitted a chunk"):
            replay.verify_prepared_legs(case["manifest"], run, package)

    def test_chartfields_remain_distinct_and_codes_are_not_numeric_coercions(self):
        case = self.cases["66000"]
        for column, expected_count in [("CLASS_FLD", 9), ("DEPTID", 9), ("PRODUCT", 10), ("CHARTFIELD1", 11)]:
            originals = {r[column] for r in case["originals"]}
            retained = {r[f"original_{column}"] for _, r in case["normalized"]}
            retained |= {case["source_rows"][i][column] for i in case["manifest"]["zero_rows"]}
            self.assertEqual(len(originals), expected_count)
            self.assertEqual(retained, originals)
        self.assertIn("8315A", {r["original_CLASS_FLD"] for _, r in self.cases["31500"]["normalized"]})
        for agency, case in self.cases.items():
            chart = json.loads((case["out"] / "chart.json").read_text())["accounts"]
            self.assertEqual(len(chart), PINNED[agency]["accounts"])
            self.assertEqual({r["code"] for r in chart}, {r["ACCOUNT"] for r in case["originals"]})
            self.assertTrue(all(isinstance(r["code"], str) and len(r["code"]) == 6 for r in chart))


class ReplayRefusalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_modified_source_and_self_supplied_manifest_cannot_replace_committed_pin(self):
        fixture = replay.FIXTURES / "omes-fy2024-q4-31500.csv"
        changed = self.root / fixture.name
        changed.write_bytes(fixture.read_bytes() + b"\r\n")
        # An attacker-provided adjacent sidecar claims the changed bytes are
        # authentic. input_provenance must consult the committed pin instead.
        adjacent = json.loads(fixture.with_suffix(".json").read_text())
        adjacent["subset_sha256"] = hashlib.sha256(changed.read_bytes()).hexdigest()
        adjacent["subset_bytes"] = changed.stat().st_size
        changed.with_suffix(".json").write_text(json.dumps(adjacent))
        output = self.root / "prepared"
        with self.assertRaisesRegex(replay.ReplayError, "SHA-256 differs"):
            replay.normalize(changed, "31500", output)
        self.assertFalse(output.exists())

    def test_wrong_agency_cannot_be_claimed_for_an_authentic_fixture(self):
        fixture = replay.FIXTURES / "omes-fy2024-q4-31500.csv"
        with self.assertRaises(replay.ReplayError):
            replay.normalize(fixture, "66000", self.root / "prepared")

    def test_existing_run_is_unchanged_on_prepare_or_run_refusal(self):
        output = self.root / "previous-success"
        output.mkdir()
        (output / "report.json").write_bytes(b'{"status":"PASS"}\n')
        (output / "retained-evidence.bin").write_bytes(b"the original proof bytes")
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        for action in ("prepare", "run"):
            argv = [action, "--agency", "31500", "--out", str(output)]
            if action == "run":
                argv += ["--fa", sys.executable, "--fa-verify", sys.executable]
            with self.subTest(action=action), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with mock.patch.object(replay, "run_native") as native:
                    self.assertNotEqual(replay.main(argv), 0)
                    native.assert_not_called()
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)

    def test_amount_comparison_rejects_cent_change_missing_or_extraneous_nonzero_cell(self):
        expected = {"101000": 123456, "431000": -123456}
        replay.same_cells(dict(expected), expected, "unchanged")
        for actual in [
            {"101000": 123457, "431000": -123456},
            {"101000": 123456},
            {**expected, "999999": 1},
            {"101000": 123455, "431000": -123455},
        ]:
            with self.subTest(actual=actual), self.assertRaisesRegex(replay.ReplayError, "account-cell mismatch"):
                replay.same_cells(actual, expected, "mutated")
        # Zero suppression in a sparse native TB is not a monetary difference.
        replay.same_cells({**expected, "511000": 0}, expected, "sparse zeros")

    def test_native_tb_gross_assertion_catches_canceling_changes_hidden_by_net(self):
        native = object.__new__(replay.Native)
        expected_gross = {"101000:debit": 10000, "101000:credit": 10000}
        row = {"code": "101000", "debits": "100.00 USD", "credits": "100.00 USD", "net": "0.00 USD"}
        with mock.patch.object(native, "call", return_value={"data": {"rows": [row]}}):
            self.assertEqual(native.tb("FY2024-P10", expected_gross=expected_gross), {"101000": 0})
        row.update(debits="100.01 USD", credits="100.01 USD")
        with mock.patch.object(native, "call", return_value={"data": {"rows": [row]}}):
            # An unchanged net cannot hide a change in either gross side.
            self.assertEqual(native.tb("FY2024-P10"), {"101000": 0})
            with self.assertRaisesRegex(replay.ReplayError, "gross debit/credit activity"):
                native.tb("FY2024-P10", expected_gross=expected_gross)

    def test_native_document_preserves_automated_custody_and_binds_its_fixture_review(self):
        native = replay.Native(Path(sys.executable), Path(sys.executable), self.root)
        oid = "ab" * 32
        added = {"oid": oid, "grade": "AgentUpload", "self_sourced": True,
                 "doc_commit": "cd" * 32, "recorded_at": 1}
        reviewed = {"claim": "Reviewed", "subject": oid,
                    "attestation_vid": "ef" * 16, "recorded_at": 2}
        with mock.patch.object(native, "call", side_effect=[{"data": added}, {"data": reviewed}]) as call:
            self.assertEqual(native.document(self.root / "source.csv"), oid)
            self.assertNotIn("--grade", call.call_args_list[0].args)
            self.assertEqual(call.call_args_list[1].args, (
                "document", "attest", "review", "--document", oid,
                "--as", "public-data-fixture-document-reviewer", "--grant", "approve",
            ))
        self.assertEqual(native.document_custody[0]["intake_grade"], "AgentUpload")
        self.assertEqual(native.document_custody[0]["review_attestation_vid"], reviewed["attestation_vid"])
        for grade, self_sourced in [("HumanUpload", False), ("AgentUpload", False)]:
            with self.subTest(grade=grade, self_sourced=self_sourced):
                wrong = dict(added, grade=grade, self_sourced=self_sourced)
                with mock.patch.object(native, "call", return_value={"data": wrong}) as call:
                    with self.assertRaisesRegex(replay.ReplayError, "self-sourced AgentUpload"):
                        native.document(self.root / "source.csv")
                    self.assertEqual(call.call_count, 1)
        for wrong in [dict(reviewed, subject="00" * 32), dict(reviewed, claim="Confirmed")]:
            with mock.patch.object(native, "call", side_effect=[{"data": added}, {"data": wrong}]):
                with self.assertRaisesRegex(replay.ReplayError, "does not bind"):
                    native.document(self.root / "source.csv")
        self.assertEqual(len(native.document_custody), 1)

    def test_money_round_trip_above_binary_float_exact_integer_range(self):
        self.assertEqual(replay.money(2**53 + 1), "90071992547409.93")
        self.assertEqual(replay.money(-(2**53 + 1)), "-90071992547409.93")
        self.assertEqual(replay.money(0), "0.00")
        for value in [2**53 - 1, 2**53 + 1, 10**30 + 17, -(10**30 + 17)]:
            with self.subTest(value=value):
                self.assertEqual(cents(replay.money(value)), value)

    def test_period_assignment_and_other_sources_crosswalk_are_explicit(self):
        for period, date in DATES.items():
            self.assertEqual(replay.period_end(int(period)), date)
        for period in (0, 1, 9, 13):
            with self.subTest(period=period), self.assertRaises(replay.ReplayError):
                replay.period_end(period)
        self.assertEqual(replay.account_spec("631100", "Appropriated Transfers In")["type"], "Equity")
        with self.assertRaisesRegex(replay.ReplayError, "explicit classification"):
            replay.account_spec("633110", "Payroll Withholding")

    def test_ads_tamper_changes_one_cent_preserving_schema_other_fields_and_newlines(self):
        header = (
            "Journal_ID|Journal_Entry_Line_Number|Effective_Date|Recorded_Seq|Entry_Class|"
            "GL_Account_Number|Debit_Credit_Indicator|Amount|Transaction_Currency|Unit_Scale|"
            "JE_Header_Description|Migrated_From|Line_Description\r\n"
        )
        other_unit = "J-1|1|2024-04-30|42|7|101000|D|100.00|EUR|2|Other currency|source-1|untouched\n"
        original_fields = [
            "J-2", "1", "2024-04-30", "43", "7", "101000", "D",
            "90071992547409.93", "USD", "2", "A description – unchanged",
            "source-2", "escaped\\pseparator",
        ]
        path = self.root / "GL_Detail.txt"
        for ending in ("\r\n", "\n", ""):
            with self.subTest(ending=repr(ending)):
                raw = (header + other_unit + "|".join(original_fields) + ending).encode("utf-8")
                path.write_bytes(raw)
                mutation = replay.tamper_ads_amount(path)
                lines = path.read_bytes().decode("utf-8").splitlines(keepends=True)
                self.assertEqual(len(lines), 3)
                self.assertEqual(lines[0], header)
                self.assertEqual(lines[1], other_unit)
                fields = lines[2].rstrip("\r\n").split("|")
                self.assertEqual(len(fields), 13)
                self.assertEqual(fields[:7], original_fields[:7])
                self.assertEqual(fields[8:], original_fields[8:])
                self.assertEqual(fields[7], "90071992547409.94")
                self.assertEqual(lines[2], "|".join(fields) + ending)
                self.assertEqual(mutation, {
                    "line": 3, "old_amount": "90071992547409.93",
                    "new_amount": "90071992547409.94", "delta_cents": 1,
                })

    def test_ads_tamper_refuses_without_a_qualifying_row_and_preserves_bytes(self):
        path = self.root / "GL_Detail.txt"
        raw = b"header\r\nJ-1|1|2024-04-30|42|7|101000|D|100.00|EUR|2|Other|source|untouched\r\n"
        path.write_bytes(raw)
        with self.assertRaisesRegex(replay.ReplayError, "no USD-cent monetary row"):
            replay.tamper_ads_amount(path)
        self.assertEqual(path.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
