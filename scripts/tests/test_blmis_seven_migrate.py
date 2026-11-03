"""Independent source oracles for the seven-account FullDetail migration.

Offline checks use retained Glantz B-2 and the three complete exact Magnify
accounts. Set FA_BLMIS_GLANTZ_PDF for the complete 393-observation population;
also set FA_BLMIS_MAGNIFY_PDF to exercise fresh extraction of both originals.
Native-shaped comparator fixtures below are test inputs, not native-run proof.
"""

from collections import Counter, defaultdict
from contextlib import redirect_stderr
from copy import deepcopy
import calendar
import csv
from datetime import date
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_migrate as migration
import blmis_magnify as magnify
import blmis_source as glantz


GLANTZ_ACCOUNTS = ("1T0026", "1ZA192", "1ZB010", "1ZB143")
MAGNIFY_ACCOUNTS = ("1FN025", "1FN097", "1FR051")
SELECTED_ACCOUNTS = set(GLANTZ_ACCOUNTS + MAGNIFY_ACCOUNTS)
EXCLUDED_ACCOUNTS = {"1ZR010", "1ZR176", "1FN024", "1FN037", "1FN073"}
STOP_ID = "SRC-BLM-001:1ZB010:p35:l39"
CHECK_ID = "SRC-BLM-001:1ZB010:p35:l38"
GLANTZ_SHA256 = "751a8a55bf02b022076af39c8637086630090b41164f70e2a04184c0d003dec1"
MAGNIFY_SHA256 = "25055acd72befe051e8939b528ebcf47be996edcbaa04c712efeb3ebb8dba8ec"
MAGNIFY_ROWS_SHA256 = "f10a7bc474512a0f4db4b457d4865a4ff7909053f28f24e3dfa023afb60cf697"
GLANTZ_PDF = os.environ.get("FA_BLMIS_GLANTZ_PDF")
MAGNIFY_PDF = os.environ.get("FA_BLMIS_MAGNIFY_PDF")


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, strict=True))


def literal_cents(literal):
    text = re.sub(r" \[[1-4]\]$", "", literal)
    if text == "-":
        return 0
    if not re.fullmatch(r"(?:\([0-9,]+\)|[0-9,]+)", text):
        raise AssertionError(f"not a printed numeric cell: {literal!r}")
    amount = Decimal(text.strip("()").replace(",", "")) * 100
    if amount != amount.to_integral_exact():
        raise AssertionError("source contains a fractional cent")
    return -int(amount) if text.startswith("(") else int(amount)


def movement(raw):
    withdrawal = raw["withdrawals_literal"]
    if withdrawal in ("*", "* [4]"):
        # Used only when diagnosing excluded 1FN037; no selected row has a star.
        assert raw["account"] == "1FN037" and raw["withdrawal_marker"] == "[4]"
        withdrawal_cents = 0
    else:
        withdrawal_cents = literal_cents(withdrawal)
    return withdrawal_cents + sum(literal_cents(raw[f"{field}_literal"])
                                  for field in ("deposits", "transfers_in", "transfers_out"))


def source_date(raw):
    month, day, year = map(int, raw["date_literal"].split("/"))
    return date(year, month, day).isoformat()


def money(cents):
    return f"{Decimal(cents) / 100:.2f}"


def ordered_raw(glantz_rows, magnify_rows, *, selected=True):
    """Independent named interpretation followed by a stable source/date merge."""
    original = list(glantz_rows)
    ids = [row["row_id"] for row in original]
    if STOP_ID in ids or CHECK_ID in ids:
        assert STOP_ID in ids and CHECK_ID in ids
        check, stop = ids.index(CHECK_ID), ids.index(STOP_ID)
        assert stop == check + 1
        assert original[check]["description"] == "CHECK"
        assert original[stop]["description"] == "STOP PAYMENT"
        assert source_date(original[check]) == source_date(original[stop]) == "2006-10-17"
        assert movement(original[check]) == -2_500_000 and movement(original[stop]) == 2_500_000
        original[check], original[stop] = original[stop], original[check]
    combined = original + list(magnify_rows)
    if selected:
        combined = [row for row in combined if row["account"] in SELECTED_ACCOUNTS]
    return sorted(combined, key=lambda row: (source_date(row), row["row_id"].split(":", 1)[0]))


def interpreted(raw_rows):
    """Supply comparator inputs from literals, without the production normalizer."""
    return [{**row, "date": source_date(row), "pdf_page": int(row["pdf_page"]),
             "source_line": int(row["source_line"]),
             "exhibit": row.get("exhibit", "B" if row["row_id"].startswith("SRC-BLM-006:") else "B-2"),
             "principal_movement_cents": movement(row),
             "printed_balance_cents": literal_cents(row["printed_balance_literal"])}
            for row in raw_rows]


def expected_citation(raw):
    source_id = raw["row_id"].split(":", 1)[0]
    exhibit = "B" if source_id == "SRC-BLM-006" else raw.get("exhibit", "B-2")
    return (f"constructed principal counterpart; {source_id} Exhibit {exhibit} "
            f"PDF p{raw['pdf_page']} line {raw['source_line']}")


def expected_normalized(raw_rows):
    result = []
    for raw in raw_rows:
        amount = movement(raw)
        if not amount:
            continue
        for account, signed in ((f"BLMIS-{raw['account']}", -amount),
                                ("BLMIS-MIGRATION-OFFSET", amount)):
            result.append({"entry_id": raw["row_id"], "effective_date": source_date(raw),
                           "account_code": account, "signed_amount": money(signed),
                           "description": raw["description"], "memo": expected_citation(raw),
                           "source_row": raw["row_id"]})
    return result


def expected_controls(raw_rows):
    """Read the last printed balance; never derive an expected control from legs."""
    accounts = sorted({row["account"] for row in raw_rows})
    first, last = min(map(source_date, raw_rows)), max(map(source_date, raw_rows))
    year, month = map(int, first[:7].split("-"))
    controls = []
    while year <= int(last[:4]):
        day = f"{year:04}-{month:02}-{calendar.monthrange(year, month)[1]:02}"
        cells, anchors = {}, []
        for account in accounts:
            prior = [row for row in raw_rows if row["account"] == account and source_date(row) <= day]
            if not prior:
                continue
            raw = prior[-1]
            value = literal_cents(raw["printed_balance_literal"])
            anchors.append({"account": account, "at_date": day, "source_row_id": raw["row_id"],
                            "source_date": source_date(raw), "printed_balance_cents": value})
            if value:
                cells[f"BLMIS-{account}"] = -value
        offset = -sum(cells.values())
        if offset:
            cells["BLMIS-MIGRATION-OFFSET"] = offset
        controls.append({"period": f"FY{year}-P{month:02}", "at_date": day,
                         "printed_anchors": anchors, "cells_cents": cells,
                         "lines": [{"account": account, "unit": "USD", "net": money(value)}
                                   for account, value in sorted(cells.items())]})
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    return controls


def folded_cells(raw_rows, at_date):
    cells = defaultdict(int)
    for raw in raw_rows:
        if source_date(raw) <= at_date:
            amount = movement(raw)
            cells[f"BLMIS-{raw['account']}"] -= amount
            cells["BLMIS-MIGRATION-OFFSET"] += amount
    return {account: amount for account, amount in cells.items() if amount}


def comparator_export(raw_rows):
    """Native-shaped export solely for fault injection into the comparator."""
    exported, identities, receipts = [], {}, {}
    for raw in raw_rows:
        amount = movement(raw)
        if not amount:
            continue
        index = len(identities) + 1
        vid, sequence = f"{index:032x}", 500 + index
        identities[raw["row_id"]] = vid
        receipts[vid] = {"entry_vid": vid, "recorded_at": sequence}
        for ordinal, (account, signed) in enumerate(((f"BLMIS-{raw['account']}", -amount),
                                                   ("BLMIS-MIGRATION-OFFSET", amount)), 1):
            exported.append({"entry_id": vid, "line_no": str(ordinal), "effective_date": source_date(raw),
                             "recorded_seq": str(sequence), "entry_class": "12", "account_code": account,
                             "side": "D" if signed > 0 else "C", "amount": money(abs(signed)),
                             "currency": "USD", "unit_scale": "2", "description": raw["description"],
                             "memo": expected_citation(raw),
                             "migrated_from": f"{migration.SEVEN_SOURCE_SYSTEM}:{raw['row_id']}"})
    return exported, identities, receipts


def write_export(path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write("# fa_csv_gl_v1|book=unit-test-comparator-only\n")
        writer = csv.DictWriter(stream, fieldnames=migration.ledger.CSV_GL_COLUMNS[:-1])
        writer.writeheader()
        writer.writerows(rows)
    return path


class OfflineCrossSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        magnify_raw = (magnify.FIXTURE_DIR / "rows.csv").read_bytes()
        assert hashlib.sha256(magnify_raw).hexdigest() == MAGNIFY_ROWS_SHA256
        cls.raw = ordered_raw(read_csv(glantz.FIXTURE_DIR / "rows.csv"),
                              read_csv(magnify.FIXTURE_DIR / "rows.csv"))
        cls.rows = interpreted(cls.raw)

    def test_complete_retained_b2_and_three_magnify_account_census(self):
        self.assertEqual(Counter(row["account"] for row in self.raw),
                         {"1ZA192": 75, "1FN025": 58, "1FN097": 4, "1FR051": 27})
        self.assertEqual(len(self.raw), 164)
        self.assertEqual(sum(movement(row) == 0 for row in self.raw), 16)
        self.assertEqual(sum(movement(row) != 0 for row in self.raw), 148)
        running = defaultdict(int)
        for raw in self.raw:
            running[raw["account"]] += movement(raw)
            self.assertEqual(running[raw["account"]], literal_cents(raw["printed_balance_literal"]), raw["row_id"])

    def test_cross_source_normalization_retains_every_literal_and_citation(self):
        actual = migration.normalized_rows(self.rows)
        self.assertEqual(actual, expected_normalized(self.raw))
        self.assertEqual(len(actual), 296)
        self.assertEqual({row["entry_id"].split(":", 1)[0] for row in actual}, {"SRC-BLM-001", "SRC-BLM-006"})
        self.assertFalse(any(row["account"] in EXCLUDED_ACCOUNTS for row in self.rows))

    def test_printed_controls_do_not_consume_normalized_movement_amounts(self):
        controls = migration.printed_controls(self.rows)
        self.assertEqual(controls, expected_controls(self.raw))
        altered = deepcopy(self.rows)
        for row in altered:
            row["principal_movement_cents"] += 1
        self.assertEqual(migration.printed_controls(altered), controls)
        self.assertNotEqual(migration.normalized_rows(altered), migration.normalized_rows(self.rows))

    def test_printed_cell_change_moves_controls_without_changing_journal_amounts(self):
        altered = deepcopy(self.rows)
        anchor = [row for row in altered if row["account"] == "1FN097"][-1]
        anchor["printed_balance_cents"] += 1
        original_controls = migration.printed_controls(self.rows)
        changed_controls = migration.printed_controls(altered)
        self.assertEqual(migration.normalized_rows(altered), migration.normalized_rows(self.rows))
        for original, changed in zip(original_controls, changed_controls, strict=True):
            expected = dict(original["cells_cents"])
            if changed["at_date"] >= anchor["date"]:
                expected["BLMIS-1FN097"] -= 1
                expected["BLMIS-MIGRATION-OFFSET"] += 1
            self.assertEqual(changed["cells_cents"], expected)

    def test_cross_source_export_citations_and_migration_lineage_are_exact(self):
        exported, identities, receipts = comparator_export(self.raw)
        with tempfile.TemporaryDirectory() as directory:
            path = write_export(Path(directory) / "export.csv", exported)
            self.assertEqual(migration.check_export(path, self.rows, identities, receipts,
                                                   source_system=migration.SEVEN_SOURCE_SYSTEM),
                             {"entries": 148, "legs": 296, "text_and_provenance_exact": True})
            with self.assertRaises(migration.live.CheckError):
                migration.check_export(path, self.rows, identities, receipts)
            for source_id, other in (("SRC-BLM-001", "SRC-BLM-006"), ("SRC-BLM-006", "SRC-BLM-001")):
                index = next(index for index, row in enumerate(exported) if source_id in row["memo"])
                for field, value in (("memo", exported[index]["memo"].replace(source_id, other)),
                                     ("migrated_from", exported[index]["migrated_from"].replace(source_id, other)),
                                     ("migrated_from", exported[index]["migrated_from"].replace(
                                         migration.SEVEN_SOURCE_SYSTEM, migration.SOURCE_SYSTEM))):
                    with self.subTest(source_id=source_id, field=field):
                        altered = deepcopy(exported)
                        altered[index][field] = value
                        write_export(path, altered)
                        with self.assertRaises(migration.live.CheckError):
                            migration.check_export(path, self.rows, identities, receipts,
                                                   source_system=migration.SEVEN_SOURCE_SYSTEM)

    def test_magnify_original_requires_explicit_combined_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            with self.assertRaises(migration.live.CheckError):
                migration.prepare(output, None, magnify_pdf=Path(directory) / "not-an-original.pdf")
            self.assertFalse(output.exists())

    def test_new_cli_scope_returns_unrun_when_native_binaries_are_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            error = io.StringIO()
            with redirect_stderr(error):
                code = migration.main(["run", "--include-magnify", "--magnify-pdf", str(root / "unused.pdf"),
                                       "--out", str(root / "not-created"), "--fa", str(root / "missing-fa"),
                                       "--fa-verify", str(root / "missing-verifier")])
            self.assertEqual(code, 4)
            self.assertEqual(json.loads(error.getvalue())["status"], "UNRUN")
            self.assertFalse((root / "not-created").exists())


@unittest.skipUnless(GLANTZ_PDF, "set FA_BLMIS_GLANTZ_PDF for the complete seven-account source oracle")
class CompleteSevenSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original = Path(GLANTZ_PDF)
        assert hashlib.sha256(original.read_bytes()).hexdigest() == GLANTZ_SHA256
        raw, _ = glantz.extract_glantz_pdf(original)
        cls.glantz_raw = list(csv.DictReader(io.StringIO(raw.decode("utf-8")), strict=True))
        cls.magnify_raw = read_csv(magnify.FIXTURE_DIR / "rows.csv")
        cls.raw = ordered_raw(cls.glantz_raw, cls.magnify_raw)
        cls.rows = interpreted(cls.raw)

    def test_complete_seven_account_population_and_from_inception_span(self):
        self.assertEqual(Counter(row["account"] for row in self.raw),
                         {"1T0026": 117, "1ZA192": 75, "1ZB010": 61, "1ZB143": 51,
                          "1FN025": 58, "1FN097": 4, "1FR051": 27})
        self.assertEqual((len(self.raw), sum(movement(row) == 0 for row in self.raw)), (393, 22))
        self.assertEqual((source_date(self.raw[0]), source_date(self.raw[-1])), ("1990-12-14", "2008-10-30"))
        self.assertEqual(len({row["row_id"] for row in self.raw}), 393)

    def test_all_running_balances_equal_independent_printed_cells(self):
        running = defaultdict(int)
        for raw in self.raw:
            running[raw["account"]] += movement(raw)
            self.assertEqual(running[raw["account"]], literal_cents(raw["printed_balance_literal"]), raw["row_id"])
        self.assertEqual(running, {"1T0026": -737416500, "1ZA192": -994703100,
                                   "1ZB010": -50750000, "1ZB143": -1695468800,
                                   "1FN025": -474582200, "1FN097": -32179000, "1FR051": -1123001900})

    def test_every_monthly_control_comes_from_printed_cells_and_matches_literal_fold(self):
        expected = expected_controls(self.raw)
        self.assertEqual(migration.printed_controls(self.rows), expected)
        self.assertEqual(len(expected), 217)
        self.assertEqual((expected[0]["period"], expected[-1]["period"]), ("FY1990-P12", "FY2008-P12"))
        for control in expected:
            self.assertEqual(folded_cells(self.raw, control["at_date"]), control["cells_cents"], control["period"])
        self.assertEqual([anchor["account"] for anchor in expected[0]["printed_anchors"]], ["1FN025"])
        self.assertEqual([anchor for anchor in expected[-1]["printed_anchors"] if anchor["account"] == "1FN097"][0]
                         ["source_date"], "1999-04-05")

    def test_exactly_five_accounts_have_source_discrepancies_including_one_that_closes_exactly(self):
        running, gaps = defaultdict(int), defaultdict(list)
        for raw in ordered_raw(self.glantz_raw, self.magnify_raw, selected=False):
            account = raw["account"]
            running[account] += movement(raw)
            difference = running[account] - literal_cents(raw["printed_balance_literal"])
            if difference:
                gaps[account].append((raw["row_id"], difference))
        self.assertEqual(set(gaps), EXCLUDED_ACCOUNTS)
        self.assertEqual(SELECTED_ACCOUNTS & set(gaps), set())
        final = [row for row in self.glantz_raw if row["account"] == "1ZR176"][-1]
        self.assertEqual(running["1ZR176"], literal_cents(final["printed_balance_literal"]))
        self.assertTrue(gaps["1ZR176"], "closing equality cannot erase intermediate source discrepancies")

    def test_all_742_normalized_legs_are_exact_source_pairs_without_adjustments(self):
        normalized = migration.normalized_rows(self.rows)
        self.assertEqual(normalized, expected_normalized(self.raw))
        self.assertEqual(len(normalized), 742)
        monetary_ids = [row["row_id"] for row in self.raw if movement(row)]
        self.assertEqual([row["entry_id"] for row in normalized[::2]], monetary_ids)
        self.assertEqual(len(monetary_ids), 371)
        for first, second in zip(normalized[::2], normalized[1::2], strict=True):
            self.assertEqual(first["entry_id"], second["entry_id"])
            self.assertEqual(Decimal(first["signed_amount"]) + Decimal(second["signed_amount"]), 0)

    def test_real_glantz_pair_survives_global_order_and_net_preserving_omission_is_detectable(self):
        monetary = [row for row in self.raw if movement(row)]
        indices = migration.omission_pair_indices(self.rows)
        self.assertEqual([monetary[index]["row_id"] for index in indices], [STOP_ID, CHECK_ID])
        self.assertEqual([movement(monetary[index]) for index in indices], [2_500_000, -2_500_000])
        self.assertEqual([row["row_id"] for row in self.raw if row["row_id"] in {STOP_ID, CHECK_ID}],
                         [STOP_ID, CHECK_ID])
        without = [row for row in self.raw if row["row_id"] not in {STOP_ID, CHECK_ID}]
        for control in expected_controls(self.raw):
            self.assertEqual(folded_cells(without, control["at_date"]), control["cells_cents"])
        self.assertEqual(len(expected_normalized(without)), 738)
        self.assertNotEqual(migration.source_gross(interpreted(without)), migration.source_gross(self.rows))
        exported, identities, receipts = comparator_export(self.raw)
        missing_vids = {identities[STOP_ID], identities[CHECK_ID]}
        with tempfile.TemporaryDirectory() as directory:
            path = write_export(Path(directory) / "omitted.csv",
                                [row for row in exported if row["entry_id"] not in missing_vids])
            with self.assertRaises(migration.live.CheckError):
                migration.check_export(path, self.rows, identities, receipts,
                                       source_system=migration.SEVEN_SOURCE_SYSTEM)

    def test_balanced_one_dollar_mutation_cannot_match_independent_printed_controls(self):
        normalized = expected_normalized(self.raw)
        original = glantz.csv_bytes(glantz.LEGACY_COLUMNS, normalized)
        altered, mutation = migration.changed_dollar(original)
        changed = list(csv.DictReader(io.StringIO(altered.decode("utf-8"))))
        self.assertEqual(changed[2:], normalized[2:])
        self.assertEqual(sum(Decimal(row["signed_amount"]) for row in changed[:2]), 0)
        self.assertEqual(mutation["source_row_id"], self.raw[0]["row_id"])
        self.assertEqual(abs(mutation["principal_delta_cents"]), 100)
        self.assertIs(mutation["printed_controls_changed"], False)
        for control in expected_controls(self.raw):
            cells = defaultdict(int)
            for row in changed:
                if row["effective_date"] <= control["at_date"]:
                    cells[row["account_code"]] += int(Decimal(row["signed_amount"]) * 100)
            actual = {key: value for key, value in cells.items() if value}
            self.assertNotEqual(actual, control["cells_cents"], control["period"])

    def test_full_cross_source_export_has_all_371_entries_and_742_legs(self):
        exported, identities, receipts = comparator_export(self.raw)
        with tempfile.TemporaryDirectory() as directory:
            path = write_export(Path(directory) / "all.csv", exported)
            self.assertEqual(migration.check_export(path, self.rows, identities, receipts,
                                                   source_system=migration.SEVEN_SOURCE_SYSTEM),
                             {"entries": 371, "legs": 742, "text_and_provenance_exact": True})


@unittest.skipUnless(GLANTZ_PDF and MAGNIFY_PDF,
                     "set FA_BLMIS_GLANTZ_PDF and FA_BLMIS_MAGNIFY_PDF for dual-original extraction")
class DualOriginalPreparation(unittest.TestCase):
    def test_both_actual_originals_are_freshly_extracted_and_every_retained_source_row_is_accounted_for(self):
        observed, created = [], []
        real_run = subprocess.run

        def observed_run(command, *args, **kwargs):
            if Path(command[0]).name == "pdftotext":
                original = kwargs.get("input")
                self.assertIsInstance(original, bytes)
                observed.append((tuple(command), hashlib.sha256(original).hexdigest()))
            return real_run(command, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "prepared"
            with mock.patch("subprocess.run", side_effect=observed_run):
                rows, manifest = migration.prepare(output, Path(GLANTZ_PDF), include_magnify=True,
                                                    magnify_pdf=Path(MAGNIFY_PDF),
                                                    on_created=lambda: created.append(output.is_dir()))
            self.assertEqual(created, [True])
            expected_extracts = {
                (("pdftotext", "-layout", "-f", "27", "-l", "40", "-", "-"), GLANTZ_SHA256),
                (("pdftotext", "-layout", "-f", "112", "-l", "162", "-", "-"), MAGNIFY_SHA256),
            }
            self.assertEqual(set(observed), expected_extracts)
            self.assertGreaterEqual(len(observed), 2)
            originals = [("source", GLANTZ_SHA256, 379), ("magnify-source", MAGNIFY_SHA256, 2364)]
            for name, digest, count in originals:
                self.assertEqual(hashlib.sha256((output / name / "source.pdf").read_bytes()).hexdigest(), digest)
                self.assertEqual((output / name / "rows.csv").read_bytes(),
                                 (output / name / "extracted-source/rows.csv").read_bytes())
                self.assertEqual(len(read_csv(output / name / "rows.csv")), count)
                self.assertTrue((output / name / "extracted-source/layout.txt").stat().st_size)
            glantz_raw = read_csv(output / "source/rows.csv")
            magnify_raw = read_csv(output / "magnify-source/rows.csv")
            expected = ordered_raw(glantz_raw, magnify_raw)
            self.assertEqual([row["row_id"] for row in rows], [row["row_id"] for row in expected])
            self.assertEqual(read_csv(output / "legacy.csv"), expected_normalized(expected))
            self.assertEqual(manifest["controls"], expected_controls(expected))
            self.assertEqual(manifest["complete_source_rows"], 2743)
            self.assertEqual(manifest["included_observations"], 393)
            self.assertEqual((manifest["monetary_observations"], manifest["normalized_source_rows"]), (371, 742))
            self.assertEqual(set(manifest["included_accounts"]), SELECTED_ACCOUNTS)
            self.assertEqual(set(manifest["excluded_accounts"]), EXCLUDED_ACCOUNTS)
            self.assertEqual(manifest["zero_principal_rows"], [row["row_id"] for row in expected if not movement(row)])
            self.assertEqual(len(manifest["zero_principal_rows"]), 22)
            all_raw = glantz_raw + magnify_raw
            self.assertEqual(set(manifest["excluded_rows"]),
                             {row["row_id"] for row in all_raw if row["account"] in EXCLUDED_ACCOUNTS})
            self.assertEqual(len(manifest["excluded_rows"]), 2350)
            self.assertEqual(manifest["entry_order"], [row["row_id"] for row in expected if movement(row)])
            self.assertEqual(manifest["source_system"], migration.SEVEN_SOURCE_SYSTEM)
            self.assertEqual(manifest["opening_date"], "2009-01-01")
            self.assertEqual(tomllib.loads((output / "column_map.toml").read_text())["columns"]["source_system"],
                             migration.SEVEN_SOURCE_SYSTEM)
            self.assertEqual(json.loads((output / "no-opening-stock.json").read_text())["lines"], [])
            chart = json.loads((output / "chart.json").read_text())["accounts"]
            self.assertEqual({row["code"]: row["type"] for row in chart},
                             {**{f"BLMIS-{account}": "Equity" for account in SELECTED_ACCOUNTS},
                              "BLMIS-MIGRATION-OFFSET": "Asset"})
            self.assertEqual({item["source_id"]: (item["source_sha256"], item["source_rows"])
                              for item in manifest["source_inputs"]},
                             {"SRC-BLM-001": (GLANTZ_SHA256, 379), "SRC-BLM-006": (MAGNIFY_SHA256, 2364)})
            for name, expected_digest in manifest["outputs"].items():
                actual = (output / name).read_bytes()
                self.assertEqual((len(actual), hashlib.sha256(actual).hexdigest()),
                                 (expected_digest["bytes"], expected_digest["sha256"]))


if __name__ == "__main__":
    unittest.main()
