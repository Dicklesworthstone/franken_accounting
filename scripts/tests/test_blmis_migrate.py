"""Source-to-migration comparator tests; constructed envelopes are not native evidence."""
from contextlib import redirect_stderr
from copy import deepcopy
import csv
from datetime import date
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_migrate as migration
import blmis_source as source


def cents(literal):
    text = re.sub(r"\s+\[[12]\]$", "", literal)
    if text == "-":
        return 0
    value = Decimal(text.strip("()").replace(",", "")) * 100
    if value != value.to_integral_exact():
        raise AssertionError("fractional source cent")
    return -int(value) if text.startswith("(") else int(value)


def movement(raw):
    return sum(cents(raw[name + "_literal"]) for name in ("deposits", "withdrawals", "transfers_in", "transfers_out"))


def money(value):
    return f"{Decimal(value) / Decimal(100):.2f}"


def source_date(raw):
    month, day, year = map(int, raw["date_literal"].split("/"))
    return date(year, month, day).isoformat()


def package_from_literals(raw_rows):
    """Independent native-shaped comparator input, never a simulated import."""
    chunks, identities = [], {}
    for raw in raw_rows:
        delta = movement(raw)
        if not delta:
            continue
        index = len(chunks)
        vid = f"{index + 1:032x}"
        day = source_date(raw)
        legs = []
        for ordinal, (account, amount) in enumerate((("BLMIS-1ZA192", -delta), (migration.OFFSET_ACCOUNT, delta))):
            legs.append({"index": ordinal, "account": account, "side": "debit" if amount > 0 else "credit",
                         "amount": money(abs(amount)) + " USD", "dimensions": []})
        chunks.append({"index": index, "entry_vid": vid,
                       "proposal_digest": hashlib.sha256(("test-only:" + raw["row_id"]).encode()).hexdigest(),
                       "effective_date": day, "document_date": day,
                       "effective_period": f"FY{day[:4]}-P{day[5:7]}", "counts_after_finalize": True,
                       "leg_count": 2, "legs": legs})
        identities[raw["row_id"]] = vid
    return {"mode": "FullDetail", "sole_opening_source": True, "source_oid": "a" * 64,
            "row_count": 2 * len(chunks), "chunk_count": len(chunks), "chunks": chunks}, identities


def export_from_literals(raw_rows, identities):
    rows, receipts = [], {}
    for raw in raw_rows:
        delta = movement(raw)
        if not delta:
            continue
        vid = identities[raw["row_id"]]
        sequence = int(vid, 16) + 500
        receipts[vid] = {"entry_vid": vid, "recorded_at": sequence}
        for ordinal, (account, amount) in enumerate((("BLMIS-1ZA192", -delta), (migration.OFFSET_ACCOUNT, delta)), 1):
            rows.append({"entry_id": vid, "line_no": str(ordinal), "effective_date": source_date(raw),
                         "recorded_seq": str(sequence), "entry_class": "12", "account_code": account,
                         "side": "D" if amount > 0 else "C", "amount": money(abs(amount)), "currency": "USD",
                         "unit_scale": "2", "description": raw["description"],
                         "migrated_from": f"{migration.SOURCE_SYSTEM}:{raw['row_id']}",
                         "memo": (f"constructed principal counterpart; SRC-BLM-001 Exhibit B-2 "
                                  f"PDF p{raw['pdf_page']} line {raw['source_line']}"), "dimension_set_v1": ""})
    return rows, receipts


class MigrationComparators(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, _ = source.load_fixture()
        with (source.FIXTURE_DIR / "rows.csv").open(newline="", encoding="utf-8") as stream:
            cls.raw_rows = list(csv.DictReader(stream))

    def test_monthly_controls_select_printed_cells_including_quiet_months(self):
        controls = migration.printed_controls(self.rows)
        self.assertEqual(len(controls), 193)
        self.assertEqual((controls[0]["period"], controls[-1]["period"]), ("FY1992-P12", "FY2008-P12"))
        for control in controls:
            raw = [row for row in self.raw_rows if source_date(row) <= control["at_date"]][-1]
            expected = cents(raw["printed_balance_literal"])
            self.assertEqual(control["cells_cents"], {"BLMIS-1ZA192": -expected, migration.OFFSET_ACCOUNT: expected})
            self.assertEqual(control["printed_anchors"][0]["source_row_id"], raw["row_id"])
            self.assertEqual(sum(control["cells_cents"].values()), 0)
        self.assertEqual(controls[-1]["printed_anchors"][0]["source_date"], "2008-10-30")
        self.assertEqual(controls[-1]["cells_cents"]["BLMIS-1ZA192"], 994_703_100)

    def test_printed_controls_are_independent_of_normalized_movements(self):
        changed = deepcopy(self.rows)
        for row in changed:
            row["principal_movement_cents"] = 123
            row["cash_movement_cents"] = -999
            row["transfer_movement_cents"] = 876
        self.assertEqual(migration.printed_controls(changed), migration.printed_controls(self.rows))
        self.assertNotEqual(migration.normalized_rows(changed), migration.normalized_rows(self.rows))

    def test_controls_omit_zero_and_preinception_cells_and_sort_accounts(self):
        rows = [
            {"account": "Z", "date": "2000-11-01", "row_id": "z1", "printed_balance_cents": 100},
            {"account": "Z", "date": "2000-11-30", "row_id": "z2", "printed_balance_cents": 0},
            {"account": "A", "date": "2000-12-15", "row_id": "a1", "printed_balance_cents": -200},
            {"account": "A", "date": "2000-12-15", "row_id": "a2", "printed_balance_cents": -300},
        ]
        controls = migration.printed_controls(rows)
        self.assertEqual(controls[0]["lines"], [])
        self.assertEqual([anchor["account"] for anchor in controls[0]["printed_anchors"]], ["Z"])
        self.assertEqual(controls[1]["lines"], [
            {"account": "BLMIS-A", "unit": "USD", "net": "3.00"},
            {"account": migration.OFFSET_ACCOUNT, "unit": "USD", "net": "-3.00"},
        ])
        self.assertEqual(controls[1]["printed_anchors"][0]["source_row_id"], "a2")

    def test_controls_refuse_unsorted_account_dates(self):
        rows = deepcopy(self.rows)
        rows[0], rows[-1] = rows[-1], rows[0]
        with self.assertRaisesRegex(migration.live.CheckError, "dates are not ordered"):
            migration.printed_controls(rows)

    def test_normalization_retains_original_amounts_text_and_zero_observation_boundary(self):
        normalized = migration.normalized_rows(self.rows)
        self.assertEqual(len(normalized), 148)
        offset = 0
        for raw in self.raw_rows:
            delta = movement(raw)
            if not delta:
                self.assertFalse(any(row["source_row"] == raw["row_id"] for row in normalized))
                continue
            pair = normalized[offset:offset + 2]
            self.assertEqual([Decimal(row["signed_amount"]) * 100 for row in pair], [-delta, delta])
            self.assertEqual([row["account_code"] for row in pair], ["BLMIS-1ZA192", migration.OFFSET_ACCOUNT])
            for row in pair:
                self.assertEqual(row["entry_id"], raw["row_id"])
                self.assertEqual(row["effective_date"], source_date(raw))
                self.assertEqual(row["description"], raw["description"])
                self.assertIn(f"line {raw['source_line']}", row["memo"])
            offset += 2
        self.assertEqual(offset, len(normalized))

    def test_one_dollar_negative_is_still_balanced_and_changes_only_one_pair(self):
        original = source.csv_bytes(source.LEGACY_COLUMNS, migration.normalized_rows(self.rows))
        altered, mutation = migration.changed_dollar(original)
        before = list(csv.DictReader(io.StringIO(original.decode())))
        after = list(csv.DictReader(io.StringIO(altered.decode())))
        self.assertEqual(before[2:], after[2:])
        self.assertEqual(sum(Decimal(row["signed_amount"]) for row in after[:2]), 0)
        self.assertEqual(abs(Decimal(before[0]["signed_amount"]) - Decimal(after[0]["signed_amount"])), 1)
        self.assertEqual(mutation["source_row_id"], self.rows[0]["row_id"])
        self.assertIs(mutation["printed_controls_changed"], False)
        for first, second in zip(before[:2], after[:2], strict=True):
            self.assertEqual({key: value for key, value in first.items() if key != "signed_amount"},
                             {key: value for key, value in second.items() if key != "signed_amount"})

    def test_native_preparation_matches_all_source_legs_and_dates(self):
        package, identities = package_from_literals(self.raw_rows)
        self.assertEqual(migration.check_prepared(package, self.rows, "a" * 64), identities)

    def test_native_preparation_refuses_lost_and_changed_source_geometry(self):
        package, _ = package_from_literals(self.raw_rows)
        mutations = [
            lambda value: value["chunks"][0].update(effective_date="1992-12-08"),
            lambda value: value["chunks"][0].update(effective_period="FY1992-P11"),
            lambda value: value["chunks"][0].update(counts_after_finalize=False),
            lambda value: value["chunks"][0]["legs"][0].update(amount="1.00 USD"),
            lambda value: value["chunks"][0]["legs"][0].update(dimensions=[{"dimension": 12, "value": "f" * 32}]),
            lambda value: value["chunks"][1].update(entry_vid=value["chunks"][0]["entry_vid"]),
            lambda value: value["chunks"].pop(),
            lambda value: value.update(source_oid="b" * 64),
        ]
        for change in mutations:
            with self.subTest(change=change):
                altered = deepcopy(package)
                change(altered)
                with self.assertRaises(migration.live.CheckError):
                    migration.check_prepared(altered, self.rows, "a" * 64)

    def test_source_omission_pair_is_anchored_not_searched_for(self):
        pair = [
            {"row_id": source.GLANTZ_REORDER["computation_row_ids"][0], "account": "1ZB010",
             "date": "2006-10-17", "description": "STOP PAYMENT", "principal_movement_cents": 2_500_000},
            {"row_id": source.GLANTZ_REORDER["computation_row_ids"][1], "account": "1ZB010",
             "date": "2006-10-17", "description": "CHECK", "principal_movement_cents": -2_500_000},
        ]
        self.assertEqual(migration.omission_pair_indices(pair), [0, 1])
        for changed in (pair[:1], list(reversed(pair)), [dict(pair[0], date="2006-10-18"), pair[1]],
                        [dict(pair[0], principal_movement_cents=1), dict(pair[1], principal_movement_cents=-1)]):
            with self.subTest(changed=changed), self.assertRaises(migration.live.CheckError):
                migration.omission_pair_indices(changed)

    def arbitrary_group(self):
        package, _ = package_from_literals(self.raw_rows)
        package["package_oid"] = "b" * 64
        selected = [package["chunks"][0], package["chunks"][2]]
        receipts = [{"chunk_index": chunk["index"], "entry_vid": chunk["entry_vid"],
                     "proposal_digest": chunk["proposal_digest"], "recorded_at": 500 + index,
                     "already_recorded": False} for index, chunk in enumerate(selected)]
        event = {"event": "migration_import_group_staged", "data": {
            "package_oid": package["package_oid"], "run_vid": "c" * 32, "atomic": False,
            "run_state": "Open", "selected_count": 2, "completed_count": 2, "recorded_count": 2,
            "chunk_count": len(package["chunks"]), "ready_to_finalize": False, "chunks": receipts,
        }}
        return package, selected, event

    def test_noncontiguous_group_binds_original_indices_and_exact_retry(self):
        package, selected, event = self.arbitrary_group()
        receipts = migration.check_stage_group(event, selected, package, "c" * 32, {})
        recorded = {receipt["entry_vid"]: receipt for receipt in receipts}
        again = deepcopy(event)
        for receipt in again["data"]["chunks"]:
            receipt["already_recorded"] = True
        self.assertEqual(migration.check_stage_group(again, selected, package, "c" * 32, recorded, retry=True),
                         again["data"]["chunks"])
        again["data"]["chunks"][0]["recorded_at"] += 1
        with self.assertRaisesRegex(migration.live.CheckError, "original publication"):
            migration.check_stage_group(again, selected, package, "c" * 32, recorded, retry=True)

    def test_arbitrary_group_refuses_wrong_members_counts_and_publication_order(self):
        package, selected, event = self.arbitrary_group()
        mutations = [
            lambda value: value["data"].update(recorded_count=3),
            lambda value: value["data"].update(ready_to_finalize=True),
            lambda value: value["data"].update(atomic=True),
            lambda value: value["data"]["chunks"][1].update(chunk_index=1),
            lambda value: value["data"]["chunks"][1].update(recorded_at=500),
            lambda value: value["data"]["chunks"][0].update(proposal_digest="f" * 64),
            lambda value: value["data"]["chunks"].pop(),
        ]
        for change in mutations:
            with self.subTest(change=change):
                changed = deepcopy(event)
                change(changed)
                with self.assertRaises(migration.live.CheckError):
                    migration.check_stage_group(changed, selected, package, "c" * 32, {})

    def write_export(self, directory, rows, *, dimensions=False):
        path = Path(directory) / "native.csv"
        columns = migration.ledger.CSV_GL_COLUMNS if dimensions else migration.ledger.CSV_GL_COLUMNS[:-1]
        with path.open("w", newline="", encoding="utf-8") as stream:
            stream.write("# fa_csv_gl_v1|book=unit-test-only" +
                         ("|dimension_encoding=fa-dimension-ids-v1" if dimensions else "") + "\n")
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows({key: row[key] for key in columns} for row in rows)
        return path

    def test_export_retains_every_leg_and_exact_provenance(self):
        _, identities = package_from_literals(self.raw_rows)
        rows, receipts = export_from_literals(self.raw_rows, identities)
        with tempfile.TemporaryDirectory() as directory:
            result = migration.check_export(self.write_export(directory, rows), self.rows, identities, receipts)
        self.assertEqual(result, {"entries": 74, "legs": 148, "text_and_provenance_exact": True})

    def test_dimension_bearing_export_is_refused_for_the_untagged_model(self):
        # Preserve the original 14-column comparator fixture as a negative:
        # the real native writer correctly emitted 13 columns for this model.
        _, identities = package_from_literals(self.raw_rows)
        rows, receipts = export_from_literals(self.raw_rows, identities)
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_export(directory, rows, dimensions=True)
            with self.assertRaisesRegex(migration.live.CheckError, "dimension attribution"):
                migration.check_export(path, self.rows, identities, receipts)
            rows[0]["dimension_set_v1"] = "12:" + "f" * 32
            path = self.write_export(directory, rows, dimensions=True)
            with self.assertRaisesRegex(migration.live.CheckError, "dimension attribution"):
                migration.check_export(path, self.rows, identities, receipts)

    def test_export_refuses_missing_balanced_entry_or_text_and_lineage_loss(self):
        _, identities = package_from_literals(self.raw_rows)
        rows, receipts = export_from_literals(self.raw_rows, identities)
        mutations = [
            lambda value: value.__delitem__(slice(0, 2)),
            lambda value: value[0].update(migrated_from=""),
            lambda value: value[0].update(memo=""),
            lambda value: value[0].update(description="changed"),
            lambda value: value[0].update(recorded_seq="500"),
            lambda value: value[0].update(account_code=migration.OFFSET_ACCOUNT),
            lambda value: value.append(value[0].copy()),
        ]
        for change in mutations:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                altered = deepcopy(rows)
                change(altered)
                with self.assertRaises(migration.live.CheckError):
                    migration.check_export(self.write_export(directory, altered), self.rows, identities, receipts)

    def test_missing_native_binaries_return_unrun_without_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream = io.StringIO()
            with redirect_stderr(stream):
                code = migration.main(["run", "--out", str(root / "new-output"),
                                       "--fa", str(root / "missing-fa"), "--fa-verify", str(root / "missing-verifier")])
            self.assertEqual(code, 4)
            self.assertEqual(json.loads(stream.getvalue())["status"], "UNRUN")
            self.assertFalse((root / "new-output").exists())

    def test_preparation_refuses_existing_output_without_overwriting_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            original = path / "report.json"
            original.write_bytes(b"preserve this existing evidence\n")
            with self.assertRaises(FileExistsError):
                migration.prepare(path, None)
            self.assertEqual(original.read_bytes(), b"preserve this existing evidence\n")


@unittest.skipUnless(os.environ.get("FA_BLMIS_GLANTZ_PDF"), "set FA_BLMIS_GLANTZ_PDF to run pinned original-PDF extraction")
class OriginalPdfMigration(unittest.TestCase):
    def test_complete_four_account_transform_and_printed_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            rows, manifest = migration.prepare(Path(directory) / "prepared", Path(os.environ["FA_BLMIS_GLANTZ_PDF"]))
            self.assertEqual(len(rows), 304)
            self.assertEqual(manifest["complete_source_rows"], 379)
            self.assertEqual(manifest["monetary_observations"], 297)
            self.assertEqual(manifest["normalized_source_rows"], 594)
            self.assertEqual(len(manifest["zero_principal_rows"]), 7)
            self.assertEqual(len(manifest["excluded_rows"]), 75)
            self.assertEqual(set(manifest["excluded_accounts"]), {"1ZR010", "1ZR176"})
            controls = manifest["controls"]
            self.assertEqual(len(controls), 194)
            self.assertEqual((controls[0]["period"], controls[-1]["period"]), ("FY1992-P11", "FY2008-P12"))
            self.assertEqual(controls[-1]["cells_cents"], {
                "BLMIS-1T0026": 737_416_500, "BLMIS-1ZA192": 994_703_100,
                "BLMIS-1ZB010": 50_750_000, "BLMIS-1ZB143": 1_695_468_800,
                migration.OFFSET_ACCOUNT: -3_478_338_400,
            })
            for control in controls:
                self.assertEqual(sum(control["cells_cents"].values()), 0)
                self.assertTrue(all(line["net"] != "0.00" for line in control["lines"]))
            self.assertEqual(manifest["same_day_rule"]["rule"], "same_day_display_reorder")
            omitted = migration.omission_pair_indices(rows)
            monetary = [row for row in rows if movement(row)]
            missing_ids = {monetary[index]["row_id"] for index in omitted}
            self.assertEqual(missing_ids, set(source.GLANTZ_REORDER["computation_row_ids"]))
            # Literal movement columns prove that deleting both genuine rows
            # loses source population but leaves every declared monthly net
            # unchanged. This is why a balance-only migration gate is weaker.
            for control in controls:
                folded = {}
                for row in rows:
                    if row["date"] > control["at_date"] or row["row_id"] in missing_ids:
                        continue
                    delta = movement(row)
                    account = "BLMIS-" + row["account"]
                    folded[account] = folded.get(account, 0) - delta
                    folded[migration.OFFSET_ACCOUNT] = folded.get(migration.OFFSET_ACCOUNT, 0) + delta
                self.assertEqual({code: value for code, value in folded.items() if value}, control["cells_cents"])
            self.assertEqual(sum(abs(movement(row)) for row in rows if row["row_id"] in missing_ids), 5_000_000)


if __name__ == "__main__":
    unittest.main()
