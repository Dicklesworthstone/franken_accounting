"""Unit-test the BLMIS replay driver's source-to-report comparisons.

The reports below are deliberately constructed test inputs, never native run
evidence. Their amounts come independently from Decimal and the retained source
literals, and their receipt digests are explicitly test-only identities. A green
suite does not establish that fa or fa-verify executed the accounting workflow.
"""

from contextlib import redirect_stderr, redirect_stdout
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_replay as replay
import blmis_source as source


def cents(literal):
    """Independent decoding of this fixture's published whole-dollar cells."""
    text = re.sub(r"\s+(?:\[[12]\]|\*)$", "", literal)
    if text == "-":
        return 0
    negative = text.startswith("(")
    value = Decimal(text.strip("()").replace(",", "")) * Decimal(100)
    if value != value.to_integral_exact():
        raise AssertionError("test source has a fractional cent")
    return -int(value) if negative else int(value)


def amount(value):
    return f"{Decimal(value) / Decimal(100):.2f} USD"


def source_date(row):
    month, day, year = map(int, row["date_literal"].split("/"))
    return date(year, month, day).isoformat()


def movement(row):
    return sum(cents(row[f"{field}_literal"]) for field in (
        "deposits", "withdrawals", "transfers_in", "transfers_out"))


def comparator_inputs(raw_rows, *, empty=False):
    """Native-shaped unit inputs, not simulated execution or proof material."""
    posted, lines = {}, []
    for ordinal, row in enumerate(raw_rows, 1):
        delta = movement(row)
        if not delta:
            continue
        receipt = {
            "vid": f"{ordinal + 1000:032x}",
            "entry_digest": hashlib.sha256(("unit-input-only:" + row["row_id"]).encode()).hexdigest(),
            "recorded_at": 1000 + ordinal,
        }
        posted[row["row_id"]] = receipt
        lines.append({
            "entry_digest": receipt["entry_digest"], "recorded_at": receipt["recorded_at"],
            "leg_index": 0, "effective_date": source_date(row), "class": "Original",
            "account": "BLMIS-1ZA192", "unit": "USD",
            "debits": amount(max(-delta, 0)), "credits": amount(max(delta, 0)),
            "running_balance": amount(-cents(row["printed_balance_literal"])),
        })
    if empty:
        lines = []
    debit = sum(max(-movement(row), 0) for row in raw_rows) if not empty else 0
    credit = sum(max(movement(row), 0) for row in raw_rows) if not empty else 0
    closing = -cents(raw_rows[-1]["printed_balance_literal"]) if not empty else 0
    data = {
        "label": "blmis-glantz-1za192-published-principal",
        "known_at": 2000 if not empty else 999,
        "effective_from": source_date(raw_rows[0]),
        "effective_through": source_date(raw_rows[-1]),
        "cells": [{"account": "BLMIS-1ZA192", "unit": "USD", "opening": amount(0),
                   "debits": amount(debit), "credits": amount(credit),
                   "net_change": amount(closing), "closing": amount(closing),
                   "line_count": len(lines)}],
        "lines": lines,
    }
    return data, posted


TEST_PARTY = {"code": "BLMIS-1ZA192", "vid": "b" * 32, "dimension": 12, "value": "a" * 32}


def principal_analysis_input(raw_rows, *, include_transfers=True, known_at=2000):
    """A comparator input built from raw source literals, never an executed run."""
    cash_in = sum(cents(row["deposits_literal"]) for row in raw_rows)
    cash_out = -sum(cents(row["withdrawals_literal"]) for row in raw_rows)
    transfer_in = sum(cents(row["transfers_in_literal"]) for row in raw_rows) if include_transfers else 0
    transfer_out = -sum(cents(row["transfers_out_literal"]) for row in raw_rows) if include_transfers else 0
    winner = cash_out + transfer_out - cash_in - transfer_in
    population = sum(bool(movement(row) if include_transfers else
                          cents(row["deposits_literal"]) + cents(row["withdrawals_literal"])) for row in raw_rows)
    return {"event": "procedure_run", "data": {
        "procedure": "ponzi.net_investment", "version": 5, "claim": "statistical",
        "known_at": known_at, "effective_through": source_date(raw_rows[-1]), "finding_count": 1,
        "findings": [{"statistic": {"name": "fictitious_profit_clawback", "value": winner,
                                    "scale": 2, "population": population},
                      "narrative": (f"investor BLMIS-1ZA192 (cohort 1, status=net_winner): "
                                    f"cash_in={cash_in}, cash_out={cash_out}, "
                                    f"transfer_in={transfer_in}, transfer_out={transfer_out}, "
                                    f"fictitious_profit_clawback={winner}, "
                                    "principal_rule=posted_principal_transfer_v1, attribution=complete")}],
    }}


def export_test_input(raw_rows, path, format_name, mutate=None):
    """Write an export-shaped unit input directly from original source literals."""
    _, posted = comparator_inputs(raw_rows)
    records = []
    for row in raw_rows:
        delta = movement(row)
        if not delta:
            continue
        cash = cents(row["deposits_literal"]) + cents(row["withdrawals_literal"])
        transfer = cents(row["transfers_in_literal"]) + cents(row["transfers_out_literal"])
        contra = ("BLMIS-CASH", cash) if cash else ("BLMIS-TRANSFER", transfer)
        for ordinal, (account, signed) in enumerate([("BLMIS-1ZA192", -delta), contra], 1):
            receipt = posted[row["row_id"]]
            memo = (f"analysis counterpart; SRC-BLM-001 Exhibit {row.get('exhibit', 'B-2')} "
                    f"PDF p{row['pdf_page']} line {row['source_line']}")
            records.append([receipt["vid"], str(ordinal), source_date(row), str(receipt["recorded_at"]),
                            "1", account, "D" if signed > 0 else "C", amount(abs(signed)).split()[0],
                            "USD", "2", row["description"], r"\N" if format_name == "ads" else "", memo,
                            "12:" + "a" * 32 if ordinal == 1 else ""])
    if mutate is not None:
        mutate(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "csv-gl":
        with path.open("w", encoding="utf-8", newline="") as stream:
            stream.write("# fa_csv_gl_v1|book=source-comparator-only|dimension_encoding=fa-dimension-ids-v1\n")
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(replay.ledger.CSV_GL_COLUMNS)
            writer.writerows(records)
    else:
        (path.parent / "ADS_Coordinate_Certificate.toml").write_text(
            'schema_version = 1\nformat = "aicpa_ads_gl_v3"\ndimension_encoding = "fa-dimension-ids-v1"\n',
            encoding="utf-8")
        path.write_text("|".join(replay.ledger.ADS_GL_COLUMNS) + "\n"
                        + "".join("|".join(record) + "\n" for record in records), encoding="utf-8")
    return posted


class BlmisReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, _ = source.load_fixture()
        with (source.FIXTURE_DIR / "rows.csv").open(encoding="utf-8", newline="") as stream:
            cls.originals = list(csv.DictReader(stream, strict=True))
        cls.directory = tempfile.TemporaryDirectory(prefix="fa-blmis-comparator-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.package = Path(cls.directory.name) / "package"
        cls.manifest = source.prepare(cls.package)
        with (cls.package / "legacy.csv").open(encoding="utf-8", newline="") as stream:
            cls.normalized = list(csv.DictReader(stream, strict=True))

    def normalized_path(self, records, *, columns=source.LEGACY_COLUMNS, suffix=""):
        path = Path(self.directory.name) / "mutated.csv"
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
        path.write_text(buffer.getvalue() + suffix, encoding="utf-8")
        return path

    def test_normalized_entries_keep_every_source_row_and_exact_counterpart(self):
        entries = replay.normalized_entries(self.package / "legacy.csv", self.rows)
        expected_rows = [row for row in self.originals if movement(row)]
        self.assertEqual(len(self.originals), 75)
        self.assertEqual(len(entries), 74)
        self.assertEqual(len(self.normalized), 148)
        for entry, row in zip(entries, expected_rows, strict=True):
            self.assertEqual(entry["idempotency_key"], row["row_id"])
            self.assertEqual(entry["effective_date"], source_date(row))
            self.assertEqual(entry["description"], row["description"])
            cash = cents(row["deposits_literal"]) + cents(row["withdrawals_literal"])
            transfer = cents(row["transfers_in_literal"]) + cents(row["transfers_out_literal"])
            expected = [("BLMIS-1ZA192", -(cash + transfer))]
            expected.append(("BLMIS-CASH", cash) if cash else ("BLMIS-TRANSFER", transfer))
            self.assertEqual(len(entry["legs"]), 2)
            self.assertEqual(sum(value for _, value in expected), 0)
            for leg, (account, value) in zip(entry["legs"], expected, strict=True):
                self.assertEqual(leg["account"], account)
                self.assertEqual(leg["side"], "debit" if value > 0 else "credit")
                self.assertEqual(leg["amount"], amount(abs(value)))
                if account == "BLMIS-1ZA192":
                    self.assertEqual(leg["party"], "BLMIS-1ZA192")
                else:
                    self.assertNotIn("party", leg, "cash and transfer clearing remain untagged")

    def test_zero_principal_transfer_is_retained_without_an_invented_entry(self):
        zeros = [row for row in self.originals if not movement(row)]
        self.assertEqual(len(zeros), 1)
        zero = zeros[0]
        self.assertEqual(cents(zero["reported_literal"]), 20_000_000)
        self.assertIn("[2]", zero["reported_literal"])
        self.assertEqual(self.manifest["zero_principal_rows"], [zero["row_id"]])
        entries = replay.normalized_entries(self.package / "legacy.csv", self.rows)
        self.assertNotIn(zero["row_id"], {entry["idempotency_key"] for entry in entries})
        report, posted = comparator_inputs(self.originals)
        replay.check_ledger(report, self.rows, posted)
        self.assertNotIn(zero["row_id"], posted)
        position = self.originals.index(zero)
        self.assertEqual(zero["printed_balance_literal"], self.originals[position - 1]["printed_balance_literal"])

    def test_native_principal_comparator_separates_cash_transfers_and_published_control(self):
        complete = replay.check_principal_analysis(
            principal_analysis_input(self.originals), self.rows, 2000, include_transfers=True)
        missing = replay.check_principal_analysis(
            principal_analysis_input(self.originals, include_transfers=False), self.rows, 2000,
            include_transfers=False)
        self.assertEqual(complete["printed_closing_principal_cents"], -994_703_100)
        self.assertEqual(complete["native_principal_cents"], -994_703_100)
        self.assertEqual(complete["net_winner_cents"], 994_703_100)
        self.assertEqual(complete["cash_in_cents"], 1_043_998_300)
        self.assertEqual(complete["cash_out_cents"], 1_692_438_000)
        self.assertEqual(complete["transfer_in_cents"], 53_736_600)
        self.assertEqual(complete["transfer_out_cents"], 400_000_000)
        self.assertEqual(complete["gap_from_printed_principal_cents"], 0)
        self.assertEqual(missing["net_winner_cents"], 648_439_700)
        self.assertEqual(missing["gap_from_printed_principal_cents"], 346_263_400)
        self.assertEqual(missing["cash_in_cents"], complete["cash_in_cents"])
        self.assertEqual(missing["cash_out_cents"], complete["cash_out_cents"])
        with self.assertRaises(replay.ledger.ReplayError):
            replay.check_principal_analysis(principal_analysis_input(self.originals, include_transfers=False),
                                            self.rows, 2000, include_transfers=True)
        chart = json.loads((self.package / "chart.json").read_text())
        clearing = next(account for account in chart["accounts"] if account["code"] == "BLMIS-TRANSFER")
        self.assertEqual(clearing["type"], "Liability", "explicit transfer role admits an analysis clearing account")

    def test_native_principal_comparator_refuses_wrong_scope_claim_and_attribution(self):
        for field, value in (("procedure", "distribution.pro_rata"), ("version", 4), ("known_at", 1999),
                             ("effective_through", "2008-10-29"), ("claim", "invariant"), ("finding_count", 2)):
            report = principal_analysis_input(self.originals)
            report["data"][field] = value
            with self.subTest(field=field), self.assertRaises(replay.ledger.ReplayError):
                replay.check_principal_analysis(report, self.rows, 2000, include_transfers=True)
        for field, value in (("name", "net_equity_claim"), ("value", 994_703_101), ("scale", 0), ("population", 75)):
            report = principal_analysis_input(self.originals)
            report["data"]["findings"][0]["statistic"][field] = value
            with self.subTest(statistic=field), self.assertRaises(replay.ledger.ReplayError):
                replay.check_principal_analysis(report, self.rows, 2000, include_transfers=True)
        for before, after in (("BLMIS-1ZA192", "BLMIS-OTHER"), ("attribution=complete", "attribution=incomplete"),
                              ("posted_principal_transfer_v1", "inferred_transfer"),
                              ("cash_in=1043998300", "cash_in=1097734900"),
                              ("transfer_in=53736600", "transfer_in=127042200")):
            report = principal_analysis_input(self.originals)
            finding = report["data"]["findings"][0]
            finding["narrative"] = finding["narrative"].replace(before, after)
            with self.subTest(attribution=after), self.assertRaises(replay.ledger.ReplayError):
                replay.check_principal_analysis(report, self.rows, 2000, include_transfers=True)
        for duplicate in (False, True):
            report = principal_analysis_input(self.originals)
            report["data"]["findings"] = report["data"]["findings"] * 2 if duplicate else []
            report["data"]["finding_count"] = len(report["data"]["findings"])
            with self.subTest(duplicate=duplicate), self.assertRaises(replay.ledger.ReplayError):
                replay.check_principal_analysis(report, self.rows, 2000, include_transfers=True)

    def test_principal_role_control_checks_both_native_prefixes_and_later_history(self):
        # These are call-contract inputs only. Real runner PASS still requires
        # the actual executable responses recorded in commands.jsonl.
        without = principal_analysis_input(self.originals, include_transfers=False, known_at=1500)
        complete = principal_analysis_input(self.originals, known_at=2000)
        for changed_history in (False, True):
            with self.subTest(changed_history=changed_history):
                native = mock.Mock(spec=replay.ledger.Native)
                native.head.side_effect = [1500, 2000]
                native.call.side_effect = [without, {}, complete, complete if changed_history else without]
                if changed_history:
                    with self.assertRaisesRegex(replay.ledger.ReplayError, "changed the earlier native analysis"):
                        replay.verify_principal_analysis(native, self.rows)
                else:
                    result = replay.verify_principal_analysis(native, self.rows)
                    self.assertEqual(result["transfer_gap_cents"], 346_263_400)
                    self.assertTrue(result["historical_missing_role_result_unchanged"])
                    self.assertEqual(native.call.call_args_list, [
                        mock.call("procedure", "run", "ponzi.net_investment", "--effective-through", "2008-10-30",
                                  "--as-known-at", 1500),
                        mock.call("chart", "role", "BLMIS-TRANSFER", "investor_transfer"),
                        mock.call("procedure", "run", "ponzi.net_investment", "--effective-through", "2008-10-30",
                                  "--as-known-at", 2000),
                        mock.call("procedure", "run", "ponzi.net_investment", "--effective-through", "2008-10-30",
                                  "--as-known-at", 1500),
                    ])

    def test_native_party_registration_uses_actual_dimension_identity_not_party_vid(self):
        registered = {"event": "rea_recorded", "data": {"object": "party", "code": "BLMIS-1ZA192",
                      "target": "b" * 32, "already_recorded": False}}
        listing = {"event": "parties", "data": {"parties": [{"code": "BLMIS-1ZA192", "kind": "Counterparty",
                    "vid": "b" * 32, "dimension_id": 12, "dimension_value_vid": "a" * 32}]}}
        for mutation in (None, "party_vid_as_value", "wrong_party", "wrong_kind", "other_dimension", "duplicate"):
            with self.subTest(mutation=mutation):
                changed = deepcopy(listing)
                party = changed["data"]["parties"][0]
                if mutation == "party_vid_as_value":
                    party["dimension_value_vid"] = party["vid"]
                elif mutation == "wrong_party":
                    party["code"] = "BLMIS-OTHER"
                elif mutation == "wrong_kind":
                    party["kind"] = "Vendor"
                elif mutation == "other_dimension":
                    party["dimension_id"] = 3
                elif mutation == "duplicate":
                    changed["data"]["parties"].append(deepcopy(party))
                native = mock.Mock(spec=replay.ledger.Native)
                native.call.side_effect = [registered, changed]
                out = Path(self.directory.name) / f"party-registration-{mutation}"
                out.mkdir()
                if mutation is None:
                    self.assertEqual(replay.register_source_party(native, out), TEST_PARTY)
                else:
                    with self.assertRaises(replay.ledger.ReplayError):
                        replay.register_source_party(native, out)

    def test_export_comparator_matches_all_148_original_principal_and_counterpart_legs(self):
        for format_name in ("csv-gl", "ads"):
            with self.subTest(format=format_name):
                path = Path(self.directory.name) / "all-source-exports" / format_name / "GL_Detail.txt"
                posted = export_test_input(self.originals, path, format_name)
                report = replay.verify_source_export(path, format_name, self.rows, posted, TEST_PARTY)
                self.assertEqual(report, {"format": format_name, "rows": 148, "tagged_rows": 74,
                                          "untagged_rows": 74, "dimension_encoding": "fa-dimension-ids-v1",
                                          "party": "BLMIS-1ZA192"})

    def test_export_comparator_refuses_changed_party_tags_with_all_money_unchanged(self):
        for format_name in ("csv-gl", "ads"):
            for mutation in ("substitute", "drop", "invent_for_contra", "wrong_dimension"):
                with self.subTest(format=format_name, mutation=mutation):
                    def change(records):
                        monetary = [row[:13] for row in records]
                        if mutation == "substitute":
                            records[0][13] = "12:" + "b" * 32
                        elif mutation == "drop":
                            records[0][13] = ""
                        elif mutation == "invent_for_contra":
                            records[1][13] = records[0][13]
                        else:
                            records[0][13] = "3:" + "a" * 32
                        self.assertEqual([row[:13] for row in records], monetary)
                    path = Path(self.directory.name) / "party-tampered-exports" / format_name / mutation / "GL_Detail.txt"
                    posted = export_test_input(self.originals, path, format_name, change)
                    with self.assertRaisesRegex(replay.ledger.ReplayError, "changed party attribution"):
                        replay.verify_source_export(path, format_name, self.rows, posted, TEST_PARTY)

    def test_export_comparator_refuses_lost_source_text_and_invented_provenance(self):
        for format_name in ("csv-gl", "ads"):
            for leg in (0, 1):
                for field, index, value in (
                    ("description", 10, "SOURCE DESCRIPTION LOST"),
                    ("memo", 12, ""),
                    ("other_source_citation", 12, "analysis counterpart; SRC-BLM-OTHER Exhibit B-2 PDF p31 line 16"),
                    ("migrated_from", 11, "invented migration provenance"),
                ):
                    def change(records):
                        before = deepcopy(records)
                        records[leg][index] = value
                        self.assertNotEqual(before[leg][index], records[leg][index])
                        self.assertEqual([row[:10] + row[13:] for row in records],
                                         [row[:10] + row[13:] for row in before],
                                         "only the selected source text field may change")
                    path = Path(self.directory.name) / "text-tampered-exports" / format_name / str(leg) / field / "GL_Detail.txt"
                    posted = export_test_input(self.originals, path, format_name, change)
                    with self.subTest(format=format_name, leg=leg, field=field), \
                            self.assertRaisesRegex(replay.ledger.ReplayError, "source description, citation memo or original-entry provenance"):
                        replay.verify_source_export(path, format_name, self.rows, posted, TEST_PARTY)

    def test_export_comparator_checks_counterpart_money_receipts_dates_and_row_coverage(self):
        for format_name in ("csv-gl", "ads"):
            for mutation in ("amount", "account", "date", "sequence", "class", "omit", "duplicate", "reorder"):
                with self.subTest(format=format_name, mutation=mutation):
                    def change(records):
                        if mutation == "amount":
                            records[1][7] = f"{Decimal(records[1][7]) + Decimal('0.01'):.2f}"
                        elif mutation == "account":
                            records[1][5] = "BLMIS-TRANSFER"
                        elif mutation == "date":
                            records[1][2] = "1992-12-08"
                        elif mutation == "sequence":
                            records[1][3] = str(int(records[1][3]) + 1)
                        elif mutation == "class":
                            records[1][4] = "12"
                        elif mutation == "omit":
                            records.pop()
                        elif mutation == "duplicate":
                            records.append(list(records[-1]))
                        else:
                            records[0], records[1] = records[1], records[0]
                    path = Path(self.directory.name) / "source-tampered-exports" / format_name / mutation / "GL_Detail.txt"
                    posted = export_test_input(self.originals, path, format_name, change)
                    with self.assertRaises(replay.ledger.ReplayError):
                        replay.verify_source_export(path, format_name, self.rows, posted, TEST_PARTY)

    def test_normalized_missing_extra_duplicate_and_reordered_rows_are_refused(self):
        variants = {
            "missing": self.normalized[:-1],
            "extra": self.normalized + [self.normalized[-1]],
            "duplicate_replaces_row": [self.normalized[0], self.normalized[0]] + self.normalized[2:],
            "same_day_entries_reordered": self.normalized[2:4] + self.normalized[:2] + self.normalized[4:],
            "legs_reordered": [self.normalized[1], self.normalized[0]] + self.normalized[2:],
        }
        for name, records in variants.items():
            with self.subTest(name=name), self.assertRaises(replay.ledger.ReplayError):
                replay.normalized_entries(self.normalized_path(records), self.rows)

    def test_normalized_source_identity_date_account_and_amount_corruption_is_refused(self):
        mutations = {
            "entry_id": "SRC-BLM-001:1ZA192:p31:l999",
            "source_row": "SRC-BLM-OTHER:1ZA192:p31:l16",
            "effective_date": "1992-12-08",
            "account_code": "BLMIS-CASH",
            "signed_amount": "-383000.01",
            "description": "Unattributed replacement",
        }
        for field, value in mutations.items():
            records = deepcopy(self.normalized)
            records[0][field] = value
            with self.subTest(field=field), self.assertRaises(replay.ledger.ReplayError):
                replay.normalized_entries(self.normalized_path(records), self.rows)

    def test_normalized_schema_and_extra_or_missing_csv_cells_are_refused(self):
        path = Path(self.directory.name) / "malformed.csv"
        original = (self.package / "legacy.csv").read_text(encoding="utf-8")
        records = original.splitlines(keepends=True)
        variants = {
            "header": original.replace("source_row\n", "unexpected\n", 1),
            "surplus_cell": records[0] + records[1].rstrip("\n") + ",unbound-extra\n" + "".join(records[2:]),
            "missing_memo_and_source": records[0] + ",".join(records[1].split(",")[:5]) + "\n" + "".join(records[2:]),
        }
        for name, content in variants.items():
            path.write_text(content, encoding="utf-8")
            with self.subTest(name=name), self.assertRaises(replay.ledger.ReplayError):
                replay.normalized_entries(path, self.rows)

    def test_normalized_provenance_memo_is_bound_to_the_source_location(self):
        records = deepcopy(self.normalized)
        records[0]["memo"] = "analysis counterpart; different source page and line"
        with self.assertRaises(replay.ledger.ReplayError):
            replay.normalized_entries(self.normalized_path(records), self.rows)

    def test_reported_transfer_amount_cannot_replace_trustee_principal_credit(self):
        row = next(row for row in self.originals if movement(row)
                   and row["description"].startswith("TRANS FROM")
                   and cents(row["reported_literal"]) != movement(row))
        records = deepcopy(self.normalized)
        replaced = 0
        for record in records:
            if record["source_row"] == row["row_id"]:
                value = cents(row["reported_literal"])
                if record["account_code"] == "BLMIS-1ZA192":
                    value = -value
                record["signed_amount"] = f"{Decimal(value) / Decimal(100):.2f}"
                replaced += 1
        self.assertEqual(replaced, 2)
        with self.assertRaises(replay.ledger.ReplayError):
            replay.normalized_entries(self.normalized_path(records), self.rows)

    def test_complete_report_is_compared_to_all_printed_controls(self):
        report, posted = comparator_inputs(self.originals)
        self.assertEqual(len(posted), 74)
        self.assertEqual(len({receipt["entry_digest"] for receipt in posted.values()}), 74)
        self.assertEqual(report["cells"][0]["closing"], "9947031.00 USD")
        running = 0
        for row in self.originals:
            running += movement(row)
            self.assertEqual(running, cents(row["printed_balance_literal"]), row["row_id"])
        replay.check_ledger(report, self.rows, posted)

    def test_missing_extra_and_duplicate_native_lines_are_refused(self):
        original, posted = comparator_inputs(self.originals)
        variants = {
            "missing": original["lines"][:-1],
            "extra": original["lines"] + [original["lines"][-1]],
            "duplicate": [original["lines"][0], original["lines"][0]] + original["lines"][2:],
        }
        for name, lines in variants.items():
            report = deepcopy(original)
            report["lines"] = deepcopy(lines)
            report["cells"][0]["line_count"] = len(lines)
            with self.subTest(name=name), self.assertRaises(replay.ledger.ReplayError):
                replay.check_ledger(report, self.rows, posted)

    def test_same_day_source_order_is_checked_despite_identical_dates(self):
        report, posted = comparator_inputs(self.originals)
        self.assertEqual(report["lines"][0]["effective_date"], report["lines"][1]["effective_date"])
        report["lines"][0], report["lines"][1] = report["lines"][1], report["lines"][0]
        with self.assertRaises(replay.ledger.ReplayError):
            replay.check_ledger(report, self.rows, posted)

    def test_amount_substitution_preserving_final_net_and_gross_totals_is_refused(self):
        report, posted = comparator_inputs(self.originals)
        first, second = report["lines"][:2]
        self.assertEqual(first["debits"], "0.00 USD")
        self.assertEqual(second["debits"], "0.00 USD")
        first["credits"] = amount(cents(self.originals[0]["reported_literal"]) + 1)
        second["credits"] = amount(cents(self.originals[1]["reported_literal"]) - 1)
        first["running_balance"] = amount(-cents(self.originals[0]["printed_balance_literal"]) - 1)
        with self.assertRaises(replay.ledger.ReplayError):
            replay.check_ledger(report, self.rows, posted)

    def test_native_line_identity_date_class_and_running_control_are_bound(self):
        mutations = {
            "entry_digest": "f" * 64, "leg_index": 1, "recorded_at": 1000,
            "effective_date": "1992-12-08", "class": "Adjusting",
            "account": "BLMIS-CASH", "unit": "EUR", "running_balance": "-383000.01 USD",
        }
        for field, value in mutations.items():
            report, posted = comparator_inputs(self.originals)
            report["lines"][0][field] = value
            with self.subTest(field=field), self.assertRaises(replay.ledger.ReplayError):
                replay.check_ledger(report, self.rows, posted)

    def test_wrong_missing_or_extra_source_receipts_are_rejected(self):
        report, original = comparator_inputs(self.originals)
        first, second = list(original)[:2]
        wrong_key = deepcopy(original)
        wrong_key["SRC-BLM-OTHER:1ZA192:p31:l16"] = wrong_key.pop(first)
        missing = deepcopy(original)
        missing.pop(first)
        extra = deepcopy(original)
        extra["not-a-source-row"] = {"entry_digest": "e" * 64, "recorded_at": 9999}
        exchanged = deepcopy(original)
        exchanged[first], exchanged[second] = exchanged[second], exchanged[first]
        for name, posted in (("wrong_key", wrong_key), ("missing", missing), ("extra", extra), ("exchanged", exchanged)):
            with self.subTest(name=name), self.assertRaises((replay.ledger.ReplayError, KeyError)):
                replay.check_ledger(report, self.rows, posted)

    def test_native_report_scope_currency_and_rollforward_controls_are_checked(self):
        for field, value in (("label", "another-scope"), ("effective_from", "1992-12-08"),
                             ("effective_through", "2008-10-31")):
            report, posted = comparator_inputs(self.originals)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(replay.ledger.ReplayError):
                replay.check_ledger(report, self.rows, posted)
        for field, value in (("account", "BLMIS-CASH"), ("unit", "EUR"), ("opening", "0.01 USD"),
                             ("debits", "20924380.01 USD"), ("credits", "10977349.01 USD"),
                             ("net_change", "9947031.01 USD"), ("closing", "9947031.01 USD"),
                             ("line_count", 73)):
            report, posted = comparator_inputs(self.originals)
            report["cells"][0][field] = value
            with self.subTest(field=field), self.assertRaises(replay.ledger.ReplayError):
                replay.check_ledger(report, self.rows, posted)
        for count in (0, 2):
            report, posted = comparator_inputs(self.originals)
            report["cells"] *= count
            with self.subTest(cell_count=count), self.assertRaises(replay.ledger.ReplayError):
                replay.check_ledger(report, self.rows, posted)

    def test_native_amount_units_are_checked_inside_every_amount_field(self):
        for target, fields in (("cell", ("opening", "debits", "credits", "net_change", "closing")),
                               ("line", ("debits", "credits", "running_balance"))):
            for field in fields:
                report, posted = comparator_inputs(self.originals)
                cell = report["cells"][0] if target == "cell" else report["lines"][0]
                cell[field] = cell[field].replace("USD", "EUR")
                with self.subTest(target=target, field=field), self.assertRaises(replay.ledger.ReplayError):
                    replay.check_ledger(report, self.rows, posted)

    def test_empty_historical_prefix_has_zero_activity_and_no_later_lines(self):
        empty, posted = comparator_inputs(self.originals, empty=True)
        replay.check_ledger(empty, self.rows, posted, empty=True)
        nonempty, _ = comparator_inputs(self.originals)
        for name in ("later_line", "closing", "gross_activity", "opening"):
            report = deepcopy(empty)
            if name == "later_line":
                report["lines"] = [nonempty["lines"][0]]
                report["cells"][0]["line_count"] = 1
            else:
                field = "debits" if name == "gross_activity" else name
                report["cells"][0][field] = "0.01 USD"
            with self.subTest(name=name), self.assertRaises(replay.ledger.ReplayError):
                replay.check_ledger(report, self.rows, posted, empty=True)

    def certified_inputs(self):
        data, posted = comparator_inputs(self.originals)
        # These identifiers and encoded events test orchestration only. They
        # are not cryptographic certificates and are never sent to fa-verify.
        certificate = {"oid": "unit-only-certificate", "output_digest": "unit-only-output",
                       "output_format": "fa:roll-forward:v1"}
        report = {"event": "general_ledger", "certificate": certificate["oid"], "data": data}
        events = [report, {"event": "report_certificate", "data": certificate}]
        first = (json.dumps(report, sort_keys=True) + "\n").encode()
        encoded = first + (json.dumps(events[1], sort_keys=True) + "\n").encode()
        native = mock.Mock(spec=replay.ledger.Native)
        native.command.side_effect = lambda *args: [str(arg) for arg in args]
        native.execute_events.side_effect = [(events, encoded), ([report], first)]
        return native, posted, events, encoded, first

    def test_certified_report_replays_the_identical_account_date_and_known_at_scope(self):
        native, posted, events, _, _ = self.certified_inputs()
        result = replay.check_certified_ledger(native, self.rows, posted)
        self.assertEqual(result["compared_native_lines"], 74)
        self.assertEqual(result["known_at"], 2000)
        commands = [call.args[0] for call in native.execute_events.call_args_list]
        arguments = ["--account", "BLMIS-1ZA192", "--unit", "USD", "--from", "1992-12-07",
                     "--to", "2008-10-30", "--label", "blmis-glantz-1za192-published-principal"]
        self.assertEqual(commands[0], ["gl", "detail", *arguments, "--certify"])
        self.assertEqual(commands[1], ["replay", "C:unit-only-certificate", "--view", "detail",
                                      *arguments, "--as-known-at", str(events[0]["data"]["known_at"])])

    def test_certified_report_rejects_wrong_event_order_or_missing_certificate(self):
        for name in ("missing", "reversed", "extra", "wrong_event"):
            native, posted, events, encoded, _ = self.certified_inputs()
            changed = deepcopy(events)
            if name == "missing":
                changed.pop()
            elif name == "reversed":
                changed.reverse()
            elif name == "extra":
                changed.append(deepcopy(events[0]))
            else:
                changed[0]["event"] = "trial_balance"
            native.execute_events.side_effect = [(changed, encoded)]
            with self.subTest(name=name), self.assertRaises(replay.ledger.ReplayError):
                replay.check_certified_ledger(native, self.rows, posted)

    def test_certificate_format_binding_and_exact_replay_bytes_are_required(self):
        for name in ("format", "binding", "bytes", "event_count"):
            native, posted, events, encoded, first = self.certified_inputs()
            if name == "format":
                events[1]["data"]["output_format"] = "fa:other-report:v1"
            elif name == "binding":
                events[0]["certificate"] = "different-certificate"
            replay_events = [events[0], events[0]] if name == "event_count" else [events[0]]
            replay_bytes = first.replace(b"1992-12-07", b"1992-12-08") if name == "bytes" else first
            native.execute_events.side_effect = [(events, encoded), (replay_events, replay_bytes)]
            with self.subTest(name=name), self.assertRaises(replay.ledger.ReplayError):
                replay.check_certified_ledger(native, self.rows, posted)

    def test_missing_native_binary_is_unrun_and_creates_no_output(self):
        output = Path(self.directory.name) / "must-not-create"
        absent = Path(self.directory.name) / "missing-fa-executable"
        with mock.patch.object(replay, "run_native") as run, redirect_stderr(io.StringIO()) as error:
            status = replay.main(["run", "--out", str(output), "--fa", str(absent), "--fa-verify", str(absent)])
        self.assertEqual(status, 4)
        self.assertEqual(json.loads(error.getvalue())["status"], "UNRUN")
        self.assertFalse(output.exists())
        run.assert_not_called()

    def test_native_run_consumes_current_pdf_extraction_before_constructing_native_client(self):
        # Stop before any accounting execution. This verifies source flow and
        # ordering only, not a successful native posting or proof-verifier run.
        class ReachedNative(Exception):
            pass

        raw = (source.FIXTURE_DIR / "rows.csv").read_bytes()
        metadata = (source.FIXTURE_DIR / "source.json").read_bytes()

        def extraction(path, *, layout_out):
            self.assertEqual(path.read_bytes(), b"%PDF-unit-only-input")
            layout_out.write_bytes(b"unit-only extractor stream\n")
            return raw, metadata

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "pdf-first"

            def stop_at_native(binary, verifier, directory):
                self.assertEqual(directory, output)
                for name in ("source.pdf", "extracted-source/layout.txt", "extracted-source/rows.csv",
                             "extracted-source/source.json", "legacy.csv", "manifest.json", "extraction.json"):
                    self.assertTrue((output / name).is_file(), name)
                self.assertFalse((output / "book").exists())
                raise ReachedNative()

            with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-unit-only-input"), \
                    mock.patch.object(source, "extract_pdf", side_effect=extraction) as extract, \
                    mock.patch.object(source, "load_fixture", wraps=source.load_fixture) as load, \
                    mock.patch.object(source, "prepare") as fallback, \
                    mock.patch.object(replay.ledger, "Native", side_effect=stop_at_native) as native:
                with self.assertRaises(ReachedNative):
                    replay.run_native(Path(sys.executable), Path(sys.executable), output, Path(tmp) / "provided.pdf")
            native.assert_called_once_with(Path(sys.executable), Path(sys.executable), output)
            extract.assert_called_once_with(output / "source.pdf", layout_out=output / "extracted-source/layout.txt")
            self.assertEqual(load.call_args_list, [mock.call(output / "extracted-source")] * 2)
            fallback.assert_not_called()

    def test_pdf_drift_and_unavailable_extraction_refuse_before_native_without_fixture_fallback(self):
        outcomes = (
            ("drift", mock.Mock(returncode=0, stdout=b"changed extraction layout\n"), None, 1, "FAIL"),
            ("unavailable", None, FileNotFoundError("pdftotext"), 4, "UNRUN"),
        )
        for name, result, exception, expected_exit, expected_status in outcomes:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "refused"
                with mock.patch.object(source, "verify_pdf", return_value=b"%PDF-unit-only-input"), \
                        mock.patch.object(source.subprocess, "run", return_value=result, side_effect=exception), \
                        mock.patch.object(source, "prepare") as fallback, \
                        mock.patch.object(replay.ledger, "Native") as native, \
                        redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error:
                    status = replay.main(["run", "--out", str(output), "--pdf", str(Path(tmp) / "provided.pdf"),
                                          "--fa", sys.executable, "--fa-verify", sys.executable])
                self.assertEqual(status, expected_exit)
                self.assertEqual(json.loads(error.getvalue())["status"], expected_status)
                self.assertEqual(json.loads((output / "failure.json").read_bytes())["status"], expected_status)
                self.assertTrue((output / "source.pdf").is_file())
                self.assertFalse((output / "book").exists())
                self.assertFalse((output / "legacy.csv").exists())
                self.assertFalse((output / "report.json").exists())
                if name == "drift":
                    self.assertEqual((output / "extracted-source/layout.txt").read_bytes(), result.stdout)
                else:
                    self.assertIn("install Poppler", error.getvalue())
                fallback.assert_not_called()
                native.assert_not_called()

    def test_concurrent_output_creator_keeps_ownership_and_receives_no_failure_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "another-run"
            existing = {"existing-evidence.txt": b"retained by another invocation\n"}

            def verify_while_another_run_creates_output(_path):
                # This happens after prepare_pdf's initial existence check,
                # before its exclusive mkdir. Only the other run owns it.
                output.mkdir()
                for name, raw in existing.items():
                    (output / name).write_bytes(raw)
                return b"%PDF-unit-only-input"

            with mock.patch.object(source, "verify_pdf", side_effect=verify_while_another_run_creates_output), \
                    mock.patch.object(source, "extract_pdf") as extract, \
                    mock.patch.object(replay.ledger, "Native") as native, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error:
                status = replay.main(["run", "--out", str(output), "--pdf", str(Path(tmp) / "provided.pdf"),
                                      "--fa", sys.executable, "--fa-verify", sys.executable])
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(error.getvalue())["status"], "FAIL")
            self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, existing)
            extract.assert_not_called()
            native.assert_not_called()

    def test_existing_output_is_preserved_even_on_an_execution_failure(self):
        original = {path.name: path.read_bytes() for path in self.package.iterdir()}
        with mock.patch.object(replay.ledger, "Native") as native, redirect_stderr(io.StringIO()) as error, \
                redirect_stdout(io.StringIO()):
            status = replay.main(["run", "--out", str(self.package),
                                  "--fa", sys.executable, "--fa-verify", sys.executable])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(error.getvalue())["status"], "FAIL")
        self.assertIn("already exists", json.loads(error.getvalue())["error"])
        self.assertEqual({path.name: path.read_bytes() for path in self.package.iterdir()}, original)
        native.assert_not_called()


def six_account_test_inputs(originals):
    """Construct unit inputs from raw cells; no native execution is represented."""
    ordered = deepcopy(originals)
    # Independently spell out the single reviewed source display exception.
    check = next(i for i, row in enumerate(ordered)
                 if row["account"] == "1ZB010" and int(row["pdf_page"]) == 35 and int(row["source_line"]) == 38)
    stop = next(i for i, row in enumerate(ordered)
                if row["account"] == "1ZB010" and int(row["pdf_page"]) == 35 and int(row["source_line"]) == 39)
    assert stop == check + 1
    assert ordered[check]["description"] == "CHECK" and ordered[stop]["description"] == "STOP PAYMENT"
    ordered[check], ordered[stop] = ordered[stop], ordered[check]
    groups, posted = {}, {}
    for index, row in enumerate(ordered, 1):
        groups.setdefault(row["account"], []).append(row)
        if movement(row):
            posted[row["row_id"]] = {
                "vid": hashlib.sha256(("unit-vid-only:" + row["row_id"]).encode()).hexdigest()[:32],
                "entry_digest": hashlib.sha256(("unit-digest-only:" + row["row_id"]).encode()).hexdigest(),
                "recorded_at": 1000 + index,
            }
    reports = {}
    for account, history in groups.items():
        principal, debits, credits, lines = 0, 0, 0, []
        for row in history:
            value = movement(row)
            principal += value
            if value == 0:
                continue
            receipt = posted[row["row_id"]]
            debits += max(-value, 0)
            credits += max(value, 0)
            lines.append({"entry_digest": receipt["entry_digest"], "recorded_at": receipt["recorded_at"],
                          "leg_index": 0, "effective_date": source_date(row), "class": "Original",
                          "account": f"BLMIS-{account}", "unit": "USD",
                          "debits": amount(max(-value, 0)), "credits": amount(max(value, 0)),
                          "running_balance": amount(-principal)})
        reports[account] = {"oid": f"unit-only-certificate-{account}", "native_report": {
            "label": f"blmis-glantz-{account.lower()}-published-principal", "known_at": 2000,
            "effective_from": source_date(history[0]), "effective_through": source_date(history[-1]),
            "cells": [{"account": f"BLMIS-{account}", "unit": "USD", "opening": amount(0),
                       "debits": amount(debits), "credits": amount(credits), "net_change": amount(-principal),
                       "closing": amount(-principal), "line_count": len(lines)}], "lines": lines}}
    return ordered, groups, posted, reports


def six_account_analysis_input(originals, *, include_transfers):
    """Independent raw-literal expectations for the native-shaped unit input."""
    positions = {}
    population = 0
    for row in originals:
        account = row["account"]
        values = positions.setdefault(account, {"in": 0, "out": 0, "tin": 0, "tout": 0, "dates": []})
        cash = cents(row["deposits_literal"]) + cents(row["withdrawals_literal"])
        transfer = (cents(row["transfers_in_literal"]) + cents(row["transfers_out_literal"])) if include_transfers else 0
        if cash > 0:
            values["in"] += cash
        else:
            values["out"] -= cash
        if transfer > 0:
            values["tin"] += transfer
        else:
            values["tout"] -= transfer
        if cash > 0 or transfer > 0:
            values["dates"].append(date.fromisoformat(source_date(row)))
        if cash != 0 or transfer != 0:
            population += 1
    first_date = min(at for item in positions.values() for at in item["dates"])
    findings = []
    for account, item in positions.items():
        principal = item["in"] + item["tin"] - item["out"] - item["tout"]
        if principal == 0:
            continue
        cohort = (min(item["dates"]) - first_date).days // 90 + 1 if item["dates"] else 1
        if principal < 0:
            name, status = "fictitious_profit_clawback", "net_winner"
        else:
            name, status = "net_equity_claim", "net_loser"
        findings.append({"statistic": {"name": name, "value": abs(principal), "scale": 2, "population": population},
                         "narrative": (f"investor BLMIS-{account} (cohort {cohort}, status={status}): "
                                       f"cash_in={item['in']}, cash_out={item['out']}, transfer_in={item['tin']}, "
                                       f"transfer_out={item['tout']}, {name}={abs(principal)}, "
                                       "principal_rule=posted_principal_transfer_v1, attribution=complete")})
    return {"event": "procedure_run", "data": {"procedure": "ponzi.net_investment", "version": 5,
            "claim": "statistical", "known_at": 2000, "effective_through": max(source_date(row) for row in originals),
            "finding_count": len(findings), "findings": findings}}


class GlantzSixAccountReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pdf = os.environ.get("FA_BLMIS_GLANTZ_PDF")
        if not pdf:
            raise unittest.SkipTest("six-account source comparisons require FA_BLMIS_GLANTZ_PDF pointing to the pinned original; not native execution")
        cls.directory = tempfile.TemporaryDirectory(prefix="fa-glantz-six-comparator-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.package = Path(cls.directory.name) / "package"
        cls.manifest = source.prepare_glantz(cls.package, pdf=Path(pdf))
        cls.rows, cls.metadata = source.load_glantz_fixture(cls.package)
        with (cls.package / "rows.csv").open(encoding="utf-8", newline="") as stream:
            cls.originals = list(csv.DictReader(stream, strict=True))
        cls.ordered_originals, cls.original_groups, cls.posted, cls.reports = six_account_test_inputs(cls.originals)
        cls.ordered = source.glantz_computation_order(cls.rows)
        cls.groups = replay.grouped_accounts(cls.ordered)

    def test_all_379_source_observations_map_to_372_native_intents_and_744_legs(self):
        entries = replay.normalized_entries(self.package / "legacy.csv", self.ordered)
        monetary = [row for row in self.ordered_originals if movement(row)]
        self.assertEqual(len(self.originals), 379)
        self.assertEqual(len(entries), 372)
        self.assertEqual(sum(len(entry["legs"]) for entry in entries), 744)
        self.assertEqual([entry["idempotency_key"] for entry in entries], [row["row_id"] for row in monetary])
        for row, entry in zip(monetary, entries, strict=True):
            principal, contra = entry["legs"]
            self.assertEqual(principal["party"], f"BLMIS-{row['account']}")
            self.assertEqual(principal["account"], principal["party"])
            self.assertEqual(principal["amount"], amount(abs(movement(row))))
            self.assertEqual(principal["side"], "credit" if movement(row) > 0 else "debit")
            self.assertNotIn("party", contra)
            self.assertEqual(contra["amount"], principal["amount"])
            self.assertNotEqual(contra["side"], principal["side"])
        self.assertEqual(set(self.manifest["zero_principal_rows"]),
                         {row["row_id"] for row in self.originals if not movement(row)})
        self.assertEqual(len(self.manifest["zero_principal_rows"]), 7)

    def test_every_native_account_line_is_compared_with_the_exact_source_discrepancy(self):
        expected_off = {"1T0026": 0, "1ZA192": 0, "1ZB010": 0, "1ZB143": 0, "1ZR010": 50, "1ZR176": 12}
        for account, rows in self.groups.items():
            with self.subTest(account=account):
                report = self.reports[account]["native_report"]
                receipts = {row["row_id"]: self.posted[row["row_id"]] for row in rows if movement(row)}
                gaps = replay.printed_gaps(rows)
                self.assertEqual(len(gaps), expected_off[account])
                replay.check_ledger(report, rows, receipts, published_gaps=gaps, label=report["label"])
                if gaps:
                    with self.assertRaises(replay.ledger.ReplayError):
                        replay.check_ledger(report, rows, receipts, label=report["label"])
                    changed = dict(gaps)
                    changed[next(iter(changed))] += 1
                    with self.assertRaises(replay.ledger.ReplayError):
                        replay.check_ledger(report, rows, receipts, published_gaps=changed, label=report["label"])
        self.assertEqual(replay.printed_gaps(self.groups["1ZR010"])[self.groups["1ZR010"][-1]["row_id"]], 900)
        self.assertEqual(set(replay.printed_gaps(self.groups["1ZR176"]).values()), {-100})

    def test_stopped_check_keeps_signed_cash_and_only_the_named_same_day_order_changes(self):
        self.assertEqual([row["row_id"] for row in self.ordered], [row["row_id"] for row in self.ordered_originals])
        changed_positions = [i for i, (before, after) in enumerate(zip(self.originals, self.ordered_originals, strict=True))
                             if before["row_id"] != after["row_id"]]
        self.assertEqual(len(changed_positions), 2)
        stop = next(row for row in self.originals if row["description"] == "STOP PAYMENT")
        self.assertEqual(cents(stop["withdrawals_literal"]), 2_500_000)
        entries = replay.normalized_entries(self.package / "legacy.csv", self.ordered)
        entry = next(entry for entry in entries if entry["idempotency_key"] == stop["row_id"])
        self.assertEqual([(leg["account"], leg["side"], leg["amount"]) for leg in entry["legs"]],
                         [("BLMIS-1ZB010", "credit", "25000.00 USD"), ("BLMIS-CASH", "debit", "25000.00 USD")])
        self.assertNotIn("reverses", entry, "the source never names the stopped check's native identity")
        raw_order = [row for row in self.rows if row["account"] == "1ZB010"]
        report = self.reports["1ZB010"]["native_report"]
        receipts = {row["row_id"]: self.posted[row["row_id"]] for row in raw_order if movement(row)}
        with self.assertRaises(replay.ledger.ReplayError):
            replay.check_ledger(report, raw_order, receipts, label=report["label"])

    def test_both_paired_credits_recompute_from_native_shaped_originating_balances(self):
        pairs = replay.check_transfer_pairs(self.ordered, self.reports, self.posted)
        self.assertEqual([pair["originating_principal_cents"] for pair in pairs], [485_500_000, -485_468_800])
        self.assertEqual([pair["statement_amount_cents"] for pair in pairs], [400_000_000, 20_000_000])
        self.assertEqual([pair["credited_principal_cents"] for pair in pairs], [400_000_000, 0])
        self.assertTrue(all(pair["rule"] == "trustee_transfer_credit" for pair in pairs))
        self.assertTrue(all(pair["originating_certificate"].startswith("unit-only-") for pair in pairs))
        for pair in pairs:
            self.assertIn(pair["native_originating_balance_row_id"], self.posted)
        for field in ("running_balance", "entry_digest", "recorded_at"):
            changed = deepcopy(self.reports)
            basis = self.posted[pairs[0]["native_originating_balance_row_id"]]
            line = next(item for item in changed["1ZA192"]["native_report"]["lines"]
                        if item["entry_digest"] == basis["entry_digest"])
            line[field] = {"running_balance": "-4854999.99 USD", "entry_digest": "f" * 64, "recorded_at": 999}[field]
            with self.subTest(field=field), self.assertRaises(replay.ledger.ReplayError):
                replay.check_transfer_pairs(self.ordered, changed, self.posted)

    def test_transfer_pair_cannot_invent_missing_history_or_substitute_statement_credit(self):
        for mutation in ("missing_counterpart", "ambiguous_counterpart", "reported_amount", "principal_credit"):
            rows = deepcopy(self.ordered)
            selected = next(row for row in rows if row["account"] == "1ZA192" and row["date"] == "2005-12-23")
            if mutation == "missing_counterpart":
                rows.remove(selected)
            elif mutation == "ambiguous_counterpart":
                rows.append(deepcopy(selected))
            elif mutation == "reported_amount":
                selected["reported_cents"] += 100
            else:
                selected["transfers_in_cents"] = selected["reported_cents"]
            with self.subTest(mutation=mutation), self.assertRaises(replay.ledger.ReplayError):
                replay.check_transfer_pairs(rows, self.reports, self.posted)

    def test_all_six_native_principal_outcomes_preserve_source_balances_and_gaps(self):
        complete = replay.check_glantz_principal_analysis(
            six_account_analysis_input(self.originals, include_transfers=True), self.ordered, 2000, include_transfers=True)
        missing = replay.check_glantz_principal_analysis(
            six_account_analysis_input(self.originals, include_transfers=False), self.ordered, 2000, include_transfers=False)
        self.assertEqual(complete["population"], 372)
        self.assertEqual(missing["population"], 362)
        self.assertEqual(set(complete["source_accounts"]), set(self.groups))
        positions = complete["source_accounts"]
        self.assertEqual(positions["1ZR176"]["native_principal_cents"], -281_796_500)
        self.assertTrue(positions["1ZR176"]["native_finding_expected"])
        self.assertEqual(complete["native_report"]["data"]["finding_count"], 6)
        self.assertEqual(positions["1ZR010"]["gap_from_printed_principal_cents"], 900)
        self.assertEqual(positions["1ZB010"]["cash_in_cents"], 124_500_000)
        self.assertEqual(positions["1ZB010"]["cash_out_cents"], 155_250_000)
        deltas = {account: position["native_principal_cents"] - missing["source_accounts"][account]["native_principal_cents"]
                  for account, position in positions.items()}
        self.assertEqual(deltas, {"1T0026": 238_426_600, "1ZA192": -346_263_400, "1ZB010": -20_000_000,
                                  "1ZB143": 395_500_000, "1ZR010": 0, "1ZR176": 0})

    def test_six_account_principal_comparison_refuses_missing_extra_swapped_or_changed_findings(self):
        for mutation in ("missing", "duplicate", "wrong_party", "wrong_cohort", "cash_as_transfer",
                         "population", "amount", "zero_finding", "wrong_scope"):
            report = six_account_analysis_input(self.originals, include_transfers=True)
            finding = report["data"]["findings"][0]
            if mutation == "missing":
                report["data"]["findings"].pop()
            elif mutation in ("duplicate", "zero_finding"):
                extra = deepcopy(finding)
                if mutation == "zero_finding":
                    extra["narrative"] = extra["narrative"].replace("BLMIS-1T0026", "BLMIS-1ZR176")
                    extra["statistic"]["value"] = 0
                report["data"]["findings"].append(extra)
            elif mutation == "wrong_party":
                finding["narrative"] = finding["narrative"].replace("BLMIS-1T0026", "BLMIS-1ZA192")
            elif mutation == "wrong_cohort":
                finding["narrative"] = re.sub(r"cohort [0-9]+,", "cohort 999999,", finding["narrative"])
            elif mutation == "cash_as_transfer":
                finding["narrative"] = finding["narrative"].replace("transfer_in=", "cash_in=")
            elif mutation == "population":
                finding["statistic"]["population"] = 379
            elif mutation == "amount":
                finding["statistic"]["value"] += 1
            else:
                report["data"]["effective_through"] = "2008-10-29"
            report["data"]["finding_count"] = len(report["data"]["findings"])
            with self.subTest(mutation=mutation), self.assertRaises(replay.ledger.ReplayError):
                replay.check_glantz_principal_analysis(report, self.ordered, 2000, include_transfers=True)

    def test_all_744_export_legs_keep_separate_native_party_dimensions(self):
        parties = {account: {"code": f"BLMIS-{account}", "vid": f"{index + 100:032x}",
                             "dimension": 12, "value": f"{index + 200:032x}"}
                   for index, account in enumerate(sorted(self.groups))}
        base_records = []
        for row in self.ordered_originals:
            delta = movement(row)
            if not delta:
                continue
            receipt = self.posted[row["row_id"]]
            cash = cents(row["deposits_literal"]) + cents(row["withdrawals_literal"])
            transfer = cents(row["transfers_in_literal"]) + cents(row["transfers_out_literal"])
            contra = ("BLMIS-CASH", cash) if cash else ("BLMIS-TRANSFER", transfer)
            for ordinal, (account, value) in enumerate([(f"BLMIS-{row['account']}", -delta), contra], 1):
                memo = (f"analysis counterpart; SRC-BLM-001 Exhibit {row['exhibit']} "
                        f"PDF p{row['pdf_page']} line {row['source_line']}")
                base_records.append([receipt["vid"], str(ordinal), source_date(row), str(receipt["recorded_at"]),
                                     "1", account, "D" if value > 0 else "C", amount(abs(value)).split()[0],
                                     "USD", "2", row["description"], "", memo,
                                     "12:" + parties[row["account"]]["value"] if ordinal == 1 else ""])
        self.assertEqual(len(base_records), 744)
        for format_name in ("csv-gl", "ads"):
            for mutation in (None, "swap_party", "omit_account", "tag_clearing", "money", "extra",
                             "description", "memo", "other_exhibit", "migrated_from"):
                records = deepcopy(base_records)
                if format_name == "ads":
                    for record in records:
                        record[11] = r"\N"
                if mutation == "swap_party":
                    records[0][13] = "12:" + parties["1ZA192"]["value"]
                elif mutation == "omit_account":
                    ids = {receipt["vid"] for row_id, receipt in self.posted.items() if ":1ZR176:" in row_id}
                    records = [record for record in records if record[0] not in ids]
                elif mutation == "tag_clearing":
                    records[1][13] = records[0][13]
                elif mutation == "money":
                    records[-1][7] = f"{Decimal(records[-1][7]) + Decimal('0.01'):.2f}"
                elif mutation == "extra":
                    records.append(list(records[-1]))
                elif mutation == "description":
                    records[-1][10] = "unattributed native replacement"
                elif mutation == "memo":
                    records[-1][12] = ""
                elif mutation == "other_exhibit":
                    self.assertIn("Exhibit B-6", records[-1][12])
                    records[-1][12] = records[-1][12].replace("Exhibit B-6", "Exhibit B-2")
                elif mutation == "migrated_from":
                    records[-1][11] = "invented migration provenance"
                path = Path(self.directory.name) / f"six-export-{format_name}-{mutation}" / "GL_Detail.txt"
                path.parent.mkdir()
                if format_name == "csv-gl":
                    with path.open("w", encoding="utf-8", newline="") as stream:
                        stream.write("# fa_csv_gl_v1|book=unit-only-six-account|dimension_encoding=fa-dimension-ids-v1\n")
                        writer = csv.writer(stream, lineterminator="\n")
                        writer.writerow(replay.ledger.CSV_GL_COLUMNS)
                        writer.writerows(records)
                else:
                    (path.parent / "ADS_Coordinate_Certificate.toml").write_text(
                        'schema_version = 1\nformat = "aicpa_ads_gl_v3"\ndimension_encoding = "fa-dimension-ids-v1"\n',
                        encoding="utf-8")
                    path.write_text("|".join(replay.ledger.ADS_GL_COLUMNS) + "\n"
                                    + "".join("|".join(record) + "\n" for record in records), encoding="utf-8")
                with self.subTest(format=format_name, mutation=mutation):
                    if mutation is None:
                        result = replay.verify_source_export(path, format_name, self.ordered, self.posted, parties)
                        self.assertEqual(result["rows"], 744)
                        self.assertEqual(result["tagged_rows"], 372)
                        self.assertEqual(result["parties"], sorted(item["code"] for item in parties.values()))
                    else:
                        with self.assertRaises(replay.ledger.ReplayError):
                            replay.verify_source_export(path, format_name, self.ordered, self.posted, parties)

    def test_all_account_cli_requires_native_binaries_and_never_reports_comparator_tests_as_execution(self):
        output = Path(self.directory.name) / "six-missing-binary"
        absent = Path(self.directory.name) / "absent-native-executable"
        with mock.patch.object(replay, "run_glantz_native") as run, redirect_stderr(io.StringIO()) as error:
            status = replay.main(["run", "--account", "all", "--out", str(output),
                                  "--fa", str(absent), "--fa-verify", str(absent)])
        self.assertEqual(status, 4)
        self.assertEqual(json.loads(error.getvalue())["status"], "UNRUN")
        self.assertFalse(output.exists())
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
