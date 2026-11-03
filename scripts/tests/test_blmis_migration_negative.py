"""Monetary-twin comparator units; fabricated envelopes never claim native execution."""
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
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_migration_negative as twin


TARGET_ROW = {"row_id": "SRC-BLM-001:1T0026:p27:l16", "account": "1T0026", "date": "1992-11-19",
              "description": "CHECK WIRE", "principal_movement_cents": 280000000,
              "pdf_page": 27, "source_line": 16, "exhibit": "B-1"}


def rendered(cents):
    return f"{Decimal(cents) / 100:.2f} USD"


class ComparatorUnits(unittest.TestCase):
    def setUp(self):
        self.members = {f"{n:032x}": {"proposal_digest": hashlib.sha256(f"unit-only-{n}".encode()).hexdigest(),
                                     "recorded_at": n + 40} for n in range(1, 4)}
        self.expected = [{"period": "FY1992-P11", "account_code": "BLMIS-1T0026", "unit": "USD",
                          "declared": "-5100000.00 USD", "folded": "-5100001.00 USD"},
                         {"period": "FY1992-P11", "account_code": "BLMIS-MIGRATION-OFFSET", "unit": "USD",
                          "declared": "4612161.00 USD", "folded": "4612162.00 USD"}]
        self.event = {"event": "migration_run", "data": {
            "run_vid": "a" * 32, "mode": "FullDetail", "state": "Open", "chunk_count": 3,
            "chunks": [{"vid": vid, **value} for vid, value in self.members.items()],
            "ties_out": False, "mismatches": deepcopy(self.expected)}}

    def test_only_balanced_amounts_differ_between_manual_twins(self):
        original = twin.chunk_intent(TARGET_ROW, "a" * 32, "source", ["b" * 64], 0)
        changed = twin.chunk_intent(TARGET_ROW, "a" * 32, "source", ["b" * 64], 100)
        self.assertEqual([leg["side"] for leg in changed["legs"]], ["credit", "debit"])
        self.assertEqual([leg["amount"] for leg in original["legs"]], ["2800000.00 USD"] * 2)
        self.assertEqual([leg["amount"] for leg in changed["legs"]], ["2800001.00 USD"] * 2)
        for leg in original["legs"]:
            leg["amount"] = "2800001.00 USD"
        self.assertEqual(original, changed)
        self.assertEqual(changed["source_id"], TARGET_ROW["row_id"])
        self.assertEqual(changed["effective_period"], "FY1992-P11")
        self.assertEqual(changed["document_date"], "1992-11-19")

    def test_mutation_rejects_other_sizes_and_boolean_amounts(self):
        for delta in (True, -100, 1, 101, 100.0):
            with self.subTest(delta=delta), self.assertRaises(twin.live.CheckError):
                twin.chunk_intent(TARGET_ROW, "a" * 32, "source", [], delta)

    def test_source_target_requires_original_identity_amount_and_date(self):
        self.assertEqual(twin.target_row([TARGET_ROW]), TARGET_ROW)
        for field, value in (("date", "1992-11-20"), ("description", "ALTERED"),
                             ("principal_movement_cents", 280000100), ("account", "1ZA192")):
            row = {**TARGET_ROW, field: value}
            with self.subTest(field=field), self.assertRaises(twin.live.CheckError):
                twin.target_row([row])
        for rows in ([], [TARGET_ROW, TARGET_ROW]):
            with self.assertRaises(twin.live.CheckError):
                twin.target_row(rows)

    def test_complete_native_shaped_mismatch_matrix_accepts_order_independently(self):
        changed = deepcopy(self.event)
        changed["data"]["mismatches"].reverse()
        twin.check_run(changed, "a" * 32, self.members, self.expected)

    def test_mismatches_reject_missing_extra_duplicate_wrong_amount_period_unit_account(self):
        edits = [lambda values: values.pop(), lambda values: values.append(deepcopy(values[0])),
                 lambda values: values[0].update(folded="-5100002.00 USD"),
                 lambda values: values[0].update(declared="-5100001.00 USD"),
                 lambda values: values[0].update(period="FY1992-P12"),
                 lambda values: values[0].update(unit="GBP"),
                 lambda values: values[0].update(account_code="BLMIS-1ZA192"),
                 lambda values: values[0].update(extra="unrecognized")]
        for edit in edits:
            event = deepcopy(self.event)
            edit(event["data"]["mismatches"])
            with self.subTest(edit=edit), self.assertRaises(twin.live.CheckError):
                twin.check_run(event, "a" * 32, self.members, self.expected)

    def test_population_requires_every_original_native_receipt(self):
        edits = [lambda value: value["chunks"].pop(),
                 lambda value: value["chunks"].append(deepcopy(value["chunks"][0])),
                 lambda value: value["chunks"][0].update(proposal_digest="c" * 64),
                 lambda value: value["chunks"][0].update(recorded_at=99),
                 lambda value: value.update(chunk_count=2), lambda value: value.update(state="Finalized"),
                 lambda value: value.update(mode="OpeningOnly"), lambda value: value.update(ties_out=True)]
        for edit in edits:
            event = deepcopy(self.event)
            edit(event["data"])
            with self.subTest(edit=edit), self.assertRaises(twin.live.CheckError):
                twin.check_run(event, "a" * 32, self.members, self.expected)

    def test_positive_requires_zero_mismatches_and_a_true_tieout(self):
        event = deepcopy(self.event)
        event["data"].update(mismatches=[], ties_out=True)
        twin.check_run(event, "a" * 32, self.members, [])
        event["data"]["ties_out"] = False
        with self.assertRaises(twin.live.CheckError):
            twin.check_run(event, "a" * 32, self.members, [])

    def refusal(self):
        message = "the run's chunks do not fold to its declared trial balance (2 line(s), in debit sign): "
        message += ("`BLMIS-1T0026` USD through `FY1992-P11`: declared -5100000.00 USD, folded -5100001.00 USD; "
                    "`BLMIS-MIGRATION-OFFSET` USD through `FY1992-P11`: declared 4612161.00 USD, folded 4612162.00 USD")
        return {"event": "error", "data": {"exit": 3, "class": "refusal", "refusal_id": "FA-REF-131", "message": message}}

    def test_refusal_requires_exact_monetary_law_and_every_named_cell(self):
        twin.check_monetary_refusal(self.refusal(), self.expected)
        for edit in (lambda d: d.update(exit=4), lambda d: d.update(refusal_id="FA-REF-012"),
                     lambda d: d.update(message="371 chunks; source completeness refused"),
                     lambda d: d.update(message=d["message"].replace("folded -5100001.00", "folded -5100002.00")),
                     lambda d: d.update(message=d["message"].split("; ")[0])):
            event = self.refusal()
            edit(event["data"])
            with self.subTest(edit=edit), self.assertRaises(twin.live.CheckError):
                twin.check_monetary_refusal(event, self.expected)

    def test_cold_copy_preserves_bytes_and_refuses_existing_destination(self):
        root = Path(tempfile.mkdtemp(prefix="blmis-monetary-copy-"))
        original = root / "original"
        original.mkdir()
        (original / "payload").write_bytes(b"complete native-prefix stand-in for copy-helper unit only")
        result = twin.copy_closed_prefix(original, root / "positive")
        self.assertEqual(result["files"], 1)
        self.assertEqual((root / "positive/payload").read_bytes(), (original / "payload").read_bytes())
        with self.assertRaises(twin.live.CheckError):
            twin.copy_closed_prefix(original, root / "positive")
        self.assertTrue((original / "payload").is_file())

    def test_cold_copy_rejects_symlinked_prefix(self):
        root = Path(tempfile.mkdtemp(prefix="blmis-monetary-copy-link-"))
        (root / "original").mkdir()
        (root / "held").write_bytes(b"retained")
        (root / "original/link").symlink_to(root / "held")
        with self.assertRaises(twin.live.CheckError):
            twin.copy_closed_prefix(root / "original", root / "positive")
        self.assertFalse((root / "positive").exists())

    def test_missing_binary_returns_unrun_before_touching_output(self):
        root = Path(tempfile.mkdtemp(prefix="blmis-monetary-missing-"))
        output = root / "existing"
        output.mkdir()
        marker = output / "retained"
        marker.write_bytes(b"existing evidence")
        error = io.StringIO()
        with redirect_stderr(error):
            code = twin.main(["--out", str(output), "--fa", str(root / "absent-fa"),
                              "--fa-verify", str(root / "absent-verifier")])
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(error.getvalue())["status"], "UNRUN")
        self.assertEqual(marker.read_bytes(), b"existing evidence")
        self.assertEqual(list(output.iterdir()), [marker])


class OriginalSourceOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        glantz, magnify = os.environ.get("FA_BLMIS_GLANTZ_PDF"), os.environ.get("FA_BLMIS_MAGNIFY_PDF")
        if not glantz or not magnify:
            raise unittest.SkipTest("both pinned originals are required for the independent full-population oracle")
        cls.output = Path(tempfile.mkdtemp(prefix="blmis-monetary-originals-")) / "prepared"
        cls.rows, cls.manifest = twin.migration.prepare(cls.output, Path(glantz), include_magnify=True, magnify_pdf=Path(magnify))

    def test_independent_decimal_originals_fix_complete_388_cell_oracle(self):
        raw = []
        for directory in ("source", "magnify-source/extracted-source"):
            with (self.output / directory / "rows.csv").open(newline="") as stream:
                raw.extend(csv.DictReader(stream))
        accounts = {"1T0026", "1ZA192", "1ZB010", "1ZB143", "1FN025", "1FN097", "1FR051"}
        raw = [row for row in raw if row["account"] in accounts]
        self.assertEqual(len(raw), 393)
        def day(row):
            month, number, year = map(int, row["date_literal"].split("/"))
            return date(year, month, number)
        def cents(value):
            value = value.strip()
            if value in ("", "-"):
                return 0
            amount = Decimal(value.strip("()").replace(",", "")) * 100
            self.assertEqual(amount, amount.to_integral_exact())
            return -int(amount) if value.startswith("(") else int(amount)
        self.assertEqual(sum(any(cents(row[name + "_literal"]) for name in
                                 ("deposits", "withdrawals", "transfers_in", "transfers_out")) for row in raw), 371)
        def order(row):
            line = int(row["source_line"])
            if row["row_id"] == "SRC-BLM-001:1ZB010:p35:l38":
                line = 39
            elif row["row_id"] == "SRC-BLM-001:1ZB010:p35:l39":
                line = 38
            return day(row), int(row["pdf_page"]), line
        grouped = {account: sorted((r for r in raw if r["account"] == account), key=order) for account in accounts}
        target = next(row for row in raw if row["row_id"] == "SRC-BLM-001:1T0026:p27:l16")
        self.assertEqual(cents(target["deposits_literal"]), 280000000)
        self.assertEqual(day(target), date(1992, 11, 19))
        matrix, controls = [], []
        year, month = 1990, 12
        while year <= 2008:
            through = date(year, month, calendar.monthrange(year, month)[1])
            cells = {}
            for account, values in grouped.items():
                prior = [row for row in values if day(row) <= through]
                if prior:
                    balance = -cents(prior[-1]["printed_balance_literal"])
                    if balance:
                        cells["BLMIS-" + account] = balance
            offset = -sum(cells.values())
            if offset:
                cells["BLMIS-MIGRATION-OFFSET"] = offset
            controls.append(cells)
            if through >= date(1992, 11, 19):
                for account, delta in (("BLMIS-1T0026", -100), ("BLMIS-MIGRATION-OFFSET", 100)):
                    matrix.append({"period": f"FY{year}-P{month:02}", "account_code": account, "unit": "USD",
                                   "declared": rendered(cells.get(account, 0)), "folded": rendered(cells.get(account, 0) + delta)})
            year, month = (year + 1, 1) if month == 12 else (year, month + 1)
        self.assertEqual(controls, [item["cells_cents"] for item in self.manifest["controls"]])
        self.assertEqual(len(controls), 217)
        self.assertEqual(len(matrix), 388)
        self.assertEqual(matrix, twin.expected_mismatches(self.manifest["controls"], twin.target_row(self.rows), 100))
        digest = hashlib.sha256(json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "061314cd52aa21432bc0cfb3aa450478356a83f76b420093874f5439653acc4f")


if __name__ == "__main__":
    unittest.main()
