"""Exact predicate models and planted comparator failures, never native evidence."""

from copy import deepcopy
from datetime import date
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_analytics as analytics
import blmis_magnify
import blmis_source
import blmis_square_one


def row(index, day, dollars, account="A", *, transfer=False):
    literal = f"({-dollars:,})" if dollars < 0 else f"{dollars:,}"
    fields = {name: "-" for name in ("deposits", "withdrawals", "transfers_in", "transfers_out")}
    field = ("transfers_in" if dollars >= 0 else "transfers_out") if transfer else (
        "deposits" if dollars >= 0 else "withdrawals")
    fields[field] = literal
    when = date.fromisoformat(day)
    return {"row_id": f"unit-test-only:{account}:{index}", "account": account,
            "date": day, "date_literal": f"{when.month}/{when.day}/{when.year}",
            "cash_movement_cents": 0 if transfer else dollars * 100,
            "transfer_movement_cents": dollars * 100 if transfer else 0,
            "principal_movement_cents": dollars * 100,
            **{f"{name}_literal": value for name, value in fields.items()}}


def receipts(rows):
    return {value["row_id"]: {"vid": f"{index + 1:032x}", "recorded_at": index + 1}
            for index, value in enumerate(rows) if value["principal_movement_cents"]}


def native_report(procedure, entries, expected, accounts, known_at=100):
    """Build native-shaped comparator inputs; these are not engine executions."""
    values = deepcopy(expected)
    by_row = {entry["row_id"]: entry for entry in entries}
    for value in values:
        converted = []
        for citation in value["cites"]:
            native = dict.fromkeys(("entry", "ordinal", "account", "period", "document", "principal", "approval", "attestation"))
            native["kind"] = citation["kind"]
            if citation["kind"] == "account":
                native["account"] = accounts[citation["account"]]
            else:
                native["entry"] = by_row[citation["source_row"]]["vid"]
                if citation["kind"] == "leg":
                    native["ordinal"] = citation["ordinal"]
            converted.append(native)
        value["cites"] = converted
    version, parameters = analytics.PROCEDURES[procedure]
    return {"event": "procedure_run", "data": {
        "procedure": procedure, "version": version, "claim": "statistical",
        "known_at": known_at, "effective_through": None, "inputs": [],
        "parameters": [{"name": name, "value": value} for name, value in sorted(parameters.items())],
        "work": {"entries": len(entries), "legs": 0 if procedure == "jet.weekend" else 2 * len(entries)},
        "findings": values, "finding_count": len(values),
    }}


class SourcePredicateTests(unittest.TestCase):
    def model(self, rows):
        entries = analytics.source_entries(rows, receipts(rows))
        return entries, analytics.expected_findings(entries)

    def test_round_and_weekend_predicates_use_literal_amounts_and_calendar(self):
        rows = [row(1, "2026-10-31", 1000), row(2, "2026-11-01", -250), row(3, "2026-11-02", 2000)]
        _, expected = self.model(rows)
        rounds = expected["jet.round_amounts"]
        self.assertEqual([finding["cites"][0]["source_row"] for finding in rounds], [rows[0]["row_id"], rows[2]["row_id"]])
        self.assertTrue(all(finding["statistic"] == {"name": "round_legs", "value": 2, "scale": 0, "population": 6}
                            and finding["severity"] == "Medium" for finding in rounds))
        weekends = expected["jet.weekend"]
        self.assertEqual([finding["statistic"]["value"] for finding in weekends], [6, 7])
        self.assertEqual([finding["statistic"]["population"] for finding in weekends], [3, 3])

    def test_duplicates_keep_sign_account_and_counterpart_and_next_distinct_date(self):
        rows = [row(1, "2026-01-01", 1000), row(2, "2026-01-01", 1000),
                row(3, "2026-01-03", 1000), row(4, "2026-01-05", 1000),
                row(5, "2026-01-05", -1000), row(6, "2026-01-05", 1000, "B"),
                row(7, "2026-01-05", 1000, transfer=True), row(8, "2026-03-01", 1000)]
        _, expected = self.model(rows)
        same = expected["duplicates.same_same_same"]
        self.assertEqual(len(same), 1)
        self.assertEqual(same[0]["statistic"]["value"], 2)
        pairs = expected["duplicates.same_same_different"]
        self.assertEqual([[cite["source_row"] for cite in value["cites"]] for value in pairs], [
            [rows[0]["row_id"], rows[2]["row_id"]], [rows[1]["row_id"], rows[2]["row_id"]],
            [rows[2]["row_id"], rows[3]["row_id"]]])
        self.assertTrue(all(value["statistic"]["value"] == 2 for value in pairs))

    def test_rsf_separates_principal_parties_and_untagged_counterpart_accounts(self):
        rows = [row(index, "2026-01-01", amount) for index, amount in enumerate((1000, 100, 50, -1000, -100, -50), 1)]
        _, expected = self.model(rows)
        values = expected["numbers.relative_size_factor"]
        self.assertEqual(len(values), 2)
        self.assertTrue(all(value["severity"] == "High" and value["statistic"] == {
            "name": "rsf_bps", "value": 100000, "scale": 0, "population": 6} for value in values))
        self.assertEqual(sum(cite["kind"] == "account" for value in values for cite in value["cites"]), 1)
        self.assertIn({"kind": "account", "account": "BLMIS-CASH"}, values[0]["cites"])

    def test_round_density_uses_whole_book_baseline_and_retains_leg_witnesses(self):
        rows = [row(index, "2026-01-01", 100, "A") for index in range(20)]
        rows.extend(row(index + 20, "2026-01-01", 101, "B") for index in range(80))
        _, expected = self.model(rows)
        values = expected["numbers.round_amount_density"]
        self.assertEqual(len(values), 1)
        value = values[0]
        self.assertEqual(value["severity"], "High")
        self.assertEqual(value["statistic"], {"name": "round_legs", "value": 20, "population": 20, "scale": 0})
        self.assertEqual(value["cites"][0], {"kind": "account", "account": "BLMIS-A"})
        self.assertEqual(len(value["cites"]), 21)
        self.assertTrue(all(cite["ordinal"] == 0 for cite in value["cites"][1:]))

    def test_benford_keeps_minimum_and_exact_rational_scale(self):
        small = analytics.benford_finding([499, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(small["statistic"], {"name": "population", "value": 499, "scale": 0, "population": 499})
        self.assertIn("no conformity is claimed", small["narrative"])
        scored = analytics.benford_finding([500, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(scored["statistic"], {"name": "mad", "value": 155326667, "scale": 9, "population": 500})
        self.assertEqual(scored["severity"], "High")
        self.assertIn("KS 698970004e-9", scored["narrative"])

    def test_starred_withholding_requires_the_published_exclusion_premise(self):
        rows = [row(1, "2026-01-01", 100), row(2, "2026-01-02", 0)]
        rows[1].update(withdrawals_literal="* [4]", star=True,
                       principal_rule="withholding_refund_exclusion", footnote_premises=["test:footnote:4"])
        entries, _ = self.model(rows)
        self.assertEqual(len(entries), 1)
        rows[1]["footnote_premises"] = []
        with self.assertRaisesRegex(analytics.ledger.ReplayError, "withholding premise"):
            self.model(rows)

    def test_mutated_derived_amount_or_date_cannot_override_source_literals(self):
        for field, replacement in (("principal_movement_cents", 10001), ("date", "2026-01-02")):
            rows = [row(1, "2026-01-01", 100)]
            rows[0][field] = replacement
            with self.assertRaises(analytics.ledger.ReplayError):
                self.model(rows)

    def test_missing_extra_or_reused_native_receipts_are_refused(self):
        rows = [row(1, "2026-01-01", 100), row(2, "2026-01-02", 200)]
        originals = receipts(rows)
        for mutation in ("missing", "extra", "same_vid", "same_sequence"):
            changed = deepcopy(originals)
            if mutation == "missing":
                changed.pop(rows[0]["row_id"])
            elif mutation == "extra":
                changed["invented"] = {"vid": "f" * 32, "recorded_at": 99}
            elif mutation == "same_vid":
                changed[rows[1]["row_id"]]["vid"] = changed[rows[0]["row_id"]]["vid"]
            else:
                changed[rows[1]["row_id"]]["recorded_at"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(analytics.ledger.ReplayError):
                analytics.source_entries(rows, changed)

    def test_complete_authentic_source_populations_keep_zero_rows_and_one_side_counts(self):
        for module, observations, monetary, round_count, pairs in (
            (blmis_source, 75, 74, 71, 0), (blmis_square_one, 1050, 340, 37, 3),
            (blmis_magnify, 2364, 1586, 189, 30),
        ):
            with self.subTest(source=module.__name__):
                rows, _ = module.load_fixture()
                entries, expected = self.model(rows)
                self.assertEqual((len(rows), len(entries)), (observations, monetary))
                self.assertEqual(len(expected["jet.round_amounts"]), round_count)
                self.assertEqual(len(expected["duplicates.same_same_different"]), pairs)
                self.assertEqual(expected["benford.first_digit"][0]["statistic"]["population"], monetary)
                if module is blmis_magnify:
                    self.assertEqual(expected["benford.first_digit"][0]["statistic"]["value"], 7606233)
                    self.assertEqual(len(expected["duplicates.same_same_same"]), 9)


class ComparatorFailureTests(unittest.TestCase):
    def setUp(self):
        rows = [row(1, "2026-10-31", 1000), row(2, "2026-11-01", 2000)]
        self.entries = analytics.source_entries(rows, receipts(rows))
        self.expected = analytics.expected_findings(self.entries)["jet.round_amounts"]
        self.accounts = {"BLMIS-A": "a" * 32, "BLMIS-CASH": "b" * 32}
        self.report = native_report("jet.round_amounts", self.entries, self.expected, self.accounts)

    def check(self, report):
        return analytics.check_report(report, "jet.round_amounts", self.expected, self.entries, self.accounts, 100)

    def test_complete_comparator_input_resolves_every_source_citation(self):
        self.assertEqual(self.check(self.report), self.expected)

    def test_wrong_procedure_version_scope_and_threshold_are_refused(self):
        for field, value in (("procedure", "jet.weekend"), ("version", 2), ("claim", "invariant"),
                             ("known_at", 99), ("effective_through", "2026-11-01"),
                             ("parameters", [{"name": "round_power", "value": 2}])):
            report = deepcopy(self.report)
            report["data"][field] = value
            with self.subTest(field=field), self.assertRaises(analytics.ledger.ReplayError):
                self.check(report)

    def test_omission_duplication_extra_entries_and_incorrect_statistics_are_refused(self):
        for mutation in ("missing", "duplicate", "extra_work", "value", "scale", "population", "severity", "narrative"):
            report = deepcopy(self.report)
            data = report["data"]
            if mutation == "missing":
                data["findings"].pop()
                data["finding_count"] -= 1
            elif mutation == "duplicate":
                data["findings"][1] = deepcopy(data["findings"][0])
            elif mutation == "extra_work":
                data["work"]["entries"] += 1
            elif mutation in ("value", "scale", "population"):
                data["findings"][0]["statistic"][mutation] += 1
            else:
                data["findings"][0][mutation] = "invented"
            with self.subTest(mutation=mutation), self.assertRaises(analytics.ledger.ReplayError):
                self.check(report)

    def test_wrong_row_leg_or_unrelated_citation_handle_is_refused(self):
        for mutation in ("other_row", "missing_leg", "extra_handle", "repeated_leg", "unrelated_kind"):
            report = deepcopy(self.report)
            cites = report["data"]["findings"][0]["cites"]
            if mutation == "other_row":
                cites[0]["entry"] = "f" * 32
            elif mutation == "missing_leg":
                cites[1]["ordinal"] = 2
            elif mutation == "extra_handle":
                cites[0]["document"] = "f" * 64
            elif mutation == "repeated_leg":
                cites[2]["ordinal"] = 0
            else:
                cites[0]["kind"] = "document"
            with self.subTest(mutation=mutation), self.assertRaises(analytics.ledger.ReplayError):
                self.check(report)


if __name__ == "__main__":
    unittest.main()
