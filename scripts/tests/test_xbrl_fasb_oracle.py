"""Controls for the exact arithmetic and coverage of the native-export oracle."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import xbrl_fasb_oracle as oracle


class CalculationTests(unittest.TestCase):
    def check_facts(self, facts, required=()):
        envelope = """
        <x:xbrl xmlns:x="http://www.xbrl.org/2003/instance"
                xmlns:g="http://fasb.org/us-gaap/2026"
                xmlns:iso="http://www.xbrl.org/2003/iso4217">
          <x:context id="now"><x:period><x:instant>2026-12-31</x:instant></x:period></x:context>
          <x:unit id="USD"><x:measure>iso:USD</x:measure></x:unit>
          <x:unit id="EUR"><x:measure>iso:EUR</x:measure></x:unit>
        """
        items = "".join(
            f'<g:{name} contextRef="now" unitRef="{unit}">{amount}</g:{name}>'
            for name, amount, unit in facts
        )
        names = {"Parent": "instant", "Credit": "instant", "Offset": "instant"}
        roles = {"example": {"Parent": {"Credit": 1, "Offset": -1}}}
        return oracle.compare((envelope + items + "</x:xbrl>").encode(), names, roles, set(required))

    def test_equal_duplicates_and_small_discrepancies_at_large_magnitudes(self):
        facts = [("Credit", "100000000000000000000000000000.10", "USD"),
                 ("Offset", "0.010", "USD"), ("Offset", "0.01", "USD")]
        correct = self.check_facts([*facts, ("Parent", "100000000000000000000000000000.09", "USD")])
        self.assertEqual(correct["status"], "PASS")
        self.assertEqual(correct["distinct_facts"], 3)
        changed = self.check_facts([*facts, ("Parent", "100000000000000000000000000000.10", "USD")])
        self.assertEqual(changed["status"], "FAIL")
        self.assertFalse(changed["complete"][0]["exact"])

    def test_absent_contributor_in_same_unit_leaves_calculation_ungraded(self):
        facts = [("Parent", "48", "USD"), ("Credit", "48", "USD"), ("Offset", "0", "EUR")]
        report = self.check_facts(facts)
        self.assertEqual(report["status"], "UNRUN")
        self.assertEqual(report["incomplete"][0]["missing_children"], ["Offset"])
        required = self.check_facts(facts, ["Parent"])
        self.assertEqual(required["status"], "FAIL")
        self.assertEqual(required["missing_required"], ["Parent"])

    def test_conflicting_duplicate_refuses_even_without_a_reported_parent(self):
        with self.assertRaisesRegex(ValueError, "conflicting amounts"):
            self.check_facts([("Offset", "0", "USD"), ("Offset", "0.01", "USD")])


if __name__ == "__main__":
    unittest.main()
