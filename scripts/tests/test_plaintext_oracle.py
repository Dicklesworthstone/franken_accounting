"""Exact parser refusals and real external-tool differentials on declared test books.

The small journals here are synthetic controls, not public records. The real
tool tests skip explicitly when executables are absent; parser tests cannot
stand in for those executions. Set FA_ORACLE_BEAN_CHECK, FA_ORACLE_BEAN_QUERY
and FA_ORACLE_HLEDGER to use executables outside PATH.
"""

from contextlib import redirect_stdout
import csv
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import plaintext_oracle as oracle


TOOLS = {key: os.environ.get(env) or shutil.which(default) for key, env, default in (
    ("bean_check", "FA_ORACLE_BEAN_CHECK", "bean-check"),
    ("bean_query", "FA_ORACLE_BEAN_QUERY", "bean-query"),
    ("hledger", "FA_ORACLE_HLEDGER", "hledger"),
)}
ACCOUNTS = (("1000.10", "Asset", "Assets:A1000-10"),
            ("3000", "Equity", "Equity:A3000"),
            ("5000", "Expense", "Expenses:A5000"))
POSTINGS = (
    ("2024-01-01", "USD", 2, "1000.10", "150.27", "3000", "-150.27"),
    ("2024-01-02", "USD", 2, "1000.10", "-20.12", "5000", "20.12"),
    ("2024-01-03", "USD", 2, "1000.10", "-130.15", "5000", "130.15"),
    ("2024-01-04", "EUR", 3, "1000.10", "9.876", "3000", "-9.876"),
)
CONTENT = "a" * 64
CERTIFICATE = "b" * 64
BEANCOUNT_RECOVERY_PREFIXES = (
    "", "  ", "\t", "  invalid ",
    '2024-01-05 * "unfinished" ', '  fa_entry_id: "unfinished" ',
    '  invalid" ', '  invalid"; ',
    '  1" " ', '  fa_entry_id:" " ',
)


def fixtures(postings: tuple = POSTINGS) -> dict[str, str]:
    """Hand-declared entries: zero-net USD cash and a separate 3-decimal unit."""
    common = (
        "; fa_book_name: Synthetic external accounting control\n"
        "; fa_base_unit: USD@2\n"
        "; fa_effective_through: 2024-01-31\n"
        "; fa_known_at_seq: 9\n"
        f"; fa_content_digest: {CONTENT}\n"
        f"; fa_certificate_digest: {CERTIFICATE}\n"
    )
    bean = common + 'option "title" "Synthetic external accounting control"\noption "operating_currency" "USD"\n'
    ledger = common
    native = (
        "# fa_csv_gl_v1|book=Synthetic external accounting control|base=USD@2|"
        f"effective_through=2024-01-31|known_at=9|entries={len(postings)}|"
        f"content_digest={CONTENT}|certificate_digest={CERTIFICATE}\n"
    )
    names = {}
    for code, kind, name in ACCOUNTS:
        names[code] = name
        native += f"# fa_account|{code}|Account {code}|{kind}|{'C' if kind == 'Equity' else 'D'}\n"
        bean += (f"1970-01-01 open {name}\n  fa_code: \"{code}\"\n"
                 f"  fa_name: \"Account {code}\"\n  fa_type: \"{kind}\"\n")
        ledger += f"account {name}  ; fa_code:{code} fa_type:{kind} fa_name:Account {code}\n"
    with io.StringIO(newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(oracle.CSV_COLUMNS)
        for index, (day, currency, scale, debit_code, debit, credit_code, credit) in enumerate(postings, 1):
            bean += f'\n{day} * "Control {index}"\n  fa_entry_id: "entry-{index}"\n'
            ledger += f"\n{day} * Control {index}  ; fa_entry_id:entry-{index} fa_seq:{index + 1} fa_class:12\n"
            for ordinal, (code, amount) in enumerate(((debit_code, debit), (credit_code, credit)), 1):
                writer.writerow([f"entry-{index}", ordinal, day, index + 1, 12, code,
                                 "C" if amount.startswith("-") else "D", amount.lstrip("-"),
                                 currency, scale, f"Control {index}", "", ""])
                bean += f"  {names[code]}  {amount} {currency}\n"
                ledger += f"    {names[code]}    {amount} {currency}\n"
        native += stream.getvalue()
    return {"csv_gl": native, "beancount": bean, "hledger_journal": ledger}


def native_tb_fixture() -> dict:
    """Hand-declared stock/gross controls, not computed by the comparator."""
    cells = (
        ("1000.10", "Asset", "USD", "150.27", "150.27", "0.00"),
        ("1000.10", "Asset", "EUR", "9.876", "0.000", "9.876"),
        ("3000", "Equity", "USD", "0.00", "150.27", "-150.27"),
        ("3000", "Equity", "EUR", "0.000", "9.876", "-9.876"),
        ("5000", "Expense", "USD", "150.27", "0.00", "150.27"),
    )
    return {
        "v": 1, "event": "trial_balance", "book": "c" * 32, "warnings": [],
        "coordinate": {"branch": "trunk", "effective": "as-of:2024-01-31", "known_at": 9},
        "data": {
            "mode": "stock", "activity": False, "balanced": True, "dimension": None, "periods": [],
            "effective_through": "2024-01-31", "known_at": 9,
            "rows": [{"code": code, "type": kind, "name": f"Account {code}",
                      "debits": f"{debit} {unit}", "credits": f"{credit} {unit}", "net": f"{net} {unit}",
                      "debits_pending": f"0 {unit}", "credits_pending": f"0 {unit}"}
                     for code, kind, unit, debit, credit, net in cells],
            "unit_totals": [{"unit": "USD", "debits": "300.54 USD", "credits": "300.54 USD"},
                            {"unit": "EUR", "debits": "9.876 EUR", "credits": "9.876 EUR"}],
        },
    }


def save_fixture(directory: Path, texts: dict[str, str] | None = None) -> dict[str, Path]:
    names = {"csv_gl": "native.csv", "beancount": "journal.beancount", "hledger_journal": "journal.hledger"}
    result = {}
    for key, text in (texts or fixtures()).items():
        path = directory / names[key]
        path.write_text(text, encoding="utf-8")
        result[key] = path
    return result


def contra_fixtures() -> dict[str, str]:
    """The producer's optional D/C metadata retains both override directions."""
    texts = fixtures()
    texts["csv_gl"] = texts["csv_gl"].replace(
        "Account 1000.10|Asset|D", "Account 1000.10|Asset|C").replace(
        "Account 3000|Equity|C", "Account 3000|Equity|D")
    texts["beancount"] = texts["beancount"].replace(
        '  fa_type: "Asset"\n', '  fa_type: "Asset"\n  fa_normal_side_v1: "C"\n').replace(
        '  fa_type: "Equity"\n', '  fa_type: "Equity"\n  fa_normal_side_v1: "D"\n')
    texts["hledger_journal"] = texts["hledger_journal"].replace(
        "fa_type:Asset ", "fa_type:Asset fa_normal_side_v1:C ").replace(
        "fa_type:Equity ", "fa_type:Equity fa_normal_side_v1:D ")
    return texts


def directive_word_fixtures() -> dict[str, str]:
    """Directive words are ordinary account, quoted-source and comment data."""
    texts = fixtures()
    for key in ("beancount", "hledger_journal"):
        texts[key] = texts[key].replace("Assets:A1000-10", "Assets:Aplugin-include")
        texts[key] += '\n; include "not-included.bean" plugin "not.loaded"\n'
    texts["beancount"] = texts["beancount"].replace(
        '"Control 1"', json.dumps('include "not-included.bean"; plugin "not.loaded" \\ source'))
    # Exercise every native structural form without changing a monetary cell.
    texts["beancount"] = texts["beancount"].replace(
        '  fa_type: "Asset"\n',
        '  fa_type: "Asset"\n  fa_normal_side_v1: "D"\n  fa_roles_v1: "cash"\n', 1)
    texts["beancount"] = texts["beancount"].replace(
        '  fa_entry_id: "entry-1"\n',
        '  fa_entry_id: "entry-1"\n  fa_recorded_seq: 2\n  fa_class: 12\n'
        '  fa_migrated_from: "include plugin source"\n', 1)
    texts["beancount"] = texts["beancount"].replace(
        '  Assets:Aplugin-include  150.27 USD\n',
        '  Assets:Aplugin-include  150.27 USD ; memo:include "data" plugin\n', 1)
    texts["beancount"] = texts["beancount"].replace(
        '  Equity:A3000  -150.27 USD\n',
        '  Equity:A3000  -150.27 USD\n'
        '    fa_memo_hex_v1: "20696e636c75646520706c7567696e20"\n'
        '    fa_dimensions_v1: "1:00000000000000000000000000000001"\n', 1)
    texts["beancount"] += (
        '2024-02-01 balance Assets:Aplugin-include 0.00 USD\n'
        '2024-02-01 balance Assets:Aplugin-include 9.876 EUR\n')
    return texts


class ExactControlsTests(unittest.TestCase):
    def setUp(self):
        self.texts = fixtures()
        self.reference = oracle.read_reference(self.texts["csv_gl"])
        self.mapping = oracle.read_account_map(self.texts["beancount"], "beancount", self.reference)

    def test_source_uses_explicit_account_codes_and_exact_net_gross_counts(self):
        self.assertEqual(self.mapping["Assets:A1000-10"], "1000.10")
        self.assertEqual(self.reference.entries, 4)
        self.assertEqual(self.reference.postings, 8)
        self.assertEqual(vars(self.reference.cells[("1000.10", "USD")]), {
            "net": 0, "debit": 15027, "credit": 15027, "postings": 3,
            "debit_postings": 1, "credit_postings": 2,
        })
        self.assertEqual(self.reference.cells[("1000.10", "EUR")].net, 9876)
        self.assertEqual(oracle.read_account_map(self.texts["hledger_journal"], "hledger", self.reference),
                         self.mapping)

    def test_decimal_parser_never_rounds_or_accepts_binary_floats(self):
        self.assertEqual(oracle.minor_units("-123456789012345678901234567890.12", 2),
                         -12345678901234567890123456789012)
        self.assertEqual(oracle.minor_units("1.23000", 2), 123)
        self.assertEqual(oracle.minor_units("0.00000001", 8), 1)
        for value in (0.1, 1, None, "NaN", "inf", "1e2", " 1.00", "1.001", "1,000.00", "1_000"):
            with self.subTest(value=value), self.assertRaises(oracle.OracleError):
                oracle.minor_units(value, 2)

    def test_native_tb_matches_exact_gross_and_keeps_pending_separate(self):
        doc = native_tb_fixture()
        doc["data"]["rows"][0]["name"] = "Name\u0085with\u2028separators"
        doc["data"]["rows"].append({
            "code": "5000", "type": "Expense", "debits": "0 GBP", "credits": "0 GBP", "net": "0 GBP",
            "debits_pending": "4.12 GBP", "credits_pending": "0 GBP",
        })
        doc["data"]["unit_totals"].append({"unit": "GBP", "debits": "0 GBP", "credits": "0 GBP"})
        result = oracle.read_native_trial_balance(json.dumps(doc, ensure_ascii=False), self.reference)
        self.assertEqual(result, {"observed_book_id": "c" * 32, "known_at": 9,
                                  "effective_through": "2024-01-31", "account_currency_cells": 5})

    def test_native_tb_refuses_wrong_scope_coordinate_and_account_cells(self):
        changes = (
            lambda d: d["coordinate"].update(known_at=10),
            lambda d: d["coordinate"].update(branch="draft"),
            lambda d: d["data"].update(known_at=10),
            lambda d: d["data"].update(effective_through="2024-02-01"),
            lambda d: d["data"].update(mode="activity"),
            lambda d: d["data"].update(activity=True),
            lambda d: d["data"].update(dimension={"kind": "department", "value": 1}),
            lambda d: d["data"].update(periods=["FY2024-P01"]),
            lambda d: d["data"].update(balanced=False),
            lambda d: d.update(warnings=["diagnostic"]),
            lambda d: d["data"]["rows"][0].update(code="9999"),
            lambda d: d["data"]["rows"][0].update(code=[]),
            lambda d: d["data"]["rows"][0].update(type="Liability"),
            lambda d: d["data"]["rows"][0].update(net="0.01 USD"),
            lambda d: d["data"]["rows"][0].update(debits="150.27 GBP", credits="150.27 GBP", net="0 GBP"),
            lambda d: d["data"]["rows"][1].update(debits="9.8761 EUR", net="9.8761 EUR"),
            lambda d: d["data"]["rows"].append(dict(d["data"]["rows"][0])),
            lambda d: d["data"]["rows"].pop(),
            lambda d: d["data"]["unit_totals"].append(dict(d["data"]["unit_totals"][0])),
            lambda d: d["data"]["unit_totals"].pop(),
            lambda d: d["data"]["unit_totals"][0].update(debits="300.55 USD", credits="300.55 USD"),
        )
        for index, change in enumerate(changes):
            doc = native_tb_fixture()
            change(doc)
            with self.subTest(index=index), self.assertRaises(oracle.OracleError):
                oracle.read_native_trial_balance(json.dumps(doc), self.reference)
        # The question remains balanced and every net is unchanged. Its gross
        # activity is still wrong, even with matching self-reported totals.
        doc = native_tb_fixture()
        doc["data"]["rows"][0].update(debits="150.28 USD", credits="150.28 USD")
        doc["data"]["unit_totals"][0].update(debits="300.55 USD", credits="300.55 USD")
        with self.assertRaises(oracle.OracleError):
            oracle.read_native_trial_balance(json.dumps(doc), self.reference)

    def test_native_tb_refuses_duplicate_json_fields_noninteger_numbers_and_extra_events(self):
        text = json.dumps(native_tb_fixture())
        for changed in (
            text.replace('"balanced": true', '"balanced": true, "balanced": true'),
            text.replace('"known_at": 9', '"known_at": 9.0'),
            text.replace('"known_at": 9', '"known_at": NaN'),
            text + "\n" + text,
        ):
            with self.subTest(changed=changed), self.assertRaises(oracle.OracleError):
                oracle.read_native_trial_balance(changed, self.reference)

    def test_native_csv_refuses_count_leg_scope_scale_and_schema_damage(self):
        text = self.texts["csv_gl"]
        mutations = [
            text.replace("entries=4", "entries=5"),
            text.replace("entry-1,2,", "entry-1,1,"),
            text.replace("2024-01-01,2,12", "2024-01-01,10,12"),
            text.replace("2024-01-01,2,12", "2024-02-01,2,12"),
            text.replace("USD,2,Control 1", "USD,3,Control 1", 1),
            text.replace(",150.27,USD", ",150.271,USD", 1),
            text.replace(",150.27,USD", ",0.00,USD", 1),
            text.replace("account_code,side", "account_code,side,side"),
            text.replace("# fa_account|3000|", "# fa_account|1000.10|"),
        ]
        for changed in mutations:
            with self.subTest(changed=changed[:160]), self.assertRaises((oracle.OracleError, ValueError)):
                oracle.read_reference(changed)

    def test_coordinate_and_explicit_mapping_must_match_every_export(self):
        for kind, key in (("beancount", "beancount"), ("hledger", "hledger_journal")):
            for old, new in (("fa_known_at_seq: 9", "fa_known_at_seq: 10"),
                             ("fa_base_unit: USD@2", "fa_base_unit: USD@3"),
                             (CONTENT, "c" * 64),
                             ("fa_effective_through: 2024-01-31", "fa_effective_through: 2024-02-01")):
                with self.subTest(kind=kind, field=old), self.assertRaises(oracle.OracleError):
                    oracle.read_account_map(self.texts[key].replace(old, new), kind, self.reference)
        without_code = self.texts["beancount"].replace('  fa_code: "1000.10"\n', "")
        with self.assertRaisesRegex(oracle.OracleError, "explicit fa_code"):
            oracle.read_account_map(without_code, "beancount", self.reference)
        collision = self.texts["beancount"].replace("Equity:A3000", "Assets:A1000-10")
        with self.assertRaises(oracle.OracleError):
            oracle.read_account_map(collision, "beancount", self.reference)

    def test_normal_balance_overrides_match_the_native_chart(self):
        texts = contra_fixtures()
        reference = oracle.read_reference(texts["csv_gl"])
        self.assertEqual(reference.normal_sides, {"1000.10": "C", "3000": "D", "5000": "D"})
        self.assertEqual(self.reference.normal_sides, {"1000.10": "D", "3000": "C", "5000": "D"})
        for kind, key in (("beancount", "beancount"), ("hledger", "hledger_journal")):
            with self.subTest(kind=kind):
                self.assertEqual(oracle.read_account_map(texts[key], kind, reference), self.mapping)

    def test_normal_balance_metadata_refuses_invalid_duplicate_missing_and_foreign_side(self):
        texts = contra_fixtures()
        reference = oracle.read_reference(texts["csv_gl"])
        for kind, key, token, replacements in (
            ("beancount", "beancount", '  fa_normal_side_v1: "C"\n', (
                '  fa_normal_side_v1: "X"\n',
                '  fa_normal_side_v1: "D"\n',
                '  fa_normal_side_v1: "C"\n  fa_normal_side_v1: "C"\n',
                '',
                '  fa_normal_side_v2: "C"\n',
            )),
            ("hledger", "hledger_journal", " fa_normal_side_v1:C", (
                " fa_normal_side_v1:X",
                " fa_normal_side_v1:D",
                " fa_normal_side_v1:C fa_normal_side_v1:C",
                "",
                " fa_normal_side_v2:C",
            )),
        ):
            for replacement in replacements:
                with self.subTest(kind=kind, replacement=replacement), self.assertRaises(oracle.OracleError):
                    oracle.read_account_map(texts[key].replace(token, replacement), kind, reference)

    def test_native_normal_balance_is_checked_when_plaintext_uses_its_type_default(self):
        changed = self.texts["csv_gl"].replace("Account 1000.10|Asset|D", "Account 1000.10|Asset|C")
        reference = oracle.read_reference(changed)
        for kind, key in (("beancount", "beancount"), ("hledger", "hledger_journal")):
            with self.subTest(kind=kind), self.assertRaisesRegex(oracle.OracleError, "normal balance"):
                oracle.read_account_map(self.texts[key], kind, reference)

    def test_includes_plugins_and_automatic_posting_rules_are_not_native_exports(self):
        for kind, key, appended in (
            ("beancount", "beancount", '\ninclude "unbound.bean"\n'),
            ("beancount", "beancount", '\nplugin "unknown.module"\n'),
            ("hledger", "hledger_journal", "\ninclude unbound.journal\n"),
            ("hledger", "hledger_journal", "\n= expenses\n  assets:cash  -1 USD\n"),
        ):
            with self.subTest(kind=kind, directive=appended), self.assertRaises(oracle.OracleError):
                oracle.read_account_map(self.texts[key] + appended, kind, self.reference)
        # Beancount recovers from malformed prefixes and can still load an
        # include or execute a plugin. Parser errors do not make them inert.
        for prefix in BEANCOUNT_RECOVERY_PREFIXES:
            for directive in ("include", "plugin"):
                for separator in (" ", ""):
                    appended = f'\n{prefix}{directive}{separator}"not-used"\n'
                    with self.subTest(directive=appended), self.assertRaises(oracle.OracleError):
                        oracle.read_account_map(self.texts["beancount"] + appended,
                                                "beancount", self.reference)

    def test_beancount_recovery_directives_never_reach_external_tool_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for prefix in BEANCOUNT_RECOVERY_PREFIXES:
                for directive in ("include", "plugin"):
                    for separator in (" ", ""):
                        appended = f'\n{prefix}{directive}{separator}"not-used"\n'
                        texts = dict(self.texts)
                        texts["beancount"] += appended
                        paths = save_fixture(root, texts)
                        out = root / "must-not-be-created"
                        with self.subTest(directive=appended), mock.patch.object(
                                oracle, "resolve_tool",
                                side_effect=AssertionError("external tool resolution reached")) as resolve:
                            with self.assertRaises(oracle.OracleError):
                                oracle.run_oracle(**paths, out=out)
                            resolve.assert_not_called()
                            self.assertFalse(out.exists())

    def test_directive_words_remain_data_in_strings_comments_and_account_names(self):
        texts = directive_word_fixtures()
        expected = dict(self.mapping)
        expected["Assets:Aplugin-include"] = expected.pop("Assets:A1000-10")
        for kind, key in (("beancount", "beancount"), ("hledger", "hledger_journal")):
            with self.subTest(kind=kind):
                self.assertEqual(oracle.read_account_map(texts[key], kind, self.reference), expected)

    def test_versioned_hex_metadata_preserves_identity_and_rejects_ambiguity(self):
        book = "  Public book\r\nÉxpenditure\t  "
        self.reference.coordinate["book"] = book
        original = "; fa_book_name: Synthetic external accounting control"
        encoded = "; fa_book_name_hex_v1: " + book.encode("utf-8").hex()
        for kind, key in (("beancount", "beancount"), ("hledger", "hledger_journal")):
            valid = self.texts[key].replace(original, encoded)
            if kind == "hledger":
                valid = valid.replace("fa_code:1000.10", "fa_code_hex_v1:313030302e3130")
                valid = valid.replace("fa_name:Account 1000.10", "fa_name_hex_v1:204e616d650a20")
            self.assertEqual(oracle.read_account_map(valid, kind, self.reference), self.mapping)
            for bad in ("0", "FE", "ff", "20 20"):
                with self.subTest(kind=kind, bad=bad), self.assertRaises(oracle.OracleError):
                    oracle.read_account_map(valid.replace(encoded, "; fa_book_name_hex_v1: " + bad),
                                            kind, self.reference)
            with self.subTest(kind=kind, duplicate=True), self.assertRaises(oracle.OracleError):
                oracle.read_account_map(valid + original + "\n", kind, self.reference)
            if kind == "hledger":
                for token in ("313030302e3130", "204e616d650a20"):
                    with self.subTest(token=token), self.assertRaises(oracle.OracleError):
                        oracle.read_account_map(valid.replace(token, "ff"), kind, self.reference)

    def test_beanquery_refuses_duplicate_missing_foreign_and_nondecimal_cells(self):
        header = "account,currency,total,postings\n"
        valid = header + "Assets:A1000-10,USD, 0.00 ,3\n"
        self.assertEqual(oracle.parse_beanquery(valid, self.mapping, self.reference.scales),
                         {("1000.10", "USD"): (0, 3)})
        for changed in (valid + valid.splitlines()[-1] + "\n",
                        valid.replace("Assets:A1000-10", "Assets:UNKNOWN"),
                        valid.replace("USD", "ZZZ"), valid.replace("0.00", "0.001"),
                        valid.replace("0.00", "0e2"), valid.replace(",3", ",3.0"),
                        valid.replace("postings", "postings,postings"),
                        valid + "incomplete\n"):
            with self.subTest(changed=changed), self.assertRaises(oracle.OracleError):
                oracle.parse_beanquery(changed, self.mapping, self.reference.scales)
        with self.assertRaisesRegex(oracle.OracleError, "mismatch"):
            oracle.compare_cells({}, {("1000.10", "USD"): (0, 3)}, "missing zero-net population")

    def test_hledger_balance_retains_zero_and_refuses_ambiguous_output(self):
        header = '"account","balance"\n'
        valid = header + '"Assets:A1000-10","0"\n"Expenses:A5000","150.27 USD"\n'
        self.assertEqual(oracle.parse_hledger_balances(valid, self.mapping, "USD", 2),
                         {("1000.10", "USD"): 0, ("5000", "USD"): 15027})
        for changed in (valid + '"Assets:A1000-10","0"\n',
                        valid.replace("150.27 USD", "150.27 USD, 2.00 EUR"),
                        valid.replace("150.27 USD", "150.27 EUR"),
                        valid.replace("150.27 USD", "150.271 USD"),
                        valid.replace("150.27 USD", "1.5e2 USD")):
            with self.subTest(changed=changed), self.assertRaises(oracle.OracleError):
                oracle.parse_hledger_balances(changed, self.mapping, "USD", 2)

    def test_missing_tool_is_unrun_and_never_creates_an_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = save_fixture(root)
            out = root / "oracle"
            with mock.patch.object(shutil, "which", return_value=None), self.assertRaises(oracle.Unavailable):
                oracle.run_oracle(**paths, out=out)
            self.assertFalse(out.exists())
            captured = io.StringIO()
            with mock.patch.object(shutil, "which", return_value=None), redirect_stdout(captured):
                status = oracle.main(["--csv-gl", str(paths["csv_gl"]), "--beancount", str(paths["beancount"]),
                                      "--hledger-journal", str(paths["hledger_journal"]), "--out", str(out)])
            self.assertEqual(status, 4)
            self.assertEqual(json.loads(captured.getvalue())["status"], "UNRUN")
            self.assertFalse(out.exists())

    def test_existing_output_is_preserved_before_any_external_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "oracle"
            out.mkdir()
            marker = out / "original"
            marker.write_text("preserve")
            with mock.patch.object(oracle.subprocess, "run") as execute:
                with self.assertRaisesRegex(oracle.OracleError, "already exists"):
                    oracle.run_oracle(Path("missing"), Path("missing"), Path("missing"), out)
                execute.assert_not_called()
            self.assertEqual(marker.read_text(), "preserve")


@unittest.skipUnless(all(TOOLS.values()), "UNRUN: real bean-check, bean-query and hledger executables are required")
class ExternalToolTests(unittest.TestCase):
    def run_external(self, texts=None, native_tb=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        paths = save_fixture(root, texts)
        tb_path = None
        if native_tb is not None:
            tb_path = root / "native-tb.jsonl"
            tb_path.write_text(native_tb, encoding="utf-8")
        report = oracle.run_oracle(**paths, out=root / "oracle", native_tb=tb_path, **TOOLS)
        return root, report

    def test_real_tools_match_the_supplied_native_trial_balance_and_retain_its_bytes(self):
        text = json.dumps(native_tb_fixture())
        root, report = self.run_external(native_tb=text)
        self.assertEqual(report["status"], "PASS", report.get("error"))
        self.assertIn("native_trial_balance_matches_native_csv_net_gross_and_unit_totals", report["checks"])
        self.assertEqual(report["native_trial_balance"]["observed_book_id"], "c" * 32)
        pin = report["input_files"]["native_tb"]
        self.assertEqual((root / "oracle" / pin["snapshot"]).read_text(), text)
        self.assertEqual(oracle.snapshot(root / "native-tb.jsonl"),
                         {key: pin[key] for key in ("bytes", "sha256")})

    def test_native_trial_balance_original_and_snapshot_changes_invalidate_real_tool_success(self):
        real_run = oracle.Commands.run
        for snapshot in (False, True):
            def run_and_mutate(commands, label, argv, **kwargs):
                result = real_run(commands, label, argv, **kwargs)
                if label == "bean-check":
                    path = (commands.output / "inputs" if snapshot else commands.output.parent) / "native-tb.jsonl"
                    with path.open("a", encoding="utf-8") as stream:
                        stream.write("\n")
                return result
            with self.subTest(snapshot=snapshot):
                with mock.patch.object(oracle.Commands, "run", run_and_mutate):
                    root, report = self.run_external(native_tb=json.dumps(native_tb_fixture()))
                transcript = [json.loads(line) for line in (root / "oracle/commands.jsonl").read_text().splitlines()]
                self.assertEqual(len(transcript), 14)
                self.assertTrue(all(row["exit"] == 0 for row in transcript), transcript)
                self.assertTrue(all(row["stderr"]["bytes"] == 0 or "--version" in row["command"]
                                    for row in transcript), transcript)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn("native_tb bytes changed", report["error"])
                self.assertEqual(report["commands"], 14, "all real external commands actually completed")

    def test_real_tools_accept_both_normal_balance_override_directions(self):
        _, report = self.run_external(contra_fixtures())
        self.assertEqual(report["status"], "PASS", report.get("error"))
        self.assertEqual((report["entries"], report["postings"], report["account_currency_cells"]), (4, 8, 5))
        self.assertEqual(report["commands"], 14)

    def test_real_tools_keep_directive_words_as_source_text_and_account_names(self):
        _, report = self.run_external(directive_word_fixtures())
        self.assertEqual(report["status"], "PASS", report.get("error"))
        self.assertEqual((report["entries"], report["postings"], report["account_currency_cells"]), (4, 8, 5))
        self.assertEqual(report["commands"], 14)

    def test_real_tools_match_multicurrency_gross_counts_and_zero_net_cell(self):
        texts = fixtures()
        # Published source controls may declare categories with no in-period
        # detail. A declaration is not an invented zero monetary posting.
        texts["csv_gl"] = texts["csv_gl"].replace(
            "entry_id,line_no", "# fa_account|5999|Unused expenses|Expense|D\nentry_id,line_no")
        texts["beancount"] += ('\n1970-01-01 open Expenses:A5999\n'
                                '  fa_code: "5999"\n  fa_type: "Expense"\n')
        texts["hledger_journal"] += ('\naccount Expenses:A5999  ; fa_code:5999 '
                                      'fa_type:Expense fa_name:Unused expenses\n')
        for kind in ("beancount", "hledger_journal"):
            texts[kind] = texts[kind].replace(
                "; fa_book_name: Synthetic external accounting control",
                "; fa_book_name_hex_v1: " + b"Synthetic external accounting control".hex())
        texts["hledger_journal"] = texts["hledger_journal"].replace(
            "fa_code:1000.10", "fa_code_hex_v1:313030302e3130").replace(
            "fa_name:Account 1000.10", "fa_name_hex_v1:204e616d650a20")
        root, report = self.run_external(texts)
        self.assertEqual(report["status"], "PASS", report.get("error"))
        self.assertEqual((report["entries"], report["postings"], report["account_currency_cells"]), (4, 8, 5))
        self.assertEqual(report["declared_accounts"], 4)
        self.assertEqual(report["commands"], 14)
        transcript = [json.loads(line) for line in (root / "oracle/commands.jsonl").read_text().splitlines()]
        self.assertEqual(len(transcript), 14)
        self.assertTrue(all(command["exit"] == 0 for command in transcript))
        for command in transcript:
            for stream in ("stdout", "stderr"):
                actual = oracle.snapshot(root / "oracle" / command[stream]["file"])
                self.assertEqual(actual, {key: command[stream][key] for key in ("sha256", "bytes")})
        self.assertTrue(all(tool["version"] and tool["sha256"] for tool in report["tools"].values()))
        self.assertIn("beanquery_debit_and_counts_match_every_native_cell", report["checks"])
        self.assertIn("hledger_independent_gross_credits_match_every_native_cell", report["checks"])
        self.assertIsNone(report["native_trial_balance"])
        self.assertNotIn("native_trial_balance_matches_native_csv_net_gross_and_unit_totals", report["checks"])

    def test_balanced_beancount_amount_change_still_fails_external_differential(self):
        texts = fixtures()
        texts["beancount"] = texts["beancount"].replace("150.27 USD", "150.28 USD")
        root, report = self.run_external(texts)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("bean-query net/posting-count", report["error"])
        self.assertIn("bean_check_validates_untouched_export", report["checks"])
        self.assertEqual(json.loads((root / "oracle/report.json").read_text())["status"], "FAIL")

    def test_valid_source_unicode_separators_and_literal_metadata_controls(self):
        texts = fixtures()
        narration = "Vendor\u2028north\u2029office\x85reference\vdetail"
        account_name = "Account\x00name\vline\u2028branch\u2029section\x85reference"
        texts["csv_gl"] = ("# fa_csv_text_encoding_v1|percent-utf8\n" + texts["csv_gl"]).replace(
            "|Account 1000.10|", "|" + quote(account_name, safe="") + "|").replace("Control 1", narration)
        texts["beancount"] = texts["beancount"].replace(
            'fa_name: "Account 1000.10"', 'fa_name: "' + account_name + '"').replace(
            '"Control 1"', '"' + narration + '"')
        # Native hledger displays control characters without creating physical
        # lines, and preserves the complete source string in its hex metadata.
        display = narration.replace("\x85", "\\u{85}").replace("\v", "\\u{b}")
        texts["hledger_journal"] = texts["hledger_journal"].replace(
            "fa_name:Account 1000.10", "fa_name_hex_v1:" + account_name.encode().hex()).replace(
            "2024-01-01 * Control 1  ; fa_entry_id:entry-1 fa_seq:2 fa_class:12\n",
            f"2024-01-01 * {display}  ; fa_entry_id:entry-1 fa_seq:2 fa_class:12 "
            f"fa_description_hex_v1:{narration.encode().hex()}\n")
        _, report = self.run_external(texts)
        self.assertEqual(report["status"], "PASS", report.get("error"))
        self.assertEqual((report["entries"], report["postings"], report["account_currency_cells"]), (4, 8, 5))

    def test_balanced_hledger_amount_change_still_fails_external_differential(self):
        texts = fixtures()
        texts["hledger_journal"] = texts["hledger_journal"].replace("150.27 USD", "150.28 USD")
        _, report = self.run_external(texts)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("hledger parsed posting gross/net/counts", report["error"])
        self.assertIn("beanquery_credit_and_counts_match_every_native_cell", report["checks"])

    def test_balances_and_total_counts_cannot_hide_changed_gross_activity(self):
        texts = fixtures()
        # Same account/currency net and same posting counts; crossing one
        # original credit into a debit changes gross activity independently.
        texts["beancount"] = texts["beancount"].replace(
            "  Assets:A1000-10  -20.12 USD\n  Expenses:A5000  20.12 USD\n",
            "  Assets:A1000-10  1.00 USD\n  Expenses:A5000  -1.00 USD\n",
        ).replace(
            "  Assets:A1000-10  -130.15 USD\n  Expenses:A5000  130.15 USD\n",
            "  Assets:A1000-10  -151.27 USD\n  Expenses:A5000  151.27 USD\n",
        )
        _, report = self.run_external(texts)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("beanquery_net_and_counts_match_every_native_cell", report["checks"])
        self.assertIn("bean-query debit/posting-count", report["error"])

    def test_balanced_offsetting_extra_entries_fail_even_when_every_balance_agrees(self):
        texts = fixtures()
        texts["beancount"] += (
            '\n2024-01-05 * "extra"\n  Assets:A1000-10  1.00 USD\n  Expenses:A5000  -1.00 USD\n'
            '\n2024-01-06 * "extra reverse"\n  Assets:A1000-10  -1.00 USD\n  Expenses:A5000  1.00 USD\n'
        )
        _, report = self.run_external(texts)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("bean-query net/posting-count", report["error"])

    def test_removing_balanced_offsetting_entries_fails_both_real_engines(self):
        complete = fixtures(POSTINGS + (
            ("2024-01-05", "USD", 2, "1000.10", "1.00", "5000", "-1.00"),
            ("2024-01-06", "USD", 2, "1000.10", "-1.00", "5000", "1.00"),
        ))
        for kind in ("beancount", "hledger_journal"):
            with self.subTest(kind=kind):
                # The source has both cancelling transactions. Omitting them
                # from just one export keeps every net balance unchanged.
                texts = dict(complete)
                texts[kind] = fixtures()[kind]
                _, report = self.run_external(texts)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn("bean_check_validates_untouched_export", report["checks"])
                expected = ("bean-query net/posting-count" if kind == "beancount"
                            else "hledger transaction count")
                self.assertIn(expected, report["error"])


if __name__ == "__main__":
    unittest.main()
