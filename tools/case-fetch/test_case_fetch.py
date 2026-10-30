"""Unit tests for case_fetch.py (bead fa-yugf.22, A9), run with
`python3 -B -m unittest discover tools/case-fetch` and by fa-oracles'
`case_fetch_unittests_pass` gate test.

The fixture documents under fixtures/docs are synthetic. No test reaches a
remote network: fetch tests run in this process against a 127.0.0.1 server,
and a guard on socket.connect refuses every other address.
"""

import contextlib
import gzip
import hashlib
import http.server
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
import zlib
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_fetch as cf  # noqa: E402

FIXTURES = HERE / "fixtures"
DOCS = FIXTURES / "docs"
TOOL = HERE / "case_fetch.py"
BINDING = HERE.parents[1] / "crates" / "fa-oracles" / "data" / "binding_fixtures.toml"
FETCHED_UTC = "2026-10-26T00:00:00Z"
LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost")

_connect = socket.socket.connect


def _guarded_connect(self, address):
    host = address[0] if isinstance(address, tuple) else address
    if host not in LOCAL_HOSTS:
        raise OSError(f"test network guard: refused a connection to {address!r}")
    return _connect(self, address)


socket.socket.connect = _guarded_connect


def sha(data):
    return hashlib.sha256(data).hexdigest()


def qsha(text):
    return sha(text.encode("utf-8"))


def read_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


class Case:
    """A temporary copy of the fixture case and an empty cache."""

    def __init__(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.dir = self.root / "case"
        self.cache = self.root / "cache"
        shutil.copytree(FIXTURES / "case", self.dir)
        self.cache.mkdir()
        env = mock.patch.dict(os.environ, {"FA_CASES_CACHE": str(self.cache)})
        env.start()
        test.addCleanup(env.stop)
        os.environ.pop("FA_SEC_CONTACT", None)

    def sources(self):
        return read_toml(self.dir / "sources.toml")["source"]

    def seed(self):
        """Put every recorded source's fixture bytes in the cache."""
        for s in self.sources():
            if "sha256" in s:
                self.put(s["sha256"], (DOCS / s["archive_url"].rsplit("/", 1)[1]).read_bytes())
        return self

    def put(self, digest, data):
        (self.cache / digest).write_bytes(data)
        (self.cache / (digest + ".fetched.json")).write_text(
            json.dumps({"fetched_utc": FETCHED_UTC, "url": "fixture"}) + "\n", encoding="utf-8")

    def add(self, file, text):
        with open(self.dir / file, "a", encoding="utf-8") as f:
            f.write("\n" + text)

    def run(self, *args, extra_env=None):
        """The tool in this process: (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        env = dict(extra_env or {})
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = cf.main([args[0], str(self.dir), *args[1:]])
        return code, out.getvalue(), err.getvalue()

    def receipts(self):
        return {r["fact"]: r for r in read_toml(self.dir / "receipts.toml")["receipt"]}


def fact_row(fid, source, kind, anchor, quote, about_scope, granularity="journal_entry",
             cell=None):
    lines = ["[[fact]]", f'id = "{fid}"', 'provenance = "sourced"', f'source = "{source}"',
             f'anchor_kind = "{kind}"', f'anchor = "{anchor}"', f'quote_sha256 = "{qsha(quote)}"',
             f'about_scope = "{about_scope}"', f'granularity = "{granularity}"']
    if cell:
        lines.append(f'cell = "{cell}"')
    return "\n".join(lines) + "\n"


def value_row(fid, ordinal, literal, rule, value, unit="", param=None, precision=None):
    lines = ["[[value]]", f'fact = "{fid}"', f"ordinal = {ordinal}", f'literal = "{literal}"',
             f'rule = "{rule}"']
    if param is not None:
        lines.append(f"param = {param}")
    lines += [f'value = "{value}"', f'unit = "{unit}"']
    if precision is not None:
        lines.append(f"precision = {precision}")
    return "\n".join(lines) + "\n"


TRANSFER = ("During the second quarter of 2001, the Example Company transferred $560 million of "
            "line costs to construction in progress on July 17, 2001.")


class VerifyFixture(unittest.TestCase):
    def test_verify_writes_receipts_with_all_four_booleans_true(self):
        case = Case(self).seed()
        code, out, _ = case.run("verify")
        self.assertEqual(code, 0, out)
        receipts = case.receipts()
        facts = {f["id"]: f for f in read_toml(case.dir / "facts.toml")["fact"]}
        self.assertEqual(sorted(receipts), sorted(facts))
        sources = {s["id"]: s for s in case.sources()}
        binding = {r["id"]: r for r in read_toml(BINDING)["values"]}
        for fid, r in receipts.items():
            with self.subTest(fact=fid):
                self.assertIn(f"VERIFY {fid} PASS", out)
                for key in ("quote_found_once", "aligned", "values_in_quote", "scope_ok"):
                    self.assertIs(r[key], True, key)
                kind = facts[fid]["anchor_kind"]
                self.assertEqual(r["alignment"], "value" if kind in ("table_cell", "xbrl")
                                 else "sentence")
                self.assertEqual(r["quote_sha256"], facts[fid]["quote_sha256"])
                self.assertEqual(r["original_hash_compared"],
                                 sources[r["source"]]["original_hash_compared"])
                self.assertEqual(r["verified_utc"], FETCHED_UTC)
        # The fixture facts carrying F4's and W406-TA-2000's values and scopes
        # hash to the bytes fa-oracles' Rust values_canonical produced.
        self.assertEqual(receipts["FX-TRANSFER"]["values_sha256"], binding["F4"]["values_sha256"])
        self.assertEqual(receipts["FX-TA"]["values_sha256"],
                         binding["W406-TA-2000"]["values_sha256"])
        # The receipt's anchor is the range the quote was found at.
        self.assertEqual(receipts["FX-TRANSFER"]["anchor"], "p12:l3-4")
        self.assertEqual(receipts["FX-LINE"]["anchor"], "l7-7")
        self.assertEqual(receipts["FX-PARA"]["anchor"], "para29")

    def test_rerun_on_unchanged_cache_is_byte_identical(self):
        case = Case(self).seed()
        self.assertEqual(case.run("verify")[0], 0)
        first = (case.dir / "receipts.toml").read_bytes()
        self.assertEqual(case.run("verify")[0], 0)
        self.assertEqual((case.dir / "receipts.toml").read_bytes(), first)

    def test_value_bound_fact_gets_alignment_value_and_prose_fact_sentence(self):
        case = Case(self).seed()
        self.assertEqual(case.run("verify")[0], 0)
        r = case.receipts()
        self.assertEqual(r["FX-TA"]["alignment"], "value")
        self.assertEqual(r["FX-XBRL"]["alignment"], "value")
        self.assertEqual(r["FX-TRANSFER"]["alignment"], "sentence")
        self.assertEqual(r["FX-LINE"]["alignment"], "sentence")

    def test_paragraph_anchor_is_prose(self):
        case = Case(self).seed()
        self.assertEqual(case.run("verify")[0], 0)
        self.assertEqual(case.receipts()["FX-PARA"]["alignment"], "sentence")

    def test_receipts_parse_with_the_registry_toml_subset(self):
        case = Case(self).seed()
        self.assertEqual(case.run("verify")[0], 0)
        text = (case.dir / "receipts.toml").read_text(encoding="utf-8")
        read_toml(case.dir / "receipts.toml")
        for n, line in enumerate(text.splitlines(), 1):
            with self.subTest(line=n):
                if not line or line.startswith("#") or line == "[[receipt]]":
                    continue
                key, sep, value = line.partition(" = ")
                self.assertTrue(sep and key.replace("_", "").isalnum(), line)
                if value in ("true", "false"):
                    continue
                self.assertTrue(value.startswith('"') and value.endswith('"'), line)
                body = value[1:-1].replace("\\\\", "").replace('\\"', "")
                body = body.replace("\\n", "").replace("\\t", "")
                self.assertNotIn("\\", body, "only the four escapes")
                self.assertNotIn('"', body)

    def test_verify_accepts_a_case_directory_path(self):
        before = {p: p.read_bytes() for p in (FIXTURES / "case").iterdir()}
        case = Case(self).seed()
        self.assertEqual(case.run("verify")[0], 0)
        self.assertTrue((case.dir / "receipts.toml").is_file())
        self.assertFalse((FIXTURES / "case" / "receipts.toml").exists())
        self.assertEqual({p: p.read_bytes() for p in (FIXTURES / "case").iterdir()}, before)


class VerifyPlantedFailures(unittest.TestCase):
    """The five planted failures of §4.4 and the derived ones; each prints a
    `FAIL ` line naming the fact and exits 1."""

    def planted(self, *rows):
        case = Case(self).seed()
        for file, text in rows:
            case.add(file, text)
        code, out, _ = case.run("verify")
        return case, code, out

    def assert_fails(self, code, out, fid, words):
        self.assertEqual(code, 1, out)
        lines = [ln for ln in out.splitlines() if ln.startswith(f"FAIL {fid} ")]
        self.assertTrue(lines, out)
        self.assertTrue(any(words in ln for ln in lines), lines)

    def test_quote_not_found_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-ABSENT", "SRC-FX-001", "page", "p12:l3-10",
            "The committee approved every entry.", "period:2001Q2")))
        self.assert_fails(code, out, "FX-ABSENT", "no sentence-aligned span")

    def test_quote_found_twice_fails(self):
        case, code, out = self.planted(("facts.toml", fact_row(
            "FX-TWICE", "SRC-FX-001", "page", "p12:l10-10", "The committee reviewed the ledger.",
            "period:FY2001", "statement_line")))
        self.assert_fails(code, out, "FX-TWICE", "spans at the anchor")
        self.assertIs(case.receipts()["FX-TWICE"]["quote_found_once"], False)

    def test_value_not_in_quote_fails(self):
        case, code, out = self.planted(
            ("facts.toml", fact_row("FX-VALUE", "SRC-FX-001", "page", "p12:l3-5", TRANSFER,
                                    "period:2001Q2")),
            ("facts.toml", value_row("FX-VALUE", 1, "$561 million", "scale", "56100000000",
                                     "USD", 6, 6)))
        self.assert_fails(code, out, "FX-VALUE", "is not in the quote")
        self.assertIs(case.receipts()["FX-VALUE"]["values_in_quote"], False)

    def test_value_under_the_wrong_rule_result_fails(self):
        _, code, out = self.planted(
            ("facts.toml", fact_row("FX-SCALE", "SRC-FX-001", "page", "p12:l3-5", TRANSFER,
                                    "period:2001Q2")),
            ("facts.toml", value_row("FX-SCALE", 1, "$560 million", "scale", "560000000",
                                     "USD", 6, 6)))
        self.assert_fails(code, out, "FX-SCALE", "under scale is 56000000000")

    def test_scope_conflict_fails(self):
        quote = ("These entries for the first quarter of 2001 were made without any supporting "
                 "documentation or proper business rationale.")
        case, code, out = self.planted(("facts.toml", fact_row(
            "FX-SCOPE", "SRC-FX-001", "page", "p12:l8-9", quote, "entry:FX-TRANSFER")))
        self.assert_fails(code, out, "FX-SCOPE",
                          "scope: names period 2001Q1, entry FX-TRANSFER is 2001Q2")
        self.assertIs(case.receipts()["FX-SCOPE"]["scope_ok"], False)

    def test_entry_scope_naming_no_fact_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-NO-ENTRY", "SRC-FX-001", "page", "p12:l3-5", TRANSFER, "entry:FX-NONE")))
        self.assert_fails(code, out, "FX-NO-ENTRY", "scope: entry:FX-NONE names no fact")

    def test_unstructured_scope_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-FREE", "SRC-FX-001", "page", "p12:l3-5", TRANSFER,
            "the 2Q01 line-cost transfer to CIP")))
        self.assert_fails(code, out, "FX-FREE", "is not entry:<fact>, period:<label>")

    def test_sentence_fragment_fails(self):
        case, code, out = self.planted(("facts.toml", fact_row(
            "FX-FRAGMENT", "SRC-FX-001", "page", "p12:l6-7", "entered and approved",
            "entry:FX-TRANSFER")))
        self.assert_fails(code, out, "FX-FRAGMENT", "not sentence-aligned")
        r = case.receipts()["FX-FRAGMENT"]
        self.assertIs(r["aligned"], False)
        self.assertIs(r["quote_found_once"], True)

    def test_part_of_a_heading_line_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-HEAD-PART", "SRC-FX-001", "page", "p12:l1-1", "SUMMARY",
            "period:FY2001", "statement_line")))
        self.assert_fails(code, out, "FX-HEAD-PART", "not sentence-aligned")

    def test_fact_citing_a_blocked_source_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-BLOCKED", "SRC-FX-005", "line", "l1-1",
            "A candidate source the fixture marks BLOCKED.", "period:FY2001")))
        self.assert_fails(code, out, "FX-BLOCKED", "status is BLOCKED (facts may cite only OK")

    def test_quote_outside_its_anchor_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-ELSEWHERE", "SRC-FX-001", "page", "p12:l8-9", TRANSFER,
            "period:2001Q2")))
        self.assert_fails(code, out, "FX-ELSEWHERE", "no sentence-aligned span")

    def test_xbrl_fact_with_wrong_decimals_fails(self):
        case, code, out = self.planted(
            ("facts.toml", fact_row("FX-XBRL-DEC", "SRC-FX-004", "xbrl", "us-gaap:Assets|c-2022",
                                    "1616334000", "period:FY2022", "xbrl_fact",
                                    "total_assets@2022-12-31")),
            ("facts.toml", value_row("FX-XBRL-DEC", 1, "1616334000", "scale", "161633400000",
                                     "USD", 0, 6)))
        self.assert_fails(code, out, "FX-XBRL-DEC", "decimals:")
        self.assertIs(case.receipts()["FX-XBRL-DEC"]["values_in_quote"], False)

    def test_xbrl_fact_missing_a_dimension_member_fails(self):
        case, code, out = self.planted(
            ("facts.toml", fact_row("FX-XBRL-MEM", "SRC-FX-004", "xbrl",
                                    "us-gaap:Assets|c-2022-adj", "-12000000",
                                    "period:FY2022", "xbrl_fact",
                                    "total_assets@2022-12-31")),
            ("facts.toml", value_row("FX-XBRL-MEM", 1, "-12000000", "scale", "-1200000000",
                                     "USD", 0, 3)))
        self.assert_fails(code, out, "FX-XBRL-MEM", "member:")
        self.assertIs(case.receipts()["FX-XBRL-MEM"]["values_in_quote"], False)

    def test_table_cell_fragment_fails(self):
        _, code, out = self.planted(("facts.toml", fact_row(
            "FX-CELL-PART", "SRC-FX-003", "table_cell", "Selected Financial Data|Basis|2000",
            "previously reported", "period:FY2000", "statement_line", "basis@2000-12-31")))
        self.assert_fails(code, out, "FX-CELL-PART", "fragment of its cell")


class Locate(unittest.TestCase):
    TEXT = ("Intro line.\n\nThe first sentence is here. The second one follows. "
            "The first sentence is here.\nA closing line.\n")

    def bind(self, quote, anchor="l3-3"):
        fact = {"id": "T", "anchor_kind": "line", "anchor": anchor, "quote_sha256": qsha(quote)}
        b = cf.Binding(fact)
        cf.bind_prose(cf.Located(self.TEXT), fact, b)
        return b

    def test_find_by_hash_selects_the_one_matching_span(self):
        b = self.bind("The second one follows.")
        self.assertEqual(b.quote, "The second one follows.")
        self.assertTrue(b.found_once and b.aligned, b.problems)
        self.assertEqual(b.anchor, "l3-3")
        two = self.bind("The second one follows. The first sentence is here.")
        self.assertTrue(two.aligned and two.found_once, two.problems)

    def test_find_by_hash_with_zero_or_two_matches_fails(self):
        zero = self.bind("No such sentence.")
        self.assertFalse(zero.found_once or zero.aligned)
        self.assertTrue(any("no sentence-aligned span" in p for p in zero.problems))
        twice = self.bind("The first sentence is here.")
        self.assertFalse(twice.found_once)
        self.assertTrue(any("2 spans" in p for p in twice.problems), twice.problems)

    def test_heading_only_line_is_one_sentence(self):
        loc = cf.Located("Body text.\nUNAUDITED\nMore body text.")
        fact = {"id": "H", "anchor_kind": "line", "anchor": "l2-2", "quote_sha256": qsha("UNAUDITED")}
        b = cf.Binding(fact)
        cf.bind_prose(loc, fact, b)
        self.assertTrue(b.found_once and b.aligned, b.problems)

    def test_missing_page_label_fails(self):
        fact = {"id": "P", "anchor_kind": "page", "anchor": "p99:l1-1", "quote_sha256": qsha("x")}
        b = cf.Binding(fact)
        cf.bind_prose(cf.Located("a.\f12\n"), fact, b)
        self.assertTrue(any("printed page 99" in p for p in b.problems), b.problems)


class TableCells(unittest.TestCase):
    """The table layouts filings print (synthetic text in each shape)."""

    # EDGAR's stripped HTML: header cells over several lines, the label above its values;
    # the same table printed twice, on printed pages 48 and 49.
    STACKED_PAGE = ("As of December 31, 2000\n\nPreviously\nReported(1)\n\nOther\nAdjustments\n\n"
                    "As Restated\n\nAssets:\n\nCurrent assets\n$\t9,657\t$\t(160\t)\t$\t9,497\n\n"
                    "Total\n$\t98,727\t$\t(54,539\t)\t$\t44,188\n\n{n}\n")
    STACKED = STACKED_PAGE.format(n=48) + "\f" + STACKED_PAGE.format(n=49)
    YEARS = ("As of December 31,\n\nPro Forma\n\n2002(4)\n\n2002\n\n1999\n\n"
             "(Unaudited)\t(Restated)\t(Restated)\n\nTotal assets\n24,247\t26,536\t85,280\n")
    LEADERS = ("SELECTED DATA\n                  1999       2000\n"
               "Total assets............  $91,072    $98,903\n")
    FDS = ("<DESCRIPTION>FINANCIAL DATA SCHEDULE DEC. 31, 1999\n<MULTIPLIER> 1,000,000\n"
           "<S>             <C>\n<TOTAL-ASSETS>                91,072\n")

    def cell(self, text, anchor):
        return [c for c, _ in cf.table_cell(cf.Located(text), anchor)]

    def test_stacked_layout_reads_multi_line_headers_from_the_right(self):
        table = "As of December 31, 2000@p49"
        self.assertEqual(self.cell(self.STACKED, f"{table}|Total|Previously Reported(1)"), ["98,727"])
        self.assertEqual(self.cell(self.STACKED, f"{table}|Total|Other Adjustments"), ["(54,539)"])
        self.assertEqual(self.cell(self.STACKED, f"{table}|Total|As Restated"), ["44,188"])
        # Without the page pin the twice-printed table resolves twice (verify refuses it).
        self.assertEqual(self.cell(self.STACKED, "As of December 31, 2000|Total|As Restated"),
                         ["44,188", "44,188"])
        self.assertEqual(self.cell(self.YEARS, "As of December 31,|Total assets|1999"), ["85,280"])
        self.assertEqual(self.cell(self.YEARS, "As of December 31,|Total assets|2002"), ["26,536"])

    # A 2008-era EDGAR statement whose cells hold block elements: one cell per line, `$` and a
    # closing `)` on lines of their own, a descriptive line under a label.
    PERCELL = ("LEHMAN-STYLE HOLDINGS\n\nStatement of Financial Condition\n\nAt\n\nIn millions\n\n"
               "May 31, 2008\n\nNov 30, 2007\n\nAssets\n\nCash\n\n$\n\n6,513\n\n$\n\n7,286\n\n"
               "Inventory owned\n(includes $43,031 in 2008 pledged as collateral)\n\n269,409\n\n"
               "313,129\n\nAccumulated loss\n\n(359\n\n)\n\n(310\n\n)\n\nCommitments\n\n"
               "Total assets\n\n$\n\n639,432\n\n$\n\n691,063\n")

    def test_percell_layout_reads_one_cell_per_line(self):
        table = "Statement of Financial Condition"
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Cash|May 31, 2008"), ["6,513"])
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Cash|Nov 30, 2007"), ["7,286"])
        # A descriptive line between a label and its values is skipped.
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Inventory owned|Nov 30, 2007"),
                         ["313,129"])
        # A value split from its closing parenthesis is one cell.
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Accumulated loss|May 31, 2008"),
                         ["(359)"])
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Total assets|Nov 30, 2007"),
                         ["691,063"])
        # No column of that name, or a row with too few values, resolves nothing.
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Cash|Dec 31, 2008"), [])
        self.assertEqual(self.cell(self.PERCELL, f"{table}|Commitments|May 31, 2008"), [])

    # A `pdftotext -layout` table: month-days over years, two of them a single space apart, a
    # label split by a wide gap, and ratio cells.
    DATECOL = ("                     Ratios Table\n\n"
               "                              At the Quarter Ended\n"
               "                       May 31       Feb 29,  Nov 30, Aug 31,\n"
               "  $ in Millions         2008         2008      2007      2007\n"
               "  (a) Total Assets    639,432      786,035   691,063   659,216\n"
               "      Less:\n"
               "      Segregated cash    (13,031)   (16,569)   (12,743)  (10,579)\n"
               "  Leverage Ratio     (a) / (c)   24.3 x   31.7 x   30.7 x   30.3 x\n")

    # An EDGAR text filing: the balance sheet continues under its repeated title, row labels
    # run over several lines with the values on the last, and a subsidiary's statements (whose
    # title contains the parent's) follow.
    TEXT_BS = ("                 CONSOLIDATED BALANCE SHEET\n"
               "                                              December 31,\n"
               "(In millions)                              2000         1999\n"
               "ASSETS\n"
               "  Cash and cash equivalents               $ 1,374     $   288\n"
               "  Trade receivables (net of allowance\n"
               "   for doubtful accounts of $133 and\n"
               "   $40, respectively)                      10,396       3,030\n"
               "  Inventories                                 953         598\n"
               "Total Assets                              $65,503     $33,381\n"
               "\n"
               "                 CONSOLIDATED BALANCE SHEET\n"
               "                                                    December 31,\n"
               "(In millions, except shares)                      2000         1999\n"
               "  Accounts payable                               $ 9,777     $ 2,154\n"
               "Commitments and Contingencies\n"
               " (Notes 13, 14 and 15)\n"
               "\n"
               "Minority Interests                                 2,414       2,430\n"
               "<PAGE>\n"
               "             CONSOLIDATED STATEMENT OF CASH FLOWS\n"
               "  Inventories                                (133)        (12)\n"
               "\n"
               "                        CONSOLIDATED BALANCE SHEETS\n"
               "                                              2000         1999\n"
               "  Cash and cash equivalents                   30.0        25.0\n")

    def test_text_filing_titles_labels_and_continued_statements(self):
        table = "CONSOLIDATED BALANCE SHEET"
        # The subsidiary's longer title is no title when lines equal the anchor's exactly.
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}|Cash and cash equivalents|2000"),
                         ["$ 1,374"])
        # A table ends at the text filing's <PAGE> line: the cash flow statement after it is not
        # the balance sheet's.
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}|Inventories|2000"), ["953"])
        # `#<n>` on the table part names the n-th table under the repeated title.
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}#2|Accounts payable|2000"), ["$ 9,777"])
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}#1|Accounts payable|2000"), [])
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}#3|Accounts payable|2000"), [])
        # A row both titles reach is one cell, not one per title.
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}|Accounts payable|2000"), ["$ 9,777"])
        # A label over three lines is anchored by its first; the values are on its last.
        self.assertEqual(
            self.cell(self.TEXT_BS, f"{table}|Trade receivables (net of allowance|1999"), ["3,030"])
        # A label that continues onto no values resolves nothing.
        self.assertEqual(self.cell(self.TEXT_BS, f"{table}|Commitments and Contingencies|2000"), [])
        # A repeated label is addressed by its occurrence; one past the last resolves nothing.
        rep = ("BALANCE\n           2000\n  Other     5\n  Assets from price risk\n   management   7\n"
               "  Other     9\n  Assets from price risk\n   management   11\n")
        self.assertEqual(self.cell(rep, "BALANCE|Other|2000"), ["5"])
        self.assertEqual(self.cell(rep, "BALANCE|Other#2|2000"), ["9"])
        self.assertEqual(self.cell(rep, "BALANCE|Other#3|2000"), [])
        self.assertEqual(self.cell(rep, "BALANCE|Assets from price risk#2|2000"), ["11"])
        # Without an exact title line, the subsidiary's table is found by containment.
        self.assertEqual(
            self.cell(self.TEXT_BS, "CONSOLIDATED BALANCE SHEETS|Cash and cash equivalents|2000"),
            ["30.0"])

    def test_datecol_layout_pairs_month_days_with_years(self):
        table = "Ratios Table"
        self.assertEqual(self.cell(self.DATECOL, f"{table}|(a) Total Assets|May 31, 2008"),
                         ["639,432"])
        # Month-days a single space apart are still separate columns.
        self.assertEqual(self.cell(self.DATECOL, f"{table}|(a) Total Assets|Aug 31, 2007"),
                         ["659,216"])
        self.assertEqual(self.cell(self.DATECOL, f"{table}|Segregated cash|Nov 30, 2007"),
                         ["(12,743)"])
        # A label split by a wide gap is one label; a ratio cell is a value.
        self.assertEqual(self.cell(self.DATECOL,
                                   f"{table}|Leverage Ratio (a) / (c)|Feb 29, 2008"), ["31.7 x"])
        # No such column, or a row with no values, resolves nothing.
        self.assertEqual(self.cell(self.DATECOL, f"{table}|(a) Total Assets|May 31, 2009"), [])
        self.assertEqual(self.cell(self.DATECOL, f"{table}|Less:|May 31, 2008"), [])

    def test_leader_dots_and_fds_tags(self):
        self.assertEqual(self.cell(self.LEADERS, "SELECTED DATA|Total assets|2000"), ["$98,903"])
        fds = "FINANCIAL DATA SCHEDULE DEC. 31, 1999"
        self.assertEqual(self.cell(self.FDS, f"{fds}|<TOTAL-ASSETS>|<C>"), ["91,072"])
        self.assertEqual(self.cell(self.FDS, f"{fds}|<MULTIPLIER>|<C>"), ["1,000,000"])
        self.assertEqual(self.cell(self.FDS, f"{fds}|<CASH>|<C>"), [])

    def test_unknown_column_or_row_finds_nothing(self):
        self.assertEqual(self.cell(self.STACKED, "As of December 31, 2000@p49|Total|Restated"), [])
        self.assertEqual(self.cell(self.STACKED, "As of December 31, 2000@p49|Goodwill|As Restated"),
                         [])
        self.assertEqual(self.cell(self.STACKED, "As of December 31, 2000@p50|Total|As Restated"), [])


class SharedFixtures(unittest.TestCase):
    """The rows fa-oracles' Rust checks read too (binding_fixtures.toml)."""

    def test_normalization_matches_the_shared_fixtures(self):
        for row in read_toml(BINDING)["normalize"]:
            with self.subTest(row=row["id"]):
                got = cf.normalize(bytes.fromhex(row["input_hex"]).decode("utf-8"))
                self.assertEqual(got, bytes.fromhex(row["normalized_hex"]).decode("utf-8"))
                self.assertEqual(sha(got.encode("utf-8")), row["quote_sha256"])

    def test_sentence_alignment_matches_the_shared_fixtures(self):
        for row in read_toml(BINDING)["sentence"]:
            with self.subTest(row=row["id"]):
                loc = cf.Located(row["text"])
                quote = cf.normalize(row["quote"])
                self.assertEqual(loc.count(quote), row["count"])
                s = loc.norm.find(quote)
                aligned = s in loc.starts and s + len(quote) in loc.ends
                self.assertEqual(aligned, row["aligned"])

    def test_scope_matches_the_shared_fixtures(self):
        for row in read_toml(BINDING)["scope"]:
            with self.subTest(row=row["id"]):
                entry = row.get("entry_period") or None
                ok, why = cf.scope_ok(row["quote"], row["about_scope"], row["granularity"],
                                      lambda _fact: entry, frozenset(row.get("case_accounts", [])))
                self.assertEqual(ok, row["scope_ok"], why)
                self.assertEqual(why, row["reason"])

    def test_values_sha256_matches_the_shared_fixture_rows(self):
        for row in read_toml(BINDING)["values"]:
            with self.subTest(row=row["id"]):
                values = []
                for line in row["value_lines"]:
                    ordinal, literal, rule, param, value, unit, precision = line.split("\t")
                    values.append({"ordinal": int(ordinal), "literal": literal, "rule": rule,
                                   "param": int(param) if param else None, "value": value,
                                   "unit": unit,
                                   "precision": int(precision) if precision else None})
                data = cf.values_canonical(row["about_scope"], values)
                self.assertEqual(data.hex(), row["canonical_hex"])
                self.assertEqual(sha(data), row["values_sha256"])


class Rules(unittest.TestCase):
    SCALES = {"USD": 2}

    def rule(self, rule, literal, param=None, unit="", precision=None):
        return cf.apply_rule(rule, literal, param, unit, precision, self.SCALES)

    def test_literal_rules(self):
        self.assertEqual(self.rule("scale", "$560 million", 6, "USD", 6), "56000000000")
        self.assertEqual(self.rule("scale", "$742,725,000", 0, "USD", 0), "74272500000")
        self.assertEqual(self.rule("scale", "$1.4 billion", 9, "USD", 8), "140000000000")
        self.assertEqual(self.rule("scale", "98,727", 0, "", 0), "98727")
        self.assertEqual(self.rule("scale", "(1,234)", 0, "USD", 0), "-123400")
        self.assertEqual(self.rule("number_word", "three"), "3")
        self.assertEqual(self.rule("date_literal", "July 17, 2001"), "2001-07-17")
        self.assertEqual(self.rule("date_range_literal",
                                   "on or about and between July 17 and 19, 2000"),
                         "2000-07-17..2000-07-19")
        self.assertEqual(self.rule("month_literal", "In September 2001"), "2001-09")
        self.assertEqual(self.rule("month_day_literal", "Friday, April 20"), "--04-20 Friday")
        self.assertEqual(self.rule("month_day_literal", "On August 22"), "--08-22")
        self.assertEqual(self.rule("month_day_literal", "February 29"), "--02-29")
        self.assertEqual(self.rule("month_day_literal", "Over the course of April 23 and 24"),
                         "--04-23..--04-24")
        for planted in ("July 17, 2001", "February 30", "Friday", "April 24 and 23",
                        "April 23 and 24, 2001"):
            with self.assertRaises(cf.RuleError, msg=planted):
                self.rule("month_day_literal", planted)
        self.assertEqual(self.rule("period_literal", "the second quarter of 2001"), "2001Q2")
        self.assertEqual(self.rule("period_literal", "1Q02"), "2002Q1")

    def test_scale_reads_the_derivation_tables_literal_grammar(self):
        # A2's scale grammar (fa-oracles derive.rs): dashes, U+2212, parentheses,
        # and x/% only on a unitless value.
        self.assertEqual(self.rule("scale", "\u2014", 6, "USD", 6), "0")
        self.assertEqual(self.rule("scale", "-", 6, "USD", 6), "0")
        self.assertEqual(self.rule("scale", "\u2212153", 6, "USD", 6), "-15300000000")
        self.assertEqual(self.rule("scale", "(153)", 6, "USD", 6), "-15300000000")
        self.assertEqual(self.rule("scale", "13.9x", 0, "", -1), "139")
        with self.assertRaises(cf.RuleError):
            self.rule("scale", "13.9x", 0, "USD", 0)

    def test_a_rule_that_does_not_fit_its_literal_is_refused(self):
        with self.assertRaises(cf.RuleError):
            self.rule("scale", "$1.45 million", 6, "", 6)
        with self.assertRaises(cf.RuleError):
            self.rule("date_literal", "sometime in 2001")
        with self.assertRaises(cf.RuleError):
            self.rule("period_literal", "the first and second quarters of 2001 and 2002Q1")
        with self.assertRaises(cf.RuleError):
            self.rule("period_literal", "1Q01 and 2Q01")

    def test_a_literal_inside_a_longer_number_does_not_bind(self):
        self.assertFalse(cf.literal_in("560", "a total of 5,560 dollars"))
        self.assertFalse(cf.literal_in("560", "a total of 1560 dollars"))
        self.assertTrue(cf.literal_in("560", "a total of 560 dollars"))
        self.assertTrue(cf.literal_in("$560 million", "transferred $560 million of costs"))


class Extract(unittest.TestCase):
    def test_html_strip_separates_blocks_cells_and_pages(self):
        text = cf.strip_html((DOCS / "filing.htm").read_bytes())
        pages = text.split("\f")
        self.assertEqual(len(pages), 2)
        self.assertIn("Total assets\t$\t103,914\t$\t98,727", pages[0])
        self.assertNotIn("padding", text, "style content is dropped")
        self.assertTrue(pages[0].endswith("As restated\tAs previously reported\n"), pages[0])
        self.assertTrue(pages[1].startswith("The amounts above"))

    def test_extract_prints_each_sources_extraction_field(self):
        case = Case(self).seed()
        code, out, _ = case.run("extract")
        self.assertEqual(code, 0, out)
        report = (DOCS / "report.txt").read_bytes()
        self.assertIn(f'EXTRACT SRC-FX-001 extraction = ["case_fetch.py extract", "text-utf-8", '
                      f'"{sha(report)}"]', out)
        self.assertIn('"case-fetch-strip-v1"', out)

    def test_missing_pdftotext_reports_unrun(self):
        case = Case(self)
        pdf = b"%PDF-1.4 synthetic fixture bytes\n"
        case.put(sha(pdf), pdf)
        case.add("sources.toml", "\n".join([
            "[[source]]", 'id = "SRC-FX-PDF"', 'title = "A pdf source"', 'publisher = "fixture"',
            'original_url = "http://127.0.0.1:PORT/report.pdf"',
            'retrieval_route = "original"', "original_hash_compared = false",
            f'sha256 = "{sha(pdf)}"', 'format = "pdf"', 'redistribution_basis = "fixture"',
            'assertion_status = "allegation"', 'anchor_scheme = ["page"]', 'status = "OK"', ""]))
        empty = Path(tempfile.mkdtemp(dir=case.root))
        env = dict(os.environ, PATH=str(empty), FA_CASES_CACHE=str(case.cache))
        out = subprocess.run([sys.executable, "-B", str(TOOL), "extract", str(case.dir)],
                             env=env, capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(out.returncode, 4, out.stdout + out.stderr)
        self.assertIn("UNRUN SRC-FX-PDF: pdftotext is not installed", out.stdout)


class XbrlFacts(unittest.TestCase):
    def test_xbrl_facts_rows_carry_instance_lines(self):
        case = Case(self).seed()
        code, out, _ = case.run("xbrl-facts")
        self.assertEqual(code, 0, out)
        lines = (DOCS / "instance.xml").read_text(encoding="utf-8").splitlines()
        rows = [ln.split("\t") for ln in out.splitlines() if ln.startswith("XBRL\t")]
        self.assertEqual([r[1] for r in rows], ["FX-XBRL", "FX-XBRL-ADJ"])
        for row in rows:
            n = int(row[-1].removeprefix("line="))
            self.assertIn(f'contextRef="{row[3]}"', lines[n - 1])
            self.assertIn(f">{row[8]}<", lines[n - 1])
        self.assertIn("srt:RestatementAxis=srt:RestatementAdjustmentMember", rows[1][7])

    DUPLICATED = (
        '<xbrli:xbrl xmlns:xbrli="http://www.xbrl.org/2003/instance"'
        ' xmlns:us-gaap="http://fasb.org/us-gaap/2022">\n'
        '<xbrli:context id="c-1"><xbrli:period><xbrli:instant>2022-12-31</xbrli:instant>'
        '</xbrli:period></xbrli:context>\n'
        '<xbrli:unit id="usd"><xbrli:measure>iso4217:USD</xbrli:measure></xbrli:unit>\n'
        '<us-gaap:Assets contextRef="c-1" unitRef="usd" decimals="-3">1616334000</us-gaap:Assets>\n'
        '<us-gaap:Assets contextRef="c-1" unitRef="usd" decimals="-3">1616334000</us-gaap:Assets>\n'
        '<us-gaap:Liabilities contextRef="c-1" unitRef="usd" decimals="-3">900000000</us-gaap:Liabilities>\n'
        '<us-gaap:Liabilities contextRef="c-1" unitRef="usd" decimals="-5">900100000</us-gaap:Liabilities>\n'
        '</xbrli:xbrl>\n')

    def bind_duplicated(self, concept, literal):
        fact = {"anchor": f"{concept}|c-1", "anchor_kind": "xbrl",
                "quote_sha256": cf.sha256_hex(literal.encode("utf-8")),
                "cell": f"{concept.split(':')[1]}@2022-12-31"}
        values = [{"ordinal": 1, "literal": literal, "rule": "scale", "param": 0,
                   "value": str(int(literal) * 100), "unit": "USD", "precision": 3}]
        b = cf.Binding(fact)
        b.member_ok = True
        cf.bind_xbrl(self.DUPLICATED, fact, values, {"USD": 2}, b)
        return b

    def test_duplicates_that_agree_are_one_fact(self):
        b = self.bind_duplicated("us-gaap:Assets", "1616334000")
        self.assertEqual(b.problems, [])
        self.assertIs(b.found_once, True)
        self.assertIs(b.aligned, True)

    def test_duplicates_that_disagree_fail(self):
        b = self.bind_duplicated("us-gaap:Liabilities", "900000000")
        self.assertIs(b.found_once, False)
        self.assertIn("us-gaap:Liabilities in context c-1 occurs 2 times with 2 different values",
                      b.problems)


class DecodeContent(unittest.TestCase):
    def test_identity_gzip_and_deflate_decode_and_anything_else_refuses(self):
        doc = b"<html>report</html>"
        self.assertEqual(cf.decode_content(doc, ""), doc)
        self.assertEqual(cf.decode_content(doc, "identity"), doc)
        self.assertEqual(cf.decode_content(gzip.compress(doc), "gzip"), doc)
        self.assertEqual(cf.decode_content(gzip.compress(doc), " GZIP "), doc)
        self.assertEqual(cf.decode_content(zlib.compress(doc), "deflate"), doc)
        with self.assertRaises(OSError):
            cf.decode_content(doc, "br")
        with self.assertRaises(OSError):
            cf.decode_content(doc, "gzip")


class Handler(http.server.SimpleHTTPRequestHandler):
    agents = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DOCS), **kwargs)

    def do_GET(self):
        Handler.agents.append(self.headers.get("User-Agent", ""))
        super().do_GET()

    def log_message(self, *args):
        pass


class GzipHandler(Handler):
    """Serves each document gzip-encoded, as an Internet Archive capture of an
    EDGAR response arrives (Content-Encoding: gzip)."""

    def do_GET(self):
        Handler.agents.append(self.headers.get("User-Agent", ""))
        body = gzip.compress((DOCS / self.path.lstrip("/")).read_bytes(), mtime=0)
        self.send_response(200)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Fetch(unittest.TestCase):
    def serve(self, handler=Handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def case_on_port(self, handler=Handler):
        case = Case(self)
        port = self.serve(handler)
        path = case.dir / "sources.toml"
        path.write_text(path.read_text(encoding="utf-8").replace("PORT", str(port)),
                        encoding="utf-8")
        return case

    def test_fetch_stores_verified_bytes_and_skips_blocked_rows(self):
        Handler.agents = []
        case = self.case_on_port()
        with mock.patch.object(cf, "MIN_REQUEST_INTERVAL_S", 0.0):
            code, out, _ = case.run("fetch")
        self.assertEqual(code, 0, out)
        self.assertIn("SKIP SRC-FX-005 BLOCKED fixture: an unread candidate", out)
        for s in case.sources():
            if s["status"] == "OK":
                self.assertIn(f"FETCHED {s['id']} sha256={s['sha256']}", out)
                self.assertTrue((case.cache / s["sha256"]).is_file())
        self.assertTrue(Handler.agents)
        self.assertTrue(all(a == cf.USER_AGENT for a in Handler.agents), Handler.agents)
        code, out, _ = case.run("fetch")
        self.assertEqual(code, 0, out)
        self.assertIn("CACHED SRC-FX-001", out)

    def test_fetch_decodes_a_gzip_content_encoding_before_hashing(self):
        case = self.case_on_port(GzipHandler)
        with mock.patch.object(cf, "MIN_REQUEST_INTERVAL_S", 0.0):
            code, out, _ = case.run("fetch", "--source", "SRC-FX-001")
        self.assertEqual(code, 0, out)
        report = (DOCS / "report.txt").read_bytes()
        self.assertIn(f"FETCHED SRC-FX-001 sha256={sha(report)}", out)
        self.assertTrue(out.rstrip().endswith("verified"), out)
        self.assertEqual((case.cache / sha(report)).read_bytes(), report)

    def test_fetch_single_blocked_source_prints_an_unverified_sha256(self):
        case = self.case_on_port()
        code, out, _ = case.run("fetch", "--source", "SRC-FX-005")
        self.assertEqual(code, 0, out)
        blocked = sha((DOCS / "blocked.txt").read_bytes())
        self.assertIn(f"FETCHED SRC-FX-005 sha256={blocked}", out)
        self.assertTrue(out.rstrip().endswith("unverified"), out)
        self.assertFalse((case.dir / "receipts.toml").exists())

    def test_fetch_of_changed_bytes_fails(self):
        case = self.case_on_port()
        path = case.dir / "sources.toml"
        report_sha = sha((DOCS / "report.txt").read_bytes())
        path.write_text(path.read_text(encoding="utf-8").replace(report_sha, "0" * 64),
                        encoding="utf-8")
        code, out, _ = case.run("fetch", "--source", "SRC-FX-001")
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL SRC-FX-001: fetched sha256 {report_sha} differs", out)

    def test_throttle_spaces_requests_by_the_interval(self):
        clock = [0.0]
        slept = []
        with mock.patch.object(cf.time, "monotonic", lambda: clock[0]), \
                mock.patch.object(cf.time, "sleep", lambda s: (slept.append(s),
                                                              clock.__setitem__(0, clock[0] + s))):
            t = cf.Throttle(1.0)
            t.wait()
            clock[0] += 0.25
            t.wait()
        self.assertEqual(slept, [0.75])

    def test_sec_contact_is_never_written(self):
        sentinel = "contact-sentinel-7f3a@example.invalid"
        case = Case(self)
        seen = []

        def opener(url, agent):
            seen.append(agent)
            return (DOCS / "report.txt").read_bytes()

        case.add("sources.toml", "\n".join([
            "[[source]]", 'id = "SRC-FX-SEC"', 'title = "A direct EDGAR row"',
            'publisher = "fixture"',
            'original_url = "https://www.sec.gov/Archives/edgar/data/0/fixture.txt"',
            'retrieval_route = "original"', "original_hash_compared = true", 'format = "txt"',
            'redistribution_basis = "fixture"', 'assertion_status = "allegation"',
            'anchor_scheme = ["line"]', 'status = "OK"', ""]))
        report = cf.Report(io.StringIO())
        with mock.patch.dict(os.environ, {"FA_SEC_CONTACT": ""}):
            os.environ.pop("FA_SEC_CONTACT")
            cf.fetch(case.dir, "SRC-FX-SEC", report, opener=opener, throttle=cf.Throttle(0))
        self.assertEqual(report.exit_code(), 4)
        self.assertEqual(seen, [], "no direct sec.gov request without FA_SEC_CONTACT")
        out = io.StringIO()
        report = cf.Report(out)
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"FA_SEC_CONTACT": sentinel}), \
                contextlib.redirect_stderr(err):
            cf.fetch(case.dir, "SRC-FX-SEC", report, opener=opener, throttle=cf.Throttle(0))
            self.seed_and_verify(case)
        self.assertEqual(seen, [f"{cf.USER_AGENT} {sentinel}"])
        self.assertNotIn(sentinel, out.getvalue() + err.getvalue())
        for path in case.root.rglob("*"):
            if path.is_file():
                with self.subTest(file=str(path.relative_to(case.root))):
                    self.assertNotIn(sentinel.encode(), path.read_bytes())

    def seed_and_verify(self, case):
        case.seed()
        with contextlib.redirect_stdout(io.StringIO()):
            cf.main(["verify", str(case.dir)])


class Cli(unittest.TestCase):
    def test_usage_error_exits_2(self):
        out = subprocess.run([sys.executable, "-B", str(TOOL), "frobnicate"],
                             capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(out.returncode, 2)

    def test_help_prints_usage(self):
        out = subprocess.run([sys.executable, "-B", str(TOOL), "--help"],
                             capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(out.returncode, 0)
        for word in ("fetch", "extract", "xbrl-facts", "verify"):
            self.assertIn(word, out.stdout)


if __name__ == "__main__":
    unittest.main()
