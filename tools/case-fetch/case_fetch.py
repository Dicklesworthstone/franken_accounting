#!/usr/bin/env python3
"""Fetch, extract and verify the public-record sources of the forensic case studies.

docs/FORENSIC_CASE_STUDIES_PLAN.md §4.4; bead fa-yugf.22 (A9). A facts file is
accepted only with the receipts this tool's `verify` writes, and its review
re-runs `verify` with a second cache (§4.5): the research workspace is not a
source. The tool lives outside the Rust workspace because it needs an HTTP
client and runs only at authoring time; nothing in a test reads the network,
the cache, or this code's output other than the committed receipts, which
fa-oracles validates offline.

Only Python's standard library is used (>= 3.11 for tomllib); run it with
`python3 -B`. Subcommands:

  fetch <case> [--source <id>]   download OK sources into the cache
  extract <case>                 print each cached source's extraction field
  xbrl-facts <case>              print the instance rows the case's xbrl facts cite
  verify <case>                  bind every sourced fact and write receipts.toml

<case> is a directory name under crates/fa-oracles/cases/ or, when it contains
`/`, a path to a case directory. stdout follows the gate vocabulary (`FAIL `
and `UNRUN ` lines at column 0); diagnostics go to stderr. Exit 0 when
everything is verified, 1 on any FAIL, 4 when a required system tool, cached
file or the network is unavailable (UNRUN, never a pass), 2 on a usage error.

The rules below are shared with fa-oracles' Rust checks (A3a) through
crates/fa-oracles/data/binding_fixtures.toml; change both or neither.

Normalization: decode UTF-8, replace every run of U+0009, U+000A, U+000B,
U+000C, U+000D, U+0020 and U+00A0 with one U+0020, trim. No case folding, no
Unicode normalization, typographic quotes kept. `quote_sha256` is the SHA-256
of the normalized bytes.

Sentence alignment: a quote starts at the text's start or after `[.?!]`, an
optional closing `"` or `)`, and whitespace; it ends with `[.?!]` and an
optional closing `"` or `)` followed by whitespace or the end. A `.` whose
preceding token (after a leading `(`, `[` or quote mark) is a registered
abbreviation is not a boundary. A block boundary (a blank line or a page
break in the extraction, and its end) is also a boundary: a quote may start
at a block's first character and end at its last, so the sentence after an
unpunctuated heading can be quoted. Lines of an anchor that contain no
`[.?!]` form one heading sentence: the quote must be their whole normalized
text.

Scope (case-fetch-scope-v1): the period words of a text are quarter labels
(`1Q01`, `2001Q1`, `Q1 2001`, `first quarter of 2001`) and fiscal years
(`fiscal 2001`, `fiscal year 2001`, `FY2001`, each covering its four
quarters); its account words are `account:<id>` and `account <id>` (also
`account No. <id>`, `account number <id>`, `account #<id>`) where <id> is
4-12 upper-case letters and digits with at least one digit. A quote conflicts
with `about_scope` when both name periods and the quarter sets are disjoint,
or both name accounts and the sets are disjoint. An `about_scope` that starts
with `scheme:` cannot back a `journal_entry` fact (§2.1: through an
interpretation only).
"""

import argparse
import hashlib
import html.parser
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import xml.parsers.expat
from fractions import Fraction
from pathlib import Path

TOOL_VERSION = "case-fetch-v1"
STRIP_VERSION = "case-fetch-strip-v1"
SCOPE_VERSION = "case-fetch-scope-v1"
EXTRACT_TOOL = "case_fetch.py extract"
USER_AGENT = "franken_accounting-agent (+https://github.com/Dicklesworthstone/franken_accounting)"
MIN_REQUEST_INTERVAL_S = 1.0

ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = ROOT / "crates" / "fa-oracles" / "cases"
UNITS_FILE = ROOT / "registries" / "units.toml"

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_UNRUN = 0, 1, 2, 4

PROSE_ANCHORS = ("page", "line", "paragraph")
VALUE_ANCHORS = ("table_cell", "xbrl")
TEXT_FORMATS = ("txt", "text")
HTML_FORMATS = ("htm", "html")
XML_FORMATS = ("xml", "xbrl")
FETCH_ROUTES = ("original", "archive_capture", "third_party_copy")
ABBREVIATIONS = frozenset(("p", "pp", "Inc", "Co", "No", "U.S", "Mr", "Ms", "Dr"))
WHITESPACE = frozenset("\t\n\x0b\x0c\r \u00a0")
MONTHS = {
    name: i + 1
    for i, names in enumerate(
        (
            ("january", "jan"),
            ("february", "feb"),
            ("march", "mar"),
            ("april", "apr"),
            ("may",),
            ("june", "jun"),
            ("july", "jul"),
            ("august", "aug"),
            ("september", "sep", "sept"),
            ("october", "oct"),
            ("november", "nov"),
            ("december", "dec"),
        )
    )
    for name in names
}
NUMBER_WORDS = {
    w: i
    for i, w in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve thirteen "
        "fourteen fifteen sixteen seventeen eighteen nineteen twenty".split()
    )
}
NUMBER_WORDS.update({"thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70,
                     "eighty": 80, "ninety": 90, "hundred": 100})
ORDINALS = {"first": 1, "second": 2, "third": 3, "fourth": 4}


class Report:
    """The gate verdict lines: stdout for the transcript, stderr for diagnostics."""

    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.fails = 0
        self.unruns = 0

    def line(self, text):
        print(text, file=self.out)

    def fail(self, text):
        self.fails += 1
        self.line("FAIL " + text)

    def unrun(self, text):
        self.unruns += 1
        self.line("UNRUN " + text)

    def note(self, text):
        print(text, file=sys.stderr)

    def exit_code(self):
        if self.fails:
            return EXIT_FAIL
        if self.unruns:
            return EXIT_UNRUN
        return EXIT_OK


# --- inputs -----------------------------------------------------------------

def case_dir(arg):
    path = Path(arg) if "/" in arg else CASES_DIR / arg
    if not (path / "sources.toml").is_file():
        raise SystemExit(f"case_fetch: {path}/sources.toml not found")
    return path


def read_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def sources_of(case):
    return {row["id"]: row for row in read_toml(case / "sources.toml").get("source", [])}


def facts_of(case):
    path = case / "facts.toml"
    if not path.is_file():
        return {}, {}
    doc = read_toml(path)
    facts = {row["id"]: row for row in doc.get("fact", [])}
    values = {}
    for row in doc.get("value", []):
        values.setdefault(row["fact"], []).append(row)
    for rows in values.values():
        rows.sort(key=lambda r: r["ordinal"])
    return facts, values


def unit_scales():
    """The scale of each unit code's latest version (registries/units.toml)."""
    scales = {}
    for row in read_toml(UNITS_FILE).get("unit", []):
        code, version = row["code"], row.get("version", 1)
        if code not in scales or version >= scales[code][0]:
            scales[code] = (version, row["scale"])
    return {code: scale for code, (_, scale) in scales.items()}


def cache_root():
    explicit = os.environ.get("FA_CASES_CACHE")
    if explicit:
        return Path(explicit)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "franken_accounting" / "cases"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def cached(sha):
    """The cached bytes and their fetch time, or None."""
    if not sha:
        return None
    root = cache_root()
    body, sidecar = root / sha, root / (sha + ".fetched.json")
    if not body.is_file() or not sidecar.is_file():
        return None
    data = body.read_bytes()
    if sha256_hex(data) != sha:
        return None
    fetched_utc = fetch_time(sidecar)
    return None if fetched_utc is None else (data, fetched_utc)


def fetch_time(sidecar):
    """The sidecar's fetch time, or None when it is unreadable."""
    try:
        return json.loads(sidecar.read_text(encoding="utf-8"))["fetched_utc"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def store(data, url):
    """Store bytes under their SHA-256; the first fetch time is kept."""
    root = cache_root()
    root.mkdir(parents=True, exist_ok=True)
    sha = sha256_hex(data)
    (root / sha).write_bytes(data)
    sidecar = root / (sha + ".fetched.json")
    if fetch_time(sidecar) is None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sidecar.write_text(json.dumps({"fetched_utc": stamp, "url": url}, sort_keys=True) + "\n",
                           encoding="utf-8")
    return sha, fetch_time(sidecar)


# --- fetch ------------------------------------------------------------------

def is_sec_host(url):
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host == "sec.gov" or host.endswith(".sec.gov")


def fetch_url(row):
    route = row.get("retrieval_route", "")
    if route == "original":
        return row.get("original_url", "")
    if route in ("archive_capture", "third_party_copy"):
        return row.get("archive_url", "")
    return ""


def user_agent(url):
    """The project UA; direct sec.gov requests append FA_SEC_CONTACT (OD 1)."""
    if is_sec_host(url):
        contact = os.environ.get("FA_SEC_CONTACT", "")
        return f"{USER_AGENT} {contact}" if contact else None
    return USER_AGENT


def urlopen_bytes(url, agent):
    req = urllib.request.Request(url, headers={"User-Agent": agent})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


class Throttle:
    def __init__(self, interval=MIN_REQUEST_INTERVAL_S):
        self.interval = interval
        self.last = None

    def wait(self):
        now = time.monotonic()
        if self.last is not None and now - self.last < self.interval:
            time.sleep(self.interval - (now - self.last))
        self.last = time.monotonic()


def fetch(case, only, report, opener=urlopen_bytes, throttle=None):
    throttle = throttle or Throttle()
    sources = sources_of(case)
    if only is not None and only not in sources:
        report.fail(f"fetch {only}: no such source in {case}/sources.toml")
        return
    for sid in sorted(sources):
        row = sources[sid]
        if only is not None and sid != only:
            continue
        if only is None and row.get("status") != "OK":
            reason = row.get("status_reason") or row.get("notes") or "no reason recorded"
            report.line(f"SKIP {sid} {row.get('status', '?')} {reason}")
            continue
        recorded = row.get("sha256", "")
        hit = cached(recorded)
        if hit is not None:
            report.line(f"CACHED {sid} sha256={recorded} fetched_utc={hit[1]}")
            continue
        url = fetch_url(row)
        if not url:
            report.unrun(f"{sid}: retrieval_route `{row.get('retrieval_route')}` has no fetchable url")
            continue
        agent = user_agent(url)
        if agent is None:
            report.unrun(f"{sid}: direct sec.gov fetch needs FA_SEC_CONTACT (owner decision 1)")
            continue
        throttle.wait()
        try:
            data = opener(url, agent)
        except (urllib.error.URLError, OSError) as e:
            report.unrun(f"{sid}: network unavailable fetching {url}: {e}")
            continue
        sha, fetched_utc = store(data, url)
        if not recorded:
            report.line(f"FETCHED {sid} sha256={sha} fetched_utc={fetched_utc} unverified")
        elif sha != recorded:
            report.fail(f"{sid}: fetched sha256 {sha} differs from sources.toml {recorded}")
        else:
            report.line(f"FETCHED {sid} sha256={sha} fetched_utc={fetched_utc} verified")


# --- extract ----------------------------------------------------------------

class Strip(html.parser.HTMLParser):
    """case-fetch-strip-v1: block elements end lines, table cells are TAB-separated,
    a `page-break-before|after: always` style is a form feed, script/style/head are
    dropped, character references are decoded (U+00A0 kept)."""

    BLOCKS = frozenset(
        "address article aside blockquote br center dd div dl dt fieldset figure footer form "
        "h1 h2 h3 h4 h5 h6 header hr li main nav ol p pre section table tbody thead tfoot "
        "title tr ul caption".split()
    )
    SKIP = frozenset(("script", "style", "head"))
    VOID = frozenset("area base br col embed hr img input link meta source track wbr".split())

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip = 0
        self.pre = 0
        self.after_break = []

    @staticmethod
    def breaks(attrs):
        style = "".join(dict(attrs).get("style", "") .split()).lower()
        return ("page-break-before:always" in style, "page-break-after:always" in style)

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
            return
        before, after = self.breaks(attrs)
        if before:
            self.parts.append("\f")
        if tag in self.BLOCKS:
            self.parts.append("\n")
        if tag in ("td", "th"):
            self.parts.append("\t")
        if tag == "pre":
            self.pre += 1
        if after:
            if tag in self.VOID:
                self.parts.append("\f")
            else:
                self.after_break.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if tag in self.BLOCKS:
            self.parts.append("\n")
        if tag == "pre":
            self.pre = max(0, self.pre - 1)
        if tag in self.after_break:
            self.after_break.reverse()
            self.after_break.remove(tag)
            self.after_break.reverse()
            self.parts.append("\f")

    def handle_data(self, data):
        if self.skip:
            return
        if self.pre:
            self.parts.append(data)
        else:
            self.parts.append(re.sub(r"[ \t\n\r\x0c]+", " ", data))

    def text(self):
        """Lines cleaned of runs of spaces, blocks separated by one blank line,
        no blank line at a page's start or end."""
        pages = []
        for page in "".join(self.parts).split("\f"):
            lines = []
            for raw in page.split("\n"):
                line = re.sub(r"[ \u00a0]+", " ", raw)
                line = re.sub(r" *\t[ \t]*", "\t", line).strip(" \t")
                if line or (lines and lines[-1]):
                    lines.append(line)
            while lines and not lines[-1]:
                lines.pop()
            pages.append("\n".join(lines))
        return "\n\f".join(pages)


def strip_html(data):
    parser = Strip()
    parser.feed(decode(data)[0])
    parser.close()
    return parser.text()


def decode(data):
    """UTF-8, else Windows-1252 (older EDGAR text); the method names which."""
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace"), "cp1252"


def pdftotext_version():
    exe = shutil.which("pdftotext")
    if exe is None:
        return None
    out = subprocess.run([exe, "-v"], capture_output=True, text=True, check=False, timeout=60)
    match = re.search(r"pdftotext version (\S+)", out.stderr + out.stdout)
    return match.group(1) if match else "unknown"


class Unrun(Exception):
    pass


def extraction(row, data):
    """(text, method) for one source's bytes."""
    fmt = row.get("format", "").lower()
    if fmt == "pdf":
        version = pdftotext_version()
        if version is None:
            raise Unrun("pdftotext is not installed (needed to extract a pdf source)")
        out = subprocess.run([shutil.which("pdftotext"), "-layout", "-enc", "UTF-8", "-", "-"],
                             input=data, capture_output=True, check=False, timeout=600)
        if out.returncode != 0:
            raise Unrun(f"pdftotext exited {out.returncode}: {out.stderr.decode(errors='replace')}")
        return out.stdout.decode("utf-8"), f"pdftotext {version} -layout"
    if fmt in HTML_FORMATS:
        return strip_html(data), STRIP_VERSION
    if fmt in TEXT_FORMATS or fmt in XML_FORMATS:
        text, enc = decode(data)
        return text.replace("\r\n", "\n"), f"text-{enc}"
    raise Unrun(f"no extractor for format `{fmt}`")


def extraction_field(text, method):
    return [EXTRACT_TOOL, method, sha256_hex(text.encode("utf-8"))]


def extract(case, report):
    for sid, row in sorted(sources_of(case).items()):
        if row.get("status") != "OK":
            continue
        hit = cached(row.get("sha256", ""))
        if hit is None:
            report.unrun(f"{sid}: not in the cache; run `fetch` first")
            continue
        try:
            text, method = extraction(row, hit[0])
        except Unrun as e:
            report.unrun(f"{sid}: {e}")
            continue
        field = extraction_field(text, method)
        report.line(f"EXTRACT {sid} extraction = {toml_array(field)}")
        recorded = row.get("extraction")
        if recorded and recorded[2] != field[2]:
            report.fail(f"{sid}: extraction sha256 {field[2]} differs from sources.toml {recorded[2]}")


# --- normalization and sentences --------------------------------------------

def normalize(text):
    out, gap = [], False
    for ch in text:
        if ch in WHITESPACE:
            gap = True
            continue
        if gap and out:
            out.append(" ")
        gap = False
        out.append(ch)
    return "".join(out)


class Located:
    """An extraction normalized, with each normalized character's editor line
    (1-based over `\\n`), page (1-based over `\\f`) and line within its page."""

    def __init__(self, text):
        self.raw = text
        self.lines = text.split("\n")
        self.page_texts = text.split("\f")
        self.page_labels = [page_label(p, i + 1) for i, p in enumerate(self.page_texts)]
        chars, gline, page, pline = [], [], [], []
        block_starts, block_ends = set(), set()
        g, p, pl, gap, newlines, paged = 1, 1, 1, False, 0, False
        for ch in text:
            if ch in WHITESPACE:
                gap = True
            else:
                if gap and chars:
                    if newlines >= 2 or paged:
                        block_ends.add(len(chars))
                        block_starts.add(len(chars) + 1)
                    chars.append(" ")
                    gline.append(g)
                    page.append(p)
                    pline.append(pl)
                gap, newlines, paged = False, 0, False
                chars.append(ch)
                gline.append(g)
                page.append(p)
                pline.append(pl)
            if ch == "\n":
                g += 1
                pl += 1
                newlines += 1
            elif ch == "\f":
                p += 1
                pl = 1
                paged = True
        self.norm = "".join(chars)
        self.gline, self.page, self.pline = gline, page, pline
        self.starts, self.ends = sentence_bounds(self.norm, block_starts, block_ends)

    def span(self, keep):
        """The normalized [lo, hi) of the kept characters, without edge spaces."""
        idx = [i for i in range(len(self.norm)) if keep(i) and self.norm[i] != " "]
        if not idx:
            return None
        return idx[0], idx[-1] + 1

    def count(self, quote):
        n, at = 0, self.norm.find(quote)
        while at != -1:
            n += 1
            at = self.norm.find(quote, at + 1)
        return n


PAGE_NUMBER = re.compile(r"^(?:page\s+)?-?\s*(\d{1,4}|[ivxlcdm]{1,8})\s*-?$", re.IGNORECASE)


def page_label(page_text, index):
    lines = [ln.strip(" \t\u00a0\x0b\r") for ln in page_text.split("\n")]
    lines = [ln for ln in lines if ln]
    for candidate in (lines[-1:] + lines[:1]):
        m = PAGE_NUMBER.match(candidate)
        if m:
            return m.group(1).lower()
    return str(index)


TERMINATOR = re.compile(r'[.?!]["\)]?(?= |$)')


def abbreviated(norm, dot):
    start = norm.rfind(" ", 0, dot) + 1
    token = norm[start:dot].lstrip("([\"'\u201c\u2018")
    return token in ABBREVIATIONS


def sentence_bounds(norm, block_starts=(), block_ends=()):
    """Sentence start and end offsets in a normalized text; the block
    boundaries come from the raw extraction's blank lines and page breaks."""
    starts, ends = {0} | set(block_starts), set(block_ends) | {len(norm)}
    for m in TERMINATOR.finditer(norm):
        if norm[m.start()] == "." and abbreviated(norm, m.start()):
            continue
        ends.add(m.end())
        if m.end() < len(norm):
            starts.add(m.end() + 1)
    return starts, ends


def word_spans(norm, lo, hi):
    """Word-aligned sub-spans of [lo, hi): starts after a space, ends before one."""
    starts = [i for i in range(lo, hi) if norm[i] != " " and (i == lo or norm[i - 1] == " ")]
    ends = [i + 1 for i in range(lo, hi) if norm[i] != " " and (i + 1 == hi or norm[i + 1] == " ")]
    return [(s, e) for s in starts for e in ends if s < e]


# --- literal rules (shared semantics with the derivation table, §2.4) -------

NUMBER = re.compile(r"(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?")
QUARTER_PATTERNS = (
    (re.compile(r"\b([1-4])Q(\d{2})\b"), lambda m: (two_digit_year(m.group(2)), int(m.group(1)))),
    (re.compile(r"\b(\d{4}) ?Q([1-4])\b"), lambda m: (int(m.group(1)), int(m.group(2)))),
    (re.compile(r"\bQ([1-4]) (\d{4})\b"), lambda m: (int(m.group(2)), int(m.group(1)))),
    (re.compile(r"\b(first|second|third|fourth)[ -]quarter(?: of)?,? (\d{4})\b", re.IGNORECASE),
     lambda m: (int(m.group(2)), ORDINALS[m.group(1).lower()])),
)
FISCAL_PATTERNS = (
    re.compile(r"\bfiscal(?: year)? (\d{4})\b", re.IGNORECASE),
    re.compile(r"\bFY ?(\d{4})\b"),
)
ACCOUNT_PATTERN = re.compile(
    r"\baccount(?::| (?:No\. ?|number |#)?)([0-9A-Z]{4,12})\b", re.IGNORECASE)


def two_digit_year(yy):
    n = int(yy)
    return 2000 + n if n < 50 else 1900 + n


class RuleError(ValueError):
    pass


def number_of(literal):
    """scale's literal grammar (A2, crates/fa-oracles/src/cases/derive.rs):
    a lone dash is 0; a leading - or U+2212, or parentheses, negate."""
    if literal.strip() in ("-", "\u2013", "\u2014"):
        return Fraction(0)
    m = NUMBER.search(literal)
    if m is None:
        raise RuleError(f"no number in `{literal}`")
    whole = m.group(1).replace(",", "")
    frac = m.group(2) or ""
    value = Fraction(int(whole + frac), 10 ** len(frac))
    head = literal[: m.start()]
    if "-" in head or "\u2212" in head or literal.strip().startswith("("):
        value = -value
    return value


def date_of(month, day, year):
    mo = MONTHS.get(month.lower().rstrip("."))
    if mo is None:
        raise RuleError(f"unknown month `{month}`")
    d, y = int(day), int(year)
    import datetime
    try:
        return datetime.date(y, mo, d).isoformat()
    except ValueError as e:
        raise RuleError(str(e)) from e


DATE_MDY = re.compile(r"\b([A-Za-z]{3,9}\.?) (\d{1,2}),? (\d{4})\b")
DATE_DMY = re.compile(r"\b(\d{1,2}) ([A-Za-z]{3,9}\.?),? (\d{4})\b")
RANGE_SAME_MONTH = re.compile(
    r"\b([A-Za-z]{3,9}\.?) (\d{1,2}) ?(?:and|through|to|-|\u2013) ?(\d{1,2}),? (\d{4})\b")
RANGE_TWO_DATES = re.compile(
    r"\b([A-Za-z]{3,9}\.?) (\d{1,2}),? (\d{4}) ?(?:and|through|to|-|\u2013) ?"
    r"([A-Za-z]{3,9}\.?) (\d{1,2}),? (\d{4})\b")
MONTH_YEAR = re.compile(r"\b([A-Za-z]{3,9}\.?),? (\d{4})\b")


def apply_rule(rule, literal, param, unit, precision, scales):
    """The canonical value a [[value]] row's literal yields under its rule."""
    if rule == "scale":
        if unit and literal.rstrip().endswith(("x", "%")):
            raise RuleError(f"`{literal}`: a trailing x or % belongs to a unitless value")
        value = number_of(literal) * Fraction(10) ** int(param or 0)
        if unit:
            if unit not in scales:
                raise RuleError(f"unit `{unit}` is not in registries/units.toml")
            value *= Fraction(10) ** scales[unit]
        else:
            value /= Fraction(10) ** int(precision or 0)
        if value.denominator != 1:
            raise RuleError(f"`{literal}` is not an integer at the stated scale")
        return str(value.numerator)
    if rule == "number_word":
        word = literal.strip().lower()
        if word not in NUMBER_WORDS:
            raise RuleError(f"`{literal}` is not a registered number word")
        return str(NUMBER_WORDS[word])
    if rule == "date_literal":
        m = DATE_MDY.search(literal)
        if m and m.group(1).lower().rstrip(".") in MONTHS:
            return date_of(m.group(1), m.group(2), m.group(3))
        m = DATE_DMY.search(literal)
        if m and m.group(2).lower().rstrip(".") in MONTHS:
            return date_of(m.group(2), m.group(1), m.group(3))
        raise RuleError(f"`{literal}` is not a date")
    if rule == "date_range_literal":
        m = RANGE_TWO_DATES.search(literal)
        if m:
            a = date_of(m.group(1), m.group(2), m.group(3))
            b = date_of(m.group(4), m.group(5), m.group(6))
        else:
            m = RANGE_SAME_MONTH.search(literal)
            if not m:
                raise RuleError(f"`{literal}` is not a date range")
            a = date_of(m.group(1), m.group(2), m.group(4))
            b = date_of(m.group(1), m.group(3), m.group(4))
        if a > b:
            raise RuleError(f"`{literal}` runs backwards")
        return f"{a}..{b}"
    if rule == "month_literal":
        for m in MONTH_YEAR.finditer(literal):
            mo = MONTHS.get(m.group(1).lower().rstrip("."))
            if mo:
                return f"{int(m.group(2)):04d}-{mo:02d}"
        raise RuleError(f"`{literal}` is not a month")
    if rule == "period_literal":
        phrase = re.sub(r"^(?:(?:the|in|for|during)\s+)+", "", literal.strip(), flags=re.I)
        phrase = phrase.rstrip(".,;:")
        for pattern, parse in QUARTER_PATTERNS:
            m = pattern.fullmatch(phrase)
            if m:
                year, q = parse(m)
                return f"{year}Q{q}"
        for pattern in FISCAL_PATTERNS:
            m = pattern.fullmatch(phrase)
            if m:
                return f"FY{m.group(1)}"
        raise RuleError(f"`{literal}` is not exactly one period phrase")
    raise RuleError(f"unknown rule `{rule}`")


def quarter_labels(text):
    found = []
    for pattern, parse in QUARTER_PATTERNS:
        for m in pattern.finditer(text):
            year, q = parse(m)
            label = f"{year}Q{q}"
            if label not in found:
                found.append(label)
    return found


def period_quarters(text):
    quarters = set(quarter_labels(text))
    for pattern in FISCAL_PATTERNS:
        for m in pattern.finditer(text):
            quarters.update(f"{m.group(1)}Q{q}" for q in range(1, 5))
    return quarters


def account_ids(text):
    return {m.group(1) for m in ACCOUNT_PATTERN.finditer(text)
            if any(c.isdigit() for c in m.group(1)) and m.group(1) == m.group(1).upper()}


def scope_ok(quote, about_scope, granularity):
    """case-fetch-scope-v1 (see the module docstring)."""
    if about_scope.startswith("scheme:") and granularity == "journal_entry":
        return False, "a scheme-level scope backs a journal_entry fact only through an interpretation"
    pq, ps = period_quarters(quote), period_quarters(about_scope)
    if pq and ps and pq.isdisjoint(ps):
        return False, f"the quote names {sorted(pq)}, the scope {sorted(ps)}"
    aq, as_ = account_ids(quote), account_ids(about_scope)
    if aq and as_ and aq.isdisjoint(as_):
        return False, f"the quote names accounts {sorted(aq)}, the scope {sorted(as_)}"
    return True, ""


def literal_in(literal, quote):
    """Whether `literal` occurs in `quote` as a whole token run (never inside a
    longer number or word)."""
    lit = normalize(literal)
    if not lit:
        return False
    at = quote.find(lit)
    while at != -1:
        before = quote[at - 1] if at > 0 else " "
        after = quote[at + len(lit)] if at + len(lit) < len(quote) else " "
        before2 = quote[at - 2] if at > 1 else " "
        after2 = quote[at + len(lit) + 1] if at + len(lit) + 1 < len(quote) else " "
        glued_before = before.isalnum() or (before in ",." and before2.isdigit() and lit[0].isdigit())
        glued_after = after.isalnum() or (after in ",." and after2.isdigit() and lit[-1].isdigit())
        if not glued_before and not glued_after:
            return True
        at = quote.find(lit, at + 1)
    return False


def values_bind(quote, rows, scales, whole=False):
    """(ok, problems): every value's literal occurs in the quote (is the whole
    quote, for value-bound anchors) and its rule yields the recorded value."""
    problems = []
    for v in rows:
        literal = v["literal"]
        present = normalize(literal) == quote if whole else literal_in(literal, quote)
        if not present:
            problems.append(f"value {v['ordinal']} literal `{literal}` is not in the quote")
            continue
        try:
            got = apply_rule(v["rule"], literal, v.get("param"), v.get("unit", ""),
                             v.get("precision"), scales)
        except RuleError as e:
            problems.append(f"value {v['ordinal']}: {e}")
            continue
        if got != str(v["value"]):
            problems.append(f"value {v['ordinal']}: `{literal}` under {v['rule']} is {got}, "
                            f"not {v['value']}")
    return not problems, problems


def values_canonical(about_scope, rows):
    """A1a's canonical values bytes (fa-oracles values_canonical)."""
    def opt(x):
        return "" if x is None else str(x)
    out = f"fa:case-values:v1\nabout_scope={about_scope}\n"
    for v in sorted(rows, key=lambda r: r["ordinal"]):
        out += "\t".join((str(v["ordinal"]), v["literal"], v["rule"], opt(v.get("param")),
                          str(v["value"]), v.get("unit", ""), opt(v.get("precision")))) + "\n"
    return out.encode("utf-8")


# --- binding ----------------------------------------------------------------

class Binding:
    def __init__(self, fact):
        self.fact = fact
        self.quote = None
        self.quote_sha256 = fact.get("quote_sha256", "")
        self.anchor = fact.get("anchor", "")
        self.found_once = False
        self.aligned = False
        self.values = False
        self.scope = False
        self.problems = []

    def binds(self):
        return self.found_once and self.aligned and self.values and self.scope


def region_of(loc, kind, anchor):
    """The normalized [lo, hi) the anchor names, or a problem string."""
    if kind == "page":
        m = re.fullmatch(r"p([0-9A-Za-z]+):l(\d+)-(\d+)", anchor)
        if not m:
            return f"anchor `{anchor}` is not `p<page>:l<first>-<last>`"
        label, a, b = m.group(1).lower(), int(m.group(2)), int(m.group(3))
        pages = [i + 1 for i, lbl in enumerate(loc.page_labels) if lbl == label]
        if len(pages) != 1:
            return f"printed page {label} occurs on {len(pages)} pages of the extraction"
        page = pages[0]
        if b > len(loc.page_texts[page - 1].split("\n")):
            return f"page {label} has fewer than {b} lines"
        span = loc.span(lambda i: loc.page[i] == page and a <= loc.pline[i] <= b)
    elif kind == "line":
        m = re.fullmatch(r"l(\d+)-(\d+)", anchor)
        if not m:
            return f"anchor `{anchor}` is not `l<first>-<last>`"
        a, b = int(m.group(1)), int(m.group(2))
        if b > len(loc.lines):
            return f"the extraction has fewer than {b} lines"
        span = loc.span(lambda i: a <= loc.gline[i] <= b)
    elif kind == "paragraph":
        m = re.fullmatch(r"para(\d+)", anchor)
        if not m:
            return f"anchor `{anchor}` is not `para<n>`"
        n = int(m.group(1))
        heads = [i + 1 for i, ln in enumerate(loc.lines) if re.match(rf"^\s*{n}\.(\s|$)", ln)]
        if len(heads) != 1:
            return f"paragraph {n} begins {len(heads)} lines of the extraction"
        nxt = [i + 1 for i, ln in enumerate(loc.lines) if re.match(rf"^\s*{n + 1}\.(\s|$)", ln)
               and i + 1 > heads[0]]
        last = nxt[0] - 1 if nxt else len(loc.lines)
        span = loc.span(lambda i: heads[0] <= loc.gline[i] <= last)
    else:
        return f"anchor kind `{kind}` is not prose"
    return span if span else f"the anchor `{anchor}` holds no text"


def found_anchor(loc, kind, anchor, s, e):
    if kind == "page":
        return f"p{anchor.split(':', 1)[0][1:]}:l{loc.pline[s]}-{loc.pline[e - 1]}"
    if kind == "line":
        return f"l{loc.gline[s]}-{loc.gline[e - 1]}"
    return anchor


def heading_region(loc, lo, hi):
    lines = sorted({loc.gline[i] for i in range(lo, hi)})
    return not any(re.search(r"[.?!]", loc.lines[g - 1]) for g in lines)


def bind_prose(loc, fact, b):
    kind = fact["anchor_kind"]
    region = region_of(loc, kind, fact["anchor"])
    if isinstance(region, str):
        b.problems.append(region)
        return
    lo, hi = region
    heading = heading_region(loc, lo, hi)
    norm = loc.norm
    if "quote" in fact:
        quote = normalize(fact["quote"])
        hits = []
        at = norm.find(quote)
        while at != -1:
            hits.append(at)
            at = norm.find(quote, at + 1)
        inside = [h for h in hits if lo <= h and h + len(quote) <= hi]
        if len(hits) != 1 or len(inside) != 1:
            b.problems.append(f"the quote occurs {len(hits)} times in the extraction, "
                              f"{len(inside)} at the anchor")
            if not inside:
                return
        s, e = inside[0], inside[0] + len(quote)
        b.found_once = len(hits) == 1 and len(inside) == 1
        if sha256_hex(quote.encode("utf-8")) != fact.get("quote_sha256"):
            b.problems.append("the quote's SHA-256 differs from quote_sha256")
            b.found_once = False
        b.aligned = (s, e) == (lo, hi) if heading else (s in loc.starts and e in loc.ends)
    else:
        want = fact.get("quote_sha256", "")
        if heading:
            candidates = [(lo, hi)]
        else:
            ss = sorted(x for x in loc.starts if lo <= x < hi)
            es = sorted(x for x in loc.ends if lo < x <= hi)
            candidates = [(s, e) for s in ss for e in es if s < e]
        matches = [(s, e) for s, e in candidates
                   if sha256_hex(norm[s:e].encode("utf-8")) == want]
        if len(matches) > 1:
            b.problems.append(f"quote_sha256 matches {len(matches)} spans at the anchor")
            return
        if not matches:
            fragments = [(s, e) for s, e in word_spans(norm, lo, hi)
                         if sha256_hex(norm[s:e].encode("utf-8")) == want]
            if len(fragments) == 1:
                s, e = fragments[0]
                b.quote = norm[s:e]
                b.found_once = loc.count(b.quote) == 1
                b.anchor = found_anchor(loc, kind, fact["anchor"], s, e)
                b.problems.append("the quote is not sentence-aligned (a fragment of its sentence)")
            else:
                b.problems.append("no sentence-aligned span at the anchor has the quote's SHA-256")
            return
        s, e = matches[0]
        b.aligned = True
        b.found_once = loc.count(norm[s:e]) == 1
        if not b.found_once:
            b.problems.append("the quote occurs more than once in the extraction")
    b.quote = norm[s:e]
    b.anchor = found_anchor(loc, kind, fact["anchor"], s, e)
    if not b.aligned:
        b.problems.append("the quote is not sentence-aligned (a fragment of its sentence)")


CELL_SPLIT = re.compile(r"\t+| {2,}")


def cells(line):
    raw = [c.strip(" \u00a0\f") for c in CELL_SPLIT.split(line.strip(" \t\u00a0\f"))]
    out = []
    for c in raw:
        if c in ("", "$"):
            continue
        if c in (")", "%", ")%") and out:
            out[-1] += c
            continue
        out.append(c)
    return out


def table_cell(loc, anchor):
    """The cells the `table|row|column` anchor names (one per matching table)."""
    parts = anchor.split("|")
    if len(parts) != 3:
        return f"anchor `{anchor}` is not `<table>|<row>|<column>`"
    table, row, column = (normalize(p) for p in parts)
    found = []
    titles = [i for i, ln in enumerate(loc.lines) if table in normalize(ln)]
    for t in titles:
        header = None
        for j in range(t + 1, min(len(loc.lines), t + 400)):
            line = loc.lines[j]
            if "\f" in line and j > t + 1:
                break
            cs = [normalize(c) for c in cells(line)]
            if header is None:
                if column in cs:
                    header = (cs, cs.index(column))
                continue
            if cs and cs[0] == row:
                head, col = header
                from_right = len(head) - 1 - col
                idx = len(cs) - 1 - from_right
                if idx >= 1:
                    found.append((cs[idx], j + 1))
                break
    return found


def bind_table_cell(loc, fact, b):
    found = table_cell(loc, fact["anchor"])
    if isinstance(found, str):
        b.problems.append(found)
        return
    want = fact.get("quote_sha256", "")
    exact = [(c, ln) for c, ln in found if sha256_hex(c.encode("utf-8")) == want]
    if len(exact) == 1:
        b.quote = exact[0][0]
        b.found_once = len(found) == 1
        b.aligned = True
        if not b.found_once:
            b.problems.append(f"the cell resolves in {len(found)} tables")
        return
    frags = [(c, s, e) for c, _ in found for s, e in word_spans(c, 0, len(c))
             if (s, e) != (0, len(c)) and sha256_hex(c[s:e].encode("utf-8")) == want]
    if frags:
        b.quote = frags[0][0][frags[0][1]:frags[0][2]]
        b.found_once = len(frags) == 1
        b.problems.append("the quote is a fragment of its cell, not the whole cell")
        return
    b.problems.append(f"the cell `{fact['anchor']}` was found {len(found)} times; none has "
                      f"the quote's SHA-256")


class Instance:
    """An XBRL instance's contexts, units and facts, each fact with its line."""

    def __init__(self, text):
        self.contexts, self.units, self.facts = {}, {}, []
        parser = xml.parsers.expat.ParserCreate()
        stack, ctx, text_buf = [], None, []
        dims = []

        def local(name):
            return name.split(":", 1)[-1]

        def start(name, attrs):
            nonlocal ctx, dims
            stack.append((name, dict(attrs), parser.CurrentLineNumber))
            text_buf.append([])
            ln = local(name)
            if ln == "context":
                ctx = {"id": attrs.get("id", ""), "period": "", "members": []}
            elif ln == "explicitMember" and ctx is not None:
                dims.append(attrs.get("dimension", ""))

        def chars(data):
            if text_buf:
                text_buf[-1].append(data)

        def end(name):
            nonlocal ctx
            _, attrs, line = stack.pop()
            body = "".join(text_buf.pop()).strip()
            ln = local(name)
            if ln == "context" and ctx is not None:
                self.contexts[ctx["id"]] = ctx
                ctx = None
            elif ctx is not None and ln in ("instant",):
                ctx["period"] = body
            elif ctx is not None and ln == "startDate":
                ctx["period"] = body + ".."
            elif ctx is not None and ln == "endDate":
                ctx["period"] += body
            elif ctx is not None and ln == "explicitMember":
                ctx["members"].append((dims.pop() if dims else "", body))
            elif ln == "unit":
                self.units[attrs.get("id", "")] = " ".join(self.unit_measures)
                self.unit_measures = []
            elif ln == "measure":
                self.unit_measures.append(body)
            elif "contextRef" in attrs:
                self.facts.append({"concept": name, "context": attrs["contextRef"],
                                   "unit": attrs.get("unitRef", ""),
                                   "decimals": attrs.get("decimals", ""),
                                   "value": body, "line": line})

        self.unit_measures = []
        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.CharacterDataHandler = chars
        parser.Parse(text.encode("utf-8"), True)

    def find(self, concept, context):
        return [f for f in self.facts if f["concept"] == concept and f["context"] == context]


def precision_of(decimals, unit, scales):
    if decimals.upper() == "INF":
        return None if not unit else -scales.get(unit, 0)
    return -int(decimals)


def bind_xbrl(text, fact, values, scales, b):
    parts = fact["anchor"].split("|")
    if len(parts) != 2:
        b.problems.append(f"anchor `{fact['anchor']}` is not `<concept>|<context id>`")
        return
    inst = Instance(text)
    found = inst.find(parts[0], parts[1])
    if len(found) != 1:
        b.problems.append(f"{parts[0]} in context {parts[1]} occurs {len(found)} times")
        if not found:
            return
    f = found[0]
    value = normalize(f["value"])
    b.found_once = len(found) == 1
    if sha256_hex(value.encode("utf-8")) == fact.get("quote_sha256"):
        b.quote, b.aligned = value, True
    else:
        b.quote = value
        b.problems.append("the quote is not the instance fact's whole value")
    members = sorted(m.split(":", 1)[-1] for _, m in inst.contexts.get(f["context"], {}).get(
        "members", []))
    cell = fact.get("cell", "")
    key = cell.split("@", 1)[0]
    want_members = [key.split(":", 1)[1]] if ":" in key else []
    if members != want_members:
        b.problems.append(f"member: the context's explicit members are {members}, the cell "
                          f"names {want_members}")
        b.member_ok = False
    for v in values:
        precision = precision_of(f["decimals"], v.get("unit", ""), scales) if f["decimals"] else None
        if f["decimals"] and precision != v.get("precision"):
            b.problems.append(f"decimals: the instance states decimals={f['decimals']} "
                              f"(precision {precision}), value {v['ordinal']} has precision "
                              f"{v.get('precision')}")
            b.member_ok = False


def bind(fact, values, source, text, loc, scales):
    b = Binding(fact)
    b.member_ok = True
    kind = fact["anchor_kind"]
    if kind in PROSE_ANCHORS:
        bind_prose(loc, fact, b)
    elif kind == "table_cell":
        bind_table_cell(loc, fact, b)
    elif kind == "xbrl":
        bind_xbrl(text, fact, values, scales, b)
    if b.quote is not None:
        ok, problems = values_bind(b.quote, values, scales, whole=kind in VALUE_ANCHORS)
        b.values = ok and b.member_ok
        b.problems.extend(problems)
        b.scope, why = scope_ok(b.quote, fact.get("about_scope", ""), fact.get("granularity", ""))
        if not b.scope:
            b.problems.append("scope: " + why)
    return b


# --- receipts ---------------------------------------------------------------

def toml_string(s):
    if any(ord(c) < 0x20 and c not in "\n\t" for c in s) or "\x7f" in s:
        raise ValueError(f"a control character in `{s!r}` has no TOML-subset escape")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace(
        "\t", "\\t") + '"'


def toml_array(items):
    return "[" + ", ".join(toml_string(i) for i in items) + "]"


def toml_bool(v):
    return "true" if v else "false"


RECEIPT_HEADER = (
    "# GENERATED by tools/case-fetch/case_fetch.py verify (docs/FORENSIC_CASE_STUDIES_PLAN.md §4.4).\n"
    "# Never edit by hand: re-run `python3 -B tools/case-fetch/case_fetch.py verify <case>`.\n"
)


def render_receipts(rows):
    out = [RECEIPT_HEADER]
    for r in rows:
        out.append("\n[[receipt]]\n")
        for key in ("source", "fact", "anchor", "verified_utc", "tool_version",
                    "extraction_sha256", "quote_sha256", "values_sha256", "alignment"):
            out.append(f"{key} = {toml_string(r[key])}\n")
        for key in ("quote_found_once", "aligned", "values_in_quote", "scope_ok",
                    "original_hash_compared"):
            out.append(f"{key} = {toml_bool(r[key])}\n")
    return "".join(out)


def verify(case, report):
    sources = sources_of(case)
    facts, values = facts_of(case)
    scales = unit_scales()
    sourced = sorted(fid for fid, f in facts.items() if f.get("provenance") == "sourced")
    texts, receipts = {}, []
    for fid in sourced:
        fact = facts[fid]
        sid = fact.get("source", "")
        src = sources.get(sid)
        if src is None:
            report.fail(f"{fid} ({sid}): the source is not in sources.toml")
            continue
        if src.get("status") != "OK":
            report.fail(f"{fid} ({sid}): the source's status is {src.get('status')} "
                        f"(facts may cite only OK sources)")
            continue
        kind = fact.get("anchor_kind", "")
        if kind not in PROSE_ANCHORS + VALUE_ANCHORS:
            report.unrun(f"{fid}: `{kind}` anchors are verified by M2t's exhibit-b, not here")
            continue
        if sid not in texts:
            hit = cached(src.get("sha256", ""))
            if hit is None:
                texts[sid] = Unrun(f"{sid} is not in the cache; run `fetch {case.name}` first")
            else:
                try:
                    text, method = extraction(src, hit[0])
                    field = extraction_field(text, method)
                    recorded = src.get("extraction")
                    if recorded and recorded[2] != field[2]:
                        report.fail(f"{sid}: extraction sha256 {field[2]} differs from "
                                    f"sources.toml {recorded[2]} ({recorded[1]} vs {method})")
                    texts[sid] = (text, Located(text), field[2], hit[1])
                except Unrun as e:
                    texts[sid] = e
        got = texts[sid]
        if isinstance(got, Unrun):
            report.unrun(f"{fid}: {got}")
            continue
        text, loc, extraction_sha, fetched_utc = got
        rows = values.get(fid, [])
        b = bind(fact, rows, src, text, loc, scales)
        receipts.append({
            "source": sid, "fact": fid, "anchor": b.anchor, "verified_utc": fetched_utc,
            "tool_version": TOOL_VERSION, "extraction_sha256": extraction_sha,
            "quote_sha256": b.quote_sha256,
            "values_sha256": sha256_hex(values_canonical(fact.get("about_scope", ""), rows)),
            "alignment": "sentence" if kind in PROSE_ANCHORS else "value",
            "quote_found_once": b.found_once, "aligned": b.aligned,
            "values_in_quote": b.values, "scope_ok": b.scope,
            "original_hash_compared": bool(src.get("original_hash_compared", False)),
        })
        if b.binds():
            report.line(f"VERIFY {fid} PASS")
        else:
            for p in b.problems or ["a binding boolean is false"]:
                report.fail(f"{fid} ({sid} {fact.get('anchor')}): {p}")
    if report.unruns:
        report.note("verify: receipts.toml not written (some facts did not run)")
        return
    (case / "receipts.toml").write_text(render_receipts(receipts), encoding="utf-8")
    report.note(f"verify: wrote {case / 'receipts.toml'} ({len(receipts)} receipts)")


def xbrl_facts(case, report):
    sources = sources_of(case)
    facts, _ = facts_of(case)
    for fid in sorted(facts):
        fact = facts[fid]
        if fact.get("anchor_kind") != "xbrl":
            continue
        src = sources.get(fact.get("source", ""), {})
        hit = cached(src.get("sha256", ""))
        if hit is None:
            report.unrun(f"{fid}: {fact.get('source')} is not in the cache")
            continue
        inst = Instance(decode(hit[0])[0])
        concept, _, context = fact["anchor"].partition("|")
        for f in inst.find(concept, context):
            ctx = inst.contexts.get(f["context"], {})
            members = ",".join(f"{d}={m}" for d, m in ctx.get("members", []))
            report.line("\t".join((
                "XBRL", fid, f["concept"], f["context"], ctx.get("period", ""),
                inst.units.get(f["unit"], f["unit"]), f["decimals"], members, f["value"],
                f"line={f['line']}")))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="case_fetch.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("fetch", help="download OK sources into the cache")
    p.add_argument("case")
    p.add_argument("--source", help="fetch this one row whatever its status")
    for name, text in (("extract", "print each cached source's extraction field"),
                       ("xbrl-facts", "print the instance rows the case's xbrl facts cite"),
                       ("verify", "bind every sourced fact and write receipts.toml")):
        sub.add_parser(name, help=text).add_argument("case")
    args = ap.parse_args(argv)
    report = Report()
    case = case_dir(args.case)
    if args.command == "fetch":
        fetch(case, args.source, report)
    elif args.command == "extract":
        extract(case, report)
    elif args.command == "xbrl-facts":
        xbrl_facts(case, report)
    else:
        verify(case, report)
    return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
