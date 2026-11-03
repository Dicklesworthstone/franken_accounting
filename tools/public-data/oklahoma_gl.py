#!/usr/bin/env python3
"""Prepare the pinned Oklahoma FY2024 Q4 public GL population.

Standard-library authoring helper, not a second accounting engine. Amounts are
exact; no balancing legs or opening balances are invented. The source is monthly
chartfield activity, not the agency's original transaction journal.
"""
from __future__ import annotations

import argparse
import calendar
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from urllib import error, parse, request

SOURCE_URL = (
    "https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/"
    "resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/download/ledger_fy24_qtr4.csv"
)
CATALOG_URL = "https://catalog.data.gov/dataset/general-ledger"
LICENSE_URL = "http://www.opendefinition.org/licenses/cc-by"
SOURCE_SHA256 = "141e2d5524f6aa9d25c7331bc56f623f43da9a1f00cdfee42b7c5f3ccf6fc0fe"
SOURCE_BYTES = 113_856_733
SOURCE_ROWS = 373_357
FIXTURE_SHA256 = "146940518122397bf9b66f92fa06b8b7a1cb15e58ae8c0cf0e42584933a1f64c"
FIXTURE_BYTES = 94_945
INDEX_SHA256 = "4538e1183c3e6ac9651d6d2fb52bfb3a5a0191b4ba567aab4fb3dd4703da9d11"
USER_AGENT = "franken_accounting-agent (+https://github.com/Dicklesworthstone/franken_accounting)"
SOURCE_SYSTEM = "oklahoma-omes-period-activity-v1"
DATA_DIR = Path(__file__).resolve().parents[2] / "crates/fa-oracles/data/oklahoma"
MAX_RECORD_BYTES = 65_536
MAX_SELECTED_ROWS = 10_000
I128_MAX = (1 << 127) - 1

HEADER = (
    "BUSINESS_UNIT", "OCP_AGNCY_NAME", "LEDGER", "FISCAL_YEAR",
    "ACCOUNTING_PERIOD", "FUND_CODE", "FUNDDESCR", "CLASS_FLD",
    "CLASSDESCR", "DEPTID", "DEPTDESCR", "ACCOUNT", "ACCTDESCR",
    "OPERATING_UNIT", "OPERUNITDESCR", "PRODUCT", "PRODUCTDESCR",
    "PROGRAM_CODE", "PGMDESCR", "BUDGET_REF", "CHARTFIELD1", "CF1DESCR",
    "CHARTFIELD2", "CF2DESCR", "PROJECT_ID", "PROJDESCR",
    "SUM(L.POSTED_TOTAL_AMT)", "BUDGET_REF_1", "ACTIVITY", "ACTVDESCR",
    "RESTYPE", "RESDESCR", "RCAT", "RCATDESCR", "RSUBCAT", "RSUBCATDESCR",
)
AMOUNT_COLUMN = "SUM(L.POSTED_TOTAL_AMT)"
GROUP_COLUMNS = (
    "BUSINESS_UNIT", "LEDGER", "FISCAL_YEAR", "ACCOUNTING_PERIOD",
    "FUND_CODE", "CLASS_FLD",
)
SCOPE_COLUMNS = GROUP_COLUMNS + (
    "DEPTID", "ACCOUNT", "OPERATING_UNIT", "PRODUCT", "PROGRAM_CODE",
    "BUDGET_REF", "CHARTFIELD1", "CHARTFIELD2", "PROJECT_ID", "BUDGET_REF_1",
    "ACTIVITY", "RESTYPE", "RCAT", "RSUBCAT",
)
# Explicit analysis mapping, never inferred from a prefix. Principal payments
# are fund expenditures here; this is not an assertion about GAAP debt balances.
ACCOUNTS = {
    "101000": ("Cash - Combining Trial Balance", "Asset"),
    "416101": ("Personal Income Tax", "Revenue"),
    "548110": ("Principal Payments-Bond Debt", "Expense"),
    "548130": ("Other Expenses-Bond Debt", "Expense"),
}
INDEX_HEADER = (
    "selected_record", "source_record", "source_byte_offset", "source_bytes", "sha256",
)
LEGACY_HEADER = (
    "entry_id", "effective_date", "account", "amount", "currency",
    "description", "memo", "source_record",
)


class DataError(ValueError):
    """A source, arithmetic, provenance or output safety refusal."""


def cents(text: str) -> int:
    """Parse exact dollars without binary floats or Decimal context loss."""
    if len(text) > 64 or not re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", text):
        raise DataError(f"invalid exact decimal amount: {text!r}")
    negative = text.startswith("-")
    whole, _, fraction = text.lstrip("-").partition(".")
    if any(digit != "0" for digit in fraction[2:]):
        raise DataError(f"fractional cents are not representable as USD scale 2: {text}")
    value = int(whole) * 100 + int((fraction + "00")[:2])
    if value > I128_MAX:
        raise DataError("amount exceeds the signed i128 accounting domain")
    return -value if negative else value


def dollars(value: int) -> str:
    magnitude = abs(value)
    return f"{'-' if value < 0 else ''}{magnitude // 100}.{magnitude % 100:02}"


def period_date(year: str, period: str) -> tuple[str, str]:
    """Map the declared July-start period to a derived calendar month end."""
    if year != "2024" or period not in ("10", "11", "12"):
        raise DataError(f"scope outside the pinned FY2024 fourth quarter: {year}/{period}")
    month = int(period) - 6
    day = calendar.monthrange(2024, month)[1]
    return f"FY2024-P{month:02}", f"2024-{month:02}-{day:02}"


class RawLines:
    """CSV iterator retaining exact record bytes with bounded record memory."""

    def __init__(self, stream):
        self.stream = stream
        self.parts: list[bytes] = []
        self.record_bytes = 0
        self.offset = 0
        self.digest = hashlib.sha256()

    def __iter__(self):
        return self

    def new_record(self):
        self.parts = []
        self.record_bytes = 0

    def __next__(self):
        raw = self.stream.readline(MAX_RECORD_BYTES + 1)
        if not raw:
            raise StopIteration
        self.record_bytes += len(raw)
        self.offset += len(raw)
        if self.record_bytes > MAX_RECORD_BYTES or self.offset > SOURCE_BYTES:
            raise DataError("source exceeds the bounded CSV record or file budget")
        self.digest.update(raw)
        self.parts.append(raw)
        try:
            return raw.decode("cp1252")
        except UnicodeDecodeError as exc:
            raise DataError("source contains undefined Windows-1252 bytes") from exc


def read_index(path: Path = DATA_DIR / "source_rows.csv") -> list[dict]:
    with path.open("rb") as stream:
        data = stream.read(100_001)
    if len(data) > 100_000 or hashlib.sha256(data).hexdigest() != INDEX_SHA256:
        raise DataError("source-row index SHA-256 differs from the pinned index")
    reader = csv.DictReader(io.StringIO(data.decode("ascii"), newline=""))
    if tuple(reader.fieldnames or ()) != INDEX_HEADER:
        raise DataError("source-row index schema differs from its declared columns")
    rows = []
    for ordinal, row in enumerate(reader, 1):
        decoded = {key: int(row[key]) for key in INDEX_HEADER[:-1]}
        decoded["sha256"] = row["sha256"]
        if decoded["selected_record"] != ordinal:
            raise DataError("source-row index is not gap-free")
        rows.append(decoded)
    if len(rows) != 312:
        raise DataError("source-row index does not contain the complete selected population")
    return rows


def collect(stream, kind: str, index: list[dict]) -> tuple[bytes, list[dict]]:
    """Read all source records; retain only the complete declared agency slice."""
    if kind not in ("full", "fixture"):
        raise DataError("source kind must be full or fixture")
    lines = RawLines(stream)
    reader = csv.reader(lines, strict=True)
    try:
        header = next(reader)
    except StopIteration as exc:
        raise DataError("source CSV is empty") from exc
    if tuple(header) != HEADER:
        raise DataError("source schema drift: expected the exact 36-column OMES header")
    selected_bytes = [b"".join(lines.parts)]
    selected = []
    source_count = 0
    while True:
        lines.new_record()
        offset = lines.offset
        try:
            fields = next(reader)
        except StopIteration:
            break
        source_count += 1
        if len(fields) != len(HEADER):
            raise DataError(f"source record {source_count}: expected 36 fields, got {len(fields)}")
        row = dict(zip(HEADER, fields, strict=True))
        if row["BUSINESS_UNIT"] != "90000":
            if kind == "fixture":
                raise DataError("selected fixture contains a different business unit")
            continue
        if len(selected) >= min(MAX_SELECTED_ROWS, len(index)):
            raise DataError("selected population exceeds its pinned row count")
        raw = b"".join(lines.parts)
        position = index[len(selected)]
        if hashlib.sha256(raw).hexdigest() != position["sha256"]:
            raise DataError(f"selected record {len(selected) + 1}: raw source-row SHA-256 mismatch")
        if kind == "full" and (
            source_count != position["source_record"]
            or offset != position["source_byte_offset"]
            or len(raw) != position["source_bytes"]
        ):
            raise DataError("selected row position differs from the complete pinned source")
        selected_bytes.append(raw)
        selected.append({"fields": row, "position": position})
    expected_hash = SOURCE_SHA256 if kind == "full" else FIXTURE_SHA256
    expected_size = SOURCE_BYTES if kind == "full" else FIXTURE_BYTES
    expected_count = SOURCE_ROWS if kind == "full" else 312
    if lines.digest.hexdigest() != expected_hash or lines.offset != expected_size:
        raise DataError(f"{kind} source SHA-256 or byte length differs from its pin")
    if source_count != expected_count or len(selected) != 312:
        raise DataError("source population does not match its pinned record counts")
    raw_selected = b"".join(selected_bytes)
    if hashlib.sha256(raw_selected).hexdigest() != FIXTURE_SHA256:
        raise DataError("complete agency extraction differs from its pinned fixture")
    return raw_selected, selected


def analyze(selected: list[dict]) -> tuple[list[dict], list[dict]]:
    """Exact activity totals and balanced reconstructed entry groups."""
    scopes = set()
    groups: dict[tuple, list[dict]] = {}
    periods: dict[str, dict] = {}
    for item in selected:
        row = item["fields"]
        if row["BUSINESS_UNIT"] != "90000" or row["LEDGER"] != "ACTUALS":
            raise DataError("unexpected business unit or ledger in selected population")
        if row["OCP_AGNCY_NAME"] != "DEVELOPMENT FINANCE AUTHORITY" or row["FUND_CODE"] != "8000":
            raise DataError("agency identity or fund differs from the declared population")
        code = row["ACCOUNT"]
        if code not in ACCOUNTS or row["ACCTDESCR"] != ACCOUNTS[code][0]:
            raise DataError(f"unmapped or renamed account: {code}")
        scope = tuple(row[key] for key in SCOPE_COLUMNS)
        if scope in scopes:
            raise DataError("duplicate chartfield scope; refusing to deduplicate or sum silently")
        scopes.add(scope)
        period, date = period_date(row["FISCAL_YEAR"], row["ACCOUNTING_PERIOD"])
        amount = cents(row[AMOUNT_COLUMN])
        entry = dict(item, cents=amount, date=date, period=period)
        group = tuple(row[key] for key in GROUP_COLUMNS)
        groups.setdefault(group, []).append(entry)
        totals = periods.setdefault(period, {
            "period": period, "source_period": int(row["ACCOUNTING_PERIOD"]), "date": date,
            "rows": 0, "nonzero_rows": 0, "entries": 0,
            "debit_cents": 0, "credit_cents": 0, "account_cents": {key: 0 for key in ACCOUNTS},
        })
        totals["rows"] += 1
        totals["nonzero_rows"] += amount != 0
        totals["debit_cents"] += max(amount, 0)
        totals["credit_cents"] += max(-amount, 0)
        totals["account_cents"][code] += amount
        if max(totals["debit_cents"], totals["credit_cents"]) > I128_MAX:
            raise DataError("period total exceeds the signed i128 accounting domain")
    normalized = []
    for group, entries in sorted(groups.items()):
        net = sum(entry["cents"] for entry in entries)
        if net:
            raise DataError(f"unbalanced source group {group}: signed residual {dollars(net)} USD")
        nonzero = [entry for entry in entries if entry["cents"]]
        if not nonzero:
            continue
        if len(nonzero) < 2:
            raise DataError("a nonzero source group cannot form a balanced journal entry")
        periods[nonzero[0]["period"]]["entries"] += 1
        entry_id = "OKGL:" + ":".join(group)
        description = f"OMES monthly activity FY{group[2]} P{group[3]} fund {group[4]} class {group[5]}"
        for entry in nonzero:
            record = entry["position"]["source_record"]
            normalized.append({
                "entry_id": entry_id, "effective_date": entry["date"],
                "account": entry["fields"]["ACCOUNT"], "amount": dollars(entry["cents"]),
                "currency": "USD", "description": description,
                "memo": f"source_record={record}", "source_record": str(record),
            })
    if set(periods) != {"FY2024-P04", "FY2024-P05", "FY2024-P06"}:
        raise DataError("selected population must contain all three quarter periods")
    period_totals = []
    for _, totals in sorted(periods.items()):
        if totals["debit_cents"] != totals["credit_cents"]:
            raise DataError("period is not exactly balanced")
        totals["account_nets"] = {
            key: dollars(value) for key, value in sorted(totals.pop("account_cents").items())
        }
        period_totals.append(totals)
    return normalized, period_totals


def json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def csv_bytes(header, rows) -> bytes:
    text = io.StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return text.getvalue().encode("utf-8")


def artifacts(source: Path, kind: str = "auto") -> dict[str, bytes]:
    if kind == "auto":
        size = source.stat().st_size
        if size == SOURCE_BYTES:
            kind = "full"
        elif size == FIXTURE_BYTES:
            kind = "fixture"
        else:
            raise DataError("source byte length matches neither pinned full file nor complete fixture")
    index = read_index()
    with source.open("rb") as stream:
        raw, selected = collect(stream, kind, index)
    normalized, period_totals = analyze(selected)
    chart = {"accounts": [
        {"code": code, "name": name, "type": account_type, "unit": "base"}
        for code, (name, account_type) in sorted(ACCOUNTS.items())
    ]}
    column_map = (
        '[columns]\nsource_system = "' + SOURCE_SYSTEM + '"\n'
        'default_unit = "USD"\nentry_id_column = "entry_id"\n'
        'effective_date_column = "effective_date"\naccount_column = "account"\n'
        'signed_amount_column = "amount"\nunit_column = "currency"\n'
        'description_column = "description"\nmemo_column = "memo"\n'
    )
    out = {
        "source.csv": raw.decode("cp1252").encode("utf-8"),
        "legacy.csv": csv_bytes(LEGACY_HEADER, normalized),
        "chart.json": json_bytes(chart),
        "column_map.toml": column_map.encode("utf-8"),
    }
    manifest = {
        "schema": "fa:public-activity:oklahoma:v1",
        "publisher": "State of Oklahoma, Office of Management and Enterprise Services",
        "source_url": SOURCE_URL, "catalog_url": CATALOG_URL,
        "license_url": LICENSE_URL, "attribution": "Oklahoma OMES public General Ledger, FY2024 Q4",
        "source_sha256": SOURCE_SHA256, "source_bytes": SOURCE_BYTES, "source_rows": SOURCE_ROWS,
        "selection": {"BUSINESS_UNIT": "90000"},
        "selection_sha256": FIXTURE_SHA256, "selection_bytes": len(raw),
        "selection_rows": len(selected), "zero_rows_retained": len(selected) - len(normalized),
        "normalized_legs": len(normalized), "reconstructed_entries": sum(p["entries"] for p in period_totals),
        "source_encoding": "Windows-1252 (strict)", "output_encoding": "UTF-8",
        "source_granularity": "monthly chartfield-level signed activity aggregates",
        "source_system": SOURCE_SYSTEM, "group_columns": list(GROUP_COLUMNS),
        "date_derivation": "FY2024 source periods 10,11,12 map to 2024-04-30,2024-05-31,2024-06-30; these are derived month ends, not original transaction dates",
        "account_mapping": "explicit fund-activity analysis: 101000 Asset; 416101 Revenue; 548110 and 548130 Expense (expenditures, not a GAAP debt or income statement claim)",
        "baseline": "zero before the selected quarter for an activity reconstruction; original opening balances are unavailable",
        "claim_boundary": "The complete published agency-quarter slice is retained. It is not a complete transaction journal, original trial balance, or reconstruction of agency financial position. Chartfields are preserved in source evidence, not queryable dimensions on the normalized legs.",
        "period_totals": period_totals, "rows": index,
        "outputs": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in sorted(out.items())},
    }
    out["manifest.json"] = json_bytes(manifest)
    return out


def prepare(source: Path, output: Path, kind: str = "auto") -> dict:
    if output.exists():
        raise DataError(f"output already exists; choose a new directory: {output}")
    prepared = artifacts(source, kind)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in prepared.items():
        with (output / name).open("xb") as stream:
            stream.write(data)
    return json.loads(prepared["manifest.json"])


class PublicRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = parse.urlparse(newurl)
        if destination.scheme != "https" or destination.hostname not in {"data.ok.gov", "s3.amazonaws.com"}:
            raise DataError("refusing an unexpected public-source redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(output: Path) -> None:
    """A failed/partial download is retained, never overwritten or deleted."""
    if output.exists():
        raise DataError(f"output already exists; choose a new file: {output}")
    opener = request.build_opener(PublicRedirect())
    req = request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    with opener.open(req, timeout=60) as response, output.open("xb") as stream:
        if response.status != 200:
            raise DataError(f"expected a complete HTTP 200 download, got {response.status}")
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > SOURCE_BYTES:
                raise DataError("download exceeds the pinned byte budget; retained file is unverified")
            digest.update(chunk)
            stream.write(chunk)
    if size != SOURCE_BYTES or digest.hexdigest() != SOURCE_SHA256:
        raise DataError("download SHA-256 or byte length mismatch; retained file is unverified")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("fetch", help="download and verify the full pinned 114 MB source")
    download.add_argument("--output", type=Path, required=True)
    build = commands.add_parser("prepare", help="prepare a new deterministic import package")
    build.add_argument("--source", type=Path, default=DATA_DIR / "source.csv")
    build.add_argument("--source-kind", choices=("auto", "fixture", "full"), default="auto")
    build.add_argument("--output", "--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            fetch(args.output)
            print(json.dumps({"status": "verified", "bytes": SOURCE_BYTES, "sha256": SOURCE_SHA256}))
        else:
            manifest = prepare(args.source, args.output, args.source_kind)
            print(json.dumps({"status": "prepared", "rows": manifest["selection_rows"], "legs": manifest["normalized_legs"], "entries": manifest["reconstructed_entries"]}))
    except (DataError, OSError, csv.Error, error.URLError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
