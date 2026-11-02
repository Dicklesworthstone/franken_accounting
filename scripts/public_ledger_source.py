#!/usr/bin/env python3
"""Lossless, exact ingestion of the Oklahoma OMES public ledger extract.

The publisher's rows are *aggregated posted activity by ChartField and month*.
They are not individual journal lines and contain no original journal IDs or
transaction dates. A balanced group is an observed property of an extract, not
an assertion that the public extract contains an entity's complete books.

All source fields stay strings. Amounts are parsed to integer thousandths so
that genuine subcent source values are reported, never rounded into cents.
"""

from __future__ import annotations

import csv
import hashlib
import os
from pathlib import Path
import re
import tempfile
from typing import Iterator, Sequence
import urllib.error
import urllib.request


SOURCE_URL = (
    "https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/"
    "resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/"
    "download/ledger_fy24_qtr4.csv"
)
SOURCE_SHA256 = "141e2d5524f6aa9d25c7331bc56f623f43da9a1f00cdfee42b7c5f3ccf6fc0fe"
SOURCE_SIZE_BYTES = 113_856_733
SOURCE_CATALOG_URL = "https://catalog.data.gov/dataset/general-ledger"
SOURCE_LICENSE_URL = "http://www.opendefinition.org/licenses/cc-by"
SOURCE_ATTRIBUTION = "State of Oklahoma, Office of Management and Enterprise Services"
SOURCE_ENCODING = "cp1252"
USER_AGENT = "franken_accounting-agent (+https://github.com/Dicklesworthstone/franken_accounting)"
AMOUNT_COLUMN = "SUM(L.POSTED_TOTAL_AMT)"
HEADERS = (
    "BUSINESS_UNIT", "OCP_AGNCY_NAME", "LEDGER", "FISCAL_YEAR",
    "ACCOUNTING_PERIOD", "FUND_CODE", "FUNDDESCR", "CLASS_FLD",
    "CLASSDESCR", "DEPTID", "DEPTDESCR", "ACCOUNT", "ACCTDESCR",
    "OPERATING_UNIT", "OPERUNITDESCR", "PRODUCT", "PRODUCTDESCR",
    "PROGRAM_CODE", "PGMDESCR", "BUDGET_REF", "CHARTFIELD1", "CF1DESCR",
    "CHARTFIELD2", "CF2DESCR", "PROJECT_ID", "PROJDESCR", AMOUNT_COLUMN,
    "BUDGET_REF_1", "ACTIVITY", "ACTVDESCR", "RESTYPE", "RESDESCR", "RCAT",
    "RCATDESCR", "RSUBCAT", "RSUBCATDESCR",
)
GROUP_COLUMNS = (
    "FISCAL_YEAR", "ACCOUNTING_PERIOD", "LEDGER", "FUND_CODE", "CLASS_FLD",
)
_AMOUNT = re.compile(r"([+-]?)([0-9]+)(?:\.([0-9]{1,3}))?\Z", re.ASCII)
_BLOCK_BYTES = 1024 * 1024


class SourceError(ValueError):
    """The input cannot support a lossless, source-qualified import."""


def amount_mills(text: str) -> int:
    """Parse a source decimal without binary floats or decimal-context rounding."""
    if not isinstance(text, str) or len(text) > 96:
        raise SourceError("amount must be a decimal string of at most 96 characters")
    match = _AMOUNT.fullmatch(text)
    if match is None:
        raise SourceError(f"invalid source amount {text!r}; expected at most three decimal places")
    sign, whole, fraction = match.groups()
    value = int(whole) * 1000 + int((fraction or "").ljust(3, "0"))
    return -value if sign == "-" else value


def amount_cents(text: str) -> int:
    """Refuse subcent source precision instead of silently quantizing it."""
    mills = amount_mills(text)
    if mills % 10:
        raise SourceError(f"subcent source amount {text!r} cannot be represented exactly in USD cents")
    return mills // 10


def fingerprint(path: str | Path) -> dict:
    """Return the hash and size of actual bytes, including the source encoding."""
    digest = hashlib.sha256()
    size = 0
    try:
        with Path(path).open("rb") as source:
            while block := source.read(_BLOCK_BYTES):
                digest.update(block)
                size += len(block)
    except OSError as error:
        raise SourceError(f"cannot read source {path}: {error}") from error
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def verify_source(path: str | Path) -> dict:
    """Verify the complete original distribution against the reviewed source pin."""
    result = fingerprint(path)
    if result["size_bytes"] != SOURCE_SIZE_BYTES or result["sha256"] != SOURCE_SHA256:
        raise SourceError(
            f"source pin mismatch: got {result['size_bytes']} bytes / {result['sha256']}; "
            f"expected {SOURCE_SIZE_BYTES} bytes / {SOURCE_SHA256}. "
            "Do not replace the pin without reviewing the new distribution."
        )
    return result


def fetch_source(destination: str | Path, *, timeout: int = 30) -> Path:
    """Fetch the pinned original with a byte limit and atomic publication.

    A verified existing file is reused. A different existing file is refused,
    preserving it. A partial or changed server response never becomes the
    destination. Network access is deliberately limited to this named source.
    """
    target = Path(destination)
    if target.is_symlink():
        raise SourceError("source destination must not be a symlink")
    if target.exists():
        verify_source(target)
        return target
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        raise SourceError("download timeout must be a positive integer")
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT})
    temporary: Path | None = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.geturl() != SOURCE_URL:
                raise SourceError("source download redirected; review the new source location before importing")
            length = response.headers.get("Content-Length")
            if length is not None and length != str(SOURCE_SIZE_BYTES):
                raise SourceError(f"source Content-Length {length!r} does not match the pinned byte count")
            digest = hashlib.sha256()
            size = 0
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{target.name}.", suffix=".partial",
                dir=target.parent, delete=False,
            ) as output:
                temporary = Path(output.name)
                while block := response.read(min(_BLOCK_BYTES, SOURCE_SIZE_BYTES + 1 - size)):
                    size += len(block)
                    if size > SOURCE_SIZE_BYTES:
                        raise SourceError("source response exceeded the pinned byte count")
                    digest.update(block)
                    output.write(block)
                if size != SOURCE_SIZE_BYTES or digest.hexdigest() != SOURCE_SHA256:
                    raise SourceError("downloaded source is truncated or does not match the pinned SHA-256")
                output.flush()
                os.fsync(output.fileno())
            # A second writer may have created target while the network read
            # was in progress. Publish exclusively, never replace that file.
            os.link(temporary, target)
            temporary.unlink()
            temporary = None
    except (OSError, urllib.error.URLError) as error:
        raise SourceError(f"source download failed: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def iter_rows(path: str | Path) -> Iterator[tuple[int, dict[str, str]]]:
    """Yield (one-based logical data-record ordinal, unmodified source fields).

    The header is not a data record. Embedded newlines remain inside a field;
    ordinals therefore do not pretend to be physical CSV line numbers. This
    reader performs no source-authenticity check: use ``verify_source`` for
    the full distribution or a reviewed subset manifest for an offline slice.
    """
    record = 0
    try:
        with Path(path).open("r", encoding=SOURCE_ENCODING, errors="strict", newline="") as source:
            reader = csv.reader(source, strict=True)
            header = next(reader, None)
            if header != list(HEADERS):
                raise SourceError("source CSV header does not exactly match the 36-column OMES schema")
            for record, values in enumerate(reader, 1):
                if len(values) != len(HEADERS):
                    raise SourceError(
                        f"source record {record} has {len(values)} columns, expected {len(HEADERS)}"
                    )
                if any("\x00" in value for value in values):
                    raise SourceError(f"source record {record} contains a NUL character")
                yield record, dict(zip(HEADERS, values))
    except (OSError, UnicodeError, csv.Error) as error:
        raise SourceError(f"cannot decode source CSV near data record {record + 1}: {error}") from error


def _validate_row(record: int, fields: dict[str, str]) -> None:
    checks = (
        ("BUSINESS_UNIT", r"[0-9]{5}"),
        ("FISCAL_YEAR", r"[0-9]{4}"),
        ("ACCOUNTING_PERIOD", r"[0-9]{1,2}"),
        ("FUND_CODE", r"[0-9]{4}"),
        ("CLASS_FLD", r"[0-9A-Z]{5}"),
        ("ACCOUNT", r"[0-9]{6}"),
    )
    for column, pattern in checks:
        if re.fullmatch(pattern, fields[column], re.ASCII) is None:
            raise SourceError(f"source record {record}: unsupported {column} {fields[column]!r}")
    if int(fields["FISCAL_YEAR"]) == 0 or not 1 <= int(fields["ACCOUNTING_PERIOD"]) <= 12:
        raise SourceError(f"source record {record}: unsupported fiscal year or special accounting period")
    if fields["LEDGER"] != "ACTUALS":
        raise SourceError(f"source record {record}: expected ACTUALS ledger, got {fields['LEDGER']!r}")
    if not fields["OCP_AGNCY_NAME"].strip() or not fields["ACCTDESCR"].strip():
        raise SourceError(f"source record {record}: missing agency or account description")


def _new_totals() -> dict:
    return {
        "rows": 0, "positive_rows": 0, "negative_rows": 0, "zero_rows": 0,
        "positive_mills": 0, "negative_mills": 0, "net_mills": 0, "subcent_rows": 0,
    }


def _add_amount(totals: dict, mills: int) -> None:
    totals["rows"] += 1
    totals["net_mills"] += mills
    if mills > 0:
        totals["positive_rows"] += 1
        totals["positive_mills"] += mills
    elif mills < 0:
        totals["negative_rows"] += 1
        totals["negative_mills"] += mills
    else:
        totals["zero_rows"] += 1
    if mills % 10:
        totals["subcent_rows"] += 1


def profile_source(path: str | Path, *, verify: bool = True) -> dict:
    """Stream the source and report exact census, imbalances and subcent rows.

    ``verify=False`` is for explicit local fixtures; the report marks them
    unverified. A nonzero source sum is reported as observed, never repaired.
    """
    identity = verify_source(path) if verify else fingerprint(path)
    totals = _new_totals()
    agencies: set[str] = set()
    accounts: set[str] = set()
    periods: dict[tuple[str, ...], dict] = {}
    subcents = []
    for record, fields in iter_rows(path):
        _validate_row(record, fields)
        mills = amount_mills(fields[AMOUNT_COLUMN])
        _add_amount(totals, mills)
        agencies.add(fields["BUSINESS_UNIT"])
        accounts.add(fields["ACCOUNT"])
        key = tuple(fields[k] for k in ("BUSINESS_UNIT", "FISCAL_YEAR", "ACCOUNTING_PERIOD", "LEDGER"))
        group = periods.setdefault(key, {"agency_name": fields["OCP_AGNCY_NAME"], **_new_totals()})
        _add_amount(group, mills)
        if mills % 10:
            subcents.append({
                "source_record": record, "business_unit": fields["BUSINESS_UNIT"],
                "fiscal_year": fields["FISCAL_YEAR"], "period": fields["ACCOUNTING_PERIOD"],
                "account": fields["ACCOUNT"], "amount": fields[AMOUNT_COLUMN], "amount_mills": mills,
            })
    if not totals["rows"]:
        raise SourceError("source CSV contains no data records")
    return {
        "source_url": SOURCE_URL if verify else None,
        "verified_source": verify, **identity, "encoding": SOURCE_ENCODING,
        "headers": list(HEADERS), "summary": {
            **totals, "agency_count": len(agencies), "account_count": len(accounts),
            "agency_period_count": len(periods),
            "unbalanced_agency_period_count": sum(g["net_mills"] != 0 for g in periods.values()),
        },
        "agency_periods": [{"key": list(key), **value} for key, value in sorted(periods.items())],
        "subcent_diagnostics": subcents,
    }


def read_agency(
    path: str | Path, agency: str, *, source_records: Sequence[int] | None = None,
) -> dict:
    """Read every row for one agency and group solely by source ChartFields.

    For an offline byte-preserving subset, ``source_records`` maps each input
    data-record ordinal to its original distribution ordinal. Its authenticity
    must be checked against the subset manifest by the caller. No requested
    agency row is dropped, including zeros, negatives and unbalanced groups.
    """
    if re.fullmatch(r"[0-9]{5}", agency, re.ASCII) is None:
        raise SourceError("agency must be the five-digit BUSINESS_UNIT, preserving leading zeros")
    if source_records is not None:
        if any(not isinstance(n, int) or isinstance(n, bool) or n <= 0 for n in source_records):
            raise SourceError("source-record map must contain positive integer ordinals")
        if any(a >= b for a, b in zip(source_records, source_records[1:])):
            raise SourceError("source-record map must be strictly increasing without duplicates")
    rows = []
    groups: dict[tuple[str, ...], dict] = {}
    accounts: dict[str, str] = {}
    totals = _new_totals()
    scanned = 0
    for input_record, fields in iter_rows(path):
        scanned = input_record
        if source_records is not None and input_record > len(source_records):
            raise SourceError("source-record map is shorter than the input CSV")
        record = input_record if source_records is None else source_records[input_record - 1]
        if fields["BUSINESS_UNIT"] != agency:
            continue
        _validate_row(record, fields)
        mills = amount_mills(fields[AMOUNT_COLUMN])
        row = {"source_record": record, "fields": fields, "amount_mills": mills}
        rows.append(row)
        _add_amount(totals, mills)
        code, name = fields["ACCOUNT"], fields["ACCTDESCR"]
        if code in accounts and accounts[code] != name:
            raise SourceError(f"source account {code} has conflicting descriptions; explicit review is required")
        accounts[code] = name
        key = tuple(fields[column] for column in GROUP_COLUMNS)
        group = groups.setdefault(key, {"key": list(key), "rows": [], "net_mills": 0})
        group["rows"].append(row)
        group["net_mills"] += mills
    if source_records is not None and scanned != len(source_records):
        raise SourceError("source-record map is longer than the input CSV")
    if not rows:
        raise SourceError(f"no rows found for agency {agency}; no empty import was prepared")
    ordered_groups = [groups[key] for key in sorted(groups)]
    return {
        "agency": agency, "agency_name": rows[0]["fields"]["OCP_AGNCY_NAME"],
        "headers": list(HEADERS), "rows": rows, "groups": ordered_groups,
        "accounts": [{"code": code, "name": name} for code, name in sorted(accounts.items())],
        "summary": {
            **totals, "source_rows_scanned": scanned, "account_count": len(accounts),
            "group_count": len(groups),
            "max_group_rows": max(len(g["rows"]) for g in ordered_groups),
            "max_nonzero_group_rows": max(
                sum(r["amount_mills"] != 0 for r in g["rows"]) for g in ordered_groups
            ),
        },
    }


def prepare_agency(
    path: str | Path, agency: str, *, source_records: Sequence[int] | None = None,
) -> dict:
    """Require exact cents and balance in *every* selected natural source group.

    Zero rows and all-zero groups remain in the result as source evidence. The
    caller may omit them from monetary postings, but must retain their source
    coverage. No balancing, rounding, artificial counterpart or amount split
    is performed here.
    """
    result = read_agency(path, agency, source_records=source_records)
    subcents = [r["source_record"] for r in result["rows"] if r["amount_mills"] % 10]
    if subcents:
        raise SourceError(f"agency {agency} has subcent source amounts at records {subcents[:20]}; import refused")
    unbalanced = [g for g in result["groups"] if g["net_mills"]]
    if unbalanced:
        first = unbalanced[0]
        raise SourceError(
            f"agency {agency} has {len(unbalanced)} unbalanced source group(s); "
            f"first key={first['key']} net_mills={first['net_mills']}. "
            "The complete agency import is refused; no balancing leg was invented."
        )
    return result
