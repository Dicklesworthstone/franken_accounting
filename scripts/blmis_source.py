#!/usr/bin/env python3
"""Reproduce the complete published Glantz Exhibit B-2 account 1ZA192.

This stdlib-only helper binds factual rows to a pinned court-filing PDF. The
optional authoring extraction calls Poppler's pdftotext; offline verification
and preparation need no network, PDF library, or accounting-engine substitute.
The trustee's printed principal balances remain controls, never posting input.
"""

from __future__ import annotations

import argparse
import csv
from datetime import date
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib import error, parse, request


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "crates/fa-oracles/data/blmis_glantz_1za192"
SOURCE_ID = "SRC-BLM-001"
ACCOUNT = "1ZA192"
SOURCE_URL = (
    "https://www.madofftrustee.com/document/dockets/"
    "008796-glantzcomplaint10-05394docket93.pdf"
)
SOURCE_SHA256 = "751a8a55bf02b022076af39c8637086630090b41164f70e2a04184c0d003dec1"
SOURCE_BYTES = 389_586
ROWS_SHA256 = "286af73204e2451bac782d03e1270ccb70d4b8138219f571db1c4ea0d0f90a3b"
METADATA_SHA256 = "037fd6652ccfc133cf6366a765b7f70a8ff866801f2b88ff636c9c631cbaddfc"
PDF_PAGES = (31, 32, 33)
PAGE_ROW_COUNTS = (35, 35, 5)
USER_AGENT = "franken_accounting-public-data (+https://github.com/Dicklesworthstone/franken_accounting)"
I128_MAX = (1 << 127) - 1
SOURCE_SYSTEM = "blmis-glantz-exhibit-b2-1za192-v1"
PRINCIPAL_ACCOUNT = "BLMIS-1ZA192"
CASH_ACCOUNT = "BLMIS-CASH"
TRANSFER_ACCOUNT = "BLMIS-TRANSFER"
VALUE_FIELDS = (
    "reported", "deposits", "withdrawals", "transfers_in", "transfers_out",
    "printed_balance", "two_year",
)
FOOTER_FIELDS = VALUE_FIELDS[1:]
HEADERS = (
    "Date", "Transaction Description",
    "Transaction Amount as Reported in Customer Statement", "Deposits",
    "Withdrawals", "Transfers of Principal In", "Transfers of Principal Out",
    "Balance of Principal", "2-Year Fraudulent Transfers - Fictitious Profits",
)
ROW_COLUMNS = (
    "row_id", "account", "pdf_page", "exhibit_page", "page_row", "source_line",
    "date_literal", "description", *(f"{field}_literal" for field in VALUE_FIELDS),
    "raw_line_sha256",
)
LEGACY_COLUMNS = (
    "entry_id", "effective_date", "account_code", "signed_amount",
    "description", "memo", "source_row",
)
COLUMN_MAP = '''[columns]
source_system = "blmis-glantz-exhibit-b2-1za192-v1"
entry_id_column = "entry_id"
effective_date_column = "effective_date"
account_column = "account_code"
signed_amount_column = "signed_amount"
description_column = "description"
memo_column = "memo"
'''
SCOPE = (
    "Every published transaction of Glantz Exhibit B-2 account 1ZA192, "
    "1992-12-07 through 2008-10-30. Trustee computations in a complaint, "
    "not a complete BLMIS general ledger or independently established net equity. "
    "Transfer principal is copied from the trustee's columns 6 and 7 as named "
    "oracle inputs; the statement amount in column 3 is retained separately. "
    "Cash, transfer counterpart and investor-capital accounts are an explicit "
    "analysis-book construction, not source-published double-entry accounts."
)


class SourceError(ValueError):
    """Source identity, extraction, exact arithmetic or output refusal."""


class EnvironmentError(SourceError):
    """A required acquisition or extraction facility is unavailable."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def csv_bytes(columns: tuple[str, ...], rows: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n", extrasaction="raise")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def amount_cents(literal: str, *, allow_footnote: bool = False) -> tuple[int, list[int]]:
    """The exhibit prints whole dollars, parentheses and explicit dash cells.

    No blank, fractional, malformed grouping or unknown footnote is accepted.
    The original literal is retained by callers, including every dash and marker.
    """
    require(isinstance(literal, str) and len(literal) <= 64, "invalid amount literal")
    match = re.fullmatch(r"(.+?)(?: \[([12])\])?", literal)
    require(match is not None, f"unparseable amount {literal!r}")
    number, note = match.groups()
    require(note is None or allow_footnote, "footnote outside reported-amount column")
    if number == "-":
        require(note is None, "a dash cannot carry a reported-amount footnote")
        return 0, []
    negative = number.startswith("(") and number.endswith(")")
    magnitude = number[1:-1] if negative else number
    require(re.fullmatch(r"(?:0|[1-9][0-9]*|[1-9][0-9]{0,2}(?:,[0-9]{3})+)", magnitude) is not None,
            f"unparseable whole-dollar amount {literal!r}")
    cents = int(magnitude.replace(",", "")) * 100
    require(cents <= I128_MAX, "amount exceeds the accounting i128 domain")
    return (-cents if negative else cents), ([] if note is None else [int(note)])


def iso_date(literal: str) -> str:
    require(re.fullmatch(r"[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}", literal) is not None,
            f"invalid source date {literal!r}")
    month, day, year = map(int, literal.split("/"))
    try:
        return date(year, month, day).isoformat()
    except ValueError as exc:
        raise SourceError(f"invalid source date {literal!r}") from exc


def row_values(raw: dict) -> dict:
    """Decode one retained factual row, without inventing missing source cells."""
    require(set(raw) == set(ROW_COLUMNS), "retained source row has unexpected fields")
    row = dict(raw)
    require(row["account"] == ACCOUNT, "unexpected source account")
    for field in ("pdf_page", "exhibit_page", "page_row", "source_line"):
        require(re.fullmatch(r"[1-9][0-9]*", str(row[field])) is not None,
                f"invalid provenance field {field}")
        row[field] = int(row[field])
    expected_id = f"{SOURCE_ID}:{ACCOUNT}:p{row['pdf_page']}:l{row['source_line']}"
    require(row["row_id"] == expected_id, "row identifier differs from its source location")
    require(re.fullmatch(r"[0-9a-f]{64}", row["raw_line_sha256"]) is not None,
            "invalid source-line hash")
    row["date"] = iso_date(row["date_literal"])
    description = row["description"]
    require(description in ("CHECK", "CHECK WIRE") or
            re.fullmatch(r"TRANS (?:TO|FROM) [A-Z0-9]+ \([A-Z0-9]+\)", description) is not None,
            "unrecognized source transaction description")
    for field in VALUE_FIELDS:
        value, notes = amount_cents(row[f"{field}_literal"], allow_footnote=field == "reported")
        row[f"{field}_cents"] = value
        if field == "reported":
            row["footnotes"] = notes
    require(row["deposits_cents"] >= 0 and row["transfers_in_cents"] >= 0,
            "negative amount in incoming-principal column")
    require(row["withdrawals_cents"] <= 0 and row["transfers_out_cents"] <= 0,
            "positive amount in outgoing-principal column")
    row["cash_movement_cents"] = row["deposits_cents"] + row["withdrawals_cents"]
    row["transfer_movement_cents"] = row["transfers_in_cents"] + row["transfers_out_cents"]
    row["principal_movement_cents"] = row["cash_movement_cents"] + row["transfer_movement_cents"]
    row["transfer_credit_role"] = "oracle_output" if description.startswith("TRANS ") else "not_applicable"
    if description.startswith("TRANS "):
        require(row["cash_movement_cents"] == 0, "transfer row unexpectedly contains cash movement")
    else:
        require(row["transfer_movement_cents"] == 0 and not row["footnotes"],
                "cash row unexpectedly contains transfer principal or footnote")
        require(row["cash_movement_cents"] == row["reported_cents"],
                "cash amount differs from reported amount")
    return row


def parse_layout(text: str) -> tuple[list[dict], dict]:
    """Extract the explicitly declared nine-column B-2 layout.

    Structural errors fail. Arithmetic discrepancies are returned separately by
    diagnostics(), so an altered printed balance cannot be hidden as extraction
    failure or silently corrected. This adapter intentionally supports one account.
    """
    require(len(text.encode()) <= 100_000, "unexpectedly large account extraction")
    pages = text.split("\f")
    require(len(pages) == 4 and not pages[-1].strip(), "expected exactly three PDF pages")
    rows, footer, footnotes = [], None, {}
    page_hashes = []
    for page_index, page in enumerate(pages[:-1]):
        pdf_page = PDF_PAGES[page_index]
        lines = page.splitlines()
        page_hashes.append(digest(page.encode()))
        require(f"BLMIS ACCOUNT NO. {ACCOUNT} -" in page, f"wrong account on PDF page {pdf_page}")
        require("Exhibit B-2" in page and f"Pg {page_index + 5} of 14" in page,
                f"wrong exhibit page {pdf_page}")
        require(f"Page {page_index + 1} of 3 - {ACCOUNT}" in page,
                f"missing complete-account page marker on PDF page {pdf_page}")
        require("Filed 01/22/18" in page, "source filing vintage changed")
        column_rows = [line for line in lines if "Column 1" in line]
        require(len(column_rows) == 1 and re.findall(r"Column ([0-9]+)", column_rows[0]) == list("123456789"),
                f"unexpected declared column layout on PDF page {pdf_page}")
        last_header = [line for line in lines if "Customer Statement" in line and "Fictitious Profits" in line]
        require(len(last_header) == 1 and all(label in last_header[0] for label in (
            "Date", "Description", "Deposits", "Withdrawals", "Principal In", "Principal Out", "Fictitious Profits")),
            f"unexpected source column headers on PDF page {pdf_page}")
        count = 0
        for number, line in enumerate(lines, 1):
            if re.match(r"^\s*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}\s", line):
                cells = re.split(r"\s{2,}", line.strip())
                require(len(cells) == 9, f"expected nine cells at PDF page {pdf_page} line {number}")
                count += 1
                row = {
                    "row_id": f"{SOURCE_ID}:{ACCOUNT}:p{pdf_page}:l{number}",
                    "account": ACCOUNT, "pdf_page": str(pdf_page),
                    "exhibit_page": str(page_index + 5), "page_row": str(count),
                    "source_line": str(number), "date_literal": cells[0],
                    "description": cells[1], "raw_line_sha256": digest(line.encode()),
                }
                row.update({f"{field}_literal": cell for field, cell in zip(VALUE_FIELDS, cells[2:], strict=True)})
                row_values(row)
                rows.append(row)
            elif "Total:" in line:
                require(footer is None and page_index == 2, "unexpected or duplicate printed footer")
                cells = [part.strip() for part in line.split("Total:", 1)[1].split("$")]
                require(cells[0] == "" and len(cells) == 7, "expected six printed footer amounts")
                footer = {"pdf_page": pdf_page, "source_line": number,
                          "raw_line_sha256": digest(line.encode()),
                          "cells": dict(zip(FOOTER_FIELDS, cells[1:], strict=True))}
                for cell in cells[1:]:
                    amount_cents(cell)
            elif re.fullmatch(r"\s*\[[12]\]\s*", line):
                marker = line.strip()
                require(marker not in footnotes, "duplicate source footnote")
                collected = []
                for next_line in lines[number:]:
                    if not next_line.strip() or re.fullmatch(r"\s*\[[12]\]\s*", next_line):
                        break
                    collected.append(next_line.strip())
                require(collected, "empty source footnote")
                normalized = " ".join(" ".join(collected).split())
                footnotes[marker] = {"pdf_page": pdf_page, "source_line": number,
                                     "normalized_text_sha256": digest(normalized.encode())}
        require(count == PAGE_ROW_COUNTS[page_index],
                f"incomplete account: PDF page {pdf_page} has {count} dated rows, expected {PAGE_ROW_COUNTS[page_index]}")
    require(footer is not None and set(footnotes) == {"[1]", "[2]"}, "missing footer or transfer footnotes")
    decoded = [row_values(row) for row in rows]
    require([row["date"] for row in decoded] == sorted(row["date"] for row in decoded),
            "source dates are not in printed chronological order")
    metadata = {
        "schema_version": 1, "source_id": SOURCE_ID, "source_url": SOURCE_URL,
        "source_sha256": SOURCE_SHA256, "source_bytes": SOURCE_BYTES,
        "filed_on": "2018-01-22", "account": ACCOUNT, "exhibit": "B-2",
        "pdf_pages": list(PDF_PAGES), "exhibit_pages": [5, 6, 7],
        "rows_per_page": list(PAGE_ROW_COUNTS), "row_count": len(rows),
        "headers": list(HEADERS), "printed_amount_unit": "USD whole dollars",
        "dash_interpretation": "A printed dash is no movement in that source column; blank cells are refused.",
        "row_id_basis": "Derived citation identifier: source id, trustee account id, PDF page and pdftotext line; not an original transaction id.",
        "extraction": {"command": "pdftotext -layout -f 31 -l 33 <pinned.pdf> -",
                       "authoring_version": "pdftotext version 24.02.0",
                       "utf8_sha256": digest(text.encode()), "page_utf8_sha256": page_hashes,
                       "line_hash_basis": "SHA-256 of the exact UTF-8 extracted line without its newline"},
        "footer": footer, "footnotes": footnotes,
        "footnote_meaning": {
            "[1]": "The trustee credited only remaining principal from the originating account, excluding reported fictitious profits.",
            "[2]": "The trustee credited no principal because the reported transfer consisted entirely of fictitious profits; principal stayed unchanged.",
        },
        "transfer_principal_role": "oracle_output",
        "assertion_status": "trustee_computation in a complaint; not a court finding",
        "redistribution_basis": "Factual transaction cells from a publicly hosted court filing; no full complaint or account-holder header is redistributed.",
        "scope": SCOPE,
    }
    return rows, metadata


def diagnostics(rows: list[dict], metadata: dict) -> dict:
    """Compare movement arithmetic with independently printed row/footer cells."""
    running, differences = 0, []
    totals = {field: 0 for field in ("deposits", "withdrawals", "transfers_in", "transfers_out", "two_year")}
    for row in rows:
        running += row["principal_movement_cents"]
        require(abs(running) <= I128_MAX, "principal fold exceeds i128")
        gap = running - row["printed_balance_cents"]
        if gap:
            differences.append({"row_id": row["row_id"], "gap_cents": gap})
        for field in totals:
            totals[field] += row[f"{field}_cents"]
    footer_gaps = {}
    for field, actual in {**totals, "printed_balance": running}.items():
        expected, _ = amount_cents(metadata["footer"]["cells"][field])
        if actual != expected:
            footer_gaps[field] = actual - expected
    return {"rows": len(rows), "rows_off": len(differences), "row_differences": differences,
            "maximum_gap_cents": max((abs(item["gap_cents"]) for item in differences), default=0),
            "closing_gap_cents": running - rows[-1]["printed_balance_cents"],
            "footer_gaps_cents": footer_gaps,
            "printed_closing_balance_cents": rows[-1]["printed_balance_cents"],
            "transfer_rows": sum(row["description"].startswith("TRANS ") for row in rows),
            "zero_principal_rows": [row["row_id"] for row in rows if row["principal_movement_cents"] == 0]}


def verify_rows(rows: list[dict], metadata: dict) -> dict:
    require(len(rows) == 75 and len({row["row_id"] for row in rows}) == 75,
            "complete account must contain 75 distinct source rows")
    require([row["date"] for row in rows] == sorted(row["date"] for row in rows), "source row order changed")
    for page, count in zip(PDF_PAGES, PAGE_ROW_COUNTS, strict=True):
        selected = [row for row in rows if row["pdf_page"] == page]
        require(len(selected) == count, "account page population differs")
        require([row["page_row"] for row in selected] == list(range(1, count + 1)), "source page row order differs")
    report = diagnostics(rows, metadata)
    require(report["rows_off"] == 0 and not report["footer_gaps_cents"],
            "the selected exact-footing account disagrees with printed controls")
    require(report["transfer_rows"] == 3 and len(report["zero_principal_rows"]) == 1,
            "complete account transfer population differs")
    return report


def load_fixture(directory: Path = FIXTURE_DIR) -> tuple[list[dict], dict]:
    """Trust code-owned pins, never a caller-supplied checksum sidecar."""
    raw = (directory / "rows.csv").read_bytes()
    metadata_raw = (directory / "source.json").read_bytes()
    require(digest(raw) == ROWS_SHA256, "source rows SHA-256 differs from the committed pin")
    require(digest(metadata_raw) == METADATA_SHA256, "source metadata SHA-256 differs from the committed pin")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
    require(reader.fieldnames == list(ROW_COLUMNS), "source CSV header differs")
    rows = [row_values(row) for row in reader]
    metadata = json.loads(metadata_raw)
    require(metadata["source_sha256"] == SOURCE_SHA256 and metadata["source_bytes"] == SOURCE_BYTES,
            "metadata binds another original document")
    verify_rows(rows, metadata)
    return rows, metadata


def verify_pdf(path: Path) -> bytes:
    require(path.stat().st_size == SOURCE_BYTES, "PDF byte count differs from the pinned original")
    raw = path.read_bytes()
    require(digest(raw) == SOURCE_SHA256 and raw.startswith(b"%PDF-"), "PDF SHA-256 differs from the pinned original")
    return raw


def extract_pdf(path: Path) -> tuple[bytes, bytes]:
    verify_pdf(path)
    try:
        result = subprocess.run(["pdftotext", "-layout", "-f", "31", "-l", "33", str(path), "-"],
                                capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentError(f"pdftotext extraction unavailable: {exc}") from exc
    require(result.returncode == 0, "pdftotext could not extract the pinned document")
    rows, metadata = parse_layout(result.stdout.decode("utf-8", errors="strict"))
    raw, meta = csv_bytes(ROW_COLUMNS, rows), json_bytes(metadata)
    require(digest(raw) == ROWS_SHA256 and digest(meta) == METADATA_SHA256,
            "PDF extraction differs from the reviewed fixture; review extractor/source drift, never regenerate pins automatically")
    verify_rows([row_values(row) for row in rows], metadata)
    return raw, meta


class PinnedRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = parse.urlsplit(newurl)
        require(destination.scheme == "https" and destination.hostname in ("www.madofftrustee.com", "madofftrustee.com")
                and destination.port in (None, 443) and not destination.username and not destination.password,
                "download redirect left the publisher's HTTPS origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(output: Path) -> None:
    require(not output.exists(), "download destination already exists")
    req = request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/pdf"})
    try:
        with request.build_opener(PinnedRedirect()).open(req, timeout=30) as response:
            require(response.status == 200, "expected a complete HTTP 200 PDF response")
            raw = response.read(SOURCE_BYTES + 1)
    except (OSError, error.URLError) as exc:
        raise EnvironmentError(f"source download unavailable: {exc}") from exc
    require(len(raw) == SOURCE_BYTES and digest(raw) == SOURCE_SHA256,
            "download differs from pinned PDF size or SHA-256")
    with output.open("xb") as stream:
        stream.write(raw)


def money(cents: int) -> str:
    return f"{'-' if cents < 0 else ''}{abs(cents) // 100}.{abs(cents) % 100:02}"


def last_printed_balance(rows: list[dict], at_date: str) -> dict:
    try:
        date.fromisoformat(at_date)
    except ValueError as exc:
        raise SourceError("invalid control date") from exc
    selected = [row for row in rows if row["date"] <= at_date]
    require(bool(selected), "no published balance on or before the requested date")
    row = selected[-1]
    return {"at_date": at_date, "source_row_id": row["row_id"], "source_date": row["date"],
            "printed_balance_cents": row["printed_balance_cents"]}


def prepare(output: Path, directory: Path = FIXTURE_DIR) -> dict:
    rows, metadata = load_fixture(directory)
    require(not output.exists(), "package destination already exists")
    normalized, zero_rows, mapping = [], [], []
    for row in rows:
        movement = row["principal_movement_cents"]
        if not movement:
            zero_rows.append(row["row_id"])
            continue
        for account, amount in (
            (PRINCIPAL_ACCOUNT, -movement),
            (CASH_ACCOUNT, row["cash_movement_cents"]),
            (TRANSFER_ACCOUNT, row["transfer_movement_cents"]),
        ):
            if not amount:
                continue
            normalized.append({
                "entry_id": row["row_id"], "effective_date": row["date"],
                "account_code": account, "signed_amount": money(amount),
                "description": row["description"],
                "memo": f"analysis counterpart; {SOURCE_ID} Exhibit B-2 PDF p{row['pdf_page']} line {row['source_line']}",
                "source_row": row["row_id"],
            })
        mapping.append({"entry_id": row["row_id"], "source_row_id": row["row_id"],
                        "transfer_principal_role": row["transfer_credit_role"]})
    first_year, last_year = int(rows[0]["date"][:4]), int(rows[-1]["date"][:4])
    controls = [last_printed_balance(rows, f"{year}-12-31") for year in range(first_year, last_year + 1)]
    chart = {"accounts": [
        {"code": PRINCIPAL_ACCOUNT, "name": "Published principal 1ZA192 - analysis account", "type": "Equity", "unit": "USD"},
        {"code": CASH_ACCOUNT, "name": "Published cash movements - analysis counterpart", "type": "Asset", "unit": "USD"},
        {"code": TRANSFER_ACCOUNT, "name": "Trustee-credited transfers - analysis clearing", "type": "Liability", "unit": "USD"},
    ]}
    payloads = {"rows.csv": (directory / "rows.csv").read_bytes(), "source.json": (directory / "source.json").read_bytes(),
                "legacy.csv": csv_bytes(LEGACY_COLUMNS, normalized), "chart.json": json_bytes(chart),
                "column_map.toml": COLUMN_MAP.encode(), "controls.json": json_bytes(controls)}
    manifest = {"schema_version": 1, "source_system": SOURCE_SYSTEM, "scope": SCOPE,
                "source_sha256": SOURCE_SHA256, "source_rows_sha256": ROWS_SHA256,
                "source_rows": len(rows), "monetary_rows": len(mapping), "normalized_legs": len(normalized),
                "zero_principal_rows": zero_rows, "row_mapping": mapping,
                "principal_account": PRINCIPAL_ACCOUNT, "principal_posting_sign": "negative of trustee principal movement",
                "baseline": "zero immediately before the exhibit's first transaction; not a whole-firm opening trial balance",
                "controls_basis": "last printed principal balance on or before each year end; never computed from normalized legs",
                "row_order": "source page and line order; same-day rows must be compared in exhibit order",
                "source_diagnostics": verify_rows(rows, metadata),
                "outputs": {name: {"bytes": len(raw), "sha256": digest(raw)} for name, raw in payloads.items()}}
    payloads["manifest.json"] = json_bytes(manifest)
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("fetch", help="download and verify the original 389,586-byte PDF")
    download.add_argument("--output", type=Path, required=True)
    extract = commands.add_parser("extract", help="re-extract all account rows and require reviewed byte identity")
    extract.add_argument("--pdf", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify pinned retained rows and every printed balance offline")
    verify.add_argument("--source-dir", type=Path, default=FIXTURE_DIR)
    normalize = commands.add_parser("prepare", help="prepare an explicitly constructed double-entry analysis package")
    normalize.add_argument("--source-dir", type=Path, default=FIXTURE_DIR)
    normalize.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            fetch(args.output)
            print(f"PASS source PDF bytes={SOURCE_BYTES} sha256={SOURCE_SHA256}")
        elif args.command == "extract":
            require(not args.output.exists(), "extraction destination already exists")
            raw, metadata = extract_pdf(args.pdf)
            args.output.mkdir(parents=True, exist_ok=False)
            for name, content in (("rows.csv", raw), ("source.json", metadata)):
                with (args.output / name).open("xb") as stream:
                    stream.write(content)
            print(f"PASS extracted account={ACCOUNT} rows=75 sha256={digest(raw)}")
        elif args.command == "verify":
            rows, metadata = load_fixture(args.source_dir)
            print(json.dumps(verify_rows(rows, metadata), sort_keys=True))
        else:
            print(json.dumps(prepare(args.output, args.source_dir), sort_keys=True))
        return 0
    except EnvironmentError as exc:
        print(f"UNRUN {exc}", file=sys.stderr)
        return 4
    except (SourceError, OSError, UnicodeError, csv.Error, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
