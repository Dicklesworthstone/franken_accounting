#!/usr/bin/env python3
"""Reproduce published Glantz Exhibit B transaction histories.

The default preserves complete account 1ZA192. --account all acquires and
extracts the same pinned PDF to process all six published Exhibit B accounts.

This stdlib-only helper binds factual rows to a pinned court-filing PDF. The
PDF ingestion calls Poppler's pdftotext; explicit offline retained-row
verification and preparation need no network or PDF library.
The trustee's printed principal balances remain controls, never posting input.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
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


# The original B-2 API and pins above remain a separately reproducible workload.
# This explicit account census was checked against every page of Exhibit B;
# the planning document's earlier 1,429-row Glantz estimate is not the source.
GLANTZ_FIXTURE_DIR = ROOT / "crates/fa-oracles/data/blmis_glantz"
GLANTZ_SOURCE_SYSTEM = "blmis-glantz-exhibit-b1-b6-v1"
GLANTZ_ACCOUNTS = {
    "1T0026": {"exhibit": "B-1", "pdf_pages": (27, 28, 29, 30), "rows_per_page": (33, 35, 35, 14)},
    "1ZA192": {"exhibit": "B-2", "pdf_pages": (31, 32, 33), "rows_per_page": (35, 35, 5)},
    "1ZB010": {"exhibit": "B-3", "pdf_pages": (34, 35), "rows_per_page": (33, 28)},
    "1ZB143": {"exhibit": "B-4", "pdf_pages": (36, 37), "rows_per_page": (35, 16)},
    "1ZR010": {"exhibit": "B-5", "pdf_pages": (38, 39), "rows_per_page": (32, 25)},
    "1ZR176": {"exhibit": "B-6", "pdf_pages": (40,), "rows_per_page": (18,)},
}
GLANTZ_ROW_COLUMNS = (*ROW_COLUMNS, "exhibit", "reported_marker", "marker_source_line", "marker_raw_line_sha256")
GLANTZ_SCOPE = (
    "Every published transaction of all six Glantz Exhibits B-1 through B-6: "
    "379 observations, 1992-11-19 through 2008-10-30. Trustee computations in a "
    "complaint, not a complete BLMIS general ledger or a court finding. Credited "
    "principal remains a named source input. All displayed amounts, source "
    "discrepancies, zero-principal observations and footnote markers are retained. "
    "Double-entry counterparts are explicit analysis accounts. One named same-day "
    "computation-order interpretation does not assert original transaction times "
    "or an identified canceled check. No source discrepancy is balanced away."
)
GLANTZ_NOTE_MEANINGS = {
    "1T0026": {
        "[1]": "Only the principal remaining in the originating account is credited; reported fictitious profits are excluded.",
        "[2]": "The reported inward transfer contributes no principal; the principal balance is unchanged.",
    },
    "1ZA192": {
        "[1]": "Only the principal remaining in the originating account is credited; reported fictitious profits are excluded.",
        "[2]": "The reported inward transfer contributes no principal; the principal balance is unchanged.",
    },
    "1ZB010": {},
    "1ZB143": {"[1]": "The reported outward transfer removes no principal; the principal balance is unchanged."},
    "1ZR010": {},
    "1ZR176": {"*": "The note identifies the recipient and intermediary of the 2008-01-03 withdrawal; it does not change credited principal."},
}
GLANTZ_REORDER = {
    "rule": "same_day_display_reorder", "interpretation": "interpretive", "account": "1ZB010",
    "date": "2006-10-17",
    "display_row_ids": ["SRC-BLM-001:1ZB010:p35:l38", "SRC-BLM-001:1ZB010:p35:l39"],
    "computation_row_ids": ["SRC-BLM-001:1ZB010:p35:l39", "SRC-BLM-001:1ZB010:p35:l38"],
    "reason": "Compute the published STOP PAYMENT before the same-day CHECK to reproduce their printed balances; retain source display order and amounts unchanged. No source transaction time or canceled-check identity is inferred.",
}
GLANTZ_PAIR_LOCATIONS = (
    ("1993-10-20", "1ZA192", "SRC-BLM-001:1ZA192:p31:l21", "1ZB143", "SRC-BLM-001:1ZB143:p36:l16"),
    ("2005-12-23", "1ZB143", "SRC-BLM-001:1ZB143:p37:l23", "1ZA192", "SRC-BLM-001:1ZA192:p32:l43"),
)

GLANTZ_FOOTER_LITERALS = {
    "1T0026": ("18,208,000", "(27,966,431)", "2,596,266", "(212,000)", "(7,374,165)", "(6,750,000)"),
    "1ZA192": ("10,439,983", "(16,924,380)", "537,366", "(4,000,000)", "(9,947,031)", "(7,700,000)"),
    "1ZB010": ("1,220,000", "(1,527,500)", "-", "(200,000)", "(507,500)", "(385,000)"),
    "1ZB143": ("1,178,532", "(22,088,220)", "4,000,000", "(45,000)", "(16,954,688)", "(11,500,000)"),
    "1ZR010": ("5,979,184", "(9,307,173)", "-", "-", "(3,327,989)", "(3,327,989)"),
    "1ZR176": ("2,050,014", "(4,867,979)", "-", "-", "(2,817,965)", "(765,000)"),
}
# (account, PDF page, dated line, printed marker, marker extraction line).
# The source places six superscripts above their transaction in -layout output.
GLANTZ_MARKER_LOCATIONS = (
    ("1T0026", 27, 25, "[1]", 24), ("1T0026", 27, 27, "[2]", 26),
    ("1T0026", 27, 29, "[1]", 28), ("1T0026", 27, 30, "[1]", 30),
    ("1T0026", 27, 35, "[2]", 34), ("1T0026", 27, 37, "[2]", 36),
    ("1T0026", 27, 40, "[2]", 39), ("1T0026", 27, 41, "[2]", 41),
    ("1ZA192", 31, 28, "[1]", 28), ("1ZA192", 32, 43, "[2]", 43),
    ("1ZB143", 37, 23, "[1]", 23), ("1ZR176", 40, 32, "*", 32),
)
GLANTZ_TRANSFER_LOCATIONS = (
    ("1T0026", 27, 25), ("1T0026", 27, 27), ("1T0026", 27, 29), ("1T0026", 27, 30),
    ("1T0026", 27, 35), ("1T0026", 27, 37), ("1T0026", 27, 40), ("1T0026", 27, 41),
    ("1T0026", 28, 24), ("1T0026", 28, 25), ("1ZA192", 31, 21), ("1ZA192", 31, 28),
    ("1ZA192", 32, 43), ("1ZB010", 34, 34), ("1ZB143", 36, 16), ("1ZB143", 36, 18),
    ("1ZB143", 37, 23),
)
GLANTZ_ZERO_LOCATIONS = (
    ("1T0026", 27, 27), ("1T0026", 27, 35), ("1T0026", 27, 37), ("1T0026", 27, 40),
    ("1T0026", 27, 41), ("1ZA192", 32, 43), ("1ZB143", 37, 23),
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


def extract_pdf(path: Path, *, layout_out: Path | None = None) -> tuple[bytes, bytes]:
    verify_pdf(path)
    try:
        result = subprocess.run(["pdftotext", "-layout", "-f", "31", "-l", "33", str(path), "-"],
                                capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentError(
            f"pdftotext extraction unavailable: {exc}; install Poppler's pdftotext "
            "(poppler-utils on Linux or poppler on macOS), put it on PATH and rerun. "
            "The native replay cannot substitute retained rows for PDF extraction."
        ) from exc
    require(result.returncode == 0, "pdftotext could not extract the pinned document")
    if layout_out is not None:
        # Keep the actual extractor output even when a later layout or pin
        # comparison refuses it. It is evidence for diagnosing the refusal,
        # never permission to accept changed rows or regenerate source pins.
        with layout_out.open("xb") as stream:
            stream.write(result.stdout)
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


def package_payloads(directory: Path) -> tuple[dict, dict[str, bytes]]:
    """Normalize only the explicitly supplied, authenticated source rows."""
    rows, metadata = load_fixture(directory)
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
    return manifest, payloads


def prepare(output: Path, directory: Path = FIXTURE_DIR) -> dict:
    """Prepare retained factual rows offline; this does not extract a PDF."""
    require(not output.exists(), "package destination already exists")
    manifest, payloads = package_payloads(directory)
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    return manifest


def prepare_pdf(output: Path, pdf: Path | None = None, *,
                on_created: Callable[[], None] | None = None) -> dict:
    """Acquire, extract and normalize the original PDF in this invocation.

    The reviewed fixture pins are acceptance controls only. The bytes fed to
    normalization come from this PDF extraction, with no retained-row fallback.
    No accounting book is opened here, including on an extraction refusal.
    """
    require(not output.exists(), "package destination already exists")
    supplied = verify_pdf(pdf) if pdf is not None else None
    output.mkdir(parents=True, exist_ok=False)
    # Notify only after this invocation has exclusively created the directory.
    # A caller may retain failure diagnostics there, but must not infer that
    # ownership from an earlier existence check when another run can race it.
    if on_created is not None:
        on_created()
    original = output / "source.pdf"
    if supplied is None:
        fetch(original)
    else:
        with original.open("xb") as stream:
            stream.write(supplied)
    extracted = output / "extracted-source"
    extracted.mkdir()
    layout = extracted / "layout.txt"
    raw, metadata = extract_pdf(original, layout_out=layout)
    for name, content in (("rows.csv", raw), ("source.json", metadata)):
        with (extracted / name).open("xb") as stream:
            stream.write(content)
    # Loading this directory rechecks the reviewed source pins and every
    # printed balance before creating any normalized accounting input.
    manifest, payloads = package_payloads(extracted)
    retained = {}
    for path in (original, layout, extracted / "rows.csv", extracted / "source.json"):
        content = path.read_bytes()
        retained[path.relative_to(output).as_posix()] = {
            "bytes": len(content), "sha256": digest(content),
        }
    extraction = {
        "format": "fa-blmis-pdf-extraction-v1",
        "mode": "original_pdf_extracted_this_run",
        "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
        "command": ["pdftotext", "-layout", "-f", "31", "-l", "33", str(original), "-"],
        "pdf_pages": list(PDF_PAGES), "source_rows": manifest["source_rows"],
        "reviewed_rows_sha256": ROWS_SHA256, "reviewed_metadata_sha256": METADATA_SHA256,
        "retained": retained,
    }
    manifest["source_extraction"] = extraction
    payloads["extraction.json"] = json_bytes(extraction)
    manifest["outputs"].update(retained)
    manifest["outputs"]["extraction.json"] = {
        "bytes": len(payloads["extraction.json"]), "sha256": digest(payloads["extraction.json"]),
    }
    payloads["manifest.json"] = json_bytes(manifest)
    for name, content in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(content)
    return manifest



def glantz_row_values(raw: dict) -> dict:
    """Decode one original row, including markers detached by PDF extraction."""
    require(set(raw) == set(GLANTZ_ROW_COLUMNS), "Glantz source row has unexpected fields")
    row = dict(raw)
    account = row["account"]
    require(account in GLANTZ_ACCOUNTS, "unexpected Glantz source account")
    spec = GLANTZ_ACCOUNTS[account]
    require(row["exhibit"] == spec["exhibit"], "row exhibit differs from source account")
    for field in ("pdf_page", "exhibit_page", "page_row", "source_line"):
        require(re.fullmatch(r"[1-9][0-9]*", str(row[field])) is not None,
                f"invalid provenance field {field}")
        row[field] = int(row[field])
    require(row["pdf_page"] in spec["pdf_pages"] and row["exhibit_page"] == row["pdf_page"] - 26,
            "row lies outside its declared exhibit pages")
    require(row["row_id"] == f"{SOURCE_ID}:{account}:p{row['pdf_page']}:l{row['source_line']}",
            "row identifier differs from its source location")
    require(re.fullmatch(r"[0-9a-f]{64}", row["raw_line_sha256"]) is not None,
            "invalid source-line hash")
    row["date"] = iso_date(row["date_literal"])
    description = row["description"]
    require(description in ("CHECK", "CHECK WIRE", "STOP PAYMENT") or
            re.fullmatch(r"TRANS (?:TO|FROM) [A-Z0-9]+ \([A-Z0-9]+\)", description) is not None,
            "unrecognized Glantz transaction description")
    marker = row["reported_marker"]
    require(marker == "" or marker in GLANTZ_NOTE_MEANINGS[account],
            "unrecognized account-scoped reported-amount marker")
    inline = re.fullmatch(r"(.+) (\[[12]\]|\*)", row["reported_literal"])
    if inline:
        require(marker == inline[2], "reported amount and marker attribution differ")
        reported_number = inline[1]
    else:
        reported_number = row["reported_literal"]
    if marker:
        require(re.fullmatch(r"[1-9][0-9]*", str(row["marker_source_line"])) is not None,
                "missing marker source line")
        row["marker_source_line"] = int(row["marker_source_line"])
        require(row["marker_source_line"] == row["source_line"] - (0 if inline else 1),
                "marker is not on its row or the immediately preceding extraction line")
        require(re.fullmatch(r"[0-9a-f]{64}", row["marker_raw_line_sha256"]) is not None,
                "invalid marker-line hash")
        if inline:
            require(row["marker_raw_line_sha256"] == row["raw_line_sha256"],
                    "inline marker hash differs from its source row")
        else:
            require(account == "1T0026" and row["pdf_page"] == 27 and marker in ("[1]", "[2]"),
                    "undeclared detached-marker layout")
    else:
        require(row["marker_source_line"] == "" and row["marker_raw_line_sha256"] == "",
                "marker provenance exists without a marker")
        row["marker_source_line"] = None
    for field in VALUE_FIELDS:
        literal = reported_number if field == "reported" else row[f"{field}_literal"]
        row[f"{field}_cents"], _ = amount_cents(literal)
    row["footnotes"] = [int(marker[1])] if marker in ("[1]", "[2]") else []
    row["cash_movement_cents"] = row["deposits_cents"] + row["withdrawals_cents"]
    row["transfer_movement_cents"] = row["transfers_in_cents"] + row["transfers_out_cents"]
    row["principal_movement_cents"] = row["cash_movement_cents"] + row["transfer_movement_cents"]
    require(all(abs(row[f"{field}_cents"]) <= I128_MAX for field in VALUE_FIELDS)
            and abs(row["principal_movement_cents"]) <= I128_MAX, "source movement exceeds i128")
    require(row["deposits_cents"] >= 0 and row["transfers_in_cents"] >= 0
            and row["transfers_out_cents"] <= 0, "unexpected principal-column sign")
    is_transfer = description.startswith("TRANS ")
    row["transfer_credit_role"] = "oracle_output" if is_transfer else "not_applicable"
    row["transfer_pair_id"] = next(
        (f"{day}:{origin}:{destination}" for day, origin, outgoing, destination, incoming in GLANTZ_PAIR_LOCATIONS
         if row["row_id"] in (outgoing, incoming)), None)
    if is_transfer:
        require(row["deposits_cents"] == row["withdrawals_cents"] == 0,
                "transfer row unexpectedly contains cash")
        incoming = description.startswith("TRANS FROM ")
        require((row["reported_cents"] > 0 if incoming else row["reported_cents"] < 0)
                and (row["transfers_out_cents"] == 0 if incoming else row["transfers_in_cents"] == 0),
                "transfer direction disagrees with source columns")
        require(row["reported_cents"] == row["transfer_movement_cents"] or bool(marker),
                "different reported and credited transfer lacks its source marker")
        require(marker != "*", "recipient note cannot stand for a principal-credit rule")
    else:
        require(row["transfers_in_cents"] == row["transfers_out_cents"] == 0,
                "cash row unexpectedly contains transfer principal")
        require(row["cash_movement_cents"] == row["reported_cents"],
                "cash amount differs from reported amount")
        require(marker in ("", "*"), "cash row has a transfer-credit footnote")
        if description == "STOP PAYMENT":
            require(row["deposits_cents"] == 0 and row["withdrawals_cents"] > 0 and not marker,
                    "STOP PAYMENT must retain its positive withdrawal-column amount")
        else:
            require(row["withdrawals_cents"] <= 0 and
                    not (row["deposits_cents"] and row["withdrawals_cents"]),
                    "unexpected signed cash columns")
    return row


def parse_glantz_layout(text: str) -> tuple[list[dict], dict]:
    """Parse all fourteen declared Exhibit B pages; arithmetic stays diagnostic.

    The only detached-marker layout is the six superscripts on PDF page 27.
    A marker is bound to the immediately following dated row and its own exact
    extraction line. Generated row records omit holder headings and note prose;
    the local acquisition package separately retains the complete PDF/layout.
    """
    require(len(text.encode()) <= 300_000, "unexpectedly large Glantz extraction")
    pages = text.split("\f")
    require(len(pages) == 15 and not pages[-1].strip(), "expected fourteen Exhibit B PDF pages")
    rows, accounts, page_hashes = [], {}, {}
    for account, spec in GLANTZ_ACCOUNTS.items():
        account_rows, footer, notes = [], None, {}
        for page_index, (pdf_page, expected_count) in enumerate(zip(
                spec["pdf_pages"], spec["rows_per_page"], strict=True)):
            page = pages[pdf_page - 27]
            lines = page.splitlines()
            page_hashes[str(pdf_page)] = digest(page.encode())
            require(f"BLMIS ACCOUNT NO. {account} -" in page, f"wrong account on PDF page {pdf_page}")
            require(f"Exhibit {spec['exhibit']}" in page and f"Pg {pdf_page - 26} of 14" in page,
                    f"wrong exhibit on PDF page {pdf_page}")
            require(f"Page {page_index + 1} of {len(spec['pdf_pages'])} - {account}" in page,
                    f"incomplete-account page marker on PDF page {pdf_page}")
            require("Filed 01/22/18" in page, "source filing vintage changed")
            column_rows = [line for line in lines if "Column 1" in line]
            require(len(column_rows) == 1 and
                    re.findall(r"Column ([0-9]+)", column_rows[0]) == list("123456789"),
                    f"unexpected nine-column declaration on PDF page {pdf_page}")
            headers = [line for line in lines if "Customer Statement" in line and "Fictitious Profits" in line]
            require(len(headers) == 1 and all(label in headers[0] for label in (
                "Date", "Description", "Deposits", "Withdrawals", "Principal In", "Principal Out")),
                f"unexpected source column headers on PDF page {pdf_page}")
            count, pending_marker = 0, None
            for number, line in enumerate(lines, 1):
                is_row = re.match(r"^\s*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}\s", line)
                if is_row:
                    cells = re.split(r"\s{2,}", line.strip())
                    require(len(cells) == 9, f"expected nine cells at PDF page {pdf_page} line {number}")
                    count += 1
                    inline = re.fullmatch(r".+ (\[[12]\]|\*)", cells[2])
                    require(not (inline and pending_marker), "duplicate inline and detached marker")
                    marker = inline[1] if inline else (pending_marker[0] if pending_marker else "")
                    marker_line = number if inline else (pending_marker[1] if pending_marker else "")
                    marker_hash = digest(line.encode()) if inline else (pending_marker[2] if pending_marker else "")
                    row = {
                        "row_id": f"{SOURCE_ID}:{account}:p{pdf_page}:l{number}",
                        "account": account, "pdf_page": str(pdf_page), "exhibit_page": str(pdf_page - 26),
                        "page_row": str(count), "source_line": str(number), "date_literal": cells[0],
                        "description": cells[1], "raw_line_sha256": digest(line.encode()),
                        "exhibit": spec["exhibit"], "reported_marker": marker,
                        "marker_source_line": str(marker_line), "marker_raw_line_sha256": marker_hash,
                    }
                    row.update({f"{field}_literal": cell for field, cell in zip(VALUE_FIELDS, cells[2:], strict=True)})
                    glantz_row_values(row)
                    account_rows.append(row)
                    pending_marker = None
                elif "Total:" in line:
                    require(footer is None and page_index == len(spec["pdf_pages"]) - 1,
                            f"unexpected or duplicate printed footer for {account}")
                    cells = [part.strip() for part in line.split("Total:", 1)[1].split("$")]
                    require(cells[0] == "" and len(cells) == 7, "expected six printed footer amounts")
                    footer = {"pdf_page": pdf_page, "source_line": number, "raw_line_sha256": digest(line.encode()),
                              "cells": dict(zip(FOOTER_FIELDS, cells[1:], strict=True))}
                    for cell in cells[1:]:
                        amount_cents(cell)
                elif re.fullmatch(r"\s*\[[12]\]\s*", line):
                    marker = line.strip()
                    next_is_row = number < len(lines) and re.match(
                        r"^\s*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}\s", lines[number])
                    if next_is_row:
                        require(pdf_page == 27 and pending_marker is None,
                                "undeclared or ambiguous detached-marker location")
                        pending_marker = (marker, number, digest(line.encode()))
                    else:
                        require(footer is not None and marker not in notes, "duplicate or misplaced footnote body")
                        collected = []
                        for following in lines[number:]:
                            if not following.strip() or re.fullmatch(r"\s*\[[12]\]\s*", following):
                                break
                            collected.append(following.strip())
                        require(bool(collected), "empty source footnote")
                        normalized = " ".join(" ".join(collected).split())
                        notes[marker] = {"pdf_page": pdf_page, "source_line": number,
                                         "normalized_text_sha256": digest(normalized.encode())}
                elif line.lstrip().startswith("* "):
                    require(footer is not None and "*" not in notes, "duplicate or misplaced asterisk note")
                    normalized = " ".join(line.strip()[2:].split())
                    require(bool(normalized), "empty asterisk note")
                    notes["*"] = {"pdf_page": pdf_page, "source_line": number,
                                  "normalized_text_sha256": digest(normalized.encode())}
                elif pending_marker is not None:
                    raise SourceError("detached marker is not immediately followed by its dated source row")
            require(pending_marker is None, "unconsumed detached marker")
            require(count == expected_count,
                    f"incomplete account {account}: PDF page {pdf_page} has {count} dated rows, expected {expected_count}")
        require(footer is not None and set(notes) == set(GLANTZ_NOTE_MEANINGS[account]),
                f"missing or unexpected account-scoped footnotes for {account}")
        decoded = [glantz_row_values(row) for row in account_rows]
        require([row["date"] for row in decoded] == sorted(row["date"] for row in decoded),
                f"source dates are not in printed chronological order for {account}")
        accounts[account] = {
            "account": account, "exhibit": spec["exhibit"], "pdf_pages": list(spec["pdf_pages"]),
            "exhibit_pages": [page - 26 for page in spec["pdf_pages"]],
            "rows_per_page": list(spec["rows_per_page"]), "row_count": len(account_rows),
            "footer": footer, "footnotes": notes, "footnote_meaning": dict(GLANTZ_NOTE_MEANINGS[account]),
        }
        rows.extend(account_rows)
    metadata = {
        "schema_version": 1, "source_id": SOURCE_ID, "source_url": SOURCE_URL,
        "source_sha256": SOURCE_SHA256, "source_bytes": SOURCE_BYTES, "filed_on": "2018-01-22",
        "accounts": accounts, "row_count": len(rows), "headers": list(HEADERS),
        "printed_amount_unit": "USD whole dollars", "scope": GLANTZ_SCOPE,
        "assertion_status": "trustee_computation in a complaint; not a court finding",
        "redistribution_basis": "The factual rows.csv and source.json omit account-holder headings and original footnote prose. The local acquisition package separately retains the complete public original PDF and actual extracted layout, including its original headings and notes.",
        "dash_interpretation": "A printed dash is no movement in that source column; blank cells are refused.",
        "marker_policy": "Inline markers remain in reported_literal. Detached superscripts retain their own source line and hash. Marker meaning is account-scoped; an asterisk identifies a recipient, not a principal-credit adjustment.",
        "row_id_basis": "Derived citation identifier: source id, trustee account id, PDF page and extracted line; not an original BLMIS transaction id.",
        "extraction": {"command": "pdftotext -layout -f 27 -l 40 <pinned.pdf> -",
                       "reviewed_anchor_version": "pdftotext version 24.02.0 (existing B-2 fixture)",
                       "utf8_sha256": digest(text.encode()), "page_utf8_sha256": page_hashes,
                       "line_hash_basis": "SHA-256 of the exact UTF-8 extracted line without its newline"},
        "same_day_display_reorder": GLANTZ_REORDER,
        "planning_census_discrepancy": {"prior_estimate_rows": 1429, "observed_rows": len(rows),
                                      "basis": "All six complete account page sequences, PDF pages 27 through 40, contain 379 dated rows."},
    }
    return rows, metadata


def glantz_computation_order(rows: list[dict]) -> list[dict]:
    """Apply one reviewed same-day interpretation, never search for a fit."""
    ordered = list(rows)
    ids = [row["row_id"] for row in rows]
    require(len(ids) == len(set(ids)), "duplicate Glantz source row identifier")
    check_id, stop_id = GLANTZ_REORDER["display_row_ids"]
    if check_id not in ids and stop_id not in ids:
        return ordered
    require(check_id in ids and stop_id in ids, "named same-day pair is incomplete")
    check_index, stop_index = ids.index(check_id), ids.index(stop_id)
    require(stop_index == check_index + 1, "named same-day pair is not in source display order")
    check, stop = rows[check_index], rows[stop_index]
    require(check["account"] == stop["account"] == "1ZB010"
            and check["date"] == stop["date"] == "2006-10-17"
            and check["description"] == "CHECK" and stop["description"] == "STOP PAYMENT"
            and check["principal_movement_cents"] == -2_500_000
            and stop["principal_movement_cents"] == 2_500_000,
            "named same-day pair differs from reviewed source movements")
    ordered[check_index], ordered[stop_index] = stop, check
    return ordered


def glantz_transfer_pairs(rows: list[dict]) -> list[dict]:
    """Evaluate only the two explicitly reviewed cross-account source pairs.

    Matching is by published account references and reviewed source locations,
    not amount/date similarity. The 13 other TRANS rows remain named inputs.
    This interpretive rule is not the native posted-principal-transfer rule.
    """
    by_id = {row["row_id"]: row for row in rows}
    require(len(by_id) == len(rows), "duplicate source row in transfer comparison")
    pairs = []
    for day, origin, outgoing_id, destination, incoming_id in GLANTZ_PAIR_LOCATIONS:
        require(outgoing_id in by_id and incoming_id in by_id, "reviewed cross-account pair is incomplete")
        outgoing, incoming = by_id[outgoing_id], by_id[incoming_id]
        require(outgoing["account"] == origin and incoming["account"] == destination
                and outgoing["date"] == incoming["date"] == day,
                "reviewed transfer account/date differs")
        require(outgoing["description"].startswith("TRANS TO ")
                and outgoing["description"].endswith(f"({destination})")
                and incoming["description"].startswith("TRANS FROM ")
                and incoming["description"].endswith(f"({origin})"),
                "reviewed transfer counterpart references differ")
        require(outgoing["reported_cents"] == -incoming["reported_cents"]
                and incoming["reported_cents"] > 0, "paired reported statement amounts differ")
        origin_rows = [row for row in rows if row["account"] == origin]
        position = next(i for i, row in enumerate(origin_rows) if row["row_id"] == outgoing_id)
        require(position > 0, "reviewed transfer has no preceding published origin balance")
        prior = origin_rows[position - 1]
        credited = min(incoming["reported_cents"], max(0, prior["printed_balance_cents"]))
        pairs.append({
            "pair_id": f"{day}:{origin}:{destination}", "date": day,
            "origin_account": origin, "destination_account": destination,
            "origin_row_id": outgoing_id, "destination_row_id": incoming_id,
            "origin_preceding_row_id": prior["row_id"],
            "statement_amount_cents": incoming["reported_cents"],
            "origin_printed_principal_before_cents": prior["printed_balance_cents"],
            "rule": "trustee_transfer_credit",
            "interpretation": "min(statement amount, max(0, preceding printed origin principal)); tested on these two source pairs only",
            "recomputed_credit_cents": credited,
            "origin_credited_out_cents": -outgoing["transfer_movement_cents"],
            "destination_credited_in_cents": incoming["transfer_movement_cents"],
            "agrees_with_both_printed_credits":
                credited == -outgoing["transfer_movement_cents"] == incoming["transfer_movement_cents"],
        })
    return pairs


def _glantz_order_diagnostics(rows: list[dict], metadata: dict) -> dict:
    report = diagnostics(rows, metadata)
    previous, local = 0, []
    for row in rows:
        gap = row["printed_balance_cents"] - previous - row["principal_movement_cents"]
        if gap:
            local.append({"row_id": row["row_id"], "gap_cents": gap})
        previous = row["printed_balance_cents"]
    report["local_row_differences"] = local
    report["local_gap_basis"] = "current printed balance minus previous printed balance minus source movement"
    report["maximum_local_gap_cents"] = max((abs(row["gap_cents"]) for row in local), default=0)
    report["source_fold_closing_balance_cents"] = sum(row["principal_movement_cents"] for row in rows)
    return report


def glantz_diagnostics(rows: list[dict], metadata: dict) -> dict:
    """Report every printed disagreement; this function does not repair source."""
    require({row["account"] for row in rows} == set(GLANTZ_ACCOUNTS),
            "diagnostics require all six Glantz accounts")
    ordered = glantz_computation_order(rows)
    accounts = {}
    for account in GLANTZ_ACCOUNTS:
        displayed = [row for row in rows if row["account"] == account]
        computed = [row for row in ordered if row["account"] == account]
        raw_report = _glantz_order_diagnostics(displayed, metadata["accounts"][account])
        computed_report = _glantz_order_diagnostics(computed, metadata["accounts"][account])
        exact = computed_report["rows_off"] == 0 and not computed_report["footer_gaps_cents"]
        accounts[account] = {
            "classification": ("exact" if raw_report["rows_off"] == 0 else "exact_under_named_same_day_order")
                if exact else "printed_source_discrepancy",
            "display_order": raw_report, "computation_order": computed_report,
            "cash_in_cents": sum(max(0, row["cash_movement_cents"]) for row in displayed),
            "cash_out_cents": sum(max(0, -row["cash_movement_cents"]) for row in displayed),
            "transfer_in_cents": sum(max(0, row["transfer_movement_cents"]) for row in displayed),
            "transfer_out_cents": sum(max(0, -row["transfer_movement_cents"]) for row in displayed),
            "movement_column_totals_cents": {
                field: sum(row[f"{field}_cents"] for row in displayed)
                for field in ("deposits", "withdrawals", "transfers_in", "transfers_out", "two_year")
            },
        }
    transfers = [row for row in rows if row["description"].startswith("TRANS ")]
    paired = {row_id for _, _, outgoing, _, incoming in GLANTZ_PAIR_LOCATIONS for row_id in (outgoing, incoming)}
    return {
        "source_rows": len(rows), "monetary_rows": sum(row["principal_movement_cents"] != 0 for row in rows),
        "accounts": accounts, "same_day_display_reorder": GLANTZ_REORDER,
        "transfer_rows": len(transfers),
        "transfer_pairs": glantz_transfer_pairs(rows),
        "unpaired_transfer_rows": [
            {"row_id": row["row_id"], "account": row["account"], "description": row["description"],
             "reported_cents": row["reported_cents"], "credited_principal_cents": row["transfer_movement_cents"],
             "reported_marker": row["reported_marker"], "role": "oracle_output",
             "reason": "The counterparty account history is not published in this Exhibit B."}
            for row in transfers if row["row_id"] not in paired
        ],
        "zero_principal_rows": [row["row_id"] for row in rows if not row["principal_movement_cents"]],
        "detached_marker_rows": [row["row_id"] for row in rows if row["reported_marker"]
                                 and row["marker_source_line"] != row["source_line"]],
        "gap_convention": "cumulative source fold minus printed balance; local gaps use printed delta minus source movement",
        "precision_limit": "Whole-dollar published cells; the cause of source differences is not established. No cent-level source precision is inferred.",
    }


def verify_glantz_rows(rows: list[dict], metadata: dict) -> dict:
    """Require the reviewed source population and exact discrepancy signature.

    This accepts the pinned published disagreements. It does not accept an
    arbitrary tolerance band, normalize them away or declare all accounts exact.
    """
    require(len(rows) == 379 and len({row["row_id"] for row in rows}) == 379,
            "complete Glantz exhibit must contain 379 distinct rows")
    require([(row["pdf_page"], row["source_line"]) for row in rows] ==
            sorted((row["pdf_page"], row["source_line"]) for row in rows),
            "Glantz source display order changed")
    require(metadata["source_sha256"] == SOURCE_SHA256 and metadata["source_bytes"] == SOURCE_BYTES
            and metadata["row_count"] == 379 and set(metadata["accounts"]) == set(GLANTZ_ACCOUNTS),
            "Glantz metadata binds another source population")
    for account, spec in GLANTZ_ACCOUNTS.items():
        account_rows = [row for row in rows if row["account"] == account]
        require([row["date"] for row in account_rows] == sorted(row["date"] for row in account_rows),
                "account source date order changed")
        for page, count in zip(spec["pdf_pages"], spec["rows_per_page"], strict=True):
            selected = [row for row in account_rows if row["pdf_page"] == page]
            require(len(selected) == count and [row["page_row"] for row in selected] == list(range(1, count + 1)),
                    f"complete account/page population differs for {account} page {page}")
    for account in GLANTZ_ACCOUNTS:
        require(tuple(metadata["accounts"][account]["footer"]["cells"][field] for field in FOOTER_FIELDS)
                == GLANTZ_FOOTER_LITERALS[account], f"{account}: printed footer literals differ from original")
    observed_markers = [(row["account"], row["pdf_page"], row["source_line"],
                         row["reported_marker"], row["marker_source_line"])
                        for row in rows if row["reported_marker"]]
    require(observed_markers == list(GLANTZ_MARKER_LOCATIONS),
            "source footnote-marker locations differ from the reviewed exhibit")
    observed_transfers = [(row["account"], row["pdf_page"], row["source_line"])
                          for row in rows if row["description"].startswith("TRANS ")]
    require(observed_transfers == list(GLANTZ_TRANSFER_LOCATIONS)
            and all(row["transfer_credit_role"] == "oracle_output" for row in rows
                    if row["description"].startswith("TRANS ")),
            "credited transfer source rows or oracle-input flags differ")
    observed_zero = [(row["account"], row["pdf_page"], row["source_line"])
                     for row in rows if not row["principal_movement_cents"]]
    require(observed_zero == list(GLANTZ_ZERO_LOCATIONS), "zero-principal observation locations differ")
    report = glantz_diagnostics(rows, metadata)
    expected_local = {
        "1ZR010": [(38, 23, -100), (38, 36, -100), (38, 41, -100), (38, 44, -100),
                   (38, 47, -100), (39, 22, -100), (39, 26, -100), (39, 29, -100), (39, 33, -100)],
        "1ZR176": [(40, 21, 100), (40, 33, -100)],
    }
    for account in GLANTZ_ACCOUNTS:
        actual = report["accounts"][account]["computation_order"]
        expected = [{"row_id": f"{SOURCE_ID}:{account}:p{page}:l{line}", "gap_cents": gap}
                    for page, line, gap in expected_local.get(account, [])]
        require(actual["local_row_differences"] == expected,
                f"{account}: printed row discrepancies differ from the reviewed source")
        expected_footer = {"deposits": 900, "printed_balance": 900} if account == "1ZR010" else {}
        require(actual["footer_gaps_cents"] == expected_footer,
                f"{account}: printed footer discrepancies differ from the reviewed source")
    display = report["accounts"]["1ZB010"]["display_order"]
    require(display["row_differences"] == [
        {"row_id": row_id, "gap_cents": -2_500_000} for row_id in GLANTZ_REORDER["display_row_ids"]
    ], "same-day display discrepancy differs from reviewed source")
    require(report["monetary_rows"] == 372 and len(report["zero_principal_rows"]) == 7
            and report["transfer_rows"] == 17 and len(report["unpaired_transfer_rows"]) == 13
            and len(report["detached_marker_rows"]) == 6, "Glantz source/transfer population differs")
    require(all(pair["agrees_with_both_printed_credits"] for pair in report["transfer_pairs"]),
            "reviewed source transfer pair does not reproduce")
    return report


def _decode_glantz_bytes(raw: bytes, meta: bytes) -> tuple[list[dict], dict]:
    require(len(raw) <= 300_000 and len(meta) <= 300_000, "oversized Glantz source extraction")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
    require(reader.fieldnames == list(GLANTZ_ROW_COLUMNS), "Glantz source CSV header differs")
    rows = [glantz_row_values(row) for row in reader]
    metadata = json.loads(meta)
    verify_glantz_rows(rows, metadata)
    return rows, metadata


def _extract_glantz_pdf(path: Path, *, layout_out: Path | None = None) -> tuple[bytes, bytes, bytes]:
    """Extract only verified PDF bytes; never trust a generated checksum sidecar.

    New line hashes describe this extraction. They are not represented as an
    unavailable pre-existing fixture pin. The already-reviewed B-2 bytes anchor
    the extractor, in addition to the complete original PDF's size and SHA-256.
    """
    original = verify_pdf(path)
    try:
        result = subprocess.run(["pdftotext", "-layout", "-f", "27", "-l", "40", "-", "-"],
                                input=original, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentError(
            f"pdftotext extraction unavailable: {exc}; install Poppler's pdftotext "
            "(poppler-utils on Linux or poppler on macOS), put it on PATH and rerun. "
            "Complete Glantz preparation cannot substitute retained rows for PDF extraction."
        ) from exc
    require(result.returncode == 0, "pdftotext could not extract the pinned document")
    require(len(result.stdout) <= 300_000, "oversized Glantz extraction")
    if layout_out is not None:
        # Retain actual extractor output even if later source validation refuses.
        with layout_out.open("xb") as stream:
            stream.write(result.stdout)
    text = result.stdout.decode("utf-8", errors="strict")
    rows, metadata = parse_glantz_layout(text)
    anchor_text = "\f".join(text.split("\f")[4:7]) + "\f"
    anchor_rows, anchor_metadata = parse_layout(anchor_text)
    anchor_raw = csv_bytes(ROW_COLUMNS, anchor_rows)
    require(digest(anchor_raw) == ROWS_SHA256 and digest(json_bytes(anchor_metadata)) == METADATA_SHA256,
            "existing B-2 source anchor changed; review extractor/source drift, never refresh its pins automatically")
    projected_anchor = [{key: row[key] for key in ROW_COLUMNS} for row in rows if row["account"] == ACCOUNT]
    require(csv_bytes(ROW_COLUMNS, projected_anchor) == anchor_raw,
            "complete-exhibit parser disagrees with the independently pinned B-2 parser")
    verify_glantz_rows([glantz_row_values(row) for row in rows], metadata)
    return csv_bytes(GLANTZ_ROW_COLUMNS, rows), json_bytes(metadata), result.stdout


def extract_glantz_pdf(path: Path, *, layout_out: Path | None = None) -> tuple[bytes, bytes]:
    raw, meta, _ = _extract_glantz_pdf(path, layout_out=layout_out)
    return raw, meta


def _glantz_payloads(raw: bytes, meta: bytes, original: bytes, layout: bytes) -> tuple[dict[str, bytes], dict]:
    """Deterministic package construction, also used to verify stored outputs."""
    require(len(original) == SOURCE_BYTES and digest(original) == SOURCE_SHA256,
            "normalization requires the pinned original PDF")
    rows, metadata = _decode_glantz_bytes(raw, meta)
    require(digest(layout) == metadata["extraction"]["utf8_sha256"], "raw layout differs from extracted metadata")
    ordered = glantz_computation_order(rows)
    normalized, mapping, zero_rows = [], [], []
    principal_accounts = {account: f"BLMIS-{account}" for account in GLANTZ_ACCOUNTS}
    for row in ordered:
        movement = row["principal_movement_cents"]
        if not movement:
            zero_rows.append(row["row_id"])
            continue
        for account, amount in (
            (principal_accounts[row["account"]], -movement),
            (CASH_ACCOUNT, row["cash_movement_cents"]),
            (TRANSFER_ACCOUNT, row["transfer_movement_cents"]),
        ):
            if amount:
                normalized.append({
                    "entry_id": row["row_id"], "effective_date": row["date"], "account_code": account,
                    "signed_amount": money(amount), "description": row["description"],
                    "memo": f"analysis counterpart; {SOURCE_ID} Exhibit {row['exhibit']} PDF p{row['pdf_page']} line {row['source_line']}",
                    "source_row": row["row_id"],
                })
        mapping.append({
            "entry_id": row["row_id"], "source_row_id": row["row_id"], "source_account": row["account"],
            "exhibit": row["exhibit"], "transfer_principal_role": row["transfer_credit_role"],
            "transfer_pair_id": row["transfer_pair_id"], "reported_marker": row["reported_marker"],
        })
    controls = {}
    for account in GLANTZ_ACCOUNTS:
        account_rows = [row for row in ordered if row["account"] == account]
        first_year, last_year = int(account_rows[0]["date"][:4]), int(account_rows[-1]["date"][:4])
        annual = []
        for year in range(first_year, last_year + 1):
            control = last_printed_balance(account_rows, f"{year}-12-31")
            source_fold = sum(row["principal_movement_cents"] for row in account_rows if row["date"] <= control["at_date"])
            annual.append({"account": account, **control, "source_fold_cents": source_fold,
                           "source_fold_minus_printed_cents": source_fold - control["printed_balance_cents"]})
        controls[account] = annual
    chart = {"accounts": [
        {"code": code, "name": f"Published principal {account} - analysis account", "type": "Equity", "unit": "USD"}
        for account, code in principal_accounts.items()
    ] + [
        {"code": CASH_ACCOUNT, "name": "Published cash movements - analysis counterpart", "type": "Asset", "unit": "USD"},
        {"code": TRANSFER_ACCOUNT, "name": "Trustee-credited transfers - analysis clearing", "type": "Liability", "unit": "USD"},
    ]}
    source_report = verify_glantz_rows(rows, metadata)
    payloads = {
        "source.pdf": original, "rows.csv": raw, "source.json": meta,
        "extracted-source/layout.txt": layout, "extracted-source/rows.csv": raw, "extracted-source/source.json": meta,
        "legacy.csv": csv_bytes(LEGACY_COLUMNS, normalized),
        "column_map.toml": COLUMN_MAP.replace(SOURCE_SYSTEM, GLANTZ_SOURCE_SYSTEM).encode(),
        "chart.json": json_bytes(chart), "controls.json": json_bytes(controls),
    }
    retained = {name: {"bytes": len(payloads[name]), "sha256": digest(payloads[name])}
                for name in ("source.pdf", "extracted-source/layout.txt", "extracted-source/rows.csv", "extracted-source/source.json")}
    extraction = {
        "format": "fa-blmis-glantz-pdf-extraction-v1", "mode": "original_pdf_extracted_this_run",
        "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
        "command": ["pdftotext", "-layout", "-f", "27", "-l", "40", "-", "-"],
        "stdin": "Verified source.pdf bytes; the extractor cannot race a subsequently changed source path.",
        "pdf_pages": list(range(27, 41)), "source_rows": len(rows),
        "reviewed_b2_rows_sha256": ROWS_SHA256, "reviewed_b2_metadata_sha256": METADATA_SHA256,
        "retained": retained,
    }
    payloads["extraction.json"] = json_bytes(extraction)
    manifest = {
        "schema_version": 1, "source_system": GLANTZ_SOURCE_SYSTEM, "scope": GLANTZ_SCOPE,
        "source_extraction": extraction,
        "source_sha256": SOURCE_SHA256, "source_rows_sha256": digest(raw),
        "source_rows": len(rows), "source_accounts": len(GLANTZ_ACCOUNTS),
        "monetary_rows": len(mapping), "normalized_legs": len(normalized),
        "principal_accounts": principal_accounts, "zero_principal_rows": zero_rows, "row_mapping": mapping,
        "computation_order": [row["row_id"] for row in ordered],
        "posting_order": [row["entry_id"] for row in mapping], "same_day_display_reorder": GLANTZ_REORDER,
        "principal_posting_sign": "negative of trustee principal movement",
        "baseline": "zero before each account's first published transaction; not a whole-firm opening trial balance",
        "controls_basis": "last printed principal at each year end, with separate unadjusted source fold and its explicit discrepancy",
        "source_diagnostics": source_report, "transfer_pairs": source_report["transfer_pairs"],
        "extraction_evidence": "Generated from the size/SHA-256-pinned original PDF, with the existing B-2 rows and metadata pins checked independently. New row hashes are extraction receipts, not a claimed pre-existing full-exhibit fixture pin.",
        "outputs": {name: {"bytes": len(data), "sha256": digest(data)} for name, data in payloads.items()},
    }
    payloads["manifest.json"] = json_bytes(manifest)
    return payloads, manifest


def load_glantz_fixture(directory: Path = GLANTZ_FIXTURE_DIR, pdf: Path | None = None) -> tuple[list[dict], dict]:
    """Re-extract the pinned original and verify every retained generated byte.

    The six-account workload is acquisition-backed. A rows file and its own
    checksum are not independent evidence. Prepared payloads are regenerated
    before comparison; changing a sidecar cannot bless a changed source or leg.
    """
    source_pdf = pdf if pdf is not None else directory / "source.pdf"
    if not source_pdf.is_file() or not all((directory / name).is_file() for name in ("rows.csv", "source.json")):
        raise EnvironmentError(
            "complete Glantz source is not prepared; run python3 -B scripts/blmis_source.py prepare "
            "--account all --output NEW_DIR, then verify --account all --source-dir NEW_DIR")
    original = verify_pdf(source_pdf)
    raw, meta, layout = _extract_glantz_pdf(source_pdf)
    expected = {"rows.csv": raw, "source.json": meta}
    analysis_names = ("legacy.csv", "column_map.toml", "chart.json", "controls.json", "manifest.json")
    if any((directory / name).exists() for name in analysis_names):
        expected, _ = _glantz_payloads(raw, meta, original, layout)
    else:
        if (directory / "source.pdf").exists():
            expected["source.pdf"] = original
        if (directory / "layout.txt").exists():
            expected["layout.txt"] = layout
    for name, data in expected.items():
        path = directory / name
        require(path.is_file() and path.stat().st_size == len(data) and path.read_bytes() == data,
                f"Glantz {name} differs from re-extraction/reconstruction of the pinned original")
    return _decode_glantz_bytes(raw, meta)


def prepare_glantz(output: Path, pdf: Path | None = None, *,
                   on_created: Callable[[], None] | None = None) -> dict:
    """Acquire and normalize this invocation's original PDF, without fallback.

    Verified source and actual extractor output survive later refusals. Ownership
    notification follows the exclusive mkdir, never an earlier existence check.
    """
    require(not output.exists(), "package destination already exists")
    supplied = verify_pdf(pdf) if pdf is not None else None
    output.mkdir(parents=True, exist_ok=False)
    if on_created is not None:
        on_created()
    original_path = output / "source.pdf"
    if supplied is None:
        fetch(original_path)
    else:
        with original_path.open("xb") as stream:
            stream.write(supplied)
    extracted = output / "extracted-source"
    extracted.mkdir()
    layout_path = extracted / "layout.txt"
    raw, meta, layout = _extract_glantz_pdf(original_path, layout_out=layout_path)
    for name, data in (("rows.csv", raw), ("source.json", meta)):
        with (extracted / name).open("xb") as stream:
            stream.write(data)
    original = verify_pdf(original_path)
    payloads, manifest = _glantz_payloads(raw, meta, original, layout)
    retained_names = {"source.pdf", "extracted-source/layout.txt", "extracted-source/rows.csv", "extracted-source/source.json"}
    for name, data in payloads.items():
        target = output / name
        if name in retained_names:
            require(target.read_bytes() == data, f"retained {name} changed during preparation")
            continue
        with target.open("xb") as stream:
            stream.write(data)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("fetch", help="download and verify the original 389,586-byte PDF")
    download.add_argument("--output", type=Path, required=True)
    extract = commands.add_parser("extract", help="extract the pinned original PDF; default B-2 or all six Exhibit B accounts")
    extract.add_argument("--pdf", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify retained B-2 pins, or re-extract and verify a prepared six-account package")
    verify.add_argument("--source-dir", type=Path)
    verify.add_argument("--pdf", type=Path, help="original PDF for --account all; otherwise use the package's source.pdf")
    normalize = commands.add_parser("prepare", help="prepare B-2 retained rows offline; --account all acquires and extracts the original PDF")
    normalize.add_argument("--source-dir", type=Path)
    normalize.add_argument("--pdf", type=Path, help="original PDF for --account all; otherwise download it")
    normalize.add_argument("--output", type=Path, required=True)
    from_pdf = commands.add_parser("prepare-pdf", help="acquire the original PDF, extract and prepare the selected account population")
    from_pdf.add_argument("--pdf", type=Path, help="pinned original PDF; otherwise download from the publisher")
    from_pdf.add_argument("--output", type=Path, required=True)
    for command in (extract, verify, normalize, from_pdf):
        command.add_argument("--account", choices=(ACCOUNT, "all"), default=ACCOUNT,
                             help="1ZA192 preserves the existing complete-account workload; all includes every Glantz Exhibit B row")
    args = parser.parse_args(argv)
    all_accounts = getattr(args, "account", ACCOUNT) == "all"
    try:
        if args.command == "fetch":
            fetch(args.output)
            print(f"PASS source PDF bytes={SOURCE_BYTES} sha256={SOURCE_SHA256}")
        elif args.command == "extract":
            require(not args.output.exists(), "extraction destination already exists")
            if all_accounts:
                original = verify_pdf(args.pdf)
                args.output.mkdir(parents=True, exist_ok=False)
                with (args.output / "source.pdf").open("xb") as stream:
                    stream.write(original)
                raw, metadata = extract_glantz_pdf(args.output / "source.pdf", layout_out=args.output / "layout.txt")
            else:
                raw, metadata = extract_pdf(args.pdf)
                args.output.mkdir(parents=True, exist_ok=False)
            for name, content in (("rows.csv", raw), ("source.json", metadata)):
                with (args.output / name).open("xb") as stream:
                    stream.write(content)
            count = 379 if all_accounts else 75
            print(f"PASS extracted account={args.account} rows={count} sha256={digest(raw)}")
        elif args.command == "verify":
            if all_accounts:
                rows, metadata = load_glantz_fixture(args.source_dir or GLANTZ_FIXTURE_DIR, args.pdf)
                report = glantz_diagnostics(rows, metadata)
            else:
                require(args.pdf is None, "--pdf verification requires --account all; default B-2 verifies retained pins")
                rows, metadata = load_fixture(args.source_dir or FIXTURE_DIR)
                report = verify_rows(rows, metadata)
            print(json.dumps(report, sort_keys=True))
        elif args.command == "prepare-pdf":
            prepare_source = prepare_glantz if all_accounts else prepare_pdf
            manifest = prepare_source(args.output, args.pdf)
            print(json.dumps({"status": "PREPARED", "source_rows": manifest["source_rows"],
                              "source_sha256": SOURCE_SHA256, "extraction": manifest["source_extraction"],
                              "output": str(args.output)}, sort_keys=True))
        elif all_accounts:
            pdf = args.pdf
            if args.source_dir is not None:
                load_glantz_fixture(args.source_dir, pdf)
                if pdf is None:
                    pdf = args.source_dir / "source.pdf"
            print(json.dumps(prepare_glantz(args.output, pdf), sort_keys=True))
        else:
            require(args.pdf is None, "default prepare is offline; use prepare-pdf to acquire and extract the original")
            print(json.dumps(prepare(args.output, args.source_dir or FIXTURE_DIR), sort_keys=True))
        return 0
    except EnvironmentError as exc:
        print(f"UNRUN {exc}", file=sys.stderr)
        return 4
    except (SourceError, OSError, UnicodeError, csv.Error, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
