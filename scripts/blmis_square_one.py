#!/usr/bin/env python3
"""Acquire and reproduce every Square One Exhibit B customer-account row.

The PDF's twelve-column, whole-dollar presentation is evidence, including its
709 starred withholding cells and its printed arithmetic discrepancies. This
helper never repairs the source to make it balance. All computations use integer
cents; the generated double-entry book is an explicit principal-history model,
not the original company's general ledger or an independent legal conclusion.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
import csv
import io
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib import error, request

from blmis_source import (
    EnvironmentError, I128_MAX, LEGACY_COLUMNS, PinnedRedirect, SourceError,
    USER_AGENT, amount_cents, csv_bytes, digest, iso_date, json_bytes,
    last_printed_balance, money, require,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "crates/fa-oracles/data/blmis_square_one"
SOURCE_ID = "SRC-BLM-005"
ACCOUNT = "1FR048"
SOURCE_SYSTEM = "blmis-square-one-exhibit-b-1fr048-v1"
SOURCE_URL = (
    "https://www.madofftrustee.com/document/dockets/"
    "009665-squareonecomplaint10-04330docket0167.pdf"
)
SOURCE_BYTES = 1_190_822
SOURCE_SHA256 = "396af6d399fb75fc966254b29f9f6e2e1fb0df5bd4ce9d4a48134fe38d56897b"
# Authored once from the pinned original, never regenerated during verification.
ROWS_SHA256 = "0b3d9666f7a55926333b53241d51e30a3ce4e3b417da7f072c4fcfc3d4a34afd"
METADATA_SHA256 = "56b89c945d4b463c9929f8470a3625e58024adaeba67f656735399f892cf9284"
PDF_PAGES = tuple(range(60, 79))
PAGE_ROW_COUNTS = (64, 64, 64, 64, 63, *(55 for _ in range(13)), 16)
STAR_COUNT = 709
FOOTNOTE_ID = f"{SOURCE_ID}:footnote:1"
FOOTNOTE_SHA256 = "21d5993db7ad460f0d8c540503be631e4c35cf8d70b4b14acaf1b5d71d490c4f"
PRINCIPAL_ACCOUNT = "BLMIS-1FR048"
CASH_ACCOUNT = "BLMIS-CASH"
VALUE_FIELDS = (
    "reported", "deposits", "withdrawals", "transfers_in", "transfers_out",
    "printed_balance", "ninety_day", "two_year", "six_year", "full_history",
)
FOOTER_FIELDS = VALUE_FIELDS[1:]
HEADERS = (
    "Date", "Transaction Description", "Amount as Reported in Customer Statement",
    "Deposits", "Withdrawals", "Transfers In", "Transfers Out", "Balance of Principal",
    "90-Day Preferential Transfers", "2-Year Cash Withdrawals",
    "6-Year Cash Withdrawals", "Full History Cash Withdrawals",
)
HEADER_LINES = (
    " ".join(f"Column {i}" for i in range(1, 13)),
    "Amount 90-Day 2-Year 6-Year Full History",
    "as Reported in Balance of Preferential Cash Cash Cash",
    "Date Transaction Description Customer Statement Deposits Withdrawals Transfers In "
    "Transfers Out Principal Transfers Withdrawals Withdrawals Withdrawals",
)
ROW_COLUMNS = (
    "row_id", "account", "pdf_page", "exhibit_page", "account_page", "page_row", "source_line",
    "date_literal", "description", *(f"{field}_literal" for field in VALUE_FIELDS),
    "withdrawal_marker", "marker_source_line", "marker_raw_line_sha256", "raw_line_sha256",
)
COLUMN_MAP = f'''[columns]
source_system = "{SOURCE_SYSTEM}"
entry_id_column = "entry_id"
effective_date_column = "effective_date"
account_column = "account_code"
signed_amount_column = "signed_amount"
description_column = "description"
memo_column = "memo"
'''
SCOPE = (
    "Every published transaction of Square One Exhibit B account 1FR048: 1,050 observations, "
    "1999-02-01 through 2008-12-03. Trustee computations in a complaint, not a complete BLMIS "
    "general ledger or a court finding. All twelve printed columns, zero-dollar observations, "
    "709 starred withholding cells and source arithmetic discrepancies are retained. Under "
    "the exhibit's footnote [1], starred reported withholding amounts do not reduce principal. "
    "The principal and cash-counterpart accounts are a constructed principal-history book; "
    "they do not purport to reconstruct gross tax payments or dated IRS refunds. No source "
    "difference is silently corrected, tolerated or posted as a balancing adjustment."
)
FOOTNOTE_MEANING = (
    "The trustee excludes the starred withholding amounts from principal, explaining that "
    "BLMIS paid these amounts to the IRS for account holders and that the IRS later refunded "
    "the amounts within the stated six-year scope. The source supplies no dated refund entries."
)


def description_kind(description: str) -> str:
    """Recognize the published transaction forms, retaining their exact text."""
    if description == "CHECK WIRE":
        return "cash_transfer"
    if description == "FIDELITY SPARTAN U S TREASURY MONEY MARKET W/H TAX DIV FDLXX":
        return "tax_withholding"
    if description == "W/H 1/31/03G":
        return "tax_withholding"
    if re.fullmatch(r"W/H TAX DIV [A-Z][A-Z0-9.]*", description):
        return "tax_withholding"
    if re.fullmatch(r"CXL W/H TAX DIV [A-Z][A-Z0-9.]*", description):
        return "tax_withholding_cancellation"
    raise SourceError("unrecognized Square One transaction description")


def row_values(raw: dict) -> dict:
    """Decode retained literals; the star exclusion is a named derived rule."""
    require(set(raw) == set(ROW_COLUMNS), "Square One source row has unexpected fields")
    row = dict(raw)
    require(row["account"] == ACCOUNT, "unexpected Square One account")
    row["exhibit"] = "B"
    for field in ("pdf_page", "exhibit_page", "account_page", "page_row", "source_line"):
        require(re.fullmatch(r"[1-9][0-9]*", str(row[field])) is not None,
                f"invalid provenance field {field}")
        row[field] = int(row[field])
    page = row["pdf_page"]
    require(page in PDF_PAGES and row["exhibit_page"] == page - 58 and row["account_page"] == page - 59,
            "row lies outside its declared exhibit pages")
    require(row["page_row"] <= PAGE_ROW_COUNTS[page - PDF_PAGES[0]], "invalid page row ordinal")
    require(row["row_id"] == f"{SOURCE_ID}:{ACCOUNT}:p{page}:l{row['source_line']}",
            "row identifier differs from its source location")
    require(re.fullmatch(r"[0-9a-f]{64}", row["raw_line_sha256"]) is not None,
            "invalid source-line hash")
    row["date"] = iso_date(row["date_literal"])
    row["transaction_kind"] = description_kind(row["description"])
    withdrawal = row["withdrawals_literal"]
    row["star"] = withdrawal in ("*", "* [1]")
    marker = row["withdrawal_marker"]
    row["footnote_premises"] = [FOOTNOTE_ID] if row["star"] else []
    if row["star"]:
        require(marker == "[1]", "starred withdrawal lacks footnote [1]")
        require(re.fullmatch(r"[1-9][0-9]*", str(row["marker_source_line"])) is not None,
                "starred withdrawal lacks marker provenance")
        row["marker_source_line"] = int(row["marker_source_line"])
        inline = withdrawal == "* [1]"
        require(row["marker_source_line"] == row["source_line"] - (0 if inline else 1),
                "withdrawal marker is not on its row or immediately preceding it")
        require(re.fullmatch(r"[0-9a-f]{64}", row["marker_raw_line_sha256"]) is not None,
                "invalid footnote marker-line hash")
        if inline:
            require(row["marker_raw_line_sha256"] == row["raw_line_sha256"],
                    "inline footnote marker hash differs from its source row")
        require(row["transaction_kind"] == "tax_withholding", "star outside a withholding transaction")
    else:
        require(marker == row["marker_source_line"] == row["marker_raw_line_sha256"] == "",
                "unstarred withdrawal unexpectedly carries footnote [1]")
    for field in VALUE_FIELDS:
        if field == "withdrawals" and row["star"]:
            # This is a derived principal contribution, not a fabricated source
            # numeric cell. The raw '*' literal and reported amount survive.
            value = 0
        else:
            value, _ = amount_cents(row[f"{field}_literal"])
        row[f"{field}_cents"] = value
    require(row["deposits_cents"] >= 0, "negative deposit")
    require(row["transfers_in_cents"] == row["transfers_out_cents"] == 0,
            "Square One source unexpectedly contains a principal transfer")
    row["cash_movement_cents"] = row["deposits_cents"] + row["withdrawals_cents"]
    row["principal_movement_cents"] = row["cash_movement_cents"]
    row["transfer_movement_cents"] = 0
    row["principal_rule"] = "withholding_refund_exclusion" if row["star"] else "sum_printed_movement_columns"
    row["excluded_reported_cents"] = row["reported_cents"] if row["star"] else 0
    if row["star"]:
        require(row["reported_cents"] <= 0 and row["deposits_cents"] == 0,
                "unexpected starred withholding amount or deposit")
    else:
        require(row["cash_movement_cents"] == row["reported_cents"],
                "unstarred cash movement differs from its reported amount")
    if row["withdrawals_cents"] > 0:
        require(row["transaction_kind"] == "tax_withholding_cancellation",
                "positive withdrawal is not a printed withholding cancellation")
    if row["transaction_kind"] == "tax_withholding_cancellation":
        require(row["withdrawals_cents"] > 0 and row["deposits_cents"] == 0,
                "withholding cancellation does not carry a positive withdrawal cell")
    return row


def parse_layout(text: str) -> tuple[list[dict], dict]:
    """Parse the declared twelve-column table; balance gaps are diagnostics."""
    require(len(text.encode()) <= 1_000_000, "unexpectedly large Square One extraction")
    pages = text.split("\f")
    require(len(pages) == 20 and not pages[-1].strip(), "expected exactly nineteen account pages")
    rows, page_hashes = [], []
    footer = None
    footnote = None
    for index, page in enumerate(pages[:-1]):
        pdf_page = PDF_PAGES[index]
        lines = page.splitlines()
        page_hashes.append(digest(page.encode()))
        require(f"BLMIS ACCOUNT NO. {ACCOUNT} -" in page, f"wrong account on PDF page {pdf_page}")
        require("10-04330-smb" in page and "Doc 167-2" in page and "Filed 12/21/18" in page,
                f"wrong filing identity on PDF page {pdf_page}")
        require(f"Pg {index + 2} of 20" in page and "Exhibit B" in page,
                f"wrong exhibit pagination on PDF page {pdf_page}")
        require(f"Page {index + 1} of 19 - {ACCOUNT}" in page,
                f"missing complete-account page marker on PDF page {pdf_page}")
        header_positions = [i for i, line in enumerate(lines) if "Column 1" in line]
        require(len(header_positions) == 1, f"missing or duplicate columns on PDF page {pdf_page}")
        header_index = header_positions[0]
        normalized_headers = tuple(" ".join(line.split()) for line in lines[header_index:header_index + 4])
        require(normalized_headers == HEADER_LINES, f"unexpected declared headers on PDF page {pdf_page}")
        count = 0
        consumed_markers = set()
        for line_number, line in enumerate(lines, 1):
            if re.match(r"^\s*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}\s", line):
                cells = re.split(r"\s{2,}", line.strip())
                require(len(cells) == 12, f"expected twelve cells at PDF page {pdf_page} line {line_number}")
                count += 1
                withdrawal = cells[4]
                marker_line = ""
                marker_hash = ""
                if withdrawal in ("*", "* [1]"):
                    if withdrawal == "* [1]":
                        marker_line = str(line_number)
                        marker_hash = digest(line.encode())
                    else:
                        require(line_number > 1 and re.fullmatch(r"\s*\[1\]\s*", lines[line_number - 2]) is not None,
                                f"star lacks adjacent footnote marker at PDF page {pdf_page} line {line_number}")
                        marker_line = str(line_number - 1)
                        marker_hash = digest(lines[line_number - 2].encode())
                        consumed_markers.add(line_number - 1)
                row = {
                    "row_id": f"{SOURCE_ID}:{ACCOUNT}:p{pdf_page}:l{line_number}",
                    "account": ACCOUNT, "pdf_page": str(pdf_page), "exhibit_page": str(index + 2),
                    "account_page": str(index + 1), "page_row": str(count), "source_line": str(line_number),
                    "date_literal": cells[0], "description": cells[1],
                    "withdrawal_marker": "[1]" if marker_line else "", "marker_source_line": marker_line,
                    "marker_raw_line_sha256": marker_hash, "raw_line_sha256": digest(line.encode()),
                }
                row.update({f"{field}_literal": value for field, value in zip(VALUE_FIELDS, cells[2:], strict=True)})
                row_values(row)
                rows.append(row)
            elif "Total:" in line:
                require(footer is None and pdf_page == 78, "unexpected or duplicate printed footer")
                cells = [cell.strip() for cell in line.split("Total:", 1)[1].split("$")]
                require(cells[0] == "" and len(cells) == 10, "expected nine printed footer amounts")
                for cell in cells[1:]:
                    amount_cents(cell)
                footer = {
                    "pdf_page": pdf_page, "source_line": line_number, "raw_line_sha256": digest(line.encode()),
                    "cells": dict(zip(FOOTER_FIELDS, cells[1:], strict=True)),
                }
            elif re.fullmatch(r"\s*\[1\]\s*", line) and footer is not None:
                require(footnote is None and pdf_page == 78, "unexpected or duplicate footnote definition")
                collected = []
                for body in lines[line_number:]:
                    if not body.strip():
                        break
                    collected.append(body.strip())
                normalized = " ".join(" ".join(collected).split())
                require(digest(normalized.encode()) == FOOTNOTE_SHA256, "withholding footnote text changed")
                footnote = {
                    "fact_id": FOOTNOTE_ID, "marker": "[1]", "pdf_page": pdf_page,
                    "source_line": line_number, "text_source_lines": list(range(line_number + 1, line_number + 1 + len(collected))),
                    "normalized_text_sha256": digest(normalized.encode()), "meaning": FOOTNOTE_MEANING,
                }
                consumed_markers.add(line_number)
        marker_lines = {i for i, line in enumerate(lines, 1) if re.fullmatch(r"\s*\[1\]\s*", line)}
        require(marker_lines == consumed_markers, f"unattributed footnote marker on PDF page {pdf_page}")
        require(count == PAGE_ROW_COUNTS[index],
                f"incomplete account: PDF page {pdf_page} has {count} dated rows, expected {PAGE_ROW_COUNTS[index]}")
    require(footer is not None and footnote is not None, "missing printed footer or withholding footnote")
    metadata = {
        "schema_version": 1, "source_id": SOURCE_ID, "source_url": SOURCE_URL,
        "source_sha256": SOURCE_SHA256, "source_bytes": SOURCE_BYTES, "filed_on": "2018-12-21",
        "account": ACCOUNT, "exhibit": "B", "pdf_pages": list(PDF_PAGES),
        "exhibit_pages": list(range(2, 21)), "account_pages": list(range(1, 20)),
        "rows_per_page": list(PAGE_ROW_COUNTS), "row_count": len(rows), "starred_withdrawal_cells": STAR_COUNT,
        "headers": list(HEADERS), "printed_amount_unit": "USD whole dollars",
        "dash_interpretation": "A printed dash is no movement in that column; blank cells are refused.",
        "star_interpretation": "The literal star is preserved. A zero principal contribution is derived only under footnote [1], never parsed as a printed numeric zero.",
        "row_id_basis": "Derived source citation: complaint id, trustee account id, PDF page and pdftotext line; not an original transaction id.",
        "extraction": {
            "command": "pdftotext -layout -f 60 -l 78 - - < <pinned.pdf>",
            "authoring_version": "pdftotext version 24.02.0", "utf8_sha256": digest(text.encode()),
            "page_utf8_sha256": page_hashes,
            "line_hash_basis": "SHA-256 of the exact UTF-8 extraction line without its newline",
        },
        "footer": footer, "footnotes": {"[1]": footnote},
        "assertion_status": "trustee_computation in a complaint; not a court finding",
        "redistribution_basis": "Factual transaction cells from a publicly hosted court filing; no full complaint or account-holder header is redistributed.",
        "scope": SCOPE,
    }
    verify_rows([row_values(row) for row in rows], metadata)
    return rows, metadata


def diagnostics(rows: list[dict], metadata: dict) -> dict:
    """Literal movement fold versus independently printed controls, without tolerance."""
    running, differences = 0, []
    totals = {field: 0 for field in FOOTER_FIELDS if field != "printed_balance"}
    for row in rows:
        running += row["principal_movement_cents"]
        require(abs(running) <= I128_MAX, "principal fold exceeds i128")
        gap = running - row["printed_balance_cents"]
        if gap:
            differences.append({"row_id": row["row_id"], "gap_cents": gap})
        for field in totals:
            totals[field] += row[f"{field}_cents"]
            require(abs(totals[field]) <= I128_MAX, "column total exceeds i128")
    footer_gaps = {}
    for field, actual in {**totals, "printed_balance": running}.items():
        expected, _ = amount_cents(metadata["footer"]["cells"][field])
        if actual != expected:
            footer_gaps[field] = actual - expected
    return {
        "rows": len(rows), "rows_off": len(differences), "row_differences": differences,
        "maximum_gap_cents": max((abs(item["gap_cents"]) for item in differences), default=0),
        "closing_gap_cents": running - rows[-1]["printed_balance_cents"],
        "source_closing_balance_cents": running,
        "printed_closing_balance_cents": rows[-1]["printed_balance_cents"],
        "column_sums_cents": totals, "footer_gaps_cents": footer_gaps,
        "starred_withdrawal_cells": sum(row["star"] for row in rows),
        "excluded_reported_cents": sum(row["excluded_reported_cents"] for row in rows),
        "nonzero_principal_rows": sum(row["principal_movement_cents"] != 0 for row in rows),
        "zero_principal_rows": [row["row_id"] for row in rows if row["principal_movement_cents"] == 0],
        "positive_withdrawal_rows": [row["row_id"] for row in rows if row["withdrawals_cents"] > 0],
        "footnote_premises": [FOOTNOTE_ID],
        "comparison_class": "source_discrepancy_retained; not exact printed-balance footing",
    }


def verify_rows(rows: list[dict], metadata: dict) -> dict:
    """Require complete source/footnote coverage; arithmetic gaps are returned."""
    require(len(rows) == sum(PAGE_ROW_COUNTS), "complete account row count differs")
    require(len({row["row_id"] for row in rows}) == len(rows), "duplicate source row identifier")
    require([(row["pdf_page"], row["source_line"]) for row in rows] ==
            sorted((row["pdf_page"], row["source_line"]) for row in rows), "source display order changed")
    require([row["date"] for row in rows] == sorted(row["date"] for row in rows), "source dates are out of order")
    for page, count in zip(PDF_PAGES, PAGE_ROW_COUNTS, strict=True):
        selected = [row for row in rows if row["pdf_page"] == page]
        require(len(selected) == count and [row["page_row"] for row in selected] == list(range(1, count + 1)),
                f"incomplete account page {page}")
    require(metadata.get("source_sha256") == SOURCE_SHA256 and metadata.get("source_bytes") == SOURCE_BYTES,
            "metadata binds another original document")
    require(metadata.get("row_count") == len(rows) and metadata.get("rows_per_page") == list(PAGE_ROW_COUNTS),
            "metadata source census differs")
    footnote = metadata.get("footnotes", {}).get("[1]", {})
    require(footnote.get("fact_id") == FOOTNOTE_ID and footnote.get("normalized_text_sha256") == FOOTNOTE_SHA256,
            "StarPremiseMissing: starred source rows require the pinned withholding footnote [1]")
    require(all(row["footnote_premises"] == ([FOOTNOTE_ID] if row["star"] else []) for row in rows),
            "StarPremiseMissing: a row lacks its source footnote premise")
    require(sum(row["star"] for row in rows) == STAR_COUNT and metadata.get("starred_withdrawal_cells") == STAR_COUNT,
            "starred-cell census differs from the 709 source cells")
    require(set(metadata.get("footer", {}).get("cells", {})) == set(FOOTER_FIELDS), "printed footer columns differ")
    return diagnostics(rows, metadata)


def load_fixture(directory: Path = FIXTURE_DIR) -> tuple[list[dict], dict]:
    raw = (directory / "rows.csv").read_bytes()
    meta = (directory / "source.json").read_bytes()
    require(digest(raw) == ROWS_SHA256, "source rows SHA-256 differs from the committed pin")
    require(digest(meta) == METADATA_SHA256, "source metadata SHA-256 differs from the committed pin")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
    require(reader.fieldnames == list(ROW_COLUMNS), "source CSV header differs")
    rows = [row_values(row) for row in reader]
    metadata = json.loads(meta)
    verify_rows(rows, metadata)
    return rows, metadata


def verify_pdf(path: Path) -> bytes:
    require(path.stat().st_size == SOURCE_BYTES, "PDF byte count differs from the pinned original")
    raw = path.read_bytes()
    require(raw.startswith(b"%PDF-") and digest(raw) == SOURCE_SHA256,
            "PDF SHA-256 differs from the pinned original")
    return raw


def fetch(output: Path) -> None:
    require(not output.exists(), "download destination already exists")
    req = request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/pdf"})
    try:
        with request.build_opener(PinnedRedirect()).open(req, timeout=30) as response:
            require(response.status == 200, "expected complete HTTP 200 PDF response")
            raw = response.read(SOURCE_BYTES + 1)
    except (OSError, error.URLError) as exc:
        raise EnvironmentError(f"Square One source download unavailable: {exc}") from exc
    require(len(raw) == SOURCE_BYTES and digest(raw) == SOURCE_SHA256,
            "download differs from pinned PDF size or SHA-256")
    with output.open("xb") as stream:
        stream.write(raw)


def extract_pdf(path: Path, *, layout_out: Path | None = None) -> tuple[bytes, bytes]:
    original = verify_pdf(path)
    try:
        process = subprocess.run(
            ["pdftotext", "-layout", "-f", "60", "-l", "78", "-", "-"],
            input=original, capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentError(f"pdftotext unavailable: {exc}; install Poppler and rerun; no retained-row fallback") from exc
    require(process.returncode == 0, "pdftotext could not extract the pinned document")
    if layout_out is not None:
        with layout_out.open("xb") as stream:
            stream.write(process.stdout)
    try:
        text = process.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SourceError("pdftotext output is not UTF-8") from exc
    rows, metadata = parse_layout(text)
    raw, meta = csv_bytes(ROW_COLUMNS, rows), json_bytes(metadata)
    require(digest(raw) == ROWS_SHA256 and digest(meta) == METADATA_SHA256,
            "PDF extraction differs from the reviewed fixture; investigate drift, never regenerate pins automatically")
    return raw, meta


def package_payloads(directory: Path) -> tuple[dict, dict[str, bytes]]:
    rows, metadata = load_fixture(directory)
    normalized, mapping, observations = [], [], []
    running = 0
    for row in rows:
        movement = row["principal_movement_cents"]
        running += movement
        observations.append({
            "source_row_id": row["row_id"], "date": row["date"], "posted": movement != 0,
            "star": row["star"], "footnote_premises": row["footnote_premises"],
            "source_fold_cents": running, "printed_balance_cents": row["printed_balance_cents"],
            "source_fold_minus_printed_cents": running - row["printed_balance_cents"],
        })
        if not movement:
            continue
        for account, amount in ((PRINCIPAL_ACCOUNT, -movement), (CASH_ACCOUNT, movement)):
            normalized.append({
                "entry_id": row["row_id"], "effective_date": row["date"], "account_code": account,
                "signed_amount": money(amount), "description": row["description"],
                "memo": f"analysis counterpart; {SOURCE_ID} Exhibit B PDF p{row['pdf_page']} line {row['source_line']}",
                "source_row": row["row_id"],
            })
        mapping.append({"entry_id": row["row_id"], "source_row_id": row["row_id"], "source_account": ACCOUNT})
    controls = []
    for year in range(int(rows[0]["date"][:4]), int(rows[-1]["date"][:4]) + 1):
        control = last_printed_balance(rows, f"{year}-12-31")
        folded = sum(row["principal_movement_cents"] for row in rows if row["date"] <= control["at_date"])
        controls.append({**control, "source_fold_cents": folded,
                         "source_fold_minus_printed_cents": folded - control["printed_balance_cents"]})
    chart = {"accounts": [
        {"code": PRINCIPAL_ACCOUNT, "name": "Published principal 1FR048 - analysis account", "type": "Equity", "unit": "USD"},
        {"code": CASH_ACCOUNT, "name": "Principal cash movements - analysis counterpart", "type": "Asset", "unit": "USD"},
    ]}
    payloads = {
        "rows.csv": (directory / "rows.csv").read_bytes(), "source.json": (directory / "source.json").read_bytes(),
        "legacy.csv": csv_bytes(LEGACY_COLUMNS, normalized), "chart.json": json_bytes(chart),
        "column_map.toml": COLUMN_MAP.encode(), "controls.json": json_bytes(controls),
        "observations.json": json_bytes(observations),
    }
    manifest = {
        "schema_version": 1, "source_system": SOURCE_SYSTEM, "scope": SCOPE,
        "source_sha256": SOURCE_SHA256, "source_rows_sha256": ROWS_SHA256,
        "source_rows": len(rows), "source_accounts": 1, "monetary_rows": len(mapping), "normalized_legs": len(normalized),
        "principal_account": PRINCIPAL_ACCOUNT, "principal_accounts": {ACCOUNT: PRINCIPAL_ACCOUNT},
        "principal_posting_sign": "negative of trustee principal movement", "row_mapping": mapping,
        "zero_principal_rows": [row["row_id"] for row in rows if row["principal_movement_cents"] == 0],
        "computation_order": [row["row_id"] for row in rows], "posting_order": [row["entry_id"] for row in mapping],
        "starred_withdrawal_cells": STAR_COUNT, "footnote_premises": [FOOTNOTE_ID],
        "baseline": "Zero immediately before the exhibit's first transaction; not a whole-firm opening trial balance.",
        "controls_basis": "Last printed principal balance on or before each year end; source fold and difference are retained separately, never used to replace the printed control.",
        "row_order": "Source page and line order, including same-day rows; no inferred source transaction time.",
        "source_diagnostics": verify_rows(rows, metadata),
        "outputs": {name: {"bytes": len(raw), "sha256": digest(raw)} for name, raw in payloads.items()},
    }
    payloads["manifest.json"] = json_bytes(manifest)
    return manifest, payloads


def prepare(output: Path, directory: Path = FIXTURE_DIR) -> dict:
    """Prepare authenticated retained rows offline, without claiming PDF extraction."""
    require(not output.exists(), "package destination already exists")
    manifest, payloads = package_payloads(directory)
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    return manifest


def prepare_pdf(output: Path, pdf: Path | None = None, *, on_created: Callable[[], None] | None = None) -> dict:
    """Acquire/extract the original now; retained fixtures are acceptance pins only."""
    require(not output.exists(), "package destination already exists")
    supplied = verify_pdf(pdf) if pdf is not None else None
    output.mkdir(parents=True, exist_ok=False)
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
    raw, meta = extract_pdf(original, layout_out=layout)
    for name, value in (("rows.csv", raw), ("source.json", meta)):
        with (extracted / name).open("xb") as stream:
            stream.write(value)
    manifest, payloads = package_payloads(extracted)
    retained = {}
    for path in (original, layout, extracted / "rows.csv", extracted / "source.json"):
        value = path.read_bytes()
        retained[path.relative_to(output).as_posix()] = {"bytes": len(value), "sha256": digest(value)}
    extraction = {
        "format": "fa-blmis-square-one-pdf-extraction-v1", "mode": "original_pdf_extracted_this_run",
        "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
        "command": ["pdftotext", "-layout", "-f", "60", "-l", "78", "-", "-"],
        "stdin": "Verified source.pdf bytes; extraction cannot race a changed source path.",
        "pdf_pages": list(PDF_PAGES), "source_rows": len(load_fixture(extracted)[0]),
        "reviewed_rows_sha256": ROWS_SHA256, "reviewed_metadata_sha256": METADATA_SHA256, "retained": retained,
    }
    manifest["source_extraction"] = extraction
    payloads["extraction.json"] = json_bytes(extraction)
    manifest["outputs"].update(retained)
    manifest["outputs"]["extraction.json"] = {"bytes": len(payloads["extraction.json"]), "sha256": digest(payloads["extraction.json"])}
    payloads["manifest.json"] = json_bytes(manifest)
    for name, value in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(value)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch_parser = sub.add_parser("fetch", help="download the original PDF and verify its pin")
    fetch_parser.add_argument("--out", required=True, type=Path)
    extract_parser = sub.add_parser("extract", help="extract the pinned PDF into a new directory")
    extract_parser.add_argument("--pdf", required=True, type=Path)
    extract_parser.add_argument("--out", required=True, type=Path)
    verify_parser = sub.add_parser("verify", help="verify retained factual rows offline")
    verify_parser.add_argument("--fixture", type=Path, default=FIXTURE_DIR)
    prepare_parser = sub.add_parser("prepare", help="prepare a native-compatible principal-history package")
    prepare_parser.add_argument("--out", required=True, type=Path)
    selection = prepare_parser.add_mutually_exclusive_group()
    selection.add_argument("--pdf", type=Path, help="extract this pinned original; otherwise download it")
    selection.add_argument("--retained", action="store_true", help="explicit offline preparation; no PDF acquisition claim")
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            fetch(args.out)
            result = {"source_sha256": SOURCE_SHA256, "source_bytes": SOURCE_BYTES}
        elif args.command == "extract":
            require(not args.out.exists(), "extraction destination already exists")
            raw, meta = extract_pdf(args.pdf)
            args.out.mkdir(parents=True, exist_ok=False)
            for name, value in (("rows.csv", raw), ("source.json", meta)):
                with (args.out / name).open("xb") as stream:
                    stream.write(value)
            rows, metadata = load_fixture(args.out)
            result = verify_rows(rows, metadata)
        elif args.command == "verify":
            rows, metadata = load_fixture(args.fixture)
            result = verify_rows(rows, metadata)
        else:
            result = prepare(args.out) if args.retained else prepare_pdf(args.out, args.pdf)
        print(json.dumps(result, sort_keys=True))
        return 0
    except EnvironmentError as exc:
        print(f"UNRUN {exc}", file=sys.stderr)
        return 4
    except (SourceError, OSError, UnicodeError, csv.Error, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
