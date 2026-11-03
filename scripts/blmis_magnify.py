#!/usr/bin/env python3
"""Reproduce all six Magnify Exhibit B accounts from the pinned public filing.

All 2,364 source observations survive the mixed 11/12-column extraction,
including tax stars, transfer-credit footnotes, positive corrections, literal
zeros and printed arithmetic differences. The normalized journal is an explicit
principal-history analysis construction, not BLMIS's original double-entry GL.
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
FIXTURE_DIR = ROOT / "crates/fa-oracles/data/blmis_magnify"
SOURCE_ID = "SRC-BLM-006"
SOURCE_SYSTEM = "blmis-magnify-exhibit-b-v1"
SOURCE_URL = (
    "https://www.madofftrustee.com/document/dockets/"
    "magnify_affidavit_opposingcounsel_10-05279_docket150.pdf"
)
SOURCE_BYTES = 28_947_445
SOURCE_SHA256 = "25055acd72befe051e8939b528ebcf47be996edcbaa04c712efeb3ebb8dba8ec"
ROWS_SHA256 = "f10a7bc474512a0f4db4b457d4865a4ff7909053f28f24e3dfa023afb60cf697"
METADATA_SHA256 = "7350a15658dfc63da0386f8b17ca19acc09c454938df5abf94ca78e96e89fc80"
PDF_PAGES = tuple(range(112, 163))
CASH_ACCOUNT = "BLMIS-CASH"
TRANSFER_ACCOUNT = "BLMIS-TRANSFER"
ACCOUNTS = {
    "1FN024": {"pdf_pages": tuple(range(112, 120)), "rows_per_page": (45, 45, 45, 45, 45, 45, 45, 27), "columns": 11},
    "1FN025": {"pdf_pages": (120, 121), "rows_per_page": (45, 13), "columns": 11},
    "1FN037": {"pdf_pages": tuple(range(122, 160)), "rows_per_page": (*(52 for _ in range(37)), 3), "columns": 12},
    "1FN073": {"pdf_pages": (160,), "rows_per_page": (6,), "columns": 11},
    "1FN097": {"pdf_pages": (161,), "rows_per_page": (4,), "columns": 11},
    "1FR051": {"pdf_pages": (162,), "rows_per_page": (27,), "columns": 11},
}
STAR_COUNT = 717
PARTIAL_DESCRIPTION_ROW = f"{SOURCE_ID}:1FN037:p134:l27"
VALUE_FIELDS = (
    "reported", "deposits", "withdrawals", "transfers_in", "transfers_out",
    "printed_balance", "ninety_day", "two_year", "six_year", "full_history",
)
HEADERS = (
    "Date", "Transaction Description", "Transaction Amount Reported in Customer Statement",
    "Cash Deposits", "Cash Withdrawals", "Transfers of Principal In", "Transfers of Principal Out",
    "Balance of Principal", "90-Day Transfers", "Two Year Transfers", "Six Year Transfers", "Full History Transfers",
)
ROW_COLUMNS = (
    "row_id", "account", "pdf_page", "exhibit_page", "account_page", "page_row", "source_line",
    "source_column_count", "date_literal", "description", *(f"{field}_literal" for field in VALUE_FIELDS),
    "reported_marker", "withdrawal_marker", "marker_source_line", "marker_raw_line_sha256", "raw_line_sha256",
)
NOTE_HASHES = {
    "partial_out": "f9eca2d3368853bbe58df9d1143c71eb8407b4d0bf913fd03efc5305c82c973f",
    "zero_out": "76c6305b3a298d356ca0b4abf297a69b827313be988db0f0aa9204aa74937d38",
    "zero_in": "8caf39e8bb0c34079e3c9fe1afabcd8672ac862289283a43edc65e5d53d7cf1c",
    "partial_in": "65a22295479e5ca4bf6b5bde60608347c430b86d116fcaf946fe0bfad8f291f6",
    "other_recipients": "dfc44144e8e6e5dda3abdf9896f1291c22f7a7c1cb317786c395b41f5f4ed47c",
    "withholding_refunds": "21d5993db7ad460f0d8c540503be631e4c35cf8d70b4b14acaf1b5d71d490c4f",
}
NOTE_ROLES = {
    "1FN024": {"[1]": "partial_out", "[2]": "zero_out", "[3]": "zero_in", "[4]": "other_recipients"},
    "1FN025": {"[1]": "zero_out", "[2]": "other_recipients"},
    "1FN037": {"[1]": "partial_in", "[2]": "zero_in", "[3]": "zero_out", "[4]": "withholding_refunds"},
    "1FN073": {}, "1FN097": {},
    "1FR051": {"[1]": "zero_in", "[2]": "other_recipients"},
}
NOTE_MEANINGS = {
    "partial_out": "The trustee debits remaining principal rather than the full reported outward transfer; credited principal is a source oracle input.",
    "zero_out": "The trustee assigns no principal to the reported outward transfer, describing the reported amount as fictitious profits.",
    "zero_in": "The trustee assigns no principal to the reported inward transfer, describing the reported amount as fictitious profits.",
    "partial_in": "The trustee credits remaining originating-account principal rather than the full reported inward transfer; the credited amount is a source oracle input.",
    "other_recipients": "The marked total includes initial transfers to defendants other than the account holder, with details referenced in Exhibit D.",
    "withholding_refunds": "The trustee excludes starred tax withholdings within the stated six-year prefiling period from principal, explaining subsequent IRS refunds without dated refund entries.",
}
ROUNDING_NOTE = "Note: Numbers might not add to totals shown due to rounding."
SCOPE = (
    "Every dated row of the six Magnify Exhibit B accounts: 2,364 observations. "
    "The pinned publisher-hosted affidavit contains an attached copy of the complaint's "
    "Exhibit B; original and enclosing docket identities are retained. These are trustee "
    "computations in a complaint, not a complete BLMIS general ledger or court findings. "
    "All eleven/twelve printed columns, positive corrections, source zero cells, 717 starred "
    "tax observations and arithmetic differences survive. Transfer principal is an explicit "
    "oracle input, not independently reproduced net equity. Analysis counterparts and the "
    "zero-before-first-row baseline are declared constructions. No dated IRS refunds, "
    "missing description text, absent lookback columns or balancing adjustments are invented."
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


def value_fields(account: str) -> tuple[str, ...]:
    return VALUE_FIELDS if ACCOUNTS[account]["columns"] == 12 else tuple(field for field in VALUE_FIELDS if field != "ninety_day")


def note_id(account: str, marker: str) -> str:
    return f"{SOURCE_ID}:{account}:footnote:{marker[1:-1]}"


def number(literal: str, *, annotated: bool = False) -> tuple[int, str]:
    match = re.fullmatch(r"(.+?)(?: (\[[1-4]\]))?", literal)
    require(match is not None, "invalid Magnify monetary literal")
    numeric, marker = match.groups()
    require(marker is None or annotated, "unexpected annotated monetary column")
    return amount_cents(numeric)[0], marker or ""


def transaction_kind(description: str, row_id: str) -> str:
    require(isinstance(description, str) and 0 < len(description) <= 160
            and re.fullmatch(r"[A-Z0-9 /&().'\-]+", description) is not None,
            "invalid Magnify transaction description")
    if description.startswith("TRANS "):
        require(re.fullmatch(r"TRANS (?:FROM|TO) [A-Z0-9]+ \([A-Z0-9]+\)", description) is not None,
                "unknown transfer description form")
        return "transfer"
    if description == "(1FN024)":
        require(row_id == PARTIAL_DESCRIPTION_ROW, "incomplete description outside its reviewed source location")
        return "transfer_annotation_only"
    if any(word in description for word in ("CANCEL", "CXL", "CORRECT", "RETURNED")):
        return "correction_or_return"
    if description.startswith(("CHECK", "CHECK-WIRE")):
        return "cash_transfer"
    if "W/H" in description or "WITHHOLDING TAX" in description:
        return "tax_withholding"
    raise SourceError("unrecognized Magnify transaction description")


def row_values(raw: dict) -> dict:
    require(set(raw) == set(ROW_COLUMNS), "Magnify source row has unexpected fields")
    row = dict(raw)
    account = row["account"]
    require(account in ACCOUNTS, "unexpected Magnify source account")
    spec = ACCOUNTS[account]
    for key in ("pdf_page", "exhibit_page", "account_page", "page_row", "source_line", "source_column_count"):
        require(re.fullmatch(r"[1-9][0-9]*", str(row[key])) is not None, f"invalid source provenance {key}")
        row[key] = int(row[key])
    page = row["pdf_page"]
    require(page in spec["pdf_pages"] and row["account_page"] == spec["pdf_pages"].index(page) + 1
            and row["exhibit_page"] == page - 111 and row["source_column_count"] == spec["columns"],
            "source account/page/layout attribution differs")
    require(row["row_id"] == f"{SOURCE_ID}:{account}:p{page}:l{row['source_line']}", "source citation differs from its location")
    require(re.fullmatch(r"[0-9a-f]{64}", row["raw_line_sha256"]) is not None, "invalid source-line hash")
    row["exhibit"] = "B"
    row["date"] = iso_date(row["date_literal"])
    row["transaction_kind"] = transaction_kind(row["description"], row["row_id"])
    row["star"] = row["withdrawals_literal"] in ("*", "* [4]")
    row["footnote_premises"] = []
    for field in VALUE_FIELDS:
        literal = row[f"{field}_literal"]
        if field == "ninety_day" and spec["columns"] == 11:
            require(literal == "", "invented ninety-day cell in an eleven-column source table")
            row[f"{field}_cents"] = None
        elif field == "withdrawals" and row["star"]:
            require(account == "1FN037" and row["withdrawal_marker"] == "[4]", "unknown tax-star premise")
            row[f"{field}_cents"] = 0
            row["footnote_premises"].append(note_id(account, "[4]"))
        else:
            value, marker = number(literal, annotated=field == "reported")
            row[f"{field}_cents"] = value
            if field == "reported":
                require(marker == row["reported_marker"] and (not marker or marker in NOTE_ROLES[account]),
                        "reported amount's account-scoped footnote differs")
                if marker:
                    row["footnote_premises"].append(note_id(account, marker))
    if row["star"]:
        inline = row["withdrawals_literal"] == "* [4]"
        require(re.fullmatch(r"[1-9][0-9]*", str(row["marker_source_line"])) is not None, "star lacks marker source line")
        row["marker_source_line"] = int(row["marker_source_line"])
        require(row["marker_source_line"] == row["source_line"] - (0 if inline else 1), "star marker attribution changed")
        require(re.fullmatch(r"[0-9a-f]{64}", row["marker_raw_line_sha256"]) is not None, "star lacks marker-line hash")
        if inline:
            require(row["marker_raw_line_sha256"] == row["raw_line_sha256"], "inline star marker hash differs")
    else:
        require(row["withdrawal_marker"] == row["marker_source_line"] == row["marker_raw_line_sha256"] == "",
                "unstarred withdrawal has a star marker")
    require(row["deposits_cents"] >= 0 and row["transfers_in_cents"] >= 0 and row["transfers_out_cents"] <= 0,
            "incoming/outgoing principal column sign differs")
    row["cash_movement_cents"] = row["deposits_cents"] + row["withdrawals_cents"]
    row["transfer_movement_cents"] = row["transfers_in_cents"] + row["transfers_out_cents"]
    row["principal_movement_cents"] = row["cash_movement_cents"] + row["transfer_movement_cents"]
    transfer = row["transaction_kind"] in ("transfer", "transfer_annotation_only")
    row["transfer_credit_role"] = "oracle_output" if transfer else "not_applicable"
    row["transfer_principal_role"] = row["transfer_credit_role"]
    row["excluded_reported_cents"] = row["reported_cents"] if row["star"] else 0
    row["principal_rule"] = "withholding_refund_exclusion" if row["star"] else "sum_printed_principal_columns"
    if transfer:
        require(row["cash_movement_cents"] == 0 and not row["star"], "transfer contains cash or a tax star")
        marker = row["reported_marker"]
        role = NOTE_ROLES[account].get(marker)
        inward = row["description"].startswith("TRANS FROM") or row["row_id"] == PARTIAL_DESCRIPTION_ROW
        require(row["reported_cents"] > 0 if inward else row["reported_cents"] < 0, "reported transfer direction differs")
        require(row["transfers_out_cents"] == 0 if inward else row["transfers_in_cents"] == 0, "principal transfer direction differs")
        if marker:
            require(role in (("zero_in", "partial_in") if inward else ("zero_out", "partial_out")), "transfer footnote direction differs")
            if role.startswith("zero_"):
                require(row["transfer_movement_cents"] == 0, "zero-credit footnote unexpectedly contributes principal")
        if row["row_id"] == PARTIAL_DESCRIPTION_ROW:
            require(marker == "[2]" and row["description"] == "(1FN024)", "incomplete printed description's premise changed")
    else:
        require(row["transfer_movement_cents"] == 0 and not row["reported_marker"], "cash observation has transfer principal or annotation")
        if row["star"]:
            require(row["transaction_kind"] == "tax_withholding" and row["reported_cents"] <= 0
                    and row["cash_movement_cents"] == 0, "starred withholding changes principal")
        else:
            require(row["reported_cents"] == row["cash_movement_cents"], "reported cash differs from principal movement")
    return row


def parse_layout(text: str) -> tuple[list[dict], dict]:
    require(len(text.encode()) <= 2_000_000, "unexpectedly large Magnify table extraction")
    pages = text.split("\f")
    require(len(pages) == 52 and not pages[-1].strip(), "expected exactly fifty-one Magnify table pages")
    rows, page_hashes = [], []
    accounts = {account: {"footnotes": {}} for account in ACCOUNTS}
    for pdf_page, page in zip(PDF_PAGES, pages[:-1], strict=True):
        account = next(account for account, spec in ACCOUNTS.items() if pdf_page in spec["pdf_pages"])
        spec = ACCOUNTS[account]
        index = spec["pdf_pages"].index(pdf_page)
        fields = value_fields(account)
        footer_fields = fields[1:]
        lines = page.splitlines()
        page_hashes.append(digest(page.encode()))
        require(f"BLMIS ACCOUNT NO. {account}" in page and f"Page {index + 1} of {len(spec['pdf_pages'])} - {account}" in page,
                f"account pagination differs on PDF page {pdf_page}")
        require(all(word in page for word in ("150-1", "143-2", "10/30/17", "09/29/17", "Exhibit B")),
                f"enclosing or embedded docket identity differs on PDF page {pdf_page}")
        header_indices = [i for i, line in enumerate(lines) if "Column 1 " in line]
        require(len(header_indices) == 1, "missing or duplicate declared table columns")
        h = header_indices[0]
        expected_headers = (
            " ".join(f"Column {i}" for i in range(1, spec["columns"] + 1)), "Transaction Amount",
            "Reported in Cash Cash Transfers of Transfers of Balance of " + ("90-Day " if spec["columns"] == 12 else "") + "Two Year Six Year Full History",
            "Date Transaction Description Customer Statement Deposits Withdrawals Principal In Principal Out Principal "
            + " ".join("Transfers" for _ in range(spec["columns"] - 8)),
        )
        require(tuple(" ".join(line.split()) for line in lines[h:h + 4]) == expected_headers,
                f"unknown declared layout on PDF page {pdf_page}")
        footer_indices = [i for i, line in enumerate(lines) if "Total:" in line]
        require(len(footer_indices) == (1 if index == len(spec["pdf_pages"]) - 1 else 0), "missing or misplaced printed footer")
        footer_index = footer_indices[0] if footer_indices else None
        consumed, count = set(), 0
        for n, line in enumerate(lines, 1):
            if not re.match(r"^\s*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}\s", line):
                continue
            cells = re.split(r"\s{2,}", line.strip())
            require(len(cells) == spec["columns"], f"wrong cell count on PDF page {pdf_page} line {n}")
            count += 1
            withdrawal = cells[4]
            marker_line, marker_hash = "", ""
            if withdrawal in ("*", "* [4]"):
                if withdrawal == "* [4]":
                    marker_line, marker_hash = str(n), digest(line.encode())
                else:
                    require(n > 1 and re.fullmatch(r"\s*\[4\]\s*", lines[n - 2]) is not None,
                            f"star lacks adjacent footnote [4] on PDF page {pdf_page} line {n}")
                    marker_line, marker_hash = str(n - 1), digest(lines[n - 2].encode())
                    consumed.add(n - 1)
            reported_marker = re.search(r" (\[[1-4]\])$", cells[2])
            row = {
                "row_id": f"{SOURCE_ID}:{account}:p{pdf_page}:l{n}", "account": account,
                "pdf_page": str(pdf_page), "exhibit_page": str(pdf_page - 111), "account_page": str(index + 1),
                "page_row": str(count), "source_line": str(n), "source_column_count": str(spec["columns"]),
                "date_literal": cells[0], "description": cells[1],
                "reported_marker": reported_marker[1] if reported_marker else "",
                "withdrawal_marker": "[4]" if marker_line else "", "marker_source_line": marker_line,
                "marker_raw_line_sha256": marker_hash, "raw_line_sha256": digest(line.encode()),
                **{f"{field}_literal": "" for field in VALUE_FIELDS},
            }
            row.update({f"{field}_literal": literal for field, literal in zip(fields, cells[2:], strict=True)})
            row_values(row)
            rows.append(row)
        require(count == spec["rows_per_page"][index], f"incomplete dated-row population on PDF page {pdf_page}")
        if footer_index is not None:
            footer_line = lines[footer_index]
            parts = list(re.finditer(r"\$([^$]+)", footer_line))
            require(len(parts) == len(footer_fields), "printed footer cell count differs")
            footer = {
                "pdf_page": pdf_page, "source_line": footer_index + 1, "raw_line_sha256": digest(footer_line.encode()),
                "cells": {field: part[1].strip() for field, part in zip(footer_fields, parts, strict=True)},
                "markers": [],
            }
            for field, part in zip(footer_fields, parts, strict=True):
                _, marker = number(part[1].strip(), annotated=True)
                if marker:
                    require(NOTE_ROLES[account].get(marker) == "other_recipients", "unknown footer annotation")
                    footer["markers"].append({"field": field, "marker": marker, "source_line": footer_index + 1,
                                              "raw_line_sha256": digest(footer_line.encode())})
            for n, line in enumerate(lines, 1):
                match = re.fullmatch(r"\s*(\[[1-4]\])\s*", line)
                if not match or n in consumed:
                    continue
                marker = match[1]
                column = line.index("[")
                if abs(n - (footer_index + 1)) <= 2 and column >= parts[0].start():
                    field_index = max(i for i, part in enumerate(parts) if part.start() <= column)
                    require(NOTE_ROLES[account].get(marker) == "other_recipients", "unrecognized detached footer annotation")
                    footer["markers"].append({"field": footer_fields[field_index], "marker": marker,
                                              "source_line": n, "raw_line_sha256": digest(line.encode())})
                else:
                    require(n > footer_index + 1 and marker in NOTE_ROLES[account], "unrecognized source footnote definition")
                    collected = []
                    for body in lines[n:]:
                        if not body.strip() or re.fullmatch(r"\s*\[[1-4]\]\s*", body) or body.strip().startswith("Note:"):
                            break
                        collected.append(body.strip())
                    normalized = " ".join(" ".join(collected).split())
                    role = NOTE_ROLES[account][marker]
                    require(digest(normalized.encode()) == NOTE_HASHES[role], "account-scoped footnote text differs")
                    require(marker not in accounts[account]["footnotes"], "duplicate source footnote definition")
                    accounts[account]["footnotes"][marker] = {
                        "fact_id": note_id(account, marker), "pdf_page": pdf_page, "source_line": n,
                        "text_source_lines": list(range(n + 1, n + 1 + len(collected))),
                        "normalized_text_sha256": digest(normalized.encode()), "role": role, "meaning": NOTE_MEANINGS[role],
                    }
                consumed.add(n)
            note_lines = [(n, line) for n, line in enumerate(lines, 1) if "Numbers might not add" in line]
            require(len(note_lines) == 1 and " ".join(note_lines[0][1].split()) == ROUNDING_NOTE, "missing or changed rounding note")
            accounts[account].update({
                "footer": footer, "pdf_pages": list(spec["pdf_pages"]), "rows_per_page": list(spec["rows_per_page"]),
                "source_column_count": spec["columns"], "row_count": sum(spec["rows_per_page"]),
                "headers": list(HEADERS if spec["columns"] == 12 else tuple(header for header in HEADERS if header != "90-Day Transfers")),
                "rounding_note": {"fact_id": f"{SOURCE_ID}:{account}:rounding-note", "pdf_page": pdf_page,
                                  "source_line": note_lines[0][0], "normalized_text_sha256": digest(ROUNDING_NOTE.encode()),
                                  "meaning": "The source attributes possible differences in displayed totals to rounding; the helper does not establish the cause independently."},
            })
        markers = {n for n, line in enumerate(lines, 1) if re.fullmatch(r"\s*\[[1-4]\]\s*", line)}
        require(markers == consumed, f"unattributed source marker on PDF page {pdf_page}")
    metadata = {
        "schema_version": 1, "source_id": SOURCE_ID, "source_url": SOURCE_URL,
        "source_bytes": SOURCE_BYTES, "source_sha256": SOURCE_SHA256,
        "enclosing_filing": {"case": "10-05279", "document": "150", "filed_on": "2017-10-30",
                             "description": "Published affidavit with an attached copy of the second amended complaint"},
        "embedded_filing": {"case": "10-05279", "document": "143-2", "filed_on": "2017-09-29", "exhibit": "B"},
        "pdf_pages": list(PDF_PAGES), "source_row_count": len(rows), "accounts": accounts,
        "extraction": {"command": "pdftotext -layout -f 112 -l 162 - - < <pinned.pdf>",
                       "authoring_version": "pdftotext version 24.02.0", "utf8_sha256": digest(text.encode()),
                       "page_utf8_sha256": page_hashes,
                       "line_hash_basis": "SHA-256 of the exact UTF-8 extraction line without its newline"},
        "printed_amount_unit": "USD whole dollars",
        "absent_column_rule": "Eleven-column accounts have no ninety-day column: its retained field is explicitly empty and decoded value None, never a fabricated source zero.",
        "star_rule": "Only 1FN037's footnote [4] gives the literal withdrawal star a derived zero principal contribution; reported withholding amounts survive separately.",
        "description_exception": {"source_row_id": PARTIAL_DESCRIPTION_ROW, "literal": "(1FN024)",
                                  "interpretation": "The source itself prints only the account annotation. Its reported-amount footnote [2] supplies the inward zero-principal interpretation; no description words are reconstructed."},
        "row_id_basis": "Source citation, not an original transaction identifier: source id, account, physical PDF page and extraction line.",
        "assertion_status": "trustee_computation in a complaint reproduced as an affidavit attachment; not a court finding",
        "redistribution_basis": "Factual transaction cells and citation metadata only; full source PDF and account-holder headers are not committed.",
        "scope": SCOPE,
    }
    verify_rows([row_values(row) for row in rows], metadata)
    return rows, metadata


def diagnostics(rows: list[dict], metadata: dict) -> dict:
    accounts = {}
    for account in ACCOUNTS:
        selected = [row for row in rows if row["account"] == account]
        running, gaps = 0, []
        totals = {field: 0 for field in value_fields(account)[1:] if field != "printed_balance"}
        for row in selected:
            running += row["principal_movement_cents"]
            require(abs(running) <= I128_MAX, "principal fold exceeds i128")
            gap = running - row["printed_balance_cents"]
            if gap:
                gaps.append({"row_id": row["row_id"], "gap_cents": gap})
            for field in totals:
                totals[field] += row[f"{field}_cents"]
                require(abs(totals[field]) <= I128_MAX, "column sum exceeds i128")
        footer = metadata["accounts"][account]["footer"]["cells"]
        footer_gaps = {field: actual - number(footer[field], annotated=True)[0]
                       for field, actual in {**totals, "printed_balance": running}.items()
                       if actual != number(footer[field], annotated=True)[0]}
        accounts[account] = {
            "rows": len(selected), "rows_off": len(gaps), "row_differences": gaps,
            "maximum_gap_cents": max((abs(gap["gap_cents"]) for gap in gaps), default=0),
            "closing_gap_cents": running - selected[-1]["printed_balance_cents"],
            "source_closing_balance_cents": running, "printed_closing_balance_cents": selected[-1]["printed_balance_cents"],
            "column_sums_cents": totals, "footer_gaps_cents": footer_gaps,
            "nonzero_principal_rows": sum(row["principal_movement_cents"] != 0 for row in selected),
            "starred_withdrawal_cells": sum(row["star"] for row in selected),
            "excluded_reported_cents": sum(row["excluded_reported_cents"] for row in selected),
            "positive_withdrawal_rows": [row["row_id"] for row in selected if row["withdrawals_cents"] > 0],
            "literal_trans_descriptions": sum(row["description"].startswith("TRANS ") for row in selected),
            "transfer_observations": sum(row["transfer_credit_role"] == "oracle_output" for row in selected),
            "rounding_note_premise": metadata["accounts"][account]["rounding_note"]["fact_id"],
        }
    return {"source_rows": len(rows), "source_accounts": len(accounts), "accounts": accounts,
            "starred_withdrawal_cells": sum(row["star"] for row in rows),
            "nonzero_principal_rows": sum(row["principal_movement_cents"] != 0 for row in rows),
            "zero_principal_rows": [row["row_id"] for row in rows if row["principal_movement_cents"] == 0],
            "transfer_observations": sum(row["transfer_credit_role"] == "oracle_output" for row in rows),
            "literal_trans_descriptions": sum(row["description"].startswith("TRANS ") for row in rows),
            "no_tolerance_or_adjustment": True}


def verify_rows(rows: list[dict], metadata: dict) -> dict:
    require(len(rows) == 2364 and len({row["row_id"] for row in rows}) == len(rows), "Magnify source census/identity differs")
    require([(row["pdf_page"], row["source_line"]) for row in rows] ==
            sorted((row["pdf_page"], row["source_line"]) for row in rows), "source page order changed")
    require(metadata.get("source_sha256") == SOURCE_SHA256 and metadata.get("source_bytes") == SOURCE_BYTES,
            "metadata binds another original source")
    require(set(metadata.get("accounts", {})) == set(ACCOUNTS), "metadata account population differs")
    for account, spec in ACCOUNTS.items():
        selected = [row for row in rows if row["account"] == account]
        require([row["date"] for row in selected] == sorted(row["date"] for row in selected), "account date order differs")
        for page, count in zip(spec["pdf_pages"], spec["rows_per_page"], strict=True):
            page_rows = [row for row in selected if row["pdf_page"] == page]
            require(len(page_rows) == count and [row["page_row"] for row in page_rows] == list(range(1, count + 1)),
                    f"incomplete source page {page}")
        meta = metadata["accounts"][account]
        require(set(meta["footnotes"]) == set(NOTE_ROLES[account]), "account-scoped footnote census differs")
        for marker, role in NOTE_ROLES[account].items():
            note = meta["footnotes"][marker]
            require(note.get("fact_id") == note_id(account, marker) and note.get("normalized_text_sha256") == NOTE_HASHES[role],
                    "source footnote premise differs")
        for row in selected:
            expected_notes = ([note_id(account, "[4]")] if row["star"] else [])
            if row["reported_marker"]:
                expected_notes.append(note_id(account, row["reported_marker"]))
            require(row["footnote_premises"] == expected_notes, "source row lacks its explicit footnote premises")
            require(row["transfer_credit_role"] == ("oracle_output" if row["transaction_kind"].startswith("transfer") else "not_applicable"),
                    "transfer principal lost its source-oracle label")
        require(meta["rounding_note"]["normalized_text_sha256"] == digest(ROUNDING_NOTE.encode()), "rounding-note premise differs")
        require(set(meta["footer"]["cells"]) == set(value_fields(account)[1:]), "footer layout differs")
    require(sum(row["star"] for row in rows) == STAR_COUNT, "starred-cell census differs from 717")
    return diagnostics(rows, metadata)


def load_fixture(directory: Path = FIXTURE_DIR) -> tuple[list[dict], dict]:
    raw, meta = (directory / "rows.csv").read_bytes(), (directory / "source.json").read_bytes()
    require(digest(raw) == ROWS_SHA256, "source rows SHA-256 differs from the committed pin")
    require(digest(meta) == METADATA_SHA256, "source metadata SHA-256 differs from the committed pin")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
    require(reader.fieldnames == list(ROW_COLUMNS), "retained CSV schema differs")
    rows, metadata = [row_values(row) for row in reader], json.loads(meta)
    verify_rows(rows, metadata)
    return rows, metadata


def computation_order(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda row: (row["date"], row["pdf_page"], row["source_line"]))


def verify_pdf(path: Path) -> bytes:
    require(path.stat().st_size == SOURCE_BYTES, "PDF byte count differs from the pinned original")
    raw = path.read_bytes()
    require(raw.startswith(b"%PDF-") and digest(raw) == SOURCE_SHA256, "PDF SHA-256 differs from the pinned original")
    return raw


def fetch(output: Path) -> None:
    require(not output.exists(), "download destination already exists")
    req = request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/pdf"})
    try:
        with request.build_opener(PinnedRedirect()).open(req, timeout=30) as response:
            require(response.status == 200, "expected complete HTTP 200 source response")
            raw = response.read(SOURCE_BYTES + 1)
    except (OSError, error.URLError) as exc:
        raise EnvironmentError(f"Magnify source download unavailable: {exc}") from exc
    require(len(raw) == SOURCE_BYTES and digest(raw) == SOURCE_SHA256, "download differs from the pinned original")
    with output.open("xb") as stream:
        stream.write(raw)


def extract_pdf(path: Path, *, layout_out: Path | None = None) -> tuple[bytes, bytes]:
    original = verify_pdf(path)
    try:
        result = subprocess.run(["pdftotext", "-layout", "-f", "112", "-l", "162", "-", "-"],
                                input=original, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EnvironmentError(f"pdftotext unavailable: {exc}; install Poppler; no retained-row fallback") from exc
    require(result.returncode == 0, "pdftotext could not extract the pinned source")
    if layout_out is not None:
        with layout_out.open("xb") as stream:
            stream.write(result.stdout)
    rows, metadata = parse_layout(result.stdout.decode("utf-8", errors="strict"))
    raw, meta = csv_bytes(ROW_COLUMNS, rows), json_bytes(metadata)
    require(digest(raw) == ROWS_SHA256 and digest(meta) == METADATA_SHA256,
            "extraction differs from reviewed source pins; investigate drift, never regenerate pins automatically")
    return raw, meta


def package_payloads(directory: Path) -> tuple[dict, dict[str, bytes]]:
    rows, metadata = load_fixture(directory)
    ordered = computation_order(rows)
    normalized, mappings, observations = [], [], []
    principals = {account: f"BLMIS-{account}" for account in ACCOUNTS}
    running = dict.fromkeys(ACCOUNTS, 0)
    for row in ordered:
        account, movement = row["account"], row["principal_movement_cents"]
        running[account] += movement
        observations.append({"source_row_id": row["row_id"], "account": account, "date": row["date"],
                             "posted": movement != 0, "star": row["star"], "footnote_premises": row["footnote_premises"],
                             "transfer_credit_role": row["transfer_credit_role"], "source_fold_cents": running[account],
                             "printed_balance_cents": row["printed_balance_cents"],
                             "source_fold_minus_printed_cents": running[account] - row["printed_balance_cents"]})
        if not movement:
            continue
        for code, amount in ((principals[account], -movement), (CASH_ACCOUNT, row["cash_movement_cents"]),
                             (TRANSFER_ACCOUNT, row["transfer_movement_cents"])):
            if not amount:
                continue
            normalized.append({"entry_id": row["row_id"], "effective_date": row["date"], "account_code": code,
                               "signed_amount": money(amount), "description": row["description"],
                               "memo": f"analysis counterpart; {SOURCE_ID} Exhibit B PDF p{row['pdf_page']} line {row['source_line']}",
                               "source_row": row["row_id"]})
        mappings.append({"entry_id": row["row_id"], "source_row_id": row["row_id"], "source_account": account,
                         "transfer_credit_role": row["transfer_credit_role"]})
    controls = {}
    for account in ACCOUNTS:
        selected = [row for row in rows if row["account"] == account]
        controls[account] = []
        for year in range(int(selected[0]["date"][:4]), int(selected[-1]["date"][:4]) + 1):
            control = last_printed_balance(selected, f"{year}-12-31")
            folded = sum(row["principal_movement_cents"] for row in selected if row["date"] <= control["at_date"])
            controls[account].append({"account": account, **control, "source_fold_cents": folded,
                                      "source_fold_minus_printed_cents": folded - control["printed_balance_cents"]})
    chart = {"accounts": [{"code": code, "name": f"Published principal {account} - analysis account", "type": "Equity", "unit": "USD"}
                          for account, code in principals.items()] + [
        {"code": CASH_ACCOUNT, "name": "Principal cash movements - analysis counterpart", "type": "Asset", "unit": "USD"},
        {"code": TRANSFER_ACCOUNT, "name": "Trustee-credited principal transfers - analysis clearing", "type": "Liability", "unit": "USD"},
    ]}
    payloads = {"rows.csv": (directory / "rows.csv").read_bytes(), "source.json": (directory / "source.json").read_bytes(),
                "legacy.csv": csv_bytes(LEGACY_COLUMNS, normalized), "column_map.toml": COLUMN_MAP.encode(),
                "chart.json": json_bytes(chart), "controls.json": json_bytes(controls), "observations.json": json_bytes(observations)}
    manifest = {"schema_version": 1, "source_system": SOURCE_SYSTEM, "scope": SCOPE,
                "source_sha256": SOURCE_SHA256, "source_rows_sha256": ROWS_SHA256,
                "source_rows": len(rows), "source_accounts": len(ACCOUNTS), "monetary_rows": len(mappings), "normalized_legs": len(normalized),
                "principal_accounts": principals, "row_mapping": mappings,
                "principal_posting_sign": "negative of trustee principal movement",
                "computation_order": [row["row_id"] for row in ordered], "posting_order": [row["entry_id"] for row in mappings],
                "zero_principal_rows": [row["row_id"] for row in ordered if row["principal_movement_cents"] == 0],
                "baseline": "Zero before each account's first source row, not a whole-firm opening trial balance.",
                "row_order": "Post by date, PDF page and line; each account retains its printed same-day order. No original transaction times are inferred.",
                "controls_basis": "Independently printed balances, with source folds and differences retained separately.",
                "source_diagnostics": verify_rows(rows, metadata),
                "outputs": {name: {"bytes": len(raw), "sha256": digest(raw)} for name, raw in payloads.items()}}
    payloads["manifest.json"] = json_bytes(manifest)
    return manifest, payloads


def prepare(output: Path, directory: Path = FIXTURE_DIR) -> dict:
    require(not output.exists(), "package destination already exists")
    manifest, payloads = package_payloads(directory)
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    return manifest


def prepare_pdf(output: Path, pdf: Path | None = None, *, on_created: Callable[[], None] | None = None) -> dict:
    require(not output.exists(), "package destination already exists")
    supplied = verify_pdf(pdf) if pdf is not None else None
    output.mkdir(parents=True, exist_ok=False)
    if on_created:
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
    extraction = {"format": "fa-blmis-magnify-pdf-extraction-v1", "mode": "original_pdf_extracted_this_run",
                  "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
                  "command": ["pdftotext", "-layout", "-f", "112", "-l", "162", "-", "-"],
                  "stdin": "The complete verified original PDF bytes, not an excerpt or reconstructed PDF.",
                  "pdf_pages": list(PDF_PAGES), "source_rows": manifest["source_rows"],
                  "reviewed_rows_sha256": ROWS_SHA256, "reviewed_metadata_sha256": METADATA_SHA256, "retained": retained}
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
    download = sub.add_parser("fetch")
    download.add_argument("--out", type=Path, required=True)
    extract = sub.add_parser("extract")
    extract.add_argument("--pdf", type=Path, required=True)
    extract.add_argument("--out", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--fixture", type=Path, default=FIXTURE_DIR)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--out", type=Path, required=True)
    select = prepare_parser.add_mutually_exclusive_group()
    select.add_argument("--pdf", type=Path)
    select.add_argument("--retained", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            fetch(args.out)
            result = {"source_bytes": SOURCE_BYTES, "source_sha256": SOURCE_SHA256}
        elif args.command == "extract":
            require(not args.out.exists(), "extraction destination already exists")
            raw, meta = extract_pdf(args.pdf)
            args.out.mkdir(parents=True, exist_ok=False)
            for name, value in (("rows.csv", raw), ("source.json", meta)):
                with (args.out / name).open("xb") as stream:
                    stream.write(value)
            result = verify_rows(*load_fixture(args.out))
        elif args.command == "verify":
            result = verify_rows(*load_fixture(args.fixture))
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
