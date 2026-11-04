#!/usr/bin/env python3
"""Reconcile original House disbursements and build an explicit analysis book.

Both full publisher files are hash pinned. Preparation selects every record of
one exact organization, including its inline controls, and retains all original
fields. The modeled counterpart is explicitly Equity, not inferred bank cash.
Only the real native replay can establish that FrankenAccounting processed it.
"""

from __future__ import annotations

import argparse
import calendar
from collections import Counter, defaultdict
import csv
import datetime as dt
from decimal import Decimal, localcontext
import io
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.parse
import urllib.request

# Shared, standard-library-only artifact and exact integer helpers.
import public_spend as common


DataError = common.DataError
json_bytes = common.json_bytes
jsonl_bytes = common.jsonl_bytes
sha256 = common.sha256
amount_text = common.amount_text
checked_minor = common.checked_minor
write_bundle = common.write_bundle
DEFAULT_MANIFEST = Path(__file__).with_name("house_sources.toml")
DEFAULT_ORGANIZATION = "FISCAL YEAR 2026 CHIEF ADMIN OFCR OF THE HOUSE"
MODEL = "house_published_disbursements_v1"
UNIT = "USD"
SCALE = 2
MAX_ROWS_PER_ENTRY = 12
OFFSET_ACCOUNT = "published-disbursement-offset"
MODEL_BOUNDARY = (
    "An expenditure analysis book of the complete selected published organization. "
    "Each nonzero DETAIL amount maps to an Expense account for its exact program "
    "and category, with an explicit modeled Equity counterpart. These are not the "
    "House's original journals, cash balances, opening balances, or full general "
    "ledger. Summary and subtotal rows are controls only, never monetary inputs. "
    "No original debit/credit counterpart, fiscal-year accrual, or undisclosed "
    "appropriation identity is inferred."
)
DATE_POLICY = (
    "Use a nonblank published TRANSACTION DATE only when it falls inside the "
    "publication quarter. A blank GL TRANSACTION DATE is assigned the quarter's "
    "last day solely for this analysis book. Original blanks and service-period "
    "dates remain unchanged in retained evidence. Service dates never substitute "
    "for transaction dates; no monthly distribution of undated payroll is inferred. "
    "A malformed service-date literal remains unparsed with an explicit diagnostic. "
    "Published two-digit years are interpreted as 2000 through 2099 in this source."
)
SECTION_POLICY = (
    "Publication sections are numbered in the original order within one exact "
    "organization and end at its printed OFFICE TOTALS. Corresponding detail and "
    "summary sections must agree on their complete category, program, and office "
    "controls. Repeated labels in separate sections remain distinct controls and "
    "are aggregated only for the explicitly declared program/category accounts. "
    "A repeated control key within a section is refused as ambiguous."
)
DETAIL_HEADERS = (
    "ORGANIZATION", "FISCAL YEAR OR LEGISLATIVE YEAR", "ORGANIZATION CODE",
    "PROGRAM", "PROGRAM CODE", "SORT SUBTOTAL DESCRIPTION", "BUDGET OBJECT CLASS",
    "SORT SEQUENCE", "TRANSACTION DATE", "DATA SOURCE", "DOCUMENT", "VENDOR NAME",
    "VENDOR ID", "PERFORM START DT", "PERFORM END DT", "DESCRIPTION",
    "BUDGET OBJECT CODE", "AMOUNT",
)
SUMMARY_HEADERS = ("ORGANIZATION", "PROGRAM", "DESCRIPTION", "YTD AMOUNT", "QTD AMOUNT")
ROW_KINDS = {"DETAIL", "SUBTOTAL", "GRAND TOTAL FOR ORGANIZATION"}
MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}
AMOUNT = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?\Z", re.ASCII)
SOURCE_DATE = re.compile(r"([0-9]{1,2})-([A-Z][a-z]{2})-([0-9]{2})\Z", re.ASCII)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DataError(message)


def house_url(url: str) -> str:
    common.https_url(url)
    parsed = urllib.parse.urlsplit(url)
    try:
        permitted = parsed.hostname in {"www.house.gov", "house.gov"} and parsed.port in (None, 443)
    except ValueError as error:
        raise DataError("invalid House source URL port") from error
    require(permitted, "source and redirects must remain on the House HTTPS publisher")
    return url


def validate_spec(spec: dict) -> None:
    require(spec.get("schema_version") == 1, "unsupported House source manifest")
    require(isinstance(spec.get("id"), str)
            and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", spec["id"]) is not None,
            "invalid House dataset identity")
    require(spec.get("encoding") == "utf-8", "House publication encoding must be explicitly UTF-8")
    try:
        start = dt.date.fromisoformat(spec["period_start"])
        end = dt.date.fromisoformat(spec["period_end"])
    except (KeyError, ValueError, TypeError) as error:
        raise DataError("invalid publication quarter") from error
    require(start == dt.date(2026, 4, 1) and end == dt.date(2026, 7, 1),
            "this adapter's reviewed date and reporting contract is 2026 Q2")
    for kind in ("detail", "summary"):
        item = spec.get(kind, {})
        require(isinstance(item.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                f"{kind} requires a pinned SHA-256")
        length, maximum = item.get("byte_length"), item.get("max_bytes")
        require(type(length) is int and type(maximum) is int
                and 0 < length <= maximum <= 32 * 1024 * 1024,
                f"{kind} requires a positive bounded byte count")
        house_url(item["url"])
    require(isinstance(spec.get("controls"), dict) and bool(spec["controls"]),
            "complete source census controls are required")


def load_spec(manifest: Path = DEFAULT_MANIFEST) -> dict:
    with Path(manifest).open("rb") as stream:
        spec = tomllib.load(stream)
    validate_spec(spec)
    return spec


def verify_source(raw: bytes, kind: str, spec: dict) -> None:
    require(kind in ("detail", "summary"), "unknown House source kind")
    declaration = spec[kind]
    require(len(raw) == declaration["byte_length"], f"{kind} source byte count mismatch")
    require(sha256(raw) == declaration["sha256"], f"{kind} source SHA-256 mismatch")


class HouseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        house_url(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def acquire_source(kind: str, spec: dict, path: Path | None = None) -> bytes:
    """Bound and authenticate actual bytes before any normalized output exists."""
    validate_spec(spec)
    item = spec[kind]
    if path is not None:
        require(not Path(path).is_symlink(), f"{kind} source must not be a symlink")
        with Path(path).open("rb") as stream:
            raw = stream.read(item["max_bytes"] + 1)
    else:
        request = urllib.request.Request(house_url(item["url"]), headers={
            "User-Agent": common.USER_AGENT, "Accept": "text/csv",
        })
        opener = urllib.request.build_opener(HouseRedirects())
        with opener.open(request, timeout=45) as response:
            house_url(response.geturl())
            require(response.status == 200, f"{kind} requires a complete HTTP 200 response")
            raw = response.read(item["max_bytes"] + 1)
    verify_source(raw, kind, spec)
    return raw


def parse_minor(value: str) -> int:
    """Accept only the publisher's plain dollars with zero, one or two decimals."""
    require(isinstance(value, str) and len(value) <= 64 and AMOUNT.fullmatch(value) is not None,
            f"invalid published dollar amount {value!r}")
    whole, _, fraction = value.removeprefix("-").partition(".")
    magnitude = int(whole) * 100 + int((fraction + "00")[:2])
    return checked_minor(-magnitude if value.startswith("-") else magnitude)


def reference_minor(value: str) -> int:
    """Independent Decimal fold of the original literal, never normalized CSV."""
    with localcontext() as context:
        context.prec = 100
        cents = Decimal(value) * 100
        require(cents.is_finite() and cents == cents.to_integral_value(),
                "reference source amount is not exact integer cents")
        return checked_minor(int(cents))


def source_date(value: str) -> str | None:
    if not value.strip():
        return None
    match = SOURCE_DATE.fullmatch(value)
    require(match is not None, f"invalid published date {value!r}")
    day, month, year = match.groups()
    require(month in MONTHS, f"unknown source month {month!r}")
    try:
        return dt.date(2000 + int(year), MONTHS[month], int(day)).isoformat()
    except ValueError as error:
        raise DataError(f"invalid published calendar date {value!r}") from error


def effective_date(fields: dict, spec: dict) -> tuple[str, str]:
    date = source_date(fields["TRANSACTION DATE"])
    if date is not None:
        require(spec["period_start"] <= date < spec["period_end"],
                f"published transaction date {date} is outside the quarter; no redating is allowed")
        return date, "published_transaction_date"
    require(fields["DATA SOURCE"] == "GL", "only the published undated GL stream has a reviewed date policy")
    return (dt.date.fromisoformat(spec["period_end"]) - dt.timedelta(days=1)).isoformat(), "undated_gl_quarter_end"


def service_date(value: str) -> dict:
    """Preserve non-accounting date defects; never repair or silently coerce them."""
    try:
        date = source_date(value)
        return {"literal": value, "parsed_iso": date, "status": "blank" if date is None else "parsed"}
    except DataError as error:
        return {"literal": value, "parsed_iso": None, "status": "unparsed_as_published", "reason": str(error)}


def decode_records(raw: bytes, kind: str, spec: dict) -> list[dict]:
    verify_source(raw, kind, spec)
    expected_headers = DETAIL_HEADERS if kind == "detail" else SUMMARY_HEADERS
    try:
        reader = csv.reader(io.StringIO(raw.decode(spec["encoding"], errors="strict"), newline=""), strict=True)
        original_headers = next(reader)
        headers = tuple(value.strip() for value in original_headers)
        require(headers == expected_headers, f"{kind} source header drift")
        result = []
        previous_line = reader.line_num
        for ordinal, fields in enumerate(reader, 1):
            require(len(fields) == len(headers), f"{kind} record {ordinal} has an incorrect field count")
            require(all("\0" not in value for value in fields), f"{kind} record {ordinal} contains NUL")
            original = dict(zip(headers, fields, strict=True))
            require(bool(original["ORGANIZATION"].strip()), f"{kind} record {ordinal} lacks an organization")
            amounts = ("AMOUNT",) if kind == "detail" else ("QTD AMOUNT", "YTD AMOUNT")
            for column in amounts:
                require(parse_minor(original[column]) == reference_minor(original[column]),
                        f"{kind} record {ordinal}: integer and Decimal source amounts disagree")
            if kind == "detail":
                require(original["SORT SEQUENCE"] in ROW_KINDS,
                        f"detail record {ordinal}: unsupported source row kind")
                if original["SORT SEQUENCE"] == "DETAIL":
                    require(original["DATA SOURCE"] in {"AP", "AR", "GL"},
                            f"detail record {ordinal}: unknown data source stream")
            result.append({
                "row_id": f"{spec['id']}:{kind}:{spec[kind]['sha256'][:16]}:{ordinal:06}",
                "source_kind": kind, "source_sha256": spec[kind]["sha256"],
                "record_ordinal": ordinal, "physical_line_start": previous_line + 1,
                "physical_line_end": reader.line_num,
                "record_sha256": sha256(json_bytes({"headers": original_headers, "fields": fields})),
                "raw_fields": original,
            })
            previous_line = reader.line_num
        return result
    except (UnicodeError, csv.Error, StopIteration) as error:
        raise DataError(f"{kind} source encoding or CSV structure is invalid") from error


def source_census(detail: list[dict], summary: list[dict], spec: dict) -> dict:
    rows = [row["raw_fields"] for row in detail]
    activity = [row for row in rows if row["SORT SEQUENCE"] == "DETAIL"]
    amounts = [reference_minor(row["AMOUNT"]) for row in activity]
    # The full publication is retained even when an unselected organization
    # contains a malformed date. Its diagnostic is explicit in profile(); the
    # required accounting date is enforced when that organization is prepared.
    dates = [service_date(row["TRANSACTION DATE"])["parsed_iso"] for row in activity]
    result = {
        "record_count": len(rows), "detail_rows": len(activity),
        "subtotal_rows": sum(row["SORT SEQUENCE"] == "SUBTOTAL" for row in rows),
        "office_total_rows": sum(row["SORT SEQUENCE"] == "GRAND TOTAL FOR ORGANIZATION" for row in rows),
        "summary_rows": len(summary), "organization_count": len({row["ORGANIZATION"] for row in activity}),
        "positive_rows": sum(value > 0 for value in amounts),
        "negative_rows": sum(value < 0 for value in amounts),
        "zero_rows": sum(value == 0 for value in amounts),
        "positive_minor": str(checked_minor(sum(value for value in amounts if value > 0))),
        "negative_minor": str(checked_minor(sum(value for value in amounts if value < 0))),
        "net_minor": str(checked_minor(sum(amounts))),
        "duplicate_detail_rows": len(activity) - len({tuple(row.values()) for row in activity}),
        "missing_transaction_dates": sum(not row["TRANSACTION DATE"].strip() for row in activity),
        "outside_quarter_transaction_dates": sum(
            date is not None and not spec["period_start"] <= date < spec["period_end"] for date in dates
        ),
        "unparsed_service_dates": sum(service_date(row[column])["status"] == "unparsed_as_published"
                                      for row in activity for column in ("PERFORM START DT", "PERFORM END DT")),
        "data_sources": dict(sorted(Counter(row["DATA SOURCE"] for row in activity).items())),
    }
    require(result == spec["controls"], "full source census differs from independently pinned controls")
    return result


def read_sources(detail: bytes, summary: bytes, spec: dict) -> tuple[list[dict], list[dict], dict]:
    validate_spec(spec)
    detail_rows = decode_records(detail, "detail", spec)
    summary_rows = decode_records(summary, "summary", spec)
    return detail_rows, summary_rows, source_census(detail_rows, summary_rows, spec)


def date_diagnostics(detail: list[dict], spec: dict) -> list[dict]:
    """Retain precise citations for date anomalies without correcting literals."""
    result = []
    for record in detail:
        fields = record["raw_fields"]
        if fields["SORT SEQUENCE"] != "DETAIL":
            continue
        for column in ("TRANSACTION DATE", "PERFORM START DT", "PERFORM END DT"):
            parsed = service_date(fields[column])
            classification = None
            if parsed["status"] == "unparsed_as_published":
                classification = "unparsed_transaction_date" if column == "TRANSACTION DATE" else "unparsed_service_date"
            elif column == "TRANSACTION DATE" and parsed["parsed_iso"] is not None \
                    and not spec["period_start"] <= parsed["parsed_iso"] < spec["period_end"]:
                classification = "transaction_date_outside_publication_quarter"
            if classification is not None:
                result.append({"row_id": record["row_id"], "record_ordinal": record["record_ordinal"],
                               "organization": fields["ORGANIZATION"], "column": column,
                               "classification": classification, **parsed})
    return result


def _classification(record: dict) -> str:
    fields = record["raw_fields"]
    if record["source_kind"] == "detail":
        if fields["SORT SEQUENCE"] == "DETAIL":
            return "detail"
        if fields["SORT SEQUENCE"] == "GRAND TOTAL FOR ORGANIZATION":
            require(fields["DESCRIPTION"].strip() == "OFFICE TOTALS:", "unknown detail office total label")
            return "office"
        category = fields["DESCRIPTION"].strip() == fields["SORT SUBTOTAL DESCRIPTION"] + " TOTALS:"
        program = fields["DESCRIPTION"].strip() == fields["PROGRAM"] + " TOTALS:"
        require(category != program, f"ambiguous or unknown inline subtotal at {record['row_id']}")
        return "category" if category else "program"
    description = fields["DESCRIPTION"].strip()
    if description == "OFFICE TOTALS:":
        return "office"
    if description == fields["PROGRAM"] + " TOTALS:":
        return "program"
    require(not description.endswith("TOTALS:"), f"unknown summary total label at {record['row_id']}")
    return "category"


def _sections(records: list[dict]) -> list[list[dict]]:
    sections: list[list[dict]] = []
    current: list[dict] = []
    for record in records:
        record["control_kind"] = _classification(record)
        record["publication_section"] = len(sections) + 1
        current.append(record)
        if record["control_kind"] == "office":
            sections.append(current)
            current = []
    require(not current, "organization has an unterminated publication section without OFFICE TOTALS")
    require(bool(sections), "organization has no complete publication section")
    return sections


def _control_map(rows: list[dict], kind: str) -> dict:
    result = {}
    for record in rows:
        if record["control_kind"] != kind:
            continue
        fields = record["raw_fields"]
        key = fields["PROGRAM"]
        if kind == "category":
            key = (key, fields["SORT SUBTOTAL DESCRIPTION"] if record["source_kind"] == "detail"
                   else fields["DESCRIPTION"])
        require(key not in result, f"ambiguous repeated {kind} control within publication section: {key!r}")
        result[key] = record
    return result


def _control_minor(record: dict) -> int:
    column = "AMOUNT" if record["source_kind"] == "detail" else "QTD AMOUNT"
    return reference_minor(record["raw_fields"][column])


def reconcile_organization(detail: list[dict], summary: list[dict], organization: str) -> tuple[list[dict], list[dict], dict]:
    """Compare every selected publisher category/program/office control exactly.

    No summary row is silently deduplicated. Zero-QTD summary-only categories
    survive with their YTD literal, but do not manufacture source activity.
    """
    selected = [dict(row) for row in detail if row["raw_fields"]["ORGANIZATION"] == organization]
    summaries = [dict(row) for row in summary if row["raw_fields"]["ORGANIZATION"] == organization]
    require(bool(selected) and bool(summaries), "exact organization must occur in both complete publications")
    dsections, ssections = _sections(selected), _sections(summaries)
    require(len(dsections) == len(ssections), "detail and summary have different office-section populations")
    checks = []
    category_qtd: dict[tuple[str, str], int] = defaultdict(int)
    for index, (drows, srows) in enumerate(zip(dsections, ssections, strict=True), 1):
        movements: dict[tuple[str, str], int] = defaultdict(int)
        citations: dict[tuple[str, str], list[str]] = defaultdict(list)
        for record in drows:
            if record["control_kind"] == "detail":
                fields = record["raw_fields"]
                key = fields["PROGRAM"], fields["SORT SUBTOTAL DESCRIPTION"]
                require(all(value.strip() for value in key), "detail program/category must be nonblank")
                movements[key] += reference_minor(fields["AMOUNT"])
                citations[key].append(record["row_id"])
        dcategory, scategory = _control_map(drows, "category"), _control_map(srows, "category")
        dprogram, sprogram = _control_map(drows, "program"), _control_map(srows, "program")
        require(set(movements) <= set(dcategory), "source detail has a missing inline category subtotal")
        require(set(dcategory) <= set(scategory), "inline category has no independent summary control")
        for key in sorted(set(movements) | set(dcategory) | set(scategory)):
            observed = checked_minor(movements.get(key, 0))
            expected = _control_minor(scategory[key])
            if key in dcategory:
                require(_control_minor(dcategory[key]) == observed,
                        f"inline category subtotal discrepancy in section {index}: {key!r}")
            require(observed == expected,
                    f"independent summary category discrepancy in section {index}: {key!r}; "
                    f"detail={observed}, summary={expected} cents")
            category_qtd[key] = checked_minor(category_qtd[key] + expected)
            checks.append({"kind": "category", "publication_section": index,
                           "program": key[0], "category": key[1],
                           "detail_row_ids": citations.get(key, []),
                           "inline_row_id": dcategory[key]["row_id"] if key in dcategory else None,
                           "summary_row_id": scategory[key]["row_id"],
                           "detail_minor": str(observed), "summary_qtd_minor": str(expected),
                           "difference_minor": "0", "summary_only_zero": key not in movements})
        movement_programs: dict[str, int] = defaultdict(int)
        summary_programs: dict[str, int] = defaultdict(int)
        for (program, _), amount in movements.items():
            movement_programs[program] += amount
        for (program, _), row in scategory.items():
            summary_programs[program] += _control_minor(row)
        require(set(movement_programs) <= set(dprogram), "source detail has a missing inline program subtotal")
        require(set(dprogram) <= set(sprogram), "inline program has no independent summary control")
        require(set(summary_programs) == set(sprogram), "summary program and category populations differ")
        for program in sorted(set(movement_programs) | set(dprogram) | set(sprogram)):
            observed = checked_minor(movement_programs.get(program, 0))
            expected = _control_minor(sprogram[program])
            require(summary_programs[program] == expected,
                    f"independent summary program does not foot in section {index}: {program!r}")
            if program in dprogram:
                require(_control_minor(dprogram[program]) == observed,
                        f"inline program subtotal discrepancy in section {index}: {program!r}")
            require(observed == expected,
                    f"independent summary program discrepancy in section {index}: {program!r}")
            checks.append({"kind": "program", "publication_section": index, "program": program,
                           "inline_row_id": dprogram[program]["row_id"] if program in dprogram else None,
                           "summary_row_id": sprogram[program]["row_id"], "detail_minor": str(observed),
                           "summary_qtd_minor": str(expected), "difference_minor": "0"})
        observed = checked_minor(sum(movements.values()))
        expected = _control_minor(srows[-1])
        require(_control_minor(drows[-1]) == observed, f"inline OFFICE TOTALS discrepancy in section {index}")
        require(sum(summary_programs.values()) == expected,
                f"independent summary OFFICE TOTALS does not foot in section {index}")
        require(observed == expected, f"independent OFFICE TOTALS discrepancy in section {index}")
        checks.append({"kind": "office", "publication_section": index,
                       "inline_row_id": drows[-1]["row_id"], "summary_row_id": srows[-1]["row_id"],
                       "detail_minor": str(observed), "summary_qtd_minor": str(expected), "difference_minor": "0"})
    return selected, summaries, {
        "organization": organization, "section_policy": SECTION_POLICY,
        "publication_sections": len(dsections), "checks": checks,
        "category_qtd": [{"program": key[0], "category": key[1], "qtd_minor": str(amount)}
                         for key, amount in sorted(category_qtd.items())],
        "qtd_net_minor": str(checked_minor(sum(category_qtd.values()))),
        "claim_boundary": "Exact agreement of published detail with published controls; no audit opinion or complete-GL claim.",
    }


def expense_account(program: str, category: str) -> str:
    return "expense-" + sha256(json_bytes([MODEL, program, category]))[:16]


def _account_cells(movement: dict, summary_net: dict | None = None) -> list[dict]:
    result = []
    for account, (debit, credit) in sorted(movement.items()):
        net = debit - credit if summary_net is None else summary_net[account]
        require(net == debit - credit, "source detail gross activity differs from independent published net")
        result.append({"account": account, "debit_minor": str(checked_minor(debit)),
                       "credit_minor": str(checked_minor(credit)), "signed_minor": str(checked_minor(net)),
                       "balance_debit_minor": str(max(net, 0)), "balance_credit_minor": str(max(-net, 0))})
    return result


def _selected_stats(records: list[dict]) -> dict:
    fields = [record["raw_fields"] for record in records if record["control_kind"] == "detail"]
    values = [reference_minor(row["AMOUNT"]) for row in fields]
    documents = [row["DOCUMENT"] for row in fields if row["DOCUMENT"].strip()]
    return {
        "row_count": len(fields), "retained_detail_file_records": len(records),
        "positive_rows": sum(value > 0 for value in values),
        "negative_rows": sum(value < 0 for value in values), "zero_rows": values.count(0),
        "positive_minor": str(checked_minor(sum(value for value in values if value > 0))),
        "negative_minor": str(checked_minor(sum(value for value in values if value < 0))),
        "net_minor": str(checked_minor(sum(values))),
        "duplicate_detail_rows": len(fields) - len({tuple(row.values()) for row in fields}),
        "missing_transaction_dates": sum(not row["TRANSACTION DATE"].strip() for row in fields),
        "nonblank_document_rows": len(documents), "distinct_nonblank_documents": len(set(documents)),
        "data_sources": dict(sorted(Counter(row["DATA SOURCE"] for row in fields).items())),
        "program_count": len({row["PROGRAM"] for row in fields}),
        "budget_object_code_count": len({row["BUDGET OBJECT CODE"] for row in fields}),
        "organization_codes": sorted({row["ORGANIZATION CODE"] for row in fields}),
        "fiscal_or_legislative_years": sorted({row["FISCAL YEAR OR LEGISLATIVE YEAR"] for row in fields}),
        "unparsed_service_dates": sum(service_date(row[column])["status"] == "unparsed_as_published"
                                      for row in fields for column in ("PERFORM START DT", "PERFORM END DT")),
    }


def build_bundle(detail: bytes, summary: bytes, organization: str = DEFAULT_ORGANIZATION,
                 *, spec: dict | None = None) -> dict[str, bytes]:
    """Return the complete immutable preparation; all accounting is still unrun."""
    spec = load_spec() if spec is None else spec
    all_detail, all_summary, census = read_sources(detail, summary, spec)
    records, summaries, controls = reconcile_organization(all_detail, all_summary, organization)
    pairs = {(row["program"], row["category"]): expense_account(row["program"], row["category"])
             for row in controls["category_qtd"]}
    require(len(set(pairs.values())) == len(pairs), "program/category account identity collision")
    stats = _selected_stats(records)
    require(len(stats["organization_codes"]) == 1 and len(stats["fiscal_or_legislative_years"]) == 1,
            "exact organization label has ambiguous native organization or fiscal-year identities")
    source_system = f"house-sod:{spec['id']}:{sha256(organization.encode())[:16]}"
    grouped: dict[str, list[dict]] = defaultdict(list)
    oracle_rows = []
    for record in records:
        fields = record["raw_fields"]
        kind = record["control_kind"]
        record.update(disposition=f"unposted_{kind}_control", effective_date=None, date_policy=None,
                      amount_minor=str(parse_minor(fields["AMOUNT"])), expense_account=None)
        if kind != "detail":
            continue
        date, policy = effective_date(fields, spec)
        amount = parse_minor(fields["AMOUNT"])
        account = pairs[fields["PROGRAM"], fields["SORT SUBTOTAL DESCRIPTION"]]
        record.update(disposition="posted" if amount else "unposted_zero", effective_date=date,
                      date_policy=policy, expense_account=account,
                      service_period_start=service_date(fields["PERFORM START DT"]),
                      service_period_end=service_date(fields["PERFORM END DT"]))
        if amount:
            grouped[date].append(record)
        # Each oracle amount is independently read from the untouched publisher
        # literal. No generated leg, normalizer sign, or manifest total is input.
        oracle_date, _ = effective_date(fields, spec)
        oracle_rows.append((oracle_date, account, reference_minor(fields["AMOUNT"])))
    generated = io.StringIO(newline="")
    writer = csv.writer(generated, lineterminator="\n")
    writer.writerow(["entry_id", "effective_date", "account_code", "side", "amount", "currency", "description", "memo"])
    entries = []
    links = {}
    for date, dated in sorted(grouped.items()):
        for part, start in enumerate(range(0, len(dated), MAX_ROWS_PER_ENTRY), 1):
            batch = dated[start:start + MAX_ROWS_PER_ENTRY]
            entry_id = f"house26q2-{sha256(organization.encode())[:8]}-{spec['detail']['sha256'][:12]}-{date}-{part:04}"
            description = f"House published expenditure analysis; {date}; part {part}"
            entries.append({"entry_id": entry_id, "effective_date": date,
                            "source_row_ids": [row["row_id"] for row in batch]})
            for position, row in enumerate(batch):
                amount = int(row["amount_minor"])
                memo = f"source_row={row['row_id']}"
                for account, side in ((row["expense_account"], "D" if amount > 0 else "C"),
                                      (OFFSET_ACCOUNT, "C" if amount > 0 else "D")):
                    writer.writerow([entry_id, date, account, side, amount_text(abs(amount)), UNIT, description, memo])
                links[row["row_id"]] = {"entry_id": entry_id, "expense_leg_ordinal": position * 2 + 1,
                                       "offset_leg_ordinal": position * 2 + 2}
    chart = {"accounts": [
        {"code": OFFSET_ACCOUNT, "name": "Modeled House disbursement offset (not bank cash)", "type": "Equity", "unit": UNIT},
        *[{"code": account, "name": f"Published expenditure: {program} / {category}", "type": "Expense", "unit": UNIT}
          for (program, category), account in sorted(pairs.items(), key=lambda item: item[1])],
    ]}
    # Quarter-end account NET controls come from the separate publisher SUMMARY
    # file. Its printed YTD figures are retained but are not treated as QTD.
    summary_net = {pairs[row["program"], row["category"]]: int(row["qtd_minor"])
                   for row in controls["category_qtd"]}
    summary_net[OFFSET_ACCOUNT] = -checked_minor(sum(summary_net.values()))
    monthly = []
    for month in range(4, 13):
        at_date = dt.date(2026, month, calendar.monthrange(2026, month)[1]).isoformat()
        movement = {account["code"]: [0, 0] for account in chart["accounts"]}
        for date, account, amount in oracle_rows:
            if date <= at_date:
                movement[account][0] += max(amount, 0)
                movement[account][1] += max(-amount, 0)
                movement[OFFSET_ACCOUNT][0] += max(-amount, 0)
                movement[OFFSET_ACCOUNT][1] += max(amount, 0)
        accounts = _account_cells(movement, summary_net if month >= 6 else None)
        monthly.append({
            "period": f"FY2026-P{month:02}", "at_date": at_date,
            "source_activity_through": min(at_date, "2026-06-30"),
            "net_control_basis": "independent_published_summary_qtd" if month >= 6 else "original_dated_detail_decimal_fold",
            "carry_only": month > 6,
            "scope": "Only this Q2 publication is loaded; later months carry its activity and assert no later real-world completeness.",
            "accounts": accounts,
            "lines": [{"account": row["account"], "unit": UNIT, "net": amount_text(int(row["signed_minor"]))}
                      for row in accounts],
        })
    expected = {
        "model": MODEL, "model_boundary": MODEL_BOUNDARY, "date_policy": DATE_POLICY,
        "dataset_id": spec["id"], "organization": organization, "source_system": source_system,
        "unit": UNIT, "scale": SCALE, "period_start": spec["period_start"], "period_end": spec["period_end"],
        "opening_date": "2027-01-01", "source_sha256": spec["detail"]["sha256"],
        "summary_sha256": spec["summary"]["sha256"], "source_stats": stats,
        "accounts": monthly[2]["accounts"], "controls": monthly,
        "entry_count": len(entries), "leg_count": len(links) * 2, "posted_row_count": len(links),
        "zero_row_count": stats["zero_rows"], "entries": entries,
        "source_documents": {kind: {**spec[kind], "mime": "text/csv;charset=utf-8"} for kind in ("detail", "summary")},
    }
    provenance = [{
        **row, "offset_account": OFFSET_ACCOUNT if row["control_kind"] == "detail" else None,
        **links.get(row["row_id"], {"entry_id": None, "expense_leg_ordinal": None, "offset_leg_ordinal": None}),
    } for row in records]
    columns = (
        '[columns]\n'
        f'source_system = "{source_system}"\n'
        'default_unit = "USD"\n'
        'entry_id_column = "entry_id"\n'
        'effective_date_column = "effective_date"\n'
        'account_column = "account_code"\n'
        'side_column = "side"\n'
        'amount_column = "amount"\n'
        'unit_column = "currency"\n'
        'description_column = "description"\n'
        'memo_column = "memo"\n'
    )
    files = {
        "raw-detail.csv": detail, "raw-summary.csv": summary,
        "records.jsonl": jsonl_bytes(records), "summary-records.jsonl": jsonl_bytes(summaries),
        "provenance.jsonl": jsonl_bytes(provenance), "controls.json": json_bytes(controls),
        "chart.json": json_bytes(chart),
        "account_map.json": json_bytes({row["code"]: row["code"] for row in chart["accounts"]}),
        "legacy.csv": generated.getvalue().encode("utf-8"), "columns.toml": columns.encode(),
        "expected_tb.json": json_bytes(expected),
    }
    files["receipt.json"] = json_bytes({
        "schema_version": 1, "model": MODEL, "model_boundary": MODEL_BOUNDARY,
        "date_policy": DATE_POLICY, "section_policy": SECTION_POLICY,
        "dataset_id": spec["id"], "organization": organization,
        "publisher": spec["publisher"], "publication_url": spec["publication_url"],
        "terms_url": spec["terms_url"], "source_encoding": spec["encoding"],
        "sources": {kind: spec[kind] for kind in ("detail", "summary")},
        "full_source_census": census, "source_stats": stats,
        "retained_summary_records": len(summaries), "max_source_rows_per_entry": MAX_ROWS_PER_ENTRY,
        "source_identity_policy": "Original file SHA-256 and CSV record ordinal identify each row. Document IDs and identical fields are never deduplicated.",
        "record_digest_policy": "SHA-256 of UTF-8 JSON containing original header strings and decoded field strings; not a raw byte-slice hash.",
        "header_policy": "Only header padding is stripped for field keys. Complete original headers and field bytes remain in the pinned raw publications.",
        "entry_group_policy": "At most 12 nonzero source rows with one analysis effective date; deterministic analysis grouping, not original journal membership.",
        "native_validation": "UNRUN: preparation and publisher controls do not establish native accounting execution.",
        "files": {name: {"sha256": sha256(value), "bytes": len(value)} for name, value in sorted(files.items())},
    })
    return files


def verify_prepared(directory: Path, organization: str = DEFAULT_ORGANIZATION, *, spec: dict | None = None) -> dict:
    """Rebuild from both pinned originals and compare every byte of preparation."""
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "prepared directory must be a real directory")
    spec = load_spec() if spec is None else spec
    detail = acquire_source("detail", spec, directory / "raw-detail.csv")
    summary = acquire_source("summary", spec, directory / "raw-summary.csv")
    expected_files = build_bundle(detail, summary, organization, spec=spec)
    require({path.name for path in directory.iterdir()} == set(expected_files), "prepared file population differs from complete source regeneration")
    for name, expected in expected_files.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == expected,
                f"prepared file differs from pinned-source regeneration: {name}")
    return json.loads(expected_files["expected_tb.json"])


def profile(detail: bytes, summary: bytes, *, spec: dict | None = None) -> dict:
    """Census every organization, including unsupported structure and differences."""
    spec = load_spec() if spec is None else spec
    drows, srows, census = read_sources(detail, summary, spec)
    details: dict[str, list[dict]] = defaultdict(list)
    summaries: dict[str, list[dict]] = defaultdict(list)
    for row in drows:
        details[row["raw_fields"]["ORGANIZATION"]].append(row)
    for row in srows:
        summaries[row["raw_fields"]["ORGANIZATION"]].append(row)
    organizations = []
    for name in sorted(set(details) | set(summaries)):
        value = {"organization": name, "detail_file_rows": len(details[name]), "summary_file_rows": len(summaries[name])}
        try:
            selected, _, controls = reconcile_organization(details[name], summaries[name], name)
            value.update(source_stats=_selected_stats(selected), publisher_controls="PASS",
                         publisher_control_count=len(controls["checks"]), publication_sections=controls["publication_sections"])
            try:
                for row in selected:
                    if row["control_kind"] == "detail":
                        effective_date(row["raw_fields"], spec)
                value["date_policy"] = "ADMISSIBLE"
            except DataError as error:
                value.update(date_policy="REFUSED", date_reason=str(error))
        except DataError as error:
            value.update(publisher_controls="REFUSED", reason=str(error))
        organizations.append(value)
    return {"dataset_id": spec["id"], "sources": {kind: spec[kind] for kind in ("detail", "summary")},
            "full_source_census": census, "organizations": organizations,
            "source_date_diagnostics": date_diagnostics(drows, spec),
            "native_validation": "UNRUN", "model_boundary": MODEL_BOUNDARY}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="acquire and verify both complete pinned publisher files")
    fetch.add_argument("--out", type=Path, required=True)
    inspect = sub.add_parser("profile", help="check the full population without hiding discrepancies")
    prepare = sub.add_parser("prepare", help="prepare every source row of one exact organization")
    for command in (inspect, prepare):
        command.add_argument("--detail", type=Path, required=True)
        command.add_argument("--summary", type=Path, required=True)
    prepare.add_argument("--organization", default=DEFAULT_ORGANIZATION)
    prepare.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("verify", help="regenerate and compare an existing prepared directory")
    check.add_argument("--prepared", type=Path, required=True)
    check.add_argument("--organization", default=DEFAULT_ORGANIZATION)
    args = parser.parse_args(argv)
    try:
        spec = load_spec()
        if args.command == "fetch":
            files = {}
            for kind in ("detail", "summary"):
                path = args.out / f"raw-{kind}.csv"
                files[path.name] = acquire_source(kind, spec, path if path.exists() else None)
            write_bundle(args.out, files)
            result = {"status": "PASS", "sources": {kind: spec[kind] for kind in ("detail", "summary")}}
        elif args.command == "verify":
            expected = verify_prepared(args.prepared, args.organization, spec=spec)
            result = {"status": "PASS", "organization": args.organization, "entry_count": expected["entry_count"],
                      "leg_count": expected["leg_count"], "native_validation": "UNRUN"}
        else:
            detail = acquire_source("detail", spec, args.detail)
            summary = acquire_source("summary", spec, args.summary)
            if args.command == "profile":
                result = profile(detail, summary, spec=spec)
            else:
                files = build_bundle(detail, summary, args.organization, spec=spec)
                write_bundle(args.out, files)
                expected = json.loads(files["expected_tb.json"])
                result = {"status": "PASS", "organization": args.organization, "source_stats": expected["source_stats"],
                          "entry_count": expected["entry_count"], "leg_count": expected["leg_count"], "native_validation": "UNRUN"}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (DataError, OSError, ValueError) as error:
        print(f"House source refusal: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
