#!/usr/bin/env python3
"""Pinned public expenditure extracts to a declared, replayable accounting model.

This is a development/data-acquisition helper, not a second accounting engine.
The native CLI imports and verifies the modeled book in run_live.py. All network
access is opt-in at preparation time; build_bundle is deterministic and offline.
"""

from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
from decimal import Decimal, localcontext
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.parse
import urllib.request


DEFAULT_MANIFEST = Path(__file__).with_name("sources.toml")
USER_AGENT = (
    "franken_accounting-agent "
    "(+https://github.com/Dicklesworthstone/franken_accounting)"
)
MODEL = "published_expenditure_v1"
ATTRIBUTION_PROFILE = "fa-public-spend-attribution-v1"
ATTRIBUTION_POLICY = (
    "Exact published supplier labels map to analysis Counterparty objects and "
    "expense-area labels to cost_center values. Equal source strings share a "
    "value; case, spaces and Unicode remain significant. Codes are dataset- and "
    "kind-scoped SHA-256 identities, not publisher identifiers or independently "
    "resolved legal entities. Both the expenditure leg and its declared modeled "
    "offset carry the same tags. Zero observations remain in the source census "
    "without monetary legs. No missing source attribution is inferred."
)
OFFSET_ACCOUNT = "published-payment-offset"
MAX_ROWS_PER_ENTRY = 12
UNIT = "GBP"
SCALE = 2
I128_MAX = (1 << 127) - 1
MODEL_BOUNDARY = (
    "Published expenditure model: Expense categories and an explicit Equity "
    "published-payment-offset are modeled counterparts, not the publisher's "
    "general ledger, bank account, or original journal entries. No cash balance, "
    "opening balance, VAT split, invoice date, approval, or fraud finding is inferred."
)


class DataError(ValueError):
    """The pinned source or its complete deterministic transformation is invalid."""


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def jsonl_bytes(rows: list[dict]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        for row in rows
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_minor(value: int) -> int:
    if not -I128_MAX <= value <= I128_MAX:
        raise DataError("amount or aggregate exceeds the signed i128 posting range")
    return value


def https_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise DataError("source URL and every redirect must be HTTPS without credentials or fragments")
    return url


def validate_spec(spec: dict) -> None:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", spec.get("id", "")):
        raise DataError("dataset id must contain lowercase ASCII words joined by hyphens")
    if not re.fullmatch(r"[0-9a-f]{64}", spec.get("sha256", "")):
        raise DataError("source requires a pinned lowercase SHA-256")
    if spec.get("encoding") != "cp1252":
        raise DataError("these source adapters require explicitly declared cp1252 encoding")
    if spec.get("amount_style") not in {"decimal", "sterling_whole_pounds"}:
        raise DataError("unsupported declared source amount style")
    if not 0 < spec.get("byte_length", 0) <= spec.get("max_bytes", 0) <= 32 * 1024 * 1024:
        raise DataError("source requires a positive byte length and a bounded maximum of at most 32 MiB")
    headers = spec.get("headers", [])
    if not headers or len(headers) != len(set(headers)) or not all(isinstance(h, str) and h for h in headers):
        raise DataError("source headers must be unique nonempty strings")
    for name in ("date", "amount", "expense_type", "expense_area", "supplier", "transaction"):
        if spec.get(f"{name}_column") not in headers:
            raise DataError(f"missing declared {name} column")
    try:
        start = dt.date.fromisoformat(spec["period_start"])
        end = dt.date.fromisoformat(spec["period_end"])
    except (KeyError, ValueError) as error:
        raise DataError("invalid declared half-open source period") from error
    if start >= end:
        raise DataError("declared source period must be nonempty")
    https_url(spec["url"])


def load_sources(manifest: Path = DEFAULT_MANIFEST) -> dict[str, dict]:
    with Path(manifest).open("rb") as handle:
        value = tomllib.load(handle)
    if value.get("schema_version") != 1 or not value.get("datasets"):
        raise DataError("unsupported or empty public-data manifest")
    result = {}
    for dataset_id, declaration in value["datasets"].items():
        spec = {**declaration, "id": dataset_id}
        validate_spec(spec)
        result[dataset_id] = spec
    return result


def verify_source(spec: dict, raw: bytes) -> None:
    validate_spec(spec)
    if len(raw) > spec["max_bytes"]:
        raise DataError("source exceeds declared download limit")
    if len(raw) != spec["byte_length"]:
        raise DataError(f"source byte count mismatch: expected {spec['byte_length']}, got {len(raw)}")
    actual = sha256(raw)
    if actual != spec["sha256"]:
        raise DataError(f"source SHA-256 mismatch: expected {spec['sha256']}, got {actual}")


class HttpsRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        https_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def acquire_source(spec: dict, source: Path | None = None) -> bytes:
    """Read bounded bytes and verify them before any output file is created."""
    validate_spec(spec)
    if source is not None:
        with Path(source).open("rb") as handle:
            raw = handle.read(spec["max_bytes"] + 1)
    else:
        request = urllib.request.Request(
            https_url(spec["url"]), headers={"User-Agent": USER_AGENT, "Accept": "text/csv"}
        )
        opener = urllib.request.build_opener(HttpsRedirects())
        with opener.open(request, timeout=30) as response:
            https_url(response.geturl())
            if response.status != 200:
                raise DataError(f"source server returned HTTP {response.status}")
            raw = response.read(spec["max_bytes"] + 1)
    verify_source(spec, raw)
    return raw


def parse_amount(value: str, style: str) -> int:
    """Convert a strictly declared source amount into integer pence, never float."""
    if style == "decimal":
        if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)\.[0-9]{2}", value):
            raise DataError(f"invalid fixed two-decimal source amount {value!r}")
        negative = value.startswith("-")
        whole, fractional = value.removeprefix("-").split(".")
        magnitude = int(whole) * 100 + int(fractional)
    elif style == "sterling_whole_pounds":
        if not re.fullmatch(r"-?£(?:0|[1-9][0-9]{0,2}(?:,[0-9]{3})*|[1-9][0-9]*)", value):
            raise DataError(f"invalid published whole-pound source amount {value!r}")
        negative = value.startswith("-")
        magnitude = int(value.removeprefix("-").removeprefix("£").replace(",", "")) * 100
    else:
        raise DataError(f"unsupported amount style {style!r}")
    return checked_minor(-magnitude if negative else magnitude)


def amount_text(minor: int) -> str:
    absolute = abs(minor)
    return f"{'-' if minor < 0 else ''}{absolute // 100}.{absolute % 100:02}"


def expense_account(expense_type: str) -> str:
    # Stable across input order and other categories. Detect the unlikely prefix
    # collision in build_bundle rather than combining two distinct source types.
    return "expense-" + sha256(expense_type.encode("utf-8"))[:16]


def decode_records(spec: dict, raw: bytes) -> list[dict]:
    verify_source(spec, raw)
    try:
        decoded = raw.decode(spec["encoding"], errors="strict")
    except UnicodeError as error:
        raise DataError("source is not valid in its declared encoding") from error
    reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
    try:
        headers = next(reader)
        if headers != spec["headers"]:
            raise DataError(f"source header drift: expected {spec['headers']!r}, got {headers!r}")
        result = []
        for ordinal, fields in enumerate(reader, 1):
            if len(fields) != len(headers):
                raise DataError(f"record {ordinal}: expected {len(headers)} fields, got {len(fields)}")
            if any("\x00" in field for field in fields):
                raise DataError(f"record {ordinal}: NUL in source field")
            row = dict(zip(headers, fields, strict=True))
            date_text = row[spec["date_column"]]
            if not re.fullmatch(r"[0-9]{2}/[0-9]{2}/[0-9]{4}", date_text):
                raise DataError(f"record {ordinal}: date must be DD/MM/YYYY")
            day, month, year = map(int, date_text.split("/"))
            try:
                effective_date = dt.date(year, month, day).isoformat()
            except ValueError as error:
                raise DataError(f"record {ordinal}: invalid calendar date {date_text!r}") from error
            if not spec["period_start"] <= effective_date < spec["period_end"]:
                raise DataError(f"record {ordinal}: date {effective_date} outside declared source period")
            for column in ("expense_type", "expense_area", "supplier", "transaction"):
                if not row[spec[f"{column}_column"]].strip():
                    raise DataError(f"record {ordinal}: empty {column}")
            minor = parse_amount(row[spec["amount_column"]], spec["amount_style"])
            kind = row[spec["expense_type_column"]]
            result.append({
                "row_id": f"{spec['sha256']}:{ordinal}",
                "record_ordinal": ordinal,
                "record_sha256": sha256(json_bytes(row)),
                "effective_date": effective_date,
                "amount_minor": str(minor),
                "currency": UNIT,
                "expense_account": expense_account(kind),
                "expense_type": kind,
                "expense_area": row[spec["expense_area_column"]],
                "supplier": row[spec["supplier_column"]],
                "transaction_number": row[spec["transaction_column"]],
                "disposition": "posted" if minor else "unposted_zero",
                "raw_fields": row,
            })
    except (csv.Error, StopIteration) as error:
        raise DataError(f"malformed or empty source CSV: {error}") from error
    if not result:
        raise DataError("source has no data records")
    return result


def independent_controls(spec: dict, raw: bytes) -> tuple[dict, list[tuple[dict, int]]]:
    """Separate raw-file Decimal fold: never reads normalized rows or generated GL.

    Decimal is used solely as an independent parsing oracle; generated amounts
    use parse_amount's integer arithmetic. Both must agree with locked controls.
    """
    rows = list(csv.DictReader(io.StringIO(raw.decode(spec["encoding"]), newline=""), strict=True))
    observations = []
    for row in rows:
        published = row[spec["amount_column"]].replace("£", "").replace(",", "")
        # i128 has up to 39 decimal digits. The default Decimal precision (28)
        # would silently round an otherwise valid wide source amount.
        with localcontext() as context:
            context.prec = max(80, len(published) + 4)
            value = Decimal(published) * 100
        if value != value.to_integral_value():
            raise DataError("oracle found a fraction of a penny")
        observations.append((row, checked_minor(int(value))))
    amounts = [minor for _, minor in observations]
    transactions = collections.Counter(row[spec["transaction_column"]] for row in rows)
    stats = {
        "row_count": len(rows),
        "positive_rows": sum(value > 0 for value in amounts),
        "negative_rows": sum(value < 0 for value in amounts),
        "zero_rows": sum(value == 0 for value in amounts),
        "positive_minor": str(checked_minor(sum(value for value in amounts if value > 0))),
        "negative_minor": str(checked_minor(sum(value for value in amounts if value < 0))),
        "net_minor": str(checked_minor(sum(amounts))),
        "min_minor": str(min(amounts)),
        "max_minor": str(max(amounts)),
        "duplicate_rows": len(rows) - len({tuple(row[h] for h in spec["headers"]) for row in rows}),
        "transaction_count": len(transactions),
        "split_transaction_count": sum(count > 1 for count in transactions.values()),
        "max_transaction_rows": max(transactions.values()),
        "expense_type_count": len({row[spec["expense_type_column"]] for row in rows}),
        "expense_area_count": len({row[spec["expense_area_column"]] for row in rows}),
        "supplier_count": len({row[spec["supplier_column"]] for row in rows}),
        "date_count": len({row[spec["date_column"]] for row in rows}),
    }
    if stats != spec.get("controls"):
        differences = {key: {"expected": spec.get("controls", {}).get(key), "actual": value}
                       for key, value in stats.items() if spec.get("controls", {}).get(key) != value}
        raise DataError(f"independent source controls differ from pinned manifest: {differences}")
    return stats, observations


def attribution_code(dataset: str, kind: str, value: str) -> str:
    """An exact source label's bounded native code, with unambiguous domains."""
    if kind not in ("cost_center", "party") or not isinstance(value, str) or not value.strip():
        raise DataError("native attribution requires a nonblank source label and registered kind")
    if len(value.encode("utf-8")) > 256:
        raise DataError("source attribution label exceeds the native 256-byte name bound; no truncation is permitted")
    return sha256(json_bytes([ATTRIBUTION_PROFILE, dataset, kind, value]))


def attribution_oracle(spec: dict, observations: list[tuple[dict, int]]) -> dict:
    """Independent original-field folds, including zero-only source values.

    No generated CSV, native tag or posting receipt supplies these expectations.
    The expenditure/offset rule is the same explicit model as the whole-book TB.
    """
    result = {"profile": ATTRIBUTION_PROFILE, "policy": ATTRIBUTION_POLICY}
    for kind, field, output in (("cost_center", "expense_area", "cost_centers"),
                                ("party", "supplier", "suppliers")):
        buckets: dict[str, dict] = {}
        identities: dict[str, str] = {}
        for row, amount in observations:
            name = row[spec[f"{field}_column"]]
            code = attribution_code(spec["id"], kind, name)
            if identities.setdefault(code, name) != name:
                raise DataError("native attribution digest collision between distinct source labels")
            bucket = buckets.setdefault(name, {"code": code, "name": name, "row_count": 0,
                                               "posted_row_count": 0, "positive_minor": 0,
                                               "negative_minor": 0, "accounts": {}})
            bucket["row_count"] += 1
            bucket["posted_row_count"] += int(amount != 0)
            bucket["positive_minor"] += max(amount, 0)
            bucket["negative_minor"] += min(amount, 0)
            for account, signed in ((expense_account(row[spec["expense_type_column"]]), amount),
                                    (OFFSET_ACCOUNT, -amount)):
                cell = bucket["accounts"].setdefault(account, [0, 0])
                cell[0] += max(signed, 0)
                cell[1] += max(-signed, 0)
        values = []
        for name, bucket in sorted(buckets.items()):
            accounts = [{"account": account, "debit_minor": str(checked_minor(debit)),
                         "credit_minor": str(checked_minor(credit)),
                         "signed_minor": str(checked_minor(debit - credit))}
                        for account, (debit, credit) in sorted(bucket["accounts"].items())]
            values.append({**bucket, "accounts": accounts,
                           "positive_minor": str(checked_minor(bucket["positive_minor"])),
                           "negative_minor": str(checked_minor(bucket["negative_minor"]))})
        result[output] = values
    return result


def build_bundle(spec: dict, raw: bytes, *, native_attribution: bool = False) -> dict[str, bytes]:
    """Return all exact files for one complete dataset; no I/O or clock reads."""
    if type(native_attribution) is not bool:
        raise DataError("native attribution must be explicitly enabled or disabled")
    records = decode_records(spec, raw)
    stats, oracle_rows = independent_controls(spec, raw)
    if [int(row["amount_minor"]) for row in records] != [value for _, value in oracle_rows]:
        raise DataError("integer adapter and independent Decimal oracle disagree")
    category_accounts = {row["expense_type"]: row["expense_account"] for row in records}
    if len(set(category_accounts.values())) != len(category_accounts):
        raise DataError("expense account digest-prefix collision")
    attribution = attribution_oracle(spec, oracle_rows) if native_attribution else None
    attribution_maps = {} if attribution is None else {
        field: {value["name"]: value["code"] for value in attribution[collection]}
        for field, collection in (("expense_area", "cost_centers"), ("supplier", "suppliers"))
    }

    # Full source detail stays in records/provenance; bounded memos link each
    # imported leg to it. Grouping is model bookkeeping, never an assertion that
    # the publisher's payment id is one of its original journal entries.
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for record in records:
        if record["disposition"] == "posted":
            grouped[record["effective_date"]].append(record)
    generated = io.StringIO(newline="")
    writer = csv.writer(generated, lineterminator="\n")
    writer.writerow(["entry_id", "effective_date", "account_code", "side", "amount",
                     "currency", "description", "memo"]
                    + (["cost_center_code", "supplier_code"] if native_attribution else []))
    links = {}
    entries = []
    for date, dated in sorted(grouped.items()):
        for part, start in enumerate(range(0, len(dated), MAX_ROWS_PER_ENTRY), 1):
            selected = dated[start:start + MAX_ROWS_PER_ENTRY]
            entry_id = f"{spec['id']}:{spec['sha256'][:12]}:{date}:{part:04}"
            description = f"Published expenditure model; source {spec['id']}; date {date}; part {part}"
            entries.append({"entry_id": entry_id, "effective_date": date,
                            "source_row_ids": [record["row_id"] for record in selected]})
            for position, record in enumerate(selected):
                minor = int(record["amount_minor"])
                memo = f"source_row={record['row_id']}"
                for account, side in (
                    (record["expense_account"], "D" if minor > 0 else "C"),
                    (OFFSET_ACCOUNT, "C" if minor > 0 else "D"),
                ):
                    writer.writerow([entry_id, date, account, side, amount_text(abs(minor)),
                                     UNIT, description, memo]
                                    + ([attribution_maps["expense_area"][record["expense_area"]],
                                        attribution_maps["supplier"][record["supplier"]]]
                                       if native_attribution else []))
                links[record["row_id"]] = {
                    "entry_id": entry_id,
                    "expense_leg_ordinal": position * 2 + 1,
                    "offset_leg_ordinal": position * 2 + 2,
                }

    provenance = [{
        "row_id": row["row_id"], "source_sha256": spec["sha256"],
        "record_ordinal": row["record_ordinal"], "record_sha256": row["record_sha256"],
        "disposition": row["disposition"], "raw_fields": row["raw_fields"],
        "transaction_number": row["transaction_number"],
        "expense_account": row["expense_account"], "offset_account": OFFSET_ACCOUNT,
        **links.get(row["row_id"], {"entry_id": None, "expense_leg_ordinal": None,
                                   "offset_leg_ordinal": None}),
    } for row in records]

    chart = {"accounts": [
        {"code": OFFSET_ACCOUNT, "name": "Modeled published-payment offset (not bank cash)",
         "type": "Equity", "unit": UNIT},
        *[{"code": code, "name": f"Published expenditure: {kind}", "type": "Expense", "unit": UNIT}
          for kind, code in sorted(category_accounts.items(), key=lambda item: item[1])],
    ]}

    # Expected accounting amounts are folded independently from original source
    # fields, not from the generated CSV or its posting signs.
    movement = {account["code"]: [0, 0] for account in chart["accounts"]}
    dimension_columns = {
        "expense_type": spec["expense_type_column"],
        "expense_area": spec["expense_area_column"],
        "supplier": spec["supplier_column"],
        "transaction_number": spec["transaction_column"],
        "source_date": spec["date_column"],
    }
    dimensions = {name: {} for name in dimension_columns}
    for original, amount in oracle_rows:
        account = category_accounts[original[spec["expense_type_column"]]]
        movement[account][0] += max(amount, 0)
        movement[account][1] += max(-amount, 0)
        movement[OFFSET_ACCOUNT][0] += max(-amount, 0)
        movement[OFFSET_ACCOUNT][1] += max(amount, 0)
        for name, column in dimension_columns.items():
            bucket = dimensions[name].setdefault(original[column], [0, 0, 0])
            bucket[0] += 1
            bucket[1] += max(amount, 0)
            bucket[2] += min(amount, 0)
    accounts = [{
        "account": account, "debit_minor": str(checked_minor(debit)),
        "credit_minor": str(checked_minor(credit)),
        "signed_minor": str(checked_minor(debit - credit)),
        "balance_debit_minor": str(max(debit - credit, 0)),
        "balance_credit_minor": str(max(credit - debit, 0)),
    } for account, (debit, credit) in sorted(movement.items())]
    if sum(int(account["signed_minor"]) for account in accounts) != 0:
        raise DataError("declared expenditure model is not balanced")
    expected = {
        "model": MODEL, "model_boundary": MODEL_BOUNDARY,
        "dataset_id": spec["id"], "source_sha256": spec["sha256"],
        "source_system": f"public-spend:{spec['id']}", "unit": UNIT, "scale": SCALE,
        "period_start": spec["period_start"], "period_end": spec["period_end"],
        "accounts": accounts, "source_stats": stats,
        "entry_count": len(entries), "leg_count": len(links) * 2,
        "posted_row_count": len(links), "zero_row_count": stats["zero_rows"],
        "entries": entries,
    }
    if native_attribution:
        expected["native_attribution"] = ATTRIBUTION_PROFILE
    dimension_output = {
        name: [{"value": value, "row_count": count, "positive_minor": str(checked_minor(positive)),
                "negative_minor": str(checked_minor(negative)),
                "signed_minor": str(checked_minor(positive + negative))}
               for value, (count, positive, negative) in sorted(buckets.items())]
        for name, buckets in dimensions.items()
    }
    columns = (
        '[columns]\n'
        f'source_system = "public-spend:{spec["id"]}"\n'
        'default_unit = "GBP"\n'
        'entry_id_column = "entry_id"\n'
        'effective_date_column = "effective_date"\n'
        'account_column = "account_code"\n'
        'side_column = "side"\n'
        'amount_column = "amount"\n'
        'unit_column = "currency"\n'
        'description_column = "description"\n'
        'memo_column = "memo"\n'
    )
    if native_attribution:
        columns += ('\n[dimension_columns]\n'
                    'cost_center = "cost_center_code"\n'
                    'party = "supplier_code"\n')
    outputs = {
        "raw.csv": raw,
        "records.jsonl": jsonl_bytes(records),
        "provenance.jsonl": jsonl_bytes(provenance),
        "chart.json": json_bytes(chart),
        "account_map.json": json_bytes({row["code"]: row["code"] for row in chart["accounts"]}),
        "legacy.csv": generated.getvalue().encode("utf-8"),
        "columns.toml": columns.encode(),
        "expected_tb.json": json_bytes(expected),
        "dimensions.json": json_bytes(dimension_output),
    }
    if attribution is not None:
        outputs["native_attribution.json"] = json_bytes(attribution)
    receipt = {
        "schema_version": 1, "model": MODEL, "model_boundary": MODEL_BOUNDARY,
        "dataset_id": spec["id"], "source_sha256": spec["sha256"],
        "source_bytes": len(raw), "source_encoding": spec["encoding"],
        "source_url": spec["url"], "publication_url": spec["publication_url"],
        "schema_url": spec["schema_url"], "license_url": spec["license_url"],
        "attribution": f"Contains public sector information licensed under the Open Government Licence v3.0. Source: {spec['publisher']}.",
        "source_limits": spec["limits"],
        "published_amount_precision": spec["published_amount_precision"],
        "source_stats": stats, "max_source_rows_per_entry": MAX_ROWS_PER_ENTRY,
        "entry_count": len(entries), "leg_count": len(links) * 2,
        "files": {name: {"sha256": sha256(content), "bytes": len(content)}
                  for name, content in sorted(outputs.items())},
    }
    if native_attribution:
        receipt["native_attribution"] = ATTRIBUTION_PROFILE
    outputs["receipt.json"] = json_bytes(receipt)
    return outputs


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    """Create missing files exclusively; exact retries are allowed, overwrites are not."""
    output = Path(output)
    if output.exists() and not output.is_dir():
        raise DataError(f"output is not a directory: {output}")
    for name, data in files.items():
        path = output / name
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != data)):
            raise DataError(f"refusing to overwrite different existing output: {path}")
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        path = output / name
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise DataError(f"existing output changed during preparation: {path}")
            continue
        with path.open("xb") as handle:
            handle.write(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list pinned complete public transaction extracts")
    prepare = sub.add_parser("prepare", help="verify and normalize all original rows")
    prepare.add_argument("--dataset", required=True)
    prepare.add_argument("--source", type=Path, help="offline original CSV; still checks all manifest pins")
    prepare.add_argument("--out", type=Path, required=True)
    prepare.add_argument("--native-attribution", action="store_true",
                         help="retain exact supplier labels as native parties and expense areas as cost centers")
    args = parser.parse_args(argv)
    try:
        sources = load_sources(args.manifest)
        if args.command == "list":
            print(json.dumps({key: {"title": value["title"], "rows": value["controls"]["row_count"],
                                   "source_sha256": value["sha256"]}
                              for key, value in sorted(sources.items())}, sort_keys=True, indent=2))
            return 0
        if args.dataset not in sources:
            raise DataError(f"unknown dataset {args.dataset!r}; choose one of {sorted(sources)}")
        spec = sources[args.dataset]
        raw = acquire_source(spec, args.source)
        files = build_bundle(spec, raw, native_attribution=args.native_attribution)
        write_bundle(args.out, files)
        print(json.dumps({"status": "PASS", "dataset": args.dataset, "output": str(args.out),
                          "source_rows": spec["controls"]["row_count"],
                          "source_sha256": spec["sha256"], "model": MODEL}, sort_keys=True))
        return 0
    except (DataError, OSError, ValueError) as error:
        print(f"FAIL public-data: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
