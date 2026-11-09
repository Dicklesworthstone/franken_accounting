#!/usr/bin/env python3
"""Compare untouched native GL exports with real Beancount and hledger tools.

The CSV export supplies exact fixed-scale controls. bean-check validates the
Beancount input, bean-query computes net/gross balances and posting counts,
and hledger computes balances independently and exposes its parsed postings.
This does not implement a replacement Beancount or hledger accounting engine.

Account identities come from the exports' explicit fa_code metadata, never
from reversing the lossy account-name sanitizer. Every command, exit status,
stdout/stderr, input snapshot, executable hash and version is retained. A
missing oracle is UNRUN, never PASS. See plan section 16.3 and bead fa-sa4w.

Tool contracts: https://beancount.github.io/docs/beancount_query_language/
and https://hledger.org/1.52/hledger.html#print . This bounded native-export
profile compares signed units, not valuation, lots, dimensions or provenance.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from dataclasses import dataclass, field
from datetime import date
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import unquote_to_bytes


CSV_COLUMNS = (
    "entry_id", "line_no", "effective_date", "recorded_seq", "entry_class",
    "account_code", "side", "amount", "currency", "unit_scale", "description",
    "migrated_from", "memo",
)
HLEDGER_COLUMNS = (
    "txnidx", "date", "date2", "status", "code", "description", "comment",
    "account", "amount", "commodity", "credit", "debit", "posting-status",
    "posting-comment",
)
METADATA = {
    "fa_book_name": "book", "fa_base_unit": "base",
    "fa_effective_through": "effective_through", "fa_known_at_seq": "known_at",
    "fa_content_digest": "content_digest", "fa_certificate_digest": "certificate_digest",
}
ROOTS = {"Asset": "Assets", "Liability": "Liabilities", "Equity": "Equity",
         "Revenue": "Income", "Expense": "Expenses"}
DECIMAL = re.compile(r"([+-]?)([0-9]+)(?:\.([0-9]+))?\Z", re.ASCII)
UNSIGNED = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
QUERY = ("SELECT account, currency, sum(number) AS total, count(*) AS postings"
         "{where} GROUP BY account, currency ORDER BY account, currency;")
SCOPE = (
    "Exact signed-unit balances, separate debit/credit activity and posting counts "
    "for every account/currency cell in the three same-coordinate native exports. "
    "No cost conversion, market valuation, lot, dimension, evidence-custody, "
    "original-source authenticity or full-book completeness claim. Native export "
    "certificate verification and original-source reconciliation remain separate."
)


class OracleError(ValueError):
    """The exported population or independent result failed a comparison."""


class Unavailable(OracleError):
    """An external oracle could not execute to completion."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OracleError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(path: Path) -> dict:
    data = path.read_bytes()
    return {"sha256": digest(data), "bytes": len(data)}


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False)
        stream.write("\n")


def integer(text: str, label: str, *, positive: bool = False) -> int:
    require(isinstance(text, str) and len(text) <= 20 and UNSIGNED.fullmatch(text) is not None,
            f"{label} is not a canonical nonnegative integer: {text!r}")
    value = int(text)
    require(not positive or value > 0, f"{label} must be positive")
    return value


def minor_units(text: str, scale: int) -> int:
    """Parse exact decimal text without floats, context rounding or tolerance."""
    require(isinstance(text, str) and len(text) <= 512,
            "amount must be bounded decimal text, never a floating-point value")
    require(type(scale) is int and 0 <= scale <= 255, "unit scale is outside the native u8 range")
    match = DECIMAL.fullmatch(text)
    require(match is not None, f"nondecimal amount {text!r}")
    sign, whole, fraction = match.groups()
    fraction = fraction or ""
    require(not any(char != "0" for char in fraction[scale:]),
            f"amount {text!r} has nonzero digits below declared scale {scale}")
    value = int(whole) * 10 ** scale + int((fraction[:scale].ljust(scale, "0")) or "0")
    return -value if sign == "-" else value


def rows(text: str, expected_header: tuple[str, ...], label: str) -> list[dict[str, str]]:
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        require(next(reader, None) == list(expected_header), f"{label}: unexpected or missing CSV schema")
        result = []
        for ordinal, values in enumerate(reader, 2):
            require(len(values) == len(expected_header) and all("\0" not in value for value in values),
                    f"{label}: malformed CSV record {ordinal}")
            result.append(dict(zip(expected_header, values, strict=True)))
        return result
    except csv.Error as error:
        raise OracleError(f"{label}: malformed CSV: {error}") from error


@dataclass
class Cell:
    net: int = 0
    debit: int = 0
    credit: int = 0
    postings: int = 0
    debit_postings: int = 0
    credit_postings: int = 0

    def add(self, amount: int) -> None:
        require(type(amount) is int and amount != 0, "the native monetary profile has no zero posting")
        self.net += amount
        self.postings += 1
        if amount > 0:
            self.debit += amount
            self.debit_postings += 1
        else:
            self.credit -= amount
            self.credit_postings += 1


@dataclass
class Reference:
    coordinate: dict
    accounts: dict[str, str]
    scales: dict[str, int]
    normal_sides: dict[str, str]
    cells: dict[tuple[str, str], Cell] = field(default_factory=dict)
    entries: int = 0
    postings: int = 0


def cell_rows(cells: dict[tuple[str, str], Cell], scales: dict[str, int]) -> list[dict]:
    return [{"account": account, "currency": unit, "scale": scales[unit],
             "net_minor": str(value.net), "debit_minor": str(value.debit),
             "credit_minor": str(value.credit), "postings": value.postings,
             "debit_postings": value.debit_postings, "credit_postings": value.credit_postings}
            for (account, unit), value in sorted(cells.items())]


def metadata_text(value: str, escaped: bool) -> str:
    if not escaped:
        return value
    require(re.search(r"%(?![0-9A-Fa-f]{2})", value) is None, "malformed percent-encoded CSV metadata")
    return unquote_to_bytes(value).decode("utf-8", errors="strict")


def metadata_hex(value: str) -> str:
    """Decode only the native v1 lowercase UTF-8 hex metadata extension."""
    require(re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None,
            "malformed lowercase hex metadata")
    try:
        return bytes.fromhex(value).decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise OracleError("hex metadata is not valid UTF-8") from error


def read_reference(text: str) -> Reference:
    """Read only the native CSV wire and derive integer controls independently."""
    stream = io.StringIO(text, newline="")
    escaped = False
    coordinate = None
    accounts: dict[str, str] = {}
    normal_sides: dict[str, str] = {}
    for line in stream:
        line = line.rstrip("\r\n")
        if line == "# fa_csv_text_encoding_v1|percent-utf8":
            require(coordinate is None and not escaped, "late or repeated CSV metadata encoding")
            escaped = True
        elif line.startswith("# fa_csv_gl_v1|"):
            require(coordinate is None, "duplicate native CSV coordinate")
            coordinate = {}
            for part in line.split("|")[1:]:
                key, separator, value = part.partition("=")
                require(separator == "=" and key not in coordinate, "malformed or repeated CSV coordinate field")
                coordinate[key] = value
            required = {"book", "base", "effective_through", "known_at", "entries",
                        "content_digest", "certificate_digest"}
            require(set(coordinate) in (required, required | {"dimension_encoding"}),
                    "native CSV coordinate fields are incomplete or unknown")
            if "dimension_encoding" in coordinate:
                require(coordinate["dimension_encoding"] == "fa-dimension-ids-v1",
                        "native CSV uses an unknown dimension encoding")
            coordinate["book"] = metadata_text(coordinate["book"], escaped)
            base, separator, scale = coordinate["base"].rpartition("@")
            require(separator == "@", "native CSV has no base-unit scale")
            base = metadata_text(base, escaped)
            scale_value = integer(scale, "base-unit scale")
            require(scale_value <= 255 and bool(base), "invalid native base unit")
            coordinate["base"] = f"{base}@{scale_value}"
            date.fromisoformat(coordinate["effective_through"])
            integer(coordinate["known_at"], "known-at sequence")
            integer(coordinate["entries"], "declared entry count")
            for name in ("content_digest", "certificate_digest"):
                require(re.fullmatch(r"[0-9a-f]{64}", coordinate[name], re.ASCII) is not None,
                        f"invalid native {name}")
        elif line.startswith("# fa_account|"):
            require(coordinate is not None, "account declaration precedes native coordinate")
            parts = line.split("|")[1:]
            require(len(parts) == 4 and parts[2] in ROOTS and parts[3] in ("D", "C"),
                    "malformed native account declaration")
            code = metadata_text(parts[0], escaped)
            require(code and code not in accounts, "duplicate or empty native account code")
            accounts[code] = parts[2]
            normal_sides[code] = parts[3]
        elif line.startswith(("# fa_account_roles_v1|", "# fa_assertion|", "# fa_csv_empty_optional_v1|")):
            require(coordinate is not None, "native ancillary metadata has no coordinate")
        elif line.startswith("#") or not line:
            raise OracleError(f"unknown or empty native CSV metadata line {line!r}")
        else:
            header = line
            break
    else:
        raise OracleError("native CSV has no detail header")
    require(coordinate is not None and bool(accounts), "native CSV lacks coordinate or chart")
    columns = CSV_COLUMNS + (("dimension_set_v1",) if "dimension_encoding" in coordinate else ())
    records = rows(header + "\n" + stream.read(), columns, "native CSV")
    base, _, scale = coordinate["base"].rpartition("@")
    reference = Reference(coordinate, accounts, {base: int(scale)}, normal_sides)
    seen_entries: dict[str, tuple[str, str, str]] = {}
    counts: dict[str, int] = defaultdict(int)
    for row in records:
        entry = row["entry_id"]
        require(entry and row["account_code"] in accounts, "native row has no entry or declared account")
        counts[entry] += 1
        require(integer(row["line_no"], "native leg ordinal", positive=True) == counts[entry],
                "native CSV duplicated, omitted or reordered an entry's legs")
        identity = (row["effective_date"], row["recorded_seq"], row["entry_class"])
        require(seen_entries.setdefault(entry, identity) == identity, "native entry metadata changes between legs")
        require(date.fromisoformat(row["effective_date"]) <= date.fromisoformat(coordinate["effective_through"]),
                "native CSV contains a posting after its declared effective cutoff")
        require(integer(row["recorded_seq"], "native recorded sequence", positive=True)
                <= int(coordinate["known_at"]), "native row exceeds its known-at coordinate")
        integer(row["entry_class"], "native entry class")
        unit = row["currency"]
        require(re.fullmatch(r"[A-Z][A-Z0-9._'-]*", unit, re.ASCII) is not None,
                f"unsupported plaintext commodity code {unit!r}")
        scale = integer(row["unit_scale"], "native unit scale")
        require(scale <= 255 and reference.scales.setdefault(unit, scale) == scale,
                "native currency has conflicting or invalid scales")
        amount = minor_units(row["amount"], scale)
        require(amount > 0 and row["side"] in ("D", "C"), "native posting has invalid amount or side")
        if row["side"] == "C":
            amount = -amount
        reference.cells.setdefault((row["account_code"], unit), Cell()).add(amount)
    reference.entries = len(seen_entries)
    reference.postings = len(records)
    require(reference.entries == int(coordinate["entries"]), "native CSV entry count differs from its coordinate")
    require(reference.postings > 0, "empty native exports cannot establish an external differential")
    return reference


def read_account_map(text: str, kind: str, reference: Reference) -> dict[str, str]:
    """Read native declarations, not monetary postings or inferred account codes."""
    require(kind in ("beancount", "hledger"), "unknown plaintext format")
    # Match native Rust str::lines and the external journal grammars: Unicode
    # separators and vertical tabs inside source text are not new directives.
    lines = [line.removesuffix("\r") for line in text.split("\n")]
    metadata = {}
    mapping: dict[str, str] = {}
    seen_codes = set()

    def declare(name: str, code: str, account_type: str, normal_side: str | None) -> None:
        require(code in reference.accounts and account_type == reference.accounts[code],
                f"{kind}: account declaration differs from native chart: {code!r}")
        if normal_side is None:
            normal_side = "C" if account_type in ("Liability", "Equity", "Revenue") else "D"
        require(normal_side in ("D", "C"),
                f"{kind}: invalid fa_normal_side_v1 {normal_side!r}; expected D or C")
        require(normal_side == reference.normal_sides[code],
                f"{kind}: normal balance differs from native chart: {code!r}")
        require(name.startswith(ROOTS[account_type] + ":") and not any(c.isspace() for c in name),
                f"{kind}: invalid account name {name!r}")
        require(name not in mapping and code not in seen_codes,
                f"{kind}: duplicate or colliding account mapping {name!r} / {code!r}")
        mapping[name] = code
        seen_codes.add(code)

    for index, line in enumerate(lines):
        if line.startswith("; fa_"):
            key, separator, raw = line[2:].partition(":")
            value = raw[1:] if raw.startswith(" ") else raw
            if key == "fa_book_name_hex_v1":
                key = "fa_book_name"
                value = metadata_hex(value)
            require(separator and key in METADATA and key not in metadata,
                    f"{kind}: unknown or repeated coordinate metadata {key!r}")
            metadata[key] = value
        if kind == "beancount":
            match = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} open (\S+)", line)
            if match:
                values = {}
                for following in lines[index + 1:]:
                    if not following.startswith((" ", "\t")):
                        break
                    key, separator, value = following.strip().partition(":")
                    require(separator and key in {"fa_code", "fa_name", "fa_type", "fa_roles_v1", "fa_normal_side_v1"}
                            and key not in values, "Beancount account metadata is malformed or repeated")
                    # Beancount strings permit literal control bytes such as
                    # NUL/VT; JSON's stricter default would reject valid native
                    # metadata. Quoting and escape syntax remain checked.
                    values[key] = json.loads(value.strip(), strict=False)
                    require(isinstance(values[key], str), "Beancount account metadata must be text")
                require({"fa_code", "fa_type"} <= values.keys(), "Beancount account lacks explicit fa_code/fa_type")
                declare(match[1], values["fa_code"], values["fa_type"], values.get("fa_normal_side_v1"))
            elif line and not line.startswith((" ", "\t", ";")):
                require(line.startswith(('option "title" ', 'option "operating_currency" '))
                        or re.match(r"[0-9]{4}-[0-9]{2}-[0-9]{2} (?:\* |balance )", line) is not None,
                        "Beancount input is not the native export profile (includes/plugins are not admitted)")
        else:
            if line.startswith("account "):
                match = re.fullmatch(
                    r"account (\S+)\s+; (fa_code|fa_code_hex_v1):(.*?) fa_type:(\S+)"
                    r"(?: fa_normal_side_v1:(\S+))?"
                    r"(?: fa_roles_v1:\S+)? (fa_name|fa_name_hex_v1):(.*)", line)
                require(match is not None, "hledger account lacks unambiguous explicit fa_code/fa_type")
                code = metadata_hex(match[3]) if match[2] == "fa_code_hex_v1" else match[3]
                if match[6] == "fa_name_hex_v1":
                    metadata_hex(match[7])
                declare(match[1], code, match[4], match[5])
            elif line and not line.startswith((" ", "\t", ";")):
                require(re.match(r"[0-9]{4}-[0-9]{2}-[0-9]{2} \* ", line) is not None,
                        "hledger input is not the native export profile (includes/rules are not admitted)")
    require(set(metadata) == set(METADATA), f"{kind}: coordinate metadata is incomplete")
    require(all(metadata[key] == reference.coordinate[field] for key, field in METADATA.items()),
            f"{kind}: export coordinate differs from the native CSV; use the same known-at and effective cutoff")
    require(seen_codes == set(reference.accounts), f"{kind}: account mapping omits native chart accounts")
    return mapping


def parse_beanquery(text: str, mapping: dict[str, str], scales: dict[str, int]) -> dict:
    result = {}
    for row in rows(text, ("account", "currency", "total", "postings"), "bean-query"):
        require(row["account"] in mapping and row["currency"] in scales,
                "bean-query returned an undeclared account or currency")
        key = (mapping[row["account"]], row["currency"])
        require(key not in result, "bean-query repeated an account/currency cell")
        result[key] = (minor_units(row["total"].strip(), scales[key[1]]),
                       integer(row["postings"].strip(), "bean-query posting count", positive=True))
    return result


def expected_cells(reference: Reference, measure: str) -> dict:
    require(measure in ("net", "debit", "credit"), "unknown cell measure")
    count = "postings" if measure == "net" else f"{measure}_postings"
    sign = -1 if measure == "credit" else 1
    return {key: (getattr(value, measure) * sign, getattr(value, count))
            for key, value in reference.cells.items() if getattr(value, count)}


def compare_cells(actual: dict, expected: dict, label: str) -> None:
    differences = [{"account": key[0], "currency": key[1],
                    "expected": expected.get(key), "actual": actual.get(key)}
                   for key in sorted(actual.keys() | expected.keys()) if actual.get(key) != expected.get(key)]
    require(not differences, f"{label}: {len(differences)} account/currency mismatches: "
            + json.dumps(differences[:12], sort_keys=True))


def parse_hledger_postings(text: str, mapping: dict[str, str], reference: Reference) -> dict:
    cells: dict[tuple[str, str], Cell] = {}
    transaction_ids = set()
    for row in rows(text, HLEDGER_COLUMNS, "hledger print"):
        require(row["account"] in mapping and row["commodity"] in reference.scales,
                "hledger returned an undeclared account or currency")
        transaction_ids.add(integer(row["txnidx"], "hledger transaction index", positive=True))
        unit = row["commodity"]
        amount = minor_units(row["amount"], reference.scales[unit])
        side = "debit" if amount > 0 else "credit"
        opposite = "credit" if amount > 0 else "debit"
        require(row[opposite] == "" and minor_units(row[side], reference.scales[unit]) == abs(amount),
                "hledger print's amount and debit/credit columns disagree")
        cells.setdefault((mapping[row["account"]], unit), Cell()).add(amount)
    require(transaction_ids == set(range(1, reference.entries + 1)),
            "hledger transaction count or coverage differs from native CSV")
    compare_cells({key: vars(value) for key, value in cells.items()},
                  {key: vars(value) for key, value in reference.cells.items()},
                  "hledger parsed posting gross/net/counts")
    return cells


def parse_hledger_balances(text: str, mapping: dict[str, str], unit: str, scale: int) -> dict:
    result = {}
    for row in rows(text, ("account", "balance"), "hledger balance"):
        require(row["account"] in mapping, "hledger balance returned an undeclared account")
        key = (mapping[row["account"]], unit)
        require(key not in result, "hledger balance repeated an account/currency cell")
        value = row["balance"]
        if value == "0":
            amount = 0
        else:
            number, separator, currency = value.rpartition(" ")
            require(separator and currency == unit,
                    f"hledger balance has an unexpected commodity or mixed amount {value!r}")
            amount = minor_units(number, scale)
        result[key] = amount
    return result


def resolve_tool(value: str | Path | None, default: str) -> Path:
    candidate = shutil.which(str(value or default))
    if candidate is None:
        raise Unavailable(f"missing executable {value or default}; install the real external accounting tool")
    path = Path(candidate).resolve(strict=True)
    require(path.is_file() and os.access(path, os.X_OK), f"tool is not executable: {path}")
    return path


class Commands:
    def __init__(self, output: Path, timeout: int):
        self.output = output
        self.timeout = timeout
        self.records: list[dict] = []
        self.environment = dict(os.environ)
        for key in ("LEDGER_FILE", "LEDGER_BEGIN", "LEDGER_END", "LEDGER_DEPTH", "HLEDGER_CONF"):
            self.environment.pop(key, None)
        self.environment.update(NO_COLOR="1", LC_ALL="C.UTF-8", PYTHONDONTWRITEBYTECODE="1")

    def run(self, label: str, argv: list[str], *, allow_stderr: bool = False) -> str:
        ordinal = len(self.records) + 1
        prefix = f"{ordinal:02}-{label}"
        stdout = self.output / f"{prefix}.stdout"
        stderr = self.output / f"{prefix}.stderr"
        started = time.monotonic_ns()
        error = None
        code = None
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                result = subprocess.run(argv, stdout=out, stderr=err, cwd=self.output,
                                        env=self.environment, timeout=self.timeout, check=False)
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                error = str(exc)
        record = {"command": argv, "exit": code, "elapsed_ms": (time.monotonic_ns() - started) // 1_000_000,
                  "stdout": {"file": stdout.name, **snapshot(stdout)},
                  "stderr": {"file": stderr.name, **snapshot(stderr)}}
        if error is not None:
            record["execution_error"] = error
        self.records.append(record)
        with (self.output / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        if error is not None:
            raise Unavailable(f"{label} did not execute to completion: {error}")
        require(code == 0, f"{label} exited {code}; see {stderr.name} and {stdout.name}")
        require(allow_stderr or stderr.stat().st_size == 0,
                f"{label} emitted diagnostics; partial or warning-bearing output is not accepted; see {stderr.name}")
        return stdout.read_text(encoding="utf-8", errors="strict")


def run_oracle(csv_gl: Path, beancount: Path, hledger_journal: Path, out: Path, *,
               bean_check: str | Path | None = None, bean_query: str | Path | None = None,
               hledger: str | Path | None = None, timeout: int = 300) -> dict:
    """Execute the real tools and retain a PASS/FAIL/UNRUN report in a new directory.

    Input/profile errors and missing tools before execution raise OracleError or
    Unavailable without creating the output directory. A started attempt retains
    all completed and failed commands and returns its explicit status.
    """
    require(type(timeout) is int and timeout > 0, "timeout must be a positive integer")
    out = Path(out).absolute()
    require(not out.exists(), "oracle output already exists; preserve the previous run and choose a new directory")
    inputs = {"csv_gl": Path(csv_gl).resolve(strict=True), "beancount": Path(beancount).resolve(strict=True),
              "hledger": Path(hledger_journal).resolve(strict=True)}
    content = {name: path.read_bytes() for name, path in inputs.items()}
    reference = read_reference(content["csv_gl"].decode("utf-8", errors="strict"))
    maps = {kind: read_account_map(content[kind].decode("utf-8", errors="strict"), kind, reference)
            for kind in ("beancount", "hledger")}
    require(maps["beancount"] == maps["hledger"], "plaintext exports disagree about original account identities")
    tools = {"bean_check": resolve_tool(bean_check, "bean-check"),
             "bean_query": resolve_tool(bean_query, "bean-query"),
             "hledger": resolve_tool(hledger, "hledger")}
    tool_pins = {name: {"path": str(path), **snapshot(path)} for name, path in tools.items()}
    out.mkdir(parents=True, exist_ok=False)
    retained = out / "inputs"
    retained.mkdir()
    filenames = {"csv_gl": "native.csv", "beancount": "journal.beancount", "hledger": "journal.hledger"}
    input_pins = {}
    for name, data in content.items():
        path = retained / filenames[name]
        with path.open("xb") as stream:
            stream.write(data)
        input_pins[name] = {"original_path": str(inputs[name]), "snapshot": str(path.relative_to(out)),
                            "sha256": digest(data), "bytes": len(data)}
    write_json(out / "inputs.json", input_pins)
    write_json(out / "expected.json", {"coordinate": reference.coordinate,
                                        "cells": cell_rows(reference.cells, reference.scales)})
    commands = Commands(out, timeout)
    report = {"format": "fa-plaintext-oracle-v1", "status": "FAIL", "scope": SCOPE,
              "coordinate": reference.coordinate, "input_files": input_pins,
              "tools": tool_pins, "entries": reference.entries, "postings": reference.postings,
              "account_currency_cells": len(reference.cells), "declared_accounts": len(reference.accounts),
              "currencies": reference.scales, "checks": [],
              "compared_controls": {"file": "expected.json", **snapshot(out / "expected.json")},
              "helper_sha256": snapshot(Path(__file__))["sha256"], "python_version": sys.version,
              "tool_hash_scope": "Hashes bind the resolved executable files; Python launcher hashes do not bind all installed package dependencies."}
    try:
        for name, path in tools.items():
            version = commands.run(f"{name}-version", [str(path), "--version"], allow_stderr=True)
            require(version.strip(), f"{name} returned no version")
            tool_pins[name]["version"] = version.strip()
        bean_path = str(retained / filenames["beancount"])
        commands.run("bean-check", [str(tools["bean_check"]), bean_path])
        report["checks"].append("bean_check_validates_untouched_export")
        for measure, clause in (("net", ""), ("debit", " WHERE number > 0"), ("credit", " WHERE number < 0")):
            output = commands.run(f"beanquery-{measure}",
                                  [str(tools["bean_query"]), "-f", "csv", bean_path, QUERY.format(where=clause)])
            observed = parse_beanquery(output, maps["beancount"], reference.scales)
            compare_cells(observed, expected_cells(reference, measure), f"bean-query {measure}/posting-count")
            report["checks"].append(f"beanquery_{measure}_and_counts_match_every_native_cell")
        base = [str(tools["hledger"]), "--no-conf", "-f", str(retained / filenames["hledger"])]
        output = commands.run("hledger-postings", [*base, "print", "-O", "csv"])
        observed = parse_hledger_postings(output, maps["hledger"], reference)
        write_json(out / "hledger-posting-controls.json", {"cells": cell_rows(observed, reference.scales)})
        report["checks"].append("hledger_parsed_postings_match_native_net_gross_and_counts")
        for index, unit in enumerate(sorted({key[1] for key in reference.cells})):
            for measure, query in (("net", []), ("debit", ["amt:>0"]), ("credit", ["amt:<0"])):
                output = commands.run(f"hledger-{index:02}-{measure}",
                                      [*base, "balance", "--flat", "--no-total", "--empty", "-O", "csv",
                                       f"cur:^{re.escape(unit)}$", *query])
                actual = parse_hledger_balances(output, maps["hledger"], unit, reference.scales[unit])
                expected = {key: value[0] for key, value in expected_cells(reference, measure).items()
                            if key[1] == unit}
                compare_cells(actual, expected, f"hledger {unit} {measure}")
        report["checks"].extend(["hledger_independent_net_balances_match_every_native_cell",
                                 "hledger_independent_gross_debits_match_every_native_cell",
                                 "hledger_independent_gross_credits_match_every_native_cell"])
        report["status"] = "PASS"
    except Unavailable as error:
        report.update(status="UNRUN", error=str(error))
    except (OracleError, OSError, UnicodeError, ValueError) as error:
        report.update(status="FAIL", error=str(error))
    # An observed change to either submitted bytes or an executable invalidates
    # the completed result. Never publish a success for a different input.
    try:
        for name, path in inputs.items():
            expected = {key: input_pins[name][key] for key in ("sha256", "bytes")}
            require(snapshot(path) == expected and snapshot(retained / filenames[name]) == expected,
                    f"{name} bytes changed during external verification")
        for name, path in tools.items():
            require(snapshot(path) == {key: tool_pins[name][key] for key in ("sha256", "bytes")},
                    f"{name} executable changed during external verification")
        report["checks"].append("original_snapshot_and_executable_hashes_unchanged")
    except (OracleError, OSError) as error:
        report.update(status="FAIL", error=str(error))
    report["commands"] = len(commands.records)
    report["command_transcript"] = {"file": "commands.jsonl", **snapshot(out / "commands.jsonl")}
    write_json(out / "report.json", report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv-gl", type=Path, required=True, help="untouched fa export csv-gl output")
    parser.add_argument("--beancount", type=Path, required=True, help="untouched same-coordinate Beancount export")
    parser.add_argument("--hledger-journal", type=Path, required=True, help="untouched same-coordinate hledger export")
    parser.add_argument("--out", type=Path, required=True, help="new directory for immutable input copies and tool transcripts")
    parser.add_argument("--bean-check", type=Path, help="real bean-check executable; default PATH")
    parser.add_argument("--bean-query", type=Path, help="real bean-query executable; default PATH")
    parser.add_argument("--hledger", type=Path, help="real hledger executable; default PATH (requires --no-conf)")
    parser.add_argument("--timeout", type=int, default=300, help="per-command timeout in seconds")
    args = parser.parse_args(argv)
    try:
        report = run_oracle(args.csv_gl, args.beancount, args.hledger_journal, args.out,
                            bean_check=args.bean_check, bean_query=args.bean_query,
                            hledger=args.hledger, timeout=args.timeout)
    except Unavailable as error:
        report = {"status": "UNRUN", "error": str(error)}
    except (OracleError, OSError, UnicodeError, ValueError) as error:
        report = {"status": "FAIL", "error": str(error)}
    print(json.dumps({key: report[key] for key in ("status", "error", "entries", "postings", "account_currency_cells", "commands")
                      if key in report}, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "UNRUN": 4}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
