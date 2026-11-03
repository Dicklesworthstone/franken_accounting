#!/usr/bin/env python3
"""Replay authentic OMES ledger activity through fa and the independent verifier.

This is an integration driver, not another accounting engine. Python derives a
source oracle using integer cents; every journal write, approval, migration,
register and proof uses the real binaries. See docs/public_ledger.md for scope.
"""

from __future__ import annotations

import argparse
import calendar
from collections import defaultdict
import csv
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
import tomllib
import uuid
from typing import Callable

import public_ledger_source as source


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/fa-oracles/fixtures/public_ledger"
SOURCE_SYSTEM = "oklahoma-omes-period-activity-v1"
# Docket's admitted MIME token contains no spaces. Keep the original Windows
# code page explicit without transcoding the retained publisher bytes.
ORIGINAL_CSV_MIME = "text/csv;charset=windows-1252"
SOURCE_UPLOADER = "public-data-source-uploader"
SOURCE_REVIEWER = "public-data-source-reviewer"
REVIEW_SCOPE = (
    "Source and helper documents are AgentUpload. A distinct local test "
    "principal records native Reviewed attestations; this exercises evidence "
    "admission, not independently authenticated human examination. Generated "
    "transforms do not assert the receipt-derived Generated provenance grade."
)
PERIODS = ["FY2024-P10", "FY2024-P11", "FY2024-P12"]
DIMENSION_ENCODING = "fa-dimension-ids-v1"
CSV_GL_COLUMNS = (
    "entry_id", "line_no", "effective_date", "recorded_seq", "entry_class",
    "account_code", "side", "amount", "currency", "unit_scale", "description",
    "migrated_from", "memo", "dimension_set_v1",
)
ADS_GL_COLUMNS = (
    "Journal_ID", "Journal_Entry_Line_Number", "Effective_Date", "Recorded_Seq", "Entry_Class",
    "GL_Account_Number", "Debit_Credit_Indicator", "Amount", "Transaction_Currency", "Unit_Scale",
    "JE_Header_Description", "Migrated_From", "Line_Description", "FA_Dimension_Set_V1",
)
COLUMN_MAP = '''[columns]
source_system = "oklahoma-omes-period-activity-v1"
entry_id_column = "entry_id"
effective_date_column = "effective_date"
account_column = "account_code"
signed_amount_column = "signed_amount"
description_column = "description"

[dimension_columns]
department = "original_DEPTID"
'''
SCOPE = (
    "Complete published FY2024 Q4 activity for one agency, all chartfields. "
    "Source rows are monthly chartfield aggregates, not original journal lines. "
    "This activity-only book has no agency opening stock; dates are declared "
    "period ends. Native FullDetail describes this scoped activity import, "
    "not recovered transaction-level history or the agency's financial statements."
)


class ReplayError(Exception):
    """An input, native command or independent reconciliation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayError(message)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")



def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def publish_bytes(path: Path, content: bytes) -> None:
    """Publish a complete immutable file, retaining any interrupted temporary.

    Linking a synced file is exclusive and atomic: a crash cannot expose a
    half-written authoritative checkpoint. Pending files are never read as
    checkpoints and are kept for investigation, not automatically deleted.
    """
    if path.exists():
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == content,
                f"retained file differs: {path}")
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    else:
        pending = path.with_name(f".pending-{path.name}-{uuid.uuid4().hex}")
        with pending.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_fact(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), f"missing recovery checkpoint: {path}")
    record = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(record, dict) and set(record) == {"sha256", "value"}
            and isinstance(record["value"], dict), f"invalid recovery checkpoint: {path}")
    require(record["sha256"] == hashlib.sha256(json_bytes(record["value"])).hexdigest(),
            f"recovery checkpoint checksum differs: {path}")
    return record["value"]


class ReplayRecovery:
    """Retained workflow inputs, never an alternative journal or receipt store."""

    def __init__(self, output: Path, path: Path, agency: str,
                 binary: Path, verifier: Path, *, resume: bool,
                 on_created: Callable[[], None] | None = None):
        try:
            import fcntl
        except ImportError as error:
            raise ReplayError("resumable native runs require POSIX advisory file locking") from error
        self.output = output
        self.directory = output / "recovery"
        self.resumed = resume
        self.attempt: Path | None = None
        self.lock = None
        self.manifest, self.artifacts = preparation_artifacts(path, agency)
        pins = {
            "format": "fa-public-ledger-recovery-v1", "agency": agency,
            "input_sha256": sha256(path),
            "artifacts": {name: hashlib.sha256(content).hexdigest()
                          for name, content in sorted(self.artifacts.items())},
            "runtime": {
                "fa_sha256": sha256(binary), "fa_verify_sha256": sha256(verifier),
                "driver_sha256": sha256(Path(__file__)),
                "normalizer_sha256": sha256(Path(source.__file__)),
                "python_version": list(sys.version_info[:3]),
            },
        }
        self.facts: dict[str, dict] = {}
        if resume:
            saved = read_fact(self.directory / "pins.json")
            require({key: saved.get(key) for key in pins} == pins,
                    "resume source, agency, normalization, Python or executable pins differ")
            require(set(saved) == set(pins) | {"source_path", "fa_path", "fa_verify_path"},
                    "recovery pins have unexpected fields")
            require(not (output / "report.json").exists(), "run already completed; preserve and read report.json")
        else:
            require(not output.exists(), "output already exists; use run --resume for an interrupted pinned run")
            output.mkdir(parents=True, exist_ok=False)
            if on_created is not None:
                on_created()
            self.directory.mkdir()
            self.save("pins", {**pins, "source_path": str(path.resolve(strict=True)),
                               "fa_path": str(binary.resolve(strict=True)),
                               "fa_verify_path": str(verifier.resolve(strict=True))})
        # Lock a pre-existing immutable file, so refusal never creates a lock
        # file in another run. A process death releases the advisory lock.
        self.lock = (self.directory / "pins.json").open("rb")
        try:
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(not (output / "report.json").exists(), "run already completed; preserve and read report.json")
            allowed_plans = {f"plan-{run['name']}" for run in self.manifest["runs"]}
            for checkpoint in sorted(self.directory.glob("*.json")):
                name = checkpoint.stem
                require(name in {"pins", "book", "preactivation"} or name in allowed_plans
                        or name.startswith("input-"), f"unknown recovery checkpoint: {name}")
                self.facts[name] = read_fact(checkpoint)
            for name, content in self.artifacts.items():
                self.check_input(output / name, content)
            for name, value in self.facts.items():
                if name.startswith("input-"):
                    filename, content = self.input_value(value)
                    require(name == f"input-{filename}", "recovery input name differs")
                    require(filename not in self.artifacts, "recovery input shadows a source artifact")
                    self.check_input(output / filename, content)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    @staticmethod
    def check_input(path: Path, content: bytes) -> None:
        if path.exists():
            require(path.is_file() and not path.is_symlink() and path.read_bytes() == content,
                    f"retained input differs: {path}")

    @staticmethod
    def input_value(value: dict) -> tuple[str, bytes]:
        require(set(value) == {"name", "hex"} and isinstance(value["name"], str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value["name"]) is not None,
                "invalid retained input name")
        content = bytes.fromhex(value["hex"])
        require(content.hex() == value["hex"], "retained input has noncanonical byte encoding")
        return value["name"], content

    def save(self, name: str, value: dict) -> dict:
        if name in self.facts:
            require(self.facts[name] == value, f"immutable recovery checkpoint differs: {name}")
        record = {"sha256": hashlib.sha256(json_bytes(value)).hexdigest(), "value": value}
        publish_bytes(self.directory / f"{name}.json", json_bytes(record))
        self.facts[name] = value
        return value

    def restore_inputs(self) -> None:
        # Only after every pin, existing file and native scope passed preflight.
        for name, content in self.artifacts.items():
            publish_bytes(self.output / name, content)
        for name, value in self.facts.items():
            if name.startswith("input-"):
                filename, content = self.input_value(value)
                publish_bytes(self.output / filename, content)

    def input(self, name: str, content: bytes) -> Path:
        value = {"name": name, "hex": content.hex()}
        self.input_value(value)
        path = self.output / name
        require(name not in self.artifacts, "dynamic input shadows a source artifact")
        require(f"input-{name}" in self.facts or not path.exists(),
                f"untracked native input exists: {path}")
        self.save(f"input-{name}", value)
        publish_bytes(path, content)
        return path

    def input_json(self, name: str, value: dict) -> Path:
        return self.input(name, json_bytes(value))

    def retained_json(self, name: str) -> dict:
        fact = self.facts.get(f"input-{name}")
        require(fact is not None, f"native progress has no retained input: {name}")
        filename, content = self.input_value(fact)
        require(filename == name, "retained input identity differs")
        value = json.loads(content)
        require(isinstance(value, dict), "retained native input is not an object")
        return value

    def begin_attempt(self) -> Path:
        attempts = self.output / "attempts"
        attempts.mkdir(exist_ok=True)
        numbers = [int(path.name) for path in attempts.iterdir()
                   if path.is_dir() and re.fullmatch(r"[0-9]{6}", path.name)]
        require(not numbers or max(numbers) < 999999, "too many replay attempts")
        self.attempt = attempts / f"{max(numbers, default=0) + 1:06}"
        self.attempt.mkdir(exist_ok=False)
        return self.attempt

    def remember_book(self, info: dict) -> None:
        require(re.fullmatch(r"[0-9a-f]{32}", info["book_id"], re.ASCII) is not None,
                "native book identity is invalid")
        require(info["base_unit"] == "USD" and info["entities"] == [],
                "native book scope differs from the declared activity book")
        self.save("book", {key: info[key] for key in ("book_id", "base_unit", "calendar", "entities")})


def money(cents: int) -> str:
    return f"{'-' if cents < 0 else ''}{abs(cents) // 100}.{abs(cents) % 100:02}"


def period_end(period: int) -> str:
    require(period in (10, 11, 12), f"unsupported source fiscal period {period}")
    month = period - 6
    return f"2024-{month:02}-{calendar.monthrange(2024, month)[1]:02}"


def input_provenance(path: Path, agency: str) -> tuple[dict, list[int] | None]:
    """Trust checked-in pins, never an untrusted sidecar supplied with a file."""
    digest = sha256(path)
    if digest == source.SOURCE_SHA256:
        require(path.stat().st_size == source.SOURCE_SIZE_BYTES, "source size differs")
        return {"kind": "complete_distribution", "sha256": digest}, None
    manifest_path = FIXTURES / f"omes-fy2024-q4-{agency}.json"
    require(manifest_path.is_file(), "input is not the pinned distribution or a pinned agency fixture")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(digest == manifest["subset_sha256"], "agency fixture SHA-256 differs from its committed pin")
    require(path.stat().st_size == manifest["subset_bytes"], "agency fixture size differs")
    require(manifest["business_unit"] == agency, "fixture belongs to another agency")
    require(manifest["source_sha256"] == source.SOURCE_SHA256, "fixture pins a different distribution")
    records = [row["record_index"] for row in manifest["source_records"]]
    require(len(records) == manifest["rows"], "fixture record map has the wrong length")
    require(records == sorted(set(records)), "fixture record map is not unique and increasing")
    return {"kind": "complete_agency_selection", "sha256": digest, "manifest": manifest}, records


def original_bytes(path: Path, agency: str) -> bytes:
    """Select original logical records byte-for-byte, including CRLF."""
    class Lines:
        def __init__(self, stream):
            self.stream = stream
            self.consumed: list[bytes] = []

        def __iter__(self):
            return self

        def __next__(self):
            line = next(self.stream)
            self.consumed.append(line)
            return line.decode("cp1252")

    with path.open("rb") as raw, io.BytesIO() as out:
        physical = Lines(raw)
        records = csv.reader(physical, strict=True)
        header = next(records)
        require(header == list(source.HEADERS), "source schema differs during extraction")
        out.write(b"".join(physical.consumed))
        physical.consumed.clear()
        for fields in records:
            require(len(fields) == len(header), "ragged source record during extraction")
            if fields[0] == agency:
                out.write(b"".join(physical.consumed))
            physical.consumed.clear()
        return out.getvalue()


def extract_original(path: Path, destination: Path, agency: str) -> None:
    with destination.open("xb") as stream:
        stream.write(original_bytes(path, agency))


def account_spec(code: str, name: str) -> dict:
    types = {"1": "Asset", "2": "Liability", "3": "Equity", "4": "Revenue", "5": "Expense"}
    if code == "631100":
        # The source calls this Other Financing Sources/Uses, not revenue.
        # Equity is an explicit activity-book crosswalk, never a GAAP assertion.
        kind = "Equity"
    else:
        require(code[:1] in types, f"account {code} needs an explicit classification crosswalk")
        kind = types[code[0]]
    return {"code": code, "name": name, "type": kind, "unit": "USD"}


def oracle(rows: list[dict]) -> dict[str, dict[str, int]]:
    """Fold original source fields independently of normalized migration files."""
    result: dict[str, dict[str, int]] = {period: defaultdict(int) for period in PERIODS}
    for row in rows:
        fields = row["fields"]
        period = f"FY{fields['FISCAL_YEAR']}-P{int(fields['ACCOUNTING_PERIOD']):02}"
        require(period in result, f"unexpected source period {period}")
        result[period][fields["ACCOUNT"]] += source.amount_cents(fields["SUM(L.POSTED_TOTAL_AMT)"])
    return {period: dict(cells) for period, cells in result.items()}


def gross_oracle(rows: list[dict]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {period: defaultdict(int) for period in PERIODS}
    for row in rows:
        fields = row["fields"]
        period = f"FY{fields['FISCAL_YEAR']}-P{int(fields['ACCOUNTING_PERIOD']):02}"
        cents = source.amount_cents(fields["SUM(L.POSTED_TOTAL_AMT)"])
        side = "debit" if cents >= 0 else "credit"
        result[period][f"{fields['ACCOUNT']}:{side}"] += abs(cents)
    return {period: dict(cells) for period, cells in result.items()}


def department_code(value: str) -> str | None:
    """Preserve an identifier exactly; a whitespace-only source field is absent."""
    require(isinstance(value, str), "source department must be a string")
    if not value.strip():
        return None
    require(value == value.strip(), f"nonblank department code has surrounding whitespace: {value!r}")
    require(1 <= len(value) <= 64 and all("!" <= character <= "~" for character in value),
            "department code must be 1..64 printable ASCII characters without spaces")
    return value


def department_specs(rows: list[dict]) -> list[dict[str, str]]:
    names: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        fields = row["fields"]
        code = department_code(fields["DEPTID"])
        if code is None:
            continue
        descriptions = names[code]
        if fields["DEPTDESCR"].strip():
            descriptions.add(fields["DEPTDESCR"])
        require(len(descriptions) <= 1, f"department {code} has conflicting source descriptions")
    return [{"code": code, "name": next(iter(labels)) if labels else f"OMES department {code}"}
            for code, labels in sorted(names.items())]


def department_oracle(rows: list[dict]) -> dict[str, dict[str, dict]]:
    """Fold raw DEPTID/account/month cells; the empty key denotes untagged rows.

    Departments need not balance individually. No missing value is assigned to
    an invented department to make a departmental trial balance balance.
    """
    result: dict[str, dict[str, dict]] = {period: {} for period in PERIODS}
    for row in rows:
        fields = row["fields"]
        period = f"FY{fields['FISCAL_YEAR']}-P{int(fields['ACCOUNTING_PERIOD']):02}"
        require(period in result, f"unexpected source period {period}")
        code = department_code(fields["DEPTID"]) or ""
        bucket = result[period].setdefault(code, {
            "rows": 0, "monetary_rows": 0, "account_nets": {}, "gross_cents": {},
        })
        amount = source.amount_cents(fields[source.AMOUNT_COLUMN])
        account = fields["ACCOUNT"]
        bucket["rows"] += 1
        bucket["monetary_rows"] += int(amount != 0)
        bucket["account_nets"][account] = bucket["account_nets"].get(account, 0) + amount
        side = "credit" if amount < 0 else "debit"
        cell = f"{account}:{side}"
        bucket["gross_cents"][cell] = bucket["gross_cents"].get(cell, 0) + abs(amount)
    return result


def preparation_artifacts(path: Path, agency: str) -> tuple[dict, dict[str, bytes]]:
    """Recompute every source-derived input without touching an existing run."""
    provenance, record_map = input_provenance(path, agency)
    selected = source.prepare_agency(path, agency, source_records=record_map)
    rows = selected["rows"]
    require(bool(rows), f"no published rows for agency {agency}")
    require({r["fields"]["FISCAL_YEAR"] for r in rows} == {"2024"}, "unexpected fiscal year")
    require({r["fields"]["ACCOUNTING_PERIOD"] for r in rows} == {"10", "11", "12"}, "agency must cover all three quarter periods")
    departments = department_specs(rows)
    department_activity = department_oracle(rows)
    original = original_bytes(path, agency)
    artifacts = {"original-agency.csv": original}
    activity = oracle(rows)
    accounts = sorted({r["fields"]["ACCOUNT"]: r["fields"]["ACCTDESCR"] for r in rows}.items())
    chart = [account_spec(code, name) for code, name in accounts]
    artifacts["chart.json"] = json_bytes({"accounts": chart})
    artifacts["column_map.toml"] = COLUMN_MAP.encode("utf-8")

    # Separate native migration runs follow actual fund/class boundaries.
    # Each source monetary row is one leg. No row is split or netted away.
    partitions: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for group in selected["groups"]:
        fy, period, ledger, fund, cls = group["key"]
        require(str(fy) == "2024" and str(period) in ("10", "11", "12"), "unexpected group key")
        require(ledger == "ACTUALS", "only published ACTUALS ledger is admitted")
        partitions[(ledger, fund, cls)].append(group)
    fieldnames = ["entry_id", "effective_date", "account_code", "signed_amount", "description", "source_record"]
    fieldnames += [f"original_{column}" for column in source.HEADERS]
    used: set[int] = set()
    omitted_zero: list[int] = []
    runs: list[dict] = []
    mapping: list[dict] = []
    for index, (key, groups) in enumerate(sorted(partitions.items())):
        monetary = [r for group in groups for r in group["rows"] if r["amount_mills"] != 0]
        zeros = [r["source_record"] for group in groups for r in group["rows"] if r["amount_mills"] == 0]
        omitted_zero.extend(zeros)
        if not monetary:
            continue
        name = f"run-{index:03}"
        normalized = f"{name}.csv"
        run_rows: list[dict] = []
        group_ids = []
        with io.StringIO(newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for group in sorted(groups, key=lambda g: int(g["key"][1])):
                year, period, ledger, fund, cls = group["key"]
                entry_id = f"OK:{agency}:{year}:{period}:{ledger}:{fund}:{cls}"
                legs = [r for r in group["rows"] if r["amount_mills"]]
                if not legs:
                    continue
                group_ids.append(entry_id)
                for leg_index, row in enumerate(legs, 1):
                    record = row["source_record"]
                    require(record not in used, f"source record {record} was mapped twice")
                    used.add(record)
                    original_fields = row["fields"]
                    cents = source.amount_cents(original_fields["SUM(L.POSTED_TOTAL_AMT)"])
                    values = {f"original_{column}": original_fields[column] for column in source.HEADERS}
                    values.update(entry_id=entry_id, effective_date=period_end(int(period)),
                                  account_code=original_fields["ACCOUNT"], signed_amount=money(cents),
                                  description=f"Published OMES period activity {entry_id}; aggregate, not an original journal entry",
                                  source_record=str(record))
                    writer.writerow(values)
                    run_rows.append(row)
                    mapping.append({"source_record": record, "run": name, "entry_id": entry_id,
                                    "leg": leg_index, "account": original_fields["ACCOUNT"], "cents": cents,
                                    "department": department_code(original_fields["DEPTID"])})
            artifacts[normalized] = stream.getvalue().encode("utf-8")
        runs.append({"name": name, "key": list(key), "source": normalized,
                     "sha256": hashlib.sha256(artifacts[normalized]).hexdigest(), "entry_ids": group_ids,
                     "rows": len(run_rows), "activity_cents": oracle(run_rows)})
    require(used | set(omitted_zero) == {r["source_record"] for r in rows}, "source-row coverage gap")
    require(not (used & set(omitted_zero)), "zero/monetary source-row overlap")
    manifest = {
        "format": "fa-public-ledger-replay-v1", "scope": SCOPE,
        "source_url": source.SOURCE_URL, "source_sha256": source.SOURCE_SHA256,
        "source_encoding": source.SOURCE_ENCODING, "normalized_encoding": "utf-8",
        "original_selection_mime": ORIGINAL_CSV_MIME,
        "review_scope": REVIEW_SCOPE,
        "input_sha256": provenance["sha256"], "input_kind": provenance["kind"],
        "agency": agency, "agency_name": rows[0]["fields"]["OCP_AGNCY_NAME"],
        "original_selection_sha256": hashlib.sha256(original).hexdigest(), "source_rows": len(rows),
        "source_columns": len(source.HEADERS), "account_count": len(accounts),
        "monetary_rows": len(used), "zero_rows": sorted(omitted_zero),
        "row_mapping": mapping, "runs": runs, "activity_cents": activity,
        "activity_gross_cents": gross_oracle(rows),
        "departments": departments, "department_activity": department_activity,
        "date_policy": "FY2024 periods 10/11/12 map to 2024-04-30/05-31/06-30; source has no transaction dates",
        "chart_policy": "OMES prefixes 1 Asset, 2 Liability, 3 Equity, 4 Revenue, 5 Expense; explicit 631100 Other Financing Sources/Uses -> Equity in the activity-only test book",
        "dimension_policy": "original_DEPTID maps to native department; nonblank codes stay exact strings, whitespace-only is absent, and surrounding whitespace on a nonblank code is refused. Every other chartfield remains in retained evidence, without native projection. An empty department oracle key denotes untagged source rows; it is never a native value.",
        "oracle_policy": "Integer-cent fold of original source fields; not an audited agency opening/closing trial balance",
    }
    artifacts["manifest.json"] = json_bytes(manifest)
    return manifest, artifacts


def normalize(path: Path, agency: str, output: Path, *,
              on_created: Callable[[], None] | None = None) -> dict:
    manifest, artifacts = preparation_artifacts(path, agency)
    output.mkdir(parents=True, exist_ok=False)
    if on_created is not None:
        on_created()
    for name, content in artifacts.items():
        with (output / name).open("xb") as stream:
            stream.write(content)
    return manifest


class Native:
    def __init__(self, binary: Path, verifier: Path, output: Path):
        self.binary = binary.resolve(strict=True)
        self.verifier = verifier.resolve(strict=True)
        self.output = output
        self.book = output / "book"
        self.commands = 0
        self.document_custody: list[dict] = []
        self.log_path: Path | None = output / "commands.jsonl"
        self.environment = dict(os.environ)
        self.environment.pop("FA_BOOK", None)
        self.environment.pop("FA_TOKEN", None)
        self.environment.update(NO_COLOR="1", CI="1")

    def execute_events(self, command: list[str], expect: int | tuple[int, ...] = 0,
                       *, input_text: str | None = None) -> tuple[list[dict], str]:
        self.commands += 1
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                input=input_text, env=self.environment, timeout=600, check=False)
        if self.log_path is not None:
            with self.log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps({"command": command, "exit": result.returncode,
                                      "stdout": result.stdout, "stderr": result.stderr}, ensure_ascii=False) + "\n")
        accepted = (expect,) if isinstance(expect, int) else expect
        require(result.returncode in accepted,
                f"native command exited {result.returncode}, expected {expect}: {command!r}\n{result.stdout}\n{result.stderr}")
        try:
            lines = result.stdout.splitlines()
            require(bool(lines), f"native command returned no robot envelope: {command!r}")
            values = [json.loads(line) for line in lines]
        except (ValueError, IndexError) as error:
            raise ReplayError(f"invalid native JSON from {command!r}") from error
        require(all(isinstance(value, dict) for value in values), "native result is not a JSON object")
        return values, result.stdout

    def execute(self, command: list[str], expect: int | tuple[int, ...] = 0,
                *, input_text: str | None = None) -> dict:
        values, _ = self.execute_events(command, expect, input_text=input_text)
        require(len(values) == 1, f"native command did not return one robot envelope: {command!r}")
        return values[0]

    def command(self, *args: object) -> list[str]:
        return [str(self.binary), "--book", str(self.book), *map(str, args), "--json"]

    def call(self, *args: object, expect: int | tuple[int, ...] = 0,
             input_text: str | None = None) -> dict:
        return self.execute(self.command(*args), expect, input_text=input_text)

    def document(self, path: Path, kind: str = "Spreadsheet", mime: str = "text/csv") -> str:
        # These bytes were fetched or transformed by the driver. Neither a
        # public publisher nor a generated file makes this a human upload or
        # establishes the receipt chain required for the Generated grade.
        added = self.call("document", "add", path, "--kind", kind, "--mime", mime,
                          "--grade", "AgentUpload", "--as", SOURCE_UPLOADER)
        require(added.get("event") == "document", "source intake did not return a document receipt")
        document = added["data"]
        require(document.get("grade") == "AgentUpload" and document.get("self_sourced") is True,
                "source intake did not retain the declared self-sourced AgentUpload provenance")
        oid = document["oid"]
        require(isinstance(oid, str) and re.fullmatch(r"[0-9a-f]{64}", oid, re.ASCII) is not None,
                "source intake returned an invalid document identity")
        # The real evidence law requires a different principal's Reviewed
        # attestation before self-sourced evidence can meet a posting minimum.
        # These are local fixture principals, as declared by REVIEW_SCOPE.
        reviewed = self.call("document", "attest", "review", "--document", oid,
                             "--as", SOURCE_REVIEWER, "--grant", "approve")
        require(reviewed.get("event") == "attestation_recorded"
                and reviewed["data"].get("claim") == "Reviewed"
                and reviewed["data"].get("subject") == oid,
                "source review did not attest the retained document")
        review = reviewed["data"]
        # A distinct test principal exercises the native review law. It is
        # operated by this same harness, not an independent human auditor.
        self.document_custody.append({
            "file": path.name, "oid": oid, "doc_commit": document["doc_commit"],
            "intake_grade": document["grade"], "self_sourced": document["self_sourced"],
            "intake_recorded_at": document["recorded_at"],
            "review_principal": SOURCE_REVIEWER, "review_claim": review["claim"],
            "review_attestation_vid": review["attestation_vid"],
            "review_recorded_at": review["recorded_at"],
        })
        return oid

    def head(self) -> int:
        return self.call("book", "info")["coordinate"]["known_at"]

    def approve(self, digest: str, label: str) -> list[str]:
        return [self.call("approve", "--proposal", digest, "--as", f"public-data-{label}-{reviewer}")
                ["data"]["approval_vid"] for reviewer in ("a", "b")]

    def register_departments(self, specifications: list[dict]) -> dict[str, dict]:
        values = {}
        for spec in specifications:
            code = spec["code"]
            require(department_code(code) == code and code not in values,
                    "department registry contains a blank or repeated source code")
            value = self.call("dimension", "add", "department", code, "--name", spec["name"])["data"]["value"]
            require(value["dimension"] == "department" and value["code"] == code,
                    f"native department registration changed source code {code}")
            values[code] = {"dimension": value["dimension_id"], "value": value["vid"]}
        require(len({value["value"] for value in values.values()}) == len(values),
                "distinct source departments share a native value identity")
        return values

    def tb(self, period: str, *, activity: bool = False, known_at: int | None = None,
           expected_gross: dict[str, int] | None = None,
           department: str | None = None) -> dict[str, int]:
        args: list[object] = ["tb", "--period", period]
        if activity:
            args.append("--activity")
        if known_at is not None:
            args.extend(["--as-known-at", known_at])
        if department is not None:
            args.extend(["--dimension", f"department={department}"])
        cells, _ = trial_balance_cells(self.call(*args)["data"], period, expected_gross, department)
        return cells

    def certified_department_tb(self, period: str, department: str,
                                expected_gross: dict[str, int]) -> tuple[dict[str, int], str]:
        command = self.command("tb", "--period", period, "--dimension", f"department={department}", "--certify")
        events, original = self.execute_events(command)
        require(len(events) == 2 and events[0].get("event") == "trial_balance"
                and events[1].get("event") == "report_certificate",
                "certified department TB must return its report and retained certificate")
        cells, _ = trial_balance_cells(events[0]["data"], period, expected_gross, department)
        certificate = events[1]["data"]
        require(certificate["output_format"] == "fa:dimension-trial-balance:v1",
                "department certificate has another report format")
        oid = certificate["oid"]
        require(events[0].get("certificate") == oid, "department report does not bind its retained certificate")
        replayed, replay_bytes = self.execute_events(self.command("replay", f"C:{oid}"))
        require(len(replayed) == 1 and replay_bytes == original.splitlines(keepends=True)[0],
                f"department {department} certificate did not replay the exact robot report")
        return cells, oid


def trial_balance_cells(data: dict, period: str, expected_gross: dict[str, int] | None,
                        department: str | None = None) -> tuple[dict[str, int], dict[str, int]]:
    if department is not None:
        require(data.get("dimension") == {"dimension": "department", "value": department, "values": [department]},
                f"native TB returned a different department scope than {department}")
    cells = {}
    gross = {}
    for row in data["rows"]:
        amount, unit = row["net"].rsplit(" ", 1)
        require(unit == "USD", f"unexpected native TB unit {unit}")
        require(row["code"] not in cells, "native TB repeats an account")
        cells[row["code"]] = source.amount_cents(amount)
        for field, side in (("debits", "debit"), ("credits", "credit")):
            amount, unit = row[field].rsplit(" ", 1)
            require(unit == "USD", f"unexpected native TB gross unit {unit}")
            gross[f"{row['code']}:{side}"] = source.amount_cents(amount)
        require(cells[row["code"]] == gross[f"{row['code']}:debit"] - gross[f"{row['code']}:credit"],
                f"native TB net disagrees with debit/credit amounts for {row['code']}")
    if expected_gross is not None:
        same_cells(gross, expected_gross, f"{period} department {department} gross debit/credit activity")
    return cells, gross


def same_cells(actual: dict[str, int], expected: dict[str, int], label: str) -> None:
    mismatches = {code: {"actual_cents": actual.get(code, 0), "expected_cents": expected.get(code, 0)}
                  for code in sorted(actual.keys() | expected.keys()) if actual.get(code, 0) != expected.get(code, 0)}
    require(not mismatches, f"{label}: account-cell mismatch: {json.dumps(mismatches, sort_keys=True)}")


def parse_dimension_set(text: str) -> list[dict]:
    """Read the declared native-identity wire; no value code is inferred from a VID."""
    if not text:
        return []
    items = text.split(";")
    require(len(items) <= 64, "exported dimension set exceeds its native bound")
    dimensions = []
    previous = -1
    for item in items:
        match = re.fullmatch(r"(0|[1-9][0-9]*):([0-9a-f]{32})", item, re.ASCII)
        require(match is not None, "exported dimension set has a noncanonical identity")
        kind, value = match.groups()
        kind = int(kind)
        require(previous < kind <= 0xFFFFFFFF, "exported dimension kinds are repeated, unordered or out of range")
        dimensions.append({"dimension": kind, "value": value})
        previous = kind
    return dimensions


def exported_rows(path: Path, format_name: str):
    """Read monetary fields and exact IDs from the public workload's exports.

    CSV uses logical records. ADS text escaping never inserts a literal pipe
    or newline inside a field; its text columns remain opaque here. The native
    round-trip reader separately checks descriptions, memos and certificates.
    """
    require(format_name in ("csv-gl", "ads"), "unsupported public-ledger export oracle")
    with path.open(encoding="utf-8", newline="") as stream:
        if format_name == "csv-gl":
            encoding = None
            header = None
            for line in stream:
                if line.startswith("#"):
                    if line.startswith("# fa_csv_gl_v1|"):
                        require(encoding is None, "CSV export repeats its coordinate header")
                        fields = line.rstrip("\r\n").split("|")
                        marker = [field for field in fields if field.startswith("dimension_encoding=")]
                        require(marker == [f"dimension_encoding={DIMENSION_ENCODING}"],
                                "CSV export does not declare native dimension identities")
                        encoding = DIMENSION_ENCODING
                    continue
                if line.strip():
                    header = next(csv.reader([line], strict=True))
                    break
            require(encoding == DIMENSION_ENCODING and header == list(CSV_GL_COLUMNS),
                    "CSV export lacks its complete dimension-bearing schema")
            records = csv.reader(stream, strict=True)
        else:
            certificate = tomllib.loads((path.parent / "ADS_Coordinate_Certificate.toml").read_text(encoding="utf-8"))
            require(certificate.get("dimension_encoding") == DIMENSION_ENCODING,
                    "ADS export does not declare native dimension identities")
            require(certificate.get("format") in ("aicpa_ads_gl_v2", "aicpa_ads_gl_v3"),
                    "ADS export uses an unknown text encoding")
            require(stream.readline().rstrip("\r\n").split("|") == list(ADS_GL_COLUMNS),
                    "ADS export lacks its complete dimension-bearing schema")
            records = (line.rstrip("\r\n").split("|") for line in stream)
        for fields in records:
            require(len(fields) == len(CSV_GL_COLUMNS), "exported GL row has the wrong field count")
            yield dict(zip(CSV_GL_COLUMNS, fields, strict=True))


def verify_exported_legs(manifest: dict, entry_ids: dict[str, str], department_values: dict[str, dict],
                         path: Path, format_name: str) -> dict:
    """Check every export leg against its original record and native registration.

    The source-to-entry identity map comes from the actual prepared proposals.
    Amounts and departments come from the independently checked source manifest,
    rather than another export or an account-level net balance.
    """
    source_entries = {row["entry_id"] for row in manifest["row_mapping"]}
    require(set(entry_ids) == source_entries and len(set(entry_ids.values())) == len(entry_ids),
            "export identity map does not cover each source entry exactly once")
    expected = {}
    for original in manifest["row_mapping"]:
        key = (entry_ids[original["entry_id"]], str(original["leg"]))
        require(key not in expected, "source manifest repeats an export leg")
        expected[key] = original
    require(len(expected) == manifest["monetary_rows"], "source manifest monetary row count differs")
    seen = set()
    ordinals: dict[str, int] = defaultdict(int)
    tagged = 0
    for row in exported_rows(path, format_name):
        key = (row["entry_id"], row["line_no"])
        require(key in expected and key not in seen, "export substituted, repeated or added a source leg")
        original = expected[key]
        ordinals[key[0]] += 1
        require(row["line_no"] == str(ordinals[key[0]]), "export reordered a source entry's legs")
        code = original["department"]
        require(code is None or code in department_values, "export source department is not registered")
        dimensions = [] if code is None else [department_values[code]]
        actual_dimensions = parse_dimension_set(row["dimension_set_v1"])
        require(actual_dimensions == dimensions,
                f"{format_name} changed dimension attribution of source record {original['source_record']}")
        period = int(original["entry_id"].split(":")[3])
        require(row["effective_date"] == period_end(period)
                and row["entry_class"] == "12"
                and row["account_code"] == original["account"]
                and row["side"] == ("D" if original["cents"] > 0 else "C")
                and row["amount"] == money(abs(original["cents"]))
                and row["currency"] == "USD" and row["unit_scale"] == "2",
                f"{format_name} changed monetary fields of source record {original['source_record']}")
        seen.add(key)
        tagged += bool(actual_dimensions)
    require(seen == set(expected), "export omitted original source legs")
    return {"format": format_name, "rows": len(seen), "tagged_rows": tagged,
            "untagged_rows": len(seen) - tagged, "dimension_encoding": DIMENSION_ENCODING}


def require_ads_dimension_proof(report: dict, rows: int) -> None:
    require(report.get("tool") == "fa-verify" and report.get("command") == "ads"
            and report.get("verdict") == "verified", "ADS verification did not succeed")
    checks = [check for check in report.get("checks", []) if check.get("check") == "ads_extract"]
    require(len(checks) == 1 and checks[0].get("result") == "pass",
            "ADS verifier did not prove the extract")
    detail = checks[0].get("detail", {})
    coverage = detail.get("dimension_rows")
    require(type(coverage) is int and coverage == rows and detail.get("rows") == rows,
            "ADS verifier did not authenticate dimensions on every exported source row")


def tamper_ads_amount(path: Path) -> dict:
    """Change one cent without changing the extract's schema or other fields."""
    lines = path.read_bytes().decode("utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines[1:], 1):
        fields = line.rstrip("\r\n").split("|")
        if len(fields) not in (13, 14) or fields[8:10] != ["USD", "2"]:
            continue
        old = fields[7]
        fields[7] = money(source.amount_cents(old) + 1)
        newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        lines[index] = "|".join(fields) + newline
        path.write_bytes("".join(lines).encode("utf-8"))
        return {"line": index + 1, "old_amount": old, "new_amount": fields[7], "delta_cents": 1}
    raise ReplayError("ADS export has no USD-cent monetary row for the tamper control")


def tamper_ads_dimension(path: Path) -> dict:
    """Change one native value identity, preserving every monetary and text field."""
    lines = path.read_bytes().decode("utf-8").splitlines(keepends=True)
    require(bool(lines) and lines[0].rstrip("\r\n").split("|") == list(ADS_GL_COLUMNS),
            "ADS dimension tamper control requires the dimension-bearing schema")
    for index, line in enumerate(lines[1:], 1):
        fields = line.rstrip("\r\n").split("|")
        require(len(fields) == len(ADS_GL_COLUMNS), "ADS dimension tamper control found a ragged row")
        dimensions = parse_dimension_set(fields[-1])
        if not dimensions:
            continue
        first = dimensions[0]
        old = first["value"]
        new = f"{int(old, 16) ^ 1:032x}"
        fields[-1] = ";".join(f"{value['dimension']}:{new if ordinal == 0 else value['value']}"
                              for ordinal, value in enumerate(dimensions))
        newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        lines[index] = "|".join(fields) + newline
        path.write_bytes("".join(lines).encode("utf-8"))
        return {"line": index + 1, "entry_id": fields[0], "leg": int(fields[1]),
                "dimension": first["dimension"], "old_value": old, "new_value": new}
    raise ReplayError("ADS export has no tagged row for the dimension tamper control")


def verify_prepared_legs(manifest: dict, run: dict, package: dict, department_values: dict[str, dict]) -> None:
    """Check native proposals row-for-row; a matching net alone is insufficient."""
    require(package["row_count"] == run["rows"], "native parser omitted or added source rows")
    require(package["chunk_count"] == len(run["entry_ids"]), "native parser changed source group count")
    require(len(package["chunks"]) == len(run["entry_ids"]), "native package omitted a chunk")
    for index, (entry_id, chunk) in enumerate(zip(run["entry_ids"], package["chunks"], strict=True)):
        expected = [row for row in manifest["row_mapping"]
                    if row["run"] == run["name"] and row["entry_id"] == entry_id]
        fiscal_period = int(entry_id.split(":")[3])
        require(chunk["index"] == index, "native chunk order differs")
        require(chunk["effective_date"] == period_end(fiscal_period), "native allocation date differs")
        require(chunk["document_date"] == period_end(fiscal_period), "native source date differs")
        require(chunk["effective_period"] == f"FY2024-P{fiscal_period:02}", "native fiscal period differs")
        require(chunk["counts_after_finalize"] is True, "source activity would be excluded after finalize")
        require(chunk["leg_count"] == len(expected) == len(chunk["legs"]), "native leg count differs")
        for ordinal, (actual, row) in enumerate(zip(chunk["legs"], expected, strict=True)):
            side = "debit" if row["cents"] > 0 else "credit"
            code = row["department"]
            require(code is None or code in department_values,
                    f"source department {code} has no registered native value")
            dimensions = [] if code is None else [department_values[code]]
            require(actual == {"index": ordinal, "account": row["account"], "side": side,
                               "amount": f"{money(abs(row['cents']))} USD", "dimensions": dimensions},
                    f"native proposal differs from original source record {row['source_record']}")


def verify_staged_group(event: dict, package: dict, run_vid: str, *,
                        retry: bool = False, recover: bool = False) -> list[dict]:
    require(event.get("event") == "migration_import_group_staged", "missing native grouped staging event")
    result = event["data"]
    chunks = package["chunks"]
    require(result.get("package_oid") == package["package_oid"] and result.get("run_vid") == run_vid,
            "native group refers to a different approved package or run")
    require(result.get("atomic") is False, "grouped chunks must retain separate native publications")
    require(result.get("selected_count") == result.get("completed_count")
            == result.get("recorded_count") == result.get("chunk_count") == len(chunks),
            "native group omitted or duplicated source chunks")
    expected_state = package["run_state"] if recover else ("Finalized" if retry else "Open")
    require(expected_state in ("Open", "Finalized") and result.get("run_state") == expected_state
            and result.get("ready_to_finalize") is (expected_state == "Open"),
            "native group returned an incorrect activation state")
    receipts = result.get("chunks")
    require(isinstance(receipts, list) and len(receipts) == len(chunks), "native group omitted chunk receipts")
    sequences = set()
    for index, (chunk, receipt) in enumerate(zip(chunks, receipts, strict=True)):
        require(receipt.get("chunk_index") == index and receipt.get("entry_vid") == chunk["entry_vid"]
                and receipt.get("proposal_digest") == chunk["proposal_digest"],
                "native grouped receipt differs from an approved source proposal")
        seq = receipt.get("recorded_at")
        require(type(seq) is int and seq > 0 and seq not in sequences, "native group repeats a publication sequence")
        sequences.add(seq)
        previous = chunk["recorded_at"] if recover else None
        expected_retry = retry or previous is not None
        require(receipt.get("already_recorded") is expected_retry, "native grouped receipt misstates its retry status")
        if previous is not None:
            require(type(previous) is int and seq == previous,
                    "recovered group changed an original native publication sequence")
    return receipts


def verify_department_balances(native: Native, manifest: dict, before_finalize: int) -> list[dict]:
    cumulative = {row["code"]: defaultdict(int) for row in manifest["departments"]}
    cumulative_gross = {code: defaultdict(int) for code in cumulative}
    for period in PERIODS:
        for code in cumulative:
            expected = manifest["department_activity"][period].get(code, {})
            net = expected.get("account_nets", {})
            gross = expected.get("gross_cents", {})
            same_cells(native.tb(period, activity=True, department=code, expected_gross=gross),
                       net, f"{period} department {code} activity")
            for account, cents in net.items():
                cumulative[code][account] += cents
            for cell, cents in gross.items():
                cumulative_gross[code][cell] += cents
            same_cells(native.tb(period, department=code, expected_gross=dict(cumulative_gross[code])),
                       dict(cumulative[code]), f"{period} department {code} cumulative")
            same_cells(native.tb(period, department=code, known_at=before_finalize), {},
                       f"{period} department {code} immutable preactivation history")
    certificates = []
    for code in cumulative:
        net, oid = native.certified_department_tb(PERIODS[-1], code, dict(cumulative_gross[code]))
        same_cells(net, dict(cumulative[code]), f"certified quarter activity for department {code}")
        certificates.append({"department": code, "period": PERIODS[-1], "certificate_oid": oid,
                             "account_nets": dict(cumulative[code]),
                             "gross_cents": dict(cumulative_gross[code])})
    return certificates



def run_key(manifest: dict, run: dict) -> str:
    return f"omes-{manifest['agency']}-{run['name']}"


def package_identity(package: dict) -> dict:
    return {
        key: package[key] for key in
        ("package_oid", "run_vid", "run_body_digest", "source_oid")
    } | {"chunks": [{"entry_vid": chunk["entry_vid"],
                    "proposal_digest": chunk["proposal_digest"]}
                   for chunk in package["chunks"]]}


def activation_membership(prepared: list[dict]) -> dict:
    result = {}
    for run in prepared:
        package = run["package"]
        require(package["recorded_count"] == package["chunk_count"] and package["ties_out"],
                "activation prefix requires every source chunk to be staged and tied out")
        require(all(type(chunk["recorded_at"]) is int and chunk["recorded_at"] > 0
                    for chunk in package["chunks"]), "native chunk receipt is missing")
        result[run["name"]] = {
            **package_identity(package),
            "recorded_at": [chunk["recorded_at"] for chunk in package["chunks"]],
        }
    return result


def check_finalization_plan(plan: dict, run: dict) -> None:
    require(isinstance(plan, dict) and set(plan) == {
        "run_vid", "action", "proposal_digest", "tie_out_digest", "chunk_count", "bytes", "plan",
    }, "retained finalization plan shape differs")
    require(plan["run_vid"] == run["run_vid"] and plan["action"] == "finalize"
            and plan["tie_out_digest"] == run["tie_out_digest"]
            and plan["chunk_count"] == run["chunk_count"] and plan["plan"] is None,
            "retained finalization plan differs from the native migration")
    for field in ("proposal_digest", "tie_out_digest"):
        require(isinstance(plan[field], str)
                and re.fullmatch(r"[0-9a-f]{64}", plan[field], re.ASCII) is not None,
                "retained finalization plan digest is invalid")
    wire = bytes.fromhex(plan["bytes"])
    require(wire.hex() == plan["bytes"] and wire.startswith(b"FA-MIGRATE-PLAN\0"),
            "retained finalization proposal bytes are invalid")


def preflight_recovery(native: Native, recovery: ReplayRecovery) -> dict[str, dict]:
    """Read the real book before restoring files or making a continuation write."""
    manifest = recovery.manifest
    book_fact = recovery.facts.get("book")
    if not native.book.exists():
        require(book_fact is None, "the pinned native book is missing; do not create a replacement")
        require(not any(name != "pins" for name in recovery.facts),
                "recovery progress exists without its native book")
        return {}
    require(book_fact is not None,
            "existing book has no pinned identity; genesis acknowledgement was not retained, so refuse adoption")
    info = native.call("book", "info")["data"]
    require({key: info.get(key) for key in book_fact} == book_fact
            and set(book_fact) == {"book_id", "base_unit", "calendar", "entities"},
            "native book identity or declared scope differs")

    expected_accounts = {row["code"]: row for row in json.loads(recovery.artifacts["chart.json"])["accounts"]}
    observed_accounts = native.call("chart", "list")["data"]["accounts"]
    for account in observed_accounts:
        expected = expected_accounts.get(account["code"])
        require(expected is not None and all(account.get(key) == expected[key]
                                            for key in ("code", "name", "type", "unit"))
                and account.get("leaf") is True
                and all(account.get(key) is None for key in ("lower_bound", "upper_bound", "limit_scope")),
                f"native chart differs from source crosswalk: {account['code']}")
    require(len({row["code"] for row in observed_accounts}) == len(observed_accounts),
            "native chart repeats an account")
    expected_departments = {spec["code"]: spec["name"] for spec in manifest["departments"]}
    departments = {}
    for value in native.call("dimension", "list", "department")["data"]["values"]:
        require(value["dimension"] == "department" and value["code"] in expected_departments
                and value["code"] not in departments and value["name"] == expected_departments[value["code"]]
                and all(value[field] is None for field in ("parent", "valid_from", "valid_to")),
                "native department definition differs from the retained source")
        departments[value["code"]] = {"dimension": value["dimension_id"], "value": value["vid"]}

    expected_runs = {run_key(manifest, run): run for run in manifest["runs"]}
    current = {}
    for key, run in expected_runs.items():
        response = native.call("migrate", "show", key, expect=(0, 3))
        if response.get("event") == "error":
            require(response["data"].get("exit") == 3
                    and response["data"].get("refusal_id") == "FA-REF-132",
                    f"cannot inspect native migration {key}")
            require(f"input-{run['name']}-import.json" not in recovery.facts,
                    f"previously opened native migration is missing: {key}")
            continue
        require(response.get("event") == "migration_run", "unexpected migration inspection response")
        actual = response["data"]
        require(actual["state"] in ("Open", "Finalized"),
                f"native migration {key} is {actual['state']}; an abandoned run cannot be resumed")
        original = recovery.retained_json(f"{run['name']}-open.json")
        require(actual["run_key"] == key and original["run_key"] == key
                and actual["source_system"] == original["source_system"] == SOURCE_SYSTEM
                and actual["mode"] == original["mode"] == "FullDetail"
                and actual["opening_date"] == original["opening_date"] == "2024-07-01"
                and actual["trial_balance_oid"] == original["trial_balance"],
                f"native migration declaration differs: {key}")
        current[key] = actual

    packages = {}
    documents = native.call("document", "list")["data"]["documents"]
    package_mimes = {
        "application/vnd.frankenaccounting.legacy-opening-import.v1",
        "application/vnd.frankenaccounting.legacy-period-balances-import.v1",
        "application/vnd.frankenaccounting.legacy-full-detail-import.v1",
    }
    for document in documents:
        if document["mime"] not in package_mimes:
            continue
        package = native.call("migrate", "import", "--action", "show",
                              "--package", document["oid"])["data"]
        key = package["run_key"]
        require(key in current and key not in packages and package["mode"] == "FullDetail",
                "native book contains an unexpected or duplicate migration package")
        run = expected_runs[key]
        actual = current[key]
        original = recovery.retained_json(f"{run['name']}-import.json")
        expected_intent = {
            "run": f"MR:{actual['run_vid']}", "source": f"D:{package['source_oid']}",
            "format": "csv", "column_map": COLUMN_MAP,
            "entry_periods": {entry_id: f"FY2024-P{int(entry_id.split(':')[3]):02}"
                              for entry_id in run["entry_ids"]},
            "account_map": {code: code for code in expected_accounts},
        }
        require(original == expected_intent, "retained import configuration differs from its native package")
        require(package["package_oid"] == document["oid"] and package["run_vid"] == actual["run_vid"]
                and package["run_state"] == actual["state"], "native package identity or state differs")
        verify_prepared_legs(manifest, run, package, departments)
        recorded = [{"vid": chunk["entry_vid"], "proposal_digest": chunk["proposal_digest"],
                     "recorded_at": chunk["recorded_at"]}
                    for chunk in package["chunks"] if chunk["recorded_at"] is not None]
        require(len(recorded) == package["recorded_count"] == actual["chunk_count"]
                and sorted(recorded, key=lambda item: item["vid"])
                == sorted(actual["chunks"], key=lambda item: item["vid"]),
                "native staged receipts are not members of the original immutable package")
        packages[key] = package
    for key, actual in current.items():
        require(key in packages or (actual["state"] == "Open" and actual["chunk_count"] == 0),
                "native migration has posted chunks without its original retained package")
        plan = recovery.facts.get(f"plan-{expected_runs[key]['name']}")
        if plan is not None:
            require(set(plan) == {"plan"}, "invalid finalization checkpoint")
            check_finalization_plan(plan["plan"], actual)
        approval_name = f"{expected_runs[key]['name']}-finalize-approvals.json"
        if f"input-{approval_name}" in recovery.facts:
            approved = recovery.retained_json(approval_name)
            require(plan is not None and approved.get("proposal_digest") == plan["plan"]["proposal_digest"],
                    "retained finalization approvals refer to a different proposal")
        if actual["state"] == "Finalized":
            require(plan is not None and "preactivation" in recovery.facts,
                    "finalized migration lacks the original plan or preactivation snapshot")
            require(f"input-{approval_name}" in recovery.facts,
                    "finalized migration lacks its original approval identities")
    prefix = recovery.facts.get("preactivation")
    if prefix is not None:
        require(len(packages) == len(expected_runs), "preactivation checkpoint has missing native packages")
        prepared = [{"name": expected_runs[key]["name"], "package": packages[key]}
                    for key in expected_runs]
        require(set(prefix) == {"known_at", "packages"}
                and prefix["packages"] == activation_membership(prepared),
                "preactivation package membership differs")
        require(type(prefix["known_at"]) is int and 0 < prefix["known_at"] <= native.head()
                and all(seq <= prefix["known_at"] for item in prefix["packages"].values()
                        for seq in item["recorded_at"]),
                "preactivation snapshot is outside the staged native history")
        for period in PERIODS:
            same_cells(native.tb(period, known_at=prefix["known_at"], expected_gross={}), {},
                       f"{period} retained preactivation snapshot")
    else:
        require(not any(name.startswith("plan-") for name in recovery.facts),
                "finalization plan has no original preactivation snapshot")
    return packages


def activation_prefix(native: Native, recovery: ReplayRecovery, prepared: list[dict]) -> int:
    membership = activation_membership(prepared)
    prefix = recovery.facts.get("preactivation")
    if prefix is None:
        require(all(run["package"]["run_state"] == "Open" for run in prepared),
                "cannot reconstruct an empty prefix after a migration finalized")
        prefix = {"known_at": native.head(), "packages": membership}
    require(prefix["packages"] == membership, "original preactivation package membership changed")
    require(type(prefix["known_at"]) is int and all(seq <= prefix["known_at"]
            for item in membership.values() for seq in item["recorded_at"]),
            "preactivation snapshot predates the original staged receipts")
    for period in PERIODS:
        same_cells(native.tb(period, known_at=prefix["known_at"], expected_gross={}), {},
                   f"{period} staged visibility at original preactivation snapshot")
    recovery.save("preactivation", prefix)
    return prefix["known_at"]



def retained_stage_selection(native: Native, recovery: ReplayRecovery, run: dict) -> Path:
    name = f"{run['name']}-stage.json"
    if f"input-{name}" in recovery.facts:
        selection = recovery.retained_json(name)
    else:
        selection = {"chunks": [
            {"index": index, "approvals": native.approve(chunk["proposal_digest"], "chunk-reviewer")}
            for index, chunk in enumerate(run["package"]["chunks"])
        ]}
    chunks = selection.get("chunks")
    require(set(selection) == {"chunks"} and isinstance(chunks, list)
            and len(chunks) == len(run["package"]["chunks"]), "retained stage selection changed")
    for index, selected in enumerate(chunks):
        require(isinstance(selected, dict) and set(selected) == {"index", "approvals"}
                and type(selected["index"]) is int and selected["index"] == index,
                "retained stage selection changed source chunk order")
        approvals = selected["approvals"]
        require(isinstance(approvals, list) and len(approvals) == 2 and len(set(approvals)) == 2
                and all(isinstance(approval, str)
                        and re.fullmatch(r"[0-9a-f]{32}", approval, re.ASCII) is not None
                        for approval in approvals), "retained stage approvals are invalid")
    # Once published, reuse these IDs, including approvals whose first response
    # was lost. Native staging rechecks the approvals against each exact digest.
    return recovery.input_json(name, selection)


def finalize_recovered(native: Native, recovery: ReplayRecovery, run: dict) -> dict:
    require("preactivation" in recovery.facts, "finalization requires the original preactivation snapshot")
    actual = native.call("migrate", "show", run["run_vid"])["data"]
    require(actual["state"] in ("Open", "Finalized") and actual["ties_out"],
            "native migration cannot be finalized")
    name = f"plan-{run['name']}"
    saved = recovery.facts.get(name)
    if saved is None:
        require(actual["state"] == "Open", "cannot regenerate an already approved finalization proposal")
        proposed = native.call("migrate", "finalize", run["run_vid"], "--dry-run")["data"]
        check_finalization_plan(proposed, actual)
        # This must be durable before the first approval, including a lost
        # approval response. Retrying uses these exact sealed proposal bytes.
        saved = recovery.save(name, {"plan": proposed})
    proposed = saved["plan"]
    check_finalization_plan(proposed, actual)
    recovery.save(name, saved)
    approval_name = f"{run['name']}-finalize-approvals.json"
    if f"input-{approval_name}" in recovery.facts:
        approved = recovery.retained_json(approval_name)
    else:
        require(actual["state"] == "Open", "finalized migration lacks its original approval identities")
        approved = {"proposal_digest": proposed["proposal_digest"],
                    "approvals": native.approve(proposed["proposal_digest"], "finalize-reviewer")}
    approvals = approved.get("approvals")
    require(set(approved) == {"proposal_digest", "approvals"}
            and approved["proposal_digest"] == proposed["proposal_digest"]
            and isinstance(approvals, list) and len(approvals) == 2
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value, re.ASCII)
                    for value in approvals) and len(set(approvals)) == 2,
            "retained finalization approvals differ from the original proposal")
    recovery.input_json(approval_name, approved)
    head = native.head()
    result = native.call("migrate", "finalize", run["run_vid"], "--plan", "-",
                         "--approval", approvals[0], "--approval", approvals[1],
                         input_text=proposed["bytes"] + "\n")["data"]
    require(result["run_vid"] == run["run_vid"] and result["to"] == "Finalized",
            "migration did not finalize the original run")
    if actual["state"] == "Finalized":
        require(result["already_recorded"] and native.head() == head,
                "finalization retry changed the original native result")
    return result


def run_native(binary: Path, verifier: Path, output: Path, manifest: dict,
               *, recovery: ReplayRecovery) -> dict:
    require(manifest == recovery.manifest and output == recovery.output,
            "native replay differs from its pinned recovery inputs")
    native = Native(binary, verifier, output)
    native.log_path = None
    recovered = preflight_recovery(native, recovery)
    recovery.restore_inputs()
    attempt = recovery.begin_attempt()
    native.log_path = attempt / "commands.jsonl"
    if not native.book.exists():
        native.call("book", "create", "--name", f"OMES {manifest['agency']} FY2024 Q4 ACTIVITY ONLY",
                    "--base-unit", "USD", "--calendar", "monthly", "--year-start-month", "7",
                    "--opening-date", "2024-07-01")
    # Persist identity before the first schema, document or monetary mutation.
    recovery.remember_book(native.call("book", "info")["data"])
    accounts = json.loads((output / "chart.json").read_text())["accounts"]
    for index in range(0, len(accounts), 32):
        chart_file = recovery.input_json(f"chart-{index:03}.json", {"accounts": accounts[index:index + 32]})
        native.call("chart", "import", chart_file)
    department_values = native.register_departments(manifest["departments"])
    native.call("period", "create", "--fiscal-year", "2024")
    raw_oid = native.document(output / "original-agency.csv", mime=ORIGINAL_CSV_MIME)
    manifest_oid = native.document(output / "manifest.json", "Workpaper", "application/json")
    empty = recovery.input("no-opening-stock.csv", b"account,unit,net\n")
    empty_oid = native.document(empty)
    prepared = []
    retries = []
    entry_ids: dict[str, str] = {}
    checks = ["pinned_source_bytes", "complete_agency_row_coverage", "all_source_groups_balance_exactly",
              "no_subcent_rounding", "all_original_chartfields_retained",
              "source_and_helper_agent_uploads_have_native_local_reviews"]
    for run in manifest["runs"]:
        name = run["name"]
        source_oid = native.document(output / run["source"])
        cumulative: dict[str, int] = defaultdict(int)
        periods = []
        for period in PERIODS:
            for account, cents in run["activity_cents"][period].items():
                cumulative[account] += cents
            lines = [{"account": account, "unit": "USD", "net": money(cents)}
                     for account, cents in sorted(cumulative.items()) if cents]
            oracle_path = recovery.input_json(f"{name}-{period}-source-oracle.json",
                                              {"scope": SCOPE, "period": period, "lines": lines,
                                               "source_sha256": source.SOURCE_SHA256})
            tb_oid = native.document(oracle_path, "Spreadsheet", "application/json")
            periods.append({"period": period, "trial_balance": tb_oid, "lines": lines})
        run_body = {"run_key": f"omes-{manifest['agency']}-{name}", "source_system": SOURCE_SYSTEM,
                    "mode": "FullDetail", "trial_balance": empty_oid, "opening_date": "2024-07-01",
                    "lines": [], "periods": periods, "detail_base": [], "sole_opening_source": True}
        run_path = recovery.input_json(f"{name}-open.json", run_body)
        run_vid = native.call("migrate", "open", "--intent", run_path)["data"]["run_vid"]
        intent = {"run": f"MR:{run_vid}", "source": f"D:{source_oid}", "format": "csv",
                  "column_map": COLUMN_MAP,
                  # June 30 also belongs to year-end adjustment/closing periods.
                  # Route each aggregate by its published fiscal period, not by
                  # an ambiguous date or inferred closing-journal semantics.
                  "entry_periods": {entry_id: f"FY2024-P{int(entry_id.split(':')[3]):02}"
                                    for entry_id in run["entry_ids"]},
                  "account_map": {row["code"]: row["code"] for row in accounts}}
        intent_path = recovery.input_json(f"{name}-import.json", intent)
        package = native.call("migrate", "import", "--action", "prepare", "--intent", intent_path)["data"]
        verify_prepared_legs(manifest, run, package, department_values)
        require(package["run_state"] in ("Open", "Finalized"), "native migration is not resumable")
        previous = recovered.get(run_key(manifest, run))
        if previous is not None:
            require(package_identity(package) == package_identity(previous),
                    "preparation changed the original native package or proposal identities")
        for source_id, chunk in zip(run["entry_ids"], package["chunks"], strict=True):
            require(source_id not in entry_ids, "source entry occurs in more than one native migration")
            require(re.fullmatch(r"[0-9a-f]{32}", chunk["entry_vid"], re.ASCII) is not None,
                    "native proposal has an invalid entry identity")
            entry_ids[source_id] = chunk["entry_vid"]
        if not prepared:
            head = native.head()
            again = native.call("migrate", "import", "--action", "prepare", "--intent", intent_path)["data"]
            require(again["package_oid"] == package["package_oid"] and again["already_recorded"], "preparation retry changed package")
            require(native.head() == head, "preparation retry published another entry")
            checks.append("preparation_retry_is_idempotent")
        prepared.append({"name": name, "run_vid": run_vid,
                         "package_oid": package["package_oid"], "package": package})

    # All existing and newly prepared populations are checked before staging.
    # A lost grouped response is recovered by native membership, not a local
    # completed-count file: each receipt has its own original CommitSeq.
    for run in prepared:
        name, run_vid, package_oid = run["name"], run["run_vid"], run["package_oid"]
        package = run["package"]
        selection_path = retained_stage_selection(native, recovery, run)
        command = ["migrate", "import", "--action", "stage", "--package", package_oid,
                   "--intent", selection_path]
        receipts = verify_staged_group(native.call(*command), package, run_vid, recover=True)
        for staged in receipts:
            native.call("document", "attach", staged["entry_vid"], "--evidence", raw_oid, "--evidence", manifest_oid)
        retries.append((command, receipts, package, run_vid))
        shown = native.call("migrate", "import", "--action", "show", "--package", package_oid)["data"]
        require(shown["ties_out"] and shown["recorded_count"] == package["chunk_count"], "staged source does not tie out")
        require(package_identity(shown) == package_identity(package), "staging changed native package membership")
        run["package"] = shown

    before_finalize = activation_prefix(native, recovery, prepared)
    checks.append("all_staged_activity_is_invisible")
    for run in prepared:
        finalize_recovered(native, recovery, run)
    checks.append("native_approved_finalization")
    cumulative = defaultdict(int)
    cumulative_gross = defaultdict(int)
    for period in PERIODS:
        expected = manifest["activity_cents"][period]
        expected_gross = manifest["activity_gross_cents"][period]
        same_cells(native.tb(period, activity=True, expected_gross=expected_gross), expected, f"{period} activity")
        for account, cents in expected.items():
            cumulative[account] += cents
        for account_side, cents in expected_gross.items():
            cumulative_gross[account_side] += cents
        same_cells(native.tb(period, expected_gross=dict(cumulative_gross)), dict(cumulative), f"{period} cumulative")
        same_cells(native.tb(period, known_at=before_finalize), {}, f"{period} immutable preactivation history")
        native.call("registers", "advance", "--period", period)
        native.call("verify", "registers", "--period", period)
    checks.extend(["every_month_account_cell_matches_source", "cumulative_balances_match_source",
                   "native_proposal_legs_preserve_every_source_row", "gross_debit_credit_account_cells_match_source",
                   "historical_preactivation_prefix_stays_invisible", "native_registers_equal_journal_fold"])
    department_certificates = verify_department_balances(native, manifest, before_finalize)
    checks.append("every_native_leg_preserves_source_department_or_absence")
    if department_values:
        checks.extend(["native_department_monthly_and_cumulative_net_and_gross_match_source",
                       "department_preactivation_history_stays_invisible",
                       "department_certificates_replay_exact_robot_reports"])
    # Retry every saved chunk after finalization, across separate process opens.
    head = native.head()
    for command, receipts, package, run_vid in retries:
        again = verify_staged_group(native.call(*command), package, run_vid, retry=True)
        require([row["recorded_at"] for row in again] == [row["recorded_at"] for row in receipts],
                "finalized grouped retry changed a publication identity")
    require(native.head() == head, "finalized retries appended duplicate history")
    checks.append("all_finalized_chunk_retries_are_idempotent")
    native.call("verify", "projections")
    held = {row["oid"]: row for row in native.call("document", "list")["data"]["documents"]}
    for intake in native.document_custody:
        current = held.get(intake["oid"])
        require(current is not None and current["grade"] == intake["intake_grade"]
                and current["doc_commit"] == intake["doc_commit"]
                and current["recorded_at"] == intake["intake_recorded_at"],
                "review or migration changed the original document custody")
    checks.append("native_upload_custody_preserved_and_fixture_reviews_recorded")
    native.call("checkpoint", "create", "--grant", "witness")
    native.call("verify", "accumulator")
    checks.extend(["native_projections_match_payloads", "signed_accumulator_checkpoint"])
    csv_export = attempt / "gl.csv"
    native.call("export", "csv-gl", "--as-of", "2024-06-30", "--out", csv_export)
    native.call("verify", "export", "csv-gl", csv_export)
    exported = native.call("export", "ads", "--as-of", "2024-06-30", "--out", attempt / "ads", "--with-proofs")
    native.call("verify", "export", "ads", attempt / "ads")
    export_oracles = [
        verify_exported_legs(manifest, entry_ids, department_values, csv_export, "csv-gl"),
        verify_exported_legs(manifest, entry_ids, department_values, attempt / "ads/GL_Detail.txt", "ads"),
    ]
    checks.extend(["native_csv_and_ads_reread_certificates", "every_exported_leg_preserves_source_department_or_absence"])
    trusted_key = exported["data"]["proof"]["checkpoint_public_key"]
    # This is the caller's just-created test book's trusted key, not a key read
    # from an untrusted incoming bundle. Production recipients need their own
    # separately authenticated anchor; this harness does not establish one.
    verification = native.execute([str(native.verifier), "ads", str(attempt / "ads"), "--key", trusted_key, "--json"])
    require_ads_dimension_proof(verification, manifest["monetary_rows"])
    checks.extend(["independent_fa_verify_ads_proof", "independent_fa_verify_authenticates_every_exported_dimension_set"])
    # Mutate a COPY, leaving the accepted evidence and production book intact.
    tampered = attempt / "ads-tampered"
    shutil.copytree(attempt / "ads", tampered)
    mutation = tamper_ads_amount(tampered / "GL_Detail.txt")
    rejected = native.execute([str(native.verifier), "ads", str(tampered), "--key", trusted_key, "--json"], expect=8)
    checks.append("independent_verifier_rejects_tampered_extract")
    dimension_tampered = attempt / "ads-dimension-tampered"
    shutil.copytree(attempt / "ads", dimension_tampered)
    dimension_mutation = tamper_ads_dimension(dimension_tampered / "GL_Detail.txt")
    dimension_rejected = native.execute([str(native.verifier), "ads", str(dimension_tampered),
                                         "--key", trusted_key, "--json"], expect=8)
    checks.append("independent_verifier_rejects_dimension_only_tampering")
    checks.extend(["resume_inputs_and_native_book_identity_pinned",
                   "original_native_packages_and_publication_receipts_preserved",
                   "original_finalize_proposals_durable_before_approval"])
    return {"status": "PASS", "scope": SCOPE, "agency": manifest["agency"],
            "recovery": {"resumed": recovery.resumed, "attempt": str(attempt.relative_to(output)),
                         "native_packages_recovered": len(recovered),
                         "book_id": recovery.facts["book"]["book_id"],
                         "original_preactivation_seq": before_finalize},
            "source_sha256": source.SOURCE_SHA256, "source_rows": manifest["source_rows"],
            "monetary_rows": manifest["monetary_rows"], "source_columns": manifest["source_columns"],
            "account_count": manifest["account_count"], "migration_runs": len(prepared),
            "migration_entries": len(entry_ids), "commands": native.commands, "checks": checks,
            "activity_cents": manifest["activity_cents"], "final_cumulative_cents": dict(cumulative),
             "department_value_count": len(department_values),
             "department_certificates": department_certificates,
             "department_scope": "Exact nonblank DEPTID values; source blanks stay untagged, and departmental slices need not balance",
            "independent_verification": verification, "tamper_refusal": rejected,
            "tamper_mutation": mutation,
            "export_source_oracles": export_oracles,
            "dimension_tamper_refusal": dimension_rejected, "dimension_tamper_mutation": dimension_mutation,
            "dimension_export_scope": "Exact native kind IDs and value VIDs, including explicit empty sets; source codes are checked separately against retained source and native registration, not inferred from a VID",
            "document_custody": native.document_custody,
            "document_review_scope": "Native AgentUpload custody is retained; Reviewed attestations use a distinct fixture principal operated by this same harness, not an independent human auditor",
            "approval_scope": "Distinct local test principals exercise native SoD; not independent human authentication",
            "review_scope": REVIEW_SCOPE,
            "trust_scope": "Verifier uses caller-trusted key of freshly created test book; no external authentication claim"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    fetch = sub.add_parser("fetch", help="download and verify the complete pinned 114 MB distribution")
    fetch.add_argument("--out", type=Path, required=True)
    profile = sub.add_parser("profile", help="profile every statewide record; report discrepancies without balancing")
    profile.add_argument("--source", type=Path, required=True)
    profile.add_argument("--out", type=Path, required=True)
    for action in ("prepare", "run"):
        command = sub.add_parser(action, help="normalize a complete agency" if action == "prepare" else "execute real native migration, folds and offline proof verification")
        command.add_argument("--source", type=Path, help="pinned statewide CSV or committed complete-agency fixture")
        command.add_argument("--agency", help="exact business-unit code; default 31500, or the original agency with --resume")
        command.add_argument("--out", type=Path, required=True, help="new directory, or an interrupted pinned run with --resume")
        if action == "run":
            command.add_argument("--fa", type=Path, help="default target/debug/fa; resume defaults to the original executable")
            command.add_argument("--fa-verify", type=Path, help="default target/debug/fa-verify; resume defaults to the original executable")
            command.add_argument("--resume", action="store_true", help="continue the original pinned book and proposals; preserve prior attempts")
    args = parser.parse_args(argv)
    started = time.monotonic()
    output_created = False

    def own_output() -> None:
        nonlocal output_created
        output_created = True

    recovery: ReplayRecovery | None = None
    try:
        if args.action == "fetch":
            print(source.fetch_source(args.out))
        elif args.action == "profile":
            value = source.profile_source(args.source)
            write_json(args.out, value)
            print(json.dumps({"status": "PROFILED", "report": str(args.out), "source_sha256": source.SOURCE_SHA256}))
        else:
            saved = read_fact(args.out / "recovery/pins.json") if args.action == "run" and args.resume else {}
            agency = args.agency or saved.get("agency", "31500")
            path = args.source or (Path(saved["source_path"]) if saved else FIXTURES / f"omes-fy2024-q4-{agency}.csv")
            if args.action == "run":
                binary = args.fa or Path(saved.get("fa_path", ROOT / "target/debug/fa"))
                verifier = args.fa_verify or Path(saved.get("fa_verify_path", ROOT / "target/debug/fa-verify"))
                require(binary.is_file() and verifier.is_file(),
                        "build fa and fa-verify first: cargo build -p fa-cli --bin fa -p fa-verify --bin fa-verify")
                recovery = ReplayRecovery(args.out, path, agency, binary, verifier,
                                          resume=args.resume, on_created=own_output)
                manifest = recovery.manifest
                report = run_native(binary, verifier, args.out, manifest, recovery=recovery)
                report["elapsed_seconds"] = round(time.monotonic() - started, 3)
                require(recovery.attempt is not None, "native run has no validation attempt")
                publish_bytes(recovery.attempt / "report.json", json_bytes(report))
                publish_bytes(args.out / "report.json", json_bytes(report))
                print(json.dumps({key: report[key] for key in ("status", "agency", "source_rows", "monetary_rows", "account_count", "migration_entries", "commands", "elapsed_seconds")}))
            else:
                manifest = normalize(path, agency, args.out, on_created=own_output)
                print(json.dumps({"status": "PREPARED", "agency": agency, "source_rows": manifest["source_rows"], "out": str(args.out)}))
        return 0
    except (ReplayError, source.SourceError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        message = {"status": "FAIL", "error": str(error)}
        failure = None
        if recovery is not None and recovery.attempt is not None:
            failure = recovery.attempt / "failure.json"
        elif args.action in ("run", "prepare") and output_created and args.out.is_dir():
            failure = args.out / "failure.json"
        if failure is not None and not failure.exists():
            try:
                publish_bytes(failure, json_bytes(message))
            except OSError as save_error:
                message["failure_record_error"] = str(save_error)
        print(json.dumps(message), file=sys.stderr)
        return 1
    finally:
        if recovery is not None:
            recovery.close()


if __name__ == "__main__":
    raise SystemExit(main())
