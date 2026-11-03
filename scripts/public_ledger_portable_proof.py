#!/usr/bin/env python3
"""Independently verify a retained public-ledger dimension report.

Run after public_ledger.py (or its source-bound companion) has completed.
The native producer and fa-verify establish acceptance. The framing inspection
only describes and checks the expected storage profile; it is not a verifier.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from public_ledger import DIMENSION_COLUMNS, PERIODS, period_end, read_fact

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FILES = ("report.fab", "checkpoint.bin", "report.receipt")
MAX_PUBLIC_COMPRESSED_BYTES = 2 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def source_binding_mode(report: dict, retained: dict, requested: bool | None) -> tuple[bool, str]:
    """Inherit the canonical replay contract; historical companions need a flag.

    Recovery v1 represents an unbound run by absence of bind_source. The older
    fresh-only companion did not record its binding contract, so its reports
    remain explicitly selected rather than retroactively relabeled.
    """
    pinned = "bind_source" in retained
    declared = "bind_source" in report
    if pinned or declared:
        require(not pinned or retained["bind_source"] is True,
                "recovery source-binding pin is not canonical")
        require(declared and type(report["bind_source"]) is bool,
                "completed report lacks its pinned source-binding contract")
        require(report["bind_source"] == pinned,
                "completed report and recovery source-binding mode differ")
        require(requested is None or requested == pinned,
                "requested source-binding mode differs from the completed replay")
        return pinned, "canonical_recovery_pins"
    return bool(requested), "legacy_explicit_selection" if requested is not None else "legacy_unbound_default"


def original_book_identity(retained: dict, report: dict, *, native: dict | None = None) -> dict:
    """Admit the original recovery book, independently of mutable report data."""
    fields = {"book_id", "base_unit", "calendar", "entities"}
    require(isinstance(retained, dict) and set(retained) == fields,
            "original recovery book identity has an unexpected shape")
    require(isinstance(retained["book_id"], str)
            and re.fullmatch(r"[0-9a-f]{32}", retained["book_id"], re.ASCII) is not None
            and retained["base_unit"] == "USD" and retained["entities"] == []
            and isinstance(retained["calendar"], str) and bool(retained["calendar"])
            and retained["calendar"] == retained["calendar"].strip(),
            "original recovery book identity is outside the declared activity-book scope")
    recovery = report.get("recovery")
    require(isinstance(recovery, dict) and recovery.get("book_id") == retained["book_id"],
            "completed report book identity differs from the original recovery book")
    if native is not None:
        require(isinstance(native, dict) and {key: native.get(key) for key in fields} == retained,
                "native book identity or declared scope differs from the original recovery book")
    return dict(retained)


def select_dimension_report(report: dict, dimension: str, value: str | None) -> dict:
    """Choose an exact source code, preserving leading zeroes and case."""
    require(dimension in DIMENSION_COLUMNS, "unsupported source dimension")
    rows = report.get("dimension_certificates", {}).get(dimension)
    require(isinstance(rows, list) and bool(rows),
            f"completed replay has no retained {dimension} reports")
    count = report.get("dimension_value_counts", {}).get(dimension)
    require(type(count) is int and count == len(rows),
            f"retained {dimension} report population differs from the replay")
    by_code = {}
    certificate_ids = set()
    for row in rows:
        require(isinstance(row, dict), "retained dimension report is not an object")
        code = row.get(dimension)
        require(isinstance(code, str) and bool(code) and code == code.strip()
                and code not in by_code, "retained dimension code is blank, altered or repeated")
        require(isinstance(row.get("certificate_oid"), str)
                and re.fullmatch(r"[0-9a-f]{64}", row["certificate_oid"], re.ASCII) is not None,
                "retained certificate identity is invalid")
        require(row["certificate_oid"] not in certificate_ids,
                "distinct source values reuse one retained certificate")
        certificate_ids.add(row["certificate_oid"])
        require(isinstance(row.get("period"), str)
                and re.fullmatch(r"FY[0-9]{4}-P[0-9]{2}", row["period"], re.ASCII) is not None,
                "retained dimension report has no exact fiscal period")
        for name in ("account_nets", "gross_cents"):
            cells = row.get(name)
            require(isinstance(cells, dict)
                    and all(isinstance(key, str) and bool(key) and type(amount) is int
                            for key, amount in cells.items()),
                    "retained source controls must be exact integer-cent cells")
        require(all(amount >= 0 for amount in row["gross_cents"].values()),
                "retained source gross activity cannot be negative")
        by_code[code] = row
    selected = min(by_code) if value is None else value
    require(selected in by_code, f"source {dimension} code {selected!r} has no retained report")
    return by_code[selected]


def original_source_control(manifest: dict, report: dict, selected: dict, dimension: str) -> dict:
    """Recover cumulative cells from the immutable original-source manifest.

    The caller checks its artifact hash against the original recovery pins.
    A mutable completion report cannot substitute a different source oracle.
    """
    require(manifest.get("format") == "fa-public-ledger-replay-v1",
            "unsupported original-source manifest profile")
    for key in ("agency", "source_sha256", "source_rows", "monetary_rows"):
        require(key in manifest and key in report and manifest[key] == report[key],
                f"completed report {key} differs from the pinned source manifest")
    activity = manifest.get("dimension_activity", {}).get(dimension)
    require(isinstance(activity, dict) and set(activity) == set(PERIODS)
            and selected["period"] in PERIODS,
            "source dimension controls do not cover the declared fiscal periods")
    values = manifest.get("dimensions", {}).get(dimension)
    require(isinstance(values, list)
            and sum(isinstance(value, dict) and value.get("code") == selected[dimension]
                    for value in values) == 1,
            "selected dimension does not identify one original source value")
    controls = {"account_nets": {}, "gross_cents": {}}
    for period in PERIODS:
        if period > selected["period"]:
            continue
        require(isinstance(activity[period], dict), "invalid source-period dimension controls")
        cells = activity[period].get(selected[dimension], {})
        require(isinstance(cells, dict), "invalid source-value dimension controls")
        for name in controls:
            current = cells.get(name, {})
            require(isinstance(current, dict)
                    and all(isinstance(key, str) and bool(key) and type(amount) is int
                            for key, amount in current.items()),
                    "source controls must be exact integer-cent cells")
            require(name != "gross_cents" or all(amount >= 0 for amount in current.values()),
                    "source gross controls cannot be negative")
            for key, amount in current.items():
                controls[name][key] = controls[name].get(key, 0) + amount
    for name, actual in controls.items():
        expected = selected[name]
        require({key: amount for key, amount in actual.items() if amount}
                == {key: amount for key, amount in expected.items() if amount},
                f"retained report {name} differ from its pinned original-source controls")
    return {**selected, **controls}


class Reader:
    def __init__(self, value: bytes):
        self.value = value
        self.pos = 0

    def take(self, count: int) -> bytes:
        require(0 <= count <= len(self.value) - self.pos, "truncated framing")
        result = self.value[self.pos:self.pos + count]
        self.pos += count
        return result

    def number(self, width: int, endian: str = "little", *, signed: bool = False) -> int:
        return int.from_bytes(self.take(width), endian, signed=signed)

    def blob(self) -> bytes:
        return self.take(self.number(4))

    def finish(self) -> None:
        require(self.pos == len(self.value), "unexpected trailing framing bytes")


def inspect_output(value: bytes) -> dict:
    """Read exact cells after fa-verify has authenticated and recomputed them.

    This is a source-control comparison, not another cryptographic verifier.
    The wire is DimensionTrialBalance::canonical_bytes and TrialBalance::
    canonical_bytes; unsupported shapes refuse rather than lose attribution.
    """
    outer = Reader(value)
    domain = b"fa:dimension-trial-balance:v1"
    require(outer.take(len(domain)) == domain, "unexpected dimension output domain")
    dimension, code = outer.blob().decode("utf-8"), outer.blob().decode("utf-8")
    count = outer.number(4)
    require(count <= len(outer.value) // 4, "impossible dimension-value count")
    values = [outer.blob().decode("utf-8") for _ in range(count)]
    tb = Reader(outer.blob())
    outer.finish()
    domain = b"fa:trial-balance:v1"
    require(tb.take(len(domain)) == domain, "unexpected trial-balance output domain")
    count = tb.number(4)
    require(count <= len(tb.value) // 4, "impossible output-period count")
    periods = [tb.blob().decode("utf-8") for _ in range(count)]
    known_at = tb.number(8)
    present = tb.number(1)
    require(present in (0, 1), "invalid output effective-date option")
    effective_through = tb.number(4, signed=True) if present else None
    activity = tb.number(1)
    require(activity in (0, 1), "invalid output activity flag")
    count = tb.number(4)
    require(count <= len(tb.value) // 93, "impossible output-account count")
    nets, gross, accounts = {}, {}, set()
    debit_total, credit_total = 0, 0
    for _ in range(count):
        account = tb.take(16)
        account_code = tb.blob().decode("utf-8")
        tb.blob().decode("utf-8")  # Name is authenticated by fa-verify.
        account_type, unit = tb.number(1), tb.number(4)
        debits, credits, pending_debits, pending_credits = [tb.number(16, signed=True) for _ in range(4)]
        require(account not in accounts and account_code not in nets,
                "portable output repeats an account identity or code")
        require(account_code and unit == 0 and 1 <= account_type <= 5,
                "portable output is outside the declared USD activity-book chart")
        require(debits >= 0 and credits >= 0 and pending_debits == pending_credits == 0,
                "portable output has negative gross amounts or pending activity")
        accounts.add(account)
        nets[account_code] = debits - credits
        gross[f"{account_code}:debit"] = debits
        gross[f"{account_code}:credit"] = credits
        debit_total += debits
        credit_total += credits
    totals = []
    for _ in range(2):
        count = tb.number(4)
        require(count <= len(tb.value) // 36, "impossible output-unit count")
        units = {}
        for _ in range(count):
            unit = tb.number(4)
            require(unit == 0 and unit not in units, "portable output has an unexpected or repeated unit")
            units[unit] = (tb.number(16, signed=True), tb.number(16, signed=True))
        totals.append(units)
    tb.finish()
    require(totals[0].get(0, (0, 0)) == (debit_total, credit_total)
            and totals[1].get(0, (0, 0)) == (0, 0), "portable output totals differ from its exact rows")
    return {"dimension": dimension, "value": code, "values": values, "periods": periods,
            "known_at": known_at, "effective_through": effective_through, "activity": bool(activity),
            "account_nets": nets, "gross_cents": gross, "account_rows": len(accounts),
            "unit_id": 0, "unit_code": "USD", "unit_scale": 2}


def reconcile_source_output(closure: dict, selected: dict, dimension: str) -> dict:
    """Compare the verified portable cells with the completed source oracle."""
    output = closure["output"]
    require(selected["period"] in PERIODS, "portable report period is outside the pinned source quarter")
    # DateDay is signed days since 1970-01-01. Native stock Periods selections
    # end at period.end - 1; source FY2024 periods 10/11/12 declare these exact
    # inclusive civil dates, not merely a matching label or any non-null cutoff.
    expected_date = dt.date.fromisoformat(period_end(int(selected["period"].rsplit("-P", 1)[1])))
    expected_day = (expected_date - dt.date(1970, 1, 1)).days
    require(closure["dimension"] == output["dimension"] == dimension
            and closure["dimension_value"] == output["value"] == selected[dimension]
            and output["values"] == [selected[dimension]],
            "portable dimension scope differs from the retained source report")
    require(closure["selected"] == output["periods"] == [selected["period"]]
            and closure["known_at"] == output["known_at"]
            and not output["activity"] and type(output["effective_through"]) is int
            and output["effective_through"] == expected_day,
            "portable period, snapshot or stock selection differs from the retained source report")
    compared = {}
    for name in ("account_nets", "gross_cents"):
        actual = {key: amount for key, amount in output[name].items() if amount}
        expected = {key: amount for key, amount in selected[name].items() if amount}
        require(actual == expected, f"portable {name} differ from the original-source control cells")
        compared[name] = len(expected)
    return {"status": "PASS", "dimension": dimension, "value": selected[dimension],
            "period": selected["period"], "effective_through": expected_date.isoformat(),
            "nonzero_cells_compared": compared,
            "scope": "Verified native output compared with the completed replay's original-source oracle; no publisher-signature claim."}


def inspect(bundle: bytes, *, source_bound: bool, require_fragments: bool) -> dict:
    """Describe the already independently verified v8 dimension-report wire."""
    container = Reader(bundle)
    require(container.blob() == b"fa:report-bundle:v1", "unexpected bundle domain")
    major, minor = container.number(2), container.number(2)
    require(major == 1, "this helper supports native dimension report bundles")
    require(minor == int(source_bound), "bundle source profile differs from request")
    certificate = Reader(container.blob())
    fmt = certificate.take(24).decode("ascii")
    require(fmt == "fa:report-certificate:v8", "expected native dimension certificate")
    require(certificate.blob() == b"fa-fold-over-prefix", "unexpected certificate scope")
    require(certificate.blob() == b"embedded-owner", "unexpected certificate authority")
    require(certificate.blob() == b"fa:dimension-trial-balance:v1", "unexpected output format")
    book, branch = certificate.take(16).hex(), certificate.take(16).hex()
    known_at = certificate.number(8)
    require(certificate.number(1) == 6, "expected dimension selector")
    selector = certificate.number(1)
    if selector in (0, 2):
        count = certificate.number(4)
        require(0 < count <= 1024, "invalid period count")
        selected = [certificate.blob().decode("utf-8") for _ in range(count)]
    else:
        require(selector == 1, "unsupported period selector")
        selected = [int.from_bytes(certificate.take(4), "little", signed=True)]
    dimension, value = certificate.blob().decode("utf-8"), certificate.blob().decode("utf-8")
    certificate.take(64)  # Registry and journal commitments: checked by fa-verify.
    leaves = certificate.number(8)
    native_count = certificate.number(4)
    require(8 <= native_count <= 12, "invalid dimension native-input count")
    native = []
    for _ in range(native_count):
        payload = Reader(certificate.blob())
        magic = b"fgdb:native-result-certificate:v1"
        require(payload.take(len(magic)) == magic, "unexpected native input domain")
        version = payload.number(1)
        payload.take(32)
        snapshot = payload.number(8, "big")
        payload.take(128)
        facade = payload.number(1)
        statement = payload.take(payload.number(8, "big")).decode("utf-8")
        require(version == 1 and snapshot == known_at, "native input coordinate differs")
        native.append({"statement": statement, "facade": facade, "snapshot": snapshot,
                       "trailing_bytes": len(payload.value) - payload.pos})
    labels = []
    for item in native[8:]:
        match = re.match(r"MATCH \(n:([A-Za-z]+)\)", item["statement"])
        require(match is not None, "unrecognized additive storage selector")
        labels.append(match.group(1))
    run_fragments = "MigrationRunFragment" in labels
    entry_fragments = "EntryFragment" in labels
    expected = (["MigrationRunFragment"] if run_fragments else [])
    if source_bound:
        expected += ["MigrationSource", "MigrationSourceFragment"]
    if entry_fragments:
        expected += ["EntryFragment"]
    require(labels == expected, "additive storage selectors are missing, extra or reordered")
    for item, label in zip(native[8:], expected):
        statement = (f"MATCH (n:{label}) FOR SYSTEM_TIME AS OF SEQ {known_at} "
                     "RETURN n,n._fa_payload,n._fa_digest,n.book_id ORDER BY n")
        require(item["statement"] == statement and item["facade"] == 4
                and item["trailing_bytes"] == 0, "storage selector differs from fixed native profile")
    if require_fragments:
        require(run_fragments and entry_fragments, "required real storage-fragment closure is absent")
        require(native_count == (12 if source_bound else 10), "fragment storage-input count differs")
    output = inspect_output(certificate.blob())
    certificate.take(32)
    require(certificate.number(1) == 0, "expected sequence-selected driver certificate")
    digest = certificate.take(32).hex()
    certificate.finish()
    container.blob()  # Signed checkpoint.
    container.blob()  # Authenticated prefix.
    records = container.number(4)
    for _ in range(records):
        container.number(4)
        container.blob()
    run_bodies = container.number(4)
    for _ in range(run_bodies):
        container.number(8)
        container.blob()
    witnesses = 0
    if source_bound:
        witnesses = container.number(4)
        for _ in range(witnesses):
            container.number(8)
            container.blob()
        require(witnesses > 0, "source-bound profile has no source witnesses")
    require(run_bodies > 0, "public-ledger report has no canonical migration bodies")
    container.finish()
    return {"bundle_major": major, "bundle_minor": minor, "certificate_format": fmt,
            "book": book, "branch": branch, "known_at": known_at, "selected": selected,
            "dimension": dimension, "dimension_value": value, "journal_leaves": leaves,
            "native_input_count": native_count, "native_inputs": native,
            "additive_input_labels": labels, "certificate_digest": digest,
            "canonical_records": records, "migration_run_bodies": run_bodies,
            "migration_source_witnesses": witnesses,
            "output": output,
            "scope": "Descriptive framing only; separate fa-verify establishes authentication."}


def proof_file_snapshot(out: Path, *, expected: dict | None = None) -> dict:
    """Bind acceptance to the exact three files submitted to fa-verify."""
    current = {name: {"bytes": (out / name).stat().st_size, "sha256": sha(out / name)}
               for name in PUBLIC_FILES}
    require(expected is None or current == expected,
            "produced proof files changed from the bytes submitted for native verification")
    return current


def public_example(out: Path, key: str, certificate: str, source_bound: bool,
                   *, verified_files: dict) -> tuple[dict, list]:
    """Fixed public-proof allowlist; never includes a native book or private key."""
    encoded = []
    files = []
    require(set(verified_files) == set(PUBLIC_FILES), "public example lacks the exact verified proof-file inventory")
    for name in PUBLIC_FILES:
        raw = (out / name).read_bytes()
        identity = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        require(identity == verified_files[name],
                "public example bytes differ from the native-verified proof files")
        packed = gzip.compress(raw, mtime=0)
        require(gzip.decompress(packed) == raw, "public example compression changed bytes")
        files.append({"name": name, **identity,
                      "gzip_bytes": len(packed), "gzip_sha256": hashlib.sha256(packed).hexdigest()})
        encoded.append((name, base64.b64encode(packed).decode("ascii")))
    total = sum(item["gzip_bytes"] for item in files)
    if total > MAX_PUBLIC_COMPRESSED_BYTES:
        return {"status": "OMITTED_SIZE_CAP", "compressed_bytes": total,
                "compressed_limit": MAX_PUBLIC_COMPRESSED_BYTES}, []
    return {"format": "fa:public-proof-example:v1", "status": "READY",
            "public_key": key, "certificate": certificate, "source_bound": source_bound,
            "trust": "Caller-trusted fixture key; no external identity claim.",
            "compressed_bytes": total, "files": files}, encoded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path, help="completed public-ledger output")
    parser.add_argument("--out", required=True, type=Path, help="new sibling proof directory")
    parser.add_argument("--fa", required=True, type=Path)
    parser.add_argument("--fa-verify", required=True, type=Path)
    binding = parser.add_mutually_exclusive_group()
    binding.add_argument("--source-bound", dest="source_bound", action="store_true", default=None,
                         help="require source binding; canonical replay pins are inherited when omitted")
    binding.add_argument("--unbound", dest="source_bound", action="store_false",
                         help="require an unbound replay; refuses a pinned source-bound run")
    parser.add_argument("--dimension", choices=tuple(DIMENSION_COLUMNS), default="department",
                        help="retained source dimension to verify; default department")
    parser.add_argument("--value", help="exact source code; default first code in lexical order")
    parser.add_argument("--require-entry-fragments", action="store_true",
                        help="require both RunFragment and EntryFragment; 10/12 native inputs")
    parser.add_argument("--emit-public-example", action="store_true",
                        help="emit bounded gzip/base64 of the three public proof files after PASS")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    record = {"status": "RUNNING", "started_utc": utc(), "invocation": sys.argv,
              "source_bound_requested": args.source_bound,
              "dimension_requested": args.dimension, "value_requested": args.value,
              "entry_fragments_required": args.require_entry_fragments,
              "trust_scope": "Caller-trusted public key of the fixture book; no external identity claim.",
              "commands": []}
    owned = False
    watched: dict[str, Path] = {}
    pins: dict[str, str] = {}
    verified_files: dict = {}
    emission: list = []
    started = time.monotonic()
    try:
        run = args.run.resolve(strict=True)
        require(out != run and run not in out.parents, "proof output must be separate from the completed run")
        require(not out.exists(), "proof output already exists; preserve it and use a new directory")
        report_path, pins_path = run / "report.json", run / "recovery/pins.json"
        book_path = run / "recovery/book.json"
        manifest_path = run / "manifest.json"
        report = json.loads(report_path.read_text())
        retained_pins = read_fact(pins_path)
        require(retained_pins.get("format") == "fa-public-ledger-recovery-v1",
                "unexpected completed-run recovery profile")
        require(report["status"] == "PASS", "public-ledger replay did not pass")
        original_book_sha = sha(book_path)
        original_book = original_book_identity(read_fact(book_path), report)
        source_bound, binding_origin = source_binding_mode(report, retained_pins, args.source_bound)
        selected = select_dimension_report(report, args.dimension, args.value)
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        binary, verifier = args.fa.resolve(strict=True), args.fa_verify.resolve(strict=True)
        watched = {"report": report_path, "recovery_pins": pins_path,
                   "original_book": book_path,
                   "source_manifest": manifest_path,
                   "fa": binary, "fa_verify": verifier, "helper": Path(__file__).resolve(),
                   "driver": ROOT / "scripts/public_ledger.py",
                   "normalizer": ROOT / "scripts/public_ledger_source.py"}
        pins = {name: sha(path) for name, path in watched.items()}
        require(pins["original_book"] == original_book_sha,
                "original recovery book identity changed during admission")
        require(hashlib.sha256(manifest_bytes).hexdigest() == pins["source_manifest"]
                == retained_pins["artifacts"]["manifest.json"],
                "original-source manifest differs from the completed replay's immutable pin")
        selected = original_source_control(manifest, report, selected, args.dimension)
        require(pins["fa"] == retained_pins["runtime"]["fa_sha256"]
                and pins["fa_verify"] == retained_pins["runtime"]["fa_verify_sha256"],
                "executables differ from the completed replay")
        require(pins["driver"] == retained_pins["runtime"]["driver_sha256"]
                and pins["normalizer"] == retained_pins["runtime"]["normalizer_sha256"],
                "source helpers differ from the completed replay")
        certificate = selected["certificate_oid"]
        record.update(book_output=str(run), selected_retained_certificate=selected,
                      original_book_identity=original_book,
                      source_bound=source_bound, source_binding_selection=binding_origin,
                      source_rows=report["source_rows"], migration_entries=report["migration_entries"],
                      binary_and_input_sha256_before=pins)
        out.mkdir(parents=True, exist_ok=False)
        owned = True

        def execute(arguments: list[str], *, verify: bool = False) -> list[dict]:
            command = ([str(verifier)] if verify else [str(binary), "--book", str(run / "book")])
            command += arguments + ["--json"]
            item = {"command": command}
            try:
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=600)
                item.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
            except subprocess.TimeoutExpired as error:
                def text(value: str | bytes | None) -> str:
                    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")
                item.update(exit=None, stdout=text(error.stdout), stderr=text(error.stderr), timed_out=True)
            record["commands"].append(item)
            with (out / "commands.jsonl").open("a") as stream:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
            require(item["exit"] == 0, "native command failed: " + json.dumps(item, sort_keys=True))
            return [json.loads(line) for line in item["stdout"].splitlines() if line]

        info = execute(["book", "info"])
        require(len(info) == 1, "native book inspection did not return one identity")
        original_book_identity(original_book, report, native=info[0]["data"])
        checkpoint = out / "checkpoint.bin"
        signed = execute(["proof", "signed-checkpoint", "--state", "latest", "--out", str(checkpoint)])
        require(len(signed) == 1 and signed[0]["event"] == "proof_exported",
                "signed checkpoint was not exported")
        state = signed[0]["data"]["state_oid"]
        key = signed[0]["data"]["checkpoint_public_key"]
        require(re.fullmatch(r"[0-9a-f]{64}", key, re.ASCII) is not None, "invalid fixture public key")
        require(re.fullmatch(r"[0-9a-f]{64}", state, re.ASCII) is not None, "invalid checkpoint state")
        bundle, receipt = out / "report.fab", out / "report.receipt"
        produced = execute(["bundle", "produce", "--certificate", "C:" + certificate, "--state", state,
                            "--out", str(bundle), "--receipt-out", str(receipt)])
        require(len(produced) == 1 and produced[0]["event"] == "bundle_produced"
                and produced[0]["data"]["scope"] == "report"
                and produced[0]["data"]["checkpoint_public_key"] == key,
                "report bundle or its fixture signing key differs")
        verified_files = proof_file_snapshot(out)
        record["proof_files_before_verification"] = verified_files
        bundle_bytes = bundle.read_bytes()
        require({"bytes": len(bundle_bytes), "sha256": hashlib.sha256(bundle_bytes).hexdigest()}
                == verified_files["report.fab"], "report bundle changed while capturing its verification input")
        accepted = execute(["report", str(bundle), "--key", key, "--checkpoint", str(checkpoint),
                            "--receipt", str(receipt), "--expect", certificate], verify=True)
        require(len(accepted) == 1 and accepted[0].get("verdict") == "verified",
                "independent report verifier did not accept")
        proof_file_snapshot(out, expected=verified_files)
        closure = inspect(bundle_bytes, source_bound=source_bound,
                          require_fragments=args.require_entry_fragments)
        require(closure["certificate_digest"] == certificate
                and closure["book"] == original_book["book_id"],
                "portable certificate identity differs from retained report")
        source_controls = reconcile_source_output(closure, selected, args.dimension)
        require(closure["migration_run_bodies"] == report["migration_runs"],
                "portable report does not retain every migration run body")
        require(closure["migration_source_witnesses"] == (report["migration_runs"] if source_bound else 0),
                "portable source witness count differs from actual replay")
        (out / "trusted-public-key.txt").write_text(key + "\n")
        record.update(status="PASS", closure=closure, independent_verifier=accepted,
                      original_source_control_comparison=source_controls,
                      trusted_public_key=key, expected_certificate=certificate, checkpoint_state=state,
                      artifact_files={**verified_files, "trusted-public-key.txt": {
                          "bytes": (out / "trusted-public-key.txt").stat().st_size,
                          "sha256": sha(out / "trusted-public-key.txt"),
                      }})
        if args.emit_public_example:
            example, emission = public_example(out, key, certificate, source_bound, verified_files=verified_files)
            record["public_example"] = example
    except Exception as error:
        record.update(status="FAIL", error=str(error))
    finally:
        record.update(finished_utc=utc(), elapsed_seconds=round(time.monotonic() - started, 3))
        if pins:
            try:
                after = {name: sha(path) for name, path in watched.items()}
                record["binary_and_input_sha256_after"] = after
                record["input_hashes_unchanged"] = after == pins
                if after != pins:
                    record.update(status="FAIL", error="input or executable bytes changed during verification")
            except OSError as error:
                record.update(status="FAIL", pin_check_error=str(error))
        if verified_files:
            try:
                after_proof = proof_file_snapshot(out)
                record["proof_files_after_verification"] = after_proof
                record["verified_proof_files_unchanged"] = after_proof == verified_files
                if after_proof != verified_files:
                    record.update(status="FAIL", error="produced proof bytes changed after native verification")
            except OSError as error:
                record.update(status="FAIL", proof_file_check_error=str(error))
        if owned:
            try:
                (out / "validation.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
            except OSError as error:
                record.update(status="FAIL", evidence_write_error=str(error))
    if record["status"] != "PASS":
        print(json.dumps(record, sort_keys=True), file=sys.stderr)
        return 1
    if args.emit_public_example:
        example = record["public_example"]
        print("BEGIN FA_PUBLIC_PROOF_MANIFEST_V1")
        print(json.dumps(example, sort_keys=True, indent=2))
        print("END FA_PUBLIC_PROOF_MANIFEST_V1")
        for name, encoded in emission:
            print("BEGIN FA_PUBLIC_PROOF_GZIP_BASE64 " + name)
            for start in range(0, len(encoded), 76):
                print(encoded[start:start + 76])
            print("END FA_PUBLIC_PROOF_GZIP_BASE64 " + name)
    print(json.dumps({"status": "PASS", "output": str(out), "elapsed_seconds": record["elapsed_seconds"],
                      "dimension": args.dimension, "value": selected[args.dimension],
                      "source_bound": source_bound,
                      "original_source_control_comparison": record["original_source_control_comparison"],
                      "native_input_count": record["closure"]["native_input_count"],
                      "migration_source_witnesses": record["closure"]["migration_source_witnesses"],
                      "artifact_files": record["artifact_files"],
                      "binary_sha256": {"fa": pins["fa"], "fa_verify": pins["fa_verify"]}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
