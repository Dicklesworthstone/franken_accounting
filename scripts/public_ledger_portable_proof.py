#!/usr/bin/env python3
"""Independently verify a retained public-ledger departmental report.

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

from public_ledger import read_fact

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


class Reader:
    def __init__(self, value: bytes):
        self.value = value
        self.pos = 0

    def take(self, count: int) -> bytes:
        require(0 <= count <= len(self.value) - self.pos, "truncated framing")
        result = self.value[self.pos:self.pos + count]
        self.pos += count
        return result

    def number(self, width: int, endian: str = "little") -> int:
        return int.from_bytes(self.take(width), endian)

    def blob(self) -> bytes:
        return self.take(self.number(4))

    def finish(self) -> None:
        require(self.pos == len(self.value), "unexpected trailing framing bytes")


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
        require(native_count == (12 if source_bound else 10), "university storage-input count differs")
    certificate.blob()  # Canonical output is checked by the independent verifier.
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
            "scope": "Descriptive framing only; separate fa-verify establishes authentication."}


def public_example(out: Path, key: str, certificate: str, source_bound: bool) -> tuple[dict, list]:
    """Fixed public-proof allowlist; never includes a native book or private key."""
    encoded = []
    files = []
    for name in PUBLIC_FILES:
        raw = (out / name).read_bytes()
        packed = gzip.compress(raw, mtime=0)
        require(gzip.decompress(packed) == raw, "public example compression changed bytes")
        files.append({"name": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
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
    parser.add_argument("--source-bound", action="store_true")
    parser.add_argument("--require-entry-fragments", action="store_true",
                        help="require both RunFragment and EntryFragment; 10/12 native inputs")
    parser.add_argument("--emit-public-example", action="store_true",
                        help="emit bounded gzip/base64 of the three public proof files after PASS")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    record = {"status": "RUNNING", "started_utc": utc(), "invocation": sys.argv,
              "source_bound_requested": args.source_bound,
              "entry_fragments_required": args.require_entry_fragments,
              "trust_scope": "Caller-trusted public key of the fixture book; no external identity claim.",
              "commands": []}
    owned = False
    watched: dict[str, Path] = {}
    pins: dict[str, str] = {}
    emission: list = []
    started = time.monotonic()
    try:
        run = args.run.resolve(strict=True)
        require(out != run and run not in out.parents, "proof output must be separate from the completed run")
        require(not out.exists(), "proof output already exists; preserve it and use a new directory")
        out.mkdir(parents=True, exist_ok=False)
        owned = True
        report_path, pins_path = run / "report.json", run / "recovery/pins.json"
        report = json.loads(report_path.read_text())
        retained_pins = read_fact(pins_path)
        require(retained_pins.get("format") == "fa-public-ledger-recovery-v1",
                "unexpected completed-run recovery profile")
        require(report["status"] == "PASS", "public-ledger replay did not pass")
        binary, verifier = args.fa.resolve(strict=True), args.fa_verify.resolve(strict=True)
        watched = {"report": report_path, "recovery_pins": pins_path,
                   "fa": binary, "fa_verify": verifier, "helper": Path(__file__).resolve(),
                   "driver": ROOT / "scripts/public_ledger.py",
                   "normalizer": ROOT / "scripts/public_ledger_source.py"}
        pins = {name: sha(path) for name, path in watched.items()}
        require(pins["fa"] == retained_pins["runtime"]["fa_sha256"]
                and pins["fa_verify"] == retained_pins["runtime"]["fa_verify_sha256"],
                "executables differ from the completed replay")
        require(pins["driver"] == retained_pins["runtime"]["driver_sha256"]
                and pins["normalizer"] == retained_pins["runtime"]["normalizer_sha256"],
                "source helpers differ from the completed replay")
        selected = report["dimension_certificates"]["department"][0]
        certificate = selected["certificate_oid"]
        require(re.fullmatch(r"[0-9a-f]{64}", certificate, re.ASCII) is not None,
                "retained certificate identity is invalid")
        record.update(book_output=str(run), selected_retained_certificate=selected,
                      source_rows=report["source_rows"], migration_entries=report["migration_entries"],
                      binary_and_input_sha256_before=pins)

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
        require(len(info) == 1 and info[0]["data"]["book_id"] == report["recovery"]["book_id"],
                "native book identity differs from completed replay")
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
        accepted = execute(["report", str(bundle), "--key", key, "--checkpoint", str(checkpoint),
                            "--receipt", str(receipt), "--expect", certificate], verify=True)
        require(len(accepted) == 1 and accepted[0].get("verdict") == "verified",
                "independent report verifier did not accept")
        closure = inspect(bundle.read_bytes(), source_bound=args.source_bound,
                          require_fragments=args.require_entry_fragments)
        require(closure["certificate_digest"] == certificate
                and closure["book"] == report["recovery"]["book_id"],
                "portable certificate identity differs from retained report")
        require(closure["dimension"] == "department"
                and closure["dimension_value"] == selected["department"],
                "portable department differs from retained report")
        require(closure["migration_run_bodies"] == report["migration_runs"],
                "portable report does not retain every migration run body")
        require(closure["migration_source_witnesses"] == (report["migration_runs"] if args.source_bound else 0),
                "portable source witness count differs from actual replay")
        (out / "trusted-public-key.txt").write_text(key + "\n")
        record.update(status="PASS", closure=closure, independent_verifier=accepted,
                      trusted_public_key=key, expected_certificate=certificate, checkpoint_state=state,
                      artifact_files={name: {"bytes": (out / name).stat().st_size, "sha256": sha(out / name)}
                                      for name in (*PUBLIC_FILES, "trusted-public-key.txt")})
        if args.emit_public_example:
            example, emission = public_example(out, key, certificate, args.source_bound)
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
                      "native_input_count": record["closure"]["native_input_count"],
                      "migration_source_witnesses": record["closure"]["migration_source_witnesses"],
                      "artifact_files": record["artifact_files"],
                      "binary_sha256": {"fa": pins["fa"], "fa_verify": pins["fa_verify"]}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
