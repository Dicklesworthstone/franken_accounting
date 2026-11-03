#!/usr/bin/env python3
"""Continue a complete Magnify posting run interrupted during exact retries.

This deliberately narrow recovery profile accepts only the frozen replay helpers
and original engine below. It verifies a separate, byte-identical book copy,
re-extracts the complete original PDF, and checks every archived command against
the expected workflow. Archived commands are evidence; they are never executed.
Only an incomplete final header consistent with the next retry is admitted; the
complete census and unchanged live head establish safe reissue. No missing post,
changed input, changed book head, or later-phase interruption is resumable.

The result is an explicitly split execution. No initial loaded-helper hash is
inferred from files found after the interruption. All continuation dependencies,
source inputs and executable bytes are pinned before they are used.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import time


PROFILE = "fa-blmis-magnify-exact-retry-continuation-v1"
ENGINE_COMMIT = "3f947acbe31d89e74feec05891aa49b7400e7260"
BINARY_PINS = {
    "fa": "8a4e8ccaabd72a3a4644c73459e7fc98ece73c3fb419c4a7a51ce4317e72be2f",
    "fa_verify": "b1f3b63ffb92058075ef158ff9c14f05454e018c6914fb8d51ee5cd3e16c6f05",
}
# This recovery profile deliberately refuses later adapters or interpretations.
# A new profile needs its own review; changing these is not a resume workaround.
MODULE_PINS = {
    "blmis_source.py": "9e3b6ae3882cf88cff90e826907f4f0f5446646ceff46c65544cfedd5ba60df2",
    "blmis_magnify.py": "876362a7872e5f447c5eef10d3310fb6ec3004f8ce8a78053dcd3064ac2382d5",
    "public_ledger_source.py": "d9653bab775d00073b1c32e266ca2ee5358a53cadf3ef028df189fad1cbd9b80",
    "public_ledger.py": "e68114166f93b247f1780360e1bf15d0a67426c0eb5d6afce59ff330faf77548",
    "blmis_analytics.py": "77a742fda836a6f6211b062bba03b31122f640bf59efbecbc5e97a65c6c1dc5e",
    "blmis_replay.py": "c3f61901ec54a76fd9a969f54384d0ec792bf5b0bfc0264817444c16c060758a",
    "native_document_readback.py": "22157b96fc3713c62b3b5bee544207892036c4273d405e3bd66ea9678b78c1d6",
    "blmis_magnify_replay.py": "0262cd453149a84abe256f50135a697185f03b4f537a5706573336bbb4147585",
}


class ContinuationError(Exception):
    """The interrupted run is outside the supported, proven recovery boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContinuationError(message)


def fingerprint(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), f"not a regular retained file: {path}")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": digest}


def pinned(path: Path, expected: str) -> dict:
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid SHA-256 pin")
    actual = fingerprint(path)
    require(actual["sha256"] == expected, f"retained bytes changed: {path}")
    return actual


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def dependencies(binary: Path, verifier: Path) -> tuple[object, dict]:
    directory = Path(__file__).resolve().parent
    modules = {name: pinned(directory / name, expected) for name, expected in MODULE_PINS.items()}
    executables = {name: pinned(path, BINARY_PINS[name])
                   for name, path in (("fa", binary), ("fa_verify", verifier))}
    # Hash the source before importing it. Run this command in a fresh Python
    # process; the command's own before/after identity is retained as well.
    workload = importlib.import_module("blmis_magnify_replay")
    for name, before in modules.items():
        loaded = sys.modules[name.removesuffix(".py")]
        require(Path(loaded.__file__).resolve() == directory / name,
                f"another module was imported for {name}")
        require(fingerprint(directory / name) == before, f"module changed while loading: {name}")
    return workload, {"modules": modules, "binaries": executables,
                      "continuation": fingerprint(Path(__file__).resolve())}


def file_inventory(directory: Path) -> dict[str, dict]:
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), f"recovery input contains a symlink: {path}")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = fingerprint(path)
        else:
            require(path.is_dir(), f"recovery input contains a special file: {path}")
    return result


def copy_guard(prior: Path, copied: Path, inventory_path: Path, expected: str) -> tuple[dict, dict]:
    record_pin = pinned(inventory_path, expected)
    record = json.loads(inventory_path.read_text(encoding="utf-8"))
    require(record.get("status") == "BYTE_IDENTICAL_COPY"
            and Path(record["source"]).resolve() == prior
            and Path(record["destination"]).resolve() == copied,
            "copy inventory names another original or destination")
    expected_files = {}
    for item in record["inventory"]:
        name = item["path"]
        relative = PurePosixPath(name)
        require(isinstance(name, str) and not relative.is_absolute() and ".." not in relative.parts
                and relative.as_posix() == name and name not in expected_files,
                "copy inventory has a repeated or escaping path")
        require(type(item["bytes"]) is int and item["bytes"] >= 0
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                "copy inventory has an invalid file identity")
        expected_files[name] = {"bytes": item["bytes"], "sha256": item["sha256"]}
    require(record["file_count"] == len(expected_files)
            and record["total_bytes"] == sum(item["bytes"] for item in expected_files.values()),
            "copy inventory census differs")
    require(file_inventory(prior) == expected_files, "original run differs from its preserved inventory")
    require(file_inventory(copied) == expected_files, "copied run is not byte-identical before continuation")
    require(all(not (prior / name).samefile(copied / name) for name in expected_files),
            "working copy shares a file with the preserved original")
    require("book/book.keys" in expected_files and "commands.jsonl" in expected_files
            and expected_files.get("failure.json", {}).get("bytes") == 0
            and "report.json" not in expected_files,
            "original is not the preserved incomplete run with its empty failure record")
    return expected_files, {"path": str(inventory_path), **record_pin,
                            "file_count": len(expected_files), "total_bytes": record["total_bytes"]}


def transcript(path: Path, expected: str) -> tuple[list[dict], bytes, dict]:
    identity = pinned(path, expected)
    records, tail = [], b""
    with path.open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                # Only the final physical line can lack a newline. A complete
                # JSON record without its terminator is not this narrow profile.
                try:
                    json.loads(line)
                except (ValueError, UnicodeError):
                    tail = line
                    break
                raise ContinuationError("unterminated complete transcript record")
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError) as error:
                raise ContinuationError("malformed complete transcript record") from error
            require(isinstance(record, dict) and set(record) == {"command", "exit", "stdout", "stderr"}
                    and isinstance(record["command"], list) and bool(record["command"])
                    and all(isinstance(value, str) for value in record["command"])
                    and type(record["exit"]) is int and record["exit"] == 0
                    and isinstance(record["stdout"], str) and isinstance(record["stderr"], str),
                    "prior command is malformed or did not complete with exit zero")
            records.append(record)
    require(bool(records) and bool(tail), "expected one preserved incomplete final retry record")
    return records, tail, {**identity, "complete_records": len(records),
                           "incomplete_tail_bytes": len(tail),
                           "incomplete_tail_sha256": hashlib.sha256(tail).hexdigest()}


def retry_tail(tail: bytes, next_command: list[str]) -> None:
    # The known ENOSPC boundary lost part of the command header, before any
    # receipt was durable. Do not interpret an arbitrary partial JSON object.
    header = (json.dumps({"command": next_command}, ensure_ascii=False)[:-1]
              + ', "exit": 0, "stdout": ').encode("utf-8")
    require(tail.startswith(b'{"command": [') and len(tail) < len(header) and header.startswith(tail),
            "incomplete final prefix is inconsistent with the next exact retry command header")


class RecordedCommands:
    """A cursor over actual retained results; never a native execution layer."""

    def __init__(self, records: list[dict], prior: Path, output: Path):
        self.records, self.index = records, 0
        self.prior, self.output = prior, output
        self.binary = records[0]["command"][0]
        self.book = prior / "book"
        self.book_id: str | None = None
        self.document_custody: list[dict] = []

    def command(self, *args: object) -> list[str]:
        mapped = []
        for arg in map(str, args):
            if arg == str(self.output) or arg.startswith(str(self.output) + "/"):
                arg = str(self.prior) + arg[len(str(self.output)):]
            mapped.append(arg)
        return [str(self.binary), "--book", str(self.book), *mapped, "--json"]

    def execute_events(self, command: list[str]) -> tuple[list[dict], str]:
        require(self.index < len(self.records), "prior transcript ends before complete postings and certification")
        record = self.records[self.index]
        require(record["command"] == command, f"prior command order or intent differs at record {self.index + 1}")
        values = [json.loads(line) for line in record["stdout"].splitlines()]
        require(bool(values) and all(isinstance(value, dict) and value.get("v") == 1 for value in values),
                "prior result has an invalid native envelope")
        for value in values:
            if self.book_id is None:
                self.book_id = value.get("book")
                require(isinstance(self.book_id, str) and re.fullmatch(r"[0-9a-f]{32}", self.book_id) is not None,
                        "initial native book identity is invalid")
            require(value.get("book") == self.book_id, "prior transcript crosses native books")
        self.index += 1
        return values, record["stdout"]

    def call(self, *args: object) -> dict:
        values, _ = self.execute_events(self.command(*args))
        require(len(values) == 1, "expected one prior native result")
        return values[0]

    def head(self) -> int:
        return self.call("book", "info")["coordinate"]["known_at"]


def post_receipt(result: dict, previous: int, book: str) -> dict:
    require(result.get("event") == "posted" and result.get("book") == book,
            "a fresh source row is missing its original posting receipt")
    receipt = result["data"]
    require(type(receipt["recorded_at"]) is int and receipt["recorded_at"] == previous + 1
            and result["coordinate"]["known_at"] == receipt["recorded_at"]
            and re.fullmatch(r"[0-9a-f]{32}", receipt["vid"]) is not None
            and re.fullmatch(r"[0-9a-f]{64}", receipt["entry_digest"]) is not None,
            "fresh source receipt has another order or native identity")
    return receipt


def retry_receipt(result: dict, posted: dict, book: str, head: int) -> None:
    require(result.get("event") == "recorded" and result.get("book") == book
            and result["coordinate"]["known_at"] == head
            and all(result["data"][field] == posted[field] for field in ("vid", "entry_digest", "recorded_at")),
            "exact retry changed its original identity or appended history")


def book_guard(actual: dict, expected: dict) -> None:
    require(actual.get("event") == expected.get("event") == "book"
            and actual.get("book") == expected.get("book")
            and actual.get("coordinate") == expected.get("coordinate")
            and actual.get("data") == expected.get("data"),
            "copied native book identity, head or census differs from the retry checkpoint")


def prior_readback(cursor: RecordedCommands, workload: object, original: Path, oid: str) -> dict:
    helper = importlib.import_module("native_document_readback")
    shown = cursor.call("document", "show", oid)
    result = cursor.call("document", "read", oid, "--out", cursor.prior / "original-readback.pdf")
    held, data = shown["data"], result["data"]
    identity = fingerprint(original)
    require(shown.get("event") == "document_shown" and result.get("event") == "document_read"
            and shown["coordinate"] == result["coordinate"] and held["oid"] == oid
            and data["view"] == "full" and data["out"] == str(cursor.prior / "original-readback.pdf")
            and data["size"] == held["size"] == identity["bytes"]
            and all(data[field] == held[field] for field in ("oid", "doc_commit", "kind", "mime", "grade"))
            and all(data.get(field, "missing") is None for field in
                    ("disclosed_chunks", "withheld_chunks", "view_commit", "extraction"))
            and helper._hex_digest(data["bytes_hex"], data["size"]) == workload.source.SOURCE_SHA256
            and fingerprint(cursor.prior / "original-readback.pdf") == identity,
            "retained cold readback does not contain the complete original PDF")
    return {"source": str(original), "recovered": str(cursor.prior / "original-readback.pdf"),
            "oid": oid, "doc_commit": held["doc_commit"], **identity,
            "evidence": "revalidated complete prior native document response; not newly executed"}


def reconstruct(cursor: RecordedCommands, workload: object, manifest: dict,
                rows: list[dict], observations: list[dict], entries: list[dict]) -> dict:
    """Reapply the frozen assertions to every completed archived phase."""
    source, replay, ledger = workload.source, workload.replay, workload.ledger
    output = cursor.output
    created = cursor.call("book", "create", "--name", "Magnify six-account published principal ANALYSIS ONLY",
                          "--base-unit", "USD", "--calendar", "monthly")
    require(created.get("event") == "book_created" and created["data"]["book_id"] == cursor.book_id,
            "prior run did not create its declared analysis book")
    cursor.call("chart", "import", output / "chart.json")
    replay.configure_analysis_roles(cursor, list(source.ACCOUNTS))
    parties = workload.register_parties(cursor, output)
    for account in source.ACCOUNTS:
        name = f"source-account-party-{account}.json"
        require((output / name).read_bytes() == (cursor.prior / name).read_bytes(),
                "retained party declaration differs from the complete source")
    years = range(int(rows[0]["date"][:4]), int(rows[-1]["date"][:4]) + 1)
    periods = sorted({f"FY{row['date'][:4]}-P{row['date'][5:7]}" for row in rows if row["principal_movement_cents"]})
    for year in years:
        cursor.call("period", "create", "--fiscal-year", year)
    for period in periods:
        cursor.call("period", "open", period)
    evidence, readback = [], None
    for name, kind, mime in (("source.pdf", "Other", "application/pdf"), ("rows.csv", "Spreadsheet", "text/csv"),
                             ("source.json", "Workpaper", "application/json"), ("manifest.json", "Workpaper", "application/json"),
                             ("observations.json", "Workpaper", "application/json"), ("extracted-source/layout.txt", "Other", "text/plain"),
                             ("extraction.json", "Workpaper", "application/json")):
        oid = ledger.Native.document(cursor, output / name, kind, mime)
        evidence.append(oid)
        if name == "source.pdf":
            readback = prior_readback(cursor, workload, output / name, oid)
    before_posts = cursor.head()
    require(type(before_posts) is int and before_posts > 0, "invalid pre-posting native prefix")
    posted, paths, previous, seen_vids = {}, {}, before_posts, set()
    for index, entry in enumerate(entries, 1):
        entry["evidence"] = evidence
        name = f"entry-{index:04}.json"
        require((cursor.prior / name).read_bytes() == ledger.json_bytes(entry),
                f"retained source intent changed: {name}")
        ledger.write_json(output / name, entry)
        receipt = post_receipt(cursor.call("post", "--intent", output / name), previous, cursor.book_id)
        require(receipt["vid"] not in seen_vids, "two source rows share one native entry")
        seen_vids.add(receipt["vid"])
        previous = receipt["recorded_at"]
        posted[entry["idempotency_key"]] = receipt
        paths[entry["idempotency_key"]] = output / name
    require({path.name for path in cursor.prior.glob("entry-*.json")} == {path.name for path in paths.values()},
            "retained intent census has an extra or missing source entry")
    certificates, comparisons, encoded_reports = {}, {}, {}
    for account, selected in replay.grouped_accounts(rows).items():
        selected_observations = [row for row in observations if row["account"] == account]
        selected_posted = {row["row_id"]: posted[row["row_id"]] for row in selected if row["principal_movement_cents"]}
        certified_index = cursor.index
        certificate = replay.check_certified_ledger(cursor, selected, selected_posted,
                                                    published_gaps=workload.gap_map(selected_observations),
                                                    label=workload.label(account), retain_report=True)
        encoded_reports[account] = cursor.records[certified_index]["stdout"].splitlines(keepends=True)[0]
        comparisons[account] = workload.compare_native_observations(certificate["native_report"], selected,
                                                                    selected_posted, selected_observations)
        certificates[account] = certificate
        historical = cursor.call("gl", "detail", *replay.gl_arguments(selected, label=workload.label(account)),
                                 "--as-known-at", before_posts)["data"]
        replay.check_ledger(historical, selected, selected_posted, empty=True, label=workload.label(account))
    transfers = workload.transfer_scope(comparisons)
    checkpoint = cursor.call("book", "info")
    head = checkpoint["coordinate"]["known_at"]
    require(checkpoint.get("event") == "book" and type(head) is int and head == previous + len(source.ACCOUNTS),
            "certification checkpoint contains unexpected native publications")
    completed_retries = 0
    for row_id, path in paths.items():
        if cursor.index == len(cursor.records):
            break
        retry_receipt(cursor.call("post", "--intent", path), posted[row_id], cursor.book_id, head)
        completed_retries += 1
    require(0 < completed_retries < len(entries) and cursor.index == len(cursor.records),
            "interruption is not inside the incomplete exact-retry phase")
    return {"posted": posted, "paths": paths, "certificates": certificates, "comparisons": comparisons,
            "encoded_reports": encoded_reports, "transfers": transfers, "parties": parties,
            "before_posts": before_posts, "checkpoint": checkpoint, "head": head,
            "completed_retries": completed_retries, "document_custody": cursor.document_custody,
            "original_readback": readback, "periods": periods, "years": list(years)}


def prepare(args: argparse.Namespace, *, on_created: Callable[[], None] | None = None
            ) -> tuple[object, dict, dict, dict, dict, list[dict], list[dict], dict]:
    prior, copied, output = args.prior.resolve(strict=True), args.copy.resolve(strict=True), args.out.resolve()
    require(prior.is_dir() and copied.is_dir() and prior != copied
            and not prior.is_relative_to(copied) and not copied.is_relative_to(prior),
            "continuation requires a separate copied run")
    require(not output.exists() and not args.out.is_symlink()
            and not output.is_relative_to(prior) and not output.is_relative_to(copied),
            "continuation output must be new and outside both preserved runs")
    workload, pins = dependencies(args.fa.resolve(strict=True), args.fa_verify.resolve(strict=True))
    files, copy_record = copy_guard(prior, copied, args.inventory.resolve(strict=True), args.inventory_sha256)
    records, tail, log_identity = transcript(prior / "commands.jsonl", args.transcript_sha256)
    pinned(Path(records[0]["command"][0]), BINARY_PINS["fa"])
    require(files["commands.jsonl"] == {key: log_identity[key] for key in ("bytes", "sha256")},
            "transcript and copy inventory disagree")
    manifest = workload.source.prepare_pdf(output, prior / "source.pdf", on_created=on_created)
    for path in output.rglob("*"):
        if path.is_file():
            name = path.relative_to(output).as_posix()
            require(name in files and fingerprint(path) == files[name],
                    f"fresh source extraction or normalization differs from the retained input: {name}")
    source_rows, metadata = workload.source.load_fixture(output / "extracted-source")
    rows = workload.source.computation_order(source_rows)
    observations = workload.source_observations(rows)
    entries = workload.replay.normalized_entries(output / "legacy.csv", rows, source_id=workload.source.SOURCE_ID)
    require(len(rows) == manifest["source_rows"] == 2364
            and manifest["source_accounts"] == len(workload.source.ACCOUNTS) == 6
            and len(entries) == manifest["monetary_rows"] == 1586
            and manifest["normalized_legs"] == len(entries) * 2 == 3172
            and sum(row["star"] for row in observations) == 717,
            "complete Magnify population differs")
    controls = workload.annual_source_controls(observations)
    require(json.loads((output / "controls.json").read_text(encoding="utf-8")) == controls,
            "annual controls differ from independent printed-source observations")
    cursor = RecordedCommands(records, prior, output)
    state = reconstruct(cursor, workload, manifest, rows, observations, entries)
    next_path = list(state["paths"].values())[state["completed_retries"]]
    retry_tail(tail, cursor.command("post", "--intent", next_path))
    state.update(prior=str(prior), copied=str(copied), output=str(output), original_files=files,
                 annual_controls=controls, source_diagnostics=workload.source.verify_rows(source_rows, metadata))
    provenance = {"format": PROFILE, "execution_mode": "continued_after_interruption",
                  "initial_loaded_helper_hashes": None,
                  "initial_provenance_limit": "No launch-time helper snapshot was retained. Current files do not prove which code the initial process loaded. Complete actual source, intents, receipts and retained certificate responses are independently revalidated here.",
                  "initial_original": str(prior), "working_copy": str(copied), "copy_inventory": copy_record,
                  "original_transcript": log_identity, "original_failure_file": files["failure.json"],
                  "original_completed_commands_revalidated": len(records),
                  "original_fresh_postings_revalidated": len(entries),
                  "original_exact_retries_revalidated": state["completed_retries"],
                  "remaining_exact_retries": len(entries) - state["completed_retries"],
                  "next_retry_to_reissue": next_path.name,
                  "incomplete_tail_interpretation": "The preserved partial header is consistent with this retry but cannot identify the unseen complete command or result. The full source/receipt census and unchanged live native head must establish that reissue is safe.",
                  "book_id": cursor.book_id, "before_postings": state["before_posts"],
                  "retry_checkpoint": state["head"], "engine_commit": ENGINE_COMMIT,
                  "pins_before": pins, "fresh_source_reextraction_matches_retained_inputs": True,
                  "archived_checks_revalidated": [
                      "complete_native_original_pdf_intake_review_and_full_readback",
                      "complete_chart_period_party_and_evidence_command_order",
                      "all_1586_source_intents_and_unique_ordered_posting_receipts",
                      "six_exact_certified_ledgers_and_replays",
                      "six_empty_preimport_prefixes",
                      "all_2364_source_observations_and_printed_discrepancies",
                      "all_acknowledged_exact_retries_are_a_contiguous_original_prefix"]}
    return workload, pins, provenance, state, manifest, rows, observations, controls


def live_preflight(native: object, workload: object, state: dict, rows: list[dict], observations: list[dict]) -> dict:
    book_guard(native.call("book", "info"), state["checkpoint"])
    # Existing retained certificates are replayed, not reissued. Nothing may
    # publish until the original retry-phase head and source census survive.
    for account, selected in workload.replay.grouped_accounts(rows).items():
        certificate = state["certificates"][account]
        arguments = workload.replay.gl_arguments(selected, label=workload.label(account))
        values, encoded = native.execute_events(native.command(
            "replay", f"C:{certificate['oid']}", "--view", "detail", *arguments,
            "--as-known-at", certificate["known_at"]))
        require(len(values) == 2 and values[0].get("event") == "general_ledger"
                and values[1].get("event") == "report_replayed"
                and encoded.splitlines(keepends=True)[0] == state["encoded_reports"][account]
                and values[1]["certificate"] == certificate["oid"]
                and values[1]["book"] == state["checkpoint"]["book"]
                and values[1]["coordinate"] == values[0]["coordinate"]
                and values[1]["data"]["family"] == "roll-forward"
                and values[1]["data"]["known_at"] == certificate["known_at"]
                and values[1]["data"]["output_digest"] == certificate["output_digest"],
                "copied book did not replay its original certified source bytes")
        selected_posted = {row["row_id"]: state["posted"][row["row_id"]] for row in selected if row["principal_movement_cents"]}
        selected_observations = [row for row in observations if row["account"] == account]
        require(workload.compare_native_observations(values[0]["data"], selected, selected_posted, selected_observations)
                == state["comparisons"][account], "copied book changed its source comparison")
        historical = native.call("gl", "detail", *arguments, "--as-known-at", state["before_posts"])["data"]
        workload.replay.check_ledger(historical, selected, selected_posted, empty=True, label=workload.label(account))
    held_parties = native.call("party", "list")["data"]["parties"]
    require(len(held_parties) == 6 and all(value["kind"] == "Counterparty" for value in held_parties)
            and {value["code"].removeprefix("BLMIS-"): {
        "code": value["code"], "vid": value["vid"], "dimension": value["dimension_id"],
        "value": value["dimension_value_vid"]} for value in held_parties} == state["parties"],
        "copied book changed its source party identities")
    readback = workload.readback_document(native, Path(state["output"]) / "source.pdf",
                                          state["original_readback"]["oid"],
                                          Path(state["output"]) / "continued-original-readback.pdf")
    book_guard(native.call("book", "info"), state["checkpoint"])
    return readback


def complete(native: object, workload: object, state: dict, rows: list[dict], observations: list[dict],
             manifest: dict, controls: dict) -> dict:
    """Run every remaining assertion from the original frozen driver."""
    ledger, replay, output = workload.ledger, workload.replay, Path(state["output"])
    posted, parties = state["posted"], state["parties"]
    for row_id, path in list(state["paths"].items())[state["completed_retries"]:]:
        retry_receipt(native.call("post", "--intent", path), posted[row_id], state["checkpoint"]["book"], state["head"])
    require(native.head() == state["head"], "continued exact retries appended duplicate history")
    native_annual = []
    for year in state["years"]:
        at_date = f"{year}-12-31"
        expected = workload.cumulative_cells(observations, at_date)
        ledger.same_cells(native.tb(f"FY{year}-P12"), expected, f"native six-account annual principal at {at_date}")
        native_annual.append({"at_date": at_date, "native_trial_balance_cents": expected,
                              "printed_controls": [control for account_controls in controls.values()
                                                   for control in account_controls if control["at_date"] == at_date]})
    principal = replay.verify_glantz_principal_analysis(native, rows)
    analytics = workload.analytics.run_native(native, rows, posted)
    for period in state["periods"]:
        native.call("registers", "advance", "--period", period)
        native.call("verify", "registers", "--period", period)
    native.call("verify", "projections")
    held = {row["oid"]: row for row in native.call("document", "list")["data"]["documents"]}
    for intake in native.document_custody:
        document = held.get(intake["oid"])
        require(document is not None and document["grade"] == intake["intake_grade"]
                and document["doc_commit"] == intake["doc_commit"]
                and document["recorded_at"] == intake["intake_recorded_at"],
                "continuation changed original document custody")
    native.call("checkpoint", "create", "--grant", "witness")
    native.call("verify", "accumulator")
    csv_export = output / "gl.csv"
    native.call("export", "csv-gl", "--as-of", rows[-1]["date"], "--out", csv_export)
    native.call("verify", "export", "csv-gl", csv_export)
    exported = native.call("export", "ads", "--as-of", rows[-1]["date"], "--out", output / "ads", "--with-proofs")
    native.call("verify", "export", "ads", output / "ads")
    exports = [replay.verify_source_export(path, kind, rows, posted, parties, source_id=workload.source.SOURCE_ID)
               for path, kind in ((csv_export, "csv-gl"), (output / "ads/GL_Detail.txt", "ads"))]
    key = exported["data"]["proof"]["checkpoint_public_key"]
    verified = native.execute([str(native.verifier), "ads", str(output / "ads"), "--key", key, "--json"])
    ledger.require_ads_dimension_proof(verified, manifest["normalized_legs"])
    tamper_results = {}
    for name, mutate in (("amount", ledger.tamper_ads_amount), ("party", ledger.tamper_ads_dimension)):
        directory = output / f"ads-{name}-tampered"
        shutil.copytree(output / "ads", directory)
        mutation = mutate(directory / "GL_Detail.txt")
        refusal = native.execute([str(native.verifier), "ads", str(directory), "--key", key, "--json"], expect=8)
        tamper_results[name] = {"mutation": mutation, "refusal": refusal}
    return {"native_annual_controls": native_annual, "principal_analysis": principal,
            "record_silent_analytics": analytics, "verified_register_periods": state["periods"],
            "export_source_oracles": exports, "independent_verification": verified,
            "tamper_refusals": tamper_results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run"), help="check reconstructs evidence without invoking either native binary")
    parser.add_argument("--prior", type=Path, required=True, help="untouched interrupted output")
    parser.add_argument("--copy", type=Path, required=True, help="separate verified copy containing book/")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--transcript-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fa", type=Path, required=True)
    parser.add_argument("--fa-verify", type=Path, required=True)
    args = parser.parse_args(argv)
    invocation = list(sys.orig_argv) if argv is None else [sys.executable, str(Path(__file__).resolve()), *argv]
    started, utc = time.monotonic(), datetime.now(timezone.utc).isoformat()
    owns_output = False

    def created() -> None:
        nonlocal owns_output
        owns_output = True

    try:
        workload, before, provenance, state, manifest, rows, observations, controls = prepare(args, on_created=created)
        provenance.update(invocation=invocation, started_utc=utc, python=sys.version,
                          prepared_source_and_intents=file_inventory(args.out.resolve()))
        write_json(args.out / "continuation-start.json", provenance)
        if args.command == "check":
            result = {"status": "READY_FOR_NATIVE_PREFLIGHT", "native_commands_executed": 0,
                      "execution_mode": "evidence_reconstruction_only", "continuation": provenance}
            write_json(args.out / "preflight.json", result)
        else:
            native = workload.ledger.Native(args.fa, args.fa_verify, args.out.resolve())
            native.book = Path(state["copied"]) / "book"
            native.document_custody = state["document_custody"]
            cold_readback = live_preflight(native, workload, state, rows, observations)
            write_json(args.out / "native-preflight.json", {
                "status": "PASS", "scope": "native_recovery_preflight_only",
                "book_id": state["checkpoint"]["book"], "unchanged_head": state["head"],
                "commands": native.commands, "original_document_readback": cold_readback,
                "checks": ["exact_book_identity_head_and_census", "six_retained_certificate_replays",
                           "every_source_movement_and_printed_discrepancy", "six_empty_preimport_prefixes",
                           "source_party_identity_census", "complete_original_pdf_cold_readback",
                           "no_publication_during_native_preflight"]})
            finished = complete(native, workload, state, rows, observations, manifest, controls)
            _, after = dependencies(args.fa.resolve(strict=True), args.fa_verify.resolve(strict=True))
            require(after == before, "source helper or executable changed during continuation")
            require(file_inventory(Path(state["prior"])) == state["original_files"],
                    "original interrupted run changed during continuation")
            for name, identity in provenance["prepared_source_and_intents"].items():
                require(fingerprint(args.out / name) == identity, f"continuation input changed: {name}")
            provenance.update(pins_after=after, original_unchanged=True, prepared_inputs_unchanged=True,
                              finished_utc=datetime.now(timezone.utc).isoformat(),
                              continuation_transcript=fingerprint(args.out / "commands.jsonl"),
                              continuation_commands=native.commands,
                              continued_exact_retries=len(state["posted"]) - state["completed_retries"])
            result = {"status": "PASS", "execution_mode": "continued_after_interruption", "continuation": provenance,
                      "scope": workload.source.SCOPE, "source_sha256": workload.source.SOURCE_SHA256,
                      "source_rows_sha256": workload.source.ROWS_SHA256, "source_extraction": manifest["source_extraction"],
                      "source_rows": len(rows), "source_accounts": 6, "native_entries": len(state["posted"]),
                      "native_legs": len(state["posted"]) * 2, "source_diagnostics": state["source_diagnostics"],
                      "source_comparisons": state["comparisons"], "entry_receipts": state["posted"],
                      "ledger_certificates": state["certificates"], "annual_controls": controls,
                      "source_account_parties": state["parties"], "transfer_scope": state["transfers"],
                      "document_custody": state["document_custody"], "original_document_readback": cold_readback,
                      "prior_document_readback": state["original_readback"], **finished,
                      "commands": native.commands, "binaries": {"fa_sha256": BINARY_PINS["fa"],
                                                                  "fa_verify_sha256": BINARY_PINS["fa_verify"]},
                      "driver_sha256": before["continuation"]["sha256"],
                      "review_scope": workload.ledger.REVIEW_SCOPE,
                      "result_scope": "A split execution: all original source/posting/certificate evidence was revalidated, the copied native book reproduced its retained certificates and original PDF, every unconfirmed exact retry ran, and every remaining original gate passed. The interrupted run alone remains incomplete.",
                      "principal_scope": "Trustee-published principal inputs and explicit withholding-refund exclusion; all 58 transfer credits remain source oracle inputs, with no legal net-equity conclusion.",
                      "trust_scope": "Caller-trusted local analysis-book key; no court or trustee signing-key claim",
                      "checks_continuation_executed": [
                          "complete_original_pdf_reextracted_and_all_inputs_matched",
                          "exact_native_book_identity_and_retry_checkpoint",
                          "six_original_certificates_replayed_against_copied_native_book",
                          "six_empty_preimport_prefixes_rechecked",
                          "complete_original_pdf_native_cold_readback",
                          "every_remaining_exact_retry_without_new_history",
                          "all_26_annual_cumulative_trial_balances",
                          "native_principal_analysis_with_role_history",
                          "seven_record_silent_source_predicates_and_certified_replays",
                          "all_posting_month_registers", "native_projections",
                          "unchanged_original_document_custody", "signed_accumulator_checkpoint",
                          "every_exported_leg_text_and_party_dimension_vs_source",
                          "independent_ads_proofs", "one_cent_tamper_rejected", "party_only_tamper_rejected",
                          "original_failed_run_and_all_continuation_inputs_unchanged"],
                      "elapsed_seconds": round(time.monotonic() - started, 3)}
            write_json(args.out / "report.json", result)
        print(json.dumps({"status": result["status"], "execution_mode": result["execution_mode"],
                          "prior_retries": state["completed_retries"], "remaining_retries": len(state["posted"]) - state["completed_retries"]}))
        return 0
    except Exception as error:
        failure = {"status": "FAIL", "execution_mode": "continuation_incomplete", "format": PROFILE,
                   "error": str(error), "invocation": invocation, "started_utc": utc,
                   "finished_utc": datetime.now(timezone.utc).isoformat()}
        if owns_output and args.out.is_dir() and not (args.out / "continuation-failure.json").exists():
            try:
                write_json(args.out / "continuation-failure.json", failure)
            except OSError as record_error:
                # Preserve any partially written file and still report the
                # original failure through stderr when storage is exhausted.
                failure["failure_record_error"] = str(record_error)
        print(json.dumps(failure), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
