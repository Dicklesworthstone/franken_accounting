#!/usr/bin/env python3
"""Exercise a complete pinned public expenditure extract through the real fa CLI.

This is an execution harness, not an alternative accounting engine. The native
migration laws, approvals, activation, folds, exports, certificates and independent
fa-verify binary supply the results. Python supplies source-derived expectations.
All generated books are explicitly scoped models of published expenditure.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
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
from typing import Any

import public_spend


REVIEWERS = ("public-data-fixture-reviewer-a", "public-data-fixture-reviewer-b")


class CheckError(RuntimeError):
    """An observed native result or retained input broke the test contract."""


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise CheckError(detail)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def executable_fingerprint(path: Path) -> tuple[int, int, int, int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def executable_identity(path: Path) -> dict[str, Any]:
    """Bind a run to the bytes that existed before its first native command.

    Stat checks detect ordinary concurrent rebuilds without rehashing several
    hundred megabytes before every command. This is an execution consistency
    guard, not protection against a hostile actor racing filesystem metadata.
    """
    before = executable_fingerprint(path)
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    require(executable_fingerprint(path) == before,
            f"native executable changed while its initial identity was read: {path}")
    return {"path": str(path), "sha256": hasher.hexdigest(), "fingerprint": before}


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def write_new(path: Path, value: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(value)


def body(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("data", event)
    require(isinstance(value, dict), "native event has no object body")
    return value


def event_named(events: list[dict[str, Any]], name: str) -> dict[str, Any]:
    found = [event for event in events if event.get("event") == name]
    require(len(found) == 1, f"expected exactly one {name} event, received {len(found)}")
    return found[0]


def money(text: str, *, unit: bool = True) -> int:
    """Read the CLI's fixed two-place GBP representation without floating point."""
    require(isinstance(text, str), "native amount is not an exact decimal string")
    match = re.fullmatch(r"(-?)([0-9]+)\.([0-9]{2})" + (r" GBP" if unit else ""), text)
    require(match is not None, f"unexpected exact GBP amount: {text!r}")
    assert match is not None
    value = int(match[2]) * 100 + int(match[3])
    return -value if match[1] else value


def decimal(value: int) -> str:
    return f"{'-' if value < 0 else ''}{abs(value) // 100}.{abs(value) % 100:02}"


def verify_prepared(directory: Path, dataset: str, *,
                    native_attribution: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebuild every expected output from independently pinned original bytes.

    Rehashing a modified manifest is insufficient: the pinned source catalogue and
    deterministic transformation must agree before the first native write.
    """
    sources = public_spend.load_sources()
    require(dataset in sources, f"unknown pinned dataset {dataset!r}")
    expected_files = public_spend.build_bundle(sources[dataset], (directory / "raw.csv").read_bytes(),
                                              native_attribution=native_attribution)
    for name, expected in expected_files.items():
        actual = (directory / name).read_bytes()
        require(actual == expected, f"prepared {name} differs from its pinned source transformation")
    expected_tb = json.loads(expected_files["expected_tb.json"])
    return sources[dataset], expected_tb


def expected_cells(expected: dict[str, Any]) -> dict[str, tuple[int, int, int]]:
    cells: dict[str, tuple[int, int, int]] = {}
    for account in expected["accounts"]:
        code = account["account"]
        require(code not in cells, f"duplicate source expectation for account {code}")
        debit, credit, net = (int(account[name]) for name in ("debit_minor", "credit_minor", "signed_minor"))
        require(debit >= 0 and credit >= 0 and debit - credit == net, f"inconsistent source totals for {code}")
        if debit or credit:
            cells[code] = debit, credit, net
    require(sum(value[2] for value in cells.values()) == 0, "declared expenditure model is unbalanced")
    return cells


def check_source_binding(event: dict[str, Any], *, book_id: str, run_vid: str,
                         source_oid: str, source_commit: str, package_oid: str,
                         source_rows: int, chunks: list[dict[str, Any]], recorded: set[str],
                         previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check native population observations against the original prepared source.

    This oracle neither supplies the kernel's manifest nor authenticates a proof.
    The complete source reconstruction and standalone verifier remain separate.
    """
    preparation = body(event)
    value = preparation.get("source_binding")
    require(isinstance(value, dict), "native omitted the requested source binding")
    require(event.get("book") == book_id, "source binding event belongs to a different book")
    for name, width in [("book_id", 32), ("run_vid", 32), ("manifest_vid", 32),
                        ("run_body_digest", 64), ("manifest_digest", 64), ("source_oid", 64),
                        ("source_commit", 64), ("package_oid", 64), ("package_commit", 64)]:
        require(isinstance(value.get(name), str)
                and re.fullmatch(r"[0-9a-f]{" + str(width) + "}", value[name]) is not None,
                f"native source binding has no canonical {name}")
    require(value["book_id"] == book_id and value["run_vid"] == run_vid,
            "native bound a different book or migration run")
    require(value["source_oid"] == source_oid.removeprefix("D:") and value["source_commit"] == source_commit,
            "native bound a different normalized source document")
    require(value["package_oid"] == package_oid.removeprefix("D:"), "native bound a different prepared package")
    require(value["run_body_digest"] == preparation.get("run_body_digest")
            and value["package_commit"] == preparation.get("package_commit"),
            "native source binding differs from its prepared run body or package commitment")
    require(type(value.get("source_rows")) is int and value["source_rows"] == source_rows
            and 0 < source_rows < 2**64, "native bound the wrong normalized source-row census")
    members = [chunk["entry_vid"] for chunk in chunks]
    require(1 <= len(chunks) <= 4096 and len(set(members)) == len(members),
            "prepared source population is empty, repeated or too large")
    for chunk in chunks:
        require(re.fullmatch(r"[0-9a-f]{32}", chunk["entry_vid"]) is not None
                and re.fullmatch(r"[0-9a-f]{64}", chunk["proposal_digest"]) is not None,
                "prepared source member has a noncanonical native identity")
    require(recorded <= set(members), "observed staging contains a foreign prepared member")
    require(type(value.get("expected_chunks")) is int and value["expected_chunks"] == len(members)
            and type(value.get("recorded_chunks")) is int and value["recorded_chunks"] == len(recorded),
            "native source binding changed the expected or recorded chunk census")
    missing = value.get("missing_chunks")
    require(isinstance(missing, list) and all(isinstance(item, str) for item in missing)
            and len(missing) == len(set(missing)) and set(missing) == set(members) - recorded,
            "native source binding hid, duplicated or substituted a missing member")
    require(value.get("unexpected_chunks") == [], "native source binding contains unexpected members")
    require(value.get("complete") is (len(recorded) == len(members)),
            "native source binding misstates population completeness")
    if previous is not None:
        for name in ("manifest_vid", "manifest_digest", "book_id", "run_vid", "run_body_digest",
                     "source_oid", "source_commit", "package_oid", "package_commit", "source_rows", "expected_chunks"):
            require(value[name] == previous[name], f"native source binding changed immutable {name}")
    return dict(value)


def check_binding_receipt(event: dict[str, Any], *, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    preparation = body(event)
    receipt = preparation.get("source_binding_receipt")
    require(isinstance(receipt, dict), "native prepare omitted its source-binding receipt")
    require(isinstance(receipt.get("control_entry"), str)
            and re.fullmatch(r"[0-9a-f]{32}", receipt["control_entry"]) is not None,
            "native source-binding receipt has no canonical control identity")
    upload_at, bound_at = preparation.get("recorded_at"), receipt.get("recorded_at")
    coordinate = event.get("coordinate", {}).get("known_at")
    require(type(upload_at) is int and type(bound_at) is int and 0 < upload_at < bound_at
            and type(coordinate) is int and coordinate >= bound_at,
            "native source-binding receipt lost the separate upload and binding coordinates")
    retry = previous is not None
    require(receipt.get("already_recorded") is retry and preparation.get("already_recorded") is retry,
            "native prepare changed package or binding retry status")
    if not retry:
        require(bound_at == upload_at + 1 and coordinate == bound_at,
                "fresh preparation did not publish only its package and source binding")
    if previous is not None:
        require(receipt["control_entry"] == previous["control_entry"] and bound_at == previous["recorded_at"],
                "native source-binding retry changed its original publication identity")
    return dict(receipt)


def check_source_report_bundle(bundle: bytes, binding: dict[str, Any], chunks: list[dict[str, Any]]) -> dict[str, int]:
    """Inspect bounded container framing and compare the exact expected witness.

    No record, certificate, signature or arithmetic is decoded here. Only the
    actual independent fa-verify invocation establishes authenticated acceptance.
    """
    require(len(bundle) <= 64 * 1024 * 1024, "source-aware report bundle exceeds 64 MiB")
    position = 0

    def take(count: int) -> bytes:
        nonlocal position
        require(count <= len(bundle) - position, "source-aware report bundle is truncated")
        value = bundle[position:position + count]
        position += count
        return value

    def number(width: int) -> int:
        return int.from_bytes(take(width), "little")

    def blob(limit: int) -> bytes:
        length = number(4)
        require(length <= limit, "source-aware report field exceeds its bound")
        return take(length)

    def count(minimum_bytes: int) -> int:
        value = number(4)
        require(value <= (len(bundle) - position) // minimum_bytes,
                "source-aware report list count exceeds its retained bytes")
        return value

    require(blob(64) == b"fa:report-bundle:v1", "native source-aware report has a different container domain")
    major, minor = number(2), number(2)
    require(major in (1, 2, 3) and minor == 1, "native report omitted its source-aware manifest closure")
    for _ in range(3):
        blob(64 * 1024 * 1024)
    records = count(8)
    for _ in range(records):
        number(4)
        blob(8 * 1024 * 1024)
    for _ in range(count(12)):
        number(8)
        blob(8 * 1024 * 1024)
    require(count(12) == 1, "fresh single-run book report has an unexpected source-witness population")
    leaf_index = number(8)
    require(leaf_index < records, "source witness references a missing prefix record")
    manifest = blob(256 * 1024)
    expected = bytearray(b"FA-MIGRATION-SOURCE\0" + (1).to_bytes(2, "little"))
    expected.extend(bytes.fromhex(binding["book_id"]))
    expected.extend(int(binding["run_vid"], 16).to_bytes(16, "little"))
    for name in ("run_body_digest", "source_oid", "source_commit", "package_oid", "package_commit"):
        expected.extend(bytes.fromhex(binding[name]))
    expected.extend(binding["source_rows"].to_bytes(8, "little"))
    expected.extend(len(chunks).to_bytes(4, "little"))
    for chunk in chunks:
        expected.extend(int(chunk["entry_vid"], 16).to_bytes(16, "little"))
        expected.extend(bytes.fromhex(chunk["proposal_digest"]))
    require(manifest == expected, "report source witness differs from the exact prepared source population")
    if major == 1:
        require(position == len(bundle), "source-aware v1 report has trailing container bytes")
    return {"major": major, "minor": minor, "source_witnesses": 1,
            "manifest_bytes": len(manifest), "bind_leaf_index": leaf_index}


def check_tb(event: dict[str, Any], expected: dict[str, Any], *, invisible: bool = False) -> None:
    rows = body(event).get("rows")
    require(isinstance(rows, list), "trial balance has no rows array")
    actual: dict[str, tuple[int, int, int]] = {}
    for row in rows:
        code = row["code"]
        require(code not in actual, f"duplicate native GBP trial-balance row for {code}")
        values = tuple(money(row[key]) for key in ("debits", "credits", "net"))
        require(values[0] - values[1] == values[2], f"native net does not equal debit minus credit for {code}")
        for pending in ("debits_pending", "credits_pending"):
            if pending in row:
                require(money(row[pending]) == 0, f"unexpected pending amount for {code}")
        if any(values):
            actual[code] = values
    target = {} if invisible else expected_cells(expected)
    require(actual == target, f"native trial balance differs from source by account: {actual!r} != {target!r}")


def check_staged_group(event: dict[str, Any], chunks: list[dict[str, Any]], *,
                       start: int, total: int, package: str, run_vid: str,
                       already_recorded: bool = False) -> list[dict[str, Any]]:
    """Bind every returned receipt to the independently checked prepared chunk.

    A group commits its members separately. Neither a success count nor a
    balanced final fold can replace checking the exact approved identities.
    """
    require(event.get("event") == "migration_import_group_staged", "native emitted no group staging result")
    result = body(event)
    require(result.get("package_oid") == package.removeprefix("D:")
            and result.get("run_vid") == run_vid, "native staged a different package or migration run")
    require(result.get("atomic") is False, "native grouped staging misstates its publication boundary")
    require(result.get("selected_count") == result.get("completed_count") == len(chunks),
            "native group omitted a selected chunk")
    require(result.get("recorded_count") == start + len(chunks) and result.get("chunk_count") == total,
            "native grouped staging returned the wrong chunk census")
    require(result.get("run_state") == "Open"
            and result.get("ready_to_finalize") is (start + len(chunks) == total),
            "native grouped staging returned the wrong activation readiness")
    receipts = result.get("chunks")
    require(isinstance(receipts, list) and len(receipts) == len(chunks), "native group has an incomplete receipt list")
    sequences = set()
    for offset, (chunk, receipt) in enumerate(zip(chunks, receipts, strict=True)):
        require(isinstance(receipt, dict), "native group receipt is not an object")
        require(receipt.get("chunk_index") == start + offset
                and receipt.get("entry_vid") == chunk["entry_vid"]
                and receipt.get("proposal_digest") == chunk["proposal_digest"],
                "native staged a different chunk than the approved source proposal")
        sequence = receipt.get("recorded_at")
        require(type(sequence) is int and sequence > 0 and sequence not in sequences,
                "native group has an invalid or repeated publication sequence")
        sequences.add(sequence)
        require(receipt.get("already_recorded") is already_recorded, "native group returned the wrong retry status")
    return receipts


def check_approval_group(events: list[dict[str, Any]], proposals: list[str], *,
                         principal: str, book_id: str,
                         previous: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    """Check each native receipt before using it as a migration approval.

    The command publishes independently, so a refused later member can leave a
    real approved prefix. Native.execute retains that output and refuses the
    run; a zero exit still requires a complete ordered census and exact retry
    identities here. Fixture principals remain distinct, automated test roles.
    """
    require(len(events) == len(proposals), "native approval group omitted or added a proposal receipt")
    identifiers = {receipt["approval_vid"] for receipt in previous.values()}
    sequences = {receipt["recorded_at"] for receipt in previous.values()}
    receipts = []
    for event, proposal in zip(events, proposals, strict=True):
        require(event.get("event") == "approved", "native approval group emitted a different event")
        require(event.get("book") == book_id, "native approval receipt belongs to another book")
        authority = event.get("authority")
        require(isinstance(authority, dict) and authority.get("principal") == principal,
                "native approval receipt belongs to another reviewer")
        receipt = body(event)
        require(receipt.get("approved_digest") == proposal,
                "native approval group changed proposal order or digest")
        identifier, sequence = receipt.get("approval_vid"), receipt.get("recorded_at")
        require(isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{32}", identifier) is not None,
                "native approval has an invalid identifier")
        require(type(sequence) is int and sequence > 0, "native approval has an invalid publication sequence")
        coordinate = event.get("coordinate")
        require(isinstance(coordinate, dict) and type(coordinate.get("known_at")) is int
                and coordinate["known_at"] >= sequence, "native approval receipt is beyond its recorded coordinate")
        prior = previous.get((principal, proposal))
        if prior is None:
            require(receipt.get("already_recorded") is False,
                    "new source proposal unexpectedly returned an existing approval")
            epoch = receipt.get("security_policy_epoch")
            require(type(epoch) is int and epoch >= 0, "new approval has no valid security policy epoch")
            require(identifier not in identifiers and sequence not in sequences,
                    "different proposal approvals share a native identity")
        else:
            require(receipt.get("already_recorded") is True and "security_policy_epoch" in receipt
                    and receipt["security_policy_epoch"] is None,
                    "approval retry did not return an existing native receipt")
            require(identifier == prior["approval_vid"] and sequence == prior["recorded_at"],
                    "approval retry changed its original native identity")
        identifiers.add(identifier)
        sequences.add(sequence)
        receipts.append(dict(receipt))
    return receipts


def check_evidence_group(events: list[dict[str, Any]], entries: list[str], *,
                         documents: dict[str, str], book_id: str, principal: str,
                         staged_at: dict[str, int], previous: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Bind every supplement to its staged entry and the retained source bytes."""
    require(len(events) == len(entries), "native evidence group omitted or added an entry receipt")
    expected = {(oid, commitment, "Source") for oid, commitment in documents.items()}
    identifiers = {receipt["supplement_vid"] for receipt in previous.values()}
    sequences = {receipt["recorded_at"] for receipt in previous.values()}
    last_new_sequence = max(staged_at.values())
    receipts = []
    for event, entry in zip(events, entries, strict=True):
        require(event.get("event") == "evidence_attached", "native evidence group emitted a different event")
        require(event.get("book") == book_id, "native evidence receipt belongs to another book")
        authority = event.get("authority")
        require(isinstance(authority, dict) and authority.get("principal") == principal,
                "native evidence receipt belongs to another principal")
        receipt = body(event)
        require(receipt.get("entry") == entry, "native evidence group changed target order or entry identity")
        for field in ("body_digest", "entry_digest"):
            require(isinstance(receipt.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", receipt[field]) is not None,
                    f"native evidence receipt has an invalid {field}")
        identifier, sequence = receipt.get("supplement_vid"), receipt.get("recorded_at")
        require(isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{32}", identifier) is not None,
                "native evidence supplement has an invalid identifier")
        require(type(sequence) is int and sequence > staged_at[entry],
                "native evidence has an invalid sequence or precedes its staged entry")
        coordinate = event.get("coordinate")
        require(isinstance(coordinate, dict) and type(coordinate.get("known_at")) is int
                and coordinate["known_at"] >= sequence, "native evidence receipt is beyond its recorded coordinate")
        citations = receipt.get("documents")
        require(isinstance(citations, list) and len(citations) == len(expected),
                "native evidence supplement has an incomplete source-document census")
        actual = set()
        for citation in citations:
            require(isinstance(citation, dict)
                    and all(isinstance(citation.get(key), str) for key in ("document_oid", "doc_commit", "role")),
                    "native evidence citation is malformed")
            actual.add((citation["document_oid"], citation["doc_commit"], citation["role"]))
        require(actual == expected, "native evidence supplement changed source documents, commitments or roles")
        prior = previous.get(entry)
        if prior is None:
            require(receipt.get("already_recorded") is False, "new source attachment unexpectedly returned an existing supplement")
            require(coordinate["known_at"] == sequence and sequence > last_new_sequence,
                    "new evidence receipts do not follow the complete staged group in native publication order")
            require(identifier not in identifiers and sequence not in sequences,
                    "different source attachments share a native identity")
            last_new_sequence = sequence
        else:
            require(receipt.get("already_recorded") is True, "evidence retry did not return an existing native receipt")
            require(all(receipt[field] == prior[field] for field in
                        ("supplement_vid", "recorded_at", "entry_digest", "body_digest", "documents")),
                    "evidence retry changed its original native commitment or identity")
        identifiers.add(identifier)
        sequences.add(sequence)
        receipts.append(dict(receipt))
    return receipts


def dimension_set(value: str) -> tuple[tuple[int, str], ...]:
    """Read the native canonical export identities; never derive them from labels."""
    require(isinstance(value, str), "native dimension set must be a string")
    if not value:
        return ()
    result = []
    previous = 0
    for field in value.split(";"):
        match = re.fullmatch(r"([1-9][0-9]*):([0-9a-f]{32})", field)
        require(match is not None, "native dimension set contains an invalid identity")
        assert match is not None
        kind = int(match[1])
        require(previous < kind <= 0xFFFFFFFF, "native dimension kinds are repeated, unordered or out of range")
        result.append((kind, match[2]))
        previous = kind
    require(len(result) <= 64, "native dimension set exceeds its declared bound")
    return tuple(result)


def source_dimensions(row: dict[str, str], identities: dict[str, dict]) -> tuple[tuple[int, str], ...]:
    result = []
    for kind, column in (("cost_center", "cost_center_code"), ("party", "supplier_code")):
        code = row.get(column)
        require(code in identities[kind], f"normalized source names an unknown {kind} code")
        value = identities[kind][code]
        result.append((value["dimension"], value["value"]))
    return tuple(result)


def check_attribution_inventory(attribution: dict, cost_centers: list[dict], parties: list[dict],
                                created: dict[str, dict]) -> dict[str, dict]:
    """Join exact original labels to independently read native value identities."""
    result: dict[str, dict] = {"cost_center": {}, "party": {}}
    for kind, source_key, rows, number in (("cost_center", "cost_centers", cost_centers, 2),
                                          ("party", "suppliers", parties, 12)):
        expected = {value["code"]: value for value in attribution[source_key]}
        require(len(expected) == len(attribution[source_key]) == len(rows),
                f"native {kind} census differs from the complete source")
        for row in rows:
            code = row.get("code")
            require(code in expected and code not in result[kind], f"native {kind} code is unexpected or repeated")
            original = expected[code]
            receipt = created[kind][code]
            if kind == "cost_center":
                require(row.get("dimension") == kind and row.get("dimension_id") == number
                        and row.get("name") == original["name"]
                        and all(row.get(field) is None for field in ("parent", "valid_from", "valid_to"))
                        and row == receipt["value"], "native cost-center definition changed exact source attribution")
                vid = row.get("vid")
            else:
                name = row.get("name")
                require(row.get("kind") == "Counterparty" and row.get("dimension_id") == number
                        and isinstance(name, dict) and name.get("untrusted_content") == original["name"]
                        and name.get("source") == "P:" + str(row.get("vid"))
                        and row.get("vid") == receipt["target"]
                        and row.get("created_at") == receipt["recorded_at"],
                        "native party definition changed the exact published supplier label")
                vid = row.get("dimension_value_vid")
                require(vid != row.get("vid"), "native Party object identity replaced its dimension value")
            require(isinstance(vid, str) and re.fullmatch(r"[0-9a-f]{32}", vid) is not None,
                    "native attribution has an invalid value identity")
            result[kind][code] = {"dimension": number, "value": vid, "name": original["name"]}
        require(len({value["value"] for value in result[kind].values()}) == len(expected),
                "distinct source labels share one native value identity")
    return result


def register_attribution(native: Native, attribution: dict) -> dict[str, dict]:
    require(attribution.get("profile") == public_spend.ATTRIBUTION_PROFILE,
            "unknown native attribution profile")
    created: dict[str, dict] = {"cost_center": {}, "party": {}}
    parties_dir = native.out / "source-parties"
    parties_dir.mkdir()
    for kind, source_key in (("cost_center", "cost_centers"), ("party", "suppliers")):
        for value in attribution[source_key]:
            code, name = value["code"], value["name"]
            if kind == "cost_center":
                event = native.one(["dimension", "add", kind, code, "--name", name])
                require(event.get("event") == "dimension_value_recorded", "native omitted the dimension receipt")
            else:
                path = parties_dir / f"{code}.json"
                write_new(path, json_bytes({"code": code, "kind": "Counterparty", "name": name}))
                event = native.one(["party", "add", str(path)])
                require(event.get("event") == "rea_recorded" and body(event).get("object") == "party"
                        and body(event).get("code") == code, "native omitted the source-party receipt")
            require(event.get("book") == native.book_id
                    and isinstance(event.get("authority"), dict)
                    and event["authority"].get("principal") == native.owner_principal,
                    "native attribution was registered under another book or authority")
            require(body(event).get("already_recorded") is False, "fresh source registration was unexpectedly reused")
            created[kind][code] = body(event)
    cost_centers = body(native.one(["dimension", "list", "cost_center"]))["values"]
    parties = body(native.one(["party", "list"]))["parties"]
    identities = check_attribution_inventory(attribution, cost_centers, parties, created)
    write_new(native.out / "native-attribution-identities.json", json_bytes(identities))
    return identities


def check_prepared_attribution(chunks: list[dict], prepared: Path, identities: dict[str, dict]) -> None:
    """Compare every ordered source group, including both modeled leg tags."""
    groups: dict[str, tuple[str, list[tuple]]] = {}
    with (prepared / "legacy.csv").open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, strict=True):
            day, legs = groups.setdefault(row["entry_id"], (row["effective_date"], []))
            require(day == row["effective_date"], "one source journal names multiple effective dates")
            legs.append((row["account_code"], {"D": "debit", "C": "credit"}[row["side"]],
                         money(row["amount"], unit=False), source_dimensions(row, identities)))
    expected = Counter((day, tuple(legs)) for day, legs in groups.values())
    actual = Counter()
    for index, chunk in enumerate(chunks):
        require(chunk.get("index") == index and chunk.get("leg_count") == len(chunk.get("legs", [])),
                "native prepared attribution has a different ordered chunk census")
        legs = []
        for ordinal, leg in enumerate(chunk["legs"]):
            require(leg.get("index") == ordinal, "native prepared leg order differs")
            tags = leg.get("dimensions")
            require(isinstance(tags, list) and len(tags) == 2,
                    "native prepared leg lost or added an attribution dimension")
            dimensions = tuple((value.get("dimension"), value.get("value")) for value in tags)
            legs.append((leg.get("account"), leg.get("side"), money(leg["amount"]), dimensions))
        actual[(chunk.get("effective_date"), tuple(legs))] += 1
    require(actual == expected, "native prepared legs changed source supplier, cost-center, amount or order")


def export_rows(path: Path) -> list[dict[str, str]]:
    # Strip only the metadata prefix, never a physical line inside a quoted cell.
    with path.open(encoding="utf-8", newline="") as stream:
        text = stream.read()
    lines = text.splitlines(keepends=True)
    start = 0
    while start < len(lines) and lines[start].startswith("#"):
        start += 1
    return list(csv.DictReader(io.StringIO("".join(lines[start:]), newline=""), strict=True))


def check_export(path: Path, prepared: Path, expected: dict[str, Any], *,
                 attribution: dict | None = None, identities: dict[str, dict] | None = None) -> dict[str, int]:
    """Compare every exported native leg, including its source identity and memo.

    A zero grand total alone would admit omissions, duplicate payments and paired
    sign changes. This multiset check independently compares the complete dated
    source-model leg population, retaining repeated original rows.
    """
    attributed = expected.get("native_attribution") == public_spend.ATTRIBUTION_PROFILE
    require(attributed == (attribution is not None and identities is not None),
            "native attribution export has no exact source oracle and value inventory")
    with (prepared / "legacy.csv").open(encoding="utf-8", newline="") as stream:
        source = list(csv.DictReader(stream, strict=True))
    source_legs: Counter[tuple[Any, ...]] = Counter()
    source_ordinals: Counter[str] = Counter()
    for row in source:
        side = row["side"].lower()
        side = {"d": "debit", "c": "credit"}.get(side, side)
        source_id = expected["source_system"] + ":" + row["entry_id"]
        source_ordinals[source_id] += 1
        source_legs[(source_id, source_ordinals[source_id], row["effective_date"], row["account_code"], side,
                     money(row["amount"], unit=False), row["description"], row["memo"],
                     source_dimensions(row, identities) if attributed else ())] += 1
    reader = export_rows(path)
    actual_legs: Counter[tuple[Any, ...]] = Counter()
    entries: dict[str, str] = {}
    for row in reader:
        require(row["currency"] == "GBP" and row["unit_scale"] == "2", "export changed source currency or scale")
        require(row["entry_class"] == "12", "exported source entry is not native Migration class")
        require(row["side"] in ("D", "C"), "export has an unknown posting side")
        side = "debit" if row["side"] == "D" else "credit"
        actual_legs[(row["migrated_from"], int(row["line_no"]), row["effective_date"], row["account_code"], side,
                     money(row["amount"], unit=False), row["description"], row["memo"],
                     dimension_set(row.get("dimension_set_v1", "")))] += 1
        prior = entries.setdefault(row["entry_id"], row["migrated_from"])
        require(prior == row["migrated_from"], "native entry combines different source journals")
    require(actual_legs == source_legs, "native export lost, duplicated or changed dated source legs/memos")
    require(sum(actual_legs.values()) == expected["leg_count"], "native export leg census differs from source")
    require(len(entries) == expected["entry_count"], "native export journal census differs from source")
    require(len(set(entries.values())) == len(entries), "source journal was split across multiple native entries")
    if attributed:
        assert attribution is not None and identities is not None
        # Independent gross/net controls for every value are rebuilt from the
        # original publisher fields during preflight, not from these exports.
        for kind, source_key in (("cost_center", "cost_centers"), ("party", "suppliers")):
            by_value = {value["value"]: code for code, value in identities[kind].items()}
            number = 2 if kind == "cost_center" else 12
            observed: dict[str, dict[str, list[int]]] = {}
            for row in reader:
                tags = dict(dimension_set(row["dimension_set_v1"]))
                require(tags.get(number) in by_value, "export contains an unknown native source attribution")
                code = by_value[tags[number]]
                cell = observed.setdefault(code, {}).setdefault(row["account_code"], [0, 0, 0])
                amount = money(row["amount"], unit=False)
                cell[0 if row["side"] == "D" else 1] += amount
                cell[2] += amount if row["side"] == "D" else -amount
            for value in attribution[source_key]:
                actual = {code: tuple(cell) for code, cell in observed.get(value["code"], {}).items() if any(cell)}
                require(actual == expected_cells(value), f"exported {kind} gross/net cells differ from original source")
    return {"entries": len(entries), "legs": sum(actual_legs.values())}


def check_cost_center_report(event: dict, value: dict, *, invisible: bool = False) -> None:
    require(event.get("event") == "trial_balance", "native cost-center report has another event type")
    require(body(event).get("dimension") == {"dimension": "cost_center", "value": value["code"],
                                             "values": [value["code"]]},
            "native trial balance selected another cost center or an unexpected descendant")
    check_tb(event, value, invisible=invisible)


def certify_cost_centers(native: Native, attribution: dict, period: str, pre_finalize: int) -> list[dict]:
    """Exercise every published expense area, including a zero-only area."""
    directory = native.out / "cost-center-reports"
    directory.mkdir()
    reports = []
    for value in attribution["cost_centers"]:
        code = value["code"]
        selected = ["tb", "--period", period, "--dimension", "cost_center=" + code]
        historical = native.one([*selected, "--as-known-at", str(pre_finalize)])
        check_cost_center_report(historical, value, invisible=True)
        require(historical.get("coordinate", {}).get("known_at") == pre_finalize,
                "cost-center historical report moved its selected prefix")
        check_cost_center_report(native.one([*selected, "--activity"]), value)
        certified = native.execute([*selected, "--certify"])
        report = event_named(certified, "trial_balance")
        check_cost_center_report(report, value)
        certificate = body(event_named(certified, "report_certificate"))
        require(certificate.get("output_format") == "fa:dimension-trial-balance:v1"
                and report.get("certificate") == certificate.get("oid"),
                "native cost-center certificate is not bound to the selected report")
        replay_path = directory / f"{code}.report"
        replayed = native.execute(["replay", "C:" + certificate["oid"], "--output", str(replay_path)])
        replay = event_named(replayed, "trial_balance")
        check_cost_center_report(replay, value)
        require(body(replay) == body(report), "cost-center replay changed its exact report")
        require(body(event_named(replayed, "report_replayed")).get("output_digest") == certificate["output_digest"],
                "native cost-center replay changed its certified output digest")
        reports.append({"code": code, "name": value["name"], "source_rows": value["row_count"],
                        "posted_source_rows": value["posted_row_count"], "certificate_oid": certificate["oid"],
                        "output_digest": certificate["output_digest"],
                        "known_at": report["coordinate"]["known_at"],
                        "historical_known_at": pre_finalize,
                        "replayed_report_sha256": digest(replay_path.read_bytes())})
        print(f"cost centers: certified {len(reports)}/{len(attribution['cost_centers'])}", file=sys.stderr, flush=True)
    return reports


def verify_cost_center_proofs(native: Native, reports: list[dict], state: dict, signed: dict,
                             checkpoint: Path, binding: dict | None, chunks: list[dict]) -> None:
    for report in reports:
        code = report["code"]
        bundle = native.out / "cost-center-reports" / f"{code}.fab"
        receipt = bundle.with_suffix(".receipt")
        native.one(["bundle", "produce", "--certificate", "C:" + report["certificate_oid"],
                    "--state", state["oid"], "--out", str(bundle), "--receipt-out", str(receipt)])
        if binding is not None:
            report["source_population"] = check_source_report_bundle(bundle.read_bytes(), binding, chunks)
        results = native.execute(["report", str(bundle), "--key", signed["checkpoint_public_key"],
                                  "--checkpoint", str(checkpoint), "--receipt", str(receipt),
                                  "--expect", report["certificate_oid"]], verifier=True)
        verified = [value for value in results if value.get("verdict") == "verified"]
        require(len(verified) == 1, "standalone verifier did not authenticate the cost-center report")
        checks = [check for check in verified[0].get("checks", []) if check.get("check") == "dimension_filter"]
        require(len(checks) == 1 and checks[0].get("result") == "pass"
                and checks[0].get("scope") == "authenticated_journal"
                and checks[0].get("detail", {}).get("dimension") == "cost_center"
                and checks[0].get("detail", {}).get("value") == code
                and checks[0].get("detail", {}).get("included_values") == [code],
                "standalone verifier did not independently bind the exact cost-center selection")
        report.update(bundle_sha256=digest(bundle.read_bytes()), receipt_sha256=digest(receipt.read_bytes()),
                      independently_verified=True)


def tamper_export_attribution(source: Path, destination: Path, kind: str,
                              identities: dict[str, dict]) -> dict:
    """Change one valid dimension identity, retaining every other logical cell."""
    rows = export_rows(source)
    number = 2 if kind == "cost_center" else 12
    require(kind in ("cost_center", "party") and bool(rows), "invalid attribution tamper control")
    before = dict(dimension_set(rows[0]["dimension_set_v1"]))[number]
    candidates = sorted(value["value"] for value in identities[kind].values() if value["value"] != before)
    require(bool(candidates), f"{kind} substitution control requires two distinct published values")
    after = candidates[0]
    token = f"{number}:{before}"
    replacement = f"{number}:{after}"
    with source.open(encoding="utf-8", newline="") as stream:
        text = stream.read()
    require(token in text, "attribution tamper target is missing")
    write_new(destination, text.replace(token, replacement, 1).encode("utf-8"))
    changed = export_rows(destination)
    expected = [dict(row) for row in rows]
    expected[0]["dimension_set_v1"] = rows[0]["dimension_set_v1"].replace(token, replacement, 1)
    require(changed == expected and changed != rows,
            "attribution negative control changed anything besides one valid dimension value")
    return {"kind": kind, "dimension": number, "before": before, "after": after,
            "changed_legs": 1, "file": destination.name, "sha256": digest(destination.read_bytes())}


class Native:
    def __init__(self, fa: Path, verifier: Path, out: Path, timeout: int, fad: Path | None = None,
                 stage_group_size: int = 64, batch_approvals: bool = False, batch_evidence: bool = False,
                 bind_source: bool = False, native_attribution: bool = False):
        self.fa, self.verifier, self.out, self.timeout = fa, verifier, out, timeout
        require(type(stage_group_size) is int and 1 <= stage_group_size <= 4096,
                "stage group size must be an integer between 1 and 4096")
        self.stage_group_size = stage_group_size
        require(type(batch_approvals) is bool, "batch approvals must be explicitly enabled or disabled")
        self.batch_approvals = batch_approvals
        self.approval_group_requests = 0
        self.approval_receipts: dict[tuple[str, str], dict[str, Any]] = {}
        self.book_id: str | None = None
        require(type(batch_evidence) is bool, "batch evidence must be explicitly enabled or disabled")
        self.batch_evidence = batch_evidence
        require(type(bind_source) is bool, "source binding must be explicitly enabled or disabled")
        self.bind_source = bind_source
        require(type(native_attribution) is bool, "native attribution must be explicitly enabled or disabled")
        self.native_attribution = native_attribution
        self.evidence_group_requests = 0
        self.evidence_receipts: dict[str, dict[str, Any]] = {}
        self.document_commitments: dict[str, str] = {}
        self.owner_principal: str | None = None
        self.fad = fad
        self.book = out / "book"
        self.calls = 0
        self.daemon: subprocess.Popen[bytes] | None = None
        self.daemon_streams: list[Any] = []
        self.daemon_record: dict[str, Any] | None = None
        self.reviewer_tokens: list[Path] = []
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("FA_")}
        self.env.update(NO_COLOR="1", TERM="dumb")
        paths = {"fa": self.fa, "fa_verify": self.verifier}
        if self.fad is not None:
            paths["fad"] = self.fad
        self.identities = {key: executable_identity(path) for key, path in paths.items()}
        (out / "transcript").mkdir()

    def check_executable(self, key: str) -> None:
        identity = self.identities[key]
        path = Path(identity["path"])
        try:
            unchanged = executable_fingerprint(path) == identity["fingerprint"]
        except OSError as error:
            raise CheckError(f"native executable became unavailable during this run: {path}") from error
        require(unchanged, f"native executable changed during this run: {path}")

    def check_executables(self) -> None:
        for key in self.identities:
            self.check_executable(key)

    def execute(self, args: list[str], *, verifier: bool = False,
                expected_exit: int = 0, token: Path | None = None,
                daemon_control: bool = False, request_bytes: bytes | None = None) -> list[dict[str, Any]]:
        if daemon_control:
            require(self.fad is not None and token is None and not verifier, "invalid daemon control request")
            executable = "fad"
            command = [str(self.fad), *args, "--book", str(self.book), "--json"]
        elif verifier:
            require(token is None, "standalone verifier cannot receive a book token")
            executable = "fa_verify"
            command = [str(self.verifier), *args, "--json"]
        else:
            executable = "fa"
            command = [str(self.fa), "--book", str(self.book)]
            if self.daemon is not None:
                require(self.daemon.poll() is None, "native daemon exited during the bulk import")
                command += ["--via", "fad"]
            if token is not None:
                command += ["--token", str(token)]
            command += args + ["--json"]
        self.check_executable(executable)
        self.calls += 1
        stem = f"{self.calls:05d}"
        started = time.monotonic()
        input_path = self.out / "transcript" / f"{stem}.stdin.bin"
        if request_bytes is not None:
            write_new(input_path, request_bytes)
        with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
            request = {"call": self.calls, "argv": command, "state": "started"}
            if request_bytes is not None:
                request.update(stdin_sha256=digest(request_bytes), stdin_bytes=len(request_bytes),
                               stdin_path=str(input_path.relative_to(self.out)))
            log.write(json.dumps(request) + "\n")
        try:
            completed = subprocess.run(command, input=request_bytes, capture_output=True,
                                       env=self.env, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as error:
            write_new(self.out / "transcript" / f"{stem}.stdout.jsonl", error.stdout or b"")
            write_new(self.out / "transcript" / f"{stem}.stderr.txt", error.stderr or b"")
            raise CheckError(f"native command timed out after {self.timeout}s: {args}") from error
        write_new(self.out / "transcript" / f"{stem}.stdout.jsonl", completed.stdout)
        write_new(self.out / "transcript" / f"{stem}.stderr.txt", completed.stderr)
        with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"call": self.calls, "state": "completed", "exit": completed.returncode,
                                  "seconds": round(time.monotonic() - started, 3),
                                  "stdout_sha256": digest(completed.stdout),
                                  "stderr_sha256": digest(completed.stderr)}) + "\n")
        self.check_executable(executable)
        require(completed.returncode == expected_exit,
                f"native command {args} exited {completed.returncode}, expected {expected_exit}: "
                + completed.stdout.decode(errors="replace")[-3000:]
                + completed.stderr.decode(errors="replace")[-1000:])
        try:
            events = [json.loads(line) for line in completed.stdout.decode("utf-8").splitlines()]
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CheckError(f"native command did not emit valid JSONL: {args}") from error
        require(bool(events) and all(isinstance(event, dict) for event in events), "native command emitted no event objects")
        if expected_exit == 0:
            require(all(event.get("event") != "error" for event in events), "native success includes an error event")
        return events

    def one(self, args: list[str], *, expected_exit: int = 0, token: Path | None = None,
            request_bytes: bytes | None = None) -> dict[str, Any]:
        events = self.execute(args, expected_exit=expected_exit, token=token, request_bytes=request_bytes)
        require(len(events) == 1, f"expected one native event for {args}, received {len(events)}")
        return events[0]

    def head(self) -> int:
        return self.one(["book", "info"])["coordinate"]["known_at"]

    def document(self, path: Path, kind: str, mime: str) -> str:
        # The native upload records the actual launch posture's custody. The
        # harness never relabels its uploads as human or third-party evidence.
        uploaded = body(self.one(["document", "add", str(path), "--kind", kind, "--mime", mime]))
        oid = uploaded["oid"]
        if self.batch_evidence or self.bind_source:
            commitment = uploaded.get("doc_commit")
            require(isinstance(oid, str) and re.fullmatch(r"[0-9a-f]{64}", oid) is not None
                    and isinstance(commitment, str) and re.fullmatch(r"[0-9a-f]{64}", commitment) is not None,
                    "native upload returned no source-document commitment")
            require(oid not in self.document_commitments or self.document_commitments[oid] == commitment,
                    "native upload changed an earlier document commitment")
            self.document_commitments[oid] = commitment
        # A separate fixture principal exercises the actual native review law.
        # This is automated test-role separation, not independent human review;
        # the original AgentUpload/Generated custody remains unchanged.
        self.one(["document", "attest", "review", "--document", oid,
                  "--as", "public-data-fixture-reviewer-a", "--grant", "approve"])
        return oid

    def approvals(self, proposal: str) -> list[str]:
        # Fixture role separation only: this is NOT independent human review.
        if self.reviewer_tokens:
            return [body(self.one(["approve", "--proposal", proposal], token=token))["approval_vid"]
                    for token in self.reviewer_tokens]
        return [body(self.one(["approve", "--proposal", proposal, "--as", who]))["approval_vid"]
                for who in REVIEWERS]

    def approval_group(self, proposals: list[str]) -> list[list[str]]:
        if not self.batch_approvals:
            return [self.approvals(proposal) for proposal in proposals]
        require(1 <= len(proposals) <= 4096
                and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in proposals)
                and len(set(proposals)) == len(proposals),
                "approval group needs 1..4096 distinct native proposal digests")
        require(isinstance(self.book_id, str) and re.fullmatch(r"[0-9a-f]{32}", self.book_id) is not None,
                "approval group has no independently observed native book identity")
        require(len(self.reviewer_tokens) == 2 and self.reviewer_tokens[0] != self.reviewer_tokens[1],
                "approval group needs two separately issued reviewer tokens")
        request = json_bytes(proposals)
        by_reviewer = []
        for principal, token in zip(REVIEWERS, self.reviewer_tokens, strict=True):
            self.approval_group_requests += 1
            events = self.execute(["approve", "--proposals", "-"], token=token, request_bytes=request)
            receipts = check_approval_group(events, proposals, principal=principal, book_id=self.book_id,
                                            previous=self.approval_receipts)
            self.approval_receipts.update({(principal, proposal): receipt
                                          for proposal, receipt in zip(proposals, receipts, strict=True)})
            by_reviewer.append([receipt["approval_vid"] for receipt in receipts])
        return [list(pair) for pair in zip(*by_reviewer, strict=True)]

    def attach_sources(self, entries: list[str], documents: list[str], *, staged_at: dict[str, int]) -> None:
        evidence_args = [item for oid in documents for item in ("--evidence", oid)]
        if not self.batch_evidence:
            for entry in entries:
                self.one(["document", "attach", entry, *evidence_args])
            return
        require(1 <= len(entries) <= 4096
                and all(isinstance(entry, str) and re.fullmatch(r"[0-9a-f]{32}", entry) for entry in entries)
                and len(set(entries)) == len(entries), "evidence group needs 1..4096 distinct native entry identities")
        require(1 <= len(documents) <= 1024 and len(entries) * len(documents) <= 16384
                and all(isinstance(oid, str) and re.fullmatch(r"[0-9a-f]{64}", oid)
                        and oid in self.document_commitments for oid in documents)
                and len(set(documents)) == len(documents),
                "evidence group needs independently retained source commitments within the native citation bound")
        require(set(staged_at) == set(entries) and all(type(value) is int and value > 0 for value in staged_at.values()),
                "evidence group has no exact native staging receipt census")
        require(isinstance(self.book_id, str) and re.fullmatch(r"[0-9a-f]{32}", self.book_id) is not None
                and isinstance(self.owner_principal, str) and bool(self.owner_principal),
                "evidence group has no independently observed book and caller identity")
        self.evidence_group_requests += 1
        events = self.execute(["document", "attach", "--entries", "-", *evidence_args], request_bytes=json_bytes(entries))
        receipts = check_evidence_group(events, entries,
                                       documents={oid: self.document_commitments[oid] for oid in documents},
                                       book_id=self.book_id, principal=self.owner_principal,
                                       staged_at=staged_at, previous=self.evidence_receipts)
        self.evidence_receipts.update(dict(zip(entries, receipts, strict=True)))

    def start_bulk(self) -> None:
        """Optionally hold the same native book through its existing daemon.

        Every approval still names an issued principal and every stage still
        enters the ordinary native migration admission path. Only the thousands
        of redundant file-store reopens inside the bulk loop are amortized.
        """
        if self.fad is None and not self.batch_approvals:
            return
        require(self.daemon is None, "native daemon is already running")
        require(not self.reviewer_tokens, "bulk reviewer tokens have already been issued")
        for who in REVIEWERS:
            token = self.out / f"{who}.token"
            self.one(["capability", "issue", "--holder", who, "--profile", "human",
                      "--op", "read", "--op", "approve", "--out", str(token),
                      "--grant", "issue_capability", "--grant", "read", "--grant", "approve"])
            self.reviewer_tokens.append(token)
        if self.fad is None:
            return
        self.check_executable("fad")
        self.calls += 1
        stem = f"{self.calls:05d}"
        stdout = self.out / "transcript" / f"{stem}.stdout.jsonl"
        stderr = self.out / "transcript" / f"{stem}.stderr.txt"
        command = [str(self.fad), "serve", "--book", str(self.book), "--json"]
        with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"call": self.calls, "argv": command, "state": "started"}) + "\n")
        self.daemon_streams = [stdout.open("xb"), stderr.open("xb")]
        self.daemon_record = {"call": self.calls, "started": time.monotonic(), "stdout": stdout, "stderr": stderr}
        try:
            self.daemon = subprocess.Popen(command, stdout=self.daemon_streams[0], stderr=self.daemon_streams[1], env=self.env)
        except OSError:
            for stream in self.daemon_streams:
                stream.close()
            self.daemon_streams = []
            self.daemon_record = None
            raise
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            require(self.daemon.poll() is None, "native daemon exited before readiness: " + stderr.read_text(errors="replace")[-2000:])
            for line in stdout.read_bytes().splitlines():
                try:
                    event = json.loads(line)
                except (UnicodeError, json.JSONDecodeError):
                    continue  # A concurrently written final line can be incomplete.
                if isinstance(event, dict) and event.get("event") == "fad_serving":
                    self.check_executable("fad")
                    return
            time.sleep(0.1)
        raise CheckError(f"native daemon did not become ready within {self.timeout}s")

    def stop_bulk(self) -> None:
        if self.daemon is None:
            return
        process = self.daemon
        try:
            require(process.poll() is None, "native daemon exited before its explicit stop")
            self.execute(["stop"], daemon_control=True)
            try:
                code = process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired as error:
                raise CheckError("native daemon did not exit after its stop request") from error
            require(code == 0, f"native daemon exited {code}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for stream in self.daemon_streams:
                stream.close()
            record = self.daemon_record
            assert record is not None
            with (self.out / "commands.jsonl").open("a", encoding="utf-8") as log:
                log.write(json.dumps({"call": record["call"], "state": "completed", "exit": process.returncode,
                                      "seconds": round(time.monotonic() - record["started"], 3),
                                      "stdout_sha256": digest(record["stdout"].read_bytes()),
                                      "stderr_sha256": digest(record["stderr"].read_bytes())}) + "\n")
            self.daemon = None
            self.daemon_streams = []
            self.daemon_record = None

    @staticmethod
    def with_approvals(args: list[str], approvals: list[str]) -> list[str]:
        return args + [item for approval in approvals for item in ("--approval", approval)]


def run(native: Native, prepared: Path, dataset: str, expected: dict[str, Any]) -> dict[str, Any]:
    require(native.native_attribution == (expected.get("native_attribution") == public_spend.ATTRIBUTION_PROFILE),
            "native attribution execution and preparation profiles differ")
    start = date.fromisoformat(expected["period_start"])
    period = f"FY{start.year}-P{start.month:02}"
    go_live = f"{start.year + 1}-01-01"
    created = native.one(["book", "create", "--name", f"Published expenditure model: {dataset}",
                          "--base-unit", "GBP", "--opening-date", go_live])
    native.book_id = created.get("book")
    authority = created.get("authority")
    native.owner_principal = authority.get("principal") if isinstance(authority, dict) else None
    native.one(["chart", "import", str(prepared / "chart.json")])
    native.one(["period", "create", "--fiscal-year", str(start.year)])
    attribution = identities = None
    if native.native_attribution:
        attribution = json.loads((prepared / "native_attribution.json").read_bytes())
        identities = register_attribution(native, attribution)
    docs = {}
    documents = [("raw.csv", "Spreadsheet", "text/csv;charset=windows-1252"),
                 ("legacy.csv", "Spreadsheet", "text/csv;charset=utf-8"),
                 ("receipt.json", "Workpaper", "application/json"),
                 ("provenance.jsonl", "Workpaper", "application/x-ndjson"),
                 ("records.jsonl", "Workpaper", "application/x-ndjson"),
                 ("expected_tb.json", "Workpaper", "application/json")]
    if native.native_attribution:
        documents.append(("native_attribution.json", "Workpaper", "application/json"))
    for name, kind, mime in documents:
        docs[name] = native.document(prepared / name, kind, mime)
    readback = native.out / "document-readback"
    readback.mkdir()
    for name, oid in docs.items():
        destination = readback / name
        observed = body(native.one(["document", "read", oid, "--out", str(destination)]))
        require(observed["view"] == "full" and destination.read_bytes() == (prepared / name).read_bytes(),
                f"retained document {name} differs from its source bytes after reopen")
    lines = [{"account": account, "unit": "GBP", "net": decimal(net)}
             for account, (_, _, net) in expected_cells(expected).items() if net]
    empty_tb = native.out / "scope-opening.json"
    write_new(empty_tb, json_bytes({"scope": "constructed published-expenditure model; no departmental opening stock asserted",
                                    "lines": []}))
    opening_doc = native.document(empty_tb, "Spreadsheet", "application/json")
    periods = []
    # The native historical span must run to go-live. Later empty months carry
    # this model's sole source month forward; no assertion about missing public
    # activity or actual departmental closing balances is made.
    for month in range(start.month, 13):
        code = f"FY{start.year}-P{month:02}"
        tb_path = native.out / f"source-control-{code}.json"
        write_new(tb_path, json_bytes({"period": code,
                                      "scope": "computed from the pinned published month only; not an audited trial balance",
                                      "source_sha256": digest((prepared / "raw.csv").read_bytes()), "lines": lines}))
        periods.append({"period": code, "trial_balance": native.document(tb_path, "Spreadsheet", "application/json"),
                        "lines": lines})
    run_path = native.out / "migration-run.json"
    write_new(run_path, json_bytes({"run_key": "public-expenditure-v1", "source_system": expected["source_system"],
                                   "mode": "FullDetail", "trial_balance": opening_doc, "opening_date": go_live,
                                   "lines": [], "periods": periods, "detail_base": [], "sole_opening_source": True}))
    run_vid = body(native.one(["migrate", "open", "--intent", str(run_path)]))["run_vid"]
    intent_path = native.out / "import.json"
    entry_periods = {entry["entry_id"]: period for entry in expected["entries"]}
    write_new(intent_path, json_bytes({"run": "MR:" + run_vid, "source": "D:" + docs["legacy.csv"], "format": "csv",
                                      "default_unit": "GBP", "account_map": json.loads((prepared / "account_map.json").read_bytes()),
                                      "column_map": (prepared / "columns.toml").read_text(), "entry_periods": entry_periods}))
    prepare_args = ["migrate", "import", "--action", "prepare", "--intent", str(intent_path)]
    if native.bind_source:
        prepare_args.append("--bind-source")
    preparation_event = native.one(prepare_args)
    preparation = body(preparation_event)
    require(preparation["mode"] == "FullDetail" and preparation["sole_opening_source"] is True, "native changed migration mode")
    chunks = preparation["chunks"]
    require(len(chunks) == expected["entry_count"] > 0, "native chunk count differs from complete source")
    require(sum(chunk["leg_count"] for chunk in chunks) == expected["leg_count"], "native preparation changed source leg count")
    if identities is not None:
        check_prepared_attribution(chunks, prepared, identities)
    package = preparation["package_oid"]
    binding = binding_receipt = source_report = None
    binding_inputs: dict[str, Any] = {}
    if native.bind_source:
        binding_inputs = {"book_id": native.book_id, "run_vid": run_vid,
                          "source_oid": docs["legacy.csv"], "source_commit": native.document_commitments[docs["legacy.csv"]],
                          "package_oid": package, "source_rows": expected["leg_count"], "chunks": chunks}
        binding = check_source_binding(preparation_event, **binding_inputs, recorded=set())
        binding_receipt = check_binding_receipt(preparation_event)
    before = native.head()
    again_event = native.one(prepare_args)
    again = body(again_event)
    require(again["package_oid"] == package and again["already_recorded"] is True,
            "import prepare retry did not return its original retained package")
    require(native.head() == before, "import prepare retry published new state")
    if native.bind_source:
        check_source_binding(again_event, **binding_inputs, recorded=set(), previous=binding)
        check_binding_receipt(again_event, previous=binding_receipt)
        require(again["recorded_at"] == preparation["recorded_at"], "prepare retry changed its original package upload coordinate")
    check_tb(native.one(["tb", "--period", period]), expected, invisible=True)
    first_approvals: list[str] = []
    native.start_bulk()
    stage_requests = 0
    for start in range(0, len(chunks), native.stage_group_size):
        selected = chunks[start:start + native.stage_group_size]
        proposals = [chunk["proposal_digest"] for chunk in selected]
        approved = native.approval_group(proposals)
        if start == 0 and native.batch_approvals:
            before = native.head()
            require(native.approval_group(proposals) == approved, "approval group retry changed its reviewer pairs")
            require(native.head() == before, "approval group retry published a duplicate")
        selection = []
        for offset, approvals in enumerate(approved):
            selection.append({"index": start + offset, "approvals": approvals})
            if start + offset == 0:
                first_approvals = approvals
        selection_path = native.out / f"stage-{start:05d}.json"
        request_bytes = json_bytes({"chunks": selection})
        write_new(selection_path, request_bytes)
        # The daemon accepts inline request bytes without a filesystem grant.
        # Retain the same bytes locally for reproducibility, but do not ask fad
        # to read an unrestricted host path on the operator's behalf.
        args = ["migrate", "import", "--action", "stage", "--package", package, "--intent", "-"]
        receipts = check_staged_group(native.one(args, request_bytes=request_bytes), selected, start=start, total=len(chunks),
                                      package=package, run_vid=run_vid)
        stage_requests += 1
        entries = [staged["entry_vid"] for staged in receipts]
        staged_at = {staged["entry_vid"]: staged["recorded_at"] for staged in receipts}
        evidence = [docs[name] for name in ("raw.csv", "receipt.json", "provenance.jsonl", "records.jsonl")]
        if native.native_attribution:
            evidence.append(docs["native_attribution.json"])
        native.attach_sources(entries, evidence, staged_at=staged_at)
        if start == 0 and native.batch_evidence:
            before = native.head()
            native.attach_sources(entries, evidence, staged_at=staged_at)
            require(native.head() == before, "source evidence group retry published a duplicate")
        if start == 0:
            before = native.head()
            retry = check_staged_group(native.one(args, request_bytes=request_bytes), selected, start=start, total=len(chunks),
                                       package=package, run_vid=run_vid, already_recorded=True)
            require([row["recorded_at"] for row in retry] == [row["recorded_at"] for row in receipts],
                    "staged group retry changed its native publication identities")
            require(native.head() == before, "staged group retry published a duplicate")
            check_tb(native.one(["tb", "--period", period]), expected, invisible=True)
        print(f"{dataset}: staged {start + len(selected)}/{len(chunks)} chunks; source rows preserved",
              file=sys.stderr, flush=True)
    bulk_head = native.head()
    native.stop_bulk()
    require(native.head() == bulk_head, "native daemon stop/reopen changed the recorded frontier")
    shown_event = native.one(["migrate", "import", "--action", "show", "--package", package])
    shown = body(shown_event)
    require(shown["ties_out"] is True and shown["run_state"] == "Open", "fully staged source does not tie out natively")
    if native.bind_source:
        binding = check_source_binding(shown_event, **binding_inputs,
                                       recorded={chunk["entry_vid"] for chunk in chunks}, previous=binding)
    check_tb(native.one(["tb", "--period", period]), expected, invisible=True)
    pre_finalize = native.head()
    plan = native.out / "finalize.plan"
    planned = body(native.one(["migrate", "finalize", run_vid, "--plan-out", str(plan)]))
    approvals = native.approvals(planned["proposal_digest"])
    before_commit = native.head()
    final = body(native.one(native.with_approvals(["migrate", "finalize", run_vid, "--plan", str(plan)], approvals)))
    require(final["to"] == "Finalized", "native run was not finalized")
    require(final["recorded_at"] == before_commit + 1 and native.head() == final["recorded_at"],
            "native finalization did not publish the complete run in exactly one commit")
    check_tb(native.one(["tb", "--period", period]), expected)
    check_tb(native.one(["tb", "--period", period, "--as-known-at", str(pre_finalize)]), expected, invisible=True)
    native.one(["registers", "advance", "--period", period])
    native.one(["verify", "registers", "--period", period])
    before = native.head()
    again = body(native.one(native.with_approvals(["migrate", "import", "--action", "stage", "--package", package,
                                                  "--chunk", "0"], first_approvals)))
    require(again["already_recorded"] is True and native.head() == before, "post-finalization retry duplicated source data")
    if native.bind_source:
        before = native.head()
        terminal_event = native.one(prepare_args)
        terminal = body(terminal_event)
        require(terminal.get("run_state") == "Finalized", "source-bound prepare retry lost terminal run state")
        binding = check_source_binding(terminal_event, **binding_inputs,
                                       recorded={chunk["entry_vid"] for chunk in chunks}, previous=binding)
        check_binding_receipt(terminal_event, previous=binding_receipt)
        require(terminal["recorded_at"] == preparation["recorded_at"] and native.head() == before,
                "terminal source-bound prepare retry republished package or binding")
    export = native.out / "native.csv"
    native.one(["export", "csv-gl", "--period", period, "--out", str(export)])
    native.one(["verify", "export", "csv-gl", str(export)])
    census = check_export(export, prepared, expected, attribution=attribution, identities=identities)
    attribution_controls = []
    cost_center_reports = []
    if attribution is not None and identities is not None:
        for kind in ("cost_center", "party"):
            tampered_export = native.out / f"tampered-{kind}.csv"
            mutation = tamper_export_attribution(export, tampered_export, kind, identities)
            native.execute(["verify", "export", "csv-gl", str(tampered_export)], expected_exit=8)
            attribution_controls.append(mutation)
        cost_center_reports = certify_cost_centers(native, attribution, period, pre_finalize)
    certified_events = native.execute(["tb", "--period", period, "--certify"])
    certificate_event = event_named(certified_events, "report_certificate")
    report_events = [event for event in certified_events if event.get("event") != "report_certificate"]
    require(len(report_events) == 1, "certification did not emit one native trial balance")
    check_tb(report_events[0], expected)
    certificate = body(certificate_event)
    locator = "C:" + certificate["oid"]
    replay = native.execute(["replay", locator, "--output", str(native.out / "replayed.report")])
    # The retained canonical output digest is the report's native replay promise.
    check_tb(event_named(replay, "trial_balance"), expected)
    replay_body = body(event_named(replay, "report_replayed"))
    require(replay_body.get("output_digest") == certificate["output_digest"], "native replay did not reproduce the certified output digest")
    state = body(native.one(["checkpoint", "create", "--grant", "witness"]))
    signed = body(native.one(["proof", "signed-checkpoint", "--state", state["oid"]]))
    checkpoint_path = native.out / "report.checkpoint"
    write_new(checkpoint_path, bytes.fromhex(signed["bytes"]))
    if cost_center_reports:
        verify_cost_center_proofs(native, cost_center_reports, state, signed, checkpoint_path, binding, chunks)
    bundle_path, receipt_path = native.out / "trial-balance.fab", native.out / "trial-balance.receipt"
    native.one(["bundle", "produce", "--certificate", locator, "--state", state["oid"],
                "--out", str(bundle_path), "--receipt-out", str(receipt_path)])
    if native.bind_source:
        assert binding is not None
        source_report = check_source_report_bundle(bundle_path.read_bytes(), binding, chunks)
    verify_args = ["report", str(bundle_path), "--key", signed["checkpoint_public_key"],
                   "--checkpoint", str(checkpoint_path), "--receipt", str(receipt_path), "--expect", certificate["oid"]]
    verified = native.execute(verify_args, verifier=True)
    require(any(event.get("verdict") == "verified" for event in verified), "independent verifier returned no verified verdict")
    bad_path = native.out / "tampered-trial-balance.fab"
    tampered = bytearray(bundle_path.read_bytes())
    require(bool(tampered), "native produced an empty report bundle")
    tampered[len(tampered) // 2] ^= 1
    write_new(bad_path, bytes(tampered))
    bad_args = verify_args.copy()
    bad_args[1] = str(bad_path)
    negative = native.execute(bad_args, verifier=True, expected_exit=8)
    require(not any(event.get("verdict") == "verified" for event in negative), "tampered bundle was labeled verified")
    return {"status": "PASS", "dataset": dataset, "source_sha256": digest((prepared / "raw.csv").read_bytes()),
            "source_stats": expected["source_stats"], "native_export": census, "native_calls": native.calls,
            "stage_group_size": native.stage_group_size, "stage_requests": stage_requests,
            "batch_approvals": native.batch_approvals, "approval_group_requests": native.approval_group_requests,
            "batch_evidence": native.batch_evidence, "evidence_group_requests": native.evidence_group_requests,
            "bind_source": native.bind_source, "source_binding": binding, "source_binding_receipt": binding_receipt,
            "source_report": source_report,
            "native_attribution": public_spend.ATTRIBUTION_PROFILE if native.native_attribution else None,
            "attribution_identities": identities, "cost_center_reports": cost_center_reports,
            "attribution_tamper_controls": attribution_controls,
            "period": period, "migration_run": run_vid, "package_oid": package, "documents": docs,
            "certificate_digest": certificate["oid"], "output_digest": certificate["output_digest"],
            "checkpoint_public_key": signed["checkpoint_public_key"], "bundle_sha256": digest(bundle_path.read_bytes()),
            "checks": ["pinned_original_bytes", "deterministic_source_transform", "all_source_documents_durable_byte_identity",
                       "complete_chunk_and_leg_census", "group_receipts_bind_every_approved_chunk",
                       "prepare_retry_without_publication", "chunk_retry_without_publication", "staged_invisibility",
                       "native_full_detail_tieout", "atomic_finalization", "historical_invisibility",
                       "exact_gross_and_net_by_account", "registers_equal_fold", "finalized_retry_without_publication",
                       "native_csv_export_verification", "every_dated_exported_leg_and_memo", "native_certificate_replay",
                       "independent_fa_verify_report", "tampered_bundle_refused"]
                      + (["approval_groups_bound_to_each_digest_and_reviewer", "approval_group_retry_without_publication"]
                         if native.batch_approvals else [])
                      + (["group_evidence_binds_every_entry_and_source_commitment", "evidence_group_retry_without_publication"]
                         if native.batch_evidence else [])
                      + (["native_source_binding_matches_complete_prepared_population", "bound_prepare_retry_without_publication",
                          "source_population_complete_before_activation", "terminal_binding_retry_retains_original_identity",
                          "portable_source_manifest_matches_every_prepared_proposal"] if native.bind_source else [])
                      + (["native_source_supplier_and_cost_center_inventory",
                          "every_prepared_leg_preserves_supplier_and_cost_center",
                          "every_exported_leg_preserves_supplier_and_cost_center",
                          "all_supplier_and_cost_center_gross_and_net_cells_match_original_source",
                          "all_cost_center_historical_prefixes_remain_invisible",
                          "all_cost_center_stock_and_activity_reports_match_original_source",
                          "all_cost_center_certificates_replay_exactly",
                          "all_cost_center_portable_reports_independently_verified",
                          "supplier_only_and_cost_center_only_export_mutations_refused"]
                         if native.native_attribution else []),
            "boundary": "Complete published monthly expenditure extract under a declared offset-account model; not a complete original GL, independent human review, fraud finding, or audited trial balance."}


def binary(value: str) -> Path:
    found = shutil.which(value)
    path = Path(found if found else value).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError(f"executable not found: {value}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True, help="complete public_spend.py output directory")
    parser.add_argument("--dataset", required=True, help="pinned sources.toml dataset id")
    parser.add_argument("--out", type=Path, required=True, help="new retained execution directory; existing paths are refused")
    parser.add_argument("--fa", type=binary, default="fa")
    parser.add_argument("--fa-verify", type=binary, default="fa-verify")
    parser.add_argument("--fad", type=binary, help="optional native fad executable for the bulk staging loop")
    parser.add_argument("--timeout", type=int, default=300, help="per-native-command timeout in seconds")
    parser.add_argument("--stage-group-size", type=int, default=64,
                        help="independently approved chunks per source-authenticated request (1..4096; default 64)")
    parser.add_argument("--batch-approvals", action="store_true",
                        help="approve each staging group in two token-bound native calls; requires fa approve --proposals")
    parser.add_argument("--batch-evidence", action="store_true",
                        help="attach source documents to each staging group in one native call; requires document attach --entries")
    parser.add_argument("--bind-source", action="store_true",
                        help="bind the complete retained native package before staging and verify its portable source manifest")
    parser.add_argument("--native-attribution", action="store_true",
                        help="require attributed preparation; import all supplier/expense-area tags and prove every cost-center report")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    if not 1 <= args.stage_group_size <= 4096:
        parser.error("--stage-group-size must be between 1 and 4096")
    prepared, out = args.prepared.resolve(), args.out.resolve()
    try:
        _, expected = verify_prepared(prepared, args.dataset, native_attribution=args.native_attribution)
        out.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, CheckError) as error:
        print(f"public-data preflight refused: {error}", file=sys.stderr)
        return 2
    native: Native | None = None
    started = time.monotonic()
    result = {"status": "FAIL", "dataset": args.dataset,
              "boundary": ("Only completed commands have confirmed outcomes. An interrupted started command "
                           "may have committed; retry the exact retained selections. No unexecuted native check passed.")}
    code = 1
    try:
        native = Native(args.fa, args.fa_verify, out, args.timeout, args.fad, args.stage_group_size,
                        args.batch_approvals, args.batch_evidence, args.bind_source, args.native_attribution)
        result = run(native, prepared, args.dataset, expected)
        code = 0
    except KeyboardInterrupt:
        result["error"] = "interrupted before all required native observations completed"
        code = 130
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        # An interrupted or unexpectedly failed run must not leave its daemon
        # holding the book's writer lease. Preserve the primary failure too.
        try:
            if native is not None:
                native.stop_bulk()
        except Exception as error:
            result["status"] = "FAIL"
            result["daemon_shutdown_error"] = f"{type(error).__name__}: {error}"
            if code == 0:
                code = 1
    if native is not None:
        try:
            native.check_executables()
        except CheckError as error:
            result["status"] = "FAIL"
            result["executable_identity_error"] = str(error)
            if code == 0:
                code = 1
        result.update({key + "_sha256": identity["sha256"] for key, identity in native.identities.items()})
        if code == 0:
            result["checks"].append("executable_identity_guards")
    result["native_calls"] = native.calls if native is not None else 0
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["bulk_transport"] = "native_fad" if args.fad is not None else "direct_cli"
    result["batch_approvals"] = args.batch_approvals
    result["approval_group_requests"] = native.approval_group_requests if native is not None else 0
    result["batch_evidence"] = args.batch_evidence
    result["bind_source"] = args.bind_source
    result["native_attribution"] = public_spend.ATTRIBUTION_PROFILE if args.native_attribution else None
    result["evidence_group_requests"] = native.evidence_group_requests if native is not None else 0
    write_new(out / "result.json", json_bytes(result))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
