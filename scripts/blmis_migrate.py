#!/usr/bin/env python3
"""Import published Glantz principal rows through native source-bound FullDetail.

This is the migration counterpart to blmis_replay.py. The original PDF is
re-extracted in every invocation. Declared monthly balances come from printed
principal cells; the CSV independently uses published movement columns. Native
preparation, approvals, staging, finalization, certificates and fa-verify supply
the accounting results. The four exact-footing Glantz accounts are a declared
subset; the two accounts with printed discrepancies remain retained as evidence.
"""
from __future__ import annotations

import argparse
import calendar
from collections import defaultdict
import csv
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import time

import blmis_source as source
import public_ledger as ledger

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/public-data"))
import run_live as live


ACCOUNTS = ("1T0026", "1ZA192", "1ZB010", "1ZB143")
EXCLUDED_ACCOUNTS = ("1ZR010", "1ZR176")
OFFSET_ACCOUNT = "BLMIS-MIGRATION-OFFSET"
SOURCE_SYSTEM = "blmis-glantz-printed-principal-migration-v1"
SCOPE = (
    "All 304 published observations of Glantz Exhibits B-1 through B-4, including "
    "seven zero-principal observations; 297 monetary observations enter the native "
    "migration. Exhibits B-5 and B-6 remain in the retained complete six-account "
    "source and discrepancy report. Credited transfer principal is a trustee "
    "oracle input, not an independently established legal net-equity result. "
    "The five-account double-entry model and counterpart are explicit analysis "
    "constructions, not a recovered BLMIS general ledger."
)
REVIEW_SCOPE = (
    "AgentUpload source documents receive Reviewed attestations from a distinct "
    "local fixture principal. Two separately issued Human fixture capabilities "
    "approve native proposals. These roles are automated test separation, not "
    "independently authenticated human examination or court approval."
)


def citation(row: dict) -> str:
    return (f"constructed principal counterpart; {source.SOURCE_ID} Exhibit "
            f"{row.get('exhibit', 'B-2')} PDF p{row['pdf_page']} line {row['source_line']}")


def normalized_rows(rows: list[dict]) -> list[dict]:
    """One balanced analysis entry per monetary observation; no source splitting."""
    normalized = []
    seen = set()
    for row in rows:
        live.require(row["row_id"] not in seen, "source repeats an observation identity")
        seen.add(row["row_id"])
        movement = row["principal_movement_cents"]
        if not movement:
            continue
        for account, signed in ((f"BLMIS-{row['account']}", -movement), (OFFSET_ACCOUNT, movement)):
            normalized.append({"entry_id": row["row_id"], "effective_date": row["date"],
                               "account_code": account, "signed_amount": source.money(signed),
                               "description": row["description"], "memo": citation(row),
                               "source_row": row["row_id"]})
    return normalized


def printed_controls(rows: list[dict]) -> list[dict]:
    """Select printed cells only. Movement columns and normalized entries are not inputs."""
    live.require(bool(rows), "printed controls require published observations")
    accounts = sorted({row["account"] for row in rows})
    grouped = {account: [row for row in rows if row["account"] == account] for account in accounts}
    live.require(all([row["date"] for row in values] == sorted(row["date"] for row in values)
                     for values in grouped.values()), "source account dates are not ordered")
    first = min(row["date"] for row in rows)
    last_year = int(max(row["date"] for row in rows)[:4])
    year, month = int(first[:4]), int(first[5:7])
    controls = []
    while year <= last_year:
        at_date = f"{year:04}-{month:02}-{calendar.monthrange(year, month)[1]:02}"
        cells, anchors = {}, []
        for account, account_rows in grouped.items():
            if account_rows[0]["date"] > at_date:
                # There is no published value to select yet. This is the
                # declared from-inception model, not an invented zero citation.
                continue
            anchor = source.last_printed_balance(account_rows, at_date)
            anchors.append({"account": account, **anchor})
            if anchor["printed_balance_cents"]:
                cells[f"BLMIS-{account}"] = -anchor["printed_balance_cents"]
        offset = -sum(cells.values())
        if offset:
            cells[OFFSET_ACCOUNT] = offset
        lines = [{"account": account, "unit": "USD", "net": source.money(cents)}
                 for account, cents in sorted(cells.items())]
        controls.append({"period": f"FY{year}-P{month:02}", "at_date": at_date,
                         "printed_anchors": anchors, "cells_cents": cells, "lines": lines})
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    live.require(len(controls) <= 256, "published historical span exceeds the native run-period bound")
    return controls


def prepare(output: Path, pdf: Path | None, *, on_created=None) -> tuple[list[dict], dict]:
    """Retain complete acquisition and the narrower, explicit migration transform."""
    if pdf is not None:
        source.verify_pdf(pdf)
    output.mkdir(parents=True, exist_ok=False)
    if on_created is not None:
        on_created()
    original = output / "source"
    source_manifest = source.prepare_glantz(original, pdf)
    rows, metadata = source.load_glantz_fixture(original)
    diagnostics = source.glantz_diagnostics(rows, metadata)
    live.require(set(diagnostics["accounts"]) == set(ACCOUNTS) | set(EXCLUDED_ACCOUNTS),
                 "complete source account census differs")
    for account in ACCOUNTS:
        live.require(diagnostics["accounts"][account]["classification"] in
                     ("exact", "exact_under_named_same_day_order"),
                     f"{account} does not support an exact printed-control migration")
    live.require(all(diagnostics["accounts"][account]["classification"] == "printed_source_discrepancy"
                     for account in EXCLUDED_ACCOUNTS), "declared discrepancy population changed")
    ordered = source.glantz_computation_order(rows)
    selected = [row for row in ordered if row["account"] in ACCOUNTS]
    normalized = normalized_rows(selected)
    controls = printed_controls(selected)
    live.require(len(selected) == 304 and len(normalized) == 594 and len(controls) == 194,
                 "complete published migration population or period span changed")
    chart = {"accounts": [
        {"code": f"BLMIS-{account}", "name": f"Published principal {account} - analysis", "type": "Equity", "unit": "USD"}
        for account in ACCOUNTS
    ] + [{"code": OFFSET_ACCOUNT, "name": "Constructed counterpart of published principal",
          "type": "Asset", "unit": "USD"}]}
    payloads = {
        "legacy.csv": source.csv_bytes(source.LEGACY_COLUMNS, normalized),
        "column_map.toml": source.COLUMN_MAP.replace(source.SOURCE_SYSTEM, SOURCE_SYSTEM).encode(),
        "chart.json": source.json_bytes(chart),
        "printed-controls.json": source.json_bytes({
            "scope": SCOPE, "source_sha256": source.SOURCE_SHA256,
            "basis": "last_balance_on_or_before per account; counterpart is the negated sum of printed cells",
            "same_day_rule": source.GLANTZ_REORDER, "controls": controls}),
        "no-opening-stock.json": source.json_bytes({"scope": "Historical detail is the sole opening source", "lines": []}),
    }
    manifest = {
        "format": "fa-blmis-glantz-migration-v1", "scope": SCOPE,
        "source_system": SOURCE_SYSTEM, "source_sha256": source.SOURCE_SHA256,
        "source_rows_sha256": source_manifest["source_rows_sha256"],
        "complete_source_rows": len(rows), "included_accounts": list(ACCOUNTS),
        "included_observations": len(selected), "monetary_observations": len(normalized) // 2,
        "normalized_source_rows": len(normalized),
        "zero_principal_rows": [row["row_id"] for row in selected if not row["principal_movement_cents"]],
        "excluded_accounts": {account: diagnostics["accounts"][account] for account in EXCLUDED_ACCOUNTS},
        "excluded_rows": [row["row_id"] for row in rows if row["account"] in EXCLUDED_ACCOUNTS],
        "entry_order": [row["row_id"] for row in selected if row["principal_movement_cents"]],
        "controls": controls, "opening_date": f"{int(controls[-1]['at_date'][:4]) + 1}-01-01",
        "same_day_rule": source.GLANTZ_REORDER,
        "outputs": {name: {"bytes": len(data), "sha256": source.digest(data)} for name, data in payloads.items()},
    }
    payloads["migration-manifest.json"] = source.json_bytes(manifest)
    for name, data in payloads.items():
        live.write_new(output / name, data)
    return selected, manifest


def check_prepared(package: dict, rows: list[dict], source_oid: str) -> dict[str, str]:
    """Check complete native proposal geometry against published movements."""
    monetary = [row for row in rows if row["principal_movement_cents"]]
    live.require(package.get("mode") == "FullDetail" and package.get("sole_opening_source") is True,
                 "native preparation changed migration inclusion law")
    live.require(package.get("source_oid") == source_oid and package.get("row_count") == 2 * len(monetary)
                 and package.get("chunk_count") == len(monetary), "native parser changed complete source coverage")
    chunks = package.get("chunks")
    live.require(isinstance(chunks, list) and len(chunks) == len(monetary), "native preparation omitted a source entry")
    identities, digests = {}, set()
    for index, (row, chunk) in enumerate(zip(monetary, chunks, strict=True)):
        live.require(chunk.get("index") == index and chunk.get("effective_date") == row["date"]
                     and chunk.get("document_date") == row["date"]
                     and chunk.get("effective_period") == f"FY{row['date'][:4]}-P{row['date'][5:7]}"
                     and chunk.get("counts_after_finalize") is True,
                     f"native changed source date, order or period for {row['row_id']}")
        expected = []
        for ordinal, (account, signed) in enumerate(((f"BLMIS-{row['account']}", -row["principal_movement_cents"]),
                                                    (OFFSET_ACCOUNT, row["principal_movement_cents"]))):
            expected.append({"index": ordinal, "account": account, "side": "debit" if signed > 0 else "credit",
                             "amount": f"{source.money(abs(signed))} USD", "dimensions": []})
        live.require(chunk.get("leg_count") == 2 and chunk.get("legs") == expected,
                     f"native prepared legs differ from published row {row['row_id']}")
        vid, digest = chunk.get("entry_vid"), chunk.get("proposal_digest")
        live.require(isinstance(vid, str) and re.fullmatch(r"[0-9a-f]{32}", vid) is not None
                     and vid not in identities.values() and isinstance(digest, str)
                     and re.fullmatch(r"[0-9a-f]{64}", digest) is not None and digest not in digests,
                     "native preparation repeats or corrupts a source proposal identity")
        identities[row["row_id"]] = vid
        digests.add(digest)
    return identities


def changed_dollar(csv_bytes: bytes) -> tuple[bytes, dict]:
    """A balanced negative control changes one observation, never its printed TB."""
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8"), newline=""), strict=True)
    live.require(reader.fieldnames == list(source.LEGACY_COLUMNS), "negative source schema differs")
    rows = list(reader)
    live.require(len(rows) >= 2 and rows[0]["entry_id"] == rows[1]["entry_id"]
                 and rows[1]["account_code"] == OFFSET_ACCOUNT, "negative control has no first complete source pair")
    first, second = (ledger.source.amount_cents(row["signed_amount"]) for row in rows[:2])
    live.require(first + second == 0, "negative source pair is not balanced")
    delta = 100 if first > 0 else -100
    rows[0]["signed_amount"] = source.money(first + delta)
    rows[1]["signed_amount"] = source.money(second - delta)
    return source.csv_bytes(source.LEGACY_COLUMNS, rows), {
        "source_row_id": rows[0]["entry_id"], "principal_delta_cents": delta,
        "counterpart_delta_cents": -delta, "printed_controls_changed": False,
    }


def check_tb(event: dict, control: dict, *, empty: bool = False, gross: dict | None = None) -> dict:
    live.require(event.get("event") == "trial_balance", "native returned no trial balance")
    cells, actual_gross = ledger.trial_balance_cells(live.body(event), control["period"], None)
    ledger.same_cells(cells, {} if empty else control["cells_cents"], f"printed source control {control['period']}")
    if empty:
        ledger.same_cells(actual_gross, {}, "staged history leaked gross activity")
    elif gross is not None:
        ledger.same_cells(actual_gross, gross, "published source gross activity")
    return {"period": control["period"], "at_date": control["at_date"], "native_cells_cents": cells}


def source_gross(rows: list[dict]) -> dict[str, int]:
    gross = defaultdict(int)
    for row in rows:
        movement = row["principal_movement_cents"]
        if movement:
            for account, signed in ((f"BLMIS-{row['account']}", -movement), (OFFSET_ACCOUNT, movement)):
                gross[f"{account}:{'debit' if signed > 0 else 'credit'}"] += abs(signed)
    return dict(gross)


def check_export(path: Path, rows: list[dict], identities: dict[str, str], receipts: dict[str, dict]) -> dict:
    """Every dated leg, citation and native provenance is checked, including offsets."""
    monetary = [row for row in rows if row["principal_movement_cents"]]
    live.require(set(identities) == {row["row_id"] for row in monetary}
                 and len(set(identities.values())) == len(identities)
                 and set(receipts) == set(identities.values()), "export receipt/source census differs")
    expected = {}
    for row in monetary:
        vid = identities[row["row_id"]]
        for ordinal, (account, signed) in enumerate(((f"BLMIS-{row['account']}", -row["principal_movement_cents"]),
                                                    (OFFSET_ACCOUNT, row["principal_movement_cents"])), 1):
            expected[(vid, str(ordinal))] = (row, account, signed)
    seen = set()
    for actual in ledger.exported_rows(path, "csv-gl"):
        key = actual["entry_id"], actual["line_no"]
        live.require(key in expected and key not in seen, "native export added, repeated or substituted a source leg")
        row, account, signed = expected[key]
        live.require(actual["effective_date"] == row["date"] and actual["entry_class"] == "12"
                     and actual["recorded_seq"] == str(receipts[key[0]]["recorded_at"])
                     and actual["account_code"] == account and actual["side"] == ("D" if signed > 0 else "C")
                     and actual["amount"] == source.money(abs(signed))
                     and actual["currency"] == "USD" and actual["unit_scale"] == "2"
                     and actual["dimension_set_v1"] == "", f"native export changed source geometry {row['row_id']}")
        live.require(actual["description"] == row["description"] and actual["memo"] == citation(row)
                     and actual["migrated_from"] == f"{SOURCE_SYSTEM}:{row['row_id']}",
                     f"native export lost source description, citation or migration provenance {row['row_id']}")
        seen.add(key)
    live.require(seen == set(expected), "native export omitted source observations or counterpart legs")
    return {"entries": len(monetary), "legs": len(seen), "text_and_provenance_exact": True}


def omission_pair_indices(rows: list[dict]) -> list[int]:
    """The named real CHECK/STOP PAYMENT pair; never search for convenient offsets."""
    monetary = [row for row in rows if row["principal_movement_cents"]]
    identifiers = source.GLANTZ_REORDER["computation_row_ids"]
    indices = [index for index, row in enumerate(monetary) if row["row_id"] in identifiers]
    selected = [monetary[index] for index in indices]
    live.require(len(selected) == 2 and [row["row_id"] for row in selected] == identifiers
                 and all(row["account"] == "1ZB010" and row["date"] == "2006-10-17" for row in selected)
                 and [row["description"] for row in selected] == ["STOP PAYMENT", "CHECK"]
                 and [row["principal_movement_cents"] for row in selected] == [2_500_000, -2_500_000],
                 "published offsetting source pair differs from its declared negative-control anchors")
    return indices


def check_stage_group(event: dict, selected: list[dict], package: dict, run_vid: str,
                      recorded: dict[str, dict], *, retry: bool = False, finalized: bool = False) -> list[dict]:
    """Check arbitrary source selections, including the deliberately withheld pair."""
    live.require(event.get("event") == "migration_import_group_staged", "native returned no grouped staging receipt")
    value = live.body(event)
    expected_members = set(recorded) | {chunk["entry_vid"] for chunk in selected}
    expected_state = "Finalized" if finalized else "Open"
    live.require(value.get("package_oid") == package["package_oid"] and value.get("run_vid") == run_vid
                 and value.get("atomic") is False and value.get("run_state") == expected_state,
                 "grouped staging changed package, run or publication boundary")
    live.require(value.get("selected_count") == value.get("completed_count") == len(selected)
                 and value.get("recorded_count") == len(expected_members)
                 and value.get("chunk_count") == len(package["chunks"])
                 and value.get("ready_to_finalize") is (not finalized and len(expected_members) == len(package["chunks"])),
                 "grouped staging changed source population coverage")
    receipts = value.get("chunks")
    live.require(isinstance(receipts, list) and len(receipts) == len(selected), "grouped staging omitted source receipts")
    previous_sequence = max((item["recorded_at"] for item in recorded.values()), default=0)
    for chunk, receipt in zip(selected, receipts, strict=True):
        vid, sequence = receipt.get("entry_vid"), receipt.get("recorded_at")
        live.require(receipt.get("chunk_index") == chunk["index"] and vid == chunk["entry_vid"]
                     and receipt.get("proposal_digest") == chunk["proposal_digest"]
                     and receipt.get("already_recorded") is retry and type(sequence) is int and sequence > 0,
                     "grouped staging substituted an approved source identity")
        if retry:
            live.require(vid in recorded and sequence == recorded[vid]["recorded_at"],
                         "source retry changed its original publication")
        else:
            live.require(vid not in recorded and sequence > previous_sequence,
                         "fresh source chunks do not have distinct ordered publications")
            previous_sequence = sequence
    return receipts


def stage_selection(native: live.Native, selected: list[dict], package: dict, run_vid: str,
                    receipts: dict[str, dict], documents: dict[str, str]) -> tuple[bytes, list[dict]]:
    approvals = native.approval_group([chunk["proposal_digest"] for chunk in selected])
    request = live.json_bytes({"chunks": [{"index": chunk["index"], "approvals": values}
                                          for chunk, values in zip(selected, approvals, strict=True)]})
    live.write_new(native.out / f"stage-{len(receipts):04d}.json", request)
    event = native.one(["migrate", "import", "--action", "stage", "--package", package["package_oid"], "--intent", "-"],
                       request_bytes=request)
    staged = check_stage_group(event, selected, package, run_vid, receipts)
    receipts.update({receipt["entry_vid"]: receipt for receipt in staged})
    native.attach_sources([item["entry_vid"] for item in staged],
                          [documents[name] for name in ("source/source.pdf", "source/rows.csv", "source/source.json", "migration-manifest.json")],
                          staged_at={item["entry_vid"]: item["recorded_at"] for item in staged})
    return request, staged


def add_document(native: live.Native, path: Path, kind: str, mime: str, custody: list[dict]) -> str:
    document = live.body(native.one(["document", "add", str(path), "--kind", kind, "--mime", mime,
                                     "--grade", "AgentUpload", "--as", "blmis-migration-source-uploader"]))
    live.require(document.get("grade") == "AgentUpload" and document.get("self_sourced") is True,
                 "source custody did not retain its actual AgentUpload grade")
    oid, commitment = document["oid"], document["doc_commit"]
    live.require(re.fullmatch(r"[0-9a-f]{64}", oid) is not None
                 and re.fullmatch(r"[0-9a-f]{64}", commitment) is not None, "source document identity is malformed")
    native.document_commitments[oid] = commitment
    review = native.one(["document", "attest", "review", "--document", oid,
                         "--as", "blmis-migration-source-reviewer", "--grant", "approve"])
    live.require(review.get("event") == "attestation_recorded" and live.body(review).get("claim") == "Reviewed"
                 and live.body(review).get("subject") == oid, "source review did not bind its document")
    custody.append({"path": str(path.relative_to(native.out)), "oid": oid, "doc_commit": commitment,
                    "grade": document["grade"], "self_sourced": document["self_sourced"],
                    "review": live.body(review)})
    return oid


def certify(native: live.Native, control: dict) -> dict:
    events = native.execute(["tb", "--period", control["period"], "--certify"])
    raw = (native.out / "transcript" / f"{native.calls:05d}.stdout.jsonl").read_bytes()
    live.require(len(events) == 2 and events[1].get("event") == "report_certificate",
                 "certified trial balance returned an unexpected event sequence")
    checked = check_tb(events[0], control)
    certificate = live.body(events[1])
    live.require(certificate.get("output_format") == "fa:trial-balance:v1"
                 and events[0].get("certificate") == certificate.get("oid"), "trial balance certificate binding differs")
    replayed = native.execute(["replay", "C:" + certificate["oid"]])
    replay_bytes = (native.out / "transcript" / f"{native.calls:05d}.stdout.jsonl").read_bytes()
    live.require(len(replayed) == 1 and replay_bytes == raw.splitlines(keepends=True)[0],
                 f"{control['period']} did not replay exact certified robot bytes")
    return {**checked, "certificate_oid": certificate["oid"], "output_digest": certificate["output_digest"]}


def verify_report(native: live.Native, certificate: dict, state: dict, signed: dict,
                  binding: dict, chunks: list[dict]) -> dict:
    period = certificate["period"]
    directory = native.out / "proofs" / period
    directory.mkdir(parents=True)
    bundle, receipt = directory / "report.fab", directory / "report.receipt"
    locator = "C:" + certificate["certificate_oid"]
    native.one(["bundle", "produce", "--certificate", locator, "--state", state["oid"],
                "--out", str(bundle), "--receipt-out", str(receipt)])
    closure = live.check_source_report_bundle(bundle.read_bytes(), binding, chunks)
    arguments = ["report", str(bundle), "--key", signed["checkpoint_public_key"],
                 "--checkpoint", str(native.out / "report.checkpoint"), "--receipt", str(receipt),
                 "--expect", certificate["certificate_oid"]]
    events = native.execute(arguments, verifier=True)
    live.require(any(event.get("verdict") == "verified" for event in events), "standalone report verifier did not accept")
    return {"period": period, "bundle_sha256": ledger.sha256(bundle), "source_closure": closure,
            "verifier": events, "verifier_arguments": arguments}


def run_native(native: live.Native, rows: list[dict], manifest: dict) -> dict:
    output, controls = native.out, manifest["controls"]
    created = native.one(["book", "create", "--name", "Glantz published principal MIGRATION ANALYSIS ONLY",
                          "--base-unit", "USD", "--calendar", "monthly", "--opening-date", manifest["opening_date"]])
    native.book_id = created["book"]
    native.owner_principal = created["authority"]["principal"]
    native.one(["chart", "import", str(output / "chart.json")])
    for year in range(int(controls[0]["at_date"][:4]), int(controls[-1]["at_date"][:4]) + 1):
        native.one(["period", "create", "--fiscal-year", str(year)])
    custody, documents = [], {}
    for name, kind, mime in (
        ("source/source.pdf", "Other", "application/pdf"),
        ("source/extracted-source/layout.txt", "Workpaper", "text/plain"),
        ("source/rows.csv", "Spreadsheet", "text/csv"),
        ("source/source.json", "Workpaper", "application/json"),
        ("migration-manifest.json", "Workpaper", "application/json"),
        ("legacy.csv", "Spreadsheet", "text/csv"),
        ("printed-controls.json", "Spreadsheet", "application/json"),
        ("no-opening-stock.json", "Spreadsheet", "application/json"),
    ):
        documents[name] = add_document(native, output / name, kind, mime, custody)
    run = {"run_key": "glantz-four-printed-principal-v1", "source_system": SOURCE_SYSTEM,
           "mode": "FullDetail", "trial_balance": documents["no-opening-stock.json"],
           "opening_date": manifest["opening_date"], "lines": [], "detail_base": [], "sole_opening_source": True,
           "periods": [{"period": control["period"], "trial_balance": documents["printed-controls.json"],
                        "lines": control["lines"]} for control in controls]}
    live.write_new(output / "migration-run.json", live.json_bytes(run))
    run_vid = live.body(native.one(["migrate", "open", "--intent", str(output / "migration-run.json")]))["run_vid"]
    accounts = [account["code"] for account in json.loads((output / "chart.json").read_bytes())["accounts"]]
    intent = {"run": "MR:" + run_vid, "source": "D:" + documents["legacy.csv"], "format": "csv",
              "default_unit": "USD", "account_map": {account: account for account in accounts},
              "column_map": (output / "column_map.toml").read_text(encoding="utf-8"),
              "entry_periods": {row["row_id"]: f"FY{row['date'][:4]}-P{row['date'][5:7]}"
                                for row in rows if row["principal_movement_cents"]}}
    live.write_new(output / "import.json", live.json_bytes(intent))
    changed, mutation = changed_dollar((output / "legacy.csv").read_bytes())
    live.write_new(output / "one-dollar-negative.csv", changed)
    negative_oid = add_document(native, output / "one-dollar-negative.csv", "Spreadsheet", "text/csv", custody)
    live.write_new(output / "one-dollar-import.json", live.json_bytes({**intent, "source": "D:" + negative_oid}))
    before_negative = native.head()
    negative = native.one(["migrate", "import", "--action", "prepare", "--bind-source", "--intent",
                           str(output / "one-dollar-import.json")], expected_exit=2)
    live.require("does not tie exactly to the independently declared trial balance" in json.dumps(negative),
                 "one-dollar import twin refused for another reason")
    live.require(native.head() == before_negative, "refused import twin published a package, binding or chunk")
    untouched = live.body(native.one(["migrate", "show", run_vid]))
    live.require(untouched["state"] == "Open" and untouched["chunk_count"] == 0 and untouched["chunks"] == [],
                 "refused import twin staged or terminated its run")
    prepare_args = ["migrate", "import", "--action", "prepare", "--bind-source", "--intent", str(output / "import.json")]
    preparation_event = native.one(prepare_args)
    package = live.body(preparation_event)
    identities = check_prepared(package, rows, documents["legacy.csv"])
    chunks = package["chunks"]
    binding_inputs = {"book_id": native.book_id, "run_vid": run_vid,
                      "source_oid": documents["legacy.csv"], "source_commit": native.document_commitments[documents["legacy.csv"]],
                      "package_oid": package["package_oid"], "source_rows": manifest["normalized_source_rows"], "chunks": chunks}
    binding = live.check_source_binding(preparation_event, **binding_inputs, recorded=set())
    binding_receipt = live.check_binding_receipt(preparation_event)
    before_retry = native.head()
    repeated = native.one(prepare_args)
    live.check_source_binding(repeated, **binding_inputs, recorded=set(), previous=binding)
    live.check_binding_receipt(repeated, previous=binding_receipt)
    live.require(native.head() == before_retry, "identical bound preparation published duplicate history")
    check_tb(native.one(["tb", "--period", controls[-1]["period"]]), controls[-1], empty=True)
    native.start_bulk()
    receipts, first_selection, first_chunks = {}, None, []
    omitted_indices = omission_pair_indices(rows)
    initially_selected = [chunk for chunk in chunks if chunk["index"] not in omitted_indices]
    omitted_chunks = [chunks[index] for index in omitted_indices]
    for start in range(0, len(initially_selected), native.stage_group_size):
        selected = initially_selected[start:start + native.stage_group_size]
        request, staged = stage_selection(native, selected, package, run_vid, receipts, documents)
        args = ["migrate", "import", "--action", "stage", "--package", package["package_oid"], "--intent", "-"]
        if start == 0:
            first_selection, first_chunks = request, selected
            before_retry = native.head()
            retry = check_stage_group(native.one(args, request_bytes=request), selected, package, run_vid, receipts, retry=True)
            live.require(retry == [{**receipt, "already_recorded": True} for receipt in staged]
                         and native.head() == before_retry, "staging retry changed original outcomes")
        print(f"BLMIS migration: staged {len(receipts)}/{len(chunks)} source observations; real offsetting pair withheld", file=sys.stderr, flush=True)
    partial_event = native.one(["migrate", "import", "--action", "show", "--package", package["package_oid"]])
    partial = live.body(partial_event)
    live.require(partial["ties_out"] is True and partial["run_state"] == "Open",
                 "the genuine offsetting omission does not retain all native monetary tie-outs")
    incomplete = live.check_source_binding(partial_event, **binding_inputs, recorded=set(receipts), previous=binding)
    live.require(incomplete["complete"] is False
                 and set(incomplete["missing_chunks"]) == {chunk["entry_vid"] for chunk in omitted_chunks},
                 "source binding did not identify the two deliberately omitted observations")
    before_omission = native.head()
    # --dry-run executes the actual native transition planner. Its source
    # completeness check runs before a plan exists and leaves this run Open.
    omission_refusal = native.one(["migrate", "finalize", run_vid, "--dry-run"], expected_exit=3)
    refusal = live.body(omission_refusal)
    live.require(refusal.get("refusal_id") == "FA-REF-131" and refusal.get("exit") == 3
                 and f"{len(chunks) - 2} of {len(chunks)} exact source chunks; 2 missing and 0 unexpected" in refusal.get("message", ""),
                 "offsetting omission was not refused by native source completeness")
    live.require(native.head() == before_omission, "refused incomplete finalization published history")
    still_open = live.body(native.one(["migrate", "show", run_vid]))
    live.require(still_open["state"] == "Open" and still_open["chunk_count"] == len(chunks) - 2
                 and still_open["ties_out"] is True and still_open["mismatches"] == [],
                 "source-completeness refusal changed the open run or its matching monetary controls")
    omission_negative = {"source_row_ids": source.GLANTZ_REORDER["computation_row_ids"],
                         "missing_entry_vids": incomplete["missing_chunks"], "recorded_chunks": len(receipts),
                         "expected_chunks": len(chunks), "all_monthly_monetary_tieouts_match": True,
                         "exit": 3, "refusal": omission_refusal, "run_remained_open": True, "no_publication": True}
    stage_selection(native, omitted_chunks, package, run_vid, receipts, documents)
    print("BLMIS migration: source-completeness negative refused; original missing pair staged", file=sys.stderr, flush=True)
    native.stop_bulk()
    shown = native.one(["migrate", "import", "--action", "show", "--package", package["package_oid"]])
    live.require(live.body(shown)["ties_out"] is True and live.body(shown)["run_state"] == "Open",
                 "complete native migration does not tie to printed controls")
    binding = live.check_source_binding(shown, **binding_inputs, recorded=set(receipts), previous=binding)
    check_tb(native.one(["tb", "--period", controls[-1]["period"]]), controls[-1], empty=True)
    before_finalize = native.head()
    plan_path = output / "finalize.plan"
    planned = live.body(native.one(["migrate", "finalize", run_vid, "--plan-out", str(plan_path)]))
    approvals = native.approvals(planned["proposal_digest"])
    before_commit = native.head()
    final = live.body(native.one(native.with_approvals(["migrate", "finalize", run_vid, "--plan", str(plan_path)], approvals)))
    live.require(final["to"] == "Finalized" and final["recorded_at"] == before_commit + 1
                 and native.head() == final["recorded_at"], "native did not activate the whole run in one publication")
    check_tb(native.one(["tb", "--period", controls[-1]["period"]]), controls[-1], gross=source_gross(rows))
    check_tb(native.one(["tb", "--period", controls[-1]["period"], "--as-known-at", str(before_finalize)]),
             controls[-1], empty=True)
    before_retry = native.head()
    terminal = native.one(prepare_args)
    live.require(live.body(terminal)["run_state"] == "Finalized", "terminal preparation retry lost finalized state")
    live.check_source_binding(terminal, **binding_inputs, recorded=set(receipts), previous=binding)
    live.check_binding_receipt(terminal, previous=binding_receipt)
    live.require(native.head() == before_retry, "terminal preparation retry published duplicate history")
    # The original selection and approvals remain the retry authority after
    # activation. Never regenerate different entry proposals after approval.
    live.require(first_selection is not None, "migration staged no first group")
    before_retry = native.head()
    retried = native.one(["migrate", "import", "--action", "stage", "--package", package["package_oid"],
                          "--intent", "-"], request_bytes=first_selection)
    check_stage_group(retried, first_chunks, package, run_vid, receipts, retry=True, finalized=True)
    live.require(native.head() == before_retry, "finalized source retry changed native history")
    exported = output / "native.csv"
    native.one(["export", "csv-gl", "--as-of", controls[-1]["at_date"], "--out", str(exported)])
    native.one(["verify", "export", "csv-gl", str(exported)])
    export_census = check_export(exported, rows, identities, receipts)
    certificates = []
    for index, control in enumerate(controls, 1):
        certificates.append(certify(native, control))
        native.one(["registers", "advance", "--period", control["period"]])
        native.one(["verify", "registers", "--period", control["period"]])
        if index % 12 == 0 or index == len(controls):
            print(f"BLMIS migration: certified and replayed {index}/{len(controls)} printed monthly controls", file=sys.stderr, flush=True)
    native.one(["verify", "projections"])
    state = live.body(native.one(["checkpoint", "create", "--grant", "witness"]))
    signed = live.body(native.one(["proof", "signed-checkpoint", "--state", state["oid"]]))
    live.write_new(output / "report.checkpoint", bytes.fromhex(signed["bytes"]))
    proofs = []
    for index, certificate in enumerate(certificates, 1):
        proofs.append(verify_report(native, certificate, state, signed, binding, chunks))
        if index % 12 == 0 or index == len(certificates):
            print(f"BLMIS migration: independently verified {index}/{len(certificates)} source-bound period reports", file=sys.stderr, flush=True)
    arguments = list(proofs[-1]["verifier_arguments"])
    bad = bytearray(Path(arguments[1]).read_bytes())
    live.require(bool(bad), "native report bundle is empty")
    bad[len(bad) // 2] ^= 1
    bad_path = output / "tampered-report.fab"
    live.write_new(bad_path, bytes(bad))
    arguments[1] = str(bad_path)
    rejected = native.execute(arguments, verifier=True, expected_exit=8)
    live.require(not any(event.get("verdict") == "verified" for event in rejected), "tampered proof was accepted")
    return {"status": "PASS", "scope": SCOPE, "review_scope": REVIEW_SCOPE,
            "source_sha256": source.SOURCE_SHA256, "source_rows_sha256": manifest["source_rows_sha256"],
            "source_observations": manifest["complete_source_rows"], "included_observations": len(rows),
            "included_accounts": list(ACCOUNTS), "excluded_accounts": manifest["excluded_accounts"],
            "zero_principal_rows": manifest["zero_principal_rows"], "native_entries": len(receipts),
            "normalized_source_rows": manifest["normalized_source_rows"], "monthly_controls": len(controls),
            "migration_run": run_vid, "source_binding": binding, "source_binding_receipt": binding_receipt,
            "finalization": final, "documents": custody, "entry_identities": identities, "entry_receipts": receipts,
            "one_dollar_negative": {"mutation": mutation, "exit": 2, "refusal": negative, "no_publication": True},
            "offsetting_omission_negative": omission_negative,
            "native_export": export_census, "certificates": certificates, "independent_reports": proofs,
            "tampered_report_refusal": rejected, "native_calls": native.calls,
            "binaries": native.identities, "driver_sha256": ledger.sha256(Path(__file__)),
            "trust_scope": "Caller-trusted checkpoint of a fresh local analysis book; no external trustee or court signing key",
            "source_order": "Retained source identities and effective dates; named same-day computation order is disclosed, never an original transaction timestamp",
            "checks": ["fresh_pinned_complete_pdf_extraction", "declared_exact_footing_account_population",
                       "printed_only_monthly_controls", "balanced_one_dollar_prepare_twin_refused_before_publication",
                       "native_generic_csv_full_detail", "exact_prepared_leg_and_date_census", "native_source_population_binding",
                       "real_offsetting_pair_omission_refused_despite_all_monetary_tieouts", "original_missing_members_repaired_same_open_run",
                       "approved_grouped_staging", "staged_and_historical_invisibility", "atomic_finalization",
                       "stable_prepare_and_stage_retries", "exact_gross_and_net", "every_exported_dated_leg_text_and_provenance",
                       "every_month_certified_and_replayed", "every_month_registers_equal_fold", "every_month_independent_source_bound_report",
                       "tampered_report_refused"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for action in ("prepare", "run"):
        command = commands.add_parser(action)
        command.add_argument("--out", type=Path, required=True, help="new output directory; existing paths are refused")
        command.add_argument("--pdf", type=Path, help="already downloaded pinned Glantz original; still re-extracted")
        if action == "run":
            command.add_argument("--fa", type=Path, default=ROOT / "target/debug/fa")
            command.add_argument("--fa-verify", type=Path, default=ROOT / "target/debug/fa-verify")
            command.add_argument("--fad", type=Path, help="optional native daemon for grouped staging")
            command.add_argument("--timeout", type=int, default=600)
            command.add_argument("--stage-group-size", type=int, default=64)
    args = parser.parse_args(argv)
    if args.command == "run":
        if args.timeout < 1 or not 1 <= args.stage_group_size <= 4096:
            parser.error("positive timeout and a stage group size of 1..4096 are required")
        if not all(path.is_file() for path in [args.fa, args.fa_verify, *([args.fad] if args.fad else [])]):
            print(json.dumps({"status": "UNRUN", "error": "Build matching fa and fa-verify binaries, or pass their paths"}), file=sys.stderr)
            return 4
    output, owned, native = args.out.resolve(), False, None
    started = time.monotonic()

    def created() -> None:
        nonlocal owned
        owned = True

    try:
        rows, manifest = prepare(output, args.pdf, on_created=created)
        if args.command == "prepare":
            print(json.dumps({"status": "PREPARED", "included_observations": len(rows),
                              "monetary_observations": manifest["monetary_observations"],
                              "monthly_controls": len(manifest["controls"]), "out": str(output)}, sort_keys=True))
            return 0
        native = live.Native(args.fa.resolve(), args.fa_verify.resolve(), output, args.timeout,
                             args.fad.resolve() if args.fad else None, args.stage_group_size,
                             batch_approvals=True, batch_evidence=True, bind_source=True)
        report = run_native(native, rows, manifest)
        native.check_executables()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        live.write_new(output / "report.json", live.json_bytes(report))
        print(json.dumps({key: report[key] for key in ("status", "included_observations", "native_entries", "monthly_controls", "native_calls", "elapsed_seconds")}))
        return 0
    except (source.SourceError, ledger.ReplayError, live.CheckError, OSError, ValueError,
            KeyError, TypeError, csv.Error, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        status = "UNRUN" if isinstance(error, source.EnvironmentError) else "FAIL"
        failure = {"status": status, "error": f"{type(error).__name__}: {error}",
                   "elapsed_seconds": round(time.monotonic() - started, 3)}
        if owned:
            live.write_new(output / "failure.json", live.json_bytes(failure))
        print(json.dumps(failure), file=sys.stderr)
        return 4 if status == "UNRUN" else 1
    finally:
        if native is not None:
            native.stop_bulk()


if __name__ == "__main__":
    raise SystemExit(main())
