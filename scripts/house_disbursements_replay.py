#!/usr/bin/env python3
"""Replay a complete House office's published quarter through the native engine.

The source adapter separately reconciles transaction detail to the publisher's
summary. This driver verifies the actual CSV importer, source-bound migration,
monthly folds, every exported leg, durable evidence and an offline report proof.
It never substitutes subtotal rows, a balancing plug or an inferred bank account
for the declared expenditure analysis model.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import io
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/public-data"))
import house_disbursements as source
import run_live as live
import public_ledger as ledger


def usd(text: str) -> int:
    live.require(isinstance(text, str) and re.fullmatch(r"-?[0-9]+\.[0-9]{2} USD", text) is not None,
                 f"native amount is not exact USD cents: {text!r}")
    return ledger.source.amount_cents(text[:-4])


def check_tb(event: dict, control: dict, *, known_at: int, book_id: str,
             invisible: bool = False) -> dict:
    """Compare gross and net amounts, including cells whose net cancels to zero."""
    data = live.body(event)
    coordinate = event.get("coordinate", {})
    live.require(event.get("event") == "trial_balance" and event.get("book") == book_id
                 and data.get("periods") == [control["period"]]
                 and data.get("effective_through") == control["at_date"]
                 and coordinate.get("effective") == "period:" + control["period"]
                 and coordinate.get("branch") == "trunk"
                 and type(data.get("known_at")) is int and data["known_at"] == known_at
                 and type(coordinate.get("known_at")) is int and coordinate["known_at"] == known_at
                 and data.get("mode") == "stock" and data.get("activity") is False
                 and data.get("dimension") is None and data.get("balanced") is True,
                 "native trial balance changed the requested book, period, effective cutoff, known-at prefix or mode")
    rows = data.get("rows")
    live.require(isinstance(rows, list), "native trial balance omitted its rows")
    observed = {}
    for row in rows:
        code = row["code"]
        live.require(code not in observed, "native trial balance repeated an account")
        values = tuple(usd(row[key]) for key in ("debits", "credits", "net"))
        live.require(values[0] >= 0 and values[1] >= 0 and values[0] - values[1] == values[2],
                     "native trial balance has inconsistent debit/credit/net amounts")
        for field in ("debits_pending", "credits_pending"):
            live.require(field not in row or usd(row[field]) == 0, "import unexpectedly created pending amounts")
        observed[code] = values
    actual = {code: values for code, values in observed.items() if any(values)}
    expected = {} if invisible else live.expected_cells(control)
    live.require(actual == expected, f"{control['period']} native gross/net cells differ from the source controls")
    return {"period": control["period"], "effective_through": control["at_date"],
            "known_at": known_at, "cells": len(actual), "invisible": invisible}


def legacy_rows(prepared: Path) -> list[dict]:
    with (prepared / "legacy.csv").open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, strict=True))


def check_prepared(package: dict, prepared: Path, expected: dict) -> None:
    """Check every prepared native leg before collecting its independent approvals."""
    grouped = defaultdict(list)
    for row in legacy_rows(prepared):
        grouped[row["entry_id"]].append(row)
    chunks = package.get("chunks")
    live.require(package.get("mode") == "FullDetail" and package.get("sole_opening_source") is True,
                 "native importer changed the declared migration mode")
    live.require(isinstance(chunks, list) and len(chunks) == expected["entry_count"] == len(grouped),
                 "native importer lost or duplicated a complete analysis journal")
    live.require(len({chunk["entry_vid"] for chunk in chunks}) == len(chunks), "native prepared repeated entry identities")
    for index, (chunk, entry) in enumerate(zip(chunks, expected["entries"], strict=True)):
        rows = grouped[entry["entry_id"]]
        day = entry["effective_date"]
        live.require(chunk["index"] == index and chunk["effective_date"] == day
                     and chunk["effective_period"] == f"FY{day[:4]}-P{day[5:7]}"
                     and chunk["counts_after_finalize"] is True and chunk["recorded_at"] is None,
                     "native preparation changed source dates, historical routing or visibility")
        live.require(chunk["leg_count"] == len(rows) == len(chunk["legs"]), "native preparation changed leg census")
        for ordinal, (leg, row) in enumerate(zip(chunk["legs"], rows, strict=True)):
            live.require(leg["index"] == ordinal and leg["account"] == row["account_code"]
                         and leg["side"] == {"D": "debit", "C": "credit"}[row["side"]]
                         and usd(leg["amount"]) == ledger.source.amount_cents(row["amount"])
                         and leg["dimensions"] == [], "native prepared leg differs from its original source model")
    live.require(sum(chunk["leg_count"] for chunk in chunks) == expected["leg_count"],
                 "native normalized source population changed")


def check_export(path: Path, prepared: Path, expected: dict) -> dict:
    """Require exact source lineage, dates, text and signed amounts for every leg."""
    source_legs, actual_legs = Counter(), Counter()
    ordinals, native_entries = Counter(), {}
    for row in legacy_rows(prepared):
        identity = expected["source_system"] + ":" + row["entry_id"]
        ordinals[identity] += 1
        source_legs[(identity, ordinals[identity], row["effective_date"], row["account_code"],
                     row["side"], ledger.source.amount_cents(row["amount"]), row["description"], row["memo"])] += 1
    for row in live.export_rows(path):
        live.require(row["currency"] == "USD" and row["unit_scale"] == "2" and row["entry_class"] == "12",
                     "export changed the migration class, unit or exact scale")
        live.require(row.get("dimension_set_v1", "") == "", "export added undeclared source dimensions")
        actual_legs[(row["migrated_from"], int(row["line_no"]), row["effective_date"], row["account_code"],
                     row["side"], ledger.source.amount_cents(row["amount"]), row["description"], row["memo"])] += 1
        prior = native_entries.setdefault(row["entry_id"], row["migrated_from"])
        live.require(prior == row["migrated_from"], "native combined separate analysis journals")
    live.require(actual_legs == source_legs, "native export lost, duplicated or changed dated source legs or provenance")
    live.require(len(native_entries) == len(set(native_entries.values())) == expected["entry_count"]
                 and sum(actual_legs.values()) == expected["leg_count"], "native export changed the source population")
    return {"entries": len(native_entries), "legs": sum(actual_legs.values())}


def monetary_twin(prepared: Path) -> bytes:
    """Change one actual source observation and its offset by exactly one cent."""
    rows = legacy_rows(prepared)
    live.require(len(rows) >= 2 and rows[0]["entry_id"] == rows[1]["entry_id"]
                 and rows[0]["side"] != rows[1]["side"] and rows[0]["amount"] == rows[1]["amount"],
                 "source has no first paired observation for the monetary negative")
    for row in rows[:2]:
        row["amount"] = ledger.money(ledger.source.amount_cents(row["amount"]) + 1)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def run(native: live.Native, prepared: Path, expected: dict) -> dict:
    controls = expected["controls"]
    live.require(expected["unit"] == "USD" and expected["scale"] == 2 and len(controls) == 9,
                 "House replay requires the complete April–December scoped control chain")
    live.require([control["period"] for control in controls] == [f"FY2026-P{month:02}" for month in range(4, 13)],
                 "House migration controls have a missing, repeated or reordered month")
    created = native.one(["book", "create", "--name", "House published disbursements ANALYSIS ONLY",
                          "--base-unit", "USD", "--calendar", "monthly", "--opening-date", "2027-01-01"])
    native.book_id = created["book"]
    native.owner_principal = created["authority"]["principal"]
    native.one(["chart", "import", str(prepared / "chart.json")])
    native.one(["period", "create", "--fiscal-year", "2026"])
    documents = {}
    for name, kind, mime in (
        ("raw-detail.csv", "Spreadsheet", "text/csv"),
        ("raw-summary.csv", "Spreadsheet", "text/csv"),
        ("legacy.csv", "Spreadsheet", "text/csv;charset=utf-8"),
        ("records.jsonl", "Workpaper", "application/x-ndjson"),
        ("provenance.jsonl", "Workpaper", "application/x-ndjson"),
        ("receipt.json", "Workpaper", "application/json"),
        ("expected_tb.json", "Workpaper", "application/json"),
        ("controls.json", "Workpaper", "application/json"),
    ):
        documents[name] = native.document(prepared / name, kind, mime)
    readback = native.out / "document-readback"
    readback.mkdir()
    for name, oid in documents.items():
        target = readback / name
        observed = live.body(native.one(["document", "read", oid, "--out", str(target)]))
        live.require(observed["view"] == "full" and target.read_bytes() == (prepared / name).read_bytes(),
                     f"retained House source document changed after reopen: {name}")
    opening = native.out / "no-opening-stock.json"
    live.write_new(opening, live.json_bytes({"scope": "Quarterly expenditure analysis; no original opening stock asserted", "lines": []}))
    opening_doc = native.document(opening, "Workpaper", "application/json")
    run_path = native.out / "migration-run.json"
    live.write_new(run_path, live.json_bytes({
        "run_key": "house-disbursements-q2-2026-v1", "source_system": expected["source_system"],
        "mode": "FullDetail", "trial_balance": opening_doc, "opening_date": "2027-01-01",
        "lines": [], "detail_base": [], "sole_opening_source": True,
        # The native net-TB wire forbids explicit zero lines. Keep the complete
        # gross/net source controls above and below; omit only zero NET claims
        # from this projection, never source activity or its offsetting legs.
        "periods": [{"period": control["period"], "trial_balance": documents["controls.json"],
                     "lines": [line for line in control["lines"]
                               if ledger.source.amount_cents(line["net"]) != 0]}
                    for control in controls],
    }))
    run_vid = live.body(native.one(["migrate", "open", "--intent", str(run_path)]))["run_vid"]
    intent = {"run": "MR:" + run_vid, "source": "D:" + documents["legacy.csv"], "format": "csv",
              "default_unit": "USD", "account_map": json.loads((prepared / "account_map.json").read_bytes()),
              "column_map": (prepared / "columns.toml").read_text(encoding="utf-8"),
              "entry_periods": {entry["entry_id"]: f"FY{entry['effective_date'][:4]}-P{entry['effective_date'][5:7]}"
                                for entry in expected["entries"]}}
    intent_path = native.out / "import.json"
    live.write_new(intent_path, live.json_bytes(intent))
    twin = native.out / "one-cent-negative.csv"
    live.write_new(twin, monetary_twin(prepared))
    twin_doc = native.document(twin, "Spreadsheet", "text/csv")
    twin_intent = native.out / "one-cent-import.json"
    live.write_new(twin_intent, live.json_bytes({**intent, "source": "D:" + twin_doc}))
    before = native.head()
    negative = native.one(["migrate", "import", "--action", "prepare", "--bind-source", "--intent", str(twin_intent)], expected_exit=2)
    live.require("does not tie exactly to the independently declared trial balance" in json.dumps(negative),
                 "monetary twin refused for a reason other than its independent control mismatch")
    live.require(native.head() == before, "refused balanced monetary twin published native history")
    untouched = live.body(native.one(["migrate", "show", run_vid]))
    live.require(untouched["state"] == "Open" and untouched["chunk_count"] == 0,
                 "refused monetary twin changed or staged the migration run")
    prepare_args = ["migrate", "import", "--action", "prepare", "--bind-source", "--intent", str(intent_path)]
    preparation_event = native.one(prepare_args)
    package = live.body(preparation_event)
    check_prepared(package, prepared, expected)
    chunks = package["chunks"]
    binding_args = {"book_id": native.book_id, "run_vid": run_vid, "source_oid": documents["legacy.csv"],
                    "source_commit": native.document_commitments[documents["legacy.csv"]],
                    "package_oid": package["package_oid"], "source_rows": expected["leg_count"], "chunks": chunks}
    binding = live.check_source_binding(preparation_event, **binding_args, recorded=set())
    binding_receipt = live.check_binding_receipt(preparation_event)
    quarter = controls[2]
    before = native.head()
    check_tb(native.one(["tb", "--period", quarter["period"]]), quarter,
             known_at=before, book_id=native.book_id, invisible=True)
    again = native.one(prepare_args)
    live.check_source_binding(again, **binding_args, recorded=set(), previous=binding)
    live.check_binding_receipt(again, previous=binding_receipt)
    live.require(native.head() == before, "exact source preparation retry republished its package or binding")
    native.start_bulk()
    staged_ids = set()
    first_request = first_receipts = None
    for start in range(0, len(chunks), native.stage_group_size):
        selected = chunks[start:start + native.stage_group_size]
        approved = native.approval_group([chunk["proposal_digest"] for chunk in selected])
        request = live.json_bytes({"chunks": [{"index": chunk["index"], "approvals": approvals}
                                              for chunk, approvals in zip(selected, approved, strict=True)]})
        live.write_new(native.out / f"stage-{start:05d}.json", request)
        args = ["migrate", "import", "--action", "stage", "--package", package["package_oid"], "--intent", "-"]
        receipts = live.check_staged_group(native.one(args, request_bytes=request), selected, start=start,
                                           total=len(chunks), package=package["package_oid"], run_vid=run_vid)
        entries = [receipt["entry_vid"] for receipt in receipts]
        native.attach_sources(entries, [documents[name] for name in ("raw-detail.csv", "raw-summary.csv", "receipt.json", "provenance.jsonl")],
                              staged_at={receipt["entry_vid"]: receipt["recorded_at"] for receipt in receipts})
        staged_ids.update(entries)
        if start == 0:
            first_request, first_receipts = request, receipts
            before = native.head()
            retried = live.check_staged_group(native.one(args, request_bytes=request), selected, start=start,
                                              total=len(chunks), package=package["package_oid"], run_vid=run_vid, already_recorded=True)
            live.require([row["recorded_at"] for row in retried] == [row["recorded_at"] for row in receipts]
                         and native.head() == before, "staging retry changed native source receipt identities")
        print(f"House: staged {len(staged_ids)}/{len(chunks)} complete analysis journals", file=sys.stderr, flush=True)
    native.stop_bulk()
    shown = native.one(["migrate", "import", "--action", "show", "--package", package["package_oid"]])
    live.require(live.body(shown)["ties_out"] is True and live.body(shown)["run_state"] == "Open",
                 "complete source population does not tie to all independent native controls")
    binding = live.check_source_binding(shown, **binding_args, recorded=staged_ids, previous=binding)
    pre_finalize = native.head()
    check_tb(native.one(["tb", "--period", quarter["period"]]), quarter,
             known_at=pre_finalize, book_id=native.book_id, invisible=True)
    plan = native.out / "finalize.plan"
    planned = live.body(native.one(["migrate", "finalize", run_vid, "--plan-out", str(plan)]))
    approvals = native.approvals(planned["proposal_digest"])
    before_commit = native.head()
    finalized = live.body(native.one(native.with_approvals(["migrate", "finalize", run_vid, "--plan", str(plan)], approvals)))
    live.require(finalized["to"] == "Finalized" and finalized["recorded_at"] == before_commit + 1
                 and native.head() == finalized["recorded_at"], "whole source population did not activate atomically")
    monthly = []
    for control in controls:
        monthly.append(check_tb(native.one(["tb", "--period", control["period"],
                                            "--as-known-at", str(finalized["recorded_at"])]), control,
                                known_at=finalized["recorded_at"], book_id=native.book_id))
        check_tb(native.one(["tb", "--period", control["period"], "--as-known-at", str(pre_finalize)]), control,
                 known_at=pre_finalize, book_id=native.book_id, invisible=True)
    native.one(["registers", "advance", "--period", quarter["period"]])
    native.one(["verify", "registers", "--period", quarter["period"]])
    before = native.head()
    terminal = native.one(prepare_args)
    live.check_source_binding(terminal, **binding_args, recorded=staged_ids, previous=binding)
    live.check_binding_receipt(terminal, previous=binding_receipt)
    live.require(live.body(terminal)["run_state"] == "Finalized" and native.head() == before,
                 "terminal preparation retry changed the activated source population")
    live.require(first_request is not None and first_receipts is not None, "native staged no first source group")
    retried = live.body(native.one(["migrate", "import", "--action", "stage", "--package", package["package_oid"], "--intent", "-"],
                                   request_bytes=first_request))
    live.require(retried["run_state"] == "Finalized" and native.head() == before
                 and retried["chunks"] == [{**row, "already_recorded": True} for row in first_receipts],
                 "post-finalization staging retry changed original receipts")
    export_known_at = native.head()
    export_files = {}
    for name, filename in (("csv-gl", "native.csv"), ("beancount", "journal.beancount"), ("hledger", "journal.hledger")):
        path = native.out / filename
        native.one(["export", name, "--period", quarter["period"], "--as-known-at", str(export_known_at), "--out", str(path)])
        native.one(["verify", "export", name, str(path)])
        export_files[name] = {"path": filename, "sha256": ledger.sha256(path)}
    exported = check_export(native.out / "native.csv", prepared, expected)
    events = native.execute(["tb", "--period", quarter["period"], "--as-known-at", str(export_known_at), "--certify"])
    certificate = live.body(live.event_named(events, "report_certificate"))
    check_tb(live.event_named(events, "trial_balance"), quarter, known_at=export_known_at, book_id=native.book_id)
    replay = native.execute(["replay", "C:" + certificate["oid"], "--output", str(native.out / "replayed.report")])
    check_tb(live.event_named(replay, "trial_balance"), quarter, known_at=export_known_at, book_id=native.book_id)
    live.require(live.body(live.event_named(replay, "report_replayed"))["output_digest"] == certificate["output_digest"],
                 "certified report replay changed its exact output digest")
    state = live.body(native.one(["checkpoint", "create", "--grant", "witness"]))
    signed = live.body(native.one(["proof", "signed-checkpoint", "--state", state["oid"]]))
    checkpoint = native.out / "report.checkpoint"
    live.write_new(checkpoint, bytes.fromhex(signed["bytes"]))
    bundle, receipt = native.out / "quarter.fab", native.out / "quarter.receipt"
    native.one(["bundle", "produce", "--certificate", "C:" + certificate["oid"], "--state", state["oid"],
                "--out", str(bundle), "--receipt-out", str(receipt)])
    source_closure = live.check_source_report_bundle(bundle.read_bytes(), binding, chunks)
    verify_args = ["report", str(bundle), "--key", signed["checkpoint_public_key"], "--checkpoint", str(checkpoint),
                   "--receipt", str(receipt), "--expect", certificate["oid"]]
    verified = native.execute(verify_args, verifier=True)
    live.require(any(event.get("verdict") == "verified" for event in verified), "offline verifier did not accept the source-bound report")
    tampered = bytearray(bundle.read_bytes())
    tampered[len(tampered) // 2] ^= 1
    bad = native.out / "tampered-quarter.fab"
    live.write_new(bad, bytes(tampered))
    native.execute([verify_args[0], str(bad), *verify_args[2:]], verifier=True, expected_exit=8)
    return {
        "status": "PASS", "organization": expected["organization"], "source_stats": expected["source_stats"],
        "source_receipt_sha256": ledger.sha256(prepared / "receipt.json"), "source_controls_sha256": ledger.sha256(prepared / "controls.json"),
        "entry_count": expected["entry_count"], "leg_count": expected["leg_count"], "native_export": exported,
        "monthly_controls": monthly, "migration_run": run_vid, "finalized_at": finalized["recorded_at"],
        "source_binding": binding, "source_binding_receipt": binding_receipt, "source_report": source_closure,
        "documents": documents, "export_known_at": export_known_at, "exports": export_files,
        "one_cent_refusal": negative, "certificate_digest": certificate["oid"], "output_digest": certificate["output_digest"],
        "checkpoint_public_key": signed["checkpoint_public_key"], "bundle_sha256": ledger.sha256(bundle), "verifier": verified,
        "checks": ["complete_original_detail_and_summary_pins", "publisher_summary_reconciled_before_native_writes",
                   "subtotal_and_office_total_rows_not_posted", "original_blank_dates_and_service_periods_retained",
                   "all_retained_source_document_bytes_match_after_reopen", "every_prepared_leg_matches_declared_source_model",
                   "balanced_one_cent_change_refused_against_independent_controls_without_publication",
                   "source_manifest_binds_every_original_proposal", "exact_prepare_and_stage_retries",
                   "staged_invisibility", "complete_population_and_cumulative_tieout", "atomic_finalization",
                   "nine_monthly_gross_net_and_historical_controls", "exact_book_period_effective_and_known_at_coordinates",
                   "registers_equal_native_fold",
                   "terminal_source_binding_and_receipt_retry", "every_exported_dated_leg_and_memo",
                   "same_coordinate_csv_beancount_and_hledger_exports", "native_export_verification",
                   "certified_report_replay", "independent_source_bound_report_verification", "tampered_report_refused"],
        "scope": "Complete selected House organization's published quarterly disbursements; explicit expenditure/offset analysis book, not an original double-entry GL. Missing transaction dates use the disclosed quarter-end analysis assignment. Fixture reviewer roles are not independent human examination. The caller trusts the local test-book key.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--organization", default=source.DEFAULT_ORGANIZATION)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fa", default="fa")
    parser.add_argument("--fa-verify", default="fa-verify")
    parser.add_argument("--fad", help="optional native daemon to amortize persistent-book reopens")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--stage-group-size", type=int, default=64)
    args = parser.parse_args(argv)
    if args.timeout < 1 or not 1 <= args.stage_group_size <= 4096:
        parser.error("timeout must be positive and stage group size must be in 1..4096")
    try:
        fa, verifier = live.binary(args.fa), live.binary(args.fa_verify)
        fad = live.binary(args.fad) if args.fad else None
    except argparse.ArgumentTypeError as error:
        print(f"UNRUN {error}", file=sys.stderr)
        return 4
    prepared, output = args.prepared.resolve(), args.out.resolve()
    helper_paths = {Path(path).resolve() for path in
                    (__file__, source.__file__, source.common.__file__, live.__file__, ledger.__file__, ledger.source.__file__)}
    helper_hashes = {str(path.relative_to(ROOT)): ledger.sha256(path) for path in sorted(helper_paths)}
    try:
        expected = source.verify_prepared(prepared, args.organization)
        prepared_hashes = {path.name: ledger.sha256(path) for path in prepared.iterdir()}
        output.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, live.CheckError) as error:
        print(f"FAIL House source preflight: {error}", file=sys.stderr)
        return 1
    native = None
    started = time.monotonic()
    result, code = {"status": "FAIL", "organization": args.organization}, 1
    try:
        native = live.Native(fa, verifier, output, args.timeout, fad, args.stage_group_size,
                             batch_approvals=True, batch_evidence=True, bind_source=True)
        result = run(native, prepared, expected)
        code = 0
    except KeyboardInterrupt:
        result["error"], code = "interrupted before all native checks completed", 130
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if native is not None:
            try:
                native.stop_bulk()
                native.check_executables()
            except Exception as error:
                result.update(status="FAIL", finalization_error=f"{type(error).__name__}: {error}")
                code = 1
            result.update(native_calls=native.calls, executables=native.identities,
                          approval_group_requests=native.approval_group_requests,
                          evidence_group_requests=native.evidence_group_requests)
        try:
            live.require(all(ledger.sha256(ROOT / name) == digest for name, digest in helper_hashes.items()),
                         "a running source or native replay helper changed during execution")
            live.require({path.name for path in prepared.iterdir()} == set(prepared_hashes)
                         and all(ledger.sha256(prepared / name) == digest for name, digest in prepared_hashes.items()),
                         "prepared source bytes changed after their original-source authentication")
        except Exception as error:
            result.update(status="FAIL", integrity_error=f"{type(error).__name__}: {error}")
            code = 1
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["helper_sha256"] = helper_hashes[str(Path(__file__).resolve().relative_to(ROOT))]
        result["helpers"] = helper_hashes
        result["prepared_files"] = prepared_hashes
        live.write_new(output / "result.json", live.json_bytes(result))
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
