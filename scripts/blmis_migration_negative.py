#!/usr/bin/env python3
"""Exercise the native monetary finalization refusal on seven real accounts.

This isolated, explicitly unbound control complements blmis_migrate.py. Both
twins share 370 unchanged native source chunks. The same manual adapter stages
the last genuine source observation with its original amount in the positive
twin and a balanced $1 alteration in the negative twin. Printed controls and
both complete originals remain unchanged. No bound migration is modified.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import blmis_migrate as migration

live, source, ledger = migration.live, migration.source, migration.ledger
ROOT = Path(__file__).resolve().parents[1]
TARGET = "SRC-BLM-001:1T0026:p27:l16"
RUN_KEY = "blmis-seven-monetary-finalize-twin-v1"
# Independently derived from both raw source tables with Decimal, including
# the disclosed Glantz same-day display-order interpretation. No native output
# or normalized movement field supplied this oracle.
EXPECTED_MATRIX_SHA256 = "061314cd52aa21432bc0cfb3aa450478356a83f76b420093874f5439653acc4f"


def target_row(rows: list[dict]) -> dict:
    found = [row for row in rows if row["row_id"] == TARGET]
    live.require(len(found) == 1, "the named original mutation target is missing or duplicated")
    row = found[0]
    live.require(row["account"] == "1T0026" and row["date"] == "1992-11-19"
                 and row["description"] == "CHECK WIRE"
                 and row["principal_movement_cents"] == 280_000_000,
                 "the named original $2,800,000 CHECK WIRE observation changed")
    return row


def chunk_intent(row: dict, run_vid: str, source_system: str,
                 evidence: list[str], delta_cents: int) -> dict:
    live.require(type(delta_cents) is int and delta_cents in (0, 100),
                 "the control permits only the original amount or exactly one dollar")
    live.require(row["row_id"] == TARGET and row["principal_movement_cents"] == 280_000_000,
                 "manual control must use the named original observation")
    movement = row["principal_movement_cents"] + delta_cents
    return {"run": run_vid, "class": "Migration", "idempotency_key": row["row_id"],
            "source_system": source_system, "source_id": row["row_id"],
            "effective_date": row["date"], "document_date": row["date"],
            "effective_period": f"FY{row['date'][:4]}-P{row['date'][5:7]}",
            "description": row["description"], "evidence": evidence,
            "legs": [{"account": account, "side": "debit" if amount > 0 else "credit",
                      "amount": f"{source.money(abs(amount))} USD", "memo": migration.citation(row)}
                     for account, amount in ((f"BLMIS-{row['account']}", -movement),
                                             (migration.OFFSET_ACCOUNT, movement))]}


def expected_mismatches(controls: list[dict], row: dict, delta_cents: int) -> list[dict]:
    """Printed cells are the baseline; the deliberately supplied delta is explicit."""
    live.require(type(delta_cents) is int and delta_cents in (0, 100), "unsupported control delta")
    if delta_cents == 0:
        return []
    result = []
    for control in controls:
        if control["at_date"] < row["date"]:
            continue
        for account, delta in ((f"BLMIS-{row['account']}", -delta_cents),
                               (migration.OFFSET_ACCOUNT, delta_cents)):
            declared = control["cells_cents"].get(account, 0)
            result.append({"period": control["period"], "account_code": account, "unit": "USD",
                           "declared": f"{source.money(declared)} USD",
                           "folded": f"{source.money(declared + delta)} USD"})
    live.require(bool(result), "mutation target lies outside all printed controls")
    return result


def check_run(event: dict, run_vid: str, members: dict[str, dict], mismatches: list[dict]) -> dict:
    live.require(event.get("event") == "migration_run", "native returned no run observation")
    body = live.body(event)
    live.require(body.get("run_vid") == run_vid and body.get("mode") == "FullDetail"
                 and body.get("state") == "Open" and body.get("chunk_count") == len(members),
                 "native run changed identity, state or complete population")
    chunks = body.get("chunks")
    live.require(isinstance(chunks, list) and len(chunks) == len(members)
                 and len({chunk["vid"] for chunk in chunks}) == len(chunks),
                 "native run dropped or duplicated a chunk")
    observed = {chunk["vid"]: {"proposal_digest": chunk["proposal_digest"],
                               "recorded_at": chunk["recorded_at"]} for chunk in chunks}
    live.require(observed == members, "native run substituted a staged chunk or receipt")
    actual = body.get("mismatches")
    fields = {"period", "account_code", "unit", "declared", "folded"}
    live.require(isinstance(actual, list) and all(set(line) == fields for line in actual),
                 "native mismatch schema differs")
    key = lambda item: (item["period"], item["account_code"], item["unit"])
    live.require(len({key(item) for item in actual}) == len(actual)
                 and sorted(actual, key=key) == sorted(mismatches, key=key),
                 "native mismatches differ from the exact printed controls and one-dollar delta")
    live.require(body.get("ties_out") is (not mismatches), "native tie-out verdict contradicts its cells")
    return body


def check_monetary_refusal(event: dict, mismatches: list[dict]) -> dict:
    body = live.body(event)
    live.require(event.get("event") == "error" and body.get("exit") == 3
                 and body.get("class") == "refusal" and body.get("refusal_id") == "FA-REF-131",
                 "finalization did not produce the native monetary refusal")
    prefix = ("the run's chunks do not fold to its declared trial balance "
              f"({len(mismatches)} line(s), in debit sign): ")
    message = body.get("message", "")
    live.require(message.startswith(prefix), "finalization refused for a different law or population gap")
    expected = [f"`{line['account_code']}` USD through `{line['period']}`: "
                f"declared {line['declared']}, folded {line['folded']}" for line in mismatches]
    actual = message[len(prefix):].split("; ")
    live.require(len(actual) == len(expected) and sorted(actual) == sorted(expected),
                 "refusal does not identify every exact monetary mismatch")
    return body


def fingerprint_tree(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        live.require(not path.is_symlink(), "a controlled book prefix contains a symlink")
        if path.is_file():
            result[str(path.relative_to(root))] = {"bytes": path.stat().st_size,
                                                  "sha256": ledger.sha256(path)}
    live.require(bool(result), "controlled book prefix is empty")
    return result


def copy_closed_prefix(source_book: Path, positive_book: Path) -> dict:
    live.require(not positive_book.exists() and not positive_book.is_symlink(),
                 "positive control destination already exists")
    before = fingerprint_tree(source_book)
    shutil.copytree(source_book, positive_book)
    live.require(fingerprint_tree(source_book) == before == fingerprint_tree(positive_book),
                 "controlled cold book copy changed a prefix byte")
    return {"files": len(before), "bytes": sum(value["bytes"] for value in before.values()),
            "manifest_sha256": live.digest(live.json_bytes(before)), "manifest": before}


def stage_manual(native: live.Native, run_vid: str, intent: dict, label: str) -> tuple[dict, dict]:
    intent_path, plan_path = native.out / f"{label}-chunk.json", native.out / f"{label}-chunk.plan"
    live.write_new(intent_path, live.json_bytes(intent))
    plan = live.body(native.one(["migrate", "stage", run_vid, "--intent", str(intent_path),
                                 "--plan-out", str(plan_path)]))
    live.require(plan.get("action") == "stage" and plan.get("run_vid") == run_vid
                 and re.fullmatch(r"[0-9a-f]{64}", plan.get("proposal_digest", "")) is not None,
                 "native manual stage plan has another scope or no digest")
    approvals = native.approvals(plan["proposal_digest"])
    response = native.one(native.with_approvals(["migrate", "stage", run_vid, "--plan", str(plan_path)], approvals))
    live.require(response.get("event") == "posted", "fresh manual source chunk was not admitted")
    receipt = live.body(response)
    live.require(re.fullmatch(r"[0-9a-f]{32}", receipt.get("vid", "")) is not None
                 and type(receipt.get("recorded_at")) is int and receipt["recorded_at"] > 0,
                 "native manual chunk has no valid publication receipt")
    entry = live.body(native.one(["entry", "show", receipt["vid"]]))
    live.require(entry.get("found") is True and entry.get("vid") == receipt["vid"]
                 and entry.get("class") == "Migration" and entry.get("approvals") == 2
                 and entry.get("recorded_at") == receipt["recorded_at"]
                 and entry.get("proposal_digest") == plan["proposal_digest"]
                 and entry.get("entry_digest") == receipt["entry_digest"]
                 and entry.get("effective_date") == intent["effective_date"]
                 and entry.get("document_date") == intent["document_date"]
                 and entry.get("description", {}).get("untrusted_content") == intent["description"],
                 "native manual chunk changed its approved source identity, dates or description")
    legs = entry.get("legs")
    live.require(isinstance(legs, list) and len(legs) == 2, "manual native chunk lost a source leg")
    for observed, expected in zip(legs, intent["legs"], strict=True):
        live.require(observed.get("amount") == expected["amount"] and observed.get("side") == expected["side"]
                     and observed.get("dimensions") == []
                     and observed.get("memo", {}).get("untrusted_content") == expected["memo"],
                     "native manual chunk changed amount, side, citation or dimensions")
    return {"vid": receipt["vid"], "proposal_digest": plan["proposal_digest"],
            "recorded_at": receipt["recorded_at"], "entry_digest": receipt["entry_digest"]}, entry


def run_native(native: live.Native, rows: list[dict], manifest: dict) -> dict:
    output, controls, target = native.out, manifest["controls"], target_row(rows)
    monetary = [row for row in rows if row["principal_movement_cents"]]
    live.require(len(monetary) == 371 and len(controls) == 217, "seven-account source population changed")
    expected = expected_mismatches(controls, target, 100)
    matrix_digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    live.require(len(expected) == 388 and matrix_digest == EXPECTED_MATRIX_SHA256,
                 "printed-control mismatch matrix differs from the independent original-literal oracle")
    created = native.one(["book", "create", "--name", "BLMIS monetary finalization CONTROL ONLY",
                          "--base-unit", "USD", "--calendar", "monthly", "--opening-date", manifest["opening_date"]])
    native.book_id, native.owner_principal = created["book"], created["authority"]["principal"]
    native.one(["chart", "import", str(output / "chart.json")])
    for year in range(int(controls[0]["at_date"][:4]), int(controls[-1]["at_date"][:4]) + 1):
        native.one(["period", "create", "--fiscal-year", str(year)])
    custody, documents = [], {}
    for spec in manifest["document_specs"]:
        documents[spec["path"]] = migration.add_document(native, output / spec["path"], spec["kind"], spec["mime"], custody)
    control = {"scope": "Isolated unbound monetary-law control; original source files and printed cells are unchanged",
               "target": TARGET, "source_amount_cents": target["principal_movement_cents"],
               "negative_principal_delta_cents": -100, "negative_counterpart_delta_cents": 100,
               "positive_delta_cents": 0, "source_binding": False}
    live.write_new(output / "native-twin-control.json", live.json_bytes(control))
    documents["native-twin-control.json"] = migration.add_document(
        native, output / "native-twin-control.json", "Workpaper", "application/json", custody)
    run = {"run_key": RUN_KEY, "source_system": manifest["source_system"], "mode": "FullDetail",
           "trial_balance": documents["no-opening-stock.json"], "opening_date": manifest["opening_date"],
           "lines": [], "detail_base": [], "sole_opening_source": True,
           "periods": [{"period": item["period"], "trial_balance": documents["printed-controls.json"],
                        "lines": item["lines"]} for item in controls]}
    live.write_new(output / "native-run.json", live.json_bytes(run))
    run_vid = live.body(native.one(["migrate", "open", "--intent", str(output / "native-run.json")]))["run_vid"]
    accounts = [item["code"] for item in json.loads((output / "chart.json").read_bytes())["accounts"]]
    intent = {"run": "MR:" + run_vid, "source": "D:" + documents["legacy.csv"], "format": "csv", "default_unit": "USD",
              "account_map": {account: account for account in accounts},
              "column_map": (output / "column_map.toml").read_text(),
              "entry_periods": {row["row_id"]: f"FY{row['date'][:4]}-P{row['date'][5:7]}" for row in monetary}}
    live.write_new(output / "native-import.json", live.json_bytes(intent))
    package = live.body(native.one(["migrate", "import", "--action", "prepare", "--intent", str(output / "native-import.json")]))
    identities = migration.check_prepared(package, rows, documents["legacy.csv"])
    live.require("source_binding" in package and package["source_binding"] is None
                 and package.get("source_binding_receipt") is None,
                 "monetary control unexpectedly acquired a source binding")
    target_index = [row["row_id"] for row in monetary].index(TARGET)
    selected = [chunk for chunk in package["chunks"] if chunk["index"] != target_index]
    native.start_bulk()
    receipts = {}
    for start in range(0, len(selected), native.stage_group_size):
        migration.stage_selection(native, selected[start:start + native.stage_group_size], package, run_vid, receipts, documents)
        print(f"Monetary twin: staged {len(receipts)}/370 unchanged original source members", file=sys.stderr, flush=True)
    live.require(len(receipts) == 370 and identities[TARGET] not in receipts, "common prefix contains the mutation target")
    common_members = {vid: {"proposal_digest": value["proposal_digest"], "recorded_at": value["recorded_at"]}
                      for vid, value in receipts.items()}
    prefix = live.body(native.one(["migrate", "show", run_vid]))
    live.require(prefix["state"] == "Open" and prefix["chunk_count"] == 370, "common source prefix changed")
    migration.check_tb(native.one(["tb", "--period", controls[-1]["period"]]), controls[-1], empty=True)
    prefix_head = native.head()
    negative_book, positive_book = native.book, output / "positive-book"
    live.require(native.daemon is None, "cold control copy requires closed embedded CLI processes")
    copied = copy_closed_prefix(negative_book, positive_book)
    live.write_new(output / "common-prefix-files.json", live.json_bytes(copied.pop("manifest")))
    evidence = [documents[name] for name in ("source/source.pdf", "source/rows.csv", "magnify-source/source.pdf",
                                            "magnify-source/rows.csv", "legacy.csv", "native-twin-control.json")]
    positive_intent = chunk_intent(target, run_vid, manifest["source_system"], evidence, 0)
    negative_intent = chunk_intent(target, run_vid, manifest["source_system"], evidence, 100)
    only_amounts = deepcopy(positive_intent)
    for index in range(2):
        only_amounts["legs"][index]["amount"] = negative_intent["legs"][index]["amount"]
    live.require(only_amounts == negative_intent, "twins differ in something other than the balanced dollar")
    results = {}
    for label, book, delta, chunk in (("positive", positive_book, 0, positive_intent),
                                       ("negative", negative_book, 100, negative_intent)):
        native.book = book
        live.require(native.head() == prefix_head, "cold twin did not start at the exact common frontier")
        receipt, entry = stage_manual(native, run_vid, chunk, label)
        live.require(receipt["vid"] not in common_members, "manual target repeated another original source member")
        members = {**common_members, receipt["vid"]: {key: receipt[key] for key in ("proposal_digest", "recorded_at")}}
        mismatches = expected_mismatches(controls, target, delta)
        observed = check_run(native.one(["migrate", "show", run_vid]), run_vid, members, mismatches)
        live.write_new(output / f"{label}-run.json", live.json_bytes(observed))
        migration.check_tb(native.one(["tb", "--period", controls[-1]["period"]]), controls[-1], empty=True)
        before = native.head()
        plan_path = output / f"{label}-finalize.plan"
        result = native.one(["migrate", "finalize", run_vid, "--plan-out", str(plan_path)], expected_exit=3 if delta else 0)
        if delta:
            check_monetary_refusal(result, mismatches)
            live.require(not plan_path.exists(), "refused monetary twin published a finalization plan")
        else:
            planned = live.body(result)
            live.require(planned.get("action") == "finalize" and planned.get("run_vid") == run_vid
                         and planned.get("chunk_count") == 371 and planned.get("tie_out_digest") == observed["tie_out_digest"]
                         and plan_path.is_file(), "unaltered full-population twin did not plan finalization")
        after = native.head()
        live.require(after == before, "finalization planning published history")
        check_run(native.one(["migrate", "show", run_vid]), run_vid, members, mismatches)
        migration.check_tb(native.one(["tb", "--period", controls[-1]["period"]]), controls[-1], empty=True)
        results[label] = {"delta_cents": delta, "chunks": 371, "ties_out": not mismatches,
                          "mismatch_count": len(mismatches), "expected_mismatches": mismatches,
                          "manual_receipt": receipt, "manual_entry": entry,
                          "planner_exit": 3 if delta else 0, "planner_event": result,
                          "frontier_before": before, "frontier_after": after, "state": "Open", "visible_rows": 0}
        print(f"Monetary twin: {label} full 371-member population checked; planner exit {3 if delta else 0}", file=sys.stderr, flush=True)
    live.require(results["positive"]["manual_receipt"]["proposal_digest"] != results["negative"]["manual_receipt"]["proposal_digest"],
                 "the balanced dollar did not change the approved native proposal")
    live.require([leg["account"] for leg in results["positive"]["manual_entry"]["legs"]]
                 == [leg["account"] for leg in results["negative"]["manual_entry"]["legs"]],
                 "the manual twins changed native account identities")
    return {"status": "PASS", "format": "fa-blmis-native-monetary-twin-v1", "scope": manifest["scope"],
            "control_scope": control, "source_binding": False,
            "source_binding_boundary": "Fresh unbound control books only; original bound runs are unchanged. Manual target chunks do not claim retained-package membership.",
            "source_inputs": manifest["source_inputs"], "included_accounts": manifest["included_accounts"],
            "included_observations": 393, "monetary_entries_per_twin": 371, "normalized_source_rows": 742,
            "monthly_printed_controls": 217, "source_target": target, "common_prefix": {**copied, "known_at": prefix_head, "chunks": 370},
            "independent_mismatch_matrix_sha256": matrix_digest,
            "run_vid": run_vid, "original_prepared_target": package["chunks"][target_index],
            "positive": results["positive"], "negative": results["negative"], "documents": custody,
            "review_scope": migration.REVIEW_SCOPE, "native_calls": native.calls, "binaries": native.identities,
            "driver_sha256": ledger.sha256(Path(__file__)), "standalone_verifier_invoked": False,
            "checks": ["fresh_both_pinned_originals", "unchanged_printed_controls", "native_unbound_preparation",
                       "370_original_grouped_approved_chunks", "hash_identical_cold_book_prefix", "same_manual_adapter_both_twins",
                       "371_members_in_each_twin", "unaltered_native_finalize_plan_accepted", "exact_388_monetary_mismatches",
                       "native_monetary_FA_REF_131", "no_finalization_publication", "staged_history_remains_invisible"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pdf", type=Path, help="pinned Glantz original; omitted means fetch")
    parser.add_argument("--magnify-pdf", type=Path, help="pinned Magnify original; omitted means fetch")
    parser.add_argument("--fa", type=Path, default=ROOT / "target/debug/fa")
    parser.add_argument("--fa-verify", type=Path, default=ROOT / "target/debug/fa-verify",
                        help="matching executable identity required by the shared native runner; no verifier call is claimed here")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("timeout must be positive")
    if not all(path.is_file() for path in (args.fa, args.fa_verify)):
        print(json.dumps({"status": "UNRUN", "error": "Matching native executables are missing"}), file=sys.stderr)
        return 4
    output, owned, native = args.out.resolve(), False, None
    started = time.monotonic()
    def created() -> None:
        nonlocal owned
        owned = True
    try:
        rows, manifest = migration.prepare(output, args.pdf, on_created=created,
                                            include_magnify=True, magnify_pdf=args.magnify_pdf)
        native = live.Native(args.fa.resolve(), args.fa_verify.resolve(), output, args.timeout,
                             batch_approvals=True, batch_evidence=True, bind_source=False)
        result = run_native(native, rows, manifest)
        native.check_executables()
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        live.write_new(output / "report.json", live.json_bytes(result))
        print(json.dumps({key: result[key] for key in ("status", "monetary_entries_per_twin", "monthly_printed_controls", "native_calls", "elapsed_seconds")}))
        return 0
    except (source.SourceError, ledger.ReplayError, live.CheckError, OSError, ValueError, KeyError,
            TypeError, csv.Error, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        status = "UNRUN" if isinstance(error, source.EnvironmentError) else "FAIL"
        failure = {"status": status, "error": f"{type(error).__name__}: {error}", "elapsed_seconds": round(time.monotonic() - started, 3)}
        if owned:
            live.write_new(output / "failure.json", live.json_bytes(failure))
        print(json.dumps(failure), file=sys.stderr)
        return 4 if status == "UNRUN" else 1
    finally:
        if native is not None:
            native.stop_bulk()


if __name__ == "__main__":
    raise SystemExit(main())
