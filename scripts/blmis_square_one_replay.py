#!/usr/bin/env python3
"""Replay the complete Square One principal history through real native tools.

Published arithmetic differences remain visible in every observation. Native
balances must equal the independently folded source movements exactly; the
source's three-dollar difference is neither a tolerance nor a balancing entry.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
import csv
from decimal import Decimal, localcontext
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import blmis_replay as replay
import blmis_analytics as analytics
import blmis_square_one as source
import public_ledger as ledger


ROOT = Path(__file__).resolve().parents[1]
LABEL = "blmis-square-one-1fr048-published-principal"


def literal_cents(literal: str) -> int:
    """Independent Decimal interpretation of numeric printed cells only."""
    ledger.require(isinstance(literal, str), "source amount literal is not text")
    if literal == "-":
        return 0
    negative = literal.startswith("(") and literal.endswith(")")
    magnitude = literal[1:-1] if negative else literal
    ledger.require(re.fullmatch(r"(?:0|[1-9][0-9]*|[1-9][0-9]{0,2}(?:,[0-9]{3})+)", magnitude) is not None,
                   "source oracle requires an explicit printed whole-dollar amount")
    with localcontext() as context:
        context.prec = 60
        value = int(Decimal(magnitude.replace(",", "")) * Decimal(100))
    ledger.require(value <= source.I128_MAX, "source oracle amount exceeds the accounting domain")
    return -value if negative else value


def source_observations(rows: list[dict]) -> list[dict]:
    """Fold raw columns independently of normalization, keeping every zero row.

    The star is an explicit application of the source's pinned footnote. It is
    not interpreted as a missing cell or as an IRS refund at an invented date.
    """
    running, observations, seen = 0, [], set()
    previous_date = ""
    for row in rows:
        row_id = row["row_id"]
        ledger.require(row_id not in seen and row_id.startswith(f"{source.SOURCE_ID}:{source.ACCOUNT}:")
                       and row["account"] == source.ACCOUNT and row["exhibit"] == "B"
                       and row["date"] >= previous_date,
                       "source oracle population has another identity, account or date order")
        seen.add(row_id)
        previous_date = row["date"]
        star = row["withdrawals_literal"] in ("*", "* [1]")
        ledger.require(type(row["star"]) is bool and row["star"] == star
                       and row["footnote_premises"] == ([source.FOOTNOTE_ID] if star else []),
                       "source oracle withholding exclusion lacks its exact footnote premise")
        deposits = literal_cents(row["deposits_literal"])
        withdrawals = 0 if star else literal_cents(row["withdrawals_literal"])
        reported = literal_cents(row["reported_literal"])
        printed = literal_cents(row["printed_balance_literal"])
        ledger.require(literal_cents(row["transfers_in_literal"]) == 0
                       and literal_cents(row["transfers_out_literal"]) == 0,
                       "source oracle unexpectedly contains credited transfers")
        movement = deposits + withdrawals
        ledger.require(deposits == row["deposits_cents"] and withdrawals == row["withdrawals_cents"]
                       and reported == row["reported_cents"] and printed == row["printed_balance_cents"]
                       and movement == row["cash_movement_cents"] == row["principal_movement_cents"]
                       and row["transfer_movement_cents"] == 0,
                       f"decoded source amounts differ from independent literals at {row_id}")
        if star:
            ledger.require(deposits == movement == 0 and reported <= 0,
                           "starred withholding unexpectedly changes principal")
        else:
            ledger.require(movement == reported, "unstarred source amount differs from cash movement")
        running += movement
        ledger.require(abs(running) <= source.I128_MAX, "source principal exceeds the accounting domain")
        observations.append({"source_row_id": row_id, "date": row["date"],
                             "principal_movement_cents": movement, "star": star,
                             "reported_cents": reported, "source_principal_cents": running,
                             "printed_principal_cents": printed,
                             "source_minus_printed_cents": running - printed})
    ledger.require(bool(observations), "source oracle has no observations")
    return observations


def gap_map(observations: list[dict]) -> dict[str, int]:
    return {row["source_row_id"]: row["source_minus_printed_cents"]
            for row in observations if row["source_minus_printed_cents"]}


def compare_native_observations(data: dict, rows: list[dict], posted: dict[str, dict],
                                observations: list[dict]) -> dict:
    """Check every native cent and report, rather than erase, source gaps."""
    ledger.require(observations == source_observations(rows),
                   "native comparison received an altered source oracle")
    replay.check_ledger(data, rows, posted, published_gaps=gap_map(observations), label=LABEL)
    monetary = [row for row in observations if row["principal_movement_cents"]]
    by_row = {row["source_row_id"]: -replay.usd(line["running_balance"])
              for row, line in zip(monetary, data["lines"], strict=True)}
    previous = 0
    comparisons = []
    for observation in observations:
        row_id = observation["source_row_id"]
        if observation["principal_movement_cents"]:
            previous = by_row[row_id]
        ledger.require(previous == observation["source_principal_cents"],
                       f"native principal differs by one or more cents at {row_id}")
        gap = previous - observation["printed_principal_cents"]
        ledger.require(gap == observation["source_minus_printed_cents"],
                       f"native report changed the published source discrepancy at {row_id}")
        comparisons.append({**observation, "native_principal_cents": previous,
                            "native_minus_printed_cents": gap})
    return {"observations": comparisons, "source_rows": len(comparisons),
            "native_lines": len(monetary),
            "zero_principal_observations": len(comparisons) - len(monetary),
            "starred_exclusions": sum(row["star"] for row in comparisons),
            "printed_rows_off": sum(row["native_minus_printed_cents"] != 0 for row in comparisons),
            "maximum_printed_gap_cents": max(abs(row["native_minus_printed_cents"]) for row in comparisons),
            "native_closing_principal_cents": previous,
            "printed_closing_principal_cents": observations[-1]["printed_principal_cents"],
            "closing_gap_cents": comparisons[-1]["native_minus_printed_cents"],
            "native_matches_source_movements_exactly": True,
            "all_printed_balances_equal": all(row["native_minus_printed_cents"] == 0 for row in comparisons)}


def annual_source_controls(observations: list[dict]) -> list[dict]:
    controls = []
    for year in range(int(observations[0]["date"][:4]), int(observations[-1]["date"][:4]) + 1):
        at_date = f"{year}-12-31"
        prior = [row for row in observations if row["date"] <= at_date]
        ledger.require(bool(prior), "annual source control precedes the published account")
        last = prior[-1]
        controls.append({"at_date": at_date, "source_row_id": last["source_row_id"],
                         "source_date": last["date"],
                         "printed_balance_cents": last["printed_principal_cents"],
                         "source_fold_cents": last["source_principal_cents"],
                         "source_fold_minus_printed_cents": last["source_minus_printed_cents"]})
    return controls


def register_party(native: ledger.Native, output: Path) -> dict:
    path = output / "source-account-party.json"
    ledger.write_json(path, {"code": source.PRINCIPAL_ACCOUNT, "kind": "Counterparty",
                            "name": "Square One Exhibit B account 1FR048 - analysis counterparty"})
    result = native.call("party", "add", path)
    data = result["data"]
    ledger.require(result.get("event") == "rea_recorded" and data["object"] == "party"
                   and data["code"] == source.PRINCIPAL_ACCOUNT and data["already_recorded"] is False,
                   "native source party registration differs")
    listing = native.call("party", "list")
    parties = listing["data"]["parties"]
    ledger.require(listing.get("event") == "parties" and len(parties) == 1,
                   "native principal book has another party population")
    party = parties[0]
    ledger.require(party["code"] == source.PRINCIPAL_ACCOUNT and party["kind"] == "Counterparty"
                   and party["vid"] == data["target"] and party["dimension_id"] == 12,
                   "native source party differs from its creation receipt")
    for value in (party["vid"], party["dimension_value_vid"]):
        ledger.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None,
                       "native source party has an invalid identity")
    ledger.require(party["vid"] != party["dimension_value_vid"], "party VID replaced its dimension value VID")
    return {"code": source.PRINCIPAL_ACCOUNT, "vid": party["vid"],
            "dimension": 12, "value": party["dimension_value_vid"]}


def run_native(binary: Path, verifier: Path, output: Path, pdf: Path | None, *,
               on_created: Callable[[], None] | None = None) -> dict:
    manifest = source.prepare_pdf(output, pdf, on_created=on_created)
    rows, metadata = source.load_fixture(output / "extracted-source")
    observations = source_observations(rows)
    entries = replay.normalized_entries(output / "legacy.csv", rows, source_id=source.SOURCE_ID)
    ledger.require(len(rows) == manifest["source_rows"] == 1050
                   and len(entries) == manifest["monetary_rows"] == 340
                   and len(entries) * 2 == manifest["normalized_legs"] == 680,
                   "complete Square One population differs from its source manifest")
    annual_controls = annual_source_controls(observations)
    ledger.require(json.loads((output / "controls.json").read_text(encoding="utf-8")) == annual_controls,
                   "prepared annual controls differ from independent printed-source observations")
    native = ledger.Native(binary, verifier, output)
    native.call("book", "create", "--name", "Square One 1FR048 published principal ANALYSIS ONLY",
                "--base-unit", "USD", "--calendar", "monthly")
    native.call("chart", "import", output / "chart.json")
    chart = native.call("chart", "list")
    accounts = chart["data"]["accounts"]
    ledger.require(chart.get("event") == "accounts" and len(accounts) == 2
                   and {row["code"]: row["type"] for row in accounts}
                   == {source.PRINCIPAL_ACCOUNT: "Equity", source.CASH_ACCOUNT: "Asset"}
                   and all(row["unit"] == "USD" and row["leaf"] is True for row in accounts),
                   "native chart differs from the declared two-account principal model")
    native.call("chart", "role", source.CASH_ACCOUNT, "cash")
    party = register_party(native, output)
    for year in range(int(rows[0]["date"][:4]), int(rows[-1]["date"][:4]) + 1):
        native.call("period", "create", "--fiscal-year", year)
    periods = sorted({f"FY{row['date'][:4]}-P{row['date'][5:7]}" for row in rows
                      if row["principal_movement_cents"]})
    for period in periods:
        native.call("period", "open", period)
    evidence = []
    for path, kind, mime in ((output / "source.pdf", "Other", "application/pdf"),
                             (output / "rows.csv", "Spreadsheet", "text/csv"),
                             (output / "source.json", "Workpaper", "application/json"),
                             (output / "manifest.json", "Workpaper", "application/json"),
                             (output / "observations.json", "Workpaper", "application/json"),
                             (output / "extracted-source/layout.txt", "Other", "text/plain"),
                             (output / "extraction.json", "Workpaper", "application/json")):
        evidence.append(native.document(path, kind, mime))
    before_posts = native.head()
    posted, paths = {}, {}
    previous_sequence = before_posts
    for index, entry in enumerate(entries, 1):
        entry["evidence"] = evidence
        path = output / f"entry-{index:04}.json"
        ledger.write_json(path, entry)
        result = native.call("post", "--intent", path)
        ledger.require(result.get("event") == "posted", "fresh source monetary row was not posted")
        receipt = result["data"]
        ledger.require(receipt["recorded_at"] > previous_sequence, "same-day source order lost its native commit")
        previous_sequence = receipt["recorded_at"]
        posted[entry["idempotency_key"]] = receipt
        paths[entry["idempotency_key"]] = path
    certificate = replay.check_certified_ledger(native, rows, posted,
                                               published_gaps=gap_map(observations), label=LABEL,
                                               retain_report=True)
    comparison = compare_native_observations(certificate["native_report"], rows, posted, observations)
    historical = native.call("gl", "detail", *replay.gl_arguments(rows, label=LABEL),
                             "--as-known-at", before_posts)["data"]
    replay.check_ledger(historical, rows, posted, empty=True, label=LABEL)
    head = native.head()
    for row_id, path in paths.items():
        result = native.call("post", "--intent", path)
        ledger.require(result.get("event") == "recorded", "exact source retry was not recognized")
        ledger.require(all(result["data"][field] == posted[row_id][field]
                           for field in ("vid", "entry_digest", "recorded_at")),
                       "source retry changed its native identity")
    ledger.require(native.head() == head, "exact source retries appended duplicate history")
    for control in annual_controls:
        principal = control["source_fold_cents"]
        expected = {source.PRINCIPAL_ACCOUNT: -principal, source.CASH_ACCOUNT: principal}
        ledger.same_cells(native.tb(f"FY{control['at_date'][:4]}-P12"), expected,
                          f"native annual principal at {control['at_date']}")
        control["native_trial_balance_cents"] = expected
    known_at = native.head()
    procedure = native.call("procedure", "run", replay.PONZI_PROCEDURE,
                            "--effective-through", rows[-1]["date"], "--known-at", known_at)
    principal_analysis = replay.check_glantz_principal_analysis(procedure, rows, known_at, include_transfers=True)
    record_silent_analytics = analytics.run_native(native, rows, posted)
    for period in periods:
        native.call("registers", "advance", "--period", period)
        native.call("verify", "registers", "--period", period)
    native.call("verify", "projections")
    held = {row["oid"]: row for row in native.call("document", "list")["data"]["documents"]}
    for intake in native.document_custody:
        document = held.get(intake["oid"])
        ledger.require(document is not None and document["grade"] == intake["intake_grade"]
                       and document["doc_commit"] == intake["doc_commit"]
                       and document["recorded_at"] == intake["intake_recorded_at"],
                       "review or posting changed original document custody")
    native.call("checkpoint", "create", "--grant", "witness")
    native.call("verify", "accumulator")
    csv_export = output / "gl.csv"
    native.call("export", "csv-gl", "--as-of", rows[-1]["date"], "--out", csv_export)
    native.call("verify", "export", "csv-gl", csv_export)
    exported = native.call("export", "ads", "--as-of", rows[-1]["date"], "--out", output / "ads", "--with-proofs")
    native.call("verify", "export", "ads", output / "ads")
    exports = [replay.verify_source_export(path, format_name, rows, posted, party, source_id=source.SOURCE_ID)
               for path, format_name in ((csv_export, "csv-gl"), (output / "ads/GL_Detail.txt", "ads"))]
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
    return {"status": "PASS", "scope": source.SCOPE, "source_sha256": source.SOURCE_SHA256,
            "source_rows_sha256": source.ROWS_SHA256, "source_extraction": manifest["source_extraction"],
            "source_rows": len(rows), "native_entries": len(posted), "native_legs": len(posted) * 2,
            "source_diagnostics": source.verify_rows(rows, metadata), "source_comparison": comparison,
            "entry_receipts": posted, "ledger_certificate": certificate, "annual_controls": annual_controls,
            "source_account_party": party, "principal_analysis": principal_analysis,
            "record_silent_analytics": record_silent_analytics,
            "document_custody": native.document_custody, "verified_register_periods": periods,
            "export_source_oracles": exports, "independent_verification": verified, "tamper_refusals": tamper_results,
            "commands": native.commands,
            "binaries": {"fa_sha256": ledger.sha256(native.binary), "fa_verify_sha256": ledger.sha256(native.verifier)},
            "driver_sha256": ledger.sha256(Path(__file__)),
            "result_scope": "PASS means exact agreement with the independently folded published movements, with every printed discrepancy retained; it does not assert that the printed source balances are exact",
            "principal_scope": "Principal-history analysis using the trustee's withholding-refund exclusion as an explicit premise; no reconstruction of gross IRS payments or dated refunds, and no legal net-equity conclusion",
            "review_scope": ledger.REVIEW_SCOPE,
            "trust_scope": "Caller-trusted key of a fresh local analysis book; no court or trustee signing-key claim",
            "checks": ["original_pdf_extracted_this_run", "all_1050_source_observations",
                       "independent_decimal_raw_literal_fold", "all_709_starred_exclusions_have_footnote_premises",
                       "all_710_zero_principal_observations_compared", "all_340_entries_and_680_legs",
                       "every_source_discrepancy_reported_without_tolerance_or_plug", "exact_certified_ledger_replay",
                       "immutable_preimport_prefix", "every_exact_retry_without_new_history",
                       "all_annual_source_controls", "native_principal_analysis", "all_posting_month_registers",
                       "seven_record_silent_source_predicates_and_certified_replays",
                       "native_projections", "unchanged_original_document_custody", "signed_accumulator_checkpoint",
                       "all_exported_legs_text_and_party_dimensions_vs_source", "independent_ads_proofs",
                       "one_cent_tamper_rejected", "party_only_tamper_rejected"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="replay the entire source using real fa and fa-verify")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--pdf", type=Path, help="verified original PDF; otherwise download it")
    run.add_argument("--fa", type=Path, default=ROOT / "target/debug/fa")
    run.add_argument("--fa-verify", type=Path, default=ROOT / "target/debug/fa-verify")
    args = parser.parse_args(argv)
    if not args.fa.is_file() or not args.fa_verify.is_file():
        print(json.dumps({"status": "UNRUN", "error": "Build fa and fa-verify or provide their paths"}), file=sys.stderr)
        return 4
    owns_output = False

    def created() -> None:
        nonlocal owns_output
        owns_output = True

    started = time.monotonic()
    try:
        report = run_native(args.fa, args.fa_verify, args.out, args.pdf, on_created=created)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        ledger.write_json(args.out / "report.json", report)
        print(json.dumps({key: report[key] for key in ("status", "source_rows", "native_entries", "commands", "elapsed_seconds")}))
        return 0
    except (source.SourceError, ledger.ReplayError, OSError, ValueError, KeyError, TypeError,
            csv.Error, subprocess.TimeoutExpired) as error:
        status = "UNRUN" if isinstance(error, source.EnvironmentError) else "FAIL"
        failure = {"status": status, "error": str(error)}
        if owns_output and args.out.is_dir() and not (args.out / "failure.json").exists():
            ledger.write_json(args.out / "failure.json", failure)
        print(json.dumps(failure), file=sys.stderr)
        return 4 if status == "UNRUN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
