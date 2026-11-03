#!/usr/bin/env python3
"""Replay every Magnify account through actual fa and fa-verify binaries.

Every native cent must agree with an independent fold of the printed movement
columns. Published balance gaps, tax-star premises and credited-transfer inputs
remain explicit observations; none becomes a tolerance or balancing entry.
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

import blmis_magnify as source
import blmis_replay as replay
from native_document_readback import readback_document
import public_ledger as ledger


ROOT = Path(__file__).resolve().parents[1]
TAX_PREMISE = f"{source.SOURCE_ID}:1FN037:footnote:4"
OUTWARD_TRANSFER = f"{source.SOURCE_ID}:1FN024:p116:l43"
INWARD_TRANSFER = f"{source.SOURCE_ID}:1FN037:p122:l18"
EXTERNAL_TRANSFER = f"{source.SOURCE_ID}:1FN024:p112:l58"


def label(account: str) -> str:
    return f"blmis-magnify-{account.lower()}-published-principal"


def literal_cents(literal: str) -> int:
    """Decode only numeric printed cells, independently of the source parser."""
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


def reported_cents(literal: str) -> tuple[int, str]:
    ledger.require(isinstance(literal, str), "reported source literal is not text")
    match = re.fullmatch(r"(.+?)(?: (\[[1-4]\]))?", literal)
    ledger.require(match is not None, "source oracle reported annotation is malformed")
    amount, marker = match.groups()
    return literal_cents(amount), marker or ""


def source_observations(rows: list[dict]) -> list[dict]:
    """Fold raw literals in declared order, retaining zero rows and source gaps.

    Transfer columns are the trustee's credited principal, an explicit source
    input. The printed running balance never supplies a posting amount.
    """
    running, seen, observations = dict.fromkeys(source.ACCOUNTS, 0), set(), []
    previous = ("", 0, 0)
    for row in rows:
        row_id, account = row["row_id"], row["account"]
        order = (row["date"], row["pdf_page"], row["source_line"])
        ledger.require(account in source.ACCOUNTS and row_id not in seen
                       and row_id == f"{source.SOURCE_ID}:{account}:p{row['pdf_page']}:l{row['source_line']}"
                       and row["exhibit"] == "B" and order >= previous,
                       "source oracle population has another identity, account or computation order")
        previous = order
        seen.add(row_id)
        star = row["withdrawals_literal"] in ("*", "* [4]")
        reported, marker = reported_cents(row["reported_literal"])
        premises = ([f"{source.SOURCE_ID}:{account}:footnote:{marker[1:-1]}"] if marker else [])
        if star:
            premises.append(TAX_PREMISE)
        ledger.require(type(row["star"]) is bool and row["star"] == star
                       and row["reported_marker"] == marker
                       and row["footnote_premises"] == premises
                       and (not star or (account == "1FN037" and row["withdrawal_marker"] == "[4]"))
                       and (star or row["withdrawal_marker"] == "")
                       and (not marker or marker in source.NOTE_ROLES[account]),
                       "source oracle observation lacks its exact account-scoped footnote premise")
        deposits = literal_cents(row["deposits_literal"])
        withdrawals = 0 if star else literal_cents(row["withdrawals_literal"])
        inward = literal_cents(row["transfers_in_literal"])
        outward = literal_cents(row["transfers_out_literal"])
        printed = literal_cents(row["printed_balance_literal"])
        cash, transfer = deposits + withdrawals, inward + outward
        movement = cash + transfer
        decoded = {"reported_cents": reported, "deposits_cents": deposits, "withdrawals_cents": withdrawals,
                   "transfers_in_cents": inward, "transfers_out_cents": outward,
                   "printed_balance_cents": printed, "cash_movement_cents": cash,
                   "transfer_movement_cents": transfer, "principal_movement_cents": movement}
        ledger.require(all(type(row[key]) is int and row[key] == value for key, value in decoded.items()),
                       f"decoded source amounts differ from independent literals at {row_id}")
        ledger.require(deposits >= 0 and inward >= 0 and outward <= 0,
                       "source oracle principal column direction differs")
        transfer_row = row["description"].startswith("TRANS ") or row_id == source.PARTIAL_DESCRIPTION_ROW
        role = "oracle_output" if transfer_row else "not_applicable"
        ledger.require(row["transfer_credit_role"] == row["transfer_principal_role"] == role,
                       "source transfer credit was relabeled as independently reproduced")
        if transfer_row:
            ledger.require(cash == 0 and not star, "source transfer unexpectedly contains cash or a tax star")
        elif star:
            ledger.require(deposits == movement == transfer == 0 and reported <= 0 and not marker,
                           "starred withholding unexpectedly changes principal")
        else:
            ledger.require(transfer == 0 and not marker and movement == reported,
                           "unstarred cash observation differs from its reported movement")
        running[account] += movement
        ledger.require(abs(running[account]) <= source.I128_MAX, "source principal exceeds the accounting domain")
        observations.append({"source_row_id": row_id, "account": account, "date": row["date"],
                             "principal_movement_cents": movement, "cash_movement_cents": cash,
                             "transfer_movement_cents": transfer, "reported_cents": reported,
                             "star": star, "footnote_premises": premises, "transfer_credit_role": role,
                             "source_principal_cents": running[account], "printed_principal_cents": printed,
                             "source_minus_printed_cents": running[account] - printed})
    ledger.require(bool(observations), "source oracle has no observations")
    return observations


def gap_map(observations: list[dict]) -> dict[str, int]:
    return {row["source_row_id"]: row["source_minus_printed_cents"]
            for row in observations if row["source_minus_printed_cents"]}


def compare_native_observations(data: dict, rows: list[dict], posted: dict[str, dict],
                                observations: list[dict]) -> dict:
    ledger.require(observations == source_observations(rows),
                   "native comparison received an altered source oracle")
    account = rows[0]["account"]
    replay.check_ledger(data, rows, posted, published_gaps=gap_map(observations), label=label(account))
    monetary = [row for row in observations if row["principal_movement_cents"]]
    by_row = {row["source_row_id"]: -replay.usd(line["running_balance"])
              for row, line in zip(monetary, data["lines"], strict=True)}
    previous, comparisons = 0, []
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
    return {"account": account, "observations": comparisons, "source_rows": len(comparisons),
            "native_lines": len(monetary), "zero_principal_observations": len(comparisons) - len(monetary),
            "starred_exclusions": sum(row["star"] for row in comparisons),
            "transfer_oracle_observations": sum(row["transfer_credit_role"] == "oracle_output" for row in comparisons),
            "printed_rows_off": sum(row["native_minus_printed_cents"] != 0 for row in comparisons),
            "maximum_printed_gap_cents": max(abs(row["native_minus_printed_cents"]) for row in comparisons),
            "native_closing_principal_cents": previous,
            "printed_closing_principal_cents": observations[-1]["printed_principal_cents"],
            "closing_gap_cents": comparisons[-1]["native_minus_printed_cents"],
            "native_matches_source_movements_exactly": True,
            "all_printed_balances_equal": all(row["native_minus_printed_cents"] == 0 for row in comparisons)}


def annual_source_controls(observations: list[dict]) -> dict[str, list[dict]]:
    controls = {}
    for account in source.ACCOUNTS:
        selected = [row for row in observations if row["account"] == account]
        ledger.require(bool(selected), "annual controls omitted a published account")
        controls[account] = []
        for year in range(int(selected[0]["date"][:4]), int(selected[-1]["date"][:4]) + 1):
            at_date = f"{year}-12-31"
            last = [row for row in selected if row["date"] <= at_date][-1]
            controls[account].append({"account": account, "at_date": at_date,
                                      "source_row_id": last["source_row_id"], "source_date": last["date"],
                                      "printed_balance_cents": last["printed_principal_cents"],
                                      "source_fold_cents": last["source_principal_cents"],
                                      "source_fold_minus_printed_cents": last["source_minus_printed_cents"]})
    return controls


def cumulative_cells(observations: list[dict], at_date: str) -> dict[str, int]:
    """The complete book through a date, including ended and not-yet-open accounts."""
    cells = {f"BLMIS-{account}": 0 for account in source.ACCOUNTS}
    cells.update({source.CASH_ACCOUNT: 0, source.TRANSFER_ACCOUNT: 0})
    for row in observations:
        if row["date"] <= at_date:
            cells[f"BLMIS-{row['account']}"] -= row["principal_movement_cents"]
            cells[source.CASH_ACCOUNT] += row["cash_movement_cents"]
            cells[source.TRANSFER_ACCOUNT] += row["transfer_movement_cents"]
    ledger.require(sum(cells.values()) == 0, "independent source model is not balanced")
    return cells


def transfer_scope(comparisons: dict[str, dict]) -> dict:
    """Report actual native transfer arithmetic without claiming legal credit reproduction."""
    observations = {row["source_row_id"]: row for account in comparisons.values() for row in account["observations"]}
    transfers = [row for row in observations.values() if row["transfer_credit_role"] == "oracle_output"]
    ledger.require(len(transfers) == 58 and sum(row["principal_movement_cents"] == 0 for row in transfers) == 55,
                   "native transfer observation population differs from the complete source")
    origin, recipient, external = (observations[key] for key in (OUTWARD_TRANSFER, INWARD_TRANSFER, EXTERNAL_TRANSFER))
    before = origin["native_principal_cents"] - origin["principal_movement_cents"]
    credit = recipient["transfer_movement_cents"]
    ledger.require(origin["date"] == recipient["date"] == "1989-03-17"
                   and origin["reported_cents"] == -300_000_000 and recipient["reported_cents"] == 300_000_000
                   and credit == -origin["transfer_movement_cents"] == 281_666_100
                   and before == 281_662_700 and origin["native_principal_cents"] == -3_400
                   and origin["printed_principal_cents"] == 0 and origin["native_minus_printed_cents"] == -3_400,
                   "native transfer-event arithmetic differs from the pinned source limitation")
    ledger.require(external["transfer_movement_cents"] == 68_200,
                   "external-source credited transfer differs from the pinned observation")
    return {"transfer_oracle_observations": len(transfers), "zero_principal_transfer_observations": 55,
            "independent_credit_reproduction": False,
            "paired_source_credit": {"date": origin["date"], "outgoing_row_id": OUTWARD_TRANSFER,
                                     "incoming_row_id": INWARD_TRANSFER, "reported_amount_cents": recipient["reported_cents"],
                                     "source_credited_principal_cents": credit, "native_origin_principal_before_cents": before,
                                     "native_origin_principal_after_cents": origin["native_principal_cents"],
                                     "printed_origin_principal_after_cents": 0,
                                     "native_origin_minus_printed_cents": origin["native_minus_printed_cents"],
                                     "source_credit_minus_native_available_cents": credit - before},
            "external_origin": {"source_row_id": EXTERNAL_TRANSFER, "origin_source_account": "105102",
                                "source_credited_principal_cents": external["transfer_movement_cents"],
                                "origin_history_present": False},
            "scope": "Every credited amount is an oracle input from the trustee's table. Native source-fold agreement does not establish legal transfer credit; the paired credit exceeds the literal-origin principal by $34, and the $682 external origin lacks its ledger."}


def register_parties(native: ledger.Native, output: Path) -> dict:
    receipts = {}
    for account in source.ACCOUNTS:
        code = f"BLMIS-{account}"
        path = output / f"source-account-party-{account}.json"
        ledger.write_json(path, {"code": code, "kind": "Counterparty",
                                "name": f"Magnify Exhibit B account {account} - analysis counterparty"})
        result = native.call("party", "add", path)
        data = result["data"]
        ledger.require(result.get("event") == "rea_recorded" and data["object"] == "party"
                       and data["code"] == code and data["already_recorded"] is False,
                       "native source account party registration differs")
        receipts[code] = data["target"]
    listing = native.call("party", "list")
    parties = listing["data"]["parties"]
    ledger.require(listing.get("event") == "parties" and len(parties) == len(source.ACCOUNTS)
                   and {party["code"] for party in parties} == set(receipts),
                   "native analysis book has another party population")
    identities, values = {}, set()
    for party in parties:
        ledger.require(party["kind"] == "Counterparty" and party["dimension_id"] == 12
                       and party["vid"] == receipts[party["code"]],
                       "native source party differs from its registration receipt")
        for value in (party["vid"], party["dimension_value_vid"]):
            ledger.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None,
                           "native source party has an invalid identity")
        value = party["dimension_value_vid"]
        ledger.require(value not in values and value not in receipts.values(),
                       "native source party dimension is duplicated or replaced by a party VID")
        values.add(value)
        identities[party["code"].removeprefix("BLMIS-")] = {
            "code": party["code"], "vid": party["vid"], "dimension": 12, "value": value}
    return identities


def run_native(binary: Path, verifier: Path, output: Path, pdf: Path | None, *,
               on_created: Callable[[], None] | None = None) -> dict:
    manifest = source.prepare_pdf(output, pdf, on_created=on_created)
    source_rows, metadata = source.load_fixture(output / "extracted-source")
    rows = source.computation_order(source_rows)
    observations = source_observations(rows)
    entries = replay.normalized_entries(output / "legacy.csv", rows, source_id=source.SOURCE_ID)
    ledger.require(len(rows) == manifest["source_rows"] == 2364
                   and manifest["source_accounts"] == len(source.ACCOUNTS) == 6
                   and len(entries) == manifest["monetary_rows"] == 1586
                   and len(entries) * 2 == manifest["normalized_legs"] == 3172
                   and sum(row["star"] for row in observations) == 717,
                   "complete Magnify population differs from its source manifest")
    annual_controls = annual_source_controls(observations)
    ledger.require(json.loads((output / "controls.json").read_text(encoding="utf-8")) == annual_controls,
                   "prepared annual controls differ from independent printed-source observations")
    native = ledger.Native(binary, verifier, output)
    native.call("book", "create", "--name", "Magnify six-account published principal ANALYSIS ONLY",
                "--base-unit", "USD", "--calendar", "monthly")
    native.call("chart", "import", output / "chart.json")
    replay.configure_analysis_roles(native, list(source.ACCOUNTS))
    parties = register_parties(native, output)
    years = range(int(rows[0]["date"][:4]), int(rows[-1]["date"][:4]) + 1)
    for year in years:
        native.call("period", "create", "--fiscal-year", year)
    periods = sorted({f"FY{row['date'][:4]}-P{row['date'][5:7]}" for row in rows if row["principal_movement_cents"]})
    for period in periods:
        native.call("period", "open", period)
    evidence, original_readback = [], None
    for path, kind, mime in ((output / "source.pdf", "Other", "application/pdf"),
                             (output / "rows.csv", "Spreadsheet", "text/csv"),
                             (output / "source.json", "Workpaper", "application/json"),
                             (output / "manifest.json", "Workpaper", "application/json"),
                             (output / "observations.json", "Workpaper", "application/json"),
                             (output / "extracted-source/layout.txt", "Other", "text/plain"),
                             (output / "extraction.json", "Workpaper", "application/json")):
        oid = native.document(path, kind, mime)
        evidence.append(oid)
        if path == output / "source.pdf":
            original_readback = readback_document(native, path, oid, output / "original-readback.pdf")
            ledger.require(original_readback["bytes"] == source.SOURCE_BYTES
                           and original_readback["recovered_sha256"] == source.SOURCE_SHA256,
                           "native original readback differs from the complete pinned Magnify PDF")
    ledger.require(original_readback is not None, "complete original PDF was not read back from native custody")
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
        ledger.require(receipt["recorded_at"] > previous_sequence, "source order lost its native commit")
        previous_sequence = receipt["recorded_at"]
        posted[entry["idempotency_key"]] = receipt
        paths[entry["idempotency_key"]] = path
    certificates, comparisons = {}, {}
    for account, selected in replay.grouped_accounts(rows).items():
        selected_observations = [row for row in observations if row["account"] == account]
        selected_posted = {row["row_id"]: posted[row["row_id"]] for row in selected if row["principal_movement_cents"]}
        certificate = replay.check_certified_ledger(native, selected, selected_posted,
                                                   published_gaps=gap_map(selected_observations), label=label(account),
                                                   retain_report=True)
        comparisons[account] = compare_native_observations(certificate["native_report"], selected,
                                                          selected_posted, selected_observations)
        certificates[account] = certificate
        historical = native.call("gl", "detail", *replay.gl_arguments(selected, label=label(account)),
                                 "--as-known-at", before_posts)["data"]
        replay.check_ledger(historical, selected, selected_posted, empty=True, label=label(account))
    transfers = transfer_scope(comparisons)
    head = native.head()
    for row_id, path in paths.items():
        result = native.call("post", "--intent", path)
        ledger.require(result.get("event") == "recorded", "exact source retry was not recognized")
        ledger.require(all(result["data"][field] == posted[row_id][field]
                           for field in ("vid", "entry_digest", "recorded_at")),
                       "source retry changed its native identity")
    ledger.require(native.head() == head, "exact source retries appended duplicate history")
    native_annual = []
    for year in years:
        at_date = f"{year}-12-31"
        expected = cumulative_cells(observations, at_date)
        ledger.same_cells(native.tb(f"FY{year}-P12"), expected, f"native six-account annual principal at {at_date}")
        native_annual.append({"at_date": at_date, "native_trial_balance_cents": expected,
                              "printed_controls": [control for controls in annual_controls.values()
                                                   for control in controls if control["at_date"] == at_date]})
    principal_analysis = replay.verify_glantz_principal_analysis(native, rows)
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
    exports = [replay.verify_source_export(path, format_name, rows, posted, parties, source_id=source.SOURCE_ID)
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
            "source_rows": len(rows), "source_accounts": len(source.ACCOUNTS),
            "native_entries": len(posted), "native_legs": len(posted) * 2,
            "source_diagnostics": source.verify_rows(source_rows, metadata), "source_comparisons": comparisons,
            "entry_receipts": posted, "ledger_certificates": certificates, "annual_controls": annual_controls,
            "native_annual_controls": native_annual, "source_account_parties": parties,
            "principal_analysis": principal_analysis, "transfer_scope": transfers,
            "document_custody": native.document_custody, "original_document_readback": original_readback,
            "verified_register_periods": periods,
            "export_source_oracles": exports, "independent_verification": verified, "tamper_refusals": tamper_results,
            "commands": native.commands,
            "binaries": {"fa_sha256": ledger.sha256(native.binary), "fa_verify_sha256": ledger.sha256(native.verifier)},
            "driver_sha256": ledger.sha256(Path(__file__)),
            "result_scope": "PASS means exact agreement with independently folded published movements, with every printed discrepancy retained. It does not assert that printed source balances are exact.",
            "principal_scope": "Analysis of the trustee's published principal inputs and explicit withholding-refund exclusion; no dated refund reconstruction or legal net-equity conclusion. All 58 transfer credits remain source oracle inputs.",
            "review_scope": ledger.REVIEW_SCOPE,
            "trust_scope": "Caller-trusted key of a fresh local analysis book; no court or trustee signing-key claim",
            "checks": ["complete_original_pdf_extracted_and_intaken_this_run", "complete_28_9_mb_original_cold_readback",
                       "all_2364_source_observations_and_six_accounts",
                       "independent_decimal_raw_literal_fold", "all_717_tax_stars_have_scoped_footnote_premises",
                       "all_778_zero_principal_observations_compared", "all_1586_entries_and_3172_legs",
                       "every_printed_discrepancy_retained_without_tolerance_or_plug", "six_exact_certified_ledger_replays",
                       "six_immutable_preimport_prefixes", "every_exact_retry_without_new_history",
                       "all_26_annual_cumulative_trial_balances", "native_principal_analysis_with_role_history",
                       "native_transfer_event_34_dollar_gap_retained", "all_posting_month_registers",
                       "native_projections", "unchanged_complete_original_document_custody", "signed_accumulator_checkpoint",
                       "every_exported_leg_text_and_party_dimension_vs_source", "independent_ads_proofs",
                       "one_cent_tamper_rejected", "party_only_tamper_rejected"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="replay every source account using real fa and fa-verify")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--pdf", type=Path, help="verified complete original PDF; otherwise download it")
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
