#!/usr/bin/env python3
"""Run the complete pinned Glantz account through persistent native accounting.

The exhibit supplies transaction components and printed principal controls.
The three-account analysis model is explicit; it is not BLMIS's original chart.
Only the real fa and fa-verify executables can produce a successful run report.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
import csv
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import blmis_source as source
import public_ledger as ledger


ROOT = Path(__file__).resolve().parents[1]
LABEL = "blmis-glantz-1za192-published-principal"
PARTY_CODE = "BLMIS-1ZA192"
PRINCIPAL_RULE = "posted_principal_transfer_v1"
PONZI_PROCEDURE = "ponzi.net_investment"


def usd(value: str) -> int:
    amount, unit = value.rsplit(" ", 1)
    ledger.require(unit == "USD", "native amount has another unit")
    return ledger.source.amount_cents(amount)


def normalized_entries(path: Path, rows: list[dict]) -> list[dict]:
    """Check source-to-intent coverage before any native book is created."""
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        ledger.require(reader.fieldnames == list(source.LEGACY_COLUMNS), "normalized CSV schema differs")
        normalized = list(reader)
    ledger.require(all(set(row) == set(source.LEGACY_COLUMNS)
                       and all(isinstance(value, str) for value in row.values()) for row in normalized),
                   "normalized CSV has a ragged or invalid source record")
    entries = []
    offset = 0
    for row in rows:
        movement = row["principal_movement_cents"]
        if movement == 0:
            continue
        expected = [(source.PRINCIPAL_ACCOUNT, -movement)]
        if row["cash_movement_cents"]:
            expected.append((source.CASH_ACCOUNT, row["cash_movement_cents"]))
        if row["transfer_movement_cents"]:
            expected.append((source.TRANSFER_ACCOUNT, row["transfer_movement_cents"]))
        ledger.require(len(expected) == 2 and sum(amount for _, amount in expected) == 0,
                       f"source row {row['row_id']} does not define one balanced analysis entry")
        legs = []
        for account, amount in expected:
            ledger.require(offset < len(normalized), "normalized CSV dropped a source leg")
            actual = normalized[offset]
            offset += 1
            expected_memo = (f"analysis counterpart; {source.SOURCE_ID} Exhibit B-2 "
                             f"PDF p{row['pdf_page']} line {row['source_line']}")
            ledger.require(actual["entry_id"] == actual["source_row"] == row["row_id"]
                           and actual["effective_date"] == row["date"]
                           and actual["account_code"] == account
                           and ledger.source.amount_cents(actual["signed_amount"]) == amount
                           and actual["description"] == row["description"] and actual["memo"] == expected_memo,
                           f"normalized leg differs from source row {row['row_id']}")
            leg = {"account": account, "side": "debit" if amount > 0 else "credit",
                   "amount": f"{source.money(abs(amount))} USD", "memo": actual["memo"]}
            if account == source.PRINCIPAL_ACCOUNT:
                leg["party"] = PARTY_CODE
            legs.append(leg)
        entries.append({"idempotency_key": row["row_id"], "effective_date": row["date"],
                        "description": row["description"], "legs": legs})
    ledger.require(offset == len(normalized), "normalized CSV added or duplicated source legs")
    ledger.require(len({entry["idempotency_key"] for entry in entries}) == len(entries),
                   "source entries repeat an idempotency key")
    return entries


def register_source_party(native: ledger.Native, output: Path) -> dict:
    """Bind the source account label to actual native party and dimension IDs."""
    path = output / "source-account-party.json"
    ledger.write_json(path, {"code": PARTY_CODE, "kind": "Counterparty",
                            "name": "Glantz Exhibit B-2 account 1ZA192 - analysis counterparty"})
    recorded = native.call("party", "add", path)
    data = recorded["data"]
    ledger.require(recorded.get("event") == "rea_recorded" and data["object"] == "party"
                   and data["code"] == PARTY_CODE and data["already_recorded"] is False,
                   "native source party registration differs")
    listed = native.call("party", "list")
    parties = listed["data"]["parties"]
    ledger.require(listed.get("event") == "parties" and len(parties) == 1,
                   "native analysis book does not contain exactly its source account party")
    party = parties[0]
    ledger.require(party["code"] == PARTY_CODE and party["kind"] == "Counterparty"
                   and party["vid"] == data["target"] and party["dimension_id"] == 12,
                   "native listed party disagrees with its creation receipt")
    for value in (party["vid"], party["dimension_value_vid"]):
        ledger.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None,
                       "native party has an invalid identity")
    ledger.require(party["vid"] != party["dimension_value_vid"],
                   "native party VID was substituted for its dimension value VID")
    return {"code": PARTY_CODE, "vid": party["vid"],
            "dimension": party["dimension_id"], "value": party["dimension_value_vid"]}


def check_principal_analysis(report: dict, rows: list[dict], known_at: int,
                             *, include_transfers: bool) -> dict:
    """Compare the actual v5 finding with source components and printed control.

    Trustee-credited transfer principal remains an explicit input. This checks
    the native calculation under that rule, not an independent legal claim.
    """
    data = report["data"]
    ledger.require(report.get("event") == "procedure_run" and data["procedure"] == PONZI_PROCEDURE
                   and data["version"] == 5 and data["claim"] == "statistical"
                   and data["known_at"] == known_at and data["effective_through"] == rows[-1]["date"],
                   "native principal analysis has another procedure, version or scope")
    cash_in = sum(row["deposits_cents"] for row in rows)
    cash_out = -sum(row["withdrawals_cents"] for row in rows)
    transfer_in = sum(row["transfers_in_cents"] for row in rows) if include_transfers else 0
    transfer_out = -sum(row["transfers_out_cents"] for row in rows) if include_transfers else 0
    principal = cash_in + transfer_in - cash_out - transfer_out
    published = rows[-1]["printed_balance_cents"]
    if include_transfers:
        ledger.require(principal == published, "source components disagree with printed closing principal")
    else:
        ledger.require(principal != published, "missing-transfer-role control lost its source discrepancy")
    ledger.require(principal < 0, "this source account no longer has its published net-winner outcome")
    population = sum(bool(row["cash_movement_cents"]
                          or (include_transfers and row["transfer_movement_cents"])) for row in rows)
    findings = data["findings"]
    ledger.require(data["finding_count"] == len(findings) == 1,
                   "native principal analysis omitted, duplicated or added an investor finding")
    finding = findings[0]
    ledger.require(finding["statistic"] == {
        "name": "fictitious_profit_clawback", "value": -principal, "scale": 2, "population": population,
    }, "native principal analysis differs from source cash and credited transfers")
    expected_narrative = (
        f"investor {PARTY_CODE} (cohort 1, status=net_winner): cash_in={cash_in}, cash_out={cash_out}, "
        f"transfer_in={transfer_in}, transfer_out={transfer_out}, fictitious_profit_clawback={-principal}, "
        f"principal_rule={PRINCIPAL_RULE}, attribution=complete"
    )
    ledger.require(finding["narrative"] == expected_narrative,
                   "native principal analysis changed party attribution, components or principal rule")
    return {"procedure": PONZI_PROCEDURE, "version": 5, "principal_rule": PRINCIPAL_RULE,
            "party": PARTY_CODE, "known_at": known_at, "includes_declared_transfers": include_transfers,
            "cash_in_cents": cash_in, "cash_out_cents": cash_out,
            "transfer_in_cents": transfer_in, "transfer_out_cents": transfer_out,
            "printed_closing_principal_cents": published, "native_principal_cents": principal,
            "net_winner_cents": -principal, "gap_from_printed_principal_cents": principal - published,
            "native_report": report}


def verify_principal_analysis(native: ledger.Native, rows: list[dict]) -> dict:
    """Run real missing-role and complete-role observations across native prefixes."""
    command = ["procedure", "run", PONZI_PROCEDURE, "--effective-through", rows[-1]["date"]]
    before_role = native.head()
    without = native.call(*command, "--as-known-at", before_role)
    missing = check_principal_analysis(without, rows, before_role, include_transfers=False)
    native.call("chart", "role", source.TRANSFER_ACCOUNT, "investor_transfer")
    after_role = native.head()
    ledger.require(after_role > before_role, "declaring principal-transfer semantics did not publish native history")
    complete = check_principal_analysis(native.call(*command, "--as-known-at", after_role),
                                        rows, after_role, include_transfers=True)
    historical = native.call(*command, "--as-known-at", before_role)
    ledger.require(historical == without, "later transfer-role assignment changed the earlier native analysis")
    return {"complete": complete, "without_transfer_role": missing,
            "historical_missing_role_result_unchanged": True,
            "transfer_gap_cents": complete["net_winner_cents"] - missing["net_winner_cents"]}


def verify_source_export(path: Path, format_name: str, rows: list[dict],
                         posted: dict[str, dict], party: dict) -> dict:
    """Match every exported leg, including contra legs, to original source rows."""
    monetary = [row for row in rows if row["principal_movement_cents"]]
    ledger.require(set(posted) == {row["row_id"] for row in monetary}, "export/source receipt coverage differs")
    identities = [posted[row["row_id"]]["vid"] for row in monetary]
    ledger.require(len(set(identities)) == len(identities)
                   and all(re.fullmatch(r"[0-9a-f]{32}", value) is not None for value in identities),
                   "native export receipts have duplicate or invalid entry identities")
    expected = {}
    for row in monetary:
        receipt = posted[row["row_id"]]
        contra = ((source.CASH_ACCOUNT, row["cash_movement_cents"])
                  if row["cash_movement_cents"] else (source.TRANSFER_ACCOUNT, row["transfer_movement_cents"]))
        for ordinal, (account, signed) in enumerate([(source.PRINCIPAL_ACCOUNT, -row["principal_movement_cents"]), contra], 1):
            dimensions = [{"dimension": party["dimension"], "value": party["value"]}] if ordinal == 1 else []
            expected[(receipt["vid"], str(ordinal))] = (row, receipt, account, signed, dimensions)
    seen = set()
    last_ordinal = {}
    for actual in ledger.exported_rows(path, format_name):
        key = (actual["entry_id"], actual["line_no"])
        ledger.require(key in expected and key not in seen, "export substituted, repeated or added a source leg")
        row, receipt, account, signed, dimensions = expected[key]
        last_ordinal[key[0]] = last_ordinal.get(key[0], 0) + 1
        ledger.require(key[1] == str(last_ordinal[key[0]]), "export reordered the principal and counterpart legs")
        ledger.require(ledger.parse_dimension_set(actual["dimension_set_v1"]) == dimensions,
                       f"{format_name} changed party attribution of source row {row['row_id']}")
        ledger.require(actual["effective_date"] == row["date"] and actual["entry_class"] == "1"
                       and actual["recorded_seq"] == str(receipt["recorded_at"])
                       and actual["account_code"] == account and actual["side"] == ("D" if signed > 0 else "C")
                       and actual["amount"] == source.money(abs(signed))
                       and actual["currency"] == "USD" and actual["unit_scale"] == "2",
                       f"{format_name} changed source monetary fields for {row['row_id']}")
        seen.add(key)
    ledger.require(seen == set(expected), "export omitted source principal or counterpart legs")
    return {"format": format_name, "rows": len(seen), "tagged_rows": len(monetary),
            "untagged_rows": len(monetary), "dimension_encoding": ledger.DIMENSION_ENCODING,
            "party": PARTY_CODE}


def check_ledger(data: dict, rows: list[dict], posted: dict[str, dict], *, empty: bool = False) -> None:
    """Match every actual native line to an independently printed source balance.

    The native principal account is credit-normal, whereas the exhibit prints
    remaining principal as positive. Its debit-minus-credit report is therefore
    the negative of the printed balance; this sign convention never changes.
    """
    ledger.require(data["label"] == LABEL and data["effective_from"] == rows[0]["date"]
                   and data["effective_through"] == rows[-1]["date"],
                   "native ledger has another source/date scope")
    ledger.require(type(data["known_at"]) is int and data["known_at"] > 0,
                   "native ledger has an invalid recorded prefix")
    expected = [] if empty else [row for row in rows if row["principal_movement_cents"]]
    if not empty:
        ledger.require(set(posted) == {row["row_id"] for row in expected}, "native receipt/source coverage differs")
    ledger.require(len(data["cells"]) == 1, "native ledger must contain exactly the requested account/unit")
    cell = data["cells"][0]
    ledger.require(cell["account"] == source.PRINCIPAL_ACCOUNT and cell["unit"] == "USD",
                   "native ledger has another account or currency")
    ledger.require(usd(cell["opening"]) == 0, "analysis ledger has an undeclared opening balance")
    ledger.require(cell["line_count"] == len(expected) == len(data["lines"]),
                   "native ledger added, omitted or duplicated source rows")
    debit = sum(-row["principal_movement_cents"] for row in expected if row["principal_movement_cents"] < 0)
    credit = sum(row["principal_movement_cents"] for row in expected if row["principal_movement_cents"] > 0)
    closing = 0 if empty else -rows[-1]["printed_balance_cents"]
    ledger.require(usd(cell["debits"]) == debit and usd(cell["credits"]) == credit,
                   "native gross principal activity differs from source components")
    ledger.require(usd(cell["net_change"]) == usd(cell["closing"]) == closing,
                   "native closing principal differs from the printed control")
    seen = set()
    for line, row in zip(data["lines"], expected, strict=True):
        receipt = posted[row["row_id"]]
        movement = row["principal_movement_cents"]
        identity = (line["entry_digest"], line["leg_index"])
        ledger.require(identity not in seen, "native ledger repeats a source contribution")
        seen.add(identity)
        ledger.require(line["account"] == source.PRINCIPAL_ACCOUNT and line["unit"] == "USD"
                       and line["entry_digest"] == receipt["entry_digest"] and line["leg_index"] == 0
                       and line["recorded_at"] == receipt["recorded_at"]
                       and 0 < line["recorded_at"] <= data["known_at"]
                       and line["effective_date"] == row["date"] and line["class"] == "Original",
                       f"native line identity/date differs from source row {row['row_id']}")
        ledger.require(usd(line["debits"]) == max(-movement, 0)
                       and usd(line["credits"]) == max(movement, 0),
                       f"native gross line differs from source row {row['row_id']}")
        ledger.require(usd(line["running_balance"]) == -row["printed_balance_cents"],
                       f"native running principal differs from printed source row {row['row_id']}")
    if not empty:
        observed = {row["row_id"]: -usd(line["running_balance"])
                    for row, line in zip(expected, data["lines"], strict=True)}
        previous_principal = 0
        for row in rows:
            if row["principal_movement_cents"]:
                previous_principal = observed[row["row_id"]]
            ledger.require(previous_principal == row["printed_balance_cents"],
                           f"native principal differs at source observation {row['row_id']}")


def gl_arguments(rows: list[dict]) -> list[object]:
    return ["--account", source.PRINCIPAL_ACCOUNT, "--unit", "USD", "--from", rows[0]["date"],
            "--to", rows[-1]["date"], "--label", LABEL]


def check_certified_ledger(native: ledger.Native, rows: list[dict], posted: dict[str, dict]) -> dict:
    events, encoded = native.execute_events(native.command("gl", "detail", *gl_arguments(rows), "--certify"))
    ledger.require(len(events) == 2 and events[0].get("event") == "general_ledger"
                   and events[1].get("event") == "report_certificate", "native certified ledger envelope differs")
    report, certificate = events[0], events[1]["data"]
    check_ledger(report["data"], rows, posted)
    ledger.require(certificate["output_format"] == "fa:roll-forward:v1"
                   and report.get("certificate") == certificate["oid"], "native ledger certificate binding differs")
    replay, replay_bytes = native.execute_events(native.command(
        "replay", f"C:{certificate['oid']}", "--view", "detail", *gl_arguments(rows),
        "--as-known-at", report["data"]["known_at"]))
    ledger.require(len(replay) == 1 and replay_bytes == encoded.splitlines(keepends=True)[0],
                   "retained native ledger certificate did not replay exact robot bytes")
    return {"oid": certificate["oid"], "known_at": report["data"]["known_at"],
            "output_digest": certificate["output_digest"], "compared_native_lines": len(posted)}


def run_native(binary: Path, verifier: Path, output: Path, pdf: Path | None, *,
               on_created: Callable[[], None] | None = None) -> dict:
    # PDF acquisition, exact extraction, printed controls and normalization
    # must succeed before the first native command can create a book.
    manifest = source.prepare_pdf(output, pdf, on_created=on_created)
    rows, metadata = source.load_fixture(output / "extracted-source")
    entries = normalized_entries(output / "legacy.csv", rows)
    original_pdf = output / "source.pdf"
    native = ledger.Native(binary, verifier, output)
    native.call("book", "create", "--name", "Glantz 1ZA192 published principal ANALYSIS ONLY",
                "--base-unit", "USD", "--calendar", "monthly")
    native.call("chart", "import", output / "chart.json")
    party = register_source_party(native, output)
    native.call("chart", "role", source.CASH_ACCOUNT, "cash")
    native.call("chart", "role", source.PRINCIPAL_ACCOUNT, "investor_capital")
    years = range(int(rows[0]["date"][:4]), int(rows[-1]["date"][:4]) + 1)
    for year in years:
        native.call("period", "create", "--fiscal-year", year)
    for year, month in sorted({(row["date"][:4], row["date"][5:7]) for row in rows}):
        native.call("period", "open", f"FY{year}-P{month}")
    evidence = []
    for path, kind, mime in ((original_pdf, "Other", "application/pdf"),
                             (output / "extracted-source/layout.txt", "Other", "text/plain;charset=utf-8"),
                             (output / "extraction.json", "Workpaper", "application/json"),
                             (output / "rows.csv", "Spreadsheet", "text/csv"),
                             (output / "source.json", "Workpaper", "application/json"),
                             (output / "manifest.json", "Workpaper", "application/json")):
        oid = native.call("document", "add", path, "--kind", kind, "--mime", mime,
                          "--grade", "AgentUpload")["data"]["oid"]
        # Reviewed by a distinct local test principal. This exercises the real
        # evidence rule without claiming authenticated human examination.
        native.call("document", "attest", "review", "--document", oid,
                    "--as", "blmis-source-reviewer", "--grant", "approve")
        evidence.append(oid)
    before_posts = native.head()
    posted, paths = {}, {}
    previous_sequence = before_posts
    for index, entry in enumerate(entries, 1):
        entry["evidence"] = evidence
        path = output / f"entry-{index:03}.json"
        ledger.write_json(path, entry)
        result = native.call("post", "--intent", path)
        ledger.require(result.get("event") == "posted", "a fresh source row was not posted")
        receipt = result["data"]
        ledger.require(receipt["recorded_at"] > previous_sequence, "source order lost its distinct native commit")
        previous_sequence = receipt["recorded_at"]
        posted[entry["idempotency_key"]] = receipt
        paths[entry["idempotency_key"]] = path
    # Separate publications preserve the exhibit's order even for same-day rows.
    # No source time-of-day or original BLMIS recorded sequence is fabricated.
    certificate = check_certified_ledger(native, rows, posted)
    historical = native.call("gl", "detail", *gl_arguments(rows), "--as-known-at", before_posts)["data"]
    check_ledger(historical, rows, posted, empty=True)
    head = native.head()
    for row_id, path in paths.items():
        retried = native.call("post", "--intent", path)
        ledger.require(retried.get("event") == "recorded", "exact source retry was not recognized")
        for field in ("vid", "entry_digest", "recorded_at"):
            ledger.require(retried["data"][field] == posted[row_id][field],
                           f"source retry changed {field} for {row_id}")
    ledger.require(native.head() == head, "source retries appended duplicate history")
    annual_controls = []
    for control in json.loads((output / "controls.json").read_text(encoding="utf-8")):
        at_date = control["at_date"]
        selected = [row for row in rows if row["date"] <= at_date]
        annual = {source.PRINCIPAL_ACCOUNT: -control["printed_balance_cents"],
                  source.CASH_ACCOUNT: sum(row["cash_movement_cents"] for row in selected),
                  source.TRANSFER_ACCOUNT: sum(row["transfer_movement_cents"] for row in selected)}
        ledger.same_cells(native.tb(f"FY{at_date[:4]}-P12"), annual, f"native year-end control {at_date}")
        annual_controls.append({**control, "native_trial_balance_cents": annual})
    final_period = f"FY{rows[-1]['date'][:4]}-P{rows[-1]['date'][5:7]}"
    expected = {source.PRINCIPAL_ACCOUNT: -rows[-1]["printed_balance_cents"],
                source.CASH_ACCOUNT: sum(row["cash_movement_cents"] for row in rows),
                source.TRANSFER_ACCOUNT: sum(row["transfer_movement_cents"] for row in rows)}
    ledger.same_cells(native.tb(final_period), expected, "native final three-account source reconciliation")
    principal_analysis = verify_principal_analysis(native, rows)
    register_periods = sorted({f"FY{row['date'][:4]}-P{row['date'][5:7]}"
                               for row in rows if row["principal_movement_cents"]})
    for period in register_periods:
        native.call("registers", "advance", "--period", period)
        native.call("verify", "registers", "--period", period)
    native.call("verify", "projections")
    native.call("checkpoint", "create", "--grant", "witness")
    native.call("verify", "accumulator")
    csv_export = output / "gl.csv"
    native.call("export", "csv-gl", "--as-of", rows[-1]["date"], "--out", csv_export)
    native.call("verify", "export", "csv-gl", csv_export)
    exported = native.call("export", "ads", "--as-of", rows[-1]["date"], "--out", output / "ads", "--with-proofs")
    native.call("verify", "export", "ads", output / "ads")
    export_oracles = [verify_source_export(csv_export, "csv-gl", rows, posted, party),
                      verify_source_export(output / "ads/GL_Detail.txt", "ads", rows, posted, party)]
    key = exported["data"]["proof"]["checkpoint_public_key"]
    verified = native.execute([str(native.verifier), "ads", str(output / "ads"), "--key", key, "--json"])
    ledger.require_ads_dimension_proof(verified, manifest["normalized_legs"])
    tampered = output / "ads-tampered"
    shutil.copytree(output / "ads", tampered)
    mutation = ledger.tamper_ads_amount(tampered / "GL_Detail.txt")
    refused = native.execute([str(native.verifier), "ads", str(tampered), "--key", key, "--json"], expect=8)
    dimension_tampered = output / "ads-dimension-tampered"
    shutil.copytree(output / "ads", dimension_tampered)
    dimension_mutation = ledger.tamper_ads_dimension(dimension_tampered / "GL_Detail.txt")
    dimension_refused = native.execute([str(native.verifier), "ads", str(dimension_tampered),
                                       "--key", key, "--json"], expect=8)
    return {"status": "PASS", "scope": source.SCOPE, "source_sha256": source.SOURCE_SHA256,
            "source_extraction": manifest["source_extraction"],
            "source_rows_sha256": source.ROWS_SHA256, "source_rows": len(rows), "native_entries": len(posted),
            "zero_principal_rows": manifest["zero_principal_rows"], "commands": native.commands,
            "source_diagnostics": source.verify_rows(rows, metadata), "ledger_certificate": certificate,
            "entry_receipts": posted, "native_trial_balance_cents": expected,
            "annual_controls": annual_controls,
            "source_account_party": party, "principal_analysis": principal_analysis,
            "export_source_oracles": export_oracles,
            "verified_register_periods": register_periods,
            "independent_verification": verified, "tamper_refusal": refused, "tamper_mutation": mutation,
            "dimension_tamper_refusal": dimension_refused, "dimension_tamper_mutation": dimension_mutation,
            "binaries": {"fa_sha256": ledger.sha256(native.binary), "fa_verify_sha256": ledger.sha256(native.verifier)},
            "driver_sha256": ledger.sha256(Path(__file__)),
            "source_order_policy": "One native publication per monetary source row, preserving same-day exhibit order",
            "principal_sign": "Native debit-minus-credit is the negative of the trustee's printed principal",
            "principal_analysis_scope": "Exact posted principal under posted_principal_transfer_v1; trustee-credited transfer amounts are explicit inputs, not an independent legal net-equity or clawback determination",
            "review_scope": "Distinct local test reviewer exercises AgentUpload evidence admission; no authenticated human review claim",
            "trust_scope": "Caller-trusted key of a fresh local analysis book; no external court or trustee signing-key claim",
            "checks": ["pinned_original_pdf", "original_pdf_extracted_in_this_run",
                       "extracted_rows_match_reviewed_pins", "complete_75_row_source", "every_printed_running_balance",
                       "every_source_footer", "normalized_row_and_leg_coverage", "native_source_order_and_identity",
                       "native_gross_principal_activity", "exact_certified_ledger_replay", "immutable_preimport_prefix",
                       "all_17_printed_year_end_controls", "zero_principal_observation_retained_and_compared",
                       "every_exact_retry_without_new_history", "native_registers_equal_fold", "native_projections",
                       "declared_source_account_party_and_roles", "native_principal_analysis_matches_printed_control",
                       "missing_transfer_role_exposes_source_gap", "historical_missing_role_analysis_unchanged",
                       "every_exported_principal_and_counterpart_leg_matches_source",
                       "signed_accumulator_checkpoint", "independent_ads_verification",
                       "independent_ads_dimension_coverage_on_all_148_legs",
                       "one_cent_tamper_rejected", "party_only_tamper_rejected"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="post and verify the complete account using real native executables")
    run.add_argument("--out", type=Path, required=True, help="new directory; existing evidence is never overwritten")
    run.add_argument("--pdf", type=Path, help="already downloaded pinned original; otherwise fetch it; both paths require pdftotext extraction")
    run.add_argument("--fa", type=Path, default=ROOT / "target/debug/fa")
    run.add_argument("--fa-verify", type=Path, default=ROOT / "target/debug/fa-verify")
    args = parser.parse_args(argv)
    if not args.fa.is_file() or not args.fa_verify.is_file():
        print(json.dumps({"status": "UNRUN", "error": "Build fa and fa-verify first, or pass --fa and --fa-verify"}), file=sys.stderr)
        return 4
    owns_output = False

    def output_created() -> None:
        nonlocal owns_output
        owns_output = True

    started = time.monotonic()
    try:
        report = run_native(args.fa, args.fa_verify, args.out, args.pdf, on_created=output_created)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        ledger.write_json(args.out / "report.json", report)
        print(json.dumps({field: report[field] for field in ("status", "source_rows", "native_entries", "commands", "elapsed_seconds")}))
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
