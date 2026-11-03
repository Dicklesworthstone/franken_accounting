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
from datetime import date
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
        principal_account = f"BLMIS-{row['account']}"
        expected = [(principal_account, -movement)]
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
            expected_memo = (f"analysis counterpart; {source.SOURCE_ID} Exhibit {row.get('exhibit', 'B-2')} "
                             f"PDF p{row['pdf_page']} line {row['source_line']}")
            ledger.require(actual["entry_id"] == actual["source_row"] == row["row_id"]
                           and actual["effective_date"] == row["date"]
                           and actual["account_code"] == account
                           and ledger.source.amount_cents(actual["signed_amount"]) == amount
                           and actual["description"] == row["description"] and actual["memo"] == expected_memo,
                           f"normalized leg differs from source row {row['row_id']}")
            leg = {"account": account, "side": "debit" if amount > 0 else "credit",
                   "amount": f"{source.money(abs(amount))} USD", "memo": actual["memo"]}
            if account == principal_account:
                leg["party"] = principal_account
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
        identity = party if "code" in party else party[row["account"]]
        principal_account = f"BLMIS-{row['account']}"
        ledger.require(identity["code"] == principal_account and identity["dimension"] == 12,
                       "export source account has another native party binding")
        contra = ((source.CASH_ACCOUNT, row["cash_movement_cents"])
                  if row["cash_movement_cents"] else (source.TRANSFER_ACCOUNT, row["transfer_movement_cents"]))
        for ordinal, (account, signed) in enumerate([(principal_account, -row["principal_movement_cents"]), contra], 1):
            dimensions = [{"dimension": identity["dimension"], "value": identity["value"]}] if ordinal == 1 else []
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
            **({"party": party["code"]} if "code" in party else
               {"parties": sorted(identity["code"] for identity in party.values())})}


def check_ledger(data: dict, rows: list[dict], posted: dict[str, dict], *, empty: bool = False,
                 published_gaps: dict[str, int] | None = None, label: str = LABEL) -> None:
    """Match every actual native line to an independently printed source balance.

    The native principal account is credit-normal, whereas the exhibit prints
    remaining principal as positive. Its debit-minus-credit report is therefore
    the negative of the printed balance; this sign convention never changes.
    """
    account = f"BLMIS-{rows[0]['account']}"
    ledger.require(all(f"BLMIS-{row['account']}" == account for row in rows),
                   "one native account comparator received mixed source accounts")
    gaps = {} if published_gaps is None else published_gaps
    ledger.require(set(gaps) <= {row["row_id"] for row in rows}
                   and all(type(value) is int for value in gaps.values()),
                   "published source gap map has another scope or an invalid amount")
    ledger.require(data["label"] == label and data["effective_from"] == rows[0]["date"]
                   and data["effective_through"] == rows[-1]["date"],
                   "native ledger has another source/date scope")
    ledger.require(type(data["known_at"]) is int and data["known_at"] > 0,
                   "native ledger has an invalid recorded prefix")
    expected = [] if empty else [row for row in rows if row["principal_movement_cents"]]
    if not empty:
        ledger.require(set(posted) == {row["row_id"] for row in expected}, "native receipt/source coverage differs")
    ledger.require(len(data["cells"]) == 1, "native ledger must contain exactly the requested account/unit")
    cell = data["cells"][0]
    ledger.require(cell["account"] == account and cell["unit"] == "USD",
                   "native ledger has another account or currency")
    ledger.require(usd(cell["opening"]) == 0, "analysis ledger has an undeclared opening balance")
    ledger.require(cell["line_count"] == len(expected) == len(data["lines"]),
                   "native ledger added, omitted or duplicated source rows")
    debit = sum(-row["principal_movement_cents"] for row in expected if row["principal_movement_cents"] < 0)
    credit = sum(row["principal_movement_cents"] for row in expected if row["principal_movement_cents"] > 0)
    closing = 0 if empty else -(rows[-1]["printed_balance_cents"] + gaps.get(rows[-1]["row_id"], 0))
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
        ledger.require(line["account"] == account and line["unit"] == "USD"
                       and line["entry_digest"] == receipt["entry_digest"] and line["leg_index"] == 0
                       and line["recorded_at"] == receipt["recorded_at"]
                       and 0 < line["recorded_at"] <= data["known_at"]
                       and line["effective_date"] == row["date"] and line["class"] == "Original",
                       f"native line identity/date differs from source row {row['row_id']}")
        ledger.require(usd(line["debits"]) == max(-movement, 0)
                       and usd(line["credits"]) == max(movement, 0),
                       f"native gross line differs from source row {row['row_id']}")
        ledger.require(usd(line["running_balance"]) == -(row["printed_balance_cents"] + gaps.get(row["row_id"], 0)),
                       f"native running principal differs from printed source row {row['row_id']}")
    if not empty:
        observed = {row["row_id"]: -usd(line["running_balance"])
                    for row, line in zip(expected, data["lines"], strict=True)}
        previous_principal = 0
        for row in rows:
            if row["principal_movement_cents"]:
                previous_principal = observed[row["row_id"]]
            ledger.require(previous_principal == row["printed_balance_cents"] + gaps.get(row["row_id"], 0),
                           f"native principal differs at source observation {row['row_id']}")


def gl_arguments(rows: list[dict], *, label: str = LABEL) -> list[object]:
    return ["--account", f"BLMIS-{rows[0]['account']}", "--unit", "USD", "--from", rows[0]["date"],
            "--to", rows[-1]["date"], "--label", label]


def check_certified_ledger(native: ledger.Native, rows: list[dict], posted: dict[str, dict], *,
                           published_gaps: dict[str, int] | None = None,
                           label: str = LABEL, retain_report: bool = False) -> dict:
    arguments = gl_arguments(rows, label=label)
    events, encoded = native.execute_events(native.command("gl", "detail", *arguments, "--certify"))
    ledger.require(len(events) == 2 and events[0].get("event") == "general_ledger"
                   and events[1].get("event") == "report_certificate", "native certified ledger envelope differs")
    report, certificate = events[0], events[1]["data"]
    check_ledger(report["data"], rows, posted, published_gaps=published_gaps, label=label)
    ledger.require(certificate["output_format"] == "fa:roll-forward:v1"
                   and report.get("certificate") == certificate["oid"], "native ledger certificate binding differs")
    replay, replay_bytes = native.execute_events(native.command(
        "replay", f"C:{certificate['oid']}", "--view", "detail", *arguments,
        "--as-known-at", report["data"]["known_at"]))
    ledger.require(len(replay) == 1 and replay_bytes == encoded.splitlines(keepends=True)[0],
                   "retained native ledger certificate did not replay exact robot bytes")
    return {"oid": certificate["oid"], "known_at": report["data"]["known_at"],
            "output_digest": certificate["output_digest"], "compared_native_lines": len(posted),
            **({"native_report": report["data"]} if retain_report else {})}


def grouped_accounts(rows: list[dict]) -> dict[str, list[dict]]:
    """Keep each account's declared computation order within the full exhibit."""
    accounts: dict[str, list[dict]] = {}
    for row in rows:
        accounts.setdefault(row["account"], []).append(row)
    return accounts


def printed_gaps(rows: list[dict]) -> dict[str, int]:
    """Source-only diagnostic, never a change to a posted monetary amount.

    The caller first verifies the complete pinned extraction. Comparing these
    exact discrepancies with native lines prevents a source rounding/display
    inconsistency from being hidden by an invented balancing transaction.
    """
    running, gaps = 0, {}
    for row in rows:
        running += (row["deposits_cents"] + row["withdrawals_cents"]
                    + row["transfers_in_cents"] + row["transfers_out_cents"])
        difference = running - row["printed_balance_cents"]
        if difference:
            gaps[row["row_id"]] = difference
    return gaps


def register_glantz_parties(native: ledger.Native, output: Path, rows: list[dict]) -> dict:
    """Declare one analysis counterparty for every published source account."""
    accounts = sorted(grouped_accounts(rows))
    receipts = {}
    for account in accounts:
        code = f"BLMIS-{account}"
        path = output / f"source-account-party-{account}.json"
        ledger.write_json(path, {"code": code, "kind": "Counterparty",
                                "name": f"Glantz account {account} - analysis counterparty"})
        recorded = native.call("party", "add", path)
        data = recorded["data"]
        ledger.require(recorded.get("event") == "rea_recorded" and data["object"] == "party"
                       and data["code"] == code and data["already_recorded"] is False,
                       "native source account party registration differs")
        receipts[code] = data["target"]
    listing = native.call("party", "list")
    parties = listing["data"]["parties"]
    ledger.require(listing.get("event") == "parties" and len(parties) == len(accounts)
                   and {party["code"] for party in parties} == set(receipts),
                   "native analysis book does not contain exactly the source account parties")
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
                       "native source party dimension is duplicated or substituted by a party VID")
        values.add(value)
        account = party["code"].removeprefix("BLMIS-")
        identities[account] = {"code": party["code"], "vid": party["vid"], "dimension": 12, "value": value}
    return identities


def check_glantz_principal_analysis(report: dict, rows: list[dict], known_at: int, *,
                                    include_transfers: bool) -> dict:
    """Check the complete native investor population, including zero outcomes.

    Signed reversal rows are actual positive cash movements, so a stop-payment
    is counted in gross cash-in even when the exhibit places it in Withdrawals.
    A zero principal has no native finding; its value is also checked against
    the certified account ledger by the caller.
    """
    data = report["data"]
    through = max(row["date"] for row in rows)
    ledger.require(report.get("event") == "procedure_run" and data["procedure"] == PONZI_PROCEDURE
                   and data["version"] == 5 and data["claim"] == "statistical"
                   and data["known_at"] == known_at and data["effective_through"] == through,
                   "native six-account principal analysis has another method or scope")
    positions = {}
    population = 0
    for account, selected in grouped_accounts(rows).items():
        position = {"cash_in_cents": 0, "cash_out_cents": 0,
                    "transfer_in_cents": 0, "transfer_out_cents": 0, "first_inflow": None}
        for row in selected:
            cash = row["deposits_cents"] + row["withdrawals_cents"]
            transfer = row["transfers_in_cents"] + row["transfers_out_cents"] if include_transfers else 0
            position["cash_in_cents"] += max(cash, 0)
            position["cash_out_cents"] += max(-cash, 0)
            position["transfer_in_cents"] += max(transfer, 0)
            position["transfer_out_cents"] += max(-transfer, 0)
            population += bool(cash or transfer)
            if (cash > 0 or transfer > 0) and position["first_inflow"] is None:
                position["first_inflow"] = row["date"]
        position["printed_closing_principal_cents"] = selected[-1]["printed_balance_cents"]
        positions[account] = position
    inflow_dates = [position["first_inflow"] for position in positions.values() if position["first_inflow"]]
    ledger.require(bool(inflow_dates), "published account population has no funding date")
    first = date.fromisoformat(min(inflow_dates))
    expected = {}
    for account, position in positions.items():
        cash_in, cash_out = position["cash_in_cents"], position["cash_out_cents"]
        transfer_in, transfer_out = position["transfer_in_cents"], position["transfer_out_cents"]
        principal = cash_in + transfer_in - cash_out - transfer_out
        cohort = ((date.fromisoformat(position["first_inflow"]) - first).days // 90 + 1
                  if position["first_inflow"] else 1)
        position.update({"native_principal_cents": principal, "cohort": cohort,
                         "gap_from_printed_principal_cents": principal - position["printed_closing_principal_cents"],
                         "native_finding_expected": principal != 0})
        if principal == 0:
            continue
        name = "fictitious_profit_clawback" if principal < 0 else "net_equity_claim"
        status = "net_winner" if principal < 0 else "net_loser"
        narrative = (f"investor BLMIS-{account} (cohort {cohort}, status={status}): "
                     f"cash_in={cash_in}, cash_out={cash_out}, transfer_in={transfer_in}, transfer_out={transfer_out}, "
                     f"{name}={abs(principal)}, principal_rule={PRINCIPAL_RULE}, attribution=complete")
        expected[narrative] = {"name": name, "value": abs(principal), "scale": 2, "population": population}
    findings = data["findings"]
    ledger.require(data["finding_count"] == len(findings) == len(expected),
                   "native principal analysis omitted, duplicated or added an account outcome")
    seen = set()
    for finding in findings:
        narrative = finding["narrative"]
        ledger.require(narrative in expected and narrative not in seen,
                       "native principal analysis changed an account, cohort or attribution")
        ledger.require(finding["statistic"] == expected[narrative],
                       "native principal analysis changed a source component or population")
        seen.add(narrative)
    return {"procedure": PONZI_PROCEDURE, "version": 5, "principal_rule": PRINCIPAL_RULE,
            "known_at": known_at, "includes_declared_transfers": include_transfers,
            "source_accounts": positions, "population": population, "native_report": report}


def verify_glantz_principal_analysis(native: ledger.Native, rows: list[dict]) -> dict:
    command = ["procedure", "run", PONZI_PROCEDURE, "--effective-through", max(row["date"] for row in rows)]
    before = native.head()
    missing_report = native.call(*command, "--as-known-at", before)
    missing = check_glantz_principal_analysis(missing_report, rows, before, include_transfers=False)
    native.call("chart", "role", source.TRANSFER_ACCOUNT, "investor_transfer")
    after = native.head()
    ledger.require(after > before, "declaring transfer semantics did not publish history")
    complete = check_glantz_principal_analysis(native.call(*command, "--as-known-at", after),
                                              rows, after, include_transfers=True)
    ledger.require(native.call(*command, "--as-known-at", before) == missing_report,
                   "later transfer-role assignment changed the earlier six-account analysis")
    differences = {}
    for account, selected in grouped_accounts(rows).items():
        actual = (complete["source_accounts"][account]["native_principal_cents"]
                  - missing["source_accounts"][account]["native_principal_cents"])
        expected = sum(row["transfers_in_cents"] + row["transfers_out_cents"] for row in selected)
        ledger.require(actual == expected, "declared native transfer effect differs from the source")
        differences[account] = actual
    return {"complete": complete, "without_transfer_role": missing,
            "historical_missing_role_result_unchanged": True, "declared_transfer_effect_cents": differences}


def check_transfer_pairs(rows: list[dict], reports: dict[str, dict], posted: dict[str, dict]) -> list[dict]:
    """Recompute the two in-complaint credits from certified originating balances.

    This explicit interpretive rule is min(statement transfer, max(principal,
    0)). Other transfer credits stay unverified source inputs; descriptions are
    not used to invent missing counterpart histories or transfer matches.
    """
    pairs = (("1993-10-20", "1ZA192", "1ZB143", 400_000_000),
             ("2005-12-23", "1ZB143", "1ZA192", 0))
    accounts = grouped_accounts(rows)
    results = []
    for at_date, origin, recipient, expected_credit in pairs:
        outgoing = [row for row in accounts[origin] if row["date"] == at_date
                    and re.fullmatch(rf"TRANS TO [A-Z0-9]+ \({re.escape(recipient)}\)", row["description"])]
        incoming = [row for row in accounts[recipient] if row["date"] == at_date
                    and re.fullmatch(rf"TRANS FROM [A-Z0-9]+ \({re.escape(origin)}\)", row["description"])]
        ledger.require(len(outgoing) == len(incoming) == 1, "declared transfer pair is missing or ambiguous")
        debit, credit = outgoing[0], incoming[0]
        ledger.require(debit["reported_cents"] < 0 and credit["reported_cents"] == -debit["reported_cents"],
                       "paired source statement amounts do not agree")
        report = reports[origin]["native_report"]
        account_label = f"blmis-glantz-{origin.lower()}-published-principal"
        selected_receipts = {row["row_id"]: posted[row["row_id"]] for row in accounts[origin]
                             if row["principal_movement_cents"]}
        check_ledger(report, accounts[origin], selected_receipts,
                     published_gaps=printed_gaps(accounts[origin]), label=account_label)
        earlier = accounts[origin][:accounts[origin].index(debit)]
        earlier_money = [row for row in earlier if row["principal_movement_cents"]]
        principal_before = 0
        basis = None
        if earlier_money:
            basis = earlier_money[-1]["row_id"]
            receipt = posted[basis]
            matching = [line for line in report["lines"] if line["entry_digest"] == receipt["entry_digest"]]
            ledger.require(len(matching) == 1, "certified originating principal lacks its source basis")
            principal_before = -usd(matching[0]["running_balance"])
        recomputed = min(credit["reported_cents"], max(principal_before, 0))
        ledger.require(recomputed == expected_credit == credit["transfers_in_cents"] == -debit["transfers_out_cents"],
                       "certified originating balance does not reproduce the declared transfer credit")
        results.append({"date": at_date, "origin": origin, "recipient": recipient,
                        "outgoing_row_id": debit["row_id"], "incoming_row_id": credit["row_id"],
                        "rule": "trustee_transfer_credit", "statement_amount_cents": credit["reported_cents"],
                        "originating_principal_cents": principal_before, "credited_principal_cents": recomputed,
                        "native_originating_balance_row_id": basis,
                        "originating_certificate": reports[origin]["oid"]})
    return results


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


def run_glantz_native(binary: Path, verifier: Path, output: Path, pdf: Path | None, *,
                      on_created: Callable[[], None] | None = None) -> dict:
    """Replay all six published accounts without repairing inconsistent source cells."""
    manifest = source.prepare_glantz(output, pdf=pdf, on_created=on_created)
    original_rows, metadata = source.load_glantz_fixture(output)
    original_pdf = output / "source.pdf"
    rows = source.glantz_computation_order(original_rows)
    accounts = grouped_accounts(rows)
    entries = normalized_entries(output / "legacy.csv", rows)
    ledger.require(len(entries) == manifest["monetary_rows"]
                   and len(entries) * 2 == manifest["normalized_legs"],
                   "complete Glantz normalized population differs from its manifest")
    source.verify_pdf(original_pdf)
    native = ledger.Native(binary, verifier, output)
    native.call("book", "create", "--name", "Glantz six published accounts ANALYSIS ONLY",
                "--base-unit", "USD", "--calendar", "monthly")
    native.call("chart", "import", output / "chart.json")
    parties = register_glantz_parties(native, output, rows)
    native.call("chart", "role", source.CASH_ACCOUNT, "cash")
    for account in accounts:
        native.call("chart", "role", f"BLMIS-{account}", "investor_capital")
    first_date = min(row["date"] for row in rows)
    last_date = max(row["date"] for row in rows)
    for year in range(int(first_date[:4]), int(last_date[:4]) + 1):
        native.call("period", "create", "--fiscal-year", year)
    for year, month in sorted({(row["date"][:4], row["date"][5:7]) for row in rows}):
        native.call("period", "open", f"FY{year}-P{month}")
    evidence = []
    for path, kind, mime in ((original_pdf, "Other", "application/pdf"),
                             (output / "rows.csv", "Spreadsheet", "text/csv"),
                             (output / "source.json", "Workpaper", "application/json"),
                             (output / "manifest.json", "Workpaper", "application/json"),
                             (output / "extracted-source/layout.txt", "Other", "text/plain"),
                             (output / "extraction.json", "Workpaper", "application/json")):
        evidence.append(native.document(path, kind, mime))
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
    certificates, comparisons = {}, {}
    for account, selected in accounts.items():
        label = f"blmis-glantz-{account.lower()}-published-principal"
        receipts = {row["row_id"]: posted[row["row_id"]] for row in selected if row["principal_movement_cents"]}
        gaps = printed_gaps(selected)
        certificates[account] = check_certified_ledger(native, selected, receipts,
                                                      published_gaps=gaps, label=label, retain_report=True)
        historical = native.call("gl", "detail", *gl_arguments(selected, label=label),
                                 "--as-known-at", before_posts)["data"]
        check_ledger(historical, selected, receipts, empty=True, label=label)
        comparisons[account] = {"source_rows": len(selected), "native_lines": len(receipts),
                                "printed_balances_equal": not gaps, "printed_row_gaps_cents": gaps,
                                "printed_closing_principal_cents": selected[-1]["printed_balance_cents"],
                                "native_closing_principal_cents": -usd(
                                    certificates[account]["native_report"]["cells"][0]["closing"])}
    transfer_pairs = check_transfer_pairs(rows, certificates, posted)
    head = native.head()
    for row_id, path in paths.items():
        retried = native.call("post", "--intent", path)
        ledger.require(retried.get("event") == "recorded", "exact source retry was not recognized")
        for field in ("vid", "entry_digest", "recorded_at"):
            ledger.require(retried["data"][field] == posted[row_id][field],
                           f"source retry changed {field} for {row_id}")
    ledger.require(native.head() == head, "source retries appended duplicate history")
    annual_controls = []
    for year in range(int(first_date[:4]), int(last_date[:4]) + 1):
        at_date = f"{year}-12-31"
        selected = [row for row in rows if row["date"] <= at_date]
        expected = {source.CASH_ACCOUNT: sum(row["cash_movement_cents"] for row in selected),
                    source.TRANSFER_ACCOUNT: sum(row["transfer_movement_cents"] for row in selected)}
        controls = {}
        for account, history in accounts.items():
            prior = [row for row in history if row["date"] <= at_date]
            principal = sum(row["deposits_cents"] + row["withdrawals_cents"]
                            + row["transfers_in_cents"] + row["transfers_out_cents"] for row in prior)
            expected[f"BLMIS-{account}"] = -principal
            controls[account] = {"row_id": prior[-1]["row_id"] if prior else None,
                                 "printed_principal_cents": prior[-1]["printed_balance_cents"] if prior else 0,
                                 "source_movement_principal_cents": principal,
                                 "gap_cents": principal - prior[-1]["printed_balance_cents"] if prior else 0}
        ledger.same_cells(native.tb(f"FY{year}-P12"), expected, f"native all-account source control {at_date}")
        annual_controls.append({"at_date": at_date, "accounts": controls, "native_trial_balance_cents": expected})
    principal_analysis = verify_glantz_principal_analysis(native, rows)
    register_periods = sorted({f"FY{row['date'][:4]}-P{row['date'][5:7]}"
                               for row in rows if row["principal_movement_cents"]})
    for period in register_periods:
        native.call("registers", "advance", "--period", period)
        native.call("verify", "registers", "--period", period)
    native.call("verify", "projections")
    held = {row["oid"]: row for row in native.call("document", "list")["data"]["documents"]}
    for intake in native.document_custody:
        current = held.get(intake["oid"])
        ledger.require(current is not None and current["grade"] == intake["intake_grade"]
                       and current["doc_commit"] == intake["doc_commit"]
                       and current["recorded_at"] == intake["intake_recorded_at"],
                       "review or posting changed the original source document custody")
    native.call("checkpoint", "create", "--grant", "witness")
    native.call("verify", "accumulator")
    csv_export = output / "gl.csv"
    native.call("export", "csv-gl", "--as-of", last_date, "--out", csv_export)
    native.call("verify", "export", "csv-gl", csv_export)
    exported = native.call("export", "ads", "--as-of", last_date, "--out", output / "ads", "--with-proofs")
    native.call("verify", "export", "ads", output / "ads")
    export_oracles = [verify_source_export(csv_export, "csv-gl", rows, posted, parties),
                      verify_source_export(output / "ads/GL_Detail.txt", "ads", rows, posted, parties)]
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
    return {"status": "PASS", "scope": manifest["scope"], "source_sha256": source.SOURCE_SHA256,
            "source_rows_sha256": manifest["source_rows_sha256"], "source_rows": len(rows),
            "source_extraction": manifest["source_extraction"],
            "native_entries": len(posted), "native_legs": manifest["normalized_legs"],
            "source_accounts": sorted(accounts), "zero_principal_rows": manifest["zero_principal_rows"],
            "source_diagnostics": source.glantz_diagnostics(original_rows, metadata),
            "source_comparisons": comparisons, "ledger_certificates": certificates,
            "entry_receipts": posted, "annual_controls": annual_controls,
            "source_account_parties": parties, "principal_analysis": principal_analysis,
            "document_custody": native.document_custody,
            "recomputed_transfer_pairs": transfer_pairs,
            "unpaired_transfer_credit_scope": "The other 13 transfer rows retain trustee-credited principal as explicit inputs",
            "export_source_oracles": export_oracles, "verified_register_periods": register_periods,
            "independent_verification": verified, "tamper_refusals": tamper_results,
            "commands": native.commands,
            "binaries": {"fa_sha256": ledger.sha256(native.binary), "fa_verify_sha256": ledger.sha256(native.verifier)},
            "driver_sha256": ledger.sha256(Path(__file__)),
            "result_scope": "PASS means the native book matches every published movement and exactly reproduces the diagnosed source discrepancies; it does not assert all printed balances are arithmetically exact",
            "source_order_policy": "Source display order with the explicitly pinned same_day_display_reorder for the 1ZB010 check/stop-payment pair; one native publication per monetary row",
            "principal_sign": "Native debit-minus-credit is negative remaining principal; no source discrepancy is plugged",
            "principal_analysis_scope": "posted_principal_transfer_v1 with trustee-credited transfers as explicit inputs; the two paired credits separately recompute under trustee_transfer_credit",
            "review_scope": "Distinct local test reviewer exercises AgentUpload evidence admission; no authenticated human review claim",
            "trust_scope": "Caller-trusted key of a fresh local analysis book; no external court or trustee signing-key claim",
            "checks": ["pinned_original_pdf", "native_source_intake_and_custody_receipts", "complete_six_account_379_row_population",
                       "all_372_monetary_entries_and_744_legs", "all_seven_zero_principal_observations_retained",
                       "every_native_running_balance_vs_source_and_explicit_gap", "named_same_day_display_reorder",
                       "both_transfer_credits_from_certified_originating_principal", "exact_certified_ledger_replay",
                       "immutable_preimport_prefix", "every_annual_all_account_control",
                       "every_exact_retry_without_new_history", "native_registers_equal_fold", "native_projections",
                       "all_six_native_party_bindings", "all_six_native_principal_outcomes",
                       "missing_transfer_role_control_for_all_accounts", "historical_missing_role_result_unchanged",
                       "all_exported_money_and_party_dimensions_vs_original_source",
                       "signed_accumulator_checkpoint", "independent_ads_verification_and_dimension_coverage",
                       "one_cent_tamper_rejected", "party_only_tamper_rejected"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="post and verify the complete account using real native executables")
    run.add_argument("--out", type=Path, required=True, help="new directory; existing evidence is never overwritten")
    run.add_argument("--pdf", type=Path, help="already downloaded pinned original; otherwise fetch it; both paths require pdftotext extraction")
    run.add_argument("--account", choices=("1ZA192", "all"), default="1ZA192",
                     help="all replays all six published accounts and reports their source discrepancies explicitly")
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
        driver = run_glantz_native if args.account == "all" else run_native
        report = driver(args.fa, args.fa_verify, args.out, args.pdf, on_created=output_created)
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
