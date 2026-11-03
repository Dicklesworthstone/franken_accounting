#!/usr/bin/env python3
"""Check record-silent forensic observations against published BLMIS inputs.

This is an independent exact-integer predicate model for the declared analysis
books, not a fraud classifier. The input is the complete extracted source, not
the native findings. Receipt identities bind source rows to native citations;
they do not supply amounts, dates, expected findings or thresholds.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from fractions import Fraction
import json
from pathlib import Path
import re

import blmis_source as source
import public_ledger as ledger


PROCEDURES = {
    "jet.round_amounts": (1, {"round_power": 3}),
    "jet.weekend": (1, {}),
    "duplicates.same_same_same": (1, {}),
    "duplicates.same_same_different": (1, {"window_days": 30}),
    "numbers.relative_size_factor": (1, {"min_rsf_bps": 50000, "min_subset_size": 3}),
    "numbers.round_amount_density": (1, {"round_power": 2, "min_legs": 20, "z_squared": 9}),
    "benford.first_digit": (2, {
        "min_population": 500, "mad_close": 6, "mad_acceptable": 12,
        "mad_marginal": 15, "currency_iso4217": 840, "side": 0, "account_type": 0,
    }),
}
# The published first-digit table at the native contract's nine-place scale.
# Its rounded last cell is reduced by one so the probabilities sum to 10^9.
# This is a pinned comparison law, not a separately estimated distribution.
BENFORD_1E9 = (301029996, 176091259, 124938737, 96910013, 79181246,
               66946790, 57991947, 51152522, 45757490)
MAX_CITES = 4096
SCOPE = (
    "Record-silent observations on the complete published account-table population "
    "in this run, under the declared principal/cash/transfer analysis mapping. "
    "The litigation selected these accounts; they are not a representative sample "
    "of BLMIS. Counts are technical predicates, not fraud findings, false-positive "
    "rates, audit assurance or a legal determination. Ordinary recurring payments "
    "can satisfy the duplicate and round-number predicates. Trustee transfer credits "
    "and withholding exclusions remain explicit source premises."
)


def literal_cents(literal: str, row: dict, field: str) -> int:
    """Decode original whole-dollar cells without using the adapter's amounts."""
    text = re.sub(r"(?:\s*\[\d+\])+$", "", literal).strip()
    if text == "*":
        ledger.require(field == "withdrawals" and row.get("star") is True
                       and row.get("principal_rule") == "withholding_refund_exclusion"
                       and bool(row.get("footnote_premises")),
                       "analytics source star lacks its explicit withholding premise")
        return 0
    if text == "-":
        return 0
    negative = text.startswith("(") and text.endswith(")")
    digits = text[1:-1] if negative else text
    ledger.require(re.fullmatch(r"(?:[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)", digits) is not None,
                   "analytics source amount is not a published whole-dollar literal")
    return int(digits.replace(",", "")) * (-100 if negative else 100)


def source_entries(rows: list[dict], posted: dict[str, dict]) -> list[dict]:
    """Rebuild the explicit two-leg model directly from dated source cells."""
    entries, seen = [], set()
    for row in rows:
        row_id = row["row_id"]
        ledger.require(row_id not in seen, "analytics source repeats an observation")
        seen.add(row_id)
        month, day, year = map(int, row["date_literal"].split("/"))
        effective = date(year, month, day)
        ledger.require(effective.isoformat() == row["date"], "analytics source date changed")
        values = {field: literal_cents(row[f"{field}_literal"], row, field)
                  for field in ("deposits", "withdrawals", "transfers_in", "transfers_out")}
        cash = values["deposits"] + values["withdrawals"]
        transfer = values["transfers_in"] + values["transfers_out"]
        movement = cash + transfer
        ledger.require((cash, transfer, movement) == (row["cash_movement_cents"],
                       row["transfer_movement_cents"], row["principal_movement_cents"]),
                       f"analytics source movement disagrees with original literals: {row_id}")
        if not movement:
            ledger.require(row_id not in posted, "a zero-principal observation became a native posting")
            continue
        ledger.require(bool(cash) != bool(transfer), "analytics source does not define one counterpart")
        receipt = posted.get(row_id)
        ledger.require(isinstance(receipt, dict)
                       and re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("vid"))) is not None
                       and type(receipt.get("recorded_at")) is int and receipt["recorded_at"] > 0,
                       "analytics source has no valid native posting receipt")
        principal = f"BLMIS-{row['account']}"
        entries.append({
            "row_id": row_id, "date": effective.isoformat(), "day": effective.toordinal(),
            "weekday": effective.isoweekday(), "vid": receipt["vid"],
            "recorded_at": receipt["recorded_at"],
            "legs": [(principal, -movement, principal),
                     (source.CASH_ACCOUNT if cash else source.TRANSFER_ACCOUNT, movement, None)],
        })
    ledger.require(bool(entries) and set(posted) == {entry["row_id"] for entry in entries},
                   "analytics source-to-posting coverage is incomplete or contains extra entries")
    ledger.require(len({entry["vid"] for entry in entries}) == len(entries)
                   and len({entry["recorded_at"] for entry in entries}) == len(entries),
                   "analytics source receipts repeat a native identity or publication")
    return entries


def cite(entry: dict, ordinal: int | None = None) -> dict:
    return {"kind": "entry" if ordinal is None else "leg", "source_row": entry["row_id"],
            **({"ordinal": ordinal} if ordinal is not None else {})}


def finding(severity: str, name: str, value: int, population: int, cites: list[dict],
            narrative: str, scale: int = 0) -> dict:
    return {"severity": severity, "statistic": {"name": name, "value": value,
            "scale": scale, "population": population}, "cites": cites, "narrative": narrative}


def expected_findings(entries: list[dict]) -> dict[str, list[dict]]:
    """Evaluate seven declared predicates without consulting a native report."""
    expected = {name: [] for name in PROCEDURES}
    count = len(entries)
    same_day, same_legs, debit_groups, account_legs = (defaultdict(list) for _ in range(4))
    first_digits = [0] * 9
    for entry in entries:
        legs = entry["legs"]
        round_legs = [ordinal for ordinal, (_, amount, _) in enumerate(legs)
                      if abs(amount) % 100000 == 0]
        if round_legs:
            expected["jet.round_amounts"].append(finding(
                "Medium" if len(round_legs) == len(legs) else "Low", "round_legs", len(round_legs),
                2 * count, [cite(entry)] + [cite(entry, ordinal) for ordinal in round_legs],
                f"{len(round_legs)} of {len(legs)} legs are whole multiples of 10^3 units"))
        if entry["weekday"] in (6, 7):
            expected["jet.weekend"].append(finding(
                "Low", "iso_weekday", entry["weekday"], count, [cite(entry)],
                f"dated on ISO weekday {entry['weekday']} (6 = Saturday, 7 = Sunday)"))
        signature = tuple(sorted((account, signed) for account, signed, _ in legs))
        same_day[(signature, entry["day"])].append(entry)
        same_legs[signature].append(entry)
        for ordinal, (account, signed, party) in enumerate(legs):
            account_legs[account].append((entry, ordinal, abs(signed)))
            if signed > 0:
                debit_groups[("party", party) if party else ("account", account)].append((signed, entry))
                if signed >= 100:
                    first_digits[int(str(signed)[0]) - 1] += 1
    for group in same_day.values():
        if len(group) >= 2:
            ordered = sorted(group, key=lambda entry: entry["vid"])
            suffix = f" (the first {MAX_CITES} by entry id cited)" if len(group) > MAX_CITES else ""
            expected["duplicates.same_same_same"].append(finding(
                "Medium", "entries", len(group), count, [cite(entry) for entry in ordered[:MAX_CITES]],
                f"{len(group)} entries share the same legs and effective date{suffix}"))
    for group in same_legs.values():
        ordered = sorted(group, key=lambda entry: (entry["day"], entry["recorded_at"], entry["vid"]))
        # Each occurrence is compared with the earliest recorded occurrence on
        # the next distinct date, not all pairs in the thirty-day window.
        by_day = defaultdict(list)
        for entry in ordered:
            by_day[entry["day"]].append(entry)
        days = sorted(by_day)
        for first, second in zip(days, days[1:]):
            apart = second - first
            if apart <= 30:
                for entry in by_day[first]:
                    expected["duplicates.same_same_different"].append(finding(
                        "Low", "days_apart", apart, count, [cite(entry), cite(by_day[second][0])],
                        f"two entries share the same legs {apart} day(s) apart (window 30)"))
    for (kind, identity), group in debit_groups.items():
        if len(group) < 3:
            continue
        ordered = sorted(group, key=lambda item: (-item[0], item[1]["vid"]))
        (largest, first), (second, following) = ordered[:2]
        ratio = largest * 10000 // second
        if ratio >= 50000:
            citations = [cite(first), cite(following)]
            if kind == "account":
                citations.append({"kind": "account", "account": identity})
            expected["numbers.relative_size_factor"].append(finding(
                "High" if ratio >= 100000 else "Medium", "rsf_bps", ratio, count, citations,
                f"largest debit {largest} vs second-largest {second} across {len(group)} postings "
                f"yields RSF {ratio} bps (min_rsf_bps 50000)"))
    total = 2 * count
    round_total = sum(amount % 10000 == 0 for group in account_legs.values() for _, _, amount in group)
    for account, group in account_legs.items():
        n = len(group)
        rounded = sorted((item for item in group if item[2] % 10000 == 0),
                         key=lambda item: (item[0]["recorded_at"], item[0]["vid"], item[1]))
        x = len(rounded)
        excess = x * total - n * round_total
        if n < 20 or not 0 < round_total < total or excess <= 0:
            continue
        threshold = 9 * n * round_total * (total - round_total)
        squared = excess * excess
        if squared >= threshold:
            citations = [{"kind": "account", "account": account}]
            citations.extend(cite(entry, ordinal) for entry, ordinal, _ in rounded[:MAX_CITES - 1])
            expected["numbers.round_amount_density"].append(finding(
                "High" if squared >= 4 * threshold else "Medium", "round_legs", x, n, citations,
                f"{x} of {n} legs on this account are whole multiples of 10^2 units, "
                f"against {round_total} of {total} across the book (z^2 >= 9)"))
    expected["benford.first_digit"] = [benford_finding(first_digits)]
    return expected


def benford_finding(counts: list[int]) -> dict:
    """Use exact rationals, quantizing only at the declared statistic scale."""
    population = sum(counts)
    if population < 500:
        return finding("Info", "population", population, population, [],
                       f"population {population} is below the registered minimum 500; no conformity is claimed")
    expected = [Fraction(value, 10**9) for value in BENFORD_1E9]
    deviations = [Fraction(observed, population) - probability
                  for observed, probability in zip(counts, expected, strict=True)]
    mad = int(sum(abs(value) for value in deviations) * 10**9 / 9)
    cumulative = Fraction(0)
    distances = []
    for value in deviations:
        cumulative += value
        distances.append(abs(cumulative))
    ks = int(max(distances) * 10**9)
    chi = sum(int(Fraction(population) * difference**2 / probability * 10**6)
              for difference, probability in zip(deviations, expected, strict=True))
    severity = "Info" if mad <= 6000000 else "Low" if mad <= 12000000 else "Medium" if mad <= 15000000 else "High"
    return finding(severity, "mad", mad, population, [],
                   f"first-digit counts {counts} over {population} legs; MAD {mad}e-9 "
                   "(close ≤ 6000000e-9, acceptable ≤ 12000000e-9, marginal ≤ 15000000e-9); "
                   f"chi-square {chi}e-6 with 8 degrees of freedom, KS {ks}e-9", scale=9)


def source_finding(value: dict, entries: list[dict], account_ids: dict[str, str]) -> dict:
    """Resolve every native citation, rejecting unrelated or malformed handles."""
    by_vid = {entry["vid"]: entry for entry in entries}
    by_account = {identity: account for account, identity in account_ids.items()}
    result = {key: value[key] for key in ("severity", "statistic", "narrative")}
    citations = []
    fields = {"kind", "entry", "ordinal", "account", "period", "document", "principal", "approval", "attestation"}
    for native in value["cites"]:
        ledger.require(set(native) == fields, "analytics citation schema differs")
        kind = native["kind"]
        used = {"kind", "entry"} | ({"ordinal"} if kind == "leg" else set())
        if kind == "account":
            used = {"kind", "account"}
            ledger.require(native["account"] in by_account, "analytics cited an account outside the source model")
            resolved = {"kind": kind, "account": by_account[native["account"]]}
        else:
            ledger.require(kind in ("entry", "leg") and native["entry"] in by_vid,
                           "analytics cited an entry outside the source population")
            entry = by_vid[native["entry"]]
            if kind == "leg":
                ledger.require(type(native["ordinal"]) is int and native["ordinal"] in (0, 1),
                               "analytics cited a missing source leg")
            resolved = cite(entry, native["ordinal"] if kind == "leg" else None)
        ledger.require(all(native[field] is None for field in fields - used),
                       "analytics citation carries an unrelated handle")
        citations.append(resolved)
    result["cites"] = citations
    return result


def check_report(report: dict, procedure: str, expected: list[dict], entries: list[dict],
                 account_ids: dict[str, str], known_at: int) -> list[dict]:
    data = report["data"]
    version, parameters = PROCEDURES[procedure]
    ledger.require(report.get("event") == "procedure_run" and data.get("procedure") == procedure
                   and data.get("version") == version and data.get("claim") == "statistical"
                   and data.get("known_at") == known_at and data.get("effective_through") is None,
                   "analytics procedure, version, claim or source coordinate changed")
    ledger.require(data.get("parameters") == [{"name": name, "value": value}
                   for name, value in sorted(parameters.items())] and data.get("inputs") == [],
                   "analytics changed the declared procedure parameters or scope")
    ledger.require(data["work"]["entries"] == len(entries)
                   and data["work"]["legs"] == (0 if procedure == "jet.weekend" else 2 * len(entries)),
                   "analytics did not examine the complete source posting population")
    native = data["findings"]
    ledger.require(type(data.get("finding_count")) is int and data["finding_count"] == len(native) == len(expected),
                   f"{procedure} omitted, duplicated or added source findings")
    resolved = [source_finding(value, entries, account_ids) for value in native]
    canonical = lambda values: sorted(json.dumps(value, sort_keys=True, ensure_ascii=False) for value in values)
    ledger.require(canonical(resolved) == canonical(expected),
                   f"{procedure} disagrees with the source predicate, statistics, severity or citations")
    return resolved


def run_native(native: ledger.Native, rows: list[dict], posted: dict[str, dict]) -> dict:
    """Run, record and replay the full sweep at one fixed native prefix."""
    entries = source_entries(rows, posted)
    expected = expected_findings(entries)
    known_at = native.head()
    account_ids = {}
    final_day = max(entry["date"] for entry in entries)
    period = f"FY{final_day[:4]}-P{final_day[5:7]}"
    for code in sorted({account for entry in entries for account, _, _ in entry["legs"]}):
        explained = native.call("explain", "balance", code, "--period", period, "--as-known-at", known_at)
        data = explained["data"]
        ledger.require(explained.get("event") == "balance_explained" and data.get("account") == code
                       and data.get("known_at") == known_at and data.get("period") == period
                       and re.fullmatch(r"[0-9a-f]{32}", str(data.get("account_vid"))) is not None,
                       "analytics account citation binding differs from the native chart")
        account_ids[code] = data["account_vid"]
    ledger.require(len(set(account_ids.values())) == len(account_ids), "analytics account bindings are not unique")
    results, replay_bytes = {}, {}
    for procedure in PROCEDURES:
        report = native.call("procedure", "run", procedure, "--known-at", known_at)
        resolved = check_report(report, procedure, expected[procedure], entries, account_ids, known_at)
        recorded = native.call("finding", "record", procedure, "--known-at", known_at)
        record = recorded["data"]
        certificate = record["certificate"]
        ledger.require(recorded.get("event") == "findings_recorded"
                       and re.fullmatch(r"[0-9a-f]{64}", certificate) is not None
                       and recorded.get("certificate") == certificate
                       and recorded.get("book") == report.get("book")
                       and recorded.get("coordinate") == report.get("coordinate")
                       and record.get("source_known_at") == known_at
                       and record.get("procedure") == procedure and record.get("version") == PROCEDURES[procedure][0]
                       and record.get("claim") == "statistical" and record.get("effective_through") is None
                       and record.get("finding_count") == len(expected[procedure])
                       and record.get("findings_digest") == report["data"]["findings_digest"],
                       "recorded forensic run does not bind the checked source result")
        identities = record.get("finding_ids")
        ledger.require(isinstance(identities, list) and len(identities) == len(expected[procedure])
                       and len(set(identities)) == len(identities)
                       and all(isinstance(identity, str) and re.fullmatch(r"[0-9a-f]{32}", identity) is not None
                               for identity in identities), "recorded forensic finding identities are incomplete or repeated")
        replayed, raw = native.execute_events(native.command("replay", f"C:{certificate}"))
        ledger.require(len(replayed) == 1 and replayed[0].get("certificate") == certificate
                       and replayed[0].get("book") == report.get("book")
                       and replayed[0].get("coordinate") == report.get("coordinate")
                       and replayed[0]["data"] == report["data"],
                       "native forensic certificate does not replay its exact source result")
        replay_bytes[procedure] = raw
        results[procedure] = {"version": PROCEDURES[procedure][0], "parameters": PROCEDURES[procedure][1],
                              "finding_count": len(resolved), "source_findings": resolved,
                              "certificate": certificate, "native_record": record,
                              "native_report": report, "record_label": "silent"}
    # Every run is re-read after all finding records have advanced the book.
    # Later evidence must not alter the pinned predicate or its native bytes.
    for procedure, result in results.items():
        _, raw = native.execute_events(native.command("replay", f"C:{result['certificate']}"))
        ledger.require(raw == replay_bytes[procedure], "later findings changed an earlier certified forensic result")
        result["historical_replay_byte_identical"] = True
    result = {"format": "fa-blmis-record-silent-analytics-v1", "status": "PASS", "scope": SCOPE,
              "record_label": "silent", "source_known_at": known_at, "source_observations": len(rows),
              "monetary_entries": len(entries), "native_legs": 2 * len(entries),
              "zero_principal_observations": len(rows) - len(entries),
              "source_accounts": sorted({row["account"] for row in rows}),
              "effective_date_scope": "All source postings at the recorded prefix; these procedures take no effective-through filter",
              "account_citation_bindings": account_ids, "procedures": results,
              "oracle_sha256": ledger.sha256(Path(__file__)),
              "verification_scope": "Independent source predicates and native retained-certificate replay; no offline fa-verify analytic-recomputation claim"}
    ledger.write_json(native.output / "record-silent-analytics.json", result)
    return result
