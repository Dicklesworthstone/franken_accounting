"""Derived views of the explicit synthetic demo, not a live accounting engine.

The original sample contains no settlement links. Its opposite-sided items stay
open separately: they must not be silently netted or called paid invoices.
"""
from datetime import date

from demo import ACCOUNTS, digest, money
from reports import expected_bands


def report(source, path, selection, error):
    account = next((a for a in ACCOUNTS if a[0] == selection["account"]), None)
    if account is None:
        raise error("Unknown demonstration account.", 400)
    at = source.at(selection["known_at"])
    cutoff = selection["end"]
    legs = [(e, i, side, amount) for e in source.entries
            if e["seq"] <= at and e["date"] <= cutoff
            for i, (code, side, amount) in enumerate(e["legs"]) if code == account[0]]
    if path == "/api/ledger":
        if selection["unit"] != "USD":
            raise error("The synthetic sample contains USD only.", 400)
        opening = sum(n if side == "Debit" else -n for e, _, side, n in legs if e["date"] < selection["start"])
        running, debits, credits = opening, 0, 0
        lines = []
        for entry, ordinal, side, amount in sorted(legs, key=lambda r: (r[0]["date"], r[0]["seq"], r[0]["entry_digest"], r[1])):
            if entry["date"] < selection["start"]:
                continue
            debit, credit = (amount, 0) if side == "Debit" else (0, amount)
            running += debit - credit
            debits += debit
            credits += credit
            lines.append({"account": account[0], "unit": "USD", "entry_digest": entry["entry_digest"],
                          "leg_index": ordinal, "recorded_at": entry["seq"], "effective_date": entry["date"],
                          "class": "Original", "reason_code": "None", "debits": money(debit),
                          "credits": money(credit), "running_balance": money(running)})
        cell = {"account": account[0], "account_vid": digest(account[0])[:32], "name": account[1],
                "type": account[2], "unit": "USD", "opening": money(opening), "debits": money(debits),
                "credits": money(credits), "net_change": money(debits - credits), "closing": money(running),
                "line_count": len(lines)}
        body = {"label": "Synthetic general ledger", "known_at": at, "effective_from": selection["start"],
                "effective_through": cutoff, "cells": [cell], "lines": lines}
        return {"report": source.event("general_ledger", body, at)}
    bounds = selection["bounds"]
    bands = expected_bands(bounds)
    items, cells = [], {}
    debit_total = credit_total = 0
    for entry, ordinal, side, amount in legs:
        age = (date.fromisoformat(cutoff) - date.fromisoformat(entry["date"])).days
        bucket = sum(age > bound for bound in bounds)
        items.append({"entry": entry["vid"], "ordinal": ordinal, "account": account[0], "side": side,
                      "effective_date": entry["date"], "recorded_at": entry["seq"], "original": money(amount),
                      "applied": money(0), "applied_out": money(0), "open": money(amount), "age_days": age, "bucket": bucket})
        cell = cells.setdefault(bucket, [0, 0, 0])
        cell[side == "Credit"] += amount
        cell[2] += 1
        if side == "Debit":
            debit_total += amount
        else:
            credit_total += amount
    items.sort(key=lambda i: (i["bucket"], i["effective_date"], i["recorded_at"], i["entry"], i["ordinal"]))
    totals = [{"account": account[0], "unit": "USD", "debits": money(debit_total),
               "credits": money(credit_total), "item_count": len(items)}] if items else []
    body = {"account": account[0], "known_at": at, "effective_through": cutoff, "bands": bands,
            "items": items, "totals": totals, "cells": [{"account": account[0], "unit": "USD", "bucket": bucket,
            "debits": money(d), "credits": money(c), "item_count": n} for bucket, (d, c, n) in sorted(cells.items())]}
    reconciliation = {"account": account[0], "account_vid": digest(account[0])[:32], "name": account[1],
                      "known_at": at, "effective_through": cutoff, "reconciled": True, "bands": bands,
                      "item_count": len(items), "rows": [{"unit": "USD", "posted_debits": money(debit_total),
                      "posted_credits": money(credit_total), "pending_debits": money(0), "pending_credits": money(0),
                      "open_debits": money(debit_total), "open_credits": money(credit_total), "open_item_count": len(items),
                      "posted_net": money(debit_total-credit_total), "open_net": money(debit_total-credit_total),
                      "difference": money(0)}]}
    return {"report": source.event("aging", body, at),
            "reconciliation": source.event("aging_reconciled", reconciliation, at)}
