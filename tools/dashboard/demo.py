"""Explicit deterministic synthetic preview, never a fallback for native errors."""
from __future__ import annotations

import calendar
import hashlib

BOOK = "d" * 32
ACCOUNTS = [
    ("1000", "Operating bank", "Asset"), ("1100", "Trade receivables", "Asset"),
    ("1500", "Equipment & fixtures", "Asset"), ("2000", "Trade payables", "Liability"),
    ("2100", "Deferred revenue", "Liability"), ("3000", "Owner capital", "Equity"),
    ("4000", "Studio revenue", "Revenue"), ("5000", "Project delivery", "Expense"),
    ("6100", "People & contractors", "Expense"), ("6200", "Workspace", "Expense"),
    ("6300", "Software & tools", "Expense"),
]


def money(n: int) -> str:
    return f"{'-' if n < 0 else ''}{abs(n) // 100}.{abs(n) % 100:02d} USD"


def digest(value: str) -> str:
    return hashlib.sha256(("synthetic-dashboard:" + value).encode()).hexdigest()


class DemoSource:
    mode = "demo"

    def __init__(self, error_type=ValueError):
        self.error_type = error_type
        self.entries = []
        self.periods = []
        self.add(1, "Owner funding", [("1000", "Debit", 28000000), ("3000", "Credit", 28000000)])
        self.add(1, "Studio equipment", [("1500", "Debit", 4250000), ("1000", "Credit", 4250000)])
        self.add(1, "Annual service deposit", [("1000", "Debit", 1800000), ("2100", "Credit", 1800000)])
        for month in range(1, 10):
            revenue = 4800000 + month * 670000
            self.add(month, "Client project milestone", [("1100", "Debit", revenue), ("4000", "Credit", revenue)])
            self.add(month, "Client remittance", [("1000", "Debit", revenue - 760000), ("1100", "Credit", revenue - 760000)])
            self.add(month, "Project delivery costs", [("5000", "Debit", 980000 + month * 60000), ("2000", "Credit", 980000 + month * 60000)])
            self.add(month, "Supplier settlement", [("2000", "Debit", 920000 + month * 55000), ("1000", "Credit", 920000 + month * 55000)])
            self.add(month, "Team and specialist fees", [("6100", "Debit", 1740000 + month * 40000), ("1000", "Credit", 1740000 + month * 40000)])
            self.add(month, "Workspace and tools", [("6200", "Debit", 420000), ("6300", "Debit", 96000), ("1000", "Credit", 516000)])
        self.head = 100 + len(self.entries)
        for month in range(1, 13):
            self.periods.append({"code": f"FY2026-P{month:02d}", "state": "Locked" if month < 7 else
                                 "Closed" if month < 9 else "Open" if month == 9 else "Future",
                                 "kind": "Regular", "start": f"2026-{month:02d}-01",
                                 "end": f"2026-{month+1:02d}-01" if month < 12 else "2027-01-01",
                                 "fiscal_year": 2026})

    def add(self, month, description, legs):
        seq = 101 + len(self.entries)
        self.entries.append({"vid": f"{seq:032x}", "entry_digest": digest(str(seq)), "seq": seq,
                             "date": f"2026-{month:02d}-{min(28, 3 + len(self.entries) % 25):02d}",
                             "month": month, "description": description, "legs": legs})

    def event(self, name, data, at=None, effective="all"):
        return {"v": 1, "event": name, "book": BOOK, "coordinate": {"branch": "trunk",
                "known_at": self.head if at is None else at, "effective": effective, "time_evidence": None},
                "certificate": None, "authority": {"posture": "synthetic-demo"},
                "warnings": ["Synthetic demonstration data. Not a real book or verification result."],
                "next_actions": [], "data": data}

    def bootstrap(self):
        return {"book": self.event("book", {"book_id": BOOK, "base_unit": "USD", "calendar": "monthly",
                "periods": 12, "accounts": len(ACCOUNTS), "units_registered": 1, "entities": [],
                "periods_by_state": {"Locked": 6, "Closed": 2, "Open": 1, "Future": 3}}),
                "periods": self.event("periods", {"periods": self.periods})}

    def at(self, known_at):
        at = self.head if known_at == "HEAD" else int(known_at)
        if at > self.head:
            raise self.error_type("The demo snapshot is beyond its synthetic frontier.", 400)
        return at

    def month(self, period):
        row = next((p for p in self.periods if p["code"] == period), None)
        if row is None:
            raise self.error_type("Unknown demonstration period.", 400)
        return int(row["start"][5:7])

    def tb(self, period, at, activity):
        month = self.month(period)
        totals = {code: [0, 0] for code, _, _ in ACCOUNTS}
        for entry in self.entries:
            if entry["seq"] <= at and (entry["month"] == month if activity else entry["month"] <= month):
                for code, side, amount in entry["legs"]:
                    totals[code][side == "Credit"] += amount
        rows = [{"code": code, "name": name, "type": kind, "debits": money(totals[code][0]),
                 "credits": money(totals[code][1]), "net": money(totals[code][0] - totals[code][1]),
                 "debits_pending": money(0), "credits_pending": money(0)} for code, name, kind in ACCOUNTS]
        return self.event("trial_balance", {"periods": [period], "known_at": at,
            "effective_through": f"2026-{month:02d}-{calendar.monthrange(2026, month)[1]}",
            "activity": activity, "mode": "activity" if activity else "stock", "rows": rows,
            "balanced": True, "unit_totals": [{"unit": "USD", "debits": money(sum(v[0] for v in totals.values())),
            "credits": money(sum(v[1] for v in totals.values()))}], "pending_unit_totals": []}, at, "period:" + period)

    def overview(self, period, known_at):
        at = self.at(known_at)
        return {"known_at": str(at), "stock": self.tb(period, at, False), "activity": self.tb(period, at, True)}

    def evidence_head(self, entry):
        return [{"document_oid": digest("doc" + entry["vid"]), "doc_commit": digest("commit" + entry["vid"]), "role": 1}]

    def account(self, account, period, known_at):
        selected = next((a for a in ACCOUNTS if a[0] == account), None)
        if selected is None:
            raise self.error_type("Unknown demonstration account.", 400)
        at, month = self.at(known_at), self.month(period)
        contributions = []
        for entry in self.entries:
            if entry["seq"] > at or entry["month"] != month:
                continue
            for ordinal, (code, side, amount) in enumerate(entry["legs"]):
                if code == account:
                    contributions.append({"entry": entry["vid"], "entry_digest": entry["entry_digest"],
                        "class": "Original", "effective_date": entry["date"], "recorded_at": entry["seq"],
                        "ordinal": ordinal, "side": side, "amount": money(amount), "column": "posted",
                        "released_at": None, "resolves": None, "supersedes": [], "evidence": self.evidence_head(entry)})
        row = next(r for r in self.tb(period, at, True)["data"]["rows"] if r["code"] == account)
        cell = {key: row[key] for key in ("debits", "credits", "net", "debits_pending", "credits_pending")}
        cell.update(unit="USD", entry_count=len(contributions), pending_count=0)
        return {"report": self.event("balance_explained", {"account": account, "account_vid": digest(account)[:32],
            "name": selected[1], "type": selected[2], "period": period, "known_at": at, "watermark": at,
            "fold_digest": digest(period + account), "certificate": None, "cells": [cell],
            "contributions": contributions, "history": [], "last_changed_at": at}, at, "period:" + period)}

    def entry(self, vid):
        entry = next((e for e in self.entries if e["vid"] == vid), None)
        if entry is None:
            raise self.error_type("Entry not found in the synthetic sample.", 404)
        doc = self.evidence_head(entry)[0]
        data = {"vid": vid, "entry_digest": entry["entry_digest"], "proposal_digest": digest("proposal" + vid),
                "class": "Original", "effective_date": entry["date"], "period": f"FY2026-P{entry['month']:02d}",
                "recorded_at": entry["seq"], "principal": "1" * 32, "description": {
                    "untrusted_content": entry["description"], "source": "E:" + vid},
                "approvals": 0, "resolves": None, "disposition": None, "supersedes": [], "superseded_by": [],
                "evidence": [doc], "legs": [{"ordinal": i, "side": side, "account": code,
                    "account_vid": digest(code)[:32], "account_name": next(a[1] for a in ACCOUNTS if a[0] == code),
                    "amount": money(amount), "memo": None} for i, (code, side, amount) in enumerate(entry["legs"])]}
        evidence = {"entry": vid, "entry_digest": entry["entry_digest"], "proposal_digest": data["proposal_digest"],
                    "class": "Original", "recorded_at": entry["seq"], "min_documents": 1,
                    "accepted_kinds": ["Invoice"], "accepts_self_sourced": False, "accepts_manual_assertion": True,
                    "satisfied": True, "manual_assertions": [], "documents": [{**doc, "role_name": "Source",
                    "kind": "Invoice", "grade": "HumanUpload", "self_sourced": False, "size": 42816,
                    "recorded_at": entry["seq"] - 1, "reviews": [], "supplements": [], "counts_toward_minimum": True}]}
        return {"entry": self.event("entry_explained", data), "evidence": self.event("evidence_explained", evidence)}

    def health(self):
        return {"report": self.event("book_triage", {"health": "ok", "daemon": "absent", "periods": 12,
                "periods_by_state": self.bootstrap()["book"]["data"]["periods_by_state"], "open_periods": ["FY2026-P09"],
                "accounts": len(ACCOUNTS), "pending_cells": 0, "due_holds": 0, "due_reversals": 0,
                "blocked_reversals": 0, "derived": [{"name": "registers", "status": "ok", "detail":
                "Synthetic check for interface preview only. No native verifier was run.", "fix": None}]})}

    def projections(self):
        return {"report": self.event("projections_verified", {"known_at": self.head,
                "entries_checked": len(self.entries), "legs_checked": sum(len(e["legs"]) for e in self.entries),
                "edges_checked": sum(len(e["legs"]) * 3 for e in self.entries), "drift": []})}
