"""Read-only adapters for native general-ledger and reconciled aging reports.

Only selection and response contracts live here. Live balances, running balances,
application liveness and reconciliation are always supplied by fa, never folded
by this module. Error is injected to share the launcher's typed HTTP errors.
"""
from __future__ import annotations

from datetime import date
import re
from typing import Any

ROUTES = {
    "/api/ledger": {"account", "unit", "from", "to", "known_at"},
    "/api/aging": {"account", "as_of", "known_at", "buckets"},
}


def operand(value: str | None, name: str, error: type[Exception]) -> str:
    # The native CLI splits comma lists. This endpoint intentionally selects ONE
    # account/unit, including when invoked outside the browser UI.
    if (not value or len(value) > 128 or value.startswith("-") or "," in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise error(f"Select one explicit {name}; lists and option-shaped values are not accepted.", 400)
    if name == "unit" and any(c.isspace() for c in value):
        raise error("Select one native unit code.", 400)
    return value


def civil_date(value: str | None, name: str, error: type[Exception]) -> str:
    if not value or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise error(f"{name} must be a civil date in YYYY-MM-DD form.", 400)
    try:
        date.fromisoformat(value)
    except ValueError as cause:
        raise error(f"{name} is not a valid civil date.", 400) from cause
    return value


def known_at(value: str, error: type[Exception]) -> str:
    if value != "HEAD" and (not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or int(value) >= 2**64):
        raise error("known_at must be HEAD or an unsigned 64-bit commit sequence.", 400)
    return value


def bucket_bounds(value: str, error: type[Exception]) -> list[int]:
    parts = value.split(",")
    if not 1 <= len(parts) <= 12 or any(not re.fullmatch(r"0|[1-9][0-9]{0,6}", p) for p in parts):
        raise error("Use 1–12 increasing whole-day bucket bounds, for example 30,60,90.", 400)
    bounds = [int(p) for p in parts]
    if any(a >= b for a, b in zip(bounds, bounds[1:])) or bounds[-1] > 1000000:
        raise error("Age bucket bounds must increase strictly and not exceed 1000000 days.", 400)
    return bounds


def select(path: str, params: dict[str, str], error: type[Exception]) -> dict[str, Any]:
    if path not in ROUTES or set(params) - ROUTES[path]:
        raise error("Unsupported report or parameters.", 400)
    selection: dict[str, Any] = {
        "account": operand(params.get("account"), "account", error),
        "known_at": known_at(params.get("known_at", "HEAD"), error),
    }
    if path == "/api/ledger":
        selection.update(unit=operand(params.get("unit"), "unit", error),
                         start=civil_date(params.get("from"), "from", error),
                         end=civil_date(params.get("to"), "to", error))
        if selection["start"] > selection["end"]:
            raise error("The inclusive from date must not be after to.", 400)
    else:
        selection.update(end=civil_date(params.get("as_of"), "as_of", error),
                         bounds=bucket_bounds(params.get("buckets", "30,60,90"), error))
    return selection


def expected_bands(bounds: list[int]) -> list[dict[str, int | None]]:
    lower = 0
    bands = []
    for upper in bounds:
        bands.append({"lower_inclusive": lower, "upper_inclusive": upper})
        lower = upper + 1
    return bands + [{"lower_inclusive": lower, "upper_inclusive": None}]


def scope(event: dict[str, Any], selection: dict[str, Any], error: type[Exception], *, aging: bool = False) -> dict[str, Any]:
    body = event.get("data")
    if not isinstance(body, dict) or body.get("effective_through") != selection["end"]:
        raise error("Native report did not honor the requested effective cutoff.", 409)
    if aging:
        if body.get("account") != selection["account"] or body.get("bands") != expected_bands(selection["bounds"]):
            raise error("Native aging account or age bands disagree with the selection.", 409)
    elif body.get("effective_from") != selection["start"]:
        raise error("Native ledger did not honor the requested start date.", 409)
    return body


def dispatch(source: Any, path: str, params: dict[str, str], error: type[Exception]) -> dict[str, Any]:
    selection = select(path, params, error)
    if source.mode == "demo":
        from demo_reports import report
        return report(source, path, selection, error)
    if path == "/api/ledger":
        event = source.call(["gl", "detail", "--account", selection["account"],
                             "--unit", selection["unit"], "--from", selection["start"],
                             "--to", selection["end"], "--as-known-at", selection["known_at"]],
                            "general_ledger")
        source.pin(event, selection["known_at"])
        body = scope(event, selection, error)
        for key in ("cells", "lines"):
            if not isinstance(body.get(key), list):
                raise error("Native ledger omitted its cells or movement rows.")
            if any(not isinstance(row, dict) or row.get("account") != selection["account"]
                   or row.get("unit") != selection["unit"] for row in body[key]):
                raise error("Native ledger contains rows outside the requested account/unit.", 409)
        if len(body["cells"]) > 1:
            raise error("Native ledger repeated the selected account/unit cell.", 409)
        return {"report": event}
    argv = ["gl", "aging", "--account", selection["account"], "--as-of", selection["end"]]
    for bound in selection["bounds"]:
        argv.extend(["--bucket", str(bound)])
    event = source.call(argv + ["--as-known-at", selection["known_at"]], "aging")
    at = source.pin(event, selection["known_at"])
    body = scope(event, selection, error, aging=True)
    for key in ("items", "cells", "totals"):
        if not isinstance(body.get(key), list):
            raise error("Native aging omitted its items, cells or unit totals.")
    if any(not isinstance(row, dict) or row.get("account") != selection["account"]
           for row in body["items"] + body["cells"]):
        raise error("Native aging contains rows outside the requested account.", 409)
    # The native reconciliation is a second fold, explicitly pinned to the first.
    # A refused or failed reconciliation prevents publishing a partial green view.
    reconciliation = source.call(argv + ["--as-known-at", at, "--reconcile"], "aging_reconciled")
    source.pin(reconciliation, at)
    check = scope(reconciliation, selection, error, aging=True)
    if type(check.get("reconciled")) is not bool or not isinstance(check.get("rows"), list):
        raise error("Native reconciliation omitted its verdict or unit rows.")
    return {"report": event, "reconciliation": reconciliation}
