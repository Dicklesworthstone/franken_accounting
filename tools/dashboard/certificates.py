"""Read-only retained-report certificate inspection for the local dashboard."""
from __future__ import annotations

import re
from typing import Any

ROUTES = {
    "/api/certificate-status": {"oid"},
    "/api/certificate-replay": {"oid"},
}
REPLAY_EVENTS = ("trial_balance", "statement", "balance_explained", "open_items")


def certificate_oid(value: str | None, error: type[Exception]) -> str:
    if value and value.startswith("C:"):
        value = value[2:]
    if not value or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise error("A retained certificate id must contain exactly 64 hexadecimal digits.", 400)
    return value.lower()


def _demo(source: Any, path: str, oid: str) -> dict[str, Any]:
    known = max(0, source.head - 8)
    if path == "/api/certificate-status":
        later = [entry["vid"] for entry in source.entries if entry["seq"] > known][-3:]
        body = {
            "oid": oid,
            "status": "SupersededBy" if later else "Current",
            "known_at": known,
            "checked_at": source.head,
            "later_entries": later,
            "replay_scope": "fa-fold-over-prefix",
            "authority": "synthetic-demo",
        }
        return {"status": source.event("certificate_status", body, source.head)}
    replay = source.tb("FY2026-P09", known, False)
    replay["certificate"] = oid
    replay["warnings"] = ["Synthetic demonstration replay. No retained native certificate was verified."]
    return {"replay": replay}


def dispatch(source: Any, path: str, params: dict[str, str], error: type[Exception]) -> dict[str, Any]:
    if path not in ROUTES or set(params) - ROUTES[path]:
        raise error("Unsupported certificate request or parameters.", 400)
    oid = certificate_oid(params.get("oid"), error)
    if source.mode == "demo":
        return _demo(source, path, oid)
    if path == "/api/certificate-status":
        event = source.call(["certificate", "status", "C:" + oid], "certificate_status")
        body = event["data"]
        if body.get("oid") != oid or event.get("certificate") not in (None, oid):
            raise error("Native certificate identity disagrees with the requested retained artifact.", 409)
        if body.get("status") not in ("Current", "SupersededBy") or not isinstance(body.get("later_entries"), list):
            raise error("Native certificate status omitted its verdict or later-entry list.")
        if any(not isinstance(vid, str) or not re.fullmatch(r"[0-9a-f]{32}", vid) for vid in body["later_entries"]):
            raise error("Native certificate status returned an invalid later-entry handle.")
        return {"status": event}
    event = source.call_one_of(["replay", "C:" + oid], REPLAY_EVENTS)
    if event.get("certificate") not in (None, oid):
        raise error("Native replay identified a different certificate.", 409)
    return {"replay": event}
