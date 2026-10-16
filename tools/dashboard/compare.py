"""Two native stock snapshots, one effective scope. No Python accounting fold.

Resolve B once, then read explicit A. Never compare independently moving HEADs,
change effective periods between reads, or return a successful half-comparison.
The browser computes labeled presentation differences, not a causal attribution.
"""
from __future__ import annotations

import re
from typing import Any

from reports import civil_date, known_at, operand

PARAMETERS = {"period", "before", "after"}


def snapshot(event: dict[str, Any], period: str, requested: str,
             error: type[Exception]) -> int:
    coordinate, body = event.get("coordinate"), event.get("data")
    if not isinstance(coordinate, dict) or not isinstance(body, dict):
        raise error("Native comparison omitted its coordinate or report.", 409)
    at = coordinate.get("known_at")
    if (type(at) is not int or not 0 <= at < 2**64
            or type(body.get("known_at")) is not int or body.get("known_at") != at
            or coordinate.get("branch") != "trunk"
            or not re.fullmatch(r"[a-f0-9]{32}", str(event.get("book", "")))):
        raise error("Native comparison did not identify an exact trunk snapshot.", 409)
    if requested != "HEAD" and at != int(requested):
        raise error("Native comparison returned a different recorded snapshot.", 409)
    if body.get("periods") != [period] or body.get("activity") is not False:
        raise error("Native comparison did not honor the selected stock period.", 409)
    civil_date(body.get("effective_through"), "native effective cutoff", error)
    if not isinstance(body.get("rows"), list) or type(body.get("balanced")) is not bool:
        raise error("Native comparison omitted its stock rows or balance verdict.", 409)
    return at


def compare(source: Any, params: dict[str, str], error: type[Exception]) -> dict[str, Any]:
    if set(params) - PARAMETERS:
        raise error("Unsupported comparison parameters.", 400)
    period = operand(params.get("period"), "period", error)
    before = known_at(params.get("before", ""), error)
    after = known_at(params.get("after", "HEAD"), error)
    if before == "HEAD":
        raise error("Snapshot A must name an explicit commit sequence.", 400)
    if after != "HEAD" and int(before) > int(after):
        raise error("Snapshot A must not be later than snapshot B.", 400)

    def read(at: str) -> dict[str, Any]:
        if source.mode == "demo":
            return source.tb(period, source.at(at), False)
        return source.call(["tb", "--period", period, "--as-known-at", at], "trial_balance")

    right = read(after)
    right_at = snapshot(right, period, after, error)
    if int(before) > right_at:
        raise error("Snapshot A is beyond the resolved snapshot B.", 400)
    left = right if int(before) == right_at else read(before)
    left_at = snapshot(left, period, before, error)
    if (left["book"] != right["book"]
            or left["data"]["effective_through"] != right["data"]["effective_through"]
            or left["data"].get("mode") != right["data"].get("mode")):
        raise error("Comparison snapshots have different books or effective scopes.", 409)
    return {"before": left, "after": right, "period": period,
            "before_known_at": left_at, "after_known_at": right_at,
            "scope": "native-stock-snapshot-comparison"}
