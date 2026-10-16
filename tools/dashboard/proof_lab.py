"""Read-only checkpoint-chain and portable-proof adapter for the local dashboard."""
from __future__ import annotations

import re
from typing import Any

ROUTES = {
    "/api/checkpoints": set(),
    "/api/proof-export": {"kind", "state", "entry", "account", "unit", "as_of", "with_record"},
}
KINDS = {"signed-checkpoint", "checkpoint", "prefix", "inclusion", "balance"}


def _hex(value: str | None, digits: int, name: str, error: type[Exception]) -> str:
    if not value or not re.fullmatch(rf"[0-9a-fA-F]{{{digits}}}", value):
        raise error(f"{name} must contain exactly {digits} hexadecimal digits.", 400)
    return value.lower()


def _state(value: str | None, error: type[Exception]) -> str:
    if value in (None, "", "latest"):
        return "latest"
    return _hex(value, 64, "state", error)


def _operand(value: str | None, name: str, error: type[Exception]) -> str:
    if not value or len(value) > 128 or value.startswith("-") or "," in value or any(ord(c) < 32 for c in value):
        raise error(f"Select one explicit {name}.", 400)
    return value


def select(params: dict[str, str], error: type[Exception]) -> dict[str, Any]:
    kind = params.get("kind")
    if kind not in KINDS:
        raise error("Proof kind must be signed-checkpoint, checkpoint, prefix, inclusion, or balance.", 400)
    state = _state(params.get("state"), error)
    allowed = {"kind", "state"}
    argv = ["proof", kind, "--state", state]
    if kind == "inclusion":
        allowed |= {"entry", "with_record"}
        entry = params.get("entry", "").removeprefix("E:")
        entry = _hex(entry, 32, "entry", error)
        argv += ["--entry", entry]
        flag = params.get("with_record", "0")
        if flag not in ("0", "1"):
            raise error("with_record must be 0 or 1.", 400)
        if flag == "1":
            argv.append("--with-record")
    elif kind == "balance":
        allowed |= {"account", "unit", "as_of"}
        argv += ["--account", _operand(params.get("account"), "account", error),
                 "--unit", _operand(params.get("unit"), "unit", error)]
        if params.get("as_of"):
            value = params["as_of"]
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
                raise error("as_of must be YYYY-MM-DD.", 400)
            argv += ["--as-of", value]
    if set(params) - allowed:
        raise error("Parameters not used by this proof kind are not accepted.", 400)
    return {"kind": kind, "state": state, "argv": argv}


def _demo_chain(source: Any) -> dict[str, Any]:
    head = source.head
    states = []
    for i, through in enumerate((max(0, head - 24), max(0, head - 12), head)):
        states.append({"oid": f"{i+1:064x}", "through_seq": through,
                       "recorded_at": through + 1, "leaf_count": max(0, through - 90),
                       "finding": None})
    body = {"status": "verified", "signatures": "ed25519", "scope": "entry_prefix",
            "states_checked": len(states), "broken": None, "verified_through": head,
            "states": list(reversed(states)), "unchained": []}
    return {"report": source.event("accumulator_verified", body, head)}


def _demo_proof(source: Any, selection: dict[str, Any]) -> dict[str, Any]:
    raw = ("synthetic-" + selection["kind"]).encode().hex()
    state = "3".zfill(64) if selection["state"] == "latest" else selection["state"]
    body = {"kind": selection["kind"], "scope": "entry_prefix", "state_oid": state,
            "recorded_at": source.head, "through_seq": source.head, "leaf_count": len(source.entries),
            "root": "a"*64, "checkpoint_bytes": "00"*80, "next_state_oid": None,
            "next_checkpoint_bytes": None, "signatures": "ed25519",
            "trust": "synthetic_demo_only", "checkpoint_public_key": "b"*64,
            "claim": {"synthetic": True}, "byte_len": len(bytes.fromhex(raw)), "bytes": raw, "file": None}
    event = source.event("proof_exported", body, source.head)
    event["warnings"] = ["Synthetic proof preview. No native checkpoint or signature was produced."]
    return {"proof": event}


def dispatch(source: Any, path: str, params: dict[str, str], error: type[Exception]) -> dict[str, Any]:
    if path not in ROUTES or set(params) - ROUTES[path]:
        raise error("Unsupported proof request or parameters.", 400)
    if path == "/api/checkpoints":
        if source.mode == "demo":
            return _demo_chain(source)
        return {"report": source.call(["verify", "accumulator"], "accumulator_verified", verification=True)}
    selection = select(params, error)
    if source.mode == "demo":
        return _demo_proof(source, selection)
    event = source.call(selection["argv"], "proof_exported")
    body = event["data"]
    if body.get("kind") != selection["kind"]:
        raise error("Native proof kind differs from the requested proof.", 409)
    if selection["state"] != "latest" and body.get("state_oid") != selection["state"]:
        raise error("Native proof resolved a different checkpoint state.", 409)
    if not isinstance(body.get("bytes"), str) or not re.fullmatch(r"[0-9a-f]*", body["bytes"]) or len(body["bytes"]) % 2:
        raise error("Native proof did not return complete inline proof bytes.")
    return {"proof": event}
