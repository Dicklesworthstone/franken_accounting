#!/usr/bin/env python3
"""Recover an admitted original through a fresh native document-read process.

The public CLI writes the recovered bytes with ``--out`` and also includes
``bytes_hex`` in its robot response. Both representations must reproduce the
original size and SHA-256. A metadata receipt alone is not a readback check.
The caller's Native instance retains the actual process transcript; this
helper returns a compact receipt rather than repeating the document payload.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

import public_ledger as ledger


def fingerprint(path: Path) -> tuple[int, str]:
    """Hash a file without an additional full-document allocation."""
    size, digest = 0, hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _hex_digest(value: object, size: int) -> str:
    ledger.require(isinstance(value, str) and len(value) == size * 2
                   and re.fullmatch(r"[0-9a-f]*", value, re.ASCII) is not None,
                   "native document read returned malformed or incomplete hexadecimal bytes")
    digest = hashlib.sha256()
    for offset in range(0, len(value), 131072):
        digest.update(bytes.fromhex(value[offset:offset + 131072]))
    return digest.hexdigest()


def readback_document(native: ledger.Native, source_path: Path, oid: str,
                      output_path: Path) -> dict:
    """Check the full original by OID after native storage has been reopened.

    Native.call starts a separate real CLI process for every invocation. The
    ``document read`` therefore cannot reuse the process that admitted the
    source. Existing destinations, redacted responses, changed identities,
    changed source files and any byte difference fail closed. This works for
    both inline and externally stored documents; it does not infer a storage
    class from the public metadata, which does not expose that field.
    """
    source_path = Path(source_path).resolve(strict=True)
    requested_output = Path(output_path)
    ledger.require(not requested_output.exists() and not requested_output.is_symlink(),
                   "document readback destination already exists")
    output_path = requested_output.resolve()
    ledger.require(source_path.is_file() and source_path != output_path,
                   "document readback requires a separate original file and new output")
    ledger.require(output_path.parent.is_dir(), "document readback output parent does not exist")
    ledger.require(isinstance(oid, str) and re.fullmatch(r"[0-9a-f]{64}", oid, re.ASCII) is not None,
                   "document readback requires a native document OID")
    size, source_sha256 = fingerprint(source_path)
    shown = native.call("document", "show", oid)
    ledger.require(shown.get("v") == 1 and shown.get("event") == "document_shown"
                   and isinstance(shown.get("data"), dict),
                   "native document metadata returned another robot envelope")
    held = shown["data"]
    ledger.require(held.get("oid") == oid and type(held.get("size")) is int
                   and held["size"] == size
                   and isinstance(held.get("doc_commit"), str)
                   and re.fullmatch(r"[0-9a-f]{64}", held["doc_commit"], re.ASCII) is not None,
                   "native document metadata differs from the original identity or size")
    result = native.call("document", "read", oid, "--out", output_path)
    ledger.require(result.get("v") == 1 and result.get("event") == "document_read"
                   and isinstance(result.get("data"), dict)
                   and result.get("book") == shown.get("book")
                   and result.get("coordinate") == shown.get("coordinate"),
                   "native document read changed its envelope, book or recorded coordinate")
    data = result["data"]
    ledger.require(data.get("view") == "full"
                   and all(data.get(field) == held.get(field)
                           for field in ("oid", "doc_commit", "kind", "mime", "grade", "size"))
                   and type(data.get("size")) is int and data["size"] == size
                   and data.get("out") == str(output_path)
                   and all(field in data and data[field] is None for field in
                           ("disclosed_chunks", "withheld_chunks", "view_commit", "extraction")),
                   "native document read is not the original full document under its held commitment")
    robot_sha256 = _hex_digest(data.get("bytes_hex"), size)
    ledger.require(robot_sha256 == source_sha256,
                   "native document robot bytes differ from the original SHA-256")
    ledger.require(output_path.is_file() and not output_path.is_symlink(),
                   "native document read did not create a separate recovered file")
    recovered_size, recovered_sha256 = fingerprint(output_path)
    ledger.require((recovered_size, recovered_sha256) == (size, source_sha256),
                   "native document recovered file differs from the original bytes")
    ledger.require(fingerprint(source_path) == (size, source_sha256),
                   "original source changed during native document readback")
    return {
        "format": "fa-native-document-readback-v1",
        "oid": oid,
        "doc_commit": held["doc_commit"],
        "book": result["book"],
        "coordinate": result["coordinate"],
        "kind": data["kind"],
        "mime": data["mime"],
        "grade": data["grade"],
        "view": "full",
        "source": str(source_path),
        "recovered": str(output_path),
        "bytes": size,
        "source_sha256": source_sha256,
        "recovered_sha256": recovered_sha256,
        "robot_bytes_sha256": robot_sha256,
        "source_unchanged": True,
        "read_protocol": "document read --out in a separate fa CLI process; exact file and robot bytes",
    }
