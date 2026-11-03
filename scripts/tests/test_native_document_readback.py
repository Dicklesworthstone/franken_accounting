"""Source-bound native readback checks; no mocked run is a native PASS."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_document_readback as readback
import public_ledger as ledger


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.pdf"
        self.output = self.root / "recovered.pdf"
        self.content = b"%PDF-1.4\noriginal bytes\x00\xff\n%%EOF\n"
        self.source.write_bytes(self.content)
        self.oid = "a" * 64
        self.metadata = {"oid": self.oid, "doc_commit": "b" * 64,
                         "size": len(self.content), "kind": "Other",
                         "mime": "application/pdf", "grade": "AgentUpload"}
        self.data = {**self.metadata, "view": "full", "bytes_hex": self.content.hex(),
                     "out": str(self.output), "disclosed_chunks": None,
                     "withheld_chunks": None, "view_commit": None, "extraction": None}
        self.calls = []

    def native(self, *, metadata=None, data=None, output_bytes=None, after_read=None,
               read_envelope=None):
        metadata = self.metadata if metadata is None else metadata
        data = self.data if data is None else data
        output_bytes = self.content if output_bytes is None else output_bytes
        owner = self

        class FakeNative:
            def call(self, *args):
                owner.calls.append(args)
                envelope = {"v": 1, "book": "c" * 32,
                            "coordinate": {"branch": "trunk", "known_at": 3,
                                           "effective": "all", "time_evidence": None}}
                if args[:2] == ("document", "show"):
                    return {**envelope, "event": "document_shown", "data": deepcopy(metadata)}
                owner.assertEqual(args, ("document", "read", owner.oid, "--out", owner.output))
                owner.output.write_bytes(output_bytes)
                if after_read:
                    after_read()
                return {**envelope, "event": "document_read", "data": deepcopy(data),
                        **(read_envelope or {})}

        return FakeNative()

    def test_full_file_and_robot_payload_match_original(self):
        receipt = readback.readback_document(self.native(), self.source, self.oid, self.output)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(receipt["bytes"], len(self.content))
        self.assertEqual(receipt["source_sha256"], hashlib.sha256(self.content).hexdigest())
        self.assertEqual(receipt["source_sha256"], receipt["recovered_sha256"])
        self.assertEqual(receipt["source_sha256"], receipt["robot_bytes_sha256"])
        self.assertNotIn("bytes_hex", receipt)

    def test_existing_destination_is_not_overwritten(self):
        self.output.write_bytes(b"keep this")
        with self.assertRaises(ledger.ReplayError):
            readback.readback_document(self.native(), self.source, self.oid, self.output)
        self.assertEqual(self.output.read_bytes(), b"keep this")
        self.assertEqual(self.calls, [])

    def test_original_cannot_be_destination(self):
        with self.assertRaises(ledger.ReplayError):
            readback.readback_document(self.native(), self.source, self.oid, self.source)
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(self.calls, [])

    def test_changed_native_identity_or_size_refuses_before_read(self):
        for field, value in (("oid", "d" * 64), ("size", len(self.content) - 1),
                             ("size", True), ("doc_commit", "not-a-commit")):
            with self.subTest(field=field, value=value), self.assertRaises(ledger.ReplayError):
                readback.readback_document(self.native(metadata={**self.metadata, field: value}),
                                           self.source, self.oid, self.output)
        self.assertTrue(all(call[:2] == ("document", "show") for call in self.calls))

    def test_redaction_and_changed_read_commitment_fail(self):
        for field, value in (("view", "redacted"), ("doc_commit", "d" * 64),
                             ("oid", "d" * 64), ("size", True),
                             ("withheld_chunks", 1), ("extraction", {})):
            with self.subTest(field=field):
                output = self.root / f"failed-{field}.pdf"
                # Each independent refusal uses a new output, as the real CLI does.
                self.output = output
                data = {**self.data, "out": str(output), field: value}
                with self.assertRaises(ledger.ReplayError):
                    readback.readback_document(self.native(data=data), self.source, self.oid, output)

    def test_same_length_changed_robot_bytes_fail(self):
        changed = bytes([self.content[0] ^ 1]) + self.content[1:]
        with self.assertRaises(ledger.ReplayError):
            readback.readback_document(self.native(data={**self.data, "bytes_hex": changed.hex()}),
                                       self.source, self.oid, self.output)

    def test_correct_robot_bytes_do_not_hide_changed_output(self):
        changed = bytes([self.content[0] ^ 1]) + self.content[1:]
        with self.assertRaises(ledger.ReplayError):
            readback.readback_document(self.native(output_bytes=changed),
                                       self.source, self.oid, self.output)

    def test_correct_robot_bytes_do_not_hide_truncated_output(self):
        with self.assertRaises(ledger.ReplayError):
            readback.readback_document(self.native(output_bytes=self.content[:-1]),
                                       self.source, self.oid, self.output)

    def test_source_change_during_readback_is_detected(self):
        changed = bytes([self.content[0] ^ 1]) + self.content[1:]
        with self.assertRaises(ledger.ReplayError):
            readback.readback_document(self.native(after_read=lambda: self.source.write_bytes(changed)),
                                       self.source, self.oid, self.output)

    def test_wrong_book_or_coordinate_is_rejected(self):
        for field, value in (("book", "d" * 32), ("coordinate", {"known_at": 4})):
            with self.subTest(field=field):
                self.output = self.root / f"wrong-{field}.pdf"
                data = {**self.data, "out": str(self.output)}
                with self.assertRaises(ledger.ReplayError):
                    readback.readback_document(self.native(data=data, read_envelope={field: value}),
                                               self.source, self.oid, self.output)

    def test_noncanonical_robot_hex_is_rejected(self):
        with self.assertRaises(ledger.ReplayError):
            readback._hex_digest("aa bb", 2)
        with self.assertRaises(ledger.ReplayError):
            readback._hex_digest("AABB", 2)
        with self.assertRaises(ledger.ReplayError):
            readback._hex_digest("aabb", 3)


if __name__ == "__main__":
    unittest.main()
