"""Planted recovery-guard failures; these are not native execution evidence."""

from copy import deepcopy
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blmis_magnify_continue as recovery


BOOK = "1" * 32


def envelope(event="recorded", at=12):
    return {"v": 1, "book": BOOK, "event": event,
            "coordinate": {"branch": "trunk", "effective": "all", "known_at": at},
            "data": {"vid": "2" * 32, "entry_digest": "3" * 64, "recorded_at": 11}}


def record(command, value=None):
    return {"command": command, "exit": 0, "stdout": json.dumps(value or envelope()) + "\n", "stderr": ""}


class TranscriptGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magnify-continuation-guards-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "commands.jsonl"
        self.command = ["/fixture/fa", "--book", "/fixture/original/book", "post", "--intent",
                        "/fixture/original/entry-0002.json", "--json"]
        self.header = (json.dumps({"command": self.command})[:-1] + ', "exit": 0, "stdout": ').encode()

    def parse(self, data):
        self.path.write_bytes(data)
        return recovery.transcript(self.path, hashlib.sha256(data).hexdigest())

    def test_one_incomplete_final_header_is_preserved_and_bound_to_next_retry(self):
        complete = json.dumps(record(self.command)).encode() + b"\n"
        tail = self.header[:90]
        records, retained, identity = self.parse(complete + tail)
        self.assertEqual(records, [record(self.command)])
        self.assertEqual(retained, tail)
        self.assertEqual(identity["complete_records"], 1)
        self.assertEqual(identity["incomplete_tail_bytes"], len(tail))
        self.assertEqual(self.path.read_bytes(), complete + tail)
        recovery.retry_tail(retained, self.command)

    def test_malformed_complete_record_cannot_be_ignored(self):
        with self.assertRaisesRegex(recovery.ContinuationError, "malformed complete"):
            self.parse(b'{"command":\n' + self.header[:30])

    def test_empty_line_in_the_middle_is_not_skipped(self):
        with self.assertRaisesRegex(recovery.ContinuationError, "malformed complete"):
            self.parse(json.dumps(record(self.command)).encode() + b"\n\n" + self.header[:30])

    def test_complete_unterminated_record_and_clean_completion_are_not_this_profile(self):
        for raw in (json.dumps(record(self.command)).encode(), json.dumps(record(self.command)).encode() + b"\n"):
            with self.subTest(raw=raw[-1:]), self.assertRaises(recovery.ContinuationError):
                self.parse(raw)

    def test_failed_or_boolean_exit_is_never_completed_success(self):
        for exit_code in (1, 5, 8, False):
            changed = record(self.command)
            changed["exit"] = exit_code
            with self.subTest(exit_code=exit_code), self.assertRaises(recovery.ContinuationError):
                self.parse(json.dumps(changed).encode() + b"\n" + self.header[:30])

    def test_changed_transcript_pin_refuses(self):
        self.path.write_bytes(b"changed")
        with self.assertRaisesRegex(recovery.ContinuationError, "retained bytes changed"):
            recovery.transcript(self.path, "0" * 64)

    def test_wrong_next_retry_and_partial_receipt_are_refused(self):
        wrong = self.command.copy()
        wrong[-2] = "/fixture/original/entry-0003.json"
        for tail in (self.header[:-2], b'{"command": ["another-binary"', b"garbage",
                     self.header + b'"partial response'):
            with self.subTest(tail=tail), self.assertRaises(recovery.ContinuationError):
                recovery.retry_tail(tail, wrong)
        with self.assertRaises(recovery.ContinuationError):
            recovery.retry_tail(self.header + b'"partial response', self.command)


class ReceiptAndOrderGuards(unittest.TestCase):
    def test_fresh_post_requires_next_sequence_and_matching_envelope(self):
        valid = envelope("posted", 11)
        self.assertEqual(recovery.post_receipt(valid, 10, BOOK), valid["data"])
        for mutation in ("gap", "envelope", "event", "book", "digest"):
            value = deepcopy(valid)
            if mutation == "gap":
                value["data"]["recorded_at"] += 1
            elif mutation == "envelope":
                value["coordinate"]["known_at"] += 1
            elif mutation == "event":
                value["event"] = "recorded"
            elif mutation == "book":
                value["book"] = "4" * 32
            else:
                value["data"]["entry_digest"] = "bad"
            with self.subTest(mutation=mutation), self.assertRaises(recovery.ContinuationError):
                recovery.post_receipt(value, 10, BOOK)

    def test_retry_cannot_change_identity_or_publish_history(self):
        valid = envelope()
        recovery.retry_receipt(valid, valid["data"], BOOK, 12)
        for field in ("vid", "entry_digest", "recorded_at", "head", "event", "book"):
            changed = deepcopy(valid)
            if field == "head":
                changed["coordinate"]["known_at"] = 13
            elif field == "event":
                changed["event"] = "posted"
            elif field == "book":
                changed["book"] = "5" * 32
            else:
                changed["data"][field] = "altered"
            with self.subTest(field=field), self.assertRaises(recovery.ContinuationError):
                recovery.retry_receipt(changed, valid["data"], BOOK, 12)

    def test_prior_commands_are_matched_in_order_and_never_executed(self):
        prior, output = Path("/fixture/original"), Path("/fixture/continued")
        command = ["/not-an-executable", "--book", str(prior / "book"), "post", "--intent",
                   str(prior / "entry-0001.json"), "--json"]
        cursor = recovery.RecordedCommands([record(command)], prior, output)
        result = cursor.call("post", "--intent", output / "entry-0001.json")
        self.assertEqual(result, envelope())
        self.assertEqual(cursor.index, 1)
        with self.assertRaisesRegex(recovery.ContinuationError, "ends before"):
            cursor.call("post", "--intent", output / "entry-0002.json")

    def test_gapped_duplicate_or_wrong_intent_path_refuses(self):
        prior, output = Path("/fixture/original"), Path("/fixture/continued")
        command = ["/not-an-executable", "--book", str(prior / "book"), "post", "--intent",
                   str(prior / "entry-0002.json"), "--json"]
        for index in (1, 3):
            cursor = recovery.RecordedCommands([record(command)], prior, output)
            with self.subTest(index=index), self.assertRaisesRegex(recovery.ContinuationError, "order or intent"):
                cursor.call("post", "--intent", output / f"entry-{index:04}.json")
            self.assertEqual(cursor.index, 0)

    def test_copied_book_cannot_change_id_head_or_population(self):
        expected = {"event": "book", "book": BOOK, "coordinate": {"known_at": 12},
                    "data": {"book_id": BOOK, "accounts": 8, "periods": 390}}
        recovery.book_guard(deepcopy(expected), expected)
        for kind in ("book", "head", "population"):
            value = deepcopy(expected)
            if kind == "book":
                value["book"] = "6" * 32
            elif kind == "head":
                value["coordinate"]["known_at"] = 13
            else:
                value["data"]["accounts"] = 9
            with self.subTest(kind=kind), self.assertRaises(recovery.ContinuationError):
                recovery.book_guard(value, expected)


class PreservedCopyGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magnify-copy-guards-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.prior, self.copied = root / "prior", root / "copied"
        for directory in (self.prior, self.copied):
            (directory / "book").mkdir(parents=True)
            (directory / "book/book.keys").write_bytes(b"unit-test-only-not-real-keys")
            (directory / "commands.jsonl").write_bytes(b"unit-test-only-transcript")
            (directory / "failure.json").write_bytes(b"")
        entries = [{"path": name, **identity} for name, identity in recovery.file_inventory(self.prior).items()]
        self.record = {"status": "BYTE_IDENTICAL_COPY", "source": str(self.prior), "destination": str(self.copied),
                       "inventory": entries, "file_count": len(entries), "total_bytes": sum(item["bytes"] for item in entries)}
        self.path = root / "inventory.json"

    def check(self):
        self.path.write_text(json.dumps(self.record))
        return recovery.copy_guard(self.prior, self.copied, self.path, recovery.fingerprint(self.path)["sha256"])

    def test_exact_separate_copy_is_accepted(self):
        files, receipt = self.check()
        self.assertEqual(len(files), 3)
        self.assertEqual(receipt["file_count"], 3)

    def test_changed_copied_file_refuses(self):
        (self.copied / "commands.jsonl").write_bytes(b"changed")
        with self.assertRaisesRegex(recovery.ContinuationError, "not byte-identical"):
            self.check()

    def test_extra_original_file_refuses(self):
        (self.prior / "unexpected").write_bytes(b"unexpected")
        with self.assertRaisesRegex(recovery.ContinuationError, "original run differs"):
            self.check()

    def test_extra_copied_file_refuses(self):
        (self.copied / "unexpected").write_bytes(b"unexpected")
        with self.assertRaisesRegex(recovery.ContinuationError, "not byte-identical"):
            self.check()

    def test_repeated_or_escaping_inventory_path_refuses(self):
        for name in ("../outside", "/absolute", self.record["inventory"][0]["path"]):
            changed = deepcopy(self.record)
            self.record["inventory"].append({"path": name, "bytes": 0, "sha256": "0" * 64})
            with self.subTest(name=name), self.assertRaises(recovery.ContinuationError):
                self.check()
            self.record = changed

    def test_hardlinked_book_is_not_a_preserved_copy(self):
        # Use a new inventory with an additional shared file; no file replacement.
        source = self.prior / "book/shared"
        source.write_bytes(b"shared")
        os.link(source, self.copied / "book/shared")
        self.record["inventory"].append({"path": "book/shared", **recovery.fingerprint(source)})
        self.record["file_count"] += 1
        self.record["total_bytes"] += len(b"shared")
        with self.assertRaisesRegex(recovery.ContinuationError, "shares a file"):
            self.check()


class FailureRecordingGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magnify-failure-guards-")
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "output"
        self.arguments = ["check", "--prior", "/fixture/prior", "--copy", "/fixture/copy",
                          "--inventory", "/fixture/inventory", "--inventory-sha256", "0" * 64,
                          "--transcript-sha256", "0" * 64, "--out", str(self.output),
                          "--fa", "/fixture/fa", "--fa-verify", "/fixture/fa-verify"]

    def test_create_race_never_writes_into_an_unowned_output(self):
        def raced(_args, *, on_created):
            self.assertIsNotNone(on_created)
            self.output.mkdir()  # Simulate a different process winning creation.
            (self.output / "foreign-owner").write_bytes(b"preserve")
            raise FileExistsError("output was created by another invocation")

        stderr = io.StringIO()
        with patch.object(recovery, "prepare", side_effect=raced), redirect_stderr(stderr):
            self.assertEqual(recovery.main(self.arguments), 1)
        self.assertEqual([path.name for path in self.output.iterdir()], ["foreign-owner"])
        self.assertIn("another invocation", json.loads(stderr.getvalue())["error"])

    def test_secondary_enospc_preserves_partial_record_and_original_failure(self):
        def failed(_args, *, on_created):
            self.output.mkdir()
            on_created()
            raise RuntimeError("original native failure")

        def exhausted(path, _value):
            path.write_bytes(b'{"status":')
            raise OSError(28, "No space left on device")

        stderr = io.StringIO()
        with patch.object(recovery, "prepare", side_effect=failed), \
             patch.object(recovery, "write_json", side_effect=exhausted), redirect_stderr(stderr):
            self.assertEqual(recovery.main(self.arguments), 1)
        result = json.loads(stderr.getvalue())
        self.assertEqual(result["error"], "original native failure")
        self.assertIn("No space left", result["failure_record_error"])
        self.assertEqual((self.output / "continuation-failure.json").read_bytes(), b'{"status":')


if __name__ == "__main__":
    unittest.main()
