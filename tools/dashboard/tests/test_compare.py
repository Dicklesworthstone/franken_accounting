"""Native-response contract fixtures and a real loopback listener; not kernel oracles."""
import copy
import http.client
import json
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compare import compare
from demo import DemoSource
from serve import DashboardError, DashboardServer, exact_transport


class NativeFixture:
    mode = "live"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def call(self, argv, event):
        self.calls.append((argv, event))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class CompareContract(unittest.TestCase):
    def setUp(self):
        self.demo = DemoSource(DashboardError)
        self.left = self.demo.tb("FY2026-P09", 151, False)
        self.right = self.demo.tb("FY2026-P09", 157, False)
        self.params = {"period": "FY2026-P09", "before": "151", "after": "HEAD"}

    def test_resolves_right_once_then_reads_explicit_left_without_any_write_flags(self):
        source = NativeFixture([self.right, self.left])
        result = compare(source, self.params, DashboardError)
        self.assertEqual((result["before_known_at"], result["after_known_at"]), (151, 157))
        self.assertEqual(source.calls, [
            (["tb", "--period", "FY2026-P09", "--as-known-at", "HEAD"], "trial_balance"),
            (["tb", "--period", "FY2026-P09", "--as-known-at", "151"], "trial_balance")])
        self.assertEqual(result["before"]["data"]["rows"], self.left["data"]["rows"])

    def test_equal_snapshots_are_one_native_read_not_a_synthetic_empty_diff(self):
        source = NativeFixture([self.right])
        result = compare(source, {**self.params, "before": "157"}, DashboardError)
        self.assertIs(result["before"], result["after"])
        self.assertEqual(len(source.calls), 1)

    def test_second_refusal_aborts_the_whole_response(self):
        source = NativeFixture([self.right, DashboardError("history unavailable", 502)])
        with self.assertRaisesRegex(DashboardError, "history unavailable"):
            compare(source, self.params, DashboardError)

    def test_malformed_selectors_refuse_before_native_io(self):
        for changes in [{"before": "HEAD"}, {"before": "-1"}, {"before": "1.0"},
                        {"after": str(2**64)}, {"before": "158", "after": "157"},
                        {"period": "one,two"}, {"period": "--certify"}, {"book": "other"},
                        {"period": "p\x7f"}, {"before": ""}]:
            with self.subTest(changes=changes):
                source = NativeFixture([])
                with self.assertRaises(DashboardError):
                    compare(source, {**self.params, **changes}, DashboardError)
                self.assertFalse(source.calls)

    def test_future_left_stops_after_resolving_head(self):
        source = NativeFixture([self.right])
        with self.assertRaises(DashboardError):
            compare(source, {**self.params, "before": "158"}, DashboardError)
        self.assertEqual(len(source.calls), 1)

    def test_source_coordinates_periods_and_modes_are_not_silently_relabelled(self):
        attacks = [lambda x: x.update(book="e"*32),
                   lambda x: x["coordinate"].update(known_at=150),
                   lambda x: x["coordinate"].update(branch="scenario"),
                   lambda x: x["data"].update(activity=True),
                   lambda x: x["data"].update(periods=["FY2026-P08"]),
                   lambda x: x["data"].update(effective_through="2026-09-29"),
                   lambda x: x["data"].update(mode="other"),
                   lambda x: x["data"].update(rows=None),
                   lambda x: x["data"].update(balanced="true")]
        for attack in attacks:
            left = copy.deepcopy(self.left)
            attack(left)
            with self.subTest(left=left), self.assertRaises(DashboardError):
                compare(NativeFixture([self.right, left]), self.params, DashboardError)

    def test_red_native_verdict_is_preserved_not_promoted_to_green(self):
        left = copy.deepcopy(self.left)
        left["data"]["balanced"] = False
        result = compare(NativeFixture([self.right, left]), self.params, DashboardError)
        self.assertIs(result["before"]["data"]["balanced"], False)

    def test_full_u64_sequences_travel_without_a_float(self):
        left, right = copy.deepcopy(self.left), copy.deepcopy(self.right)
        for event, seq in [(left, 2**64-2), (right, 2**64-1)]:
            event["coordinate"]["known_at"] = event["data"]["known_at"] = seq
        result = exact_transport(compare(NativeFixture([right, left]),
                                         {**self.params, "before": str(2**64-2)}, DashboardError))
        self.assertEqual(result["after_known_at"], str(2**64-1))

    def test_demo_uses_the_existing_explicit_demo_snapshots(self):
        result = compare(self.demo, self.params, DashboardError)
        self.assertEqual(result["before"], self.left)
        self.assertEqual(result["after"], self.right)
        self.assertTrue(result["before"]["warnings"])


class CompareHTTP(unittest.TestCase):
    def setUp(self):
        self.server = DashboardServer(DemoSource(DashboardError), "Synthetic", 0)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, suffix="", *, headers=None, token=True, method="GET"):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        hdr = {"Authorization": "Bearer " + self.server.token} if token else {}
        hdr.update(headers or {})
        client.request(method, "/api/compare?period=FY2026-P09&before=151" + suffix, headers=hdr)
        reply = client.getresponse()
        status, body = reply.status, json.loads(reply.read())
        client.close()
        return status, body

    def test_private_route_returns_two_scoped_snapshots(self):
        status, body = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(body["before_known_at"], "151")
        self.assertEqual(body["after_known_at"], "157")
        self.assertEqual(body["mode"], "demo")
        self.assertTrue(body["read_only"])

    def test_comparison_cannot_bypass_session_or_origin_or_method_gates(self):
        for opts in [{"token": False}, {"headers": {"Origin": "https://other.invalid"}},
                     {"headers": {"Host": "other.invalid"}}, {"method": "POST"}]:
            with self.subTest(opts=opts):
                self.assertIn(self.request(**opts)[0], (401, 403, 405))

    def test_duplicate_unknown_and_option_parameters_refuse(self):
        for suffix in ["&before=150", "&after=--certify", "&command=post", "&known_at=1"]:
            with self.subTest(suffix=suffix):
                self.assertEqual(self.request(suffix)[0], 400)


if __name__ == "__main__":
    unittest.main()
