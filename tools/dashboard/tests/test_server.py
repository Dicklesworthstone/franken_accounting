"""Gateway/security and native-contract tests. Fixtures are not kernel tests."""
import copy
import http.client
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serve import DashboardError, DashboardServer, NativeSource, exact_transport, run_bounded, sequence
from demo import DemoSource


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.demo = DemoSource(DashboardError)
        self.source = NativeSource("/trusted/fa", Path("/fixed/book"), "operator", None, 2)

    @staticmethod
    def output(event, code=0):
        return code, json.dumps(event).encode(), b""

    def test_overview_pins_second_fold_to_first_coordinate(self):
        report = self.demo.overview("FY2026-P09", "HEAD")
        with patch("serve.run_bounded", side_effect=[self.output(report["stock"]), self.output(report["activity"])]) as run:
            result = self.source.overview("FY2026-P09", "HEAD")
            self.assertEqual(result["known_at"], str(self.demo.head))
            self.assertEqual(run.call_args_list[0].args[0][-1], "HEAD")
            self.assertEqual(run.call_args_list[1].args[0][-1], str(self.demo.head))
            for call in run.call_args_list:
                argv = call.args[0]
                self.assertEqual(argv[:3], ["/trusted/fa", "--book", "/fixed/book"])
                self.assertNotIn("--certify", argv)
                self.assertNotIn("--grant", argv)
                self.assertNotIn("--via", argv)  # keep the native lease/daemon routing

    def test_mixed_snapshot_refuses_instead_of_presenting_partial_overview(self):
        report = self.demo.overview("FY2026-P09", "HEAD")
        report["activity"]["coordinate"]["known_at"] += 1
        with patch("serve.run_bounded", side_effect=[self.output(report["stock"]), self.output(report["activity"])]):
            with self.assertRaises(DashboardError):
                self.source.overview("FY2026-P09", "HEAD")

    def test_different_book_on_same_path_requires_restart(self):
        first = self.demo.bootstrap()["book"]
        second = copy.deepcopy(first)
        second["book"] = "e" * 32
        with patch("serve.run_bounded", side_effect=[self.output(first), self.output(second)]):
            self.source.call(["book", "info"], "book")
            with self.assertRaises(DashboardError):
                self.source.call(["book", "info"], "book")

    def test_native_refusal_is_preserved_not_replaced_with_demo(self):
        error = {"v": 1, "event": "error", "data": {"message": "permission denied", "exit": 7, "fix": "Use authorized native access"}}
        with patch("serve.run_bounded", return_value=self.output(error, 7)):
            with self.assertRaises(DashboardError) as caught:
                self.source.bootstrap()
        self.assertEqual(caught.exception.detail["exit"], 7)

    def test_red_verification_is_a_red_report_even_without_a_success_event(self):
        error = {"v": 1, "event": "error", "data": {"message": "projection mismatch", "exit": 8, "detail": ["missing edge"]}}
        with patch("serve.run_bounded", return_value=self.output(error, 8)):
            result = self.source.projections()["report"]
        self.assertTrue(result["failed"])
        self.assertIsNone(result["data"])
        self.assertEqual(result["error"]["detail"], ["missing edge"])

    def test_exact_transport_preserves_128_bit_amounts_and_64_bit_sequences(self):
        data = {"known_at": 2**64 - 1, "mantissa": -(2**127), "good": True, "missing": None}
        result = exact_transport(data)
        self.assertEqual(result["known_at"], str(2**64 - 1))
        self.assertEqual(result["mantissa"], str(-(2**127)))
        self.assertIs(result["good"], True)
        self.assertIsNone(result["missing"])

    def test_unsupported_envelopes_and_numeric_encodings_fail_closed(self):
        valid = self.demo.bootstrap()["book"]
        candidates = [b"not json", b'{"v":1,"v":1,"event":"book","data":{}}',
                      b'{"v":1,"data":{"n":NaN}}', b'{"v":1,"data":{"n":1.5}}']
        for change in [{"v": 2}, {"v": True}, {"coordinate": None}, {"book": "foreign"}, {"data": []}]:
            candidates.append(json.dumps({**valid, **change}).encode())
        for output in candidates:
            with self.subTest(output=output[:80]), patch("serve.run_bounded", return_value=(0, output, b"")):
                with self.assertRaises(DashboardError):
                    self.source.call(["book", "info"], "book")

    def test_duplicate_expected_events_are_not_silently_selected(self):
        encoded = json.dumps(self.demo.bootstrap()["book"]).encode()
        with patch("serve.run_bounded", return_value=(0, encoded+b"\n"+encoded, b"")):
            with self.assertRaises(DashboardError):
                self.source.call(["book", "info"], "book")

    def test_sequence_rejects_negative_fractional_and_overflow(self):
        for value in ["-1", "1.0", "01", str(2**64), "--yes", "head"]:
            with self.subTest(value=value), self.assertRaises(DashboardError):
                sequence(value)
        self.assertEqual(sequence(str(2**64-1)), str(2**64-1))
        self.assertEqual(sequence("HEAD"), "HEAD")

    def test_native_process_captures_stdout_and_stderr_separately(self):
        code, out, err = run_bounded([sys.executable, "-c", "import sys;print('data');print('diagnostic',file=sys.stderr)"], 2)
        self.assertEqual((code, out, err), (0, b"data\n", b"diagnostic\n"))

    def test_native_process_output_is_bounded_during_read(self):
        with patch("serve.MAX_OUTPUT", 128), self.assertRaises(DashboardError) as caught:
            run_bounded([sys.executable, "-c", "print('x'*10000)"], 2)
        self.assertEqual(caught.exception.status, 413)

    def test_native_process_timeout_is_reported(self):
        with self.assertRaises(DashboardError) as caught:
            run_bounded([sys.executable, "-c", "import time;time.sleep(5)"], 0.05)
        self.assertEqual(caught.exception.status, 504)


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.server = DashboardServer(DemoSource(DashboardError), "Test book", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, *, auth=True, method="GET", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        values = {"Authorization": "Bearer " + self.server.token} if auth else {}
        values.update(headers or {})
        connection.request(method, path, headers=values)
        response = connection.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), body
        connection.close()
        return result

    def test_loopback_binding_and_private_api(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertEqual(self.request("/api/bootstrap", auth=False)[0], 401)
        status, _, body = self.request("/api/bootstrap")
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["mode"], "demo")
        self.assertIs(result["read_only"], True)
        self.assertIsInstance(result["book"]["coordinate"]["known_at"], str)

    def test_wrong_token_and_dns_rebinding_are_refused(self):
        self.assertEqual(self.request("/api/bootstrap", headers={"Authorization": "Bearer wrong"})[0], 401)
        self.assertEqual(self.request("/api/bootstrap", headers={"Host": "attacker.example"})[0], 403)

    def test_cross_origin_and_cross_site_are_refused(self):
        for headers in [{"Origin": "https://attacker.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}]:
            with self.subTest(headers=headers):
                self.assertEqual(self.request("/api/bootstrap", headers=headers)[0], 403)
        self.assertEqual(self.request("/api/bootstrap", headers={"Origin": self.server.origin})[0], 200)

    def test_no_write_or_arbitrary_command_surface(self):
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
            self.assertEqual(self.request("/api/overview", method=method)[0], 405)
        for path in ["/api/post", "/api/query", "/api/run", "/api/commit"]:
            self.assertEqual(self.request(path)[0], 404)

    def test_request_parameters_are_bounded_and_allowlisted(self):
        for path in ["/api/overview?period=FY2026-P09&book=elsewhere", "/api/overview?period=a&period=b",
                     "/api/overview?period=--yes", "/api/overview?period=x&known_at=-1", "/api/entry?vid=garbage",
                     "/api/health?grant=post", "/api/overview?period=%00", "/api/bootstrap?bad"]:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 400)

    def test_traversal_keys_and_directory_listing_are_not_routes(self):
        for path in ["/book.keys", "/../serve.py", "/%2e%2e/serve.py", "/web/", "/demo.py", "/serve.py"]:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)

    def test_security_headers_have_no_cors_or_cache(self):
        _, headers, _ = self.request("/api/bootstrap")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])

    def test_native_calls_are_serialized_instead_of_competing_for_the_writer(self):
        self.server.native_lock.acquire()
        try:
            self.assertEqual(self.request("/api/bootstrap")[0], 429)
        finally:
            self.server.native_lock.release()
        self.assertEqual(self.request("/api/bootstrap")[0], 200)

    def test_unknown_demo_selection_does_not_become_a_successful_empty_report(self):
        status, _, _ = self.request("/api/overview?period=not-a-period")
        self.assertEqual(status, 400)

    def test_overview_account_and_entry_paths_share_explicit_synthetic_mode(self):
        result = json.loads(self.request("/api/overview?period=FY2026-P09&known_at=150")[2])
        self.assertEqual(result["known_at"], "150")
        self.assertEqual(result["activity"]["coordinate"]["known_at"], "150")
        account = json.loads(self.request("/api/account?period=FY2026-P09&account=1000&known_at=157")[2])
        vid = account["report"]["data"]["contributions"][0]["entry"]
        detail = json.loads(self.request("/api/entry?vid="+vid)[2])
        self.assertEqual(detail["entry"]["data"]["vid"], vid)
        self.assertEqual(detail["mode"], "demo")

    @unittest.skipUnless(os.environ.get("FA_DASHBOARD_NATIVE_BOOK"), "Native book/binary not supplied; not a kernel integration run")
    def test_opt_in_existing_native_book_reports_share_snapshot(self):
        source = NativeSource(os.environ.get("FA_DASHBOARD_FA", "fa"),
                              Path(os.environ["FA_DASHBOARD_NATIVE_BOOK"]), "operator", None, 30)
        first = source.bootstrap()
        periods = first["periods"]["data"]["periods"]
        self.assertTrue(periods, "provide an existing book with a fiscal period")
        report = source.overview(periods[0]["code"], str(first["book"]["coordinate"]["known_at"]))
        self.assertEqual(report["stock"]["data"]["known_at"], report["activity"]["data"]["known_at"])


if __name__ == "__main__":
    unittest.main()
