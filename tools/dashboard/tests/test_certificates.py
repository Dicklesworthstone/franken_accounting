import http.client
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import certificates
from demo import DemoSource
from serve import DashboardError, DashboardServer


class FakeLive:
    mode = "live"
    def __init__(self):
        self.calls = []
    def call(self, argv, event):
        self.calls.append(("call", argv, event))
        oid = argv[-1].removeprefix("C:")
        return {"v": 1, "event": "certificate_status", "book": "b"*32, "certificate": oid,
                "coordinate": {"branch": "trunk", "known_at": 44, "effective": "period:FY2026-P09"},
                "data": {"oid": oid, "status": "SupersededBy", "known_at": 31, "checked_at": 44,
                         "later_entries": ["1"*32], "replay_scope": "fa-fold-over-prefix",
                         "authority": "embedded-owner"}}
    def call_one_of(self, argv, events):
        self.calls.append(("any", argv, events))
        oid = argv[-1].removeprefix("C:")
        return {"v": 1, "event": "trial_balance", "book": "b"*32, "certificate": oid,
                "coordinate": {"branch": "trunk", "known_at": 31, "effective": "period:FY2026-P09"},
                "data": {"known_at": 31, "rows": [], "balanced": True}}


class CertificateContractTests(unittest.TestCase):
    def test_certificate_ids_accept_optional_handle_prefix_and_normalize_case(self):
        value = "Ab" * 32
        self.assertEqual(certificates.certificate_oid("C:" + value, DashboardError), value.lower())
        self.assertEqual(certificates.certificate_oid(value, DashboardError), value.lower())

    def test_certificate_ids_fail_closed(self):
        for value in [None, "", "C:abc", "g"*64, "a"*63, "--yes", "a"*65]:
            with self.subTest(value=value), self.assertRaises(DashboardError):
                certificates.certificate_oid(value, DashboardError)

    def test_live_status_uses_retained_certificate_command_and_preserves_later_entries(self):
        source = FakeLive()
        oid = "a"*64
        result = certificates.dispatch(source, "/api/certificate-status", {"oid": oid}, DashboardError)
        self.assertEqual(source.calls, [("call", ["certificate", "status", "C:"+oid], "certificate_status")])
        self.assertEqual(result["status"]["data"]["later_entries"], ["1"*32])

    def test_live_replay_runs_once_and_accepts_only_supported_report_events(self):
        source = FakeLive()
        oid = "b"*64
        result = certificates.dispatch(source, "/api/certificate-replay", {"oid": oid}, DashboardError)
        self.assertEqual(result["replay"]["event"], "trial_balance")
        kind, argv, events = source.calls[0]
        self.assertEqual((kind, argv), ("any", ["replay", "C:"+oid]))
        self.assertEqual(events, certificates.REPLAY_EVENTS)

    def test_native_identity_mismatch_is_refused(self):
        source = FakeLive()
        original = source.call
        def wrong(argv, event):
            value = original(argv, event)
            value["data"]["oid"] = "f"*64
            return value
        source.call = wrong
        with self.assertRaises(DashboardError) as caught:
            certificates.dispatch(source, "/api/certificate-status", {"oid": "a"*64}, DashboardError)
        self.assertEqual(caught.exception.status, 409)

    def test_demo_status_and_replay_are_explicitly_synthetic(self):
        source = DemoSource(DashboardError)
        oid = "a"*64
        status = certificates.dispatch(source, "/api/certificate-status", {"oid": oid}, DashboardError)["status"]
        replay = certificates.dispatch(source, "/api/certificate-replay", {"oid": oid}, DashboardError)["replay"]
        self.assertEqual(status["data"]["authority"], "synthetic-demo")
        self.assertIn("Synthetic", replay["warnings"][0])
        self.assertEqual(replay["certificate"], oid)


class CertificateHttpTests(unittest.TestCase):
    def setUp(self):
        self.server = DashboardServer(DemoSource(DashboardError), "Certificate test", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
    def request(self, path, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        conn.request(method, path, headers={"Authorization": "Bearer " + self.server.token})
        response = conn.getresponse(); body = response.read(); status = response.status; headers = dict(response.getheaders()); conn.close()
        return status, headers, body

    def test_certificate_assets_and_private_routes_are_served(self):
        for path, mime in [("/proofs.html","text/html"),("/proofs.mjs","text/javascript"),("/proofs.css","text/css")]:
            status, headers, _ = self.request(path)
            self.assertEqual(status, 200)
            self.assertIn(mime, headers["Content-Type"])
        self.assertEqual(self.request("/api/certificate-status?oid="+"a"*64)[0], 200)
        self.assertEqual(self.request("/api/certificate-replay?oid="+"a"*64)[0], 200)

    def test_unknown_parameters_invalid_ids_and_write_methods_are_refused(self):
        self.assertEqual(self.request("/api/certificate-status?oid="+"a"*64+"&grant=read")[0], 400)
        self.assertEqual(self.request("/api/certificate-status?oid=bad")[0], 400)
        self.assertEqual(self.request("/api/certificate-status?oid="+"a"*64, "POST")[0], 405)


if __name__ == "__main__":
    unittest.main()
