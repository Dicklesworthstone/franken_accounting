"""Real local HTTP asset delivery; no browser/CSP execution claim."""
import http.client
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo import DemoSource
from serve import DashboardError, DashboardServer


class ReportAssets(unittest.TestCase):
    def setUp(self):
        self.server = DashboardServer(DemoSource(DashboardError), "Asset test", 0)
        self.worker = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": .01}, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def request(self, path, **headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_exact_report_assets_are_delivered_without_inline_script_permission(self):
        for path, mime in [("/reports.html", "text/html"), ("/reporting.mjs", "text/javascript"),
                           ("/report-model.mjs", "text/javascript"), ("/reports.css", "text/css")]:
            with self.subTest(path=path):
                status, headers, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertTrue(headers["Content-Type"].startswith(mime))
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
                self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
                self.assertEqual(int(headers["Content-Length"]), len(body))
                self.assertGreater(len(body), 100)

    def test_existing_dashboard_links_to_both_read_only_workspaces(self):
        status, _, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b'href="/reports.html#ledger"', body)
        self.assertIn(b'href="/reports.html#aging"', body)
        self.assertIn(b'src="/app.js"', body)  # the existing overview remains intact

    def test_report_assets_keep_host_validation_and_have_no_directory_or_source_route(self):
        self.assertEqual(self.request("/reports.html", Host="attacker.example")[0], 403)
        self.assertEqual(self.request("/reports.html", Origin="https://attacker.example")[0], 403)
        self.assertEqual(self.request("/reports.html?book=other")[0], 400)
        for path in ["/reports.py", "/demo_reports.py", "/tests/", "/web/", "/%2e%2e/reports.py"]:
            self.assertEqual(self.request(path)[0], 404)


if __name__ == "__main__":
    unittest.main()
