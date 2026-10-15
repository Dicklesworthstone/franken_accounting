"""Native-API contract and real HTTP tests, not accounting-kernel integration."""
import copy
import http.client
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo import DemoSource
from reports import dispatch, expected_bands, select
from serve import DashboardError, DashboardServer, NativeSource

LEDGER = {"account": "1000", "unit": "USD", "from": "2026-09-01", "to": "2026-09-30", "known_at": "HEAD"}
AGING = {"account": "1100", "as_of": "2026-09-30", "buckets": "30,60,90", "known_at": "HEAD"}


class ReportContracts(unittest.TestCase):
    def setUp(self):
        self.demo = DemoSource(DashboardError)
        self.native = NativeSource("/trusted/fa", Path("/trusted/book"), "operator", None, 2)

    def fixture(self, path, params):
        return dispatch(self.demo, path, params, DashboardError)

    @staticmethod
    def output(event):
        return 0, json.dumps(event).encode(), b""

    def test_ledger_calls_only_native_detail_with_explicit_scope(self):
        event = self.fixture("/api/ledger", LEDGER)["report"]
        with patch("serve.run_bounded", return_value=self.output(event)) as execute:
            result = dispatch(self.native, "/api/ledger", LEDGER, DashboardError)
        self.assertEqual(result["report"], event)
        self.assertEqual(execute.call_args.args[0][8:], ["detail", "--account", "1000", "--unit", "USD", "--from", "2026-09-01", "--to", "2026-09-30", "--as-known-at", "HEAD"])
        self.assertNotIn("--certify", execute.call_args.args[0])
        self.assertNotIn("--grant", execute.call_args.args[0])

    def test_aging_reconciliation_is_pinned_to_first_report_not_head(self):
        fixture = self.fixture("/api/aging", AGING)
        with patch("serve.run_bounded", side_effect=[self.output(fixture["report"]), self.output(fixture["reconciliation"])]) as execute:
            result = dispatch(self.native, "/api/aging", AGING, DashboardError)
        calls = [c.args[0] for c in execute.call_args_list]
        self.assertEqual(calls[0][-1], "HEAD")
        self.assertEqual(calls[1][-3:], ["--as-known-at", str(self.demo.head), "--reconcile"])
        self.assertEqual(calls[0].count("--bucket"), 3)
        self.assertEqual(result["report"]["data"]["known_at"], result["reconciliation"]["data"]["known_at"])

    def test_red_reconciliation_is_preserved_without_an_invented_zero(self):
        fixture = self.fixture("/api/aging", AGING)
        fixture["reconciliation"]["data"]["reconciled"] = False
        fixture["reconciliation"]["data"]["rows"][0]["difference"] = "0.01 USD"
        with patch("serve.run_bounded", side_effect=[self.output(fixture["report"]), self.output(fixture["reconciliation"])]):
            result = dispatch(self.native, "/api/aging", AGING, DashboardError)
        self.assertIs(result["reconciliation"]["data"]["reconciled"], False)
        self.assertEqual(result["reconciliation"]["data"]["rows"][0]["difference"], "0.01 USD")

    def test_refused_reconciliation_does_not_publish_partial_success(self):
        fixture = self.fixture("/api/aging", AGING)
        failure = {"v": 1, "event": "error", "data": {"exit": 8, "message": "native mismatch", "detail": {"difference": 1}}}
        with patch("serve.run_bounded", side_effect=[self.output(fixture["report"]), (8, json.dumps(failure).encode(), b"")]):
            with self.assertRaises(DashboardError) as caught:
                dispatch(self.native, "/api/aging", AGING, DashboardError)
        self.assertEqual(caught.exception.detail["exit"], 8)

    def test_ledger_rejects_wrong_account_unit_dates_and_duplicate_cells(self):
        original = self.fixture("/api/ledger", LEDGER)["report"]
        mutations = [lambda b: b.update(effective_from="2026-08-01"),
                     lambda b: b.update(effective_through="2026-10-01"),
                     lambda b: b["lines"][0].update(account="2000"),
                     lambda b: b["cells"][0].update(unit="EUR"),
                     lambda b: b["cells"].append(copy.deepcopy(b["cells"][0])),
                     lambda b: b.update(lines=None)]
        for mutate in mutations:
            event = copy.deepcopy(original)
            mutate(event["data"])
            with self.subTest(mutation=mutate), patch("serve.run_bounded", return_value=self.output(event)):
                with self.assertRaises(DashboardError):
                    dispatch(self.native, "/api/ledger", LEDGER, DashboardError)

    def test_aging_rejects_mixed_snapshot_account_cutoff_and_bands(self):
        original = self.fixture("/api/aging", AGING)
        for field, value in [("known_at", 1), ("account", "2000"), ("effective_through", "2026-10-01"), ("bands", []), ("reconciled", "true")]:
            fixture = copy.deepcopy(original)
            fixture["reconciliation"]["data"][field] = value
            with self.subTest(field=field), patch("serve.run_bounded", side_effect=[self.output(fixture["report"]), self.output(fixture["reconciliation"])]):
                with self.assertRaises(DashboardError):
                    dispatch(self.native, "/api/aging", AGING, DashboardError)

    def test_invalid_selectors_refuse_before_any_native_process(self):
        bad = [("/api/ledger", {**LEDGER, key: value}) for key, value in
               [("from", "2026-02-30"), ("to", "2026-01-01"), ("unit", "USD,EUR"), ("unit", "USD EUR"),
                ("account", "1000,2000"), ("account", "--grant"), ("known_at", str(2**64)), ("from", "20260901")]]
        bad += [("/api/aging", {**AGING, "buckets": value}) for value in ["", "30,30", "60,30", "-1", "1.5", "1e2", ",30", "0,1,2,3,4,5,6,7,8,9,10,11,12"]]
        with patch("serve.run_bounded") as execute:
            for path, params in bad:
                with self.subTest(path=path, params=params), self.assertRaises(DashboardError):
                    dispatch(self.native, path, params, DashboardError)
            execute.assert_not_called()

    def test_calendar_validation_accepts_leap_days_without_wall_clock(self):
        selection = select("/api/ledger", {**LEDGER, "from": "2024-02-29", "to": "2024-02-29"}, DashboardError)
        self.assertEqual(selection["start"], "2024-02-29")
        self.assertEqual(expected_bands([0, 30]), [{"lower_inclusive": 0, "upper_inclusive": 0},
            {"lower_inclusive": 1, "upper_inclusive": 30}, {"lower_inclusive": 31, "upper_inclusive": None}])

    def test_empty_ledger_is_success_without_synthetic_values(self):
        event = self.fixture("/api/ledger", LEDGER)["report"]
        event["data"].update(cells=[], lines=[])
        with patch("serve.run_bounded", return_value=self.output(event)):
            result = dispatch(self.native, "/api/ledger", LEDGER, DashboardError)
        self.assertEqual(result["report"]["data"]["cells"], [])

    def test_demo_running_balance_and_aging_use_the_existing_sample_only(self):
        from decimal import Decimal
        parse = lambda value: Decimal(value.split(" ")[0])
        report = self.fixture("/api/ledger", LEDGER)["report"]["data"]
        cell = report["cells"][0]
        running = parse(cell["opening"])
        for line in report["lines"]:
            running += parse(line["debits"]) - parse(line["credits"])
            self.assertEqual(parse(line["running_balance"]), running)
        self.assertEqual(parse(cell["closing"]), running)
        aging = self.fixture("/api/aging", AGING)["report"]["data"]
        self.assertTrue(any(i["side"] == "Credit" for i in aging["items"]))
        self.assertTrue(any(i["side"] == "Debit" for i in aging["items"]))
        self.assertTrue(all(i["applied"] == "0.00 USD" for i in aging["items"]), "sample has no settlement links")
        historical = self.fixture("/api/ledger", {**LEDGER, "known_at": "110"})["report"]["data"]
        self.assertEqual(historical["lines"], [])


class ReportHttp(unittest.TestCase):
    def setUp(self):
        self.server = DashboardServer(DemoSource(DashboardError), "Report test", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path, auth=True, method="GET", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        values = {"Authorization": "Bearer " + self.server.token} if auth else {}
        values.update(headers or {})
        connection.request(method, path, headers=values)
        response = connection.getresponse()
        body = response.read()
        status = response.status
        connection.close()
        return status, json.loads(body)

    def test_new_routes_use_real_private_http_and_exact_integer_transport(self):
        for path in ["/api/ledger?account=1000&unit=USD&from=2026-09-01&to=2026-09-30", "/api/aging?account=1100&as_of=2026-09-30"]:
            with self.subTest(path=path):
                self.assertEqual(self.request(path, auth=False)[0], 401)
                status, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(body["mode"], "demo")
                self.assertIsInstance(body["report"]["coordinate"]["known_at"], str)
                self.assertIs(body["read_only"], True)

    def test_new_routes_keep_no_write_no_authority_and_no_file_input_contract(self):
        for path in ["/api/ledger?account=1000&book=other", "/api/aging?account=1100&grant=post",
                     "/api/aging?account=1100&as_of=2026-09-30&keys=secret", "/api/aging?account=1100&account=2000"]:
            self.assertEqual(self.request(path)[0], 400)
        self.assertEqual(self.request("/api/ledger", method="POST")[0], 405)
        self.assertEqual(self.request("/api/aging", headers={"Origin": "https://other.example"})[0], 403)
        self.assertEqual(self.request("/api/aging", headers={"Host": "other.example"})[0], 403)

    def test_malformed_and_unavailable_reports_do_not_return_success(self):
        for path in ["/api/ledger", "/api/aging?account=1100&as_of=invalid",
                     "/api/ledger?account=missing&unit=USD&from=2026-09-01&to=2026-09-30"]:
            self.assertEqual(self.request(path)[0], 400)

    def test_new_routes_share_native_serialization(self):
        self.server.native_lock.acquire()
        try:
            self.assertEqual(self.request("/api/aging?account=1100&as_of=2026-09-30")[0], 429)
        finally:
            self.server.native_lock.release()


if __name__ == "__main__":
    unittest.main()
