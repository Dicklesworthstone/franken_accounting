"""Real local HTTP asset tests, not a browser module-loader or native-book test."""
import http.client
from pathlib import Path
import re
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo import DemoSource
from serve import DashboardError, DashboardServer, ROOT


class WorkbenchAssets(unittest.TestCase):
    def setUp(self):
        self.server=DashboardServer(DemoSource(DashboardError), "Synthetic", 0)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={"poll_interval": .01},daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, path, headers=None):
        connection=http.client.HTTPConnection("127.0.0.1", self.server.server_port,timeout=3)
        connection.request("GET",path,headers=headers or {})
        response=connection.getresponse()
        result=response.status,dict(response.getheaders()),response.read()
        connection.close()
        return result

    def test_default_route_serves_the_connected_workbench_not_a_static_mockup(self):
        status,headers,html=self.request("/")
        self.assertEqual(status,200)
        self.assertIn("text/html",headers["Content-Type"])
        self.assertEqual(html,(ROOT/"web/index.html").read_bytes())
        text=html.decode()
        self.assertIn('src="/workbench.mjs"',text)
        self.assertIn('href="/workbench.css"',text)
        for view in ["overview","ledger","aging","compare","graph","periods","health"]:
            self.assertIn('data-view="'+view+'"',text)
        self.assertIn('href="/reports.html#ledger"',text)
        self.assertIn('href="/reports.html#aging"',text)

    def test_all_new_module_assets_have_exact_bytes_and_javascript_mime(self):
        for filename in ["workbench.mjs","workbench-model.mjs","graph-layout.mjs"]:
            with self.subTest(filename=filename):
                status,headers,data=self.request("/"+filename)
                self.assertEqual(status,200)
                self.assertIn("javascript",headers["Content-Type"])
                self.assertEqual(data,(ROOT/"web"/filename).read_bytes())
                self.assertEqual(headers["X-Content-Type-Options"],"nosniff")
        status,headers,data=self.request("/workbench.css")
        self.assertEqual(status,200)
        self.assertIn("text/css",headers["Content-Type"])
        self.assertEqual(data,(ROOT/"web/workbench.css").read_bytes())

    def test_workbench_does_not_require_csp_relaxation_or_cross_origin_assets(self):
        _,headers,html=self.request("/")
        self.assertEqual(headers["Cache-Control"],"no-store")
        policy=headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'",policy)
        self.assertIn("style-src 'self'",policy)
        self.assertIn("frame-ancestors 'none'",policy)
        self.assertNotIn("unsafe-inline",policy)
        self.assertNotIn("unsafe-eval",policy)
        self.assertNotIn("Access-Control-Allow-Origin",headers)
        self.assertNotRegex(html.decode(),r'(?:src|href)="https?://')

    def test_new_assets_do_not_open_directory_or_arbitrary_file_access(self):
        for path in ["/compare.py","/workbench.mjs?book=other","/web/workbench.mjs","/../compare.py"]:
            with self.subTest(path=path):
                self.assertIn(self.request(path)[0],(400,404))
        self.assertEqual(self.request("/workbench.mjs",{"Host":"elsewhere.invalid"})[0],403)
        self.assertEqual(self.request("/workbench.css",{"Origin":"https://elsewhere.invalid"})[0],403)

    def test_all_direct_local_esm_imports_are_in_the_allowlisted_asset_graph(self):
        from serve import STATIC
        visited=set()
        def visit(filename):
            if filename in visited:
                return
            visited.add(filename)
            source=(ROOT/"web"/filename).read_text()
            for imported in re.findall(r"^import .* from ['\"]\./([^'\"]+)['\"];",source,re.M):
                self.assertIn("/"+imported,STATIC)
                self.assertTrue((ROOT/"web"/imported).is_file())
                visit(imported)
        visit("workbench.mjs")
        self.assertEqual(visited,{"workbench.mjs","workbench-model.mjs","graph-layout.mjs","amounts.mjs","report-model.mjs"})


if __name__=="__main__":
    unittest.main()
