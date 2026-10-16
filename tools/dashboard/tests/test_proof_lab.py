import http.client
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proof_lab
from demo import DemoSource
from serve import DashboardError, DashboardServer


class FakeLive:
    mode = "live"
    def __init__(self): self.calls=[]
    def call(self, argv, event, verification=False):
        self.calls.append((argv,event,verification))
        if event == "accumulator_verified":
            return {"event":"accumulator_verified","coordinate":{"branch":"trunk","known_at":50},
                    "data":{"status":"verified","signatures":"ed25519","scope":"entry_prefix","states_checked":1,
                            "broken":None,"verified_through":49,"states":[{"oid":"a"*64,"through_seq":49,
                            "recorded_at":50,"leaf_count":7,"finding":None}],"unchained":[]}}
        return {"event":"proof_exported","coordinate":{"branch":"trunk","known_at":50},
                "data":{"kind":argv[1],"state_oid":"a"*64,"bytes":"00","byte_len":1}}


class ProofLabContractTests(unittest.TestCase):
    def test_inclusion_is_tightly_scoped(self):
        s=proof_lab.select({"kind":"inclusion","state":"a"*64,"entry":"E:"+"1"*32,"with_record":"1"},DashboardError)
        self.assertEqual(s["argv"],["proof","inclusion","--state","a"*64,"--entry","1"*32,"--with-record"])
        for bad in [{"kind":"inclusion","state":"latest","entry":"x"},
                    {"kind":"inclusion","state":"latest","entry":"1"*32,"with_record":"yes"},
                    {"kind":"prefix","state":"latest","entry":"1"*32}]:
            with self.subTest(bad=bad),self.assertRaises(DashboardError): proof_lab.select(bad,DashboardError)

    def test_balance_accepts_one_account_unit_and_optional_date(self):
        s=proof_lab.select({"kind":"balance","state":"latest","account":"1000","unit":"USD","as_of":"2026-09-30"},DashboardError)
        self.assertEqual(s["argv"],["proof","balance","--state","latest","--account","1000","--unit","USD","--as-of","2026-09-30"])
        with self.assertRaises(DashboardError): proof_lab.select({"kind":"balance","account":"1000,2000","unit":"USD"},DashboardError)

    def test_checkpoint_chain_uses_native_verifier_without_writes(self):
        source=FakeLive();result=proof_lab.dispatch(source,"/api/checkpoints",{},DashboardError)
        self.assertEqual(result["report"]["data"]["states_checked"],1)
        self.assertEqual(source.calls,[(["verify","accumulator"],"accumulator_verified",True)])

    def test_proof_export_validates_kind_and_explicit_state(self):
        source=FakeLive();oid="a"*64
        result=proof_lab.dispatch(source,"/api/proof-export",{"kind":"prefix","state":oid},DashboardError)
        self.assertEqual(result["proof"]["data"]["kind"],"prefix")
        self.assertEqual(source.calls[-1][0],["proof","prefix","--state",oid])

    def test_demo_proof_is_explicitly_synthetic(self):
        source=DemoSource(DashboardError)
        chain=proof_lab.dispatch(source,"/api/checkpoints",{},DashboardError)["report"]
        proof=proof_lab.dispatch(source,"/api/proof-export",{"kind":"prefix","state":"latest"},DashboardError)["proof"]
        self.assertEqual(chain["data"]["signatures"],"ed25519")
        self.assertEqual(proof["data"]["trust"],"synthetic_demo_only")
        self.assertIn("Synthetic proof",proof["warnings"][0])


class ProofLabHttpTests(unittest.TestCase):
    def setUp(self):
        self.server=DashboardServer(DemoSource(DashboardError),"Proof test",0)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={"poll_interval":.01},daemon=True);self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
    def request(self,path,method="GET"):
        c=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=3)
        c.request(method,path,headers={"Authorization":"Bearer "+self.server.token});r=c.getresponse();body=r.read();status=r.status;headers=dict(r.getheaders());c.close();return status,headers,body
    def test_assets_and_private_routes(self):
        for path,mime in [("/proof-lab.html","text/html"),("/proof-lab.mjs","text/javascript"),("/proof-lab.css","text/css")]:
            status,headers,_=self.request(path);self.assertEqual(status,200);self.assertIn(mime,headers["Content-Type"])
        self.assertEqual(self.request("/api/checkpoints")[0],200)
        self.assertEqual(self.request("/api/proof-export?kind=prefix&state=latest")[0],200)
    def test_browser_cannot_smuggle_output_paths_or_irrelevant_args(self):
        self.assertEqual(self.request("/api/proof-export?kind=prefix&state=latest&out=/tmp/x")[0],400)
        self.assertEqual(self.request("/api/proof-export?kind=signed-checkpoint&state=latest&entry="+"1"*32)[0],400)
        self.assertEqual(self.request("/api/proof-export?kind=prefix&state=latest","POST")[0],405)


if __name__=="__main__": unittest.main()
