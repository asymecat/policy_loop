"""Tests for the PolicyLoop Web UI backend (stdlib server + analyze API)."""

import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from policy_loop.agents.demo import SCENARIOS
from webui import server as ws

SMALL = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "sample_policy.te"
XPERM = SCENARIOS[0][1]   # media_service ioctl 0x6412 -> XPERM_GAP


class TestWebUI(unittest.TestCase):
    def test_analyze_case_structure(self):
        ws.get_index(str(SMALL))
        out = ws.analyze_case(XPERM, str(SMALL))
        self.assertEqual(out["classification"], "XPERM_GAP")
        self.assertIn("0x6412", out["patch"])
        self.assertEqual(out["verify"]["status"], "SUCCESS")
        agents = {t["agent"] for t in out["trace"]}
        for a in ("LogAgent", "PolicyAgent", "SecurityAgent",
                  "RepairAgent", "ReviewerAgent", "VerifyAgent"):
            self.assertIn(a, agents)
        self.assertTrue(out["explanation"])

    def test_http_meta_and_analyze(self):
        ws.get_index(str(SMALL))
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), ws.Handler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            meta = json.loads(urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/meta").read())
            self.assertGreaterEqual(len(meta["scenarios"]), 3)

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/analyze",
                data=json.dumps({"denial": XPERM,
                                 "policy": str(SMALL)}).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            data = json.loads(urllib.request.urlopen(req).read())
            self.assertTrue(data["ok"])
            self.assertEqual(data["case"]["classification"], "XPERM_GAP")
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
