"""Integration test: demo verdict path over a real-format denial."""

import unittest
from pathlib import Path

from policy_loop.denial import parse
from policy_loop.demo import _verdict_label
from policy_loop.policy import load_text

ROOT = Path(__file__).resolve().parents[1]
POLICY = (ROOT / "data" / "fixtures" / "sample_policy.te").read_text(
    encoding="utf-8")


class TestDemoVerdict(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(POLICY)

    def _deny(self, text):
        return parse(text)[0]

    def test_xperm_gap_detected(self):
        d = self._deny(
            'avc: denied { ioctl } for pid=7881, comm="/system/bin/media_service" '
            'path="/dev/camera/video0" dev="" ino=23 ioctlcmd=0x6412 '
            "scontext=u:r:media_service:s0 "
            "tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file permissive=1"
        )
        verdict = _verdict_label(self.idx, d)
        self.assertIn("XPERM_GAP", verdict)
        self.assertIn("0x6412", verdict)

    def test_neverallow_flagged(self):
        d = self._deny(
            'avc: denied { read } for pid=9999 comm="evil" '
            "scontext=u:r:normal_hap:s0 tcontext=u:object_r:dev_bbox:s0 "
            "tclass=chr_file permissive=1"
        )
        verdict = _verdict_label(self.idx, d)
        self.assertIn("neverallow", verdict)

    def test_raw_excludes_interleaved_comments(self):
        text = (
            "avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:one:s0 "
            "tcontext=u:object_r:two:s0 tclass=file permissive=1\n"
            "# comment line before next event\n"
            'avc: denied { write } for pid=2 comm="b" scontext=u:r:three:s0 '
            "tcontext=u:object_r:four:s0 tclass=file permissive=0"
        )
        recs = parse(text)
        self.assertEqual(len(recs), 2)
        self.assertNotIn("# comment", recs[0].raw)


if __name__ == "__main__":
    unittest.main()
