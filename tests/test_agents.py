"""Tests for the L3 Multi-Agent closed loop (deterministic, offline)."""

import unittest
from pathlib import Path

from policy_loop.agents import Orchestrator
from policy_loop.policy import load_text

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_POLICY = (ROOT / "data" / "fixtures" / "sample_policy.te").read_text(
    encoding="utf-8")

XPERM_DENIAL = (
    'avc: denied { ioctl } for pid=7881, comm="/system/bin/media_service" '
    'path="/dev/camera/video0" dev="" ino=23 ioctlcmd=0x6412 '
    "scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 "
    "tclass=chr_file permissive=1"
)
ESCALATION_DENIAL = (
    'avc: denied { read } for pid=9999 comm="some_app" '
    "scontext=u:r:normal_hap:s0 tcontext=u:object_r:dev_bbox:s0 "
    "tclass=chr_file permissive=1"
)
READ_DENIAL = (
    'avc: denied { read } for pid=42 comm="media_service" '
    "scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 "
    "tclass=chr_file permissive=1"
)


class TestAgents(unittest.TestCase):
    def setUp(self):
        self.index = load_text(SAMPLE_POLICY)
        self.orch = Orchestrator(index=self.index)

    def test_pipeline_records_full_trace(self):
        case = self.orch.analyze(XPERM_DENIAL)
        agents = [t.agent for t in case.trace]
        for a in ("LogAgent", "PolicyAgent", "SecurityAgent",
                  "RepairAgent", "ReviewerAgent", "VerifyAgent"):
            self.assertIn(a, agents)
        self.assertTrue(case.explanation)

    def test_xperm_gap_patch_and_verified(self):
        case = self.orch.analyze(XPERM_DENIAL)
        self.assertEqual(case.classification, "XPERM_GAP")
        self.assertIn("allowxperm", case.patch)
        self.assertIn("0x6412", case.patch)
        self.assertEqual(case.review["status"], "APPROVE")
        self.assertEqual(case.verify["status"], "SUCCESS")

    def test_neverallow_escalation_blocks_autofix(self):
        case = self.orch.analyze(ESCALATION_DENIAL)
        self.assertEqual(case.classification, "POTENTIAL_ESCALATION")
        self.assertEqual(case.patch, "")          # no auto patch
        self.assertTrue(case.needs_human)
        self.assertEqual(case.verify["status"], "HUMAN_REVIEW_REQUIRED")

    def test_allowed_permissive_is_noise(self):
        case = self.orch.analyze(READ_DENIAL)
        # sample policy grants media_service read on dev_camera_file
        self.assertEqual(case.classification, "NOISE_OR_ALREADY_FIXED")
        self.assertEqual(case.patch, "")

    def test_reviewer_rejects_overbroad_patch(self):
        # hand-craft a case whose patch is broader than the denial
        from policy_loop.agents.security_case import SecurityCase
        case = SecurityCase(id="T")
        case.denial_raw = XPERM_DENIAL
        case.record = {"source_domain": "media_service",
                       "target_type": "dev_camera_file",
                       "tclass": "chr_file",
                       "permissions": ["ioctl"], "ioctl_cmd": "0x6412",
                       "permissive": True}
        # Policy verdict says ioctl denied by xperm whitelist
        case.policy_verdict = {
            "src": "media_service", "tgt": "dev_camera_file", "cls": "chr_file",
            "requested_perms": ["ioctl"],
            "granted_perms": ["read", "open"],
            "all_allowed": False,
            "neverallow_hits": [],
            "matching_rules": [],
            "ioctl": {"allowed": False, "reason": "allowxperm", "cmd": "0x6412"},
        }
        case.classification = "XPERM_GAP"
        case.patch = "allow media_service dev_camera_file:chr_file { read write open ioctl };"
        case.candidates = []
        case.recommended = {"id": "B", "needs_human": False}

        from policy_loop.agents.reviewer import ReviewerAgent
        res = ReviewerAgent(index=self.index).run(case)
        self.assertFalse(res.ok)
        self.assertEqual(case.review["status"], "REJECT")
        self.assertTrue(any("过" in r for r in case.review["reasons"]))


if __name__ == "__main__":
    unittest.main()
