"""Tests for service-placeholder logical-target resolution (M3).

Covers PolicyIndex.resolve_logical_target (named samgr/hdf services, numeric
samgr self-registration ``add``, conservative refusal to invent targets) and
replay's ``--resolve`` logical-coverage path.
"""

import json
import tempfile
import unittest
from pathlib import Path

from policy_loop.policy import load_text
from policy_loop.eval.replay import replay


class TestResolveLogicalTarget(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(
            "type hdf_intell_x;\n"
            "type sa_client_svc;\n"
            "type sa_intell_voice_service;\n"
            "type intell_voice_service;\n"
            "type selection_service;\n"
            "type other_type;\n"
            "type default_service;\n"
            "allow intell_voice_service sa_intell_voice_service:samgr_class "
            "{ add };\n")

    def test_named_hdf(self):
        got = self.idx.resolve_logical_target(
            "audio_host", "hdf_devmgr_class", "default_hdf_service",
            "intell_x", frozenset({"add"}))
        self.assertEqual(got, "hdf_intell_x")

    def test_named_samgr(self):
        got = self.idx.resolve_logical_target(
            "client", "samgr_class", "default_service",
            "client_svc", frozenset({"get"}))
        self.assertEqual(got, "sa_client_svc")

    def test_numeric_self_add_samgr(self):
        # an SA registers itself with samgr under its own numeric id
        got = self.idx.resolve_logical_target(
            "intell_voice_service", "samgr_class", "default_service",
            "312", frozenset({"add"}))
        self.assertEqual(got, "sa_intell_voice_service")

    def test_numeric_get_client_unresolvable(self):
        # client get on a remote numeric SA -> needs external id registry
        got = self.idx.resolve_logical_target(
            "normal_hap", "samgr_class", "default_service",
            "312", frozenset({"get"}))
        self.assertIsNone(got)

    def test_numeric_hdf_unresolvable(self):
        got = self.idx.resolve_logical_target(
            "face_auth_host", "hdf_devmgr_class", "default_hdf_service",
            "5100", frozenset({"add"}))
        self.assertIsNone(got)

    def test_candidate_must_be_declared(self):
        got = self.idx.resolve_logical_target(
            "host", "hdf_devmgr_class", "default_hdf_service",
            "no_such_service", frozenset({"add"}))
        self.assertIsNone(got)

    def test_non_placeholder_target_untouched(self):
        got = self.idx.resolve_logical_target(
            "a", "samgr_class", "sa_real_service", "312", frozenset({"get"}))
        self.assertIsNone(got)

    def test_no_service_field_untouched(self):
        got = self.idx.resolve_logical_target(
            "a", "samgr_class", "default_service", None, frozenset({"get"}))
        self.assertIsNone(got)


class TestReplayResolvePath(unittest.TestCase):
    def _golden(self, tmp: Path, denial: dict) -> Path:
        g = {"file": "x.te", "rule_line": 1,
             "rule_raw": "allow intell_voice_service "
                         "sa_intell_voice_service:samgr_class { add };",
             "denials": [denial]}
        p = tmp / "golden.jsonl"
        p.write_text(json.dumps(g, ensure_ascii=False) + "\n", encoding="utf-8")
        return p

    def _te(self, tmp: Path) -> Path:
        d = tmp / "sepolicy"
        d.mkdir(exist_ok=True)
        (d / "a.te").write_text(
            "type intell_voice_service;\n"
            "type default_service;\n"
            "type sa_intell_voice_service;\n"
            "type normal_hap;\n"
            "allow intell_voice_service sa_intell_voice_service:samgr_class "
            "{ add };\n", encoding="utf-8")
        return d

    def _placeholder_denial(self, service, perms):
        return {"source_domain": "intell_voice_service",
                "target_type": "default_service", "tclass": "samgr_class",
                "permissions": perms, "service": service}

    def test_raw_leaves_placeholder_uncovered(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            g = self._golden(tmp, self._placeholder_denial("312", ["add"]))
            st = replay(g, self._te(tmp), resolve=False)
            self.assertEqual(st["uncovered_count"], 1)
            self.assertEqual(st["resolved_count"], 0)

    def test_resolve_covers_self_add(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            g = self._golden(tmp, self._placeholder_denial("312", ["add"]))
            st = replay(g, self._te(tmp), resolve=True)
            self.assertEqual(st["uncovered_count"], 0)
            self.assertEqual(st["resolved_count"], 1)
            self.assertEqual(st["coverage_all_rate"], 1.0)

    def test_resolve_ignores_client_get(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            g = self._golden(
                tmp, {"source_domain": "normal_hap",
                      "target_type": "default_service",
                      "tclass": "samgr_class", "permissions": ["get"],
                      "service": "312"})
            st = replay(g, self._te(tmp), resolve=True)
            self.assertEqual(st["uncovered_count"], 1)   # still uncovered
            self.assertEqual(st["resolved_count"], 0)


if __name__ == "__main__":
    unittest.main()
