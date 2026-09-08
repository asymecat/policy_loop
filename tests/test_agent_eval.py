"""Tests for the leave-one-out agent evaluation logic (synthetic, no corpus)."""

import unittest

from policy_loop.eval.agent_eval import scan_informative, without_fix_light
from policy_loop.policy import load_text


def _denial(src, tgt, cls, perms):
    return {"source_domain": src, "target_type": tgt, "tclass": cls,
            "permissions": perms, "raw": ""}


def _pair(rule_raw, denial):
    return {"rule_kind": "allow", "rule_raw": rule_raw,
            "denials": [denial], "file": "x.te"}


class TestAgentEval(unittest.TestCase):
    def test_remove_single_fix_flips_to_denied(self):
        # the fix is the ONLY rule granting read -> informative
        policy = "type dom;\ntype tgt;\nallow dom tgt:file { read };\n"
        idx = load_text(policy)
        g = _pair("allow dom tgt:file { read };",
                  _denial("dom", "tgt", "file", ["read"]))
        scan = scan_informative(idx, [g])
        self.assertEqual(scan["stats"]["informative"], 1)
        self.assertEqual(scan["stats"]["covered_elsewhere"], 0)

    def test_covered_elsewhere_when_other_rule_grants(self):
        # a second, differently-worded rule still grants read after removal
        policy = ("type dom;\ntype tgt;\n"
                  "allow dom tgt:file { read };\n"
                  "allow dom tgt:file read;\n")
        idx = load_text(policy)
        g = _pair("allow dom tgt:file { read };",
                  _denial("dom", "tgt", "file", ["read"]))
        scan = scan_informative(idx, [g])
        self.assertEqual(scan["stats"]["covered_elsewhere"], 1)
        self.assertEqual(scan["stats"]["informative"], 0)

    def test_allowxperm_pairs_counted_separately(self):
        policy = "type dom;\ntype tgt;\nallow dom tgt:file ioctl;\n"
        idx = load_text(policy)
        g = {"rule_kind": "allowxperm",
             "rule_raw": "allowxperm dom tgt:file ioctl { 0x1 };",
             "denials": [_denial("dom", "tgt", "file", ["ioctl"])],
             "file": "x.te"}
        scan = scan_informative(idx, [g])
        self.assertEqual(scan["stats"]["pairs_allowxperm"], 1)

    def test_without_fix_light_removes_rule(self):
        idx = load_text("type dom;\ntype tgt;\nallow dom tgt:file { read };\n")
        self.assertEqual(len(idx.rules), 1)
        idx2 = without_fix_light(idx, "allow dom tgt:file { read };")
        self.assertEqual(len(idx2.rules), 0)
        # original untouched
        self.assertEqual(len(idx.rules), 1)


if __name__ == "__main__":
    unittest.main()
