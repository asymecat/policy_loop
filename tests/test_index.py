"""Tests for policy_loop.policy.index (deterministic .te query)."""

import unittest
from pathlib import Path

from policy_loop.policy import load_dir, load_text

ROOT = Path(__file__).resolve().parents[1]

SAMPLE = """
type media_service;
type sys_prod_file;
type dev_camera_file;
type dev_bbox;
attribute hap_domain;
type normal_hap, hap_domain;
type system_basic_hap, hap_domain;

allow media_service dev_camera_file:chr_file { open read };
allowxperm media_service dev_camera_file:chr_file ioctl { 0x641f };
allow media_service sys_prod_file:file { ioctl };
neverallow normal_hap dev_bbox:chr_file { read };
allow hap_domain sys_prod_file:file { read };
"""


class TestIndex(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(SAMPLE)

    def test_simple_allow_true(self):
        ok, granted, rules = self.idx.has_access(
            "media_service", "dev_camera_file", "chr_file",
            frozenset({"read"}),
        )
        self.assertTrue(ok)
        self.assertIn("read", granted)
        self.assertEqual(len(rules), 1)

    def test_simple_deny_missing_perm(self):
        ok, _, _ = self.idx.has_access(
            "media_service", "dev_camera_file", "chr_file",
            frozenset({"write"}),
        )
        self.assertFalse(ok)

    def test_attribute_expansion(self):
        # normal_hap carries attribute hap_domain, and the allow targets hap_domain
        ok, _, _ = self.idx.has_access(
            "normal_hap", "sys_prod_file", "file", frozenset({"read"})
        )
        self.assertTrue(ok)

    def test_attribute_negative(self):
        # a type NOT carrying hap_domain must not inherit the rule
        self.idx.type_attrs.setdefault("some_other", set())
        ok, _, _ = self.idx.has_access(
            "some_other", "sys_prod_file", "file", frozenset({"read"})
        )
        self.assertFalse(ok)

    def test_neverallow_detection(self):
        nev = self.idx.neverallow_rules("normal_hap", "dev_bbox", "chr_file")
        self.assertEqual(len(nev), 1)
        self.assertEqual(nev[0].kind, "neverallow")

    def test_allowxperm_whitelist_hit(self):
        ok, reason, _ = self.idx.ioctl_allowed(
            "media_service", "dev_camera_file", "chr_file", "0x641f"
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "allowxperm")

    def test_allowxperm_whitelist_miss(self):
        ok, reason, _ = self.idx.ioctl_allowed(
            "media_service", "dev_camera_file", "chr_file", "0x6412"
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "allowxperm")

    def test_plain_ioctl_allowed(self):
        # no allowxperm for sys_prod_file -> plain allow ioctl grants it
        ok, reason, _ = self.idx.ioctl_allowed(
            "media_service", "sys_prod_file", "file", "0xf207"
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "allow(ioctl)")

    def test_load_dir_fixture(self):
        idx = load_dir(ROOT / "data" / "fixtures")
        self.assertEqual(idx.summary()["rules"], 5)
        # sample_policy.te inside fixtures dir is indexed
        ok, _, _ = idx.has_access(
            "media_service", "dev_camera_file", "chr_file", frozenset({"read"})
        )
        self.assertTrue(ok)

    def test_typeattribute_space_separated(self):
        # OpenHarmony uses whitespace-separated typeattribute:
        #   typeattribute normal_hap hap_domain;
        idx = load_text(
            "type normal_hap;\n"
            "type tgt;\n"
            "attribute hap_domain;\n"
            "typeattribute normal_hap hap_domain;\n"
            "allow hap_domain tgt:file { read };\n"
        )
        ok, _, _ = idx.has_access("normal_hap", "tgt", "file",
                                  frozenset({"read"}))
        self.assertTrue(ok)

    def test_typeattribute_comma_separated(self):
        idx = load_text(
            "type normal_hap;\n"
            "type tgt;\n"
            "attribute hap_domain;\n"
            "typeattribute normal_hap, hap_domain;\n"
            "allow hap_domain tgt:file { read };\n"
        )
        ok, _, _ = idx.has_access("normal_hap", "tgt", "file",
                                  frozenset({"read"}))
        self.assertTrue(ok)

    def test_binder_call_macro_comma(self):
        idx = load_text("binder_call(aaa, bbb);\n")
        ok, _, _ = idx.has_access("aaa", "bbb", "binder",
                                  frozenset({"call"}))
        self.assertTrue(ok)
        # macro also grants reverse transfer and fd use
        ok2, _, _ = idx.has_access("bbb", "aaa", "binder",
                                   frozenset({"transfer"}))
        self.assertTrue(ok2)
        ok3, _, _ = idx.has_access("aaa", "bbb", "fd",
                                   frozenset({"use"}))
        self.assertTrue(ok3)

    def test_binder_call_macro_space(self):
        # upstream also writes binder_call(A B) with a space
        idx = load_text("binder_call(ccc ddd);\n")
        ok, _, _ = idx.has_access("ccc", "ddd", "binder",
                                  frozenset({"call", "transfer"}))
        self.assertTrue(ok)

    def test_condition_block_allow_parsed(self):
        idx = load_text(
            "debug_only(`\n"
            "    allow debugdom tgt:file { read };\n"
            "')\n"
            "developer_only(`\n"
            "    allow devdom tgt2:file { write };\n"
            "')\n"
        )
        ok, _, _ = idx.has_access("debugdom", "tgt", "file",
                                  frozenset({"read"}))
        self.assertTrue(ok)
        ok2, _, _ = idx.has_access("devdom", "tgt2", "file",
                                   frozenset({"write"}))
        self.assertTrue(ok2)

    def test_summary(self):
        s = self.idx.summary()
        self.assertEqual(s["rules"], 5)
        self.assertIn("allow", s["kinds"])
        self.assertIn("allowxperm", s["kinds"])
        self.assertIn("neverallow", s["kinds"])
        self.assertEqual(s["attributes"], 1)  # hap_domain
        self.assertEqual(s["types"], 6)       # 6 type declarations indexed


if __name__ == "__main__":
    unittest.main()
