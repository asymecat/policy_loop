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
        nev = self.idx.neverallow_rules("normal_hap", "dev_bbox", "chr_file",
                                        frozenset({"read"}))
        self.assertEqual(len(nev), 1)
        self.assertEqual(nev[0].kind, "neverallow")

    def test_neverallow_is_permission_scoped(self):
        """`neverallow A B:c { read }` constrains read, not the triple.

        A permission-blind match reports the same red line for every request on
        this (src, tgt, cls), which is what made the batch path escalate 1,705
        cases that were already allowed. Both halves matter: the negative is
        what a `len(nev) == 1` assertion alone cannot see.
        """
        self.assertTrue(self.idx.neverallow_rules(
            "normal_hap", "dev_bbox", "chr_file", frozenset({"read"})))
        for other in ({"ioctl"}, {"write"}, {"execute"}, set()):
            self.assertEqual(
                self.idx.neverallow_rules("normal_hap", "dev_bbox", "chr_file",
                                          frozenset(other)), [],
                msg=f"unexpected red line for {other or 'an empty perm set'}")

    def test_neverallow_wildcard_still_matches_any_request(self):
        """An empty permission set on the *rule* is `*` (has_access uses the
        same convention), so `neverallow D t:c *` must fire for every request --
        the permission-scoping fix must not turn the wildcard into a no-op."""
        idx = load_text("type d;\ntype t;\nneverallow d t:file *;\n")
        for perms in ({"read"}, {"ioctl"}, set()):
            self.assertEqual(
                len(idx.neverallow_rules("d", "t", "file", frozenset(perms))), 1,
                msg=f"wildcard neverallow missed a {{ {','.join(perms)} }} request")

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


class TestWrappedStatements(unittest.TestCase):
    """A rule statement can be wrapped across physical lines.

    The upstream tree has 40 of them (33 neverallow, 4 allow, 3 *xperm). Reading
    line by line loses them all, and loses them *silently*: `_RULE_RE` makes the
    trailing `;` optional, so a first line that already looks complete is taken
    as the whole statement and the remainder is discarded -- the statement is
    still counted as a rule, so `skipped_statements` never notices.
    """

    def test_wrapped_neverallow_is_kept_whole(self):
        idx = load_text("type a;\ntype b;\n"
                        "neverallow a b:file { read\n   write };\n")
        self.assertEqual(len(idx.rules), 1)
        self.assertEqual(idx.rules[0].kind, "neverallow")
        self.assertEqual(idx.rules[0].perms, frozenset({"read", "write"}))
        self.assertEqual(idx.summary()["skipped_statements"], 0)

    def test_wrapped_allow_grants_every_permission(self):
        idx = load_text("type app;\ntype dev_file;\n"
                        "allow app dev_file:file { open\n   read };\n")
        self.assertTrue(idx.has_access("app", "dev_file", "file", {"read"})[0])
        self.assertTrue(idx.has_access("app", "dev_file", "file", {"open"})[0])

    def test_wrapped_xperm_keeps_every_command(self):
        idx = load_text("type app;\ntype dev;\n"
                        "allowxperm app dev:chr_file ioctl {\n   0x5413\n   0x5414 };\n")
        self.assertEqual(len(idx.rules), 1)
        self.assertEqual(idx.rules[0].xperms, frozenset({"0x5413", "0x5414"}))

    def test_comment_on_the_first_line_does_not_truncate(self):
        idx = load_text("type a;\ntype b;\n"
                        "neverallow a b:file { read    # the rest is below\n"
                        "   write };\n")
        self.assertEqual(idx.rules[0].perms, frozenset({"read", "write"}))

    def test_an_unterminated_statement_is_skipped_not_swallowed(self):
        """No `;` anywhere: the join must give up rather than eat the file."""
        idx = load_text("type a;\ntype b;\n" + "neverallow a b:file { read }\n" * 200)
        self.assertEqual(idx.summary()["rules"], 0)
        self.assertGreater(idx.summary()["skipped_statements"], 0)


if __name__ == "__main__":
    unittest.main()
