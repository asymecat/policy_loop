"""Tests for policy_loop.eval.trust (golden-pair quality gate).

Covers pair_kind / denial_verdict against tiny crafted policies: the trusted
core (full perm cover, wildcard, allowxperm whitelist), the mispair buckets
(src/class/perm_disjoint), partial_fix, attr_or_name_gap, the default_*
service_gap, unparseable, and the "one rule fixes several denials" legality.
"""

import unittest
from pathlib import Path

from policy_loop.eval.trust import (
    ATTR_OR_NAME_GAP,
    MISPAIR,
    PARTIAL,
    SERVICE_GAP,
    TRUSTED,
    UNPARSEABLE,
    denial_verdict,
    pair_kind,
)
from policy_loop.policy import load_text


def denial(src, tgt, cls, perms, ioctl_cmd=None, extra=None):
    d = {"source_domain": src, "target_type": tgt, "tclass": cls,
         "permissions": list(perms)}
    if ioctl_cmd:
        d["ioctl_cmd"] = ioctl_cmd
    if extra:
        d.update(extra)
    return d


def pair(idx, raw_rule, *dens):
    return pair_kind({"rule_raw": raw_rule, "denials": list(dens)}, idx)


class TestDenialVerdict(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(
            "type app;\ntype other;\ntype dev_file;\ntype data_file;\n"
            "allow app dev_file:file { read };\n")

    def test_plain_allow_match(self):
        r = load_text("allow app dev_file:file { read };\n")
        rule = r.rules[0]
        self.assertEqual(denial_verdict(self.idx, rule,
                                        denial("app", "dev_file", "file",
                                               ["read"])), "matches")

    def test_perm_order_irrelevant(self):
        r = load_text("allow app dev_file:file { read write };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "dev_file", "file", ["write", "read"]))
        self.assertEqual(v, "matches")

    def test_src_mismatch(self):
        r = load_text("allow other dev_file:file { read };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "dev_file", "file", ["read"]))
        self.assertEqual(v, "src_mismatch")

    def test_class_mismatch(self):
        r = load_text("allow app dev_file:dir { read };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "dev_file", "file", ["read"]))
        self.assertEqual(v, "class_mismatch")

    def test_partial_and_disjoint(self):
        r = load_text("allow app dev_file:file { read };\n")
        rule = r.rules[0]
        self.assertEqual(denial_verdict(
            self.idx, rule, denial("app", "dev_file", "file", ["read",
                                                                "write"])),
            "partial")                       # proper subset covered
        self.assertEqual(denial_verdict(
            self.idx, rule, denial("app", "dev_file", "file", ["write"])),
            "perm_disjoint")                 # nothing in common

    def test_tgt_mismatch_concrete(self):
        r = load_text("allow app dev_file:file { read };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "data_file", "file", ["read"]))
        self.assertEqual(v, "tgt_mismatch")


class TestWildcard(unittest.TestCase):
    def setUp(self):
        self.idx = load_text("type app;\ntype dev_file;\ntype other;\n"
                             "allow app dev_file:file *;\n")

    def test_star_covers_any_perm(self):
        r = load_text("allow app dev_file:file *;\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "dev_file", "file", ["read",
                                                              "write"]))
        self.assertEqual(v, "matches")


class TestAllowXperm(unittest.TestCase):
    def setUp(self):
        self.idx = load_text("type app;\ntype chardev;\ntype other;\n"
                             "allowxperm app chardev:chr_file ioctl "
                             "{ 0x4001 0x4002 };\n")

    def test_cmd_in_whitelist_matches(self):
        r = load_text("allowxperm app chardev:chr_file ioctl "
                      "{ 0x4001 0x4002 };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "chardev", "chr_file", ["ioctl"],
                                  ioctl_cmd="0x4001"))
        self.assertEqual(v, "matches")

    def test_cmd_outside_whitelist_is_disjoint(self):
        r = load_text("allowxperm app chardev:chr_file ioctl { 0x4001 };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "chardev", "chr_file", ["ioctl"],
                                  ioctl_cmd="0xdead"))
        self.assertEqual(v, "perm_disjoint")

    def test_non_ioctl_perm_against_xperm_is_disjoint(self):
        r = load_text("allowxperm app chardev:chr_file ioctl { 0x4001 };\n")
        rule = r.rules[0]
        v = denial_verdict(self.idx, rule,
                           denial("app", "chardev", "chr_file", ["write"]))
        self.assertEqual(v, "perm_disjoint")


class TestPairKind(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(
            "type app;\ntype dev_file;\ntype data_file;\ntype other;\n"
            "type sa_x;\ntype sa_y;\n"
            "allow other data_file:file { write };\n")

    def test_trusted_pair(self):
        kind, counts, note = pair(self.idx,
                                  "allow app dev_file:file { read };",
                                  denial("app", "dev_file", "file", ["read"]))
        self.assertEqual(kind, TRUSTED)
        self.assertEqual(counts["matches"], 1)

    def test_rule_fixing_multiple_denials_is_legal(self):
        # aggregate fix: one rule, two denials of the same logical access
        kind, counts, note = pair(
            self.idx, "allow app dev_file:file { read write };",
            denial("app", "dev_file", "file", ["read"]),
            denial("app", "dev_file", "file", ["write"]))
        self.assertEqual(kind, TRUSTED)
        self.assertEqual(counts["matches"], 2)

    def test_mixed_pair_downgrades_to_mispair(self):
        # rule fixes one denial but is paired with an unrelated src denial
        kind, counts, note = pair(
            self.idx, "allow app dev_file:file { read };",
            denial("app", "dev_file", "file", ["read"]),
            denial("other", "dev_file", "file", ["read"]))
        self.assertEqual(kind, MISPAIR)
        self.assertEqual(counts["src_mismatch"], 1)

    def test_class_mismatch_is_mispair(self):
        kind, counts, note = pair(self.idx,
                                  "allow app dev_file:dir { read };",
                                  denial("app", "dev_file", "file", ["read"]))
        self.assertEqual(kind, MISPAIR)
        self.assertIn("class_mismatch", counts)

    def test_perm_disjoint_is_mispair(self):
        kind, counts, note = pair(self.idx,
                                  "allow app dev_file:file { read };",
                                  denial("app", "dev_file", "file",
                                         ["write"]))
        self.assertEqual(kind, MISPAIR)
        self.assertEqual(counts["perm_disjoint"], 1)

    def test_partial_fix(self):
        kind, counts, note = pair(self.idx,
                                  "allow app dev_file:file { read };",
                                  denial("app", "dev_file", "file",
                                         ["read", "write"]))
        self.assertEqual(kind, PARTIAL)
        self.assertEqual(counts["partial"], 1)

    def test_attr_or_name_gap(self):
        # same domain/class/perms, but rule targets a different concrete type
        kind, counts, note = pair(self.idx,
                                  "allow app data_file:file { read };",
                                  denial("app", "dev_file", "file", ["read"]))
        self.assertEqual(kind, ATTR_OR_NAME_GAP)
        self.assertEqual(counts["tgt_mismatch"], 1)

    def test_service_gap_placeholder(self):
        # samgr placeholder target; rule fixes a concrete sa_* type
        kind, counts, note = pair(
            self.idx, "allow app sa_x:samgr_class { get };",
            denial("app", "default_service", "samgr_class", ["get"],
                   extra={"service": "5100"}))
        self.assertEqual(kind, SERVICE_GAP)
        self.assertEqual(counts["service_gap"], 1)

    def test_service_gap_hdf(self):
        kind, counts, note = pair(
            self.idx, "allow app sa_y:hdf_devmgr_class { get };",
            denial("app", "default_hdf_service", "hdf_devmgr_class",
                   ["get"]))
        self.assertEqual(kind, SERVICE_GAP)

    def test_unparseable_rule(self):
        kind, counts, note = pair(self.idx, "allow app {", [])
        self.assertEqual(kind, UNPARSEABLE)

    def test_unparseable_denial(self):
        kind, counts, note = pair(
            self.idx, "allow app dev_file:file { read };",
            denial("app", "dev_file", "file", []))     # no requested perms
        self.assertEqual(kind, UNPARSEABLE)


if __name__ == "__main__":
    unittest.main()
