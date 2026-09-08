"""Tests for policy_loop.converge (batch denial-log convergence).

Covers: fingerprint clustering/dedup, no-index behaviour, the degenerate-patch
guards (MLS-as-type target, default_* service placeholder, unknown subject,
vacuous patch, unknown class), and the fast-path verdicts (already-allowed ->
noise / DOMAIN; neverallow -> escalation without a patch).
"""

import unittest
from pathlib import Path

from policy_loop.converge import (
    CAT_AUTO,
    CAT_HUMAN,
    CAT_NOISE,
    CAT_UNCLASS,
    _is_mls_level,
    _is_service_placeholder,
    _known_tokens,
    _patch_is_vacuous,
    converge,
)
from policy_loop.policy import load_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "fixtures" / "sample_denials.txt"


def denial(src, tgt, cls, perms, permissive="1", extra=""):
    """Build a single-line denial record."""
    return (f"#avc: denied {{ {perms} }} for pid=1, comm=\"init\" "
            f"tcontext=u:object_r:{tgt}:s0 tclass={cls} "
            f"scontext=u:r:{src}:s0 {extra} permissive={permissive}")


class TestClusterDedup(unittest.TestCase):
    def test_identical_access_dedups_across_pid_comm_path(self):
        a = ("avc: denied { read write } for pid=100 comm=\"a\" path=\"/x\" "
             "scontext=u:r:app:s0 tcontext=u:object_r:dev_file:s0 "
             "tclass=file permissive=1")
        b = a.replace("{ read write }", "{ write read }").replace(
            'pid=100 comm="a" path="/x"', 'pid=200 comm="b" path="/y"')
        c = a.replace('pid=100', 'pid=300')
        r = converge("\n\n".join([a, b, c]))   # no index
        self.assertEqual(r.total_denials, 3)
        self.assertEqual(r.unique_cases, 1)    # permission order is irrelevant
        self.assertEqual(r.clusters[0]["count"], 3)

    def test_distinct_access_stays_separate(self):
        a = denial("app", "dev_file", "file", "read")
        b = denial("app", "sys_file", "file", "read")
        r = converge("\n\n".join([a, b]))
        self.assertEqual(r.total_denials, 2)
        self.assertEqual(r.unique_cases, 2)

    def test_to_dict_has_dedup_ratio(self):
        r = converge("\n\n".join([denial("a", "t", "file", "read")] * 2))
        d = r.to_dict()
        self.assertEqual(d["dedup_ratio"], 2.0)


class TestNoIndex(unittest.TestCase):
    def test_fixture_parses_but_stays_unclassified(self):
        text = FIXTURES.read_text(encoding="utf-8")
        r = converge(text)                        # no policy index
        self.assertEqual(r.total_denials, 7)
        self.assertEqual(r.unique_cases, 7)
        self.assertEqual(r.by_category.get(CAT_UNCLASS), 7)
        self.assertEqual(r.auto_patch_lines, [])
        self.assertIn("未提供策略索引", r.readiness_note())

    def test_readiness_claims_nothing_without_index(self):
        r = converge(denial("app", "dev_file", "file", "read"))
        self.assertEqual(r.unique_cases, 1)
        self.assertIn("未提供策略索引", r.readiness_note())


class TestDegeneratePatchGuards(unittest.TestCase):
    """Each guard turns a would-be AUTO patch into needs_human."""

    def _converge_one(self, te, raw):
        return converge(raw, index=load_text(te)).clusters[0]

    def test_mls_as_type_target_is_human(self):
        # tcontext "u:charger_exec:s0" lost its object_r role -> parser sees s0
        raw = ("#avc: denied { entrypoint } for pid=235 comm=\"init\" "
               "path=\"/vendor/bin/charger\" scontext=u:r:charger:s0 "
               "tcontext=u:charger_exec:s0 tclass=file permissive=1")
        c = self._converge_one("type charger;\ntype charger_exec;\n", raw)
        self.assertEqual(c["category"], CAT_HUMAN)
        self.assertIn("可疑", c["why"])

    def test_default_service_placeholder_is_human(self):
        raw = ("avc: denied { get } for service=5100 pid=403 "
               "scontext=u:r:face_auth_host:s0 "
               "tcontext=u:object_r:default_service:s0 "
               "tclass=samgr_class permissive=1")
        c = self._converge_one("type face_auth_host;\n", raw)
        self.assertEqual(c["category"], CAT_HUMAN)
        self.assertIn("default_*", c["why"])

    def test_unknown_subject_is_human(self):
        # no type "file" exists in policy; the patch could never compile
        raw = ("avc: denied { transfer } for pid=6408 comm=\"/system/bin/sa_main\" "
               "scontext=u:r:file:s0 tcontext=u:r:system_core_hap:s0 "
               "tclass=binder permissive=1")
        c = self._converge_one("type system_core_hap;\ntype bar;\n", raw)
        self.assertEqual(c["category"], CAT_HUMAN)
        self.assertIn("不在当前策略语料", c["why"])

    def test_unknown_class_is_human(self):
        # hand-written log typo: samar_class instead of samgr_class
        raw = ("avc: denied { get } for service=1152 sid=u:r:edm_sa:s0 "
               "scontext=u:r:edm_sa:s0 "
               "tcontext=u:object_r:sa_net_policy_manager:s0 "
               "tclass=samar_class permissive=0")
        te = ("type edm_sa;\ntype sa_net_policy_manager;\ntype other;\n"
              "type other_t;\nallow other other_t:samgr_class { get };\n")
        c = self._converge_one(te, raw)
        self.assertEqual(c["category"], CAT_HUMAN)
        self.assertIn("samar_class", c["why"])

    def test_no_bogus_line_lands_in_auto_patches(self):
        te = ("type app;\ntype dev_file;\ntype other;\ntype other_t;\n"
              "allow other other_t:file { read };\n")
        raws = [
            # mls-as-type target
            ("#avc: denied { entrypoint } for pid=1 comm=\"init\" "
             "scontext=u:r:charger:s0 tcontext=u:charger_exec:s0 "
             "tclass=file permissive=1"),
            # placeholder target
            ("avc: denied { get } for service=5100 pid=1 "
             "scontext=u:r:face_auth_host:s0 tcontext=u:object_r:default_service:s0 "
             "tclass=samgr_class permissive=1"),
            # genuinely missing but valid -> SHOULD stay auto
            denial("app", "dev_file", "file", "read"),
        ]
        r = converge("\n\n".join(raws), index=load_text(te))
        self.assertIn(CAT_AUTO, r.by_category)
        # the two degenerate ones must not produce suggestions
        self.assertEqual(len(r.auto_patch_lines), 1)
        self.assertEqual(r.auto_patch_lines[0],
                         "allow app dev_file:file { read };")
        human_whys = " | ".join(h["why"] for h in r.human_items)
        self.assertIn("可疑", human_whys)
        self.assertIn("default_*", human_whys)


class TestFastPath(unittest.TestCase):
    """Cheap verdicts for already-covered / neverallow cases."""

    TE_ALLOW = ("type d;\ntype tgt;\ntype other;\ntype other_t;\n"
                "allow d tgt:file { read };\n")

    def test_covered_in_permissive_is_noise(self):
        r = converge(denial("d", "tgt", "file", "read", "1"),
                     index=load_text(self.TE_ALLOW))
        c = r.clusters[0]
        self.assertEqual(c["category"], CAT_NOISE)
        self.assertEqual(c["classification"], "NOISE_OR_ALREADY_FIXED")

    def test_covered_in_enforcing_is_domain_mismatch(self):
        r = converge(denial("d", "tgt", "file", "read", "0"),
                     index=load_text(self.TE_ALLOW))
        c = r.clusters[0]
        self.assertEqual(c["category"], CAT_HUMAN)
        self.assertEqual(c["classification"], "DOMAIN_OR_LABEL_MISMATCH")

    def test_neverallow_is_escalation_without_patch(self):
        te = ("type d;\ntype tgt;\nneverallow d tgt:file { read };\n")
        r = converge(denial("d", "tgt", "file", "read", "1"),
                     index=load_text(te))
        c = r.clusters[0]
        self.assertEqual(c["category"], CAT_HUMAN)
        self.assertEqual(c["classification"], "POTENTIAL_ESCALATION")
        self.assertEqual(c["patch"], "")
        self.assertIn("neverallow", c["why"])

    def test_missing_rule_goes_full_pipeline_to_auto(self):
        te = ("type app;\ntype dev_file;\ntype other;\ntype other_t;\n"
              "allow other other_t:file { read };\n")
        r = converge(denial("app", "dev_file", "file", "read", "1"),
                     index=load_text(te))
        c = r.clusters[0]
        self.assertEqual(c["category"], CAT_AUTO)
        self.assertIn("allow app dev_file:file { read };", r.auto_patch_lines)


class TestHelpers(unittest.TestCase):
    def test_is_mls_level(self):
        self.assertTrue(_is_mls_level("s0"))
        self.assertTrue(_is_mls_level("s15"))
        self.assertFalse(_is_mls_level("s0x"))
        self.assertFalse(_is_mls_level("charger_exec"))
        self.assertFalse(_is_mls_level("dev_file"))
        self.assertFalse(_is_mls_level(""))

    def test_is_service_placeholder(self):
        self.assertTrue(_is_service_placeholder("default_service"))
        self.assertTrue(_is_service_placeholder("default_hdf_service"))
        self.assertFalse(_is_service_placeholder("sa_1_service"))
        self.assertFalse(_is_service_placeholder("hmdfs"))

    def test_patch_is_vacuous(self):
        self.assertTrue(_patch_is_vacuous("allow a b:file {  };"))
        self.assertTrue(_patch_is_vacuous("allow a b:file { };"))
        self.assertFalse(_patch_is_vacuous("allow a b:file { read };"))
        self.assertFalse(_patch_is_vacuous("allow a b:file *;"))
        self.assertFalse(_patch_is_vacuous(""))       # unparseable -> don't block

    def test_known_tokens_and_classes(self):
        te = ("type app;\ntype dev_file;\nallow app dev_file:file { read };\n")
        idx = load_text(te)
        tokens, classes = _known_tokens(idx)
        self.assertIn("app", tokens)
        self.assertIn("dev_file", tokens)
        self.assertIn("file", classes)
        self.assertNotIn("nope", tokens)


if __name__ == "__main__":
    unittest.main()
