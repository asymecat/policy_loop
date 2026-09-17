"""Tests for the cross-layer view (application layer <-> system layer).

The claim this module makes is a *policy* claim -- "this denial is an APL
boundary, not a missing rule" -- so the tests are mostly about when it must
**refuse** to make it: a domain serving several levels, an APL outside the
known ladder, a sibling that merely looks like a debug build. Each of those
would otherwise produce a confident wrong answer, which in a security tool is
worse than no answer.

Two further things are pinned here because they are easy to break by accident:

* the view is *advisory* -- adding it must not move a single classification,
  patch or verdict (``test_cross_layer_does_not_change_any_verdict``);
* it is *host-only* -- the default report/explain objects must stay exactly
  what the on-device tool emits, because ``tests/diff_device.py`` compares
  them key by key (``TestDeviceParity``).
"""

import unittest
from pathlib import Path

from policy_loop.agents import Orchestrator
from policy_loop.converge import converge
from policy_loop.explain import explain
from policy_loop.policy import load_text
from policy_loop.policy.cross_layer import APL_ORDER, analyze, apl_rank
from policy_loop.policy.sehap import SehapTable

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "raw" / "oh-selinux" / "sepolicy"
DENIALS = ROOT / "data" / "corpus" / "real_denials.txt"

# A miniature of the upstream tree: two levels that may read /sys files and one
# that may not (the real ``normal_hap -> sys_file`` boundary), plus the debug
# pairs and the targets the advice has to name.
TE = """
type normal_hap, domain;
type debug_hap, domain;
type system_basic_hap, domain;
type system_core_hap, domain;
type input_isolate_hap, domain;
type input_isolate_debug_hap, domain;
type distributed_isolate_hap, domain;
type media_service, domain;
type sys_file, file_type;
type dev_file, dir_type;
type sa_thermal_service, service_type;
type usb_device, file_type;

allow system_basic_hap sys_file:file { read open };
allow system_core_hap sys_file:file { read open };
allow media_service dev_file:dir { mounton };
"""

SEHAP = """
apl=normal domain=normal_hap type=normal_hap_data_file
apl=normal debuggable=true domain=debug_hap type=debug_hap_data_file
apl=system_basic domain=system_basic_hap type=system_basic_hap_data_file
apl=system_core domain=system_core_hap type=system_core_hap_data_file
apl=normal extra=input_isolate domain=input_isolate_hap type=normal_hap_data_file
apl=normal debuggable=true extra=input_isolate domain=input_isolate_debug_hap type=normal_hap_data_file
apl=normal extension=distributed domain=distributed_isolate_hap type=normal_hap_data_file
apl=normal debuggable=true extension=distributed domain=distributed_isolate_hap type=normal_hap_data_file
apl=ultra domain=ultra_hap type=appdat
"""


def _index(te: str = TE, sehap: str = SEHAP):
    idx = load_text(te)
    if sehap is not None:
        table = SehapTable()
        table.add_text(sehap, "test")
        idx.sehap = table
    return idx


class TestAplLadder(unittest.TestCase):
    def test_ranks_follow_the_ladder_not_the_alphabet(self):
        """Sorted alphabetically, ``system_basic`` < ``system_core`` < ``normal``
        -- the opposite of the privilege order, which is the whole point."""
        self.assertLess(apl_rank("normal"), apl_rank("system_basic"))
        self.assertLess(apl_rank("system_basic"), apl_rank("system_core"))

    def test_unknown_level_ranks_below_everything(self):
        for known in APL_ORDER:
            self.assertLess(apl_rank("quantum"), apl_rank(known))


class TestCrossLayerAnalysis(unittest.TestCase):
    def setUp(self):
        self.index = _index()

    def test_non_app_domain_says_cross_layer_does_not_apply(self):
        v = analyze(self.index, "media_service", "dev_file", "dir", ["mounton"])
        self.assertFalse(v["app"])
        self.assertEqual(v["fix_layer"], "system")
        self.assertIn("不是应用域", v["headline"])

    def test_already_allowed_app_access_needs_no_layer(self):
        v = analyze(self.index, "system_core_hap", "sys_file", "file", ["read"])
        self.assertTrue(v["app"])
        self.assertEqual(v["fix_layer"], "none")

    def test_higher_apl_allows_it_is_a_boundary(self):
        """The flagship case: ``normal_hap`` may not read sys_file, while both
        higher levels may. Patching the .te would erase a level boundary."""
        v = analyze(self.index, "normal_hap", "sys_file", "file", ["read"])
        self.assertEqual(v["fix_layer"], "app")
        self.assertEqual(v["boundary"]["higher_apl_allowing"],
                         ["system_basic", "system_core"])
        self.assertIn("APL 分级边界", v["headline"])
        # The blast radius has to be stated, not implied.
        self.assertIn("共享域", v["headline"])
        self.assertTrue(any("全部应用" in a for a in v["advice"]))

    def test_no_app_domain_allows_it_is_a_system_layer_gap(self):
        v = analyze(self.index, "normal_hap", "usb_device", "file", ["read"])
        self.assertEqual(v["fix_layer"], "system")
        self.assertEqual(v["boundary"]["higher_apl_allowing"], [])
        self.assertTrue(any("影响面" in a for a in v["advice"]))

    def test_multi_level_domain_refuses_the_boundary_claim(self):
        """A domain serving several levels cannot attribute a denial to one of
        them, so 'a higher level has it' is not sayable."""
        table = SehapTable()
        table.add_text("apl=normal domain=isolated_gpu type=t\n"
                       "apl=system_core domain=isolated_gpu type=t\n"
                       "apl=system_basic domain=system_basic_hap type=t\n", "t")
        idx = _index()
        idx.sehap = table
        v = analyze(idx, "isolated_gpu", "sys_file", "file", ["read"])
        self.assertTrue(v["multi_level_domain"])
        self.assertNotEqual(v["fix_layer"], "app")
        self.assertTrue(any("多个 APL 等级" in e for e in v["evidence"]))

    def test_unknown_apl_refuses_the_boundary_claim(self):
        """Every ranked level would look 'higher' than an unranked one, so the
        comparison is refused rather than made in the wrong direction."""
        v = analyze(self.index, "ultra_hap", "sys_file", "file", ["read"])
        self.assertNotEqual(v["fix_layer"], "app")
        self.assertTrue(any("不在已建模的阶梯" in e for e in v["evidence"]))

    def test_debug_pair_is_the_matching_sibling(self):
        v = analyze(self.index, "normal_hap", "usb_device", "file", ["read"])
        self.assertEqual(v["debug_pair"]["kind"], "sibling")
        self.assertEqual(v["debug_pair"]["domain"], "debug_hap")
        self.assertFalse(v["debug_pair"]["allows"])

    def test_debug_pair_does_not_cross_extra_or_extension(self):
        """``input_isolate_debug_hap`` is the debug build of
        ``input_isolate_hap``, *not* of ``normal_hap`` -- matching on the flag
        alone would offer it as one."""
        v = analyze(self.index, "normal_hap", "usb_device", "file", ["read"])
        self.assertNotEqual(v["debug_pair"]["domain"], "input_isolate_debug_hap")
        v2 = analyze(self.index, "input_isolate_hap", "usb_device", "file", ["read"])
        self.assertEqual(v2["debug_pair"]["domain"], "input_isolate_debug_hap")

    def test_same_domain_debug_pair(self):
        """``distributed_isolate_hap`` declares both builds itself."""
        v = analyze(self.index, "distributed_isolate_hap", "usb_device", "file",
                    ["read"])
        self.assertEqual(v["debug_pair"]["kind"], "same_domain")
        self.assertTrue(any("同时声明" in e for e in v["evidence"]))

    def test_undeclared_domain_is_reported_as_unqueried(self):
        """``ultra_hap`` has a ``sehap_contexts`` entry but no type in this
        policy, so it cannot be queried. It must be counted as *unqueried* --
        folding it into "denied" would dress up "not in this index" as a
        policy answer, which is the one thing worse than no answer."""
        v = analyze(self.index, "normal_hap", "usb_device", "file", ["read"])
        self.assertEqual(v["boundary"]["uncovered"], ["ultra_hap"])
        self.assertNotIn("ultra_hap", v["boundary"]["allowing"])
        self.assertTrue(any("无法查询" in e for e in v["evidence"]))
        # ...and a declared domain that simply denies is not confused with it.
        self.assertNotIn("input_isolate_debug_hap", v["boundary"]["uncovered"])

    def test_placeholder_target_is_resolved_for_queries(self):
        """M3 applies here too: the queries must run against the concrete type
        the ``service=`` names, and the advice must name *that*, not the
        placeholder it cannot be written against."""
        v = analyze(self.index, "normal_hap", "default_service", "samgr_class",
                    ["add"], service="thermal_service")
        self.assertEqual(v["target"], "default_service")
        self.assertEqual(v["resolved_target"], "sa_thermal_service")
        self.assertTrue(any("sa_thermal_service" in a for a in v["advice"]))
        self.assertTrue(any("占位符" in a for a in v["advice"]))

    def test_no_sehap_table_means_no_view(self):
        self.assertIsNone(analyze(_index(sehap=None), "normal_hap", "usb_device",
                                  "file", ["read"]))

    def test_allowed_flag_is_reused_not_recomputed(self):
        """converge already knows the verdict; passing it must give the same
        answer as letting the view query for itself."""
        args = ("normal_hap", "sys_file", "file", ["read"])
        self.assertEqual(analyze(self.index, *args, allowed=False)["headline"],
                         analyze(self.index, *args)["headline"])


class TestCrossLayerDoesNotChangeVerdicts(unittest.TestCase):
    """The view is advisory. The strongest statement of that is a diff: the
    same denial, run through an index that knows the APL bridge and one that
    does not, must produce identical everything-else."""

    DENIAL = ('audit: avc: denied { read } for pid=7 comm="app" '
              "scontext=u:r:normal_hap:s0 tcontext=u:object_r:sys_file:s0 "
              "tclass=file")

    def test_cross_layer_does_not_change_any_verdict(self):
        with_bridge = Orchestrator(index=_index()).analyze(self.DENIAL)
        without = Orchestrator(index=_index(sehap=None)).analyze(self.DENIAL)
        self.assertTrue(with_bridge.cross_layer)
        self.assertFalse(without.cross_layer)
        for field in ("classification", "explanation", "patch", "needs_human",
                      "review", "verify", "recommended"):
            self.assertEqual(getattr(with_bridge, field),
                             getattr(without, field), field)

    def test_converge_buckets_are_identical_with_and_without_the_view(self):
        text = self.DENIAL + "\n"
        plain = converge(text, index=_index())
        viewed = converge(text, index=_index(), cross_layer=True)
        self.assertEqual(plain.by_category, viewed.by_category)
        self.assertEqual(plain.auto_patch_lines, viewed.auto_patch_lines)

    def test_the_agent_reports_the_layer_it_concluded(self):
        case = Orchestrator(index=_index()).analyze(self.DENIAL)
        trace = [t for t in case.trace if t.agent == "CrossLayerAgent"]
        self.assertEqual(len(trace), 1)
        self.assertIn("应用层", trace[0].detail)
        self.assertIn("APL 分级边界", trace[0].detail)


class TestDeviceParity(unittest.TestCase):
    """The default objects are the device contract. A new host-only key in
    them turns ``tests/diff_device.py`` red -- correctly, since the device
    cannot compute one -- so the view is opt-in there and tested to be absent.
    """

    DENIAL = ('audit: avc: denied { read } for pid=7 comm="app" '
              "scontext=u:r:normal_hap:s0 tcontext=u:object_r:sys_file:s0 "
              "tclass=file")

    def test_default_report_carries_no_cross_layer_key(self):
        d = converge(self.DENIAL + "\n", index=_index()).to_dict()
        self.assertNotIn("cross_layer_summary", d)
        for c in d["clusters"]:
            self.assertNotIn("cross_layer", c)

    def test_requested_report_carries_them(self):
        r = converge(self.DENIAL + "\n", index=_index(), cross_layer=True)
        d = r.to_dict()
        self.assertIn("cross_layer_summary", d)
        self.assertEqual(d["clusters"][0]["cross_layer"]["fix_layer"], "app")
        self.assertEqual(
            d["cross_layer_summary"]["auto_patches_on_shared_domain"][0]["patch"],
            "allow normal_hap sys_file:file { read };")

    def test_default_explain_carries_no_cross_layer_key(self):
        self.assertNotIn("cross_layer", explain(self.DENIAL, index=_index()))

    def test_requested_explain_carries_it(self):
        out = explain(self.DENIAL, index=_index(), cross_layer=True)
        self.assertEqual(out["cross_layer"]["fix_layer"], "app")

    def test_a_index_without_the_bridge_changes_nothing(self):
        """--policy pointing at a single .te file has no sehap table; the
        report must still be the object the device produces."""
        d = converge(self.DENIAL + "\n", index=_index(sehap=None),
                     cross_layer=True).to_dict()
        self.assertNotIn("cross_layer_summary", d)


@unittest.skipUnless(CORPUS.exists() and DENIALS.exists(),
                     "upstream corpus not cloned (see README: data/raw)")
class TestCrossLayerCorpus(unittest.TestCase):
    """What the view says about the real 5,161-denial corpus.

    These numbers are the feature's justification, so they are asserted rather
    than described: an APL boundary that the .te-only view calls
    ``auto_repairable`` is the case that motivates the whole module.
    """

    @classmethod
    def setUpClass(cls):
        from policy_loop.policy import load_dir

        cls.index = load_dir(CORPUS)
        cls.report = converge(DENIALS.read_text(encoding="utf-8",
                                                errors="surrogateescape"),
                              index=cls.index, cross_layer=True)
        cls.summary = cls.report.cross_layer_summary

    def test_only_a_small_share_of_denials_is_cross_layer(self):
        self.assertEqual(self.summary["app_domain_cases"], 350)
        self.assertEqual(self.summary["unique_cases_total"], 4911)

    def test_the_apl_boundary_cases_are_found(self):
        boundary = {(c["src"], c["tgt"], c["cls"])
                    for c in self.summary["apl_boundary_cases"]}
        self.assertEqual(boundary, {("normal_hap", "sys_file", "file")})

    def test_shared_domain_patches_are_surfaced(self):
        """Auto-approved patches on a shared ``*_hap`` domain: each one grants
        the permission to every app at that level, which nothing else in the
        report says out loud."""
        patches = self.summary["auto_patches_on_shared_domain"]
        self.assertTrue(patches)
        self.assertTrue(all(p["fix_layer"] in ("app", "system") for p in patches))
        self.assertTrue(any(p["fix_layer"] == "app" for p in patches),
                        "the boundary case must not read as a plain auto-patch")

    def test_no_boundary_case_is_left_unflagged_by_the_patch_list(self):
        boundary_patches = {c["patch"] for c in self.summary["apl_boundary_cases"]}
        listed = {p["patch"] for p in self.summary["auto_patches_on_shared_domain"]}
        self.assertTrue(boundary_patches <= listed)


if __name__ == "__main__":
    unittest.main()
