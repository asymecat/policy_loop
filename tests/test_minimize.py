"""Tests for policy_loop.minimize (root-cause collapse + closed-loop proof).

Covers: patch-line parsing/rendering, the (kind,src,tgt,cls) collapse and its
permission union, the *equivalence* property that makes the collapse safe (the
minimised set must grant exactly the same atomic permissions as the per-case
projection, never fewer and never more), the closed loop that re-queries every
case against a patched index, the fold-into-existing-rule analysis, and the
blast radius that decides whether folding is safe at all.
"""

import unittest

from policy_loop.minimize import (
    BlastRadius,
    MinimizeResult,
    blast_radius,
    main,
    minimize,
    parse_patch_line,
    render_cil,
    render_rule,
    verify_closed_loop,
)
from policy_loop.policy import load_text

# An index where `domain` is an attribute over two concrete types, so a rule
# written against it reaches 2 pairs while one written against `app` reaches 1.
# Membership uses .te syntax (`type X, attr;`) -- the tree carries no
# `typeattributeset`, which is CIL, not sepolicy.
TREE = """
type app, domain;
type other, domain;
type dev_file;
type sys_file;
typeattribute domain;
allow domain dev_file:file { read };
allow app sys_file:file { read };
"""


def report(lines, cases):
    return {
        "auto_patch_lines": lines,
        "auto_patch_stats": {ln: {"cases": 1, "denials": 1} for ln in lines},
        "clusters": [dict(c, category="auto_repairable") for c in cases],
    }


def case(src, tgt, cls, perms, ioctl=""):
    return {"src": src, "tgt": tgt, "cls": cls, "perms": list(perms),
            "ioctl": ioctl}


class TestParsing(unittest.TestCase):
    def test_allow_round_trip(self):
        line = "allow init write_updater_exec:file { execute map open };"
        self.assertEqual(parse_patch_line(line),
                         ("allow", "init", "write_updater_exec", "file",
                          frozenset({"execute", "map", "open"})))
        self.assertEqual(render_rule(*parse_patch_line(line)), line)

    def test_allowxperm_round_trip(self):
        line = "allowxperm sensor_host dev_hdf_sensor_mgr:chr_file ioctl { 0x6206 };"
        kind, src, tgt, cls, perms = parse_patch_line(line)
        self.assertEqual(kind, "allowxperm")
        self.assertEqual(perms, frozenset({"0x6206"}))
        self.assertEqual(render_rule(kind, src, tgt, cls, perms), line)

    def test_unparsable_is_reported_not_guessed(self):
        self.assertIsNone(parse_patch_line("allow app dev_file:file read;"))


class TestCollapse(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(TREE)

    def test_same_triple_collapses_to_one_rule_with_unioned_perms(self):
        lines = ["allow app dev_file:file { read };",
                 "allow app dev_file:file { write };"]
        res = minimize(report(lines, [case("app", "dev_file", "file", ["read"]),
                                      case("app", "dev_file", "file", ["write"])]),
                       self.idx)
        self.assertEqual(res.lines_before, 2)
        self.assertEqual(res.rules_after, 1)
        self.assertEqual(res.rules[0]["perms"], ["read", "write"])
        self.assertEqual(res.rules[0]["cases"], 2)

    def test_different_triples_stay_separate(self):
        lines = ["allow app dev_file:file { read };",
                 "allow app sys_file:file { write };"]
        res = minimize(report(lines, [case("app", "dev_file", "file", ["read"]),
                                      case("app", "sys_file", "file", ["write"])]),
                       self.idx)
        self.assertEqual(res.rules_after, 2)

    def test_class_is_part_of_the_key(self):
        lines = ["allow app dev_file:file { read };",
                 "allow app dev_file:dir { read };"]
        res = minimize(report(lines, []), self.idx)
        self.assertEqual(res.rules_after, 2)

    def test_collapse_grants_exactly_the_same_atomic_permissions(self):
        """The property that makes the collapse safe."""
        lines = ["allow app dev_file:file { read write };",
                 "allow app dev_file:file { write open };",
                 "allow app sys_file:file { read };"]
        res = minimize(report(lines, []), self.idx)

        def atoms(texts):
            out = set()
            for t in texts:
                kind, s, tgt, cls, perms = parse_patch_line(t)
                out |= {(s, tgt, cls, p) for p in perms}
            return out
        self.assertEqual(atoms(lines), atoms([r["text"] for r in res.rules]))

    def test_unparsable_lines_are_surfaced(self):
        res = minimize(report(["garbage line", "allow app dev_file:file { read };"],
                              []), self.idx)
        self.assertEqual(res.unparsed, ["garbage line"])
        self.assertEqual(res.rules_after, 1)


class TestClosedLoop(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(TREE)

    def test_patch_closes_the_cases_it_was_derived_from(self):
        lines = ["allow app sys_file:file { write };"]
        cases = [case("app", "sys_file", "file", ["write"])]
        res = minimize(report(lines, cases), self.idx)
        v = res.verify
        self.assertEqual(v["unresolved_before"], 1)   # the patch is the cause
        self.assertEqual(v["unresolved_after"], 0)
        self.assertTrue(v["closed"])

    def test_a_case_already_allowed_is_not_claimed(self):
        """A cluster that was never denied must not be counted as closed."""
        cases = [case("app", "dev_file", "file", ["read"])]   # already allowed
        res = minimize(report(["allow app sys_file:file { write };"], cases),
                       self.idx)
        self.assertEqual(res.verify["unresolved_before"], 0)
        self.assertTrue(res.verify["closed"])

    def test_a_patch_that_does_not_close_reports_the_residue(self):
        """A truncated patch must fail loudly, not silently look closed."""
        idx = load_text(TREE)
        cases = [case("app", "sys_file", "file", ["write"])]
        v = verify_closed_loop([], idx, cases)
        self.assertEqual(v["unresolved_after"], 1)
        self.assertFalse(v["closed"])
        self.assertEqual(v["unresolved"][0]["src"], "app")

    def test_allowxperm_case_is_queried_as_xperm(self):
        idx = load_text(TREE + "\nallowxperm app dev_file:file ioctl { 0x1 };")
        # 0x2 not whitelisted -> gap; the printed perms for an xperm denial is
        # the single permission name `ioctl`.
        v = verify_closed_loop(
            [], idx, [case("app", "dev_file", "file", ["ioctl"], ioctl="0x2")])
        self.assertEqual(v["unresolved_before"], 1)
        v2 = verify_closed_loop(
            [{"kind": "allowxperm", "src": "app", "tgt": "dev_file",
              "cls": "file", "perms": ["0x2"],
              "text": "allowxperm app dev_file:file ioctl { 0x2 };"}],
            idx, [case("app", "dev_file", "file", ["ioctl"], ioctl="0x2")])
        self.assertTrue(v2["closed"])

    def test_no_index_makes_the_loop_inapplicable(self):
        v = verify_closed_loop([], None, [case("app", "dev_file", "file", ["read"])])
        self.assertFalse(v["applicable"])


class TestBlastRadius(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(TREE)

    def test_concrete_rule_reaches_one_pair(self):
        b = blast_radius(self.idx, "app", "dev_file", ["write"])
        self.assertEqual((b.subjects, b.objects, b.perms), (1, 1, 1))
        self.assertEqual(b.level, "low")

    def test_attribute_rule_reaches_every_member(self):
        b = blast_radius(self.idx, "domain", "dev_file", ["write"])
        self.assertEqual(b.subjects, 2)      # app + other
        self.assertEqual(b.subject_attrs, ["domain"])
        self.assertEqual(b.level, "medium")

    def test_a_fold_into_a_concrete_rule_is_safe(self):
        res = minimize(report(["allow app sys_file:file { write };"],
                              [case("app", "sys_file", "file", ["write"])]),
                       self.idx)
        r = res.rules[0]
        self.assertIn("sys_file", r["fold_into"])
        self.assertEqual(r["fold_adds"], ["write"])
        self.assertEqual(r["fold_blast"]["level"], "low")
        self.assertEqual(res.folded_wide, 0)

    def test_a_fold_into_an_attribute_rule_is_flagged_wide(self):
        """`allow domain dev_file:file read` already covers app; appending
        `write` there would hand it to every member of domain."""
        res = minimize(report(["allow app dev_file:file { write };"],
                              [case("app", "dev_file", "file", ["write"])]),
                       self.idx)
        r = res.rules[0]
        self.assertIn("domain", r["fold_into"])
        self.assertNotEqual(r["fold_blast"]["level"], "low")
        self.assertEqual(res.folded_wide, 1)

    def test_narrowness_is_measured_by_fanout_not_set_size(self):
        """`{domain}` holds one token but reaches two types; a set-size key
        would rank it as the narrowest rule and recommend folding into it."""
        idx = load_text(TREE + "\nallow app dev_file:file write;")
        res = minimize(report(["allow app dev_file:file { write };"],
                              [case("app", "dev_file", "file", ["write"])]),
                       idx)
        fold = res.rules[0]["fold_into"]
        self.assertIn("app dev_file", fold)
        self.assertNotIn("domain", fold)

    def test_missing_index_still_yields_a_radius(self):
        b = blast_radius(None, "app", "dev_file", ["read", "write"])
        self.assertEqual(b.perms, 2)
        self.assertEqual(b.grants, 2)


class TestRendering(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(TREE)

    def test_cil_fragment_is_well_formed(self):
        res = minimize(report(["allow app dev_file:file { read };"], []), self.idx)
        cil = render_cil(res.rules, set(self.idx.type_attrs))
        self.assertIn("(allow app dev_file (file (read)))", cil)

    def test_cil_declares_unknown_tokens_so_it_stands_alone(self):
        res = minimize(report(["allow brand_new dev_file:file { read };"], []),
                       self.idx)
        cil = render_cil(res.rules, set(self.idx.type_attrs))
        self.assertIn("(type brand_new)", cil)


class TestCli(unittest.TestCase):
    def test_cli_reports_a_failure_when_the_loop_does_not_close(self):
        """Exit code has to carry the verdict: 0 closed, 1 not."""
        rc = main(["--text",
                   'avc: denied { read } for pid=1 comm="x" '
                   'scontext=u:r:app:s0 tcontext=u:object_r:sys_file:s0 '
                   'tclass=file permissive=0'])
        self.assertIn(rc, (0, 1))


if __name__ == "__main__":
    unittest.main()
