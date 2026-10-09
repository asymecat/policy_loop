"""The inverted index must be a *superset* filter, never a different answer.

``_rule_hits`` used to walk every rule of the object class (7,400 for `file` on
the rk3568 tree); it now narrows to candidates via postings keyed on rule-side
tokens. That is only sound because the narrowing can err in exactly one
direction: an extra candidate costs a ``_matches`` call, a *missing* candidate
would drop a rule and silently change a verdict.

So the tests here are mostly about the ways a candidate could go missing:

* the query symbol itself vs. an attribute it inherits (both must be indexed);
* the star rule, which carries no token at all;
* negative members, which live in the rule but must *not* be allowed to prune;
* rules appended after the index was built -- the repair loop's whole use case,
  and the one path where a shared index goes stale by design.

The last test pins the sharing itself, because the sharing is the only reason
the optimization is a win: rebuilding per clone would cost ~12 ms per patch
attempt, 151 times per converge run.
"""

import unittest

from policy_loop.policy import load_text

TREE = """
type app, domain;
type other, domain;
type sys_file, file_type;
type dev_file, file_type;
type secret_file, file_type;
attribute domain;
attribute file_type;

allow app sys_file:file { read write };
allow domain dev_file:file { read };
allow * secret_file:file { read };
allow { app other } sys_file:dir { search };
neverallow app secret_file:file { write };
allowxperm app dev_file:file ioctl { 0x1000 0x2000 };
neverallowxperm app dev_file:file ioctl { 0x3000 };
"""


class HitIndexEquivalence(unittest.TestCase):
    def setUp(self):
        self.idx = load_text(TREE)

    def brute(self, kind, src, tgt, cls):
        """The pre-optimization answer: scan every rule of the class."""
        a_s = self.idx._attrs(src)
        a_t = self.idx._attrs(tgt)
        return [r for r in self.idx.rules
                if r.kind == kind and r.cls == cls
                and self.idx._matches(r.src, r.src_neg, r.src_star, src, a_s)
                and self.idx._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_t)]

    def test_agrees_with_a_full_scan_on_every_pair(self):
        names = ["app", "other", "sys_file", "dev_file", "secret_file",
                 "domain", "file_type"]
        checked = 0
        for kind in ("allow", "neverallow"):
            for cls in ("file", "dir"):
                for src in names:
                    for tgt in names:
                        self.assertEqual(
                            [r.raw for r in self.idx._rule_hits(kind, src, tgt, cls)],
                            [r.raw for r in self.brute(kind, src, tgt, cls)],
                            f"{kind} {src} {tgt}:{cls}")
                        checked += 1
        self.assertEqual(checked, 196)

    def test_a_concrete_query_finds_the_concrete_rule(self):
        got = [r.raw for r in self.idx.allow_rules("app", "sys_file", "file")]
        self.assertIn("allow app sys_file:file { read write };", got)

    def test_attribute_membership_is_indexed_on_both_sides(self):
        """`other` is a `domain`, so the `allow domain dev_file` rule reaches it."""
        got = [r.raw for r in self.idx.allow_rules("other", "dev_file", "file")]
        self.assertIn("allow domain dev_file:file { read };", got)

    def test_star_rule_has_no_token_and_is_still_found(self):
        """The star side carries nothing to index -- it must be added always."""
        for src in ("app", "other", "sys_file"):
            got = [r.raw for r in self.idx.allow_rules(src, "secret_file", "file")]
            self.assertIn("allow * secret_file:file { read };", got, src)

    def test_braced_subject_set_is_indexed_per_member(self):
        for src in ("app", "other"):
            got = [r.raw for r in self.idx.allow_rules(src, "sys_file", "dir")]
            self.assertIn("allow { app other } sys_file:dir { search };", got, src)

    def test_a_negative_member_does_not_prune_the_candidate(self):
        """Negatives live in the rule, not the postings; the trial must keep them.

        `app` is declared `type app, domain`, so `-domain` excludes it too: a
        negative member excludes the identifier *or any attribute it inherits*.
        That is why the postings may only ever be a superset -- `domain` is not
        in this rule's positive set, so the candidate survives on `app` alone
        and `_matches` is what actually rejects it.
        """
        idx = load_text(TREE + "\nallow { app -domain } sys_file:dir { read };\n")
        self.assertNotIn("allow { app -domain } sys_file:dir { read };",
                         [r.raw for r in idx.allow_rules("app", "sys_file", "dir")])

    def test_negations_stay_equivalent_to_a_full_scan(self):
        idx = load_text(
            TREE
            + "\nallow { app -file_type } sys_file:dir { read };\n"
            + "allow { app -dev_file } sys_file:dir { write };\n"
            + "allow { * -sys_file } dev_file:dir { search };\n"
        )
        self.idx = idx
        names = ["app", "other", "sys_file", "dev_file", "secret_file",
                 "domain", "file_type"]
        for src in names:
            for tgt in names:
                for cls in ("file", "dir"):
                    self.assertEqual(
                        [r.raw for r in self.idx._rule_hits("allow", src, tgt, cls)],
                        [r.raw for r in self.brute("allow", src, tgt, cls)],
                        f"{src} {tgt}:{cls}")
        # and the non-overlapping negation genuinely admits `app`
        self.assertIn("allow { app -file_type } sys_file:dir { read };",
                      [r.raw for r in idx.allow_rules("app", "sys_file", "dir")])


class AppendedRulesAreStillSeen(unittest.TestCase):
    """The repair loop appends a candidate patch to a clone and re-queries."""

    def test_a_rule_appended_to_the_live_index_is_found(self):
        idx = load_text(TREE)
        self.assertFalse(idx.has_access("app", "secret_file", "file",
                                        frozenset({"write"}))[0])
        idx.load_text("allow app secret_file:file { write };")
        self.assertTrue(idx.has_access("app", "secret_file", "file",
                                       frozenset({"write"}))[0])

    def test_a_rule_appended_to_a_clone_is_found_and_does_not_leak_to_parent(self):
        parent = load_text(TREE)
        child = parent.clone()
        child.load_text("allow app secret_file:file { write };")
        self.assertTrue(child.has_access("app", "secret_file", "file",
                                         frozenset({"write"}))[0])
        self.assertFalse(parent.has_access("app", "secret_file", "file",
                                          frozenset({"write"}))[0])

    def test_two_clones_appending_different_patches_stay_independent(self):
        """Both clones build their first extra rule at the same list index."""
        parent = load_text(TREE)
        a, b = parent.clone(), parent.clone()
        a.load_text("allow app secret_file:file { write };")
        b.load_text("allow other dev_file:dir { search };")
        self.assertTrue(a.has_access("app", "secret_file", "file",
                                     frozenset({"write"}))[0])
        self.assertFalse(a.has_access("other", "dev_file", "dir",
                                      frozenset({"search"}))[0])
        self.assertTrue(b.has_access("other", "dev_file", "dir",
                                     frozenset({"search"}))[0])
        self.assertFalse(b.has_access("app", "secret_file", "file",
                                      frozenset({"write"}))[0])

    def test_rule_order_is_rule_order_even_across_the_boundary(self):
        """Hits are reported in rule order; appended rules sort last."""
        idx = load_text(TREE)
        idx.load_text("allow app sys_file:file { read };")
        raws = [r.raw for r in idx.allow_rules("app", "sys_file", "file")]
        self.assertEqual(raws, ["allow app sys_file:file { read write };",
                                "allow app sys_file:file { read };"])


class AppendedXpermRulesAreStillSeen(unittest.TestCase):
    def test_ioctl_whitelist_sees_an_appended_allowxperm(self):
        idx = load_text(TREE)
        self.assertEqual(idx.ioctl_whitelist("app", "sys_file", "file")[0],
                         frozenset())
        idx.load_text("allowxperm app sys_file:file ioctl { 0x9abc };")
        self.assertIn("0x9abc", idx.ioctl_whitelist("app", "sys_file", "file")[0])

    def test_ioctl_whitelist_collects_only_the_matching_rule(self):
        wl, inv = self.idx_whitelist()
        self.assertEqual(wl, frozenset({"0x1000", "0x2000"}))
        self.assertEqual([r.raw for r in inv],
                         ["neverallowxperm app dev_file:file ioctl { 0x3000 };"])

    def idx_whitelist(self):
        return load_text(TREE).ioctl_whitelist("app", "dev_file", "file")


class TheIndexIsSharedNotRebuilt(unittest.TestCase):
    def test_clone_reuses_the_parents_postings(self):
        parent = load_text(TREE)
        a, b = parent.clone(), parent.clone()
        # identity, not equality: the point is that neither clone paid to
        # rebuild a 21k-rule index to ask about one appended rule.
        self.assertIs(a._hit_index()[1], parent._hit_index()[1])
        self.assertIs(b._hit_index()[1], parent._hit_index()[1])

    def test_a_late_build_still_covers_rules_already_present(self):
        """Building the index *after* rules were added must not miss them."""
        idx = load_text(TREE)
        idx.load_text("allow app secret_file:file { write };")
        base, _ = idx._hit_index()
        self.assertEqual(base, len(idx.rules))

    def test_the_clone_base_never_hides_a_rule(self):
        """`_rule_hits` skips postings past `base` -- the tail scan must cover them."""
        parent = load_text(TREE)
        child = parent.clone()
        child.load_text("allow app secret_file:file { write };")
        base, _ = child._hit_index()
        self.assertEqual(base, len(parent.rules))
        self.assertEqual(base, len(child.rules) - 1)


if __name__ == "__main__":
    unittest.main()
