"""The device self test's vectors must not drift from the host engine.

`denial_check --selftest` carries its own policy, log and expected table, and
the table is generated *by the host engine* (`tools/gen_selftest_vectors.py`)
precisely so that it is a frozen differential rather than a snapshot of the
binary's own behaviour. That guarantee only holds while somebody regenerates
and re-pastes; the failure mode it is meant to prevent -- the table quietly
agreeing with whatever the device does -- looks exactly like a green self test.

So the table is checked here instead of trusted: this regenerates it from the
policy and log embedded in `test.cpp` and compares the result with what is
embedded there. A device tree whose vectors have drifted fails on the host, in
a second, without a board.

It also asserts the property the vectors exist for: that the six guards are
each reachable from at least one vector. Coverage of a branch is the kind of
thing that is claimed in a comment and lost in an edit.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import gen_selftest_vectors as gen        # noqa: E402
from policy_loop.converge import converge  # noqa: E402
from policy_loop.explain import explain, to_json  # noqa: E402
from policy_loop.export.pli import export_text    # noqa: E402
from policy_loop.policy.index import load_text    # noqa: E402

TEST_CPP = (ROOT / "device/selinux_adapter/framework/tools/denial_check"
            "/test.cpp")


def raw_string(name: str) -> str:
    """The contents of `const char *const <name> = R"TAG(...)TAG";`."""
    m = re.search(r'const char \*const ' + name + r' = R"(\w+)\((.*?)\)\1";',
                  TEST_CPP.read_text(), re.S)
    assert m, name
    return m.group(2)


def table(name: str) -> str:
    """The body of a braced table, braces excluded."""
    src = TEST_CPP.read_text()
    start = src.index(f"{name}[] = {{")
    end = src.index("\n};", start)
    return src[src.index("{", start) + 1:end]


class TestEmbeddedTables(unittest.TestCase):

    def test_policy_and_log_are_the_generator_s_own(self):
        self.assertEqual(raw_string("kSelfTestPli"),
                         export_text(load_text(gen.POLICY, source="selftest.embedded"),
                                     src_label="selftest.embedded",
                                     gen_time="2026-09-10T00:00:00Z"))
        self.assertEqual(raw_string("kSelfTestLog"), gen.LOG)

    def test_digest_table_matches_the_host_engine(self):
        index = load_text(gen.POLICY, source="selftest.embedded")
        report = converge(gen.LOG, index=index).to_dict()
        want = ["    " + gen._cpp(c) for c in report["clusters"]]
        self.assertEqual([l for l in table("kSelfTestVectors").splitlines()
                          if l.strip()], want)

    def test_explain_table_matches_the_host_engine(self):
        index = load_text(gen.POLICY, source="selftest.embedded")
        lines = gen.LOG.splitlines()
        want = []
        for lineno, label in gen.EXPLAIN_PICKS:
            line = lines[lineno - 1]
            result = explain(line, index=index)
            self.assertIsNotNone(result, f"EXPLAIN_PICKS line {lineno} ({label})")
            want.append(gen._cpp_str(to_json(result).rstrip("\n")))
        got = [l.strip()[:-2]
               for l in table("kSelfTestExplainVectors").splitlines()
               # Each row is `{line,\n "<json>"},` -- drop the struct's
               # own braces and comma, keep the quoted literal.
               if l.strip().startswith('"{')]
        self.assertEqual(got, want)


class TestGuardCoverage(unittest.TestCase):
    """Six guards, six reasons -- every one of them pinned by a vector."""

    @staticmethod
    def branch(reason: str) -> str:
        """A guard's identity, with the offending token blanked out.

        Two guards name the token that tripped them, so the same branch yields
        a different string per vector; the branch is what coverage is about.
        """
        return re.sub(r"「[^」]*」", "「…」", reason)

    def setUp(self):
        index = load_text(gen.POLICY, source="selftest.embedded")
        report = converge(gen.LOG, index=index).to_dict()
        self.whys = {self.branch(c["why"]) for c in report["clusters"]}
        self.advisories = [explain(gen.LOG.splitlines()[n - 1], index=index)
                           .get("advisory", "")
                           for n, _ in gen.EXPLAIN_PICKS]

    def test_each_guard_fires_on_at_least_one_vector(self):
        from policy_loop.converge import apply_guards
        from policy_loop.denial import parse as parse_denials

        from policy_loop.denial import fingerprint

        index = load_text(gen.POLICY, source="selftest.embedded")
        # The patch has to be the one the pipeline produced, not a stand-in:
        # the vacuous-patch guard is a predicate *on the patch*, so a synthetic
        # `{ d }` would leave that branch unreachable and the count at five.
        patches = {c["fp"]: c["patch"]
                   for c in converge(gen.LOG, index=index).to_dict()["clusters"]}
        reasons = {}
        for rec in parse_denials(gen.LOG):
            r = apply_guards(rec, patches.get(fingerprint(rec), ""), index)
            if r:
                reasons.setdefault(self.branch(r), []).append(rec.raw[:60])
        self.assertEqual(len(reasons), 6, sorted(reasons))
        for why in reasons:
            self.assertIn(why, self.whys,
                          f"guard reason absent from the digest table: {why}")

    def test_the_explain_path_carries_the_guard_reasons_too(self):
        # `advisory` is the only field on the explain path that says a patch
        # must not be applied -- if it stopped being filled, the vectors that
        # exist to pin it would still pass on every other field.
        self.assertGreaterEqual(sum(1 for a in self.advisories if a), 6)


if __name__ == "__main__":
    unittest.main()
