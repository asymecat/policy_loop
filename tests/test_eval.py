"""Tests for the L2 eval corpus/golden extraction tooling."""

import tempfile
import unittest
from pathlib import Path

from policy_loop.eval.extract import extract

TWO_LAYOUTS = """\
type dom;
type tgt;
type dom2;
type tgt2;

# comment-first layout: denial above, fix below
# avc: denied { read } for pid=1 comm="a" scontext=u:r:dom:s0 tcontext=u:object_r:tgt:s0 tclass=file permissive=1
allow dom tgt:file { read };

# rule-first layout: fix above, denial evidence below
allow dom2 tgt2:file { write };
# avc: denied { write } for pid=2 comm="b" scontext=u:r:dom2:s0 tcontext=u:object_r:tgt2:s0 tclass=file permissive=0

type unrelated;
allow unrelated tgt:file { read };
"""


class TestExtract(unittest.TestCase):
    def _run(self, text: str):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "x.te").write_text(text, encoding="utf-8")
            return extract(root)

    def test_parses_hash_comment_denials(self):
        res = self._run(TWO_LAYOUTS)
        self.assertEqual(res["stats"]["denial_comment_lines"], 2)
        self.assertEqual(res["stats"]["golden_denials"], 2)

    def test_pairs_both_directions(self):
        res = self._run(TWO_LAYOUTS)
        golden = res["golden"]
        self.assertEqual(len(golden), 2)
        by_dir = {g["direction"]: g for g in golden}
        self.assertIn("comment_first", by_dir)
        self.assertIn("rule_first", by_dir)
        # comment_first pair: denial source dom matches rule src
        cf = by_dir["comment_first"]
        self.assertEqual(cf["denials"][0]["source_domain"], "dom")
        self.assertIn("allow dom tgt:file", cf["rule_raw"])
        rf = by_dir["rule_first"]
        self.assertEqual(rf["denials"][0]["source_domain"], "dom2")
        self.assertEqual(rf["rule_raw"].startswith("allow dom2"), True)

    def test_rule_without_denial_comment_is_ignored(self):
        res = self._run(TWO_LAYOUTS)
        # the 'allow unrelated ...' line has no adjacent denial -> not emitted
        rules = [g["rule_raw"] for g in res["golden"]]
        self.assertNotIn("allow unrelated tgt:file { read };", rules)


if __name__ == "__main__":
    unittest.main()
