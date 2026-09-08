"""Tests for LLM-provider plumbing and naive-LLM profile helpers."""

import os
import unittest

from policy_loop.eval.agent_eval import scope_of
from policy_loop.eval.agent_llm_eval import extract_rule, naive_llm_patch

V = {"src": "media_service", "tgt": "dev_camera_file", "cls": "chr_file",
     "requested_perms": ["ioctl"], "granted_perms": []}


class TestLlmHelpers(unittest.TestCase):
    def test_naive_llm_patch_overbroad(self):
        p = naive_llm_patch(V, "greedy")
        self.assertTrue(p.startswith("allow media_service dev_camera_file"))
        # greedy profile adds permissions that were NOT requested (over-broad)
        self.assertIn("read", p)
        self.assertIn("write", p)
        self.assertIn("ioctl", p)

    def test_scope_of_single_perm_form(self):
        # LLMs often emit the legal single-permission form without braces
        self.assertEqual(
            scope_of("allow samgr snapshot_display:dir search;"), {"search"})
        self.assertEqual(
            scope_of("allow msdp_sa render_service:fd use;"), {"use"})
        # brace form still works
        self.assertEqual(scope_of("allow a b:file { read write };"),
                         {"read", "write"})

    def test_extract_rule_parses(self):
        self.assertEqual(extract_rule("```\nallow a b:file { read };\n```"),
                         "allow a b:file { read };")
        self.assertIsNone(extract_rule("NO, this looks like escalation"))
        self.assertIsNone(extract_rule(""))  # no allow line -> None

    def test_extract_rule_keeps_allowxperm(self):
        self.assertEqual(
            extract_rule("allowxperm a b:chr_file ioctl { 0x6412 };"),
            "allowxperm a b:chr_file ioctl { 0x6412 };")

    def test_openai_provider_requires_key(self):
        saved = os.environ.get("OPENAI_API_KEY")
        os.environ.pop("OPENAI_API_KEY", None)
        try:
            from policy_loop.agents.providers import OpenAICompatibleProvider
            p = OpenAICompatibleProvider()
            self.assertFalse(p.available)
            self.assertIsNone(p.complete("hi"))  # no crash, returns None
        finally:
            if saved is not None:
                os.environ["OPENAI_API_KEY"] = saved


if __name__ == "__main__":
    unittest.main()
