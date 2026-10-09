"""policy_loop.explain -- the host half of `denial_check --explain`.

The parity gate is tests/diff_device.py (`explain` mode), which compares this
against the C++ tool case by case. What is tested here is the part that gate
cannot state on its own: the shape of the object, the rendered-token rule, and
the two "not a denial" paths.
"""

import json
import unittest

from policy_loop.explain import _token, explain, to_json
from policy_loop.policy import load_text

POLICY = """\
attribute domain;

type init, domain;
type media_service, domain;
type default_service, domain;
type audio_svc, domain;

type dev_null, file_type;
type sa_audio_svc, file_type;

allow init dev_null:chr_file { read write open };
allow media_service dev_null:chr_file { read open };
allow media_service sa_audio_svc:samgr_class { get };
"""

DENIED_MISSING = (
    'audit: type=1400 audit(1700000000.3:3): avc:  denied  { write } for  '
    'pid=2 comm="media_service" scontext=u:r:media_service:s0 '
    'tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0'
)

DENIED_ALLOWED = (
    'audit: type=1400 audit(1700000000.1:1): avc:  denied  { read } for  '
    'pid=1 comm="init" scontext=u:r:init:s0 '
    'tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=1'
)


def index():
    return load_text(POLICY, source="test_explain.embedded")


class TestToken(unittest.TestCase):
    def test_absent_renders_as_the_literal(self):
        # Not null: the same object's `explanation` says "None", and C++
        # BuildVerdict stores that literal outright.
        self.assertEqual(_token(None), "None")

    def test_present_passes_through(self):
        self.assertEqual(_token("media_service"), "media_service")
        self.assertEqual(_token(""), "")


class TestExplain(unittest.TestCase):
    def test_no_denial_is_none(self):
        # The caller prints "this is not a denial"; it is not an error.
        self.assertIsNone(explain("nothing to see here", index=index()))
        self.assertIsNone(explain("", index=index()))

    def test_missing_rule(self):
        r = explain(DENIED_MISSING, index=index())
        self.assertEqual(r["classification"], "MISSING_RULE")
        self.assertEqual(r["src"], "media_service")
        self.assertEqual(r["tgt"], "dev_null")
        self.assertEqual(r["cls"], "chr_file")
        self.assertEqual(r["requested"], ["write"])
        self.assertEqual(r["granted"], [])
        self.assertEqual(r["missing"], ["write"])
        self.assertEqual(r["patch"],
                         "allow media_service dev_null:chr_file { write };")
        self.assertEqual(r["review"], "APPROVE")
        self.assertEqual(r["verify"], "SUCCESS")
        self.assertEqual(r["recommended"]["id"], "B")
        self.assertFalse(r["needs_human"])
        self.assertIsNone(r["ioctl"])

    def test_already_allowed_is_noise_and_gets_no_patch(self):
        r = explain(DENIED_ALLOWED, index=index())
        self.assertEqual(r["classification"], "NOISE_OR_ALREADY_FIXED")
        self.assertEqual(r["missing"], [])
        self.assertEqual(r["patch"], "")
        self.assertEqual(r["recommended"]["id"], "-")
        self.assertFalse(r["needs_human"])

    def test_every_key_of_the_contract_is_present(self):
        """The key set is the device contract, not a convenience.

        tests/diff_device.py compares this object against `denial_check
        --explain --json` key by key, so a key added here and not on the device
        (or the reverse) is a gate failure rather than a new field.
        """
        r = explain(DENIED_MISSING, index=index())
        self.assertEqual(sorted(r), [
            "advisory", "classification", "cls", "explanation", "granted",
            "ioctl", "missing", "needs_human", "patch", "recommended",
            "requested", "review", "src", "tgt", "verify"])
        self.assertEqual(sorted(r["recommended"]), ["id", "title"])

    def test_a_clean_case_carries_no_advisory(self):
        r = explain(DENIED_MISSING, index=index())
        self.assertEqual(r["advisory"], "")
        self.assertEqual(r["recommended"]["title"], "最小权限补齐")

    def test_a_placeholder_target_is_refused_not_patched(self):
        """The defect this field exists for: `--explain` used to hand out a rule
        against a `default_*` placeholder, which can never land."""
        line = ('avc: denied { get } for service=x pid=1 '
                'scontext=u:r:media_service:s0 '
                'tcontext=u:object_r:default_hdf_service:s0 '
                'tclass=samgr_class permissive=0')
        r = explain(line, index=index())
        self.assertIn("占位符", r["advisory"])
        # `recommended.title` is rewritten too, so a reader who only looks at
        # the recommendation still sees the refusal rather than a patch.
        self.assertEqual(r["recommended"]["title"], r["advisory"])

    def test_an_mls_level_target_is_refused(self):
        line = ('avc: denied { read } for comm="a" '
                'scontext=u:r:media_service:s0 '
                'tcontext=u:object_r:s0 tclass=file permissive=0')
        r = explain(line, index=index())
        self.assertIn("安全级别", r["advisory"])


class TestToJson(unittest.TestCase):
    def test_sorted_keys_and_cjk_kept_verbatim(self):
        out = to_json({"b": 1, "a": "中文"})
        # ensure_ascii=False: the device emits UTF-8 bytes, not \uXXXX.
        self.assertEqual(out, '{"a": "中文", "b": 1}\n')

    def test_matches_the_device_separators(self):
        out = to_json(explain(DENIED_MISSING, index=index()))
        self.assertIn('", "', out)          # ", " between items
        self.assertIn('": ', out)           # ": " after a key
        self.assertTrue(out.endswith("}\n"))
        self.assertIsInstance(json.loads(out), dict)


if __name__ == "__main__":
    unittest.main()
