"""denial_check --case -- the shape contract of a per-record verdict.

tests/diff_device.py (`case` mode) is the parity gate: over the whole corpus it
proves the device's per-record verdicts equal the lines the batch report
carries. What is tested here is what that gate cannot state on its own -- the
key set, the emitted order, and the rule tying `guards_applied`, `auto_safe`
and `advisory` together. A cluster in the report has no guard fields at all, so
comparing a verdict against one is blind to exactly those.

The policy is the hand-written fixture rather than the upstream corpus, so the
expected verdicts are readable instead of recorded. The file skips itself when
the device binary has not been built.
"""

import json
import pathlib
import subprocess
import tempfile
import unittest

from policy_loop.export.pli import export_text
from policy_loop.policy import load_text

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path("/tmp/denial_check_host")
FIXTURE = ROOT / "data" / "fixtures" / "sample_policy.te"

# The keys CaseVerdictToJson emits, in the order it emits them. Listed rather
# than derived: a key that silently disappeared is what this is here to catch,
# and the order is load-bearing -- it is what lets the host compare the two
# sides with `diff` instead of walking fields.
KEYS = [
    "advisory", "all_allowed", "auto_safe", "category", "classification", "cls",
    "granted", "guards_applied", "has_ioctl", "ioctl_allowed", "ioctl_cmd",
    "ioctl_reason", "missing", "needs_human", "neverallow_hits", "patch",
    "produced_patch", "quick_settled", "requested", "review_status", "src",
    "tgt", "verify_status", "why",
]

# scontext, tcontext, tclass, perms, permissive, ioctlcmd, service
#
# One row per way a verdict can be reached against the fixture policy: already
# allowed under both modes, a neverallow hit, a clean gap, and the two ways the
# guards block a gap that the pipeline was happy with.
ROWS = [
    "media_service\tdev_camera_file\tchr_file\topen,read\tpermissive\t-\t-",
    "media_service\tdev_camera_file\tchr_file\topen,read\tenforcing\t-\t-",
    "normal_hap\tdev_bbox\tchr_file\tread\tunknown\t-\t-",
    "media_service\tdev_camera_file\tchr_file\topen,write\tenforcing\t-\t-",
    "media_service\tnonexistent_file\tchr_file\twrite\tenforcing\t-\t-",
    "media_service\tdefault_service\tsamgr_class\tadd\tenforcing\t-\t-",
]


@unittest.skipUnless(BIN.exists(), f"{BIN} not built (run tools/devbuild.sh)")
class CaseApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="case_api_")
        cls.pli = pathlib.Path(cls._tmp.name) / "fixture.pli"
        cls.pli.write_text(export_text(load_text(FIXTURE.read_text()),
                                       "fixtures/sample_policy.te",
                                       gen_time="<fixed>"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def lines(self, rows, full=False):
        """Run one --case batch and return its raw output lines."""
        src = pathlib.Path(self._tmp.name) / "cases.tsv"
        src.write_text("".join(r + "\n" for r in rows))
        cmd = [str(BIN), "--index", str(self.pli), "--case", str(src)]
        if full:
            cmd.append("--full")
        proc = subprocess.run(cmd, capture_output=True, check=True)
        return proc.stdout.decode("utf-8").splitlines()

    def verdicts(self, rows, full=False):
        return [json.loads(line) for line in self.lines(rows, full)]

    def check_invariants(self, v):
        self.assertEqual(set(v), set(KEYS))
        # The guards are what this mode is for, so every verdict carries their
        # answer rather than leaving a caller to infer it.
        self.assertTrue(v["guards_applied"])
        self.assertEqual(v["auto_safe"], v["category"] == "auto_repairable")
        if v["advisory"]:
            # A guard fired: the case is a human's, and `why` is the guard's
            # reason because that is the answer to "why not this patch".
            self.assertEqual(v["category"], "needs_human")
            self.assertEqual(v["why"], v["advisory"])
        if v["quick_settled"]:
            # Settled without the pipeline, so the pipeline's fields were never
            # computed. `quick_settled` is what keeps that apart from "no patch
            # proposed", which is why it has to travel with them.
            self.assertEqual(v["patch"], "")
            self.assertEqual(v["review_status"], "")
            self.assertEqual(v["verify_status"], "")

    def test_keys_are_emitted_sorted(self):
        # Read as pairs, not as a dict: the order on the wire is the contract,
        # and json.loads would have thrown it away.
        for line in self.lines(ROWS):
            pairs = json.loads(line, object_pairs_hook=list)
            self.assertEqual([k for k, _ in pairs], KEYS)
            self.assertNotIn("\n", line)

    def test_every_row_holds_the_invariants(self):
        verdicts = self.verdicts(ROWS)
        self.assertEqual(len(verdicts), len(ROWS))
        for v in verdicts:
            self.check_invariants(v)

    def test_verdicts(self):
        v = self.verdicts(ROWS)

        # Already allowed, logged only: noise, settled cheaply.
        self.assertEqual(v[0]["category"], "noise_or_already_allowed")
        self.assertEqual(v[0]["classification"], "NOISE_OR_ALREADY_FIXED")
        self.assertTrue(v[0]["quick_settled"])
        self.assertTrue(v[0]["all_allowed"])
        self.assertEqual(v[0]["why"], "策略已允许（历史/噪声）")

        # Already allowed yet blocked: not a permission gap, so not a patch --
        # the same case, decided the other way because the log said enforcing.
        self.assertEqual(v[1]["category"], "needs_human")
        self.assertEqual(v[1]["classification"], "DOMAIN_OR_LABEL_MISMATCH")
        self.assertEqual(v[1]["auto_safe"], False)

        # A neverallow is a red line: refused before any patch is built.
        self.assertEqual(v[2]["classification"], "POTENTIAL_ESCALATION")
        self.assertEqual(v[2]["neverallow_hits"], 1)
        self.assertEqual(v[2]["category"], "needs_human")
        self.assertIn("neverallow", v[2]["why"])

        # A clean gap: the one shape that reaches auto_repairable.
        self.assertEqual(v[3]["category"], "auto_repairable")
        self.assertEqual(v[3]["missing"], ["write"])
        self.assertTrue(v[3]["auto_safe"])
        self.assertEqual(v[3]["advisory"], "")
        self.assertEqual(v[3]["patch"],
                         "allow media_service dev_camera_file:chr_file { write };")
        self.assertEqual(v[3]["review_status"], "APPROVE")
        self.assertEqual(v[3]["verify_status"], "SUCCESS")

        # Guard 3: a target this policy never names. The pipeline was happy --
        # patch written, APPROVE, SUCCESS -- because it only simulated the rule
        # against the index it has. The guard is what notices the rule could
        # never land, which is why a verdict without it is not safe to act on.
        self.assertEqual(v[4]["produced_patch"], True)
        self.assertEqual(v[4]["review_status"], "APPROVE")
        self.assertEqual(v[4]["category"], "needs_human")
        self.assertFalse(v[4]["auto_safe"])
        self.assertIn("不在当前策略语料中", v[4]["advisory"])

        # Guard 2: a samgr placeholder. Same shape -- a patch that names
        # default_service instead of the concrete type it stands for.
        self.assertIn("default_service", v[5]["patch"])
        self.assertEqual(v[5]["category"], "needs_human")
        self.assertIn("占位符", v[5]["advisory"])

    def test_full_path_words_the_same_case_differently(self):
        # Why CasePath exists. Both paths agree on the classification and the
        # bucket; they disagree on `why`, because the batch settles these cases
        # without ever running the agent that writes the other sentence. A
        # caller needing report parity must ask for the quick path.
        quick = self.verdicts(ROWS[:2])
        full = self.verdicts(ROWS[:2], full=True)
        for q, f in zip(quick, full):
            self.assertEqual(q["classification"], f["classification"])
            self.assertEqual(q["category"], f["category"])
            self.assertTrue(q["quick_settled"])
            self.assertFalse(f["quick_settled"])
            self.assertNotEqual(q["why"], f["why"])
            self.check_invariants(f)


if __name__ == "__main__":
    unittest.main()
