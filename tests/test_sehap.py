"""Tests for policy_loop.policy.sehap — the APL <-> SELinux domain bridge.

This table is what lets the engine answer "is this denial from an application
process, and at what level" — a question the ``.te`` tree cannot answer at all.
Two things therefore have to be true, and they are checked differently:

1. the *reader* is faithful — an independent regex extraction of the same files
   must yield the same entry set (comparing the parser against itself would
   prove nothing);
2. the *loader* is complete — every subsystem ``sehap_contexts`` is read, which
   is what makes the isolated/sandboxed domains resolvable. Stopping at
   ``base/public`` still passes a "parses fine" check while losing most of the
   domains real denials name, so the corpus test asserts domain coverage over
   the actual denial set instead.
"""

import json
import re
import unittest
from pathlib import Path

from policy_loop.denial.parser import parse
from policy_loop.policy import load_dir
from policy_loop.policy.sehap import (KNOWN_EXTRAS, SehapEntry, SehapTable,
                                      load_sehap, parse_sehap_text)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "raw" / "oh-selinux" / "sepolicy"
GOLDEN = ROOT / "data" / "eval" / "golden.jsonl"

FIELDS = ("apl", "domain", "type", "debuggable", "name", "extension", "extra")


def _field(line: str, key: str) -> str:
    """Independent extraction: one regex per key, no shared tokenizer."""
    m = re.search(r"(?:^|\s)" + key + r"=(\S+)", line)
    return m.group(1) if m else ""


def _independent_entries(root: Path) -> set:
    """Re-read every sehap_contexts file with a throwaway regex reader."""
    out = set()
    for path in sorted(root.rglob("sehap_contexts")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            apl, domain = _field(s, "apl"), _field(s, "domain")
            if not apl or not domain:
                continue
            out.add((apl, domain, _field(s, "type"),
                     _field(s, "debuggable").lower() == "true",
                     _field(s, "name"), _field(s, "extension"),
                     _field(s, "extra")))
    return out


SAMPLE = """
# a comment line

apl=system_core domain=system_core_hap type=system_core_hap_data_file
apl=normal domain=normal_hap type=appdat
apl=normal debuggable=true domain=debug_hap type=debug_hap_data_file
apl=normal name=com.ohos.formrenderservice domain=formrenderservice_hap type=formrenderservice_hap_data_file
apl=normal extension=distributed domain=distributed_isolate_hap type=normal_hap_data_file
apl=normal debuggable=true extension=distributed domain=distributed_isolate_hap type=normal_hap_data_file
apl=normal extra=input_isolate domain=input_isolate_hap type=normal_hap_data_file
"""


class TestSehapParse(unittest.TestCase):
    def setUp(self):
        self.entries, self.skipped = parse_sehap_text(SAMPLE, "sample")

    def test_comments_and_blanks_are_not_entries(self):
        self.assertEqual(len(self.entries), 7)
        self.assertEqual(self.skipped, [])

    def test_type_is_optional(self):
        self.assertEqual(self.entries[0].type, "system_core_hap_data_file")

    def test_debuggable_defaults_false(self):
        self.assertFalse(self.entries[1].debuggable)   # normal_hap
        self.assertTrue(self.entries[2].debuggable)    # debug_hap

    def test_discriminators_are_kept(self):
        self.assertEqual(self.entries[3].name, "com.ohos.formrenderservice")
        self.assertEqual(self.entries[4].extension, "distributed")
        self.assertEqual(self.entries[6].extra, "input_isolate")

    def test_malformed_line_is_reported_not_guessed(self):
        entries, skipped = parse_sehap_text(
            "apl=normal domain=ok_hap\n"
            "this line has no fields\n"
            "domain=no_apl_here type=x\n"
            "apl=no_domain_here\n")
        self.assertEqual([e.domain for e in entries], ["ok_hap"])
        self.assertEqual([s[0] for s in skipped], [2, 3, 4])
        self.assertEqual([s[2] for s in skipped],
                         ["no apl=", "no apl=", "length"])

    def test_device_length_filter_is_mirrored(self):
        """hap_restorecon.cpp:119 drops anything <= 20 chars, so a short but
        well-formed entry never reaches the device. Counting it here would make
        the host claim a domain the device cannot label."""
        entries, skipped = parse_sehap_text("apl=x domain=y\n")
        self.assertEqual(entries, [])
        self.assertEqual([s[2] for s in skipped], ["length"])

    def test_debuggable_is_literal_true_only(self):
        """hap_restorecon.cpp:233 compares against "true" exactly; treating
        True/TRUE as true would attribute denials to debug_hap that the device
        never enters."""
        entries, _ = parse_sehap_text(
            "apl=normal debuggable=True domain=a_debug_hap type=x_file\n"
            "apl=normal debuggable=true domain=b_debug_hap type=x_file\n")
        self.assertEqual([e.debuggable for e in entries], [False, True])

    def test_unknown_extra_invalidates_the_line(self):
        """hap_restorecon.cpp:264-267: an unrecognised extra makes the whole
        line invalid, so the domain it declares does not exist on device."""
        entries, skipped = parse_sehap_text(
            "apl=normal extra=brand_new_sandbox domain=x_hap type=x_file\n")
        self.assertEqual(entries, [])
        self.assertEqual([s[2] for s in skipped],
                         ["unknown extra=brand_new_sandbox"])

    def test_known_extras_are_kept(self):
        for extra in sorted(KNOWN_EXTRAS):
            entries, _ = parse_sehap_text(
                f"apl=normal extra={extra} domain=x_hap type=x_file\n")
            self.assertEqual([e.extra for e in entries], [extra], extra)

    def test_raw_and_source_are_retained(self):
        self.assertEqual(self.entries[0].source, "sample")
        self.assertEqual(self.entries[0].raw, SAMPLE.splitlines()[3].strip())


class TestSehapTable(unittest.TestCase):
    def setUp(self):
        self.t = SehapTable().add_text(SAMPLE)

    def test_domain_lookup_is_many_to_many(self):
        """A domain with several levels must not be collapsed to one."""
        t = SehapTable().add_text(
            "apl=normal extra=isolated_gpu domain=isolated_gpu\n"
            "apl=system_basic extra=isolated_gpu domain=isolated_gpu\n"
            "apl=system_core extra=isolated_gpu domain=isolated_gpu\n")
        self.assertEqual(len(t.lookup_domain("isolated_gpu")), 3)
        self.assertEqual(t.apls("isolated_gpu"),
                         ("normal", "system_basic", "system_core"))

    def test_debug_variant_is_a_separate_entry(self):
        got = self.t.lookup_domain("distributed_isolate_hap")
        self.assertEqual(len(got), 2)
        self.assertEqual([e.debuggable for e in got], [False, True])

    def test_unknown_domain_is_empty_not_an_error(self):
        self.assertEqual(self.t.lookup_domain("init"), ())
        self.assertFalse(self.t.is_app_domain("init"))
        self.assertTrue(self.t.is_app_domain("normal_hap"))

    def test_apls_are_sorted_and_distinct(self):
        self.assertEqual(self.t.apls("normal_hap"), ("normal",))
        self.assertEqual(self.t.apls_all(), ("normal", "system_core"))

    def test_by_name_only_indexes_named_entries(self):
        self.assertEqual(list(self.t.by_name),
                         ["com.ohos.formrenderservice"])

    def test_summary_counters(self):
        s = self.t.summary()
        self.assertEqual(s["hap_entries"], 7)
        self.assertEqual(s["hap_domains"], 6)       # distributed_isolate_hap twice
        self.assertEqual(s["hap_names"], 1)
        self.assertEqual(s["hap_apls"], 2)
        self.assertEqual(s["hap_debuggable"], 2)

    def test_adding_text_invalidates_the_indexes(self):
        self.t.add_text("apl=normal domain=late_hap\n")
        self.assertTrue(self.t.is_app_domain("late_hap"))


@unittest.skipUnless(CORPUS.exists(),
                     "upstream corpus not cloned (see README: data/raw)")
class TestSehapCorpus(unittest.TestCase):
    def setUp(self):
        self.table = load_sehap(CORPUS)

    def test_reader_agrees_with_an_independent_extraction(self):
        """Set equality, not a spot check: the two readings must match
        exactly, on every field of every entry."""
        mine = {e.as_tuple() for e in self.table.entries}
        theirs = _independent_entries(CORPUS)
        self.assertEqual(mine - theirs, set())
        self.assertEqual(theirs - mine, set())
        self.assertEqual(self.table.skipped, [])

    def test_subsystem_files_are_not_missed(self):
        """base/public alone declares 4 domains; the isolated/sandboxed ones
        that real denials name live in the per-subsystem files."""
        for domain in ("normal_hap", "debug_hap",          # base/public
                       "distributed_isolate_hap",          # dmsfwk
                       "input_isolate_hap",                # inputmethod_native
                       "medialibrary_hap",                 # userfile_manager
                       "dlpmanager_hap"):                  # dlp_permission_service
            self.assertTrue(self.table.is_app_domain(domain), domain)

    def test_load_dir_attaches_the_table(self):
        idx = load_dir(CORPUS)
        self.assertTrue(idx.rules)
        self.assertEqual(idx.sehap.summary()["hap_entries"],
                         len(self.table.entries))

    @unittest.skipUnless(GOLDEN.exists(), "golden corpus not extracted")
    def test_hap_denials_resolve_to_a_level(self):
        """Acceptance for the cross-layer direction: for a denial whose
        scontext is an application domain, the bridge must name the level.

        The one known gap is ``sceneboard_hap``, which no sehap_contexts in
        this revision declares — an honest "unknown", not a loader miss. The
        count assertion is the real guard: reading only base/public leaves
        hundreds of denials unmapped, which is exactly the failure this
        catches.
        """
        hap = 0
        unmapped = {}
        for rec in (json.loads(l) for l in
                    GOLDEN.read_text(encoding="utf-8").splitlines()):
            for d in rec["denials"]:
                for parsed in parse(d.get("raw", "")):
                    src = parsed.source_domain or ""
                    if not src.endswith("_hap"):
                        continue
                    hap += 1
                    if not self.table.is_app_domain(src):
                        unmapped[src] = unmapped.get(src, 0) + 1
        self.assertGreater(hap, 300, "expected hundreds of *_hap denials")
        self.assertLessEqual(sum(unmapped.values()), 5,
                             f"too many unmapped *_hap denials: {unmapped}")
        self.assertLessEqual(set(unmapped), {"sceneboard_hap"})


if __name__ == "__main__":
    unittest.main()
