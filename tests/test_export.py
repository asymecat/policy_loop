"""Tests for policy_loop.export — PLI v1 serialization + round-trip fidelity.

The PLI file is the *only* thing the on-device C++ tool knows about the policy,
so a silent lossy projection here would show up as wrong verdicts on DAYU200
with no local symptom. These tests therefore check three levels:

1. **byte-level golden** on a fixture — catches any accidental format change;
2. **round-trip equivalence** — export -> parse -> re-query must agree with the
   original index on real (src, tgt, cls) combinations;
3. **self-check** — a truncated/corrupted file must be rejected, not misread.
"""

import io
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from policy_loop.converge import _known_tokens as converge_known_tokens
from policy_loop.export.cli import main as export_main
from policy_loop.export.pli import (
    _known_tokens as export_known_tokens,
    compute_meta,
    export_text,
    parse_text,
)
from policy_loop.policy import load_dir, load_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data" / "fixtures" / "sample_policy.te"
CORPUS = ROOT / "data" / "raw" / "oh-selinux" / "sepolicy"

# Byte-level golden. Regenerate deliberately (never blindly) if the format
# changes: this is what stops the C++ loader and the exporter drifting apart.
GOLDEN = """PLI1
@rev 2
@src fixtures/sample_policy.te gen=<fixed> exporter=policy_loop/export/pli.py
@meta rules=5 allow=3 neverallow=1 allowxperm=1 neverallowxperm=0 types=6 attrs=1 classes=2 perms=4 known=7 skipped=0 hap_entries=0 hap_domains=0 hap_names=0 hap_apls=0 hap_debuggable=0 hap_skipped=0
@class chr_file 3
@class file 2
@type dev_bbox
@type dev_camera_file
@type media_service
@type normal_hap hap_domain
@type sys_prod_file
@type system_basic_hap hap_domain
@attr hap_domain
@known dev_bbox
@known dev_camera_file
@known hap_domain
@known media_service
@known normal_hap
@known sys_prod_file
@known system_basic_hap
@perm ioctl
@perm open
@perm read
@perm write
@rules 5
a chr_file media_service dev_camera_file open,read
x chr_file media_service dev_camera_file ioctl:0x641f
a file media_service sys_prod_file ioctl,write
n chr_file normal_hap dev_bbox read
a file hap_domain sys_prod_file read
"""


def _fixture_index():
    return load_text(FIXTURE.read_text(encoding="utf-8"), source=str(FIXTURE))


_corpus_cache = []


def _corpus_index():
    """Load the upstream corpus once per test session (it is ~1,300 files)."""
    if not _corpus_cache:
        _corpus_cache.append(load_dir(CORPUS))
    return _corpus_cache[0]


class TestPliGolden(unittest.TestCase):
    def test_fixture_export_is_byte_stable(self):
        text = export_text(_fixture_index(),
                           src_label="fixtures/sample_policy.te",
                           gen_time="<fixed>")
        self.assertEqual(text, GOLDEN)

    def test_meta_matches_index_summary(self):
        index = _fixture_index()
        meta, _, _, _ = compute_meta(index)
        summary = index.summary()
        self.assertEqual(meta["rules"], summary["rules"])
        self.assertEqual(meta["types"], summary["types"])
        self.assertEqual(meta["attrs"], summary["attributes"])
        self.assertEqual(meta["skipped"], summary["skipped_statements"])
        for kind, count in summary["kinds"].items():
            self.assertEqual(meta[kind], count)

    def test_rule_lines_are_always_five_fields(self):
        """The device splits on whitespace; a stray space would desync it."""
        for line in GOLDEN.splitlines():
            if line.startswith("@rules "):
                break
        for line in export_text(_fixture_index()).splitlines():
            if line and not line.startswith("@"):
                if line == "PLI1":
                    continue
                self.assertEqual(len(line.split()), 5, msg=line)


class TestPliRoundTrip(unittest.TestCase):
    def test_structure_survives(self):
        original = _fixture_index()
        rebuilt = parse_text(export_text(original))
        self.assertEqual(len(original.rules), len(rebuilt.rules))
        self.assertEqual(set(original.type_attrs), set(rebuilt.type_attrs))
        self.assertEqual(original.attributes, rebuilt.attributes)
        for a, b in zip(original.rules, rebuilt.rules):
            self.assertEqual(a.kind, b.kind)
            self.assertEqual(a.cls, b.cls)
            self.assertEqual(a.src, b.src)
            self.assertEqual(a.src_neg, b.src_neg)
            self.assertEqual(a.src_star, b.src_star)
            self.assertEqual(a.tgt, b.tgt)
            self.assertEqual(a.tgt_neg, b.tgt_neg)
            self.assertEqual(a.tgt_star, b.tgt_star)
            self.assertEqual(a.perms, b.perms)
            self.assertEqual(a.xperm_perm, b.xperm_perm)
            self.assertEqual(a.xperms, b.xperms)
            self.assertEqual(a.xperm_invert, b.xperm_invert)

    def test_queries_agree(self):
        original = _fixture_index()
        rebuilt = parse_text(export_text(original))
        perms = frozenset({"open", "read"})
        for index in (original, rebuilt):
            allowed, granted, _ = index.has_access(
                "media_service", "dev_camera_file", "chr_file", perms)
            self.assertTrue(allowed)
            self.assertEqual(granted, perms)
        # attribute-mediated rule: normal_hap inherits hap_domain's allow
        for index in (original, rebuilt):
            allowed, _, _ = index.has_access(
                "normal_hap", "sys_prod_file", "file", frozenset({"read"}))
            self.assertTrue(allowed, "attribute closure lost in round-trip")

    def test_known_tokens_agree_with_converge(self):
        """The device's guard uses the exported @known set; it must equal what
        converge._known_tokens computes on the same index."""
        index = _fixture_index()
        self.assertEqual(export_known_tokens(index), converge_known_tokens(index))

    def test_empty_perms_round_trip_as_wildcard(self):
        """`allow A B:c *;` and `allow A B:c { };` both yield an empty perms
        frozenset, which has_access treats as a wildcard. Encoding it as `*`
        must survive the round-trip."""
        index = load_text("type a;\ntype b;\nallow a b:file *;\n")
        rebuilt = parse_text(export_text(index))
        allowed, _, _ = rebuilt.has_access("a", "b", "file", frozenset({"x"}))
        self.assertTrue(allowed, "empty-perms wildcard lost")
        self.assertEqual(rebuilt.rules[0].perms, frozenset())


class TestXpermOpaqueSemantics(unittest.TestCase):
    """Pins two upstream quirks that the device must reproduce verbatim.

    Both are arguably wrong for SELinux semantics, but 'fixing' them on one side
    only would silently desynchronize host and device verdicts. If they are ever
    fixed, fix both and re-run the evaluation, not just the port.
    """

    POLICY = ("type dom;\ntype tgt_t;\n"
              "allowxperm dom tgt_t:chr_file ioctl { 0x5401-0x5404 0x6201 };\n")

    def test_range_token_does_not_match_its_endpoints(self):
        index = load_text(self.POLICY)
        self.assertTrue(index.ioctl_allowed("dom", "tgt_t", "chr_file",
                                            "0x5401-0x5404")[0])
        for endpoint in ("0x5401", "0x5402", "0x5403", "0x5404"):
            self.assertFalse(
                index.ioctl_allowed("dom", "tgt_t", "chr_file", endpoint)[0],
                msg=f"{endpoint} unexpectedly matched a range token")

    def test_range_quirk_survives_round_trip(self):
        index = load_text(self.POLICY)
        rebuilt = parse_text(export_text(index))
        for cmd in ("0x5401", "0x5404", "0x5401-0x5404", "0x6201", "0X6201"):
            self.assertEqual(
                index.ioctl_allowed("dom", "tgt_t", "chr_file", cmd)[0],
                rebuilt.ioctl_allowed("dom", "tgt_t", "chr_file", cmd)[0],
                msg=f"round-trip changed the verdict for {cmd}")

    def test_matching_is_case_sensitive(self):
        index = load_text(self.POLICY)
        self.assertTrue(index.ioctl_allowed("dom", "tgt_t", "chr_file",
                                            "0x6201")[0])
        self.assertFalse(index.ioctl_allowed("dom", "tgt_t", "chr_file",
                                             "0X6201")[0])


class TestPliSelfCheck(unittest.TestCase):
    def test_truncated_file_is_rejected(self):
        text = export_text(_fixture_index())
        truncated = "\n".join(text.splitlines()[:-4]) + "\n"
        with self.assertRaises(ValueError):
            parse_text(truncated)

    def test_bad_revision_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_text("PLI1\n@rev 99\n")

    def test_non_pli_input_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_text("type a;\nallow a a:file read;\n")

    def test_rule_kind_letters_match_the_spec(self):
        index = load_text("type a;\ntype b;\n"
                          "allow a b:file read;\nneverallow a b:file write;\n"
                          "allowxperm a b:file ioctl { 0x1 };\n"
                          "neverallowxperm a b:file ioctl { 0x2 };\n")
        rebuilt = parse_text(export_text(index))
        self.assertEqual([r.kind for r in rebuilt.rules],
                         ["allow", "neverallow", "allowxperm",
                          "neverallowxperm"])


class TestPliHapSection(unittest.TestCase):
    """The `@hap` section carries the APL bridge to the device, which has no
    sepolicy source to read it from. Two failure modes matter: the section
    drifting (byte golden) and the section silently losing entries (the
    counter self-check), because either leaves the device classifying
    application denials as unattributable."""

    def _index_with_hap(self):
        idx = load_text("type normal_hap;\ntype appdat;\n"
                        "allow normal_hap appdat:file read;\n")
        idx.sehap.add_text(
            "# comment\n"
            "apl=system_core domain=system_core_hap type=system_core_hap_data_file\n"
            "apl=normal domain=normal_hap type=appdat\n"
            "apl=normal debuggable=true domain=debug_hap type=debug_hap_data_file\n"
            "apl=normal extra=isolated_gpu domain=isolated_gpu\n"
            "apl=normal name=com.ohos.x domain=x_hap extension=e\n")
        return idx

    def test_hap_lines_are_byte_stable(self):
        """Sorted by (domain, apl, ...): the export must not depend on the
        order the filesystem returned the files in."""
        lines = [l for l in export_text(self._index_with_hap()).splitlines()
                 if l.startswith("@hap ")]
        self.assertEqual(lines, [
            "@hap normal debug_hap debug_hap_data_file 1 - - -",
            "@hap normal isolated_gpu - 0 - - isolated_gpu",
            "@hap normal normal_hap appdat 0 - - -",
            "@hap system_core system_core_hap system_core_hap_data_file 0 - - -",
            "@hap normal x_hap - 0 com.ohos.x e -",
        ])
        # five-field rule lines stay unaffected by the new section
        body = export_text(self._index_with_hap()).splitlines()
        rules_at = next(i for i, l in enumerate(body) if l.startswith("@rules"))
        for line in [l for l in body[rules_at + 1:] if l]:
            self.assertEqual(len(line.split()), 5)

    def test_round_trip_preserves_the_table(self):
        original = self._index_with_hap()
        rebuilt = parse_text(export_text(original))
        self.assertEqual({e.as_tuple() for e in original.sehap.entries},
                         {e.as_tuple() for e in rebuilt.sehap.entries})
        self.assertEqual(original.sehap.summary(), rebuilt.sehap.summary())

    def test_dropping_a_hap_line_fails_the_self_check(self):
        text = export_text(self._index_with_hap())
        lines = text.splitlines()
        del lines[next(i for i, l in enumerate(lines) if l.startswith("@hap "))]
        with self.assertRaises(ValueError):
            parse_text("\n".join(lines) + "\n")

    def test_malformed_hap_flag_is_rejected(self):
        text = export_text(self._index_with_hap()).replace(
            "@hap normal normal_hap appdat 0 - - -",
            "@hap normal normal_hap appdat maybe - - -")
        with self.assertRaises(ValueError):
            parse_text(text)

    def test_index_without_hap_exports_zeros(self):
        text = export_text(_fixture_index())
        self.assertNotIn("@hap ", text)
        self.assertIn("hap_entries=0", text)
        rebuilt = parse_text(text)
        self.assertEqual(rebuilt.sehap.entries, [])
        self.assertEqual(rebuilt.sehap.summary()["hap_entries"], 0)

    def test_a_v1_file_is_now_rejected(self):
        """The revision bump is the loud half of the change: a device image
        built before it must fail to load a new index rather than read one
        whose @hap section it would ignore."""
        with self.assertRaises(ValueError):
            parse_text("PLI1\n@rev 1\n@meta rules=0\n@rules 0\n")


class TestExportCli(unittest.TestCase):
    def test_check_mode_detects_drift(self):
        out = ROOT / "build" / "pli" / "_test_fixture.pli"
        out.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: out.unlink(missing_ok=True))

        with redirect_stdout(io.StringIO()):
            rc = export_main(["--policy", str(FIXTURE), "--out", str(out),
                              "--quiet"])
        self.assertEqual(rc, 0)

        with redirect_stdout(io.StringIO()):
            rc = export_main(["--policy", str(FIXTURE), "--out", str(out),
                              "--check", "--quiet"])
        self.assertEqual(rc, 0, "check reported drift on identical output")

        out.write_text(out.read_text(encoding="utf-8").replace(
            "media_service", "tampered", 1), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            rc = export_main(["--policy", str(FIXTURE), "--out", str(out),
                              "--check", "--quiet"])
        self.assertEqual(rc, 1, "check failed to notice tampering")

    def test_check_ignores_the_generation_timestamp(self):
        """The export stamps the wall clock into @src. A guard that fails on
        that alone is a guard that always fails, so --check must compare
        content: an index exported days ago passes, one with a re-stamped
        gen= line included."""
        out = ROOT / "build" / "pli" / "_test_aged.pli"
        out.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: out.unlink(missing_ok=True))

        with redirect_stdout(io.StringIO()):
            export_main(["--policy", str(FIXTURE), "--out", str(out), "--quiet"])
        aged = re.sub(r"gen=\S+", "gen=2020-01-01T00:00:00Z",
                      out.read_text(encoding="utf-8"))
        out.write_text(aged, encoding="utf-8")

        with redirect_stdout(io.StringIO()):
            rc = export_main(["--policy", str(FIXTURE), "--out", str(out),
                              "--check", "--quiet"])
        self.assertEqual(rc, 0, "check compared the clock, not the content")

    def test_check_does_not_rewrite_the_timestamp_it_ignores(self):
        out = ROOT / "build" / "pli" / "_test_stamp.pli"
        out.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: out.unlink(missing_ok=True))

        with redirect_stdout(io.StringIO()):
            export_main(["--policy", str(FIXTURE), "--out", str(out), "--quiet"])
        aged = re.sub(r"gen=\S+", "gen=2020-01-01T00:00:00Z",
                      out.read_text(encoding="utf-8"))
        out.write_text(aged, encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            export_main(["--policy", str(FIXTURE), "--out", str(out),
                         "--check", "--quiet"])
        self.assertEqual(out.read_text(encoding="utf-8"), aged)


@unittest.skipUnless(CORPUS.exists(),
                     "upstream corpus not cloned (see README: data/raw)")
class TestCorpusRoundTrip(unittest.TestCase):
    """The real 1,315-file corpus — the fidelity guarantee that matters."""

    def test_structure_survives(self):
        original = _corpus_index()
        rebuilt = parse_text(export_text(original, src_label="corpus"))
        self.assertEqual(len(original.rules), len(rebuilt.rules))
        self.assertEqual(set(original.type_attrs), set(rebuilt.type_attrs))
        self.assertEqual(original.attributes, rebuilt.attributes)

    def test_ap_bridge_survives(self):
        """The APL bridge is the one part of the index that is not derivable
        from the rules, so it is the part a lossy projection would silently
        drop -- leaving the device unable to attribute application denials."""
        original = _corpus_index()
        rebuilt = parse_text(export_text(original, src_label="corpus"))
        self.assertTrue(original.sehap.entries, "corpus has sehap_contexts")
        self.assertEqual({e.as_tuple() for e in original.sehap.entries},
                         {e.as_tuple() for e in rebuilt.sehap.entries})
        self.assertEqual(original.sehap.summary(), rebuilt.sehap.summary())
        for domain in ("normal_hap", "debug_hap", "input_isolate_hap"):
            self.assertEqual(original.sehap.apls(domain),
                             rebuilt.sehap.apls(domain))

    def test_known_tokens_agree(self):
        original = _corpus_index()
        rebuilt = parse_text(export_text(original))
        self.assertEqual(export_known_tokens(original),
                         converge_known_tokens(original))
        self.assertEqual(export_known_tokens(original),
                         converge_known_tokens(rebuilt))

    def test_query_differential_on_real_rule_endpoints(self):
        """Sample real (src, tgt, cls) triples from the corpus and require the
        rebuilt index to answer every has_access / neverallow query the same."""
        original = _corpus_index()
        rebuilt = parse_text(export_text(original))
        perms = frozenset({"read", "write", "getattr", "open", "ioctl"})

        # Two permission sets, one of them disjoint from the sampled `perms`:
        # the neverallow answer now depends on what is requested, so a single
        # set would leave the new branch (a matching triple, no perm overlap)
        # entirely unexercised in the round-trip.
        perm_sets = (perms, frozenset({"execute", "search"}))

        sampled = 0
        for rule in original.rules:
            if not rule.src or not rule.tgt:
                continue
            src = sorted(rule.src)[0]
            tgt = sorted(rule.tgt)[0]
            a1 = original.has_access(src, tgt, rule.cls, perms)
            a2 = rebuilt.has_access(src, tgt, rule.cls, perms)
            self.assertEqual((a1[0], a1[1]), (a2[0], a2[1]),
                             msg=f"{src}->{tgt}:{rule.cls}")
            for ps in perm_sets:
                # Compared field by field, not by `raw`: the rebuilt index
                # carries the PLI rule line as its raw text, so comparing raw
                # would fail on the format rather than on the matching.
                def key(r):
                    return (r.kind, r.cls, tuple(sorted(r.src)),
                            tuple(sorted(r.tgt)), tuple(sorted(r.perms)))
                self.assertEqual(
                    [key(r) for r in
                     original.neverallow_rules(src, tgt, rule.cls, ps)],
                    [key(r) for r in
                     rebuilt.neverallow_rules(src, tgt, rule.cls, ps)],
                    msg=f"neverallow {src}->{tgt}:{rule.cls} {{{sorted(ps)}}}")
            sampled += 1
        self.assertGreater(sampled, 1000, "corpus sampling looked wrong")


if __name__ == "__main__":
    unittest.main()
