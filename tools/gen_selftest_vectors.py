#!/usr/bin/env python3
"""Regenerate the fixed vectors embedded in ``denial_check --selftest``.

``--selftest`` exists so that a device with no policy index and no denial log
can still tell "the binary does not run" apart from "the binary computes the
wrong answer". It carries its own small policy (as PLI text) and twenty-three
denial lines, and compares the device's convergence output against a table of
expected lines.

That table is produced *here*, by the host engine, which is the reference
implementation -- never by the C++ binary. A table snapshotted from the binary
would pass no matter what the binary did, which is the one thing a self test
must not do.

The vectors are chosen for branch coverage rather than for realism: one case in
each category, each classification, each of the five guards that downgrades an
automatic patch to a human decision, plus the malformed records whose output is
subtlest (a missing scontext, a missing tclass, and a target context that is a
bare MLS level). Those three render an absent field into a patch line and then
have to rule on whether the result is applicable.

The last eight lines cover the M3 service mapping, which the real corpus can
only partly reach -- it exercises the *resolvable* half and none of the refusals:

  * named service, samgr and hdf        -> resolves, policy already allows
  * numeric service + samgr ``add``     -> resolves to the subject's own type
  * numeric service + ``get``           -> refused (needs the samgr id registry)
  * named service naming no real type   -> refused (never invent a target)
  * placeholder on a non-service class  -> refused
  * resolves onto a neverallow          -> POTENTIAL_ESCALATION
  * resolves but is still denied        -> the patch keeps the placeholder, so
    the placeholder guard must be what downgrades it to a human decision

Note the fingerprints: ``fingerprint()`` deliberately excludes ``service=``, so
each line needs a distinct (src, tgt, class, perms) or they collapse into one
cluster and only the first line's ``service=`` is ever consulted.

Regenerating the table means pasting both blocks below into
``framework/tools/denial_check/test.cpp`` (`kSelfTestPli`, `kSelfTestLog` and
`kSelfTestVectors`), then re-running ``denial_check --selftest`` on the host.

    python3 tools/gen_selftest_vectors.py

The digests do not depend on the PLI's ``@src`` line, so restamping it does not
invalidate the table.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy_loop.export.pli import export_text          # noqa: E402
from policy_loop.policy.index import load_text          # noqa: E402
from policy_loop.converge import converge               # noqa: E402

# The policy the vectors are judged against. Deliberately tiny, but shaped so
# that every branch of the pipeline is reachable:
#   * `app_service` carries the neverallow (POTENTIAL_ESCALATION);
#   * `media_service` has a partial grant (MISSING_RULE) and an allowxperm
#     whitelist covering exactly one ioctl command (XPERM_GAP plus the
#     already-allowed case that reaches DOMAIN_OR_LABEL_MISMATCH);
#   * `default_service` is a placeholder target;
#   * `sa_binder` is a declared type no rule mentions, so a denial naming it is
#     refused for its *class*, not its target;
#   * the class `binder` is likewise mentioned by no rule.
# The last two are what the real 4,911-cluster corpus cannot exercise: on a real
# tree almost every declared token appears in some rule.
POLICY = """\
attribute domain;
attribute file_type;

type init, domain;
type media_service, domain;
type app_service, domain;
type default_service, domain;
type unknown_domain, domain;

type dev_camera_file, file_type;
type dev_null, file_type;
type sa_binder, file_type;

type sa_audio_svc, file_type;
type hdf_sensor_dev, file_type;
type sa_evil_svc, file_type;
type sa_gap_svc, file_type;
type audio_svc, domain;

allow init dev_null:chr_file { read write open };
allow media_service dev_camera_file:chr_file { read open };
neverallow app_service dev_camera_file:chr_file { write };
allowxperm media_service dev_camera_file:chr_file ioctl { 0x5401 };
allow media_service dev_camera_file:chr_file { ioctl };

allow media_service sa_audio_svc:samgr_class { get };
allow audio_svc sa_audio_svc:samgr_class { add };
allow media_service hdf_sensor_dev:hdf_devmgr_class { get };
neverallow media_service sa_evil_svc:samgr_class { get };
"""

# Fifteen lines against thirteen expected clusters: the two `init` reads and the
# two `media_service` writes collapse pairwise, which is what makes `count` and
# the dedup path part of what is being tested rather than incidental.
LOG = """\
audit: type=1400 audit(1700000000.1:1): avc:  denied  { read } for  pid=1 comm="init" scontext=u:r:init:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=1
audit: type=1400 audit(1700000000.2:2): avc:  denied  { read } for  pid=1 comm="init" scontext=u:r:init:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.3:3): avc:  denied  { write } for  pid=2 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.4:4): avc:  denied  { write } for  pid=3 comm="app_service" scontext=u:r:app_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file permissive=1
audit: type=1400 audit(1700000000.5:5): avc:  denied  { read } for  pid=4 comm="ghost" scontext=u:r:ghost_domain:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.6:6): avc:  denied  { ioctl } for  pid=5 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file ioctlcmd=0x5402 permissive=0
audit: type=1400 audit(1700000000.7:7): avc:  denied  { ioctl } for  pid=6 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file ioctlcmd=0x5401 permissive=0
audit: type=1400 audit(1700000000.8:8): avc:  denied  { read } for  pid=7 comm="default_service" scontext=u:r:default_service:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.9:9): avc:  denied  { call } for  pid=8 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:sa_binder:s0 tclass=binder permissive=0
audit: type=1400 audit(1700000000.10:10): avc:  denied  { read } for  pid=9 comm="media_service" tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.11:11): avc:  denied  { read } for  pid=10 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_null:s0 permissive=0
audit: type=1400 audit(1700000000.12:12): avc:  denied  { read } for  pid=11 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.13:13): avc:  denied  { read } for  pid=1 comm="init" scontext=u:r:init:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=1
audit: type=1400 audit(1700000000.14:14): avc:  denied  { read } for  pid=12 comm="media_service" scontext=u:r:media_service:s0 tcontext=s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.15:15): avc:  denied  { write } for  pid=13 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file
audit: type=1400 audit(1700000000.16:16): avc:  denied  { get } for  pid=14 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=audio_svc permissive=1
audit: type=1400 audit(1700000000.17:17): avc:  denied  { get } for  pid=15 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_hdf_service:s0 tclass=hdf_devmgr_class service=sensor_dev permissive=1
audit: type=1400 audit(1700000000.18:18): avc:  denied  { add } for  pid=16 comm="audio_svc" scontext=u:r:audio_svc:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=312 permissive=1
audit: type=1400 audit(1700000000.19:19): avc:  denied  { get find } for  pid=17 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=999 permissive=0
audit: type=1400 audit(1700000000.20:20): avc:  denied  { get open } for  pid=18 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=no_such_svc permissive=0
audit: type=1400 audit(1700000000.21:21): avc:  denied  { get } for  pid=19 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=chr_file service=audio_svc permissive=0
audit: type=1400 audit(1700000000.22:22): avc:  denied  { get write } for  pid=20 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=evil_svc permissive=0
audit: type=1400 audit(1700000000.23:23): avc:  denied  { get } for  pid=21 comm="audio_svc" scontext=u:r:audio_svc:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=gap_svc permissive=0
"""


def digest(cluster: dict) -> str:
    """One cluster as a single comparable line.

    Field order is fixed by ``ClusterDigest`` on the C++ side; an absent
    src/tgt/cls is the empty string here, while the patch column keeps the
    engine's literal suggestion text (which spells such a field `None`), because
    the two columns answer different questions: what the verdict was, and what
    rule the operator would have been handed.
    """
    return "|".join([
        cluster["fp"], str(cluster["count"]), cluster["src"], cluster["tgt"],
        cluster["cls"], ",".join(cluster["perms"]), cluster["category"],
        cluster["classification"], cluster["review_status"],
        cluster["verify_status"], cluster["why"], cluster["patch"],
    ])


# Lines of LOG that `--explain` carries its own vectors for, by 1-based line
# number, each labelled with the branch it is there to defend.
#
# The converge vectors above already pin BuildVerdict and the pipeline; what
# `--explain` adds is the wording (`ExplainHuman`), the JSON shape
# (`ExplainToJson`) and the recommendation id, so its vectors are the full JSON
# object rather than a digest -- a digest would not say which of the three broke.
#
# The selection is one line per classification, plus the two whose output is
# subtlest: a malformed record, where an absent scontext has to render the
# literal token `None` into src, and a placeholder that resolves but is still
# denied, where the patch keeps the placeholder and the guard is the only thing
# standing between it and an operator.
EXPLAIN_PICKS = [
    (3,  "MISSING_RULE  -- patch + APPROVE + SUCCESS"),
    (4,  "POTENTIAL_ESCALATION -- neverallow, no patch, human"),
    (6,  "XPERM_GAP -- allowxperm patch, not a plain allow"),
    (7,  "the allowxperm'd command -- already allowed, so label mismatch"),
    (2,  "NOISE_OR_ALREADY_FIXED -- read that the policy grants"),
    (10, "malformed: no scontext, so src renders the literal token None"),
    (16, "placeholder resolves and the policy already allows it"),
    (23, "placeholder resolves onto a real gap -- still needs a human"),
]


def explain_vectors(index) -> list:
    """[(line, expected JSON)] for EXPLAIN_PICKS, computed by the host engine."""
    from policy_loop.explain import explain, to_json

    lines = LOG.splitlines()
    out = []
    for lineno, label in EXPLAIN_PICKS:
        line = lines[lineno - 1]
        result = explain(line, index=index)
        if result is None:
            raise SystemExit(
                f"EXPLAIN_PICKS line {lineno} ({label}) holds no denial; "
                f"the LOG above has changed and the picks need revisiting")
        out.append((line, to_json(result).rstrip("\n")))
    return out


def main() -> int:
    index = load_text(POLICY, source="selftest.embedded")
    # Pinned rather than "now": the vectors are committed to a source file, so a
    # stamp that moves on every run would make regenerating them a spurious diff
    # and hide the one thing worth noticing -- a real change to a verdict.
    pli = export_text(index, src_label="selftest.embedded",
                      gen_time="2026-09-10T00:00:00Z")

    report = converge(LOG, index=index).to_dict()

    print("// ---- kSelfTestPli ----")
    print("const char *const kSelfTestPli = R\"PLI(" + pli + ")PLI\";")
    print()
    print("// ---- kSelfTestLog ---- (paste LOG verbatim)")
    print()
    print("// ---- kSelfTestVectors ----")
    for cluster in report["clusters"]:
        # ensure_ascii=False keeps the Chinese reasons readable in the source;
        # json.dumps' escaping is a subset of C++'s, so the line pastes as-is.
        print("    " + _cpp(cluster), )
    print()
    print("// clusters=%d by_category=%s by_classification=%s" % (
        len(report["clusters"]), report["by_category"],
        report["by_classification"]))
    print()
    print("// ---- kSelfTestExplainVectors ----")
    for (lineno, label), (line, expected) in zip(EXPLAIN_PICKS,
                                                 explain_vectors(index)):
        print("    // %s" % label)
        print("    {" + _cpp_str(line) + ",")
        print("     " + _cpp_str(expected) + "},")
    return 0


def _cpp_str(s: str) -> str:
    """A C++ string literal for *s*.

    json.dumps' escaping (\\", \\\\, \\n, \\uXXXX for the rest of C0) is a subset
    of C++'s, and the JSON is mostly Chinese that must stay literal, so the JSON
    encoder is the right one here -- it produces a valid C++ literal for exactly
    this text, with no hand-rolled escaping to get wrong.
    """
    import json
    return json.dumps(s, ensure_ascii=False)


def _cpp(cluster: dict) -> str:
    import json
    return json.dumps(digest(cluster), ensure_ascii=False) + ","


if __name__ == "__main__":
    raise SystemExit(main())
