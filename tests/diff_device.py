#!/usr/bin/env python3
"""Differential harness: host Python engine vs. on-device C++ tool.

The device-side ``denial_check`` claims to reach the same verdicts as
``policy_loop``. That claim is only worth anything if it is checked, so this
harness feeds both sides the same input and compares their output. Two levels:

``parse``
    Compare denial parsing alone. Both sides emit one JSON object per record
    (JSONL, sorted keys, same separators), so the comparison is a line diff --
    which names the offending record instead of just reporting "output differs".

``report``
    Compare whole convergence reports (see ``diff_reports``). This is the
    acceptance gate: unique case counts, categories, and every patch/why string
    must match byte for byte.

Usage::

    python tests/diff_device.py parse  --corpus /tmp/corpus_B.txt
    python tests/diff_device.py report --corpus /tmp/corpus_B.txt \\
        --policy data/raw/oh-selinux/sepolicy --index build/pli/ohos-rk3568.pli

The device binary defaults to ``/tmp/denial_check_host`` (see tools/devbuild.sh).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policy_loop.denial.parser import fingerprint, parse  # noqa: E402

DEFAULT_BIN = "/tmp/denial_check_host"

# Control-byte cases. These live here rather than in data/fixtures because a
# text fixture cannot express them readably, and they are precisely where the
# two line-splitting implementations are most likely to diverge: Python's
# str.splitlines() treats \v, \f and \x1c-\x1e as line breaks, which almost no
# hand-written equivalent does. Each entry is (label, literal bytes).
EDGE_CONTROL_CASES = [
    ("crlf", "audit: avc: denied { read } for comm=\"a\"\r\nscontext=u:r:crlf:s0\r\n"
             "tcontext=u:object_r:b:s0 tclass=file\r\n"),
    ("cr-only", "audit: avc: denied { read } for comm=\"b\"\rscontext=u:r:cronly:s0\r"
                "tcontext=u:object_r:b:s0 tclass=file\r"),
    ("vertical-tab-splits", "avc: denied { read } for comm=\"c\" scontext=u:r:vt:s0\v"
                            "tcontext=u:object_r:b:s0 tclass=file"),
    ("form-feed-splits", "avc: denied { read } for comm=\"d\" scontext=u:r:ff:s0\f"
                         "tcontext=u:object_r:b:s0 tclass=file"),
    ("file-separators", "avc: denied { read } for comm=\"e\" scontext=u:r:fs:s0\x1c"
                        "tcontext=u:object_r:b:s0\x1d tclass=file\x1e"),
    ("embedded-nul", "avc: denied { read } for comm=\"f\x00g\" scontext=u:r:nul:s0 "
                     "tcontext=u:object_r:b:s0 tclass=file\x00"),
    ("no-trailing-newline", "avc: denied { read } for comm=\"h\" scontext=u:r:notrail:s0 "
                            "tcontext=u:object_r:b:s0 tclass=file"),
    ("trailing-blank-lines", "avc: denied { read } for comm=\"i\" scontext=u:r:blanks:s0 "
                             "tcontext=u:object_r:b:s0 tclass=file\n\n\n\n"),
    ("marker-at-eof", "avc: denied"),
    ("crlf-backslash-continuation", "avc: denied { read } for comm=\"j\" \\\r\n"
                                    "scontext=u:r:bslash:s0 tcontext=u:object_r:b:s0 tclass=file"),
    ("high-bytes-utf8", "avc: denied { read } for comm=\"中文\" scontext=u:r:utf8:s0 "
                        "tcontext=u:object_r:b:s0 tclass=file"),
    # Lone surrogates in the literal become the raw bytes \xff\xfe\x80 once
    # edge_corpus_text() encodes with surrogateescape. Both sides decode the
    # same way, so a parser that mangles non-UTF-8 input is caught rather than
    # quietly excused; a lossy decode on one side only would hide the bug.
    ("invalid-utf8-bytes", "avc: denied { read } for comm=\"\udcff\udcfe\udc80\" scontext=u:r:bad:s0 "
                           "tcontext=u:object_r:b:s0 tclass=file"),
    ("empty-input", ""),
    ("no-marker-at-all", "just a log line\nand another\n"),
]


def edge_corpus_text() -> str:
    """Concatenate the control-byte cases into one document.

    Joined with a plain newline so the cases also exercise block boundaries
    between differently-terminated events.
    """
    return "\n".join(text for _, text in EDGE_CONTROL_CASES)


def fingerprint_payload(rec) -> str:
    """The exact JSON byte string ``fingerprint`` hashes.

    Mirrors ``pl_avc_parser.cpp:FingerprintPayload`` -- kept here rather than
    reusing an internal helper so that a change to one side shows up as a diff
    rather than being silently absorbed by both.
    """
    key = {
        "src": rec.source_domain,
        "tgt": rec.target_type,
        "cls": rec.tclass,
        "perms": sorted(rec.permissions or ()),
        "ioctl": rec.ioctl_cmd,
    }
    return json.dumps(key, sort_keys=True, ensure_ascii=False)


def host_parse_jsonl(text: str) -> str:
    lines = []
    for rec in parse(text):
        lines.append(json.dumps({
            "cls": rec.tclass,
            "comm": rec.comm,
            "fp": fingerprint(rec),
            "ioctl": rec.ioctl_cmd,
            "name": rec.name,
            "parameter": rec.parameter,
            "path": rec.path,
            "payload": fingerprint_payload(rec),
            "permissive": rec.permissive,
            "perms": list(rec.permissions),
            "pid": rec.pid,
            "raw": rec.raw,
            "service": rec.service,
            "src": rec.source_domain,
            "tgt": rec.target_type,
        }, sort_keys=True, ensure_ascii=False))
    return "".join(line + "\n" for line in lines)


def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, **kwargs)


def diff_lines(expected: str, actual: str, limit: int = 5) -> list:
    """Line-level differences, so a failure points at a record, not a blob."""
    exp = expected.splitlines()
    act = actual.splitlines()
    problems = []
    if len(exp) != len(act):
        problems.append(f"record count: host={len(exp)} device={len(act)}")
    for i, (a, b) in enumerate(zip(exp, act)):
        if a != b:
            problems.append(f"line {i + 1} differs\n  host  : {a[:400]}\n  device: {b[:400]}")
            if len(problems) >= limit:
                problems.append("... (further differences suppressed)")
                break
    return problems


def compare_parse(label: str, data: bytes, binary: str) -> list:
    """Compare both sides on one byte exact input. Empty list == agreement."""
    # The device tool reads bytes; Python reads str. Decode with surrogateescape
    # so that no byte sequence is silently replaced -- a lossy decode on one side
    # only would hide a real divergence.
    text = data.decode("utf-8", errors="surrogateescape")
    expected = host_parse_jsonl(text)

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as fh:
        fh.write(data)
        tmp = fh.name
    try:
        proc = run([binary, "--dump-denials", "--log", tmp])
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)

    if proc.returncode != 0:
        return [f"device binary exited {proc.returncode}: "
                f"{proc.stderr.decode(errors='replace').strip()}"]
    actual = proc.stdout.decode("utf-8", errors="surrogateescape")

    problems = diff_lines(expected, actual)
    if not problems:
        print(f"[diff]   {label}: OK  {len(expected.splitlines())} records")
    return problems


def cmd_parse(args) -> int:
    inputs = [(str(args.corpus), pathlib.Path(args.corpus).read_bytes())]
    if args.edges:
        for label, text in EDGE_CONTROL_CASES:
            inputs.append((f"edge:{label}",
                           text.encode("utf-8", errors="surrogateescape")))

    failures = []
    for label, data in inputs:
        problems = compare_parse(label, data, args.bin)
        if problems:
            failures.append((label, problems))

    if failures:
        for label, problems in failures:
            print(f"[diff] parse MISMATCH [{label}]")
            for p in problems:
                print("  " + p)
        print(f"\n[diff] parse FAILED  {len(failures)}/{len(inputs)} inputs differ")
        return 1
    print(f"[diff] parse OK  {len(inputs)} input(s) agree byte for byte")
    return 0


def gen_queries(index, corpus_text: str, random_n: int, seed: int = 20260910) -> list:
    """Build the query set fed to both sides.

    Three sources, deliberately overlapping:

    * every real (src, tgt, cls, perms, ioctlcmd) a denial in the corpus
      actually reports -- the shape that matters in production;
    * perturbations of those (perm subsets, the full set, a bogus permission,
      ioctlcmd dropped) -- these are what catch the wildcard and
      unknown-token paths;
    * uniformly sampled (src, tgt, cls) triples drawn from declared names, so
      the sample is not limited to accesses someone happened to deny.
    """
    queries = []
    for rec in parse(corpus_text):
        if not (rec.source_domain and rec.target_type and rec.tclass):
            continue
        perms = list(rec.permissions)
        cmd = rec.ioctl_cmd or "-"
        queries.append((rec.source_domain, rec.target_type, rec.tclass, perms, cmd))
        if len(perms) > 1:
            queries.append((rec.source_domain, rec.target_type, rec.tclass, perms[:-1], cmd))
        queries.append((rec.source_domain, rec.target_type, rec.tclass, [], cmd))
        queries.append((rec.source_domain, rec.target_type, rec.tclass,
                        perms + ["no_such_perm_xyz"], cmd))
        queries.append((rec.source_domain, rec.target_type, rec.tclass, perms, "-"))
        # a target that is a real attribute rather than a type
        for attr in list(index.attributes)[:1]:
            queries.append((rec.source_domain, attr, rec.tclass, perms, cmd))

    rng = random.Random(seed)
    types = sorted(index.type_attrs)
    attrs = sorted(index.attributes)
    classes = sorted({r.cls for r in index.rules})
    if types and classes:
        pool = types + attrs
        for _ in range(random_n):
            src = rng.choice(pool)
            tgt = rng.choice(pool)
            cls = rng.choice(classes)
            perms = rng.sample(ALL_PERMS, rng.randint(0, 4))
            cmd = rng.choice(["-", "0x5401", "0x5401-0x5404", "0x6201", "0X6201"])
            queries.append((src, tgt, cls, perms, cmd))
    return queries


# Permission names used when sampling; deliberately mixed so that the wildcard
# path is reachable but most samples are ordinary.
ALL_PERMS = ["read", "write", "open", "ioctl", "getattr", "setattr", "execute",
             "search", "create", "unlink", "map", "call", "use", "add"]


def host_query_jsonl(index, queries) -> str:
    lines = []
    for src, tgt, cls, perms, cmd in queries:
        allowed, granted, _ = index.has_access(src, tgt, cls, frozenset(perms))
        io_allowed, io_reason, _ = index.ioctl_allowed(src, tgt, cls, cmd)
        neverallow = len(index.neverallow_rules(src, tgt, cls, frozenset(perms)))
        lines.append(json.dumps({
            "allowed": allowed,
            "granted": sorted(granted),
            "ioctl_allowed": io_allowed,
            "ioctl_reason": io_reason,
            "neverallow": neverallow,
        }, sort_keys=True, ensure_ascii=False))
    return "".join(line + "\n" for line in lines)


def write_queries(queries, path: pathlib.Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for src, tgt, cls, perms, cmd in queries:
            fh.write(f"{src}\t{tgt}\t{cls}\t{','.join(perms)}\t{cmd}\n")


def cmd_index(args) -> int:
    from policy_loop.policy import load_dir

    if not args.policy:
        print("[diff] index mode needs --policy <sepolicy dir>", file=sys.stderr)
        return 2
    policy_dir = pathlib.Path(args.policy)
    if not policy_dir.exists():
        print(f"[diff] policy dir not found: {policy_dir}", file=sys.stderr)
        return 2

    index = load_dir(policy_dir)
    summary = index.summary()

    # Gate 1: the counters. If these disagree the index did not survive export
    # and nothing downstream is worth comparing.
    proc = run([args.bin, "--index", args.index, "--index-info"])
    if proc.returncode != 0:
        print(f"[diff] device --index-info failed ({proc.returncode}): "
              f"{proc.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return 3 if proc.returncode == 3 else 2
    device_meta = json.loads(proc.stdout.decode())

    kinds = summary["kinds"]
    # The APL bridge rides along. On an index built from a single `.te` file
    # there is no sehap_contexts and the host has no `sehap` attribute at all --
    # the exporter writes zeros there, so the expectation is zeros.
    hap = getattr(index, "sehap", None)
    hap_summary = hap.summary() if hap is not None else {}
    expected = {
        "rules": summary["rules"],
        "allow": kinds.get("allow", 0),
        "neverallow": kinds.get("neverallow", 0),
        "allowxperm": kinds.get("allowxperm", 0),
        "neverallowxperm": kinds.get("neverallowxperm", 0),
        "types": summary["types"],
        "attrs": summary["attributes"],
        "skipped": summary["skipped_statements"],
        "hap_entries": hap_summary.get("hap_entries", 0),
        "hap_domains": hap_summary.get("hap_domains", 0),
        "hap_names": hap_summary.get("hap_names", 0),
        "hap_apls": hap_summary.get("hap_apls", 0),
        "hap_debuggable": hap_summary.get("hap_debuggable", 0),
        "hap_skipped": hap_summary.get("hap_skipped", 0),
    }
    mismatches = [f"{k}: host={v} device={device_meta.get(k)}"
                  for k, v in expected.items() if device_meta.get(k) != v]
    if mismatches:
        print("[diff] index counters MISMATCH")
        for m in mismatches:
            print("  " + m)
        return 1
    print(f"[diff] index counters OK  rules={expected['rules']} "
          f"types={expected['types']} attrs={expected['attrs']} "
          f"skipped={expected['skipped']} "
          f"hap_entries={expected['hap_entries']} "
          f"hap_domains={expected['hap_domains']}  "
          f"load={device_meta.get('load_ms')}ms")

    corpus = pathlib.Path(args.corpus)
    corpus_text = corpus.read_text(encoding="utf-8", errors="replace") if corpus.exists() else ""
    queries = gen_queries(index, corpus_text, args.random)
    qpath = pathlib.Path(tempfile.mkdtemp()) / "queries.tsv"
    write_queries(queries, qpath)
    print(f"[diff] {len(queries)} queries")

    expected_out = host_query_jsonl(index, queries)
    proc = run([args.bin, "--index", args.index, "--query", str(qpath)])
    if proc.returncode != 0:
        print(f"[diff] device --query failed ({proc.returncode}): "
              f"{proc.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return 2
    actual_out = proc.stdout.decode("utf-8", errors="replace")

    problems = diff_lines(expected_out, actual_out)
    if problems:
        print(f"[diff] query MISMATCH  {len(problems)} shown")
        for p in problems:
            print("  " + p)
        return 1
    print(f"[diff] query OK  {len(queries)} queries agree byte for byte")
    return 0


def compare_json(expected, actual, path: str, problems: list, limit: int = 5) -> None:
    """Deep-compare two decoded JSON values, naming the first paths that differ.

    A path-naming comparison rather than a text diff: the two sides emit the
    same object in different key orders and the device is allowed extra keys, so
    a line diff would be all noise. An empty `problems` means agreement.
    """
    if len(problems) >= limit:
        return
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in expected:
            if key not in actual:
                problems.append(f"{path}.{key}: missing on device")
                if len(problems) >= limit:
                    return
                continue
            compare_json(expected[key], actual[key], f"{path}.{key}", problems, limit)
            if len(problems) >= limit:
                return
        return
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            problems.append(f"{path}: length host={len(expected)} device={len(actual)}")
            return
        for i, (a, b) in enumerate(zip(expected, actual)):
            compare_json(a, b, f"{path}[{i}]", problems, limit)
            if len(problems) >= limit:
                return
        return
    if isinstance(expected, float) or isinstance(actual, float):
        # The report carries one float (dedup_ratio). Both sides compute it from
        # the same two integers, so it must land on the same value, not merely a
        # close one -- a tolerance here would hide a real counting difference.
        if not (isinstance(expected, (int, float)) and isinstance(actual, (int, float))
                and float(expected) == float(actual)):
            problems.append(f"{path}: host={expected!r} device={actual!r}")
        return
    if expected != actual:
        problems.append(f"{path}:\n  host  : {expected!r}\n  device: {actual!r}")


def unique_cases(text: str) -> list:
    """One representative record per unique logical access, in corpus order.

    The same clustering converge.py uses, minus the pipeline: `--explain` gives
    every duplicate in a group the same answer, so checking one per group covers
    the corpus at a fraction of the process launches.
    """
    from policy_loop.denial import fingerprint, parse as parse_denials

    seen: set = set()
    out: list = []
    for rec in parse_denials(text):
        fp = fingerprint(rec)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(rec)
    return out


def cmd_explain(args) -> int:
    from policy_loop.explain import explain
    from policy_loop.policy import load_dir

    if not args.policy:
        print("[diff] explain mode needs --policy <sepolicy dir>", file=sys.stderr)
        return 2
    policy_dir = pathlib.Path(args.policy)
    if not policy_dir.exists():
        print(f"[diff] policy dir not found: {policy_dir}", file=sys.stderr)
        return 2

    text = pathlib.Path(args.corpus).read_bytes().decode("utf-8",
                                                          errors="surrogateescape")
    index = load_dir(policy_dir)
    # `--cases 0` means every unique case; the cap exists because each one costs
    # a device process launch (the PLI index load dominates it).
    cases = unique_cases(text)
    if args.cases:
        cases = cases[:args.cases]
    if args.placeholder:
        # The M3 cases: a denial whose tcontext is a samgr/hdf placeholder. They
        # are the ones most likely to diverge, so they are always in scope.
        from policy_loop.policy import is_service_placeholder
        cases = [r for r in cases if is_service_placeholder(r.target_type)]

    # No hand-written guard cases are appended here. They were, briefly, on the
    # theory that the corpus holds no refusals; it does. Of the 4911 unique
    # cases, 90 carry a non-empty `advisory`, and between them they exercise all
    # six `apply_guards` branches (mls-level 5, placeholder 13, unknown-token 59,
    # unknown-class 6, bogus-perm 3, vacuous-patch 4). The field that was never
    # compared before was unexercised because `--explain` did not *run* the
    # guards, not because the corpus could not reach them -- so the fix belongs
    # in the engine, and this gate picks the coverage up for free.

    # The cross-layer view rides on the same cases and is compared the same way
    # -- it is the one part of `--explain` whose wording the device has to
    # reproduce from the `@hap` table rather than from the rules, so it is the
    # part most likely to drift.
    extra_flags = ["--cross-layer"] if args.cross_layer else []
    if args.cross_layer and not any(e.name for e in _hap_entries(index)):
        print("[diff] index has no @hap table: cross-layer mode has nothing to "
              "compare", file=sys.stderr)
        return 2

    problems: list = []
    checked = 0
    for rec in cases:
        expected = explain(rec.raw, index=index, cross_layer=args.cross_layer)
        proc = run([args.bin, "--index", args.index, "--explain", rec.raw,
                    "--json"] + extra_flags)
        if proc.returncode != 0:
            problems.append(f"{rec.raw[:100]}\n  device rc={proc.returncode}: "
                            f"{proc.stderr.decode(errors='replace').strip()}")
            if len(problems) >= args.limit:
                break
            continue
        try:
            actual = json.loads(proc.stdout.decode("utf-8",
                                                   errors="surrogateescape"))
        except json.JSONDecodeError as exc:
            problems.append(f"{rec.raw[:100]}\n  device output is not JSON: {exc}")
            if len(problems) >= args.limit:
                break
            continue
        before = len(problems)
        compare_json(expected, actual, "explain", problems, len(problems) + 1)
        if len(problems) > before:
            problems.insert(before, f"  line: {rec.raw[:160]}")
            if len(problems) >= args.limit:
                break
        checked += 1

    if problems:
        print(f"[diff] explain MISMATCH  ({len(problems)} shown, "
              f"{checked}/{len(cases)} agreed before this)")
        for p in problems:
            print("  " + p)
        return 1
    print(f"[diff] explain OK  cases={checked}"
          + ("  (with cross-layer)" if args.cross_layer else ""))
    return 0


def _hap_entries(index) -> list:
    """The index's APL bridge, or [] when it has none to compare from."""
    sehap = getattr(index, "sehap", None)
    return list(getattr(sehap, "entries", ()) or ())


def case_tsv(rec) -> str:
    """One record as the device's --case input line.

    The point of the format is that the *host* splits the record: the device is
    never handed an `avc: denied` line here, only fields. So a field the parser
    left as None must arrive as the absent sentinel, not as the empty string --
    the verdict renders those two differently ("None" versus "").
    """
    permissive = {True: "permissive", False: "enforcing", None: "unknown"}[rec.permissive]
    return "\t".join([
        rec.source_domain if rec.source_domain is not None else "-",
        rec.target_type if rec.target_type is not None else "-",
        rec.tclass if rec.tclass is not None else "-",
        ",".join(rec.permissions) if rec.permissions else "-",
        permissive,
        rec.ioctl_cmd if rec.ioctl_cmd else "-",
        rec.service if rec.service else "-",
    ])


def cmd_case(args) -> int:
    """Per-record verdicts vs the same case's line in the batch report.

    This is the contract ExplainCase exists to hold: one record decided on its
    own must equal that record's cluster in the report the device produces in
    batch. Both sides come from this repo -- the host's converge() and the
    device's Converge() are already known equal (see the `report` mode), so
    checking the per-record API against either one checks it against both.
    """
    from policy_loop.converge import converge
    from policy_loop.denial import fingerprint
    from policy_loop.policy import load_dir

    if not args.policy:
        print("[diff] case mode needs --policy <sepolicy dir>", file=sys.stderr)
        return 2
    policy_dir = pathlib.Path(args.policy)
    if not policy_dir.exists():
        print(f"[diff] policy dir not found: {policy_dir}", file=sys.stderr)
        return 2

    text = pathlib.Path(args.corpus).read_bytes().decode("utf-8",
                                                         errors="surrogateescape")
    index = load_dir(policy_dir)
    report = json.loads(json.dumps(converge(text, index=index).to_dict(),
                                   ensure_ascii=False))
    by_fp = {c["fp"]: c for c in report["clusters"]}

    cases = unique_cases(text)
    if args.cases:
        cases = cases[:args.cases]

    # One process for the whole batch, not one per case: the stream is the
    # interface, so driving N records must not cost N index loads.
    payload = "".join(case_tsv(rec) + "\n" for rec in cases)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="diff_case_")) / "cases.tsv"
    tmp.write_text(payload, encoding="utf-8", errors="surrogateescape")
    cmd = [args.bin, "--index", args.index, "--case", str(tmp)]
    if args.full:
        cmd.append("--full")
    proc = run(cmd)
    if proc.returncode != 0:
        print(f"[diff] case: device rc={proc.returncode}: "
              f"{proc.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return 1

    got = [json.loads(line) for line in
           proc.stdout.decode("utf-8", errors="surrogateescape").splitlines() if line]
    if len(got) != len(cases):
        print(f"[diff] case MISMATCH  device returned {len(got)} verdicts for "
              f"{len(cases)} records")
        return 1

    # The fields a cluster carries. `why` is included on purpose: the two settle
    # paths word it differently, so if the device took the wrong path for a case
    # this is where it shows.
    problems: list = []
    checked = 0
    for rec, actual in zip(cases, got):
        cluster = by_fp.get(fingerprint(rec))
        if cluster is None:
            continue
        expected = {
            "category": cluster["category"],
            "classification": cluster["classification"],
            "why": cluster["why"],
            "patch": cluster["patch"],
            "review_status": cluster["review_status"],
            "verify_status": cluster["verify_status"],
            "requested": sorted(set(cluster["perms"])),
            # The cluster keeps the raw field ("" when absent); the verdict
            # renders an absent one as "None", the way the patch text spells it.
            "src": rec.source_domain if rec.source_domain is not None else "None",
            "tgt": rec.target_type if rec.target_type is not None else "None",
            "cls": rec.tclass if rec.tclass is not None else "None",
        }
        before = len(problems)
        for key, want in expected.items():
            if actual.get(key) != want:
                problems.append(f"{key}: host {want!r} != device {actual.get(key)!r}")
        if len(problems) > before:
            problems.insert(before, f"  line: {rec.raw[:160]}")
            if len(problems) >= args.limit:
                break
        checked += 1

    if problems:
        print(f"[diff] case MISMATCH  ({len(problems)} shown, "
              f"{checked}/{len(cases)} agreed before this)")
        for p in problems:
            print("  " + p)
        return 1
    print(f"[diff] case OK  cases={checked}")
    return 0


def cmd_report(args) -> int:
    from policy_loop.converge import converge
    from policy_loop.policy import load_dir

    if not args.policy:
        print("[diff] report mode needs --policy <sepolicy dir>", file=sys.stderr)
        return 2
    policy_dir = pathlib.Path(args.policy)
    if not policy_dir.exists():
        print(f"[diff] policy dir not found: {policy_dir}", file=sys.stderr)
        return 2

    corpus = pathlib.Path(args.corpus)
    data = corpus.read_bytes()

    # Both sides decode the same bytes the same way; a lossy decode on one side
    # only would hide a divergence rather than expose it.
    text = data.decode("utf-8", errors="surrogateescape")
    index = load_dir(policy_dir)
    # Round-trip through JSON so the host side is compared as *serialized*
    # values: to_dict() carries the dataclass fields through asdict(), which
    # leaves tuples as tuples, while the device can only ever emit arrays.
    expected = json.loads(json.dumps(converge(text, index=index).to_dict(),
                                     ensure_ascii=False))

    proc = run([args.bin, "--index", args.index, "--log", str(corpus), "--converge"])
    if proc.returncode != 0:
        print(f"[diff] device --converge failed ({proc.returncode}): "
              f"{proc.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return 2
    try:
        actual = json.loads(proc.stdout.decode("utf-8", errors="surrogateescape"))
    except json.JSONDecodeError as exc:
        print(f"[diff] device report is not valid JSON: {exc}", file=sys.stderr)
        return 2

    problems: list = []
    compare_json(expected, actual, "report", problems, args.limit)
    if problems:
        print(f"[diff] report MISMATCH  ({len(problems)} shown)")
        for p in problems:
            print("  " + p)
        return 1

    # Existence-only checks on the device's own block: it carries timing and
    # sampling facts the host cannot know, so its values are not comparable --
    # but a report that lost the block entirely is a regression worth failing.
    device = actual.get("device", {})
    missing = [k for k in ("rules_loaded", "sampled", "source")
               if k not in device] if args.require_device else []
    if missing:
        print(f"[diff] device block missing keys: {', '.join(missing)}")
        return 1

    print(f"[diff] report OK  denials={expected['total_denials']} "
          f"unique={expected['unique_cases']} "
          f"by_category={expected['by_category']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", default=DEFAULT_BIN,
                    help=f"device binary (default {DEFAULT_BIN})")
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("parse", help="compare denial parsing only")
    p.add_argument("--corpus", required=True)
    p.add_argument("--edges", action="store_true",
                   help="also run the built-in control-byte cases (CRLF, \\v, "
                        "\\f, NUL, UTF-8, unterminated input)")
    p.set_defaults(func=cmd_parse)

    p = sub.add_parser("index", help="compare PLI loading and policy queries")
    p.add_argument("--corpus", required=True,
                   help="denial corpus whose records seed the query set")
    p.add_argument("--policy", required=True, help="sepolicy dir (host index)")
    p.add_argument("--index", required=True, help="PLI file for the device")
    p.add_argument("--random", type=int, default=2000,
                   help="extra uniformly sampled queries (default 2000)")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("explain", help="compare single-denial explanations")
    p.add_argument("--corpus", required=True, help="denial log to sample")
    p.add_argument("--policy", required=True, help="sepolicy dir (host index)")
    p.add_argument("--index", required=True, help="PLI file for the device")
    p.add_argument("--cases", type=int, default=200,
                   help="unique cases to check, in corpus order (0 = all)")
    p.add_argument("--placeholder", action="store_true",
                   help="check only samgr/hdf placeholder denials (the M3 cases)")
    p.add_argument("--cross-layer", action="store_true",
                   help="compare the application-layer view too (--explain "
                        "--cross-layer). Needs an index carrying @hap.")
    p.add_argument("--limit", type=int, default=5,
                   help="differences to collect before stopping (default 5)")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("case", help="compare per-record verdicts (--case)")
    p.add_argument("--corpus", required=True, help="denial log to sample")
    p.add_argument("--policy", required=True, help="sepolicy dir (host index)")
    p.add_argument("--index", required=True, help="PLI file for the device")
    p.add_argument("--cases", type=int, default=200,
                   help="unique cases to check, in corpus order (0 = all)")
    p.add_argument("--full", action="store_true",
                   help="drive the full pipeline path instead of quick-then-"
                        "pipeline (then `why` legitimately differs; not run here)")
    p.add_argument("--limit", type=int, default=5,
                   help="differences to collect before stopping (default 5)")
    p.set_defaults(func=cmd_case)

    p = sub.add_parser("report", help="compare whole convergence reports")
    p.add_argument("--corpus", required=True, help="denial log to converge")
    p.add_argument("--policy", required=True, help="sepolicy dir (host index)")
    p.add_argument("--index", required=True, help="PLI file for the device")
    p.add_argument("--limit", type=int, default=5,
                   help="differences to print before stopping (default 5)")
    p.add_argument("--require-device", action="store_true",
                   help="also require the device block's keys to be present")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    if not pathlib.Path(args.bin).exists():
        print(f"[diff] device binary not found: {args.bin}\n"
              f"       build it with tools/devbuild.sh", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
