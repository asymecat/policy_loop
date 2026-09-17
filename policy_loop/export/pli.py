"""PLI v1 — compact text serialization of a ``PolicyIndex`` for on-device lookup.

The device-side tool (``denial_check``) must reach the *same* verdicts as the
host-side Python engine, so this format is a lossless projection of exactly the
fields the deterministic queries depend on: rule kind, class, subject/target
sets (with negatives and star), permissions, and xperm command lists.

Deliberately dropped:

* ``Rule.raw`` — nothing in the query path reads it.
* ``~{ ... }`` set contents — ``PolicyIndex._parse_subject`` already collapses
  ``~set`` to ``star=True``, so we encode the same approximation.

Attribute handling: ``PolicyIndex._attrs()`` computes a *transitive* closure of
ancestor attributes per type. We pre-expand that closure here (2,076 edges /
~49 KB on the upstream corpus) rather than expanding it into the rules, which
would blow up to ~800 KB of (type, type) pairs.

Format::

    PLI1
    @rev 1
    @src <label> gen=<iso8601> exporter=policy_loop/export/pli.py
    @meta rules=.. allow=.. neverallow=.. allowxperm=.. neverallowxperm=..
          types=.. attrs=.. classes=.. perms=.. known=.. skipped=..
    @class <name> <rule_count>
    @type  <name> <ancestor-attr>...
    @attr  <name>
    @known <name>
    @perm  <name>
    @hap   <apl> <domain> <type> <debuggable> <name> <extension> <extra>
    @rules <count>
    <kind> <cls> <src> <tgt> <perms>

``@hap`` lines carry the APL <-> domain bridge (``policy/sehap.py``): the device
has no sepolicy source to read it from, and without it a denial's
``scontext=u:r:normal_hap:s0`` cannot be attributed to an application. Seven
positional fields, ``-`` for an absent one, ``debuggable`` as ``1``/``0``.

Note what the section does *not* do: it does not collapse a domain to one level.
``isolated_gpu`` legitimately appears at three levels and
``distributed_isolate_hap`` appears twice (plain and ``debuggable``), so the
reader keeps every line and the query returns a set. A future "optimization"
that dedupes by domain would silently narrow the answer.

Rule-line encoding (single-space separated; tokens contain no whitespace):

* ``kind``      — ``a`` allow / ``n`` neverallow / ``x`` allowxperm / ``z`` neverallowxperm
* ``src``/``tgt`` — comma-joined tokens; ``*`` means star; a leading ``-`` marks a
  negative member; everything else is a positive member
* ``perms``     — for ``a``/``n``: comma-joined permission names, or ``*`` when the
  set is empty (an empty set is a wildcard in ``has_access``, so the distinction
  from "no permissions" must be preserved)
                  for ``x``/``z``: ``<xperm_perm>:<cmd>,<cmd>``, with a leading ``~``
  on the perm field marking an inverted (``neverallowxperm ~{...}``) rule
"""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Iterable, Optional

__all__ = ["PLI_VERSION", "export_text", "export_file", "compute_meta",
           "parse_text"]

PLI_VERSION = 2
EXPORTER = "policy_loop/export/pli.py"

# Positions of the `@hap` fields, in the order the line carries them. Kept as a
# tuple so the encoder, the decoder and the C++ reader can all be checked
# against one list rather than three hand-kept orderings.
_HAP_FIELDS = ("apl", "domain", "type", "debuggable", "name", "extension",
               "extra")
_HAP_EMPTY = "-"


def _enc_hap(entry) -> str:
    parts = []
    for name in _HAP_FIELDS:
        value = getattr(entry, name)
        if name == "debuggable":
            parts.append("1" if value else "0")
        else:
            parts.append(value if value else _HAP_EMPTY)
    return "@hap " + " ".join(parts)


def _hap_sort_key(entry) -> tuple:
    """Total order over entries — mirrors the C++ exporter's comparator."""
    return (entry.domain, entry.apl, entry.debuggable, entry.name,
            entry.extension, entry.extra, entry.type)


def _dec_hap(fields: list):
    """Inverse of :func:`_enc_hap`; *fields* excludes the ``@hap`` marker.

    Strict on purpose: ``debuggable`` is only ever ``1`` or ``0``, so anything
    else means a corrupted line, and inventing a value for it would produce a
    table that quietly disagrees with the host.
    """
    from policy_loop.policy.sehap import SehapEntry

    if len(fields) != len(_HAP_FIELDS):
        raise ValueError(f"malformed @hap line ({len(fields)} fields): "
                         f"{' '.join(fields)!r}")
    values = ["" if f == _HAP_EMPTY else f for f in fields]
    flag = values[3]
    if flag not in ("0", "1"):
        raise ValueError(f"malformed @hap debuggable flag: {flag!r}")
    return SehapEntry(
        apl=values[0], domain=values[1], type=values[2],
        debuggable=flag == "1",
        name=values[4], extension=values[5], extra=values[6])

# kind letter <-> Python's Rule.kind
_KIND_TO_LETTER = {
    "allow": "a",
    "neverallow": "n",
    "allowxperm": "x",
    "neverallowxperm": "z",
}


def _enc_subject(pos: Iterable[str], neg: Iterable[str], star: bool) -> str:
    """Encode one side of a rule (subject or target).

    Mirrors ``PolicyIndex._parse_subject`` in reverse: ``*`` -> star, ``-name``
    -> negative, ``name`` -> positive. An empty result is encoded as ``-`` so
    the field is never blank (keeps the line 5 whitespace-separated fields).
    """
    parts = []
    if star:
        parts.append("*")
    parts.extend(sorted(neg_with_prefix(neg)))
    parts.extend(sorted(pos))
    return ",".join(parts) if parts else "-"


def neg_with_prefix(neg: Iterable[str]) -> list:
    return ["-" + n for n in neg]


def _enc_perms(rule) -> str:
    if rule.kind in ("allowxperm", "neverallowxperm"):
        perm = rule.xperm_perm or ""
        tilde = "~" if rule.xperm_invert else ""
        cmds = ",".join(sorted(rule.xperms))
        return f"{tilde}{perm}:{cmds}"
    if not rule.perms:
        return "*"          # empty set == wildcard in has_access; must not become ""
    return ",".join(sorted(rule.perms))


def _known_tokens(index) -> tuple:
    """Replicate ``converge._known_tokens``.

    Kept as a local copy rather than an import so the exporter has no dependency
    on the agent layer; ``tests/test_export.py`` asserts the two agree on the
    real corpus, so drift is caught rather than silently shipped.

    Note: only *positive* members are collected, matching the upstream behaviour
    (``Rule.src``/``Rule.tgt`` are frozensets of positives; ``src_neg`` and the
    star flag are not folded in).
    """
    known = set(index.type_attrs)
    classes: set = set()
    perms: set = set()
    for r in index.rules:
        known.update(r.src)
        known.update(r.tgt)
        classes.add(r.cls)
        if not r.is_xperm:
            perms.update(r.perms)
    return known, classes, perms


def compute_meta(index) -> dict:
    """The ``@meta`` counters, plus the ``known``/``classes`` sets they size."""
    known, classes, perms = _known_tokens(index)
    kinds: dict = {}
    for r in index.rules:
        kinds[r.kind] = kinds.get(r.kind, 0) + 1
    meta = {
        "rules": len(index.rules),
        "allow": kinds.get("allow", 0),
        "neverallow": kinds.get("neverallow", 0),
        "allowxperm": kinds.get("allowxperm", 0),
        "neverallowxperm": kinds.get("neverallowxperm", 0),
        "types": len(index.type_attrs),
        "attrs": len(index.attributes),
        "classes": len(classes),
        "perms": len(perms),
        "known": len(known),
        "skipped": index.skipped_count,
    }
    # The APL bridge. Absent on an index built from a single .te file, which
    # then exports zeros -- and a reader that finds @hap lines where the header
    # promised none fails the self-check rather than silently keeping them.
    sehap = getattr(index, "sehap", None)
    meta.update(sehap.summary() if sehap is not None else {
        "hap_entries": 0, "hap_domains": 0, "hap_names": 0, "hap_apls": 0,
        "hap_debuggable": 0, "hap_skipped": 0})
    return meta, known, classes, perms


def export_text(index, src_label: str = "<index>",
                gen_time: Optional[str] = None,
                header_note: str = "") -> str:
    """Serialize *index* to PLI v1 text."""
    import datetime

    meta, known, classes, perms = compute_meta(index)
    if gen_time is None:
        gen_time = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

    out: list = []
    out.append("PLI1")
    out.append(f"@rev {PLI_VERSION}")
    out.append(f"@src {src_label} gen={gen_time} exporter={EXPORTER}")
    out.append("@meta " + " ".join(f"{k}={v}" for k, v in meta.items()))
    if header_note:
        out.append(f"@note {header_note}")

    # class -> rule count directory (lets the device pre-size and cross-check)
    class_counts: dict = {}
    for r in index.rules:
        class_counts[r.cls] = class_counts.get(r.cls, 0) + 1
    for name in sorted(class_counts):
        out.append(f"@class {name} {class_counts[name]}")

    # type -> transitive ancestor-attribute closure, pre-expanded
    for name in sorted(index.type_attrs):
        attrs = sorted(index._attrs(name))
        out.append("@type " + name + (" " + " ".join(attrs) if attrs else ""))

    # declared attributes — needed for a faithful round-trip, because
    # resolve_logical_target() accepts a candidate that is "in type_attrs or in
    # attributes", and an attribute declared but never used appears only here.
    for name in sorted(index.attributes):
        out.append(f"@attr {name}")

    for name in sorted(known):
        out.append(f"@known {name}")
    for name in sorted(perms):
        out.append(f"@perm {name}")

    # APL bridge, in a total order so the export stays byte-stable whatever
    # order the filesystem handed the files back in.
    sehap = getattr(index, "sehap", None)
    for entry in sorted(getattr(sehap, "entries", ()), key=_hap_sort_key):
        out.append(_enc_hap(entry))

    out.append(f"@rules {len(index.rules)}")
    for r in index.rules:
        out.append(" ".join((
            _KIND_TO_LETTER[r.kind],
            r.cls,
            _enc_subject(r.src, r.src_neg, r.src_star),
            _enc_subject(r.tgt, r.tgt_neg, r.tgt_star),
            _enc_perms(r),
        )))
    out.append("")
    return "\n".join(out)


def export_file(index, out_path, src_label: str = "<index>",
                gzip_path=None, header_note: str = "") -> dict:
    """Write PLI text to *out_path* (and optionally a gzipped copy).

    Returns the meta dict, so callers can persist ``--index-info`` alongside.
    """
    text = export_text(index, src_label=src_label, header_note=header_note)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    if gzip_path:
        gz = Path(gzip_path)
        gz.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(gz, "wt", encoding="utf-8") as fh:
            fh.write(text)
    meta, _, _, _ = compute_meta(index)
    return meta


# --------------------------------------------------------------------------- #
# Reader — reference implementation of the loader the C++ side must mirror.
#
# Two purposes:
#   1. round-trip validation in tests (does the format survive a full query
#      comparison against the original index?), so format bugs are caught here
#      rather than as a mystery divergence on the device;
#   2. a readable spec for ``pl_index.cpp`` to be written against.
# --------------------------------------------------------------------------- #

_LETTER_TO_KIND = {v: k for k, v in _KIND_TO_LETTER.items()}


def _dec_subject(field: str) -> tuple:
    """Inverse of :func:`_enc_subject`. ``-`` is the empty-side marker."""
    pos: set = set()
    neg: set = set()
    star = False
    if field != "-":
        for tok in field.split(","):
            if not tok:
                continue
            if tok == "*":
                star = True
            elif tok.startswith("-"):
                neg.add(tok[1:])
            else:
                pos.add(tok)
    return frozenset(pos), frozenset(neg), star


def _dec_perms(field: str, kind: str) -> dict:
    """Inverse of :func:`_enc_perms`.

    xperm command tokens are kept as **opaque strings**, exactly as upstream
    ``_store_xp`` does — a range like ``0x5413-0x5414`` is one token and does
    NOT match its own endpoints, and matching is case-sensitive. See the note in
    ``tests/test_export.py``; this quirk is load-bearing for host/device
    agreement, so do not "fix" it on one side only.
    """
    if kind in ("allowxperm", "neverallowxperm"):
        tilde = field.startswith("~")
        body = field[1:] if tilde else field
        perm, _, cmds = body.partition(":")
        return {
            "xperm_perm": perm,
            "xperms": frozenset(c for c in cmds.split(",") if c),
            "xperm_invert": tilde,
        }
    if field == "*":
        return {"perms": frozenset()}
    return {"perms": frozenset(p for p in field.split(",") if p)}


def parse_text(text: str, source: str = "<pli>",
               verify_meta: bool = True):
    """Parse PLI v1 text back into a :class:`PolicyIndex`.

    Raises ``ValueError`` when the header is malformed or (with
    *verify_meta*) when the parsed counts disagree with ``@meta`` — the same
    self-check the device performs before answering any query.
    """
    from policy_loop.policy.index import PolicyIndex, Rule
    from policy_loop.policy.sehap import SehapTable

    idx = PolicyIndex()
    sehap = SehapTable()
    lines = text.splitlines()
    if not lines or lines[0] != "PLI1":
        raise ValueError("not a PLI1 file")
    if lines[1] != f"@rev {PLI_VERSION}":
        raise ValueError(f"unsupported PLI revision: {lines[1]!r}")

    meta: dict = {}
    class_decl: dict = {}
    known_decl: list = []
    perm_decl: list = []
    expected_rules: Optional[int] = None
    i = 1

    while i < len(lines):
        line = lines[i]
        if line.startswith("@meta "):
            for field in line[len("@meta "):].split():
                k, _, v = field.partition("=")
                meta[k] = int(v)
        elif line.startswith("@class "):
            _, name, count = line.split()
            class_decl[name] = int(count)
        elif line.startswith("@type "):
            parts = line[len("@type "):].split()
            name = parts[0]
            attrs = set(parts[1:])
            idx.type_attrs[name] = attrs
            idx.attributes.update(attrs)
        elif line.startswith("@attr "):
            idx.attributes.add(line[len("@attr "):].strip())
        elif line.startswith("@known "):
            known_decl.append(line[len("@known "):].strip())
        elif line.startswith("@perm "):
            perm_decl.append(line[len("@perm "):].strip())
        elif line.startswith("@hap "):
            sehap.entries.append(_dec_hap(line[len("@hap "):].split()))
        elif line.startswith("@rules "):
            expected_rules = int(line.split()[1])
            i += 1
            break
        i += 1

    if expected_rules is None:
        raise ValueError("missing @rules header")

    for line in lines[i:]:
        if not line:
            continue
        f = line.split()
        if len(f) != 5:
            raise ValueError(f"malformed rule line ({len(f)} fields): {line!r}")
        letter, cls, src_f, tgt_f, perms_f = f
        kind = _LETTER_TO_KIND.get(letter)
        if kind is None:
            raise ValueError(f"unknown rule kind letter: {letter!r}")
        pos, neg, star = _dec_subject(src_f)
        tpos, tneg, tstar = _dec_subject(tgt_f)
        idx.rules.append(Rule(
            kind=kind, src=pos, src_neg=neg, src_star=star,
            tgt=tpos, tgt_neg=tneg, tgt_star=tstar,
            cls=cls, **_dec_perms(perms_f, kind),
            raw=line,
        ))

    idx._sources.append(source)
    idx.sehap = sehap

    if verify_meta:
        parsed, known, classes, perms = compute_meta(idx)
        for key, got in parsed.items():
            # ``skipped``/``hap_skipped`` describe the *source* parse (macro
            # statements the indexer could not expand; sehap lines that were
            # neither blank, comment nor entry), not anything derivable from
            # the PLI payload, so they are reported rather than self-checked.
            # The device surfaces them as "index recall may be incomplete".
            if key in ("skipped", "hap_skipped"):
                continue
            want = meta.get(key)
            if want is not None and want != got:
                raise ValueError(
                    f"PLI self-check failed: @meta {key}={want} but parsed "
                    f"{got} (truncated or corrupted file?)")
        if expected_rules != len(idx.rules):
            raise ValueError(
                f"PLI self-check failed: @rules={expected_rules} but found "
                f"{len(idx.rules)} rule lines")
        if known_decl and set(known_decl) != known:
            raise ValueError("PLI self-check failed: @known disagrees with "
                             "the tokens the rules imply")
        if class_decl:
            counts: dict = {}
            for r in idx.rules:
                counts[r.cls] = counts.get(r.cls, 0) + 1
            if class_decl != counts:
                raise ValueError("PLI self-check failed: @class counts "
                                 "disagree with the rule lines")
        if perm_decl and set(perm_decl) != perms:
            raise ValueError("PLI self-check failed: @perm disagrees with "
                             "the permissions the rules imply")
    return idx
