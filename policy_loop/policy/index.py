"""Minimal OpenHarmony sepolicy (.te) index with query support.

This is the **deterministic** foundation of PolicyLoop: it answers
"does domain X have permission P on (target T, class C)?" by indexing real
`.te` rule text. Supported in this milestone (L1):

* ``type NAME, attr1, attr2;`` declarations  -> type -> attributes map
* ``allow SRC TGT:CLASS { perms };`` / single-perm form, where SRC/TGT may be
  a plain identifier, ``*``, or ``{ ... }`` sets with ``-exclusion`` members
* ``allowxperm SRC TGT:CLASS ioctl { 0x... };`` (ioctl whitelist granularity)
* ``neverallow`` / ``neverallowxperm`` red-line detection

Not yet handled (counted as ``skipped`` for transparency): policy macros such as
``binder_call()``, ``type_transition``, ``debug_only()`` etc. That is a known
limitation of L1 and is reported via ``index.skipped_count`` so query results
never silently over-claim.

No LLM is used; every verdict is traceable back to an indexed rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, List, Optional, Set

from .sehap import SehapTable, load_sehap

__all__ = ["Rule", "PolicyIndex", "load_text", "load_dir",
           "PLACEHOLDER_TARGETS", "is_service_placeholder"]

_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# The tcontexts samgr and devmgr log in place of a concrete service type. A
# denial carries one of these when the caller reached the service *through the
# manager*, which is the normal path: the concrete `sa_*`/`hdf_*` type never
# appears in the log at all.
#
# They live here, next to the resolver that undoes them, because both sides of
# the engine need to agree on what counts as a placeholder: the batch pipeline
# (_quick_verdict) and the per-case policy query (PolicyAgent) must resolve the
# same set, or the same denial gets two different verdicts depending on which
# path it took.
PLACEHOLDER_TARGETS = frozenset({"default_service", "default_hdf_service"})


def is_service_placeholder(token: Optional[str]) -> bool:
    return bool(token) and token in PLACEHOLDER_TARGETS

# allow / neverallow  (single-line; optional trailing ';')
#   allow SRC TGT:CLASS { perms };   allow SRC TGT:CLASS perm;
_RULE_RE = re.compile(
    r"^(?P<kind>allow|neverallow)\s+"
    r"(?P<src>\{.*?\}|[A-Za-z_][A-Za-z0-9_]*|\*)\s+"
    r"(?P<tgt>\{.*?\}|[A-Za-z_][A-Za-z0-9_]*|\*)\s*:\s*"
    r"(?P<cls>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<perms>\{.*?\}|[A-Za-z_][A-Za-z0-9_]*|\*)\s*;?\s*$",
    re.S,
)

# allowxperm / neverallowxperm
#   allowxperm SRC TGT:CLASS ioctl { 0x641f 0x6412 };
#   neverallowxperm SRC TGT:CLASS ioctl ~{ 0xab01 ... };
_XP_RE = re.compile(
    r"^(?P<kind>allowxperm|neverallowxperm)\s+"
    r"(?P<src>\{.*?\}|[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<tgt>\{.*?\}|[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<cls>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<perm>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?P<tilde>~)?\s*"
    r"\{(?P<xps>[^}]*)\}\s*;?\s*$",
    re.S,
)


# A statement the index is supposed to model, so a missing `;` means "wrapped",
# not "a different kind of statement". Only these four are joined (see
# `_feed_lines`); `dontaudit`/`auditallow` are not modelled either way.
_RULE_KW_RE = re.compile(r"^(allow|neverallow|allowxperm|neverallowxperm)\b")

# Ceiling on the join, so a file whose rule never terminates cannot swallow the
# remainder. Past this (or at end of file) the text is *not* fed to the rule
# regex: a blob of several clauses would match on its first clause and drop the
# rest -- the same silent narrowing the join exists to prevent -- so it is
# counted in `skipped_statements` instead, where a malformed statement belongs.
# Both bail-outs are unreachable on the upstream tree (0 occurrences in 1,315
# files), so this is a guard against a pathological file, not a live path.
_MAX_JOIN_LINES = 64


# --------------------------------------------------------------------------- #
# Rule model
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    kind: str                       # allow / neverallow / allowxperm / neverallowxperm
    src: FrozenSet[str] = frozenset()
    src_neg: FrozenSet[str] = frozenset()
    src_star: bool = False
    tgt: FrozenSet[str] = frozenset()
    tgt_neg: FrozenSet[str] = frozenset()
    tgt_star: bool = False
    cls: str = ""
    perms: FrozenSet[str] = frozenset()   # allow: permission names
    xperm_perm: Optional[str] = None      # allowxperm: e.g. "ioctl"
    xperms: FrozenSet[str] = frozenset()  # allowxperm: e.g. {"0x641f"}
    xperm_invert: bool = False            # neverallowxperm '~{...}' semantics
    raw: str = ""

    @property
    def is_xperm(self) -> bool:
        return self.kind in ("allowxperm", "neverallowxperm")


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #

@dataclass
class PolicyIndex:
    rules: List[Rule] = field(default_factory=list)
    type_attrs: dict = field(default_factory=dict)  # type -> set(attributes)
    attributes: Set[str] = field(default_factory=set)
    skipped_count: int = 0
    _sources: List[str] = field(default_factory=list)
    # The APL <-> domain bridge, loaded alongside the .te tree (see sehap.py).
    # compare=False: an index built from the same rule text stays equal whether
    # or not sehap files happened to sit next to it, so tests that compare
    # indices are not silently weakened by this addition.
    sehap: SehapTable = field(default_factory=SehapTable, compare=False,
                              repr=False)

    # ---- loading ----------------------------------------------------------
    # block keywords whose inner lines still carry real policy rules
    _BLOCK_OPEN_RE = re.compile(
        r"^(debug_only|developer_only|updater_only|vendor_only|chipset_only"
        r"|hdf_only|test_only)\s*\(\s*`?\s*$"
    )
    _BLOCK_CLOSE = ("')", "'", ")")

    def clone(self) -> "PolicyIndex":
        """An independent index that can take further ``load_text`` calls.

        The consumer is the repair loop: to decide whether a patch actually
        closes a gap it has to apply the patch and re-query, which means an
        index the patch is allowed to touch (:mod:`policy_loop.agents`).

        ``copy.deepcopy`` is the obvious way to get one and was what this
        replaced, but on the rk3568 sepolicy tree -- 21,790 rules -- it is both
        ruinously slow (once per case, thousands of cases) and intermittently
        fatal: deepcopy recurses through ``_reconstruct`` per object, and the
        ~50% of runs that segfaulted did so inside it, at 8MB stack and at
        64MB alike. A copy that is *correct* but dies half the time is worse
        than one that is merely expensive, so the copy is done by hand.

        Sharing the ``Rule`` objects is what makes this cheap, and it is sound
        because a Rule is never mutated once built: every field is a str, a
        bool or a frozenset, and the parser only ever appends new ones. The
        containers that *are* mutated -- the ``rules`` list, the ``attributes``
        set, the ``type_attrs`` sets of attributes -- each get a fresh copy, so
        a rule added to the clone cannot appear in the original. ``sehap`` is
        shared for the same reason as Rule: ``load_text`` does not touch it.
        """
        c = PolicyIndex()
        c.rules = list(self.rules)
        c.type_attrs = {name: set(attrs) for name, attrs in self.type_attrs.items()}
        c.attributes = set(self.attributes)
        c.skipped_count = self.skipped_count
        c._sources = list(self._sources)
        c.sehap = self.sehap
        # Build the postings *before* forking, then hand the same read-only
        # object to the clone. The clone's `rules` is the parent's prefix, so
        # the postings describe it exactly; the patch the clone is about to
        # append lands past `base` and is handled by the tail scan in
        # `_rule_hits`. Without this line every clone would rebuild a 21k-rule
        # index (~12 ms) for a one-rule question.
        c._hit = self._hit_index()
        return c

    def load_text(self, text: str, source: str = "<text>") -> "PolicyIndex":
        self._feed_lines(text, source)
        self._sources.append(source)
        return self

    def _feed_lines(self, text: str, source: str) -> None:
        in_block = False
        # A rule statement may be wrapped across physical lines: the upstream
        # tree has 40 of them (33 neverallow, 4 allow, 3 *xperm). Feeding such a
        # file one line at a time loses them -- and worse, it loses them
        # *invisibly*: `_RULE_RE` makes the trailing `;` optional, so a first
        # line that already ends inside the permission slot (`allow A B:file
        # read` + `write;`) is accepted as a whole statement and the rest is
        # discarded, narrowing the rule with `skipped_statements` none the
        # wiser, because the statement *was* counted as a rule. So hold any
        # rule statement that does not end in `;` and join until it does.
        pending = ""
        pending_line = 0
        for lineno, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not in_block and self._BLOCK_OPEN_RE.match(s):
                in_block = True
                continue
            if in_block:
                if s in self._BLOCK_CLOSE:
                    in_block = False
                    continue
                if s.startswith("'"):
                    s = s[1:]
                if s.startswith("`"):
                    s = s[1:]
            # Strip per physical line, not after joining: a trailing comment on
            # the first line would otherwise truncate the joined statement.
            s = s.split("#", 1)[0].strip()
            if pending:
                pending = f"{pending} {s}".strip()
                if pending.endswith(";"):
                    self._feed_line(pending, source, pending_line)
                    pending = ""
                elif lineno - pending_line >= _MAX_JOIN_LINES:
                    self.skipped_count += 1
                    pending = ""
                continue
            if s and _RULE_KW_RE.match(s) and not s.endswith(";"):
                pending, pending_line = s, lineno
                continue
            self._feed_line(s, source, lineno)
        if pending:
            self.skipped_count += 1

    def _feed_line(self, line: str, source: str, lineno: int) -> None:
        s = line.strip()
        if not s or s.startswith("#"):
            return
        s = s.split("#", 1)[0].strip()
        if not s:
            return

        if s.startswith("attribute "):
            name = s.split(None, 1)[1].rstrip(";").strip()
            if _ID_RE.fullmatch(name):
                self.attributes.add(name)
            return

        if s.startswith("typeattribute "):
            # OH declares attribute membership via a separate statement
            self._feed_type_decl("type " + s[len("typeattribute "):].strip())
            return

        if s.startswith("type "):
            self._feed_type_decl(s)
            return

        # macro expansion (currently: binder_call, per real glb_te_def.spt)
        expanded = self._expand_macro(s)
        if expanded:
            for sub in expanded:
                self._feed_line(sub, source, lineno)
            return

        for regex, store in ((_XP_RE, self._store_xp), (_RULE_RE, self._store_rule)):
            m = regex.match(s)
            if m:
                store(m)
                return
        # macro / other unsupported statement
        self.skipped_count += 1

    def _expand_macro(self, s: str) -> Optional[list]:
        """Expand a few common .te macros into allow statements (per real
        glb_te_def.spt definitions). Returns list of allow lines or None."""
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*;?$", s)
        if not m:
            return None
        name = m.group(1)
        # args may be comma- OR whitespace-separated (both appear upstream)
        args = [a.strip() for a in re.split(r"[, \t]+", m.group(2)) if a.strip()]
        if name == "binder_call" and len(args) == 2 \
                and all(_ID_RE.fullmatch(a) for a in args):
            a, b = args[0], args[1]
            return [
                f"allow {a} {b}:binder {{ call transfer }};",
                f"allow {b} {a}:binder transfer;",
                f"allow {a} {b}:fd use;",
            ]
        return None

    def _feed_type_decl(self, s: str) -> None:
        """Parse `type NAME[,| ]a1, a2;` / `typeattribute NAME a1 a2;`.

        SELinux allows attributes separated by commas (``type X, a, b;``) or
        whitespace (``typeattribute X a b;``), so split on either.
        """
        core = s[len("type "):].split(";", 1)[0]
        toks = [t for t in re.split(r"[, \t]+", core.strip()) if t]
        name = toks[0]
        if not _ID_RE.fullmatch(name):
            self.skipped_count += 1
            return
        attrs = {t for t in toks[1:] if _ID_RE.fullmatch(t)}
        if attrs:
            self.attributes.update(attrs)
        # register the type/attribute unconditionally (with or without attrs)
        self.type_attrs.setdefault(name, set()).update(attrs)
        self.__dict__.pop("_attr_cache", None)   # invalidate ancestor cache

    def _parse_subject(self, tok: str) -> tuple:
        """Return (positives, negatives, star)."""
        pos: Set[str] = set()
        neg: Set[str] = set()
        star = False
        body = tok.strip()
        if body.startswith("{") and body.endswith("}"):
            members = [x for x in body[1:-1].replace(",", " ").split() if x]
        elif body == "*":
            return pos, neg, True
        else:
            members = [body]

        for m_ in members:
            if m_ == "*":
                star = True
            elif m_.startswith("-"):
                neg.add(m_[1:])
            elif m_.startswith("~"):
                star = True  # approximate '~set' as wildcard in L1
            else:
                pos.add(m_)
        return frozenset(pos), frozenset(neg), star

    def _store_rule(self, m: re.Match) -> None:
        pos, neg, star = self._parse_subject(m.group("src"))
        tpos, tneg, tstar = self._parse_subject(m.group("tgt"))
        perms_tok = m.group("perms")
        if perms_tok.startswith("{"):
            perms = frozenset(p for p in perms_tok[1:-1].split() if p)
        elif perms_tok == "*":
            perms = frozenset()          # wildcard permission
        else:
            perms = frozenset([perms_tok])
        self.rules.append(
            Rule(
                kind=m.group("kind"),
                src=pos, src_neg=neg, src_star=star,
                tgt=tpos, tgt_neg=tneg, tgt_star=tstar,
                cls=m.group("cls"), perms=perms,
                raw=m.group(0),
            )
        )

    def _store_xp(self, m: re.Match) -> None:
        pos, neg, star = self._parse_subject(m.group("src"))
        tpos, tneg, tstar = self._parse_subject(m.group("tgt"))
        xps = frozenset(x.strip() for x in m.group("xps").split() if x.strip())
        self.rules.append(
            Rule(
                kind=m.group("kind"),
                src=pos, src_neg=neg, src_star=star,
                tgt=tpos, tgt_neg=tneg, tgt_star=tstar,
                cls=m.group("cls"),
                xperm_perm=m.group("perm"),
                xperms=xps,
                xperm_invert=bool(m.group("tilde")),
                raw=m.group(0),
            )
        )

    # ---- query --------------------------------------------------------------
    def _attrs(self, ident: str) -> Set[str]:
        """Transitive ancestor attributes of *ident* (attribute hierarchy)."""
        cache = self.__dict__.setdefault("_attr_cache", {})
        if ident in cache:
            return cache[ident]
        seen: Set[str] = set()
        stack = [ident]
        while stack:
            n = stack.pop()
            for p in self.type_attrs.get(n, ()):
                if p not in seen:
                    seen.add(p)
                    stack.append(p)
        seen.discard(ident)
        cache[ident] = seen
        return seen

    @staticmethod
    def _matches(pos, neg, star, ident: str, attrs: Set[str]) -> bool:
        if ident in neg or (attrs & neg):
            return False
        if star or ident in pos:
            return True
        return bool(attrs & pos)

    def _rule_hits(self, kind: str, src: str, tgt: str, cls: str) -> List[Rule]:
        a_src = self._attrs(src)
        a_tgt = self._attrs(tgt)
        base, index = self._hit_index()
        cand = (self._candidates(index, kind, "s", cls, src, a_src)
                & self._candidates(index, kind, "t", cls, tgt, a_tgt))
        rules = self.rules
        out = []
        for i in sorted(cand):
            if i >= base:
                continue
            r = rules[i]
            if self._matches(r.src, r.src_neg, r.src_star, src, a_src) \
                    and self._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_tgt):
                out.append(r)
        # Rules appended after the index was built (a patch being tried out)
        # are not in the postings; they sit past every candidate index, so
        # appending them keeps the by-rule-order contract of this method.
        for r in rules[base:]:
            if r.kind == kind and r.cls == cls \
                    and self._matches(r.src, r.src_neg, r.src_star, src, a_src) \
                    and self._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_tgt):
                out.append(r)
        return out

    def _rules_for_class(self, cls: str) -> list:
        """Rules grouped by object class, cached & invalidated on append."""
        from collections import defaultdict
        cache = self.__dict__.get("_class_cache")
        if cache is None or self.__dict__.get("_cache_len", -1) != len(self.rules):
            cache = defaultdict(list)
            for r in self.rules:
                cache[r.cls].append(r)
            self._class_cache = cache
            self._cache_len = len(self.rules)
        return cache.get(cls, ())

    # ---- inverted index -----------------------------------------------------
    #
    # What this replaces, and why it was worth replacing: the query path used to
    # walk every rule of the object class. On the rk3568 sepolicy tree that is
    # 7,400 rules for `file` and 3,447 for `dir`, and `file` alone carries 1,588
    # of the corpus's 4,784 unique cases -- 18.4M rule visits for one pass over
    # the corpus, each visit two `_matches` calls of set intersections.
    #
    # The replacement is exact, not a heuristic. `_matches` accepts a rule when
    # `star`, or when the query symbol or one of its ancestor attributes is in
    # the rule's positive set -- and rejects it when either is in the negative
    # set. So the rules that *could* pass are exactly those carrying one of the
    # query's tokens on that side (or the star), and that set is what gets
    # indexed. Negatives are still applied by `_matches`, so the index only ever
    # has to be a **superset** of the true hits: an extra candidate costs one
    # `_matches` call, a missing one would silently drop a rule and change an
    # answer. Everything below is arranged so the index can only be too big.
    #
    # Measured on the real corpus: candidates after intersecting both sides are
    # median 1, p90 3, max 11, against 7,400 scanned before.

    def _hit_index(self) -> tuple:
        """Return ``(base, index)``: the postings, and how many rules they cover.

        The pair is the whole trick that makes this compatible with the repair
        loop. A clone gets its parent's postings and a ``base`` of the parent's
        current length, so the ~12 ms build happens **once per index tree**
        instead of once per clone -- and a patch appended to a clone lands past
        ``base``, where :meth:`_rule_hits` picks it up with a linear scan of the
        (one or two rule) tail. Sharing is safe because the postings are never
        mutated after the build: the object handed to every clone is read-only
        by construction. Rebuilding on append instead would have cost the build
        once per patch attempt -- 151 times in one converge run.
        """
        got = self.__dict__.get("_hit")
        if got is not None:
            return got
        post: dict = {}
        star: dict = {}
        for i, r in enumerate(self.rules):
            for side, pos, st in (("s", r.src, r.src_star),
                                  ("t", r.tgt, r.tgt_star)):
                key = (r.kind, side, r.cls)
                if st:
                    star.setdefault(key, []).append(i)
                for tok in pos:
                    post.setdefault(key, {}).setdefault(tok, []).append(i)
        got = (len(self.rules), (post, star))
        self._hit = got
        return got

    @staticmethod
    def _candidates(index, kind: str, side: str, cls: str, ident: str,
                    attrs: Set[str]) -> set:
        """Rule indices that could match *ident* on one side. A superset."""
        post, star = index
        key = (kind, side, cls)
        out = set(star.get(key, ()))
        d = post.get(key)
        if d is not None:
            for tok in attrs:
                lst = d.get(tok)
                if lst:
                    out.update(lst)
            lst = d.get(ident)
            if lst:
                out.update(lst)
        return out

    def allow_rules(self, src: str, tgt: str, cls: str) -> List[Rule]:
        """allow rules granting (src -> tgt:cls) access at all."""
        return self._rule_hits("allow", src, tgt, cls)

    def has_access(self, src: str, tgt: str, cls: str,
                   perms: FrozenSet[str]) -> tuple:
        """Return (allowed, granted_perm_subset, matching_rules).

        ``allowed`` is True only if *every* requested permission is granted.
        """
        rules = self.allow_rules(src, tgt, cls)
        granted: Set[str] = set()
        for r in rules:
            if r.perms:
                granted |= r.perms
        # a rule with no perms is a wildcard perms token ('*')
        if any(not r.perms for r in rules):
            granted = granted | set(perms)
        matched = [p for p in perms if p in granted]
        all_ok = all(p in granted for p in perms)
        return all_ok, frozenset(matched), rules

    def resolve_logical_target(self, src: str, cls: str, tgt: str,
                               service: str | None,
                               perms: FrozenSet[str]) -> str | None:
        """Resolve a samgr/hdf placeholder target to its concrete type.

        Runtime logs target ``default_service`` (samgr) / ``default_hdf_service``
        (devmgr) as placeholders; real rules target concrete ``sa_*`` / ``hdf_*``
        types. OH names a service type after its *name* (``hdf_<name>`` /
        ``sa_<name>``), so a *named* ``service=`` field maps deterministically.

        Two conservative, declaration-checked rules:
          - named service   -> ``hdf_<service>`` (hdf_devmgr_class)
                             -> ``sa_<service>``  (samgr_class)
          - numeric service + samgr ``add``  -> ``sa_<src>``
            (an SA registers *itself* with samgr under its own id at startup,
            so the concrete type is the SA type named after the subject).

        Returns the concrete target only if it is a declared type/attribute in
        this index; otherwise ``None`` (do not invent targets). Numeric ids that
        name a *remote* SA (client ``get``) are not resolvable without the
        external samgr id->name registry -> caller keeps the placeholder.
        """
        if not is_service_placeholder(tgt) or not service:
            return None
        if cls not in ("samgr_class", "hdf_devmgr_class"):
            return None
        if not service.isdigit():
            cand = ("hdf_" if cls == "hdf_devmgr_class" else "sa_") + service
        elif not src:
            # self-registration names the SA type after the *subject*: a record
            # whose scontext was malformed has no name to build one from.
            # Concatenating None here would raise, taking the whole run down.
            return None
        elif cls == "samgr_class" and perms and perms <= {"add"}:
            cand = "sa_" + src          # SA registers its own samgr entry
        else:
            return None
        if cand in self.type_attrs or cand in self.attributes:
            return cand
        return None

    def neverallow_rules(self, src: str, tgt: str, cls: str,
                         perms) -> List[Rule]:
        """neverallow rules that *granting* ``perms`` would violate.

        ``neverallow`` is an assertion about **permissions**, not about a
        (subject, target, class) triple: ``neverallow A B:file execmod`` forbids
        only ``execmod``, and a denial of ``getattr`` on that same pair violates
        nothing. Matching the triple alone therefore fires on nearly every
        attribute-mediated pair -- measured on the upstream corpus, 2,646 of
        2,700 such "hits" name a permission the request never asked for. Because
        the batch path treats a hit as "stop, escalate to human", that noise did
        not merely mislabel cases: it suppressed the repair path for 1,705 cases
        that the very same query says are already allowed.

        A rule whose permission set is empty is the ``*`` wildcard and matches
        any request -- the same convention as :meth:`has_access`, and the reason
        ``neverallow domain default_service:samgr_class *;`` still fires.

        *perms* is required rather than optional so that every caller states
        what it is asking about; a default would silently restore the bug.
        """
        out = []
        for r in self._rule_hits("neverallow", src, tgt, cls):
            if not r.perms:                 # `*` -- covers every permission
                out.append(r)
            elif perms and set(perms) & r.perms:
                out.append(r)
        return out

    def ioctl_whitelist(self, src: str, tgt: str, cls: str) -> tuple:
        """Return (xperm_allowed_cmds, invert_rules) for allowxperm on ioctl.

        Same two-sided candidate narrowing as :meth:`_rule_hits`; the difference
        is that the class filter alone used to leave all 21,824 rules to walk
        (only 515 of them are ``allowxperm``), and this runs once per ioctl
        denial. ``xperm_perm == "ioctl"`` is checked *after* the candidate
        narrowing, which is sound for the same superset reason spelled out on
        ``_hit_index``: a rule dropped here for the wrong ``xperm_perm`` would
        be a rule dropped forever.
        """
        a_src, a_tgt = self._attrs(src), self._attrs(tgt)
        allowed: Set[str] = set()
        inverts: List[Rule] = []
        for r in self._xperm_hits(cls, src, tgt, a_src, a_tgt):
            if r.xperm_perm != "ioctl":
                continue
            if r.kind == "allowxperm":
                allowed |= r.xperms
            else:
                inverts.append(r)
        return frozenset(allowed), inverts

    def _xperm_hits(self, cls: str, src: str, tgt: str, a_src: Set[str],
                    a_tgt: Set[str]) -> List[Rule]:
        """``allowxperm``/``neverallowxperm`` rules reaching (src, tgt, cls)."""
        base, index = self._hit_index()
        cand: set = set()
        for kind in ("allowxperm", "neverallowxperm"):
            cand |= (self._candidates(index, kind, "s", cls, src, a_src)
                     & self._candidates(index, kind, "t", cls, tgt, a_tgt))
        # Ascending rule index, tail last: the caller returns the *first*
        # matching neverallowxperm rule, so this order is observable output.
        out = [self.rules[i] for i in sorted(cand) if i < base]
        out += [r for r in self.rules[base:] if r.is_xperm and r.cls == cls]
        return [r for r in out if self._hits(r, src, tgt, a_src, a_tgt)]

    def _hits(self, r: Rule, src: str, tgt: str, a_src: Set[str],
              a_tgt: Set[str]) -> bool:
        return (self._matches(r.src, r.src_neg, r.src_star, src, a_src)
                and self._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_tgt))

    def ioctl_allowed(self, src: str, tgt: str, cls: str, cmd: str) -> tuple:
        """Best-effort ioctl verdict given a denial's ioctlcmd.

        * if a matching ``allowxperm`` exists -> allowed only if cmd is in the
          whitelist (unless an invert/neverallowxperm rule excludes it)
        * elif plain ``allow ... ioctl`` exists (no fine-grained xperm) -> allowed
        * else -> denied
        Returns (allowed, reason, rules).
        """
        whitelist, invert_rules = self.ioctl_whitelist(src, tgt, cls)
        # neverallowxperm '~{ ... }' means "block everything in the set"
        for r in invert_rules:
            if cmd in r.xperms:
                return False, "neverallowxperm", [r]
        plain = [r for r in self.allow_rules(src, tgt, cls)
                 if "ioctl" in r.perms]
        if whitelist:
            return (cmd in whitelist), "allowxperm", []
        if plain:
            return True, "allow(ioctl)", plain
        return False, "no_allow", []

    # ---- reporting ----------------------------------------------------------
    def summary(self) -> dict:
        kinds: dict = {}
        for r in self.rules:
            kinds[r.kind] = kinds.get(r.kind, 0) + 1
        return {
            "rules": len(self.rules),
            "kinds": kinds,
            "attributes": len(self.attributes),
            "types": len(self.type_attrs),
            "skipped_statements": self.skipped_count,
            "sources": self._sources,
        }


# --------------------------------------------------------------------------- #
# Convenience loaders
# --------------------------------------------------------------------------- #

def load_text(text: str, source: str = "<text>") -> PolicyIndex:
    return PolicyIndex().load_text(text, source)


def load_dir(path: str | Path) -> PolicyIndex:
    """Recursively index all ``*.te`` files under *path* (OpenHarmony layout).

    Also indexes every ``sehap_contexts`` file found in the same tree: the APL
    bridge is not derivable from the rules, and a caller that loaded the whole
    sepolicy tree clearly wants it (see ``sehap.py``). A tree without those
    files yields an empty table, so single-component trees keep working.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"policy directory not found: {root}")
    idx = PolicyIndex()
    for te in sorted(root.rglob("*.te")):
        idx.load_text(te.read_text(encoding="utf-8", errors="replace"),
                      source=str(te))
    idx.sehap = load_sehap(root)
    return idx
