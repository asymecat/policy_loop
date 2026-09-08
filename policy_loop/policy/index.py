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

__all__ = ["Rule", "PolicyIndex", "load_text", "load_dir"]

_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

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

    # ---- loading ----------------------------------------------------------
    # block keywords whose inner lines still carry real policy rules
    _BLOCK_OPEN_RE = re.compile(
        r"^(debug_only|developer_only|updater_only|vendor_only|chipset_only"
        r"|hdf_only|test_only)\s*\(\s*`?\s*$"
    )
    _BLOCK_CLOSE = ("')", "'", ")")

    def load_text(self, text: str, source: str = "<text>") -> "PolicyIndex":
        self._feed_lines(text, source)
        self._sources.append(source)
        return self

    def _feed_lines(self, text: str, source: str) -> None:
        in_block = False
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
            self._feed_line(s, source, lineno)

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
        out = []
        for r in self._rules_for_class(cls):
            if r.kind != kind:
                continue
            if not self._matches(r.src, r.src_neg, r.src_star, src, a_src):
                continue
            if not self._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_tgt):
                continue
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

    def neverallow_rules(self, src: str, tgt: str, cls: str) -> List[Rule]:
        return self._rule_hits("neverallow", src, tgt, cls)

    def ioctl_whitelist(self, src: str, tgt: str, cls: str) -> tuple:
        """Return (xperm_allowed_cmds, invert_rules) for allowxperm on ioctl."""
        allowed: Set[str] = set()
        inverts: List[Rule] = []
        for r in self.rules:
            if r.kind == "allowxperm" and r.cls == cls and r.xperm_perm == "ioctl":
                a_src, a_tgt = self._attrs(src), self._attrs(tgt)
                if (self._matches(r.src, r.src_neg, r.src_star, src, a_src)
                        and self._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_tgt)):
                    allowed |= r.xperms
            elif r.kind == "neverallowxperm" and r.cls == cls and r.xperm_perm == "ioctl":
                a_src, a_tgt = self._attrs(src), self._attrs(tgt)
                if (self._matches(r.src, r.src_neg, r.src_star, src, a_src)
                        and self._matches(r.tgt, r.tgt_neg, r.tgt_star, tgt, a_tgt)):
                    inverts.append(r)
        return frozenset(allowed), inverts

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
    """Recursively index all ``*.te`` files under *path* (OpenHarmony layout)."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"policy directory not found: {root}")
    idx = PolicyIndex()
    for te in sorted(root.rglob("*.te")):
        idx.load_text(te.read_text(encoding="utf-8", errors="replace"),
                      source=str(te))
    return idx
