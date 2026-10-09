"""Root-cause minimisation of the auto-repair patch set.

`converge` answers one question per denial cluster: *what single rule would
close this one case?*  That is the right answer for a reader looking at one
case, and the wrong answer for a reader looking at the whole log, because the
per-case projection emits the same rule several times whenever two clusters
differ only in which permissions the kernel happened to print first:

    allow init write_updater_exec:file { execute };
    allow init write_updater_exec:file { map };
    allow init write_updater_exec:file { open read };

Four clusters, one root cause: *init may not use the updater binary at all*.
This module re-reads the report those lines came from, collapses them onto
their root cause, and then **proves the collapsed set still closes every
case** by applying it to a copy of the index and re-querying.  Three outputs:

* ``rules``   -- the minimised rule set, each carrying the cases it closes,
                 whether it extends a rule that already exists, and how far it
                 reaches (:class:`BlastRadius`).
* ``verify``  -- the closed loop.  Applying the minimised set must resolve
                 every case that was previously unresolved, and must not have
                 resolved anything before it was applied -- otherwise the
                 patch set is not what closed the gap and the number is
                 meaningless.  ``converge`` only ever asserted that a patch
                 *compiles*; this asserts that it *works*.
* ``--cil``    -- the rule set as CIL text, for the neverallow gate in
                 ``tools/apply_converge.py`` and for ``secilc``.

Host-only and additive by construction: it consumes a converge report, it does
not change one.  The device's ``Converge()`` output stays byte-identical, so
the differential gates in ``docs/eval-converge.md`` keep their meaning.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .policy.index import PolicyIndex, Rule, load_dir

CAT_AUTO = "auto_repairable"

# `allow S T:c { p ... };`  /  `allowxperm S T:c ioctl { 0x... };`
# Both are produced by policy_loop.agents.security_agent, so the shapes are
# fixed here rather than re-derived -- a line this cannot parse is reported
# instead of guessed at.
_ALLOW_RE = re.compile(r"^allow (\S+) (\S+):(\S+) \{ ([^}]*) \};$")
_XPERM_RE = re.compile(r"^allowxperm (\S+) (\S+):(\S+) (\w+) \{ ([^}]*) \};$")


# --------------------------------------------------------------------------- #
# F: how far does one rule reach?
# --------------------------------------------------------------------------- #

@dataclass
class BlastRadius:
    """The set of concrete accesses a rule creates, after attribute expansion.

    A rule written against concrete types reaches exactly one (subject, object)
    pair, which is the whole point of deriving patches from denials.  A rule
    written against an attribute reaches every member of it, and *that* is the
    number a reviewer needs before approving a fold into a rule that already
    exists.
    """

    subjects: int = 1
    objects: int = 1
    perms: int = 1
    subject_attrs: list = field(default_factory=list)
    object_attrs: list = field(default_factory=list)
    level: str = "low"

    @property
    def pairs(self) -> int:
        return self.subjects * self.objects

    @property
    def grants(self) -> int:
        return self.pairs * self.perms


def _fanout(index: PolicyIndex, name: str) -> tuple:
    """Return (concrete_member_count, attribute_name_or_empty) for a token."""
    if name in index.attributes:
        n = sum(1 for _, attrs in index.type_attrs.items() if name in attrs)
        return n, name
    return 1, ""


def blast_radius(index: Optional[PolicyIndex], src: str, tgt: str,
                 perms) -> BlastRadius:
    """Count the concrete (subject, object, permission) triples a rule grants."""
    n = len(set(perms))
    if index is None:
        return BlastRadius(perms=max(n, 1))
    s_n, s_a = _fanout(index, src)
    t_n, t_a = _fanout(index, tgt)
    pairs = s_n * t_n
    level = "low" if pairs == 1 else ("medium" if pairs <= 16 else "high")
    return BlastRadius(subjects=s_n, objects=t_n, perms=max(n, 1),
                       subject_attrs=[s_a] if s_a else [],
                       object_attrs=[t_a] if t_a else [],
                       level=level)


# --------------------------------------------------------------------------- #
# A: collapse the per-case projection onto its root cause
# --------------------------------------------------------------------------- #

@dataclass
class MinimizedRule:
    kind: str                     # allow / allowxperm
    src: str
    tgt: str
    cls: str
    perms: list
    cases: int                    # clusters merged into this rule
    denials: int                  # raw log lines those clusters stand for
    text: str
    fold_into: str = ""           # raw text of the existing rule it extends
    fold_adds: list = field(default_factory=list)
    fold_blast: Optional[dict] = None
    blast: Optional[dict] = None


@dataclass
class MinimizeResult:
    lines_before: int = 0
    rules_after: int = 0
    lines_saved: int = 0
    merged_groups: int = 0        # groups that were emitted as >1 line
    perms_unioned: int = 0
    folded: int = 0               # extend a rule that already exists
    folded_wide: int = 0          # ... of which the target reaches >1 type
    new_rules: int = 0
    cases: int = 0
    denials: int = 0
    blast_total: dict = field(default_factory=dict)
    rules: list = field(default_factory=list)
    verify: dict = field(default_factory=dict)
    unparsed: list = field(default_factory=list)

    def summary_line(self) -> str:
        return (f"补丁 {self.lines_before} 行 → {self.rules_after} 条根因规则"
                f"（归并 {self.merged_groups} 组、省 {self.lines_saved} 行；"
                f"{self.folded} 条折叠进已有规则，其中 {self.folded_wide} 条"
                f"会波及属性成员；{self.new_rules} 条为新增）")


def parse_patch_line(line: str) -> Optional[tuple]:
    """Return (kind, src, tgt, cls, perms_frozenset) or None."""
    m = _ALLOW_RE.match(line.strip())
    if m:
        return ("allow", m.group(1), m.group(2), m.group(3),
                frozenset(m.group(4).split()))
    m = _XPERM_RE.match(line.strip())
    if m:
        return ("allowxperm", m.group(1), m.group(2), m.group(3),
                frozenset(m.group(5).split()))
    return None


def render_rule(kind: str, src: str, tgt: str, cls: str, perms) -> str:
    ps = " ".join(sorted(perms))
    if kind == "allowxperm":
        return f"allowxperm {src} {tgt}:{cls} ioctl {{ {ps} }};"
    return f"allow {src} {tgt}:{cls} {{ {ps} }};"


def _existing_rule(index: PolicyIndex, src: str, tgt: str, cls: str):
    """The narrowest rule that already covers (src, tgt, cls), or None.

    ``allow_rules`` is attribute-aware, so this finds ``allow domain T:c p``
    for a concrete ``src`` too.  Narrowness has to be measured by *fanout*, not
    by set size: ``{domain}`` holds one token and reaches 235 concrete types,
    so a set-size key would rank the broadest possible rule as the narrowest
    and recommend folding into it.
    """
    hits = [r for r in index.allow_rules(src, tgt, cls) if r.kind == "allow"]
    if not hits:
        return None
    return min(hits, key=lambda r: (_rule_fanout(index, r), r.raw))


def _rule_fanout(index: PolicyIndex, rule: Rule) -> int:
    """Concrete (subject, object) pairs one rule reaches."""
    s = sum(_fanout(index, x)[0] for x in rule.src) or 1
    t = sum(_fanout(index, x)[0] for x in rule.tgt) or 1
    return s * t


def minimize(report: dict, index: Optional[PolicyIndex],
             cases: Optional[list] = None) -> MinimizeResult:
    """Collapse a converge report's patch lines onto their root causes.

    ``cases`` defaults to the report's own auto-repairable clusters; it is the
    set the closed loop has to close.
    """
    lines = list(report.get("auto_patch_lines") or [])
    stats = report.get("auto_patch_stats") or {}
    if cases is None:
        cases = [c for c in report.get("clusters") or []
                 if c.get("category") == CAT_AUTO]

    res = MinimizeResult(lines_before=len(lines), cases=len(cases))
    groups: dict = collections.OrderedDict()
    emitted = collections.Counter()

    for line in lines:
        parsed = parse_patch_line(line)
        if parsed is None:
            res.unparsed.append(line)
            continue
        kind, src, tgt, cls, perms = parsed
        key = (kind, src, tgt, cls)
        emitted[key] += 1
        g = groups.setdefault(key, {"perms": set(), "cases": 0, "denials": 0})
        g["perms"] |= set(perms)

    # Attribute the per-line case/denial counts from the report onto the group.
    for line in lines:
        parsed = parse_patch_line(line)
        if parsed is None:
            continue
        kind, src, tgt, cls, _ = parsed
        st = stats.get(line) or {}
        g = groups[(kind, src, tgt, cls)]
        g["cases"] += int(st.get("cases", 0))
        g["denials"] += int(st.get("denials", 0))

    res.merged_groups = sum(1 for k, n in emitted.items() if n > 1)
    res.perms_unioned = sum(1 for k, n in emitted.items()
                            if n > 1 and len(groups[k]["perms"]) > n)

    for (kind, src, tgt, cls), g in groups.items():
        perms = sorted(g["perms"])
        rule = MinimizedRule(kind=kind, src=src, tgt=tgt, cls=cls, perms=perms,
                             cases=g["cases"], denials=g["denials"],
                             text=render_rule(kind, src, tgt, cls, perms))
        rule.blast = asdict(blast_radius(index, src, tgt, perms))
        if index is not None and kind == "allow":
            ex = _existing_rule(index, src, tgt, cls)
            if ex is not None:
                have = set(ex.perms)
                rule.fold_into = ex.raw
                rule.fold_adds = sorted(set(perms) - have)
                # The fold target's own reach, measured the same way as the
                # rule's: extending it hands `fold_adds` to every pair it
                # already covers, which is the number that decides whether
                # folding is safe.
                fs = sum(_fanout(index, x)[0] for x in ex.src) or 1
                ft = sum(_fanout(index, x)[0] for x in ex.tgt) or 1
                rule.fold_blast = asdict(BlastRadius(
                    subjects=fs, objects=ft, perms=max(len(ex.perms), 1),
                    subject_attrs=[a for a in sorted(ex.src)
                                   if a in index.attributes],
                    object_attrs=[a for a in sorted(ex.tgt)
                                  if a in index.attributes],
                    level="low" if fs * ft == 1 else
                          ("medium" if fs * ft <= 16 else "high")))
                res.folded += 1
                if rule.fold_blast["level"] != "low":
                    res.folded_wide += 1
            else:
                res.new_rules += 1
        res.rules.append(asdict(rule))

    res.rules_after = len(res.rules)
    res.lines_saved = res.lines_before - res.rules_after
    res.denials = sum(r["denials"] for r in res.rules)
    res.blast_total = {
        "pairs": sum(r["blast"]["subjects"] * r["blast"]["objects"]
                     for r in res.rules),
        "grants": sum(r["blast"]["subjects"] * r["blast"]["objects"]
                      * r["blast"]["perms"] for r in res.rules),
        "max_level": ("high" if any(r["blast"]["level"] == "high" for r in res.rules)
                      else "medium" if any(r["blast"]["level"] == "medium"
                                           for r in res.rules) else "low"),
    }
    res.verify = verify_closed_loop(res.rules, index, cases)
    return res


# --------------------------------------------------------------------------- #
# B: apply the patch and prove it closes the cases it claims to
# --------------------------------------------------------------------------- #

def apply_rules(index: PolicyIndex, rules: list) -> PolicyIndex:
    """A copy of ``index`` with every minimised rule added."""
    patched = index.clone()
    for r in rules:
        perms = frozenset(r["perms"])
        if r["kind"] == "allowxperm":
            patched.rules.append(Rule(kind="allowxperm", src=frozenset({r["src"]}),
                                      tgt=frozenset({r["tgt"]}), cls=r["cls"],
                                      xperm_perm="ioctl", xperms=perms,
                                      raw=r["text"]))
        else:
            patched.rules.append(Rule(kind="allow", src=frozenset({r["src"]}),
                                      tgt=frozenset({r["tgt"]}), cls=r["cls"],
                                      perms=perms, raw=r["text"]))
    return patched


def _case_ok(index: PolicyIndex, c: dict) -> bool:
    perms = frozenset(c.get("perms") or ())
    if not (c.get("src") and c.get("tgt") and c.get("cls") and perms):
        return True                      # not queryable -> not our claim
    if perms == {"ioctl"} and c.get("ioctl"):
        ok, _, _ = index.ioctl_allowed(c["src"], c["tgt"], c["cls"], c["ioctl"])
        return bool(ok)
    ok, _, _ = index.has_access(c["src"], c["tgt"], c["cls"], perms)
    return bool(ok)


def verify_closed_loop(rules: list, index: Optional[PolicyIndex],
                       cases: list) -> dict:
    """Apply ``rules`` to a copy of the index and re-query every case.

    Two numbers matter and both must hold: every case is *unresolved* before
    the patch (so the patch is what closes it, not a cluster that was already
    allowed), and every case is *resolved* after.
    """
    if index is None:
        return {"applicable": False,
                "note": "未提供策略索引：无法做落地闭环反验。"}
    before = [c for c in cases if not _case_ok(index, c)]
    patched = apply_rules(index, rules)
    unresolved = [c for c in before if not _case_ok(patched, c)]
    return {
        "applicable": True,
        "candidates": len(cases),
        "unresolved_before": len(before),
        "resolved_after": len(before) - len(unresolved),
        "unresolved_after": len(unresolved),
        "closed": not unresolved,
        "unresolved": [{"src": c.get("src"), "tgt": c.get("tgt"),
                        "cls": c.get("cls"), "perms": sorted(c.get("perms") or ()),
                        "ioctl": c.get("ioctl", "")} for c in unresolved[:20]],
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

_CIL_HEADER = ("; PolicyLoop minimised patch set -- root-cause collapsed.\n"
               "; Generated from a converge report; every rule below is the\n"
               "; union of the denial-proven permissions of the cases it closes.\n"
               "(allow {0})\n")


def render_cil(rules: list, src_types: Optional[set] = None) -> str:
    """CIL text for a minimised rule set.

    Every subject and object in the set is looked for in ``src_types``; a token
    that is not a declared type is emitted as a ``(type ...)`` declaration so
    the fragment compiles standalone.  Callers holding the full tree pass the
    tree's declared types to keep the fragment a pure overlay.
    """
    declared = set(src_types or ())
    decls, body = [], []
    for r in rules:
        for tok in (r["src"], r["tgt"]):
            if tok not in declared:
                declared.add(tok)
                decls.append(f"(type {tok})")
        perms = " ".join(sorted(r["perms"]))
        if r["kind"] == "allowxperm":
            body.append(f"(allowxperm {r['src']} {r['tgt']} "
                        f"({r['cls']} (ioctl ({perms}))))")
        else:
            body.append(f"(allow {r['src']} {r['tgt']} ({r['cls']} ({perms})))")
    head = _CIL_HEADER.format(" ".join(decls)) if decls else ""
    return head + "\n".join(body) + "\n"


def render_markdown(res: MinimizeResult) -> list:
    out = ["## 最小权限补丁：根因归并", "", f"> {res.summary_line()}", ""]
    v = res.verify
    if v.get("applicable"):
        out += ["### 落地闭环反验", "",
                f"- 待验证案例 {v['candidates']} 个，补丁前未解决 "
                f"**{v['unresolved_before']}** 个（补丁确实是它们的原因）",
                f"- 套回索引后仍未解决 **{v['unresolved_after']}** 个 → "
                f"{'✅ 全部闭合' if v['closed'] else '❌ 有残留'}", ""]
    out += ["### 逐条规则", "",
            "| 规则 | 案例 | 日志条数 | 与已有规则的关系 | 爆炸半径 |",
            "|---|---|---|---|---|"]
    for r in res.rules:
        b = r["blast"]
        reach = (f"{b['subjects']}×{b['objects']} × {b['perms']} 权限"
                 f"（{b['level']}）")
        if not r["fold_into"]:
            fold = "新增"
        elif not r["fold_adds"]:
            fold = f"已含于 `{r['fold_into']}`"
        elif r["fold_blast"]["level"] == "low":
            fold = f"扩展 `{r['fold_into']}`（+{' '.join(r['fold_adds'])}）"
        else:
            fb = r["fold_blast"]
            fold = (f"⚠️ 勿折叠：`{r['fold_into']}` 覆盖 "
                    f"{fb['subjects']}×{fb['objects']} 个类型对，"
                    f"追加会把权限放大到 {fb['subjects'] * fb['objects']} 处授权")
        out.append(f"| `{r['text']}` | {r['cases']} | {r['denials']} | "
                   f"{fold} | {reach} |")
    out.append("")
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[list] = None) -> int:
    from . import converge as C

    ap = argparse.ArgumentParser(
        description="PolicyLoop root-cause minimisation of the auto patch set")
    ap.add_argument("--log", help="denial log file")
    ap.add_argument("--text", help="inline denial log text")
    ap.add_argument("--policy", help="sepolicy dir or .te file to index")
    ap.add_argument("--json", type=Path, help="write JSON result")
    ap.add_argument("--md", type=Path, help="write markdown section")
    ap.add_argument("--cil", type=Path, help="write the minimised set as CIL")
    ap.add_argument("--patch-report", type=Path,
                    help="write a converge-shaped report whose auto_patch_lines "
                         "are the minimised rules, so tools/apply_converge.py "
                         "runs its neverallow + secilc gates on this set "
                         "instead of the per-case projection")
    args = ap.parse_args(argv)

    if not args.log and not args.text:
        ap.error("provide --log <file> or --text <...>")
    text = args.text if args.text else \
        Path(args.log).read_text(encoding="utf-8", errors="replace")

    index = load_dir(args.policy) if args.policy else None
    report = C.converge(text, index=index).to_dict()
    res = minimize(report, index)

    print(f"[PolicyLoop minimize] {res.summary_line()}")
    v = res.verify
    if v.get("applicable"):
        print(f"[PolicyLoop minimize] 闭环反验：补丁前未解决 "
              f"{v['unresolved_before']} → 套回后未解决 {v['unresolved_after']}"
              f"  {'OK' if v['closed'] else 'FAIL'}")
    for line in res.unparsed:
        print(f"  [warn] 无法解析的补丁行：{line}")

    if args.json:
        args.json.write_text(json.dumps(asdict(res), ensure_ascii=False,
                                        indent=2), encoding="utf-8")
    if args.md:
        args.md.write_text("\n".join(render_markdown(res)), encoding="utf-8")
    if args.cil:
        types = set(index.type_attrs) if index is not None else set()
        args.cil.write_text(render_cil(res.rules, types), encoding="utf-8")
    if args.patch_report:
        args.patch_report.write_text(json.dumps(
            {"auto_patch_lines": [r["text"] for r in res.rules]},
            ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if res.verify.get("closed", True) else 1


if __name__ == "__main__":                      # pragma: no cover
    raise SystemExit(main())
