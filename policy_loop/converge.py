"""Batch convergence: a whole denial log -> dedup clusters -> convergence report.

Turns "permissive 模式下攒下的一大堆 `avc: denied`" into a single actionable
list:

  * cluster the log by *logical access* (src/tgt/class/perms/ioctl) so the
    5,000 lines collapse into a handful of unique cases;
  * classify each unique case with the deterministic pipeline (or a cheap
    policy query when the verdict is obvious), one case == one pipeline run;
  * bucket each case as auto_repairable / needs_human / noise;
  * collect the deduplicated least-privilege patch lines + a readiness summary
    for tightening permissive -> enforcing.

Deterministic, stdlib-only. This tool NEVER writes .te policy files: it only
produces suggested rules + placement notes, matching the project's "no
auto-write" principle.

Usage:
    python -m policy_loop.converge --log <file> [--policy <dir|.te>]
                                   [--json out.json] [--md out.md]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from policy_loop.agents import Orchestrator
from policy_loop.denial import fingerprint, parse as parse_denials
from policy_loop.policy import (PLACEHOLDER_TARGETS, is_service_placeholder,
                                load)
from policy_loop.policy.cross_layer import analyze as cross_layer_view

CAT_AUTO = "auto_repairable"          # minimal patch approved + verified
CAT_HUMAN = "needs_human"             # escalation / label issue / rejected patch
CAT_NOISE = "noise_or_already_allowed"  # policy already allows it
CAT_UNCLASS = "unclassified_no_policy"  # ran without a policy index

_HUMAN_CLASSES = ("POTENTIAL_ESCALATION", "DOMAIN_OR_LABEL_MISMATCH")
_NOISE_CLASSES = ("NOISE_OR_ALREADY_FIXED",)

# A tcontext parsed down to a bare MLS level means the log line was malformed
# (e.g. an upstream comment typo "u:charger_exec:s0" lost the object_r role),
# so the "type" is really a security level. Writing a rule against it would be
# nonsense -> always escalate to human instead of proposing a patch.
_MLS_LEVEL_RE = re.compile(r"^s[0-9]+(\.c[0-9]+(-c[0-9]+)?)?$")


def _is_mls_level(token: Optional[str]) -> bool:
    return bool(token) and _MLS_LEVEL_RE.fullmatch(token) is not None


# OH devmgr/samgr logs a *placeholder* tcontext when the denial goes through the
# service manager: the real rule must target a concrete type (e.g. the sa_*_service
# named by `service=` / the hdf_device_manager that 5100 resolves to), not the
# placeholder itself. Writing `allow X default_service:samgr_class get` would be
# wrong/unverifiable -> escalate to human.
#
# M3 resolves the placeholder *for the policy query only* (see _quick_verdict):
# enough to tell "policy already allows this" from "there is a real gap", which
# is what makes the false escalations go away. It deliberately does NOT feed the
# patch text or the guards below -- a resolved-but-still-denied case must keep
# escalating, because a patch against a placeholder can pass review and verify
# yet land no rule at all.
# The set itself lives in policy.index, next to the resolver that undoes it, so
# the batch path and PolicyAgent cannot disagree about what a placeholder is.
# These two names are the historical spellings, kept because the tests and the
# cluster note below use them.
_PLACEHOLDER_TARGETS = PLACEHOLDER_TARGETS
_is_service_placeholder = is_service_placeholder


def _known_tokens(index) -> tuple:
    """Return (tokens, classes, perms) provably part of the indexed policy.

    *tokens* = declared types/attributes + every subject/target referenced by a
    rule. A rule can only be *added* against a type that already exists
    somewhere, so a suggested patch naming a token outside this set cannot be
    the intended fix (it is a device-added domain, a generated/numeric service
    label like ``sa_1401_service`` that never matched the declared
    ``sa_*_service``, or a malformed context). We refuse to auto-suggest those.

    *classes* = every object class a rule mentions. Hand-maintained denial
    comments occasionally typo the class (``samar_class`` for ``samgr_class``,
    ``dit`` for ``dir``) in ways the kernel never would; a patch whose class
    never appears in the policy is against a nonexistent class -> needs_human.

    *perms* = every permission name a non-xperm rule grants. Same argument one
    level down: ``allow A B:c { nosuchperm };`` is not a policy that fails to
    help, it is one the policy compiler rejects outright. Transcribed log lines
    do put non-permissions in the permission slot -- ``denied { 0x5413 }`` with
    the literal word ``ioctl`` *outside* the braces, or ``{ semap open readt }``
    -- so this catches a corrupt log line rather than a policy gap, and the
    human needs to learn their log is corrupt, not receive a patch that cannot
    compile.
    """
    known = set(index.type_attrs)
    classes: set = set()
    perms: set = set()
    for r in index.rules:
        for tok in (r.src if isinstance(r.src, str) else r.src):
            known.add(tok)
        for tok in (r.tgt if isinstance(r.tgt, str) else r.tgt):
            known.add(tok)
        classes.add(r.cls)
        if not r.is_xperm:
            perms.update(r.perms)
    return known, classes, perms


def _cached_known_tokens(index) -> tuple:
    """:func:`_known_tokens`, computed once per index.

    The scan is over every rule in the tree -- 21,824 of them on the rk3568
    policy -- and the guards ask for it once per case. Converge amortized that
    by hoisting it out of the cluster loop; the single-denial path cannot, so
    the result is parked on the index instead. It is keyed off the index
    identity because it is a pure function of it, and two indexes must not
    share an entry.
    """
    got = index.__dict__.get("_known_tokens")
    if got is None:
        got = _known_tokens(index)
        index.__dict__["_known_tokens"] = got
    return got


def apply_guards(rec, patch: Optional[str], index) -> Optional[str]:
    """The six guards. Returns the reason a patch must not be auto-applied.

    A verdict has already decided *what is wrong and how one would fix it* by
    the time this runs; whether that fix may be applied unattended is a
    separate question, and this is the only thing that answers it. ``None``
    means no guard fired -- the patch is auto-safe.

    Both entry points call this, and the device calls its own ``ApplyGuards``
    at the same two points, because the two must not drift: the guards are the
    difference between "here is a rule that closes the gap" and "here is a rule
    that cannot land, and the log line you gave me is why".

      * target parsed as a bare MLS level (malformed context, e.g. an upstream
        typo ``u:charger_exec:s0`` lost the object_r role);
      * target is a ``default_*`` service placeholder (the real rule must hit
        the concrete ``sa_*``/``hdf`` type that ``service=`` resolves to);
      * subject/target not provably part of the indexed policy;
      * an object class no rule in the policy ever names (a misspelt class in a
        hand-copied log line -- ``samar_class`` for ``samgr_class`` -- yields a
        rule that cannot compile);
      * a requested permission that is not a permission name at all
        (transcription error in the log: ``denied { 0x5413 }`` with ``ioctl``
        written outside the braces);
      * a rule that grants no real permission (an ioctl-only denial routed to
        allowxperm semantics can come back as ``allow A B:c { };``).

    The order is the ranking of the reasons: the first to fire decides, so a
    target that is a security level is reported as that rather than as the
    unknown token it also is.
    """
    if index is None:
        return None
    known, known_classes, known_perms = _cached_known_tokens(index)

    if _is_mls_level(rec.target_type):
        return ("目标上下文可疑（被解析成安全级别而非类型，"
                "多为日志/注释笔误，勿照抄规则）")
    if _is_service_placeholder(rec.target_type):
        return ("目标为 default_* 占位符（service 需映射到具体 "
                "sa_*/hdf 类型才能落规则），转人工")
    if rec.source_domain not in known or rec.target_type not in known:
        unknown = (rec.source_domain if rec.source_domain not in known
                   else rec.target_type)
        return (f"主体/目标「{unknown}」不在当前策略语料中"
                "（设备新增域、生成的数字 service 标签或标注异常），"
                "补丁无法落点验证，转人工")
    if rec.tclass not in known_classes:
        return (f"对象类「{rec.tclass}」不在策略任何规则中出现"
                "（疑为日志笔误），补丁无法落点验证，转人工")
    bogus = [p for p in (rec.permissions or ()) if p not in known_perms]
    if bogus:
        return (f"权限位含非权限名「{'、'.join(bogus)}」"
                "（策略里没有任何规则授予过它；疑为日志转写笔误——"
                "ioctl 命令号被写进了权限位，而 `ioctl` 被写在括号外），"
                "照抄会落到编译不过的规则上，转人工")
    if _patch_is_vacuous(patch or ""):
        return ("补丁为空权限（ioctl 类缺口需 allowxperm 语义，"
                "当前修复路径给不出有效最小补丁），转人工")
    return None


def _patch_is_vacuous(patch: str) -> bool:
    """True when a suggested allow grants no real permission.

    RepairAgent routes an ioctl-only denial through allowxperm semantics and
    drops ``ioctl`` from the plain allow, which can yield ``allow A B:c { };``
    (empty permission set) when the class has no xperm whitelist to point at.
    Auto-suggesting such a rule is a misfire -> escalate to human instead.
    """
    m = re.search(r"\{\s*([^}]*)\}", patch)
    if not m:
        return False                      # unparseable -> don't over-block
    return not m.group(1).strip()


@dataclass
class Cluster:
    """One unique logical access found in the log + its pipeline outcome."""

    fp: str
    count: int
    permissive: int = 0
    enforcing: int = 0
    permissive_unknown: int = 0
    src: str = ""
    tgt: str = ""
    cls: str = ""
    perms: tuple = ()
    ioctl: str = ""
    comms: list = field(default_factory=list)
    sample_raw: str = ""
    # pipeline outcome
    category: str = CAT_UNCLASS
    classification: str = ""
    patch: str = ""
    review_status: str = ""
    verify_status: str = ""
    why: str = ""                     # human readable reason / recommended title
    # Host-only, and only filled when the caller asks for it (see to_dict):
    # the application-layer view of the same case. It never feeds category,
    # patch or `why`, so the device's report stays byte-identical.
    cross_layer: Optional[dict] = None


@dataclass
class ConvergeReport:
    """Aggregated convergence output for one log."""

    total_denials: int
    unique_cases: int
    by_category: dict = field(default_factory=dict)
    by_classification: dict = field(default_factory=dict)
    clusters: list = field(default_factory=list)        # list[dict] (all cases)
    auto_patch_lines: list = field(default_factory=list)  # dedup sorted
    auto_patch_stats: dict = field(default_factory=dict)  # patch -> {cases,denials}
    human_items: list = field(default_factory=list)       # list[dict]
    noise_cases: int = 0
    target_note: str = ""
    # The cross-layer roll-up; empty unless `converge(..., cross_layer=True)`.
    cross_layer_summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["dedup_ratio"] = (round(self.total_denials / self.unique_cases, 2)
                            if self.unique_cases else 0.0)
        d["readiness_note"] = self.readiness_note()
        if not self.cross_layer_summary and not any(
                c.get("cross_layer") for c in d["clusters"]):
            # No cross-layer view was asked for, so emit none -- not even as
            # nulls. `tests/diff_device.py` compares this report against the
            # on-device `Converge()` and fails on any key the device does not
            # carry. The device *can* now build the view (the `@hap` table
            # rides in the PLI), but `Converge()` does not emit it, so the key
            # stays out of the batch report either way. When the view *is*
            # requested the report stops being device-comparable, and that
            # gate is run without it -- see the section in docs/eval-converge.md.
            for c in d["clusters"]:
                c.pop("cross_layer", None)
            d.pop("cross_layer_summary", None)
        return d

    def readiness_note(self) -> str:
        a = self.by_category.get(CAT_AUTO, 0)
        h = self.by_category.get(CAT_HUMAN, 0)
        n = self.by_category.get(CAT_NOISE, 0)
        u = self.by_category.get(CAT_UNCLASS, 0)
        if u == self.unique_cases:
            return ("未提供策略索引：只能去重统计，不能生成修复建议。"
                    "加 --policy 指向 sepolicy 目录或 .te 文件即可出收敛方案。")
        human_pct = round(100 * h / max(self.unique_cases, 1))
        return (f"日志 {self.total_denials} 条 → 去重后 {self.unique_cases} 个唯一案例"
                f"（噪声/已允许 {n}）。其中 {a} 类可自动出最小权限补丁、"
                f"{h} 类需人工决策（占唯一案例约 {human_pct}%）。"
                "只建议，不写盘；真机上 enforcing 回归验证留待 L4。")


# --------------------------------------------------------------------------- #
# Cheap policy verdict (mirrors PolicyAgent + SecurityAgent.classify) so that
# obviously-noise / obviously-escalation clusters skip the full 6-agent run.
# --------------------------------------------------------------------------- #

def _quick_verdict(index, record) -> dict:
    src, tgt, cls = record.source_domain, record.target_type, record.tclass
    perms = frozenset(record.permissions or ())
    # M3: a denial that went through the service manager logs a placeholder
    # tcontext, so querying it directly answers a question nobody asked --
    # "does the policy allow access to the placeholder type?" (it never does),
    # which reads as a real gap. Resolve it to the concrete sa_*/hdf_* type the
    # `service=` field names, and query *that*: 6 of the 13 placeholder denials
    # in the real corpus turn out to be already allowed.
    #
    # Only the queries use the resolved name. `record.target_type` stays raw for
    # the reported cluster, the patch text and the six guards -- see the note on
    # _PLACEHOLDER_TARGETS above.
    qtgt = tgt
    if _is_service_placeholder(tgt):
        qtgt = (index.resolve_logical_target(src, cls, tgt, record.service, perms)
                or tgt)
    allowed, granted, _ = index.has_access(src, qtgt, cls, perms)
    nev = index.neverallow_rules(src, qtgt, cls, perms)
    ioctl = None
    if "ioctl" in perms and record.ioctl_cmd:
        io_ok, reason, _ = index.ioctl_allowed(src, qtgt, cls, record.ioctl_cmd)
        ioctl = {"allowed": io_ok, "reason": reason, "cmd": record.ioctl_cmd}
    return {
        "neverallow_hits": nev,
        "ioctl": ioctl,
        "all_allowed": bool(allowed),
        "requested_perms": sorted(perms),
        "granted_perms": sorted(granted),
    }


def _quick(record, verdict: dict) -> Optional[tuple]:
    """Decide obviously-noise / obviously-escalation cases without agents.

    Returns None when the full pipeline is needed (real repair decision).
    Returns (category, classification, patch, why) otherwise.
    """
    nev = verdict["neverallow_hits"]
    ioctl = verdict["ioctl"]
    permissive = bool(record.permissive)

    if nev:
        return (CAT_HUMAN, "POTENTIAL_ESCALATION", "",
                "命中 neverallow 红线：禁止自动放权（转人工）")
    if not verdict["all_allowed"]:
        return None                       # genuinely missing -> need a patch
    if ioctl is not None and not ioctl["allowed"]:
        return None                       # xperm gap -> need an allowxperm patch
    # policy already allows everything -> noise in permissive mode,
    # otherwise a domain/label problem (not something we patch)
    if permissive:
        return (CAT_NOISE, "NOISE_OR_ALREADY_FIXED", "", "策略已允许（历史/噪声）")
    return (CAT_HUMAN, "DOMAIN_OR_LABEL_MISMATCH", "",
            "策略已允许却被拒：疑似域/标签问题，非权限缺口")


# Kept as the module's historical spelling; the rule itself lives in
# policy_loop.policy.load so every entry point accepts the same --policy.
_load_index = load


def converge(text: str, index=None, case_prefix: str = "CONV",
             cross_layer: bool = False) -> ConvergeReport:
    """Cluster *text* by logical access and (if *index*) run the pipeline.

    *cross_layer* additionally asks, for every case whose ``scontext`` is an
    application domain, which layer owns the fix (see
    :mod:`policy_loop.policy.cross_layer`). Off by default: the view is a
    host-only addition to the report, and the default report is the object the
    device is byte-compared against.
    """
    records = parse_denials(text)
    groups: "collections.OrderedDict[str, list]" = collections.OrderedDict()
    for rec in records:
        groups.setdefault(fingerprint(rec), []).append(rec)

    orch = Orchestrator(index=index) if index is not None else None
    sehap = getattr(index, "sehap", None) if index is not None else None
    want_cross = bool(cross_layer and sehap is not None and sehap.entries)
    clusters: list = []
    auto_patch_cases: dict = {}
    auto_patch_denials: dict = {}
    human_items: list = []
    target_note = ""
    n = 0

    for fp, recs in groups.items():
        n += 1
        first = recs[0]
        cl = Cluster(fp=fp, count=len(recs), src=first.source_domain or "",
                     tgt=first.target_type or "", cls=first.tclass or "",
                     perms=tuple(first.permissions or ()), ioctl=first.ioctl_cmd or "",
                     sample_raw=first.raw)
        for r in recs:
            if r.permissive is True:
                cl.permissive += 1
            elif r.permissive is False:
                cl.enforcing += 1
            else:
                cl.permissive_unknown += 1
            if r.comm and r.comm not in cl.comms and len(cl.comms) < 5:
                cl.comms.append(r.comm)

        if index is not None:
            verdict = _quick_verdict(index, first)
            quick = _quick(first, verdict)
            if quick is not None:
                cl.category, cl.classification, cl.patch, cl.why = quick
            else:
                # genuinely needs a repair decision -> full deterministic loop
                case = orch.analyze(first.raw, case_id=f"{case_prefix}-{n:03d}")
                cl.classification = case.classification
                cl.patch = case.patch
                cl.review_status = (case.review or {}).get("status", "")
                cl.verify_status = (case.verify or {}).get("status", "")
                cl.why = ((case.recommended or {}).get("title")
                          or case.classification)
                cl.category = _categorize(cl, case)
                if not target_note and case.patch_target_note:
                    target_note = case.patch_target_note

            # Never auto-suggest a degenerate patch (see apply_guards).
            if cl.category == CAT_AUTO:
                if (reason := apply_guards(first, cl.patch, index)):
                    cl.category, cl.why = CAT_HUMAN, reason

            # The cross-layer view, after the bucket is final: it reads the
            # verdict but never writes one. Note it is computed for every
            # app-domain case, including the ones that took the cheap path --
            # the view's own "policy already allows it" answer is exactly what
            # a reader of those clusters needs, and it costs one sibling scan.
            if want_cross and sehap.is_app_domain(first.source_domain or ""):
                cl.cross_layer = cross_layer_view(
                    index, first.source_domain or "", first.target_type,
                    first.tclass, first.permissions,
                    allowed=verdict["all_allowed"],
                    service=first.service or "")

        clusters.append(cl)

        if cl.category == CAT_AUTO and cl.patch:
            auto_patch_cases[cl.patch] = auto_patch_cases.get(cl.patch, 0) + 1
            auto_patch_denials[cl.patch] = (auto_patch_denials.get(cl.patch, 0)
                                            + cl.count)
        elif cl.category == CAT_HUMAN:
            human_items.append({
                "case": cl.fp, "count": cl.count, "src": cl.src, "tgt": cl.tgt,
                "cls": cl.cls, "perms": sorted(cl.perms),
                "classification": cl.classification,
                "review": cl.review_status, "verify": cl.verify_status,
                "why": cl.why,
                "sample": cl.sample_raw[:200],
            })

    by_cat = collections.Counter(c.category for c in clusters)
    by_cls = collections.Counter(
        (c.classification or "n/a") for c in clusters
        if c.category != CAT_UNCLASS)

    report = ConvergeReport(
        total_denials=len(records),
        unique_cases=len(clusters),
        by_category=dict(by_cat),
        by_classification=dict(by_cls),
        clusters=[asdict(c) for c in clusters],
        auto_patch_lines=sorted(auto_patch_cases),
        auto_patch_stats={
            p: {"cases": auto_patch_cases[p], "denials": auto_patch_denials[p]}
            for p in sorted(auto_patch_cases)
        },
        human_items=human_items,
        noise_cases=by_cat.get(CAT_NOISE, 0),
        target_note=target_note,
        cross_layer_summary=_cross_layer_summary(clusters, len(records))
        if want_cross else {},
    )
    return report


def _cross_layer_summary(clusters: list, total_denials: int) -> dict:
    """Roll the per-cluster views up into the numbers a reader acts on.

    Two of them are the reason the section exists at all:

    * ``auto_patches_on_shared_domain`` -- auto-approved patches that land on a
      *shared* ``*_hap`` domain. Each one grants the permission to every app at
      that APL level, which is a far larger statement than "fix this denial",
      and nothing in the ``.te``-only view says so.
    * ``apl_boundary_cases`` -- cases where a higher APL level already has the
      access. Those are the ones that should not be auto-granted at all; they
      are listed, not re-bucketed (see the module docstring on why).
    """
    viewed = [c for c in clusters if c.cross_layer]
    if not viewed:
        return {}
    layers: dict = collections.Counter(c.cross_layer["fix_layer"]
                                       for c in viewed)
    apls: dict = collections.Counter(
        lvl for c in viewed for lvl in c.cross_layer["apl"])
    auto_shared = [{"patch": c.patch, "src": c.src, "tgt": c.tgt,
                    "cls": c.cls, "count": c.count,
                    "fix_layer": c.cross_layer["fix_layer"]}
                   for c in viewed
                   if c.category == CAT_AUTO and c.patch]
    boundary = [{"src": c.src, "tgt": c.tgt, "cls": c.cls,
                 "perms": sorted(c.perms), "count": c.count,
                 "patch": c.patch, "category": c.category,
                 "headline": c.cross_layer["headline"]}
                for c in viewed if c.cross_layer["fix_layer"] == "app"]
    return {
        "app_domain_cases": len(viewed),
        "unique_cases_total": len(clusters),
        "denials_total": total_denials,
        "by_fix_layer": dict(layers),
        "by_apl": dict(apls),
        "auto_patches_on_shared_domain": sorted(
            auto_shared, key=lambda d: (-d["count"], d["patch"])),
        "apl_boundary_cases": sorted(boundary, key=lambda d: -d["count"]),
        "note": ("跨层视图为宿主侧增补：它不改判 category/patch，设备端 "
                 "denial_check 也没有 @hap 表可复算，故默认报告不含该字段"
                 "（见 docs/eval-converge.md）。"),
    }


def _categorize(cl: Cluster, case) -> str:
    """Decide a cluster's bucket from a full pipeline result."""
    if case.classification in _HUMAN_CLASSES or case.needs_human:
        return CAT_HUMAN
    if case.classification in _NOISE_CLASSES:
        return CAT_NOISE
    if case.patch:
        if (case.review or {}).get("status") == "APPROVE" and \
                (case.verify or {}).get("status") == "SUCCESS":
            return CAT_AUTO
        return CAT_HUMAN          # patch rejected / not verified
    if case.classification == "MISSING_RULE":
        return CAT_HUMAN          # repair produced nothing -> not safe
    return CAT_NOISE


def _render_markdown(report: ConvergeReport) -> str:
    lines = [
        "# PolicyLoop 批量收敛报告",
        "",
        f"- 日志 denial 总数：**{report.total_denials}**",
    ]
    if report.unique_cases:
        lines.append(f"- 去重后唯一案例：**{report.unique_cases}**"
                     f"（去重比 {report.total_denials / report.unique_cases:.2f}x）")
    else:
        lines.append("- 去重后唯一案例：0")
    lines.append(
        f"- 分类分布：{json.dumps(report.by_category, ensure_ascii=False)}")
    lines += ["", "## 可自动最小修复（规则已通过评审与验证，仅建议、不写盘）", ""]
    if report.auto_patch_lines:
        for p in report.auto_patch_lines:
            st = report.auto_patch_stats[p]
            lines.append(f"```te\n{p}\n```")
            lines.append(f"  覆盖 {st['cases']} 个案例 / {st['denials']} 条 denial")
        lines.append("")
        if report.target_note:
            lines.append(f"> {report.target_note}")
    else:
        lines.append("（无）")
    lines += ["", "## 需人工决策", ""]
    if report.human_items:
        lines.append("| 案例 | 条数 | 访问 | 分类 | 原因 |")
        lines.append("|---|---|---|---|---|")
        for it in report.human_items[:100]:
            lines.append(
                f"| {it['case']} | {it['count']} | "
                f"{it['src']}→{it['tgt']}:{it['cls']} {{{','.join(it['perms'])}}} | "
                f"{it['classification']} | {it['why']} |")
    else:
        lines.append("（无）")
    lines += _render_cross_layer(report)
    lines += ["", "## 就绪度", "", report.readiness_note(), ""]
    return "\n".join(lines)


def _render_cross_layer(report: ConvergeReport) -> list:
    """The application-layer section, or nothing when it was not computed.

    Kept separate from the rest of the markdown because every other section is
    a projection of the device-comparable report; this one has no counterpart
    on device and must not be mistaken for one.
    """
    s = report.cross_layer_summary
    if not s:
        return []
    lines = ["", "## 跨层视图（应用层 ↔ 系统层）", "",
             f"- scontext 是应用域的案例：**{s['app_domain_cases']}** / "
             f"{s['unique_cases_total']} 个唯一案例"
             f"（其余 {s['unique_cases_total'] - s['app_domain_cases']} 个"
             "与跨层无关，按系统层处理）"]
    if s.get("by_apl"):
        lines.append("- 应用域案例的 APL 分布：" + "、".join(
            f"{k} {v}" for k, v in sorted(s["by_apl"].items(),
                                          key=lambda kv: -kv[1])))
    if s.get("by_fix_layer"):
        label = {"app": "应用层", "system": "系统层", "none": "无需修复"}
        lines.append("- 修复归属：" + "、".join(
            f"{label.get(k, k)} {v}"
            for k, v in sorted(s["by_fix_layer"].items(), key=lambda kv: -kv[1])))

    shared = s.get("auto_patches_on_shared_domain") or []
    lines += ["", f"### 落在共享应用域上的自动补丁（{len(shared)} 条）", ""]
    if shared:
        lines.append("`*_hap` 是**共享域**：下面每条规则对该 APL 等级的"
                     "**全部应用**生效，不只是触发它的那一个。")
        lines.append("")
        for it in shared:
            flag = ("  ← 跨层判为应用层问题，建议人工复核"
                    if it["fix_layer"] == "app" else "")
            lines.append(f"```te\n{it['patch']}\n```")
            lines.append(f"  {it['src']} → {it['tgt']}:{it['cls']}，"
                         f"覆盖 {it['count']} 条 denial{flag}")
    else:
        lines.append("（无）")

    boundary = s.get("apl_boundary_cases") or []
    lines += ["", f"### APL 分级边界（{len(boundary)} 条，建议人工而非自动放权）", ""]
    if boundary:
        lines.append("该访问在更高 APL 等级上已被允许 —— 平台是**有意**把它"
                     "挡在这一级之外的，补 `.te` 等于取消这条分级线。")
        lines.append("")
        lines.append("| scontext | 访问 | 条数 | 当前分桶 |")
        lines.append("|---|---|---|---|")
        for it in boundary:
            lines.append(
                f"| {it['src']} | {it['tgt']}:{it['cls']} "
                f"{{{','.join(it['perms'])}}} | {it['count']} | {it['category']} |")
        lines.append("")
        for it in boundary[:3]:
            lines.append(f"> {it['headline']}")
    else:
        lines.append("（无：没有案例被更高 APL 等级挡住）")
    lines.append("")
    lines.append(f"> {s['note']}")
    return lines


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="PolicyLoop batch convergence")
    ap.add_argument("--log", help="denial log file to converge")
    ap.add_argument("--text", help="inline denial log text")
    ap.add_argument("--policy", help="sepolicy dir or .te file to index")
    ap.add_argument("--json", type=Path, help="write JSON report")
    ap.add_argument("--md", type=Path, help="write markdown report")
    ap.add_argument("--cross-layer", action="store_true",
                    help="add the application-layer view (APL / shared-domain "
                         "scope / which layer owns the fix). Off by default so "
                         "the JSON report stays device-comparable; the on-device "
                         "tool reaches the same view through "
                         "`--explain --cross-layer`. The markdown report always "
                         "includes it.")
    args = ap.parse_args(argv)

    if not args.log and not args.text:
        ap.error("provide --log <file> or --text <...>")
    text = args.text if args.text else \
        Path(args.log).read_text(encoding="utf-8", errors="replace")

    index = _load_index(args.policy) if args.policy else None
    if index is not None:
        summary = index.summary()
        print(f"[PolicyLoop converge] policy rules indexed = {summary['rules']}")
        if summary["skipped_statements"]:
            # The count has always been carried in `summary()`, the JSON/PLI
            # metadata and the device's `@meta`, but a plain run never showed
            # it, so nothing said how much of the tree the index left out.
            print(f"[PolicyLoop converge] WARNING: {summary['skipped_statements']} "
                  f"statement(s) were not modelled -- verdicts on the types and "
                  f"classes they touch can be wrong; "
                  f"see docs/known-limitations.md")
    report = converge(text, index=index,
                      cross_layer=bool(args.cross_layer or args.md))

    print(f"denials={report.total_denials}  unique={report.unique_cases}  "
          f"by_category={report.by_category}")
    if report.auto_patch_lines:
        print("\n# 可自动最小修复（建议 .te，不写盘）")
        for p in report.auto_patch_lines:
            st = report.auto_patch_stats[p]
            print(f"  {p}   # {st['cases']} 案例 / {st['denials']} 条")
    if report.human_items:
        print("\n# 需人工决策")
        for it in report.human_items[:30]:
            print(f"  [{it['classification']}] {it['src']}->{it['tgt']}"
                  f":{it['cls']} {{{','.join(it['perms'])}}} x{it['count']}"
                  f"  -- {it['why']}")
    s = report.cross_layer_summary
    if s:
        print(f"\n# 跨层视图：应用域案例 {s['app_domain_cases']} / "
              f"{s['unique_cases_total']}（APL "
              f"{'、'.join(f'{k} {v}' for k, v in sorted(s['by_apl'].items(), key=lambda kv: -kv[1]))}）")
        print(f"  修复归属：{s['by_fix_layer']}")
        shared = s.get("auto_patches_on_shared_domain") or []
        if shared:
            print(f"  落在共享应用域上的自动补丁 {len(shared)} 条"
                  "（对同等级全部应用生效）：")
            for it in shared:
                flag = "  ← 建议人工复核" if it["fix_layer"] == "app" else ""
                print(f"    {it['patch']}{flag}")
        for it in (s.get("apl_boundary_cases") or [])[:5]:
            print(f"  [APL 边界] {it['headline']}")
    print("\n" + report.readiness_note())

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"\nreport written -> {args.json}")
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(_render_markdown(report), encoding="utf-8")
        print(f"markdown written -> {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
