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
from policy_loop.policy import load_dir, load_text

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
# wrong/unverifiable -> escalate to human until the M3 service mapping exists.
_PLACEHOLDER_TARGETS = frozenset({"default_service", "default_hdf_service"})


def _is_service_placeholder(token: Optional[str]) -> bool:
    return bool(token) and token in _PLACEHOLDER_TARGETS


def _known_tokens(index) -> tuple:
    """Return (tokens, classes) provably part of the indexed policy.

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
    """
    known = set(index.type_attrs)
    classes: set = set()
    for r in index.rules:
        for tok in (r.src if isinstance(r.src, str) else r.src):
            known.add(tok)
        for tok in (r.tgt if isinstance(r.tgt, str) else r.tgt):
            known.add(tok)
        classes.add(r.cls)
    return known, classes


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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["dedup_ratio"] = (round(self.total_denials / self.unique_cases, 2)
                            if self.unique_cases else 0.0)
        d["readiness_note"] = self.readiness_note()
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
    allowed, granted, _ = index.has_access(src, tgt, cls, perms)
    nev = index.neverallow_rules(src, tgt, cls)
    ioctl = None
    if "ioctl" in perms and record.ioctl_cmd:
        io_ok, reason, _ = index.ioctl_allowed(src, tgt, cls, record.ioctl_cmd)
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


def _load_index(policy: str):
    p = Path(policy)
    if p.is_dir():
        return load_dir(p)
    if p.exists():
        return load_text(p.read_text(encoding="utf-8", errors="replace"),
                         source=str(p))
    raise FileNotFoundError(f"policy not found: {policy}")


def converge(text: str, index=None, case_prefix: str = "CONV") -> ConvergeReport:
    """Cluster *text* by logical access and (if *index*) run the pipeline."""
    records = parse_denials(text)
    groups: "collections.OrderedDict[str, list]" = collections.OrderedDict()
    for rec in records:
        groups.setdefault(fingerprint(rec), []).append(rec)

    orch = Orchestrator(index=index) if index is not None else None
    known, known_classes = (_known_tokens(index) if index is not None
                            else (None, None))
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

            # Never auto-suggest a degenerate patch. Four guards:
            #  * target parsed as a bare MLS level (malformed context, e.g.
            #    an upstream typo "u:charger_exec:s0" lost the object_r role);
            #  * target is a default_* service placeholder (real rule must hit
            #    the concrete sa_*/hdf type that `service=` resolves to);
            #  * subject/target not provably part of the indexed policy;
            #  * a rule that grants no real permission (ioctl-only denial routed
            #    to allowxperm semantics can come back as "allow A B:c { };")
            if cl.category == CAT_AUTO:
                if _is_mls_level(first.target_type):
                    cl.category, cl.why = CAT_HUMAN, (
                        "目标上下文可疑（被解析成安全级别而非类型，"
                        "多为日志/注释笔误，勿照抄规则）")
                elif _is_service_placeholder(first.target_type):
                    cl.category, cl.why = CAT_HUMAN, (
                        "目标为 default_* 占位符（service 需映射到具体 "
                        "sa_*/hdf 类型才能落规则），转人工")
                elif first.source_domain not in known or \
                        first.target_type not in known:
                    unknown = (first.source_domain
                               if first.source_domain not in known
                               else first.target_type)
                    cl.category, cl.why = CAT_HUMAN, (
                        f"主体/目标「{unknown}」不在当前策略语料中"
                        "（设备新增域、生成的数字 service 标签或标注异常），"
                        "补丁无法落点验证，转人工")
                elif first.tclass not in known_classes:
                    cl.category, cl.why = CAT_HUMAN, (
                        f"对象类「{first.tclass}」不在策略任何规则中出现"
                        "（疑为日志笔误），补丁无法落点验证，转人工")
                elif _patch_is_vacuous(cl.patch):
                    cl.category, cl.why = CAT_HUMAN, (
                        "补丁为空权限（ioctl 类缺口需 allowxperm 语义，"
                        "当前修复路径给不出有效最小补丁），转人工")

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
    )
    return report


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
    lines += ["", "## 就绪度", "", report.readiness_note(), ""]
    return "\n".join(lines)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="PolicyLoop batch convergence")
    ap.add_argument("--log", help="denial log file to converge")
    ap.add_argument("--text", help="inline denial log text")
    ap.add_argument("--policy", help="sepolicy dir or .te file to index")
    ap.add_argument("--json", type=Path, help="write JSON report")
    ap.add_argument("--md", type=Path, help="write markdown report")
    args = ap.parse_args(argv)

    if not args.log and not args.text:
        ap.error("provide --log <file> or --text <...>")
    text = args.text if args.text else \
        Path(args.log).read_text(encoding="utf-8", errors="replace")

    index = _load_index(args.policy) if args.policy else None
    if index is not None:
        print(f"[PolicyLoop converge] policy rules indexed = "
              f"{index.summary()['rules']}")
    report = converge(text, index=index)

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
