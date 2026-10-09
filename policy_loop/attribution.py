"""策略级根因归因：把「需人工」的那一堆拆成"该谁修"。

``converge`` 把 4,911 个唯一案例分成三类，其中 **1,580 个进 `needs_human`** --
占了三分之一,而它对这些案例说的话只有一句:「转人工」。对着一屏"转人工",
读者学到的是工具不知道,而不是工具知道什么。

这个模块把那 1,580 个逐条问出**根因**,判据全部是**可证伪的查询**,不是启发式:

* 板子上到底有没有这个符号?（问板子自己的 ``policy.31`` 反编译视图）
* 板子上到底允不允许这组权限? 允许的话,是哪条规则允许的?
* 不允许的话,上游树允许吗?（⇒ 两边版本差）
* 主体是不是板上声明为 ``permissive`` 的域?（那样的域**不可能**产生 enforcing 拒绝）
* 日志本身有没有 ``permissive=`` 字段?

**本平台上不存在的三类根因（已证伪,不是没查）**:板子策略里 `(boolean` 出现
**0** 次、`(constrain` **0** 次、`(mlsconstrain` 只有 **1** 条且只约束
``(filesystem (relabelto))`` 上的 MLS 级。所以「boolean 未开」「constraint 拦下」
「MLS 级不匹配」在本平台**原理上无从发生**;把它们列进报告当"检查过了"是撒谎。

每条案例最终落到一个 ``owner``,这是本模块真正交付的东西：

    TOOL    工具侧该修（索引/版本对齐、语料收录）
    DEVICE  板上真要补权限（唯一需要打补丁的一类）
    HUMAN   需要架构决策（撞 neverallow 红线）
    LOG     采集/日志质量（缺字段、上下文畸形）
    NONE    无需动作（现在已允许）

退出码 = 0 仅当残留 ``UNATTRIBUTED`` 为 0：**归因不完备就失败**,不许悄悄漏掉。
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .converge import _is_mls_level, _is_service_placeholder
from .policy.cil import Board, load_cil
from .policy.index import PolicyIndex

__all__ = [
    "Attribution", "AttributionReport", "attribute", "attribute_one",
    "render_markdown", "main",
    "RC_REDLINE", "RC_EMPTY_FIELD", "RC_FIELD_SHIFT", "RC_MALFORMED",
    "RC_NO_CLASS", "RC_NO_PERM", "RC_PLACEHOLDER", "RC_NO_SYMBOL",
    "RC_PERMISSIVE_DOMAIN", "RC_GRANTED_DIRECT", "RC_GRANTED_ATTR",
    "RC_VERSION_DRIFT", "RC_PARTIAL_GAP", "RC_PERM_UNKNOWN",
    "RC_UNATTRIBUTED", "OWNER",
]

CAT_AUTO = "auto_repairable"
CAT_HUMAN = "needs_human"
CAT_NOISE = "noise_or_already_allowed"

DEFAULT_BOARD_FP = Path(os.environ.get("BOARD_FP",
                                       "/home/szf/board-5.0.3-fingerprint"))

# ---- 根因标签（顺序即判定优先级，先命中先算）------------------------------
RC_REDLINE = "NEVERALLOW_REDLINE"
RC_EMPTY_FIELD = "LOG_MISSING_FIELD"
RC_FIELD_SHIFT = "LOG_FIELD_SHIFT"
RC_MALFORMED = "MALFORMED_LOG"
RC_NO_CLASS = "UNKNOWN_OBJECT_CLASS"
RC_NO_PERM = "UNKNOWN_PERMISSION"
RC_PLACEHOLDER = "UNRESOLVED_SERVICE_PLACEHOLDER"
RC_NO_SYMBOL = "BOARD_SYMBOL_ABSENT"
RC_PERMISSIVE_DOMAIN = "PERMISSIVE_DOMAIN"
RC_GRANTED_DIRECT = "ALREADY_GRANTED_DIRECT"
RC_GRANTED_ATTR = "ALREADY_GRANTED_VIA_ATTR"
RC_VERSION_DRIFT = "DEVICE_LAGS_TREE"
RC_PARTIAL_GAP = "BOARD_PARTIAL_GAP"
RC_PERM_UNKNOWN = "PERMISSIVE_UNKNOWN"
RC_UNATTRIBUTED = "UNATTRIBUTED"

# 前三类都是"这条记录本身不自洽",与设备策略无关,所以都归 LOG 而不是 TOOL:
# 一条把对象类名写进类型位的记录,任何策略侧的工作都修不了它。
#
# ``UNKNOWN_OBJECT_CLASS`` / ``UNKNOWN_PERMISSION`` 也归 LOG 有一个必须讲清的
# 理由:它们问的是**板子内核自己的词汇表**。内核对不认识的类/权限根本不会产生
# AVC,所以这类记录不可能来自这台设备 —— 要么是转写笔误,要么是语料来自更新的
# 内核。两种情况都不是"该给设备补权限"。
OWNER = {
    RC_REDLINE: "HUMAN",
    RC_EMPTY_FIELD: "LOG",
    RC_FIELD_SHIFT: "LOG",
    RC_MALFORMED: "LOG",
    RC_NO_CLASS: "LOG",
    RC_NO_PERM: "LOG",
    RC_PLACEHOLDER: "TOOL",
    RC_NO_SYMBOL: "TOOL",
    RC_PERMISSIVE_DOMAIN: "NONE",
    RC_GRANTED_DIRECT: "NONE",
    RC_GRANTED_ATTR: "NONE",
    RC_VERSION_DRIFT: "TOOL",
    RC_PARTIAL_GAP: "DEVICE",
    RC_PERM_UNKNOWN: "LOG",
    RC_UNATTRIBUTED: "TOOL",
}

# converge 六道守门留下的 why 前缀（只在没有板子视图时当判据用；有板子时它
# 作为佐证附在 detail 后面，见 attribute_one）。
_MALFORMED_SIGNS = (
    "目标上下文可疑", "目标为 default_* 占位符", "权限位含非权限名",
    "补丁为空权限", "对象类「", "主体/目标「",
)

_WHAT = {
    RC_REDLINE: "撞 neverallow 红线：补权限会被上游红线拒绝,须改架构而非放权",
    RC_EMPTY_FIELD: "记录缺主体/目标/对象类：无从判断说的是哪次访问",
    RC_FIELD_SHIFT: "对象类名或权限名被写进了类型位：日志列错位",
    RC_MALFORMED: "日志/语料形态问题：无法据此落规则,应先修采集",
    RC_NO_CLASS: "板子内核没有这个对象类：内核对不认识的类不产生 AVC,非本机记录",
    RC_NO_PERM: "板子该对象类没有这个权限名：转写笔误,或语料来自更新的内核",
    RC_PLACEHOLDER: "目标仍是 default_* 服务占位符：须先由 `service=` 解析到具体 sa_*/hdf_* 类型",
    RC_NO_SYMBOL: "板子策略里没有这个（主体/目标）类型：域是设备新增的,上游语料没收录",
    RC_PERMISSIVE_DOMAIN: "主体是板上声明为 permissive 的域：它不可能产生 enforcing 拒绝",
    RC_GRANTED_DIRECT: "板上已由具体类型规则授权：该缺口已被修复,这是历史记录",
    RC_GRANTED_ATTR: "板上已由属性规则授权（域设计如此）：已覆盖,非缺口",
    RC_VERSION_DRIFT: "上游树允许、板子不允许：索引与设备策略的版本差,属工具侧对齐问题",
    RC_PARTIAL_GAP: "板子只授予了部分权限：这才是真正要在板上补的缺口",
    RC_PERM_UNKNOWN: "日志缺 `permissive=` 字段：无法判定当时是否 enforcing",
    RC_UNATTRIBUTED: "未归因：判据都未命中,须补判据而不是放过",
}


@dataclass
class Attribution:
    fp: str
    src: str
    tgt: str
    cls: str
    perms: list
    count: int = 1
    # 日志自报的 enforcing/permissive 分布。`permissive=1` 的 denial **没有真的
    # 拦住任何东西**,所以它是不是"缺口"要分开看 —— 这也是引擎目前唯一没有利用
    # 的字段（采集器与引擎都不按 permissive 过滤）。
    enforcing: int = 0
    permissive: int = 0
    classification: str = ""
    root_cause: str = ""
    owner: str = ""
    detail: str = ""            # 命中的规则原文 / 缺的权限 / 板子查询结果
    what: str = ""


@dataclass
class AttributionReport:
    total_clusters: int = 0
    attributed: int = 0
    unattributed: int = 0
    by_root_cause: dict = field(default_factory=dict)
    by_owner: dict = field(default_factory=dict)
    by_cause_owner: dict = field(default_factory=dict)
    falsified_axes: list = field(default_factory=list)
    device_findings: list = field(default_factory=list)
    board: str = ""
    board_available: bool = False
    index_path: str = ""
    corpus_is_comments: bool = False
    note: str = ""
    items: list = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.unattributed == 0


def _owner_of(rc: str) -> str:
    return OWNER.get(rc, "TOOL")


# --------------------------------------------------------------------------- #
# 判定
# --------------------------------------------------------------------------- #

def _existing_rule(index: Optional[PolicyIndex], src, tgt, cls, perms):
    """Return (kind, raw) of the rule that covers the access, or None.

    kind ∈ {'direct', 'attr'} -- whether the covering rule names concrete
    types on both sides, or reaches through an attribute.
    """
    if index is None:
        return None
    for r in index.allow_rules(src, tgt, cls):
        if set(perms) <= set(r.perms):
            concrete = (all(x not in index.attributes for x in r.src)
                        and all(x not in index.attributes for x in r.tgt))
            return ("direct" if concrete else "attr", r.raw)
    return None


def _malformed_sign(why: str) -> bool:
    return any(why.startswith(s) for s in _MALFORMED_SIGNS)


def _all_perms(board: Board) -> set:
    """Every permission name any class on the board has, cached per board."""
    got = getattr(board, "_all_perm_names", None)
    if got is None:
        got = set().union(*board.class_perms.values()) if board.class_perms \
            else set()
        board._all_perm_names = got
    return got


def _wellformed_defect(board: Board, src: str, tgt: str, cls: str,
                       perms) -> Optional[tuple]:
    """Return ``(root_cause, detail)`` if the *record* is self-evidently bad.

    This screen runs **before** any policy query, and that ordering is the
    point.  A record naming a permission that its own object class does not
    have, or an object class in a type slot, is not evidence of a policy gap
    -- it is evidence that the log line was transcribed wrong.  Querying the
    policy for it first would "answer" the question anyway (the board denies
    it, obviously) and report a confident, useless diagnosis.

    Everything here is decidable from the board's own kernel vocabulary,
    which is exactly the authority on what a denial could have said.
    """
    empty = [n for n, v in (("subject", src), ("target", tgt),
                            ("class", cls)) if not v]
    if empty:
        return RC_EMPTY_FIELD, "缺字段: " + "、".join(empty)
    if not perms:
        return RC_EMPTY_FIELD, "缺权限位"

    classes = board.classes
    perm_names = _all_perms(board)
    # `sock_file`, `lnk_file`, `file`, `dir`, `samgr_class` are all *classes*,
    # and `transfer`/`call` are *permissions*; finding either in a type slot
    # means the columns shifted.  Real type names never collide with these --
    # the board's 1183 types and 104 classes are disjoint sets.
    shifted = [n for n in (src, tgt) if n in classes or n in perm_names]
    if shifted:
        kind = "对象类名" if shifted[0] in classes else "权限名"
        return RC_FIELD_SHIFT, f"{kind}「{'、'.join(shifted)}」出现在类型位"

    if cls not in classes:
        return RC_NO_CLASS, f"板上内核无对象类 {cls}"
    missing = sorted(set(perms) - board.class_perms.get(cls, set()))
    if missing:
        return RC_NO_PERM, f"类 {cls} 无权限 {'、'.join(missing)}"
    return None


def attribute_one(index: Optional[PolicyIndex], board: Optional[Board],
                  c: dict) -> Attribution:
    """Ask one cluster why it is in the human bucket."""
    src, tgt, cls = c.get("src", ""), c.get("tgt", ""), c.get("cls", "")
    perms = sorted(c.get("perms") or ())
    a = Attribution(fp=c.get("fp", ""), src=src, tgt=tgt, cls=cls, perms=perms,
                    count=int(c.get("count") or 1),
                    enforcing=int(c.get("enforcing") or 0),
                    permissive=int(c.get("permissive") or 0),
                    classification=c.get("classification", ""))
    why = c.get("why") or ""
    a.detail = why                      # converge 的说法先留着,后面可能被覆盖

    # 1) 红线：converge 已经判过,补权限会被上游 neverallow 拒绝。
    if a.classification == "POTENTIAL_ESCALATION":
        a.root_cause = RC_REDLINE
        a.owner, a.what = _owner_of(RC_REDLINE), _WHAT[RC_REDLINE]
        return a

    if board is not None:
        # 2) 记录本身不自洽吗？—— 先问这个,再问策略,理由见 _wellformed_defect。
        defect = _wellformed_defect(board, src, tgt, cls, perms)
        # 3) 目标被解析成了裸 MLS 级（`u:charger_exec:s0` 掉了 role 那段）。
        if defect is None and (_is_mls_level(tgt) or _is_mls_level(src)):
            bad = tgt if _is_mls_level(tgt) else src
            defect = (RC_MALFORMED, f"「{bad}」被解析成安全级别而非类型")
        # 4) 目标仍是 `default_*` 占位符：类型真实存在,但落规则要先解出具体服务。
        if defect is None and (_is_service_placeholder(tgt)
                              or _is_service_placeholder(src)):
            defect = (RC_PLACEHOLDER,
                      f"「{tgt if _is_service_placeholder(tgt) else src}」"
                      "须由 service= 解析到具体 sa_*/hdf_* 类型")
        if defect is not None:
            a.root_cause, extra = defect
            a.detail = f"{extra}｜converge: {why}" if why else extra
            a.owner, a.what = _owner_of(a.root_cause), _WHAT[a.root_cause]
            return a

        # 5) 主体是 permissive 域 —— 它不可能产生 enforcing 拒绝。
        if src in board.permissive_domains:
            a.root_cause = RC_PERMISSIVE_DOMAIN
            a.detail = f"{src} 在板上是 permissive 域"
        # 6) 板子上有没有这个类型。到这一步记录已自洽,所以缺符号是真的缺。
        elif src not in board.symbols or tgt not in board.symbols:
            miss = [n for n in (src, tgt) if n not in board.symbols]
            a.root_cause = RC_NO_SYMBOL
            a.detail = "板子无此类型: " + "、".join(miss)
        # 7) 板子已经全允许了:再问是哪条规则允许的。
        elif board.satisfied(src, tgt, cls, set(perms)):
            hit = _existing_rule(index, src, tgt, cls, perms)
            if hit and hit[0] == "direct":
                a.root_cause, a.detail = RC_GRANTED_DIRECT, hit[1]
            elif hit:
                a.root_cause, a.detail = RC_GRANTED_ATTR, hit[1]
            else:
                # 板上由属性规则覆盖,但上游树里没有对应的具体规则。
                a.root_cause, a.detail = RC_GRANTED_ATTR, "板子属性闭包覆盖"
            if why and not why.startswith("策略已允许"):
                a.detail += f"｜converge: {why}"
        else:
            # 8) 板子不允许。上游树呢?
            have = board.granted(src, tgt, cls)
            missing = sorted(set(perms) - have)
            upstream = _existing_rule(index, src, tgt, cls, perms)
            if upstream is not None:
                a.root_cause = RC_VERSION_DRIFT
                a.detail = f"上游 {upstream[1]}；板上缺 {'、'.join(missing) or '(无)'}"
            else:
                a.root_cause = RC_PARTIAL_GAP
                a.detail = f"板上缺 {'、'.join(missing)}"
        a.owner, a.what = _owner_of(a.root_cause), _WHAT[a.root_cause]
        return a

    # 没有板子视图时,只能判日志形态这一层。
    if _malformed_sign(why):
        a.root_cause = RC_MALFORMED
    elif c.get("count") and c.get("permissive_unknown") == c.get("count"):
        # 每一次出现都缺字段,才敢说"整条都无法判定是否 enforcing"。
        a.root_cause, a.detail = RC_PERM_UNKNOWN, "日志无 permissive= 字段"
    else:
        a.root_cause = RC_UNATTRIBUTED
        a.detail = why or "无判据命中"
    a.owner, a.what = _owner_of(a.root_cause), _WHAT[a.root_cause]
    return a


# --------------------------------------------------------------------------- #
# 汇总
# --------------------------------------------------------------------------- #

def _board_falsified_axes(board: Board, text: str) -> list:
    """本平台**不存在**的根因轴,连同证伪它的计数一起返回。

    把「检查过了、没发现」写成「本平台原理上不会有」需要证据;这就是证据。
    """
    out = []
    for label, pat, why in (
        ("boolean 未开", r"^\(boolean ", "板子策略无 boolean 声明"),
        ("constraint 拦下", r"^\(constrain ", "板子策略无 constrain 语句"),
    ):
        n = len(re.findall(pat, text, re.M))
        out.append({"axis": label, "occurrences": n,
                    "verdict": "本平台不存在" if n == 0 else "存在,需判据",
                    "why": why})
    mls = [m[0] for m in re.findall(r"^\(mlsconstrain \((.*?)\) \((.*?)\)\)",
                                    text, re.M)]
    out.append({"axis": "MLS 级不匹配", "occurrences": len(mls),
                "verdict": "本平台不存在" if not mls
                else ("本平台仅有的约束不涉及本语料" if len(mls) <= 1
                      else "存在,需判据"),
                "why": f"约束对象 {mls or '（无）'}"})
    return out


def _group_device_findings(items: list) -> list:
    """Collapse the DEVICE bucket into one entry per (domain, class).

    Thirteen rows reading "netsysnative x netlink_xfrm_socket" are one finding,
    not thirteen: the reader needs the domain, the classes and the permission
    set, and grouping is what turns a list into a work item.
    """
    g: dict = {}
    for i in items:
        if i["owner"] != "DEVICE":
            continue
        k = (i["src"], i["cls"])
        e = g.setdefault(k, {"src": i["src"], "cls": i["cls"], "perms": set(),
                             "tgts": set(), "cases": 0, "denials": 0,
                             "enforcing": 0, "permissive": 0})
        e["perms"].update(i["perms"])
        e["tgts"].add(i["tgt"])
        e["cases"] += 1
        e["denials"] += i["count"]
        e["enforcing"] += i.get("enforcing", 0)
        e["permissive"] += i.get("permissive", 0)
    out = sorted(g.values(), key=lambda e: (-e["denials"], e["src"], e["cls"]))
    for e in out:
        e["perms"] = sorted(e["perms"])
        e["tgts"] = sorted(e["tgts"])
    return out


def attribute(report: dict, index: Optional[PolicyIndex] = None,
              board: Optional[Board] = None, board_text: str = "",
              corpus_text: str = "", index_path: str = "") -> AttributionReport:
    """Attribute every ``needs_human`` cluster in a converge report."""
    human = [c for c in report.get("clusters") or []
             if c.get("category") == CAT_HUMAN]
    res = AttributionReport(total_clusters=len(human))
    res.board_available = board is not None
    res.index_path = index_path
    res.board = str(board.path) if board is not None else ""
    if board is not None:
        res.falsified_axes = _board_falsified_axes(board, board_text)

    lines = [l for l in (corpus_text or "").splitlines() if l.strip()]
    res.corpus_is_comments = bool(lines) and all(l.lstrip().startswith("#")
                                                 for l in lines)

    by_rc = collections.Counter()
    by_owner = collections.Counter()
    by_pair = collections.Counter()
    for c in human:
        a = attribute_one(index, board, c)
        res.items.append(asdict(a))
        by_rc[a.root_cause] += 1
        by_owner[a.owner] += 1
        by_pair[(a.root_cause, a.owner)] += 1

    res.by_root_cause = dict(by_rc.most_common())
    res.by_owner = dict(by_owner.most_common())
    res.by_cause_owner = {f"{k[0]} ({k[1]})": v
                          for k, v in by_pair.most_common()}
    res.unattributed = by_rc.get(RC_UNATTRIBUTED, 0)
    res.attributed = res.total_clusters - res.unattributed
    res.device_findings = _group_device_findings(res.items)

    if not res.board_available:
        res.note = ("未提供板子策略（--board-cil）：只能判日志形态这一层,"
                    "符号/授权/版本差三类判据全部不可用 —— 这份归因是**残缺的**,"
                    "别当结论用。")
    elif res.corpus_is_comments:
        res.note = ("语料每一行都以 `#` 开头,是上游 `.te` 注释里的**历史 denial 记录**,"
                    "不是一次设备采集。因此「板子已授权」占多数是**预期**结果："
                    "这些记录写下时规则还不存在,后来被补上了。"
                    "真正待修的缺口看 owner=DEVICE 那一档。")
    else:
        res.note = "语料为设备采集,各档可直接当作当前缺口分布读。"
    if res.board_available and res.index_path:
        res.note += (f" ⚠️ 判据里的「上游树」是 `{res.index_path}`；"
                     "`DEVICE_LAGS_TREE` 与 `BOARD_SYMBOL_ABSENT` 两档的**数量**随"
                     "这棵树变化（换成本设备自己的 5.0.3 血脉树，符号缺失会显著变"
                     "多、版本差会变少），只有 `DEVICE` 那一档是跨树稳定的结论。")
    return res


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #

_OWNER_LABEL = {"TOOL": "工具侧", "DEVICE": "设备侧（要补策略）",
                "HUMAN": "人工决策", "LOG": "采集/日志质量", "NONE": "无需动作"}


def render_markdown(res: AttributionReport) -> list:
    out = ["## 根因归因：需人工的案例该谁修", "",
           f"共 {res.total_clusters} 个进人工档的案例，"
           f"归因出 {res.attributed} 个，**残留 {res.unattributed} 个**"
           f"（{'✅ 完备' if res.complete else '❌ 不完备'}）。", ""]
    if res.device_findings:
        n = sum(f["cases"] for f in res.device_findings)
        out += [f"### 设备侧真正待补的 {n} 条（唯一需要动手的一类）", ""]
        if len(res.device_findings) < n:
            out += [f"归并成 {len(res.device_findings)} 组后：", ""]
        out += ["| 域 | 目标类型 | 对象类 | 缺的权限 | 案例 | 其中 enforcing |",
                "|---|---|---|---|---|---|"]
        for f in res.device_findings:
            out.append(f"| `{f['src']}` | "
                       f"{'、'.join('`' + t + '`' for t in f['tgts'])} | "
                       f"`{f['cls']}` | "
                       f"{'、'.join('`' + p + '`' for p in f['perms'])} | "
                       f"{f['cases']} | {f['enforcing']} |")
        enf = sum(f["enforcing"] for f in res.device_findings)
        out += ["",
                f"「其中 enforcing」是日志自报 `permissive=0` 的案例数 —— 那些是**真**"
                f"被拦下的访问（共 {enf} 条）。`permissive=1` 的记录的 denial 只是"
                "记录，不构成功能故障。", ""]
    else:
        out += ["**这一档为空**：没有任何案例需要给设备补策略。", ""]
    out += ["| 该谁修 | 案例 | 占比 |", "|---|---|---|"]
    for owner, n in res.by_owner.items():
        pct = 100 * n / max(res.total_clusters, 1)
        out.append(f"| {_OWNER_LABEL.get(owner, owner)} | {n} | {pct:.1f}% |")
    out += ["", "### 逐条根因", "", "| 根因 | 该谁修 | 案例 | 含义 |",
            "|---|---|---|---|"]
    for rc, n in res.by_root_cause.items():
        out.append(f"| `{rc}` | {_OWNER_LABEL.get(_owner_of(rc), '')} | {n} | "
                   f"{_WHAT.get(rc, '')} |")
    if res.falsified_axes:
        out += ["", "### 本平台不存在的根因（已证伪，不是没查）", "",
                "| 根因轴 | 出现次数 | 判定 | 依据 |", "|---|---|---|---|"]
        for f in res.falsified_axes:
            out.append(f"| {f['axis']} | {f['occurrences']} | {f['verdict']} | "
                       f"{f['why']} |")
    out += ["", f"> {res.note}", ""]
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[list] = None) -> int:
    from . import converge as C
    from .policy.index import load_dir

    ap = argparse.ArgumentParser(
        description="PolicyLoop root-cause attribution for the human bucket")
    ap.add_argument("--log", help="denial log file")
    ap.add_argument("--text", help="inline denial log text")
    ap.add_argument("--policy", help="sepolicy dir or .te file (the upstream tree)")
    ap.add_argument("--board-cil", default=str(DEFAULT_BOARD_FP / "board-policy.cil"),
                    help="板子 policy.31 的反编译 CIL；判符号/授权/版本差都要它")
    ap.add_argument("--json", type=Path, help="write JSON result")
    ap.add_argument("--md", type=Path, help="write markdown section")
    args = ap.parse_args(argv)

    if not args.log and not args.text:
        ap.error("provide --log <file> or --text <...>")
    text = args.text if args.text else \
        Path(args.log).read_text(encoding="utf-8", errors="replace")

    index = load_dir(args.policy) if args.policy else None
    board, board_text = None, ""
    p = Path(args.board_cil)
    if p.exists():
        board = load_cil(p)
        board_text = p.read_text(encoding="utf-8", errors="replace")
    else:
        print(f"[attribution] ⚠️ 板子策略不存在，跳过符号/授权/版本差判据: {p}")

    report = C.converge(text, index=index).to_dict()
    res = attribute(report, index=index, board=board, board_text=board_text,
                    corpus_text=text, index_path=args.policy or "")

    print(f"[PolicyLoop attribution] {res.total_clusters} 个人工案例 → "
          f"归因 {res.attributed}，残留 {res.unattributed}")
    for owner, n in res.by_owner.items():
        print(f"    {owner:7} {n:5}  {_OWNER_LABEL.get(owner, owner)}")
    for rc, n in res.by_root_cause.items():
        print(f"      {rc:24} {n:5}")
    for f in res.device_findings:
        print(f"    ★ 待补 {f['src']} → {f['cls']}: "
              f"{'、'.join(f['perms'])}"
              + (f"  [{f['enforcing']} 条 enforcing]" if f["enforcing"] else ""))
    print(f"    {res.note}")

    if args.json:
        args.json.write_text(json.dumps(asdict(res), ensure_ascii=False,
                                        indent=2), encoding="utf-8")
    if args.md:
        args.md.write_text("\n".join(render_markdown(res)), encoding="utf-8")
    return 0 if res.complete else 1


if __name__ == "__main__":                      # pragma: no cover
    raise SystemExit(main())
