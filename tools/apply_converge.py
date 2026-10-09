#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""converge 报告 → 板子策略补丁 → policy.31 的落地桥（L4 闭环合拢）

在此之前，PolicyLoop 的两端都已跑通、但中间是断的：

    上游  converge 判出 70 类 auto_repairable，吐出 69 行最小补丁 —— **纯数据，不写盘**
    下游  build_policy.sh 把一份 CIL 补丁 + 板子原策略喂给 secilc → policy.31，
          再 checkpolicy 回验、install_to_board.sh 刷进板子 —— **真机验证过**

本工具就是中间那段：把上游那份数据按**板子实际的策略**过门，渲染成 CIL，
调同一套 secilc/checkpolicy 编译回验，产出可直接交给 install_to_board.sh 的 policy.31。

为什么本工具自带编译段、不复用 build_policy.sh：
    后者 step 4/5 的断言是**采集域专用**的（写死了 `(type denial_check)`、
    `(typetransition normal_hap data_local_tmp process denial_check)` 等）。
    喂 converge 的补丁进去必然断言失败。本工具用同一套宿主工具、同一套安全性质，
    但断言对象换成"我这次到底注入了哪几条"。

六道门（与 converge 的守门同构，但判别对象是**板子策略**而非上游语料）：

    1 解析门  .te 语句必须能解析成 `allow[ xperm] src tgt:cls { perms }`
    2 符号门  src/tgt/类的符号必须存在于板子策略（含 typeattribute 闭包）
    2b 权限门  每个权限必须真属于该类的权限集
    3 幂等门  板上已允许的权限集直接跳过 —— 可重复跑，不会堆重复规则
    4 编译门  secilc 编译；语法/冲突在这里报错
    5 回验门  checkpolicy 反编译回来，逐条确认补丁真的进了二进制，
              且相对原版**没有内容丢失**（判据见下）

★ 2b 拦的不是语法错，是**语料与板子的版本差**：补丁取自上游 master 的 .te，
  板子是 5.0.3。实测 69 行里 6 行在板子上 (类,权限) 根本不成立 ——
  `data_service_el1_file:file { add_name }`（add_name 是 dir 的权限、类写成了 file）、
  `persist_param:parameter_service { map open read }`（板子的 parameter_service
  只有 1 个权限）等。少了这道门就只剩 secilc 一句
  `Failed to resolve permission add_name`，看不出是哪一类问题。

★ 第 5 门的判据是"**内容有没有被吸收**"，不是"那行字还在不在"。
  checkpolicy 反编译会把同一 (src,tgt,类) 的授权归并成一行、把 `A A` 归一成 `A self`、
  把多个 xperm 值并进一个表达式。实测：不做任何补丁的纯 CIL→二进制→CIL 往返就已经
  有 190 处"移除"（全是 neverallow 残留的死属性）；加补丁后多出 9 处，全是上述归并。
  按字面串判会全部误报 —— 必须按权限子集 / xperm 区间覆盖来判。

⚠️ 第 4 门兜不住 neverallow。
    板子策略是从 policy.31 反编译来的，而 **neverallow 是编译期断言、不落盘** ——
    实测 `board-policy.cil` 里 `(neverallow` 出现 **0 次**。所以 secilc 重编时
    根本没有 neverallow 可查，"编译过了"不等于"没撞 neverallow"。
    这条防线由 converge 自己的索引提供（neverallow 一律转人工，不进 auto_patch）。
    本工具不重复该检查，但会在报告里显式标注 —— 不要把第 4 门当成 neverallow 的保证。

实测（2026-10-07，converge-full.json 69 行 × board-5.0.3-fingerprint）：

    69 输入 → 47 注入（45 allow + 2 allowx）/ 14 板上已满足 / 8 拒
    编译产物 policy.31 = 407 546 B，policyvers=31，头部与原版逐字节一致
    语义 diff 新增 37 行 / 移除 199 行（0 条内容丢失）；47 条注入全部回验到

  "板上已满足 14 条"本身是个结论：补丁是对**上游 master** 的索引算的，
  而板子 5.0.3 早就允许了其中的 14 条 —— 这正是"索引必须与板子同源"那条教训的量化。

用法：

    # 只判定 + 出 CIL 片段，不编译（不需要宿主工具链）
    python tools/apply_converge.py --report data/reports/converge-full.json --no-build

    # 判定 + 编译 + 回验，产出 policy.31
    python tools/apply_converge.py --report data/reports/converge-full.json

    # 换板子/换源码树（默认读 BOARD_FP / OHOS_SRC 环境变量）
    BOARD_FP=/path/to/fp OHOS_SRC=/path/to/ohos python tools/apply_converge.py ...

装到板子是**另一步**，本工具不代劳（会改设备状态）：
    bash device/selinux_policy/install_to_board.sh   # 见该脚本头部说明
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

if str(REPO) not in sys.path:           # tools/ 不是包根，库在仓库根下
    sys.path.insert(0, str(REPO))
from policy_loop.policy.cil import (   # noqa: E402
    Board,
    xperm_covered as _xperm_covered,
    xperm_intervals as _xperm_intervals,
)

DEFAULT_BOARD_FP = Path(os.environ.get("BOARD_FP", "/home/szf/board-5.0.3-fingerprint"))
DEFAULT_OHOS_SRC = Path(os.environ.get("OHOS_SRC", "/home/szf/ohos_src"))
POLICYVERS = 31

# 与 board-policy.cil（checkpolicy -b -C 的产物）对齐的解析式
_RE_TYPE = re.compile(r"^\(type ([A-Za-z0-9_.\-]+)\)", re.M)
_RE_ATTR = re.compile(r"^\(typeattribute ([A-Za-z0-9_.\-]+)\)", re.M)
_RE_CLASS = re.compile(r"^\(class ([A-Za-z0-9_.\-]+) ", re.M)
_RE_ATTRSET = re.compile(r"^\(typeattributeset ([A-Za-z0-9_.\-]+) \((.*?)\)\)\s*$", re.M)
_RE_ALLOW = re.compile(r"^\(allow (\S+) (\S+) \((\S+) \(([^)]*)\)\)\)", re.M)

# ★ 类的权限不是只有 `(class X (...))` 那一串：checkpolicy -C 会把继承自 common 的
#   权限放到 `(common NAME (...))`，再用 `(classcommon 类 common)` 绑定。只读前半截
#   会得出 "file 类没有 getattr" 这种离谱结论（实测踩过），所以必须两半合起来。
_RE_COMMON = re.compile(r"^\(common (\S+) \(([^)]*)\)\)", re.M)
_RE_CLASSCOMMON = re.compile(r"^\(classcommon (\S+) (\S+)\)", re.M)

# converge 的补丁行（.te 语法）
_RE_TE = re.compile(
    r"^allow(?P<xp>xperm)?\s+(?P<src>\S+)\s+(?P<tgt>\S+):(?P<cls>\S+)\s+"
    r"(?:(?P<op>\S+)\s+)?\{\s*(?P<perms>[^}]*?)\s*\}\s*;\s*$"
)

# 源树里的 neverallow（.te 语法）。这四条正则是**形态**级的：四个位置都接受集合
# 写法，语义留给 `_na_type_expr` / `_na_perm_list` 去解。判不出来的形态在那里
# 带原因跳过并计数，不做半吊子翻译。
#
# 为什么必须先收下再判：板子源树的 neverallow 里绝大多数是集合写法
# （`{ chipset_domain -audio_host ... }` 这种属性集减差集是 OH 的标准写法），
# 形态级就拒收的话，门 4 只能盖住 8%。
#
# 三个位置各有一条独立的 `{...}` 分支：写成 `\S+` 会让 `{ a b }` 匹配失败，
# 于是和真正的畸形行一起落进「形态不合」，把「有列表」这个可解释的原因埋掉。
#
# 类型位置还要允许**不带花括号的取反**：`neverallow * ~samgr:samgr_class list;`
# （域侧写单个属性取反是 OH 的老写法，板子上 4 条）。少这个 `~?` 就会把这 4 条
# 真实红线错记成"形态不合"丢掉。
_NA_TYPE = r"(?:~?\s*\{[^{}]*\}|\*|~?[A-Za-z0-9_][A-Za-z0-9_.\-]*)"
_NA_CLS = r"(?:\{[^{}]*\}|[A-Za-z0-9_][A-Za-z0-9_.\-]*)"
_NA_PERM = r"(?:~?\s*\{[^{}]*\}|\*|~?[A-Za-z0-9_][A-Za-z0-9_.\-]*)"

_RE_TE_NEVERALLOW = re.compile(
    rf"^neverallow\s+(?P<src>{_NA_TYPE})\s+(?P<tgt>{_NA_TYPE})\s*:\s*"
    rf"(?P<cls>{_NA_CLS})\s+(?P<perms>{_NA_PERM})\s*;\s*$",
    re.S,
)
# 命令号位置有两种合法写法（checkpolicy/policy_parse.y:783 `xperms : xperm |
# nested_xperm_set | tilde xperm | tilde nested_xperm_set`）：`{ 0x1 0x2 }` 和
# **裸的单值** `0x4517`。后者在语料树里真有一条（`dev_encaps.te`），只认花括号
# 会把它错记成"形态不合"而丢掉。
_RE_TE_NEVERALLOWX = re.compile(
    rf"^neverallowxperm\s+(?P<src>{_NA_TYPE})\s+(?P<tgt>{_NA_TYPE})\s*:\s*"
    rf"(?P<cls>{_NA_CLS})\s+(?P<op>[A-Za-z0-9_]+)\s+"
    rf"(?P<tilde>~)?\s*(?:\{{(?P<xps>[^}}]*)\}}|(?P<xps1>0x[0-9a-fA-F]+))\s*;\s*$",
    re.S,
)

# 合成属性的名字前缀。板子策略里不会有人叫这个，但仍然会和 board.symbols 对一次。
_NA_ATTR_PREFIX = "pl_na_set"


# --------------------------------------------------------------------------
# xperm 表达式
# --------------------------------------------------------------------------
# CIL 把它写成 `(allowx S T (ioctl 类 (表达式)))`，表达式是嵌套的:
#   ((0x5413))                         单个
#   (((range 0x1 0x4)))                区间
#   ((0xf50c (range 0xf546 0xf547)))   多个混排
# 板子实测 522/714 是"单个"、其余是各种区间混排。要判"某值是否已被覆盖"
# 就必须把区间摊平，光做字符串比较会漏掉藏在 range 里的值。


# --------------------------------------------------------------------------
# 板子策略
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# 五道门
# --------------------------------------------------------------------------
def gate_parse(lines: list[str]) -> list[dict]:
    """门 1：能解析成 allow / allowxperm。"""
    out, bad = [], []
    for raw in lines:
        line = raw.strip()
        m = _RE_TE.match(line)
        if not m:
            bad.append({"line": line, "verdict": "rejected", "gate": "parse",
                        "reason": "不是 allow/allowxperm 语句"})
            continue
        out.append({
            "line": line,
            "kind": "allowxperm" if m.group("xp") else "allow",
            "src": m.group("src"),
            "tgt": m.group("tgt"),
            "cls": m.group("cls"),
            "op": m.group("op") or "ioctl",
            "perms": m.group("perms").split(),
        })
    return out + bad


def gate_symbols(rules: list[dict], board: Board) -> list[dict]:
    """门 2：符号必须在板子策略里存在。"""
    for r in rules:
        if r.get("verdict"):
            continue
        missing = []
        if r["src"] not in board.symbols:
            missing.append(f"src={r['src']}")
        if r["tgt"] not in board.symbols:
            missing.append(f"tgt={r['tgt']}")
        if r["cls"] not in board.classes:
            missing.append(f"cls={r['cls']}")
        if missing:
            r["verdict"] = "rejected"
            r["gate"] = "symbols"
            r["reason"] = "板子策略无此符号: " + ", ".join(missing)
        else:
            r["verdict"] = "pending"
    return rules


def gate_perms(rules: list[dict], board: Board) -> list[dict]:
    """门 2b：每个权限必须真属于该类的权限集。

    这道门拦的是**语料与板子的版本差**，不是语法错：语料取自上游 master 的 .te，
    板子是 5.0.3。实测 69 行里有 6 行的 (类,权限) 组合在板子上根本不成立 ——
    例如 `data_service_el1_file:file { add_name }`（add_name 是 dir 的权限，类写成了 file）、
    `persist_param:parameter_service { map open read }`（板子的 parameter_service
    只有 1 个权限，上游后来加了）。少这道门就是 secilc 报
    `Failed to resolve permission add_name`，还看不出是哪一类问题。
    """
    for r in rules:
        if r["verdict"] != "pending":
            continue
        if r["kind"] == "allowxperm":
            continue          # xperm 值不是权限名，不在本门判
        valid = board.class_perms.get(r["cls"], set())
        bad = [p for p in r["perms"] if p not in valid]
        if bad:
            r["verdict"] = "rejected"
            r["gate"] = "perms"
            r["reason"] = (f"权限 {bad} 不属于类 {r['cls']}"
                           f"（该类在板子上有 {len(valid)} 个权限）—— 语料/板子版本差")
        # 通过的保持 pending，交给下一道门
    return rules


def gate_idempotent(rules: list[dict], board: Board) -> list[dict]:
    """门 3：板上已允许的直接跳过。"""
    for r in rules:
        if r["verdict"] != "pending":
            continue
        key = (r["src"], r["tgt"], r["cls"])
        if r["kind"] == "allowxperm":
            if board.xperm_satisfied(r["src"], r["tgt"], r["cls"], set(r["perms"])):
                r["verdict"] = "already_satisfied"
                r["gate"] = "idempotent"
                r["reason"] = "板子策略已允许该 xperm"
                continue
        elif board.satisfied(r["src"], r["tgt"], r["cls"], set(r["perms"])):
            r["verdict"] = "already_satisfied"
            r["gate"] = "idempotent"
            r["reason"] = "板子策略已允许这组权限（含属性闭包）"
            continue
        r["verdict"] = "emit"
        r["key"] = list(key)
    return rules


def render_cil(rules: list[dict]) -> str:
    """把 emit 的规则渲染成 CIL。"""
    out = []
    for r in rules:
        if r["verdict"] != "emit":
            continue
        perms = " ".join(sorted(set(r["perms"])))
        if r["kind"] == "allowxperm":
            # ★ xperm 的两处坑（都实测踩过，别照 .te 的写法推）：
            #   1) CIL 关键字是 `allowx`，不是 .te/conf 里的 `allowxperm`
            #      （libsepol: CIL_KEY_ALLOWX = "allowx"）→ 否则 `Unknown keyword allowxperm`
            #   2) 括号结构是 `(allowx SRC TGT (ioctl 类 (xperm)))` —— 类名在
            #      `ioctl` 之后、**不在** allowx 的第三个参数位，也没有多余一层
            #      （cil_fill_permissionx 要的是 STRING(kind) STRING(类) LIST(表达式)）。
            #      写成 `(allowx S T 类 (ioctl 类 (x)))` 或 `(allowx S T (类 (ioctl (x))))`
            #      都是 `Invalid syntax / Bad allowx rule`。
            xs = " ".join(sorted(set(r["perms"])))
            out.append(f"(allowx {r['src']} {r['tgt']} ({r['op']} {r['cls']} ({xs})))")
        else:
            out.append(f"(allow {r['src']} {r['tgt']} ({r['cls']} ({perms})))")
    return "\n".join(out) + ("\n" if out else "")


# --------------------------------------------------------------------------
# 门 4/5：编译与回验
# --------------------------------------------------------------------------
def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _shown(path: Path) -> str:
    """Path for display: repo-relative when it is inside the repo, else absolute.

    ``--out-cil /tmp/x.cil`` used to raise ``ValueError`` out of a *print* call
    after the fragment had already been written -- a crash that left the run
    half-done.
    """
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def _join_rule_lines(text: str, keywords: tuple) -> list[tuple[int, str]]:
    """语句级的源树切片：把跨行的 neverallow 拼回一条。

    The policy tree wraps 40 rule statements across physical lines; reading them
    line by line yields fragments that no regex matches, so they would silently
    drop out of the red-line set.
    """
    out: list[tuple[int, str]] = []
    pending, start = "", 0
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        if pending:
            merged = f"{pending} {s}".strip()
            if merged.endswith(";"):
                out.append((start, merged))
                pending = ""
            else:
                pending = merged
            continue
        if not s:
            continue
        if s.startswith(keywords) and not s.endswith(";"):
            pending, start = s, lineno
        elif s.startswith(keywords) and s.endswith(";"):
            out.append((lineno, s))
    if pending:
        out.append((start, pending))
    return out


_RE_M4_DEFINE = re.compile(r"^define\(`([^']+)',\s*`(.*?)'\)\s*$", re.M | re.S)


def _load_m4_defines(src_dir: Path) -> dict:
    """源树 `*.spt` 里"展开成一个符号列表"的 m4 宏。

    OH 的 neverallow 大量引用宏而不是直接写符号：

        glb_te_def.spt    define(`system_domain', `sadomain rgm_violator_sadomain hap_domain native_system_domain')
        glb_perm_def.spt  define(`devfile_class_set', `{ blk_file chr_file }')   ← 类集
                          define(`file_class_set', `{ devfile_class_set notdevfile_class_set }')  ← 还会嵌套
        glb_never_def.spt define(`never_write_dir', `{ add_name create link … }') ← 权限集

    不展开的话这些语句全都只能以"符号 system_domain 不在板子上"之类的原因跳过
    （实测 78 条类型宏 + 26 条类集 + 33 条权限集），而它们在板上是**真实存在**的
    红线 —— `native_system_domain` 是有成员的。展开就是 m4 在编译前做的事。

    含 `$1`/`ifelse(`/括号的宏是**语句模板**（`binder_call` 那种），展开出来不是
    符号列表，一律不收：拿它们当集合只会得到一堆语法碎片。
    """
    raw: dict[str, list[str]] = {}
    for f in sorted(src_dir.rglob("*.spt")):
        for name, body in _RE_M4_DEFINE.findall(
                f.read_text(encoding="utf-8", errors="replace")):
            body = body.strip()
            if not body or "$" in body or "(" in body:
                continue
            tokens = body.strip("{}").split()
            if tokens:
                raw.setdefault(name, tokens)
    out: dict[str, list[str]] = {}

    def expand(name: str, depth: int = 0) -> list[str]:
        if name in out:
            return out[name]
        if depth > 8 or name not in raw:
            return [name]
        out[name] = []                 # 先占位，自引用时不会无限递归
        got: list[str] = []
        for t in raw[name]:
            got.extend(expand(t, depth + 1) if t in raw else [t])
        out[name] = got
        return got

    for n in list(raw):
        expand(n)
    return out


def _expand_items(items: list, m4: dict) -> list:
    """列表项里的宏名就地展开（保留否定号）。"""
    out: list[str] = []
    for it in items:
        neg = it.startswith("-")
        name = it[1:] if neg else it
        out.extend(("-" + s if neg else s) for s in m4.get(name, [name]))
    return out


def _na_fold(op: str, parts: list) -> str:
    """把多元集合运算折成右结合的二叉树。

    ★ CIL 的 `and`/`or` **只收两个操作数**：`(or (a) (b) (c))` 会被
    secilc 判成 `Invalid syntax / Bad typeattributeset statement`。实测
    `(or (a) (or (b) (c)))` 才行。三元素以上的列表在这棵树上到处都是，
    不折的话注进去的 CIL 根本编译不过。
    """
    expr = parts[-1]
    for p in reversed(parts[:-1]):
        expr = f"({op} {p} {expr})"
    return expr


def _na_type_expr(tok: str, board: Board, decls: list, counter, m4: dict,
                  default_reason: str = "类型/属性不在板子策略中") -> tuple:
    """类型位置（src/tgt）→ (CIL 里能当类型用的东西, 原因)。

    `.te` 的类型位置可以写集合，CIL 的 neverallow 却只收**类型表达式**。好在
    CIL 有 `(all)` / `(or ...)` / `(and ...)` / `(not ...)`，而属性在 CIL 里就是
    类型，所以集合写法能**精确**翻译，不必把属性枚举成具体类型：

        { a b }        → (or (a) (b))
        { a -b -c }    → (and (a) (not (b)) (not (c)))
        *              → (all)
        ~{ a b }       → (not (or (a) (b)))
        ~attr          → (not (attr))

    表达式不能直接写进 neverallow 的 src/tgt 位，得先合成一个属性再引用它，
    所以返回值可能是新声明的属性名（声明追加进 `decls`）。这些写法都在板子
    策略上用 secilc 真编译验过：造违例必报、干净策略零误报，`(not (domain))`
    也确实把 domain 的成员排除了 —— 不是"看起来像检查"的装饰。
    """
    tok = tok.strip()
    negate = tok.startswith("~")
    if negate:
        tok = tok[1:].strip()
    if tok == "*":
        base = "(all)"
    else:
        items = tok.strip("{}").split() if tok.startswith("{") else [tok]
        items = _expand_items(items, m4)
        pos = [i for i in items if not i.startswith("-")]
        neg = [i[1:] for i in items if i.startswith("-")]
        # 板上没有的符号：**正项**是空转（没有任何 allow 会提到它，补丁也造不出
        # 它 —— 符号门不许引入新符号），**否定项**是什么都没排除。两种都能安全
        # 丢掉，而且丢掉之后断言在板上的强度不变。
        pos = [n for n in pos if n in board.symbols]
        neg = [n for n in neg if n in board.symbols]
        if not pos:
            # 一个正项都不剩 ⇒ 这条红线在板上恒真，跳过等价。
            return None, default_reason + "（板上空转）"
        if len(pos) == 1 and not neg and not negate:
            return pos[0], None
        base = f"({pos[0]})" if len(pos) == 1 else _na_fold(
            "or", [f"({n})" for n in pos])
        if neg:
            base = _na_fold("and", [base] + [f"(not ({n}))" for n in neg])
    if negate:
        base = f"(not {base})"
    name = f"{_NA_ATTR_PREFIX}_{next(counter)}"
    decls.append(f"(typeattribute {name})")
    decls.append(f"(typeattributeset {name} {base})")
    return name, None


def _na_self_line(src: str, cls: str, perms: list) -> str:
    """`neverallow X self:cls P` → `(neverallow X self (cls (P)))`。

    `self` 是 CIL 自己的关键字（`libsepol/cil/src/cil.c:258`，`cil_resolve_avrule`
    里 `rule->tgt_str == CIL_KEY_SELF → db->selftype`），板子策略里就有 2378 条
    `(allow X self (...))`。**不需要**把 X 摊成具体类型再逐条写 `x → x`：那条路
    我走过，它把一条断言炸成上千行，还给 `neverallow * self:…` 这类语句设了个
    4000 行的上限去兜底 —— 全是自找的。

    （先前记的"CIL 里 self 不是关键字"是**误判**：那次测的是
    `(neverallow (all) self (…))`，它报的 `Invalid syntax Bad allow rule` 来自
    `(all)`，不是 `self` —— CIL 的规则位置上不接受 `(all)`，`(all)` 只能出现在
    `typeattributeset` 的表达式里，所以 `*` 仍然要合成属性，见 `_na_type_expr`。）

    语义已用「造违例」验过：`(allow X X (cls (P)))` 必报，而 `(allow X Y ...)`
    这种跨类型的不报 —— 与 `.te` 的 `self` 一致。
    """
    return f"(neverallow {src} self ({cls} ({' '.join(perms)})))"


def _na_class_list(tok: str, board: Board, m4: dict) -> tuple:
    """类位置 → 板子上存在的类名列表（`.te` 可以写 `:{ file dir }` 或类集宏）。"""
    tok = tok.strip()
    names = tok.strip("{}").split() if tok.startswith("{") else [tok]
    names = _expand_items(_expand_items(names, m4), m4)   # 宏里还能再套宏
    if not names:
        return None, "类列表为空"
    if any(n.startswith(("-", "~")) for n in names):
        return None, "类列表含否定"
    if any(n not in board.class_perms for n in names):
        return None, "类不在板子策略中"
    return list(dict.fromkeys(names)), None


def _na_perm_list(tok: str, cls: str, board: Board, m4: dict) -> tuple:
    """权限位 → 该类在**板子策略上**的具体权限名列表，或 (None, 原因)。

    类型位置能用表达式精确翻译，权限位不行：CIL 没有权限通配，`*` 与 `~{...}`
    只能按板子该类的权限表展开/求补。这张表从 policy.31 反编译读回
    （`Board.class_perms`，含 classcommon 继承），是这个 binary 的真实权限集 ——
    拿源树的权限表来补，会把版本差当成新权限，补出来的断言反而比原版更宽。

    权限集宏（`never_write_dir` 这类，定义在 glb_never_def.spt）先展开。
    """
    tok = tok.strip()
    negate = tok.startswith("~")
    if negate:
        tok = tok[1:].strip()
    universe = board.class_perms[cls]
    if tok == "*":
        return sorted(universe), None
    items = tok.strip("{}").split() if tok.startswith("{") else [tok]
    items = _expand_items(items, m4)
    if not items:
        return None, "权限集合为空"
    if [p for p in items if p.startswith("-") or p not in universe]:
        return None, "权限名不适用于该类的板子策略"
    got = sorted(universe - set(items)) if negate else sorted(set(items))
    if not got:
        return None, "权限取反后为空集"
    return got, None


def _na_xperm_expr(xps: list, tilde: bool, stats: dict) -> tuple:
    """命令号列表 → CIL 权限表达式体（`(ioctl 类 (体))` 里那一层），或 (None, 原因)。

    ★ 两个只能这么做、不能按直觉写的地方：

    1. **命令号必须截到 16 位。** 源树里有 32 位写法（`foundation.te` 的
       `0x400c620e 0xc00c620f`），而 `.te` 那条路本来就是截断的：
       `checkpolicy/policy_define.c:1973,1993` 都是 `(uint16_t) strtoul(...)`，
       `avrule_omit_ioctls` 求补也是补到 `0xffff`。CIL 这边超过 0xFFFF 直接
       报错（`libsepol/cil/src/cil_post.c:1052`）。所以 `& 0xffff` 不是"失真
       近似"，它就是源树语义；不截反而编译不过。截了几条要计数报出来。
    2. **`~{...}` 要求补成区间，不能写 `(not ...)`。** CIL 的权限表达式不认
       `~`（实测 `(ioctl file ((~ (0x620e))))` → `permissionx value ~ not
       valid number`），`and/not` 也一样。但 `(range lo hi)` 是支持的
       （`cil_post.c:1328-1337` 明确为 `CIL_PERMISSIONX` 实现），而 16 位空间
       上挖掉 n 个值最多剩 n+1 段区间 —— 精确、且不随值域膨胀。

    两种体都在这块板子上实火验过：给补集外的号造一条 allowx 必报，给补集内
    的号造则不报（`/tmp/xp/r_probe_*.cil`）。
    """
    vals = []
    for x in xps:
        v = int(x, 16)
        if v > 0xFFFF:
            v &= 0xFFFF
            stats["xperm: 32 位命令号按源树语义截成 16 位"] += 1
        vals.append(v)
    vals = sorted(set(vals))
    if not tilde:
        return " ".join(f"0x{v:04x}" for v in vals), None
    gaps: list = []
    lo = 0
    for v in vals:
        if v > lo:
            gaps.append((lo, v - 1))
        lo = v + 1
    if lo <= 0xFFFF:
        gaps.append((lo, 0xFFFF))
    if not gaps:
        return None, "xperm 补集为空"
    return " ".join(f"(range 0x{a:04x} 0x{b:04x})" for a, b in gaps), None


def _gate4_verdict(ok) -> str:
    """片段头里那行门 4 结论 —— 由**编译结果**决定，不能预先写死。

    片段的头是编译前拼的（编译要等到工具末尾才知道结果），原先无条件写着
    "secilc 编译通过"。撞红线时这句就是假话，而片段是会被拷进策略树、也会被
    人单独阅读的东西：一句"通过"足以让人以为越权的补丁是干净的。所以编译后
    回过头来把这行改写成实际结论。`ok=None` 是 `--no-build`（红线根本没查过，
    不能说通过，也不能说失败）。
    """
    if ok is None:
        return ";; ⚠️ 本次未编译（--no-build）⇒ 下列红线**未被检查过**。"
    if ok:
        return ";; ✅ 门 4 结果：secilc 编译**通过**（红线未越）。"
    return (";; ✗ 门 4 结果：secilc 编译**失败** —— 源树的 neverallow 拦下了本补丁。\n"
            ";;    本片段**不可落地**，详见下方 secilc 报错与判定报告。")


def count_assertions(lines: list) -> int:
    """注入行里有几条是真断言（其余是合成属性的声明）。

    `(neverallow` 前缀同时覆盖 `(neverallowx`，正是想要的。
    """
    return sum(1 for ln in lines if ln.startswith("(neverallow"))


def collect_neverallow(src_dir: Path, board: Board) -> tuple[list[str], dict]:
    """源树的 neverallow → 可注入板子 CIL 的断言。

    This is what turns gate 4 into an actual red-line gate. The board policy is
    read back from the compiled binary with ``checkpolicy -b -C``, and
    ``neverallow`` is a *compile-time* assertion that does not survive into the
    binary -- the decompiled CIL carries zero of them. So ``secilc`` compiling
    the patched policy proves nothing about escalation, no matter how many gates
    are stacked on it. Only assertions re-stated in the CIL source it compiles
    are checked at all.

    Statements that cannot be translated faithfully are counted and skipped
    rather than approximated: a red line re-stated *narrower* than the original
    is worse than no red line, because it reads as a check that passed.

    返回 (注入行, 跳过原因计数)；注入行里既有合成属性的声明也有断言本身，
    断言条数用 `count_assertions` 数。
    """
    stats: collections.Counter = collections.Counter()
    decls: list[str] = []
    emitted: list[str] = []
    seen: set[str] = set()
    counter = itertools.count(1)
    m4 = _load_m4_defines(src_dir)
    for f in sorted(src_dir.rglob("*.te")):
        for _, st in _join_rule_lines(
                f.read_text(encoding="utf-8", errors="replace"),
                ("neverallow", "neverallowxperm")):
            if "(" in st:
                stats["含宏/条件表达式"] += 1
                continue
            # 合成属性先攒在局部：某条断言后半段判不过要整条丢弃时，不能把
            # 半截声明留在文件里（声明没用倒无害，但会让人以为注入成功了）。
            local_decls: list[str] = []
            m = _RE_TE_NEVERALLOW.match(st)
            if m:
                cls_names, why = _na_class_list(m.group("cls"), board, m4)
                if why:
                    stats[why] += 1
                    continue
                src_tok = m.group("src").strip()
                tgt_tok = m.group("tgt").strip()
                self_tgt = tgt_tok == "self"
                if src_tok == "self" and not self_tgt:
                    # .te 的 `self` 只出现在目标位；源位写 self 没有语义可依，
                    # 猜不得，如实跳过。
                    stats["self 出现在源位置（.te 语法里没有这个写法）"] += 1
                    continue
                src, why = _na_type_expr(
                    src_tok, board, local_decls, counter, m4)
                if why is None and not self_tgt:
                    tgt, why = _na_type_expr(
                        tgt_tok, board, local_decls, counter, m4)
                if why:
                    stats[why] += 1
                    continue
                per_cls: list[tuple] = []
                for cls in cls_names:
                    perms, why = _na_perm_list(m.group("perms"), cls, board, m4)
                    if why:
                        break
                    per_cls.append((cls, perms))
                if why:
                    # 类列表里只要有一个类译不出，整条都不能发：发一半等于
                    # 悄悄把红线收窄了。
                    stats[why] += 1
                    continue
                if self_tgt:
                    # `self` 是 CIL 自己就有的关键字，直接照写（见 `_na_self_line`）。
                    lines = [_na_self_line(src, cls, perms)
                             for cls, perms in per_cls]
                else:
                    lines = [f"(neverallow {src} {tgt} ({cls} ({' '.join(perms)})))"
                             for cls, perms in per_cls]
            else:
                mx = _RE_TE_NEVERALLOWX.match(st)
                if mx is None:
                    stats["形态不合（源列表/通配等）"] += 1
                    continue
                cls_names, why = _na_class_list(mx.group("cls"), board, m4)
                if why is None:
                    src, why = _na_type_expr(
                        mx.group("src"), board, local_decls, counter, m4)
                if why is None:
                    tgt, why = _na_type_expr(
                        mx.group("tgt"), board, local_decls, counter, m4)
                if why:
                    stats["xperm: " + why] += 1
                    continue
                xps = (mx.group("xps") or mx.group("xps1") or "").split()
                if not xps or any(not re.fullmatch(r"0x[0-9a-fA-F]+", x) for x in xps):
                    stats["xperm: 命令号形态不合"] += 1
                    continue
                body, why = _na_xperm_expr(xps, mx.group("tilde") is not None, stats)
                if why:
                    stats["xperm: " + why] += 1
                    continue
                op = mx.group("op")
                lines = [f"(neverallowx {src} {tgt} ({op} {cls} (({body}))))"
                         for cls in cls_names]
            fresh = [ln for ln in lines if ln not in seen]
            if not fresh:
                stats["重复（已去重）"] += 1
                continue
            seen.update(fresh)
            decls.extend(local_decls)
            emitted.extend(fresh)
    return decls + emitted, dict(stats)


def compile_and_verify(board_cil: Path, fragment: Path, orig_policy: Path,
                       out_dir: Path, ohos_src: Path,
                       neverallow: list[str] | None = None) -> dict:
    selinux_src = ohos_src / "third_party" / "selinux"
    secilc = selinux_src / "secilc" / "secilc"
    checkpolicy = selinux_src / "checkpolicy" / "checkpolicy"

    res: dict = {"ok": False}
    for tool in (secilc, checkpolicy):
        if not tool.exists():
            res["error"] = f"缺宿主工具: {tool}（可用 OHOS_SRC 环境变量覆盖）"
            return res

    out_dir.mkdir(parents=True, exist_ok=True)
    patched = out_dir / "patched.cil"
    # Red lines go in *with* the patch, ahead of secilc, so a collision is caught
    # by the compiler rather than by a query against an index that may itself be
    # missing the assertion. They live only in this file: a neverallow is checked
    # at compile time and leaves nothing in policy.31, so the round-trip diff
    # below (orig vs verify) is unaffected.
    redlines = list(neverallow or [])
    res["neverallow_injected"] = count_assertions(redlines)
    res["neverallow_decls"] = len(redlines) - res["neverallow_injected"]
    patched.write_text(
        board_cil.read_text(encoding="utf-8", errors="replace")
        + "\n"
        + fragment.read_text(encoding="utf-8")
        + ("\n" + "\n".join(redlines) + "\n" if redlines else ""),
        encoding="utf-8",
    )
    res["patched_lines"] = len(patched.read_text(encoding="utf-8").splitlines())

    # 门 4：编译
    # `-f` 必须显式给：secilc 默认把 file_contexts 写到**当前工作目录**，
    # 不加就会在仓库根留下一个 0 字节的 file_contexts（实测踩过）。
    # 它只是文本副产品，策略内容不受影响，所以落进产物目录即可。
    new_policy = out_dir / "policy.31"
    cp = _run([str(secilc), "-M", "true", "-c", str(POLICYVERS),
               "-f", str(out_dir / "file_contexts"),
               "-o", str(new_policy), str(patched)])
    if cp.returncode != 0:
        res["secilc_stderr"] = cp.stderr[-4000:]
        if "neverallow" in cp.stderr:
            # The whole point of injecting the assertions: this is the one gate
            # that can say "the patch crosses a red line", and it says it with
            # the compiler's own attribute closure rather than the index's.
            res["error"] = ("补丁撞 neverallow 红线（由 secilc 判定，非索引查询）"
                            if redlines else "secilc 编译失败")
            res["redline_violation"] = True
        else:
            res["error"] = "secilc 编译失败"
        return res
    res["compiled"] = True
    res["policy_bytes"] = new_policy.stat().st_size

    # 头部必须与原版一致（magic / policyvers）
    a = orig_policy.read_bytes()[:32]
    b = new_policy.read_bytes()[:32]
    if a[:20] != b[:20]:
        res["error"] = f"头部不一致: {a[:20].hex()} vs {b[:20].hex()}"
        return res
    res["policyvers"] = int.from_bytes(b[16:20], "little")

    # 门 5：回验 —— 反编译回来做语义 diff
    verify_cil = out_dir / "verify.cil"
    orig_cil = out_dir / "orig.cil"
    _run([str(checkpolicy), "-b", "-C", "-M", "-o", str(verify_cil), str(new_policy)])
    _run([str(checkpolicy), "-b", "-C", "-M", "-o", str(orig_cil), str(orig_policy)])
    if not verify_cil.exists():
        res["error"] = "checkpolicy 反编译失败（回验做不了）"
        return res

    va = set(orig_cil.read_text(encoding="utf-8", errors="replace").splitlines())
    vb = [l for l in verify_cil.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    added = [l for l in vb if l not in va]
    removed = [l for l in va if l.strip() and l not in set(vb)]

    # ★ "某行不见了"不等于"权限丢了"。checkpolicy 反编译时会把同一
    #   (src,tgt,类) 的授权归并成一行，于是原版那行字面串消失、内容被并进新行。
    #   实测：不做任何补丁的纯往返是 190 处移除（全是 neverallow 残留死属性）；
    #   加了补丁后多出的 9 处里 8 处是这种归并、1 处是 xperm 区间合并。
    #   所以判据是**权限有没有被吸收**，不是行还在不在。
    vtext = "\n".join(vb)
    vmap: dict[tuple[str, str, str], set[str]] = collections.defaultdict(set)
    for s, t, c, p in re.findall(r"^\(allow (\S+) (\S+) \((\S+) \(([^)]*)\)\)\)", vtext, re.M):
        vmap[(s, t, c)].update(p.split())
        if t == "self":                 # 反编译会把 `A A` 归一成 `A self`，两种写法都要认
            vmap[(s, s, c)].update(p.split())
    vxmap: dict[tuple[str, str, str], list[tuple[int, int]]] = collections.defaultdict(list)
    for s, t, c, e in re.findall(r"^\(allowx (\S+) (\S+) \(ioctl (\S+) \((.*)\)\)\)\s*$", vtext, re.M):
        vxmap[(s, t, c)].extend(_xperm_intervals(e))
        if t == "self":
            vxmap[(s, s, c)].extend(_xperm_intervals(e))

    def _lost(line: str) -> str | None:
        """返回丢失内容的描述；None 表示这条是被安全吸收了。"""
        if re.match(r"^\((typeattribute|typeattributeset) [A-Za-z0-9_]+", line):
            return None                      # neverallow 残留死属性，往返的正常行为
        m = re.match(r"^\(allow (\S+) (\S+) \((\S+) \(([^)]*)\)\)\)$", line)
        if m:
            s, t, c, p = m.groups()
            gone = set(p.split()) - vmap.get((s, t, c), set())
            return f"丢权限 {sorted(gone)}" if gone else None
        m = re.match(r"^\(allowx (\S+) (\S+) \(ioctl (\S+) \((.*)\)\)\)\s*$", line)
        if m:
            s, t, c, e = m.groups()
            ivals = vxmap.get((s, t, c), [])
            # 区间必须整体被覆盖才算没丢
            gone = [(hex(lo), hex(hi)) for lo, hi in _xperm_intervals(e)
                    if not all(_xperm_covered(ivals, v) for v in range(lo, hi + 1))]
            return f"丢 xperm 区间 {gone}" if gone else None
        return "无法归类的移除" if line.startswith("(allow") else None

    bad_removed = [(l, r) for l in removed if (r := _lost(l)) is not None]
    res["added"] = len(added)
    res["removed"] = len(removed)
    res["removed_all_absorbed"] = not bad_removed
    res["unexpected_removed"] = [f"{r} | {l[:100]}" for l, r in bad_removed[:10]]
    res["added_sample"] = added[:10]

    if bad_removed:
        res["error"] = (f"{len(bad_removed)} 条移除不是『被合并吸收』而是真丢了内容，不要安装")
        return res

    # 逐条确认补丁真的进了二进制。
    # ★ 不能做字面串比较：round-trip 会把 `A A` 写成 `A self`、把同一 (src,tgt,类) 的
    #   多条授权并成一行、把 xperm 值并进一个表达式。所以判据与"移除分析"统一为
    #   **内容是否被覆盖**（权限子集 / xperm 值落在区间内），而不是"那行字还在不在"。
    missing = []
    for line in fragment.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        lost = _lost(line)
        if lost is not None:
            missing.append(f"{line}  -> {lost}")
    res["unverified"] = missing
    res["ok"] = not missing
    res["verify_cil"] = str(verify_cil)
    res["policy_31"] = str(new_policy)
    return res


# --------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="converge 报告 → 板子策略补丁 → policy.31 的落地桥")
    ap.add_argument("--report", default="data/reports/converge-full.json",
                    help="converge 的 JSON 报告（取 auto_patch_lines）")
    ap.add_argument("--board-cil", default=str(DEFAULT_BOARD_FP / "board-policy.cil"),
                    help="板子原策略 CIL（默认 $BOARD_FP/board-policy.cil）")
    ap.add_argument("--orig-policy", default=str(DEFAULT_BOARD_FP / "policy.31"),
                    help="板子原 policy.31（用于头部比对与回验基线）")
    ap.add_argument("--out-cil", default="device/selinux_policy/converge-patch.cil",
                    help="CIL 片段落点")
    ap.add_argument("--out-report", default="data/reports/converge-apply.json",
                    help="判定报告落点")
    ap.add_argument("--out-dir", default="device/selinux_policy/out-converge",
                    help="编译产物目录")
    ap.add_argument("--ohos-src", default=str(DEFAULT_OHOS_SRC),
                    help="OH 源码树（提供 secilc / checkpolicy，默认 $OHOS_SRC）")
    ap.add_argument("--no-build", action="store_true",
                    help="只判定 + 出 CIL 片段，不编译（不需要宿主工具链）")
    ap.add_argument("--neverallow-src", default=os.environ.get("SEPOLICY_SRC", ""),
                    help="板子对应版本的 sepolicy 源树；把其中的 neverallow 断言"
                         "注入编译，让门 4 真的能拦越权（默认 $SEPOLICY_SRC，"
                         "或自动取 $BOARD_FP/selinux_adapter-*/sepolicy）")
    args = ap.parse_args(argv)

    report_path = REPO / args.report if not Path(args.report).is_absolute() else Path(args.report)
    board_cil = Path(args.board_cil)
    if not report_path.exists():
        print(f"缺报告: {report_path}", file=sys.stderr)
        return 2
    if not board_cil.exists():
        print(f"缺板子策略: {board_cil}（用 --board-cil 或 BOARD_FP 指定）", file=sys.stderr)
        return 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    lines = report.get("auto_patch_lines") or []
    board = Board(board_cil.read_text(encoding="utf-8", errors="replace"), board_cil)

    print(f"[apply_converge] 报告   {report_path}")
    print(f"[apply_converge] 板子   {board_cil}")
    print(f"                 板子策略: {len(board.types)} types + {len(board.attrs)} attrs, "
          f"{len(board.classes)} classes, {len(board.allows)} 条已有 allow")
    print(f"[apply_converge] 输入补丁 {len(lines)} 行")

    # Red lines first: the fragment header has to state whether gate 4 is a real
    # red-line gate for this run, and `--no-build` still reports the count.
    na_src = Path(args.neverallow_src) if args.neverallow_src else None
    if na_src is None:
        found = sorted(DEFAULT_BOARD_FP.glob("selinux_adapter-*/sepolicy"))
        na_src = found[0] if found else None
    redlines: list[str] = []
    na_stats: dict = {}
    if na_src is not None and na_src.is_dir():
        redlines, na_stats = collect_neverallow(na_src, board)
        n_na = count_assertions(redlines)
        print(f"[apply_converge] 红线   {na_src}")
        print(f"                 可注入 neverallow {n_na} 条断言"
              f"（+{len(redlines) - n_na} 行合成属性声明；"
              f"源树里的形态无法直译的已跳过: "
              f"{', '.join(f'{k} {v}' for k, v in sorted(na_stats.items())) or '无'}）")
    else:
        print("[apply_converge] 红线   ⚠️ 未提供 sepolicy 源树（--neverallow-src / "
              "$SEPOLICY_SRC）⇒ 门 4 只验证可编译性，不构成 neverallow 防线")

    rules = gate_parse(lines)
    rules = gate_symbols(rules, board)
    rules = gate_perms(rules, board)
    rules = gate_idempotent(rules, board)

    by_verdict = collections.Counter(r["verdict"] for r in rules)
    emitted = [r for r in rules if r["verdict"] == "emit"]
    fragment_text = render_cil(rules)

    HEADER = (
        ";; PolicyLoop converge 补丁片段 —— 由 tools/apply_converge.py 生成，请勿手改\n"
        f";; 来源报告: {args.report}\n"
        f";; 基线策略: {board_cil}\n"
        f";; 输入 {len(lines)} 行 → 注入 {len(emitted)} 行\n"
        ";;\n"
        + (f";; 门 4 已注入 {count_assertions(redlines)} 条源树 neverallow 断言：secilc 编译通过\n"
           ";;    同时意味着这批补丁没有越过这些红线（编译器判定，含属性闭包与 xperm 区间）。\n"
           + (f";;    ⚠️ 覆盖非全量：源树里另有 {sum(na_stats.values())} 条语句未能注入"
              f"（{', '.join(f'{k} {v}' for k, v in sorted(na_stats.items()))}），\n"
              ";;       这部分红线由 converge 索引兜底，不在本次编译检查范围内。\n"
              if na_stats else "")
           if redlines else
           ";; ⚠️ 板子策略里没有 neverallow（编译期断言，不落盘），本次也未能注入源树\n"
           ";;    断言 ⇒ secilc 编译通过**不代表**没撞 neverallow。\n")
        + ";;    剩余防线仍由 converge 的索引提供（neverallow 一律转人工）。\n"
    )
    out_cil = REPO / args.out_cil if not Path(args.out_cil).is_absolute() else Path(args.out_cil)
    out_cil.parent.mkdir(parents=True, exist_ok=True)
    out_cil.write_text(HEADER + fragment_text, encoding="utf-8")

    print("\n--- 六道门 ---")
    print(f"  输入 {len(lines)} 行 → 注入 {by_verdict.get('emit', 0)}"
          f" / 板上已满足 {by_verdict.get('already_satisfied', 0)}"
          f" / 拒 {by_verdict.get('rejected', 0)}")
    for gate, n in collections.Counter(
            r["gate"] for r in rules if r["verdict"] == "rejected").most_common():
        print(f"     拒于「{gate}」门: {n} 行")
    for r in rules:
        if r["verdict"] == "rejected":
            print(f"    ✗ {r['line']}\n        {r['reason']}")

    print(f"\n--- CIL 片段 → {_shown(out_cil)} ({len(emitted)} 行) ---")
    for l in fragment_text.splitlines()[:8]:
        print("   ", l)
    if len(emitted) > 8:
        print(f"    ... 另 {len(emitted) - 8} 行")

    result = {
        "source_report": str(report_path),
        "board_cil": str(board_cil),
        "input_lines": len(lines),
        "by_verdict": dict(by_verdict),
        "emitted": [r["line"] for r in emitted],
        "rejected": [{"line": r["line"], "gate": r["gate"], "reason": r["reason"]}
                     for r in rules if r["verdict"] == "rejected"],
        "already_satisfied": [r["line"] for r in rules if r["verdict"] == "already_satisfied"],
        "board_stats": {"types": len(board.types), "attrs": len(board.attrs),
                        "classes": len(board.classes), "allow_rules": len(board.allows),
                        "neverallow_rules": 0},
        "neverallow_note": (
            "板子策略由 policy.31 反编译而来，二进制策略不含 neverallow。"
            "本工具把板子对应版本源树里的 neverallow 断言注入待编译的 CIL，"
            "使门 4 由 secilc 真正执行红线检查（含属性闭包与 xperm 区间）；"
            "无法直译的形态（源列表/通配/取反/宏）按 na_stats 计数跳过，"
            "这部分仍只由 converge 索引覆盖。"
        ),
        "neverallow_injected": count_assertions(redlines),
        "neverallow_src": str(na_src) if na_src else "",
        "neverallow_skipped_by_shape": na_stats,
        "fragment": str(out_cil),
    }

    if args.no_build:
        result["build"] = {"ok": None, "skipped": "--no-build"}
        print("\n（--no-build：跳过编译。加不加 --no-build 之外无需其他参数即可编译）")
    else:
        print("\n--- 门 4/5：编译与回验 ---")
        build = compile_and_verify(
            board_cil, out_cil, Path(args.orig_policy),
            REPO / args.out_dir if not Path(args.out_dir).is_absolute() else Path(args.out_dir),
            Path(args.ohos_src), redlines,
        )
        result["build"] = build
        if build.get("error"):
            print(f"  ✗ {build['error']}")
            if build.get("secilc_stderr"):
                # secilc's last line is always "Failed to build policydb"; the
                # line that names the red line and the offending allow is the
                # one worth showing.
                err = build["secilc_stderr"].strip().splitlines()
                if build.get("redline_violation"):
                    hits = [l.strip() for l in err if "neverallow" in l or "allow at " in l]
                    for l in (hits or err[-1:])[:6]:
                        print("  secilc:", l[:200])
                else:
                    print("  secilc:", err[-1][:200])
        else:
            print(f"  ✓ secilc 编译通过  policy.31 = {build['policy_bytes']} B "
                  f"(policyvers={build['policyvers']})")
            if build.get("neverallow_injected"):
                print(f"  ✓ 同时通过 {build['neverallow_injected']} 条 neverallow 断言"
                      "（编译器判定的红线检查，非索引查询）")
            else:
                print("  ⚠️ 未注入 neverallow 断言 ⇒ 本次编译不构成红线检查")
            print(f"  ✓ 语义 diff: 新增 {build['added']} 行 / 移除 {build['removed']} 行"
                  f"（预期外移除 {len(build['unexpected_removed'])} 条）")
            if build.get("unverified"):
                print(f"  ✗ 回验未找到 {len(build['unverified'])} 条注入规则:")
                for l in build["unverified"][:5]:
                    print("     ", l)
            else:
                print(f"  ✓ {len(emitted)} 条注入规则全部在二进制里回验到")
            print(f"\n  产物: {build.get('policy_31')}")
            print("  下一步（会改设备状态，本工具不代劳）:")
            print("     bash device/selinux_policy/install_to_board.sh")

    out_report = REPO / args.out_report if not Path(args.out_report).is_absolute() else Path(args.out_report)
    out_report.parent.mkdir(parents=True, exist_ok=True)
    out_report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")

    # 片段头里那句"secilc 编译通过"是**编译前**写的（编译要等到这一刻才知道结果）。
    # 编译失败时它就成了假话 —— 而片段是会被拷进策略树、被人单独阅读的东西，
    # 一句"通过"足以让人以为撞红线的补丁是干净的。所以编译后回过头来纠正。
    b = result["build"]
    out_cil.write_text(
        out_cil.read_text(encoding="utf-8").replace(
            ";; 输入", _gate4_verdict(b.get("ok")) + "\n;; 输入", 1),
        encoding="utf-8")

    print(f"\n[apply_converge] 判定报告 → {_shown(out_report)}")
    if result["build"].get("ok") is False:   # 显式失败才算失败；未编译(None)不是失败
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
