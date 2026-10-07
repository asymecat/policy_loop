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
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

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


# --------------------------------------------------------------------------
# xperm 表达式
# --------------------------------------------------------------------------
# CIL 把它写成 `(allowx S T (ioctl 类 (表达式)))`，表达式是嵌套的:
#   ((0x5413))                         单个
#   (((range 0x1 0x4)))                区间
#   ((0xf50c (range 0xf546 0xf547)))   多个混排
# 板子实测 522/714 是"单个"、其余是各种区间混排。要判"某值是否已被覆盖"
# 就必须把区间摊平，光做字符串比较会漏掉藏在 range 里的值。
_RE_XPERM_RANGE = re.compile(r"\(range (0x[0-9a-fA-F]+) (0x[0-9a-fA-F]+)\)")
_RE_XPERM_HEX = re.compile(r"0x[0-9a-fA-F]+")


def _xperm_intervals(expr: str) -> list[tuple[int, int]]:
    """把 CIL 的 xperm 表达式文本摊平成 [(lo, hi), ...] 区间。"""
    ivals = [(int(a, 16), int(b, 16)) for a, b in _RE_XPERM_RANGE.findall(expr)]
    if "(all)" in expr:
        ivals.append((0, 0xFFFFFFFF))
    bare = _RE_XPERM_RANGE.sub(" ", expr)          # 先摘掉 range，免得端点被当单值重复计入
    ivals += [(int(a, 16), int(a, 16)) for a in _RE_XPERM_HEX.findall(bare)]
    return ivals


def _xperm_covered(intervals: list[tuple[int, int]], value: int) -> bool:
    return any(lo <= value <= hi for lo, hi in intervals)


# --------------------------------------------------------------------------
# 板子策略
# --------------------------------------------------------------------------
class Board:
    """板子 CIL 的可查询视图：有哪些符号、已允许了什么。"""

    def __init__(self, text: str, path: Path):
        self.path = path
        self.classes = set(_RE_CLASS.findall(text))
        self.types = set(_RE_TYPE.findall(text))
        self.attrs = set(_RE_ATTR.findall(text))
        self.symbols = self.types | self.attrs

        # 类 → 该类的完整权限集（自有 ∪ 经 classcommon 继承的 common）
        common = {n: set(p.split()) for n, p in _RE_COMMON.findall(text)}
        binding = dict(_RE_CLASSCOMMON.findall(text))
        self.class_perms = {
            c: set(perms.split()) | common.get(binding.get(c), set())
            for c, perms in re.findall(r"^\(class (\S+) \(([^)]*)\)\)", text, re.M)
        }

        # 属性闭包：n → n 所属的全部属性（含传递）
        members: dict[str, set[str]] = collections.defaultdict(set)
        for attr, body in _RE_ATTRSET.findall(text):
            members[attr].update(body.split())

        self._closure_cache: dict[str, frozenset[str]] = {}

        def closure(n: str) -> frozenset[str]:
            got = self._closure_cache.get(n)
            if got is not None:
                return got
            seen: set[str] = set()
            stack = [n]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                # 反向：谁把 cur 当成员，谁就是 cur 所属的属性
                for attr, mem in members.items():
                    if cur in mem:
                        stack.append(attr)
            got = frozenset(seen)
            self._closure_cache[n] = got
            return got

        self.closure = closure

        # 已有授权：(src, tgt, cls) → 权限集合
        self.allows: dict[tuple[str, str, str], set[str]] = collections.defaultdict(set)
        for src, tgt, cls, perms in _RE_ALLOW.findall(text):
            self.allows[(src, tgt, cls)].update(perms.split())

        # 已有 xperm：(src, tgt, cls) → 覆盖到的 ioctl 号区间
        # ★ 必须按 `(allowx ...)` 找。按 `allowxperm` 找会得 0 条 ——
        #   `allowxperm` 是 .te/conf 的写法，CIL 里根本不存在这个词。
        #   （板子实测有 714 条 xperm，全写成 allowx。这个坑骗过一次。）
        self.xperms: dict[tuple[str, str, str], list[tuple[int, int]]] = collections.defaultdict(list)
        for src, tgt, cls, expr in re.findall(
            r"^\(allowx (\S+) (\S+) \(ioctl (\S+) \((.*)\)\)\)\s*$", text, re.M
        ):
            self.xperms[(src, tgt, cls)].extend(_xperm_intervals(expr))

    def satisfied(self, src: str, tgt: str, cls: str, perms: set[str]) -> bool:
        """板上是否已允许这组权限（含 src/tgt 的属性闭包展开）。"""
        for s in self.closure(src):
            for t in self.closure(tgt):
                if perms <= self.allows.get((s, t, cls), set()):
                    return True
        return False

    def xperm_satisfied(self, src: str, tgt: str, cls: str, xperms: set[str]) -> bool:
        """板上已覆盖这组 ioctl 号吗（区间也算覆盖）。"""
        for s in self.closure(src):
            for t in self.closure(tgt):
                ivals = self.xperms.get((s, t, cls))
                if not ivals:
                    continue
                if all(_xperm_covered(ivals, int(x, 16)) for x in xperms):
                    return True
        return False


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


def compile_and_verify(board_cil: Path, fragment: Path, orig_policy: Path,
                       out_dir: Path, ohos_src: Path) -> dict:
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
    patched.write_text(
        board_cil.read_text(encoding="utf-8", errors="replace")
        + "\n"
        + fragment.read_text(encoding="utf-8"),
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
        res["error"] = "secilc 编译失败"
        res["secilc_stderr"] = cp.stderr[-4000:]
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
        ";; ⚠️ 板子策略里没有 neverallow（编译期断言，不落盘），所以 secilc 编译通过\n"
        ";;    不代表没撞 neverallow。该防线由 converge 的索引提供（neverallow 一律转人工）。\n"
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

    print(f"\n--- CIL 片段 → {out_cil.relative_to(REPO)} ({len(emitted)} 行) ---")
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
            "板子策略由 policy.31 反编译而来，二进制策略不含 neverallow，"
            "因此 secilc 编译通过不等于未撞 neverallow；该防线由 converge 索引提供。"
        ),
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
            Path(args.ohos_src),
        )
        result["build"] = build
        if build.get("error"):
            print(f"  ✗ {build['error']}")
            if build.get("secilc_stderr"):
                print("  secilc:", build["secilc_stderr"].strip().splitlines()[-1][:200])
        else:
            print(f"  ✓ secilc 编译通过  policy.31 = {build['policy_bytes']} B "
                  f"(policyvers={build['policyvers']})")
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
    print(f"\n[apply_converge] 判定报告 → {out_report.relative_to(REPO)}")
    if result["build"].get("ok") is False:   # 显式失败才算失败；未编译(None)不是失败
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
