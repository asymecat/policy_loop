"""A queryable view of a device's *actual* policy, decompiled to CIL.

Everything else in :mod:`policy_loop` reads the upstream ``.te`` tree -- the
policy as *written*.  This reads ``policy.31`` as decompiled by ``checkpolicy
-b -M -C`` -- the policy as the kernel *runs* it.  The two differ, and every
interesting question about a running device is a question about the second one:

* a patch is only meaningful if the board has the symbols it names;
* a denial is only a gap if the board does not already grant the access;
* "the tree allows it but the device denied it" is a falsifiable claim, and
  only this view can falsify it.

The loaders are the ones :mod:`tools.apply_converge` has used as its gate-4
ground truth since 10-07; this module is their canonical home so the gate and
the analysis tools share one parser instead of two that drift.

CIL gotchas this encodes, each of which cost a debugging session:

* ``allowxperm`` does not exist in CIL -- it is ``(allowx ...)``.  Searching
  for the ``.te`` spelling finds 0 of the board's 714 xperm rules.
* ``(typeattributeset A (B C))`` states *membership*; ``(typeattribute A)``
  only declares the attribute.  Authorization routinely flows through the
  former, so a query has to expand attributes transitively on **both** sides.
* ``:permissive`` domains are ``(typepermissive X)``, and a domain in that
  state cannot produce an enforcing denial at all.
"""

from __future__ import annotations

import collections
import re
from pathlib import Path

_RE_TYPE = re.compile(r"^\(type ([A-Za-z0-9_.\-]+)\)", re.M)
_RE_ATTR = re.compile(r"^\(typeattribute ([A-Za-z0-9_.\-]+)\)", re.M)
_RE_CLASS = re.compile(r"^\(class ([A-Za-z0-9_.\-]+) ", re.M)
_RE_ATTRSET = re.compile(r"^\(typeattributeset ([A-Za-z0-9_.\-]+) \((.*?)\)\)\s*$", re.M)
_RE_ALLOW = re.compile(r"^\(allow (\S+) (\S+) \((\S+) \(([^)]*)\)\)\)", re.M)
_RE_COMMON = re.compile(r"^\(common (\S+) \(([^)]*)\)\)", re.M)
_RE_CLASSCOMMON = re.compile(r"^\(classcommon (\S+) (\S+)\)", re.M)
_RE_PERMISSIVE = re.compile(r"^\(typepermissive (\S+)\)", re.M)

#   (allowx src tgt (ioctl (0x5413)))              单个
#   (allowx src tgt (ioctl (0xf50c (range 0xf546 0xf547))))   区间
#   (allowx src tgt (ioctl ((0xa (range 0xb 0xc))))          CIL 归一化后的混排
#   ((0xf50c (range 0xf546 0xf547)))               多个混排
# 板子实测 522/714 是"单个"、其余是各种区间混排。要判"某值是否已被覆盖"
# 就必须把区间摊平，光做字符串比较会漏掉藏在 range 里的值。
_RE_XPERM_RANGE = re.compile(r"\(range (0x[0-9a-fA-F]+) (0x[0-9a-fA-F]+)\)")
_RE_XPERM_HEX = re.compile(r"0x[0-9a-fA-F]+")


def xperm_intervals(expr: str) -> list:
    """把 CIL 的 xperm 表达式文本摊平成 [(lo, hi), ...] 区间。"""
    ivals = [(int(a, 16), int(b, 16)) for a, b in _RE_XPERM_RANGE.findall(expr)]
    if "(all)" in expr:
        ivals.append((0, 0xFFFFFFFF))
    bare = _RE_XPERM_RANGE.sub(" ", expr)   # 先摘掉 range，免得端点被当单值重复计入
    ivals += [(int(a, 16), int(a, 16)) for a in _RE_XPERM_HEX.findall(bare)]
    return ivals


def xperm_covered(intervals: list, value: int) -> bool:
    return any(lo <= value <= hi for lo, hi in intervals)


class Board:
    """板子 CIL 的可查询视图：有哪些符号、已允许了什么。"""

    def __init__(self, text: str, path: Path = Path("<cil>")):
        self.path = path
        self.classes = set(_RE_CLASS.findall(text))
        self.types = set(_RE_TYPE.findall(text))
        self.attrs = set(_RE_ATTR.findall(text))
        self.symbols = self.types | self.attrs
        # A domain the kernel runs in permissive mode cannot deny anything, so
        # an enforcing denial naming one is evidence the log is not the device's.
        self.permissive_domains = set(_RE_PERMISSIVE.findall(text))

        # 类 → 该类的完整权限集（自有 ∪ 经 classcommon 继承的 common）
        common = {n: set(p.split()) for n, p in _RE_COMMON.findall(text)}
        binding = dict(_RE_CLASSCOMMON.findall(text))
        self.class_perms = {
            c: set(perms.split()) | common.get(binding.get(c), set())
            for c, perms in re.findall(r"^\(class (\S+) \(([^)]*)\)\)", text, re.M)
        }

        # 属性闭包：n → n 所属的全部属性（含传递）
        members: dict = collections.defaultdict(set)
        for attr, body in _RE_ATTRSET.findall(text):
            members[attr].update(body.split())

        self._closure_cache: dict = {}

        def closure(n: str) -> frozenset:
            got = self._closure_cache.get(n)
            if got is not None:
                return got
            seen: set = set()
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
        self.allows: dict = collections.defaultdict(set)
        for src, tgt, cls, perms in _RE_ALLOW.findall(text):
            self.allows[(src, tgt, cls)].update(perms.split())

        # 已有 xperm：(src, tgt, cls) → 覆盖到的 ioctl 号区间
        # ★ 必须按 `(allowx ...)` 找。按 `allowxperm` 找会得 0 条 ——
        #   `allowxperm` 是 .te/conf 的写法，CIL 里根本不存在这个词。
        self.xperms: dict = collections.defaultdict(list)
        for src, tgt, cls, expr in re.findall(
            r"^\(allowx (\S+) (\S+) \(ioctl (\S+) \((.*)\)\)\)\s*$", text, re.M
        ):
            self.xperms[(src, tgt, cls)].extend(xperm_intervals(expr))

    # ---- queries ---------------------------------------------------------

    def granted(self, src: str, tgt: str, cls: str) -> set:
        """板上这组 (主体, 目标, 类) 已获授权的权限并集（含属性闭包）。

        ``satisfied`` answers yes/no; this answers *which* permissions are
        there, which is what a partial gap has to report.
        """
        out: set = set()
        for s in self.closure(src):
            for t in self.closure(tgt):
                out |= self.allows.get((s, t, cls), set())
        return out

    def satisfied(self, src: str, tgt: str, cls: str, perms: set) -> bool:
        """板上是否已允许这组权限（含 src/tgt 的属性闭包展开）。"""
        for s in self.closure(src):
            for t in self.closure(tgt):
                if perms <= self.allows.get((s, t, cls), set()):
                    return True
        return False

    def xperm_satisfied(self, src: str, tgt: str, cls: str, xperms: set) -> bool:
        """板上已覆盖这组 ioctl 号吗（区间也算覆盖）。"""
        for s in self.closure(src):
            for t in self.closure(tgt):
                ivals = self.xperms.get((s, t, cls))
                if not ivals:
                    continue
                if all(xperm_covered(ivals, int(x, 16)) for x in xperms):
                    return True
        return False


def load_cil(path) -> Board:
    p = Path(path)
    return Board(p.read_text(encoding="utf-8", errors="replace"), p)
