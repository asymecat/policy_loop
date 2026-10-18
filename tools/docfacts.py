#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DocGate 探针：从真实产物里取「当前真值」，供 ``tools/docgate.py`` 比对。

设计要点
--------
* **绝不 exec/import 被检查的脚本。** ``docs/figs/make_figs.py`` 一 import 就会
  ``os.makedirs`` 并写出四张 PNG（还得有 Pillow）。一律 ``ast.parse`` 读源码里
  真正会被画上去的那个字符串字面量。
* **真值一律靠派生，不靠手写常量。** 守门分支数由 AST 数 ``return`` 语句得出，
  Agent 数由 ``_PIPELINE`` 元组长得出。在引擎里手写一个 ``GUARD_COUNT = 6``
  等于把权威从「代码实际有几个分支」挪到一个整数上 —— 那正是本次事故
  （配图与代码不符、5 天没人发现）的成因。
* 探针只有三种结局：拿到值 / ``ProbeError``（**真失败**，门禁 exit 1）/
  ``ProbeUnavailable``（**环境不满足**，门禁记 SKIP 并出声）。
  「证明不了这句话了」属于第一种，绝不能悄悄记成 SKIP。

零第三方依赖（只用 stdlib）。
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]

CORPUS = ROOT / "data" / "raw" / "oh-selinux" / "sepolicy"


class ProbeError(RuntimeError):
    """探针坏了 / 真值变了 —— 门禁按**真失败**处理（exit 1）。"""


class ProbeUnavailable(RuntimeError):
    """环境不满足（语料没拉、解释器不合）—— 门禁记 SKIP 并出声。"""


class Unit(NamedTuple):
    """一个「可定位的文本单元」：Python 里是一个字符串字面量，md 里是一行。"""

    file: str          # 仓库相对路径
    lineno: int        # 起始行（隐式拼接的 Constant 取首行）
    text: str


# --------------------------------------------------------------------------- #
# 取文本单元
# --------------------------------------------------------------------------- #

def py_units(path: Path, rel: str) -> tuple[list[Unit], int]:
    """Python 源码里的字符串字面量（含 docstring）。

    返回 ``(units, joined_str_count)``：f-string 是 ``JoinedStr``，它的静态片段
    无法当作「一句话」来比对，跳过并**计数**，好让调用方出声说明漏了什么。

    隐式拼接（``"a" "b"``）会被 CPython 折成**一个** ``Constant``，
    ``lineno`` 取首行 —— 于是一条跨行的 caption 正好成为一个可定位单元。
    """
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:  # 源码都读不了，门禁必须红
        raise ProbeError(f"{rel} 解析失败：{exc}") from exc

    units: list[Unit] = []
    joined = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            joined += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            units.append(Unit(rel, node.lineno, node.value))
    return units, joined


_MD_FENCE = re.compile(r"^\s*(```|~~~)")


def md_units(path: Path, rel: str) -> tuple[list[Unit], int]:
    """Markdown 按行切成单元；代码围栏内的行也保留（报告里确有 ``` 块）。

    第二项恒为 0，只为与 :func:`py_units` 同形。
    """
    units: list[Unit] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        units.append(Unit(rel, i, line))
    return units, 0


def units_for(path: Path, rel: str) -> tuple[list[Unit], int]:
    if path.suffix == ".py":
        return py_units(path, rel)
    return md_units(path, rel)


# --------------------------------------------------------------------------- #
# 数字归一化：白名单内允许的唯一模糊度
# --------------------------------------------------------------------------- #

_CN_DIGITS = {"零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4,
              "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_EN_WORDS = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
             "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def cn_to_int(text: str) -> int | None:
    """中文数词 → int。覆盖 零…十、十一…十九、二十…九十九、两。

    刻意**不**做四舍五入、不认「几」「数」这类模糊词 —— 白名单之外宁可取不到值
    （报错），也不要把两句话比成相等。
    """
    text = text.strip()
    if not text:
        return None
    if text == "十":
        return 10
    if "十" in text:
        head, _, tail = text.partition("十")
        tens = _CN_DIGITS.get(head, 1) if head else 1
        ones = _CN_DIGITS.get(tail, 0) if tail else 0
        if head and head not in _CN_DIGITS:
            return None
        if tail and tail not in _CN_DIGITS:
            return None
        return tens * 10 + ones
    if len(text) == 1 and text in _CN_DIGITS:
        return _CN_DIGITS[text]
    return None


def normalize(raw: str, kind: str):
    """按 ``kind`` 归一化一个抓到的片段。取不到值 → ``None``。"""
    raw = raw.strip()
    if kind == "int_thousands":
        digits = raw.replace(",", "").replace("，", "")
        return int(digits) if digits.isdigit() else None
    if kind == "int":
        return int(raw) if raw.isdigit() else None
    if kind == "cn_or_int":
        return int(raw) if raw.isdigit() else cn_to_int(raw)
    if kind == "num_or_cn_or_en":
        if raw.isdigit():
            return int(raw)
        got = cn_to_int(raw)
        if got is not None:
            return got
        return _EN_WORDS.get(raw.lower())
    if kind == "float":
        try:
            return float(raw)
        except ValueError:
            return None
    if kind == "str":
        return raw
    raise ProbeError(f"未知的归一化类型：{kind}")


def normalize_text(text: str, kind: str):
    """给 fact 的值一侧做同样归一化（facts.json 里也允许写「六」这种词）。"""
    return normalize(str(text), kind)


# --------------------------------------------------------------------------- #
# 探针：活树 / AST 派生
# --------------------------------------------------------------------------- #

def _import_index():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from policy_loop.policy import index as index_mod
    except Exception as exc:  # 包坏了 = 真失败，不是环境问题
        raise ProbeError(f"导入 policy_loop.policy.index 失败：{exc}") from exc
    return index_mod


def probe_index(_cache: dict = {}) -> dict:
    """活树索引实测（本机约 0.2 秒）。语料没拉 → ``ProbeUnavailable``。"""
    if "index" in _cache:
        return _cache["index"]
    if not CORPUS.is_dir():
        raise ProbeUnavailable(
            f"上游语料不在 {CORPUS}（data/raw 不入库，需稀疏克隆）"
        )
    mod = _import_index()
    raw = mod.load_dir(CORPUS).summary()
    compact = {
        "rules": raw["rules"],
        "kinds": raw["kinds"],
        "types": raw["types"],
        "attributes": raw["attributes"],
        "skipped": raw["skipped_statements"],
        # summary() 给的是路径列表；门禁要的是「几个 .te 源」，取长度。
        "sources": len(raw["sources"]),
    }
    _cache["index"] = compact
    return compact


def probe_corpus_rev() -> str:
    """语料树当前 rev（给 manifest 记「冻结于哪棵树」用）。"""
    import subprocess

    if not CORPUS.is_dir():
        raise ProbeUnavailable(f"上游语料不在 {CORPUS}")
    repo = CORPUS
    while repo != repo.parent and not (repo / ".git").exists():
        repo = repo.parent
    if not (repo / ".git").exists():
        raise ProbeUnavailable("语料不是 git 工作树，取不到 rev")
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise ProbeError(f"git rev-parse 失败：{out.stderr.strip()}")
    return out.stdout.strip()


def _func_node(path: Path, rel: str, name: str) -> ast.FunctionDef:
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        raise ProbeError(f"{rel} 解析失败：{exc}") from exc
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise ProbeError(f"{rel} 里找不到函数 {name}() —— 改名了还是挪走了？")


def probe_guards_py_branches(root: Path = ROOT) -> int:
    """``converge.apply_guards`` 里**返回非 None** 的分支数。

    判据是「return 一个具体理由」，不是「有几个 if」—— 尾部的 ``return None``
    是"没有守门触发"，不是一道守门。
    """
    rel = "policy_loop/converge.py"
    node = _func_node(root / rel, rel, "apply_guards")
    count = 0
    for sub in ast.walk(node):
        if isinstance(sub, ast.Return) and sub.value is not None:
            if isinstance(sub.value, ast.Constant) and sub.value.value is None:
                continue
            count += 1
    if count == 0:
        raise ProbeError("apply_guards 里数出 0 个返回理由的分支 —— 探针坏了")
    return count


def probe_pipeline_agents(root: Path = ROOT) -> int:
    """``_PIPELINE`` 元组的长度（Agent 花名册的唯一真源）。"""
    rel = "policy_loop/agents/orchestrator.py"
    src = (root / rel).read_text(encoding="utf-8")
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError as exc:
        raise ProbeError(f"{rel} 解析失败：{exc}") from exc
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        if not targets:
            continue
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if "_PIPELINE" in names:
            try:
                value = ast.literal_eval(node.value)
            except ValueError as exc:
                raise ProbeError(f"_PIPELINE 不是字面量元组：{exc}") from exc
            return len(value)
    raise ProbeError(f"{rel} 里找不到 _PIPELINE —— 改名了？")


DEV_CPP = ROOT / "device" / "selinux_adapter" / "framework" / "policycoreutils" / "src" / "pl_converge.cpp"


def cpp_guards_body(path: Path | None = None) -> str:
    """取出 C++ ``ApplyGuards`` 的函数体（花括号配对，注释剥掉）。"""
    path = path or DEV_CPP
    if not path.is_file():
        raise ProbeUnavailable(f"设备端源码不在 {path}")
    text = path.read_text(encoding="utf-8")
    try:
        anchor = text.index("void ApplyGuards(")
    except ValueError as exc:
        raise ProbeError(f"{path} 里找不到 void ApplyGuards( —— 改名了？") from exc
    open_brace = text.index("{", anchor)
    depth, i = 0, open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if i >= len(text):
        raise ProbeError("ApplyGuards 的 { 没有配对的 } —— 文件结构变了？")
    body = text[open_brace + 1:i]
    body = re.sub(r"//[^\n]*", "", body)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return body


def func_string_literals(root: Path, rel: str, name: str) -> list[str]:
    """函数体里（**不含 docstring**）的全部字符串字面量。

    docstring 是在解释"为什么有这几道守门"，不是在写理由本身；把它算进来会让
    「两侧各出现一次」这种判据失去意义。
    """
    node = _func_node(root / rel, rel, name)
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr):
        first = body[0].value
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            body = body[1:]
    out: list[str] = []
    for stmt in body:
        _collect_strings(stmt, out)
    return out


def _collect_strings(node: ast.AST, out: list[str]) -> None:
    """递归收字符串。碰到 ``JoinedStr`` 就只取它的静态片段并**停止下潜** ——
    否则 ``ast.walk`` 会在收完片段之后再走一遍那些 Constant，同一句话数两次。
    """
    if isinstance(node, ast.JoinedStr):
        out.extend(p.value for p in node.values
                   if isinstance(p, ast.Constant) and isinstance(p.value, str))
        return
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
        return
    for child in ast.iter_child_nodes(node):
        _collect_strings(child, out)


_CPP_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')


def cpp_string_literals(path: Path | None = None) -> list[str]:
    """C++ ``ApplyGuards`` 函数体里的字符串字面量（注释已剥掉）。"""
    return _CPP_STR.findall(cpp_guards_body(path))


def probe_guards_cpp_branches(path: Path | None = None) -> int:
    """C++ ``ApplyGuards`` 里给 ``why`` 赋值的分支数。

    尾部那句 ``verdict->why = why;`` 是把结果写回裁决，不是又一道守门 ——
    所以只数**独立**的 ``why =``，排除 ``->why`` / ``.why``。
    """
    body = cpp_guards_body(path)
    count = len(re.findall(r"(?<![-.>\w])why\s*=", body))
    if count == 0:
        raise ProbeError("ApplyGuards 里数出 0 个 why= 分支 —— 探针坏了")
    return count
