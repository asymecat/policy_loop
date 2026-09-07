"""avc 文本解析核心。

策略: 固定格式头(denied/granted + 权限组)用一个小正则锚定;
头之后的尾巴全是 key=value,用通用扫描器吃 —— 新字段(ioctlcmd/capability/...)
进来永远不用改解析代码。
"""
from __future__ import annotations

import re

from .model import AvcRecord
from .contexts import context_type  # noqa: F401  (re-export 便利)

_HEAD_RE = re.compile(r"\bavc:\s*(denied|granted)\s*\{\s*([^}]*)\}", re.S)
_AUDIT_RE = re.compile(r"audit\(([\d.]+):(\d+)\)")

# 已知、但非 obj 细节字段: 进 extras(类型化字段在 parse 里单独落)
_KNOWN_NON_OBJ = {"scontext", "tcontext", "tclass", "permissive",
                  "pid", "comm", "scontext2", "tcontext2", "tclass2"}


def _scan_kv(s: str) -> dict:
    """通用 key=value 扫描。值带引号读到引号闭合(comm=\"a b\"),否则读到空白。"""
    out, i, n = {}, 0, len(s)
    while i < n:
        if not (s[i].isalpha() or s[i] == "_"):
            i += 1
            continue
        j = i
        while j < n and (s[j].isalnum() or s[j] == "_"):
            j += 1
        key = s[i:j]
        if j >= n or s[j] != "=":
            i = j
            continue
        j += 1
        if j < n and s[j] == '"':                      # 引号值
            j += 1
            buf = []
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j + 1])
                    j += 2
                else:
                    buf.append(s[j])
                    j += 1
            val = "".join(buf)
            j += 1  # 跳过闭合引号
        else:                                          # 无引号值(scontext 等)
            k = j
            while j < n and not s[j].isspace():
                j += 1
            val = s[k:j]
        out[key] = val
        i = j
    return out


def parse_record(text: str) -> AvcRecord:
    """解析一条(已隔离的)avc 记录。噪音/畸形行不抛异常,返回 parse_ok=False。"""
    r = AvcRecord(raw=text)
    m = _HEAD_RE.search(text)
    if not m:
        r.parse_ok, r.error = False, "not an avc denied/granted line"
        return r

    r.verdict = m.group(1)
    r.perms = m.group(2).split()
    kv = _scan_kv(text[m.end():])

    r.scontext = kv.get("scontext", "")
    r.tcontext = kv.get("tcontext", "")
    r.tclass = kv.get("tclass", "")
    if "permissive" in kv and kv["permissive"] in ("0", "1"):
        r.permissive = int(kv["permissive"])
    if "pid" in kv and kv["pid"].isdigit():
        r.pid = int(kv["pid"])
    r.comm = kv.get("comm", "")

    for k in ("name", "dev", "path", "exe"):
        if k in kv:
            r.obj[k] = kv[k]
    if "ino" in kv and kv["ino"].isdigit():
        r.obj["ino"] = int(kv["ino"])

    # 其余未知 key -> extras
    for k, v in kv.items():
        if k not in _KNOWN_NON_OBJ and k not in ("name", "dev", "ino", "path", "exe"):
            if k == "ino" or not v:
                continue
            r.extras[k] = v

    ma = _AUDIT_RE.search(text)
    if ma:
        r.ts = float(ma.group(1))
        r.audit_serial = int(ma.group(2))

    missing = [k for k in ("scontext", "tcontext", "tclass") if not getattr(r, k)]
    if missing or not r.perms or r.verdict not in ("denied", "granted"):
        r.parse_ok = False
        r.error = "missing/odd fields: " + ",".join(missing) if missing else "no perms"
    return r


def _record_open(cur: str) -> bool:
    """该条还没拿到 scontext = 尚未完整,后续缩进行应并入它。"""
    return "scontext=" not in cur


def iter_records(text: str):
    """把一段 dmesg/logcat 切成多条逻辑 avc 记录。

    规则:
      - 含 'avc: denied/granted' 的行 -> 新记录起点(并 flush 上一条)
      - 以空白开头且当前记录未闭合的缩进行 -> 续行,并入当前记录
      - 其余非空行(噪音/日志/换行导致的错位)-> flush 当前并丢弃
    建议调用方先只喂含 'avc:' 的行段,效果最稳。
    """
    cur = None
    for ln in text.splitlines():
        if not ln.strip():
            if cur is not None:
                yield cur
                cur = None
            continue
        if _HEAD_RE.search(ln):
            if cur is not None:
                yield cur
            cur = ln
        elif ln[0].isspace() and cur is not None and _record_open(cur) and "=" in ln:
            cur += " " + ln.strip()
        else:
            if cur is not None:
                yield cur
                cur = None
    if cur is not None:
        yield cur
