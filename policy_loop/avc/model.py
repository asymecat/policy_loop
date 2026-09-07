"""avc 记录的数据模型。

注意: 这些字段名就是对外 JSON 契约,
必须与 golden 集(队友标注的答案)字段完全一致,后续"对答案"自动测试靠它。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .contexts import context_type


@dataclass
class AvcRecord:
    raw: str = ""                       # 原始整行(含前缀/续行)
    parse_ok: bool = True               # 是否解析通过(不通过不抛异常)
    error: str = ""                     # parse_ok=False 时的原因
    verdict: str = ""                   # denied | granted
    perms: list = field(default_factory=list)          # ["read", "write", ...]
    scontext: str = ""                  # 源:哪个进程/域
    tcontext: str = ""                  # 目标:哪类资源
    tclass: str = ""                    # 对象类: file / dir / chr_file ...
    permissive: int | None = None       # 1=只记不拦 0=已拦截 None=没带
    pid: int | None = None
    comm: str = ""                      # 进程名(内核截断到 16 字符)
    obj: dict = field(default_factory=dict)            # 目标对象细节 name/dev/ino/path/exe
    extras: dict = field(default_factory=dict)         # ioctlcmd/capability/capname/...
    ts: float | None = None             # audit 时间戳(可选)
    audit_serial: int | None = None     # audit 序号(可选)

    def scontext_type(self) -> str:
        return context_type(self.scontext)

    def tcontext_type(self) -> str:
        return context_type(self.tcontext)

    def to_json(self) -> dict:
        return asdict(self)
