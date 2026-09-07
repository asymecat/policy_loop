"""SELinux 上下文字符串工具。

context 形如  u:r:media_service:s0  或带 MLS  u:r:installd:s0:c512,c768
索引器/分类器主要关心第 3 段(type/域),这里统一拆分避免到处切冒号。
"""
from __future__ import annotations


def split_context(ctx: str) -> dict:
    p = ctx.split(":")
    return {
        "user": p[0] if len(p) > 0 else "",
        "role": p[1] if len(p) > 1 else "",
        "type": p[2] if len(p) > 2 else "",
        "level": ":".join(p[3:]) if len(p) > 3 else "",
    }


def context_type(ctx: str) -> str:
    """取 type 段。兜底:切不出 3 段时原样返回,避免崩溃。"""
    p = ctx.split(":")
    return p[2] if len(p) > 2 else ctx
