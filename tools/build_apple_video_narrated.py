#!/usr/bin/env python3
"""PolicyLoop 产品片·精编版：浅色苹果风，15 个场景。

两种成片模式：
- 默认（中文旁白）：每场一段 edge-tts 晓晓，旁白时长决定场景时长，配乐 ducking；
- `--music-only`：无旁白，只留原创配乐，场景按 0.62 倍压缩到约 4 分钟。

视觉在 build_apple_video.py 的体系上扩展：新增七 Agent 流水线、三道守门、
audit2allow 对比、归因漏斗、双实现逐字节一致等图解。

用法：
    ~/.venvs/video/bin/python tools/build_apple_video_narrated.py --plan
    ~/.venvs/video/bin/python tools/build_apple_video_narrated.py --preview /tmp/pn
    ~/.venvs/video/bin/python tools/build_apple_video_narrated.py
    ~/.venvs/video/bin/python tools/build_apple_video_narrated.py --music-only

依赖：Pillow、numpy、imageio-ffmpeg、edge-tts（均在 ~/.venvs/video 里）。
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import wave
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import numpy as np
from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_apple_video as A                                  # noqa: E402

ROOT = A.ROOT
WORK = Path("/tmp/policyloop-apple-narrated")
TTS_DIR = WORK / "tts"
OUT_DEFAULT = Path.home() / "下载" / "PolicyLoop-产品片-讲解版-20261021.mp4"
OUT_MUSIC = Path.home() / "下载" / "PolicyLoop-产品片-精编版-20261021.mp4"
MUSIC_SCALE = 0.62          # 无旁白时场景压缩比例（约 4 分钟）

W, H = A.W, A.H
FPS = A.FPS
CX, CY = A.CX, A.CY
INK, SUB, FAINT, BLUE = A.INK, A.SUB, A.FAINT, A.BLUE
GREEN, ORANGE, RED, HAIR, WHITE = A.GREEN, A.ORANGE, A.RED, A.HAIR, A.WHITE

VOICE = "zh-CN-XiaoxiaoNeural"
RATE = "+8%"
LEAD = 0.75          # 场景开始到人声的留白
TAIL = 1.45          # 人声结束到场景结束的留白
XF = A.XF

BLUE_L = (126, 178, 240)
ORANGE_L = (238, 168, 118)
RED_L = (232, 146, 150)
GRAY_L = (206, 206, 212)

sprite = A.sprite
blit = A.blit
blit_left = A.blit_left
smooth = A.smooth
ease_out = A.ease_out


# ── 场景 ──────────────────────────────────────────────────────
@dataclass
class Scene:
    key: str
    min_dur: float
    narr: str
    beats: list[A.Beat] = field(default_factory=list)
    draw: Callable[[Image.Image, float, float], None] | None = None
    dur: float = 0.0
    audio: np.ndarray | None = None
    adur: float = 0.0

    def scale_beats(self) -> None:
        if self.min_dur <= 0:
            return
        f = self.dur / self.min_dur
        for b in self.beats:
            b.t0 *= f
            b.t1 *= f


def B(t0: float, t1: float, text: str, size: int = 64, color: tuple = INK,
      y: float = CY, bold: bool = True, track: float = 0.0,
      rise: float = 14.0, fin: float = 0.6, fout: float = 0.45,
      kind: str = "cjk", x: float | None = None) -> A.Beat:
    return A.Beat(t0, t1, text, size, color, y, bold, track, rise, fin, fout,
                  kind, x)


# ── 图形基础 ──────────────────────────────────────────────────
_card_cache: dict[tuple, Image.Image] = {}


def card_sprite(w: int, h: int, r: int = 26, blur: int = 24,
                alpha: int = 38) -> Image.Image:
    key = (w, h, r, blur, alpha)
    if key in _card_cache:
        return _card_cache[key]
    pad = blur * 2
    im = Image.new("RGBA", (w + 2 * pad, h + 2 * pad), (0, 0, 0, 0))
    sh, spad = A.shadow(w, h, r, blur=blur, alpha=alpha, dy=10)
    im.alpha_composite(sh, (pad - spad, pad - spad + 10))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((pad, pad, pad + w, pad + h), radius=r,
                        fill=(255, 255, 255, 255),
                        outline=HAIR + (255,), width=1)
    _card_cache[key] = im
    return im


def card(frame: Image.Image, box: tuple[float, float, float, float],
         a: float = 1.0, r: int = 26) -> None:
    x0, y0, x1, y1 = box
    im = card_sprite(int(x1 - x0), int(y1 - y0), r)
    blit(frame, im, (x0 + x1) / 2, (y0 + y1) / 2, a)


def label(d: ImageDraw.ImageDraw, cx: float, cy: float, text: str, size: int,
          color: tuple, bold: bool = True, a: float = 1.0,
          track: float = 0.4, kind: str = "cjk") -> None:
    im = sprite(text, size, color, bold, track, kind=kind)
    blit(d._image, im, cx, cy, a)


def label_left(d: ImageDraw.ImageDraw, x: float, cy: float, text: str,
               size: int, color: tuple, bold: bool = True, a: float = 1.0,
               track: float = 0.4, kind: str = "cjk") -> None:
    im = sprite(text, size, color, bold, track, kind=kind)
    blit_left(d._image, im, x, cy, a)


def arrow(d: ImageDraw.ImageDraw, x0: float, y0: float, x1: float, y1: float,
          color: tuple, a: float = 1.0, width: int = 2) -> None:
    al = int(255 * a)
    d.line((x0, y0, x1, y1), fill=color + (al,), width=width)
    if abs(x1 - x0) >= abs(y1 - y0):
        s = 1 if x1 > x0 else -1
        d.polygon([(x1, y1), (x1 - 11 * s, y1 - 6),
                   (x1 - 11 * s, y1 + 6)], fill=color + (al,))
    else:
        s = 1 if y1 > y0 else -1
        d.polygon([(x1, y1), (x1 - 6, y1 - 11 * s),
                   (x1 + 6, y1 - 11 * s)], fill=color + (al,))


def dashed_v(d: ImageDraw.ImageDraw, x: float, y0: float, y1: float,
             color: tuple, a: float = 0.5) -> None:
    y = y0
    al = int(255 * a)
    while y < y1:
        d.line((x, y, x, min(y + 7, y1)), fill=color + (al,), width=1)
        y += 15


def heading(frame: Image.Image, text: str, a: float = 1.0,
            y: float = 236, size: int = 50) -> None:
    im = sprite(text, size, INK, True, 0.3)
    blit(frame, im, CX, y, a)


# ── 图 1：三个难点 ────────────────────────────────────────────
THREE = [
    ("01", "判定要对",
     "真实缺陷，还是噪声 / 工具副作用 / 截断日志？"),
    ("02", "判定要能证明",
     "补丁必须最小，且不能撞 neverallow 红线。"),
    ("03", "判定要落到设备上",
     "不能只在电脑上跑脚本，设备要能自己判。"),
]


def draw_three(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    for i, (num, title, sub) in enumerate(THREE):
        st = 0.20 + i * 0.255
        a = smooth((p - st) / 0.07)
        if a <= 0:
            continue
        y = 420 + i * 170
        card(frame, (240, y - 62, 1680, y + 62), a, 24)
        d = ImageDraw.Draw(frame, "RGBA")
        label_left(d, 300, y - 18, num, 26, BLUE, True, a, 2.0, "helv")
        label_left(d, 392, y - 20, title, 36, INK, True, a, 0.4)
        label_left(d, 392, y + 28, sub, 23, SUB, False, a, 0.3)


# ── 图 2：该不该放行 ─────────────────────────────────────────
FLOW = [("denial 日志", "avc: denied"),
        ("分类", "噪声 / 缺陷 / 越权"),
        ("归因", "设备缺失 or 工具侧"),
        ("决策", "最小补丁 or 转人工")]


def draw_flow(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    bw, bh, gap = 270, 120, 46
    x0 = 210
    y = 545
    for i, (title, sub) in enumerate(FLOW):
        a = smooth((p - 0.22 - i * 0.070) / 0.06)
        if a <= 0:
            continue
        x = x0 + i * (bw + gap)
        card(frame, (x, y - bh / 2, x + bw, y + bh / 2), a, 22)
        label(ImageDraw.Draw(frame, "RGBA"), x + bw / 2, y - 16, title,
              27, INK, True, a, 0.4)
        label(ImageDraw.Draw(frame, "RGBA"), x + bw / 2, y + 26, sub,
              17, SUB, False, a, 0.3)
        if i < len(FLOW) - 1:
            arrow(ImageDraw.Draw(frame, "RGBA"),
                  x + bw + 10, y, x + bw + gap - 10, y, BLUE_L, a * 0.9)
    # 两条出口
    xe = x0 + 4 * (bw + gap) - gap
    dl = ImageDraw.Draw(frame, "RGBA")
    a_up = smooth((p - 0.52) / 0.07)
    a_dn = smooth((p - 0.62) / 0.07)
    if a_up > 0:
        arrow(dl, xe + 18, y - 20, xe + 18, y - 100, GREEN, a_up)
        label(dl, xe + 180, y - 135, "进入补丁候选", 24, GREEN, True, a_up,
              0.4)
        label(dl, xe + 180, y - 100, "需通过三道守门", 17, SUB, False, a_up,
              0.3)
    if a_dn > 0:
        arrow(dl, xe + 18, y + 20, xe + 18, y + 100, FAINT, a_dn)
        label(dl, xe + 180, y + 105, "转人工 · 附理由", 24, SUB, True, a_dn,
              0.4)
        label(dl, xe + 180, y + 140, "红线 / 证据不足 / 日志质量", 17, FAINT,
              False, a_dn, 0.3)


# ── 图 3：架构 ───────────────────────────────────────────────
HOST_ROWS = ["PLI 只读索引 · 21,824 条规则",
             "七 Agent 诊断流水线",
             "补丁生成 · 闭环反验"]
DEV_ROWS = ["pl_collector · 从 kmsg 采集",
            "denial_check · 查询与分类",
            "enforcing · 只判定 · 不写盘"]


def draw_arch2(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    a_l = smooth((p - 0.10) / 0.07)
    a_r = smooth((p - 0.34) / 0.07)
    d = ImageDraw.Draw(frame, "RGBA")
    if a_l > 0:
        card(frame, (150, 372, 920, 792), a_l, 28)
        label(d, 535, 424, "主机 · 承担重活", 30, INK, True, a_l, 0.4)
        label(d, 535, 460, "PC · Python 标准库", 17, FAINT, False, a_l, 0.3)
        for i, row in enumerate(HOST_ROWS):
            label(d, 535, 530 + i * 76, row, 24, SUB, False, a_l, 0.2)
    if a_r > 0:
        card(frame, (1000, 372, 1770, 792), a_r, 28)
        label(d, 1385, 424, "设备 · 采集与判定", 30, INK, True, a_r, 0.4)
        label(d, 1385, 460, "RK3568 · C++ 原生组件", 17, FAINT, False, a_r,
              0.3)
        for i, row in enumerate(DEV_ROWS):
            label(d, 1385, 530 + i * 76, row, 24, SUB, False, a_r, 0.2)
    a_m = smooth((p - 0.58) / 0.06)
    if a_m > 0:
        arrow(d, 928, 620, 992, 620, BLUE, a_m, 2)
        label(d, 960, 582, "PLI", 18, BLUE, True, a_m, 1.5, "helv")
    a_n = smooth((p - 0.70) / 0.08)
    if a_n > 0:
        label(d, CX, 858, "neverallow 是编译期约束，二进制策略里没有原始规则",
              22, SUB, False, a_n, 0.3)
        label(d, CX, 898, "⇒ 红线检查留在主机，设备只做确定能做的判定",
              22, INK, True, a_n, 0.3)


# ── 图 4：七 Agent 流水线 ────────────────────────────────────
PIPE = [("Log", "解析 · 去重"),
        ("Policy", "索引三问"),
        ("Security", "根因分类"),
        ("CrossLayer", "跨层建议"),
        ("Repair", "最小补丁"),
        ("Reviewer", "安全护栏"),
        ("Verify", "副本重查")]


def draw_pipeline(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    n = len(PIPE)
    nw, nh = 192, 126
    gap = (1740 - n * nw) / (n - 1)
    y = 520
    d = ImageDraw.Draw(frame, "RGBA")
    for i, (name, sub) in enumerate(PIPE):
        a = smooth((p - 0.10 - i * 0.070) / 0.05)
        if a <= 0:
            continue
        x = 90 + i * (nw + gap)
        card(frame, (x, y - nh / 2, x + nw, y + nh / 2), a, 18)
        size = 20 if len(name) < 9 else 17
        label(d, x + nw / 2, y - 20, name, size, INK, True, a, 0.3, "helv")
        label(d, x + nw / 2, y + 26, sub, 16, SUB, False, a, 0.2)
        if i < n - 1:
            arrow(d, x + nw + 8, y, x + nw + gap - 8, y, BLUE_L, a * 0.9)
    a_n = smooth((p - 0.62) / 0.08)
    if a_n > 0:
        label(d, CX, 742, "单向执行 · 不含回路 · 每个结论可追溯到日志行",
              26, INK, True, a_n, 0.4)
        label(d, CX, 800, "Reviewer 否决或 Verify 失败 ⇒ 转人工，不回退重算",
              22, ORANGE, False, a_n, 0.3)
        label(d, CX, 842, "允许反复重试，等于迭代出一个更宽的补丁", 19,
              FAINT, False, a_n, 0.3)


# ── 图 5：三道守门 ───────────────────────────────────────────
GATES = [("①  neverallow", "221 / 221", "撞红线一律拦下"),
         ("②  最小性", "179 / 179", "精确最小 · 过宽 0%"),
         ("③  闭环反验", "70 → 0", "套回索引重查 · 无遗留")]


def draw_gates(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    d = ImageDraw.Draw(frame, "RGBA")
    for i, (title, value, sub) in enumerate(GATES):
        a = smooth((p - 0.24 - i * 0.22) / 0.06)
        if a <= 0:
            continue
        cx = 430 + i * 530
        card(frame, (cx - 230, 470, cx + 230, 748), a, 28)
        label(d, cx, 522, title, 24, BLUE, True, a, 0.5)
        label(d, cx, 606, value, 58, INK, True, a, 0.5, "helv")
        label(d, cx, 686, sub, 22, SUB, False, a, 0.3)
    a_b = smooth((p - 0.76) / 0.08)
    if a_b > 0:
        label(d, CX, 822, "留一法 400 例 · 221 条应拒绝 · 179 条应生成",
              22, SUB, False, a_b, 0.3)


# ── 图 6：audit2allow 对比 ───────────────────────────────────
def draw_compare(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    d = ImageDraw.Draw(frame, "RGBA")
    x0, x1 = 470, 1560
    y1, y2 = 500, 660

    a1 = smooth((p - 0.14) / 0.06)
    if a1 > 0:
        label(d, 288, y1, "audit2allow", 26, SUB, True, a1, 0.4, "helv")
        d.rounded_rectangle((x0, y1 - 34, x1, y1 + 34), radius=10,
                            fill=GRAY_L + (int(255 * a1),))
        # 有效输出只占 5.2%
        ex = x0 + (x1 - x0) * (146 / 2833)
        d.rounded_rectangle((x0, y1 - 34, max(ex, x0 + 10), y1 + 34),
                            radius=10, fill=(120, 124, 132, int(255 * a1)))
        label(d, x1 + 52, y1, "2,833", 26, INK, True, a1, 0.4, "helv")
        label(d, (x0 + x1) / 2, y1 + 62, "2,687 条 no-op · 34 条撞红线 · 4 条类名不存在",
              19, SUB, False, a1, 0.3)

    a2 = smooth((p - 0.56) / 0.06)
    if a2 > 0:
        label(d, 288, y2, "PolicyLoop", 24, INK, True, a2, 0.4, "helv")
        ex = x0 + max(14, (x1 - x0) * (69 / 2833))
        d.rounded_rectangle((x0, y2 - 34, ex, y2 + 34), radius=10,
                            fill=BLUE + (int(255 * a2),))
        label(d, ex + 56, y2, "69", 26, BLUE, True, a2, 0.4, "helv")
        label(d, (x0 + x1) / 2, y2 + 62, "误报 0 · 过宽 0 · 撞红线 0",
              19, GREEN, False, a2, 0.3)

    a3 = smooth((p - 0.80) / 0.08)
    if a3 > 0:
        label(d, CX, 830, "同一份语料 · 有效输出 146 条 → 69 条",
              25, SUB, False, a3, 0.35)


# ── 图 7：六个数字 ───────────────────────────────────────────
SCORE = [("0", "误报", "5,161 条真实 denial 全量"),
         ("0%", "过宽率", "179/179 精确最小"),
         ("99.94%", "索引召回", "干净子集 3,522 条"),
         ("2,984,884 B", "逐字节相同", "27,912 条查询 · 两套实现"),
         ("0", "真正待补权限", "1,580 条转人工逐条归因"),
         ("372 / 0", "测试通过 / 失败", "第三方运行时依赖 0")]


def draw_scoreboard(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    d = ImageDraw.Draw(frame, "RGBA")
    for i, (value, name, sub) in enumerate(SCORE):
        a = smooth((p - 0.13 - i * 0.147) / 0.05)
        if a <= 0:
            continue
        cx = 440 + (i % 3) * 525
        cy = 455 + (i // 3) * 290
        card(frame, (cx - 242, cy - 108, cx + 242, cy + 108), a, 24)
        vs = 54 if len(value) > 8 else 62
        label(d, cx, cy - 30, value, vs, BLUE if i in (0, 1, 2) else INK,
              True, a, 0.6, "helv")
        label(d, cx, cy + 38, name, 23, INK, True, a, 0.4)
        label(d, cx, cy + 72, sub, 17, SUB, False, a, 0.25)


# ── 图 8：归因漏斗 ───────────────────────────────────────────
ATTR = [(1147, "历史噪声", (198, 198, 204)),
        (342, "工具侧", BLUE_L),
        (53, "日志质量", ORANGE_L),
        (38, "撞红线", RED_L)]


def draw_attribution(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    d = ImageDraw.Draw(frame, "RGBA")
    x0, x1, y = 250, 1670, 520
    total = 1580
    a = smooth((p - 0.12) / 0.07)
    if a <= 0:
        return
    label(d, (x0 + x1) / 2, y - 80, "1,580 条转人工", 30, INK, True, a, 0.4)
    grown = (x1 - x0) * smooth((p - 0.14) / 0.46)
    x = x0
    for val, name, color in ATTR:
        w = (x1 - x0) * val / total
        xe = min(x + w, x0 + grown)
        if xe > x:
            d.rectangle((x, y - 36, xe, y + 36), fill=color + (int(255 * a),))
        x += w
    a2 = smooth((p - 0.62) / 0.08)
    if a2 > 0:
        for j, (val, name, color) in enumerate(ATTR):
            lx = x0 + j * 356
            d.rounded_rectangle((lx, 620, lx + 14, 634), radius=3,
                                fill=color + (int(255 * a2),))
            label_left(d, lx + 26, 627, f"{name} {val:,}", 19, SUB, False,
                       a2, 0.25)
    a3 = smooth((p - 0.78) / 0.08)
    if a3 > 0:
        label(d, CX, 760, "真正需要给设备补权限", 24, SUB, False, a3, 0.35)
        label(d, CX, 838, "0 条", 76, BLUE, True, a3, 1.0, "helv")
        label(d, CX, 908, "归因残留 0 · 退出码 0 即判据", 20, FAINT, False,
              a3, 0.3)


# ── 图 9：真机（按进度切换两张截图） ────────────────────────
def draw_board(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    fade = smooth((p - 0.52) / 0.10)
    sc = 1.0 + 0.025 * ease_out(p)
    cx, cy = 1450, 565
    for im, a in ((A.DEV_A, 1 - fade), (A.DEV_B, fade)):
        if a <= 0.004:
            continue
        sz = (int(im.width * sc), int(im.height * sc))
        blit(frame, im.resize(sz, Image.BILINEAR), cx, cy, a)


# ── 图 10：双实现逐字节一致 ──────────────────────────────────
PY_LINES = ["27,912 queries", "2,984,884 bytes", "sha256 9076f293…"]
DEV_LINES = ["27,912 queries", "2,984,884 bytes", "sha256 9076f293…"]


def draw_parity(frame: Image.Image, t: float, dur: float) -> None:
    p = t / max(dur, 1e-6)
    d = ImageDraw.Draw(frame, "RGBA")
    for side, (cx, title, lines) in enumerate((
            (480, "主机 · Python", PY_LINES),
            (1440, "设备 · C++", DEV_LINES))):
        a = smooth((p - 0.12 - side * 0.10) / 0.07)
        if a <= 0:
            continue
        card(frame, (cx - 285, 420, cx + 285, 690), a, 26)
        label(d, cx, 474, title, 28, INK, True, a, 0.4)
        for i, ln in enumerate(lines):
            label(d, cx, 548 + i * 48, ln, 21, SUB, False, a, 0.2, "mono")
    a_m = smooth((p - 0.44) / 0.07)
    if a_m > 0:
        label(d, CX, 520, "=", 110, BLUE, True, a_m, 0, "helv")
        label(d, CX, 610, "sha256 相同", 20, BLUE, True, a_m, 0.5)
    a_n = smooth((p - 0.62) / 0.08)
    if a_n > 0:
        label(d, CX, 768, "一次覆盖 5 个字段：allowed / granted / ioctl 白名单 / ioctl 理由 / neverallow",
              21, SUB, False, a_n, 0.25)
    a_g = smooth((p - 0.80) / 0.08)
    if a_g > 0:
        label(d, CX, 824, "设备端五项门禁全绿", 24, GREEN, True, a_g, 0.4)
    a_p = smooth((p - 0.88) / 0.06)
    if a_p > 0:
        label(d, CX, 880, "改造后：设备查询 34× · 主机判定 238×", 20, INK,
              True, a_p, 0.35)


# ── 场景表 ───────────────────────────────────────────────────
def build_scenes() -> list[Scene]:
    sc: list[Scene] = []

    sc.append(Scene("open", 13.0,
        "PolicyLoop，一个为 OpenHarmony 设计的 SELinux 最小权限自收敛工具。"
        "它做的事只有一件：读懂每一次拒绝，判断这次权限到底该不该放，"
        "然后只给出刚好够用的那一条规则。", [
        B(0.5, 13.5, "PolicyLoop", 30, SUB, 380, True, 1.0, 10, 0.7, 0.4,
          "helv"),
        B(0.9, 13.5, "读懂每一次拒绝。", 104, INK, 500, True, 0.0, 16, 0.8,
          0.4),
        B(1.8, 13.5, "SELinux 拒绝日志的最小权限自收敛", 32, SUB, 640,
          False, 0.5, 10, 0.7, 0.4),
    ]))

    sc.append(Scene("problem", 25.0,
        "在 OpenHarmony 里，SELinux 是强制访问控制的底座。任何一个动作被拒绝，"
        "内核都会留下一条 avc denied 日志。过去常见的做法有两种："
        "跑 audit2allow 批量生成 allow 规则，或者干脆把 SELinux 改成 permissive。"
        "前者会多给权限，后者等于关掉防线。", [
        B(0.5, 6.0, "系统说：不行。", 96, INK, 500, True, 0, 14, 0.6, 0.35),
        B(6.4, 13.0, "多数人的回答：关掉它。", 62, INK, 500, True, 0, 12,
          0.6, 0.35),
        B(6.7, 13.0, "SELinux permissive", 22, ORANGE, 600, False, 3.0, 8,
          0.6, 0.35, "mono"),
        B(13.4, 21.0, "或者：一次生成几百条 allow。", 56, INK, 500, True, 0,
          12, 0.6, 0.35),
        B(13.7, 21.0, "audit2allow", 22, ORANGE, 600, False, 3.0, 8, 0.6,
          0.35, "mono"),
        B(21.4, 26.5, "两种做法，都在「多给权限」这一侧。", 44, SUB, 520,
          False, 0.4, 10, 0.6, 0.35),
    ]))

    sc.append(Scene("three", 25.0,
        "真正难的不是生成一条 allow，而是三个问题。第一，判定要对："
        "这条日志是真实缺陷，还是噪声、工具副作用，或者被截断的日志？"
        "第二，判定要能证明：补丁必须最小，不能撞 neverallow 红线。"
        "第三，判定要能在设备上落地，而不是只在电脑上跑个脚本。", [
        B(0.4, 28.0, "生成一条 allow 不难。难的是三个问题。", 40, SUB, 250,
          False, 0.3, 10, 0.6, 0.4),
    ], draw=draw_three))

    sc.append(Scene("principle", 21.0,
        "所以我们把问题换了一个问法：不是能不能放行，而是该不该放行。"
        "每一条 denial 先分类，再归因；只有确认是设备真实缺失、"
        "又不违反红线的权限，才进入补丁候选。剩下的全部转人工，并且给出理由。", [
        B(0.5, 23.0, "不是「能不能」，是「该不该」。", 62, INK, 262, True,
          0.3, 14, 0.6, 0.4),
    ], draw=draw_flow))

    sc.append(Scene("arch", 45.0,
        "架构上，主机负责重活。它加载 PLI 只读索引，跑七 Agent 诊断流水线，"
        "完成归因、补丁生成和闭环反验。设备负责采集与判定："
        "采集器从内核读 denial，判定组件用同一份索引做查询和分类。"
        "两端之间只传一份只读的 PLI。设备端不写盘，运行链路不需要电脑。"
        "为什么 neverallow 检查不放在设备上？因为 neverallow 是编译期约束，"
        "二进制策略里没有保留它的原始规则，无法在设备上反推。"
        "所以红线检查留在构建期的主机侧，设备只做它确定能做的判定。", [
        B(0.4, 45.0, "主机承担重活，设备做采集与判定。", 46, INK, 250, True,
          0.4, 12, 0.6, 0.4),
    ], draw=draw_arch2))

    sc.append(Scene("pipeline", 39.0,
        "这条流水线一共七个 Agent，依次是 Log、Policy、Security、CrossLayer、"
        "Repair、Reviewer 和 Verify。Log 负责解析与指纹去重；"
        "Policy 查索引三问：允许吗、撞红线吗、ioctl 在白名单里吗；"
        "Security 做根因分类；CrossLayer 只读地给出跨层建议，不改变结论；"
        "Repair 生成最小补丁；Reviewer 守门；"
        "Verify 在补丁已应用的索引副本上重查。"
        "七步单向，不含回路。Reviewer 否决或 Verify 失败，案例直接转人工，"
        "不回头重算——因为允许反复重试，等于让它迭代出一个更宽的补丁。", [
        B(0.4, 39.0, "七个 Agent，单向执行。", 46, INK, 250, True, 0.4, 12,
          0.6, 0.4),
    ], draw=draw_pipeline))

    sc.append(Scene("demo", 21.0,
        "这是一次真实运行。输入六条 denial，其中四条案例可以自动最小修复，"
        "归并成三条规则；另外两条，一条是历史噪声，一条是域与标签不匹配，"
        "转人工。整个过程零写盘，只输出建议。", [
        B(0.4, 26.0, "一次运行，四条自动修复。", 46, INK, 170, True, 0.5, 12,
          0.6, 0.4),
        B(14.0, 16.0, "6 条 denial，4 条案例可自动修复。", 28, SUB, 930, False,
          0.5, 10, 0.5, 0.35),
        B(17.0, 21.0, "0 次写盘。", 28, BLUE, 990, True, 0.5, 10, 0.5, 0.35),
    ], draw=A.draw_terminal))

    sc.append(Scene("gates", 32.0,
        "为了让最小这两个字可以被证明，我们加了三道守门。"
        "第一道，neverallow：任何会撞红线的补丁一律拦下，"
        "应拒绝的 221 条，全部拦截。第二道，最小性：在留一法实验里，"
        "179 条应生成补丁的样本，179 条精确最小，过宽率零。"
        "第三道，闭环反验：把生成的规则套回索引副本重新查询，"
        "补丁前未解决 70 条，套回后是 0 条。", [
        B(0.4, 32.0, "三道守门，把「最小」变成可证明。", 46, INK, 250, True,
          0.4, 12, 0.6, 0.4),
    ], draw=draw_gates))

    sc.append(Scene("compare", 28.0,
        "再和 audit2allow 比一次。同一份语料，它给出 2,833 条 allow，"
        "其中 2,687 条、也就是 94.8%，是当前策略本来就允许的 no-op，"
        "还有 34 条撞 neverallow，4 条引用了不存在的类名。"
        "PolicyLoop 给出 69 条，根因归并后 54 条，误报 0，过宽 0，撞红线 0。", [
        B(0.4, 29.0, "同一份语料，2,833 条 vs 69 条。", 46, INK, 248, True,
          0.4, 12, 0.6, 0.4),
    ], draw=draw_compare))

    sc.append(Scene("scoreboard", 38.0,
        "最强的结果，可以压成六个数字。第一，5,161 条上游真实 denial 全量跑完，"
        "进入自动补丁的案例零误报。第二，179 比 179 精确最小，过宽率 0%。"
        "第三，干净子集 3,522 条真实 denial，索引覆盖率 99.94%。"
        "第四，27,912 条查询、2,984,884 字节输出，两套独立实现逐字节相同。"
        "第五，1,580 条转人工逐条归因，真正需要补权限的是 0 条。"
        "第六，372 项测试通过，0 失败。", [
        B(0.4, 38.0, "六个数字。", 46, INK, 236, True, 0.4, 12, 0.6, 0.4),
    ], draw=draw_scoreboard))

    sc.append(Scene("attribution", 25.0,
        "1,580 条转人工，不是一句人工看看。我们逐条归因："
        "1,147 条是历史噪声，342 条是工具侧产生的 denial，"
        "53 条是日志质量问题，38 条撞红线。真正需要给设备补权限的，0 条。"
        "归因残留 0，工具退出码 0，这就是判据。", [
        B(0.4, 25.0, "1,580 条转人工，逐条归因。", 46, INK, 238, True, 0.4,
          12, 0.6, 0.4),
    ], draw=draw_attribution))

    sc.append(Scene("board", 31.0,
        "设备端不是演示动画。RK3568 开发板，OpenHarmony 5.0.3.135，"
        "enforcing 模式。冷启动 up 0 分钟的时候，采集服务已经在自己的 "
        "enforcing 域里工作，本域 denial 为 0。拨一下开关，一到两秒内，"
        "控制台就给出分类和最小补丁。需要说清楚的是：捕获路径不需要电脑，"
        "但触发动作和读屏，仍然由电脑发起。", [
        B(0.4, 34.0, "真机验证", 22, BLUE, 330, True, 0.5, 8, 0.55, 0.35,
          x=190),
        B(0.7, 34.0, "采集，不需要电脑。", 50, INK, 412, True, 0, 12, 0.6,
          0.40, x=190),
        B(1.1, 34.0, "判定，就在设备上。", 50, INK, 492, True, 0, 12, 0.6,
          0.40, x=190),
        B(1.5, 34.0, "RK3568 · OpenHarmony 5.0.3.135 · enforcing", 20, SUB,
          588, False, 0.4, 8, 0.6, 0.40, x=190),
        B(25.0, 34.0, "触发与读屏仍由电脑发起。", 22, SUB, 660, False, 0.4,
          8, 0.6, 0.40, x=190),
    ], draw=draw_board))

    sc.append(Scene("parity", 33.0,
        "主机用 Python，设备用 C++，两套代码独立实现。"
        "我们让它们回答同一组 27,912 条查询，输出 2,984,884 字节，"
        "两边的摘要完全相同。这不是逐字段抽查，是对整份输出的逐字节比对；"
        "一次覆盖 allowed、granted、ioctl 白名单、ioctl 理由和 neverallow "
        "五个字段。设备端另有五项门禁：自检、索引计数、报告差分、"
        "真实内核日志采样、查询差分，全部通过。"
        "改成类型对倒排索引后，设备查询路径快 34 倍，主机判定路径快 238 倍。", [
        B(0.4, 33.0, "主机 Python · 设备 C++。", 46, INK, 250, True, 0.4,
          12, 0.6, 0.4),
    ], draw=draw_parity))

    sc.append(Scene("limits", 22.0,
        "边界也写清楚。语料来自上游 OpenHarmony 策略仓库的历史注释，"
        "不是本机采集；板端约两秒的性能是外推值，上板后需要复测；"
        "留一法的金标准由我们自己构造，自洽不等于独立金标准。"
        "这些不影响主结论，但必须说。", [
        B(0.4, 22.0, "边界，同样清晰。", 46, INK, 300, True, 0.4, 12, 0.6,
          0.4),
        B(0.9, 22.0, "语料来自上游策略仓库，不是本机采集。", 24, SUB, 430,
          False, 0.3, 8, 0.6, 0.4),
        B(9.0, 22.0, "板端约两秒，是外推，不是实测。", 24, SUB, 500, False,
          0.3, 8, 0.6, 0.4),
        B(15.0, 22.0, "留一法金标准由自己构造，自洽不等于独立。", 24, SUB,
          570, False, 0.3, 8, 0.6, 0.4),
    ]))

    sc.append(Scene("close", 14.0,
        "PolicyLoop，让设备自己判 denial。只给建议，不写盘。"
        "主机与设备两次独立实现，2,984,884 字节，逐字节相同。", [
        B(0.5, 14.5, "PolicyLoop", 76, INK, 450, True, -1.5, 16, 0.8, 0.45,
          "helv"),
        B(1.2, 14.5, "为 OpenHarmony 而设计。", 34, SUB, 540, False, 0.5,
          10, 0.7, 0.45),
        B(2.0, 14.5, "只给建议。不写盘。", 24, FAINT, 608, False, 0.5, 8,
          0.7, 0.45),
        B(2.7, 14.5, "2026 开源鸿蒙大学生创新大赛 · 赛道一", 20, FAINT, 668,
          False, 0.5, 8, 0.7, 0.45),
    ]))
    return sc


# ── TTS 与声轨 ───────────────────────────────────────────────
SR = 44100


def tts_path(text: str) -> Path:
    key = hashlib.sha1(f"{VOICE}|{RATE}|{text}".encode()).hexdigest()[:16]
    return TTS_DIR / f"{key}.mp3"


def synth_one(text: str) -> Path:
    mp3 = tts_path(text)
    if mp3.exists() and mp3.stat().st_size > 2000:
        return mp3
    TTS_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "edge_tts", "--voice", VOICE,
                    "--rate", RATE, "--text", text, "--write-media",
                    str(mp3)], check=True, capture_output=True)
    return mp3


def decode(mp3: Path, wav: Path) -> np.ndarray:
    subprocess.run([A.FFMPEG, "-y", "-loglevel", "error", "-i", str(mp3),
                    "-ac", "1", "-ar", str(SR), "-c:a", "pcm_s16le",
                    str(wav)], check=True)
    with wave.open(str(wav), "rb") as w:
        raw = w.readframes(w.getnframes())
    return np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0


def prepare(sc: list[Scene], use_tts: bool = True,
            scale: float = 1.0) -> float:
    """合成旁白（可选）、确定每个场景的时长，返回总时长。"""
    WORK.mkdir(parents=True, exist_ok=True)
    if use_tts:
        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda s: synth_one(s.narr), sc))
    for s in sc:
        if use_tts:
            mp3 = tts_path(s.narr)
            wav = TTS_DIR / (mp3.stem + ".wav")
            pcm = decode(mp3, wav)
            s.audio = pcm
            s.adur = len(pcm) / SR
            s.dur = max(s.min_dur, LEAD + s.adur + TAIL)
        else:
            s.dur = s.min_dur * scale
        s.scale_beats()
    return sum(s.dur for s in sc)


def synth_bed(total: float, events: list[float], path: Path) -> tuple:
    """循环和弦垫 + 稀疏拨弦；返回 (left, right)。"""
    n = int(total * SR)
    t = np.arange(n, dtype=np.float64) / SR
    prog = [([130.81, 164.81, 196.00, 261.63], 0.019),
            ([110.00, 130.81, 164.81, 220.00], 0.017),
            ([174.61, 220.00, 261.63, 349.23], 0.016),
            ([98.00, 146.83, 196.00, 246.94], 0.018)]
    seg, fade = 12.0, 2.4
    left = np.zeros(n)
    right = np.zeros(n)

    def sm(x):
        x = np.clip(x, 0, 1)
        return x * x * (3 - 2 * x)

    k = 0
    while k * seg < total:
        a = k * seg
        b = min(a + seg, total)
        notes, amp = prog[k % len(prog)]
        env = np.clip(np.minimum(sm((t - a) / fade),
                                 sm((b - t) / fade)), 0, 1)
        for f0 in notes:
            for det, ph, side in ((1.0, 0.0, left), (1.0025, 0.9, right)):
                side += amp * env * np.sin(2 * np.pi * f0 * det * t + ph)
        k += 1

    # 空气层
    rng = np.random.default_rng(11)
    noise = rng.standard_normal(n).astype(np.float32)
    spec = np.fft.rfft(noise)
    freqs = np.fft.rfftfreq(n, 1 / SR)
    band = np.exp(-((np.log(np.maximum(freqs, 1)) - np.log(4200)) ** 2) /
                  (2 * 0.55 ** 2))
    air = np.fft.irfft(spec * band, n=n).astype(np.float64)
    air /= max(1e-9, np.max(np.abs(air)))
    air *= 0.0042
    left += air
    right += np.roll(air, 271)

    # 每个场景起点一个轻拨弦
    notes = [523.25, 659.25, 783.99, 880.00, 587.33, 783.99, 1046.50,
             659.25]
    dry_l = np.zeros(n)
    dry_r = np.zeros(n)
    for i, ev in enumerate(events):
        i0 = int((ev + 0.15) * SR)
        if i0 >= n:
            continue
        m = min(int(2.6 * SR), n - i0)
        tt = np.arange(m) / SR
        f0 = notes[i % len(notes)]
        env = (1 - np.exp(-tt / 0.006)) * np.exp(-tt / 0.62)
        tone = (np.sin(2 * np.pi * f0 * tt) +
                0.25 * np.sin(2 * np.pi * 2 * f0 * tt) * np.exp(-tt / 0.25))
        tone *= 0.022 * env
        dry_l[i0:i0 + m] += tone * (0.75 if i % 2 else 1.0)
        dry_r[i0:i0 + m] += tone * (1.0 if i % 2 else 0.75)
    for tap, gain in ((0.30, 0.28), (0.62, 0.10)):
        di = int(tap * SR)
        left[di:] += dry_l[:n - di] * gain
        right[di:] += dry_r[:n - di] * gain * 0.92

    fin = int(1.6 * SR)
    fout = int(3.2 * SR)
    left[:fin] *= np.linspace(0, 1, fin) ** 1.5
    right[:fin] *= np.linspace(0, 1, fin) ** 1.5
    left[-fout:] *= np.linspace(1, 0, fout) ** 1.4
    right[-fout:] *= np.linspace(1, 0, fout) ** 1.4
    return left, right


def mix_audio(sc: list[Scene], starts: list[float], total: float,
              path: Path) -> None:
    n = int(total * SR)
    voice = np.zeros(n)
    for s, st in zip(sc, starts):
        if s.audio is None:
            continue
        i0 = int((st + LEAD) * SR)
        m = min(len(s.audio), n - i0)
        if m > 0:
            voice[i0:i0 + m] += s.audio[:m]
    peak = max(1e-9, float(np.max(np.abs(voice))))
    voice *= 0.84 / peak

    # 人声包络 → 配乐 ducking
    win = int(0.06 * SR)
    env = np.convolve(np.abs(voice), np.ones(win) / win, mode="same")
    env = np.clip(env / 0.06, 0, 1)

    left, right = synth_bed(total, starts, path)
    left = left * (1.0 - 0.52 * env) + voice
    right = right * (1.0 - 0.52 * env) + voice

    mix = np.stack([left, right], axis=1)
    pk = max(1e-9, float(np.max(np.abs(mix))))
    mix = mix / pk * 0.95
    mix = np.tanh(mix * 1.12) / np.tanh(1.12) * 0.92
    # 首尾淡入淡出
    fi = int(0.8 * SR)
    fo = int(2.4 * SR)
    mix[:fi] *= np.linspace(0, 1, fi)[:, None]
    mix[-fo:] *= np.linspace(1, 0, fo)[:, None]

    pcm = (np.clip(mix, -1, 1) * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())


def synth_promo(total: float) -> tuple:
    """宣发配乐：100 BPM、C–G–Am–F，暖垫 + 钢琴式琶音 + 长音旋律。

    刻意收敛：没有密集打击，鼓点只在第 1、3 拍轻点，旋律留白，
    整体是“企业宣传片”那种稳定、干净、向上的底色，而不是轻快舞曲。
    """
    n = int(total * SR)
    left = np.zeros(n)
    right = np.zeros(n)
    rng = np.random.default_rng(7)

    bpm = 100.0
    beat = 60.0 / bpm
    bar = 4 * beat

    # 每个和弦：垫音内声部、低音、钢琴琶音四个音
    chords = [
        ([261.63, 329.63, 392.00], 130.81,
         [261.63, 392.00, 523.25, 659.25]),          # C
        ([196.00, 246.94, 293.66], 98.00,
         [246.94, 392.00, 493.88, 587.33]),          # G
        ([220.00, 261.63, 329.63], 110.00,
         [261.63, 329.63, 523.25, 659.25]),          # Am
        ([174.61, 220.00, 261.63], 87.31,
         [261.63, 349.23, 440.00, 523.25]),          # F
    ]
    # 旋律：每小节一句长音，每 4 小节出现、4 小节留白
    melody = [
        [(0.0, 659.25, 1.0), (1.0, 587.33, 0.5), (1.5, 523.25, 1.2),
         (2.75, 587.33, 0.5), (3.25, 659.25, 0.75)],
        [(0.0, 783.99, 1.2), (1.25, 659.25, 0.5), (1.75, 587.33, 0.5),
         (2.25, 523.25, 1.5)],
        [(0.0, 523.25, 1.0), (1.0, 587.33, 0.5), (1.5, 659.25, 1.2),
         (2.75, 587.33, 0.5), (3.25, 523.25, 0.75)],
        [(0.0, 587.33, 1.0), (1.0, 523.25, 0.5), (1.5, 440.00, 2.2)],
    ]

    def add(i0: int, m: int, w: np.ndarray, amp: float, pan: float) -> None:
        if m <= 0:
            return
        left[i0:i0 + m] += amp * w * (1.0 - pan)
        right[i0:i0 + m] += amp * w * pan

    def tone(t0: float, f: float, dur: float, amp: float, pan: float,
             decay: float = 0.45, attack: float = 0.006,
             harm: float = 0.20) -> None:
        i0 = int(t0 * SR)
        if i0 >= n:
            return
        m = min(int(dur * SR), n - i0)
        tt = np.arange(m) / SR
        env = (1 - np.exp(-tt / attack)) * np.exp(-tt / decay)
        w = np.sin(2 * np.pi * f * tt) + harm * np.sin(2 * np.pi * 2 * f * tt)
        add(i0, m, w * env, amp, pan)

    nbars = int(total / bar) + 1
    for b in range(nbars):
        t0 = b * bar
        if t0 >= total:
            break
        notes, bass, arp = chords[b % 4]

        # 暖垫：整小节铺底，慢起慢落
        m = min(int(bar * SR), n - int(t0 * SR))
        if m > 0:
            env = np.ones(m)
            a = min(m, int(0.40 * SR))
            r = min(m, int(0.70 * SR))
            env[:a] = np.linspace(0, 1, a) ** 1.5
            if r:
                env[-r:] *= np.linspace(1, 0, r) ** 1.2
            tt = np.arange(m) / SR
            for f in notes:
                for det, pan in ((1.0, 0.30), (1.0025, 0.70)):
                    w = (np.sin(2 * np.pi * f * det * tt + pan) +
                         0.08 * np.sin(2 * np.pi * 2 * f * det * tt))
                    add(int(t0 * SR), m, w * env, 0.0060, pan)
                    # 高八度薄层：让垫音也有中高频，不闷在 200–800 Hz
                    add(int(t0 * SR), m,
                        np.sin(2 * np.pi * 2 * f * det * tt + pan) * env,
                        0.0032, 1.0 - pan)

        # 低音：第 1 拍长音、第 3 拍轻点，圆润不抢
        tone(t0, bass, 0.95 * bar, 0.036, 0.5,
             decay=0.85, attack=0.030, harm=0.10)
        tone(t0 + 2 * beat, bass, 0.55 * bar, 0.023, 0.5,
             decay=0.55, attack=0.030, harm=0.10)

        # 钢琴式四分琶音：稳稳地走，不做八分音符的跳跃
        for k, idx in enumerate([0, 1, 2, 1]):
            tone(t0 + k * beat, arp[idx], 0.9 * beat, 0.030, 0.44,
                 decay=0.50, attack=0.006, harm=0.10)
            # 上方两层轻叠：给钢琴音色补 800 Hz 以上的“亮”和空气感
            tone(t0 + k * beat, arp[idx] * 2, 0.7 * beat, 0.026, 0.56,
                 decay=0.42, attack=0.006, harm=0.08)
            tone(t0 + k * beat, arp[idx] * 4, 0.5 * beat, 0.009, 0.40,
                 decay=0.34, attack=0.006, harm=0.05)

        # 旋律：4 小节出现、4 小节留白
        if (b // 4) % 2 == 0:
            for off, f, dur in melody[b % 4]:
                tone(t0 + off * beat, f, dur + 0.3, 0.048, 0.56,
                     decay=0.55, attack=0.010, harm=0.32)

        # 节奏：只有第 1、3 拍的软底鼓 + 反拍极轻的沙锤，不做拍手
        for bt in (0.0, 2.0):
            i0 = int((t0 + bt * beat) * SR)
            if i0 >= n:
                continue
            m = min(int(0.28 * SR), n - i0)
            tt = np.arange(m) / SR
            f = 86 * np.exp(-tt / 0.045) + 42
            ph = 2 * np.pi * np.cumsum(f) / SR
            add(i0, m, np.sin(ph) * np.exp(-tt / 0.11), 0.050, 0.5)
        for bt in (1.5, 3.5):
            ih = int((t0 + bt * beat) * SR)
            if ih >= n:
                continue
            mh = min(int(0.050 * SR), n - ih)
            tth = np.arange(mh) / SR
            nz = np.diff(rng.standard_normal(mh), prepend=0.0)
            add(ih, mh, nz * np.exp(-tth / 0.020), 0.012, 0.5)

    # 首尾淡入淡出（宣发片头尾要柔）
    fi = int(2.0 * SR)
    fo = int(4.0 * SR)
    left[:fi] *= np.linspace(0, 1, fi)
    right[:fi] *= np.linspace(0, 1, fi)
    left[-fo:] *= np.linspace(1, 0, fo)
    right[-fo:] *= np.linspace(1, 0, fo)

    return left, right


def mix_music(sc: list[Scene], starts: list[float], total: float,
              path: Path) -> None:
    """无旁白：只留配乐，抬到可独立聆听、但不压过画面的电平。"""
    left, right = synth_promo(total)
    mix = np.stack([left, right], axis=1)
    pk = max(1e-9, float(np.max(np.abs(mix))))
    mix = mix / pk * 0.72
    mix = np.tanh(mix * 1.05) / np.tanh(1.05) * 0.85
    pcm = (np.clip(mix, -1, 1) * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())


# ── 渲染 ──────────────────────────────────────────────────────
def timeline(sc: list[Scene]) -> tuple[list[float], float]:
    starts, acc = [], 0.0
    for s in sc:
        starts.append(acc)
        acc += s.dur
    return starts, acc


def frame_at(sc: list[Scene], starts: list[float], t: float) -> Image.Image:
    si = max(i for i, st in enumerate(starts) if t >= st)
    s = sc[si]
    local = t - starts[si]
    frame = A.scene_frame(s, local)
    if si > 0 and local < XF:
        prev = sc[si - 1]
        pframe = A.scene_frame(prev, prev.dur + local)
        frame = Image.blend(pframe, frame, smooth(local / XF))
    elif si == 0 and t < XF:
        frame = Image.blend(A.WHITE_IMG, frame, smooth(t / XF))
    return frame


def render(sc: list[Scene], out: Path, wav: Path) -> None:
    starts, total = timeline(sc)
    cmd = [A.FFMPEG, "-y", "-loglevel", "error",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
           "-r", str(FPS), "-i", "pipe:0", "-i", str(wav),
           "-c:v", "libx264", "-preset", "medium", "-crf", str(A.CRF),
           "-pix_fmt", "yuv420p", "-profile:v", "high",
           "-c:a", "aac", "-b:a", "192k",
           "-movflags", "+faststart", "-shortest", str(out)]
    WORK.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stderr=open(WORK / "ffmpeg.log", "wb"))
    n_frames = int(total * FPS)
    try:
        for f in range(n_frames):
            proc.stdin.write(frame_at(sc, starts, f / FPS).tobytes())
            if f % 250 == 0:
                print(f"  {f / FPS:6.1f}s / {total:.1f}s", flush=True)
    finally:
        proc.stdin.close()
        proc.wait()
    if proc.returncode != 0:
        sys.exit(f"ffmpeg 失败，见 {WORK / 'ffmpeg.log'}")
    print(f"→ {out}  ({out.stat().st_size / 1e6:.1f} MB, {total:.1f}s)")


def preview(sc: list[Scene], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    starts, total = timeline(sc)
    for i, s in enumerate(sc):
        for frac in (0.25, 0.62, 0.9):
            t = starts[i] + s.dur * frac
            frame_at(sc, starts, t).save(
                out_dir / f"{i + 1:02d}-{s.key}-{int(frac * 100)}.png")
    print(f"预览帧 → {out_dir}（总长 {total:.1f}s）")


def plan(sc: list[Scene]) -> None:
    total = sum(s.dur for s in sc)
    print(f"{'#':>2}  {'scene':<12}{'min':>7}{'narr':>7}{'dur':>7}")
    for i, s in enumerate(sc, 1):
        print(f"{i:>2}  {s.key:<12}{s.min_dur:>7.1f}{s.adur:>7.1f}"
              f"{s.dur:>7.1f}")
    print(f"总计 {total:.1f}s = {int(total // 60)}:{total % 60:04.1f}")
    print(f"旁白 {sum(s.adur for s in sc):.1f}s，"
          f"{sum(len(s.narr) for s in sc)} 字")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--preview", type=Path)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--no-sound", action="store_true",
                    help="不合成旁白/配乐，仅按 min_dur 渲染")
    ap.add_argument("--music-only", action="store_true",
                    help="无旁白，仅配乐，场景按 --scale 压缩")
    ap.add_argument("--scale", type=float, default=MUSIC_SCALE,
                    help=f"music-only 的场景压缩比例（默认 {MUSIC_SCALE}）")
    args = ap.parse_args()

    A.DEMO = A.run_demo()
    sc = build_scenes()
    if args.music_only:
        total = prepare(sc, use_tts=False, scale=args.scale)
        if args.out == OUT_DEFAULT:
            args.out = OUT_MUSIC
    else:
        total = prepare(sc, use_tts=not args.no_sound)

    if args.plan:
        plan(sc)
        return
    if args.preview:
        preview(sc, args.preview)
        return

    WORK.mkdir(parents=True, exist_ok=True)
    wav = WORK / "master.wav"
    if args.no_sound:
        with wave.open(str(wav), "wb") as w:
            w.setnchannels(2)
            w.setsampwidth(2)
            w.setframerate(SR)
            w.writeframes(b"\x00" * (4 * int(total * SR)))
    else:
        starts, _ = timeline(sc)
        if args.music_only:
            mix_music(sc, starts, total, wav)
        else:
            mix_audio(sc, starts, total, wav)
        print(f"声轨：{wav}  {wav.stat().st_size / 1e6:.1f} MB")
    render(sc, args.out, wav)


if __name__ == "__main__":
    main()
