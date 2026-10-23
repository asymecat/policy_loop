#!/usr/bin/env python3
"""PolicyLoop 产品片：苹果发布会/产品广告风格（浅色、留白、系统蓝、柔影）。

与 build_cinematic_video.py 的黑场电影感相对：
- 近白背景，深灰黑大字，少量系统蓝作强调
- 产品画面是白色窗口 + 手机机身卡片，柔和投影，缓慢上浮
- 数字从 0 跳到目标值；转场是极短交叉淡化，不做闪黑
- 仍然没有旁白，信息全部由画面文字承担

用法：
    ~/.venvs/video/bin/python tools/build_apple_video.py
    ~/.venvs/video/bin/python tools/build_apple_video.py --preview /tmp/pa
    ~/.venvs/video/bin/python tools/build_apple_video.py --no-sound

依赖：Pillow、numpy、imageio-ffmpeg。
"""

from __future__ import annotations

import argparse
import math
import subprocess
import sys
import unicodedata
import wave
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

try:
    import imageio_ffmpeg
except ImportError as e:                                   # pragma: no cover
    sys.exit(f"缺少依赖：{e}. 先安装 pillow numpy imageio-ffmpeg")

ROOT = Path(__file__).resolve().parents[1]
SCR = ROOT / "docs" / "screenshots"
OUT_DEFAULT = Path.home() / "下载" / "PolicyLoop-产品片-紧凑版-20261019.mp4"
WORK = Path("/tmp/policyloop-apple")

W, H = 1920, 1080
FPS = 25
CX, CY = W / 2, H / 2

F_CJK = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
F_CJKB = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
F_HELV = "/usr/share/fonts/opentype/urw-base35/NimbusSans-Bold.otf"
F_HELVR = "/usr/share/fonts/opentype/urw-base35/NimbusSans-Regular.otf"
IDX_UI = 2                      # Noto Sans CJK SC
IDX_MONO = 7                    # Noto Sans Mono CJK SC

# 取色按 Apple 的系统色，但在浅底上压暗一档保证可读
BG_TOP = (252, 252, 253)
BG_BOT = (242, 242, 245)
INK = (29, 29, 31)              # #1d1d1f
SUB = (110, 110, 115)           # #6e6e73
FAINT = (134, 134, 139)         # #86868b
BLUE = (0, 113, 227)            # #0071e3
HAIR = (210, 210, 215)          # #d2d2d7
CODE_BLUE = (0, 102, 204)
GREEN = (28, 122, 60)
ORANGE = (191, 72, 0)
RED = (196, 0, 15)

WHITE = (255, 255, 255)
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
CRF = 18
XF = 0.55                       # 场景交叉淡化秒数


# ── 基础工具 ──────────────────────────────────────────────────
def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if x < lo else hi if x > hi else x


def smooth(x: float) -> float:
    x = clamp(x)
    return x * x * (3 - 2 * x)


def ease_out(x: float) -> float:
    x = clamp(x)
    return 1 - (1 - x) ** 3


_fonts: dict[tuple, ImageFont.FreeTypeFont] = {}


def get_font(kind: str, size: int, bold: bool) -> ImageFont.FreeTypeFont:
    key = (kind, size, bold)
    if key in _fonts:
        return _fonts[key]
    if kind == "helv":
        f = ImageFont.truetype(F_HELV if bold else F_HELVR, size)
    elif kind == "mono":
        f = ImageFont.truetype(F_CJKB if bold else F_CJK, size,
                               index=IDX_MONO)
    else:
        f = ImageFont.truetype(F_CJKB if bold else F_CJK, size, index=IDX_UI)
    _fonts[key] = f
    return f


# ── 文字精灵（逐字字距，2× 渲染后降采样） ─────────────────────
_sprites: dict[tuple, Image.Image] = {}


def sprite(text: str, size: int, color: tuple, bold: bool = True,
           track: float = 0.0, line_gap: float = 1.5,
           kind: str = "cjk") -> Image.Image:
    key = (text, size, color, bold, track, line_gap, kind)
    if key in _sprites:
        return _sprites[key]
    s = 2
    f = get_font(kind, size * s, bold)
    ascent, descent = f.getmetrics()
    lines = text.split("\n")
    widths: list[float] = []
    for ln in lines:
        adv = [f.getlength(ch) for ch in ln]
        widths.append(sum(adv) + track * s * max(0, len(ln) - 1))
    lh = int(size * s * line_gap)
    pad = 10
    wpx = int(max(widths)) + pad * 2
    hpx = lh * (len(lines) - 1) + ascent + descent + pad * 2
    im = Image.new("RGBA", (max(wpx, 2), max(hpx, 2)), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    for i, ln in enumerate(lines):
        x = pad + (max(widths) - widths[i]) / 2
        base = pad + ascent + i * lh
        # 基线定位：逗号、句号、大小写字母才不会各按各的包围盒顶对齐
        for ch in ln:
            d.text((x, base), ch, font=f, fill=color + (255,), anchor="ls")
            x += f.getlength(ch) + track * s
    im = im.resize((max(1, im.width // 2), max(1, im.height // 2)),
                   Image.LANCZOS)
    _sprites[key] = im
    return im


def blit(frame: Image.Image, im: Image.Image, cx: float, cy: float,
         alpha: float = 1.0) -> None:
    if alpha <= 0.004:
        return
    x = int(cx - im.width / 2)
    y = int(cy - im.height / 2)
    if alpha >= 0.996:
        frame.paste(im, (x, y), im)
    else:
        mask = im.getchannel("A").point(lambda v: int(v * alpha))
        frame.paste(im, (x, y), mask)


def blit_left(frame: Image.Image, im: Image.Image, x: float, cy: float,
              alpha: float = 1.0) -> None:
    if alpha <= 0.004:
        return
    y = int(cy - im.height / 2)
    if alpha >= 0.996:
        frame.paste(im, (int(x), y), im)
    else:
        mask = im.getchannel("A").point(lambda v: int(v * alpha))
        frame.paste(im, (int(x), y), mask)


# ── 背景与投影 ────────────────────────────────────────────────
def make_bg() -> Image.Image:
    yy = np.linspace(0, 1, H).astype(np.float32)[:, None]
    arr = np.empty((H, W, 3), np.float32)
    for c in range(3):
        arr[..., c] = BG_TOP[c] + (BG_BOT[c] - BG_TOP[c]) * yy
    # 顶部一层极淡的高光，模拟发布会舞台灯
    xx = np.linspace(-1, 1, W).astype(np.float32)[None, :]
    glow = np.exp(-((xx / 0.72) ** 2 + ((yy - 0.02) / 0.55) ** 2))
    arr += glow[..., None] * 7.0
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")


BG = make_bg()
WHITE_IMG = Image.new("RGB", (W, H), WHITE)

_shadows: dict[tuple, tuple[Image.Image, int]] = {}


def shadow(w: int, h: int, r: int, blur: int = 28, alpha: int = 46,
           dy: int = 14) -> tuple[Image.Image, int]:
    key = (w, h, r, blur, alpha, dy)
    if key in _shadows:
        return _shadows[key]
    pad = blur * 2
    m = Image.new("L", (w + 2 * pad, h + 2 * pad), 0)
    ImageDraw.Draw(m).rounded_rectangle((pad, pad, pad + w, pad + h),
                                        radius=r, fill=255)
    m = m.filter(ImageFilter.GaussianBlur(blur))
    m = m.point(lambda v: int(v * alpha / 255))
    im = Image.new("RGBA", m.size, (0, 0, 0, 0))
    im.putalpha(m)
    _shadows[key] = (im, pad)
    return im, pad


def paste_shadow(frame: Image.Image, sh: Image.Image, pad: int,
                 x: float, y: float, dy: int = 0) -> None:
    frame.paste(sh, (int(x) - pad, int(y) - pad + dy), sh)


# ── 场景与节拍 ────────────────────────────────────────────────
@dataclass
class Beat:
    t0: float
    t1: float
    text: str
    size: int = 64
    color: tuple = INK
    y: float = CY
    bold: bool = True
    track: float = 0.0
    rise: float = 14.0
    fin: float = 0.6
    fout: float = 0.45
    kind: str = "cjk"
    x: float | None = None       # 给了 x 就左对齐


@dataclass
class Scene:
    key: str
    dur: float
    beats: list[Beat] = field(default_factory=list)
    draw: Callable[[Image.Image, float, float], None] | None = None


def beat_alpha(b: Beat, t: float) -> float:
    if t < b.t0 or t > b.t1:
        return 0.0
    return smooth((t - b.t0) / b.fin) * smooth((b.t1 - t) / b.fout)


def draw_beats(frame: Image.Image, beats: list[Beat], t: float) -> None:
    for b in beats:
        a = beat_alpha(b, t)
        if a <= 0:
            continue
        p = ease_out((t - b.t0) / b.fin) if t >= b.t0 else 0.0
        y = b.y + b.rise * (1 - p)
        im = sprite(b.text, b.size, b.color, b.bold, b.track, kind=b.kind)
        if b.x is None:
            blit(frame, im, CX, y, a)
        else:
            blit_left(frame, im, b.x, y, a)


# ── 真实终端素材（浅色 macOS 窗口） ───────────────────────────
CMD = ("python -m policy_loop.converge --log examples/board-denials.log "
       "--policy data/raw/oh-selinux/sepolicy")


def run_demo() -> list[str]:
    r = subprocess.run([sys.executable, "-m", "policy_loop.converge",
                        "--log", "examples/board-denials.log",
                        "--policy", "data/raw/oh-selinux/sepolicy"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"converge 运行失败：{r.stderr[-500:]}")
    return [ln.rstrip() for ln in r.stdout.splitlines()]


def cells(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def wrap_cells(s: str, maxc: int) -> list[str]:
    out, cur, n = [], "", 0
    for ch in s:
        w = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if n + w > maxc and cur:
            out.append(cur)
            cur, n = "", 0
        cur += ch
        n += w
    out.append(cur)
    return out


def out_color(ln: str) -> tuple:
    if ln.startswith("[PolicyLoop converge] policy"):
        return SUB
    if "WARNING" in ln:
        return ORANGE
    if ln.startswith("denials="):
        return INK
    if ln.startswith("#"):
        return CODE_BLUE
    if ln.startswith("  allow"):
        return GREEN
    if ln.startswith("  ["):
        return RED
    return SUB


TERM_W, TERM_H = 1600, 600
TERM_R = 16
TITLE_H = 52
TERM_PAD = 30
TERM_FS = 19
TERM_LH = 30


def terminal_image(typed: str, lines: list[str], n_out: int,
                   highlight: float) -> Image.Image:
    f = get_font("mono", TERM_FS, False)
    cell = f.getlength("M")
    maxc = int((TERM_W - TERM_PAD * 2) / cell)
    im = Image.new("RGB", (TERM_W, TERM_H), WHITE)
    d = ImageDraw.Draw(im, "RGBA")

    # 标题栏
    d.rectangle((0, 0, TERM_W, TITLE_H), fill=(246, 246, 248, 255))
    d.line((0, TITLE_H, TERM_W, TITLE_H), fill=(226, 226, 231, 255))
    for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
        cx = 28 + i * 22
        d.ellipse((cx - 6, 26 - 6, cx + 6, 26 + 6), fill=c + (255,))
    d.text((TERM_W / 2, TITLE_H / 2),
           "converge — examples/board-denials.log",
           font=get_font("helv", 15, False), fill=(134, 134, 139, 255),
           anchor="mm")

    # 命令行：macOS 的 % 提示符
    prompt = "dev@host policy_loop % "
    y = TITLE_H + 22
    cmd_chunks = wrap_cells(prompt + typed, maxc)
    for i, ck in enumerate(cmd_chunks):
        if i == 0:
            d.text((TERM_PAD, y), prompt, font=f, fill=GREEN + (255,))
            d.text((TERM_PAD + cell * len(prompt), y), ck[len(prompt):],
                   font=f, fill=INK + (255,))
        else:
            d.text((TERM_PAD, y), ck, font=f, fill=INK + (255,))
        y += TERM_LH

    # 输出，按真实终端行为从底部向上滚动
    rows: list[tuple[int, int, str]] = []      # (原始行号, y, 文本)
    for i in range(min(n_out, len(lines))):
        for part in wrap_cells(lines[i], maxc):
            rows.append((i, y, part))
            y += TERM_LH

    visible = int((TERM_H - TITLE_H - 24) / TERM_LH)
    if len(rows) > visible:
        offset_y = (len(rows) - visible) * TERM_LH
    else:
        offset_y = 0
    for i, ry, part in rows:
        yy = ry - offset_y
        if yy < TITLE_H + 8 or yy > TERM_H - TERM_LH:
            continue
        d.text((TERM_PAD, yy), part, font=f, fill=out_color(lines[i]) + (255,))
        if highlight > 0 and "allowxperm" in part:
            a = int(230 * highlight)
            d.line((TERM_PAD, yy + TERM_LH - 5,
                    TERM_PAD + int(cell * cells(part)), yy + TERM_LH - 5),
                   fill=BLUE + (a,), width=2)
    return im


def draw_terminal(frame: Image.Image, t: float, dur: float) -> None:
    n_typed = max(0, min(len(CMD), int((t - 0.4) / 0.015)))
    typed = CMD[:n_typed]
    if t < 2.1:
        n_out = 0
    else:
        n_out = min(len(DEMO), 1 + int((t - 2.1) / 0.19))
    hl = smooth((t - 5.2) / 0.8)
    img = terminal_image(typed, DEMO, n_out, hl)

    sc = 1.0 + 0.022 * ease_out(t / dur)
    w, h = int(TERM_W * sc), int(TERM_H * sc)
    x, y = CX - w / 2, 560 - h / 2
    im = img.resize((w, h), Image.BILINEAR)
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w - 1, h - 1),
                                           radius=int(TERM_R * sc), fill=255)
    sh, pad = shadow(w, h, int(TERM_R * sc), blur=34, alpha=54, dy=18)
    paste_shadow(frame, sh, pad, x, y, 18)
    frame.paste(im, (int(x), int(y)), mask)
    d = ImageDraw.Draw(frame)
    d.rounded_rectangle((x, y, x + w - 1, y + h - 1),
                        radius=int(TERM_R * sc), outline=HAIR, width=1)


# ── 架构卡片 ──────────────────────────────────────────────────
NODES = [("主机", "索引 · 编排"), ("PLI", "只读 · 传递"),
         ("设备", "采集 · 判定")]
CARD_W, CARD_H, CARD_R, CARD_PAD = 360, 180, 24, 52


def make_card(title: str, sub: str) -> Image.Image:
    w, h, pad = CARD_W, CARD_H, CARD_PAD
    im = Image.new("RGBA", (w + 2 * pad, h + 2 * pad), (0, 0, 0, 0))
    sh, spad = shadow(w, h, CARD_R, blur=24, alpha=40, dy=12)
    im.alpha_composite(sh, (pad - spad, pad - spad + 12))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((pad, pad, pad + w, pad + h), radius=CARD_R,
                        fill=WHITE + (255,), outline=HAIR + (255,), width=1)
    t = sprite(title, 34, INK, True)
    s = sprite(sub, 20, SUB, False, 0.5)
    im.alpha_composite(t, (pad + int((w - t.width) / 2),
                           pad + 50 - int(t.height / 2)))
    im.alpha_composite(s, (pad + int((w - s.width) / 2),
                           pad + 118 - int(s.height / 2)))
    return im


CARDS = [make_card(a, b) for a, b in NODES]


def draw_arch(frame: Image.Image, t: float, dur: float) -> None:
    xs = [CX - 420, CX, CX + 420]
    y0 = 530
    starts = [0.5, 1.4, 2.3]
    for i, im in enumerate(CARDS):
        a = smooth((t - starts[i]) / 0.55)
        if a <= 0:
            continue
        p = ease_out((t - starts[i]) / 0.55)
        # 卡片精灵中心 = pad + 卡片中心
        blit(frame, im, xs[i] + 0, y0 + 18 * (1 - p), a)

    # 连接线：系统蓝细线 + 圆点
    d = ImageDraw.Draw(frame, "RGBA")
    for i, st in enumerate([1.2, 2.1]):
        a = smooth((t - st) / 0.5)
        if a <= 0:
            continue
        x1 = xs[i] + CARD_W / 2 + 16
        x2 = xs[i + 1] - CARD_W / 2 - 16
        d.line((x1, y0, x2, y0), fill=BLUE + (int(90 * a),), width=2)
        mx = (x1 + x2) / 2
        d.ellipse((mx - 4, y0 - 4 + 18 * (1 - a), mx + 4, y0 + 4 + 18 * (1 - a)),
                  fill=BLUE + (int(255 * a),))


# ── 真机截图（机身卡片） ──────────────────────────────────────
BOARD_A = Image.open(SCR / "fig7-board-snapshot.png").convert("RGB")
BOARD_B = Image.open(SCR / "fig6-board-live-cards.png").convert("RGB")


def device_image(img: Image.Image, h: int) -> Image.Image:
    bezel = 12
    w = round(h * img.width / img.height)
    scr = img.resize((w, h), Image.LANCZOS)
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, w - 1, h - 1),
                                           radius=34, fill=255)
    fw, fh = w + bezel * 2, h + bezel * 2
    out = Image.new("RGBA", (fw + 160, fh + 160), (0, 0, 0, 0))
    sh, spad = shadow(fw, fh, 44, blur=38, alpha=84, dy=26)
    out.alpha_composite(sh, (80 - spad, 80 - spad + 26))
    d = ImageDraw.Draw(out)
    d.rounded_rectangle((80, 80, 80 + fw, 80 + fh), radius=46,
                        fill=(29, 29, 31, 255))
    out.paste(scr, (80 + bezel, 80 + bezel), mask)
    return out


DEV_A = device_image(BOARD_A, 760)
DEV_B = device_image(BOARD_B, 760)


def draw_board(frame: Image.Image, t: float, dur: float) -> None:
    fade = smooth((t - 7.0) / 0.9)
    sc = 1.0 + 0.02 * ease_out(t / dur)
    cx, cy = 1460, 560
    for im, a in ((DEV_A, 1 - fade), (DEV_B, fade)):
        if a <= 0.004:
            continue
        if abs(sc - 1.0) > 0.001:
            sz = (int(im.width * sc), int(im.height * sc))
            im2 = im.resize(sz, Image.BILINEAR)
        else:
            im2 = im
        blit(frame, im2, cx, cy, a)


# ── 数字场景（跳数动画） ──────────────────────────────────────
NUMBERS = [
    (0.2, 3.1, 5161, "条真实 denial"),
    (3.2, 6.0, 4911, "个去重后的案例"),
    (6.1, 9.0, 70, "个需要宽松权限的案例"),
    (9.1, 11.9, 0, "个遗留"),
]


def draw_numbers(frame: Image.Image, t: float, dur: float) -> None:
    for t0, t1, target, caption in NUMBERS:
        if t < t0 or t > t1:
            continue
        a = min(smooth((t - t0) / 0.35), smooth((t1 - t) / 0.35))
        p = ease_out((t - t0 - 0.05) / 0.75)
        val = int(round(target * p))
        txt = f"{val:,}"
        num = sprite(txt, 200, INK, True, -3.0, kind="helv")
        blit(frame, num, CX, 480, a)
        cap = sprite(caption, 30, SUB, False, 0.5)
        ca = min(smooth((t - t0 - 0.55) / 0.4), smooth((t1 - t) / 0.35))
        blit(frame, cap, CX, 660, ca)


# ── 时间线 ────────────────────────────────────────────────────
def scenes() -> list[Scene]:
    sc: list[Scene] = []

    sc.append(Scene("open", 6.5, [
        Beat(0.5, 6.2, "PolicyLoop", 30, SUB, 380, True, 1.0, 10, 0.7, 0.4,
             "helv"),
        Beat(0.9, 6.2, "读懂每一次拒绝。", 104, INK, 500, True, 0.0, 16, 0.8,
             0.4),
        Beat(1.8, 6.2, "SELinux 拒绝日志的最小权限自收敛", 32, SUB, 640,
             False, 0.5, 10, 0.7, 0.4),
    ]))

    sc.append(Scene("problem", 12.0, [
        Beat(0.5, 4.2, "系统说：不行。", 96, INK, 500, True, 0, 14, 0.6,
             0.35),
        Beat(4.6, 8.2, "多数人的回答：关掉它。", 62, INK, 500, True, 0, 12,
             0.6, 0.35),
        Beat(4.9, 8.2, "SELinux permissive", 22, ORANGE, 600, False, 3.0,
             8, 0.6, 0.35, "mono"),
        Beat(8.6, 11.8, "我们的回答：读懂它。", 62, INK, 500, True, 0, 12,
             0.6, 0.35),
        Beat(9.0, 11.8, "不是「能不能」，是「该不该」。", 32, SUB, 606,
             False, 0.5, 8, 0.6, 0.35),
    ]))

    sc.append(Scene("run", 14.0, [
        Beat(0.5, 13.5, "一次运行，四条补丁。", 46, INK, 170, True, 0.5,
             12, 0.6, 0.4),
        Beat(7.6, 10.4, "6 条 denial，4 条最小补丁。", 30, SUB, 930, False,
             0.5, 10, 0.5, 0.35),
        Beat(10.6, 13.4, "0 次写盘。", 30, BLUE, 930, True, 0.5, 10, 0.5,
             0.35),
    ], draw=draw_terminal))

    sc.append(Scene("arch", 10.0, [
        Beat(0.5, 9.7, "主机承担重活，设备只做判定。", 46, INK, 200, True,
             0.5, 12, 0.6, 0.4),
        Beat(5.2, 9.7, "索引、编排在主机。采集、判定在设备。", 26, SUB,
             750, False, 0.5, 8, 0.6, 0.4),
    ], draw=draw_arch))

    sc.append(Scene("numbers", 12.0, [], draw=draw_numbers))

    sc.append(Scene("zero", 12.5, [
        Beat(0.5, 3.5, "1,580 条，无法自动判定。", 56, INK, 470, True, 0,
             14, 0.6, 0.35),
        Beat(3.8, 6.2, "逐条归因之后——", 32, SUB, 470, False, 0.5, 10,
             0.6, 0.35),
        Beat(6.4, 10.0, "0", 240, BLUE, 468, True, -2.0, 18, 0.6, 0.4,
             "helv"),
        Beat(6.7, 10.0, "条需要额外权限", 30, SUB, 702, False, 0.5, 10,
             0.6, 0.4),
        Beat(10.2, 12.2, "权限，刚刚好。", 44, INK, 520, True, 0, 12, 0.6,
             0.35),
    ]))

    sc.append(Scene("board", 14.0, [
        Beat(0.6, 13.6, "真机验证", 24, BLUE, 340, True, 0.5, 8, 0.55, 0.35,
             x=190),
        Beat(0.9, 13.6, "采集，不需要电脑。", 54, INK, 430, True, 0, 12,
             0.6, 0.35, x=190),
        Beat(1.3, 13.6, "判定，就在设备上。", 54, INK, 512, True, 0, 12,
             0.6, 0.35, x=190),
        Beat(1.6, 13.6, "RK3568 · OpenHarmony 5.0.3.135 · enforcing", 22,
             SUB, 628, False, 0.5, 8, 0.6, 0.35, x=190),
        Beat(8.6, 13.6, "触发动作仍由电脑发起。", 24, SUB, 690, False, 0.5,
             8, 0.6, 0.35, x=190),
    ], draw=draw_board))

    sc.append(Scene("parity", 10.0, [
        Beat(0.4, 3.4, "主机用 Python。设备用 C++。", 54, INK, 420, True, 0,
             12, 0.6, 0.35),
        Beat(3.6, 6.5, "27,912 条查询。", 76, INK, 510, True, 0, 12, 0.6,
             0.35),
        Beat(6.7, 9.8, "逐字节相同。", 76, BLUE, 610, True, 0, 12, 0.6,
             0.35),
        Beat(7.0, 9.8, "2,984,884 字节，两套独立实现", 24, SUB, 706,
             False, 0.5, 8, 0.6, 0.35),
    ]))

    sc.append(Scene("limits", 9.0, [
        Beat(0.4, 8.8, "边界，同样清晰。", 48, INK, 350, True, 0.5, 12,
             0.6, 0.35),
        Beat(0.9, 8.8, "语料来自上游策略仓库，不是本机采集。", 26, SUB,
             470, False, 0.5, 8, 0.6, 0.35),
        Beat(3.0, 8.8, "板端约两秒，是外推，不是实测。", 26, SUB, 530,
             False, 0.5, 8, 0.6, 0.35),
        Beat(5.1, 8.8, "构造自洽，不等于独立金标准。", 26, SUB, 590, False,
             0.5, 8, 0.6, 0.35),
    ]))

    sc.append(Scene("close", 9.0, [
        Beat(0.5, 9.3, "PolicyLoop", 76, INK, 470, True, -1.5, 16, 0.8,
             0.45, "helv"),
        Beat(1.2, 9.3, "为 OpenHarmony 而设计。", 34, SUB, 560, False, 0.5,
             10, 0.7, 0.45),
        Beat(2.0, 9.3, "只给建议。不写盘。", 24, FAINT, 630, False, 0.5, 8,
             0.7, 0.45),
        Beat(2.7, 9.3, "2026 开源鸿蒙大学生创新大赛 · 赛道一", 20, FAINT,
             690, False, 0.5, 8, 0.7, 0.45),
    ]))
    return sc


DEMO: list[str] = []


# ── 原创配乐：C 大调暖垫 + 稀疏拨弦 ──────────────────────────
def synth_audio(total: float, events: list[float], path: Path) -> None:
    sr = 44100
    n = int(total * sr)
    t = np.arange(n, dtype=np.float64) / sr

    # 和弦垫：C — Am — F — G — C，段间用 smoothstep 交叉
    chords = [
        (0.0, 18.5, [130.81, 164.81, 196.00, 261.63]),
        (18.5, 42.5, [110.00, 130.81, 164.81, 220.00]),
        (42.5, 67.0, [174.61, 220.00, 261.63, 349.23]),
        (67.0, 91.0, [98.00, 146.83, 196.00, 246.94]),
        (91.0, total, [130.81, 164.81, 196.00, 261.63]),
    ]
    amps = [0.040, 0.032, 0.026, 0.018]
    fade = 2.5
    left = np.zeros(n)
    right = np.zeros(n)
    def smooth_np(x):
        x = np.clip(x, 0, 1)
        return x * x * (3 - 2 * x)

    for a, b, notes in chords:
        env = np.minimum(smooth_np((t - a) / fade), smooth_np((b - t) / fade))
        env = np.clip(env, 0, 1)
        for f0, amp in zip(notes, amps):
            # 轻微失谐 + 左右相位差，做出暖而宽的垫音
            for det, ph, side in ((1.0, 0.0, left), (1.0025, 0.9, right)):
                side += (amp * env *
                         np.sin(2 * np.pi * f0 * det * t + ph))

    # 空气层：极轻的高频噪声
    rng = np.random.default_rng(11)
    noise = rng.standard_normal(n).astype(np.float32)
    spec = np.fft.rfft(noise)
    freqs = np.fft.rfftfreq(n, 1 / sr)
    band = np.exp(-((np.log(np.maximum(freqs, 1)) - np.log(4200)) ** 2) /
                  (2 * 0.55 ** 2))
    air = np.fft.irfft(spec * band, n=n).astype(np.float64)
    air /= max(1e-9, np.max(np.abs(air)))
    air *= 0.009 * (0.6 + 0.4 * np.sin(2 * np.pi * 0.017 * t + 1.3))
    left += air
    right += np.roll(air, 271)

    # 稀疏拨弦：每个关键节拍一个音，带简单回声
    notes = [523.25, 659.25, 783.99, 880.00, 587.33, 783.99, 1046.50,
             659.25]
    dry_l = np.zeros(n)
    dry_r = np.zeros(n)
    for k, ev in enumerate(events):
        i0 = int(ev * sr)
        if i0 >= n:
            continue
        dur = int(2.4 * sr)
        m = min(dur, n - i0)
        tt = np.arange(m) / sr
        f0 = notes[k % len(notes)]
        env = (1 - np.exp(-tt / 0.006)) * np.exp(-tt / 0.55)
        tone = (np.sin(2 * np.pi * f0 * tt) +
                0.28 * np.sin(2 * np.pi * 2 * f0 * tt) * np.exp(-tt / 0.25))
        tone *= 0.050 * env
        dry_l[i0:i0 + m] += tone * (0.8 if k % 2 else 1.0)
        dry_r[i0:i0 + m] += tone * (1.0 if k % 2 else 0.8)

    # 回声：三次衰减复制
    left += dry_l
    right += dry_r
    for tap, gain in ((0.30, 0.30), (0.62, 0.12), (0.95, 0.05)):
        di = int(tap * sr)
        left[di:] += dry_l[:n - di] * gain
        right[di:] += dry_r[:n - di] * gain * 0.92

    # 淡入淡出
    fin = int(1.5 * sr)
    fout = int(3.0 * sr)
    left[:fin] *= np.linspace(0, 1, fin) ** 1.5
    right[:fin] *= np.linspace(0, 1, fin) ** 1.5
    left[-fout:] *= np.linspace(1, 0, fout) ** 1.4
    right[-fout:] *= np.linspace(1, 0, fout) ** 1.4

    mix = np.stack([left, right], axis=1)
    peak = max(1e-9, float(np.max(np.abs(mix))))
    mix = np.tanh(mix / peak * 1.1) * 0.42
    pcm = (np.clip(mix, -1, 1) * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(pcm.tobytes())


# ── 渲染 ──────────────────────────────────────────────────────
def scene_frame(sc: Scene, local: float) -> Image.Image:
    frame = BG.copy()
    if sc.draw:
        sc.draw(frame, local, sc.dur)
    draw_beats(frame, sc.beats, local)
    return frame


def frame_at(sc: list[Scene], starts: list[float], t: float) -> Image.Image:
    si = max(i for i, st in enumerate(starts) if t >= st)
    s = sc[si]
    local = t - starts[si]
    frame = scene_frame(s, local)
    if si > 0 and local < XF:
        prev = sc[si - 1]
        pframe = scene_frame(prev, prev.dur + local)
        frame = Image.blend(pframe, frame, smooth(local / XF))
    elif si == 0 and t < XF:
        frame = Image.blend(WHITE_IMG, frame, smooth(t / XF))
    return frame


def timeline(sc: list[Scene]) -> tuple[list[float], float]:
    starts, acc = [], 0.0
    for s in sc:
        starts.append(acc)
        acc += s.dur
    return starts, acc


def render(sc: list[Scene], out: Path, sound: bool = True) -> None:
    starts, total = timeline(sc)
    WORK.mkdir(parents=True, exist_ok=True)
    wav = WORK / "bed.wav"
    events = [0.8, 6.9, 10.6, 14.0, 18.9, 27.0, 33.0, 42.9, 45.6, 48.6,
              51.6, 54.9, 58.6, 61.2, 67.4, 75.2, 81.4, 84.6, 87.6, 91.4,
              96.0, 100.4, 103.0]
    if sound:
        synth_audio(total, events, wav)
        print(f"声轨：{wav}  {wav.stat().st_size/1e6:.1f} MB")
    else:
        sr = 44100
        with wave.open(str(wav), "wb") as w:
            w.setnchannels(2)
            w.setsampwidth(2)
            w.setframerate(sr)
            w.writeframes(b"\x00" * (4 * int(total * sr)))

    cmd = [FFMPEG, "-y", "-loglevel", "error",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
           "-r", str(FPS), "-i", "pipe:0", "-i", str(wav),
           "-c:v", "libx264", "-preset", "medium", "-crf", str(CRF),
           "-pix_fmt", "yuv420p", "-profile:v", "high",
           "-c:a", "aac", "-b:a", "192k",
           "-movflags", "+faststart", "-shortest", str(out)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stderr=open(WORK / "ffmpeg.log", "wb"))
    n_frames = int(total * FPS)
    try:
        for f in range(n_frames):
            t = f / FPS
            proc.stdin.write(frame_at(sc, starts, t).tobytes())
            if f % 250 == 0:
                print(f"  {t:6.1f}s / {total:.1f}s", flush=True)
    finally:
        proc.stdin.close()
        proc.wait()
    if proc.returncode != 0:
        sys.exit(f"ffmpeg 失败，见 {WORK/'ffmpeg.log'}")
    print(f"→ {out}  ({out.stat().st_size/1e6:.1f} MB, {total:.1f}s)")


def preview(sc: list[Scene], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    starts, total = timeline(sc)
    marks = [(1.5, "01-open"), (5.0, "02-open-end"),
             (9.5, "03-problem-b"), (15.5, "04-problem-c"),
             (20.0, "05-terminal-typing"), (23.5, "06-terminal-output"),
             (28.0, "07-terminal-done"), (35.0, "08-arch"),
             (39.5, "09-arch-caption"), (44.0, "10-num-5161"),
             (47.0, "11-num-4911"), (50.0, "12-num-70"),
             (53.0, "13-num-0"), (57.0, "14-zero-lead"),
             (62.5, "15-big-zero"), (70.5, "16-board"),
             (76.5, "17-board-b"), (83.5, "18-parity-a"),
             (87.0, "19-parity-b"), (94.5, "20-limits"),
             (102.0, "21-close"), (107.0, "22-endcard")]
    for t, name in marks:
        if t >= total:
            continue
        frame_at(sc, starts, t).save(out_dir / f"{name}.png")
    print(f"预览帧 → {out_dir}")


def main() -> None:
    global DEMO
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--preview", type=Path)
    ap.add_argument("--no-sound", action="store_true")
    args = ap.parse_args()
    DEMO = run_demo()
    sc = scenes()
    if args.preview:
        preview(sc, args.preview)
    else:
        render(sc, args.out, sound=not args.no_sound)


if __name__ == "__main__":
    main()
