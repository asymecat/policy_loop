#!/usr/bin/env python3
"""PolicyLoop 概念片：电影感产品广告风格（黑场、宽画幅、大字、慢推）。

与 build_demo_video.py 的讲解版不同，这一版不要章节标题、卡片、图表和字幕条：
画面只有产品本身（真实终端、真机界面）与一句一句的大字，声音是原创的氛围底噪。

用法：
    ~/.venvs/video/bin/python tools/build_cinematic_video.py
    ~/.venvs/video/bin/python tools/build_cinematic_video.py --preview /tmp/pv
    ~/.venvs/video/bin/python tools/build_cinematic_video.py --no-sound

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
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFont

try:
    import imageio_ffmpeg
except ImportError as e:                                   # pragma: no cover
    sys.exit(f"缺少依赖：{e}. 先安装 pillow numpy imageio-ffmpeg")

ROOT = Path(__file__).resolve().parents[1]
SCR = ROOT / "docs" / "screenshots"
OUT_DEFAULT = Path.home() / "下载" / "PolicyLoop-概念片-20261019.mp4"
WORK = Path("/tmp/policyloop-cine")

W, H = 1920, 1080
FPS = 25
BAR = 108                       # 上下黑边，2.22:1 的宽画幅
TOP, BOT = BAR, H - BAR
CX, CY = W / 2, (TOP + BOT) / 2

F_CJK = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
F_CJKB = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
F_LAT = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"
IDX_UI = 2                      # Noto Sans CJK SC
IDX_MONO = 7                    # Noto Sans Mono CJK SC

BG = (5, 7, 8)
WHITE = (244, 247, 248)
DIM = (146, 156, 162)
FAINT = (92, 101, 106)
ACCENT = (74, 224, 186)

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
CRF = 18                       # 暗场 + 静态画面，18 兼顾渐变与体积


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


def cjk(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    key = ("cjk", size, bold)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(F_CJKB if bold else F_CJK, size,
                                         index=IDX_UI)
    return _fonts[key]


def mono(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    key = ("mono", size, bold)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(F_CJKB if bold else F_CJK, size,
                                         index=IDX_MONO)
    return _fonts[key]


def lat(size: int, bold: bool = True) -> ImageFont.FreeTypeFont:
    key = ("lat", size, bold)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(F_LAT, size)
    return _fonts[key]


def get_font(kind: str, size: int, bold: bool) -> ImageFont.FreeTypeFont:
    if kind == "lat":
        return lat(size, bold)
    if kind == "mono":
        return mono(size, bold)
    return cjk(size, bold)


# ── 文字精灵（带字距，2× 渲染后降采样） ──────────────────────
_sprites: dict[tuple, Image.Image] = {}


def sprite(text: str, size: int, color: tuple, bold: bool = True,
           track: float = 0.0, line_gap: float = 1.55,
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
        # 用基线定位：逗号、句号、大小写字母才不会各按各的包围盒顶对齐
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


# ── 场景与节拍 ────────────────────────────────────────────────
@dataclass
class Beat:
    t0: float
    t1: float
    text: str
    size: int = 64
    color: tuple = WHITE
    y: float = CY
    bold: bool = True
    track: float = 0.0
    rise: float = 20.0
    fin: float = 0.7
    fout: float = 0.55
    kind: str = "cjk"


@dataclass
class Scene:
    key: str
    dur: float
    beats: list[Beat] = field(default_factory=list)
    draw: Callable[[Image.Image, float, float], None] | None = None
    fade: float = 0.45


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
        blit(frame, sprite(b.text, b.size, b.color, b.bold, b.track,
                           kind=b.kind), CX, y, a)


# ── 背景、光晕、暗角、颗粒 ────────────────────────────────────
def make_bg() -> Image.Image:
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    k = (1 - yy / (H - 1)) ** 1.3
    arr = np.empty((H, W, 3), np.float32)
    arr[..., 0] = 3.0 + 4.0 * k
    arr[..., 1] = 5.0 + 4.5 * k
    arr[..., 2] = 6.0 + 4.8 * k
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")


def make_glow(d: int = 1200, color: tuple = (70, 210, 178),
              peak: int = 34) -> Image.Image:
    yy, xx = np.mgrid[0:d, 0:d].astype(np.float32)
    r = np.sqrt((xx - d / 2) ** 2 + (yy - d / 2) ** 2) / (d / 2)
    a = np.clip(1 - r, 0, 1) ** 2.4 * peak
    arr = np.zeros((d, d, 4), np.uint8)
    arr[..., 0], arr[..., 1], arr[..., 2] = color
    arr[..., 3] = a.astype(np.uint8)
    return Image.fromarray(arr, "RGBA")


def make_vignette() -> Image.Image:
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    r = np.sqrt(((xx - W / 2) / (W / 2)) ** 2 +
                ((yy - H / 2) / (H / 2)) ** 2)
    v = 1.0 - 0.52 * np.clip(r - 0.34, 0, 1) ** 1.35
    arr = np.repeat((v * 255)[..., None], 3, axis=2)
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")


BG_IMG = make_bg()
GLOW = make_glow()
VIG = make_vignette()


def bg_frame(t: float) -> Image.Image:
    frame = BG_IMG.copy()
    gx = CX + 46 * math.sin(t * 0.047)
    gy = 470 + 26 * math.sin(t * 0.033 + 1.2)
    frame.paste(GLOW, (int(gx - GLOW.width / 2), int(gy - GLOW.height / 2)),
                GLOW)
    return frame


def letterbox(frame: Image.Image) -> None:
    d = ImageDraw.Draw(frame)
    d.rectangle((0, 0, W, TOP), fill=(0, 0, 0))
    d.rectangle((0, BOT, W, H), fill=(0, 0, 0))


# ── 真实终端素材 ──────────────────────────────────────────────
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
        return (108, 196, 160)
    if "WARNING" in ln:
        return (196, 156, 98)
    if ln.startswith("denials="):
        return (226, 232, 238)
    if ln.startswith("#"):
        return (108, 178, 208)
    if ln.startswith("  allow"):
        return (126, 214, 172)
    if ln.startswith("  ["):
        return (206, 146, 116)
    return (128, 138, 146)


TERM_W, TERM_H = 1660, 650
TERM_PAD = 30
TERM_FS = 21
TERM_LH = 31
TERM_TOP = 46


def terminal_image(typed: str, lines: list[str], n_out: int,
                   highlight: float) -> Image.Image:
    f = mono(TERM_FS)
    cell = f.getlength("M")
    maxc = int((TERM_W - TERM_PAD * 2) / cell)
    im = Image.new("RGB", (TERM_W, TERM_H), (10, 12, 13))
    d = ImageDraw.Draw(im, "RGBA")
    d.rounded_rectangle((0, 0, TERM_W - 1, TERM_H - 1), radius=3,
                        outline=(60, 68, 72, 255), width=1)
    d.rectangle((1, 1, TERM_W - 2, TERM_TOP), fill=(16, 19, 20, 255))
    d.text((TERM_PAD, TERM_TOP / 2), "converge", font=mono(15),
           fill=(150, 160, 164), anchor="lm")
    d.text((TERM_PAD + 96, TERM_TOP / 2), "examples/board-denials.log",
           font=mono(15), fill=(88, 96, 100), anchor="lm")
    d.line((1, TERM_TOP, TERM_W - 2, TERM_TOP), fill=(42, 48, 51, 255))

    prompt = "dev@host:~/policy_loop$ "
    y = TERM_TOP + 20
    chunks = wrap_cells(prompt + typed, maxc)
    for i, ck in enumerate(chunks):
        if i == 0:
            d.text((TERM_PAD, y), prompt, font=f, fill=(92, 204, 150))
            d.text((TERM_PAD + cell * len(prompt), y), ck[len(prompt):],
                   font=f, fill=(224, 230, 234))
        else:
            d.text((TERM_PAD, y), ck, font=f, fill=(224, 230, 234))
        y += TERM_LH

    rows: list[tuple[int, int, str]] = []      # (raw index, y, text)
    for i in range(min(n_out, len(lines))):
        for part in wrap_cells(lines[i], maxc):
            if y > TERM_H - TERM_LH:
                break
            d.text((TERM_PAD, y), part, font=f, fill=out_color(lines[i]))
            rows.append((i, y, part))
            y += TERM_LH

    # 只放开一个 ioctl 命令号的那行，给一道细下划线
    if highlight > 0:
        for i, ry, part in rows:
            if "allowxperm" in part:
                a = int(200 * highlight)
                d.line((TERM_PAD, ry + TERM_LH - 5,
                        TERM_PAD + int(cell * cells(part)), ry + TERM_LH - 5),
                       fill=ACCENT + (a,), width=1)
                break
    return im


def draw_terminal(frame: Image.Image, t: float, dur: float) -> None:
    n_typed = max(0, min(len(CMD), int((t - 1.0) / 0.028)))
    typed = CMD[:n_typed]
    if t < 4.2:
        n_out = 0
    else:
        n_out = min(len(DEMO), 1 + int((t - 4.2) / 0.30))
    hl = smooth((t - 9.0) / 1.2)
    img = terminal_image(typed, DEMO, n_out, hl)

    sc = 1.0 + 0.045 * ease_out(t / dur)
    w, h = int(TERM_W * sc), int(TERM_H * sc)
    img = img.resize((w, h), Image.BILINEAR)
    frame.paste(img, (int(CX - w / 2), int(460 - h / 2)))


# ── 架构：三个节点，极简 ──────────────────────────────────────
NODES = [("主机", "索引 · 编排"), ("PLI", "只读 · 传递"),
         ("设备", "采集 · 判定")]


def draw_arch(frame: Image.Image, t: float, dur: float) -> None:
    bw, bh = 348, 148
    xs = [CX - 470, CX, CX + 470]
    y0 = 430
    d = ImageDraw.Draw(frame, "RGBA")
    starts = [0.6, 3.1, 5.6]
    for i, (title, sub) in enumerate(NODES):
        a = smooth((t - starts[i]) / 0.6)
        if a <= 0:
            continue
        x, y = xs[i] - bw / 2, y0 - bh / 2
        d.rounded_rectangle((x, y, x + bw, y + bh), radius=4,
                            fill=(9, 12, 13, int(150 * a)),
                            outline=(58, 66, 70, int(220 * a)), width=1)
        blit(frame, sprite(title, 34, WHITE, True), xs[i], y0 - 20, a)
        blit(frame, sprite(sub, 20, DIM, False), xs[i], y0 + 34, a)
    for i, st in enumerate([2.0, 4.5]):
        p = ease_out((t - st) / 0.9)
        if p <= 0:
            continue
        x1, x2 = xs[i] + bw / 2 + 26, xs[i + 1] - bw / 2 - 26
        xe = x1 + (x2 - x1) * p
        d.line((x1, y0, xe, y0), fill=(64, 74, 78, 230), width=1)
        if p > 0.55:
            d.ellipse((xe - 2.5, y0 - 2.5, xe + 2.5, y0 + 2.5),
                      fill=ACCENT + (200,))


BOARD_A = Image.open(SCR / "fig7-board-snapshot.png").convert("RGB")
BOARD_B = Image.open(SCR / "fig6-board-live-cards.png").convert("RGB")


def _panel(frame: Image.Image, img: Image.Image, w: int, h: int,
           cx: float, cy: float, alpha: float) -> None:
    if alpha <= 0.004:
        return
    im = img.resize((w, h), Image.BILINEAR)
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, w - 1, h - 1), radius=6, fill=255)
    if alpha < 0.996:
        mask = mask.point(lambda v: int(v * alpha))
    frame.paste(im, (int(cx - w / 2), int(cy - h / 2)), mask)


def draw_board(frame: Image.Image, t: float, dur: float) -> None:
    fade = smooth((t - 8.6) / 1.0)
    sc = 1.0 + 0.04 * ease_out(t / dur)
    h = int(792 * sc)
    w = int(h * BOARD_A.width / BOARD_A.height)
    _panel(frame, BOARD_A, w, h, CX, 500, 1 - fade)
    _panel(frame, BOARD_B, w, h, CX, 500, fade)
    # 截图底部有一条浅色边，用渐隐压进黑场
    x0, y0 = int(CX - w / 2), int(500 - h / 2)
    fade_h = 84
    ramp = Image.new("L", (1, fade_h))
    for i in range(fade_h):
        ramp.putpixel((0, i), int(255 * (i / fade_h) ** 1.7))
    veil = Image.new("RGB", (w, fade_h), BG)
    frame.paste(veil, (x0, y0 + h - fade_h),
                ramp.resize((w, fade_h)))
    d = ImageDraw.Draw(frame)
    d.rounded_rectangle((x0, y0, x0 + w, y0 + h), radius=6,
                        outline=(46, 54, 57), width=1)


# ── 时间线 ────────────────────────────────────────────────────
def scenes() -> list[Scene]:
    sc: list[Scene] = []
    sc.append(Scene("title", 7.5, [
        Beat(1.1, 7.0, "PolicyLoop", 96, WHITE, 470, True, 10, 24, 1.1,
             0.6, "lat"),
        Beat(2.1, 7.0, "SELinux 拒绝日志的最小权限自收敛", 32, DIM, 588,
             False, 1.5, 18, 0.9, 0.6),
        Beat(3.0, 7.0, "2026 开源鸿蒙大学生创新大赛 · 赛道一", 19, FAINT,
             700, False, 1.5, 12, 0.8, 0.6),
    ]))

    sc.append(Scene("manifesto", 27.0, [
        Beat(0.6, 6.0, "系统说：不行。", 78, WHITE, 500),
        Beat(6.6, 12.8, "大多数时候，人们选择把门整个打开。", 60, WHITE, 500),
        Beat(7.1, 12.8, "SELinux permissive", 22, DIM, 604, False, 3.0,
             0, 0.8, 0.5, "mono"),
        Beat(13.4, 19.6, "我们选择，读懂它。", 66, WHITE, 500),
        Beat(20.2, 23.4, "不是「能不能放行」", 62, WHITE, 472),
        Beat(23.4, 26.6, "是「该不该放行」。", 62, ACCENT, 566),
    ]))

    sc.append(Scene("arch", 13.0, [
        Beat(7.6, 12.8, "主机承担重活，设备只留判定。", 40, WHITE, 724,
             False, 1.0, 16, 0.8, 0.5),
    ], draw=draw_arch))

    sc.append(Scene("run", 20.0, [
        Beat(9.2, 13.4, "6 条真实 denial，一次运行。", 28, DIM, 906,
             False, 1.0, 12, 0.7, 0.4),
        Beat(13.8, 17.2, "4 条自动生成最小权限补丁。", 28, DIM, 906,
             False, 1.0, 12, 0.7, 0.4),
        Beat(17.6, 19.8, "没有写盘。", 28, ACCENT, 906, False, 1.0, 12,
             0.7, 0.4),
    ], draw=draw_terminal))

    sc.append(Scene("numbers", 15.0, [
        Beat(0.3, 3.9, "5,161", 172, WHITE, 476, True, 0, 18, 0.45, 0.3),
        Beat(0.5, 3.9, "条真实 denial，来自上游策略仓库", 26, DIM, 630,
             False, 1.0, 12, 0.5, 0.3),
        Beat(4.2, 7.8, "4,911", 172, WHITE, 476, True, 0, 18, 0.45, 0.3),
        Beat(4.4, 7.8, "个去重后的案例", 26, DIM, 630, False, 1.0, 12,
             0.5, 0.3),
        Beat(8.1, 11.5, "70", 172, WHITE, 476, True, 0, 18, 0.45, 0.3),
        Beat(8.3, 11.5, "个需要宽松权限的案例", 26, DIM, 630, False, 1.0,
             12, 0.5, 0.3),
        Beat(11.8, 14.6, "0", 172, ACCENT, 476, True, 0, 18, 0.45, 0.3),
        Beat(12.0, 14.6, "个遗留", 26, DIM, 630, False, 1.0, 12, 0.5, 0.3),
    ]))

    sc.append(Scene("zero", 16.0, [
        Beat(0.4, 4.6, "1,580 条，无法自动判定。", 52, WHITE, 480),
        Beat(4.9, 8.2, "逐条归因之后——", 30, DIM, 480, False, 1.5),
        Beat(8.5, 13.0, "0", 210, ACCENT, 476, True, 0, 22, 0.7, 0.4),
        Beat(8.8, 13.0, "条需要给设备补权限", 26, DIM, 652, False, 1.0,
             12, 0.6, 0.4),
        Beat(13.2, 15.6, "放权是例外，不是默认。", 40, WHITE, 580, False,
             1.0, 14, 0.7, 0.4),
    ]))

    sc.append(Scene("board", 19.0, [
        Beat(0.8, 8.4, "RK3568 · OpenHarmony 5.0.3.135 · enforcing", 24,
             DIM, 930, False, 1.5, 10, 0.7, 0.3),
        Beat(9.8, 14.4, "采集路径不需要 PC。", 32, WHITE, 930, False, 1.0,
             12, 0.7, 0.4),
        Beat(14.8, 18.6, "触发动作仍由电脑发起。", 24, DIM, 930, False,
             1.0, 10, 0.6, 0.4),
    ], draw=draw_board))

    sc.append(Scene("parity", 14.0, [
        Beat(0.4, 4.8, "主机 Python。设备 C++。", 56, WHITE, 470),
        Beat(5.2, 9.4, "27,912 条查询。", 72, WHITE, 470),
        Beat(9.8, 13.6, "逐字节相同。", 72, ACCENT, 470),
        Beat(10.0, 13.6, "2,984,884 字节，两套实现", 24, DIM, 590, False,
             1.0, 10, 0.6, 0.4),
    ]))

    sc.append(Scene("limits", 14.0, [
        Beat(0.4, 13.2, "边界，也是设计的一部分。", 50, WHITE, 420),
        Beat(5.0, 13.4, "语料来自上游仓库，不是本机采集。", 28, DIM, 560,
             False, 1.0, 12, 0.7, 0.4),
        Beat(8.2, 13.4, "板端两秒，是外推，不是实测。", 28, DIM, 622,
             False, 1.0, 12, 0.7, 0.4),
        Beat(11.2, 13.4, "构造自洽，不等于独立金标准。", 28, DIM, 684,
             False, 1.0, 12, 0.7, 0.4),
    ]))

    sc.append(Scene("close", 13.0, [
        Beat(0.5, 5.9, "只给建议。", 62, WHITE, 430),
        Beat(2.3, 5.9, "不写盘。", 62, WHITE, 516),
        Beat(6.3, 12.4, "PolicyLoop", 46, WHITE, 560, True, 9, 18, 0.9,
             0.5, "lat"),
        Beat(6.9, 12.4, "SELinux 拒绝日志的最小权限自收敛", 26, DIM, 622,
             False, 1.2, 12, 0.8, 0.5),
        Beat(7.5, 12.4, "2026 开源鸿蒙大学生创新大赛 · 赛道一", 20, DIM,
             680, False, 1.2, 10, 0.8, 0.5),
    ]))
    return sc


DEMO: list[str] = []


# ── 原创氛围声 ────────────────────────────────────────────────
def synth_audio(total: float, events: list[float], path: Path) -> None:
    sr = 44100
    n = int(total * sr)
    t = np.arange(n, dtype=np.float64) / sr

    # 低频持续音：A1 / E2 / A2，缓慢呼吸
    lfo = 0.82 + 0.18 * np.sin(2 * np.pi * 0.027 * t + 0.4)
    drone = (0.075 * np.sin(2 * np.pi * 55.0 * t) +
             0.045 * np.sin(2 * np.pi * 82.4 * t + 0.7) +
             0.022 * np.sin(2 * np.pi * 110.0 * t + 1.9) +
             0.014 * np.sin(2 * np.pi * 164.8 * t + 0.3) +
             0.009 * np.sin(2 * np.pi * 220.0 * t + 2.4))
    drone = drone * lfo
    left = drone.copy()
    right = drone.copy()

    # 空气层：带通噪声，用频域掩码一次做完
    rng = np.random.default_rng(7)
    noise = rng.standard_normal(n).astype(np.float32)
    spec = np.fft.rfft(noise)
    freqs = np.fft.rfftfreq(n, 1 / sr)
    band = np.exp(-((np.log(np.maximum(freqs, 1)) - np.log(620)) ** 2) /
                  (2 * 0.55 ** 2))
    air = np.fft.irfft(spec * band, n=n).astype(np.float64)
    air /= max(1e-9, np.max(np.abs(air)))
    air *= 0.034 * (0.6 + 0.4 * np.sin(2 * np.pi * 0.019 * t + 2.1))
    left += air
    right += np.roll(air, 331)

    # 每次转场的低频冲击 + 一小段空气推进
    for ev in events:
        i0 = int(ev * sr)
        dur = int(2.2 * sr)
        if i0 >= n:
            continue
        m = min(dur, n - i0)
        tt = np.arange(m) / sr
        env = np.exp(-tt / 0.42) * (1 - np.exp(-tt / 0.012))
        f0 = 62 * np.exp(-tt / 0.55) + 30
        ph = 2 * np.pi * np.cumsum(f0) / sr
        thump = 0.16 * np.sin(ph) * env
        click_env = np.exp(-tt / 0.09) * (1 - np.exp(-tt / 0.004))
        click = 0.03 * rng.standard_normal(m) * click_env
        left[i0:i0 + m] += thump + click
        right[i0:i0 + m] += thump + click * 0.9

    # 结尾淡出、开头淡入
    fin = int(2.0 * sr)
    fout = int(3.5 * sr)
    ramp_in = np.linspace(0, 1, fin) ** 1.6
    ramp_out = np.linspace(1, 0, fout) ** 1.5
    left[:fin] *= ramp_in
    right[:fin] *= ramp_in
    left[-fout:] *= ramp_out
    right[-fout:] *= ramp_out

    mix = np.stack([left, right], axis=1)
    peak = max(1e-9, float(np.max(np.abs(mix))))
    mix = np.tanh(mix / peak * 1.2) * 0.40
    pcm = (np.clip(mix, -1, 1) * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(pcm.tobytes())


# ── 渲染 ──────────────────────────────────────────────────────
def render(scenes: list[Scene], out: Path, sound: bool = True) -> None:
    total = sum(s.dur for s in scenes)
    starts, acc = [], 0.0
    for s in scenes:
        starts.append(acc)
        acc += s.dur
    WORK.mkdir(parents=True, exist_ok=True)
    wav = WORK / "bed.wav"
    if sound:
        events = [0.9, 8.1, 21.0, 28.2, 34.5, 47.5, 67.8, 71.7, 75.6, 79.3,
                  91.0, 98.5, 117.5, 131.5, 145.5, 152.0]
        synth_audio(total, events, wav)
        print(f"声轨：{wav}  {wav.stat().st_size/1e6:.1f} MB")
    else:
        # 静音轨仍保留，避免平台拒收无音轨文件
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
    si = 0
    try:
        for f in range(n_frames):
            t = f / FPS
            while si + 1 < len(scenes) and t >= starts[si + 1]:
                si += 1
            s = scenes[si]
            local = t - starts[si]
            frame = bg_frame(t)
            if s.draw:
                s.draw(frame, local, s.dur)
            draw_beats(frame, s.beats, local)
            frame = ImageChops.multiply(frame, VIG)
            k = min(smooth(local / s.fade),
                    smooth((s.dur - local) / s.fade))
            if k < 0.996:
                frame = ImageEnhance.Brightness(frame).enhance(max(0.0, k))
            letterbox(frame)
            proc.stdin.write(frame.tobytes())
            if f % 250 == 0:
                print(f"  {t:6.1f}s / {total:.1f}s", flush=True)
    finally:
        proc.stdin.close()
        proc.wait()
    if proc.returncode != 0:
        sys.exit(f"ffmpeg 失败，见 {WORK/'ffmpeg.log'}")
    print(f"→ {out}  ({out.stat().st_size/1e6:.1f} MB, {total:.1f}s)")


def preview(scenes: list[Scene], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    starts, acc = [], 0.0
    for s in scenes:
        starts.append(acc)
        acc += s.dur
    marks = [(1.8, "01-title"), (6.0, "02-title-end"),
             (9.0, "03-statement-1"), (16.0, "04-statement-2"),
             (22.0, "05-statement-3"), (28.5, "06-thesis-a"),
             (32.0, "07-thesis-b"), (40.0, "08-arch"),
             (45.0, "09-arch-caption"), (52.0, "10-terminal-typing"),
             (62.0, "11-terminal-output"), (69.0, "12-number-5161"),
             (73.0, "13-number-4911"), (80.5, "14-number-0"),
             (84.5, "15-zero-lead"), (92.0, "16-big-zero"),
             (97.0, "17-zero-caption"), (101.0, "18-board-a"),
             (107.5, "19-board-b"), (115.0, "20-board-caption"),
             (120.0, "21-parity-a"), (124.0, "22-parity-b"),
             (130.0, "23-parity-c"), (134.0, "24-limits"),
             (140.5, "25-limits-lines"), (147.0, "26-close"),
             (151.0, "27-endcard"), (157.0, "28-fade")]
    for t, name in marks:
        si = max(i for i, st in enumerate(starts) if t >= st)
        s = scenes[si]
        local = t - starts[si]
        frame = bg_frame(t)
        if s.draw:
            s.draw(frame, local, s.dur)
        draw_beats(frame, s.beats, local)
        frame = ImageChops.multiply(frame, VIG)
        k = min(smooth(local / s.fade), smooth((s.dur - local) / s.fade))
        if k < 0.996:
            frame = ImageEnhance.Brightness(frame).enhance(max(0.0, k))
        letterbox(frame)
        frame.save(out_dir / f"{name}.png")
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
