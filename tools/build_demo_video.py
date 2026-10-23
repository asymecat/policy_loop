#!/usr/bin/env python3
"""生成 PolicyLoop 演示视频（约 3 分钟 / 1080p / AI 中文配音 + 字幕）。

素材全部来自仓库真实产物：
  - 终端段：实际执行 policy_loop.converge，逐行捕获 stdout；
  - 架构段：docs/figs/fig1-architecture.png；
  - 板端段：docs/screenshots/fig6/fig7（10-08 真机截图，标注「真机实录截图」）。

用法：
    python3 tools/build_demo_video.py                 # 输出 ~/下载/PolicyLoop-演示-20261018.mp4
    python3 tools/build_demo_video.py --preview /tmp/pv   # 只渲染每场景一帧，供版式检查
    python3 tools/build_demo_video.py --out /tmp/x.mp4

依赖：Pillow、edge-tts、mutagen、imageio-ffmpeg（见 README 说明）。
"""

from __future__ import annotations

import argparse
import hashlib
import math
import shutil
import subprocess
import sys
import unicodedata
import wave
from array import array
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

try:
    import imageio_ffmpeg
    from mutagen.mp3 import MP3
except ImportError as e:                                   # pragma: no cover
    sys.exit(f"缺少依赖：{e}. 先 pip install edge-tts mutagen imageio-ffmpeg pillow")

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SCR = DOCS / "screenshots"
OUT_DEFAULT = Path.home() / "下载" / "PolicyLoop-演示-20261018.mp4"

W, H = 1920, 1080
FPS = 25
FONT_R = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
FONT_B = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
FONT_M = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_IDX = 2                       # .ttc 里的简体中文面

INK = (15, 20, 35)
GRAY = (91, 100, 116)
MUTED = (138, 147, 163)
ACCENT = (0, 176, 240)
ACCENT_DARK = (0, 120, 180)
TINT = (234, 246, 253)
TINT2 = (245, 250, 254)
WHITE = (255, 255, 255)
RED = (229, 76, 94)
GREEN = (62, 166, 91)
ORANGE = (238, 130, 47)
TERM_BG = (14, 21, 38)
TERM_BAR = (28, 38, 58)

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
VOICE = "zh-CN-XiaoxiaoNeural"
TTS_RATE = "+3%"
WORK = Path("/tmp/policyloop-demo")


# ── 小工具 ────────────────────────────────────────────────────
_fonts: dict[tuple[int, bool], ImageFont.FreeTypeFont] = {}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    key = (size, bold)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(FONT_B if bold else FONT_R, size,
                                         index=FONT_IDX)
    return _fonts[key]


_mono: dict[int, ImageFont.FreeTypeFont] = {}


def mono(size: int) -> ImageFont.FreeTypeFont:
    if size not in _mono:
        _mono[size] = ImageFont.truetype(FONT_M, size)
    return _mono[size]


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if x < lo else hi if x > hi else x


def ease(x: float) -> float:
    x = clamp(x)
    return x * x * (3 - 2 * x)


def app(t: float, delay: float, dur: float = 0.55) -> float:
    """0→1 的缓动进度，用于元素依次出场。"""
    return ease((t - delay) / dur)


def wrap(d: ImageDraw.ImageDraw, text: str, f, max_w: float) -> list[str]:
    """按宽度折行；ASCII 尽量在空格处断，避免把路径/单词劈成两半。"""
    lines: list[str] = []
    for para in text.split("\n"):
        cur = ""
        for ch in para:
            if cur and d.textlength(cur + ch, font=f) > max_w:
                cut = cur.rfind(" ")
                if cut > len(cur) * 0.55 and (ch.isascii() or ch == " "):
                    lines.append(cur[:cut])
                    cur = cur[cut + 1:] + ch
                else:
                    lines.append(cur)
                    cur = ch
            else:
                cur += ch
        lines.append(cur)
    return lines


def para(d, x, y, text, size, color, max_w, line=1.55, bold=False):
    f = font(size, bold)
    for ln in wrap(d, text, f, max_w):
        d.text((x, y), ln, font=f, fill=color)
        y += size * line
    return y


def card(d, box, fill, outline=None, radius=24, width=2):
    d.rounded_rectangle(box, radius=radius, fill=fill,
                        outline=outline, width=width if outline else 0)


def chip(d, x, y, w, h, text, color, size=26, fill=TINT):
    card(d, (x, y, x + w, y + h), fill, radius=h // 2)
    d.text((x + w / 2, y + h / 2), text, font=font(size, True),
           fill=color, anchor="mm")


def image_fit(frame, path: Path, box, zoom=1.0, pan=0.5, border=None):
    im = Image.open(path).convert("RGB")
    bw, bh = box[2] - box[0], box[3] - box[1]
    scale = min(bw / im.width, bh / im.height) * zoom
    nw, nh = max(1, int(im.width * scale)), max(1, int(im.height * scale))
    im = im.resize((nw, nh), Image.LANCZOS)
    x = box[0] + (bw - nw) // 2
    y = box[1] + (bh - nh) // 2
    frame.paste(im, (x, y))
    if border:
        d = ImageDraw.Draw(frame)
        d.rectangle((x - 1, y - 1, x + nw, y + nh), outline=border, width=2)
    return (x, y, x + nw, y + nh)


# ── 场景定义 ──────────────────────────────────────────────────
@dataclass
class Scene:
    key: str
    chapter: str
    title: str
    narration: str
    min_dur: float
    draw: callable
    audio: Path | None = None
    audio_dur: float = 0.0
    chunks: list[str] = field(default_factory=list)
    dur: float = 0.0
    cues: list[tuple[float, float, str]] = field(default_factory=list)


def capture_converge() -> list[str]:
    """真实跑一遍收敛，拿 stdout（视频里的终端不是摆拍）。"""
    cmd = [sys.executable, "-m", "policy_loop.converge",
           "--log", "data/corpus/real_denials.txt",
           "--policy", "data/raw/oh-selinux/sepolicy",
           "--json", "/tmp/policyloop-demo-converge.json"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"converge 运行失败：{r.stderr[-500:]}")
    lines = [ln.rstrip() for ln in r.stdout.splitlines()]
    return lines[:14] + ["  …（共 70 类可自动修复，完整清单在报告里）"]


def s_title(frame, d, t, dur, sc):
    d.text((W / 2, 292), "2026 开源鸿蒙大学生创新大赛 · 赛道一",
           font=font(30), fill=GRAY, anchor="mm")
    d.text((W / 2, 372), "PolicyLoop", font=font(112, True), fill=INK, anchor="mm")
    d.text((W / 2, 505), "SELinux 拒绝日志的最小权限自收敛",
           font=font(48), fill=ACCENT_DARK, anchor="mm")
    w = int(240 * app(t, 0.55, 0.8))
    d.rounded_rectangle((W / 2 - w / 2, 592, W / 2 + w / 2, 598), 3, fill=ACCENT)
    d.text((W / 2, 655), "演 示 视 频", font=font(26), fill=MUTED, anchor="mm")


def s_problem(frame, d, t, dur, sc):
    cards = [
        ("读不懂", "scontext / tcontext / tclass\n权限位自成一套词汇，\n现场只看到「功能失败」。"),
        ("不知道在哪补", "规则散在 1,315 个 .te 文件里，\n一条 denial 该落 system/\n还是 vendor/，靠经验。"),
        ("补不对", "最省事的是「看到 denial 就加 allow」——\n把一次越权尝试\n固化成永久授权。"),
    ]
    for i, (head, body) in enumerate(cards):
        p = app(t, 0.15 + i * 0.28)
        y = 215 + 26 * (1 - p)
        x = 100 + i * 590
        card(d, (x, y, x + 530, y + 330), TINT2, TINT)
        d.text((x + 38, y + 34), head, font=font(40, True), fill=INK)
        para(d, x + 38, y + 110, body, 26, GRAY, 450, line=1.55)
    p = app(t, 1.15)
    y = 600 + 20 * (1 - p)
    card(d, (100, y, 1820, y + 92), INK, radius=16)
    d.text((140, y + 46), "现实中的应对：把门禁关成 permissive —— 系统看起来正常了，门实际上没有了。",
           font=font(30), fill=WHITE, anchor="lm")
    p = app(t, 1.5)
    d.text((100, 735), "上游策略仓库一次全量统计", font=font(24, True), fill=ACCENT_DARK)
    stats = ["1,315 个 .te", "51,427 行策略源码", "5,230 条历史 denial 注释", "21,824 条索引规则"]
    for i, s in enumerate(stats):
        chip(d, 100 + i * 425, 775, 390, 62, s, GRAY, size=24)


def s_goal(frame, d, t, dur, sc):
    items = [
        ("撞 neverallow", "一律拒绝自动放权"),
        ("补丁精确最小", "多一个权限位都算失败"),
        ("补完必须验证", "denial 消失，且没有新的越权"),
    ]
    for i, (h, b) in enumerate(items):
        p = app(t, 0.1 + i * 0.3)
        y = 235 + i * 150 + 18 * (1 - p)
        d.ellipse((104, y + 8, 148, y + 52), fill=ACCENT)
        d.text((126, y + 30), str(i + 1), font=font(24, True), fill=WHITE, anchor="mm")
        d.text((176, y), h, font=font(32, True), fill=INK)
        d.text((176, y + 48), b, font=font(24), fill=GRAY)
    box = (940, 195, 1830, 745)
    image_fit(frame, DOCS / "figs" / "fig1-architecture.png", box,
              border=(214, 228, 240))
    p = app(t, 0.9)
    y = 790 + 16 * (1 - p)
    card(d, (100, y, 1820, y + 84), TINT, radius=16)
    d.text((140, y + 42),
           "四层架构 · 主机端重、设备端轻 · 中间只有 PLI 只读索引（构建期导出、随镜像下发）",
           font=font(27, True), fill=ACCENT_DARK, anchor="lm")


def s_terminal(frame, d, t, dur, sc):
    lines = sc.extra                      # capture_converge() 的结果
    x0, y0, x1, y1 = 100, 180, 1820, 805
    card(d, (x0, y0, x1, y1), TERM_BG, radius=18)
    d.rounded_rectangle((x0, y0, x1, y0 + 46), radius=18, fill=TERM_BAR)
    d.rectangle((x0, y0 + 24, x1, y0 + 46), fill=TERM_BAR)
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse((x0 + 22 + i * 26, y0 + 16, x0 + 38 + i * 26, y0 + 32), fill=col)
    d.text((x0 + 120, y0 + 23), "policy_loop  ·  converge", font=font(22),
           fill=(170, 180, 200), anchor="lm")

    cmd = ('python -m policy_loop.converge --log data/corpus/real_denials.txt '
           '--policy data/raw/oh-selinux/sepolicy')
    typed = cmd[: int(clamp((t - 0.25) / 2.2) * len(cmd))]
    fx = font(23)
    d.text((x0 + 36, y0 + 72), "dev@host:~/policy_loop$", font=fx, fill=(88, 208, 141))
    pxy = x0 + 36 + d.textlength("dev@host:~/policy_loop$ ", font=fx)
    d.text((pxy, y0 + 72), typed, font=fx, fill=(226, 232, 240))
    if typed and len(typed) < len(cmd) and int(t * 3) % 2 == 0:
        cx = pxy + d.textlength(typed, font=fx)
        d.rectangle((cx + 2, y0 + 72, cx + 13, y0 + 100), fill=(226, 232, 240))

    # 输出：真实 stdout，逐行出现
    out_start = 2.8
    step = 0.38
    yy = y0 + 118
    for i, ln in enumerate(lines):
        if t < out_start + i * step:
            break
        color = (147, 160, 180)
        if ln.startswith("[PolicyLoop converge] policy"):
            color = (120, 220, 170)
        elif "WARNING" in ln:
            color = (250, 196, 120)
        elif ln.startswith("denials="):
            color = (230, 236, 246)
        elif ln.startswith("#"):
            color = (120, 210, 255)
        elif ln.startswith("  …"):
            color = (140, 150, 165)
        for part in wrap(d, ln, fx, x1 - x0 - 72):
            if yy > y1 - 34:
                break
            d.text((x0 + 36, yy), part, font=fx, fill=color)
            yy += 31

    p = app(t, 8.8)
    if p > 0:
        y = 822 + 16 * (1 - p)
        chips = [("5,161 → 4,911  唯一案例", ACCENT_DARK),
                 ("70  可自动最小修复", GREEN),
                 ("1,580  需人工决策", ORANGE)]
        for i, (s, col) in enumerate(chips):
            chip(d, 100 + i * 480, y, 450, 62, s, col, size=25, fill=TINT2)


def s_zero(frame, d, t, dur, sc):
    p = app(t, 0.1, 0.8)
    r = int(165 * (0.85 + 0.15 * p))
    cx, cy = 340, 390
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(232, 247, 238),
              outline=GREEN, width=4)
    d.text((cx, cy - 8), "0", font=font(int(170 * (0.9 + 0.1 * p)), True),
           fill=GREEN, anchor="mm")
    d.text((cx, cy + 205), "owner = DEVICE", font=font(26, True), fill=GRAY, anchor="mm")
    d.text((cx, cy + 243), "真正需要给设备补权限的条数", font=font(22), fill=MUTED, anchor="mm")

    items = [("1,147", "语料的历史噪声", MUTED),
             ("342", "工具侧要对齐的（索引 / 版本）", ACCENT_DARK),
             ("53", "日志质量问题", ORANGE),
             ("38", "架构决策（撞 neverallow 红线）", RED)]
    for i, (n, l, col) in enumerate(items):
        q = app(t, 0.35 + i * 0.18)
        x = 680 + (i % 2) * 570
        y = 225 + (i // 2) * 175 + 14 * (1 - q)
        card(d, (x, y, x + 535, y + 150), WHITE, TINT)
        d.text((x + 32, y + 32), n, font=font(44, True), fill=col)
        para(d, x + 32, y + 92, l, 22, GRAY, 470, line=1.3)

    p = app(t, 1.1)
    y = 665 + 14 * (1 - p)
    card(d, (100, y, 1820, y + 78), TINT, radius=14)
    d.text((136, y + 39), "1,580 条全部有 owner，0 条落进「其他」兜底。",
           font=font(27, True), fill=ACCENT_DARK, anchor="lm")
    y2 = y + 96
    d.text((100, y2), "自动补丁：", font=font(26, True), fill=INK)
    d.text((240, y2), "69 行 → 54 条根因规则", font=font(26), fill=GRAY)
    d.text((620, y2), "闭环反验：", font=font(26, True), fill=INK)
    d.text((760, y2), "70 → 0 未解决", font=font(26), fill=GREEN)


def s_parity(frame, d, t, dur, sc):
    panels = [
        (100, "宿主 Python", "policy_loop", TINT),
        (980, "设备 C++ / musl", "denial_check", (232, 247, 238)),
    ]
    for i, (x, head, sub, fill) in enumerate(panels):
        p = app(t, 0.15 + i * 0.25)
        y = 220 + 20 * (1 - p)
        card(d, (x, y, x + 840, y + 390), fill, radius=20)
        d.text((x + 40, y + 32), head, font=font(36, True), fill=INK)
        d.text((x + 40, y + 82), sub, font=font(24), fill=MUTED)
        rows = [("查询", "27,912 条"), ("输出", "2,984,884 B"), ("sha256", "逐字节相同")]
        for j, (k, v) in enumerate(rows):
            d.text((x + 40, y + 150 + j * 70), k, font=font(25), fill=GRAY)
            d.text((x + 220, y + 150 + j * 70), v, font=font(28, True), fill=INK)
    d.text((960, 415), "=", font=font(72, True), fill=ACCENT, anchor="mm")

    p = app(t, 0.9)
    y = 660 + 16 * (1 - p)
    d.text((100, y), "五项门禁：自检 · 索引计数 · 报告差分 · 真机采样 · 查询差分",
           font=font(26), fill=GRAY)
    chip(d, 100, y + 60, 430, 64, "设备查询 34×", ACCENT_DARK, size=26)
    chip(d, 560, y + 60, 430, 64, "宿主判定 238×", ACCENT_DARK, size=26)


def s_board(frame, d, t, dur, sc):
    d.text((100, 178), "真机实录截图 · RK3568 · OpenHarmony 5.0.3.135 · enforcing",
           font=font(22), fill=MUTED)
    zoom = 1.0 + 0.04 * clamp(t / max(dur, 0.1))
    b1 = image_fit(frame, SCR / "fig6-board-live-cards.png",
                   (160, 215, 560, 835), zoom=zoom, border=(205, 218, 232))
    b2 = image_fit(frame, SCR / "fig7-board-snapshot.png",
                   (620, 215, 1020, 835), zoom=zoom, border=(205, 218, 232))
    d.text(((b1[0] + b1[2]) / 2, 860), "板端控制台 · 实时卡片",
           font=font(23), fill=GRAY, anchor="mm")
    d.text(((b2[0] + b2[2]) / 2, 860), "板端控制台 · 载入当前快照",
           font=font(23), fill=GRAY, anchor="mm")

    facts = [
        ("合法身份", "正规 init service，开机自启，\n运行在自己的 enforcing 域"),
        ("端到端", "拨一次开关，1~2 秒出结论\n（两个 1 秒轮询叠加）"),
        ("采集不依赖 PC", "采集路径上没有任何一环\n需要 PC；演示触发仍由 PC 发起"),
    ]
    for i, (h, b) in enumerate(facts):
        p = app(t, 0.3 + i * 0.22)
        y = 230 + i * 190 + 16 * (1 - p)
        card(d, (1120, y, 1820, y + 165), TINT2, TINT)
        d.text((1156, y + 22), h, font=font(28, True), fill=ACCENT_DARK)
        para(d, 1156, y + 68, b, 24, GRAY, 620, line=1.45)


def s_denial(frame, d, t, dur, sc):
    x0, y0, x1, y1 = 100, 200, 1180, 620
    card(d, (x0, y0, x1, y1), TERM_BG, radius=18)
    d.rounded_rectangle((x0, y0, x1, y0 + 44), radius=18, fill=TERM_BAR)
    d.rectangle((x0, y0 + 22, x1, y0 + 44), fill=TERM_BAR)
    d.text((x0 + 30, y0 + 22), "真机日志  ·  /dev/kmsg", font=font(21),
           fill=(170, 180, 200), anchor="lm")

    lines = [
        ('avc: denied { read } for pid=7781 comm="media_service"', (226, 232, 240)),
        ("scontext=u:r:media_service:s0", (120, 210, 255)),
        ("tcontext=u:object_r:camera_device:s0", (120, 220, 170)),
        ("tclass=chr_file  permissive=0", (250, 196, 120)),
    ]
    for i, (ln, col) in enumerate(lines):
        if app(t, 0.12 + i * 0.16) <= 0:
            continue
        d.text((x0 + 36, y0 + 80 + i * 64), ln, font=mono(27), fill=col)

    qs = [
        ("谁访问了什么", "media_service → camera_device:chr_file"),
        ("缺哪项权限", "read"),
        ("规则改在哪", "对应子系统的 .te 文件"),
        ("授权会扩大吗", "按展开后的影响面判断"),
    ]
    for i, (h, b) in enumerate(qs):
        p = app(t, 0.85 + i * 0.22)
        y = 200 + i * 121 + 14 * (1 - p)
        card(d, (1240, y, 1820, y + 108), TINT2, TINT)
        d.rounded_rectangle((1240, y, 1248, y + 108), radius=4, fill=ACCENT)
        d.text((1276, y + 16), h, font=font(25, True), fill=INK)
        para(d, 1276, y + 55, b, 19, GRAY, 510, line=1.25)

    p = app(t, 2.0)
    y = 690 + 14 * (1 - p)
    card(d, (100, y, 1820, y + 76), INK, radius=16)
    d.text((140, y + 38), "四个问题都答完，才谈得上一条可落地的补丁。",
           font=font(30, True), fill=WHITE, anchor="lm")


def s_patch(frame, d, t, dur, sc):
    x0 = 100
    card(d, (x0, 205, 900, 425), (255, 244, 245), (245, 205, 210))
    d.text((x0 + 34, 230), "×  再加一条 allow", font=font(28, True), fill=RED)
    d.text((x0 + 34, 286), "allow render_service dev_mali:chr_file ioctl;",
           font=mono(20), fill=INK)
    para(d, x0 + 34, 336, "大类权限早已允许，这条不改变判定。",
         22, GRAY, 760)

    card(d, (x0, 460, 900, 690), (240, 252, 246), (198, 235, 212))
    d.text((x0 + 34, 485), "√  补 allowxperm", font=font(28, True), fill=GREEN)
    d.text((x0 + 34, 541), "allowxperm render_service dev_mali:chr_file",
           font=mono(20), fill=INK)
    d.text((x0 + 34, 578), "    ioctl { 0x8014 };", font=mono(20), fill=INK)
    para(d, x0 + 34, 624, "只放开这一个命令号。", 22, GRAY, 760)

    card(d, (960, 205, 1820, 690), TINT2, TINT)
    d.text((1000, 236), "这条补丁要过的检查", font=font(28, True), fill=INK)
    rows = [("命中 neverallow", "转人工", RED),
            ("目标解析后仍不允许", "拒发补丁", ORANGE),
            ("占位符无法确定", "转人工", ORANGE),
            ("评审判定过宽", "否决", RED),
            ("反验：denial 消失、无新增越权", "通过", GREEN)]
    for i, (k, v, col) in enumerate(rows):
        p = app(t, 0.5 + i * 0.2)
        y = 300 + i * 72 + 12 * (1 - p)
        d.ellipse((1002, y + 10, 1022, y + 30), fill=col)
        d.text((1040, y), k, font=font(23), fill=GRAY)
        d.text((1796, y + 12), v, font=font(23, True), fill=col, anchor="rm")

    p = app(t, 1.7)
    y = 720 + 14 * (1 - p)
    card(d, (100, y, 1820, y + 72), TINT, radius=14)
    d.text((140, y + 36), "最窄按展开后的影响面判断，不按补丁长短。",
           font=font(28, True), fill=ACCENT_DARK, anchor="lm")


def s_limits(frame, d, t, dur, sc):
    items = [
        ("语料来自上游，不是本设备采集", "5,230 条注释全部以 # 开头，评测的是历史真实 denial"),
        ("外推值一律标注", "板端 71.25 s → 约 2 s 是按 34× 外推，不是测量"),
        ("构造内自洽 ≠ 独立金标准", "exact_min=100% 是自洽性验证，独立证据只有人工修复与真机"),
        ("未做但已证伪的，写证伪", "boolean / constrain / MLS 在本平台原理上无从发生"),
    ]
    for i, (h, b) in enumerate(items):
        p = app(t, 0.12 + i * 0.23)
        y = 215 + i * 130 + 18 * (1 - p)
        d.rounded_rectangle((104, y + 10, 112, y + 46), 4, fill=ACCENT)
        d.text((140, y), h, font=font(32, True), fill=INK)
        d.text((140, y + 46), b, font=font(23), fill=GRAY)
    p = app(t, 1.1)
    y = 780 + 16 * (1 - p)
    card(d, (100, y, 1820, y + 88), INK, radius=16)
    d.text((140, y + 44), "把判断交给确定性规则，把授权留给人。",
           font=font(31, True), fill=WHITE, anchor="lm")


def s_thanks(frame, d, t, dur, sc):
    d.text((W / 2, 470), "谢  谢", font=font(120, True), fill=WHITE, anchor="mm")
    d.text((W / 2, 610), "PolicyLoop · 2026 开源鸿蒙大学生创新大赛 · 赛道一",
           font=font(30), fill=(225, 245, 255), anchor="mm")


# ── v5：录屏式演示 ────────────────────────────────────────────
# 不出现章节标题与统计数字，只演一次真实运行：敲命令 → 真实输出 → 板端界面。
MONO_CJK_IDX = 7                   # NotoSansCJK-Regular.ttc 里的 Mono SC 面
FONT_MC = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"

_mono_cjk: dict[int, ImageFont.FreeTypeFont] = {}


def tmono(size: int) -> ImageFont.FreeTypeFont:
    if size not in _mono_cjk:
        _mono_cjk[size] = ImageFont.truetype(FONT_MC, size, index=MONO_CJK_IDX)
    return _mono_cjk[size]


CMD = ("python -m policy_loop.converge --log examples/board-denials.log "
       "--policy data/raw/oh-selinux/sepolicy")
TITLE_H = 46
TERM_PX = 32


def demo_lines() -> list[str]:
    """演示用的日志真实跑一遍，终端里的输出不是手写的。"""
    cmd = [sys.executable, "-m", "policy_loop.converge",
           "--log", "examples/board-denials.log",
           "--policy", "data/raw/oh-selinux/sepolicy"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"converge 运行失败：{r.stderr[-500:]}")
    return [ln.rstrip() for ln in r.stdout.splitlines()]


def _cells(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def _cell_chunks(s: str, maxc: int) -> list[str]:
    """按终端列宽硬折行（真实终端的行为），CJK 记 2 列。"""
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


def _word_chunks(s: str, maxc: int) -> list[str]:
    """按词折行：空间够就整词带走，避免把 sepolicy 这种词劈成两半。"""
    out, cur = [], ""
    for word in s.split(" "):
        cand = (cur + " " + word) if cur else word
        if _cells(cand) > maxc and cur:
            out.append(cur)
            cur = word
        else:
            cur = cand
    out.append(cur)
    return out


def _out_color(ln: str):
    if ln.startswith("[PolicyLoop converge] policy"):
        return (120, 220, 170)
    if "WARNING" in ln:
        return (250, 196, 120)
    if ln.startswith("denials="):
        return (230, 236, 246)
    if ln.startswith("#"):
        return (120, 210, 255)
    if ln.startswith("  allow"):
        return (146, 226, 176)
    if ln.startswith("  ["):
        return (235, 168, 128)
    return (147, 160, 180)


def term_image(typed: str, lines: list[str], n_out: int, size: int,
               w: int, h: int, cursor: bool = False, blink: bool = True
               ) -> tuple[Image.Image, list[int]]:
    """画一个终端窗口；返回图与每条输出的首行 y（供标注定位）。"""
    f = tmono(size)
    cell = f.getlength("M")
    lh = int(size * 1.55)
    maxc = int((w - 2 * TERM_PX) // cell)
    im = Image.new("RGB", (w, h), TERM_BG)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, w - 1, h - 1), radius=16, fill=TERM_BG,
                        outline=(58, 70, 92), width=2)
    d.rounded_rectangle((2, 2, w - 3, TITLE_H), radius=14, fill=TERM_BAR)
    d.rectangle((2, TITLE_H - 14, w - 3, TITLE_H), fill=TERM_BAR)
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse((20 + i * 26, 16, 36 + i * 26, 32), fill=col)
    d.text((w / 2, TITLE_H / 2), "dev@host: ~/policy_loop — zsh",
           font=font(18), fill=(168, 178, 198), anchor="mm")

    prompt = "dev@host:~/policy_loop$ "
    y = TITLE_H + 26
    chunks = _word_chunks(prompt + typed, maxc)
    for i, ck in enumerate(chunks):
        if i == 0:
            d.text((TERM_PX, y), prompt, font=f, fill=(88, 208, 141))
            d.text((TERM_PX + cell * len(prompt), y), ck[len(prompt):],
                   font=f, fill=(226, 232, 240))
        else:
            d.text((TERM_PX, y), ck, font=f, fill=(226, 232, 240))
        y += lh
    if cursor and blink:
        last = chunks[-1]
        cx = TERM_PX + (cell * len(prompt) if len(chunks) == 1 else 0) \
            + d.textlength(last if len(chunks) > 1 else last[len(prompt):], font=f)
        d.rectangle((cx + 2, y - lh + 4, cx + cell - 2, y - 6),
                    fill=(226, 232, 240))

    ys: list[int] = []
    for i in range(min(n_out, len(lines))):
        ys.append(y)
        for part in _cell_chunks(lines[i], maxc):
            if y > h - lh:
                break
            d.text((TERM_PX, y), part, font=f, fill=_out_color(lines[i]))
            y += lh
    return im, ys


def s_rec_term(frame, d, t, dur, sc):
    """桌面 → 终端窗口 → 逐字敲命令 → 真实输出逐行出现。"""
    lines = sc.extra
    n_typed = max(0, min(len(CMD), int((t - 3.4) / 0.050)))
    typed = CMD[:n_typed]
    if t < 8.9:
        n_out = 0
    else:
        n_out = min(len(lines), 1 + int((t - 8.9) / 0.40))
    img, _ = term_image(typed, lines, n_out, 21, 1740, 800,
                        cursor=(3.4 <= t < 9.3 and len(typed) < len(CMD)),
                        blink=int(t * 2.2) % 2 == 0)
    y = 70 + int(10 * (1 - ease(clamp(t / 0.7))))
    frame.paste(img, (90, y))


def s_rec_zoom(frame, d, t, dur, sc):
    """同一条命令的输出放大一档，圈出其中那条 allowxperm。"""
    lines = sc.extra
    img, ys = term_image(CMD, lines, len(lines), 30, 1880, 1040)
    frame.paste(img, (20, 20))
    idx = next((i for i, ln in enumerate(lines) if "allowxperm" in ln), -1)
    if idx < 0 or idx >= len(ys):
        return
    y0 = 20 + ys[idx] - 8
    y1 = 20 + (ys[idx + 1] if idx + 1 < len(ys) else ys[idx] + 37 * 2) - 8
    p = app(t, 0.25, 0.5)
    x_end = 46 + int((1874 - 46) * p)
    dr = ImageDraw.Draw(frame, "RGBA")           # RGBA 画笔才会做半透明叠加
    dr.rounded_rectangle((46, y0, x_end, y1), radius=8, fill=(30, 120, 90, 70))
    dr.rounded_rectangle((46, y0, 52, y1), radius=3, fill=(64, 208, 152, 255))

    q = app(t, 0.65, 0.45)
    if q <= 0:
        return
    label = "只放开 0x6206 一个命令号"
    f = font(22, True)
    tw = d.textlength(label, font=f)
    pw = int((tw + 60) * q)
    ph = 44
    # 优先贴着这行文字的末尾放；放不下就退到高亮带下方右侧
    text_end = 52 + d.textlength(lines[idx], font=tmono(32))
    px = int(text_end + 24)
    py = y0 + (y1 - y0 - ph) / 2
    if px + pw > 1874:
        px = int(1874 - pw)
        py = y1 + 10
    dr.rounded_rectangle((px, py, px + pw, py + ph), radius=ph / 2,
                         fill=(18, 96, 76, 240))
    if q > 0.55:
        d.text((px + 30, py + ph / 2), label, font=f, fill=(226, 255, 244),
               anchor="lm")


def _round_paste(frame, path: Path, box, radius=18, border=(70, 82, 104),
                 crop_h: int | None = None):
    """把截图裁掉下半截（长截图里最有信息的是上半屏），再圆角贴进画面。"""
    im = Image.open(path).convert("RGB")
    if crop_h:
        im = im.crop((0, 0, im.width, min(crop_h, im.height)))
    bw, bh = box[2] - box[0], box[3] - box[1]
    s = min(bw / im.width, bh / im.height)
    im = im.resize((int(im.width * s), int(im.height * s)), Image.LANCZOS)
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, im.width - 1, im.height - 1),
                                           radius=radius, fill=255)
    x = box[0] + (bw - im.width) // 2
    y = box[1] + (bh - im.height) // 2
    frame.paste(im, (x, y), mask)
    fade_h = min(90, im.height // 3)          # 底部渐隐，暗示还有下半屏
    ramp = Image.new("L", (1, fade_h))
    for i in range(fade_h):
        ramp.putpixel((0, i), int(255 * (i / fade_h) ** 1.5))
    veil = Image.new("RGB", (im.width, fade_h), (20, 24, 34))
    frame.paste(veil, (x, y + im.height - fade_h), ramp.resize((im.width, fade_h)))
    dd = ImageDraw.Draw(frame)
    dd.rounded_rectangle((x - 1, y - 1, x + im.width, y + im.height),
                         radius=radius + 1, outline=border, width=2)
    return im.width, im.height, x, y, s


def _cursor(d, x: float, y: float, s: float = 1.6):
    """一只鼠标指针（白描边的黑箭头），让「点一下」看得出来是谁点的。"""
    pts = [(0, 0), (0, 17), (4.4, 13), (7.6, 20), (10.4, 18.6), (7.3, 12),
           (13, 12)]
    poly = [(x + px * s, y + py * s) for px, py in pts]
    d.polygon(poly, fill=(18, 22, 30), outline=None)
    d.line(poly + [poly[0]], fill=(240, 244, 250), width=3, joint="curve")


def s_rec_board(frame, d, t, dur, sc):
    """板端界面：两张真机截图，点一下「载入当前快照」。"""
    _round_paste(frame, SCR / "fig6-board-live-cards.png", (270, 96, 910, 886),
                 crop_h=880)
    bw, bh, bx, by, s = _round_paste(frame, SCR / "fig7-board-snapshot.png",
                                     (1010, 96, 1650, 886), crop_h=880)
    d.text((590, 918), "运行时卡片", font=font(23), fill=MUTED, anchor="mm")
    d.text((1330, 918), "载入当前快照", font=font(23), fill=MUTED, anchor="mm")

    # 点按波纹：图内按钮中心 (269.5, 291.5)，按缩放比映射到屏幕上
    cx = bx + int(269.5 * s)
    cy = by + int(291.5 * s)
    dr = ImageDraw.Draw(frame, "RGBA")

    def cur_pos(t0, ox, oy):
        u = clamp((t - t0) / 0.9)
        return cx + (1 - ease(u)) * ox, cy + (1 - ease(u)) * oy

    # 指针先滑到按钮上，点一下；停在那里，第二次再滑过来点
    if t >= 9.6 - 0.9:
        _cursor(dr, *cur_pos(9.6 - 0.9, -280, 180))
    elif t >= 5.2 - 0.9:
        _cursor(dr, *cur_pos(5.2 - 0.9, 300, 220))
    for start in (5.2, 9.6):
        u = (t - start) / 1.1
        if 0 <= u <= 1:
            r = 12 + 46 * u
            dr.ellipse((cx - r, cy - r, cx + r, cy + r),
                       outline=(120, 190, 255, int(230 * (1 - u))), width=4)

    p = app(t, 0.4, 0.6)
    if p > 0:
        y = 60 + int(12 * (1 - p))
        d.text((W / 2, y), "RK3568 · OpenHarmony 5.0.3.135 · enforcing",
               font=font(24), fill=(150, 162, 180), anchor="mm")


def s_rec_close(frame, d, t, dur, sc):
    p = app(t, 0.15, 0.7)
    d.text((W / 2, 430), "只给建议，不写盘。", font=font(76, True), fill=WHITE,
           anchor="mm")
    if p > 0:
        d.text((W / 2, 552), "写进策略之前，由开发者显式执行。",
               font=font(34), fill=(200, 216, 232), anchor="mm")
    d.text((W / 2, 742), "PolicyLoop", font=font(38, True), fill=(120, 208, 255),
           anchor="mm")
    d.text((W / 2, 792), "2026 开源鸿蒙大学生创新大赛 · 赛道一",
           font=font(24), fill=(140, 152, 170), anchor="mm")


def make_desk() -> Image.Image:
    top, bot = (16, 19, 27), (27, 33, 46)
    im = Image.new("RGB", (W, H))
    d = ImageDraw.Draw(im)
    for y in range(H):
        k = y / (H - 1)
        d.line((0, y, W, y), fill=tuple(int(top[i] + (bot[i] - top[i]) * k)
                                        for i in range(3)))
    return im


DESK = make_desk()


def scenes_v5() -> list[Scene]:
    """录屏式：一条命令从头跑到尾，不出现章节标题与统计数字。"""
    lines = demo_lines()
    sc = [
        Scene("rec_term", "", "",
              "PolicyLoop。下面的画面是一次真实运行：先跑一条命令。输入是板子上抓到的六条拒绝日志；几秒后输出，四条能自动生成最小权限补丁，一条是噪声，一条要人判断。",
              20.0, s_rec_term),
        Scene("rec_zoom", "", "",
              "看其中一条。sensor_host 读 hdf 传感器节点，缺的是一个 ioctl 命令号，0x6206。补一条通用 allow 没有意义；最小修法，是把这一个命令号单独放开。",
              17.0, s_rec_zoom),
        Scene("rec_board", "", "",
              "板子上跑的是同一套判定，编进应用里，不连电脑。板端读到 denial，卡片上直接给出建议。采集路径不需要 PC；但演示里触发拒绝的动作，仍由电脑发起。",
              21.0, s_rec_board),
        Scene("rec_close", "", "",
              "工具只给建议，不写盘。写不写进策略，由开发者签字。",
              9.0, s_rec_close),
    ]
    sc[0].extra = lines
    sc[1].extra = lines
    return sc


def scenes_v6() -> list[Scene]:
    """混合定稿：真实运行冷开场 → 问题/架构/实测/真机/边界，无旁白只留字幕。"""
    lines = demo_lines()
    sc = [
        Scene("title", "", "", "", 7.0, s_title),
        Scene("rec_term", "", "",
              "下面的画面不是动画，是一次真实运行。"
              "输入是板子上抓到的六条拒绝日志。"
              "四类可以自动生成最小权限补丁，一类是噪声，一类需要人工判断。"
              "工具只给建议，不写盘。",
              23.0, s_rec_term),
        Scene("problem", "01 · 问题", "一条 denial，卡住三件事",
              "一条 denial 出现时，通常卡住三件事。"
              "读不懂：scontext、tcontext、tclass 自成一套词汇。"
              "不知道在哪补：规则散在一千三百一十五个 .te 文件里。"
              "补不对：看到 denial 就加 allow，会把一次越权尝试固化成永久授权。"
              "现实中的应对，往往是切到 permissive，门禁整体失效。",
              28.0, s_problem),
        Scene("goal", "02 · 目标与架构", "从「放行」到「该不该放行」",
              "我们把问题重新定义：不问能不能放行，而问该不该放行。"
              "撞 neverallow 红线的一律拒绝自动放权。"
              "补丁按根因级最小集生成，补完反验两件事：原 denial 消失，且没有新增越权。"
              "主机承担索引与编排，设备端只保留采集、判定和展示。",
              25.0, s_goal),
        Scene("zero", "03 · 实测", "1,580 条「转人工」，真正要补权限的是 0 条",
              "五千一百六十一条真实 denial，去重后四千九百一十一个案例。"
              "三千二百六十一条是噪声或本就被允许，七十类可以自动修复，一千五百八十条转人工。"
              "转人工不等于要补权限：逐条归因后，真正需要给设备补权限的是零条。"
              "六十九行候选归并为五十四条根因规则，套回索引，未解决案例从七十降到零。",
              29.0, s_zero),
        Scene("parity", "03 · 实测", "同一份判定，两个进程，逐字节相同",
              "设备端是独立的 C++ 实现，不是主机程序的移植。"
              "两万七千九百一十二条查询、两点九八兆字节输出，两端逐字节相同。"
              "倒排索引让设备查询快三十四倍，主机判定快二百三十八倍。",
              24.0, s_parity),
        Scene("rec_board", "", "",
              "真机 RK3568，OpenHarmony 5.0.3.135，enforcing。"
              "采集器是标准的 init service，开机自启，运行在自己的域里。"
              "板端读到 denial，直接在卡片上给出建议。"
              "采集路径不需要 PC；演示里触发拒绝的动作，仍由电脑发起。",
              25.0, s_rec_board),
        Scene("limits", "04 · 边界", "口径与边界：每个数字能证明什么",
              "评测语料来自上游仓库中的真实注释，不是在本设备上采集。"
              "板端约两秒是按三十四倍外推，不是实测。"
              "构造数据上的自洽，不能替代独立金标准。"
              "把判断交给确定性规则，把授权留给人。",
              22.0, s_limits),
        Scene("rec_close", "", "",
              "只给建议，不写盘。写不写进策略，由开发者签字。",
              8.0, s_rec_close),
    ]
    sc[1].extra = lines
    return sc


def scenes() -> list[Scene]:
    term = capture_converge()
    return [
        Scene("title", "", "", "各位评委老师好，我们是 PolicyLoop。我们把 OpenHarmony 的拒绝日志，整理成可以逐项核对的修复建议。",
              10.0, s_title),
        Scene("problem", "01 · 问题", "一条 denial，卡住三件事",
              "SELinux 是强制访问控制。一条 denial 出现时，通常卡住三件事：判断不了该不该放行，定位不到在哪条规则上修，也无法验证修完是否安全。两种常见处理都不成立：直接加 allow，会把一次越权尝试变成永久授权；切到 permissive，门禁整体失效，日志却不再报错。",
              22.0, s_problem),
        Scene("goal", "02 · 目标与架构", "从「放行」到「该不该放行」",
              "我们把问题重新定义：不问能不能放行，而问该不该放行。与系统红线冲突的，一律不自动放行。补丁要求根因级最小集，并在闭环里验证两件事：原 denial 消失，且没有引入新的越权。模型只出候选，写策略仍由开发者显式执行。主机承担索引、编排与评测，设备端只保留采集与判定。",
              22.0, s_goal),
        Scene("terminal", "03 · 实测", "真实运行：整份日志，一次收敛",
              "先看一次真实运行。输入是上游策略仓库里的五千一百六十一条真实 denial，一次批量收敛，去重后是四千九百一十一个唯一案例。其中三千二百六十一条属于噪声或本就被允许，七十类可以生成最小权限补丁，一千五百八十类需要人来决定。",
              22.5, s_terminal),
        Scene("zero", "03 · 实测", "1,580 条「转人工」，真正要补权限的是 0 条",
              "这一千五百八十条是工具主动交回给人，而不是处理不了。逐条归因的结果是：真正需要给设备补权限的为零条。留一抽样里，一百七十九个候选补丁全部精确最小，二百二十一个命中红线的案例全部被拦。六十九行候选归并为五十四条根因规则，套回索引反验，原问题全部消除。",
              19.0, s_zero),
        Scene("parity", "03 · 实测", "同一份判定，两个进程，逐字节相同",
              "设备端是独立的 C++ 实现，不是主机程序的移植。我们用五项门禁证明两端同源，其中最强的一条是：两万七千九百一十二条查询、两点九八兆字节输出，逐字节相同。倒排索引带来的加速是设备查询三十四倍、主机判定二百三十八倍。",
              20.5, s_parity),
        Scene("board", "04 · 真机", "真机：拨一次开关，1~2 秒出结论",
              "真机上，采集器是一个标准的 init service，开机自启，运行在自己的 enforcing 域里。拨一次开关，一到两秒给出结论。采集链路不需要 PC；但演示里触发拒绝的动作，目前仍依赖 PC。由工具自身产生的 denial 会被标注出来，不混进分析结果。",
              19.0, s_board),
        Scene("limits", "05 · 边界", "口径与边界：每个数字能证明什么",
              "最后是边界。评测语料来自上游仓库中的真实注释，并非在本设备上采集；索引、编译树与系统版本要分别记录；构造数据上的自洽，不能替代独立金标准。",
              11.8, s_limits),
        Scene("thanks", "", "", "",
              4.0, s_thanks),
    ]


def scenes_v4() -> list[Scene]:
    """完全独立的一版：跟着一条真实 denial 走完全程，不套答辩 PPT 的结构。"""
    return [
        Scene("title", "", "", "各位评委老师好，我们是 PolicyLoop。接下来，我们跟着一条真实的拒绝日志，走完从日志到补丁的全过程。",
              10.0, s_title),
        Scene("denial", "01 · 一条日志", "一条 denial，四个问题",
              "这是上游策略仓库里的一条真实 denial：media_service 要读 camera_device，被内核拒绝。要处理的不是这一行字，而是四个问题：谁访问了什么，缺哪项权限，规则该改在哪份 .te 里，以及这次授权会不会扩大访问范围。",
              14.0, s_denial),
        Scene("goal", "02 · 判断", "先问该不该，再看能不能",
              "先问该不该放行，再看能不能放行。撞系统红线的一律不自动放权；补丁按根因级最小集生成；补完在索引副本里反验两件事：denial 消失，且没有新的越权。七个阶段单向执行，评审否决或反验失败就转人工。",
              14.0, s_goal),
        Scene("patch", "03 · 一条补丁", "缺的不是 allow，是 allowxperm",
              "举个例子：render_service 访问 dev_mali，大类权限早已允许，缺的只是一个 ioctl 命令号 0x8014。再加一条 allow 没有用，正确的最小修法是补这一条 allowxperm。",
              14.0, s_patch),
        Scene("terminal", "04 · 整批", "放到五千条日志里看",
              "把这条日志放到整批里看：五千一百六十一条真实日志，去重后四千九百一十一个案例；三千二百六十一个是噪声或已允许，一千五百八十个转人工，七十个能生成最小补丁。",
              16.0, s_terminal),
        Scene("zero", "04 · 整批", "转人工，不等于要补权限",
              "一千五百八十个转人工项逐条追到处理责任，落到设备补权限的是零条；六十九行候选归并为五十四条根因规则，套回索引全部消除。",
              14.0, s_zero),
        Scene("parity", "05 · 两端", "两份实现，逐字节相同",
              "设备端是独立的 C++ 实现。两万七千九百一十二条查询、两点九八兆字节输出，两端逐字节相同；倒排索引让设备查询快三十四倍，主机判定快二百三十八倍。",
              15.0, s_parity),
        Scene("board", "06 · 真机", "拨一次开关，1~2 秒出结论",
              "真机上，采集器是 init service，开机就在 enforcing 域里运行。拨一次开关，一到两秒出结论；采集链路不需要 PC，演示触发仍由 PC 发起。",
              15.0, s_board),
        Scene("limits", "07 · 边界", "每个数字能证明什么",
              "最后是边界：语料来自上游注释，不是本设备采集；板端约两秒是外推值；构造内自洽不能替代独立金标准。",
              12.0, s_limits),
        Scene("thanks", "", "", "",
              4.0, s_thanks),
    ]


# 终端内容挂在 scene 上（dataclass 追加字段，避免函数签名到处传）
Scene.extra = None                                        # type: ignore[attr-defined]
Scene.t0 = 0.0                                            # type: ignore[attr-defined]


# ── 字幕与音频 ────────────────────────────────────────────────
def chunk_text(text: str, max_len: int = 24) -> list[str]:
    """按标点切字幕；过长的一段再按顿号/空格/硬切，避免出现半个英文单词。"""
    parts, cur = [], ""
    for ch in text:
        cur += ch
        if ch in "，。；：！？、":
            if cur.strip():
                parts.append(cur.strip())
            cur = ""
    if cur.strip():
        parts.append(cur.strip())
    out: list[str] = []
    for p in parts:
        while len(p) > max_len:
            cut = -1
            for sep in ("、", "，", " ", ","):
                k = p.rfind(sep, 0, max_len)
                if k > cut:
                    cut = k + 1
            if cut <= 6:
                cut = max_len
            out.append(p[:cut].strip())
            p = p[cut:]
        if p.strip():
            out.append(p.strip())
    merged: list[str] = []
    for c in out:                        # 别让「SELinux」这种碎片单独占一屏
        if merged and (len(merged[-1]) < 8 or len(c) < 8) \
                and len(merged[-1]) + len(c) <= 28:
            sep = " " if (merged[-1][-1].isascii() or c[0].isascii()) else ""
            merged[-1] = merged[-1] + sep + c
        else:
            merged.append(c)
    return merged


def tts(text: str) -> Path:
    WORK.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha1(f"{VOICE}|{TTS_RATE}|{text}".encode()).hexdigest()[:16]
    path = WORK / f"tts-{h}.mp3"
    if not path.exists() or path.stat().st_size < 1000:
        subprocess.run([sys.executable, "-m", "edge_tts", "--voice", VOICE,
                        "--rate", TTS_RATE, "--text", text,
                        "--write-media", str(path)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


def decode_wav(mp3: Path) -> Path:
    wav = mp3.with_suffix(".wav")
    if not wav.exists() or wav.stat().st_mtime < mp3.stat().st_mtime:
        subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-i", str(mp3),
                        "-ac", "1", "-ar", "44100", "-c:a", "pcm_s16le", str(wav)],
                       check=True)
    return wav


def build_master(scenes: list[Scene], path: Path) -> float:
    sr = 44100
    total = sum(s.dur for s in scenes)
    n = int(total * sr) + sr // 2
    master = array("h", bytes(2 * n))
    offset = 0.0
    for s in scenes:
        if s.audio:
            wav = decode_wav(s.audio)
            with wave.open(str(wav), "rb") as w:
                data = array("h")
                data.frombytes(w.readframes(w.getnframes()))
            start = int((offset + 0.40) * sr)
            for i, v in enumerate(data):
                j = start + i
                if j >= n:
                    break
                mix = master[j] + v
                master[j] = max(-32768, min(32767, mix))
        offset += s.dur
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(master.tobytes())
    return total


def draw_subtitle(frame, sc: Scene, t: float):
    if not sc.chunks or sc.audio_dur <= 0:
        return
    rel = t - 0.55
    if rel < 0 or rel > sc.audio_dur + 0.45:
        return                              # 说完就撤，不要挂着上一句
    weights = [len(c) for c in sc.chunks]
    total = sum(weights)
    pos = clamp(rel / sc.audio_dur) * total
    idx, acc = 0, 0
    for k, w in enumerate(weights):
        if pos <= acc + w or k == len(weights) - 1:
            idx = k
            break
        acc += w
    text = sc.chunks[idx]
    f = font(34)
    d0 = ImageDraw.Draw(frame)
    lines = wrap(d0, text, f, 1600)
    box_h = 30 + len(lines) * 48
    box_w = max(d0.textlength(l, font=f) for l in lines) + 80
    x0 = (W - box_w) / 2
    y1 = 1058 if sc.key.startswith("rec_") else 1000
    y0 = y1 - box_h
    d = ImageDraw.Draw(frame)
    d.rounded_rectangle((x0, y0, x0 + box_w, y1), radius=16, fill=(20, 27, 42))
    y = y0 + 15
    for ln in lines:
        d.text((W / 2, y), ln, font=f, fill=(240, 244, 250), anchor="ma")
        y += 48
    sc.last_sub = (idx, t)                              # type: ignore[attr-defined]


def draw_cue(frame, sc: Scene, t: float):
    """无旁白版：只显示当前时间窗内的那一条字幕。"""
    cue = next((c for c in sc.cues if c[0] <= t <= c[1]), None)
    if cue is None:
        return
    f = font(34)
    d0 = ImageDraw.Draw(frame)
    lines = wrap(d0, cue[2], f, 1600)
    box_h = 30 + len(lines) * 48
    box_w = max(d0.textlength(l, font=f) for l in lines) + 80
    x0 = (W - box_w) / 2
    y1 = 1058 if sc.key.startswith("rec_") else 1000
    y0 = y1 - box_h
    d = ImageDraw.Draw(frame)
    d.rounded_rectangle((x0, y0, x0 + box_w, y1), radius=16,
                        fill=(20, 27, 42))
    y = y0 + 15
    for ln in lines:
        d.text((W / 2, y), ln, font=f, fill=(240, 244, 250), anchor="ma")
        y += 48


def draw_bg(frame, sc: Scene, t: float):
    if sc.key.startswith("rec_"):
        frame.paste(DESK, (0, 0))
        if sc.key in ("rec_term", "rec_board"):
            tt = sc.t0 + t
            d = ImageDraw.Draw(frame)
            if int(tt * 1.2) % 2 == 0:
                d.ellipse((1758, 22, 1774, 38), fill=(235, 66, 82))
            d.text((1786, 30), f"REC  {int(tt) // 60:02d}:{int(tt) % 60:02d}",
                   font=font(19, True), fill=(176, 186, 202), anchor="lm")
        return
    if sc.key == "thanks":
        frame.paste(GRAD, (0, 0))
        return
    frame.paste(BG, (0, 0))
    d = ImageDraw.Draw(frame)
    if sc.chapter:
        d.text((100, 34), sc.chapter, font=font(22, True), fill=ACCENT_DARK)
    if sc.title:
        d.text((100, 68), sc.title, font=font(48, True), fill=INK)
    d.text((100, 1036), "PolicyLoop · 2026 开源鸿蒙大学生创新大赛 赛道一",
           font=font(19), fill=MUTED)
    d.text((1820, 1036), "智能终端操作系统根社区", font=font(19), fill=ACCENT_DARK,
           anchor="ra")


def make_bg() -> Image.Image:
    im = Image.new("RGB", (W, H), WHITE)
    d = ImageDraw.Draw(im)
    d.rectangle((0, 0, W, 150), fill=(242, 250, 254))
    d.rectangle((0, 150, W, 153), fill=ACCENT)
    ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(ov).ellipse((-420, 760, 460, 1640), fill=TINT + (110,))
    im.paste(ov, (0, 0), ov)
    return im


def make_grad() -> Image.Image:
    top, bot = (0, 176, 240), (0, 132, 196)
    im = Image.new("RGB", (W, H))
    d = ImageDraw.Draw(im)
    for y in range(H):
        k = y / (H - 1)
        d.line((0, y, W, y), fill=tuple(int(top[i] + (bot[i] - top[i]) * k) for i in range(3)))
    return im


BG = make_bg()
GRAD = make_grad()


# ── 主流程 ────────────────────────────────────────────────────
def subtitle_chunks(text: str, max_len: int = 40) -> list[str]:
    """无旁白字幕：先按句号切，过长再按逗号/顿号切，尽量保持语义完整。"""
    sentences: list[str] = []
    cur = ""
    for ch in text:
        cur += ch
        if ch in "。！？":
            sentences.append(cur.strip())
            cur = ""
    if cur.strip():
        sentences.append(cur.strip())

    merge_lim = int(max_len * 1.15)       # 略超一行也保留整句，避免切断词语
    out: list[str] = []
    for s in sentences:
        if len(s) <= merge_lim:
            out.append(s)
            continue
        parts: list[str] = []
        cur = ""
        for ch in s:
            cur += ch
            if ch in "，、；：" and len(cur) >= max_len * 0.7:
                parts.append(cur.strip())
                cur = ""
        if cur.strip():
            parts.append(cur.strip())
        merged: list[str] = []
        for p in parts:
            if merged and len(merged[-1]) + len(p) <= merge_lim:
                sep = " " if (merged[-1][-1].isascii() or p[0].isascii()) else ""
                merged[-1] = merged[-1] + sep + p
            else:
                merged.append(p)
        for p in merged:
            while len(p) > merge_lim:
                out.append(p[:max_len].strip())
                p = p[max_len:]
            if p.strip():
                out.append(p.strip())
    return out


def prepare_cues(scenes: list[Scene], chars_per_sec: float = 5.6,
                 min_cue: float = 2.0) -> None:
    """无旁白模式：按阅读速度排字幕，短场景则由字幕把时长撑开。"""
    for sc in scenes:
        if not sc.narration:
            sc.dur = sc.min_dur
            continue
        sc.chunks = subtitle_chunks(sc.narration)
        base = [max(min_cue, len(c) / chars_per_sec) for c in sc.chunks]
        n = len(base)
        gap = 0.35
        need = 0.6 + sum(base) + gap * (n - 1) + 1.0
        sc.dur = max(sc.min_dur, need)
        spare = sc.dur - 1.0 - 0.6 - sum(base) - gap * (n - 1)
        if spare > 0:                     # 把余量摊进每条字幕，避免长空档
            base = [d + spare / n for d in base]
        t = 0.6
        for c, d in zip(sc.chunks, base):
            sc.cues.append((t, t + d, c))
            t += d + gap


def make_silence(total: float, path: Path) -> Path:
    """一条与画面等长的静音轨：播放器/投稿平台都按有音轨的文件处理。"""
    sr = 44100
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(b"\x00\x00" * int(total * sr))
    return path


def prepare_audio(scenes: list[Scene]):
    for sc in scenes:
        if not sc.narration:
            sc.dur = sc.min_dur
            continue
        sc.audio = tts(sc.narration)
        sc.audio_dur = MP3(str(sc.audio)).info.length
        sc.chunks = chunk_text(sc.narration)
        sc.dur = max(sc.min_dur, sc.audio_dur + 1.30)


def render(scenes: list[Scene], out: Path, silent: bool = False):
    for s in scenes:
        if s.key == "terminal":
            s.extra = capture_converge()
    total = sum(s.dur for s in scenes)
    master = WORK / "master.wav"
    if silent:
        make_silence(total, master)
    else:
        build_master(scenes, master)
    print(f"总时长 {total/60:.2f} min，开始渲染 {int(total*FPS)} 帧 …")

    cmd = [FFMPEG, "-y", "-loglevel", "error",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
           "-i", "pipe:0", "-i", str(master),
           "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
           "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k",
           "-movflags", "+faststart", "-shortest", str(out)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=open(WORK / "ffmpeg.log", "wb"))
    assert proc.stdin

    frame = Image.new("RGB", (W, H))
    n = 0
    for sc in scenes:
        sc.t0 = n / FPS
        n_frames = int(round(sc.dur * FPS))
        for i in range(n_frames):
            t = i / FPS
            draw_bg(frame, sc, t)
            sc.draw(frame, ImageDraw.Draw(frame), t, sc.dur, sc)
            if sc.cues:
                draw_cue(frame, sc, t)
            else:
                draw_subtitle(frame, sc, t)
            # 场景切换：讲课版白场淡入；录屏版直接切，只在片头从黑场淡入
            if t < 0.30 and not sc.key.startswith("rec_"):
                a = int(255 * (1 - t / 0.30))
                wv = WHITE_OVERLAYS[a // 25]
                frame.paste(wv, (0, 0), wv)
            elif sc is scenes[0] and t < 0.45:
                a = int(255 * (1 - t / 0.45))
                bv = BLACK_OVERLAYS[min(a // 25, 10)]
                frame.paste(bv, (0, 0), bv)
            proc.stdin.write(frame.tobytes())
            n += 1
        if n % 500 < n_frames:
            print(f"  {n/ (total*FPS) * 100:5.1f}%  ({n} 帧)")
    proc.stdin.close()
    if proc.wait() != 0:
        sys.exit(f"ffmpeg 失败，见 {WORK/'ffmpeg.log'}")
    print(f"→ {out}  ({out.stat().st_size/1e6:.1f} MB)")


WHITE_OVERLAYS = []
BLACK_OVERLAYS = []
for alpha in range(0, 256, 25):
    ov = Image.new("RGBA", (W, H), (255, 255, 255, alpha))
    WHITE_OVERLAYS.append(ov)
    BLACK_OVERLAYS.append(Image.new("RGBA", (W, H), (0, 0, 0, alpha)))


def preview(scenes: list[Scene], out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    for sc in scenes:
        if sc.cues:
            continue
        if sc.narration:
            sc.audio_dur = len(sc.narration) / 5.4
            sc.chunks = chunk_text(sc.narration)
            sc.dur = max(sc.min_dur, sc.audio_dur + 1.3)
        else:
            sc.dur = sc.min_dur
    for s in scenes:
        if s.key == "terminal":
            s.extra = capture_converge()
    for i, sc in enumerate(scenes):
        t = sc.dur * 0.6
        frame = Image.new("RGB", (W, H))
        draw_bg(frame, sc, t)
        sc.draw(frame, ImageDraw.Draw(frame), t, sc.dur, sc)
        if sc.cues:
            draw_cue(frame, sc, t)
        else:
            draw_subtitle(frame, sc, t)
        frame.resize((960, 540), Image.LANCZOS).save(out_dir / f"{i+1:02d}-{sc.key}.png")
    print(f"预览帧 → {out_dir}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--preview", type=Path, help="只渲染每场景一帧")
    ap.add_argument("--cut", choices=["v3", "v4", "v5", "v6"], default="v3",
                    help="v3=八幕方案版；v4=单条 denial 全程版；v5=录屏式演示；"
                         "v6=混合定稿（无旁白，只留字幕）")
    args = ap.parse_args()
    silent = args.cut == "v6"
    sc = {"v3": scenes, "v4": scenes_v4, "v5": scenes_v5,
          "v6": scenes_v6}[args.cut]()
    if silent:
        prepare_cues(sc)
        if args.out == OUT_DEFAULT:
            args.out = OUT_DEFAULT.with_name("PolicyLoop-演示-混合定稿-20261019.mp4")
    if args.preview:
        preview(sc, args.preview)
        return
    WORK.mkdir(parents=True, exist_ok=True)
    if not silent:
        prepare_audio(sc)
        print("配音：", " | ".join(f"{s.key} {s.audio_dur:.1f}s" for s in sc))
    else:
        print("字幕：", " | ".join(f"{s.key} {s.dur:.1f}s/{len(s.cues)}条"
                                   for s in sc))
    render(sc, args.out, silent=silent)


if __name__ == "__main__":
    main()
