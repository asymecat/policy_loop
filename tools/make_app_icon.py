#!/usr/bin/env python3
"""生成板端控制台的应用图标（512×512 RGBA PNG）。

只用 Pillow。所有图形先按 SS 倍超采样再 LANCZOS 缩回来（Pillow 不给自画的多边形抗锯齿，
圆环和箭头全是斜线，不这么做边缘全是台阶）。

画法统一走**蒙版**：每个图形先画成一张 L 蒙版（`*_mask`），再决定往里填什么 ——
纯色就是平涂版，渐变 + 外发光 + 镜面高光就是立体版。同一套几何两种待遇，
对比哪个好看只要换个 fill，不用重画图形。

    python3 tools/make_app_icon.py                      # 写 device/pl_console 的两处
    python3 tools/make_app_icon.py --variant all --out /tmp/ico
    python3 tools/make_app_icon.py --variant segments --out /tmp/x.png --sheet
    python3 tools/make_app_icon.py --variant plate      # 换一个图形写进仓库

系统 python 里没有 Pillow，用临时 venv：
    python3 -m venv /tmp/plicon-venv && /tmp/plicon-venv/bin/pip install Pillow
    /tmp/plicon-venv/bin/python tools/make_app_icon.py

────────────────────────────────────────────────────────────────────────────
图形改了三轮，来历都留着 —— "为什么换掉"比"现在长什么样"更容易被重新踩：

**第一轮 蓝底 + 反白 PL。** 起因是原先两份 `app_icon.png` 都是**模板占位的 1×1 透明 PNG**
⇒ 启动器里是空白方块、`module.json5` 的 `startWindowIcon` 也是空的。补了「圆角方块 + 反白 PL」，
底色取 app 的 accent `#5B8DEF`。两个毛病：**它和 OpenHarmony 的默认应用图标（也是一块蓝色
圆角方块）在桌面上分不出来**，像没换过；而且方块加两个字母**没讲出这个 app 干什么**。

**第二轮 深底 + 平涂蓝环 + 平涂绿勾。** 环讲闭环（denial → 最小补丁 → 复验）、勾讲结果，
意思对了；底色改深是因为**浅蓝底上再画蓝环就又回到"一坨蓝"**。但它是**纯平涂**：
边缘利落、没有层次，放大看是几个色块拼起来的，谈不上质感。

**第三轮（现在）同构图上质感。** 不改"环 + 勾"这个意思（它是对的），改的是画法：
环和勾都改成**双色渐变填充**（左上亮、右下暗，跟底色同一个光向）、下面垫一层**外发光**、
环的左上加一道**镜面高光**、底色从对角渐变换成**径向聚光**。另外多出两个构图完全不同的
候选：`segments`（环切成十几段，只有被修好的那几段是亮的 —— 直接对应"3261 条规则里挑出
最小那一条"）和 `shield`（盾牌，安全类应用识读成本最低）。

⚠️ 判据：**512 上好看不等于 72 上认得出**（桌面上真正显示的就是 72 上下）。必须看 `--sheet`
的多尺寸对照：加了发光和小分段之后，小尺寸更容易糊成一团。
"""

from __future__ import annotations

import argparse
import io
import math
import sys
from pathlib import Path

try:
    from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
except ImportError:  # pragma: no cover - 环境问题，不是逻辑分支
    sys.exit("需要 Pillow：python3 -m venv /tmp/plicon-venv && "
             "/tmp/plicon-venv/bin/pip install Pillow")

ROOT = Path(__file__).resolve().parents[1]

# ── 色板（全部落在 entry/src/main/resources/base/element/color.json 的家族里）────
BG_LIT = (0x1C, 0x2B, 0x47)        # 聚光中心：surface #212B38 往蓝偏一点
BG_DARK = (0x07, 0x09, 0x0D)       # 四角：比 bg #0A0E13 再压一点，才出得来景深
BG_TOP = (0x17, 0x23, 0x38)        # 平底版（plate）的对角渐变起点
BG_DEEP = (0x0A, 0x0E, 0x13)       # color: bg
ACCENT = (0x5B, 0x8D, 0xEF)        # color: accent
RING_HI = (0x9C, 0xC2, 0xFF)       # 环的受光端
RING_LO = (0x35, 0x63, 0xCC)       # 环的背光端
OK = (0x4A, 0xDE, 0x80)            # color: ok —— "已修复"就是这个绿
CHK_HI = (0x86, 0xF2, 0xB4)
CHK_LO = (0x25, 0xB0, 0x62)
INK = (0x0A, 0x0E, 0x13)
TEXT = (0xEE, 0xF3, 0xF9)
SEG_DIM = (0x33, 0x50, 0x80)       # 收敛版最外层那道暗环

# 圆角半径：量的第一版 PNG 沿 y=0 第一个不透明像素在 x≈97~110，与 HarmonyOS 桌面图标的
# 标准圆角一致。启动器多半自己还会蒙一层形状，半径对不上会出现"双层圆角"。
RADIUS_RATIO = 110 / 512

SS = 4      # 超采样倍数
N = 512     # 当前画布边长；render() 会按 --size 覆盖
W = N * SS

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
]


# ── 渐变与合成 ──────────────────────────────────────────────────────────────
# 渐变一律在 1/LOW 分辨率上算再放大：4M 个像素在纯 Python 里逐点算要几十秒，
# 而渐变是低频信号，缩上去肉眼看不出任何差别。

LOW = 8


def _low(size):
    return max(2, size // LOW)


def grad_linear(c0, c1, angle_deg=45.0):
    """线性渐变。angle 45° = 左上亮、右下暗（app 里几个面都是这个光向）。"""
    n = _low(W)
    rad = math.radians(angle_deg)
    dx, dy = math.cos(rad), math.sin(rad)
    img = Image.new("RGB", (n, n))
    px = img.load()
    # 把投影范围归一化到 [0,1]
    lo = min(0, dx * (n - 1)) + min(0, dy * (n - 1))
    hi = max(0, dx * (n - 1)) + max(0, dy * (n - 1))
    span = max(1e-6, hi - lo)
    for y in range(n):
        for x in range(n):
            t = (dx * x + dy * y - lo) / span
            px[x, y] = tuple(round(a + (b - a) * t) for a, b in zip(c0, c1))
    return img.resize((W, W), Image.BICUBIC)


def grad_radial(c_in, c_out, center=(0.5, 0.46), radius=0.78):
    """径向渐变：中心亮、边缘暗。当底色用就是一圈聚光。"""
    n = _low(W)
    cx, cy, r = center[0] * (n - 1), center[1] * (n - 1), radius * (n - 1)
    img = Image.new("RGB", (n, n))
    px = img.load()
    for y in range(n):
        for x in range(n):
            t = min(1.0, math.hypot(x - cx, y - cy) / r)
            px[x, y] = tuple(round(a + (b - a) * t) for a, b in zip(c_in, c_out))
    return img.resize((W, W), Image.BICUBIC)


def paint(base, mask, fill):
    """把 fill（纯色三元组或一张同尺寸图）按 mask 贴到 base 上。"""
    if isinstance(fill, tuple):
        layer = Image.new("RGBA", (W, W), fill + (0,))
        layer.putalpha(mask)
    else:
        layer = fill.convert("RGBA")
        layer.putalpha(mask)
    base.alpha_composite(layer)


def add_glow(base, mask, color, blur, strength):
    """在图形**下面**垫一层外发光。

    这是"平涂"和"立体"之间最省事的一步：同一条几何，加一层模糊的同色光晕就立刻离开纸面。
    blur 与 strength 都是相对量（相对画布边长），这样换 --size 不用重调。
    """
    m = mask.filter(ImageFilter.GaussianBlur(blur * W))
    m = m.point(lambda v: round(v * strength))
    layer = Image.new("RGBA", (W, W), color + (0,))
    layer.putalpha(m)
    base.alpha_composite(layer)


def rounded_mask():
    m = Image.new("L", (W, W), 0)
    ImageDraw.Draw(m).rounded_rectangle([0, 0, W - 1, W - 1],
                                        radius=round(W * RADIUS_RATIO), fill=255)
    return m


# ── 几何：都返回 L 蒙版 ─────────────────────────────────────────────────────

def _arc_pts(cx, cy, r, a0, a1, n=240):
    """沿圆弧采样一串点。角度按 Pillow 的约定：0° 在 3 点钟、顺时针为正。"""
    return [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
            for a in (a0 + (a1 - a0) * i / n for i in range(n + 1))]


def _stroke_mask(pts, width):
    """带圆角接头与圆头端点的折线蒙版。

    Pillow 的 line(joint="curve") 只处理拐点，两端仍是平口；勾的收笔要圆的，
    所以端点各自补一个实心圆。
    """
    m = Image.new("L", (W, W), 0)
    d = ImageDraw.Draw(m)
    d.line(pts, fill=255, width=round(width), joint="curve")
    r = width / 2.0
    for p in (pts[0], pts[-1]):
        d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=255)
    return m


def band_mask(cx, cy, r_out, stroke, a0, a1):
    """一段环带（外弧正向 + 内弧反向围成的闭合多边形），两端是平口。

    **不用** ImageDraw.arc(width=…)：那条路的粗笔画是贴着椭圆往内长、不以椭圆线为中心，
    于是"环的实际半径"跟传进去的参数对不上 —— 照参数在外弧位置补的圆头会整颗飘在环外，
    渲染成一个孤立的小圆点。自己拼没有这层歧义，r_out 就是外半径。
    """
    m = Image.new("L", (W, W), 0)
    ImageDraw.Draw(m).polygon(
        _arc_pts(cx, cy, r_out, a0, a1) + _arc_pts(cx, cy, r_out - stroke, a1, a0), fill=255)
    return m


def _head_mask(cx, cy, r_out, stroke, a1):
    """弧末端那个箭头。三角形单独画：圆弧的粗细是均匀的，做不出收尖。"""
    m = Image.new("L", (W, W), 0)
    r_mid = r_out - stroke / 2.0
    th = math.radians(a1 % 360)
    px, py = cx + r_mid * math.cos(th), cy + r_mid * math.sin(th)
    tx, ty = -math.sin(th), math.cos(th)      # 顺时针切线
    nx, ny = -ty, tx
    ImageDraw.Draw(m).polygon(
        [(px + tx * stroke * 0.95, py + ty * stroke * 0.95),
         (px - tx * stroke * 0.30 + nx * stroke * 0.95,
          py - ty * stroke * 0.30 + ny * stroke * 0.95),
         (px - tx * stroke * 0.30 - nx * stroke * 0.95,
          py - ty * stroke * 0.30 - ny * stroke * 0.95)], fill=255)
    return m


def ring_mask(cx, cy, r_out, stroke, gap_center=315, gap=62, head=True):
    """一圈（或一段）带箭头的环。

    缺口默认开在 315°（右上），箭头落在缺口那一侧的弧端上，读作顺时针。
    """
    a0 = gap_center + gap / 2.0
    a1 = gap_center - gap / 2.0 + 360
    m = band_mask(cx, cy, r_out, stroke, a0, a1)
    if head:
        m = ImageChops.lighter(m, _head_mask(cx, cy, r_out, stroke, a1))
    # 起点那端补圆头收笔（终点那端被箭头盖住）
    r_mid = r_out - stroke / 2.0
    th0 = math.radians(a0)
    r0 = stroke / 2.0
    c0 = (cx + r_mid * math.cos(th0), cy + r_mid * math.sin(th0))
    ImageDraw.Draw(m).ellipse([c0[0] - r0, c0[1] - r0, c0[0] + r0, c0[1] + r0], fill=255)
    return m


def clip(mask, *others):
    """把蒙版裁进另一张蒙版里。

    ★ 高光/内阴影一律要过这一道：模糊过的蒙版会**溢出图形边界**，直接合成到深色底上
    就是一圈灰雾 —— 第一次渲染时环的右上角就是这么糊掉的，看着像画错了。
    """
    for o in others:
        mask = ImageChops.multiply(mask, o)
    return mask


def check_mask(cx, cy, span, stroke, dx=0.0):
    """一个勾。span 是它横向的跨度；dx 是光学修正的横移 ——
    勾的右臂比左臂长得多，几何居中之后看上去偏右，所以要往左拉一点。"""
    s = span
    cx += dx
    return _stroke_mask([(cx - 0.42 * s, cy + 0.02 * s),
                         (cx - 0.10 * s, cy + 0.36 * s),
                         (cx + 0.46 * s, cy - 0.34 * s)], stroke)


def shield_mask(cx, cy, w, h):
    """盾牌轮廓：上边平、两腰收到下面的尖。

    ⚠️ 收腰要**早且狠**（0.38 处就开始、控制点往内拉到 0.22w），否则轮廓读成"下部圆角的
    长方块"，也就是个 U 形墓碑而不是盾牌 —— 第一版就是 0.55 才开始收、太钝。
    """
    m = Image.new("L", (W, W), 0)
    l, r = cx - w / 2, cx + w / 2
    t, b = cy - h / 2, cy + h / 2
    sh = t + h * 0.38

    def bez(p0, p1, p2, p3, n=64):
        out = []
        for i in range(n + 1):
            u = 1 - i / n
            k = i / n
            out.append((u**3 * p0[0] + 3 * u**2 * k * p1[0] + 3 * u * k**2 * p2[0] + k**3 * p3[0],
                        u**3 * p0[1] + 3 * u**2 * k * p1[1] + 3 * u * k**2 * p2[1] + k**3 * p3[1]))
        return out

    ImageDraw.Draw(m).polygon([(l, t), (r, t), (r, sh)]
                              + bez((r, sh), (r, t + h * 0.72), (cx + w * 0.22, b), (cx, b))
                              + bez((cx, b), (cx - w * 0.22, b), (l, t + h * 0.72), (l, sh)),
                              fill=255)
    # 上边两角磨圆：盾牌的肩是圆的，方角会往"公文包"上跑。
    # 圆角 = **把方角削掉**：在该角上盖一个小方块（= 半径 r_c 见方），再把内切圆补回来，
    # 剩下的 keep=0 区域正好是"方块内、圆外"，乘上去就切出了一个圆角。
    r_c = w * 0.09
    keep = Image.new("L", (W, W), 255)
    dk = ImageDraw.Draw(keep)
    for corner, ctr in (((l, t), (l + r_c, t + r_c)), ((r, t), (r - r_c, t + r_c))):
        # 右角的 ctr 在 corner 左边，rectangle 不接受 x1 < x0，所以自己排一次序
        dk.rectangle([min(corner[0], ctr[0]), min(corner[1], ctr[1]),
                      max(corner[0], ctr[0]), max(corner[1], ctr[1])], fill=0)
        dk.ellipse([ctr[0] - r_c, ctr[1] - r_c, ctr[0] + r_c, ctr[1] + r_c], fill=255)
    return ImageChops.multiply(m, keep)


def _load_font(px):
    """优先用无衬线粗体；找不到就退回 Pillow 自带的位图字体（难看，但不会崩）。"""
    for path in FONT_CANDIDATES:
        if Path(path).is_file():
            return ImageFont.truetype(path, px)
    return ImageFont.load_default()


# ── 候选 ────────────────────────────────────────────────────────────────────
# 每个候选收 (base, mask_cache)：base 是已经铺好底色的 RGBA 画布。

def v_loop(base, _):
    """**默认**：径向聚光底 + 渐变环 + 渐变勾 + 外发光 + 镜面高光。"""
    R, ST = 0.360 * W, 0.072 * W
    cx = cy = W / 2
    ring = ring_mask(cx, cy, R, ST)
    chk = check_mask(cx, cy + 0.015 * W, 0.355 * W, 0.048 * W, dx=-0.014 * W)

    add_glow(base, ring, ACCENT, 0.022, 0.50)
    add_glow(base, chk, OK, 0.020, 0.40)

    paint(base, ring, grad_linear(RING_HI, RING_LO, 45))
    paint(base, chk, grad_linear(CHK_HI, CHK_LO, 45))

    # 镜面高光：环的左上那一段再压一层亮的，让它像一根有厚度的管子。
    # ★ 必须 clip 进 ring：模糊会把蒙版摊到环外，直接合成到深底上就是一圈灰雾
    #   （第一版右上角那片脏灰就是这么来的）。
    hi = band_mask(cx, cy, R, ST * 0.55, 208, 320)
    hi = clip(hi.filter(ImageFilter.GaussianBlur(0.010 * W)), ring).point(lambda v: round(v * 0.55))
    paint(base, hi, grad_linear((0xFF, 0xFF, 0xFF), RING_HI, 20))

    # 内阴影：环的内缘压暗一点点，管子才有厚度（同样要裁进 ring）
    inner = clip(band_mask(cx, cy, R, ST * 0.42, 20, 200).filter(
        ImageFilter.GaussianBlur(0.008 * W)), ring)
    paint(base, inner.point(lambda v: round(v * 0.30)), (0x06, 0x0A, 0x14))


def v_converge(base, _):
    """三层同心环逐层收敛，最内层是绿的 —— 对应"3261 条 → 70 条 → 最小那几条"。

    比"把环切成十几段"好在**渲染上没有小件**：只有三段圆弧，缩到 72 甚至 48 都还是三条
    清楚的环（分段版的小圆头会互相咬成齿轮状，小尺寸直接糊掉，那个构图因而弃用）。
    """
    cx = cy = W / 2
    layers = [
        # (半径, 笔画, 颜色（None = 绿色渐变）, 要不要箭头)
        (0.395 * W, 0.030 * W, SEG_DIM, False),
        (0.295 * W, 0.040 * W, ACCENT, False),
        (0.195 * W, 0.050 * W, None, True),
    ]
    for r, st, col, head in layers:
        m = ring_mask(cx, cy, r, st, head=head)
        fill = (grad_linear(CHK_HI, CHK_LO, 45) if col is None
                else grad_linear(col, tuple(round(c * 0.62) for c in col), 45))
        add_glow(base, m, col or OK, 0.016, 0.25)
        paint(base, m, fill)

    # 最内层里面再点一个绿点：不画勾，小尺寸下勾会糊；一个实心点在任何尺寸都认得出来。
    dot = Image.new("L", (W, W), 0)
    r_d = 0.055 * W
    ImageDraw.Draw(dot).ellipse([cx - r_d, cy - r_d, cx + r_d, cy + r_d], fill=255)
    add_glow(base, dot, OK, 0.014, 0.45)
    paint(base, dot, grad_linear(CHK_HI, CHK_LO, 45))


def v_shield(base, _):
    """盾牌 + 勾。安全类应用识读成本最低的符号，代价是"闭环"那层意思没了。"""
    cx, cy = W / 2, W / 2
    sh = shield_mask(cx, cy, 0.600 * W, 0.740 * W)
    chk = check_mask(cx, cy - 0.01 * W, 0.290 * W, 0.050 * W)

    add_glow(base, sh, ACCENT, 0.018, 0.40)
    paint(base, sh, grad_linear(RING_HI, RING_LO, 45))
    # 盾面左上提一道光，别让它是一块平色。方向光用一个线性渐变**当蒙版**来做，
    # 再裁进盾牌轮廓 —— 比"模糊整个盾再裁回来"更像打在面上的光。
    sheen = clip(grad_linear((0x66, 0x66, 0x66), (0, 0, 0), 45).convert("L"), sh)
    paint(base, sheen, (0xFF, 0xFF, 0xFF))
    paint(base, chk, INK)


def v_loop_pl(base, _):
    """环 + 勾 + 环下一行 PL（平涂版）。

    ⚠️ 实测 48px 那行字就糊成一小撮白点、32px 完全看不见，而环和勾在同样尺寸下仍然清楚
    —— 所以不作默认，只留给想保住字母标识的场合。
    """
    cy = W * 0.425
    R, ST = 0.272 * W, 0.058 * W
    ring = ring_mask(W / 2, cy, R, ST)
    chk = check_mask(W / 2, cy + 0.010 * W, 0.300 * W, 0.040 * W, dx=-0.012 * W)
    add_glow(base, ring, ACCENT, 0.024, 0.45)
    paint(base, ring, ACCENT)
    paint(base, chk, OK)

    m = Image.new("L", (W, W), 0)
    font = _load_font(round(0.120 * W))
    d = ImageDraw.Draw(m)
    box = d.textbbox((0, 0), "PL", font=font)
    d.text((W / 2 - (box[2] - box[0]) / 2 - box[0],
            W * 0.805 - (box[3] - box[1]) / 2 - box[1]), "PL", font=font, fill=255)
    paint(base, m, TEXT)


def v_plate(base, _):
    """蓝底 + 白环 + 深色勾 —— 唯一保留"整块蓝底"的方案。

    留着是因为蓝底在桌面上更亮。但要清楚：**它和 OpenHarmony 的默认图标最像**，
    当初被吐槽"这图标怎么是蓝的"就是这一类。
    """
    R, ST = 0.360 * W, 0.072 * W
    ring = ring_mask(W / 2, W / 2, R, ST)
    chk = check_mask(W / 2, W / 2 + 0.015 * W, 0.355 * W, 0.048 * W, dx=-0.014 * W)
    paint(base, ring, grad_linear((0xFF, 0xFF, 0xFF), (0xC9, 0xDA, 0xF5), 45))
    paint(base, chk, BG_DEEP)


# 每个候选：(画法, 底色画法)
VARIANTS = {
    "loop":     (v_loop,     lambda: grad_radial(BG_LIT, BG_DARK)),
    "converge": (v_converge, lambda: grad_radial(BG_LIT, BG_DARK)),
    "shield":   (v_shield,   lambda: grad_radial(BG_LIT, BG_DARK)),
    "loop_pl":  (v_loop_pl,  lambda: grad_linear(BG_TOP, BG_DEEP, 45)),
    "plate":    (v_plate,    lambda: grad_linear((0x6E, 0x9C, 0xF5), (0x3E, 0x6D, 0xD6), 45)),
}
DEFAULT_VARIANT = "loop"


def render(name, size=N):
    global N, W
    N, W = size, size * SS
    fn, make_bg = VARIANTS[name]
    base = make_bg().convert("RGBA")
    fn(base, None)
    base.putalpha(rounded_mask())
    return base.resize((size, size), Image.LANCZOS)


def contact_sheet(img, sizes=(192, 96, 72, 48, 32)):
    """把同一份图标缩到桌面实际会用的几个尺寸并排看。

    这步不是装饰：512 上好看不等于 72 上认得出，而桌面上真正显示的就是 72 上下。
    发光和小分段在缩小时最容易糊在一起，必须在这个尺寸上确认。
    底色用浅灰：深色图标在浅底上更吃亏，拿它当坏情况的对照。
    """
    pad, gap = 24, 28
    big = max(sizes)
    sheet = Image.new("RGB", (pad * 2 + sum(sizes) + gap * (len(sizes) - 1), pad * 2 + big),
                      (0xE9, 0xEC, 0xF1))
    x = pad
    for s in sizes:
        small = img.resize((s, s), Image.LANCZOS)
        sheet.paste(small, (x, pad + (big - s) // 2), small)
        x += s + gap
    return sheet


def _png_bytes(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 PolicyLoop 板端控制台的应用图标")
    ap.add_argument("--variant", default=DEFAULT_VARIANT, choices=sorted(VARIANTS) + ["all"])
    ap.add_argument("--out", help="只写这一个路径（预览用），不动仓库里的两份；"
                                  "--variant all 时当作目录")
    ap.add_argument("--size", type=int, default=N)
    ap.add_argument("--sheet", action="store_true", help="额外输出一张多尺寸对照图")
    args = ap.parse_args()

    if args.variant == "all":
        outdir = Path(args.out or "/tmp/plicon")
        outdir.mkdir(parents=True, exist_ok=True)
        for name in sorted(VARIANTS):
            p = outdir / f"app_icon_{name}.png"
            p.write_bytes(_png_bytes(render(name, args.size)))
            print(f"写入 {p}")
        return 0

    img = render(args.variant, args.size)

    if args.sheet:
        p = Path(args.out or f"/tmp/app_icon_{args.variant}.png")
        sheet = p.with_name(p.stem + "_sizes.png")
        sheet.write_bytes(_png_bytes(contact_sheet(img)))
        print(f"多尺寸对照 {sheet}")

    if args.out:
        Path(args.out).write_bytes(_png_bytes(img))
        print(f"写入 {args.out}")
        return 0

    targets = [
        ROOT / "device" / "pl_console" / "AppScope" / "resources" / "base" / "media" / "app_icon.png",
        ROOT / "device" / "pl_console" / "entry" / "src" / "main" / "resources" / "base" / "media" / "app_icon.png",
    ]
    data = _png_bytes(img)
    for t in targets:
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_bytes(data)
        print(f"写入 {t.relative_to(ROOT)}  ({len(data)} 字节)")

    # 构建中间产物也顺手刷一遍：hvigor 增量构建不一定会重拷路径没变过的资源，
    # 留着旧图就会长成"源码改了但 HAP 里还是旧图标"这种最难查的现象。
    mid = (ROOT / "device" / "pl_console" / "entry" / "build" / "default" / "intermediates"
           / "res" / "default" / "resources" / "base" / "media" / "app_icon.png")
    if mid.parent.is_dir():
        mid.write_bytes(data)
        print(f"写入 {mid.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
