#!/usr/bin/env python3
"""生成板端控制台的应用图标。

为什么需要这个脚本：`device/pl_console` 里两份 `app_icon.png` 原本都是
**1×1 的透明 PNG**（模板占位），于是启动器里是一个空白方块、应用的启动窗口
（module.json5 的 `startWindowIcon`）也是空的。图标改一次要重新导一次 PNG，
所以把生成过程落成脚本，谁都能重建，而不是留一个来源不明的二进制。

图形与 `Index.ets` 里的 `brandMark` 是同一个：圆角方块 + 反白的 "PL"。
两处一致，屏幕上从启动器点进去不会有"换了个应用"的感觉。

只用 Pillow。超采样 4× 再缩回来做抗锯齿（Pillow 不给自己画的多边形抗锯齿）。

    python3 tools/make_app_icon.py            # 写到 device/pl_console 的两处
    python3 tools/make_app_icon.py --out /tmp/x.png   # 只出一张，给人看
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - 环境问题，不是逻辑分支
    sys.exit("需要 Pillow：python3 -m venv .venv && .venv/bin/pip install Pillow")

ROOT = Path(__file__).resolve().parents[1]

# 与 resources/base/element/color.json 保持一致 —— 改一处就要改另一处。
ACCENT_HI = (0x6E, 0x9C, 0xF7)   # 渐变起点
ACCENT_LO = (0x3F, 0x6F, 0xD8)   # 渐变终点
INK = (0x0B, 0x0F, 0x14)         # "PL" 的字色，同 color.json 里的 bg

SIZE = 512
SS = 4  # 超采样倍数
RADIUS_RATIO = 0.22
TEXT_WIDTH_RATIO = 0.56  # "PL" 占图标宽度的比例

# 优先用无衬线粗体；找不到就退回 Pillow 自带的位图字体（难看，但不会崩）。
FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
]


def _load_font(px: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONT_CANDIDATES:
        if Path(path).is_file():
            return ImageFont.truetype(path, px)
    return ImageFont.load_default()


def _gradient(size: int) -> Image.Image:
    """左上→右下的线性渐变。逐行画，再横向插值 —— 512 行够快。"""
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * (size - 1))
            px[x, y] = (
                round(ACCENT_HI[0] + (ACCENT_LO[0] - ACCENT_HI[0]) * t),
                round(ACCENT_HI[1] + (ACCENT_LO[1] - ACCENT_HI[1]) * t),
                round(ACCENT_HI[2] + (ACCENT_LO[2] - ACCENT_HI[2]) * t),
            )
    return img


def make(size: int = SIZE) -> Image.Image:
    big = size * SS
    base = _gradient(big).convert("RGBA")

    # 圆角遮罩。启动器多半自己会套形状，但真机上见过不套的 —— 自己做一次
    # 不会更差，套两次也只是同一个圆角。
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, big - 1, big - 1), radius=round(big * RADIUS_RATIO), fill=255
    )
    base.putalpha(mask)

    # "PL" 居中。按实测宽度反推字号，比猜一个好。
    target_w = big * TEXT_WIDTH_RATIO
    font_px = round(target_w / 1.30)  # DejaVu Sans Bold 的 "PL" 宽约 1.30×字号
    font = _load_font(font_px)
    draw = ImageDraw.Draw(base)
    box = draw.textbbox((0, 0), "PL", font=font)
    draw.text(
        ((big - (box[2] - box[0])) / 2 - box[0],
         (big - (box[3] - box[1])) / 2 - box[1]),
        "PL", font=font, fill=INK,
    )

    return base.resize((size, size), Image.LANCZOS)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", help="只写这一个路径（预览用），不动仓库里的两份")
    ap.add_argument("--size", type=int, default=SIZE)
    args = ap.parse_args()

    img = make(args.size)

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
    return 0


def _png_bytes(img: Image.Image) -> bytes:
    import io

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
