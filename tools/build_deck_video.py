#!/usr/bin/env python3
"""按《PolicyLoop_项目汇报_定稿.pptx》逐页生成约 3 分钟的演示视频。

画面即定稿 PPT 的每一页（LibreOffice 渲染成 1080p），
底部为中式字幕条，旁白由 edge-tts 合成。

用法：
    python3 tools/build_deck_video.py                # 输出 ~/下载/PolicyLoop-演示-定稿版-20261018.mp4
    python3 tools/build_deck_video.py --preview /tmp/pv   # 只出每页一帧，供版式检查
    python3 tools/build_deck_video.py --out /tmp/x.mp4

依赖：Pillow、edge-tts、mutagen、imageio-ffmpeg。
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import wave
from array import array
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

try:
    import imageio_ffmpeg
    from mutagen.mp3 import MP3
except ImportError as e:                                   # pragma: no cover
    sys.exit(f"缺少依赖：{e}. 先 pip install edge-tts mutagen imageio-ffmpeg pillow")

DECK = Path.home() / "下载" / "PolicyLoop_项目汇报_定稿.pptx"
OUT_DEFAULT = Path.home() / "下载" / "PolicyLoop-演示-定稿版-20261018.mp4"

W, H = 1920, 1080
FPS = 25
FONT_R = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
FONT_B = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
FONT_IDX = 2                       # .ttc 里的简体中文面

WHITE = (255, 255, 255)
BAND = (16, 26, 32)
ACCENT = (32, 110, 92)
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
VOICE = "zh-CN-XiaoxiaoNeural"
TTS_RATE = "+5%"
WORK = Path("/tmp/policyloop-deck")

# 每页旁白：与定稿页一一对应，数字口径与页面一致。
NARRATION = [
    "各位评委老师好，我们是 PolicyLoop。我们做的是 OpenHarmony 上 SELinux 拒绝日志的诊断和最小权限建议。",
    "输入 AVC 日志，输出分类、补丁、规则出处和处理责任；写策略仍由开发者执行。",
    "一条日志要拆四件事：谁访问什么、缺哪项权限、改哪份 .te、会不会扩大授权。",
    "能不能放行和应不应该放行分开判断；最小权限按展开后的授权范围算。",
    "主机做解析、索引与编排；设备只保留采集、判定和展示，两边交换结构化结果。",
    "四个选择：规则做安全判断；默认只给建议；先语料回放再真机；设备不依赖模型。",
    "设备没有 .te 源码，neverallow 也不在二进制里，所以索引必须由主机从源码构建。",
    "七个阶段单向执行；评审否决或反验失败就转人工，不回到修复重试。",
    "补丁出门前过五道检查。只缺 ioctl 命令号的例子，正确修法是补 allowxperm。",
    "5,161 行去重成 4,911 个案例：3,261 噪声、1,580 转人工、70 个出候选补丁。",
    "69 行候选归并为 54 条根因规则；套回索引，未解决案例从 70 降到 0。",
    "1,580 个转人工项逐条归因，归到设备补权限的是 0；仅限本批语料。",
    "设备端是独立 C++ 实现；27,912 条查询、2,984,884 字节输出逐字节相同。",
    "倒排索引让设备查询快 34 倍、主机判定快 238 倍；板端约 2 秒仍是外推。",
    "模型只出候选；真实模型 60 例中 54 个补丁全部最小，模拟档 120 例过宽全被拦。",
    "主机 Trace、板端实时窗口与快照；工具造成的 denial 单独标识、分开计数。",
    "真机 RK3568、5.0.3.135：采集器开机即在 enforcing 域运行，1 到 2 秒出结论。",
    "覆盖 3,520 / 3,522；留一抽样 179 / 179 最小、221 / 221 拦截；输出逐字节相同。",
    "四个问题改变方案：neverallow、printk 丢日志、caps 整套替换、固定向量补齐。",
    "边界：语料来自上游注释；索引三个快照 21,824、21,790、19,800；版本分开记录。",
    "提交前补上板复核、整批耗时实测、策略树对齐，以及 audit netlink 采集研究。",
    "谢谢各位老师，欢迎指正。",
]

XF = 0.35                          # 页间交叉淡入秒数
LEAD = 0.35                        # 旁白起始延迟
TAIL = 0.95                        # 语音结束后留白
MIN_DUR = 4.2


# ── 小工具 ────────────────────────────────────────────────────
_fonts: dict[tuple[int, bool], ImageFont.FreeTypeFont] = {}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    key = (size, bold)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(FONT_B if bold else FONT_R, size,
                                         index=FONT_IDX)
    return _fonts[key]


# ── 幻灯片 ────────────────────────────────────────────────────
def slide_pngs() -> list[Path]:
    WORK.mkdir(parents=True, exist_ok=True)
    pngs = sorted(WORK.glob("slide-*.png"))
    if pngs and pngs[0].stat().st_mtime >= DECK.stat().st_mtime:
        return pngs
    for p in WORK.glob("slide-*.png"):
        p.unlink()
    subprocess.run(["soffice", "--headless", "--convert-to", "pdf",
                    "--outdir", str(WORK), str(DECK)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pdf = WORK / (DECK.stem + ".pdf")
    subprocess.run(["pdftoppm", "-r", "144", "-png", str(pdf),
                    str(WORK / "slide")], check=True)
    return sorted(WORK.glob("slide-*.png"))


def load_slides() -> list[Image.Image]:
    out = []
    for p in slide_pngs():
        im = Image.open(p).convert("RGB")
        if im.size != (W, H):
            im = im.resize((W, H), Image.LANCZOS)
        out.append(im)
    if len(out) != len(NARRATION):
        sys.exit(f"页数不符：幻灯片 {len(out)} 页，旁白 {len(NARRATION)} 条")
    return out


# ── 字幕与音频 ────────────────────────────────────────────────
def chunk_text(text: str, max_len: int = 26) -> list[str]:
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
    for c in out:
        if merged and (len(merged[-1]) < 8 or len(c) < 8) \
                and len(merged[-1]) + len(c) <= 30:
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


@dataclass
class Page:
    img: Image.Image
    text: str
    audio: Path | None = None
    audio_dur: float = 0.0
    chunks: list[str] | None = None
    dur: float = MIN_DUR


def build_pages() -> list[Page]:
    pages = [Page(img, t) for img, t in zip(load_slides(), NARRATION)]
    for p in pages:
        if not p.text:
            continue
        p.audio = tts(p.text)
        p.audio_dur = MP3(str(p.audio)).info.length
        p.chunks = chunk_text(p.text)
        p.dur = max(MIN_DUR, p.audio_dur + TAIL)
    return pages


def build_master(pages: list[Page], path: Path) -> float:
    sr = 44100
    total = sum(p.dur for p in pages)
    n = int(total * sr) + sr // 2
    master = array("h", bytes(2 * n))
    offset = 0.0
    for p in pages:
        if p.audio:
            wav = decode_wav(p.audio)
            with wave.open(str(wav), "rb") as w:
                data = array("h")
                data.frombytes(w.readframes(w.getnframes()))
            start = int((offset + LEAD) * sr)
            for i, v in enumerate(data):
                j = start + i
                if j >= n:
                    break
                master[j] = max(-32768, min(32767, master[j] + v))
        offset += p.dur
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(master.tobytes())
    return total


# ── 画面 ──────────────────────────────────────────────────────
def draw_subtitle(frame: Image.Image, page: Page, t: float) -> None:
    if not page.chunks or page.audio_dur <= 0:
        return
    rel = t - LEAD - 0.10
    if rel < 0 or rel > page.audio_dur:
        return
    total_w = sum(len(c) for c in page.chunks)
    acc = 0.0
    idx = len(page.chunks) - 1
    for i, c in enumerate(page.chunks):
        acc += len(c)
        if rel <= page.audio_dur * acc / total_w:
            idx = i
            break
    text = page.chunks[idx]

    d = ImageDraw.Draw(frame, "RGBA")
    size = 29
    while d.textlength(text, font=font(size, True)) > 1320 and size > 18:
        size -= 2
    f = font(size, True)
    box_w = d.textlength(text, font=f) + 84
    x0 = (W - box_w) / 2
    y0, y1 = H - 74, H - 12
    d.rounded_rectangle((x0, y0, x0 + box_w, y1), radius=18,
                        fill=BAND + (234,), outline=WHITE + (40,), width=2)
    d.rectangle((x0 + 20, y0 + 14, x0 + 24, y1 - 14), fill=ACCENT + (255,))
    d.text((W / 2 + 2, (y0 + y1) / 2), text, font=f, fill=WHITE, anchor="mm")


def draw_progress(frame: Image.Image, frac: float) -> None:
    d = ImageDraw.Draw(frame, "RGBA")
    d.rectangle([0, H - 4, int(W * frac), H], fill=ACCENT + (255,))


def render(pages: list[Page], out: Path) -> None:
    total = sum(p.dur for p in pages)
    starts, acc = [], 0.0
    for p in pages:
        starts.append(acc)
        acc += p.dur
    master = WORK / "master.wav"
    build_master(pages, master)
    print(f"总时长 {total/60:.2f} min，渲染 {int(total*FPS)} 帧 …")

    cmd = [FFMPEG, "-y", "-loglevel", "error",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
           "-i", "pipe:0", "-i", str(master),
           "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
           "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k",
           "-movflags", "+faststart", "-shortest", str(out)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stderr=open(WORK / "ffmpeg.log", "wb"))

    n = int(total * FPS)
    i = 0
    try:
        for f in range(n):
            t = f / FPS
            while i + 1 < len(pages) and t >= starts[i + 1]:
                i += 1
            page = pages[i]
            local = t - starts[i]
            frame = page.img.copy()
            if local < XF:
                if i == 0:
                    a = local / XF
                    frame = Image.blend(Image.new("RGB", (W, H), (0, 0, 0)),
                                        frame, a)
                else:
                    a = local / XF
                    frame = Image.blend(pages[i - 1].img, frame, a)
            draw_subtitle(frame, page, local)
            draw_progress(frame, (f + 1) / n)
            proc.stdin.write(frame.tobytes())
    finally:
        proc.stdin.close()
        proc.wait()
    print(f"→ {out}  ({out.stat().st_size/1e6:.1f} MB)")


def preview(pages: list[Page], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, p in enumerate(pages, 1):
        frame = p.img.copy()
        draw_subtitle(frame, p, LEAD + 0.9)
        draw_progress(frame, i / len(pages))
        frame.save(out_dir / f"p{i:02d}.png")
    print(f"预览帧 → {out_dir}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    ap.add_argument("--preview", type=Path)
    args = ap.parse_args()
    pages = build_pages()
    if args.preview:
        preview(pages, args.preview)
    else:
        render(pages, args.out)


if __name__ == "__main__":
    main()
