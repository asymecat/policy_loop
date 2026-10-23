#!/usr/bin/env python3
"""生成 PolicyLoop 答辩 PPT。

版式：沿用 2026 开源鸿蒙大学生创新大赛 赛道一 答辩模板（16:9 / 微软雅黑 / 蓝色强调）。
内容取舍：一页只说一件事；正文最小 16 pt（`fmt()` 会拒绝更小的字号）；
数字页用大字号统计，不用密表。

用法：
    python3 tools/build_ppt.py                    # 输出 docs/policy_loop-答辩.pptx
    python3 tools/build_ppt.py --out /tmp/a.pptx
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
TEMPLATE = Path.home() / "下载" / "xxx团队-赛道一-答辩模板.pptx"

# ── 设计令牌（与模板同源的蓝白体系）──────────────────────────────
INK = RGBColor(0x0F, 0x14, 0x23)
GRAY = RGBColor(0x5B, 0x64, 0x74)
MUTED = RGBColor(0x8A, 0x93, 0xA3)
ACCENT = RGBColor(0x00, 0xB0, 0xF0)
ACCENT_DARK = RGBColor(0x00, 0x78, 0xB4)
TINT = RGBColor(0xEA, 0xF6, 0xFD)
TINT2 = RGBColor(0xF5, 0xFA, 0xFE)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
RED = RGBColor(0xE5, 0x4C, 0x5E)
GREEN = RGBColor(0x3E, 0xA6, 0x5B)
ORANGE = RGBColor(0xEE, 0x82, 0x2F)

FONT = "微软雅黑"
SLIDE_W, SLIDE_H = 13.333, 7.5
BODY_TOP = 1.28
BODY_LEFT = 0.55
BODY_W = SLIDE_W - 2 * BODY_LEFT
BODY_H = 5.45

# 正文最小字号：评审在投影上要能直接读，任何更小的字号都算版式缺陷。
MIN_PT = 16


# ── 基础工具 ──────────────────────────────────────────────────
def set_ea(run, face: str = FONT) -> None:
    rPr = run._r.get_or_add_rPr()
    ea = rPr.find(qn("a:ea"))
    if ea is None:
        ea = rPr.makeelement(qn("a:ea"), {})
        latin = rPr.find(qn("a:latin"))
        if latin is not None:
            latin.addnext(ea)
        else:
            rPr.append(ea)
    ea.set("typeface", face)


def fmt(run, size: float, bold: bool = False, color: RGBColor = INK) -> None:
    if size < MIN_PT:
        raise ValueError(f"字号 {size} 小于下限 {MIN_PT} pt")
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    run.font.name = FONT
    set_ea(run)


def textbox(slide, x, y, w, h, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    tf.vertical_anchor = anchor
    return box


def para(tf, first: bool = False):
    return tf.paragraphs[0] if first else tf.add_paragraph()


def write(p, text, size, bold=False, color=INK, before=0, after=0,
          line=1.15, align=PP_ALIGN.LEFT):
    r = p.add_run()
    r.text = text
    fmt(r, size, bold, color)
    p.space_before = Pt(before)
    p.space_after = Pt(after)
    p.line_spacing = line
    p.alignment = align
    return r


def card(slide, x, y, w, h, fill=TINT2, line_color=None, radius=0.06):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.adjustments[0] = radius
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    if line_color is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line_color
        shape.line.width = Pt(1)
    shape.shadow.inherit = False
    tf = shape.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP
    tf.margin_left = tf.margin_right = Inches(0.18)
    tf.margin_top = Inches(0.12)
    tf.margin_bottom = Inches(0.10)
    return shape


def write_multiline(tf, text, size, bold=False, color=INK, gap=0, line=1.3,
                    first=False, before=0):
    """把含 \\n 的文案拆成真正的段落 —— 换行符塞进 <a:t> 会让渲染器自己编缩进。"""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        p = para(tf, first=(first and i == 0))
        write(p, ln, size, bold, color, line=line,
              before=before if i == 0 else gap)
    return tf


def card_text(shape, head, body=None, head_size=19, body_size=16,
              head_color=INK, body_color=GRAY, gap=8, line=1.3):
    tf = shape.text_frame
    p = tf.paragraphs[0]
    write(p, head, head_size, True, head_color, after=gap, line=line)
    if body:
        write_multiline(tf, body, body_size, False, body_color, gap=2, line=line)
    return tf


def stat(slide, x, y, w, h, number, label, num_size=32, label_size=16,
         color=ACCENT_DARK):
    shape = card(slide, x, y, w, h, fill=WHITE, line_color=TINT)
    tf = shape.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = tf.margin_right = Inches(0.10)
    p = tf.paragraphs[0]
    write(p, number, num_size, True, color, align=PP_ALIGN.CENTER, after=4, line=1.0)
    p2 = tf.add_paragraph()
    write(p2, label, label_size, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)


def picture_fit(slide, path: Path, x, y, w, h, align="center"):
    """按比例放进 (x,y,w,h) 盒子，不裁切、不拉伸。"""
    from PIL import Image
    iw, ih = Image.open(path).size
    scale = min(w / iw, h / ih)
    dw, dh = iw * scale, ih * scale
    dx = x + (w - dw) / 2 if align == "center" else x
    dy = y + (h - dh) / 2
    return slide.shapes.add_picture(str(path), Inches(dx), Inches(dy),
                                    Inches(dw), Inches(dh))


def band(slide, y, text, size=18, height=0.75, fill=INK,
         color=WHITE, bold=False, x=BODY_LEFT, w=BODY_W):
    shape = card(slide, x, y, w, height, fill=fill)
    tf = shape.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = Inches(0.28)
    p = tf.paragraphs[0]
    write(p, text, size, bold, color, line=1.25)
    return shape


# ── 页面骨架 ──────────────────────────────────────────────────
def content_slide(prs, layout, title, kicker=None):
    slide = prs.slides.add_slide(layout)
    for ph in list(slide.placeholders):
        if ph.placeholder_format.idx == 13:      # 模板的内容页标题占位符
            ph.left, ph.top = Inches(BODY_LEFT), Inches(0.20)
            ph.width, ph.height = Inches(9.4), Inches(0.62)
            tf = ph.text_frame
            tf.word_wrap = True
            tf.vertical_anchor = MSO_ANCHOR.MIDDLE
            p = tf.paragraphs[0]
            for r in list(p.runs):
                r._r.getparent().remove(r._r)
            write(p, title, 25, True, INK, line=1.0)
    if kicker:
        tb = textbox(slide, BODY_LEFT + 0.02, 0.86, BODY_W, 0.3)
        p = tb.text_frame.paragraphs[0]
        write(p, kicker, 16, False, MUTED, line=1.0)
    return slide


def slide_number_placeholder(slide, idx):
    """复制模板的页码域（跟随母版定位，不写死数字）。"""
    xml = (
        '<p:sp xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<p:nvSpPr><p:cNvPr id="{i}" name="灯片编号占位符 {i}"/>'
        '<p:cNvSpPr><a:spLocks noGrp="true"/></p:cNvSpPr>'
        '<p:nvPr><p:ph type="sldNum" sz="quarter" idx="12"/></p:nvPr></p:nvSpPr>'
        '<p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:fld id="{{49AE70B2-8BF9-45C0-BB95-33D1B9D3A854}}" '
        'type="slidenum"><a:rPr lang="zh-CN" altLang="en-US"><a:latin typeface="微软雅黑"/>'
        '<a:ea typeface="微软雅黑"/></a:rPr><a:t>{i}</a:t></a:fld></a:p></p:txBody></p:sp>'
    ).format(i=idx)
    from pptx.oxml import parse_xml
    sp = parse_xml(xml)
    slide.shapes._spTree.append(sp)


# ── 各页 ──────────────────────────────────────────────────────
def cover(prs):
    s = prs.slides[0]
    for shp in s.shapes:
        if not shp.has_text_frame:
            continue
        texts = [r.text for p in shp.text_frame.paragraphs for r in p.runs]
        joined = "".join(texts)
        if "赛题名称" in joined:
            runs = [r for pp in shp.text_frame.paragraphs for r in pp.runs]
            runs[0].text = "PolicyLoop"
            runs[1].text = "：SELinux 拒绝日志的最小权限自收敛"
        elif "团队名称" in joined:
            runs = [r for pp in shp.text_frame.paragraphs for r in pp.runs]
            runs[0].text = "PolicyLoop 门禁团队"
            runs[1].text = ""
            runs[2].text = "2026"
            runs[4].text = "10"
            runs[6].text = "20"
        elif "开源鸿蒙大学生创新大赛" in joined:
            pass
    return s


def toc(prs):
    s = prs.slides[1]
    items = ["问题与目标", "设计与实现", "实测与边界"]
    # 按纵坐标排序：形状的文档顺序不是视觉顺序（模板里 01 的框在最后）
    boxes = sorted(
        (shp for shp in s.shapes
         if shp.has_text_frame and shp.text_frame.text.strip().startswith("子标题")),
        key=lambda shp: shp.top)
    for shp, item in zip(boxes, items):
        runs = [r for p in shp.text_frame.paragraphs for r in p.runs]
        if runs:
            runs[0].text = item
            for r in runs[1:]:
                r.text = ""
    # 目录下方留白太多，用一句主线把三部分串起来
    band(s, 5.45, "denial → 七个 Agent → 最小补丁 → 真机闭环",
         size=17, height=0.7, fill=TINT, color=ACCENT_DARK, bold=True,
         x=3.95, w=7.55)
    return s


def s_problem(prs, lay):
    s = content_slide(prs, lay, "一条 denial，卡住三件事")
    heads = [
        ("读不懂", "scontext / tcontext / tclass\n是一套自成体系的词汇。"),
        ("找不准", "1,315 个 .te 文件按子系统分目录，\n该落在哪靠经验。"),
        ("补不对", "见 denial 就加 allow，\n把越权固化成永久授权。"),
    ]
    w, gap = 3.93, 0.22
    for i, (h, b) in enumerate(heads):
        x = BODY_LEFT + i * (w + gap)
        c = card(s, x, 1.45, w, 2.15)
        card_text(c, h, b, head_size=21, body_size=16, gap=10)
    band(s, 3.9, "常见应对：把门禁关成 permissive —— 系统正常了，门没有了。", size=18)
    tb = textbox(s, BODY_LEFT, 4.85, BODY_W, 0.3)
    write(tb.text_frame.paragraphs[0], "上游策略仓库一次全量统计", 16, True, ACCENT_DARK)
    stats = [
        ("1,315", "个 .te 文件"),
        ("51,427", "行策略源码"),
        ("5,230", "条历史 denial"),
        ("21,824", "条索引规则"),
    ]
    w2, gap2 = 2.9, 0.19
    for i, (n, l) in enumerate(stats):
        stat(s, BODY_LEFT + i * (w2 + gap2), 5.25, w2, 1.3, n, l, num_size=30)
    return s


def s_differentiators(prs, lay):
    s = content_slide(prs, lay, "记住这三件事", "别的方案给不出这三个数")
    data = [
        ("0 误报", "5,161 条真实日志", "自动补丁零误报", ACCENT_DARK),
        ("2.98 MB", "27,912 条查询", "两端输出逐字节相同", ACCENT_DARK),
        ("0 条", "1,580 条转人工", "真正要补权限 0 条", GREEN),
    ]
    w, gap = 3.93, 0.22
    for i, (n, l1, l2, col) in enumerate(data):
        c = card(s, BODY_LEFT + i * (w + gap), 1.5, w, 3.0,
                 fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 54, True, col, align=PP_ALIGN.CENTER, after=12, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, l1, 18, True, INK, align=PP_ALIGN.CENTER, after=4, line=1.2)
        p3 = tf.add_paragraph()
        write(p3, l2, 16, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)
    band(s, 5.0, "难点不在写规则，而在敢让它自动写 —— 守门把「敢」变成可验证。",
         size=19, height=0.8, bold=True)
    return s


def s_goal(prs, lay):
    s = content_slide(prs, lay, "只回答一个问题：该不该放行",
                      "和「看到 denial 就放行」的区别")
    rows = [
        ("看到 denial 就加 allow", "先问：撞不撞系统红线"),
        ("加一条能通的规则", "再问：最小的那条是什么"),
        ("denial 消失就算修好", "最后：真消除，且无回归"),
    ]
    for i, (a, b) in enumerate(rows):
        c = card(s, BODY_LEFT, 1.5 + i * 1.35, BODY_W, 1.15,
                 fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        r = p.add_run(); r.text = a; fmt(r, 18, False, GRAY)
        r = p.add_run(); r.text = "   →   "; fmt(r, 18, True, MUTED)
        r = p.add_run(); r.text = b; fmt(r, 19, True, ACCENT_DARK)
    band(s, 5.75, "验收可量化：覆盖率 · 最小性 · 零越权 · 两端逐字节一致",
         size=18, height=0.75, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_arch(prs, lay):
    s = content_slide(prs, lay, "总体架构：主机端重、设备端轻",
                      "L1 内核  →  L2 评测  →  L3 流水线  →  L4 设备端")
    picture_fit(s, DOCS / "figs" / "fig1-architecture.png",
                BODY_LEFT, 1.38, BODY_W, 4.35)
    band(s, 5.95, "两侧只通过一条窄接口相连：PLI 只读索引 + JSON / TSV 判定结果",
         size=17, height=0.7, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_principles(prs, lay):
    s = content_slide(prs, lay, "四条原则，一条底线", "所有安全决策都由规则做")
    data = [
        ("① 确定性内核优先", "安全决策全是规则，LLM 只写解释。"),
        ("② 绝不自动写盘", "只出建议补丁，写盘由人决定。"),
        ("③ 先仿真，后真机", "上游语料量化，再上板取独立证据。"),
        ("④ 设备端只搬一段", "要读 kmsg、要脱离 PC 的才下沉。"),
    ]
    w, h, gap = 5.85, 2.0, 0.28
    for i, (hd, bd) in enumerate(data):
        x = BODY_LEFT + (i % 2) * (w + gap)
        y = 1.45 + (i // 2) * (h + 0.2)
        c = card(s, x, y, w, h)
        c.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        card_text(c, hd, bd, head_size=21, body_size=17, gap=12)
    band(s, 5.9, "底线：安全决策永不交给模型。", size=18, height=0.68,
         fill=INK, bold=True)
    return s


def s_neverallow(prs, lay):
    s = content_slide(prs, lay, "设备端为什么不能「自己推策略」",
                      "两个实测事实，逼出一条架构约束")
    left = [
        ("设备上没有 .te 源码",
         "只剩 policy.31（424,699 B）\n与 *_contexts。"),
        ("红线不在二进制策略里",
         "neverallow 是编译期断言，\n不写进产物。"),
    ]
    for i, (hd, bd) in enumerate(left):
        c = card(s, BODY_LEFT, 1.45 + i * 2.15, 5.95, 1.95)
        c.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        card_text(c, hd, bd, head_size=19, body_size=16, gap=10)
    x = BODY_LEFT + 6.3
    flow = [
        ("拿不到红线", RED),
        ("只能「见 denial 就放行」", RED),
        ("正是最该避免的行为", RED),
        ("索引必须构建期导出", ACCENT_DARK),
    ]
    y = 1.45
    for i, (t, col) in enumerate(flow):
        c = card(s, x, y, BODY_W - 6.3, 0.85, fill=WHITE,
                 line_color=ACCENT if i == len(flow) - 1 else TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, ("→ " if i else "") + t, 17, i == len(flow) - 1, col, line=1.15)
        y += 1.0
    band(s, 5.95, "570 条红线索引可见 430 条；缺口由部署期 secilc 断言补第二道",
         size=16, height=0.7, fill=INK)
    return s


def s_pipeline(prs, lay):
    s = content_slide(prs, lay, "七个 Agent，一条单向链",
                      "每步输入输出都是可打印的结构化字段")
    picture_fit(s, DOCS / "figs" / "fig2-agent-pipeline.png",
                BODY_LEFT, 1.32, BODY_W, 4.25)
    tb = textbox(s, BODY_LEFT, 5.72, BODY_W, 0.85)
    tf = tb.text_frame
    p = tf.paragraphs[0]
    write(p, "CrossLayerAgent 只读：加不加它，结论不变。", 17, False, INK, line=1.3)
    p2 = tf.add_paragraph()
    write(p2, "流水线没有回路：Verify 失败直接转人工。", 17, False, INK, line=1.3)
    return s


def s_guards(prs, lay):
    s = content_slide(prs, lay, "五道拒绝点：不猜、不宽、不放红线",
                      "与设备端共用同一份守门实现")
    tb = textbox(s, BODY_LEFT, 1.45, 6.0, 3.9)
    tf = tb.text_frame
    gates = [
        ("撞 neverallow", "转人工"),
        ("解析后仍不许", "拒发补丁"),
        ("占位符未解析", "不猜"),
        ("过宽 / 危险模式", "拦截"),
        ("未验证消除与回归", "不通过"),
    ]
    for i, (h, b) in enumerate(gates):
        p = para(tf, first=(i == 0))
        m = p.add_run(); m.text = f"{i + 1}  "; fmt(m, 22, True, ACCENT)
        r = p.add_run(); r.text = h; fmt(r, 17, True, INK)
        r = p.add_run(); r.text = "  →  "; fmt(r, 16, True, MUTED)
        r = p.add_run(); r.text = b; fmt(r, 17, False, GRAY)
        p.space_before = Pt(0 if i == 0 else 14)
        p.line_spacing = 1.15
    tb2 = textbox(s, BODY_LEFT, 4.75, 6.0, 0.5)
    write(tb2.text_frame.paragraphs[0], "五道各堵一类失败。", 16, False, MUTED)

    x = BODY_LEFT + 6.45
    c = card(s, x, 1.42, BODY_W - 6.45, 3.9, fill=WHITE, line_color=ACCENT)
    tf = c.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    write(p, "典型反例：只差一个命令号", 18, True, INK, after=10)
    write_multiline(tf, "ioctl 大类已允许，缺的只是 0x8014。",
                    16, False, GRAY, gap=8, line=1.35)
    p = tf.add_paragraph()
    write(p, "allowxperm render_service", 16, True, ACCENT_DARK, line=1.2, before=8)
    p = tf.add_paragraph()
    write(p, "dev_mali:chr_file ioctl { 0x8014 };", 16, True, ACCENT_DARK, line=1.2)
    p = tf.add_paragraph()
    write(p, "上游后来真的加了这一行。", 16, False, MUTED, line=1.3, before=8)
    band(s, 5.8, "六道 apply_guards：MLS 级目标 / 占位符 / 目标不在语料 / 类不在语料 / 非权限名 / 空权限",
         size=16, height=0.72, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_converge(prs, lay):
    s = content_slide(prs, lay, "一份日志，4.16 秒出清单",
                      "python -m policy_loop.converge")
    picture_fit(s, DOCS / "figs" / "fig3-converge-flow.png",
                BODY_LEFT, 1.45, 7.4, 4.15)
    x = BODY_LEFT + 7.85
    stats = [
        ("5,161 → 4,911", "日志行 → 唯一案例", ACCENT_DARK),
        ("3,261", "噪声 / 已被允许", MUTED),
        ("70", "可自动补丁", GREEN),
        ("1,580", "转人工", ORANGE),
    ]
    y = 1.45
    for n, l, col in stats:
        c = card(s, x, y, BODY_W - 7.85, 0.95, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        r = p.add_run(); r.text = n + "  "; fmt(r, 22, True, col)
        r = p.add_run(); r.text = l; fmt(r, 16, False, GRAY)
        p.line_spacing = 1.1
        y += 1.1
    band(s, 5.95, "全量零误报进入自动项；转人工是主动拒绝越权",
         size=17, height=0.7, fill=INK)
    return s


def s_minimize(prs, lay):
    s = content_slide(prs, lay, "补丁 69 行 → 54 条根因规则",
                      "先最小化，再套回索引反验")
    cards = [
        ("69 → 54", "补丁行数", ACCENT_DARK),
        ("10 组", "根因归并", ACCENT_DARK),
        ("70 → 0", "闭环反验", GREEN),
        ("0 残留", "归因", GREEN),
    ]
    w, gap = 2.9, 0.19
    for i, (n, l, col) in enumerate(cards):
        stat(s, BODY_LEFT + i * (w + gap), 1.5, w, 1.55, n, l,
             num_size=32, label_size=16, color=col)
    band(s, 3.35, "反验要求：补丁前确实没解决，套回后全部解决。",
         size=17, height=0.72, fill=TINT, color=INK)
    c = card(s, BODY_LEFT, 4.45, BODY_W, 1.55, fill=WHITE, line_color=ACCENT)
    tf = c.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    write(p, "最窄规则按影响面判，不按 token 数", 19, True, INK, after=8)
    p = tf.add_paragraph()
    write(p, "{domain} 1 个 token 覆盖 235 个类型。", 16, False, GRAY, line=1.3)
    return s


def s_attribution(prs, lay):
    s = content_slide(prs, lay, "1,580 条转人工，真正要补权限 0 条",
                      "每条都回答了「该谁修」")
    items = [
        ("1,147", "历史噪声", MUTED),
        ("342", "工具对齐", ACCENT_DARK),
        ("53", "日志质量", ORANGE),
        ("38", "撞红线", RED),
    ]
    w, gap = 2.9, 0.19
    for i, (n, l, col) in enumerate(items):
        c = card(s, BODY_LEFT + i * (w + gap), 1.5, w, 1.25,
                 fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 32, True, col, align=PP_ALIGN.CENTER, after=3, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, l, 16, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)
    c = card(s, BODY_LEFT, 3.15, 4.0, 2.2, fill=TINT, line_color=ACCENT)
    tf = c.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    write(p, "0", 66, True, GREEN, align=PP_ALIGN.CENTER, line=1.0, after=4)
    p2 = tf.add_paragraph()
    write(p2, "真正需要给设备补权限", 16, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)
    tb = textbox(s, BODY_LEFT + 4.45, 3.2, BODY_W - 4.45, 2.2)
    tf = tb.text_frame
    p = tf.paragraphs[0]
    write(p, "1,580 → 1,580，残留 0。", 19, True, INK, after=10)
    p = tf.add_paragraph()
    write(p, "退出码 0 就是判据。", 16, False, GRAY, line=1.3, after=8)
    p = tf.add_paragraph()
    write(p, "「需人工」不是洞，是主动拒绝越权。", 17, True, ACCENT_DARK, line=1.3)
    band(s, 5.65, "跨树稳定的是 DEVICE = 0；原因码数量随所选上游树变化",
         size=16, height=0.7, fill=TINT, color=INK)
    return s


def s_parity(prs, lay):
    s = content_slide(prs, lay, "两端独立实现，输出逐字节相同",
                      "Python 与 C++ 喂同一份输入")
    cards = [
        ("5 / 5", "门禁全绿", "自检 48 组，0 失败"),
        ("27,912", "条查询", "覆盖 5 个字段"),
        ("2.98 MB", "逐字节相同", "输出体 sha256 一致"),
    ]
    w, gap = 3.93, 0.22
    for i, (n, l1, l2) in enumerate(cards):
        c = card(s, BODY_LEFT + i * (w + gap), 1.55, w, 2.45,
                 fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 46, True, ACCENT_DARK, align=PP_ALIGN.CENTER, after=8, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, l1, 19, True, INK, align=PP_ALIGN.CENTER, after=4)
        p3 = tf.add_paragraph()
        write(p3, l2, 16, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)
    band(s, 4.45, "四个语义陷阱：空 perms 通配 / xperm 大小写 / permissive 三态 / 未知 perm 名 —— 错一个哈希就炸。",
         size=16, height=0.85, fill=INK)
    tb = textbox(s, BODY_LEFT, 5.55, BODY_W, 0.8)
    write(tb.text_frame.paragraphs[0],
          "设备端是独立实现（C++ / musl），不是宿主程序的移植。", 17, False, GRAY)
    return s


def s_perf(prs, lay):
    s = content_slide(prs, lay, "倒排索引：设备 34×，宿主 238×",
                      "从扫 21,824 条规则，变成查一个 (src, tgt, cls) 桶")
    data = [
        ("34×", "设备查询", "0.0987 → 0.0029 ms/条"),
        ("238×", "宿主判定", "8.842 s → 0.037 s"),
        ("151 → 1", "索引建表", "每棵树只建一次"),
    ]
    w, gap = 3.93, 0.22
    for i, (n, t, l) in enumerate(data):
        c = card(s, BODY_LEFT + i * (w + gap), 1.5, w, 2.5,
                 fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 46, True, ACCENT_DARK, align=PP_ALIGN.CENTER, after=8, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, t, 19, True, INK, align=PP_ALIGN.CENTER, after=4)
        p3 = tf.add_paragraph()
        write(p3, l, 16, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)
    band(s, 4.45, "板端 71.25 s 是旧代码实测；约 2 s 是 34× 外推，上板需复测。",
         size=17, height=0.8, fill=TINT, color=INK)
    return s


def s_llm(prs, lay):
    s = content_slide(prs, lay, "LLM 默认过宽，护栏按回最小",
                      "同批真实 denial 的三档对照")
    c = card(s, BODY_LEFT, 1.6, 4.9, 2.8, fill=WHITE, line_color=RED)
    tf = c.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    write(p, "100%", 66, True, RED, align=PP_ALIGN.CENTER, after=6, line=1.0)
    p2 = tf.add_paragraph()
    write(p2, "无约束 AI 直接放权", 19, True, INK, align=PP_ALIGN.CENTER, after=3)
    p3 = tf.add_paragraph()
    write(p3, "120/120 过宽", 16, False, GRAY, align=PP_ALIGN.CENTER)

    tb = textbox(s, BODY_LEFT + 5.15, 2.5, 1.3, 0.9)
    write(tb.text_frame.paragraphs[0], "→", 44, True, MUTED, align=PP_ALIGN.CENTER)

    c = card(s, BODY_LEFT + 6.7, 1.6, 4.9, 2.8, fill=WHITE, line_color=GREEN)
    tf = c.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    write(p, "0%", 66, True, GREEN, align=PP_ALIGN.CENTER, after=6, line=1.0)
    p2 = tf.add_paragraph()
    write(p2, "加确定性守门", 19, True, INK, align=PP_ALIGN.CENTER, after=3)
    p3 = tf.add_paragraph()
    write(p3, "120/120 拦回最小", 16, False, GRAY, align=PP_ALIGN.CENTER)

    tb = textbox(s, BODY_LEFT, 4.65, BODY_W, 0.7)
    write(tb.text_frame.paragraphs[0],
          "越权倾向消不掉，只能靠规则兜住。", 21, True, INK, align=PP_ALIGN.CENTER)
    band(s, 5.5, "真实 LLM 在最小权限指令下 54/54 精确最小 —— 模型不是问题，无约束才是。",
         size=16, height=0.75, fill=TINT, color=INK)
    return s


def s_ui(prs, lay):
    s = content_slide(prs, lay, "界面：如实区分数据来源",
                      "主机端 Agent Trace  ·  板端实时卡片  ·  快照现读")
    pics = [
        (DOCS / "screenshots" / "fig5-agent-trace.png", 2.95, "主机端 Agent Trace"),
        (DOCS / "screenshots" / "fig6-board-live-cards.png", 2.80, "板端实时卡片"),
        (DOCS / "screenshots" / "fig7-board-snapshot.png", 2.80, "板端快照"),
    ]
    x = 1.95
    for path, w, cap in pics:
        picture_fit(s, path, x, 1.35, w, 4.2)
        tb = textbox(s, x - 0.3, 5.65, w + 0.6, 0.35)
        write(tb.text_frame.paragraphs[0], cap, 16, False, MUTED,
              align=PP_ALIGN.CENTER)
        x += w + 0.55
    band(s, 6.1, "工具造成的 denial 明确标注，不冒充分析结果。",
         size=16, height=0.62, fill=INK)
    return s


def s_board(prs, lay):
    s = content_slide(prs, lay, "真机：拨一次开关，1~2 秒出结论",
                      "RK3568  ·  OpenHarmony 5.0.3.135  ·  enforcing")
    picture_fit(s, DOCS / "figs" / "fig4-board-runtime.png",
                BODY_LEFT, 1.35, 8.4, 4.3)
    x = BODY_LEFT + 8.65
    cw = BODY_W - 8.65
    items = [
        ("正规 init service", "开机自启，自有 enforcing 域。"),
        ("冷启动即采集", "up 0 min 已在采集，本域 denial 0。"),
        ("端到端 1~2 秒", "拨开关 → 采集 → 分析 → 通知。"),
    ]
    y = 1.45
    for hd, bd in items:
        c = card(s, x, y, cw, 1.3, fill=WHITE, line_color=TINT)
        card_text(c, hd, bd, head_size=17, body_size=16, gap=5, line=1.25)
        y += 1.45
    band(s, 5.95, "部署依赖 PC，运行不依赖 PC。",
         size=19, height=0.7, bold=True)
    return s


def s_numbers(prs, lay):
    s = content_slide(prs, lay, "最强的结果", "每个数字都能用附录 A 复现")
    data = [
        ("0 误报", "5,161 条真实日志\n自动项零误报"),
        ("99.94%", "索引召回率\n未覆盖仅 2 条"),
        ("100%", "补丁精确最小\n179/179"),
        ("2.98 MB", "两端输出\n逐字节相同"),
        ("34×", "设备查询加速\n宿主 238×"),
        ("0 条", "1,580 条转人工\n要补权限 0 条"),
    ]
    w, h, gap = 3.93, 2.05, 0.22
    for i, (n, l) in enumerate(data):
        x = BODY_LEFT + (i % 3) * (w + gap)
        y = 1.45 + (i // 3) * (h + 0.22)
        c = card(s, x, y, w, h, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 44, True, ACCENT_DARK, align=PP_ALIGN.CENTER, after=8, line=1.0)
        for ln in l.split("\n"):
            write(tf.add_paragraph(), ln, 16, False, GRAY,
                  align=PP_ALIGN.CENTER, line=1.25)
    band(s, 5.95, "三个零：零误报 · 零过宽 · 零待补权限。",
         size=18, height=0.65, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_pitfalls(prs, lay):
    s = content_slide(prs, lay, "四个坑，每一个都改了设计",
                      "共同点：都是「看起来正常」的假象")
    data = [
        ("neverallow 不在二进制里", "设备端不能自建语义。"),
        ("printk 会静默丢 denial", "日志和采集器一起失明。"),
        ("init 的 caps 是整套替换", "只有 SYSLOG，就没了 DAC_OVERRIDE。"),
        ("差分语料证不了分支", "固定向量首跑抓出 2 个偏差。"),
    ]
    w, h, gap = 5.85, 1.9, 0.28
    for i, (hd, bd) in enumerate(data):
        x = BODY_LEFT + (i % 2) * (w + gap)
        y = 1.45 + (i // 2) * (h + 0.2)
        c = card(s, x, y, w, h, fill=WHITE, line_color=TINT)
        card_text(c, hd, bd, head_size=18, body_size=16, gap=8)
    band(s, 5.75, "服务活着、日志干净、策略也对 —— 缺陷藏在看不见的地方。",
         size=16, height=0.7, fill=INK)
    return s


def s_limits(prs, lay):
    s = content_slide(prs, lay, "每个数字能证明什么",
                      "安全工具的可信度来自说清边界")
    data = [
        ("语料来自上游", "96.8% 逐字来自 .te 注释。"),
        ("自洽不等于金标准", "100% 是留一法自洽验证。"),
        ("外推值必须标注", "板端约 2 s 是外推。"),
        ("证伪也写进结论", "boolean / constrain 在本平台不存在。"),
    ]
    w, h, gap = 5.85, 1.55, 0.28
    for i, (hd, bd) in enumerate(data):
        x = BODY_LEFT + (i % 2) * (w + gap)
        y = 1.45 + (i // 2) * (h + 0.2)
        c = card(s, x, y, w, h, fill=WHITE, line_color=TINT)
        card_text(c, hd, bd, head_size=18, body_size=16, gap=7)
    band(s, 4.95, "索引须与策略树对齐：板子 5.0.3.135 ≠ 编译树 6.1.0.31。",
         size=17, height=0.8, fill=INK)
    return s


def s_next(prs, lay):
    s = content_slide(prs, lay, "不足与下一步")
    c1 = card(s, BODY_LEFT, 1.5, 5.85, 3.1)
    tf = c1.text_frame
    p = tf.paragraphs[0]
    write(p, "交付前必补", 19, True, ACCENT_DARK, after=14)
    for t in [
        "板端 34× 与 explain 向量待真机复测",
        "HAP 开机不自启，需手点一次",
        "cross-layer / hap 计数仍待真机证据",
    ]:
        p = tf.add_paragraph()
        m = p.add_run(); m.text = "▍ "; fmt(m, 16, True, ACCENT)
        r = p.add_run(); r.text = t; fmt(r, 16, False, INK)
        p.space_before = Pt(12); p.line_spacing = 1.3

    c2 = card(s, BODY_LEFT + 6.15, 1.5, BODY_W - 6.15, 3.1,
              fill=WHITE, line_color=TINT)
    tf = c2.text_frame
    p = tf.paragraphs[0]
    write(p, "下一步", 19, True, ACCENT_DARK, after=14)
    for t in [
        "改审计 netlink，取无损通道",
        "索引降到板子版本 5.0.3",
        "板内触发，闭环不依赖 PC",
    ]:
        p = tf.add_paragraph()
        m = p.add_run(); m.text = "▍ "; fmt(m, 16, True, ACCENT)
        r = p.add_run(); r.text = t; fmt(r, 16, False, INK)
        p.space_before = Pt(12); p.line_spacing = 1.3
    band(s, 5.05, "先把演示链上的断言都补成真机证据。",
         size=18, height=0.7, fill=INK, bold=True)
    return s


# ── 讲稿备注（每题时长按 21 页 / 11 分钟配）──────────────────────
NOTES = [
    # 封面
    "开场（约 10 秒）：各位评委老师好，我们是 PolicyLoop 门禁团队。参赛作品 PolicyLoop，"
    "解决 OpenHarmony SELinux 拒绝日志的诊断与最小权限修复问题。",
    # 目录
    "约 10 秒：三部分 —— 为什么要做、怎么做、实测到什么程度；以及我们主动划出的边界。",
    # 问题
    "约 45 秒：一条 denial 卡住三件事：读不懂、找不准、补不对。现场常见的应对是把门禁关成 permissive —— "
    "功能恢复了，强制访问控制却没有了。上游自己的注释里就埋着 5,230 条历史 denial，全靠人力诊断。",
    # 三件事
    "约 30 秒：如果只让评委记住一页，就是这一页。零误报、两端逐字节相同、真正要补权限 0 条 —— "
    "这三个数别的方案给不出来。",
    # 目标
    "约 30 秒：我们不回答「这条访问能不能放行」，回答「该不该放行」：先问红线，再问最小，最后验证真消除且无回归。",
    # 架构
    "约 30 秒：按「能独立验证」分四层，主机端重、设备端轻，中间只有 PLI 只读索引和判定结果这条窄接口。",
    # 四原则
    "约 25 秒：四原则的核心是第一条：安全决策全部由确定性规则做，LLM 只写解释；第二条，工具永不自动写盘。",
    # neverallow
    "约 40 秒：为什么不把整个系统搬到设备上？设备上没有 .te 源码，neverallow 又是编译期断言、不进二进制。"
    "拿不到红线，工具就退化成「见 denial 就放行」。所以索引必须构建期导出。",
    # 流水线
    "约 35 秒：七个 Agent 单向执行。两个刻意设计：CrossLayer 只读，加不加结论不变；流水线没有回路，"
    "Verify 失败直接转人工 —— 允许重试等于迭代出更宽的补丁。",
    # 守门
    "约 30 秒：五道拒绝点，加上六道 apply_guards。右边这个真实例子最能说明问题：只差一个命令号，"
    "「见 denial 就加 allow」会写一条已经存在的规则，我们给的是 allowxperm。",
    # 收敛
    "约 30 秒：5,161 条日志去重成 4,911 个案例，4.16 秒出清单：70 类可自动补丁，1,580 类转人工。"
    "转人工是主动拒绝越权，不是做不到。",
    # 最小化
    "约 25 秒：补丁从 69 行归并到 54 条根因规则，再套回索引反验前后都关上。最窄规则按影响面判，不按 token 数。",
    # 归因
    "约 30 秒：1,580 条逐条回答「该谁修」，真正需要给设备补权限的是 0 条。"
    "大部分是语料历史噪声，38 条是撞红线的架构决策。",
    # 两端一致
    "约 30 秒：设备端是独立的 C++ 实现。五项门禁全绿，最有说服力的是 27,912 条查询、2.98 MB 输出逐字节相同。"
    "四个语义陷阱，错一个哈希就炸。",
    # 性能
    "约 25 秒：线性扫描换成类型对倒排索引，设备 34 倍、宿主 238 倍。板端约 2 秒是外推，上板后要复测。",
    # LLM
    "约 25 秒：未受约束的 AI 直接放权，过宽率 100%；同批样本经确定性护栏，0%。越权倾向消不掉，只能靠规则兜住。",
    # 界面
    "约 20 秒：界面原则是如实区分数据来源：工具造成的 denial 必须标注，不冒充分析结果。",
    # 真机
    "约 30 秒：采集器是正规 init service，开机自启、自有 enforcing 域，拨一次开关 1~2 秒出结论。"
    "部署依赖 PC，运行不依赖 PC。",
    # 关键数字
    "约 20 秒：六个最强的数字，每一个都能用附录 A 复现。",
    # 坑
    "约 30 秒：四个坑都改过设计，共同点是「看起来正常」的假象：服务活着、日志干净、策略也对，缺陷在看不见的地方。",
    # 边界
    "约 25 秒：安全工具的可信度来自说清边界：语料来自上游、自洽不等于金标准、外推值必须标注、证伪也要写。",
    # 下一步
    "约 20 秒：交付前必补的和下一步方向。谢谢各位老师。",
]


# ── 组装 ──────────────────────────────────────────────────────
def build(out: Path) -> Path:
    prs = Presentation(str(TEMPLATE))
    layout = prs.slide_layouts[4]          # 模板内容页用的版式

    cover(prs)
    toc(prs)
    thanks_rid = list(prs.slides._sldIdLst)[3].rId   # 模板的「谢谢」页

    builders = [
        s_problem, s_differentiators, s_goal, s_arch, s_principles,
        s_neverallow, s_pipeline, s_guards, s_converge, s_minimize,
        s_attribution, s_parity, s_perf, s_llm, s_ui, s_board,
        s_numbers, s_pitfalls, s_limits, s_next,
    ]
    for i, fn in enumerate(builders):
        s = fn(prs, layout)
        slide_number_placeholder(s, i + 3)
        s.notes_slide.notes_text_frame.text = NOTES[i + 2]

    # 封面与目录也给一句开场/串场
    prs.slides[0].notes_slide.notes_text_frame.text = NOTES[0]
    prs.slides[1].notes_slide.notes_text_frame.text = NOTES[1]

    # 删掉模板里的空白示例内容页（放在新建之后，避免 partname 撞名）
    xml_slides = prs.slides._sldIdLst
    ids = list(xml_slides)
    prs.part.drop_rel(ids[2].rId)
    xml_slides.remove(ids[2])

    # 「谢谢」页挪到最后
    thanks = [el for el in xml_slides if el.rId == thanks_rid][0]
    xml_slides.remove(thanks)
    xml_slides.append(thanks)

    out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=DOCS / "policy_loop-答辩.pptx")
    args = ap.parse_args()
    p = build(args.out)
    prs = Presentation(str(p))
    print(f"→ {p}  ({len(prs.slides._sldIdLst)} 页)")
    for i, s in enumerate(prs.slides, 1):
        title = ""
        for ph in s.placeholders:
            if ph.placeholder_format.type == 13:      # SLIDE_NUMBER
                continue
            if ph.has_text_frame and ph.text_frame.text.strip():
                title = ph.text_frame.text.strip().split("\n")[0]
                break
        print(f"  {i:2d}. {title}")


if __name__ == "__main__":
    main()
