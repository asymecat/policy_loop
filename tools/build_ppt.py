#!/usr/bin/env python3
"""生成 PolicyLoop 答辩 PPT。

版式：沿用 2026 开源鸿蒙大学生创新大赛 赛道一 答辩模板（16:9 / 微软雅黑 / 蓝色强调）。
内容：`docs/report.md` 的主干，按 ~20 页 / 10-12 分钟答辩节奏取舍。

用法：
    python3 tools/build_ppt.py                    # 输出 docs/policy_loop-答辩.pptx
    python3 tools/build_ppt.py --out /tmp/a.pptx
"""

from __future__ import annotations

import argparse
import math
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


def bullets(slide, items, x, y, w, h, size=17, gap=10, marker="▍",
            marker_color=ACCENT, line=1.25, color=INK):
    """带彩色竖标记的列表 —— 比项目符号更贴近模板的简洁风。"""
    box = textbox(slide, x, y, w, h)
    tf = box.text_frame
    for i, item in enumerate(items):
        p = para(tf, first=(i == 0))
        m = p.add_run()
        m.text = marker + " "
        fmt(m, size, True, marker_color)
        if isinstance(item, tuple):          # (主句, 补充说明)
            head, tail = item
            write_head = p.add_run()
            write_head.text = head
            fmt(write_head, size, True, color)
            r = p.add_run()
            r.text = "  " + tail
            fmt(r, size - 2, False, GRAY)
        else:
            r = p.add_run()
            r.text = item
            fmt(r, size, False, color)
        p.space_before = Pt(0 if i == 0 else gap)
        p.space_after = Pt(0)
        p.line_spacing = line
    return box


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


def card_text(shape, head, body=None, head_size=16, body_size=13.5,
              head_color=INK, body_color=GRAY, gap=6, line=1.3):
    tf = shape.text_frame
    p = tf.paragraphs[0]
    write(p, head, head_size, True, head_color, after=gap, line=line)
    if body:
        write_multiline(tf, body, body_size, False, body_color, gap=2, line=line)
    return tf


def stat(slide, x, y, w, h, number, label, num_size=34, label_size=12.5,
         color=ACCENT_DARK):
    shape = card(slide, x, y, w, h, fill=WHITE, line_color=TINT)
    tf = shape.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = tf.margin_right = Inches(0.10)
    p = tf.paragraphs[0]
    write(p, number, num_size, True, color, align=PP_ALIGN.CENTER, after=2, line=1.0)
    p2 = tf.add_paragraph()
    write(p2, label, label_size, False, GRAY, align=PP_ALIGN.CENTER, line=1.15)


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


def band(slide, y, text, size=15, height=0.72, fill=INK,
         color=WHITE, bold=False, x=BODY_LEFT, w=BODY_W):
    shape = card(slide, x, y, w, height, fill=fill)
    tf = shape.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = Inches(0.28)
    p = tf.paragraphs[0]
    write(p, text, size, bold, color, line=1.25)
    return shape


def table(slide, x, y, w, rows, col_w, row_h=0.5, head_size=14,
          body_size=13, head_fill=ACCENT_DARK, zebra=True):
    """rows[0] 是表头；col_w 为相对权重。"""
    n_r, n_c = len(rows), len(rows[0])
    shape = slide.shapes.add_table(n_r, n_c, Inches(x), Inches(y),
                                   Inches(w), Inches(row_h * n_r))
    tbl = shape.table
    # 去掉默认表格样式（否则会自带边框与条纹，和模板冲突）
    tblPr = tbl._tbl.tblPr
    for el in tblPr.findall(qn("a:tableStyleId")):
        tblPr.remove(el)
    style = tblPr.makeelement(qn("a:tableStyleId"), {})
    style.text = "{2D5ABB26-0587-4C30-8999-92F81FD0307C}"  # No Style, No Grid
    tblPr.append(style)

    total = sum(col_w)
    for i, wt in enumerate(col_w):
        tbl.columns[i].width = Emu(int(Inches(w) * wt / total))
    for r in range(n_r):
        tbl.rows[r].height = Inches(row_h)

    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            cell = tbl.cell(r, c)
            cell.margin_left = cell.margin_right = Inches(0.10)
            cell.margin_top = cell.margin_bottom = Inches(0.04)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            if r == 0:
                cell.fill.fore_color.rgb = head_fill
            else:
                cell.fill.fore_color.rgb = (
                    WHITE if (not zebra or r % 2 == 1) else TINT2)
            tf = cell.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            write(p, text,
                  head_size if r == 0 else body_size,
                  bold=(r == 0), color=WHITE if r == 0 else INK, line=1.1)
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
        write(p, kicker, 12.5, False, MUTED, line=1.0)
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
            p = shp.text_frame.paragraphs[0]
            runs = [r for pp in shp.text_frame.paragraphs for r in pp.runs]
            runs[0].text = "PolicyLoop"
            runs[1].text = "：SELinux 拒绝日志的最小权限自收敛"
        elif "团队名称" in joined:
            runs = [r for pp in shp.text_frame.paragraphs for r in pp.runs]
            runs[0].text = "【团队名称】"
            runs[1].text = ""
            runs[2].text = "2026"
            runs[4].text = "10"
            runs[6].text = "18"
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
    return s


def s_problem(prs, lay):
    s = content_slide(prs, lay, "一条 denial，卡住三件事")
    heads = [
        ("读不懂", "scontext / tcontext / tclass / 权限位自成一套词汇；\n现场通常只看到「功能失败」，看不到「为什么」。"),
        ("不知道在哪补", "规则散在 1,315 个 .te 文件里，按子系统分目录；\n一条 denial 该落在 system/ 还是 vendor/，靠经验。"),
        ("补不对", "最省事的做法是「看到 denial 就加 allow」——\n把一次越权尝试固化成永久授权。"),
    ]
    w, gap = 3.95, 0.22
    for i, (h, b) in enumerate(heads):
        x = BODY_LEFT + i * (w + gap)
        c = card(s, x, 1.45, w, 2.15)
        card_text(c, h, b, head_size=19, body_size=13.5, gap=10)
    band(s, 3.88, "现实中的应对：把门禁关成 permissive —— 系统看起来正常了，实际处于无强制拦截状态。",
         size=16)
    # 上游实测
    tb = textbox(s, BODY_LEFT, 4.78, BODY_W, 0.32)
    write(tb.text_frame.paragraphs[0], "上游策略仓库一次全量统计", 13, True, ACCENT_DARK)
    stats = [
        ("1,315", "个 .te 策略文件"),
        ("51,427", "行策略源码"),
        ("5,230", "条历史 denial 注释"),
        ("21,824", "条索引出的规则"),
    ]
    w2, gap2 = 2.85, 0.19
    for i, (n, l) in enumerate(stats):
        stat(s, BODY_LEFT + i * (w2 + gap2), 5.18, w2, 1.15, n, l, num_size=28)
    return s


def s_goal(prs, lay):
    s = content_slide(prs, lay, "从「放行」到「该不该放行」",
                      "同一件事的更严格版本")
    rows = [
        ("常见做法", "本作品的目标"),
        ("这条访问要放行吗？", "这条访问该不该放行？撞系统红线的一律拒绝自动放权"),
        ("加哪条规则？", "最小的那条是什么？多一个权限位都算失败"),
        ("加完就行了吗？", "denial 消失了吗？有没有引入新的越权？"),
        ("一条一条看", "整份日志一次收敛成可执行清单"),
        ("拿不准的就写「转人工」", "转人工之后逐条归因「该谁修」—— 实测真正要打补丁的只有 0 条"),
    ]
    table(s, BODY_LEFT, 1.52, BODY_W, rows, [1, 1.85], row_h=0.72,
          head_size=15, body_size=14)
    band(s, 6.02, "验收可量化：策略覆盖率 · 补丁最小性 · 零越权（撞 neverallow 一律拒绝）· 真机端到端一致",
         size=15, height=0.66, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_arch(prs, lay):
    s = content_slide(prs, lay, "总体架构：主机端重、设备端轻",
                      "LAYERED  ·  L1 确定性内核 → L2 评测基线 → L3 诊断流水线 → L4 设备端")
    picture_fit(s, DOCS / "figs" / "fig1-architecture.png",
                BODY_LEFT, 1.35, BODY_W, 4.55)
    band(s, 6.08, "两侧之间只有一条窄接口：PLI 只读索引（构建期导出、随镜像下发）+ JSON / TSV 判定结果",
         size=15, height=0.66, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_principles(prs, lay):
    s = content_slide(prs, lay, "四条设计原则", "模块划分与流程设计都是它们的展开")
    data = [
        ("① 确定性内核优先", "解析、索引、根因、补丁、评审、验证全部是纯规则、纯标准库；\nLLM 只在配置了 key 时写「人话解释」，不参与任何安全决策。"),
        ("② 绝不自动写盘", "只产出「建议补丁 + 落点提示」；\n是否写入 .te、是否重建策略、是否上 enforcing，由人决定。"),
        ("③ 先仿真、后真机", "先用上游真实语料做数据仿真与量化评测（成本低、可反复），\n再上真机取独立证据。"),
        ("④ 设备端只搬「属于设备的那一段」", "需要读内核日志、需要脱离 PC 运行的才下沉；\n多智能体编排与评测工具留在主机。"),
    ]
    w, h, gap = 5.85, 2.35, 0.28
    for i, (hd, bd) in enumerate(data):
        x = BODY_LEFT + (i % 2) * (w + gap)
        y = 1.45 + (i // 2) * (h + 0.2)
        c = card(s, x, y, w, h)
        card_text(c, hd, bd, head_size=17.5, body_size=13.5, gap=9)
    return s


def s_neverallow(prs, lay):
    s = content_slide(prs, lay, "为什么设备端只搬「属于设备的那一段」",
                      "一个被实测逼出来的架构约束")
    left = [
        ("设备上没有策略源码", "find /system /vendor -name \"*.te\" 为空；\nSELinux 的全部家当只有 config、\n编译后的 policy.31（424,699 B）与 *_contexts。"),
        ("neverallow 不在二进制策略里", "它是编译期断言：libsepol 的 expand.c:2736\n写明不写进产出的策略。设备上拿不到红线。"),
    ]
    for i, (hd, bd) in enumerate(left):
        c = card(s, BODY_LEFT, 1.45 + i * 2.35, 6.0, 2.15)
        card_text(c, hd, bd, head_size=17, body_size=13.5, gap=9)
    # 右侧推演
    x = BODY_LEFT + 6.3
    flow = [
        ("拿不到红线", RED),
        ("工具退化成「看到 denial 就建议放权」", RED),
        ("正是它最该避免的行为", RED),
        ("结论：索引必须构建期导出、随镜像下发", ACCENT_DARK),
        ("设备端用语义，不构建语义", GREEN),
    ]
    y = 1.45
    for i, (t, col) in enumerate(flow):
        c = card(s, x, y, BODY_W - 6.3, 0.78, fill=WHITE,
                 line_color=TINT if col != ACCENT_DARK else ACCENT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, ("→ " if i else "") + t, 14.5, i >= 3, col, line=1.15)
        y += 0.9
    band(s, 6.02, "上游 570 条红线，索引看得见 430 条（419 neverallow + 11 neverallowxperm）；可见性缺口由部署期 secilc 断言补第二道",
         size=14.5, height=0.68, fill=INK)
    return s


def s_pipeline(prs, lay):
    s = content_slide(prs, lay, "七 Agent 诊断流水线：一条单向链",
                      "Orchestrator 是严格状态机，每步输入输出都是可打印的结构化字段")
    picture_fit(s, DOCS / "figs" / "fig2-agent-pipeline.png",
                BODY_LEFT, 1.3, BODY_W, 4.3)
    tb = textbox(s, BODY_LEFT, 5.72, BODY_W, 0.9)
    tf = tb.text_frame
    p = tf.paragraphs[0]
    write(p, "两个刻意的设计：", 14, True, INK, after=4)
    p2 = tf.add_paragraph()
    r = p2.add_run(); r.text = "CrossLayerAgent 只读"; fmt(r, 14, True, ACCENT_DARK)
    r = p2.add_run(); r.text = "（只出跨层建议，加不加它结论都不变）；"; fmt(r, 14, False, GRAY)
    r = p2.add_run(); r.text = "流水线不含回路"; fmt(r, 14, True, ACCENT_DARK)
    r = p2.add_run(); r.text = "——Verify 失败或 Reviewer 否决即归「需人工」，不回 Repair 重算，否则等于迭代出一个更宽的补丁。"; fmt(r, 14, False, GRAY)
    p2.line_spacing = 1.25
    return s


def s_guards(prs, lay):
    s = content_slide(prs, lay, "守门：不猜、不宽、不放行红线",
                      "五道拒绝点（流水线） + 六道 apply_guards（converge 与 --explain 共用同一份实现）")
    tb = textbox(s, BODY_LEFT, 1.45, 6.1, 4.2)
    tf = tb.text_frame
    gates = [
        ("撞 neverallow", "直接转人工，拒绝自动放权"),
        ("解析出的目标仍不许访问", "拒发补丁"),
        ("占位符目标未解析", "转人工，不猜"),
        ("补丁须过 Reviewer 评审", "过宽 / 危险模式拦截"),
        ("补丁须在索引副本上 Verify 成功", "必须真消除且无回归"),
    ]
    for i, (h, b) in enumerate(gates):
        p = para(tf, first=(i == 0))
        m = p.add_run(); m.text = f"{i + 1}  "; fmt(m, 20, True, ACCENT)
        r = p.add_run(); r.text = h; fmt(r, 15.5, True, INK)
        r = p.add_run(); r.text = "　" + b; fmt(r, 13.5, False, GRAY)
        p.space_before = Pt(0 if i == 0 else 13)
        p.line_spacing = 1.15

    x = BODY_LEFT + 6.4
    c = card(s, x, 1.42, BODY_W - 6.4, 4.35, fill=WHITE, line_color=ACCENT)
    tf = c.text_frame
    p = tf.paragraphs[0]
    write(p, "典型反例：只差一个命令号", 16.5, True, INK, after=8)
    write_multiline(tf, "render_service → dev_mali:chr_file ioctl 0x8014\n"
                        "策略已允许 ioctl 大类，缺的只是 allowxperm 白名单里的一个命令号。",
                    13.5, False, GRAY, gap=4, line=1.35, before=10)
    p = tf.add_paragraph()
    write(p, "「看到 denial 就加 allow」会写一条已经存在的规则 —— 写了等于没写。",
          13.5, False, RED, after=10, line=1.35)
    p = tf.add_paragraph()
    write(p, "本作品给出：", 13.5, True, INK, after=4)
    p = tf.add_paragraph()
    r = p.add_run()
    r.text = "allowxperm render_service dev_mali:chr_file ioctl { 0x8014 };"
    fmt(r, 13, True, ACCENT_DARK)
    p.line_spacing = 1.15
    band(s, 6.02, "apply_guards 的六个分支（MLS 级目标 / 占位符 / 主体目标不在语料 / 对象类不在语料 / 非权限名 / 空权限）两端逐字一致",
         size=14.5, height=0.68, fill=TINT, color=ACCENT_DARK, bold=True)
    return s


def s_converge(prs, lay):
    s = content_slide(prs, lay, "批量收敛：一份日志 → 一张清单",
                      "python -m policy_loop.converge  ·  本机实测 4.161 s")
    picture_fit(s, DOCS / "figs" / "fig3-converge-flow.png",
                BODY_LEFT, 1.4, 7.5, 4.4)
    x = BODY_LEFT + 7.85
    stats = [
        ("5,161 → 4,911", "日志行 → 唯一案例", ACCENT_DARK),
        ("3,261", "噪声 / 已被允许", MUTED),
        ("70", "可自动出最小权限补丁", GREEN),
        ("1,580", "需人工决策（约 32%）", ORANGE),
    ]
    y = 1.45
    for n, l, col in stats:
        c = card(s, x, y, BODY_W - 7.85, 0.92, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        r = p.add_run(); r.text = n + "  "; fmt(r, 21, True, col)
        r = p.add_run(); r.text = l; fmt(r, 12, False, GRAY)
        p.line_spacing = 1.1
        y += 1.04
    band(s, 6.08, "全量 5,161 条里零误报进入自动项：1,580 类「需人工」是工具主动拒绝越权的结果，不是它做不到",
         size=14.5, height=0.66, fill=INK)
    return s


def s_minimize(prs, lay):
    s = content_slide(prs, lay, "补丁最小化：69 行 → 54 条根因规则",
                      "同一 (src, tgt, cls) 的补丁行并成一条根因规则，再套回索引副本反验")
    cards = [
        ("69 → 54", "补丁行数（归并 10 组、省 15 行）", ACCENT_DARK),
        ("10 组", "根因归并（26 条折叠进已有规则，25 条新增）", ACCENT_DARK),
        ("70 → 0", "闭环反验：补丁前未解决 → 套回后全部解决", GREEN),
        ("0 残留", "1,580 条人工案例的归因结果", GREEN),
    ]
    w, gap = 2.95, 0.17
    for i, (n, l, col) in enumerate(cards):
        stat(s, BODY_LEFT + i * (w + gap), 1.5, w, 1.55, n, l,
             num_size=28, label_size=12, color=col)
    band(s, 3.35, "闭环反验多证了什么：converge 只断言「补丁编译得过」且名字级匹配；minimize 要求「补丁前确实未解决、套回后全部解决」——缺了前半句，本来就允许的案例会被算成补丁的功劳。",
         size=14.5, height=1.0, fill=TINT, color=INK)
    c = card(s, BODY_LEFT, 4.62, BODY_W, 1.25, fill=WHITE, line_color=ACCENT)
    tf = c.text_frame
    p = tf.paragraphs[0]
    write(p, "判定「最窄规则」必须按展开后的影响面，不能按 token 数", 16, True, INK, after=6)
    p = tf.add_paragraph()
    write(p, "{domain} 只占 1 个 token，却覆盖 235 个类型 —— 按 token 数会把最宽的规则判成最窄。",
          13.5, False, GRAY, line=1.3)
    return s


def s_attribution(prs, lay):
    s = content_slide(prs, lay, "1,580 条「转人工」，真正要补权限的是 0 条",
                      "attribution：对每一个拒绝自动放权的案例，答「该谁修」")
    items = [
        ("1,147", "语料的历史噪声", MUTED),
        ("342", "工具侧要对齐的（索引 / 版本）", ACCENT_DARK),
        ("53", "日志质量问题", ORANGE),
        ("38", "架构决策（撞 neverallow 红线）", RED),
    ]
    w, gap = 2.95, 0.17
    for i, (n, l, col) in enumerate(items):
        c = card(s, BODY_LEFT + i * (w + gap), 1.5, w, 1.35, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 30, True, col, align=PP_ALIGN.CENTER, after=2, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, l, 11.5, False, GRAY, align=PP_ALIGN.CENTER, line=1.2)
    c = card(s, BODY_LEFT, 3.15, 4.2, 2.2, fill=TINT, line_color=ACCENT)
    tf = c.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    write(p, "0", 66, True, GREEN, align=PP_ALIGN.CENTER, line=1.0, after=2)
    p2 = tf.add_paragraph()
    write(p2, "owner = DEVICE：真正需要给设备补权限的条数", 13, False, GRAY,
          align=PP_ALIGN.CENTER, line=1.2)
    tb = textbox(s, BODY_LEFT + 4.55, 3.15, BODY_W - 4.55, 2.6)
    tf = tb.text_frame
    p = tf.paragraphs[0]
    write(p, "归因完备性：1,580 → 归因 1,580，残留 0（退出码 0 即判据）", 14, True, INK, after=8)
    p = tf.add_paragraph()
    write(p, "跨树稳定的是「DEVICE 档为 0」这个结论；原因码的数量随所选上游树变化——换成与设备对应版本的源码树，符号缺失会变多、版本差会变少。",
          13, False, GRAY, line=1.35, after=8)
    p = tf.add_paragraph()
    write(p, "所以「需人工 1,580」不等于「还有 1,580 个洞」：它是工具主动拒绝越权的证据。",
          13, True, ACCENT_DARK, line=1.35)
    return s


def s_parity(prs, lay):
    s = content_slide(prs, lay, "同一份判定，两个进程，逐字节相同",
                      "设备端是独立实现（C++ / musl），喂完全相同的输入")
    rows = [
        ("#", "门禁", "做法", "结果"),
        ("1", "--selftest", "内嵌固定向量，比对宿主生成并冻结的 digest 表", "PASS：sha1 13 + converge 24 + explain 11 组，0 失败"),
        ("2", "--index-info", "两端加载同一 PLI，比计数器", "rules=21824 types=1267 attrs=49 skipped=524，与宿主一致"),
        ("3", "报告差分", "同一份语料两端各出完整 JSON，比 sha256", "逐字节相同"),
        ("4", "真机采样", "真读本机 kmsg", "suppressed≈107 非零，量化 printk 丢帧"),
        ("5", "查询差分", "27,912 条查询，比整个输出体的 sha256", "2,984,884 B 逐字节相同"),
    ]
    table(s, BODY_LEFT, 1.45, BODY_W, rows, [0.35, 1.35, 3.4, 3.6],
          row_h=0.72, head_size=14, body_size=12.5)
    band(s, 5.85, "四个真实存在的语义陷阱：空 perms 是通配而非空集 / xperm 命令大小写敏感 / permissive=2 是三态 / 通配命中时未知 perm 原样带上 —— 错一个哈希当场炸掉。",
         size=14, height=0.86, fill=INK)
    return s


def s_perf(prs, lay):
    s = content_slide(prs, lay, "倒排索引：设备 34×，宿主 238×",
                      "按对象类线性扫描 → 类型对倒排索引（postings 由 clone 继承，每棵树只建一次）")
    data = [
        ("34×", "设备查询路径", "0.0987 → 0.0029 ms/条（27,912 条查询）"),
        ("238×", "宿主判定路径", "8.842 s → 0.037 s（4,911 个唯一案例）"),
        ("151 → 1", "索引建表", "否则一次 converge 要重建 151 次"),
    ]
    w, gap = 3.95, 0.22
    for i, (n, t, l) in enumerate(data):
        c = card(s, BODY_LEFT + i * (w + gap), 1.45, w, 2.55, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 42, True, ACCENT_DARK, align=PP_ALIGN.CENTER, after=6, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, t, 14.5, True, INK, align=PP_ALIGN.CENTER, after=5)
        p3 = tf.add_paragraph()
        write(p3, l, 12, False, GRAY, align=PP_ALIGN.CENTER, line=1.25)
    band(s, 5.45, "口径：两侧各用真实实现跑同一负载，输出逐字节相同。板端 71.25 s 是旧代码在 RK3568 上的实测；"
                  "「约 2 s」是按 34× 的倍数外推而非测量，上板后须复测。",
         size=14, height=0.95, fill=TINT, color=INK)
    return s


def s_llm(prs, lay):
    s = content_slide(prs, lay, "LLM 的默认行为是过宽，护栏把它按回最小",
                      "docs/eval-llm-guardrail.md 同批真实 denial 三档对照")
    rows = [
        ("方案", "样本", "过宽（越权加权限）率"),
        ("未受约束的「AI 直接放权」（naive 档）", "120", "100%"),
        ("真实 LLM（明确最小权限指令，deepseek-v4-flash）", "54 有效补丁", "0%（54/54 通过评审）"),
        ("PolicyLoop：最小权限指令 + 规则护栏 + 确定性精修", "120", "0%（120/120 被拦截并精修回最小）"),
    ]
    table(s, BODY_LEFT, 1.5, BODY_W, rows, [4.2, 1.2, 2.6], row_h=0.7,
          head_size=15, body_size=13)
    band(s, 4.55, "越权倾向是 LLM 的默认行为，提示词消除不掉，只能靠确定性护栏兜住。",
         size=19, height=0.9, fill=INK, bold=True)
    tb = textbox(s, BODY_LEFT, 5.72, BODY_W, 0.9)
    p = tb.text_frame.paragraphs[0]
    write(p, "因此架构上把「生成候选」和「批准授权」拆成两个角色 —— 后者永远是规则，绝不用模型。",
          14, False, GRAY, line=1.3)
    return s


def s_ui(prs, lay):
    s = content_slide(prs, lay, "界面：如实区分数据来源",
                      "主机端 Agent Trace  ·  板端控制台实时卡片  ·  快照现读")
    pics = [
        (DOCS / "screenshots" / "fig5-agent-trace.png", 2.95,
         "主机端 Web UI · Agent Trace"),
        (DOCS / "screenshots" / "fig6-board-live-cards.png", 2.80,
         "板端控制台 · 拨开关后的实时卡片"),
        (DOCS / "screenshots" / "fig7-board-snapshot.png", 2.80,
         "板端控制台 · 载入当前快照"),
    ]
    x = 1.95
    for path, w, cap in pics:
        picture_fit(s, path, x, 1.30, w, 4.30)
        tb = textbox(s, x - 0.15, 5.72, w + 0.3, 0.3)
        write(tb.text_frame.paragraphs[0], cap, 11.5, False, MUTED,
              align=PP_ALIGN.CENTER)
        x += w + 0.55
    band(s, 6.12, "工具造成的 denial 明确标注「工具造成」，不冒充分析结果；「累计案例」与「本次窗口行数」分开计数 —— 它们测的不是一回事。",
         size=14, height=0.62, fill=INK)
    return s


def s_board(prs, lay):
    s = content_slide(prs, lay, "真机：拨一次开关，1~2 秒出结论",
                      "RK3568  ·  OpenHarmony 5.0.3.135  ·  enforcing")
    picture_fit(s, DOCS / "figs" / "fig4-board-runtime.png",
                BODY_LEFT, 1.32, 8.55, 4.35)
    x = BODY_LEFT + 8.75
    cw = BODY_W - 8.75
    items = [
        ("正规 init service", "开机自启、自有 enforcing 域，\n不需要 PC / su / begetctl"),
        ("冷启动即采集", "up 0 min 时服务已在域内采集，\n本域 denial = 0 条"),
        ("端到端时延", "两个 1 秒轮询叠加：拨开关 →\n采集 → 分析 → 横幅 + 系统通知"),
    ]
    y = 1.38
    for hd, bd in items:
        c = card(s, x, y, cw, 1.36, fill=WHITE, line_color=TINT)
        card_text(c, hd, bd, head_size=13.5, body_size=11.5, gap=4, line=1.25)
        y += 1.46
    band(s, 6.05, "部署依赖 PC ≠ 运行依赖 PC：采集路径上没有任何一环需要 PC",
         size=15.5, height=0.64, fill=INK, bold=True)
    return s


def s_numbers(prs, lay):
    s = content_slide(prs, lay, "关键数字", "每一个都能用附录 A 的命令复现")
    data = [
        ("21,824", "条索引规则\n1,267 类型 / 49 属性"),
        ("99.94%", "索引召回率\n（质检 + 占位解析）"),
        ("100%", "补丁精确最小\n179/179 · 过宽 0%"),
        ("2.98 MB", "两端查询输出\n逐字节相同"),
        ("34×", "设备查询加速\n宿主 238×"),
        ("0 条", "真正需要给设备\n补权限（owner=DEVICE）"),
    ]
    w, h, gap = 3.95, 2.2, 0.22
    for i, (n, l) in enumerate(data):
        x = BODY_LEFT + (i % 3) * (w + gap)
        y = 1.5 + (i // 3) * (h + 0.25)
        c = card(s, x, y, w, h, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        write(p, n, 36, True, ACCENT_DARK, align=PP_ALIGN.CENTER, after=6, line=1.0)
        p2 = tf.add_paragraph()
        write(p2, l, 12.5, False, GRAY, align=PP_ALIGN.CENTER, line=1.3)
    return s


def s_pitfalls(prs, lay):
    s = content_slide(prs, lay, "四个改变了设计的坑",
                      "每一个都推翻了动手前的假设")
    data = [
        ("neverallow 不在二进制策略里", "「让设备自己反推全部策略语义」原理上不通 —— 从设想变成架构约束。"),
        ("printk 限流会静默丢弃 denial", "每 5 秒只放 10 条，超出直接丢，dmesg 与采集器一起失明。修法：init job 写 printk_ratelimit=0；验收改用 unique_cases。"),
        ("init 的 caps 是整套替换", "「只有 CAP_SYSLOG」连 uid 0 也失去 DAC_OVERRIDE，而 DAC 失败不出 AVC —— 判活用 wchan + fd，定根用 chmod 0777。"),
        ("差分语料证明不了分支覆盖", "4,911 簇真实语料没抓到的偏差，固定向量首跑就抓出 2 个 —— 最终取「固定向量 + 差分」两条腿。"),
    ]
    w, h, gap = 5.85, 1.88, 0.28
    for i, (hd, bd) in enumerate(data):
        x = BODY_LEFT + (i % 2) * (w + gap)
        y = 1.42 + (i // 2) * (h + 0.18)
        c = card(s, x, y, w, h, fill=WHITE, line_color=TINT)
        tf = c.text_frame
        p = tf.paragraphs[0]
        write(p, f"{i + 1}  {hd}", 16, True, INK, after=7, line=1.2)
        p2 = tf.add_paragraph()
        write(p2, bd, 13, False, GRAY, line=1.35)
    band(s, 5.62, "共同点：都是「看起来正常」的假象 —— 服务活着、日志干净、策略也对，缺陷藏在看不见的地方。",
         size=15, height=0.62, fill=INK)
    return s


def s_limits(prs, lay):
    s = content_slide(prs, lay, "口径与边界：每个数字能证明什么",
                      "安全工具的可信度来自说清边界，而不是把数字说大")
    left = [
        ("语料来自上游，不是本设备采集", "5,230 条注释每一行都以 # 开头，96.8% 逐字来自上游 .te；说明的是工具在真实历史 denial 上的表现。"),
        ("构造内自洽 ≠ 独立金标准", "exact_min=100% 是「剔除规则 → 补回来」的自洽性验证；独立证据只有上游人工修复对照与真机回归。"),
    ]
    right = [
        ("外推值一律标注", "板端 71.25 s → 约 2 s 是外推；「39% 比上游更窄」只在单条 denial 视角下成立。"),
        ("未做但已证伪的，写证伪", "boolean / constrain / MLS 三类根因在本平台原理上无从发生，不列进「已检查项」。"),
    ]
    for col, items in enumerate([left, right]):
        x = BODY_LEFT + col * (6.0 + 0.3)
        y = 1.45
        for hd, bd in items:
            c = card(s, x, y, 6.0, 1.35, fill=WHITE, line_color=TINT)
            card_text(c, hd, bd, head_size=14.5, body_size=12, gap=5, line=1.3)
            y += 1.5
    # 已知边界
    tb = textbox(s, BODY_LEFT, 4.55, BODY_W, 0.3)
    write(tb.text_frame.paragraphs[0], "仍然存在的边界", 13, True, ACCENT_DARK)
    band(s, 4.9, "索引须与目标策略树对齐（上游活树 21,824 ≠ 板端 HAP 内置 19,800）　·　"
                 "红线两条防线各有洞　　板子 5.0.3.135 ≠ 编译树 6.1.0.31　·　"
                 "printk 限流只减少不消除",
         size=13.5, height=0.95, fill=INK)
    return s


def s_next(prs, lay):
    s = content_slide(prs, lay, "不足与下一步")
    c1 = card(s, BODY_LEFT, 1.55, 5.85, 3.95)
    tf = c1.text_frame
    p = tf.paragraphs[0]
    write(p, "交付前必补", 18, True, ACCENT_DARK, after=12)
    for t in [
        "--cross-layer 与 hap 计数器只有宿主侧结果，尚未在真机上跑过",
        "板端控制台 HAP 不会开机自启，需要手动点一次图标",
        "封面信息与截图占位由 docgate 的 placeholders 门禁盯着，到期未清即判红",
    ]:
        p = tf.add_paragraph()
        m = p.add_run(); m.text = "▍ "; fmt(m, 13, True, ACCENT)
        r = p.add_run(); r.text = t; fmt(r, 13, False, INK)
        p.space_before = Pt(10); p.line_spacing = 1.3

    c2 = card(s, BODY_LEFT + 6.15, 1.55, BODY_W - 6.15, 3.95, fill=WHITE, line_color=TINT)
    tf = c2.text_frame
    p = tf.paragraphs[0]
    write(p, "下一步", 18, True, ACCENT_DARK, after=12)
    for t in [
        ("改走 audit netlink", "取无损通道，摆脱 printk 限流；现在只做到把限流关掉"),
        ("索引降到与板子一致的 5.0.3", "量化版本漂移对召回率的影响"),
        ("板内触发", "实时闭环目前只有「捕获」这一半不需要 PC"),
    ]:
        p = tf.add_paragraph()
        m = p.add_run(); m.text = "▍ "; fmt(m, 13, True, ACCENT)
        r = p.add_run(); r.text = t[0]; fmt(r, 13, True, INK)
        r = p.add_run(); r.text = "　" + t[1]; fmt(r, 12, False, GRAY)
        p.space_before = Pt(10); p.line_spacing = 1.3
    return s


# ── 讲稿备注（每题时长按 20 页 / 11 分钟配）──────────────────────
NOTES = [
    # 封面
    "开场（约 10 秒）：各位评委老师好，我们是【团队名称】。参赛作品 PolicyLoop，"
    "解决的是 OpenHarmony SELinux 拒绝日志的诊断与最小权限修复问题。",
    # 目录
    "约 10 秒：汇报分三部分 —— 为什么要做、怎么做的、实测到了什么程度，以及我们主动划出的边界。",
    # 问题
    "约 50 秒：SELinux 是强制门禁，但 denial 对开发者有三个卡点：读不懂、不知道在哪补、补不对。"
    "上游策略仓库自己的注释里就埋着 5,230 条历史 denial，全靠人力诊断。现实中的应对往往是把门禁关成 permissive —— "
    "系统看起来正常了，门实际上没有了。",
    # 目标
    "约 30 秒：我们不回答「这条访问要放行吗」，而是「该不该放行」。撞系统红线的一律拒绝自动放权；"
    "补丁要求精确最小；补完还要验证真的消除且没有回归。验收指标是可量化的四组。",
    # 架构
    "约 35 秒：系统按「能独立验证」分四层，主机端重、设备端轻，中间只有一条窄接口：构建期导出的 PLI 只读索引，"
    "以及 JSON/TSV 判定结果。同一份判定逻辑三次落地：Python 做对语义、评测证明它收敛、设备端做原生组件并差分证明等价。",
    # 四原则
    "约 30 秒：四条原则。最关键的是第一条：所有安全决策都是确定性规则，LLM 不参与判定，只在配置了 key 时写人话解释。"
    "第二条：工具永不自动写盘。",
    # neverallow
    "约 50 秒：这是最常被问的问题——为什么不把整个 PolicyLoop 搬到设备上？两个事实：设备上没有 .te 源码；"
    "neverallow 是编译期断言，原理上不写进二进制策略。拿不到红线，工具就退化成「看到 denial 就建议放权」。"
    "所以索引必须构建期导出、设备端只负责用语义。",
    # 流水线
    "约 50 秒：一条 denial 走七个 Agent 的单向链。两个刻意设计：CrossLayerAgent 只读，加不加它结论不变；"
    "流水线不含回路，Verify 失败直接归「需人工」——允许重试等于让它迭代出一个更宽的补丁。",
    # 守门
    "约 35 秒：五道拒绝点 + 六道 apply_guards。右边这个真实例子最能说明问题：策略已经允许了 ioctl 大类，"
    "缺的只是一个命令号；「看到 denial 就加 allow」会写一条已经存在的规则。我们给的是 allowxperm。",
    # 收敛
    "约 35 秒：整份 5,161 条日志，去重后 4,911 个唯一案例，4.16 秒出清单：70 类可自动出最小补丁，1,580 类需人工。"
    "这个 1,580 是工具主动拒绝越权的结果，不是它做不到。",
    # 最小化
    "约 35 秒：补丁 69 行归并成 54 条根因规则。闭环反验多证了一件事：套回之前这些案例确实没被解决，"
    "否则本来就允许的案例会被算成补丁的功劳。",
    # 归因
    "约 30 秒：1,580 条逐条归因「该谁修」，真正需要给设备补权限的是 0 条：大部分是语料的历史噪声，"
    "小部分是工具侧对齐和日志质量问题，38 条是撞红线的架构决策。",
    # 两端一致
    "约 40 秒：设备端是独立的 C++ 实现，五项门禁证明两端同源。最有说服力的是第五项：27,912 条查询、"
    "2.98 MB 输出逐字节相同。空 perms、xperm 大小写、permissive 三态、未知 perm 名，错一个哈希就炸。",
    # 性能
    "约 30 秒：原来的线性扫描换成类型对倒排索引，设备侧 34 倍、宿主侧 238 倍。请注意口径："
    "板端的「约 2 秒」是按倍数外推，不是测量，上板后还要复测。",
    # LLM
    "约 30 秒：这是我们的对照实验。未受约束的 AI 直接放权，过宽率 100%；同批样本经过确定性护栏，0%。"
    "越权倾向是 LLM 的默认行为，提示词消除不掉，只能靠规则兜住。",
    # 界面
    "约 25 秒：两处界面。原则是如实区分数据来源：工具造成的 denial 必须标注「工具造成」，"
    "「累计案例」和「本次窗口行数」分开计数。",
    # 真机
    "约 40 秒：采集器是正规 init service，开机自启、自有 enforcing 域。拨一次开关，1~2 秒出结论。"
    "结论一句话：部署依赖 PC，运行不依赖 PC。",
    # 关键数字
    "约 20 秒：一页回顾六个关键数字，每一个都能用报告附录 A 的命令复现。",
    # 坑
    "约 40 秒：四个坑都改变过设计。共同点是「看起来正常」的假象：服务活着、日志干净、策略也对，缺陷在看不见的地方。",
    # 边界
    "约 30 秒：安全工具的可信度来自说清边界。语料来自上游注释而不是设备采集；构造内自洽不等于独立金标准；"
    "外推值一律标注；未做但已证伪的写证伪。",
    # 下一步
    "约 25 秒：交付前必补的三项和下一步方向。谢谢各位老师。",
]


# ── 组装 ──────────────────────────────────────────────────────
def build(out: Path) -> Path:
    prs = Presentation(str(TEMPLATE))
    layout = prs.slide_layouts[4]          # 模板内容页用的版式

    cover(prs)
    toc(prs)
    thanks_rid = list(prs.slides._sldIdLst)[3].rId   # 模板的「谢谢」页

    builders = [
        s_problem, s_goal, s_arch, s_principles, s_neverallow, s_pipeline,
        s_guards, s_converge, s_minimize, s_attribution, s_parity, s_perf,
        s_llm, s_ui, s_board, s_numbers, s_pitfalls, s_limits, s_next,
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
