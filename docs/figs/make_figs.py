# 生成 docs/figs/*.png。需要 Pillow(仅出图用,不是仓库运行依赖):
#   python3 -m venv /tmp/fv && /tmp/fv/bin/pip install Pillow && /tmp/fv/bin/python docs/figs/make_figs.py
#!/usr/bin/env python3
"""PolicyLoop 报告配图生成器(需 Pillow)。输出到 docs/figs/*.png"""
import os
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(OUT, exist_ok=True)

FONT_CANDIDATES = [
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 2),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
    ("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", 0),
]
BOLD_CANDIDATES = [
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc", 2),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc", 0),
] + FONT_CANDIDATES


def _load(cands, size):
    for path, idx in cands:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size, index=idx)
            except Exception:
                continue
    return ImageFont.load_default()


def F(size):
    return _load(FONT_CANDIDATES, size)


def FB(size):
    return _load(BOLD_CANDIDATES, size)


INK = "#202124"
MUTED = "#5F6368"
BLUE = "#1A73E8"
BLUE_BG = "#E8F0FE"
GREEN = "#0F9D58"
GREEN_BG = "#E6F4EA"
ORANGE = "#E8710A"
ORANGE_BG = "#FEF0E3"
RED = "#D93025"
RED_BG = "#FCE8E6"
GREY_BG = "#F1F3F4"


def canvas(w, h):
    im = Image.new("RGB", (w, h), "white")
    return im, ImageDraw.Draw(im)


def box(d, x, y, w, h, fill="white", outline="#5F6368", r=8, width=2):
    d.rounded_rectangle([x, y, x + w, y + h], radius=r, fill=fill,
                        outline=outline, width=width)


def panel(d, x, y, w, h, fill, outline, title, sub=None):
    d.rounded_rectangle([x, y, x + w, y + h], radius=10, fill=fill,
                        outline=outline, width=2)
    d.text((x + 16, y + 12), title, font=FB(20), fill=outline)
    if sub:
        d.text((x + 16, y + 40), sub, font=F(13), fill=MUTED)


def ctext(d, cx, cy, s, font, fill=INK):
    d.text((cx, cy), s, font=font, fill=fill, anchor="mm")


def mtext(d, x, y, s, font, fill=INK):
    d.text((x, y), s, font=font, fill=fill, anchor="lm")


def arrow(d, x1, y1, x2, y2, color=BLUE, width=3, head=9, dashed=False):
    if dashed:
        # 手绘虚线
        import math
        dx, dy = x2 - x1, y2 - y1
        L = math.hypot(dx, dy)
        if L == 0:
            return
        ux, uy = dx / L, dy / L
        t = 0.0
        while t < L - head:
            t2 = min(t + 10, L - head)
            d.line([x1 + ux * t, y1 + uy * t, x1 + ux * t2, y1 + uy * t2],
                   fill=color, width=width)
            t += 18
    else:
        d.line([x1, y1, x2, y2], fill=color, width=width)
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    p = [(x2, y2),
         (x2 - head * math.cos(ang - 0.42), y2 - head * math.sin(ang - 0.42)),
         (x2 - head * math.cos(ang + 0.42), y2 - head * math.sin(ang + 0.42))]
    d.polygon(p, fill=color)


# ---------------------------------------------------------------- 图 1 总体架构
def fig_architecture():
    W, H = 1240, 700
    im, d = canvas(W, H)

    panel(d, 40, 30, 1160, 300, "#F5F8FF", BLUE,
          "主机端(重)  ·  policy_loop/  ·  Python 标准库,零第三方依赖",
          "开发期与运行时的编排、评测;无网络也可运行")

    y = 110
    bw, bh = 205, 78
    xs = [70, 300, 530, 760, 990]
    labels = [
        ("denial 解析器", "denial/parser.py", BLUE_BG, BLUE),
        ("策略索引", "policy/index.py", BLUE_BG, BLUE),
        ("七 Agent 流水线", "agents/", BLUE_BG, BLUE),
        ("批量收敛", "converge.py", BLUE_BG, BLUE),
        ("评测体系", "eval/", GREY_BG, MUTED),
    ]
    for x, (t, s, bg, bd) in zip(xs, labels):
        box(d, x, y, bw, bh, fill=bg, outline=bd)
        ctext(d, x + bw / 2, y + 28, t, FB(16), INK)
        ctext(d, x + bw / 2, y + 54, s, F(12), MUTED)
    for i in range(4):
        arrow(d, xs[i] + bw + 4, y + bh / 2, xs[i + 1] - 6, y + bh / 2,
              color="#9AA0A6", width=2, head=7)

    mtext(d, 70, 232, "上游策略源码树 security_selinux_adapter/sepolicy(1,315 个 .te)"
          "  →  编译为 PLI 只读索引(21,790 条规则 / 1,267 类型 / 49 属性)",
          F(14), MUTED)
    mtext(d, 70, 258, "核心不变量:确定性内核优先;LLM 可插拔、可断供;所有判定可回溯到一条被索引的 .te 规则",
          F(14), INK)
    mtext(d, 70, 286, "安全红线:工具只产出「建议补丁 + 落点」,绝不自动写盘、不自动上 enforcing",
          F(14), RED)

    # 契约带
    d.rounded_rectangle([40, 350, 1200, 404], radius=8, fill="#FFFDF0",
                        outline="#F9AB00", width=2)
    ctext(d, 620, 377, "数据契约   ·   PLI 索引(构建期导出,随镜像下发,只读)   ⇄   "
                       "JSON / TSV 判定(逐条或批量)", FB(15), "#8A6D00")

    panel(d, 40, 424, 1160, 246, "#F1FBF4", GREEN,
          "设备端(轻)  ·  device/  ·  OpenHarmony 原生 C++(32 位 ARM / musl)",
          "运行时自足:不联网、不依赖 PC、不依赖 LLM;只读策略语义,只写 stdout")

    dy = 500
    dw, dh = 340, 96
    dxs = [80, 470, 860]
    dl = [
        ("pl_collector  ·  init service", "u:r:pl_collector:s0  ·  开机自启\n读 /dev/kmsg → live.jsonl"),
        ("denial_check  ·  /system/bin", "固定 API:--selftest / --index-info\n--query / --converge / --explain / --case"),
        ("板端控制台 HAP", "com.policyloop.console\n引擎编入 libplnative.so,自带索引"),
    ]
    for x, (t, s) in zip(dxs, dl):
        box(d, x, dy, dw, dh, fill="white", outline=GREEN)
        ctext(d, x + dw / 2, dy + 26, t, FB(15), INK)
        for i, line in enumerate(s.split("\n")):
            ctext(d, x + dw / 2, dy + 52 + i * 20, line, F(12), MUTED)
        if x != dxs[-1]:
            arrow(d, x + dw + 4, dy + dh / 2, x + dw + 84, dy + dh / 2,
                  color=GREEN, width=2, head=8)

    mtext(d, 80, 630, "设备端能力边界:能解析、能查询、能逐条判定与批量收敛、能采集本机日志;"
                      "不能构建索引(需 .te 源码,且 neverallow 原理上不进入二进制策略)",
          F(13), MUTED)
    mtext(d, 80, 654, "分工:策略语义在设备上(索引 / 判定 / 守门),agent 编排在主机上。",
          F(13), INK)

    im.save(f"{OUT}/fig1-architecture.png")


# ------------------------------------------------------------ 图 2 七 Agent 流水线
def fig_agent_pipeline():
    W, H = 1240, 560
    im, d = canvas(W, H)
    d.text((40, 30), "一条 denial 的诊断流水线:Log → Policy → Security → CrossLayer → Repair → Review → Verify",
           font=FB(20), fill=INK)
    d.text((40, 62), "单向前进的状态机,不重试:每个 Agent 的输入输出都是可打印的结构化字段,"
                     "整条链路确定性、可复现,不调用任何模型。",
           font=F(13), fill=MUTED)

    y = 120
    bw, bh, gap = 152, 132, 16
    agents = [
        ("LogAgent", "解析 + 指纹去重", "denial →\nDenialRecord", "#E8F0FE", BLUE),
        ("PolicyAgent", "查索引三问", "允许? 撞红线?\nioctl 白名单?", "#E8F0FE", BLUE),
        ("SecurityAgent", "根因分类", "MISSING_RULE\nXPERM_GAP\n域标签不匹配", "#E8F0FE", BLUE),
        ("CrossLayerAgent", "跨层建议(只读)", "该改配置还是\n改策略?只建议", "#F1F3F4", MUTED),
        ("RepairAgent", "生成最小补丁", "只补缺失权限\nxperm 只放该命令号", "#E6F4EA", GREEN),
        ("ReviewerAgent", "安全护栏", "危险模式 / 通配\n/ neverallow 冲突", "#FEF0E3", ORANGE),
        ("VerifyAgent", "数据驱动验证", "在「补丁已应用」的\n索引副本上重查", "#FEF0E3", ORANGE),
    ]
    for i, (name, role, detail, bg, bd) in enumerate(agents):
        x = 40 + i * (bw + gap)
        box(d, x, y, bw, bh, fill=bg, outline=bd)
        ctext(d, x + bw / 2, y + 26, name, FB(15), INK)
        ctext(d, x + bw / 2, y + 50, role, F(12), bd)
        d.line([x + 16, y + 64, x + bw - 16, y + 64], fill=bd, width=1)
        for k, line in enumerate(detail.split("\n")):
            ctext(d, x + bw / 2, y + 84 + k * 19, line, F(11), MUTED)
        if i < len(agents) - 1:
            arrow(d, x + bw + 3, y + bh / 2, x + bw + gap - 5, y + bh / 2,
                  color="#9AA0A6", width=2, head=8)

    # Verify/Review 未通过不是回路:该案直接归入「需人工」,流水线不重试
    # (orchestrator.analyze 是单向前进;唯一提前退出是 log 解析失败)
    y2 = y + bh + 40
    vx = 40 + 6 * (bw + gap) + bw / 2
    arrow(d, vx, y + bh + 4, vx, y2, color=RED, width=2, head=8)
    ctext(d, vx, y2 + 16, "未通过 → 归入「需人工」(不重试)", F(12), RED)

    # 守门带
    gy = 400
    d.rounded_rectangle([40, gy, 1200, gy + 76], radius=8, fill=RED_BG,
                        outline=RED, width=2)
    ctext(d, 620, gy + 22, "五道守门  ·  防「照抄可疑日志」式误修复", FB(15), RED)
    ctext(d, 620, gy + 50,
          "① 撞 neverallow 一律转人工   ② 解析出的目标仍不许访问 → 拒发补丁   "
          "③ 占位符目标未解析 → 转人工", F(12), "#8A1F17")
    ctext(d, 620, gy + 68,
          "④ 补丁须过 Reviewer 安全评审   ⑤ 补丁须在索引副本上 Verify 成功(消除且无回归)",
          F(12), "#8A1F17")

    d.text((40, 505), "结果三分:可自动出最小权限补丁 / 需人工决策 / 噪声·策略已允许  "
                      "——「需人工」不是失败,而是工具主动拒绝越权的证据。",
           font=F(13), fill=INK)
    im.save(f"{OUT}/fig2-agent-pipeline.png")


# ------------------------------------------------------------- 图 3 批量收敛流程
def fig_converge():
    W, H = 1240, 620
    im, d = canvas(W, H)
    d.text((40, 30), "批量收敛:整份 permissive 日志 → 一份可执行的收紧清单",
           font=FB(20), fill=INK)
    d.text((40, 62), "把「permissive → enforcing」从逐条人工看,变成一条命令出一份清单。",
           font=F(13), fill=MUTED)

    # 输入
    box(d, 40, 120, 200, 110, fill=GREY_BG, outline=MUTED)
    ctext(d, 140, 152, "整份 denial 日志", FB(15), INK)
    ctext(d, 140, 178, "5161 条", FB(18), BLUE)
    ctext(d, 140, 204, "真实语料", F(12), MUTED)

    arrow(d, 245, 175, 305, 175, color="#9AA0A6", width=3, head=9)

    box(d, 310, 120, 200, 110, fill=BLUE_BG, outline=BLUE)
    ctext(d, 410, 152, "指纹去重", FB(15), INK)
    ctext(d, 410, 178, "4911 个唯一案例", FB(16), BLUE)
    ctext(d, 410, 204, "同一访问只算一次", F(12), MUTED)

    arrow(d, 515, 175, 575, 175, color="#9AA0A6", width=3, head=9)

    box(d, 580, 120, 220, 110, fill="white", outline=BLUE)
    ctext(d, 690, 152, "快路判定", FB(15), INK)
    ctext(d, 690, 178, "策略已允许?", F(13), MUTED)
    ctext(d, 690, 200, "撞 neverallow?", F(13), MUTED)

    arrow(d, 805, 175, 865, 175, color="#9AA0A6", width=3, head=9)

    box(d, 870, 120, 230, 110, fill=BLUE_BG, outline=BLUE)
    ctext(d, 985, 152, "七 Agent 流水线", FB(15), INK)
    ctext(d, 985, 178, "逐案分类 + 最小补丁", F(13), MUTED)
    ctext(d, 985, 200, "+ 六道守门", F(13), RED)

    # 三路输出
    outs = [
        (140, "可自动最小修复", "70 类", GREEN, GREEN_BG, "补丁 + 落点提示\n(system / vendor / public)"),
        (500, "需人工决策", "1580 类", ORANGE, ORANGE_BG, "撞红线 / 域标签问题\n/ 占位目标未解析"),
        (860, "噪声 · 策略已允许", "3261 类", MUTED, GREY_BG, "策略本来就允许,\n或属工具自身痕迹"),
    ]
    for x, title, num, col, bg, note in outs:
        arrow(d, 985, 235, x + 160, 300, color=col, width=2, head=8)
        box(d, x, 305, 320, 150, fill=bg, outline=col)
        ctext(d, x + 160, 335, title, FB(16), col)
        ctext(d, x + 160, 372, num, FB(26), INK)
        for k, line in enumerate(note.split("\n")):
            ctext(d, x + 160, 405 + k * 20, line, F(12), MUTED)

    d.rounded_rectangle([40, 500, 1200, 592], radius=8, fill="#F5F8FF",
                        outline=BLUE, width=2)
    ctext(d, 620, 526, "收敛报告 + enforcing 就绪度", FB(16), BLUE)
    ctext(d, 620, 556, "唯一案例 → 三类归属逐一列出;可自动项给出补丁文本与落点,"
                       "需人工项给出理由。工具只建议,不写盘。", F(13), MUTED)
    ctext(d, 620, 578, "实测:零误报进入自动项;neverallow 一律转人工。", F(13), RED)
    im.save(f"{OUT}/fig3-converge-flow.png")


# ----------------------------------------------------------- 图 4 板端实时闭环
def fig_board_runtime():
    W, H = 1240, 620
    im, d = canvas(W, H)
    d.text((40, 30), "板端实时闭环:一次真实的运行时拒绝,1~2 秒内在板子上得到结论",
           font=FB(20), fill=INK)
    d.text((40, 62), "全链路在设备上完成,不插 PC、不用 su、不换域;"
                     "唯一的人工动作是拨一下开关。", font=F(13), fill=MUTED)

    steps = [
        ("① 拨开关", "应用写 guard.on=1\n(应用沙箱内)", BLUE_BG, BLUE),
        ("② pl_collector", "init service 自启\nu:r:pl_collector:s0\n开新采集会话", GREEN_BG, GREEN),
        ("③ 运行时被拒", "采集器自己的 fopen\n命中 enforcing 域\n→ 内核 audit", ORANGE_BG, ORANGE),
        ("④ /dev/kmsg", "audit → printk 镜像\n(已关限流)", GREY_BG, MUTED),
        ("⑤ live.jsonl", "写入应用沙箱\n指纹去重后", BLUE_BG, BLUE),
        ("⑥ HAP 分析", "每秒读一次\n→ 分类 + 最小补丁", GREEN_BG, GREEN),
        ("⑦ 横幅 + 通知", "板上直接显示\n结果与宿主逐字段一致", GREEN_BG, GREEN),
    ]
    bw, bh, gap = 150, 150, 20
    y = 120
    for i, (t, s, bg, bd) in enumerate(steps):
        x = 40 + i * (bw + gap)
        box(d, x, y, bw, bh, fill=bg, outline=bd)
        ctext(d, x + bw / 2, y + 26, t, FB(14), INK)
        d.line([x + 14, y + 42, x + bw - 14, y + 42], fill=bd, width=1)
        for k, line in enumerate(s.split("\n")):
            ctext(d, x + bw / 2, y + 66 + k * 20, line, F(11), MUTED)
        if i < len(steps) - 1:
            arrow(d, x + bw + 2, y + bh / 2, x + bw + gap - 3, y + bh / 2,
                  color="#9AA0A6", width=2, head=7)

    ctext(d, 620, 296, "这一条 denial 是采集器自己在运行时被拒产生的 —— "
                       "不是伪造的日志行,scontext 就是 u:r:pl_collector:s0,permissive=0。",
          F(13), INK)

    # 现读快照信道
    d.rounded_rectangle([40, 330, 1200, 470], radius=8, fill="#F5F8FF",
                        outline=BLUE, width=2)
    d.text((60, 348), "旁路:「载入当前快照」—— 当场自证数据不是预录的", font=FB(15), fill=BLUE)
    seq = [
        ("应用置 snapshot.req=1", "请求现读"),
        ("采集器读一次 kmsg 环形缓冲", "满积压 ≈1000 条"),
        ("写 snapshot.jsonl", "写完"),
        ("最后把 req 写回 0", "0 = 写完了并关好了"),
        ("应用认为文件完整 → 分析显示", "1070 条 → 514 个案例"),
    ]
    sx = 60
    for i, (t, s) in enumerate(seq):
        w = 210
        box(d, sx, 385, w, 66, fill="white", outline=BLUE)
        ctext(d, sx + w / 2, 405, t, F(12), INK)
        ctext(d, sx + w / 2, 429, s, F(11), MUTED)
        if i < len(seq) - 1:
            arrow(d, sx + w + 2, 418, sx + w + 14, 418, color=BLUE, width=2, head=6)
        sx += w + 16

    mtext(d, 60, 500, "自证判据:连按两次,读到的行数不同(实测 801 / 1047 / 1070 / 1084 / 1092 行),"
                      "且记录里的 pid 是本次开机才存在的进程号。", F(13), INK)
    mtext(d, 60, 528, "预录素材做不到「跟着板子一起变」。顺带:现读还能一次捞出固件自身的真缺陷 "
                      "render_service → dev_mali ioctlcmd=0x8014 ×27(XPERM_GAP)。", F(13), MUTED)
    mtext(d, 60, 562, "残留局限:走 /dev/kmsg 受 printk 环形缓冲与限流约束(已在 init job 里关掉限流),"
                      "无损通道是 audit netlink —— 如实写入报告。", F(13), RED)
    im.save(f"{OUT}/fig4-board-runtime.png")


if __name__ == "__main__":
    fig_architecture()
    fig_agent_pipeline()
    fig_converge()
    fig_board_runtime()
    print("done ->", OUT)
