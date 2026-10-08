# 板端演示脚本（demo C：`/system/bin` + 实时采集）

> ⚠️ **这份是 9/22 的旧形态，不是当前形态。** 现在的主线是
> **`demo-realtime.md`**（demo D：板端全独立控制台，不依赖 PC、不依赖 su）。
> 这份保留下来是因为它有一条**不依赖 init service** 的 CLI 动线，
> 作为 demo D 触发不出来时的备选；另外 §第 3 幕的 `--explain` 素材仍然好用。
> 注意它里面的采样数（116 条 / 57 唯一）出自当时的调试会话，别当基准数引用。

> 2026-09-22 在 DAYU200（OpenHarmony 5.0.3.135）实测通过。
> 全部命令在 PC 上经 `hdc shell` 下发；板子上没有终端 app，这是唯一入口。

## 0. 前置状态（已就绪，录前只需确认）

```bash
export PATH=/home/szf/ohos_sdk_dl/tc_extract/toolchains:$PATH
hdc list targets                     # 应有一串序列号
```

| 项 | 值 |
|---|---|
| 工具 | `/system/bin/denial_check`，158,700 B，sha256 `a203ba45…c22388`，在 PATH 上 |
| 索引 | `/data/local/tmp/ohos-5.0.3.pli`，1,122,744 B，`rev e1160d2c7030`，`sepolicy@0878c56e3e41` |
| 采样快照 | `/data/local/tmp/board_denials.txt`（756 行，备用） |

⚠️ **录前先充电**：板子 RTC 已死（时间显示 2017-08-05），电量曾低到 11%，中途断电整段作废。

---

## 第 0 幕 · 自证（15 秒）

```bash
hdc shell "denial_check --selftest"
```

**期望输出**
```
selftest: sha1 13 vectors, 0 failure(s)
selftest: converge 21 vectors, 0 failure(s)
selftest: neverallow 2 probes, 0 failure(s)
selftest: PASS
```

**台词**
> 先证明这个二进制在真机上**能跑、且算得对**。它自带一份小策略和 23 条 denial，
> 21 组收敛向量 + 2 组 neverallow 探针，全部与**宿主参考实现**比对
> ——向量不是拿它自己的输出当期望值，那样无论算成什么样都会通过。

---

## 第 1 幕 · 索引同源（15 秒）

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli --index-info"
```

**期望输出**（关键字段）
```
"rev": "e1160d2c7030", "rules": 19800, "neverallow": 329, "neverallowxperm": 9,
"source": "sepolicy@0878c56e3e41 gen=2026-09-21T06:14:50Z exporter=policy_loop/export/pli.py"
```

**台词**
> 判决只有在**索引与这块板子的固件编译策略同源**时才成立。
> 索引来自 5.0.3 源码树 `0878c56e3e41`，19,800 条规则，其中 **329 条 neverallow 红线**。
> 这一步就是在证明同源。

⚠️ **会有一行 stderr 警告**，提前说明，别慌：
> 索引里带了一个「HAP/APL 映射」段，这一版读不了，所以它**出声警告**而不是静默跳过
> —— 依赖那段的结论会被标注为不可信。这是 9 月刚加的行为。

---

## 第 2 幕 · 采集 + 分析一体（60 秒）★ 核心

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli \
  --log-cmd 'hilog -x -t kmsg' --timeout-ms 15000 --converge"
```

**期望输出**（stderr 横幅 + stdout JSON）
```
source=cmd(cmd:hilog -x -t kmsg)  lines=2554  suppressed≈1294  (sampled input; unique_cases is the robust metric)
{"total_denials": 116, "unique_cases": 57, "by_category": {"auto_repairable": 54, "needs_human": 3}, ...}
```

**台词**
> 读的是**这块板子自己的内核审计流**。注意它自报 `suppressed≈1294`
> —— OH 上审计流走 hilog，printk 出口有 5 秒 10 条的限速，**必丢**。
> 所以它不说「我抓全了」，而是给出 `unique_cases` 这个对丢帧免疫的指标。
>
> 全程计算在板子上，`hdc` 只是键盘。

---

## 第 3 幕 · 现场制造一个真实缺口（60 秒）★ 高潮

**先截一张屏**——这会强制图形管线走 mali：

```bash
hdc shell "snapshot_display -f /data/local/tmp/x.jpeg"
```

**等 2 秒，再采一次**：

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli \
  --log-cmd 'hilog -x -t kmsg' --timeout-ms 8000 --converge"
```

**期望**：分类里出现 `XPERM_GAP: 1`，cluster 为
`render_service -> dev_mali:chr_file ioctl 0x8014`，补丁
`allowxperm render_service dev_mali:chr_file ioctl { 0x8014 };`

**然后单条追问**（把下面整行粘进 `--explain`）：

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli --explain \
'audit: type=1400 audit(1501924095.986:1672): avc:  denied  { ioctl } for  pid=680 comm=\"mali-cmar-backe\" path=\"/dev/mali0\" dev=\"tmpfs\" ino=181 ioctlcmd=0x8014 scontext=u:r:render_service:s0 tcontext=u:object_r:dev_mali:s0 tclass=chr_file permissive=0'"
```

**实测输出**
```
分类  XPERM_GAP
访问  render_service -> dev_mali:chr_file { ioctl }
说明  render_service 对 dev_mali:chr_file 的 ioctl(0x8014) 被拒：策略已允许 ioctl 大类，
      但该命令号不在 allowxperm 白名单内，属于「细粒度权限缺口」而非「完全没有权限」。
建议  最小权限补齐
补丁  allowxperm render_service dev_mali:chr_file ioctl { 0x8014 };
评审  APPROVE
验证  SUCCESS
```

**台词（这段是整个演示的价值所在）**
> 我截了一张屏，它立刻把这条抓出来了。看判定：**不是「缺 ioctl 权限」**——
> 策略第 33 行 `allow render_service dev_mali:chr_file { getattr ioctl map open read write };`
> **ioctl 大类本来就是允许的**。缺的是第 84 行那张 allowxperm 白名单里的**一个命令号**。
>
> 所以 `audit2allow` 在这里会建议加一条 **已经存在** 的规则，写了等于没写
> —— 这就是我们在真实语料上量到的 2833 条 vs 69 条、**94.8% 是 no-op** 的来源。
> 我们给的是 `allowxperm … { 0x8014 };`：**精确、最小、可落地**。

---

## 第 4 幕 · 逐权限精确 + 红线拦截（40 秒）

**先给一个「有补丁」的**（只有 `write`）：

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli --explain \
'avc:  denied  { write } for  pid=1 comm=\"sh\" scontext=u:r:su:s0 tcontext=u:object_r:data_local_tmp:s0 tclass=file permissive=0'"
```
→ `MISSING_RULE`，补丁 `allow su data_local_tmp:file { write };`，评审 `APPROVE`，验证 `SUCCESS`

**同一个目标，把权限换成 `{ open write }`**（真实行）：

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli --explain \
'audit: type=1400 audit(1501923732.746:1448): avc:  denied  { write open } for  pid=722 comm=\"OS_FFRT_2_3\" scontext=u:r:su:s0 tcontext=u:object_r:data_local_tmp:s0 tclass=file permissive=1'"
```

**实测输出**
```
分类  POTENTIAL_ESCALATION
访问  su -> data_local_tmp:file { open write }
说明  该访问命中 neverallow 红线：su 请求 data_local_tmp:file {open, write}。即使技术上可加规则，
      也极可能是越权或架构问题，PolicyLoop 拒绝自动放权。
建议  人工确认/架构调整（禁止自动放权）
```
（**没有补丁行**——这就是重点。完整结构用 `--json` 看：`"review": "SKIP"`、`"verify": "HUMAN_REVIEW_REQUIRED"`、`"patch": ""`。）

**台词**
> 注意这两条是**同一个源、同一个目标、同一个对象类**，只差权限集。
> 第一条给补丁，第二条**拒绝给补丁**——因为 `open` 撞了 neverallow 红线。
>
> 所以它是**逐权限**判定的，不是逐规则。`audit2allow` 在这里照样会生成一条 allow；
> 我们的第一道守门是「撞红线直接转人工」。这就是 2833 vs 69 里那 2687 条 no-op 的来源。
>
> 顺带说一句：这几条 denial 是**我们自己的调试会话**造成的（`su` 域，`permissive=1`），
> 不是板子的缺陷。工具会把它一起抓出来，但**演示时这两类必须分开讲**。

---

## 第 5 幕 · 收尾（15 秒）

```bash
# 拔掉 USB，再敲一次
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli --log /data/local/tmp/board_denials.txt --converge"
```

（拔线后需接串口 console 才能敲；或在拔线前预先说明）

**台词**
> 判定内核是纯标准库的，不联网、不调模型、可复现。
> 索引随固件版本走，判决只对同源树成立——这是它敢给「最小修复」而不是「一堆规则」的底气。

---

## ⚠️ 两个必须提前知道的毛边

### 1. `--converge` 不区分「板子自带」和「工具造成」

分类逻辑只在 **HAP（NAPI 层）** 和 `tools/board_bridge.py` 里，CLI 没有。
用同样口径（`TOOL_DOMAINS`）给实测数据分过类：

| 来源 | 条数 | 唯一 |
|---|---|---|
| 板子自带 | 73 | 26 |
| **工具造成**（`su` 域） | **43** | **31** |

**43/116 = 37% 是我们自己的 hdc 会话足迹。** 讲稿里必须分开说，
否则「57 个唯一案例」里有一半站不住。

### 2. 索引的 `hap` 段读不了

每次加载索引都会往 stderr 印一行警告。它不是故障，是**诚实的降级声明**。
录像时要么留着并解释，要么 `2>/dev/null` 掐掉。

---

## 备用方案（第 3 幕触发不出来时）

板子空闲时不渲染，0x8014 就不复发。若 `snapshot_display` 没触发出 denial：

```bash
hdc shell "denial_check -i /data/local/tmp/ohos-5.0.3.pli \
  --log /data/local/tmp/board_denials.txt --converge"
```

这份 756 行快照里有 **90 次**该 denial 的记录（全部 enforcing），
分类为 `XPERM_GAP`，补丁同上。**但要用「这是之前采的快照」来讲，不能说是现场抓的。**
