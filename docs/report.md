# 2026 开源鸿蒙大学生创新大赛 · 赛道一

**赛题：PolicyLoop（OpenHarmony SELinux 拒绝日志的最小权限自收敛）**

| | |
|---|---|
| 学校名称 | 【待填】 |
| 团队名称 | 【待填】 |
| 队长 | 【待填】 |
| 队员 1 | 【待填】 |
| 队员 2 | 【待填】 |

> 提交材料：① 参赛作品简介（另附）② 本开发设计文档 ③ 项目视频/PPT（另附）④ 可选辅助材料

---

## 目录

- [1 简介](#1-简介)
  - [1.1 背景](#11-背景) · [1.2 目的](#12-目的)
- [2 设计描述](#2-设计描述)
  - [2.1 总体设计](#21-总体设计) · [2.2 实现思路](#22-实现思路)
  - [2.3 系统结构](#23-系统结构) · [2.4 模块功能描述](#24-模块功能描述)
  - [2.5 业务/实现流程说明](#25-业务实现流程说明) · [2.6 接口描述](#26-接口描述)
  - [2.7 UI 设计](#27-ui-设计) · [2.8 实测与验证](#28-实测与验证) · [2.9 口径与诚实性说明](#29-口径与诚实性说明)
- [3 其他](#3-其他)
  - [3.1 成员分工](#31-成员分工) · [3.2 困难与思考](#32-困难与思考) · [3.3 不足与未来工作](#33-不足与未来工作) · [3.4 参考](#34-参考)

---

# 1 简介

## 1.1 背景

OpenHarmony 用 SELinux 做强制访问控制：任何应用或系统服务要访问系统资源，都必须先过这道门禁。请求被拒时，内核会记录一条 `avc: denied` 日志：

```
avc: denied { read } for pid=2208 comm="media_service" path="/dev/video0"
     scontext=u:r:media_service:s0 tcontext=u:object_r:camera_device:s0
     tclass=chr_file permissive=0
```

这条日志对开发者极不友好，原因有三：

1. **读不懂**。`scontext` / `tcontext` / `tclass` / 权限位是一套自成一体的词汇，报错现场通常只看到“功能失败”，看不到“为什么”。
2. **不知道在哪补**。策略规则写在数百个 `.te` 文件里，按子系统分目录；一条 denial 该落到 `system/` 还是 `vendor/`、属于哪个组件，靠经验。
3. **补不对**。最省事的做法是“看到 denial 就加一条 `allow`”，这会把一次越权尝试固化成永久授权。

现实中的应对往往是**把门禁关成“只记不拦”（permissive）**：系统看起来正常了，但实际处于**无强制拦截**状态。这是配置层面长期累积的安全债。

这个问题在 OpenHarmony 上游有充分的数据佐证。本作品对上游策略仓库 `security_selinux_adapter/sepolicy` 做了一次全量统计（`python -m policy_loop.eval.corpus`）：

| 项 | 实测值 |
|---|---|
| `.te` 策略文件 | **1,315** 个 |
| 策略源码行数 | 51,427 行 |
| 含 denial 注释的文件 | 378 个 |
| 历史 `avc: denied` 注释条目 | **5,230** 条 |
| 索引出的规则 | **21,824** 条 |

也就是说：**光是上游自己的代码注释里，就埋着 5,161 条真实发生过的 denial**。这些 denial 分布在全系统各子系统中，每一条当初都被人手工诊断过。这是一条靠人力堆砌、长期存在的工作流。

> **语料口径速查**（这几个数首次出现在这里，完整对照表见 2.8）：原始注释条目 **5,230** 条 → 解析并与紧邻修复规则配对的 denial 记录 **5,161** 条（差 69 条是不与任何规则相邻、或没能解析成完整记录的注释；5,161 也是 `data/corpus/real_denials.txt` 的行数）→ 字段完整、可参与评测 **5,117** 条（44 条缺 `scontext`/`tclass` 等字段，回放时跳过）→ 指纹去重后的**唯一案例** **4,911** 个（`converge` 与各项评测的分母）。

## 1.2 目的

本作品的目标是把上面这条工作流自动化，并且**把“安全”作为一等约束而非事后检查**：

> 输入一份 `avc: denied` 日志，自动**读懂 → 定位根因 → 生成最小权限修复 → 安全评审 → 数据驱动验证**，最终支撑把设备从 permissive 收紧到 enforcing。

与“看到 denial 就加 allow”的常见做法相比，本作品要回答的是同一个问题的**更严格版本**：

| 常见做法 | 本作品的目标 |
|---|---|
| 这条访问要放行吗？ | 这条访问**该不该**放行？（撞系统红线的一律拒绝自动放权） |
| 加哪条规则？ | **最小**的那条规则是什么？多一个权限位都算失败 |
| 加完就行了吗？ | 加完之后 denial 消失了吗？有没有引入新的越权？ |
| 一条一条看 | 整份日志一次收敛成可执行清单 |
| 拿不准的就写“转人工” | 转人工之后呢？1,580 条**逐条归因**“该谁修”（实测真正要打补丁的只有 **0** 条） |

**验收目标是可量化的**，对应四组指标：策略覆盖率、补丁最小性、零越权（撞 neverallow 一律拒绝）、以及真机 enforcing 下的端到端一致性。

---

# 2 设计描述

## 2.1 总体设计

本作品按“能独立验证”划分成四层，每层都有明确的产出物与验收方式：

| 层 | 内容 | 产出物 | 验收 |
|---|---|---|---|
| L1 确定性内核 | denial 解析器 + `.te` 策略索引 | `policy_loop/denial`、`policy_loop/policy` | 解析/查询差分逐字节一致 |
| L2 评测基线 | 从上游真实语料构造 golden 集并回放 | `data/eval/golden.jsonl`、`docs/eval-L2.md` | 覆盖率、可复现命令 |
| L3 诊断流水线 | 七 Agent 最小权限流水线 + 批量收敛 + 补丁最小化/归因 | `policy_loop/agents`、`converge.py`、`minimize.py`、`attribution.py` | 留一法回归、零过宽、闭环反验 |
| L4 设备端 | 系统组件 `denial_check` + 采集服务 + 控制台 | `device/`、板端 HAP | 真机五项门禁 |

四层的关系是**同一份判定逻辑的三次落地**：先在 Python 上把语义做对（L1–L3），再用评测证明它收敛（L2/L3），最后把它变成设备上的原生系统组件并用差分证明两端等价（L4）。

> **本作品总体架构**见图 1（2.3.1）。

## 2.2 实现思路

全部实现由下面四条原则推出，模块划分（2.4）与流程设计（2.5）都是它们的展开。

### 2.2.1 确定性内核优先，LLM 可插拔、可断供

解析、索引、根因分类、最小补丁、安全评审、验证：**全部是纯规则、纯标准库实现**，每个判定都能回溯到一条被索引的 `.te` 规则。LLM 只在配置了 key 时参与“人话解释/候选草稿”，**不参与任何安全决策**。

这个选择有直接的实验依据。本作品对同一批真实 denial 做了对照（`docs/eval-llm-guardrail.md`）：

| 方案 | 过宽（越权加权限）率 |
|---|---|
| 未受约束的“AI 直接放权”（naive 档，120 样本） | **100%** |
| PolicyLoop：最小权限指令 + 规则护栏 + 确定性精修 | **0%**（120/120 被拦截并精修回最小） |

**越权倾向是 LLM 的默认行为，提示词消除不掉，只能靠确定性护栏兜住**。架构上因此把“生成候选”和“批准授权”分成两个角色，后者永远是规则。

### 2.2.2 绝不自动写盘

工具只产出「建议补丁 + 落点提示（`system/` / `vendor/` / `public/`）」。是否写入 `.te`、是否重建策略、是否上 enforcing，由人决定。这条原则贯穿主机端与设备端：设备端的 `--explain` / `--case` 也只输出建议。

### 2.2.3 先仿真、后真机

先用上游真实策略语料做数据仿真与量化评测（成本低、可反复），再上真机取独立证据。真机给出的是**独立于评测构造的第三类证据**。

### 2.2.4 设备端只搬“属于设备的那一段”

这是本作品最关键的一个架构判断，也是最常被问到的一点：**为什么不把整个 PolicyLoop 移植到设备上？**

其中一部分原理上无法下沉：

- **设备上没有策略源码。** 实测设备上 SELinux 的全部家当是 `config`（enforcing）+ 编译后的二进制 `policy.31`（424,699 B）+ 若干 `*_contexts` 文本；`find /system /vendor -name "*.te"` **为空**。
- **`neverallow` 原理上不在二进制策略里。** `neverallow` 是**编译期断言**。`third_party/selinux/libsepol/src/expand.c:2736` 的注释写明：neverallow 规则不写进产出的策略，只在编译期留给断言检查器核对。而本工具的核心守门之一就是“撞 neverallow → 拒绝自动放权”（策略里实测 419 条 `neverallow` + 11 条 `neverallowxperm`）。设备上拿不到红线，工具会退化成“看到 denial 就建议放权”，而这是它最该避免的行为。
- **多智能体编排与评测工具本就属于开发期**，不是运行时设备功能。

因此分工明确：**策略语义在设备上**（索引 / 判定 / 守门），**agent 编排在主机上**。索引由构建期从源码树导出为只读的 **PLI** 数据文件（本作品自定义的索引格式：`PolicyIndex` 的文本化只读投影，首行即格式魔数 `PLI1`、次行 `@rev` 是版本号，见 2.6.2）随镜像下发。这属于架构约束。

## 2.3 系统结构

### 2.3.1 模块划分

![图 1 本作品总体架构](figs/fig1-architecture.png)

系统分为**主机端（重）**与**设备端（轻）**两侧，中间是一条窄接口：

- **主机端**（Python 标准库，零第三方依赖）：denial 解析器、策略索引、七 Agent 诊断流水线、批量收敛、评测体系。
- **设备端**（OpenHarmony 原生 C++，32 位 ARM / musl）：采集服务 `pl_collector`、系统组件 `denial_check`、板端控制台 HAP。
- **数据契约**：PLI 只读索引（构建期导出、随镜像下发）+ JSON/TSV 判定结果（逐条或批量）。

分层依据是**“哪些能力必须和设备在一起”**：只有需要读内核日志、需要独立于 PC 运行的部分才下沉；策略语义（索引 + 判定 + 守门）下沉是因为“设备自己的策略缺口是它自己的事实”；而索引的**构建**不能下沉，因为需要 `.te` 源码。

> 两个备选方案均未采纳。**全部做成上位机工具**满足不了“系统组件”的定位，也无法在无 PC 的现场使用。**全部下沉到设备**受制于 `neverallow` 不在二进制策略中这一硬约束，且会把开发期工具塞进系统镜像。

### 2.3.2 系统架构说明

一条 denial 在系统中的完整动线，是七个 Agent 依次处理的一条**单向链**（`Log → Policy → Security → CrossLayer → Repair → Reviewer → Verify`）；其中 `CrossLayerAgent` 只出跨层建议、不改变结论：

![图 2 七 Agent 诊断流水线](figs/fig2-agent-pipeline.png)

`Orchestrator` 是一个严格状态机：`Log → Policy → Security → CrossLayer → Repair → Reviewer → Verify`。每个 Agent 的输入输出都是可打印的结构化字段（`SecurityCase` 记录全程 trace），因此整条链路可复现、可单测。流水线**刻意不含回路**：`VerifyAgent` 判失败、或 `ReviewerAgent` 否决时，该案例被归入「需人工」，而**不会回退到 `RepairAgent` 重算**，因为允许 Agent 反复重试到某次通过安全门，等于让它迭代出一个更宽的补丁（详见 2.4.3）。

业务处理上，主机端与设备端共享同一套判定语义：设备端的 `--converge`（批量报告）与 `--case`（逐条判定）**走同一份判定代码**（`ExplainCase` + `ApplyGuards`），因此两条路径的答案不会漂，这一点由差分门禁逐字段验证（见 2.8）。

### 2.3.3 文件结构

```text
policy_loop/
├── policy_loop/                      主机端引擎（Python 标准库，零第三方依赖）
│   ├── denial/parser.py              AVC denial 解析 + 指纹去重
│   ├── policy/
│   │   ├── index.py                  .te 策略索引与查询（allow/neverallow/allowxperm）
│   │   ├── cross_layer.py            APL（应用能力特权级）跨层反查
│   │   ├── cil.py                    板子 policy.31 反编译 CIL 的只读视图
│   │   └── sehap.py                  sehap_contexts 解析
│   ├── agents/                       七 Agent 流水线
│   │   ├── orchestrator.py           严格状态机
│   │   ├── security_case.py          案件档案 + Agent Trace
│   │   ├── log_agent.py / policy_agent.py / security_agent.py
│   │   ├── repair_agent.py / reviewer.py / verify_agent.py
│   │   ├── cross_layer_agent.py      跨层判定（advisory）
│   │   └── providers.py              可插拔 LLM Provider
│   ├── eval/                         评测体系
│   │   ├── corpus.py / extract.py    语料统计 / golden 抽取
│   │   ├── replay.py                 索引覆盖回放
│   │   ├── trust.py                  golden 可信度质检
│   │   └── agent_eval.py / agent_llm_eval.py   留一回归 / LLM 护栏对比
│   ├── export/pli.py + cli.py        PLI 索引导出器
│   ├── converge.py                   批量收敛（整份日志 → 三分清单）
│   ├── minimize.py                   补丁集根因归并 + 闭环反验 + 爆炸半径
│   ├── attribution.py                「需人工」1580 条的根因归因（该谁修）
│   ├── explain.py                    单条诊断
│   └── selfcheck.py                  环境 + 模块 + 冒烟自检
├── webui/server.py                   Web UI（stdlib HTTP server + /api/analyze）
├── device/                           设备端（按 OpenHarmony 源码路径镜像）
│   ├── selinux_adapter/
│   │   ├── framework/policycoreutils/src/pl_*.cpp      核心库（6 个编译单元）
│   │   ├── framework/tools/denial_check/test.cpp       命令行外壳与固定 API
│   │   └── interfaces/policycoreutils/include/pl_*.h   接口（7 个头文件）
│   ├── patches/selinux_adapter-BUILD.gn.patch          对上游 BUILD.gn 的加法
│   ├── selinux_policy/                                 域策略、安装与自检脚本
│   │   ├── pl_collector.cil / denial_check.cil
│   │   ├── build_policy.sh / build_pl_collector.sh
│   │   └── install_service.sh / install_to_board.sh / diag_domain.sh
│   ├── board/                                          板端 init 配置与运维脚本
│   │   ├── policyloop.cfg / policyloop-probe.cfg
│   │   └── pl_guard.sh / pl_domtest.sh
│   ├── pl_console/                  板端控制台 HAP 工程（ArkTS + NAPI，含内置索引）
│   └── install.sh                                      铺回 OH 源码树
├── tools/                            devbuild.sh / build_hap.sh / make_app_icon.py …
├── data/
│   ├── corpus/real_denials.txt       真实 denial 语料（5,161 条）
│   ├── eval/golden.jsonl             自证评测集（3,367 对）
│   ├── eval/golden.trusted.jsonl     质检后干净子集（2,154 对）
│   ├── reports/                      各项评测报告（已入库）
│   └── fixtures/                     测试与演示样例
├── docs/                             设计与评测文档、配图
└── tests/                            341 项单测 + 设备差分门禁 diff_device.py
```

> **可复现性**：板端控制台 HAP 的工程源码就在仓内 `device/pl_console/`，`tools/build_hap.sh` 的 `PROJ` 默认指向它，`tests/test_tool_domains_sync.py` 会校验两份工具域清单一致（不一致即测试失败）。构建可离线完成，只有签名（需本机 UDID）与装机（需 hdc）依赖板子。

## 2.4 模块功能描述

### 2.4.1 denial 解析器（`policy_loop.denial.parser`）

- **标识**：`policy_loop.denial.parser`
- **类型**：数据解析模块
- **目的**：把内核输出的、面向机器而非面向人的 AVC 日志，转成结构化记录。
- **功能列表**：解析 OH 专有形态（`parameter_service` 的 `parameter=`、`samgr_class` / `hdf_devmgr_class` 的 `service=`/`sid=`、`ioctlcmd=0x…`、`permissive` 标志、`audit:`/`avc_audit_slow:` 前缀、续行、多事件切分）；计算**指纹**用于跨批次去重。
- **处理**：纯正则 + 状态机，无外部依赖。`permissive` 按**三态**建模：`0` = 已拦截、`1` = 只记不拦、**其余取值与字段缺失一律为「未知」**。三态在计数上分开（`permissive_unknown` 独立统计），在收敛判定上则**一律走保守侧**：只有 `1` 会被判为历史噪声，未知态与 `0` 同样转人工复核（`DOMAIN_OR_LABEL_MISMATCH`），**绝不参与自动放权**。指纹去重是批量收敛的基础：它让“同一访问重复被拒上千次”收敛成一个案例，也让真机验收指标**天然免疫 printk 丢帧**（见 3.2）。

### 2.4.2 策略索引（`policy_loop.policy.index`）

- **标识**：`policy_loop.policy.index`
- **类型**：策略语义模块
- **目的**：在主机上把 `.te` 源码树编译成可查询的索引；在设备上加载同一份索引的只读投影（PLI）。
- **功能列表**：解析 `allow` / `allowxperm` / `neverallow` / `neverallowxperm`；计算 attribute 闭包（含 `typeattribute` 的空格/逗号两种写法）；展开宏（`binder_call()` 等）与条件块（`debug_only()` 等）；ioctl 白名单/xperm 语义判定。
- **处理**：查询接口三个：`has_access`（请求权限是否**全部**被授予）、`neverallow_rules`（红线）、`ioctl_allowed`（白名单判定）。另有 `resolve_logical_target`：把 `default_service` / `default_hdf_service` 这类**占位目标**按具名服务或自注册 `add` 确定性映射到 `sa_*` / `hdf_*` 具体类型。

实测索引规模（上游 1,315 个 `.te`，`sepolicy@29a2fc123dd1`）：**21,824 条规则、1,267 个类型、49 个属性**，其中 `allow` 20,758、`neverallow` 419、`allowxperm` 636、`neverallowxperm` 11，另有 524 条语句进了 `skipped` 计数（172 条宏/条件调用未展开、147 条 `allow`/`allowxperm` 与 **140 条 `neverallow`/`neverallowxperm`** 因写法不被三条正则接受、8 条 `dontaudit` 这类刻意不建模的语句、其余是宏定义体残片等）。

> **索引的红线覆盖面**：同一棵树上以 `neverallow` / `neverallowxperm` 开头的语句共 **570 条**，索引实际收进 **430 条**（即上句的 419 + 11）。被拒的 **140 条**按形态分：类位写成集合 `:{ c1 c2 }` 59 条（如 `neverallow { chipset_domain } system_file:{ blk_file chr_file … } *;`）、权限位取反 `~{ search }` 或 `~list` 50 条、目标位取反 `~{ attr … }`（源位或目标位）9 条、xperm 单值未加花括号 1 条 —— 这 **119 条是纯书写形态**，放宽三条正则即可收（1 行级改动）；余下 **21 条**的类型集合里嵌着条件宏（`debug_only(…)`），即便放宽正则也只能「看条件」，与部署期被跳过的 88 条条件式红线同类。宿主与设备之间的差分门禁**原理上抓不到**前者：设备侧读的是宿主导出的 PLI，`skipped` 在两端都只报不查，而聚合数字（分类分布、补丁行数）不变——总量会盖住单案翻转。处置见 2.9 与 `docs/known-limitations.md` §2.1：**未修**（改它会动索引规模、PLI 与随镜像下发的索引，板子不在线时不做）。

### 2.4.3 七 Agent 诊断流水线（`policy_loop.agents`）

- **标识**：`policy_loop.agents`
- **类型**：业务编排模块（确定性，无模型调用）
- **目的**：对**一条** denial 给出完整结论：根因是什么、策略红线在哪、最小补丁是什么、能不能自动落地。
- **功能列表 / 处理**：

| Agent | 职责 | 判定输出 |
|---|---|---|
| LogAgent | 解析、指纹去重 | `DenialRecord` |
| PolicyAgent | 查索引三问：允许？撞红线？ioctl 白名单？ | 策略裁决 |
| SecurityAgent | 根因分类 | `MISSING_RULE` / `XPERM_GAP` / `POTENTIAL_ESCALATION` / `NOISE_OR_ALREADY_FIXED` / `DOMAIN_OR_LABEL_MISMATCH` |
| CrossLayerAgent | 跨层建议（**只读**，advisory） | 该修在 `module.json` 还是 `.te`；只出建议、**不改变结论**（Repair 及其后忽略它） |
| RepairAgent | 生成最小权限补丁 | 普通 `allow` 只补缺失权限；`allowxperm` 只放行该命令号 |
| ReviewerAgent | 安全护栏 | 危险模式 / 越权放行 / 通配 / neverallow 冲突 → APPROVE / REJECT |
| VerifyAgent | 在“补丁已应用”的索引副本上重查 | 消除、无回归、范围最小 → SUCCESS / FAILED / SECURITY_REGRESSION |

- **跨层判定的实现**：`CrossLayerAgent` 读取 8 份 `sehap_contexts` 建立 **APL**（Ability Privilege Level，应用能力特权级）反查，区分“应用域/系统域”，让应用级与系统级的排查链路分开。它插在 Security 与 Repair 之间，**读裁决但不写裁决**，加不加它，同一条 denial 的结论都不变（见 `agents/orchestrator.py` 的 `_PIPELINE`）。
- **流水线不含回路**：`Orchestrator.analyze()` 对 `_PIPELINE` 单向前进，**唯一的提前退出是 log 解析失败**；Reviewer 否决或 Verify 判 `FAILED`/`SECURITY_REGRESSION` 时，该案在 `converge` 里由 `_categorize()` 归入「需人工」，**不回到 Repair 重算**（理由见 2.3.2）。

### 2.4.4 批量收敛（`policy_loop.converge`）

- **标识**：`policy_loop.converge`
- **类型**：批处理工作流
- **目的**：把“permissive → enforcing”从逐条人工看，变成一条命令出一份清单。
- **功能列表**：整份日志 → 指纹聚类去重 → 快路判定（策略已允许？撞 neverallow？）→ 每唯一案例跑一遍 Agent 流水线 → 输出**收敛报告**（去重比、根因分布、可自动最小修复的补丁集、需人工项、enforcing 就绪度）。
- **处理：五道守门**（防“照抄可疑日志”式误修复）：

| # | 守门 | 作用 |
|---|---|---|
| 1 | 撞 `neverallow` → 直接转人工 | 拒绝自动放权 |
| 2 | 解析出的目标仍不许访问 → 拒发补丁 | 拦住“解析成功但补丁仍写占位符”的情形 |
| 3 | 占位符目标未解析 → 转人工 | 不猜 |
| 4 | 补丁须过 Reviewer 安全评审 | 广度过宽/危险模式拦截 |
| 5 | 补丁须在索引副本上 Verify 成功 | 必须真的消除且无回归 |

> **注意**：别把这张表与代码里的 `apply_guards` 混为一谈，它们是两套分法、数也不同：
> 这里是**流水线里的 5 个拒绝点**（含 Reviewer / Verify），代码里的 `apply_guards`
> 是**另一组 6 个分支**（MLS 级目标 / `default_*` 占位符 / 主体或目标不在语料 /
> 对象类不在语料 / 权限位含非权限名 / 空权限补丁）。后者才是 converge 与 `--explain`
> **共用的那一份**：同一份实现、两个调用点，同一条记录从哪个入口问都必须拿到同一句话
> （见 `eval-converge.md`）。

### 2.4.5 补丁最小化与闭环反验（`policy_loop.minimize`）

- **标识**：`policy_loop.minimize`
- **类型**：批处理后处理（**只在宿主机跑**，不改设备端一个字节）
- **目的**：`converge` 回答的是**逐案例**的问题：“哪一条规则能关掉这一个案例？”。这对看单个案例的人是对的，对看整份日志的人是错的：两个案例只要内核打印权限的次序不同，就会被投影成两条规则，而它们其实是同一个根因。实测例：`allow init write_updater_exec:file` 的 `{ execute }` / `{ map }` / `{ open read }` 三条，是三个 cluster、一个根因，*init 本不该引用这个 updater 二进制*。
- **功能列表**：
  - **根因归并**：重读收敛报告，把同一 `(src, tgt, cls)` 的补丁行并成一条根因规则，
    并记录它**关闭了哪些案例**、是**扩了已有规则**还是**新增**。
  - **闭环反验**：把归并后的规则集套回索引的副本上**重新查询**，要求
    “补丁前未解决的案例，套回后全部解决”，且“套回前它们确实没被解决”。
    `converge` 只断言补丁**编译得过**；这一步断言补丁**真的有用**。
  - **爆炸半径**：每条规则给出 `BlastRadius`，即展开后实际受影响的类型数与规则数。
    **注意**：判定“最窄规则”必须按**展开后的影响面**，不能按 token 数：
    `{domain}` 只用 1 个 token，却覆盖 **235** 个类型。

- **输出**：`rules`（最小规则集 + 关闭的案例 + 爆炸半径）、`verify`（闭环结论）、
  `--cil`（给 `secilc` 与 neverallow 门禁用）、`--patch-report`（喂给
  `tools/apply_converge.py`，供红线门禁验证归并后的集合）。
- **实测**：补丁 **69 行 → 54 条根因规则**（归并 10 组、省 15 行；26 条折叠进已有规则，
  其中 3 条会波及属性成员；25 条为新增），闭环反验 **70 未解决 → 0**。

### 2.4.6 策略级根因归因（`policy_loop.attribution`）

- **标识**：`policy_loop.attribution`
- **类型**：批处理后处理（只读，不产生补丁）
- **目的**：`converge` 把 4,911 个唯一案例分成三类，其中 **1,580 个进 `needs_human`**，
  占三分之一，而它对这些案例说的话只有一句「转人工」。对着一屏“转人工”，读者学到的
  是**工具不知道**，而不是工具知道什么。本模块把那 1,580 条逐条问出根因，
  **判据全部是可证伪的查询**（问板子自己的 `policy.31` 反编译视图、问上游树、
  问日志字段是否完整），不引入启发式。
- **功能列表**：读收敛报告里判不了的那部分，逐条问出根因并落到一个 owner，残留数不为 0 即以非零码退出。
- **处理：每条案例落到一个 owner**：

| owner | 含义 | 实测 |
|---|---|---|
| `DEVICE` | 板上真要补权限（**唯一**需要打补丁的一类） | **0** |
| `TOOL` | 工具侧该修（索引/版本对齐、语料收录） | 342 |
| `LOG` | 采集/日志质量（缺字段、上下文畸形） | 53 |
| `HUMAN` | 需要架构决策（撞 neverallow 红线） | 38 |
| `NONE` | 无需动作（现在已允许） | 1,147 |

- **退出码即判据**：`0` 仅当残留 `UNATTRIBUTED` 为 0，**归因不完备就失败**，
  不许悄悄漏掉。实测 1,580 → 归因 1,580、残留 **0**。
- **主动证伪的三类根因**：板子策略里 `(boolean` 出现 **0** 次、`(constrain` **0** 次、
  `(mlsconstrain` 只有 **1** 条且只约束 `(filesystem (relabelto))`。所以“boolean 未开”、
  “constraint 拦下”、“MLS 级不匹配”在本平台**原理上无从发生**，把它们列进报告当
  “检查过了”站不住，本模块选择**写明证伪**。

### 2.4.7 评测体系（`policy_loop.eval`）

- **标识**：`policy_loop.eval`
- **类型**：开发期验证工具（**不随设备发行**）
- **目的**：让所有结论可量化、可复现、可被质疑。
- **功能列表**：
  - `corpus`：语料规模统计；
  - `extract`：从上游 `.te` 的 `# avc: denied …` 注释与其紧邻修复规则，按邻接配成 `(denial → 真实修复)` 对，产出 golden 集（3,367 对）；
  - `replay`：全量索引下这些真实 denial 是否已被允许，测索引/属性/宏处理的**召回**；
  - `trust`：逐对校验“规则与 denial 是否真的相关”，过滤邻接配对的错配噪声，产出 trusted 干净子集；
  - `agent_eval`：**留一法**回归，即剔除某 denial 的修复规则使其回到“未修复”，再跑 Agent 流水线，比对生成补丁；
  - `agent_llm_eval`：同批 denial 上让 LLM 自由起草补丁，量化越权率与护栏拦截率。

### 2.4.8 设备端组件 `denial_check`（`device/`）

- **标识**：`denial_check`，安装于 `/system/bin/denial_check`
- **类型**：OpenHarmony 原生可执行程序（32 位 ARM / musl 动态链接）
- **目的**：**审计设备自己的策略，应该是平台能力，而不是一件必须先有 PC 和串口线才能做的事。**
- **功能列表 / 处理**：
  - 核心是一个**独立静态库** `libdenial_check_core`（6 个编译单元），`external_deps` 为空，即它只能链到 `libc`/`libc++`/`libm`，**不得**引入 hilog 或 libselinux。原因是它的全部意义就在于“在任何能读到输入的域下运行，并把结论写 stdout 而不是写 hilog”。这条规则是**可检查的**，不是声明。
  - 固定 API 入口：`--selftest` / `--index-info` / `--query` / `--dump-denials` / `--converge` / `--explain` / `--case`。
  - `--explain` 另带 `--cross-layer`（显式打开跨层视图，需索引含 `@hap` 段）；不给就只有默认契约。
  - **`--explain` 与批处理走同一份守门**：设备端只有一个 `ApplyGuards`，单条诊断与
    批量收敛调的是它。理由同上：守门若只内联在批量聚类循环里，
    `--explain`（开发者捏着一条坏日志时最先用的那条路）就会推荐一条**编译得过、
    Verify 也判成功、只是落不了地**的规则（实例：对着 `default_service` 写
    `allow X default_service:samgr_class { get };`）。同一条记录从哪个入口问，
    都必须拿到同一句话。
  - **两条路径都进自检**：`--selftest` 内嵌一份 11 条规则的小策略与 26 条 denial，
    比对 24 组收敛向量 + 11 组解释向量（后者按**整份 JSON** 比，其中 6 组 `advisory`
    非空）。两条路径**分别**钉住：把 `--explain` 路径上的 `ApplyGuards` 调用删掉，
    解释向量 6/11 报错而收敛向量 24/24 全绿：收敛向量结构上看不见解释路径，所以
    这不是同一批断言换个写法。六道守门在收敛向量里**一道不缺**。
  - **`@hap` 进索引**：`sehap_contexts` 的 APL↔域桥表随 PLI 下发，设备端才能复现
    跨层结论（“这是 APL 分级边界” vs “这是漏配的规则”）。该表共 17 条 APL↔域映射、
    覆盖 13 个域，随 PLI 一并下发。
  - **绝不写盘**：只输出建议补丁文本。

### 2.4.9 板端采集服务 `pl_collector`

- **标识**：`pl_collector`，init service（`/system/etc/init/policyloop.cfg`）
- **类型**：系统服务（OpenHarmony init 托管）
- **目的**：让采集不再依赖 PC、`su`、`begetctl`，开机即在。
- **功能列表**：开机自启；运行在**自己的 enforcing 域** `u:r:pl_collector:s0`（无 permissive 兜底）；读 `/dev/kmsg` → 指纹去重 → 写应用沙箱内的 `live.jsonl`；响应控制台的“现读快照”请求。
- **处理**：域策略已 persist 到磁盘，重启仍生效（实测重启后 `up 0 min` 时服务已在域内采集，开机以来本域 denial = 0 条）。

### 2.4.10 板端控制台 HAP

- **标识**：`com.policyloop.console`
- **类型**：OpenHarmony 应用（HAP）
- **目的**：让“设备自己给自己出结论”这件事可见、可演示。
- **功能列表**：开关切换采集会话；每秒读一次 `live.jsonl` 并分析；显示分类 + 最小修复 + 评审/验证结论；系统通知；「载入当前快照」现读 `/dev/kmsg` 现存积压。
- **处理**：**引擎直接编进 `libplnative.so`**，索引编在 HAP 的 rawfile 里，因此**拔掉 USB 也能独立运行**，结果与宿主逐字段一致。

## 2.5 业务/实现流程说明

### 2.5.1 用例 1：单条 denial 的诊断流水线

**参与对象**：`Orchestrator`（状态机）→ 依次执行的七个 Agent（其中 `CrossLayerAgent` 只读）→ `PolicyIndex`。

**流程概览**：流水线的结构见 [2.3.2 图 2](#232-系统架构说明)（七 Agent 诊断流水线）。逐步展开为：

1. `LogAgent` 解析日志行，产出 `DenialRecord` 与指纹；
2. `PolicyAgent` 查索引：该访问当前**是否已被允许**？是否**撞 neverallow**？若是 ioctl，白名单里有没有这个命令号？
3. `SecurityAgent` 依据上一步的裁决做根因分类；
4. `RepairAgent` 生成补丁：普通 `allow` 只补缺失权限，`allowxperm` 只放行该命令号；
5. `ReviewerAgent` 安全评审：广度过宽、危险模式、与红线冲突 → REJECT；
6. `VerifyAgent` 在“补丁已应用”的索引副本上重查：denial 是否消除、有无回归、范围是否最小；
7. 若验证失败（或第 5 步被否决）→ 该案例归入「需人工」，**不回到第 4 步重算**。

**典型反例（说明守门的价值）**：设备上有 `render_service → dev_mali:chr_file { ioctl } ioctlcmd=0x8014` 的稳定复发 denial。策略**已经允许了 ioctl 大类**，缺的只是 `allowxperm` 白名单里的**一个命令号**（`XPERM_GAP`）。此时“看到 denial 就加 allow”的工具会建议加一条**已经存在**的规则（写了等于没写），而本作品给出的是：

```
allowxperm render_service dev_mali:chr_file ioctl { 0x8014 };
```

### 2.5.2 用例 2：整份日志的批量收敛

![图 3 批量收敛流程](figs/fig3-converge-flow.png)

**参与对象**：`converge` → `LogAgent`（去重）→ 快路判定 → 七 Agent 流水线 → 报告。

**实测（本机，2026-10-05 复跑）**：

```
$ python -m policy_loop.converge --log data/corpus/real_denials.txt \
      --policy data/raw/oh-selinux/sepolicy --json /tmp/converge.json
日志 5161 条 → 去重后 4911 个唯一案例（噪声/已允许 3261）。
其中 70 类可自动出最小权限补丁、1580 类需人工决策（占唯一案例约 32%）。
real 0m4.161s
```

根因分布：`DOMAIN_OR_LABEL_MISMATCH` 1,461 / `NOISE_OR_ALREADY_FIXED` 3,261 / `MISSING_RULE` 148 / `POTENTIAL_ESCALATION` 38 / `XPERM_GAP` 3。

**观察**：全量 5,161 条里 **零误报**进入自动项；`neverallow` 一律转人工。因此“需人工决策”的 1,580 类是工具**主动拒绝越权**的结果，其构成见 2.4.6 的归因表。

### 2.5.3 用例 3：板端实时闭环演示

![图 4 板端实时闭环](figs/fig4-board-runtime.png)

**参与对象**：控制台 HAP（应用沙箱）→ `pl_collector`（init service）→ 内核 audit → `/dev/kmsg`。

**动线**：拨一下开关 → 采集器开启新会话 → 它自己的那次 `fopen` 命中 enforcing 域被拒 → 内核 audit → `/dev/kmsg` → `pl_collector` 写入应用沙箱的 `live.jsonl` → HAP 每秒分析 → 横幅 + 系统通知。**唯一的人工动作是拨开关。**端到端时延约 1~2 秒，由两个 1 秒的轮询叠加而成：`pl_guard.sh` 每秒查一次 `guard.on`（`sleep 1`），HAP 侧每秒读一次 `live.jsonl`（`Index.ets` 的 `POLL_MS = 1000`）。拨动后最坏情况要等采集器下一轮才发现开关已开，再等应用下一轮才读到新行。

**这条 denial 是真的**：它由采集器自己在运行时被拒产生（`scontext=u:r:pl_collector:s0`、`permissive=0`、域为 enforcing），不是伪造的日志行。做成**运行时参数**（`--debug-log <path>`）而非编译期开关，是为了让交付的二进制只此一份，是否触发纯属**部署选择**。

**两个来源在界面上分开标注**：主按钮「载入当前快照」为**现读**，小字链为**预录样本**。区分二者的判据是“这份文件会变”：连按两次读到**不同的行数**（实测 801 / 1047 / 1070 / 1084 / 1092 行），且记录里的 `pid` 是本次开机才存在的进程号，`<开机微秒>` 与 `/proc/uptime` 对得上。

## 2.6 接口描述

### 2.6.1 调用接口（本系统使用到的周边接口）

| 接口 | 方向 | 说明 |
|---|---|---|
| `/dev/kmsg` | 读 | 内核 audit 记录镜像给 printk 的那份副本；采集服务的输入源 |
| 二进制策略 `policy.31` + `*_contexts` | 读 | 设备上 SELinux 的全部家当；只读，不修改 |
| 上游 `.te` 源码树 | 读 | 主机端构建 PLI 索引的输入（设备上没有） |
| 内核策略装载（CIL） | 写（部署期） | 安装脚本经 `checkpolicy`/`secilc` 把域策略编译并装载 |

### 2.6.2 提供接口（本系统对外提供的接口）

| 接口 | 形态 | 说明 |
|---|---|---|
| **PLI 索引** | 文本数据文件 | 构建期导出、随镜像下发的只读策略投影（含规则、类型、属性、`@hap` 段） |
| `denial_check` CLI | 命令行 | 固定 API：`--selftest` / `--index-info` / `--query` / `--dump-denials` / `--converge` / `--explain` / `--case`（`--explain` 可加 `--cross-layer`） |
| `--case` 逐条判定 | 行式 JSON/TSV | 一行一条已拆好字段的记录进，一行一个 JSON 判定出；**只输出建议，绝不写盘** |
| 收敛报告 | JSON | 字段与宿主引擎逐个相同，可直接 `diff` |
| Web UI | HTTP | `python -m webui.server` 提供 `/api/analyze` 与 Agent Trace 前端 |
| 板端控制台 | HAP | 开关 + 实时视图 + 快照现读 |

## 2.7 UI 设计

本作品有两处界面：

1. **主机端 Web UI**（`webui/server.py`，标准库 HTTP server）：单页展示 Agent Trace 动画与结果卡片，输入一条 denial 即可看到七个 Agent 的可视化过程。
2. **板端控制台 HAP**：顶部开关（切换采集会话）、状态行（`本次窗口 N 行 / 累计 M 个案例`）、案例卡片区（分类 / 最小修复 / `APPROVE · SUCCESS` / 来源标注）、主按钮「载入当前快照」与预录回放链。

**设计原则**：界面必须**如实区分数据来源**，工具造成的 denial 会明确标注「工具造成」，不冒充分析结果；“累计案例”与“本次窗口行数”分开计数，因为它们测的不是一回事。

![图 5 主机端 Web UI 的 Agent Trace 界面](screenshots/fig5-agent-trace.png)

![图 6 板端控制台拨开关后的实时结果卡片](screenshots/fig6-board-live-cards.png){width=13cm}

![图 7 板端「载入当前快照」后的状态行（已暂停实时刷新）](screenshots/fig7-board-snapshot.png){width=13cm}

## 2.8 实测与验证

> 本节为学校模板允许的自主增补章节（模板「2.4 模块功能描述」一节写明“可以根据需要增加或者删除”）。所有数字均可用附录 A 的命令复现。

**语料口径表**：下表四个数在下面各节反复出现，它们是同一批注释在四个筛选阶段的规模，彼此并不矛盾。

| 阶段 | 数量 | 定义 | 产出命令 |
|---|---|---|---|
| 注释条目 | **5,230** | 上游 `.te` 里 `# avc: denied …` 形式的注释总条数（分布在 378 个文件） | `policy_loop.eval.corpus` |
| golden denial | **5,161** | 其中能解析成 denial 记录、并配到一条修复规则的条数（归成 3,367 对） | `policy_loop.eval.extract` |
| 可评测 | **5,117** | 5,161 条里目标类可判的条数（44 条字段不全，跳过） | `policy_loop.eval.replay` |
| 唯一案例 | **4,911** | 按 `(主体, 目标, 类, 权限集)` 指纹去重后的条数，`converge` 的输入口径 | `policy_loop.converge` |

### 2.8.1 策略索引召回率（L2）

方法：把上游 `.te` 里真实发生过的 denial 拿去问“当前策略允许它吗”，测索引对属性闭包/宏展开/条件块的还原程度。

| 口径 | 样本 | coverage_all | 说明 |
|---|---|---|---|
| 全量 | 5,117 条可评测 | **97.19%** | 含邻接配对的错配噪声 |
| 质检后（trusted） | 3,522 条 | **99.80%** | 干净子集 |
| 质检 + service 占位解析 | 3,522 条 | **99.94%** | 未覆盖仅 2 条（均 `samgr_class`） |

**评测可信度质检**是本作品主动做的一步：`extract` 用“相邻配对”构造 golden，一条 `.te` 注释里的 denial 与紧挨着它的修复规则配成一对，这类启发式必然带错配。`trust` 逐对打可信标签，实测剔除 **1,213 对**（`mispair` 990、`attr_or_name_gap` 169、`unparseable` 42、`partial_fix` 12），保留 **2,154 对**；所有指标随后都在这个干净子集上重跑。分母换了，不是数字改小了。

> **两个口径不能相减**：**3,367 是「对」（pair）**，**3,522 是「条」（denial）**。一对修复规则可以同时修好几条 denial，所以 `3,367 − 990` 得到的 2,377 不对应任何一个样本量。正确的关系是：保留的 2,154 对承载 3,522 条 denial；其中 7 对 `service_gap` 原本因目标类无法解析而判不了，`replay --resolve` 之后未覆盖只剩 2 条（上表第三行）。

### 2.8.2 最小权限修复正确性（L3 留一法）

方法：剔除 golden 中该 denial 的真实修复规则，使它回到“未修复”状态，再跑 Agent 流水线并比对生成的补丁。

前置发现：真实上游策略**高度冗余**，剔除单条修复后，多数访问仍被其它规则覆盖。因此只有 **1,915 个 informative 样本**（剔除后确实变为不允许）能真正检验修复能力。

抽样 400（`seed=0`）回放结果：

| 场景 | 结果 |
|---|---|
| 应生成补丁（非 neverallow informative） | **179/179** 全部识别为 `MISSING_RULE` 并生成补丁 |
| 应拒绝放权（撞 neverallow） | **221/221** 全部正确拦截 → 转人工 |

在 179 个生成的补丁上：

| 指标 | 值 |
|---|---|
| `exact_min`（补丁 = 缺失权限，不多不少） | **100%** |
| `sufficient`（修复可消除 denial） | **100%** |
| `overbroad`（比缺失更多） | **0%** |
| `review_approve`（安全评审通过） | **100%** |
| `final_verified`（Verify SUCCESS） | **100%** |

与上游人工修复的对照：**59.2%（106/179）完全一致**；**39.1%（70/179）场景下本作品给出的权限比上游更小**。

余下 **3 条**（179 − 106 − 70）逐条看过：上游那条规则的 `(主体, 目标, 类)` 与本条 denial 根本不同，权限集也不相交。例如 `allow resource_schedule_service sa_net_policy_manager:samgr_class { get };` 被配给了一条 `sa_device_standby → resource_schedule_service` 的 denial；其中一条的目标类 `dit` 是上游注释里的转写笔误。这 3 条属于相邻配对的残差错配，既不构成“一致”也不构成“更小”，因此单列出来而不是塞进任何一档。

> **这条 100% 的边界**：`exact_min=100%` 是“补丁 = 剔除后缺失权限”这一构造下的**自洽性验证**，证明的是一致性而非独立金标准的绝对正确率（口径汇总见 2.9）。另外，“39% 比上游更窄”需注意：上游一条 `allow` 聚合修复多条 denial 是**合法**的，不能据此判上游过宽，该数字只表明“单条 denial 视角下本作品未放大权限”。

### 2.8.3 AI 放权的护栏量化

| 方案 | 样本 | 过宽率 | 撞 neverallow | 评审拦截 |
|---|---|---|---|---|
| 确定性规则（基线） | 60 | **0%**（60/60 精确最小） | 0 | — |
| 真实 LLM（明确最小权限指令，deepseek-v4-flash） | 54 有效补丁 | **0%** | 0 | 54/54 通过 |
| 未受约束的“AI 放权”（naive 档） | 120 | **100%** | — | **100% 被拦截并精修回最小** |

三档对照的结论落在数字上：不加约束的 LLM 起草，过宽率 **100%**；同一批样本经确定性守门，过宽率 **0%**，且 100% 的过宽补丁被拦回最小集。

### 2.8.4 设备端一致性（L4 五项门禁）

设备端组件与宿主机引擎必须给出同样的结论。五项门禁各自证明一件不同的事：

| # | 门禁 | 做法 | 结果 |
|---|---|---|---|
| 1 | `--selftest` | 内嵌固定向量（一份 11 条规则的小策略 + 26 行 denial），比对**由宿主 Python 生成并冻结**的 digest 表，不是拿 C++ 自己的输出当答案 | **PASS**：sha1 13 组 + converge 24 组 + explain 11 组，**0 失败**（2026-10-09 由 21 组扩到 24 组，并补上此前生成了却没人消费的 explain 表，见 3.2.2）|
| 2 | `--index-info` | 两端加载同一 PLI，比计数器 | `rules=21824 types=1267 attrs=49 skipped=524 hap_entries=17 hap_domains=13`，与宿主一致 |
| 3 | 报告差分 | 同一份语料两端各出完整 JSON 报告，比 sha256 | **逐字节相同** |
| 4 | 真机采样 | 真读本机 kmsg | `suppressed≈107` 非零，量化了 printk 丢帧 |
| 5 | 查询差分 | **27,912 条**查询，比整个输出体的 sha256 | **2,984,884 B 逐字节相同**（一次覆盖 5 个字段） |

**“2.98 MB 逐字节相同”说明了什么**：两端是**独立实现**（Python vs C++）喂完全相同的输入。本作品里真实存在的语义陷阱有四个：空 perms 是通配而非空集；xperm 命令是不透明字符串且大小写敏感；`permissive=2` 是三态不是布尔；通配规则命中时未知 perm 名要原样带上。只要错一个，哈希当场炸掉。两端的一致性由互相校验保证，不靠假设。

**性能**：查询路径原为**按对象类线性扫描**，设备 27,912 条查询 71.25 s（2.55 ms/条，含 297 ms 索引装载），宿主同工作量 40.85 s（1.46 ms/条）。

已改为**类型对倒排索引**（`_hit_index` / `pl_index.cpp::BuildCandidates`），并让 clone 继承父索引的 postings 使 ~10 ms 的建表**每棵索引树只做一次**（否则一次 converge 要重建 151 次）。

同机 A/B、两侧各用真实实现、输出逐字节相同：**设备查询路径 34×**（0.0987 → 0.0029 ms/条），**宿主判定路径 238×**（4,911 个唯一案例 8.842 s → 0.037 s，即 1.800 → 0.0076 ms/案）。板端 71.25 s 是旧代码在 RK3568 上的实测，按 34× 外推约 2 s，属**外推值**（口径见 2.9），上板后须复测。

### 2.8.5 板端实时闭环

冷启动实测：`up 0 min` 时服务已在域内采集，**开机以来本域 denial = 0 条**（采集器自身不产生越权）。拨开关后 1~2 秒内控制台给出分类与最小补丁。

### 2.8.6 补丁最小化与归因的实测

两组数字都可由**仓库内命令**复现（见附录 A）。

| 项 | 结果 |
|---|---|
| 补丁行数 | **69 → 54**（归并 10 组、省 15 行） |
| 归并方式 | 26 条折叠进**已有**规则（其中 3 条会波及属性成员）、25 条为新增 |
| 闭环反验 | 补丁前未解决 **70** → 套回后 **0**（`verify.closed = true`） |
| 归因完备性 | 1,580 个人工案例 → 归因 **1,580**、残留 **0**（退出码 0 即判据） |
| 真正待补权限 | owner=`DEVICE` 为 **0** |

**闭环反验多证了什么**：`converge` 的 Verify 只保证补丁能编译、且名字级
匹配上“应用后该 denial 消失”；`minimize` 走的是另一条路：把归并后的规则集**套回索引副本
重新查询**，并额外要求“套回**之前**这些案例确实没被解决”。缺了后半句，一个本来就已经
被允许的案例会被算成“补丁的功劳”，那个数字就没有意义。

**归因表怎么读**：1,580 条“转人工”里真正需要给设备补权限的是 **0** 条。
1,147 条是**语料的历史噪声**（口径见 2.9），342 条是工具侧要对齐的
（索引/版本），53 条是日志质量问题，38 条是架构决策（撞 neverallow 红线）。

> **两处命名不是两套结论**：2.4.6 归因表里的 `DEVICE`/`TOOL`/`LOG`/`HUMAN`/`NONE` 是**对外档位**，
> `DEVICE_LAGS_TREE`（上游树允许、板子不允许）与 `BOARD_SYMBOL_ABSENT`（板子策略里没有这个类型）
> 是 **`TOOL` 档内部的原因码**（`policy_loop/attribution.py` 里的 `RC_VERSION_DRIFT` / `RC_NO_SYMBOL`），
> 两者是包含关系。原因码的**数量**随所选上游树变化（换成本设备对应版本的源码树，
> 符号缺失会显著变多、版本差会变少）；跨树稳定的是 `DEVICE` 那一档为 0 这个结论。

### 2.8.7 工程自证

| 项 | 值 |
|---|---|
| 单元测试 | **372 通过 / 5 跳过 / 0 失败**（`python -m pytest -q` 收 377 项；`python -m unittest discover -s tests` 运行 341 项）。**两个解释器上结果相同**，差异全部来自环境依赖的记账：3.12 那个环境没装 pytest 与 python-docx，于是 `unittest discover` 收不到 pytest 风格的 `tests/test_attribution.py`、把导入失败记成 1 个 error，同时多出 1 个「缺 pandoc / python-docx」的 skip。CI 因此两个口径都跑 |
| 自检 | `python -m policy_loop.selfcheck` 全绿 |
| 第三方运行时依赖 | **0**（主机端纯标准库；设备端仅 libc/libc++/libm） |
| 稳定性门 | `tools/stability_gate.py`（逐轮全新子进程）。**同一负载、两个解释器**：3.12.14 → 60 轮 **0 崩溃**；3.13.13 → 60 轮 **6 崩溃（10%）** ⇒ 运行环境钉 **CPython 3.12**，原因与 gdb 回溯见 `docs/known-limitations.md` §7 |
| 文档生产门禁 | `tools/docgate.py`：文稿里每一句可机器验证的声明都在 `docs/facts.json` 登记，每次运行拿**文稿 ↔ 清单 ↔ 真实产物**三方对一遍。首跑即抓出 **3 处陈旧数字**（配图与两处正文仍写索引 21,790，而活树实测 21,824） |

#### 2.8.7.1 为什么还配一道「文档门禁」

交付物里有一类错误是**别的门都看不见的**：代码门禁验的是代码，评测门禁验的是指标，而
**配图上的字和正文里的数字是手写的**，改了代码，没有任何东西会因此变红。

2026-10 初的一次自查抓出：`docs/figs/` 的三张配图里，一张画着代码里**根本
不存在**的 Verify→Repair 回退回路，另外几张把 Agent 数与守门数各写少了一个。这些错误
**五天内无人发现**，靠的是人肉看图。

`docgate.py` 补的就是这个缺口，六个检查各自对一类“文稿说了谎”：

| 检查 | 抓什么 |
|---|---|
| `facts` | 登记过的每个数字，在文稿里抓到的值必须与真值一致；**反向**再扫一遍「N 条规则」这类句式，抓住**新写了但没人登记**的声明 |
| `mirrors` | 两份实现在两个进程里（主机 `converge.apply_guards` ↔ 板端 `pl_converge.cpp::ApplyGuards`）必须逐字说同一句话；图 2 上画的 Agent 数必须等于 `_PIPELINE` 的长度 |
| `figures` | 改了 `make_figs.py` 却没重新出图（按 git 谱系判，不看 mtime） |
| `placeholders` | 待填占位符只许变少不许变多，且带**到期日**，过期还留着就是红 |
| `docx` | `report.docx` 与 `report.md` 必须一致（派生物落后于源就是红） |
| `closure` | 门禁自证：每个检查都真的跑了、每条 fact 都至少有一个落点、报告引用的图都存在、没有孤儿 PNG |

三条设计原则决定了这门**会不会被绕过**：

- **按「口径」建模，不按数字。** 流水线里的拒绝点有 5 个、`apply_guards` 的守门有 6 个，
  两者数不同是**设计**而不是漂移（见 2.4.4 的注意段）；`eval-L4.md` 里的 21,790 是**旧索引**
  上的真机测量，文档已如实标注。门禁若按“全仓只许出现一个 21790”来判，就会在**正确内容**
  上误报，接着所有人学会加 `--skip`，门禁随之失效。
- **真值靠派生，不靠手写常量。** 守门分支数从 AST 数 `return` 语句得出，Agent 数从 `_PIPELINE`
  元组长得出，索引规模从活树实测得出，**不往引擎里加 `GUARD_COUNT = 6` 这类常量**。把权威从
  “代码实际有几个分支”挪到一个手写整数上，正是这次事故的成因。
- **门禁永不自动改文稿、永不自动改自己的期望值。** 并且 `--live` 必须真去跑探针：没有这一步，
  光改 `facts.json` 就能变绿，那是所有“清单式门禁”的通病。

这道门自己也进 CI，并且**给自己配了反控测试**：否则“门禁是绿的”和“门禁根本没在查”
是同一个观测结果：

| 落在哪 | 做什么 |
|---|---|
| `tests/test_docgate.py`（35 项） | 每一条判据都配一个“改坏了它得红”的反控，全部在临时树上跑 |
| `.github/workflows/ci.yml` | 三道作业：`unit`（selfcheck + unittest + pytest 两个口径）、`docgate`（含反控测试）与 `docx`（钉住 pandoc 3.1.11 / python-docx 1.2.0；工具链不符时记 SKIP 并打印两个版本，**不判红**，那是环境差异，不是文档缺陷） |
| `.github/workflows/docgate-live.yml` | 每周一 + 手动触发：稀疏克隆上游语料后跑 `--live --strict-env`。CI 上拿不到语料，活探针平时是跳过的；跳过久了清单就会被当成“已经验过”，这条就是不让它发生 |

反控里最要紧的一组是**「证明不了也得红」**：锚点被改写、AST 数出 0 个守门分支、板端源码
不在、环境缺失，分别记 FAIL 或**出声** SKIP，绝不记 OK；其中“锚点没了”报的是 `missing-site`
并在报文里给出重新登记的命令。“我再也证明不了这句话了”如果记成静默跳过，就等于让门禁
在重构之后安静失效：这次事故就是这样发生的。

另外两条分别堵两头的洞。**只改 `facts.json` 变不了绿**：`--live` 会拿真实产物把差异顶回来。
反控 `test_live_catches_manifest_edited_to_match_the_lie` 就是这一组：文稿与清单一起改，
默认检查全绿，`--live` 立刻报 4≠2。**门禁自己不写盘**：除显式 `--json` 外一个字节都不写，
反控逐文件比 sha256 快照。两条都是为了让“改不动代码就去改期望值”无法换个形式重演。

> 定位：这一节属于**工程规范**，不增加本作品的功能或创新度，只保证交付物上写的东西是真的。

## 2.9 口径与诚实性说明

前面各节的数字都带口径。这一节把它们集中在一处，其余位置只做交叉引用。四条口径限定的是**每个数字各自能证明什么、不能证明什么**。

**一、语料来自上游，不是本设备采集的。** 评测语料（5,230 条注释 / 5,161 条 denial）**每一行都以 `#` 开头**，其中 96.8% 逐字来自上游 `security_selinux_adapter` 的 `.te` 注释。那是上游开发者当年真实遇到、并写下修复的 denial 记录，但**不是任何一次设备采集**。因此 L2/L3 的数字说明的是“本工具在上游的真实历史 denial 上表现如何”，不能说明“本设备当下的策略缺口有多少”。后一个问题由 L4 真机与板端采集回答（2.4.9 / 2.8.5）。

**二、构造内自洽不等于独立金标准。** `exact_min=100%`、`sufficient=100%` 是“剔除某条规则 → 该访问变成不允许 → 工具把它补回来”这一构造下的**自洽性验证**：输入与答案出自同一棵策略树，证明的是内部一致性，不是绝对正确率。独立证据只有两条：与上游人工修复逐条对照（2.8.2 的 106 / 70 / 3），以及 L4 真机回归（2.8.4 / 2.8.5）。

**三、外推值一律标注。** 板端 71.25 s → 约 2 s 是按 34× 的倍数**外推**而非测量（2.8.4）；“39% 比上游更窄”只在单条 denial 的视角下成立（2.8.2）。

**四、未做但已证伪的，写证伪不写“已检查”。** `boolean` / `constrain` / `MLS` 三类根因在本平台原理上无从发生（`(boolean` 出现 0 次、`(constrain` 0 次、`(mlsconstrain` 仅 1 条且只约束 `(filesystem (relabelto))`），把它们列进“已检查项”不成立（2.4.6）。

**仍然存在的边界**（逐条对应 `docs/known-limitations.md`）：

| 边界 | 现状 |
|---|---|
| printk 限流丢帧 | 只**减少**不消除。`printk_ratelimit=0` 已进 init job，但 printk 环形缓冲仍有上限；无损通道是 audit netlink，本作品走 `/dev/kmsg`（3.2.4） |
| 索引须与目标策略树对齐 | 正文的 21,824 是**上游活树**（`sepolicy@29a2fc123dd1`）的实测；板端 HAP 内置的索引是 **19,800**，对齐的是板子那棵 5.0.3 树（`sepolicy@0878c56e3e41`）。**两个数不是同一棵树，不可互相套用** |
| 索引的红线覆盖面 | 上游活树上 `neverallow`/`neverallowxperm` 语句 **570 条**，索引只看见 **430 条**：**140 条**因书写形态未被三条正则接受（类位集合 59 / 权限位取反 50 / 目标位取反 9 / xperm 单值 1 / 条件宏嵌在集合里 21）。`skipped` 在两端都只报不查，**宿主↔设备的差分门禁原理上看不见**这一类。第二道防线补的正是这个洞：部署期把**板子对应源树**的 494 条红线翻译成 CIL 断言交 `secilc` 真执行，覆盖 **404/494 = 81.8%**（未注入的 90 条里 88 条是条件式红线）。两条防线各自的洞见 `docs/known-limitations.md` §2.1 / §3，答辩口径为「**两道，各自的洞如下**」 |
| 板子版本 ≠ 编译树版本 | 板子实测 `OpenHarmony-5.0.3.135`（API 15 / kernel 5.10.208 / enforcing）；设备端二进制由 `~/ohos_src`（6.1.0.31）交叉编译。两处口径不互相套用（`docs/known-limitations.md` §5） |
| `--cross-layer` 与 hap 计数器 | 宿主侧已测（2.4.8）；**尚未在真机上跑过**，属交付前必补项 |
| CPython 3.13 间歇 SIGSEGV | 已定位到解释器内部（`docs/known-limitations.md` §7）；处置为钉 CPython 3.12 + `tools/stability_gate.py`，附录 A 的命令一律用 `python3.12` |
| 占位符与截图 | 封面个人信息与 2.7 的三处界面截图待补；`docgate` 的 `placeholders` 检查对它们设了到期日，过期仍留即判红（2.8.7） |

---

# 3 其他

## 3.1 成员分工

| 角色 | 姓名 | 分工 |
|---|---|---|
| 队长 | 【待填】 | 总体方案、确定性内核与七 Agent 流水线、设备端组件、真机验证 |
| 队员 1 | 【待填】 | 评测体系与结果复核、文档与演示材料 |
| 队员 2 | 【待填】 | 【待填】 |

> 说明：本作品为系统底层作品，环境搭建门槛较高（OH 源码树 + 真机 + 交叉工具链）。队友入口文档为 `docs/onboarding.md`（纯新手教程体）。

## 3.2 困难与思考

这一节记七个**真实踩过、且改变了设计**的坑，它们是本作品若干架构决定的直接来源。

### 3.2.1 `neverallow` 不在二进制策略里：它决定了设备端的能力边界

最初的设想是“让设备自己从 `policy.31` 反推出全部策略语义”，做下去才知道**原理上不通**：`neverallow` 是编译期断言，`libsepol/src/expand.c:2736` 明确写着它不写进产出的策略；若强行展开进最终策略，代码会置 `unsupported_format = 1`，内核策略格式根本不接受。而上游活树上这类红线共 **570 条**，本作品的索引看得见其中 **430 条**（419 `neverallow` + 11 `neverallowxperm`；差额的形态与处置见 2.4.2 与 2.9）。拿不到红线，工具就退化成“看到 denial 就建议放权”，正是它最该避免的行为。

**结论**：索引必须由构建期从源码树导出、随镜像下发；设备端负责**用**策略语义，不负责**构建**它。这一条从“暂时没做”变成了“架构约束”。

### 3.2.2 差分语料证明不了覆盖率

设备端 `--selftest` 首跑就抓出 **2 个偏差**，而 **4,911 簇真实语料没抓到**：`default_service` / `sa_binder` 被判成“未知 token → 转人工”，宿主判 `auto_repairable`，根因是 C++ 的 `known` 集合漏了 `index.type_attrs`。真实语料抓不到它，是因为里面的 token 几乎都在某条规则里出现过：“声明了但没被任何规则引用”的类型只在人造小策略上出现。

**教训**：差分语料证明的是“常见路径一致”，证明不了“分支覆盖”。固定向量必须按**分支**专门设计（每个 category、每个 classification、六道 guard 各一组，外加缺 `scontext` / 缺 `tclass` / MLS 级 `tcontext` 三类畸形记录），最终取“固定向量 + 差分”两条腿走路。

2026-10-09 这条教训反向又应验一次：**差分覆盖得住，自检覆盖不住**。当时 converge 向量只有 21 组，六道守门里有 3 道（MLS 级目标 / 权限位含非权限名 / 空权限补丁）一个向量都没有；`--explain` 的自检向量表生成了却没人消费：设备自检根本不跑解释路径，而“`--explain` 也要走同一套守门”就是这项设计的核心。补齐后为 sha1 13 组 + converge 24 组 + explain 11 组；把 C++ 里 `--explain` 路径上的 `ApplyGuards` 调用删掉，explain 报错 6/11 而 converge 24/24 全绿，可见新表覆盖的是旧表结构上看不见的一条路径。

### 3.2.3 init 的 `caps` 是**整套替换**，而 DAC 失败不产生 AVC

采集服务为此做过一轮完整排查：**服务活着、`pidof` 有值、dmesg 干干净净、策略也正确**，但读不到数据。根因是 init 配置里的 `"caps": ["SYSLOG"]` 意为“**这个进程只有 CAP_SYSLOG**”，即整套替换而非追加（零初始化 + `capset`），于是连 uid 0 也失去 `CAP_DAC_OVERRIDE`，穿不过 0770 的应用沙箱目录；而 **DAC 失败根本不产生 AVC**，日志里因此什么都没有。

**定根手法**（不用重启）：把目标目录临时 `chmod 0777`，看它是否当场醒过来。**修法**落在 cfg（补 `DAC_OVERRIDE`），而不是放宽目录权限。由此得到一条判据：`(allow … (capability (dac_override)))` **不等于**进程真持有该能力，“日志干净”也不等于“没问题”。

### 3.2.4 printk 限流会**静默丢弃** denial

内核把 audit 记录镜像给 printk 的那份副本要过 `printk_ratelimit()`，板子默认**每 5 秒只放 10 条，超出的直接丢**：不进环形缓冲、不排队，于是 `dmesg` 和采集器**一起**看不见。它的现象是“**功能没触发**”而不是“出错了”，本作品一度就是这样误判的。

**两处修正**：init 配置加一个开机 job 写 `printk_ratelimit=0`，实测冷启动后零人工干预即为 `0`；**验收指标改用 `unique_cases`（指纹去重）而非 `total_denials`**，去重对丢帧天然免疫。

### 3.2.5 索引版本与策略树必须对齐

主机的索引与设备上要分析的策略若不来自同一棵树，工具会给出**自信的错答案**。实测过一次：用 master 分支的索引去判，结论是“标签不符”；换成与设备对齐的索引，结论变成 `XPERM_GAP`，并给出了上游后来**真的加上**的那行 `allowxperm … { 0x8014 };`。

索引不是“越新越好”，而要**与目标策略树对齐**；同时板子自带的 denial 与工具自己造成的 denial 必须分开统计，否则“唯一案例数”站不住。实测一次连续调试里，**82% 的 denial 是 `hdc` 敲出来的**，这些都会被工具如实标注为「工具造成」。

### 3.2.6 一个“收益与预期相反”的改动

占位符逻辑目标解析接进流水线后，实测差集为 **4 个簇**，而 `auto_patch_lines` **逐字节不变**，4 条本来是 `POTENTIAL_ESCALATION` 的告警变成了噪声：占位符上碰上了 neverallow 的**假告警**，解析后红线消失，且策略早已允许。

这一版的收益是“消灭了 4 个假安全告警”，而不是“多出自动补丁”，与动手前的预测相反。安全工具的“改进”未必体现为“多做”，也可能是“少误报”，指标该按这个口径设计。

### 3.2.7 部署形态与运行形态是两件事

板端采集最初是 `su` 里跑的脚本，演示时也看不出问题，但它的讲法经不起一个问题：**“你重启一下试试？”**

为此把采集器做成了正规 init service：**开机自启、自己的 enforcing 域、不需要 PC / 不需要 `su` / 不需要 `begetctl`**。这一步之后，讲法才从“部署依赖 PC”变成“**部署依赖 PC ≠ 运行依赖 PC**”。配套的坑是：把域策略装进内存与 persist 到磁盘是两件事，任何一次普通安装都可能把磁盘换回原版，冷启动验证因此必须作为交付前的固定动作。

## 3.3 不足与未来工作

**交付前必补的三项**

- `--cross-layer` 与 hap 计数器只有宿主侧结果（2.4.8），尚未在任何真机上跑过。处置与判据见 2.9 的处置一览。
- 板端控制台 HAP 不会开机自启，需要手动点一次图标；该限制写进了设备自述文档，没有做自启适配。
- 封面信息与三张界面截图仍是占位状态（占位符 9 处、截图标记 1 处），由 `placeholders` 门禁盯着，到期未清即判红。

**口径上的边界**（与 2.9 同一套说法，这里只列条目）

- L3 的留一法评测建立在抽样 400 例中的 179 个可生成样本上，不等于全量 1,915 个 informative 样本的结论。
- 宿主索引与板端策略树不同源：板子是 5.0.3.135，宿主索引取自 6.1 编译树，两处的数字不互相套用。
- 语料是上游 `.te` 注释而不是设备采集，它说明的是本工具在真实历史 denial 上的表现，不是线上分布的抽样估计。

**下一步**

- 改走 audit netlink 取无损通道，摆脱 printk 限流。现在只做到把限流关掉，环形缓冲的上限仍在。
- 把宿主索引降到与板子一致的 5.0.3 @ `0878c56e3` 后重跑 L2，量化版本漂移对召回率的影响。
- 板端实时闭环目前只有“捕获”这一半不需要 PC，读屏与点屏仍要 `hdc`；下一步做成板内触发。

## 3.4 参考

### 3.4.1 相关工作

| # | 参考 | 说明 |
|---|---|---|
| [1] | `audit2allow` / `audit2why`（SELinux userspace） | 最直接的同类工具，POSIX SELinux 上的事实标准。本作品对其做了完整对照调研，见下 |
| [2] | OpenHarmony `security_selinux_adapter` | 上游策略源码树与 `sehap_contexts` 等上下文文件，本作品的语料与索引来源 |
| [3] | OpenHarmony `third_party/selinux`（`libsepol` / `checkpolicy` / `secilc`） | 策略编译与断言检查；`neverallow` 编译期语义的依据（`expand.c:2736`） |

**与 `audit2allow` 的对照（全部数字本机实测，报告见 `docs/related-work-audit2allow.md`）**

把 golden 集 5,161 条去注释后喂给它，并对同一份真实 `policy.31` 输出：

| 指标 | audit2allow | PolicyLoop |
|---|---|---|
| 输出规则数 | **2,833 条** | **69 条补丁**（根因归并后 **54 条**，见 2.4.5） |
| 其中当前策略本来就允许的（no-op） | **2,687 条（94.8%）** | 0（有守门拦截） |
| 撞 neverallow | 34 条 | 0（一律转人工） |
| 引用不存在的类名 | 4 条 | 0（转人工） |

其中 4 条不存在的类名（`samger_class` / `samar_class` ×2 / `dit`）**全部是 OH 上游 `.te` 注释里的转写笔误**，逐条给了出处。

对照调研按三部分写：**A 目标不同不该比** / **B 它确实弱的地方** / **C 它确实比我们强的地方**。C 部分如实列出：`audit2why` 的 BOOLEAN/CONSTRAINT/RBAC/BOUNDS 诊断、`-M` 打通到 `semodule -i`、`--dontaudit`、xperm 支持、20 年成熟度，这些都是本作品没有、也不打算重复造的东西。

### 3.4.2 引用

**[1] SELinux userspace 的 `audit2allow` / `audit2why`**：对照对象

- 仓库 <https://github.com/SELinuxProject/selinux>，位于 `policycoreutils`
- 本机版本：SELinux userspace `3.8.1`（Ubuntu `policycoreutils-python-utils 3.8.1-2`，含 `python3-sepolgen`）；对照入口 `/usr/bin/audit2allow`
- 本作品的对照实验、逐条出处与“它确实比我们强的地方”清单见 `docs/related-work-audit2allow.md`

**[2] OpenHarmony 安全子系统 `security_selinux_adapter`**：语料与索引来源

- 仓库 <https://gitee.com/openharmony/security_selinux_adapter>
- 语料树 `sepolicy@29a2fc123dd1`：正文 2.4.2 报的索引规模出自此树
- 板子对齐树 `OpenHarmony-5.0.3-Release` @ `0878c56e3e41`：板端内置索引 19,800 条出自此树。两棵树的数字不可互相套用，见 2.9

**[3] OpenHarmony `third_party/selinux`**：策略工具链

- 上游同属 <https://github.com/SELinuxProject/selinux>
- `libsepol/src/expand.c:2736` 写明 `neverallow` 不写进产出的二进制策略，这是 3.2.1 中设备端能力边界的直接依据
- `secilc/secilc` 与 `checkpolicy/checkpolicy` 是宿主侧工具，部署期用于 CIL → `policy.31` 的编译与反编译回验；调用见 `device/selinux_policy/build_policy.sh`，参数为 `-b -M -C -c 31`

**[4] AVC 审计记录与 printk 镜像路径**

- Linux 内核（板子为 `5.10.208`）`kernel/audit.c::kauditd_printk_skb` 是 audit 记录镜像给 printk 的那条路
- 该路径受 `printk_ratelimit()` 约束而静默丢弃记录；实测与本作品的应对见 3.2.4 与 `docs/known-limitations.md`

**[5] CPython 3.13 上的间歇性 SIGSEGV**：运行环境口径

- 本机版本：`3.13.13` 可复现（1%–10% 概率），`3.12.14` 同机同命令零崩
- 一手复现数字与 gdb 回溯见 `docs/known-limitations.md` §7，崩溃点在 `_PyEval_EvalFrameDefault` 内部
- 处置为运行环境钉 CPython 3.12，并配 `tools/stability_gate.py` 复核；附录 A 的命令一律用 `python3.12`

---

# 附录 A · 复现命令

> **运行环境：CPython 3.12**（下面的命令请用 `python3.12` 代替 `python`）。
> CPython 3.13 上核心路径有约 1%–10% 概率的解释器级间歇 SIGSEGV，
> 崩溃点在 `_PyEval_EvalFrameDefault` 内部、**与本作品代码无关**，
> 已定位并附 gdb 回溯于 `docs/known-limitations.md` §7；
> 门禁工具 `tools/stability_gate.py` 可当场复现这个差异（3.12 零崩 / 3.13 崩）。

```bash
# ── 自检与单测 ────────────────────────────────────────────────
python3.12 -m policy_loop.selfcheck      # 环境 + 模块 + 冒烟
python3.12 -m unittest discover -s tests # 341 项，0 失败
python3 -m pytest -q                     # 372 通过 / 5 跳过（pytest 只装在 3.13 上；3.12 请用上面那行 unittest）
python3.12 tools/stability_gate.py --runs 60   # 稳定性门：零崩溃 = 通过
python3.12 tools/docgate.py --live            # 文档生产门禁：文稿 ↔ 清单 ↔ 真实产物

# ── 拉取上游语料（一次性）────────────────────────────────────
git clone --depth 1 --sparse \
    https://gitee.com/openharmony/security_selinux_adapter.git data/raw/oh-selinux
cd data/raw/oh-selinux && git sparse-checkout set sepolicy && cd -
# 注：正文的索引规模出自 sepolicy@29a2fc123dd1（见 3.4.2），
#     HEAD 可能已前移；要逐字复现需 `git checkout 29a2fc123dd1`。

# ── L2 评测基线（就地覆盖 data/reports/ 下的同名产物）────────
python -m policy_loop.eval.corpus                       # 语料规模
python -m policy_loop.eval.extract                      # golden 抽取（3,367 对）
python -m policy_loop.eval.replay                       # 全量回放（97.19%）
python -m policy_loop.eval.trust                        # 可信度质检
python -m policy_loop.eval.replay --golden data/eval/golden.trusted.jsonl \
    --out data/reports/replay-report.trusted.json                        # 99.80%
python -m policy_loop.eval.replay --golden data/eval/golden.trusted.jsonl \
    --resolve --out data/reports/replay-report.trusted-resolved.json     # 99.94%

# ── L3 流水线评测 ──────────────────────────────────────────────
python -m policy_loop.eval.agent_eval --limit 400 --seed 0
python -m policy_loop.eval.agent_llm_eval --limit 60 --seed 0

# ── 批量收敛（图 3 的数字来源）───────────────────────────────
python -m policy_loop.converge \
    --log data/corpus/real_denials.txt \
    --policy data/raw/oh-selinux/sepolicy \
    --json /tmp/converge.json --md /tmp/converge.md
# 本节数字对应的已入库产物是 data/reports/converge-full.json

# ── 补丁最小化 + 闭环反验（2.8.6 的数字来源）─────────────────
# 注意：data/reports/converge-permissive.json 是刻意冻结的历史批次，
# 不要就地重生成；一律把产物写到 /tmp。
python -m policy_loop.minimize \
    --log data/corpus/real_denials.txt \
    --policy data/raw/oh-selinux/sepolicy \
    --json /tmp/min.json --md /tmp/min.md --cil /tmp/min.cil
# 期望：补丁 69 行 → 54 条根因规则；闭环反验 70 未解决 → 0

# ── 「需人工」的根因归因（2.8.6 的数字来源）──────────────────
python -m policy_loop.attribution \
    --log data/corpus/real_denials.txt \
    --policy data/raw/oh-selinux/sepolicy \
    --json /tmp/attr.json --md /tmp/attr.md
# 期望：1580 个人工案例 → 归因 1580、残留 0（退出码 0 即判据）

# ── 设备端（L4）──────────────────────────────────────────────
python -m policy_loop.export --policy data/raw/oh-selinux/sepolicy \
    --out build/pli/ohos-rk3568.pli                       # 导出 PLI 索引
./device/install.sh                                       # 铺回 OH 源码树
"$OH_SRC/build.sh" --product-name rk3568 \
    --build-target //base/security/selinux_adapter:denial_check
denial_check --selftest                                   # 设备上：五项门禁之一

# ── 板端采集服务 ─────────────────────────────────────────────
cd device/selinux_policy
bash install_service.sh status     # 四组判据自检
bash install_service.sh            # 安装（内存策略 + 二进制 + cfg + 拉起）
bash install_service.sh demo       # 摆放演示起点
```

> 注：`$OH_SRC` 指 OpenHarmony 源码树根目录，设备端交叉编译需要该源码树及其产品的编译产物；`hdc` 位于 SDK 的 `toolchains` 包中（Ver 3.2.0b）。

