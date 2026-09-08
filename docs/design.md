# PolicyLoop 方案与设计

> 公开版设计文档。队内执行细节/进度见 [`docs/onboarding.md`](onboarding.md)（成员入口）。

## 问题

OpenHarmony 里应用/服务访问系统资源须过 SELinux 门禁。访问被拒时内核记录一条 `avc: denied` 日志。这类日志开发者普遍**读不懂、也不知道该在哪补规则**，常见对策是把门禁开成"只记不拦"（permissive）——系统长期处于无实际拦截状态。

PolicyLoop 把这条日志链自动化：**读懂 → 定位根因 → 生成最小权限修复 → 评审/验证 → 支撑把设备从 permissive 收紧到 enforcing**。

## 关键设计原则

1. **确定性内核优先，LLM 可插拔、可断网、可证明**
   解析 / 策略索引 / 根因分类 / 最小补丁 / 评审 / 验证全部是纯规则、纯标准库实现；每个判定都能回溯到一条被索引的 `.te` 规则。LLM 只在配置了 key 时做"解释/候选"增强，安全决策始终由规则护栏把关——AI 的越权倾向会被 Reviewer 拦截并确定性精修回最小权限（已有 LLM 对比评测实证）。
2. **绝不自动写盘**：工具只产出"建议补丁 + 落点提示（system/vendor/public）"，是否写 `.te`、重建、上 enforcing 由人/真机流程决定。
3. **"先仿真、后真机"**：先用上游真实策略语料做数据仿真与量化评测，L4 再上 DAYU200 真机 enforcing 回归拿最硬证据。

## 架构（L0–L4）

| 端 | 内容 |
|---|---|
| 主机端（重） | `policy_loop/`：denial 解析 + `.te` 策略索引 + 6-Agent 诊断闭环 + 批量收敛 + 评测；`webui/` 单页演示 |
| 设备端（轻） | L4 真机采集/回归（当前未开始；队长侧 DAYU200 + 串口） |

### 确定性核心

- `policy_loop/denial/parser.py`：OpenHarmony 风格 AVC denial → `DenialRecord`。
  支持 OH 专有形态：`parameter_service`（`parameter=`）、`samgr_class`/`hdf_devmgr_class`（`service=`/`sid=`）、`ioctlcmd=0x…`、`permissive=0|1`、`audit:`/`avc_audit_slow:` 前缀、续行、多事件切分。
- `policy_loop/policy/index.py`：`.te` 策略索引。
  支持 `allow`/`allowxperm`/`neverallow`/`neverallowxperm`、attribute 闭包（含 `typeattribute` 空格/逗号两种写法）、`binder_call()` 宏展开、条件块（`debug_only()` 等）、ioctl 白名单/xperm 语义。查询：`has_access`（请求权限是否全部被授予）、`neverallow_rules`（红线）、`ioctl_allowed`（白名单判定）。

### 诊断闭环（`policy_loop/agents/`）

单条 denial 走 **Log → Policy → Security → Repair → Review → Verify** 六步（`Orchestrator` 严格状态机，`SecurityCase` 记录全程 Agent Trace）：

| Agent | 职责 |
|---|---|
| LogAgent | 解析、指纹去重 |
| PolicyAgent | 查索引：允许？撞 neverallow？ioctl 白名单？ |
| SecurityAgent | 根因分类：`MISSING_RULE` / `XPERM_GAP` / `POTENTIAL_ESCALATION` / `NOISE_OR_ALREADY_FIXED` / `DOMAIN_OR_LABEL_MISMATCH`；出候选修复与推荐 |
| RepairAgent | 把推荐转成最小权限补丁（普通 allow 只补缺失权限 / allowxperm 只放行该命令号） |
| ReviewerAgent | 安全护栏：危险模式、越权放行、通配、neverallow 冲突 → REJECT/APPROVE |
| VerifyAgent | 在"补丁已应用"的索引副本上重查：消除、无回归、范围最小 → SUCCESS/FAILED/SECURITY_REGRESSION |

### 批量收敛（本轮新增）

`policy_loop/converge.py`：输入整份 denial 日志 → 按指纹聚类去重 → 每唯一案例跑一遍闭环 → 输出**收敛报告**（去重比、各根因分布、可自动最小修复的补丁集合、需人工项、enforcing 就绪度）。让"permissive → enforcing"从"逐条人工看"变成"一条命令出一份清单"。

## 评测方法论（可量化、可复现）

- **自证 golden 语料**：上游 `.te` 里 `# avc: denied …` 注释与其紧邻修复规则，按双向邻接配成 `(denial → 真实修复)` 对（`eval/extract.py`），产出 `data/eval/golden.jsonl`（3,367 对）。
- **回放基线**（`eval/replay.py`）：全量索引下，这些真实 denial 是否已被策略允许 —— 测量索引/属性/宏处理的**召回**。
- **留一法回归**（`eval/agent_eval.py`）：剔除某 denial 的修复规则使其回到"未修复"，再跑 Agent 闭环，比对生成补丁 vs 缺失权限 —— 测**修复正确性**。永不替 denial 造标签；剔除后仍被其它规则覆盖的记为"冗余修复"，不误导指标。
- **LLM 护栏量化**（`eval/agent_llm_eval.py`）：同批 denial 上，让 LLM 自由起草补丁，测越权率与 Reviewer 拦截/精修率。
- **可信度质检（本轮新增）**：`eval/trust.py` 校验每条 golden 对"规则与 denial 是否真的相关"，过滤邻接配对的错配噪声，产出 trusted 口径指标。

> 口径诚实性：`exact_min=100%` 是"补丁=剔除后缺失权限"构造下的自洽性验证，证明一致性而非独立金标准的绝对正确率；真正的独立证据是 L4 真机 enforcing 回归。

## 实测基线（2026-09，真实上游 `security_selinux_adapter` 语料）

- 语料：1,315 个 `.te`、索引 2.1 万+ 条规则、5,161 条真实 denial。
- 回放 coverage_all 97.2%（trusted 口径见 eval-trust 文档）。
- Agent 留一（1,915 informative）：识别需修复/拒绝越权 100%、最小权限 100%、59% 与上游人工修复一致、39% 更收敛、neverallow 一律拒自动放权。
- LLM 对比（真实模型 54 样本）：最小权限指令 + 规则护栏 → 100% 最小权限、0 越权；未受约束 AI 放权 100% 过宽且被护栏 100% 拦截精修。

## 路线（L0–L4）

| 级 | 内容 | 状态 |
|---|---|---|
| L0 | 仓库骨架 + selfcheck + CI | ✅ |
| L1 | Parser + Policy Index（数据仿真） | ✅ |
| L2 | 真实语料评测基线（coverage 97.2%） | ✅ |
| L3 | Multi-Agent 闭环 + 最小权限 patch + Verify（规则版，LLM 增强可接） | ✅ |
| L3+ | 批量收敛工作流 + golden 可信度质检 | 🚧 本轮 |
| L4 | DAYU200 真机验证（补丁构建 + enforcing 回归） | 未开始 |
