# PolicyLoop

面向 **OpenHarmony** 安全子系统（SELinux/访问控制）的 denial 诊断与**最小权限**修复 Agent —— L1（确定性核心）、L2（真实语料评测基线）、L3（确定性多 Agent 分解：分工判定 + 否决权 + 否决一律转人工）与 L3+ 批量突破（收敛工作流 / 评测可信度质检 / service 覆盖）均已落地。

> 完整方案与设计见 [`docs/design.md`](docs/design.md)（含"先仿真、后真机"执行策略）。
> 三件突破的验收文档：批量收敛 [`docs/eval-converge.md`](docs/eval-converge.md)、评测可信度质检 [`docs/eval-trust.md`](docs/eval-trust.md)。
> 已知边界与未建模路径（含逐条 file:line 出处与量化）：[`docs/known-limitations.md`](docs/known-limitations.md)。

## 现状（2026-10-09）

**无第三方运行时依赖、可断网演示。** 已实现：

- `policy_loop.denial.parser`：OpenHarmony 风格 AVC denial 解析器（含共享去重指纹）
- `policy_loop.policy.index`：`.te` 策略索引（allow/allowxperm/neverallow + attribute 闭包 + 宏展开 + ioctl xperm 判定 + **service 占位逻辑解析** `resolve_logical_target`）
- `policy_loop.agents.*`：**L3 确定性 Agent 流水线**（7 个 Agent：Log→Policy→Security→CrossLayer→Repair→Reviewer→Verify + Orchestrator Agent Trace）。各 Agent 独立判据、共享一份可审计的 `SecurityCase`，**同一条 denial 每次跑出同一个结论**；Reviewer 可否决过宽/neverallow，Verify 可判 `SECURITY_REGRESSION`，**否决不允许被自动绕过 —— 一律转人工**
- `policy_loop.converge`：**批量收敛**（整份 denial 日志 → 去重 → 逐案判定 → 最小修复清单/需人工清单/就绪度，六道守门防误报）
- `policy_loop.explain`：单条 denial 诊断（与 `converge` **共用同一份守门实现**，两个入口对同一条记录给出同一句话）
- `policy_loop.minimize`：**根因聚类 + 闭环反验 + 爆炸半径**（逐案补丁 → 最小根因规则集，并把规则集套回索引**证明它仍然关上每一个案例**）
- `policy_loop.attribution`：**策略级根因归因**（`converge` 判"转人工"的 1,580 条，逐条问出根因与**该谁修**）
- `policy_loop.eval.*`：L2 评测工具（corpus / extract / replay / **trust 质检** / agent_eval）
- `policy_loop.selfcheck`：环境 + 模块 + 冒烟自检

**L2 实测基线**（真实上游 `security_selinux_adapter` 语料，1315 个 `.te`）：
- 索引 21,790 条规则；抽取 **3,367 对 denial→修复 golden、5,161 条真实 denial**
- 回放 **coverage_all 97.2%**（5,117 条可评测中 4,973 条判定正确），见 [`docs/eval-L2.md`](docs/eval-L2.md)
- **质检后（trusted 子集 2,154 对/3,522 条）coverage_all 99.8%**；再做 service 占位逻辑解析后 **99.94%、未覆盖仅 2**（见 [`docs/eval-trust.md`](docs/eval-trust.md)）

**L3+ 批量突破**（feature 分支 `feat/engine-converge`，2026-09）：
- **批量收敛**：permissive 攒下的整份 `avc: denied` 日志 → 去重 + 快路判定 + Agent 流水线（真实语料 4,911 个唯一案中 151 个进 Agent，其余由确定性快路直接三分） → 可自动最小修复 / 需人工 / 噪声三分，含六道守门兜住"照抄可疑日志"式误修复。真实语料三批验证：真缺口批 134 唯一案 38 个可自动最小补丁全过守门；全量 5,161 条 **零误报**进自动项、neverallow 一律转人工（[`docs/eval-converge.md`](docs/eval-converge.md)）
- **评测可信度质检**：extract 的"相邻配对"里有 29.4% 是错配噪声（一条规则被配去修无关 denial），trust 逐对标注 trusted/mispair/…，指标都在干净子集上重跑（`golden.trusted.jsonl`）
- **service 覆盖**：`default_service`/`default_hdf_service` 占位目标 → `resolve_logical_target` 按具名服务/自注册 `add` 确定性映射到 `sa_*`/`hdf_*` 具体类型
- **补丁最小化 + 闭环反验**：逐案补丁坍缩到根因 ⇒ **69 行 → 54 条根因规则**，与原补丁的原子授权逐条等价；再把规则集套回索引重新查询，断言"补丁前未解决的现在全解决**且**补丁前已解决的不许算作它解决的" ⇒ **70 → 0**。`converge` 只断言补丁**能编译**，这里断言它**管用**
- **策略级根因归因**：`converge` 有 1,580 条只会说"转人工"，现在逐条问出根因与 owner（TOOL/DEVICE/HUMAN/LOG/NONE），判据全是可证伪的查询。**反直觉结论：真正要给设备补权限的是 0 条**——多数是当时规则不存在、后来被上游补上了
- **查询性能**：查询路径从按对象类线性扫描（`file` 一个类 7,400 条）换成类型对倒排索引，宿主与设备两侧同改、输出逐字节相同 ⇒ 设备查询路径 **34×**、宿主判定路径 **238×**

**L3 Agent 流水线**：一条 denial → 人话解释 + 最小权限补丁 + 安全评审 + 验证（严格状态机，规则版、断网可跑；LLM 可插拔且**默认关闭**，主流程不依赖网络或 API key）。
- golden 留一回归（1915 个真实"单规则可解释"denial 上）：**识别需修复/拒绝越权 100%、最小权限 100%、59% 与上游人工修复一致、39% 比上游更收敛、neverallow 一律拒放权**（[`docs/eval-agent-L3.md`](docs/eval-agent-L3.md)）
- LLM 对比（真模型 deepseek-v4-flash，54 个真实样本）：**最小权限指令 + 规则护栏 → 100% 最小权限、0 越权**；而"未受约束 AI 放权"100% 过宽被护栏 100% 拦截并精修（[`docs/eval-llm-guardrail.md`](docs/eval-llm-guardrail.md)）

## 快速开始

```bash
# 自检（环境/模块/冒烟样例，全绿才算就绪）
python -m policy_loop.selfcheck

# 单测（标准库 unittest，无需安装额外依赖）
python -m unittest discover -s tests -v

# L3 Multi-Agent 演示（内置 3 个场景 + Agent Trace）
python -m policy_loop.agents.demo

# Web UI（Agent Trace 动画 + 结果卡片；浏览器打开 http://127.0.0.1:8765）
python -m webui.server --port 8765
# 默认加载上游全量语料（data/raw/oh-selinux）；无则用 fixtures 小策略

# 解析任意一条 denial
python -m policy_loop.agents.demo --denial "<avc: denied ...>"

# 批量收敛：整份 denial 日志 → 收敛报告（可自动/需人工/噪声 + 就绪度）
python -m policy_loop.converge --log <denial日志> --policy data/raw/oh-selinux/sepolicy \
                               --json data/reports/converge.json --md converge.md

# 落地桥：收敛报告 → 按板子实际策略过六道门 → CIL → secilc → policy.31（+ 编译回验）
python tools/apply_converge.py --report data/reports/converge-full.json
python tools/apply_converge.py --report data/reports/converge-full.json --no-build  # 只判定

# golden 质检：给 3,367 对 denial→修复 逐对打可信标签，产出干净子集
python -m policy_loop.eval.trust
```

命令行解析演示：

```bash
python -m policy_loop.denial.parser --text "avc: denied { set } for parameter=persist.account.login_name_max pid=2208 uid=3058 gid=3058 scontext=u:r:accountmgr:s0 tcontext=u:object_r:persist_param:s0 tclass=parameter_service permissive=0"
```

## 目录结构

```text
policy_loop/
  denial/parser.py    # denial 解析（确定性，无 LLM）
  policy/index.py     # .te 策略索引与查询（allow/neverallow/allowxperm + attribute/宏）
  agents/             # L3：SecurityCase + Orchestrator + 7 Agents + 可插拔 LLM Provider（默认关闭）
  eval/               # L2/L3 评测：corpus / extract / replay / trust(质检) / agent_eval(留一)
  converge.py         # 批量收敛：整份日志 → 去重收敛报告（含补丁守门）
  selfcheck.py        # 自检入口
tools/
  apply_converge.py   # 落地桥：收敛报告 → 板子策略过门 → CIL → secilc 编译 → 回验
webui/                # Web UI：stdlib HTTP server + /api/analyze + Agent Trace 前端
data/
  fixtures/           # 测试/演示样例（含上游真实格式 denial）
  eval/golden.jsonl   # 自证 denial→修复 评测集（3,367 对，已入库）
  eval/golden.trusted.jsonl  # 质检后干净子集（2,154 对，含 pair_kind 标注）
  reports/            # corpus/replay/trust/agent-eval/converge 评测报告（已入库）
  raw/                # 上游语料（稀疏克隆，不入库，需自行拉取）
docs/                 # 方案与路线文档
tests/                # 单测（306 个，`python -m unittest discover -s tests`，0 失败）
```

## L2/L3 评测命令

```bash
# 先拉上游语料（一次性；默认在 data/raw/oh-selinux）
git clone --depth 1 --sparse https://gitee.com/openharmony/security_selinux_adapter.git data/raw/oh-selinux
# （然后）cd data/raw/oh-selinux && git sparse-checkout set sepolicy

python -m policy_loop.eval.corpus          # 语料规模统计
python -m policy_loop.eval.extract         # golden 评测集抽取
python -m policy_loop.eval.replay          # 索引覆盖回放（coverage 97.2%，全量）
python -m policy_loop.eval.trust           # 质检：golden 逐对打可信标签 → golden.trusted.jsonl
python -m policy_loop.eval.replay --golden data/eval/golden.trusted.jsonl \
                                            --out data/reports/replay-report.trusted.json
                                           # trusted 子集回放（coverage 99.8%）
python -m policy_loop.eval.replay --golden data/eval/golden.trusted.jsonl --resolve \
                                            --out data/reports/replay-report.trusted-resolved.json
                                           # 再做 service 占位逻辑解析（coverage 99.94%）
python -m policy_loop.eval.agent_eval --golden data/eval/golden.jsonl \
                                            --limit 400 --seed 0
                                           # L3 Agent 留一回归（全量；可换 --golden ...trusted）
python -m policy_loop.eval.agent_llm_eval --limit 120 --mode greedy
                                           # LLM 自由补丁 vs 规则护栏对比
```

## 接入真实 LLM（可选）

复制 `.env.example` 为 `.env` 并填入 key（`.env` 已在 `.gitignore`，密钥不会入库、不进对话）：

```text
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.deepseek.com/v1   # OpenAI/DeepSeek/Ollama 等兼容端点
OPENAI_MODEL=deepseek-chat
```

用途：
- `agent_llm_eval`：让真实 LLM 直接起草修复补丁，量化其过宽/漏修率，并验证 ReviewerAgent 护栏能拦截并精修回最小权限；
- 未配置 key 时自动回退到可复现的 **naive-LLM 档位**（`--mode moderate|greedy`），评测断网可跑。
- 主链路始终确定性优先；LLM 只做增强（解释/候选），安全决策由规则护栏把关。

## Roadmap（仿真 → 真机）

| 级 | 内容 | 状态 |
|---|---|---|
| L0 | 仓库骨架 + selfcheck + CI | ✅ |
| L1 | Parser + Policy Index（数据仿真） | ✅ |
| L2 | 真实语料评测基线（coverage 97.2%） | ✅ |
| L3 | 确定性 Agent 流水线（分工判定 + 否决权 + 否决转人工） + 最小权限 patch + Verify | ✅（规则版；LLM 可插拔，默认关闭） |
| L3+ | 批量收敛工作流（converge + 补丁守门） | ✅ |
| L3+ | 评测可信度质检（trust + trusted 子集指标） | ✅ |
| L3+ | service 占位逻辑解析（resolve_logical_target） | ✅ |
| L3+ | 补丁最小化 + 闭环反验 + 爆炸半径（`policy_loop.minimize`） | ✅ |
| L3+ | 策略级根因归因（`policy_loop.attribution`） | ✅ |
| L3+ | 查询路径类型对倒排索引（宿主 + 设备，34× / 238×） | ✅ |
| L3+ | `--explain` 与 `converge` 共用同一份六道守门（一份实现两个调用点） | ✅ |
| L4 | 设备端 C++ 组件 `denial_check`（DAYU200/RK3568 真机） | ✅ |
| L4 | 设备端固定 API 执行层（`--case` 逐条判定 + 六道守门） | ✅ |
| L4 | 设备端 `@hap` 解析 + `--explain --cross-layer` 跨层视图（4,911 案逐字段同宿主） | ✅ |
| L4 | 设备自检 `--selftest`：六道守门一道不缺 + explain 11 组固定向量 | ✅ |
| L4 | 落地桥 `tools/apply_converge.py`（收敛报告 → 板子策略过六道门 → secilc → policy.31，含编译回验） | ✅ |
