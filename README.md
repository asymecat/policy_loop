# PolicyLoop

面向 **OpenHarmony** 安全子系统（SELinux/访问控制）的 denial 诊断与**最小权限**修复 Agent —— L1（确定性核心）、L2（真实语料评测基线）与 L3（Multi-Agent 最小闭环）已完成。

> 完整方案与设计见 [`docs/design.md`](docs/design.md)（含"先仿真、后真机"执行策略）。

## 现状（2026-09-07）

**无第三方运行时依赖、可断网演示。** 已实现：

- `policy_loop.denial.parser`：OpenHarmony 风格 AVC denial 解析器
- `policy_loop.policy.index`：`.te` 策略索引（allow/allowxperm/neverallow + attribute 闭包 + 宏展开 + ioctl xperm 判定）
- `policy_loop.agents.*`：**L3 Multi-Agent 闭环**（Log→Policy→Security→Repair→Reviewer→Verify + Orchestrator Agent Trace）
- `policy_loop.eval.*`：L2 评测工具（corpus / extract / replay）
- `policy_loop.selfcheck`：环境 + 模块 + 冒烟自检

**L2 实测基线**（真实上游 `security_selinux_adapter` 语料，1315 个 `.te`）：
- 索引 21,790 条规则；抽取 **3,367 对 denial→修复 golden、5,161 条真实 denial**
- 回放 **coverage_all 97.2%**（5,117 条可评测中 4,973 条判定正确），见 [`docs/eval-L2.md`](docs/eval-L2.md)

**L3 Agent 闭环**：一条 denial → 人话解释 + 最小权限补丁 + 安全评审 + 验证（规则版，断网可跑；LLM 可插拔）。
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
  agents/             # L3：SecurityCase + Orchestrator + 6 Agents + 可插拔 LLM Provider
  eval/               # L2/L3 评测：corpus / extract / replay / agent_eval(留一)
  selfcheck.py        # 自检入口
webui/                # Web UI：stdlib HTTP server + /api/analyze + Agent Trace 前端
data/
  fixtures/           # 测试/演示样例（含上游真实格式 denial）
  eval/golden.jsonl   # 自证 denial→修复 评测集（3,367 对，已入库）
  reports/            # corpus/replay/agent-eval 评测报告（已入库）
  raw/                # 上游语料（稀疏克隆，不入库，需自行拉取）
docs/                 # 方案与路线文档
tests/                # 单测（47 个）
```

## L2/L3 评测命令

```bash
# 先拉上游语料（一次性；默认在 data/raw/oh-selinux）
git clone --depth 1 --sparse https://gitee.com/openharmony/security_selinux_adapter.git data/raw/oh-selinux
# （然后）cd data/raw/oh-selinux && git sparse-checkout set sepolicy

python -m policy_loop.eval.corpus          # 语料规模统计
python -m policy_loop.eval.extract         # golden 评测集抽取
python -m policy_loop.eval.replay          # 索引覆盖回放（coverage 97.2%）
python -m policy_loop.eval.agent_eval --limit 400 --seed 0
                                           # L3 Agent 留一回归（生成补丁正确性）
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
| L3 | Multi-Agent 闭环 + 最小权限 patch + Verify | ✅（规则版；LLM 增强待接） |
| L4 | DAYU200 真机验证 | 未开始 |
