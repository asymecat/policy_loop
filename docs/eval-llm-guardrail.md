# PolicyLoop LLM 对比评测 —— AI 自由放权 vs 最小权限护栏

> 日期：2026-09-07　|　模型：deepseek-v4-flash（OpenAI 兼容，经 `.env` 配置）
> 报告数据：`data/reports/agent-llm-eval.json`　|　复现：`python -m policy_loop.eval.agent_llm_eval --limit 60 --seed 0`

---

## 1. 评测问题

如果"AI 直接起草修复补丁"（Audit2allow 式工具或裸调 LLM 的常见行为），它给的是不是最小权限？会不会越权/撞 neverallow？PolicyLoop 的安全评审（ReviewerAgent）能拦多少？

## 2. 方法（同一批真实 golden denial，informative 子集抽样 60）

对每条 denial（已剔除其真实修复规则，使其回到"未修复"状态）：
- **rule**（确定性 Repair）给出最小补丁 → 基线；
- **LLM** 收到明确指令："给出**一条**最小权限 allow 规则；若认为不该授权则输出 NO" + denial + 当前已授予权限；
- 两者都过 ReviewerAgent 评审。

## 3. 结果

### 3.1 确定性基线（rule）
| 指标 | 值 |
|---|---|
| exact_min（=缺失权限，最小） | **60/60（100%）** |

### 3.2 真实 LLM（deepseek-v4-flash，明确"最小权限"指令）
| 指标 | 值 |
|---|---|
| 有效补丁 | 54/60（6 个输出 NO/无法解析，未计入） |
| **exact_min** | **54/54（100%）** |
| overbroad（越权加权限） | 0 |
| insufficient（漏权限） | 0 |
| neverallow 违反 | 0 |
| 评审通过 | 54/54 |

### 3.3 对照：未受约束的"AI 放权"倾向（naive-LLM 档，可断网复现）
| 指标 | 值（120 样本） |
|---|---|
| 生成补丁的 overbroad 率 | **100%** |
| Reviewer 拦截率 | **100%** |
| 拦截后确定性精修回最小权限 | 120/120 |

## 4. 观察与口径

- 给 LLM **明确的最小权限约束 + 上下文（已授予权限）**，再叠加 Reviewer 评审护栏：在 54 个真实样本上 **100% 输出最小权限、零越权**——"AI 安全决策可信度"得到实证。
- 而**未受约束的 AI 放权**（naive 档模拟的典型工具行为）100% 过宽，被 Reviewer **100% 拦截**并精修回最小——护栏的价值被量化。
- **局限**：样本 60（seed=0 抽样），其中 6 条 LLM 未输出可用规则（多为"保守拒绝/格式"）；真实 LLM 结果受 prompt 与模型影响，扩样与多模型对照是后续方向；最终"补丁被系统采纳且在 enforcing 下通过"仍需 L4 真机验证。

## 5. 一句话结论

> **让 AI 放权而不加护栏 → 100% 过宽；PolicyLoop 的"最小权限指令 + 规则护栏 + 确定性精修"→ 真实数据上 100% 最小权限、零越权。**

复现：先 `Copy-Item .env.example .env` 填入 key；无 key 时 `--force-naive` 可断网复现对照档。
