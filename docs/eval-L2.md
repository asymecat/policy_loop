# PolicyLoop L2 评测报告 —— 真实上游语料回放

> 日期：2026-09-07　|　数据源：OpenHarmony 上游 `security_selinux_adapter`（gitee 稀疏克隆，`data/raw/oh-selinux/sepolicy`）
> 目标：用真实策略与真实 denial 证据，给"解析/查询/最小权限"能力做**量化**基线。

---

## 1. 语料规模（`policy_loop.eval.corpus`）

| 指标 | 值 |
|---|---|
| `.te` 文件 | 1315 |
| 总行数 | 51,427 |
| 索引到规则 | **20,884**（allow / allowxperm / neverallow…） |
| 文本 allow 语句 | 20,635 |
| neverallow 语句 | 570 |
| type / attribute | 1,267 / 42 |
| 未解析语句（宏等） | 1,528（skipped 占比 ≈ 3%） |
| **真实 denial 注释** | **5,230 条（378 个文件）** |

**OpenHarmony 专有对象类在真实策略中得到印证**：

```text
file 7306 · dir 3410 · binder 2527 · samgr_class 2217 · chr_file 1198
fd 770 · process 482 · hdf_devmgr_class 239 · parameter_service 184 · capability 73
```

> 说明：L1 索引已能解析绝大多数 allow（其余多为 `binder_call()`、`debug_only()`、`domain_auto_transition_pattern()` 等宏与块，见 §5）。

---

## 2. Golden 评测集抽取（`policy_loop.eval.extract`）

上游 .te 采用两种布局，工具做了**双向配对**：

```text
# 布局 A：denial 注释在上、修复规则在下
# avc: denied { read } ... scontext=u:r:faultloggerd:s0 ...
allow faultloggerd dev_pdump:chr_file { read };

# 布局 B：规则在上、denial 证据注释在下
allow accountmgr account_data_file:file { lock watch };
# avc:  denied  { lock } ... 
```

**抽取结果**（自证注释 = 真实 "denial → 正确修复" 对）：

| 指标 | 值 |
|---|---|
| golden 修复对 | **3,367** |
| 其中可解析 denial | **5,161** |
| 未配对注释块 | 59（低噪声） |

产物：`data/eval/golden.jsonl`（入库、可复现）。

---

## 3. 回放指标（`policy_loop.eval.replay`）

用同一语料建全量索引，对 5,161 条真实 denial 做"该访问是否已被策略允许"判定：

| 指标 | 值 |
|---|---|
| 可评测 denial | 5,117 |
| **coverage_all（请求权限全部被允许）** | **97.19%（4,973 条）** |
| coverage_any（至少一个被允许） | 97.28% |
| 未覆盖 | 144 |

**修复画像**（"denial 请求权限" vs "上游实际修复规则给的权限"）：

| 指标 | 值 | 解读 |
|---|---|---|
| fix 平均比单条 denial 多给权限数 | 2.06 | 上游一条 allow 常聚合修复多条 denial，属正常聚合 |
| fix 恰好等于单条 denial 的最小权限占比 | 30.2% | 单 denial 场景下上游规则基本是"最小权限"的直接证据 |

---

## 4. 未覆盖归因（144 条）—— 索引增强记录

**本轮增强（A）已解决的主因**（coverage 92.0% → 97.2%）：

| 增强 | 说明 |
|---|---|
| `typeattribute` 空格分隔解析 | OpenHarmony 大量写 `typeattribute normal_hap hap_domain;`（空格分隔而非逗号），原解析全 skip → `*_hap → *_hap_attr/hap_domain` 归属从未建立。修复后 `*_hap` 未覆盖 **230 → 15** |
| `binder_call()` 宏展开 | 按真实 `glb_te_def.spt` 定义展开为 3 条 allow（双向 binder call/transfer + `fd use`），兼容**逗号与空格**两种参数分隔 |
| 条件块解析 | `debug_only()` / `developer_only()` 等块内规则按普通规则索引 |

**残余未覆盖（144 条）分布**：`file` 50 · `samgr_class` 18 · `dir` 16 · `binder` 13 · `hdf_devmgr_class` 9 · `chr_file` 7 · `fd` 5 · `process` 4

残余原因（继续增强的方向）：
1. 少量规则用 `hdi_call()` 等更深层宏（未展开）；
2. `samgr_class`/`hdf_devmgr_class` 的 target 是 `service=` 资源，需接 `service_contexts`/`hdf_service_contexts` 做第二层映射；
3. 个别 `*` 权限与 `neverallowxperm` 表达式的近似语义。

> 验收口径更新：**coverage_all 已从 92.0% → 97.19%（目标 ≥97%，达成）**。

---

## 5. 复现命令

```powershell
# 0) 拉语料（一次性；.gitignore 已排除 data/raw/，不会入库）
git clone --depth 1 --sparse https://gitee.com/openharmony/security_selinux_adapter.git data/raw/oh-selinux
cd data/raw/oh-selinux; git sparse-checkout set sepolicy; cd ../..

# 1) 语料统计 → data/reports/corpus-report.json
python -m policy_loop.eval.corpus --json data/reports/corpus-report.json

# 2) golden 抽取 → data/eval/golden.jsonl（已入库）
python -m policy_loop.eval.extract

# 3) 回放评测 → data/reports/replay-report.json
python -m policy_loop.eval.replay
```

> `data/eval/golden.jsonl` 与 `data/reports/*.json` 已提交到仓库，**没有拉取语料也能查看评测产物**；拉取语料后即可全量重跑。

---

## 6. 结论与口径

- **确定性基座已被真实数据验证**：5,000+ 真实 denial 中 **97.2%** 能被索引正确"已允许"判定（增强前 92.0%）；残余 144 条根因明确且可逐条归因，无"未知/玄学"。
- 这些指标将成为后续 AI 层的**评测锚点**（AI 生成的修复必须 ≥ 该确定性基线且不引入回归）。
- 自证注释语料（3,367 对）是本项目独有资产，可作为 "denial→golden 修复" 的**开源评测集**向社区开放（答辩亮点）。
