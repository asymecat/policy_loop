# 评测可信度质检（trust）：golden 配对审计

> 把「denial ↔ 修复规则」的评测集从"按相邻行猜测"升级为"可证明归属"。
> 逐对标注可信度，划出干净子集 `golden.trusted.jsonl`，所有覆盖率/agent 指标
> 都给出 **全量 vs trusted** 两套口径。确定性、纯标准库，只读不改语料。

## 为什么要质检

`eval/extract.py` 用**贪婪相邻配对**：一条 `# avc: denied` 注释块与其后最近的
allow 规则结成一对。上游 .te 里的 denial 注释是手维护的、自由格式，一个注释块
常常叠几条**互不相关**的 denial，或挂在一条"恰好隔了空行"的无关规则上方。于是
评测集里混入大量"这规则根本不是修这条 denial"的噪声对，任何跑在全量上的指标
都被它们稀释——正是 144 条 replay 残留里能挖出 `allow hdcd hook_param:file`
去修 `sh` 的 denial 这类例子的原因。

## 方法：pair_kind 逐对标注

对每对 (rule, denials)，用与策略索引相同的 **attribute 闭包**做归属判定
（规则 `src` 命中 denial `source_domain` 或其 attr；`tclass` 一致；allow 要求
`请求权限 ⊆ 规则权限`（`*` 通配视同全量）；allowxperm 要求请求 ≤ {ioctl} 且
cmd ∈ 白名单）。随后按严重度给对打标：

| pair_kind | 含义 | 处置 |
|---|---|---|
| `trusted` | 规则**独立完整**修复配对内每条 denial（主体/类/全权限/ioctl cmd 全部经闭包命中） | ✅ 进 trusted 子集 |
| `service_gap` | 主体类权限相符，但目标为 `default_service/default_hdf_service` 占位（samgr/hdf_devmgr）——真实修复落到具体 `sa_*`/`hdf_*` 类型 | ✅ 进 trusted 子集（交给 M3 service 映射） |
| `attr_or_name_gap` | 主体/类/权限相符，但规则目标与 denial 是**不同具体类型**（文件上下文/命名粒度） | ⏳ 相关但不可证明，剔除 |
| `partial_fix` | 规则只覆盖请求权限的**真子集** | ⏳ 剔除 |
| `mispair` | 规则**不可能**修这条 denial（src 域不同 / 类不同 / 权限完全不相交） | ❌ 相邻噪声，剔除 |
| `unparseable` | 规则或 denial 无法解析（含 `d-bms` 连字符类型、`process{` 缺空格、单命令 allowxperm 等 canonical 解析器本身跳过的形态） | ❌ 剔除 |

> 关键保守选择：**聚合修复是合法的**。一条规则修注释块里的多条 denial 不判错配；
> 只有「src 完全不同 / 类不同 / 请求权限与规则权限交集为空」这类**必然无关**才算
> mispair。宁可留白（attr_or_name_gap / unparseable）也不误杀真修复。

CLI：

```bash
python -m policy_loop.eval.trust \
  --golden data/eval/golden.jsonl \
  --root  data/raw/oh-selinux/sepolicy \
  --out   data/eval/golden.trusted.jsonl     # 只含 trusted + service_gap
  --json  data/reports/trust-report.json
```

## 质检结果（2026-09，真实上游语料，规则索引 21790）

| pair_kind | 对数 | 占比 | 说明 |
|---|---|---|---|
| trusted | 2147 | 63.8% | 干净证据核心 |
| mispair | 990 | 29.4% | 相邻噪声（上/下方向都有） |
| attr_or_name_gap | 169 | 5.0% | 目标类型不同粒度 |
| unparseable | 42 | 1.2% | canonical 解析器跳过的形态 |
| partial_fix | 12 | 0.4% | 规则只覆盖部分权限 |
| service_gap | 7 | 0.2% | default_* 占位，待 M3 映射 |

**trusted 子集 = 2154 对 / 3522 条 denial。**

denial 级判定分布：matches 3651 / class_mismatch 870 / src_mismatch 166 /
perm_disjoint 111 / tgt_mismatch 288 / service_gap 10 / partial 12 /
unparseable 44。**主体级错配（class 870 + src 166 + perm 111）合计 ~1147，正是
手写注释块叠多条 denial 的证据**——一条规则跟它真正修的那条在一起时，其余
叠进来的 denial 必然对不上。

### 与"挖坑实例"对上（验收）

- **hdcd/sh**：`hdcd.te:196` `allow hdcd hook_param:file { map open };` 配
  `sh→hook_param {open}` → **mispair**（src_mismatch）。M0 挖出的假修复被标记。✅
- **intell_voice / normal_hap / system_basic_hap → `default_service`**（注释块里
  数字 service 标签与具体类型对不上）→ **service_gap**，进 trusted 子集、留给 M3。✅

## trusted 指标（重跑 replay / agent_eval）

replay 与 agent_eval 都能 `--golden` 指向 trusted 子集，两套口径并列：

### L2 replay 覆盖率

| 口径 | denials | coverage_all | 未覆盖 |
|---|---|---|---|
| 全量 golden | 5161 | 97.19%（4973/5117 可评估） | **144** |
| **trusted 子集** | 3522 | **99.80%**（3515/3522） | **7** |
| trusted + `--resolve`（逻辑覆盖） | 3522 | **99.94%**（3520/3522） | **2** |

未覆盖从 144 → 7：**剩下的 7 条全部是同一个已知局限**——`default_service`
（4 samgr_class）与 `default_hdf_service`（3 hdf_devmgr_class）占位目标，不是
散噪声。这正是 M3 的 service→类型二次映射要打的缺口。

#### M3：占位目标逻辑解析（`--resolve`，见下节余量）

`replay --resolve` 先把可确定性推导的占位目标重映射为具体类型再查索引，7 条里
**5 条被证明已被策略允许**，未覆盖 7 → 2。剩余 2 条
（`normal_hap`/`system_basic_hap` → `default_service:samgr_class { get }`
`service=312`）是对**远端 SA 312**（`sa_intell_voice_service`）的客户端查询——
数字 SA id→名的对应关系存在 OpenHarmony 的 samgr `sa_profile` 注册表里，
**不在 sepolicy 语料中**，纯索引无法闭合；它们各自的修复规则
（`allow normal_hap_attr sa_intell_voice_service:samgr_class { get };`）已在索引
中，补上外部注册表即可覆盖。诚实口径：这 2 条是外部数据依赖，不是引擎缺陷。

### L3 agent 留一（limit 400 / seed 0）

| 阶段 | 全量 golden | trusted 子集 |
|---|---|---|
| 配对总数 | 3367 | 2154 |
| allow-fix 对 | 3222 | 2115 |
| allowxperm 对 | 145 | 39 |
| 不可解析对 | 33 | 0 |
| covered_elsewhere（冗余修复） | 1274 | 320 |
| **informative** | 1915（56.9% 的对） | **1795（83.4% 的对）** |
| 其中撞 neverallow | 1045 | 1003 |
| Phase B 评估（MISSING/ESC） | 400（179/221） | 400（183/217） |
| exact_min / sufficient / overbroad | 1.000/1.000/0.000 | 1.000/1.000/0.000 |
| review_approve / final_verified | 1.000 / 1.000 | 1.000 / 1.000 |

**读数**：同一引擎、同一采样上限下，trusted 集里 informative 对占比从 57% 升到
83%——去掉相邻噪声后，评测集每一条 pair 都更有"这是一次真实缺失/一次需放权
决策"的含量；`covered_elsewhere`（多为错配恰好被他规则覆盖）从 1274 砍到 320，
`unparseable` 从 33 归零。**这正是"把评测集的信号做纯，而不是把指标做高"。**

## M3 覆盖：service 占位逻辑解析（`resolve_logical_target`）

真实日志里 samgr/hdf 访问的 target 是 `default_service`/`default_hdf_service`
占位符，而真实规则落在具体 `sa_*`/`hdf_*` 类型上。`PolicyIndex` 新增
`resolve_logical_target(src, cls, tgt, service, perms)`，把占位目标重映射为可
推导的具体类型——**只在候选类型已被索引声明时才返回**，绝不臆造目标：

| 情形 | 映射 | 依据 |
|---|---|---|
| 具名 service + hdf_devmgr_class | `hdf_<service>` | OH 的 hdf 服务类型按其名字命名 |
| 具名 service + samgr_class | `sa_<service>` | 同上 |
| 数字 service + samgr `add` | `sa_<src>` | SA 启动时把**自己**注册进 samgr，目标即源域同名 SA 类型 |
| 其余（数字 client `get`、数字 hdf） | 不映射 | 需要 samgr `sa_profile` 外部 id→名注册表 |

实测（trusted 子集 3522 条，见上表）：7 条占位未覆盖里 **5 条经解析后证明已
允许**（3 具名 hdf 服务 + 2 个 samgr 自注册 `add`），未覆盖 7 → 2；仅剩的 2 条
为对远端数字 SA 的客户端 `get`，外部数据依赖。改动只进 `index.py` + `replay`，
不动 repair/review/verify 语义。

## 边界与诚实口径

- `exact_min=1.000` 仍是**构造使然**（补丁=剔除后缺失权限），只作自洽检查，
  不对外夸大为独立金标准；真机回归在 L4。
- mispair/attr_or_name_gap 依赖 attr 闭包：**CIL 生成的运行时类型不在 .te 声明里**
  （`type_attrs` 为空），这类目标会落到 `tgt_mismatch`/`attr_or_name_gap` 被剔除——
  是**保守剔除**而非误杀，宁可少用不可靠证据。
- 42 对 unparseable 反映 canonical 解析器自身的形态盲区（连字符类型 / 无空格
  花括号 / 单命令 allowxperm），不改 parser 语义的前提下如实归档；真要收编它们
  属于 index 解析加固，不在本轮评测可信度范围。

## 复现

```bash
python -m policy_loop.eval.trust                # 质检 + 写 trusted jsonl + 报告
python -m policy_loop.eval.replay  --golden data/eval/golden.jsonl \
                                  --out data/reports/replay-report.json
python -m policy_loop.eval.replay  --golden data/eval/golden.trusted.jsonl \
                                  --out data/reports/replay-report.trusted.json
python -m policy_loop.eval.replay  --golden data/eval/golden.trusted.jsonl --resolve \
                                  --out data/reports/replay-report.trusted-resolved.json
python -m policy_loop.eval.agent_eval --golden data/eval/golden.jsonl \
                                  --limit 400 --seed 0 --out data/reports/agent-eval.json
python -m policy_loop.eval.agent_eval --golden data/eval/golden.trusted.jsonl \
                                  --limit 400 --seed 0 --out data/reports/agent-eval.trusted.json
python -m unittest tests.test_trust -v
```

> 语料 `data/raw/oh-selinux` 不入库；trusted 子集 `data/eval/golden.trusted.jsonl`
> 由质检派生、随代码入库（含 `pair_kind` 标注）。
