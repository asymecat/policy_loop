# 已知边界与未建模路径

> 用途：答辩时当「已知边界」页用。每条给出**出处（file:line）**、**量化**、**影响面**、**处置**。
> 数字全部在仓库当前代码 + `data/raw/oh-selinux/sepolicy` 语料树上实测；复核日期 **2026-10-07**。
> 图例：✅ 已修 ／ ⚠️ 刻意不建模（有度量、不静默）／ 🔴 未修缺陷。

## 1. 「从 permissive 收紧到 enforcing」的四段

| 段 | 状态 |
|---|---|
| 采集：板端 `pl_collector`（自己的 enforcing 域、开机自启、不需 PC） | ✅ 真机 |
| 收敛：`converge` → 最小补丁 + 可自动／需人工／噪声三分 | ✅ 真机 |
| **落地：补丁 → CIL → `secilc` → 回验** | ✅ 2026-10-07 补齐（`tools/apply_converge.py`，提交 `0c30345`，六道门） |
| 刷进板子：`install_to_board.sh` + `load_policy` | ⚠️ 留人工一步（会改设备状态，需要时手动执行，命令由工具打印） |

## 2. 索引：多少策略语句根本没被建模

### 2.1 🔴 三种**合法书写**被正则拒收（本次实测新发现）

`policy_loop/policy/index.py` 的三条正则决定了索引看得见什么：`_ID_RE`(:33)、`_RULE_RE`(:53)、`_XP_RE`(:65)。
它们的标识符字符类不含 `-`、权限位不接受 `~{}`、类名位不接受 `{ c1 c2 }`。实测该树上因此被**静默丢弃**：

| 形态 | 条数 | 其中 neverallow | 例子 |
|---|---|---|---|
| 连字符标识符（`d-bms`） | **82** | 0 | `allow distributedsche d-bms:binder { call };` |
| 权限取反 `~{ }` | **46** | 46 | `neverallow { chipset_domain -system_file_violator_dir } system_file:dir ~{ search };` |
| 类列表 `{ c1 c2 }` | **69** | 68 | `neverallow { chipset_domain } system_file:{ blk_file chr_file … } *;` |

**它会造成看得见的错判**，实例可复现：

- 语料 `data/corpus/real_denials.txt:1196` 是一条真机 denial：
  `denied { call } for pid=479 comm="continue_manage" scontext=u:r:distributedsche:s0 tcontext=u:r:d-bms:s0 tclass=binder permissive=0`
- 同树上游 `…/distributedschedule/distributedsche/system/distributedsche.te:73` 就写着
  `allow distributedsche d-bms:binder { call };`
- 索引看不见这条（`d-bms` 带连字符）⇒ 当前代码判 **`MISSING_RULE`（建议补一条新规则）**；
  放宽字符类后同一案例变成 **`DOMAIN_OR_LABEL_MISMATCH`（策略已允许却被拒 → 疑似域/标签问题，不是权限缺口）**。
  **后者才对。**

**为什么现有门禁抓不到它**：

- **聚合数字不动**：放宽字符类后重跑全量语料，`by_category` 仍是 `1580/3261/70`、补丁仍是 69 行。
  该案例两种分类都落在 `needs_human` 里，**总量掩盖了单案翻转**。
- **设备侧同样看不见**：板子读的是宿主导出的 PLI 而不是 `.te`；`pl_index.h:76` 与 `pl_index.cpp:380,396`
  明确写着 `skipped` 是 “reported, not checked”。**宿主／设备差分门禁原理上抓不到这一类缺陷。**

处置建议：放宽三条正则属于 1 行级改动，但它会动到索引规模（21,790 → 21,872 条规则）、PLI、以及所有引用
索引数字的文档与报告，需重跑五项门禁后统一。**未做，待定**（见 §6）。

### 2.2 ⚠️ 刻意不建模的语句（有度量、不静默）

- 宏只展开 `binder_call`（`index.py:220`），其余宏与 `type_transition`／`boolean`／`constraint`／RBAC／
  `typebounds`／`genfscon`／`portcon`／`nodecon` 一律不建模 —— 即 **boolean 未开、约束拦下**这类 denial，
  工具会当成「缺 allow」；
- `dontaudit` 不建模。实测板子反编译策略里 **24 条 dontaudit 100% 是样板**（23 条 `process noatsecure`
  + 1 条 `process (transition siginh rlimitinh)`），**一条 file／ioctl／binder 都不盖 ⇒ 本板代价≈0**；
- `load_dir` 只读 `*.te` + `sehap_contexts`（`index.py:537`），**不读 `file_contexts`／`service_contexts`**。

度量一直是有的：`index.py:503-514` 的 `summary()['skipped_statements']`，进 PLI 的 `@meta`（`export/pli.py:195`），
设备端也收（`pl_index.cpp:396`）。
✅ **2026-10-07 起 `converge` 把它打到 stdout**（此前它只进 JSON／PLI 元数据，不看元数据就永远不知道）；
实测该树 **647 条**未建模，其中 **450 条**是宏／m4 片段／`dontaudit` 这类真·不支持形态，
**197 条是 §2.1 的缺陷**。

> 24 条 dontaudit 的实测方式：`checkpolicy -b -C -M -o orig.cil <policy.31>`
> （命令同 `device/selinux_policy/build_policy.sh:148`；产物目录被 gitignore，本机复跑即可得到）。

## 3. 🔴 neverallow 防线本身是漏的（本节最该看）

背景：neverallow 是**编译期断言，不落盘** —— 实测板子反编译出的 `orig.cil` 里 **0 条 neverallow**。
所以「`secilc` 编译通过」**不证明**没撞 neverallow；这条防线只能由 converge 的索引查询提供（已写进 `0c30345`）。

而 §2.1 的三条正则漏掉的 **164 条 neverallow 根本没进索引**（46 + 68 + 50）。也就是：

- **今天的门全绿，并不覆盖这 164 条红线**；
- 已做的核对：把其中能结构化解析的 **72 条**与当前 69 行补丁逐条比对（src／tgt／类／权限，含属性闭包
  与 `~{}` 语义）⇒ **0 条冲突** —— 今天这份补丁集是干净的；
- 但**新生成的补丁没有任何东西拦得住它们**。

处置建议：要么修 §2.1（顺带把这道防线补全），要么把「neverallow 防线覆盖不全」作为明确边界写进答辩口径。
**不能既不改也不说。**

## 4. 输入轨道

- 只认文本 `avc: denied`（`policy_loop/denial/parser.py:32`），不读 audit netlink 二进制；
- **hisysevent 作为独立输入轨道未接**：仓库里没有任何 hisysevent 采集／解析实现（设备端有一个「记录级」
  接口，其注释（`device/selinux_adapter/framework/tools/denial_check/test.cpp:1439`）提到宿主可以喂
  hisysevent 流来源的记录 —— 但那是接缝，不是入口）⇒ 应用层／系统层的分叉目前**只有系统层入口**；
- 采集侧 `printk_ratelimit` 会**静默丢** denial（已用 init job 修：`device/board/policyloop.cfg:54`，
  并如实写明这是**减少**丢失而非消除 —— 环形缓冲仍有上限）；
- 采集器自身的 AVC 流有 `dontaudit` 盲区（现象为 `HiLogAdapter_init: Can't connect to server. Errno: 13`，
  装饰性，但说明观察者本身不完美）。

## 5. 平台与自证

- 🔴 **板子版本口径仍冲突**：`docs/eval-L4.md:27,148,247` 写 6.1 Release；`docs/demo-realtime.md:3`
  写 OpenHarmony 5.0.3.135。**必须二选一** —— 它决定索引该对齐哪棵树；
- 语料同源：5,161 行 **96.8% 逐字来自上游 `.te` 注释**，自证色彩重于独立采集（`eval-trust` 已做质检，
  但根上同源）；
- 🟡 **HAP 源码在仓库外**（`tools/build_hap.sh:18` 指向 `~/ohos_audit/pl_console`）⇒ 第三方拿仓库
  **复现不出板端控制台**；
- 索引口径：语料索引 **21,790** 条 vs HAP 内置 **19,800** 条（rev `e1160d2c`，取自 5.0.3 树
  `0878c56e3e41`），已在 `docs/report.md:646` 标注待统一说明。

## 6. 处置一览

| 项 | 成本 | 建议 |
|---|---|---|
| §2.1 放宽三条正则（连带补全 §3 的 neverallow 防线） | 半天 + 重跑五项门禁 | **建议做**：同时修掉一个错判与一个安全盲区 |
| §3 的答辩口径 | 0 | 无论做不做，都必须能说清 |
| §5 板子版本二选一 | 0.5 h | 提交前必做 |
| §4 hisysevent 应用层入口 | 大 | 24 天内不碰，作为「下一步」写 |
| §2.2 boolean／constraint 诊断、dontaudit 建模 | 大 | 不碰：要动索引模型 + PLI 格式 + C++ 镜像 + 重验逐字节差分 |
