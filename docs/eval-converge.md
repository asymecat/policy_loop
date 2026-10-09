# 批量收敛工作流（converge）

> 把「permissive 模式下攒下的整份 `avc: denied` 日志」收敛成一份可执行清单：
> 去重 → 逐案判定 → 可自动最小修复 / 需人工决策 / 噪声，附 enforcing 就绪度。
> 确定性内核，纯标准库，**只产出建议、绝不自动写 .te**。

## 用法

```bash
python -m policy_loop.converge \
  --log    <denial 日志文件> \
  --policy <sepolicy 目录或 .te> \
  --json   data/reports/converge.json \   # 可选
  --md     converge.md                    # 可选：人读报告
```

不带 `--policy` 时只能做去重统计（`unclassified_no_policy`），不做策略判定。

## 流水线

1. **聚类去重**：`denial.fingerprint` 按逻辑访问 `(src,tgt,class,perms,ioctl)` 做键
   （`perms` 排序无关），pid/comm/path 等噪音不参与 → 几千条塌缩成唯一案例。
2. **快路判定**：每唯一案例先做廉价策略查询（`has_access`/`neverallow`/`ioctl`）：
   - 撞 neverallow → 直接转人工（拒绝自动放权）。**neverallow 按权限匹配**：
     `neverallow A B:file execmod` 只禁止 `execmod`，对同一三元组上的 `read`
     一个字都没说；按三元组盲匹配会把同一条红线报给每一个请求（见下「权限盲」节）；
   - 已允许 + `permissive=1` → 噪声；
   - 已允许 + enforcing → 域/标签问题转人工；
   - 其余才进入完整 6-Agent 闭环（Log→Policy→Security→Repair→Review→Verify）。
   这一层把「逐条跑闭环」的成本降到只在真缺口上花。
   查询前先做 **service 占位符解析**（M3，见下节）：日志里的 `default_service` /
   `default_hdf_service` 是占位符，直接查它等于在问「策略允不允许访问占位符」——
   永远不允许，于是每一条都被读成真缺口。解析成 `service=` 指名的具体
   `sa_*`/`hdf_*` 之后再查，才分得清「早已允许」和「真缺规则」。
3. **守门**：闭环判 AUTO 的补丁必须能作为最小修复落点验证，否则降级人工
   （见下）。通过后归入 `auto_repairable`。
4. **产出**：去重比 / 各根因分布 / 去重后最小补丁集合（含覆盖案例与条数）/
   需人工清单（附原因与样例 raw）/ enforcing 就绪度一段话。

### 守门只有一个实现，两个调用点（E）

守门原本**内联在聚类循环里**——于是 `--explain` 这条路径（开发者捏着一条坏日志时
最先用的那条）给出的补丁，恰恰是守门会拒绝的那个。最直观的例子：把上面第 2 条
（`default_service` + `samgr_class`）交给 `--explain`，它会推荐一条
`allow X default_service:samgr_class { get };` —— 这条规则**编译得过、也会被
Verify 判成功**，只是落不了地。

修法不是"在 explain 里也抄一遍守门"，是把它抽成一个函数 `apply_guards(rec, patch,
index)`，converge 与 `--explain` **调同一份**，设备端同样只有一个 `ApplyGuards`。
被钉住的不变量是：**同一条记录从哪个入口问，都必须拿到同一句话**——
批处理报告把它放进 `clusters[].why`，单条诊断把它放进 `advisory`，两者逐字符相等
（`tests/test_converge.py::TestGuardsAreOneFunctionTwoCallers`，6 项）。顺序也被钉住：
一个目标既是 MLS 级别又是未知 token 时，先报的那条决定措辞。

⚠️ 顺带说明一处**刻意的不一致**：`--explain` 对**任何**记录都跑守门，converge
只对会被自动应用的记录跑。这不是漏洞——批处理里已经升级为人工的案例不会再被改写，
守门对它没有意义；而单条诊断无论如何都会把补丁给人看，所以必须跑。

## 补丁守门（为什么自动项可信）

闭环自身的 Review/Verify 只做「应用后能消除 denial、无回归」的名字级匹配，
无法发现「规则本身引用的是不存在的类型/类」。converge 据此补了六道守门，
命中的一律从 AUTO 降级为 needs_human：

| # | 情形 | 示例 | 处置 |
|---|---|---|---|
| 1 | 目标被解析成 MLS 级别 | `tcontext=u:charger_exec:s0`（丢 `object_r`）→ tgt=`s0` | 人工复核上下文 |
| 2 | 目标是 `default_*` 占位符 | `allow X default_service:samgr_class get`（真实修复落到 `sa_*`/`hdf_device_manager`） | 解析不出就转人工（M3） |
| 3 | 主体/目标不在策略语料 | `src=file`、`tgt=sa_1401_service`（设备新增域 / 数字 service 标签） | 补丁无法落点验证 |
| 4 | 对象类不存在 | 手写日志笔误 `samar_class`/`samger_class`/`dit` | 补丁无法编译 |
| 5 | 权限位含非权限名 | `denied { 0x5413 }`（ioctl 命令号被写进权限位，`ioctl` 反被写在括号外）、`{ semap open readt }` | 补丁编译不过；且要告诉人**日志本身是坏的** |
| 6 | 空权限补丁 | ioctl-only 缺口经 allowxperm 语义后得 `allow A B:c { };` | 转人工给 allowxperm |

> 这些大多来自**上游 .te 里手维护的 denial 注释**（会缺 `object_r`、拼错类名、
> 引用 CIL 生成/数字 service 类型），而非真实内核日志。真机 permissive dump 干净得多，
> 守门主要是挡住"照抄可疑注释"这类误修复。
>
> 守门 5 值得单独说一句：**修法上刻意不改 parser**。把 `denied { 0x5413 }` 猜成
> 「ioctl 命令号 0x5413」在语义上多半猜对，但 parser 是全项目「宿主↔设备逐字节
> 一致」的地基（parse 门禁 5161 条），为语料里 2 行手抄笔误加模糊启发式，等于把
> parser 的契约从「读它写的」降级成「猜它想写的」；而守门 5 除了拦住废补丁，还能
> 把「你这行日志是坏的」这个真问题如实报给人。语料里命中 3 条（`real_denials.txt`
> 的 `:3184` / `:3350` / `:3351`）。

## M3：service 占位符解析（为什么解析了，守门还留着）

走 service manager 的 denial 在日志里记的是**占位符** target，而真实规则必须落在
具体的 `sa_*` / `hdf_*` 类型上。`policy/index.py::resolve_logical_target` 做这个映射，
只有两条**声明校验过**的规则：

| 情形 | 映射到 | 依据 |
|---|---|---|
| 具名 `service=` + `samgr_class` | `sa_<service>` | OH 以服务名命名 SA 类型 |
| 具名 `service=` + `hdf_devmgr_class` | `hdf_<service>` | 同上 |
| 数字 `service=` + samgr `add` | `sa_<src>` | SA 启动时以自身 id 向 samgr 注册自己 |
| 数字 `service=` + `get` | **不解析** | 远端 SA 需要外部 samgr id→name 注册表 |
| 候选类型未被策略声明 | **不解析** | 绝不臆造 target |

**关键设计：解析结果只喂给那三次查询，不喂给补丁文本，也不喂给六道守门。**

这不是保守，是两条硬约束：

1. **补丁与验证必须自洽。** 闭环的 Review 复查 neverallow、Verify 重新查询，读的都是
   `rec.target_type` 原始字段，而补丁文本用的是 `v.tgt`。若把解析结果写进 `v.tgt`，
   补丁会写 `sa_*`、Verify 却拿 `default_service` 重查 → **必然 FAILED**。
2. **守门 2 是真正在挡事的。** 解析得出的类型若仍然不许访问，修复路径写出的补丁是
   `allow X default_service:samgr_class { … };`——它**能通过评审、也能通过 Verify**
   （Verify 查的正是占位符）。此时唯一拦住它的是守门 2。所以守门读原始字段，
   不能改成读解析结果。

### 实测（真实语料 13 条占位符 denial）

6 条可解析，7 条不可解析（3 条数字 `get`、2 条数字 + `hdf_devmgr_class`、1 条候选未声明、
1 条 `default_service` 配 `hdf_devmgr_class` 类不匹配）。解析后，**6 个簇**由「人工」
变成「噪声」——解析成具体类型后查询 `allowed=True`，策略其实早就允许：

| 簇 | `allowed`（解析后） | 类别变化 |
|---|---|---|
| `intell_voice_service -> default_hdf_service:hdf_devmgr_class get` | True | 人工 → **噪声** |
| `intell_voice_service -> default_service:samgr_class add` | True | 人工 → **噪声** |
| `audio_host -> default_hdf_service:hdf_devmgr_class add` | True | 人工 → **噪声** |
| `intell_voice_host -> default_hdf_service:hdf_devmgr_class add` | True | 人工 → **噪声** |
| `wifi_host -> default_hdf_service:hdf_devmgr_class add` | True | 人工 → **噪声** |
| `selection_service -> default_service:samgr_class add` | True | 人工 → **噪声** |

> **订正（2026-09-17）。** 本节原先写的是「4 个簇变噪声」，并称另 2 条
> 「在具体类型上仍然命中 neverallow → 依旧转人工，**这是正确行为**」。那个说法
> **是错的**，错因是当时 neverallow 按三元组盲匹配（见下节）：那 2 条
> （`intell_voice_service -> default_service:samgr_class add`、
> `selection_service -> default_service:samgr_class add`）解析成 `sa_*` 后撞上的
> 红线，命名的权限根本不是这次请求的权限，是**假红线**；修掉权限盲之后两条都露出
> `allowed=True`，本该是噪声。所以真实收益是 **6 个假告警**被消掉，不是 4 个；
> 当时"另 2 条依旧转人工是正确的"这句话，恰好把 bug 的症状当成了预期的行为记了下来。

### 「权限盲」：neverallow 曾按三元组匹配（2026-09-17 修复）

`neverallow` 是**编译期的、逐权限的**断言：`neverallow A B:file execmod` 只禁止
`execmod`，对同一三元组上的 `read` 没有任何约束。但 `neverallow_rules()` 原先只按
`(src, tgt, cls)` 取规则，于是**同一条红线被报给了该三元组上的每一个请求**。

在真实语料上量出的偏差（规则索引 21790）：

| 口径 | 命中数 |
|---|---|
| 权限盲（修复前） | 2700 |
| 权限感知（修复后） | **54** |

即 **98% 的"红线"是假的**，其中 2657 条的真实情况是「策略本来就允许这个访问」。
更糟的是快路判定：`_quick` 一见到 neverallow 命中就立刻升级为
`POTENTIAL_ESCALATION` 转人工，**完整闭环根本不跑**，于是这些案例被挡在修复路径之外，
且给人工的理由是错的。跨 B/C/A 三批共 **1705** 个案例因此被错误挡下。

修复按权限取交集（空权限集仍是 `*` 通配，与 `has_access` 同一约定），并在两侧同时
落地：宿主 `policy/index.py::neverallow_rules` 与设备
`pl_index.cpp::NeverallowRules`，五道差分门禁全绿（见 `eval-L4.md`）。

修复的**净收益**（B 批，4911 唯一案例）：自动补丁 40 → **70**，需人工 3315 → **1580**，
噪声 1556 → **3261**。三个桶的变化量精确闭合：`1705` 个案例从人工移到噪声、
`30` 个从人工移到自动（`3315 - 1705 - 30 = 1580`）。

修复也**放出了一批之前被假红线掩盖的问题**，这是修完必须接着看的：

- 一条**编译不过的补丁**：`allow bgtaskmgr_service data_service_el1_file:file { 0x5413 };`
  ——`0x5413` 不是权限名（日志转写笔误）。已由新守门 5 兜住。
- **7 个应用域自动放权**（`normal_hap -> sys_file:file {read}` / `{open}`、
  `normal_hap -> dev_file:dir {mounton}`、`system_core_hap -> download_server:binder {get}` 等）。
  其中 `dev_file:dir mounton` 与 `distributed_isolate_hap` 自有 `hmcap supervsable`
  在修复前**就已经**是自动项（0 条权限盲命中），即**预先存在**，不是本次修复引入；
  另几条是修复后新露出的。

> 值得记下的一处**预测偏差**：动手前我预期这 4 条是"假缺规则"、另 2 条会升级成
> neverallow 告警。实测方向相反——4 条**本来就是假的 neverallow 告警**（占位符上恰好
> 撞了红线），解析后红线消失、策略其实早已允许；而 2 条真红线**本来就已转人工**，
> 类别没变。也就是说 M3 在这份语料上的收益是**消灭 4 个假的安全告警**（安全工具
> 里最不该有的那类噪声），不是多产出自动补丁。结论反而更好，但和事前的说法不同，
> 记在这里以免后人照着旧说法复述。

## 跨层视图：同一条 denial，也问一次应用层

`sehap_contexts`（`policy/sehap.py`）是 APL 等级 ↔ SELinux 域的桥：一个应用的域是从
它签名 profile 的 APL 推出来的。桥的两端引擎里都已经有了——域是系统层的说法，APL 是
应用层的说法——`policy/cross_layer.py` 是唯一把一条 denial 同时摆到两层面前的地方，
因为两层该改的东西不是一回事：

```
scontext=u:r:normal_hap  →  APL=normal  →  全部 normal 应用共用这个域
```

**让答案不显然的那个事实**：`*_hap` 域是**共享**的。`normal_hap` 不是"被拒的那个
应用"，它是设备上每一个 normal APL 应用。所以 `allow normal_hap sys_file:file read`
不是给一个应用开的小口子，是平台级放权。该不该放，`.te` 树本身答不了；跨层视图就是
去算这个：

- **别的应用域已经有了，就它没有** → 平台在两者之间画了一条线。语料上那 2 个
  `normal_hap → sys_file:file` 案例，这条线就是 APL 分级本身（`sys_file` 对
  `system_basic`/`system_core` 应用可读，对 `normal` 从不可读）。改 `.te` 等于抹掉
  一条有意的权限边界 → `fix_layer=app`：去应用层解决（提 APL，或走系统服务）。
- **没有任何应用域有** → 这条缺口没有在防谁，就是漏配 → `fix_layer=system`，并附
  **影响面**：规则落在共享域上，受益者是该等级的全部应用。

判不出来时它**拒绝**下结论，而不是给一个自信的错答案：域同时服务多个 APL 等级（归因
不到某一级）、APL 不在已建模的阶梯上（"更高"无从比较）、sehap 里声明了但本语料没有
这个 type（查不了，不能被读成"被拒"）—— 三种都写进 evidence 并退回系统层。

它**不改变**任何判定。`classification`/`patch`/review/verify 与没有 sehap 表时逐字节
相同（`TestCrossLayerDoesNotChangeVerdicts` 拿同一份语料跑两遍做差钉住）。原因是硬
约束：这些字段要与设备端 `Converge()` 逐字节对齐，而跨层结论一旦影响分类就会把
两边拆开。同理 `--json` 是设备契约，跨层键**默认不出现**，要 `--cross-layer` 显式打开
（`--md` 隐含打开）；人读输出则总是给。

> **E 之后的修正**：上面原写"设备端没有 `@hap` 表可复算跨层结论"。**表已经有了**——
> `@hap` 进了 PLI，设备端 `--explain --cross-layer` 与宿主逐字段相同（4911 案差分，
> 见 `eval-L4.md`）。所以"搬到设备上"这件事已经做完；**仍然没做**的是把它升格成
> 第七道守门（即让跨层结论改变 `classification`）——那会同时改动 converge 的分类，
> 属于门禁 3/5 的字节口径变更，不是加法。

### 实测（真实语料 5161 条 / 4911 唯一）

| 量 | 值 |
|---|---|
| 唯一案例的 scontext 是应用域 | 350（normal 250 / system_basic 57 / system_core 43） |
| `fix_layer=none`（策略已允许，跨层无需处理） | 337 |
| `fix_layer=system`（跨等级一致的缺口，按最小权限补） | 11 |
| **`fix_layer=app`（APL 分级边界，不该在系统层放开）** | **2** |
| 自动补丁落在共享域上（影响面须明说） | 7（其中 2 条 `fix_layer=app`） |

那 2 条 = `normal_hap → sys_file:file { read }` / `{ open }`，此前在 converge 里是
**auto_repairable**，也就是会被当成"通过守门的最小补丁"交出去。跨层视图是唯一说得出
"这两条不是漏配"的地方——这是这个模块存在的理由，不是它的副产品。其余 5 条
（`distributed_isolate_hap:hmcap`、`input_isolate{,_debug}_hap → render_service:
unix_stream_socket`、`normal_hap → dev_file:dir mounton`、`system_core_hap →
download_server:binder`）是共享域上的真缺口，报告现在会把影响面一起说出来。

另一个本来能当头条、实测却哑火的信号：调试/发布域对照（`normal_hap`/`debug_hap`、
`input_isolate_hap`/`input_isolate_debug_hap`，以及 `distributed_isolate_hap` 同域
声明两种 build）。它直接解释"调试能跑、打包就挂"，但在这份语料上**触发 0 次**，
所以留在 evidence 里，不当结论讲。匹配时要求除 debuggable 外全等（APL 集合、`extra`、
`name`、`extension` 都要一样），否则 `input_isolate_debug_hap` 会被当成 `normal_hap`
的调试版——那正是本模块要避免的那类自信的错答案。

### 复现

```bash
python3 -m policy_loop.converge --log data/corpus/real_denials.txt \
  --policy data/raw/oh-selinux/sepolicy --md converge.md   # --md 自带跨层一节
python3 -m policy_loop.explain --policy data/raw/oh-selinux/sepolicy \
  --line '<一条 avc: denied>'                              # 人读输出总带跨层
python3 -m policy_loop.explain ... --json                  # 设备契约：不含跨层键
python3 -m policy_loop.explain ... --json --cross-layer     # 显式打开
python3 -m unittest tests.test_cross_layer -v               # 27 项
```

## 实测（2026-09，真实上游语料，规则索引 21790）

| 批 | 输入 | 唯一 | 可自动修复 | 需人工 | 噪声/已允许 | 说明 |
|---|---|---|---|---|---|---|
| A 真实缺口 | 144 条 replay-uncovered | 134 | 38 | 96 | 0 | 真缺失案例；38 个最小补丁全部通过守门 |
| B golden 全量 | 5161 条 | 4911 | 40 | 3315 | 1556 | 覆盖/已修复不误报成自动补丁（B 列为 M3 之后） |
| C permissive-only | 3557 条 | 3402 | 34 | 1807 | 1561 | 最贴近「permissive 设备 dump」的输入形态 |
| **B′ golden 全量** | 5161 条 | 4911 | **70** | **1580** | **3261** | **neverallow 权限感知修复之后**；当前代码的实测值 |

> **口径**：A/B/C 三行量于 neverallow 权限感知修复**之前**（也即 M3 之后），
> B′ 是同一份输入在**当前代码**下的实测。两行的差别就是上节那笔账：
> `40 → 70` / `3315 → 1580` / `1556 → 3261`，闭合于 `1705` 条从人工移到噪声 +
> `30` 条从人工移到自动。下表几条 bullet 里的 neverallow 命中数（2645 / 1771）同样
> 是修复前的口径。**引用时按需选行**：讲"当前能力"用 B′，讲"修复收益"用 B 对 B′。
> B 批 M3 之前为 3319 / 1552；差值即上节那 4 个"假 neverallow 告警"被消掉，
> `auto_repairable` 前后都是 40。

- 去重比：B ≈ 1.05（上游日志本身每访问一次），A/C 相似；对真实重复刷屏的设备日志
  去重效果会更显著。
- **不误报**：B/C 中已允许（含后来才修复）的 denial **零**落进 `auto_repairable`；
  covered+permissive=1 → 噪声，covered+enforcing → `DOMAIN_OR_LABEL_MISMATCH` 转人工。
- **拒绝越权**：B 的 2645 / C 的 1771 个唯一案例命中 neverallow → 一律不自动放权，
  转人工（多为 HAP 域越权访问，需架构/标签决策，不是加 allow 能解决的）。
- **守门降级**：约四成"看似可修"的案例因主体/目标/类不在语料而被降级人工 ——
  这是**保守而非漏修**：converge 只对能在当前语料证明落点的补丁打"可自动"。

## 落地桥：从收敛报告到 policy.31（`tools/apply_converge.py`）

上面这些补丁此前是**纯数据**：`converge` 吐出 69 行最小补丁就结束，而"把补丁编进
板子策略"那一半在 `device/selinux_policy/` 里、喂的是**手写死**的 `denial_check.cil`。
两端都跑通了，中间却是断的 —— 而项目名里的"从 permissive 收紧到 enforcing"要的正是这一段。

`tools/apply_converge.py` 就是这段：读收敛报告 → 按**板子实际策略**过六道门 →
渲染 CIL → `secilc` 编译 → `checkpolicy` 反编译回验。

六道门（判别对象是板子策略，不是上游语料）：

| 门 | 判什么 |
|---|---|
| 1 解析 | `.te` 语句能解析成 `allow[xperm] src tgt:cls { perms }` |
| 2 符号 | `src`/`tgt`/类的符号存在于板子策略（含 `typeattribute` 闭包） |
| 2b 权限 | 每个权限真属于该类的权限集 |
| 3 幂等 | 板上已允许的直接跳过 —— 可重复跑，不堆重复规则 |
| 4 编译 | `secilc` 编译 |
| 5 回验 | `checkpolicy` 反编译，逐条确认补丁进了二进制、且**没有内容丢失** |

### 实测（2026-10-07，`converge-full.json` 69 行 × `board-5.0.3-fingerprint`）

```
69 输入 → 47 注入（45 allow + 2 allowx）/ 14 板上已满足 / 8 拒
编译产物 policy.31 = 407 546 B，policyvers=31，头部与原版逐字节一致
语义 diff 新增 37 行 / 移除 199 行（0 条内容丢失）；47 条注入全部回验到
连跑两次 sha256 相同；退出码 0
```

三门拦下的 8 行本身就是结论 —— 它们暴露了**语料与板子的版本差**：

- **2 行符号缺失**：`distributed_isolate_hap`、`selection_service` 在 5.0.3 上不存在。
- **6 行 (类,权限) 不成立**：`data_service_el1_file:file { add_name }`（`add_name` 是
  `dir` 的权限、类写成了 `file`）、`persist_param:parameter_service { map open read }`
  （板子的 `parameter_service` 只有 1 个权限，上游后来才加）等。
- **14 行"板上已满足"**：补丁是对**上游 master** 的索引算的，而板子 5.0.3 早就允许了
  其中 14 条。这正是"索引必须与板子同源"那条教训的量化 —— 拿错树的索引会给出
  自信的错答案。

### 三个踩过的坑（都写进了代码注释与单测）

1. **CIL 关键字是 `allowx`，不是 `allowxperm`**。写 `allowxperm` 得到
   `Error: Unknown keyword allowxperm`。反过来也骗人：拿 `xperm` 去 grep 板子策略得
   0 条，而实际有 **714 条** —— 全写成 `allowx`。
2. **括号结构是 `(allowx SRC TGT (ioctl 类 (xperm)))`**，类名在 `ioctl` 之后、
   **不在** allowx 的第三参数位（`cil_fill_permissionx` 要的是
   `STRING(kind) STRING(类) LIST(表达式)`）。写成 `(allowx S T 类 (ioctl 类 (x)))`
   或 `(allowx S T (类 (ioctl (x))))` 都是 `Invalid syntax / Bad allowx rule`。
3. **类的权限不在 `(class X (...))` 里就完了**。`checkpolicy -C` 把继承自 common 的
   权限放到 `(common NAME (...))`、再用 `(classcommon 类 common)` 绑定。只读前半截会
   得出"`file` 类没有 `getattr`"这种离谱结论（实测把 6 条真问题误报成 41 条）。

第 5 门的判据也因此不是"那行字还在不在"，而是**内容有没有被吸收**：反编译会把同一
`(src,tgt,类)` 的授权归并成一行、把 `A A` 归一成 `A self`、把多个 xperm 值并进一个
表达式。实测不做任何补丁的纯 CIL→二进制→CIL 往返就已经有 190 处"移除"（全是
neverallow 残留死属性），按字面串判会全部误报。

⚠️ **第 4 门兜不住 neverallow**：`neverallow` 是编译期断言、不落盘，实测
`board-policy.cil` 里 `(neverallow` 出现 **0 次**。所以"编译过了"≠"没撞 neverallow"。
这条防线由 converge 自己的索引提供（neverallow 一律转人工，不进 `auto_patch`）。

装上板子是**另一步**（会改设备状态，本工具不代劳）：
`bash device/selinux_policy/install_to_board.sh`。

## 边界与已知局限

- **落地桥的最后一跳仍是人工**：`apply_converge.py` 产出 `policy.31` 并回验，
  但把它刷进板子（`install_to_board.sh` → `/system/etc/selinux/.../policy.31` +
  `load_policy`）需要人按一下 —— 这是刻意的，不是缺口。
- **ioctl-only 缺口**：当唯一缺失权限是 `ioctl` 且策略既无 `allow ioctl` 也无
  allowxperm 白名单可指时，修复路径可能给出空权限补丁 → 守门 5 兜住转人工。
  真正的 allowxperm 最小补丁生成是后续工作（Review/Verify 语义本轮不动）。
- **service 映射的剩余缺口**：数字 `service=` + `get`（客户端访问远端 SA）解析不了，
  需要外部 samgr id→name 注册表，当前一律转人工。占位符解析只用于查询，
  **不进补丁也不进守门**（理由见 M3 节）。
- **快路 vs 闭环等价性**：快路判定与 `SecurityAgent.classify` 对 `(neverallow,
  ioctl, all_allowed, permissive)` 的决策一致；两种情况下已允许类 denial 不会进
  Repair/Review 的补丁路径。
- 报告口径诚实：`exact_min` 类自洽指标不对外夸大为独立金标准；收敛就绪度只服务
  "permissive → enforcing" 的决策，真机回归在 L4。

## 复现

```bash
# B′：当前代码的全量收敛 —— 仓库内 data/reports/converge-full.json 就是这条命令的产物
python -m policy_loop.converge \
  --log data/corpus/real_denials.txt \
  --policy data/raw/oh-selinux/sepolicy \
  --json data/reports/converge-full.json
#   期望：denials=5161 unique=4911
#         by_category={'needs_human': 1580, 'noise_or_already_allowed': 3261,
#                      'auto_repairable': 70}          （≈4.1 s，规则索引 21790）
#   确定性：连跑 3 次输出逐字节相同（sha256 8f91d5b7cf2bc1fa…），退出码 0。

python -m unittest tests.test_converge -v        # 27 项
python -m pytest tests/ -q                       # 全套 196 项（192 passed + 4 skipped）
```

> ⚠️ **`data/reports/converge-permissive.json` 与 `converge-uncovered.json` 是修复前的历史批次**
> （对应上表 A / C 两行），**不要重新生成** —— 它们的数字刻意停在 neverallow 权限感知修复之前，
> 与本节的 B′ 不是同一口径。仓库内**只有 `converge-full.json` 代表当前代码**。
>
> ⚠️ **报数时的单位**：`auto_repairable` = **70 是案例数**；`auto_patch_lines` = **69 是补丁行数**
> （其中一条补丁覆盖了 2 个案例）。`related-work-audit2allow.md` 里「2833 vs 69 条补丁」用的是**行数**，
> 与本表不矛盾，引用时点明单位即可。

M3 的两侧等价性不靠单测，靠设备端五项门禁（见 `eval-L4.md`）：解析逻辑在
`pl_converge.cpp::ResolveLogicalTarget` 独立重写了一遍，`--selftest` 新增 8 组固定向量
逐分支比对，报告差分在真机上逐字节相同。

其中"候选是否已声明"这一步，Python 用 `cand in type_attrs or cand in attributes`，
C++ 用 `PlIndex::IsDeclaredTypeOrAttr`（`typeNames_ ∪ attrNames_`）——**两个判定集合
在真实索引上实测完全相同**：`type_attrs` 键 1267 = PLI 的 `@type` 1267，
`attributes` 49 = PLI 的 `@attr` 49，并集 1316 = 1316。所以这一步不是"恰好通过测试"，
而是集合相等。

> 语料 `data/raw/oh-selinux` 不入库；无语料时 converge 走 no-index 去重路径。
