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

## 3. neverallow 防线（2026-10-07 已从"漏"补到"能拦"，下方注明残余）

背景：neverallow 是**编译期断言，不落盘** —— 实测板子反编译出的 `orig.cil` 里 **0 条 neverallow**。
所以「`secilc` 编译通过」本身不证明没撞 neverallow：**除非**待编译的 CIL 里重新写出断言。

✅ **2026-10-07：落地桥（`tools/apply_converge.py`）把板子对应源树的 neverallow 翻译并注入
待编译的 CIL，门 4 由"可编译性检查"变成"红线检查"** —— 现在 `secilc` 编译通过**确实**证明没撞
这些红线。翻译是**精确**的（不是近似）：类型位置的集合写法 → CIL 的 `(or …)`／`(and …)`／
`(not …)`（合成属性后引用），`*` → `(all)`，`~attr`／`~{…}` → `(not …)`，`self` 用 CIL 自己的
关键字，类集／权限集宏就地展开，`~{权限}` 按**板子反编译出来的**该类权限表求补，32 位命令号按
源树语义截成 16 位（`policy_define.c:1973,1993` 的 `(uint16_t)`），xperm 取反补成 `(range lo hi)`。

实测（板子树 5.0.3 `0878c56e3`，分母 = 源树 494 条 neverallow／neverallowxperm 语句）：

| | 值 |
|---|---|
| 注入断言 | **710 条**（+ 632 条合成属性声明） |
| 覆盖语句 | **404 / 494 = 81.8%**（此前 39 条 / 7.9%） |
| 跳过 | 90 条：88 条含 `developer_only`/`updater_only`/`debug_only`/`non_developer_mode` 条件（38/32/17/1）、1 条板上空转、1 条真畸形（`usb_service.te` 的 `;;`） |

两条独立证据，不是"看起来像检查"：

- **零误报**：`board-policy.cil` + 全部 710 条断言一起编译 **rc=0** —— 板子自己的策略满足每一条重述；
- **造违例必报**：按 6 类形态分层抽样 18 条，各造一条对应 `allow` ⇒ **18/18 触发**
  （`/tmp/xp/q*.cil`）。

🔴 **补完之后立刻抓到了真问题**：拿真实 converge 报告（69 行补丁）跑落地桥，**3 条红线冲突被抓**
（4 行 allow），工具退出码 1：

| 撞线补丁 | 被哪条红线拦下 |
|---|---|
| `allow normal_hap sys_file:file { open read }` | `normal_hap.te:46` `neverallow normal_hap_attr sys_file:file never_rw_file;` |
| `allow storage_daemon fuse_file:filesystem { unmount }` | `filesystem.te:18` `neverallow storage_daemon ~{ exfat … labeledfs }:filesystem unmount;` |
| `allow sa_device_standby resource_schedule_service:samgr_class { add }` | `domain.te:165` `neverallow * ~sa_service_attr:samgr_class ~list;` |

三条分别落在**并集／属性差集／`*`+`~attr`+`~权限`** 三种新翻译形态上。补完之前这三种形态一律
"形态不合"跳过 ⇒ 这 4 行会被放行，门 4 报"✓ 编译通过"。删掉这 4 行后其余 45 行 + 710 条断言
编译 **rc=0**（`policy.31` 494,019 B）—— 即这对正／反例都走过真工具链。

残余（**本节仍未关闭的部分**）：

- 88 条条件表达式（`developer_only` 等）**未注入**：它们是否生效取决于构建配置，跳过是如实计数，
  但这 88 条红线在门上仍是真空；
- §2.1 的三条正则漏掉的 **164 条 neverallow 根本没进索引**（46 + 68 + 50）—— 那是 **converge
  索引查询**那条防线（`policy/index.py`），与上面这条 secilc 防线**相互独立**，本次未动；
- 已做的核对：把其中能结构化解析的 **72 条**与当前 69 行补丁逐条比对（src／tgt／类／权限，含属性闭包
  与 `~{}` 语义）⇒ **0 条冲突**。

所以现在是**两道防线**：索引查询（覆盖面有洞，见上）+ 编译期断言（81.8%，实测能拦）。
答辩口径应说"两道，各自的洞如下"，不能说"neverallow 一律拒放权"。

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

- ✅ **板子版本口径已统一（原为冲突项）**：板子实测 `const.ohos.fullname =
  OpenHarmony-5.0.3.135`（API 15 / kernel 5.10.208 / enforcing），`policy.31` = 424,699 B、
  sha256 `20d8805c…`，上下文文件三项（`file_contexts` 513 / `sehap_contexts` 15 /
  `service_contexts` 350）逐条对上 `OpenHarmony-5.0.3-Release` @ `0878c56e3`
  ⇒ **索引对齐该树**（板端 HAP 内置索引即是，rev `e1160d2c`，19,800 条）。
  `docs/eval-L4.md` 原写「6.1 Release」**是事实错误，已改**。
  ⚠️ 但**编译树** `~/ohos_src` 确实是 **6.1.0.31** —— 设备端二进制由它交叉编译，
  与「板子是 5.0.3.135」并不矛盾，两处口径不要互相套用；
- 语料同源：5,161 行 **96.8% 逐字来自上游 `.te` 注释**，自证色彩重于独立采集（`eval-trust` 已做质检，
  但根上同源）；
- ✅ **HAP 源码已镜像进本仓**（`device/pl_console`，`tools/build_hap.sh` 的 `PROJ` 默认指向它）
  ⇒ 第三方 clone 仓库即可构建板端控制台；**构建**离线可做（`./tools/build_hap.sh build`，
  实测 2–3 s），**签名/装机**才需要本机 UDID 与 hdc。原记 🟡「源码在仓外
  `~/ohos_audit/pl_console`」已不成立；
- 索引口径：语料索引 **21,790** 条 vs HAP 内置 **19,800** 条（rev `e1160d2c`，取自 5.0.3 树
  `0878c56e3e41`），已在 `docs/report.md:646` 标注待统一说明。

## 6. 处置一览

| 项 | 成本 | 建议 |
|---|---|---|
| §2.1 放宽三条正则（连带补全 §3 的 neverallow 防线） | 半天 + 重跑五项门禁 | **建议做**：同时修掉一个错判与一个安全盲区 |
| §3 的答辩口径 | 0 | 无论做不做，都必须能说清 |
| §5 板子版本二选一 | 0.5 h | 提交前必做 |
| §7 CPython 3.13 间歇崩溃 | 已做 | **已定位+已处置**：钉 3.12、加 `tools/stability_gate.py`；现场命令一律用 `python3.12` |
| §4 hisysevent 应用层入口 | 大 | 24 天内不碰，作为「下一步」写 |
| §2.2 boolean／constraint 诊断、dontaudit 建模 | 大 | 不碰：要动索引模型 + PLI 格式 + C++ 镜像 + 重验逐字节差分 |

## 7. 运行时：CPython 3.13 上的间歇性 SIGSEGV（已定位到解释器内部）

> **一句话**：本项目**支持的运行环境是 CPython 3.12**。3.13 上核心路径会以
> 0.7%–10% 的概率随机段错误，换 3.12 后 480 轮零崩溃；崩溃点在
> `_PyEval_EvalFrameDefault` 内部，**改 `key=str`、甚至完全不排序都不解决**，
> 因此不是本项目某一行的写法问题。

### 7.1 实测数字

| 负载 | 解释器 | 轮数 | 崩溃 | 崩溃率 |
|---|---|---|---|---|
| `load_dir` 最小复现器 | 3.13.13（conda-forge） | 200 | 7 | 3.5% |
| 同上，关 ASLR（`setarch -R`） | 3.13.13 | 200 | 9 | 4.5% |
| 同上 | 3.13.7（Ubuntu 系统包） | 60 | 2 | 3.3% |
| 合成负载（不含本项目任何代码） | 3.13.13 | 137 | 1 | 0.7% |
| 纯 `sorted(rglob("*.te"))`，不 import 本项目 | 3.13.13 | 200 | 0 | 0% |
| **4 行复现器：`import policy_loop.policy` + 纯 `sorted(rglob)`** | 3.13.13 | 200 | 2 | **1.0%** |
| 只 `import policy_loop.policy`，不排序 | 3.13.13 | 200 | 0 | 0% |
| **`tools/stability_gate.py` 现场跑** | 3.13.13 | 60 | 6 | **10.0%** |
| **同上** | **3.12.14** | **60** | **0** | **0%** |
| `load_dir` 最小复现器 | 3.12.9 / 3.12.14 | 480 | 0 | 0% |

两个**独立构建**（conda-forge 3.13.13 与 Ubuntu 3.13.7）都崩 ⇒ 不是某个发行版
打包出来的问题。同一台机器、同一份输入，崩溃率在 0.7%–10% 之间波动 ⇒
「间歇性」本身也是可观测的量，而不是偶发噪声。

### 7.2 崩溃点

`python -X faulthandler` 拿到的是 Python 层（`tools/stability_gate.py` 会把首次
崩溃的回溯自动落盘，默认 `/tmp/policyloop-stability-crash.log`）：

```
Fatal Python error: Segmentation fault
  File ".../python3.13/pathlib/_local.py", line 202 in _parts_normcase
  File ".../python3.13/pathlib/_local.py", line 210 in __lt__
  File ".../policy_loop/policy/index.py", line 692 in load_dir
  File ".../policy_loop/policy/__init__.py", line 22 in load
```

gdb 拿到的是 C 层（注意 `set disable-randomization off` —— gdb **默认关 ASLR**，
不改这一项 40 轮复现不出来）：

```
#0  _PyEval_EvalFrameDefault     Python/generated_cases.c.h:4312   ← SIGSEGV
#5  vectorcall_unbound           Objects/typeobject.c:2581
#6  slot_tp_richcompare          Objects/typeobject.c:9725
#7  unsafe_object_compare        Objects/listobject.c:2732
#8  binarysort                   Objects/listobject.c:1834
#9  list_sort_impl               Objects/listobject.c:3078
#13 builtin_sorted               Python/bltinmodule.c:2515
```

即：`sorted()` 的比较回调刚跨进解释器就踩空。

### 7.3 已排除的假设（每条都有对照实验，不是推理）

| 假设 | 证伪方式 | 结论 |
|---|---|---|
| 本项目代码有 UB | 合成负载不含本项目任何一行，照样崩 | ❌ 排除 |
| 内存压力 / OOM | 峰值 RSS 95 MB、机器空闲 18 GB、`journalctl -k` 无 MCE | ❌ 排除 |
| 堆破坏 | `PYTHONMALLOC=debug` 全程零诊断（仍崩，但无腐败报告） | ❌ 排除 |
| ASLR | `setarch -R` 4.5% vs 基线 3.5% | ❌ 无差异 |
| `gc.disable()` 是解药 | 40 轮 0 崩后第 128 轮又崩（换了个错：`SystemError: … METH_METHOD`） | ❌ 只改变失败形态 |
| `sorted(Path)` 这一行是根因 | ①三个变体各 200 轮：baseline 7 / `key=str` 4 / 完全不排序 3，统计上无差异；②**把这一行单独拎出来、零项目代码跑 200 轮：0 崩** | ❌ 两条独立证据 ⇒ 那是**崩溃落点**，不是触发点 |
| `ulimit -v` 是测试脚手架伪影 | 带/不带各 12 轮 A/B，均 0 崩 | ❌ 排除 |

**「落点 ≠ 触发点」是这次定位最值钱的一条**：`sorted()` 只是第一个踩到已经坏了的
解释器状态的地方，把这一行改掉（`key=str`）或删掉（不排序）都不解决，而把它
单独拎出来又 0/200 不崩 —— 说明损坏发生在它之前，且需要一个**更长的前置过程**
才攒够。这也是为什么只读代码找不到它：出错的位置和写出错的位置不在一起。

> ⚠️ **统计纪律**：崩溃率在 1%–3% 量级时，n=200 的 95% 置信区间宽达 ±1%–2%
> （如 7/200 的区间约 [1.4%, 7.1%]，2/200 约 [0.1%, 3.6%]）。因此
> 「0/200 vs 2/200」**不构成**"import 是必要条件"的结论 —— 本表只用于
> **排除**那些差异足够大、或有多条独立证据的假设（如 `key=str`、纯排序），
> 不用来断定某一步"必然"参与。上表中凡是差异落在噪声内的，一律不升格为结论。

最小的自足复现器（4 行，不依赖本仓任何内部数据，只依赖语料目录）：

```python
from pathlib import Path
import policy_loop.policy            # noqa: F401
paths = sorted(Path("data/raw/oh-selinux/sepolicy").rglob("*.te"))
```

跑法：`for i in $(seq 200); do python -X faulthandler repro.py || echo CRASH; done`。

### 7.4 与上游已知问题的对应

CPython 3.13 有一族已公开的崩溃：gh-131998 / gh-132011（未绑定方法描述符，
**3.13.3 已修**，我们两个构建都晚于它 ⇒ 不是这两条）、**gh-148450**
（`tp_flags` 变更不递增 `type_version` ⇒ 特化解释器／JIT 缓存陈旧；上游称会
backport 到 3.13，**至今未 backport**）、#158031（同一条
`vectorcall_unbound → slot_tp_richcompare` 路径上的 UAF）。

> ⚠️ **口径**：与上述条目是**形态吻合，不是确证同因**。我们能确证的是
> 「崩溃在解释器内部、只在 3.13 出现、3.12 干净」；**不能**断言"就是 gh-148450"。

### 7.5 处置

- `pyproject.toml` 钉 `requires-python = ">=3.10,<3.13"`；
- 新增稳定性门 `tools/stability_gate.py`：**逐轮拉全新子进程**（崩溃是直接杀进程，
  Python 层的 try/except 根本捕不到），`python3.12 tools/stability_gate.py --runs 200`，
  零崩溃 exit 0、出现崩溃 exit 1、首次崩溃的 faulthandler 回溯自动落盘，
  `--json` 出机器可读结果；
- **现场所有 PC 侧命令一律用 `python3.12` 跑**（附录 A 的复现命令、视频里的终端片段）；
- **板端不受影响**：板子上跑的是交叉编译的 C++（`denial_check` / `pl_collector`），
  与宿主解释器无关 —— 这也是为什么演示台上的实时闭环路径不在此风险的暴露面内。

**改成 3.12 会不会让已录的门禁数字失效？不会，已实测**：同一份语料、同一份索引，
`converge --json` 在 3.12.14 与 3.13.13 上的输出**逐字节相同**
（sha256 均为 `8f91d5b7cf2bc1fa…`），`selfcheck` 两侧都是 9/9 PASS，
单元测试两侧都是 338 通过 / 4 跳过。即：**换解释器只消除崩溃，不改变任何结论** ——
这也是敢把「运行环境钉 3.12」写进复现附录的前提。
