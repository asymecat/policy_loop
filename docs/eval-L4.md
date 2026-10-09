# 设备端组件（L4 / `denial_check`）

> 把 L1–L3 引擎里**最小可独立验证的一段**——denial 解析、策略查询、最小收敛——
> 用 C++ 重写为 OpenHarmony 原生可执行程序，装进系统镜像，**在设备上自己判断
> 自己的策略缺口**，不依赖上位机。
>
> 硬约束：**只输出建议补丁文本，绝不自动写盘。**

## 为什么要有这一层

L1–L3 跑在宿主机的 Python 上。这在工程上没问题，但有两点说不通：

1. **审计设备自己的策略，不该以「手边必须有一台 PC」为前提。** 一台已经在现场
   运行的设备，它的策略缺口是它自己的事实，读懂这个事实的能力就应该在它身上。
2. **赛道一评的是「系统与技术创新」。** 一个只能插着 PC 才能跑的上位机脚本，
   和一个装在 `/system/bin` 里、PATH 上直接可呼的系统组件，是两种东西。

所以 L4 不是「把 Python 翻译成 C++」，而是**把这条流水线里真正属于设备的那一段
搬到设备上**，然后用差分验证证明它和宿主机引擎逐字节等价。

## 为什么只是「一段」，而不是整个 PolicyLoop

这是最容易问、也最该问的问题。答案是：**剩下的部分不是「还没搬」，而是「搬不过去」。**

### 一、设备上根本没有策略源码

实测 DAYU200（OpenHarmony 5.0.3.135）上 SELinux 的全部家当：

```
/system/etc/selinux/config                      # SELINUX=enforcing
/system/etc/selinux/targeted/policy/policy.31   # 编译后的二进制策略, 424699 B
/system/etc/selinux/targeted/contexts/file_contexts       # 33575 B
/system/etc/selinux/targeted/contexts/service_contexts    # 27034 B
/system/etc/selinux/targeted/contexts/parameter_contexts  #  9011 B
/system/etc/selinux/targeted/contexts/hdf_service_contexts # 6139 B
/system/etc/selinux/targeted/contexts/sehap_contexts      #  1442 B
```

`find /system /vendor -name "*.te"` → **空**。设备上一条 `.te` 源码都没有。

而索引（PLI）是从 `.te` 源码树构建的：`data/raw/oh-selinux/sepolicy`，实测
**21824 条规则、1267 个类型、49 个属性**，另有 524 条语句被跳过。索引里还带一张
**`@hap` 桥表**（`sehap_contexts` 导出：17 条声明 / 13 个应用域 / 3 个 APL 等级）。

### 二、就算想从二进制策略反推，也反推不出来——neverallow 不在里面

这不是「暂时没做」，是**原理上做不到**。`neverallow` 是**编译期断言**，不进入内核策略。

`third_party/selinux/libsepol/src/expand.c:2736` 的注释原文：

> *Neverallow rules are copied or expanded as per the settings in the state object;
> all other AV rules are expanded. If neverallow rules are expanded, they are **not
> copied**, otherwise they are **copied for later use by the assertion checker**.*

即：neverallow 只在编译期留在内存里供 `check_assertions()` 核对，**不写进产出的
策略**；而若真要把 neverallow 展开进最终策略，代码会置 `state->out->unsupported_format = 1`
——**内核策略格式根本不支持**。

而 OH 的策略里有多少条 neverallow？索引实测：

| 规则类型 | 条数 |
|---|---|
| `allow` | 20754 |
| **`neverallow`** | **392** |
| `allowxperm` | 634 |
| **`neverallowxperm`** | **10** |

**这 402 条红线恰好是这个工具最关键的一道守门。** converge 的第一条快路判定就是
「撞 neverallow → 直接转人工，拒绝自动放权」（见 `eval-converge.md`）。设备上拿不到
neverallow，这条判定就无从谈起——工具会退化成「看到 denial 就建议放权」，正是它
最该避免的行为。

所以索引必须由**构建期**从上位机的策略源码树导出，作为数据文件随镜像下发。这是
架构约束，不是偷懒。

### 三、L1–L3 里还有大量本就不属于设备的东西

多智能体闭环（LLM 调用）、`eval/trust.py` 的 golden 质检、replay 回放——这些是
**开发期的验证手段**，不是运行时设备功能。你不会往一块 RK3568 上装 Python 运行时
加一整套 agent 栈，只为了让它审计自己的策略。

设备端要的是**确定性内核**：给定日志和索引，算出结论，不联网、不调用模型、可复现。

### 四、因此设备端的实际能力边界

| 能力 | 在设备上 | 说明 |
|---|---|---|
| denial 解析 / 指纹去重 | ✅ | 核心 C++，零 OH 依赖 |
| 策略查询（`has_access` / `neverallow` / `ioctl`） | ✅ | 读 PLI，不需源码 |
| 逐条判定（`--case`：分类 + 补丁 + 六道守门） | ✅ | 固定 API，宿主自己拆好字段送进来 |
| 单条诊断（`--explain`：分类 + 最小补丁 + **同样六道守门** + 跨层视图） | ✅ | 守门在解释路径上也要跑（E），跨层视图需索引带 `@hap` |
| 最小收敛（批量报告） | ✅ | 确定性，无 LLM；本机自足路径，不依赖宿主 |
| 采集本机 kmsg | ✅ | `hilog -x -t kmsg` |
| **构建 PLI 索引** | ❌ | 需要 `.te` 源码，且 neverallow 原理上不在二进制策略中 |
| 多智能体闭环 / eval / trust | ❌ | 开发期手段，非运行时功能 |

分工的边界由此明确：**策略语义在设备上**（索引、判定、守门），**agent 编排在主机上**。
设备只回答"这条 denial 在策略上是什么、补丁是什么、能不能自动落地"，不决定要不要做、
不写盘、不联网。宿主负责读哪份日志、按什么顺序问、拿到答案后做什么。

`--case` 是这条边界上的固定接口：一行一条已拆好字段的记录进，一行一个 JSON 判定出。
它和批报告走同一份判定代码（`ExplainCase` + `ApplyGuards`），因此两者的答案不会漂——
`tests/diff_device.py case` 模式对全部 4,911 个唯一 case 逐字段验证了这一点。

## 用法

```bash
# 自检：内嵌固定向量，不依赖任何外部文件
denial_check --selftest

# 查看索引装载情况
denial_check --index <pli> --index-info

# 读设备自己的 kmsg，做最小收敛
denial_check --index <pli> --log-cmd "hilog -x -t kmsg" --timeout-ms 15000 --converge

# 对一份 denial 日志做收敛
denial_check --index <pli> --log <日志文件> --converge

# 批量策略查询（TSV: src\ttgt\tclass\tperm,perm\tioctlcmd）
denial_check --index <pli> --query <queries.tsv>
```

`--converge` 需要 `--index` **和**一个日志来源（`--log` 或 `--log-cmd`），两者缺一
则打印用法退出。

## 五项门禁

设备端组件声称「和宿主机引擎给出同样的结论」。这个声称只有在被检查过之后才值钱。
五项门禁各自证明一件不同的事：

| # | 门禁 | 做法 | 证明什么 |
|---|---|---|---|
| 1 | `--selftest` | 内嵌 24 组 converge + 11 组 explain 固定向量，比对冻结的表 | **逻辑对**。期望值由宿主机 Python 生成并冻结，**不是拿 C++ 自己的输出当答案** |
| 2 | `--index-info` | 两端加载同一 PLI，比计数器 | **数据没坏**。规则数/类型数/属性数/跳过数与宿主逐个相等 |
| 3 | 报告差分 | 同一份语料，两端各出完整 JSON 报告，比 sha256 | **端到端结论一致** |
| 4 | 真机采样 | 真读本机 kmsg | **采集通道在设备上真能工作**，并量化 printk 丢帧 |
| 5 | 查询差分 | 27912 条查询，比整个输出体的 sha256 | **最细粒度判定一致**（覆盖 5 个字段） |

### 关于门禁 3 和 5 的方法

报告是**单行 4.4 MB**，查询输出是 **2.98 MB / 27912 行**——低带宽链路上回传不现实。
但 `WithDeviceBlock()` 只是把 `, "device": {…}` 拼在报告末尾（`pl_report.cpp`），
所以两端各自 `sed 's/, "device": {.*//'` 切掉尾块再比 sha256 即可，只需传 64 个字符。

查询差分比的是**整个输出体**的 sha256，一次覆盖 `allowed` / `granted[]` /
`ioctl_allowed` / `ioctl_reason` / `neverallow` 五个字段——比逐字段计数更强：
2.98 MB 逐字节相同，意味着这五个字段不可能有任何一个偏。

## 真机验证结果（2026-09-14，DAYU200 / RK3568 / OH 5.0.3.135）

> 同日 M3（service 占位符解析）落地后**全部门禁重跑于新二进制**，见本节末尾。

```
二进制      /system/bin/denial_check   137604 B   32 位 ARM musl 动态链接
            动态依赖仅 libc / libc++ / libm —— 不 include 任何 hilog/selinux 头
索引        ohos-rk3568.pli  1239637 B  sha256 8c5529d9…e8ee4  (设备与宿主一致)
            —— 2026-10-09 重建后 1250619 B / 7d75d6fc…52c0d；本次真机结果量于旧索引
语料        real_denials.txt  5161 条
```

| # | 门禁 | 结果 |
|---|---|---|
| 1 | `--selftest` | **PASS**，sha1 13 组 + converge 21 组 + neverallow 2 探针，0 失败（当日形态；2026-10-09 扩到 converge 24 + explain 11）|
| 2 | `--index-info` | `rules=21790 types=1267 attrs=49 skipped=647 rev=cc0afe737eb9`，与宿主一致 |
| 3 | 报告差分 | 与宿主**逐字节相同** `e04838b0…8f4d7e` |
| 4 | 真机采样 | `suppressed≈107` **非零**；620 条观测 + 107 条被 printk 吞掉 |
| 5 | 查询差分 | 27912 条 / 2984884 B **逐字节相同** `9076f293…7f9b66`（M3 未触及查询路径） |

宿主侧参考值（`data/corpus/real_denials.txt`，`converge --json`）：

```
total_denials : 5161
unique_cases  : 4911
by_category   : needs_human 3315 / noise_or_already_allowed 1556 / auto_repairable 40
```

### M3 后的重跑（同一台设备，新二进制 142740 B）

新增的 8 组固定向量专门覆盖 service 解析的每个分支（可解析的具名/数字-自注册两类、
以及四类**拒绝解析**：数字 `get`、候选未声明、类不匹配，外加"解析成功但补丁仍写占位符"
那道守门兜底）。设备端 `--selftest` 一次通过，报告差分与宿主仍**逐字节相同**——
说明 C++ 独立重写的 `ResolveLogicalTarget`（走 `IsDeclaredTypeOrAttr`，与 Python 的
`cand in type_attrs or type_attrs` 同义）在真机 32 位 ARM 上逐分支与 Python 一致。

其中最有价值的一组是**守门兜底**那组：它断言 `review=APPROVE`、`verify=SUCCESS`，
类别却仍是 `needs_human`。补丁确实通过了评审和验证——唯一拦住它的就是占位符守门。

**代价（旧值，量于按对象类线性扫描的版本）**：设备 27912 条查询 71.25 s（2.55 ms/条，
含 297 ms 索引装载）；宿主同工作量 40.85 s（1.46 ms/条）。RK3568 四核 A55 对桌面 x86
约 1.7 倍，是合理量级。

> ⚠️ **上表这行已被后来的类型对索引取代，见下节「D：查询路径换成类型对索引」。**
> 保留旧值是为了让提速倍数有出处，不是当前性能。

**为什么 2.98 MB 逐字节相同是有说服力的证据**：两端是**独立实现**（Python vs C++），
喂完全相同的输入。这个项目里真实存在的语义陷阱——空 perms 是通配而非空集、
xperm 命令是不透明字符串且大小写敏感、`permissive=2` 是三态不是布尔、通配规则命中时
未知 perm 名要原样带上——只要错一个，哈希当场炸掉。我们不是「相信」两端一致，
是让它们互相证明。

### E 的两处补完（2026-10-09，宿主侧已复跑，**上板待办**）

E 是「把两个半成品接口补完」，两半都在设备侧：

**第一半，`--explain` 补上六道守门。** 守门原本内联在 converge 的聚类循环里，
于是——开发者手里捏着一条坏日志、最会用 `--explain` 追问的那条路——它给出的补丁
恰恰是守门会拒绝的那个。现在两端各有一份 `apply_guards` / `ApplyGuards`，converge
与 `--explain` 调的是同一份：同一条记录从哪个入口问，都必须拿到同一句话
（宿主侧 `tests/test_converge.py::TestGuardsAreOneFunctionTwoCallers` 6 项钉住这条不变量）。

**第二半，设备端 `@hap` 解析与跨层视图。** 索引此前带 `@hap` 段而设备**不认它**——
`--index-info` 里的 hap 计数器解析进来就被丢掉，改动前把 17 行 `@hap` 全删掉，
设备照样静默装载。现在 `@hap` 进 `hapByDomain_`，计数器真自检（自证：删掉那 17 行，
设备报 `PLI self-check failed: hap_entries declares 17 but the @hap lines give 0`，
rc=3）；`--explain --cross-layer` 复用同一张表复现宿主的跨层视图。

> **为什么跨层视图必须搬进索引**：它的结论（"这是 APL 分级边界" vs "这是漏配的规则"）
> 完全由 `sehap_contexts` 决定。⚠️ 板子上**是有**这个文件的（`/system/etc/selinux/
> targeted/contexts/sehap_contexts`，1442 B，见上文清单）——我一度写成"设备上没有该
> 文件"，**是错的**。真实理由有两条：① `denial_check` 是单文件工具，只吃
> `--index <pli>`，不读任何别处的文件；② 宿主索引来自 `.te` 源码树，两边**只有喂
> 同一份 PLI** 才对得上。所以桥表得随索引走，而不是靠设备自己再解析一遍。

**宿主↔设备差分（2026-10-09，`/tmp` 下宿主平替构建，非 ARM 交叉产物）**：

```
索引   build/pli/ohos-rk3568.pli  1250619 B  sha256 7d75d6fc…52c0d  rev a1c8e04358d2
       (源 data/raw/oh-selinux/sepolicy@29a2fc123dd1，gen 2026-10-09T11:02:30Z)
计数器 rules=21824 types=1267 attrs=49 skipped=524
       hap_entries=17 hap_domains=13 hap_names=8 hap_apls=3 hap_debuggable=3 hap_skipped=0
```

| 门禁 | 结果 |
|---|---|
| 1 解析差分 | **OK** 5161 条逐字节相同 |
| 2 索引差分 | **OK** 27912 条查询逐字节相同（含 `@hap` 计数器与宿主一致） |
| 3 报告差分 | **OK** `denials=5161 unique=4911 by_category={needs_human 1580, noise_or_already_allowed 3261, auto_repairable 70}` |
| 4 单条判定差分 | **OK** 200 案 |
| 5 解释差分 | **OK** 4911 案逐字段相同（跨层键是 opt-in，`--cross-layer` 不给就不出现） |
| 6 跨层差分 | **OK** 4911 案逐字段相同 |

> **这里此前是个洞，成因值得记一笔**：`--explain` 原本**不跑守门**（守门内联在
> converge 的聚类循环里），所以 `advisory` 字段永远是空串，差分也就永远只比空串——
> 解释路径上唯一承载"拒绝"的字段，恰好是门禁从来不碰的字段。
> ⚠️ **我一度把它写成"语料里 0 条守门拒绝"，这是错的**：守门一接上解释路径，
> 4911 条唯一案例里立刻有 **90 条**带非空 `advisory`，且六道守门**一道不缺**——
> MLS 级目标 5 / 占位符 13 / 未知 token 59 / 未知对象类 6 / 非权限名 3 / 空权限补丁 4。
> 也就是说**语料本来就能覆盖全部分支**，缺的只是让它们跑起来的那次调用；因此门禁
> 不需要任何人造向量，`compare_json` 逐键比 `advisory` 就够。
> （教训：**"某个字段没被比过"要先问是字段取不到值，还是产生该值的代码没跑**——
> 这两者看起来一模一样，但修法一个在数据、一个在引擎。）

**上板待办（板子当前离线）**：ARM 交叉产物重编 + 上面六项在真机复跑 + 索引重推
（`/data/local/tmp/ohos-rk3568.pli` 仍是 9 月那份 1239637 B）。宿主侧能证的部分已证完；
`--cross-layer` 与 hap 计数器**尚未在任何真机上跑过**，交付前必须补，措辞上不要含糊。

### D：查询路径换成类型对索引（同一台机器上量的 A/B）

原来每次查询都遍历**该对象类的全部规则**（`_rules_for_class` 缓存分成类，但类内仍是
线性），逐条跑 `_matches`。改成**类型对 postings**：建索引时把每条规则按
`(kind, 侧, 类, 记号)` 挂进倒排表（星号规则另挂一张），查询时只取「主体记号 ∪ 主体属性
∪ 星号」与「目标记号 ∪ 目标属性 ∪ 星号」的**交集**，`_matches` 只跑在这些候选上。
设备端 `pl_index.cpp::BuildCandidates/Candidates` 是同一算法的 C++ 实现。

关键不在倒排表本身，在**怎么和修复闭环共存**：`_hit_index()` 返回
`(base, postings)`，clone 直接继承父索引的 postings 并把 `base` 钉在父的当前长度，
于是 ~10 ms 的构建**每棵索引树只做一次**；补丁追加的规则落在 `base` 之后，由尾部
线性扫描接住（`_rule_hits` 的两段式）。若换成「一追加就重建」，一次 converge 要付
**151 次**构建。

**A/B 全部在同一台机器上量，两侧用各自的真实实现，输出逐字节相同**：

| 侧 | 改动前 | 改动后 | 倍数 |
|---|---|---|---|
| 设备查询路径（同一份 27912 条查询，两个二进制都输出 2984884 B） | 2.755 s / 0.0987 ms·条⁻¹ | 0.081 s / 0.0029 ms·条⁻¹ | **34×** |
| 宿主判定路径（语料 4911 唯一案例 × has_access+neverallow+ioctl） | 8.842 s / 1.800 ms·案⁻¹ | 0.037 s / 0.008 ms·案⁻¹ | **238×** |

> 「改动前」的设备侧是**从 `HEAD` 的 `device/` 源码重新编译出来的真二进制**
> （`git archive HEAD … && ADAPTER=/tmp/head_adapter ./tools/devbuild.sh release`），
> 不是把新代码改回去估的；两侧喂同一个 `queries.tsv`。两个倍数不同是因为**负载不同**
> （设备那份是按类采样出来的查询集，宿主那份是收敛的真实案例集）。
> 板端 71.25 s 是**旧代码在 RK3568 上**的实测 ⇒ 按 34× 外推约 **2 s**，但**这是外推、
> 不是测量**，上板后必须复测。

## 最有价值的一条发现

`--selftest` 首跑就抓出 **2 个偏差**，而 **4911 簇真实语料完全没抓到**。

- 现象：`default_service` / `sa_binder` 被判成「未知 token → 转人工」，宿主判
  `auto_repairable` / 走「未知 class」分支。
- 根因：C++ 的 `known` 集合原本只从规则的 src/tgt 重建，漏了 `index.type_attrs`。
- **为什么真实语料抓不到**：真实语料里的 token 几乎都在某条规则里出现过，所以
  「声明了但没被任何规则引用」的类型只在人造小策略上出现。

→ 教训：**差分语料证明不了覆盖率。** 固定向量按分支专门设计（每个 category 3 组、
每个 classification 5 组，外加缺 scontext / 缺 tclass / MLS 级 tcontext 三类畸形记录）。

⚠️ **2026-10-09 补齐**：此前 21 组 converge 向量只钉住六道守门里的 **3 道**
（占位符 4 组、未知 token 1 组、未知对象类 1 组），另外 3 道（MLS 级目标 / 权限位含
非权限名 / 空权限补丁）设备自检里**没有**向量——一个只影响那三道的移植 bug 能整个
溜过自检。现已按真实语料的形态补上三条策略规则与三条日志（**26 行 / 24 簇**）：

| 向量 | 形态 | 来源 |
|---|---|---|
| 第 24 行 | 目标上下文里是**全角冒号**（`u:object_r：dev_null:s0`），于是目标被解析成安全级 `s0` | 语料 5 条 MLS 级目标 |
| 第 25 行 | ioctl 命令号被写进权限位（`{ read 0x5413 }`） | 语料 3 条非权限名 |
| 第 26 行 | ioctl 已被 `allow` 授予、又被 `neverallowxperm` 取回 ⇒ `missing` 为空，补丁回落成 `allow A B:c {  };` | 语料 4 条空权限补丁（真身 `medialibrary_hap→hmdfs:file ioctl 0xf205`） |

**同时补上了 `--explain` 的自检**：`kSelfTestExplainVectors` 此前是**生成了却没人消费**
的死表格，设备自检根本不跑解释路径——而"`--explain` 也要走守门"正是 E 的核心改动。
现在 11 组向量按整份 JSON 比对（不是 digest），其中 6 组 `advisory` 非空。

**变体验证**（把 C++ 里对应分支改成不触发，看自检是否叫）：

| 变异 | 结果 |
|---|---|
| 关掉守门 1（MLS 级）| converge 第 22 簇 + explain 第 9 组**同时报错** |
| 关掉守门 5（非权限名）| converge 第 23 簇 + explain 第 10 组报错 |
| 关掉守门 6（空权限补丁）| converge 第 24 簇 + explain 第 11 组报错 |
| **删掉 `--explain` 路径上的 `ApplyGuards` 调用** | explain **6/11 组**报错，而 converge **24/24 全绿** |

末行是关键：它证明新表覆盖了旧表**结构上看不见**的一条路径，而不是把同一批断言换了个写法。

## 已知差异与边界

| 项 | 状态 |
|---|---|
| 索引构建 | **不在设备上**，由宿主机经 `policy_loop/export/` 导出为 PLI |
| 多智能体闭环 / eval / trust | **不在设备上**，属开发期验证手段 |
| 自动写盘 | **刻意不做**，只输出建议补丁文本 |
| SELinux 标签 | `/system/bin/denial_check` 当前是默认 `u:object_r:system_bin_file:s0`，**无专属域** |
| 上游 | `BUILD.gn` 的 `install_enable` 改动仅在本地 `~/ohos_src`，**未进上游仓库** |
| printk 丢帧 | 由内核限速造成（5 s / 10 条），非本工具缺陷 → **验收指标必须用 `unique_cases`**（指纹去重，天然免疫丢帧），不是 `total_denials` |

## 复现

```bash
# 宿主：导出索引 + 生成查询集与期望值
python3 -m policy_loop.export --policy data/raw/oh-selinux/sepolicy \
    --out build/pli/ohos-rk3568.pli
python3 /tmp/gen_queries.py            # -> queries.tsv + 期望 sha256

# 交叉编译
cd ~/ohos_src && ./build.sh --product-name rk3568 \
    --build-target //base/security/selinux_adapter:denial_check

# 下发与验证（hdc 仅为传输通道，不参与计算）
hdc file send queries.tsv /data/local/tmp/queries.tsv
hdc shell 'denial_check --index /data/local/tmp/ohos-rk3568.pli \
             --query /data/local/tmp/queries.tsv | sha256sum'
```

## 排障记录

- **`hdc` 在 SDK 的 toolchains 包里**，不在 native 包里——
  `ohos-sdk-6.0.tar.gz → linux/toolchains-linux-x64-*.zip → hdc`（Ver 3.2.0b）。
  先前判断「本机无 hdc」是因为找错了包。
- **`/tmp` 不可写**：`/` 是只读挂载。可写落点是 **`/data/local/tmp`**。
  路径可写性要实测（`echo > $f`），不能看 `ls` 权限位——权限位会骗人。
- **32 位 ARM 用户态**：DAYU200 是 64 位内核 + 32 位用户态
  （`vendor/hihope/rk3568/config.json` 的 `target_cpu` 就是 `"arm"`），
  交叉产物必须是 32 位，别按「源码树是 6.1 ⇒ 目标就是 arm64」的直觉走
  （板子是 **5.0.3.135**、编译树 `~/ohos_src` 是 **6.1.0.31**，两者不是一回事）。
- **`console=ttyFIQ0` 就是 FIQ 调试器那个 UART**：往串口灌大数据会把 console
  打进 `debug>` 调试器。恢复：调试器内发 `console` → 再发 `\x03` 回 `#`。
- **`/` 可 remount rw**（`mount -o remount,rw /` 实测成功）→ **无 dm-verity 拦截**。
