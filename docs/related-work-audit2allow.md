# 调研：audit2allow

> 起因：kmy 要求"调研 audit2allow，说清比它强在哪"。这份文档把"强在哪"拆成三份分开写：
> **哪些是目标不同（拿来比强弱没意义）**、**哪些是它真的弱**、以及**它真的比我们强的地方**
> ——最后一节才是答辩时应该主动说的。所有数字都是在本机跑出来的，命令见文末「复现」。

## 一句话结论

audit2allow 是**把拒绝记录转成能编译的 `allow` 规则**的工具；PolicyLoop 先回答**这条拒绝
该不该放行**，只对该放行的那些生成最小补丁。同一份 5161 条语料上，两者产出 **2833 条规则
vs 69 条补丁**——差 41 倍，而其中 **2687 条（94.8%）是当前策略本来就允许的**。

## 它是什么、怎么工作

版本口径：SELinux userspace，本机取的是 Ubuntu 24/questing 的 `policycoreutils-python-utils
3.8.1-2`（含 `python3-sepolgen`、`python3-selinux`）。源码 `/usr/bin/audit2allow`（399 行）
+ `sepolgen/` 包。流程：

```
auditd 记录 ──AuditParser──▶ AVCMessage ──to_access()──▶ AccessVectorSet
                                                              │
                                              PolicyGenerator ┴─▶ allow 规则
                                                              │
                                                     ModuleWriter ──▶ stdout / -o / -M 包
```

读源码后需要记住的几条：

| 机制 | 位置 | 含义 |
|---|---|---|
| 按三元组合并 | `sepolgen/access.py:285 add_av()` | 键是 `(src_type, tgt_type, (obj_class, av.type))`，`merge()` 把权限**取并集** → **一个三元组一条规则** |
| `-R/--reference` **默认开启** | `audit2allow:76`，`policygen.py:91` | 用 refpolicy 的接口定义（`/var/lib/sepolgen/interface_info`）把裸 allow 换成接口调用 |
| `-M` 打包 | `audit2allow:219` | 生成 `.te` 并调 `ModuleCompiler` 出 `.pp`，可直接 `semodule -i` |
| `-D` / `-x` | `:73` / `:90` | 出 `dontaudit` / 出 xperm 扩展权限规则 |
| `-w/--why`（= `audit2why`） | `:253` | 用 libselinux 对**已加载策略**分类：ALLOW / DONTAUDIT / BOOLEAN / TERULE / CONSTRAINT / RBAC / BOUNDS |
| `NEVERALLOW` | `refpolicy.py:575` | 只是个**规则类型**，用于解析 refpolicy 接口定义；audit2allow 从不生成、也从不检查 neverallow |

## 实测：同一份语料，两个工具

语料 = 项目的 golden `data/corpus/real_denials.txt`（5161 条 / 4911 唯一）。给 audit2allow
的输入是这份语料**去掉行首 `#`** 后的 5161 行；策略给它 rk3568 真实构建产物
`out/rk3568/src/obj/base/security/selinux_adapter/policy.31`（536 KB），这是能给它的最好条件。

| 量 | audit2allow | PolicyLoop |
|---|---|---|
| 前置要求 | **必须**有编译好的二进制策略（`-p` 或系统已加载），否则直接 exit 1 | 只要 `.te` 源码树 |
| 语料解析 | 5085 / 5161 行（98.5%） | 5161 / 5161 |
| 产出 | **2833** 条 `allow` 规则 | **69** 条最小补丁 + 1580 转人工 + 3261 无需修复 |
| 其中"当前策略已允许" | **2687** 条（94.8%）——写了等于没写 | 全部归入 `noise_or_already_allowed`，不产出规则 |
| 它自己已注明 allowed 却仍输出为**生效规则** | **2434** 条 | — |
| 撞 neverallow 编译期红线 | **34** 条 | 0（一律转人工，不自动放权） |
| 含**不存在的类**名（编译不过） | **4** 条 | 0（守门按"未知类"转人工） |
| APL 分级边界 | 照给 `allow normal_hap sys_file:file { read open };`，无任何提示 | 标 `fix_layer=app`，附共享域影响面与"提 APL 或走系统服务" |
| 共享域影响面 | 无此概念 | 每条共享域补丁都附影响面 |
| `-R` refpolicy 接口匹配 | **命中 0 次**，输出与 `-N` **逐字节相同** | 不适用（OH 不是 refpolicy 系） |

两边都给的三元组有 42 个；**只有 PolicyLoop 给的有 9 个**，其中 `bgtaskmgr_service` 是因为该
类型不在 `policy.31` 里（audit2allow 的 sid 解析失败 → 不产出），其余几个是 M3 占位符解析
（日志里的 `default_service` 被解析成具体 `sa_*`/`hdf_*`）与 xperm 类补丁——**audit2allow 只会
照着日志抄，不做这层解析**。

那 4 条编译不过的规则全部来自 OpenHarmony **上游 `.te` 注释里的转写笔误**，逐条可核对：

| 输出 | 笔误 | 上游出处 |
|---|---|---|
| `allow powermgr sa_device_standby:samger_class get;` | `samger_class` → `samgr_class` | `ohos_policy/powermgr/display_manager/system/powermgr.te:20` |
| `allow edm_sa sa_net_policy_manager:samar_class get;` | `samar_class` → `samgr_class` | `ohos_policy/customization/enterprise_device_management/system/edm_sa.te:147` |
| `allow edm_sa sa_pulseaudio_audio_service:samar_class get;` | 同上 | 同文件 `:208` |
| `allow nwebspawn data_service_el1_file:dit mounton;` | `dit` → `dir` | `ohos_policy/web/webview/system/nwebspawn.te:166` |

PolicyLoop 对这几条的实际处理是**转人工**、不产出补丁，理由原文：
「对象类「samar_class」不在策略任何规则中出现（疑为日志笔误），补丁无法落点验证，转人工」。

## 逐条差异

### A. 目标不同，不该拿来比强弱

- **audit2allow 不问"该不该放行"**，也不声称自己在问。它的模型是"拒绝 = 缺规则"，输入输出
  都是记录级的。所以 2833 vs 69 的差距不是它做得差，而是**它不回答我们回答的那个问题**。
  对比时如果只贴这个倍数，属于偷换，答辩会被问穿。
- **它的安全网在编译/装载期**：`neverallow` 是编译期断言，撞上它的 allow 会在编模块
  （`checkpolicy`）或装模块（`semodule -i`）时被拒。这层保护是真的，但它发生在（a）构建期、
  （b）全有全无（整个模块编译失败，不告诉你哪条该换成什么）。PolicyLoop 是在生成期逐条判、
  并把原因写给人工。

### B. 它真的弱的地方

1. **对"已允许"不作过滤，只加注释。** 它用 libselinux 判出了 2434 条"allowed in the current
   policy"，把这句写进注释，然后**照样输出为生效 allow 规则**。结果是一份 2833 条的清单里
   94.8% 是 no-op——对"permissive 设备 dump 该收紧什么"这个场景，噪声比信息多。
2. **没有 neverallow 概念**（见上表 `refpolicy.py:575`）。34 条输出会撞红线。
3. **没有"共享域"概念。** `allow normal_hap sys_file:file read` 一句，受益者是设备上**每一个**
   normal APL 应用——audit2allow 的输出形态里没有任何位置能表达这件事。
4. **不校验符号是否存在。** 4 条规则引用了不存在的类名，它照抄。
5. **必须给编译好的策略，否则完全跑不了**：`main()` 无条件调 `audit2why.init()`
   （`audit2allow:383`），无策略时 `ValueError: You must specify the -p option` → exit 1。
   在没有 SELinux 的开发机上，**它连生成规则这一步都进不去**。
6. **输入契约是 auditd 的记录格式**（`-a`/`-b` 走 `ausearch`，`-d` 走 dmesg）。OpenHarmony 的
   denial 在 hilog 里，没有 auditd；我们因此得自己做 `LogSource`。
7. **`-R` 在 OpenHarmony 上完全空转**：默认开启的 refpolicy 接口匹配命中 0 次，输出与 `-N`
   逐字节相同。这个功能是给 Fedora/RHEL 系（refpolicy 血统）用的。

### C. 它比我们强的地方（这节要主动讲）

1. **`audit2why` 的诊断维度我们一个都没有。** 它能把一条拒绝归到：
   - `BOOLEAN` → 给出 `setsebool -P <bool> 1`（策略里早有规则，只是布尔开关没开）
   - `CONSTRAINT` / `RBAC` / `BOUNDS` → 约束、角色、typebounds 问题
   - `DONTAUDIT` → 本来就该静音的
   PolicyLoop 只有"缺规则 / 已允许 / neverallow / 域标签"这几种，**布尔与约束两类是真空**。
   这是最该抄的一处。
2. **`-M` 打通了"生成 → 装载"**：直接产出可 `semodule -i` 的模块包。我们的交付物止于规则文本。
3. **`--dontaudit` 是合法需求**（有些拒绝就该静音，不是该放权），我们没有对应产物。
4. **`-x` 支持 xperm**，我们对 ioctl 的最小补丁生成还是"可能给出空权限补丁 → 转人工"。
5. **成熟度**：20 年、AOSP 与各发行版的事实标准、有 man page、输入格式有 auditd 生态支撑。
   我们在这份语料上能压过它，很大一部分原因是**我们为 OpenHarmony 这个特定场景做了适配**
   （hilog 输入、占位符解析、APL 桥），不是通用能力上的全面超越。

## 对 PolicyLoop 的启示

- **补 boolean / constraint / bounds 三类诊断**。它们同样能落进"改哪一层"的判据里（布尔 →
  改系统层开关；约束 → 改标签/属性，属架构决策），而且成本低：libselinux 已经算好了，我们在
  C++ 侧本来就有 `PlIndex`。
- **输出形态可以借鉴 `-M`**：一份可直接装载的产物比一堆规则文本更接近"能用"。
- **答辩口径**：先讲目标差异（我们回答"该不该放行"），再讲 B 组的实测差距，最后主动讲 C 组。
  只讲 B 组会显得没读透；主动讲 C 组才证明是调研过而不是搜过。

## 边界：这份调研没有证明的

- 口径是「本机 Ubuntu + rk3568 的 `policy.31` + golden 语料」，不是 rk3568 真机现场。
- audit2allow 判 "allowed in the current policy" 用的是 `policy.31`，与语料当时的策略版本可能
  有偏差（stderr 里有若干 `type X is not defined`）。这不影响 B 组结论的方向，但**2687 这个
  精确数字**应按"用 policy.31 判定的结果"理解。
- **没有评估它在 refpolicy 系发行版上的表现**——那里 `-R` 的接口匹配是真有用的，A 组之外的
  一部分差距会被抹平。要下"全面优于"的结论必须先补这一块。

## 复现

```bash
# 1) 取工具（不安装系统包，解包到临时目录即可）
mkdir -p /tmp/a2a && cd /tmp/a2a
apt-get download policycoreutils-python-utils python3-sepolgen python3-selinux
for d in *.deb; do dpkg -x "$d" root; done
export PYTHONPATH=/tmp/a2a/root/usr/lib/python3/dist-packages
A2A="python3 /tmp/a2a/root/usr/bin/audit2allow"

# 2) 语料去注释（golden 文件每行都以 '#' 开头）
python3 -c "
import re,pathlib
src=pathlib.Path('data/corpus/real_denials.txt').read_text(errors='surrogateescape').splitlines()
pathlib.Path('/tmp/a2a/strip.txt').write_text('\n'.join(re.sub(r'^#\s*','',l).strip() for l in src)+'\n')"

# 3) 跑（-N：OH 不是 refpolicy；实测加不加 -N 输出逐字节相同）
P=~/ohos_src/out/rk3568/src/obj/base/security/selinux_adapter/policy.31
$A2A -p $P -N -i /tmp/a2a/strip.txt > /tmp/a2a/out_N.txt

# 4) 核对本表的数字（规则数 / no-op 数 / neverallow 命中 / 未知类）
python3 - <<'EOF'
import re
from collections import defaultdict
from policy_loop.policy import load_dir
idx = load_dir("data/raw/oh-selinux/sepolicy")
RX=[re.compile(r"^allow\s+(\S+)\s+(\S+):(\S+)\s*\{([^}]*)\}\s*;"),
    re.compile(r"^allow\s+(\S+)\s+(\S+):(\S+)\s+(\S+)\s*;")]
rules=[]
for l in open("/tmp/a2a/out_N.txt",encoding="utf-8",errors="surrogateescape"):
    for rx in RX:
        m=rx.match(l)
        if m: rules.append((m.group(1),m.group(2),m.group(3),tuple(m.group(4).split()))); break
classes={r.cls for r in idx.rules}
print("规则数", len(rules))
print("no-op（策略已允许）", sum(1 for s,t,c,p in rules if idx.has_access(s,t,c,frozenset(p))[0]))
print("撞 neverallow", sum(1 for s,t,c,p in rules if idx.neverallow_rules(s,t,c,frozenset(p))))
print("未知类", [(s,t,c) for s,t,c,_ in rules if c not in classes])
EOF
```
