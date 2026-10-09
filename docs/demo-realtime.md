# 实时闭环演示（demo D：板端全独立控制台）

> 2026-10-04 在 DAYU200（OpenHarmony 5.0.3.135）冷启动后全流程实测通过
> （含新增的「载入当前快照」现读按钮）。
> 这是**当前形态**。`demo-board.md` 描述的是 9/22 的旧形态
> （`/system/bin/denial_check` + `hdc` 当键盘），那套现在只作为备用。

## 这个演示要证明的一件事

**一个系统组件在运行时被 SELinux 拒绝 → 1~2 秒内，板子自己给出分类与最小补丁。**

全链路在板子上，**不依赖 PC、不依赖 su、不换域**：

```
拨开关 → 采集器开新会话 → 它自己那次 fopen 被 enforcing 域拒绝
      → 内核 audit → /dev/kmsg → pl_collector（u:r:pl_collector:s0）
      → 应用沙箱里的 live.jsonl → HAP 每 1s 分析 → 横幅 + 系统通知
```

为什么这条动线值得演示：板子上**很难按需造出一条 denial**。三方应用的权限失败
停在 framework/JS 层，根本不产生 AVC；等板子自己犯错要碰运气。这条链路把它变成
可复现、可反复演示的。

---

## 0. 前置状态

```bash
export PATH=/home/szf/ohos_sdk_dl/tc_extract/toolchains:$PATH
cd /home/szf/policy_loop/device/selinux_policy
bash install_service.sh status          # ★ 一条命令自检全部
```

`status` 会打出四组判据，**任何一组 ✗ 都别开演**：

| 组 | 期望 |
|---|---|
| 服务进程 | `✓ pid=<n>`，`ps -Z` 显示 `u:r:pl_collector:s0` |
| 内核策略 | `内核策略 407604 字节, pl_collector 出现 1 次` / `✓ 在` |
| 共享文件 | `guard.on` / `live.jsonl` / `snapshot.req` / `snapshot.jsonl` 都在应用沙箱里 |
| **快照信道** | `快照信道: snapshot.req=[0] snapshot.jsonl=<n> 行` —— `req` 必须是 `0` |
| **printk 限流** | `✓ printk_ratelimit 板上=0 cfg 期望=0`（见 §4，这行是新增的） |

已核对的落盘物：

| 项 | 值 |
|---|---|
| 采集器 | `/system/bin/pl_collector`，171,668 B，md5 `e3f0572b8fe67e89f7611c067f07174c` |
| 控制台 HAP | `com.policyloop.console`，5,247,722 B，md5 `ff54b8ca79b39ec80f9a61dd7f35d84f`（`/data/app/el1/bundle/public/com.policyloop.console/entry.hap` 与宿主构建逐字节一致，已核） |
| 快照信道 | 沙箱里 `snapshot.req`（内容 `0` = 无人请求）与 `snapshot.jsonl`（现读结果），由采集器预建 |
| 索引 | `rev e1160d2c` · 19,800 条规则（编在 HAP 的 rawfile 里） |
| 域策略 | **已 persist** —— 冷启动后仍是 `Enforcing` 且服务自启 |
| init cfg | `/system/etc/init/policyloop.cfg` = **probe 形态**（path 里带 `--debug-log`） |

⚠️ **开演前把电量充上**。板子 RTC 已死（时间显示 2017-08-05），电量 11% 时中途断电整段作废。

---

## 现场动线（全程约 30 秒）

### 第 1 步 · 摆到起跑线（**这一步之后放下键盘**）

```bash
cd /home/szf/policy_loop/device/selinux_policy
bash install_service.sh demo
```

它按顺序做四件事，每件都在防一个具体的翻车：

| 做的 | 防的是什么 |
|---|---|
| 开关归零 `guard.on=0` | 开关还开着 ⇒ 拨了没有 0→1 跳变 ⇒ **不开新会话 ⇒ 看起来"没反应"** |
| 等采集器退出会话再清窗 | 不等就清，它会写最后一批把 `live.jsonl` 补回来 |
| `aa force-stop` + `aa start` | `aa start` 对已起的实例**不重跑 `onCreate`**，读不到新状态 |
| `dumpLayout` 查「USB 连接方式」并点掉 | 插 USB 弹的系统框**正好压在屏幕正中挡住案例卡片** |

**期望**：结尾打印 `guard.on=[0]  live.jsonl=0 字节  snapshot.req=[0]`，
界面是开关**灰**、状态 `就绪 · 开关关闭`、正文 `开关关闭。`

### 第 2 步 · ★ 拨开关（唯一的因果事件）

**放下 hdc，用手指点屏幕右上角的开关**（720×1280 下约 **(635,214)**）。

> 排练时可以用 `hdc shell "uitest uiInput click 635 214"` 代替，
> 但**正式演示要用真手指**：物理触摸走 input 子系统，
> 而 `uitest` 自己是个工具域，会在窗口里留一条「工具造成」的足迹。
>
> ⚠️ 这里的坐标是**量出来的、不是推出来的**，界面一动就失效（2026-10-09 的视觉
> 重做就把当时文档里的 (586,324) 改成了别的按钮 —— 一整天没人发现）。
> 要重新量：
> ```bash
> hdc shell "uitest dumpLayout -p /data/local/tmp/l.json"
> hdc file recv /data/local/tmp/l.json /tmp/l.json
> grep -o '"text":"[^"]*"[^}]*"bounds":"[^"]*"' /tmp/l.json | grep -E '载入当前快照|回放预录样本'
> ```
> 开关是 `Toggle` 不是 `Button`，按 `"type":"Toggle"` 找。

```bash
hdc shell "uitest uiInput click 635 214"
```

> 现场讲的时候**用真手指点屏幕**，不要用这条命令 —— 物理触摸走 input 子系统，
> 而 `uitest` 自己是个工具域，会在窗口里留一条「工具造成」的足迹。

**期望（**2 秒左右**）**：

```
监听中 · 本次窗口 N 行 / 累计 M 个案例
新 denial  MISSING_RULE · search ×1（板子自带 board）
pl_collector → data_local:dir
最小修复  allow pl_collector data_local:dir { search };
```

时延不是瞬时的，讲的时候主动拆开说，免得被当成卡顿：
**拨 → 采集器轮询到开关 → 首片 500ms 读取走完 → 才跑那行 `DebugLogWrite`**，
所以是 2 秒左右。

**窗口里最终是 2~3 条，N 不一定是 1，而且是哪几条见 §5** —— 不是缺陷，是"活着"的证据。
实测四次会话（15/15/45/12 秒）稳定落在下面的集合里。

卡片区：`pl_collector → data_local:dir` / `search ×1` / `APPROVE · SUCCESS` / `板子自带`。

### 第 3 步 · 讲清楚这条 denial 是真的

**台词（这是全场最容易被追问、也最容易讲砸的一点）**

> 这条 denial 不是伪造的日志行，是**采集器自己在运行时被拒**得到的。
>
> 采集器有一个可选的调试出口 `--debug-log <path>`。开发期把它指向
> `/data/local/tmp` —— 而 `pl_collector` 这个域**故意**在那里一无所有：
> 策略里没有任何一条 allow 提到 `data_local`。于是**每个会话窗口一打开**，
> 那一次 `fopen` 就是一条真的 `avc: denied`，`scontext` 正是
> `u:r:pl_collector:s0`，`permissive=0`，域是 enforcing。
>
> 为什么做成**运行时参数**而不是编译期开关：编进去就得有两份二进制、两套验证。
> 做成参数，二进制只有一份（就是交付的那份），是否触发纯属**部署选择** ——
> 交付形态的 cfg 与演示形态只差 `path` 里这两个元素，由脚本自检钉着。

### 第 4 步 · 收尾（可选，15 秒）

连拨两次开关，说明它**不是一次性**的：会话一开一关，每次都重新触发。
（实测连拨时窗口里 1 / 2 / 3 条都出现过——成分与条数见 §5，
条数取决于开窗那几秒里板子自己做了什么，**只有 `pl_collector` 那条是拨出来的**。）

---

## 第 5 步 · 被问「这是不是预录的快照」时，当场自证（30 秒）★ 建议必做

**这个问题一定会被问，而 10-04 起有了正面答案。**

应用里现在有**两个**来源，各自标注得清清楚楚：

| 控件 | 读什么 |
|---|---|
| 主按钮 **「载入当前快照」** | **现读**：特权侧 `pl_collector` 当场读一次 `/dev/kmsg` 的现存积压 |
| 小字链 **「回放预录样本（9/21 采 · 756 行 · 非实时）」** | 随包发布的 `board_denials.txt`（**之前采的**） |

按下主按钮 → 应用往沙箱写 `snapshot.req=1` → 采集器读一次环形缓冲、写满
`snapshot.jsonl`、**最后**才把 `req` 写回 `0` → 应用见 `0` 即认为文件已完整，读它、分析、显示。
写回的次序就是协议：`0` 必须意味着"写完了并且关好了"。

### 证法 A（最直接，30 秒）：**连按两次，条数不一样**

```bash
D=/data/app/el2/100/base/com.policyloop.console/haps/entry/files
hdc shell "uitest uiInput click 270 352"; sleep 3     # 按「载入当前快照」
hdc file recv $D/snapshot.jsonl /tmp/s1.jsonl
hdc shell "uitest uiInput click 270 352"; sleep 3     # 再按一次
hdc file recv $D/snapshot.jsonl /tmp/s2.jsonl
wc -l /tmp/s1.jsonl /tmp/s2.jsonl                     # ★ 两个数不同
```

实测读数：**801 / 1047 / 1070 / 1084 / 1092 行** —— 每次都不一样，因为 `kmsg`
环形缓冲一直在转（旧记录被挤出去、新记录进来）。

再念一行 `raw`：

```
5,21171,4974150503,-;audit: type=1400 audit(...): avc: denied { read } for pid=7617 ...
```

- **`pid=7617`** 就是 `pidof pl_collector` 打出来的那个数 —— 这次开机才存在的进程号
- 前缀 `<级别>,<序号>,<开机微秒>,<标志>;` 里 **4974.15 秒**，与 `cat /proc/uptime` 对得上

**台词**
> 判别式不是"我保证"，是**这份文件会变**：预录素材按两次拿到的是同一份，
> 这份按两次是两个不同的读数，而且号码是这次开机才有的。我没法预先造一份
> "会跟着板子一起变"的假文件。

### 证法 B（如果问的是**实时**那条路，不是快照）

主按钮证明的是"现读"；要证明 `live.jsonl` 那条实时链路，还是用清窗法：

```bash
hdc shell "echo 0 > $D/guard.on"; sleep 3        # 让采集器退出会话
hdc shell "rm -f $D/live.jsonl";  sleep 1
hdc shell "wc -c < $D/live.jsonl"                # → 0        ★ 窗口是空的
hdc shell "cat /proc/uptime"                     # → 记下 T0
hdc shell "pidof pl_collector"                   # → 记下采集器 pid
hdc shell "uitest uiInput click 635 214"         # 拨开关
sleep 3
hdc shell "wc -c < $D/live.jsonl"                # → 非 0     ★ 窗口长出来了
```

`raw` 里的 `pid=`、以及"开机微秒晚于 T0"，一份事先录好的文件伪造不了。

⚠️ 两条证法之后都要**拨一次开关**才能回到实时 —— 按主按钮会把实时视图**冻结**（见毛边 §7）。

---

## ⚠️ 毛边：必须提前知道的七件事

### 1. 窗口开着的时候别再敲 `hdc`

`hdc shell` 跑在 `su` 域（eng 版是 `typepermissive`），**每敲一条命令都会产生一串
`su` 域 denial**，被采集器照单全收。实测一次连续调试留下的痕迹：

```
685 条 denial → 685 个唯一案例（板子自带 126 / 工具造成 559）
```

**559/685 = 82% 是自己敲出来的。** 工具会如实标成「工具造成」，不会冒充分析结果，
但讲稿里必须分开说，否则「唯一案例」这个数站不住。

**操作纪律：摆好起点（第 1、2 步）之后就不要再敲 `hdc`，直到演示结束。**

### 2. `unique == total` 不是 bug

采集器那层有 `--dedupe`，重复指纹在写进 `live.jsonl` 之前就被压掉了，
所以进到应用里的每条本来就各不同 → 引擎报出来的 `unique` 自然等于 `total`。
真正的「案例数」要看界面上的 **累计 N 个案例**（那是应用按 `caseKey` 再去重一层）。

### 3. 两个计数测的不是一回事

状态行是 `本次窗口 N 行 / 累计 M 个案例`：

- `N` 是**当前窗口**的文件长度，每次开窗都会截断重建 → 中途重开一次就会掉回 1
- `M` 是**本次应用运行**累计见过的案例，跨窗口累加、不随截断回退

所以「本次窗口 1 行 / 累计 9 个案例」是对的。标签是 10-04 特意分开写的。

### 4. `printk` 限流是 `--kmsg` 这条路的天花板

采集读的是 `/dev/kmsg`，也就是内核把 audit 记录镜像给 printk 的那份副本
（`kernel/audit.c` 的 `kauditd_printk_skb`）。那份副本要过 `printk_ratelimit()`：

- 板子默认 `printk_ratelimit=5` / `burst=10` = **每 5 秒只放 10 条，超出的直接丢**
  —— 不进环形缓冲、不排队，于是 `dmesg` 和采集器**一起**看不见
- 实测痕迹：`kauditd_printk_skb: N callbacks suppressed`，那一批 denial 两种读法同时消失
  （一度被误判成「探针没触发」）

**cfg 里那个 init job 就是干这个的**：开机时写 `printk_ratelimit=0`。10-04 冷启动实测
零人工干预即为 `0 / 100000`，`status` 会把板上现值与 cfg 期望并排打出来比对。

**残留局限如实写明**：这是**减少**丢失，不是消除。printk 环形缓冲本身有上限，
无损通道是 audit netlink 套接字。本项目走 `/dev/kmsg`，故有此天花板。

### 5. 窗口里那几条 denial 是怎么来的（**一定会被问「怎么老是这几条」**）

实测四次会话（15 / 15 / 45 / 12 秒，含一次完全静默不做任何操作），稳定出现的只有：

| 那条 | 谁产的 | 实测特征 |
|---|---|---|
| `pl_collector → data_local:dir { search }` | **拨开关**（探针） | 5 次拨动 → 恰好 5 条；间隔 `[1.6, 26.2, 31.2, 46.7]` 秒，不规则 = 手指节奏 |
| `appspawn → sysfs_hungtask_userlist:file { read write }` | **板子定时器** | 全开机时段 17 次，相邻间隔**分布集合只有 `[10.0]`**（16 次连续整 10.0 秒）；**完全静默 12 秒里照样响 1 次** |
| `foundation → distributeddata:fd { use }` | **板子** | 间歇：45 秒窗口 0 次，另一次 15 秒窗口 1 次 |

**三条里只有第一条是拨开关产生的。** 反证是第二条：没有哪次手指触摸能产生
「每隔整 10.0 秒、连着 16 次」的序列——那是 `appspawn` 自己的 hung-task 监视器。

**为什么"每次都是这三条"而不是别的**（两点叠加）：

1. 板子空闲时**只有这三个不同指纹在复发**，四次窗口出现的集合始终是其子集；
2. **`--dedupe` 是每会话一次的**：45 秒那轮 appspawn 实际响了 4 次，写进窗口的**只有 1 条**，
   所以窗口不会随开窗时长膨胀，很快稳定在 2~3 条。

会话一开一关 dedupe 就重置 ⇒ **每次拨都会把这老几位重新报一遍**。
这是"从现在开始看"该有的语义，**不是预录的固定清单**。

**台词（被问到时）**
> 这三条里只有最后那条 `pl_collector` 是我拨出来的，另外两条是板子自己的。
> 看这条 `appspawn` 的间隔——**连着 16 次都是整 10.0 秒**，我让板子完全静默
> 12 秒不碰它，它照样响。预录的文件做不出这种规律；它也正好说明工具**真的在听板子**，
> 而不是在听我。

### 6. 顺带能抓到一条**真缺陷**（建议加进演示）

让屏幕重绘（实测：重启控制台应用那 8 秒）会冒出 **57 条** denial，其中 **27 条**是：

```
render_service → dev_mali:chr_file  { ioctl }   ioctlcmd=0x8014
```

这就是 `demo-board.md` 第 3 幕那条 **`XPERM_GAP` 真缺陷**——策略已允许 `ioctl` 大类，
缺的是 `allowxperm` 白名单里的**一个命令号**，所以 `audit2allow` 会建议加一条**已经存在**的
规则（写了等于没写）。一次渲染突发里连出 27 条，相邻间隔 0.01~0.02 秒。

与探针的区别是本质的：探针是"故意造的、证明链路活着"的**人造**缺口，
这条是**板子固件自己的**缺陷，补丁为
`allowxperm render_service dev_mali:chr_file ioctl { 0x8014 };`。
演示里从"链路是活的"进阶到"抓到了真问题"，这条比探针值钱。
（注意：`install_service.sh demo` 的 `aa force-stop`/`aa start` 发生在 `guard.on=0`
期间，所以这 27 条**不会**落进拨开关那个窗口——要看它得在开会话时触发重绘。）

**顺带：现读那条路也抓得到它。** 实测按一次「载入当前快照」，1070 条里排第一的就是
`render_service → dev_mali:chr_file ioctl 0x8014 ×27 · XPERM_GAP`（板子自带）。
所以"现读"不只是证明数据是真的，还能把固件自己的缺陷一次捞出来。

### 7. 「载入当前快照」会**冻结**实时视图（是设计，不是卡住）

按下按钮后界面把实时刷新**暂停**，状态行变成 `已暂停实时刷新 · 显示的是快照`，
免得刚讲的那张快照被下一秒的新记录冲掉。按钮下方会出现一行绿字：

```
当前快照（现读）· 1070 条 → 514 个案例 —— 拨一次开关恢复实时
```

**恢复方式只有一个：拨一次开关。** 开关**关**着时按 → 拨开关（0→1）解开并开新会话；
开关**开**着时按 → 拨开关（1→0）同样解开。两种都实测过。

⏱ **按下去不是瞬时的：满积压（约 1000 条）时按钮会显示「分析中…」约 8~10 秒。**
拆开说是两段：等采集器回话 ~1.5 秒（它每秒轮询一次开关目录，读满 ~0.4 秒），
其余全是在板上分析这一千条。**别当成卡住**，讲的时候把这个数字先说出来；
反正结论是 `1047 条 → 524 个案例`，一千条换一个数，听众不会嫌慢。

⚠️ 采集器没在跑时按按钮，红字是
`采集器没回应（6 秒）—— 服务在跑吗？看 install_service.sh status 第一组判据。`
这条是**常驻**的（专用状态字段），不会被每秒一次的 `tick()` 清掉 —— 旧版正是栽在
"错误提示只活不到一秒"上。实测 `install_service.sh stop` 之后按按钮，9 秒后红字仍在。

---

## 冷启动后的恢复（如果板子被重启过）

**正常情况下什么都不用做** —— 策略已 persist，init cfg 里的 job 和服务定义都在，
开机自动生效。只需：

```bash
bash install_service.sh status     # 四组判据应全 ✓
```

若「内核策略」那组报 ✗（说明策略被还原过，例如跑过 `rollback`）：

```bash
bash install_service.sh            # 重装（内存策略 + 二进制 + cfg + 拉起）
bash install_service.sh status
```

然后 `bash install_service.sh demo` 重新摆起点。

---

## 备用方案：探针没触发时

**先查这两条**，九成是它们：

```bash
hdc shell "cat /proc/sys/kernel/printk_ratelimit"        # 必须是 0
hdc shell "grep -c debug-log /system/etc/init/policyloop.cfg"   # 必须 >0（probe 形态）
```

- 第一条不是 0 → 这次开机没跑到 job（或 cfg 被换成 clean 形态后再没重启过）：
  `bash install_service.sh probe` 然后**重启**
- 第二条是 0 → 板上是 clean 形态，跑 `bash install_service.sh probe`（会重启服务）

**再不行就退回 `demo-board.md` 那套 CLI 动线** —— 它不依赖 init service，
用 `denial_check --explain` 手喂一条真实 denial 也能走完「分类 → 最小补丁 → 评审 → 验证」。
只是那样 `hdc` 就回到讲台上了，「不依赖 PC」这个卖点讲不了。
