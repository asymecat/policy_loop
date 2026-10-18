#!/bin/bash
# =====================================================================
# 把 pl_collector 装成板子上的 init service（开机自启，不依赖 su）
#
# 与 install_to_board.sh 的区别：
#   那份装的是**演示形态**（denial_check 域，二进制放 /data/local/tmp，
#   靠 type_transition 切域，域是 permissive）。重启就没了，要重跑。
#   这份装的是**生产形态**：二进制进 /system/bin，init 用 secon 指定域，
#   域 enforcing，开机自己起来。装一次就一直在。
#
# 策略加载的唯一入口（源码查实，见 install_to_board.sh 开头的长注释）：
#   覆盖 /system/etc/selinux/targeted/policy/policy.31 → 跑 load_policy。
#   它不吃参数，路径是写死的。
#
# ★ 安全手法沿用上一份：install 只进内核内存，磁盘那份立刻换回原版，
#   所以**任何时候重启都会自动回到原策略**。要真的开机也生效，
#   必须显式 persist —— 那一步才是唯一有"刷不回来"风险的动作。
#
# 用法：
#   bash install_service.sh            装（内存策略 + 二进制 + cfg + 拉起）
#   bash install_service.sh status     看服务在不在、域对不对、文件有没有
#   bash install_service.sh demo       ★ 摆到起跑线（开关归零/快照信道归零/清窗/重起应用/点掉挡屏弹窗）
#   bash install_service.sh stop       停服务
#   bash install_service.sh start      起服务
#   bash install_service.sh probe      只换 cfg：打开 --debug-log（演示用）
#   bash install_service.sh clean      只换 cfg：关掉 --debug-log（交付用）
#   bash install_service.sh persist    ★落盘（重启后仍生效）
#   bash install_service.sh uninstall  拆掉服务（留着策略不管）
#   bash install_service.sh rollback   策略也还原到原版（要重启才彻底）
#
# probe / clean 不碰策略、不碰二进制，只推一份 init cfg 再重启服务，
# 所以现场切换只要几秒，且两种形态用的是**同一份**二进制。
#
# ---------------------------------------------------------------
# 这份脚本现在管**两个**服务：pl_collector（采集）与 pl_fixer（板端修复）。
#
# 上面所有子命令（status / demo / stop / start / uninstall / rollback）对两者
# 一起生效；probe / clean 只管采集器的 cfg（修复器没有 debug 形态）。
#
# 修复器要多推两样东西：
#   /system/bin/pl_fixer            与采集器同源码、不同 argv 的第二份拷贝
#   /system/etc/init/policyloop_fixer.cfg
#   /system/etc/policyloop/{base.cil,na_all.cil}   ← 修复时现场编译的输入
#
# ★ 那两份 .cil 是**必须**的，不是可选缓存：base.cil 是每次修复的编译底座，
#   它含 pl_fixer 域本身；少了它，第一次修复装载就会把修复器从内核策略里抹掉，
#   而且现象是「装载成功、板子一切正常、但这个功能从此哑掉」。
#
# ★ 这两份资产按 134 KB + 1.6 MB 算，/ 上还有 651 MB 空闲，放得下。
#
# cfg 里带一个 init job，开机时写 /proc/sys/kernel/printk_ratelimit=0。
# 不是可选项：采集走 /dev/kmsg，那是 audit 记录在 printk 里的镜像副本，
# 板子默认「每 5 秒只放 10 条」且**超出直接丢**，突发时 dmesg 和采集器
# 一起看不见（实测 `kauditd_printk_skb: N callbacks suppressed`）。
# status 会把板上现值与 cfg 里的期望并排打出来 —— 对不上就是这次开机
# 还没读过新 cfg（init 只在开机时读），重启即可。
# =====================================================================
set -euo pipefail

# 宿主侧路径可用环境变量覆盖（默认值保持本机原样）：
#   HDC_DIR    含 hdc 的目录（SDK toolchains）
#   OHOS_SRC   OH 源码树（取 out/rk3568/security/… 下刚编好的二进制）
HDC_DIR="${HDC_DIR:-$HOME/ohos_sdk_dl/tc_extract/toolchains}"
OHOS_SRC="${OHOS_SRC:-$HOME/ohos_src}"
export PATH=$HDC_DIR:$PATH
HERE="$(cd "$(dirname "$0")" && pwd)"

STAGE=/data/local/tmp/plstage
POLICY=/system/etc/selinux/targeted/policy/policy.31
FRESHBIN=$OHOS_SRC/out/rk3568/security/selinux_adapter/denial_check
BIN=/system/bin/pl_collector
CFG=/system/etc/init/policyloop.cfg
SVC=pl_collector
APP=com.policyloop.console
APPDIR=/data/app/el2/100/base/$APP/haps/entry/files

# ---- 板端修复服务 pl_fixer -------------------------------------------
# 与采集器**同一份源码**（denial_check，靠 argv 的 --fix 进不同模式），但落成
# **两份真实拷贝**而不是一条软链：
#   ① 软链在 /system/bin 下没有 file_contexts 条目，标签要靠回退猜，而
#      lnk_file 与 file 是两套检查 —— 白添一个不可控变量。
#   ② 推二进制前必须先停服务（运行中的可执行文件是 busy text file，覆盖返回
#      ETXTBSY，而 hdc file send **照样返回 0**）。两份独立文件时停一个不影响
#      另一个，先后顺序就无所谓了。
BIN_FIXER=/system/bin/pl_fixer
CFG_FIXER=/system/etc/init/policyloop_fixer.cfg
SVC_FIXER=pl_fixer

# ---- 修复器的板端资产 -------------------------------------------------
# 都在 /system/etc/policyloop/ 下，**root 拥有、应用不可写**（这正是不能放
# 应用沙箱的原因：沙箱可写 = 应用能改编译输入）。
#   base.cil   每次修复的编译底座，必须含 pl_fixer 域（见文件头 ★）
#   na_all.cil 710 条红线断言。**只用在"检查那一次"编译里**；真要加载的那份
#              绝不能带 —— 带上会把产物从 ~408 KB 撑到 494 KB。
# 这两份由 device/selinux_policy/build_pl_collector.sh 产出（它顺手 cp 过来）。
ASSETDIR=/system/etc/policyloop
ASSET_BASE=$HERE/out/base.cil
ASSET_NA=$HERE/out/na_all.cil

sh_() { hdc shell "$1"; }

# 把内核此刻真正生效的策略拉回来，数我们的类型。这是唯一可信的判据：
# 磁盘上那份每次 install 都被还原成原版，看磁盘等于什么都没看。
#
# 返回值必须是 python 那个判定的结果，不能是收尾命令的结果：
# 这里原先直接以 rm -f 收尾，于是函数恒返回 0，上面两处 if 永远走 ✓ 分支 ——
# status 和 install 第 4 步都成了假绿灯（策略压根没进去也照样报「在」）。
# 所以先把退出码接住，再删临时文件，最后显式 return。
verify_live() {
    local tmp rc=0; tmp=$(mktemp /tmp/live_policy.XXXXXX.31)
    if ! hdc file recv /sys/fs/selinux/policy "$tmp" >/dev/null 2>&1; then
        echo "   ! 拉取 /sys/fs/selinux/policy 失败"; rm -f "$tmp"; return 1
    fi
    # `|| rc=$?` 而不是靠 set -e：被当成 if 条件调用时，set -e 在函数体内是被
    # 抑制的，光靠它接不住这个非零退出。
    python3 - "$tmp" << 'PY' || rc=$?
import sys
d = open(sys.argv[1], 'rb').read()
n, f = d.count(b'pl_collector'), d.count(b'pl_fixer')
print(f"   内核策略 {len(d)} 字节, pl_collector 出现 {n} 次, pl_fixer 出现 {f} 次")
# 两个都要在。只数采集器的话，一份「没有修复器」的策略照样报绿灯 —— 而那正是
# 回滚基线陷阱的症状：拿磁盘那份 policy.31 当基线回滚，板子看起来一切正常
# （采集器还在跑），只是修复器域当场从内核策略里消失、这个功能永久哑掉。
sys.exit(0 if (n and f) else 1)
PY
    rm -f "$tmp"
    return $rc
}

# 一个服务的进程/域/AVC 缺口。抽成函数而不是照抄一遍，理由和上面那条一样：
# 现在有两个服务，「两份要同步改」这种纪律光靠记性没有用。
svc_block() {
    local svc="$1" pid
    pid=$(sh_ "pidof $svc" 2>/dev/null | tr -d '\r' || true)
    if [ -z "$pid" ]; then
        echo "   ✗ $svc 没在跑"
    else
        echo "   ✓ $svc pid=$pid"
        echo "   ps -Z:"; sh_ "ps -Z | grep -E '$svc' " || true
        # 读别的进程的 attr/current 要 ptrace 权限，拿不到不是故障，是策略在管事。
        echo -n "   域 (/proc/$pid/attr/current): "
        sh_ "cat /proc/$pid/attr/current 2>&1" || true
    fi
}

cmd_status() {
    echo "== 服务进程 =="
    svc_block "$SVC"
    svc_block "$SVC_FIXER"
    echo
    echo "== 内核策略里有没有我们的两个域 =="
    if verify_live; then
        echo "   ✓ 两个都在"
    else
        echo "   ✗ 缺一个或都不在 —— 可能是策略没加载、被还原，"
        echo "     或者回滚时拿磁盘那份 policy.31 当了基线（它不含 pl_fixer）"
    fi
    echo
    echo "== 共享文件 =="
    sh_ "ls -la $APPDIR 2>&1 | grep -E 'guard.on|live.jsonl|snapshot.req|snapshot.jsonl|fix.req|fix.sel|fix.out|fix.rollback|总用量|total' " || true
    echo "   live.jsonl 行数: $(sh_ "wc -l < $APPDIR/live.jsonl 2>/dev/null" | tr -d '\r' || echo '?')"
    # 快照信道。req 空 = 文件压根不存在 = 采集器的守护循环没跑过（服务没起），
    # 这是「按钮没反应」最可能的根因，所以并排打出来。
    echo "   快照信道: snapshot.req=[$(sh_ "cat $APPDIR/snapshot.req 2>/dev/null" | tr -d ' \r')] "\
"snapshot.jsonl=$(sh_ "wc -l < $APPDIR/snapshot.jsonl 2>/dev/null" | tr -d ' \r') 行"
    # 修复信道。与快照信道同形，所以"没反应"的判法也一样：fix.req 空 = 修复器
    # 的守护循环没跑过 = 服务没起。fix.out 的字节数则告诉我们上一轮修复的结论
    # 有没有落下来。
    echo "   修复信道: fix.req=[$(sh_ "cat $APPDIR/fix.req 2>/dev/null" | tr -d ' \r')] "\
"fix.rollback=[$(sh_ "cat $APPDIR/fix.rollback 2>/dev/null" | tr -d ' \r')] "\
"fix.sel=$(sh_ "grep -c . $APPDIR/fix.sel 2>/dev/null" | tr -d '\r') 行 "\
"fix.out=$(sh_ "wc -c < $APPDIR/fix.out 2>/dev/null" | tr -d ' \r') 字节"
    echo
    echo "== 修复器的板端资产（缺了它只能现场编译一次，之后累积不了）=="
    # 标签必须是 system_etc_file —— pl_fixer 的读权限正是挂在这个标签上的
    # （file 读由 (allow domain system_etc_file …) 白拿）。标签不对的话，
    # 症状是修复器活着、什么都不报，只是永远读不到底座。
    sh_ "ls -laZ $ASSETDIR 2>&1" || true
    echo
    echo "== --kmsg 的前提：printk 限流（不关会静默丢 audit 记录）=="
    # 板上现值 vs cfg 里那个 job 的意图。不一致 = 这次开机没跑到 job
    # （多半是改完 cfg 还没重启 —— init 在开机时才读 cfg）。
    python3 - "$HERE/../board/policyloop.cfg" \
        "$(sh_ 'cat /proc/sys/kernel/printk_ratelimit' | tr -d '\r')" \
        "$(sh_ 'cat /proc/sys/kernel/printk_ratelimit_burst' | tr -d '\r')" << 'PY'
import json, sys
cfg, got_ratelimit, got_burst = sys.argv[1:4]
want = {}
for cmd in json.load(open(cfg))['jobs'][0]['cmds']:
    _, path, value = cmd.split(None, 2)
    want[path] = value
for p, g in zip(['/proc/sys/kernel/printk_ratelimit',
                 '/proc/sys/kernel/printk_ratelimit_burst'],
                [got_ratelimit, got_burst]):
    w = want.get(p, '(cfg 没写)')
    g = g.strip()
    print(('   ✓ ' if g == w and g else '   ✗ ') +
          f'{p.split("/")[-1]:22s} 板上={g or "?":10s} cfg 期望={w}')
PY
    echo
    echo "== 我们这两个域的 AVC 缺口（有就是权限没给够）=="
    for d in $SVC $SVC_FIXER; do
        echo "   --- u:r:$d:s0 ---"
        sh_ "dmesg | grep 'u:r:$d:s0' | tail -10" || true
    done
}

# 推一份二进制并证明它真的上去了。
# 三步缺一不可：先停服务（运行中的可执行文件是 busy text file，覆盖返回
# ETXTBSY，而 hdc file send **照样返回 0**，把输出丢掉就更看不见了）、再推、
# 再按 md5 比对。实测踩过：脚本一路打印 ✓、服务照常起来、域也对，只有板上那份
# 还是旧件（167636 vs 168320），靠 md5 才发现。
push_bin() {
    local src="$1" dst="$2" want got
    if ! hdc file send "$src" "$dst" >/dev/null 2>&1; then
        echo "   ✗ 推不到 $dst：/ 是 rw 吗？(mount -o remount,rw /)" >&2
        exit 1
    fi
    sh_ "chmod 755 $dst"
    want=$(md5sum "$src" | cut -d' ' -f1)
    got=$(sh_ "md5sum $dst" | tr -d '\r' | cut -d' ' -f1)
    if [ "$want" != "$got" ]; then
        echo "   ✗ $dst 与宿主不一致 —— 板上 $got / 宿主 $want" >&2
        echo "   ✗ 多半是推的时候服务还在跑（ETXTBSY），而 hdc 不报这个错。" >&2
        exit 1
    fi
    echo "   ✓ $dst  md5=$want"
    sh_ "ls -laZ $dst"
}

cmd_install() {
    echo "== 0. 前置检查 =="
    sh_ "getenforce"
    sh_ "ls -la $POLICY"
    echo "   宿主产物: $(ls -la "$FRESHBIN" 2>/dev/null || echo '缺失！先跑 build')"

    echo
    echo "== 1. 备份原策略（cp -n，只备份一次）=="
    sh_ "mkdir -p $STAGE"
    sh_ "cp -n $POLICY $STAGE/policy.31.orig"
    sh_ "ls -la $STAGE/policy.31.orig"

    echo
    echo "== 2. 推新策略并加载（先进内核内存）=="
    hdc file send "$HERE/out/policy.31" "$STAGE/policy.31" >/dev/null
    sh_ "cp $STAGE/policy.31 $POLICY"
    sh_ "load_policy" || true        # 不吃参数；成不成看下一步实测

    echo
    echo "== 3. 立刻把磁盘换回原版（内核留新的 ⇒ 重启自动还原）=="
    sh_ "cp $STAGE/policy.31.orig $POLICY"

    echo
    echo "== 4. ★ 实测内核里到底是不是我们的策略 =="
    if ! verify_live; then
        echo "   ✗ 新策略没进内核。板子仍是原策略，未受任何影响。" >&2
        exit 1
    fi
    echo "   ✓ pl_collector 已在内核策略里"

    echo
    echo "== 5. 放二进制（不改标签：init 对 system_bin_file 本来就有 execute）=="
    # 两份都推同一个 $FRESHBIN：pl_fixer 与 pl_collector 是同一份源码，
    # 靠 argv 的 --fix / --guard 分流。推之前两个服务都得停。
    sh_ "begetctl service_control stop $SVC" >/dev/null 2>&1 || true
    sh_ "begetctl service_control stop $SVC_FIXER" >/dev/null 2>&1 || true
    sleep 1
    push_bin "$FRESHBIN" "$BIN"
    push_bin "$FRESHBIN" "$BIN_FIXER"

    echo
    echo "== 6. 放 init cfg =="
    hdc file send "$HERE/../board/policyloop.cfg" "$STAGE/policyloop.cfg" >/dev/null
    # 覆盖已有文件而不是新建：/system/etc 下 sed -i 会失败（要建临时文件），
    # 但 cp 覆盖已有 inode 是可以的。
    sh_ "cp $STAGE/policyloop.cfg $CFG"
    sh_ "ls -laZ $CFG"
    hdc file send "$HERE/../board/policyloop_fixer.cfg" "$STAGE/policyloop_fixer.cfg" >/dev/null
    sh_ "cp $STAGE/policyloop_fixer.cfg $CFG_FIXER"
    sh_ "ls -laZ $CFG_FIXER"

    echo
    echo "== 7. 放修复器的编译底座（base.cil + na_all.cil）=="
    # 这两份是**修复时的编译输入**，必须 root 拥有且应用不可写 —— 放应用沙箱
    # 等于让应用能改编译输入。放 /system/etc 的好处在方案里：该目录已被标成
    # system_etc_file，是现成标签，不需要新增类型、不需要改 file_contexts。
    for f in "$ASSET_BASE" "$ASSET_NA"; do
        [ -e "$f" ] || { echo "   ✗ 缺 $f —— 先跑 device/selinux_policy/build_pl_collector.sh" >&2; exit 1; }
    done
    sh_ "mkdir -p $ASSETDIR"
    for f in "$ASSET_BASE" "$ASSET_NA"; do
        local b; b=$(basename "$f")
        hdc file send "$f" "$STAGE/$b" >/dev/null
        sh_ "cp $STAGE/$b $ASSETDIR/$b"
        echo "   ✓ $ASSETDIR/$b  $(stat -c%s "$f") B"
    done
    # mkdir 出来的新目录**通常**继承父目录类型，但那是继承不是保证（取决于有没有
    # type_transition 命中），而 pl_fixer 读 base.cil 的权限正是挂在 system_etc_file
    # 这个标签上的。标签错了不会有任何报错，症状是「服务活着、什么都不报、只是
    # 永远读不到底座」——所以当场 chcon 并硬验。
    sh_ "chcon u:object_r:system_etc_file:s0 $ASSETDIR $ASSETDIR/base.cil $ASSETDIR/na_all.cil 2>/dev/null || true"
    if sh_ "ls -laZ $ASSETDIR/base.cil" | grep -q 'system_etc_file'; then
        echo "   ✓ 标签 system_etc_file"
    else
        echo "   ✗ base.cil 的标签不是 system_etc_file —— pl_fixer 读不到它，修复功能会哑掉" >&2
        echo "     （chcon 没生效？/ 是 rw 吗？）当前：" >&2
        sh_ "ls -laZ $ASSETDIR" >&2
        exit 1
    fi
    sh_ "ls -laZ $ASSETDIR"

    echo
    echo "== 8. 拉起服务 =="
    for s in $SVC $SVC_FIXER; do
        sh_ "begetctl service_control stop $s" >/dev/null 2>&1 || true
    done
    for s in $SVC $SVC_FIXER; do
        sh_ "begetctl service_control start $s" || true
    done
    sleep 2

    echo
    cmd_status
}

# 两份 cfg 只允许差 --debug-log 一项。
#
# 这条自检存在是因为「两份文件要同步改」这种纪律光靠记性没有用 —— 上一次
# 同类事情（商用公告要按 rowspan 解析）就是只记着、没落进代码，结果二十多条
# 记录从未被扫过，差点报出一个假的"干净"。所以这里宁可让脚本在推之前先吵。
cfg_consistency() {
    python3 - "$HERE/../board/policyloop.cfg" "$HERE/../board/policyloop-probe.cfg" << 'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
for d in (a, b):
    d.pop('comment', None)
pa, pb = list(a['services'][0].pop('path')), list(b['services'][0].pop('path'))
# 除 comment 与 services[0].path 之外，两份必须逐字段相同 —— 含顶层 jobs。
# 早先这里只比了 services[0]，于是后来加的 jobs 段整个落在自检之外；
# 一条只覆盖一半对象的自检比没有自检更危险，它会给出「已检查」的错觉。
if a != b:
    print('   ✗ 两份 cfg 除 comment / services[0].path 外还有差异：')
    print('     clean:', json.dumps(a, ensure_ascii=False, sort_keys=True))
    print('     probe:', json.dumps(b, ensure_ascii=False, sort_keys=True))
    sys.exit(1)
only_a = [x for x in pa if x not in pb]
only_b = [x for x in pb if x not in pa]
want = ['--debug-log', '/data/local/tmp/pl_debug.log']
ok = (only_b == want and not only_a)
print(('   ✓ ' if ok else '   ✗ ') +
      f'probe 相对 clean: 多出 {only_b}, 少掉 {only_a} (期望只多出 {want})')
sys.exit(0 if ok else 1)
PY
}

cmd_cfg() {
    local which="$1" src
    if [ "$which" = probe ]; then
        src="$HERE/../board/policyloop-probe.cfg"
    else
        src="$HERE/../board/policyloop.cfg"
    fi

    echo "== 1. 两份 cfg 一致性自检 =="
    cfg_consistency

    echo
    echo "== 2. 推 cfg 并重启服务 =="
    hdc file send "$src" "$STAGE/policyloop.cfg" >/dev/null
    # 覆盖已有 inode，不新建：/system/etc 下 sed -i 会失败（要建临时文件）。
    sh_ "cp $STAGE/policyloop.cfg $CFG"
    sh_ "ls -laZ $CFG"
    if grep -q -- '--debug-log' "$src"; then
        echo "   cfg 里 --debug-log: 在"
    else
        echo "   cfg 里 --debug-log: 不在"
    fi
    sh_ "begetctl service_control stop $SVC" >/dev/null 2>&1 || true
    sh_ "begetctl service_control start $SVC" || true
    sleep 2

    echo
    cmd_status
}

# 把板子摆到「起跑线」：开关归零、清窗、重起应用、点掉挡屏的系统弹窗。
# 摆完之后演示者只需要**用手指点开关** —— 在那之前不要再敲 hdc。
#
# 为什么要有这条：演示的失败模式几乎都不是功能坏了，而是起点不干净
# （开关还开着 ⇒ 拨了没有 0→1 跳变 ⇒ 不开新会话 ⇒ 看起来"没反应"），
# 或者插着 USB 弹的系统对话框把案例卡片挡住。两件事都机械，就该机械地做掉。
cmd_demo() {
    echo "== 摆到起跑线 =="

    sh_ "echo 0 > $APPDIR/guard.on"
    echo "   1. 开关归零"

    # 快照信道也归零。留一个 '1' 的话，演示者第一次按「载入当前快照」会立刻
    # 看到 req 已经是 0（上一轮的"完成"信号还在），于是秒回一个**上一次的文件**——
    # 界面有反应、内容是旧的，比没反应更难查。
    # req 用 echo 覆盖而不是 rm：文件不存在时应用写不进去（它没有 create 权限），
    # 而 shell 重定向会建一个 0644 root 的，采集器下一轮 chmod 0666 就正好了。
    sh_ "echo 0 > $APPDIR/snapshot.req"
    sh_ "rm -f $APPDIR/snapshot.jsonl"
    echo "   1b. 快照信道归零（req=0, snapshot.jsonl 清空）"

    # 修复信道同理，而且危害更大：留一个 fix.req='1' 的话，修复器一启动就拿
    # 上一轮的**选择**去编译装载 —— 演示还没开始，板子已经在改自己的策略了。
    # fix.sel 是"选择"本身，必须一并清掉（只清 req 的话，下一次 req=1 会立刻
    # 复用上一轮那份列表，屏上出现的是旧案例，比没反应更难查）。
    sh_ "echo 0 > $APPDIR/fix.req"
    sh_ "echo 0 > $APPDIR/fix.rollback"
    sh_ "rm -f $APPDIR/fix.sel $APPDIR/fix.out"
    echo "   1c. 修复信道归零（fix.req=0, fix.rollback=0, fix.sel/fix.out 清空）"

    # 等采集器退出会话。不等的话它还会写最后一批，清完立刻被补回来。
    local a b i
    for i in 1 2 3 4 5 6; do
        sleep 1; a=$(sh_ "wc -l < $APPDIR/live.jsonl 2>/dev/null" | tr -d ' \r')
        sleep 1; b=$(sh_ "wc -l < $APPDIR/live.jsonl 2>/dev/null" | tr -d ' \r')
        [ -n "$a" ] && [ "$a" = "$b" ] && break
    done
    echo "   2. 采集器已退出会话（行数停在 ${a:-0}）"

    sh_ "rm -f $APPDIR/live.jsonl"
    sh_ "aa force-stop $APP"
    sleep 2
    sh_ "aa start -a EntryAbility -b $APP"
    sleep 3
    echo "   3. 应用已重起（它会读回 guard.on ⇒ 显示「关」）"

    # 插着 USB 会弹「USB 连接方式」，正好压在屏幕正中挡住案例卡片。
    local lay=/data/local/tmp/pl_layout.json n
    sh_ "uitest dumpLayout -p $lay" >/dev/null 2>&1
    n=$(sh_ "grep -c 'USB 连接方式' $lay 2>/dev/null" | tr -d ' \r')
    if [ -n "$n" ] && [ "$n" != "0" ]; then
        sh_ "uitest uiInput click 360 715"
        echo "   4. 已点掉「USB 连接方式」弹窗"
    else
        echo "   4. 没有挡屏的系统弹窗"
    fi

    echo
    echo "   板端现状：guard.on=[$(sh_ "cat $APPDIR/guard.on" | tr -d ' \r')]  " \
         "live.jsonl=$(sh_ "wc -c < $APPDIR/live.jsonl" | tr -d ' \r') 字节  " \
         "snapshot.req=[$(sh_ "cat $APPDIR/snapshot.req 2>/dev/null" | tr -d ' \r')]  " \
         "采集器 pid=$(sh_ "pidof $SVC" | tr -d ' \r')  " \
         "修复器 pid=$(sh_ "pidof $SVC_FIXER" | tr -d ' \r')"
    echo
    echo "   ★ 现在放下 hdc，用手指点屏幕右上角的开关（720×1280 下约 (635,214)）。"
    echo "     预期 2 秒左右出横幅：pl_collector → data_local:dir / MISSING_RULE / search ×1。"
    echo "   ★ 窗口开着期间**不要再敲 hdc** —— 那些命令跑在 su 域，会被如实记成「工具造成」。"
}

case "${1:-install}" in
status)    cmd_status; exit 0 ;;
demo)      cmd_demo; exit 0 ;;
probe)     cmd_cfg probe; exit 0 ;;
clean)     cmd_cfg base; exit 0 ;;
stop)      for s in $SVC $SVC_FIXER; do sh_ "begetctl service_control stop $s" || true; done; exit 0 ;;
start)     for s in $SVC $SVC_FIXER; do sh_ "begetctl service_control start $s" || true; done
           sleep 2; cmd_status; exit 0 ;;
uninstall)
    for s in $SVC $SVC_FIXER; do sh_ "begetctl service_control stop $s" >/dev/null 2>&1 || true; done
    sh_ "rm -f $CFG $CFG_FIXER $BIN $BIN_FIXER"
    # 资产目录也一起拆：base.cil / na_all.cil 只在修复器活着时有意义，
    # 留着 1.7 MB 在 /system 里没有好处（而且 base.cil 是一份完整的策略源）。
    # applied.cil 不在那儿 —— 它在 /data/local/tmp/policyloop/。
    sh_ "rm -rf $ASSETDIR"
    echo "已删除 $CFG / $CFG_FIXER / $BIN / $BIN_FIXER / $ASSETDIR（策略未动）"
    exit 0 ;;
rollback)
    for s in $SVC $SVC_FIXER; do sh_ "begetctl service_control stop $s" >/dev/null 2>&1 || true; done
    sh_ "rm -f $CFG $CFG_FIXER $BIN $BIN_FIXER"
    sh_ "rm -rf $ASSETDIR"
    # 累积的补丁也清掉。它是**编译输入**，留着的话下次修复会把它叠回去 ——
    # 而那时内核里早没有那些规则了，结果是"回滚了，但下次一点又全回来了"。
    sh_ "rm -rf /data/local/tmp/policyloop"
    sh_ "test -f $STAGE/policy.31.orig && cp $STAGE/policy.31.orig $POLICY"
    echo "服务与板端资产已拆，磁盘策略已还原。⚠️ 若跑过 persist，必须重启才彻底回到原策略。"
    exit 0 ;;
esac

cmd_install

echo
if [ "${1:-install}" = persist ]; then
    echo "== 9. persist：让磁盘也是新策略（★ 重启后仍生效）=="
    sh_ "cp $STAGE/policy.31 $POLICY; ls -la $POLICY"
    # ⚠️ 落盘的是**整份策略**，里面因此永久带着两条域：pl_collector 与 pl_fixer。
    #    也就是说 load_policy 这笔权限从此写在磁盘上。这和"修复结果落盘"是
    #    两件事，必须分开讲：修复结果只活在内存、重启即消失；这里持久化的是
    #    **修复器这个组件**。混成一句"我们不落盘"就是不老实。
    echo "   ⚠️ 已落盘（含 pl_collector 与 pl_fixer 两个域 —— load_policy 从此写在盘上）。"
    echo "      要回原状：bash $0 rollback 并重启。"
else
    echo "   磁盘仍是原策略 ⇒ **重启会丢掉两个域的策略**（二进制与 cfg 还在，但域没了）。"
    echo "   要让开机自启真正生效：bash $0 persist  然后重启。"
fi
