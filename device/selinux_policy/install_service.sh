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
#   bash install_service.sh stop       停服务
#   bash install_service.sh start      起服务
#   bash install_service.sh persist    ★落盘（重启后仍生效）
#   bash install_service.sh uninstall  拆掉服务（留着策略不管）
#   bash install_service.sh rollback   策略也还原到原版（要重启才彻底）
# =====================================================================
set -euo pipefail

export PATH=/home/szf/ohos_sdk_dl/tc_extract/toolchains:$PATH
HERE="$(cd "$(dirname "$0")" && pwd)"

STAGE=/data/local/tmp/plstage
POLICY=/system/etc/selinux/targeted/policy/policy.31
FRESHBIN=/home/szf/ohos_src/out/rk3568/security/selinux_adapter/denial_check
BIN=/system/bin/pl_collector
CFG=/system/etc/init/policyloop.cfg
SVC=pl_collector
APP=com.policyloop.console
APPDIR=/data/app/el2/100/base/$APP/haps/entry/files

sh_() { hdc shell "$1"; }

# 把内核此刻真正生效的策略拉回来，数我们的类型。这是唯一可信的判据：
# 磁盘上那份每次 install 都被还原成原版，看磁盘等于什么都没看。
verify_live() {
    local tmp; tmp=$(mktemp /tmp/live_policy.XXXXXX.31)
    if ! hdc file recv /sys/fs/selinux/policy "$tmp" >/dev/null 2>&1; then
        echo "   ! 拉取 /sys/fs/selinux/policy 失败"; rm -f "$tmp"; return 1
    fi
    python3 - "$tmp" << 'PY'
import sys
d = open(sys.argv[1], 'rb').read()
n = d.count(b'pl_collector')
print(f"   内核策略 {len(d)} 字节, pl_collector 出现 {n} 次")
sys.exit(0 if n else 1)
PY
    rm -f "$tmp"
}

cmd_status() {
    echo "== 服务进程 =="
    local pid
    pid=$(sh_ "pidof $SVC" 2>/dev/null | tr -d '\r' || true)
    if [ -z "$pid" ]; then
        echo "   ✗ 没在跑"
    else
        echo "   ✓ pid=$pid"
        echo "   ps -Z:"; sh_ "ps -Z | grep -E '$SVC' " || true
        echo "   域 (/proc/$pid/attr/current):"
        # 读别的进程的 attr/current 要 ptrace 权限，拿不到不是故障，是策略在管事。
        sh_ "cat /proc/$pid/attr/current 2>&1" || true
    fi
    echo
    echo "== 内核策略里有没有 pl_collector =="
    if verify_live; then echo "   ✓ 在" ; else echo "   ✗ 不在（策略没加载或已被还原）"; fi
    echo
    echo "== 共享文件 =="
    sh_ "ls -la $APPDIR 2>&1 | grep -E 'guard.on|live.jsonl|总用量|total' " || true
    echo "   live.jsonl 行数: $(sh_ "wc -l < $APPDIR/live.jsonl 2>/dev/null" | tr -d '\r' || echo '?')"
    echo
    echo "== 我们这个域的 AVC 缺口（有就是权限没给够）=="
    sh_ "dmesg | grep 'u:r:$SVC:s0' | tail -15" || true
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
    if ! hdc file send "$FRESHBIN" "$BIN" >/dev/null 2>&1; then
        echo "   ✗ 推不进去：/ 是 rw 吗？(mount -o remount,rw /)" >&2
        exit 1
    fi
    sh_ "chmod 755 $BIN"
    sh_ "ls -laZ $BIN"

    echo
    echo "== 6. 放 init cfg =="
    hdc file send "$HERE/../board/policyloop.cfg" "$STAGE/policyloop.cfg" >/dev/null
    # 覆盖已有文件而不是新建：/system/etc 下 sed -i 会失败（要建临时文件），
    # 但 cp 覆盖已有 inode 是可以的。
    sh_ "cp $STAGE/policyloop.cfg $CFG"
    sh_ "ls -laZ $CFG"

    echo
    echo "== 7. 拉起服务 =="
    sh_ "begetctl service_control stop $SVC" >/dev/null 2>&1 || true
    sh_ "begetctl service_control start $SVC" || true
    sleep 2

    echo
    cmd_status
}

case "${1:-install}" in
status)    cmd_status; exit 0 ;;
stop)      sh_ "begetctl service_control stop $SVC"; exit 0 ;;
start)     sh_ "begetctl service_control start $SVC"; sleep 2; cmd_status; exit 0 ;;
uninstall)
    sh_ "begetctl service_control stop $SVC" >/dev/null 2>&1 || true
    sh_ "rm -f $CFG $BIN"
    echo "已删除 $CFG 与 $BIN（策略未动）"
    exit 0 ;;
rollback)
    sh_ "begetctl service_control stop $SVC" >/dev/null 2>&1 || true
    sh_ "rm -f $CFG $BIN"
    sh_ "test -f $STAGE/policy.31.orig && cp $STAGE/policy.31.orig $POLICY"
    echo "服务已拆，磁盘策略已还原。⚠️ 若跑过 persist，必须重启才彻底回到原策略。"
    exit 0 ;;
esac

cmd_install

echo
if [ "${1:-install}" = persist ]; then
    echo "== 8. persist：让磁盘也是新策略（★ 重启后仍生效）=="
    sh_ "cp $STAGE/policy.31 $POLICY; ls -la $POLICY"
    echo "   ⚠️ 已落盘。要回原状：bash $0 rollback 并重启。"
else
    echo "   磁盘仍是原策略 ⇒ **重启会丢掉服务**（二进制与 cfg 还在，但域没了）。"
    echo "   要让开机自启真正生效：bash $0 persist  然后重启。"
fi
