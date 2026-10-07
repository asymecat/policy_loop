#!/bin/bash
# =====================================================================
# 把带 denial_check 域的策略装到板子上并验证
#
# 【这块板子上策略加载的唯一入口】(源码查实,不是猜的)
#   /bin/load_policy 是 OHOS 自研的(policycoreutils),不是 toybox:
#       int main(int argc, char **argv) { (void)argc; (void)argv; return LoadPolicy(); }
#   ⇒ 它**忽略一切参数**,路径由 GetPolicyFile() 自己决定:
#       1. updater 模式              → DEFAULT_POLICY
#       2. /system/etc/selinux/system.cil 不存在 → DEFAULT_POLICY   ← 本板走这条
#       3. 预编译哈希对得上           → /vendor/.../prebuild_sepolicy/policy.31
#       4. 否则                       → 现场用 updater 重编 CIL → /dev/policy.31
#   ⇒ 结论:它加载的就是 /system/etc/selinux/targeted/policy/policy.31。
#      "覆盖这个文件 + 跑 load_policy" 是唯一的入口。
#
# 【安全手法】加载完**立刻把磁盘那份换回原版**:
#   内核内存跑新策略,磁盘留旧策略 ⇒ 任何时候重启都自动回到原状。
#   要持久化必须显式 persist(那时才真的动磁盘)。
#
# 【落点与域切换方式】完整实测记录见 denial_check.cil 的附录 A/B。
#   一句话:**不打标签**。二进制落在 /data/local/tmp,类型就是它天然的
#   data_local_tmp,域切换直接以这个类型为键。两条打标签的路
#   (restorecon / 内核创建转换)都已实测走不通,别再试。
#
# 用法:
#   bash install_to_board.sh          # 装 + 放二进制 + 判定域切换 + 收缺口
#   bash install_to_board.sh verify   # 只看当前内核策略是不是我们的
#   bash install_to_board.sh diag     # 只重跑域切换判定(不改策略)
#   bash install_to_board.sh round2   # 把它自己暴露的 denial 喂回 PolicyLoop
#   bash install_to_board.sh persist  # 落盘(重启后仍生效)
#   bash install_to_board.sh rollback # 删我们的目录、清历史遗留的 file_contexts 行
# =====================================================================
set -euo pipefail

# 宿主侧路径可用环境变量覆盖（默认值保持本机原样）：
#   HDC_DIR    含 hdc 的目录（SDK toolchains）
#   OHOS_SRC   OH 源码树（取 out/<product>/security/… 下刚编好的二进制）
HDC_DIR="${HDC_DIR:-$HOME/ohos_sdk_dl/tc_extract/toolchains}"
OHOS_SRC="${OHOS_SRC:-$HOME/ohos_src}"
export PATH=$HDC_DIR:$PATH
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE=/data/local/tmp/plstage                 # 备份/暂存区
DCDIR=/data/local/tmp/policyloop              # 我们的目录
BIN=$DCDIR/denial_check
INDEX=/data/local/tmp/ohos-5.0.3.pli          # 索引留在原地(类型 data_local_tmp)
SRCBIN=/system/bin/denial_check               # 板上那份(退回用)
# 宿主机上刚编好的 device 二进制。★ 注意:重编产物落在 out/rk3568/security/…
# 而不是 out/rk3568/src/security/…(后者是 9/16 的旧件,推了白推)。
FRESHBIN=$OHOS_SRC/out/rk3568/security/selinux_adapter/denial_check
POLICY=/system/etc/selinux/targeted/policy/policy.31
FC=/system/etc/selinux/targeted/contexts/file_contexts

sh_() { hdc shell "$1"; }

# 把内核此刻真正生效的策略拉回来,数一数有没有我们的类型
verify_live() {
    local tmp; tmp=$(mktemp /tmp/live_policy.XXXXXX.31)
    if ! hdc file recv /sys/fs/selinux/policy "$tmp" >/dev/null 2>&1; then
        echo "   ! 拉取 /sys/fs/selinux/policy 失败"; rm -f "$tmp"; return 1
    fi
    python3 - "$tmp" << 'PY'
import sys
d = open(sys.argv[1], 'rb').read()
n = d.count(b'denial_check_exec')
print(f"   内核策略 {len(d)} 字节, denial_check_exec 出现 {n} 次")
sys.exit(0 if n else 1)
PY
}

cmd_verify() {
    echo "== 内核此刻生效的策略 =="
    if verify_live; then echo "   ✓ 我们的策略在内核里"; else echo "   ✗ 内核里不是我们的策略"; fi
}

cmd_diag() {
    echo "== 域切换判定(只读,不改任何东西) =="
    hdc file send "$HERE/diag_domain.sh" "$STAGE/diag_domain.sh" >/dev/null
    # 主判据是 dmesg(不需要 ptrace,谁跑都行);
    # /proc/<pid>/attr/current 是加分项,被 ptrace 挡下的话脚本会自己说明。
    sh_ "sh $STAGE/diag_domain.sh"
}

cmd_round2() {
    echo "== 把它自己暴露的 denial 喂回 PolicyLoop =="
    sh_ "dmesg | grep 'u:r:denial_check:s0' > $STAGE/self_gaps.txt"
    sh_ "wc -l $STAGE/self_gaps.txt"
    echo "   ↓ 用自家引擎对自家权限缺口算最小补齐:"
    sh_ "$BIN -i $INDEX --log $STAGE/self_gaps.txt --converge" || true
    echo
    echo "   把上面的补丁并进 denial_check.cil、去掉 (typepermissive denial_check),"
    echo "   重跑 build_policy.sh → install_to_board.sh 即第二轮(最小权限)。"
    echo "   清单可取回: hdc file recv $STAGE/self_gaps.txt ."
}

cmd_rollback() {
    echo "== 回滚 =="
    sh_ "rm -rf $DCDIR" 2>/dev/null || true
    echo "   已删除 $DCDIR"
    # 历史遗留:早前几轮往 file_contexts 追加过指向 denial_check_* 类型的条目,
    # 那些类型只在**内存策略**里存在,重启后任何 restorecon 读到都会指向未知类型。
    # 已经不用这条路了,把它清干净。
    if [ "$(sh_ "grep -c policyloop $FC" 2>/dev/null || echo 0)" != "0" ]; then
        # 不能 sed -i:它会在 /system/etc 下新建临时文件,那条路是堵的。
        # grep -v 到暂存区再 cp 回原文件(覆盖已有 inode,不新建)。
        sh_ "grep -v 'policyloop' $FC > $STAGE/fc.clean && cp $STAGE/fc.clean $FC" || true
        echo "   已清除 file_contexts 里的历史追加行"
    else
        echo "   file_contexts 里没有遗留条目"
    fi
    if sh_ "test -f $STAGE/policy.31.orig && echo yes" | grep -q yes; then
        sh_ "cp $STAGE/policy.31.orig $POLICY"
        echo "   磁盘策略文件已还原。"
    fi
    echo "   ⚠️ 如果之前跑过 persist,必须重启板子才能彻底回到原策略。"
}

case "${1:-install}" in
verify)   cmd_verify; exit 0 ;;
diag)     cmd_diag; exit 0 ;;
round2)   cmd_round2; exit 0 ;;
rollback) cmd_rollback; exit 0 ;;
esac

echo "== 0. 前置检查 =="
sh_ "getenforce"
sh_ "ls -la $POLICY $SRCBIN $INDEX"

echo
echo "== 1. 备份原策略(只备份一次,cp -n 不覆盖) =="
# 只从 $POLICY 备份:磁盘那份每次运行都被 step 4 还原成原版,是可信来源。
# (不要从 $DCDIR 里捡历史备份 —— 那份是哪一轮的已经说不清了。)
sh_ "mkdir -p $STAGE"
sh_ "cp -n $POLICY $STAGE/policy.31.orig"
sh_ "ls -la $STAGE/policy.31.orig"

echo
echo "   清掉历史遗留的 file_contexts 追加行(早前几轮的方案,已废弃)"
if [ "$(sh_ "grep -c policyloop $FC" 2>/dev/null || echo 0)" != "0" ]; then
    sh_ "grep -v 'policyloop' $FC > $STAGE/fc.clean && cp $STAGE/fc.clean $FC" || true
    echo "   ✓ 已清除"
else
    echo "   无遗留"
fi

echo
echo "== 2. 推我们的策略到暂存区 =="
hdc file send "$HERE/out/policy.31" "$STAGE/policy.31"
sh_ "ls -la $STAGE/policy.31"

echo
echo "== 3. 覆盖到 load_policy 会读的那个位置,然后加载 =="
sh_ "cp $STAGE/policy.31 $POLICY && ls -la $POLICY"
sh_ "load_policy" || true          # 它不吃参数;失败与否以下面的实测为准

echo
echo "== 4. 立刻把磁盘换回原版(内核保留新的 ⇒ 重启即自动还原) =="
sh_ "cp $STAGE/policy.31.orig $POLICY && ls -la $POLICY"

echo
echo "== 5. ★ 实测:内核里现在到底是不是我们的策略 =="
if ! verify_live; then
    echo "   ✗ 新策略没进内核。板子仍是原策略,未受任何影响。" >&2
    echo "   先别继续,把上面输出发我。" >&2
    exit 1
fi
echo "   ✓ 域与类型已在内核中"

echo
echo "== 6. 放二进制(不打标签:用它在 /data/local/tmp 里天然的 data_local_tmp 类型切域) =="
sh_ "rm -rf $DCDIR"
sh_ "mkdir -p $DCDIR"
# 优先推宿主机上刚编好的那份;拿不到才退回板上 /system/bin 里那份。
# hdcd 对 data_local_tmp 有完整 add_name/create(已实测),这条通路是通的。
if [ -f "$FRESHBIN" ] && hdc file send "$FRESHBIN" "$BIN" >/dev/null 2>&1; then
    echo "   已从宿主机推入: $FRESHBIN"
else
    sh_ "cp $SRCBIN $BIN"
    echo "   ⚠️ 宿主机那份拿不到,退回用板上 /system/bin 里的"
fi
sh_ "chmod 755 $BIN"
sh_ "ls -laZ $BIN"

echo
echo "== 7. ★ 判定域切换(本轮的核心结论就在这几行) =="
hdc file send "$HERE/diag_domain.sh" "$STAGE/diag_domain.sh" >/dev/null
sh_ "sh $STAGE/diag_domain.sh"

echo
echo "== 8. 收集 permissive 域暴露出的权限缺口(第二轮算最小补齐用) =="
sh_ "dmesg | grep 'u:r:denial_check:s0' > $STAGE/self_gaps.txt"
sh_ "wc -l $STAGE/self_gaps.txt"
if hdc file recv "$STAGE/self_gaps.txt" "$HERE/out/self_gaps.txt" >/dev/null 2>&1; then
    echo "   已取回宿主机: out/self_gaps.txt"
fi

echo
if [ "${1:-install}" = persist ]; then
    echo "== 9. persist:让磁盘也是新策略(重启后仍生效) =="
    sh_ "cp $STAGE/policy.31 $POLICY; ls -la $POLICY"
    echo "   ⚠️ 已落盘。要回原状必须 bash $0 rollback 并重启。"
else
    echo "   磁盘仍是原策略 ⇒ 重启即自动还原。要持久化: bash $0 persist"
fi

echo
echo "完成。下一步: bash $0 round2"
echo "回滚: bash $0 rollback"
