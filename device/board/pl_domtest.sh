#!/system/bin/sh
#
# 在 pl_collector 域里把采集器真跑一遍 —— 重启前的预演。
#
# 为什么需要它：init 只在**开机时**解析 /system/etc/init/*.cfg，
# 所以运行时加一个 cfg，正在跑的 init 根本不认识这个服务，
# begetctl start 会"成功返回"但什么都不发生。要验证服务能不能跑，
# 要么重启，要么自己把域切过去。
#
# 而这个 shell 本来就提供了切域的条件：hdc shell 以
# uid=0 context=u:r:su:s0 落地，su 在这个 eng 版里是 permissive，
# 所以它能写 /proc/self/attr/exec。那正是 init 的 secon 走的同一条路。
#
# ★ 切过去之后是 **enforcing** 的。su 的 permissive 只庇护 su 自己。
#
# ★★ 为什么输出要落文件、不能直接看 stdout：
#    内核在 exec 时会把"不属于新域"的描述符**关掉**，再把 0/1/2 重开成
#    /dev/null（hooks.c:1712 file_has_perm 那道 FD__USE 检查）。所以直接跑，
#    屏幕上什么都不会有 —— 不是程序没输出，是 stdout 被换成了 /dev/null。
#
# ★★ 本脚本依赖 PL_EXTRA_CIL=pl_collector_rehearsal.cil 那份**预演构建**
#    （给了 toybox 的 entrypoint）。**生产策略不要带那份文件。**
#
# 用法：hdc shell "sh /data/local/tmp/plstage/pl_domtest.sh"
#       然后拉 _probe.txt / _guard.err / live.jsonl

BIN=/system/bin/pl_collector
TB=/system/bin/toybox
APPDIR=/data/app/el2/100/base/com.policyloop.console/haps/entry/files
PROBE=$APPDIR/_probe.txt

echo -n u:r:pl_collector:s0 > /proc/self/attr/exec
if [ $? -ne 0 ]; then
    echo "!! setexeccon 失败：u:r:pl_collector:s0 解析不了（roletype/userrole 没配对？）"
    exit 1
fi

{
    echo "### 0. 基本盘"
    $BIN --version
    echo "version rc=$?"
    $BIN --selftest
    echo "selftest rc=$?"

    echo
    echo "### 1. ★ 生产命令 --guard --dedupe --kmsg，逐秒看 live.jsonl 长没长"
    $TB rm -f $APPDIR/guard.on $APPDIR/live.jsonl $APPDIR/_guard.err
    # stderr 单独留一份：guard 自己会报 "guard watching" / "session start" /
    # "switch went off"，那是判断它走到哪一步的唯一线索。
    $BIN --guard --dedupe --kmsg --dir $APPDIR > /dev/null 2> $APPDIR/_guard.err &
    $TB sleep 3

    echo "--- 开关还关着时，guard 的诊断 ---"
    $TB cat $APPDIR/_guard.err

    echo "--- 打开开关（生产里是应用干的）---"
    echo 1 > $APPDIR/guard.on
    for i in 1 2 3 4 5 6; do
        $TB sleep 1
        printf "t=%ss live.jsonl=" "$i"
        $TB wc -c < $APPDIR/live.jsonl
        # 空闲板子上没 denial，自己造一条（/proc 我们没给权限，必拒）
        $TB cat /proc/kallsyms > /dev/null 2>&1
    done

    echo "--- guard 诊断 ---"
    $TB cat $APPDIR/_guard.err
    echo "--- live.jsonl 行数 ---"
    $TB wc -l $APPDIR/live.jsonl

    echo "--- 关掉开关，看它停不停 ---"
    echo 0 > $APPDIR/guard.on
    $TB sleep 2
    $TB wc -l $APPDIR/live.jsonl
    $TB sleep 3
    $TB wc -l $APPDIR/live.jsonl
    echo "--- guard 诊断（应出现 switch went off）---"
    $TB cat $APPDIR/_guard.err

    $TB kill $GPID 2>/dev/null
} > $PROBE 2>&1

echo "done"
