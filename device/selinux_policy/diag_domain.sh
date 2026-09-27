#!/bin/sh
# =====================================================================
# 判定"域切换到底发生没有"(在板子上跑,由 install_to_board.sh 推送)
#
# 判据(按可靠性排序):
#   1. dmesg 里出现 scontext=u:r:denial_check:s0 —— 这是**正证**:只有进了
#      那个域才会产出带这个标签的审计行。0 条 = 没切进去。
#   2. /proc/<pid>/attr/current —— 加分项。从非 permissive 的域去读别人的
#      attr/current 要走 ptrace 检查,被挡下不算失败(所以写了"读不到")。
# =====================================================================
BIN=/data/local/tmp/policyloop/denial_check
IDX=/data/local/tmp/ohos-5.0.3.pli

echo "[shell 自己的域] $(cat /proc/self/attr/current 2>/dev/null || echo 读不到)"
echo "[二进制的标签] $(ls -Z $BIN 2>/dev/null)"

"$BIN" -i "$IDX" --kmsg --timeout-ms 8000 >/dev/null 2>&1 &
P=$!
sleep 2
echo "[采集进程 pid=$P 的域] $(cat /proc/$P/attr/current 2>/dev/null || echo '读不到(pttrace 被挡,看下面 dmesg)')"
wait $P
echo "[采集退出码] $?"

echo "[dmesg 中 u:r:denial_check:s0 的条数] $(dmesg | grep -c 'u:r:denial_check:s0')"
echo "--- 缺权限清单前 8 条(第二轮按这个算最小补齐)---"
dmesg | grep 'u:r:denial_check:s0' | head -8
echo "--- 对照:本 shell 域在 dmesg 里的条数 ---"
dmesg | grep -c 'scontext=u:r:su:s0'
