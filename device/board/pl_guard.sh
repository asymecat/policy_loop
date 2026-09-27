#!/system/bin/sh
#
# PolicyLoop 采集守护 —— 板端常驻的那个"特权半边"。
#
# 为什么必须是独立进程：应用拿不到 denial 流，这不是偷懒是策略划的线。
#   * 三档 HAP（normal/system_basic/system_core）全被 neverallow 挡在 /dev/kmsg 外；
#   * 板上 dmesg_restrict=1，连 CAP_SYSLOG 都要；
#   * /dev/kmsg 本身是 0660 root:system —— DAC 是第一道门，SELinux 只是第二道。
# 所以架构是刻意不对称的：**特权进程负责采集，无特权应用负责解读与呈现**。
# 应用侧一行提权代码都没有，这正是设计要的结果，不是妥协。
#
# 数据怎么过河：不新开任何 SELinux 通道，走**应用自己的沙箱**。
#   /data/app/el2/<uid>/base/<bundle>/haps/entry/files 的标签是 debug_hap_data_file，
#   板子策略里有 `(allow hap_domain debug_hap_data_file (file (read write open)))`
#   —— 应用读写自己的文件本来就允许；守护以 root 身份往同一个目录写，
#   文件按父目录继承同一个标签，于是应用读得到，**不需要一条新策略**。
#   （注意：全策略里能写 debug_hap_data_file 的只有 hap_domain 自己，
#     root 能写是因为 eng 版把 su 配成了 typepermissive —— 见 README 的"生产形态"。）
#
# 开关走文件不走 socket：应用只写自己沙箱里的 guard.on，守护轮询它。
# 应用因此不需要任何能力，连一条 allow 都不用加。
#
# 用法（PC 侧）：hdc shell "sh /data/local/tmp/policyloop/pl_guard.sh" &

APP=com.policyloop.console
BASE=/data/local/tmp/policyloop
BIN=$BASE/denial_check
LOG=$BASE/guard.log

log() {
    echo "[guard $(date '+%m-%d %H:%M:%S')] $*" >> $LOG
}

log "=== daemon up (pid $$) ==="

while true; do
    # 每次重新发现沙箱：应用可能是守护起来之后才装上的，uid 也可能变。
    FILES=$(ls -d /data/app/el2/*/base/$APP/haps/entry/files 2>/dev/null | head -1)
    if [ -z "$FILES" ]; then
        sleep 3
        continue
    fi

    SW=$FILES/guard.on
    LIVE=$FILES/live.jsonl

    # 先把两个文件建出来，应用才有得可写。
    # 这一步不能省：板子策略里应用对这个标签只有
    #   (allow hap_domain debug_hap_data_file (file (read write open)))
    # ——**只有 file 类，没有 dir 类**。也就是说应用能改已存在的文件，
    # 但**建不了新文件**。装完应用沙箱是空的，守护不先把文件摆好，
    # 开关就会以"开关写不下去"失败。（我是踩过才知道的。）
    if [ ! -f $SW ]; then echo 0 > $SW; fi
    if [ ! -f $LIVE ]; then : > $LIVE; fi
    chmod 666 $SW $LIVE 2>/dev/null

    if [ "$(cat $SW 2>/dev/null)" != "1" ]; then
        sleep 1
        continue
    fi

    # 开一次新会话：截断旧记录。应用看到的是"这次开启之后发生了什么"，
    # 而不是上一次的残留 —— 演示时这一点很重要，列表必须从空开始。
    : > $LIVE
    chmod 666 $LIVE
    log "session start -> $LIVE"

    # --kmsg 而不是 --log /dev/kmsg：前者才是"跟随"源（保持一个句柄，每次只读新增），
    # 后者是按文件快照读的，--follow 会直接拒绝它。两者差别不是路径写法。
    # --from-now 丢掉积压：环里存着开机以来的历史，开发者要的是"从现在起"。
    # --dedupe 按指纹去重：同一条 denial 每秒复发几十次，全写进去文件就没法看了。
    $BIN --follow --dedupe --from-now --kmsg >> $LIVE 2>>$LOG &
    PID=$!
    log "collector pid=$PID"

    # 应用把开关拨回去就收工。守护不退，继续等下一次开启。
    while [ "$(cat $SW 2>/dev/null)" = "1" ]; do
        sleep 1
    done

    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    log "session stop (collector rc=$?)"
done
