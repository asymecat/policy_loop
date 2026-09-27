#!/usr/bin/env bash
#
# 把采集守护送到板子上并拉起来。
#
#   tools/board_guard.sh push    只推二进制与脚本，不启动
#   tools/board_guard.sh start   推 + 起守护（先杀掉旧的）
#   tools/board_guard.sh status  看守护与采集器是否在跑
#   tools/board_guard.sh stop    停掉守护
#
# 守护起来之后，板子上就没有 PC 什么事了：开关在应用里，采集在守护里，
# 拔掉 USB 整条链路照常转。这个脚本只在"把东西送上去"这一步用。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HDC="${HDC:-$HOME/ohos_sdk_dl/tc_extract/toolchains/hdc}"
DEV=/data/local/tmp/policyloop
APP=com.policyloop.console

# 板端二进制：优先用刚编出来的那份，没有就退回已推上去的。
BIN_CANDIDATES=(
    "$HOME/ohos_src/out/rk3568/security/selinux_adapter/denial_check"
    "$ROOT/build/denial_check.arm"
)

hdc_() { "$HDC" "$@"; }

pick_bin() {
    for b in "${BIN_CANDIDATES[@]}"; do
        if [ -f "$b" ]; then echo "$b"; return 0; fi
    done
    echo "找不到板端 denial_check；先编一份：" >&2
    echo "  ~/ohos_src/build.sh --product-name rk3568 --build-target denial_check" >&2
    return 1
}

do_push() {
    local bin; bin="$(pick_bin)"
    echo "binary: $bin ($(stat -c%s "$bin") B, $(date -r "$bin" '+%m-%d %H:%M'))"
    hdc_ shell "mkdir -p $DEV"
    hdc_ file send "$bin" "$DEV/denial_check" >/dev/null
    hdc_ file send "$ROOT/device/board/pl_guard.sh" "$DEV/pl_guard.sh" >/dev/null
    hdc_ shell "chmod 755 $DEV/denial_check $DEV/pl_guard.sh"
    echo "pushed -> $DEV"
}

do_stop() {
    # 方括号防自杀：pkill -f pl_guard.sh 会匹配到执行它的这条 shell 自己。
    hdc_ shell "pkill -f 'pl_guar[d].sh'; pkill -f 'denial_check --follo[w]'" || true
    echo "stopped"
}

do_start() {
    do_stop
    do_push
    # setsid/后台化：hdc shell 退出时不能把守护带走。
    hdc_ shell "nohup sh $DEV/pl_guard.sh >/dev/null 2>&1 &"
    sleep 2
    do_status
}

do_status() {
    echo "--- 进程 ---"
    hdc_ shell "ps -ef 2>/dev/null | grep -E 'pl_guar[d]|denial_check --follo[w]' || echo '(均未运行)'"
    echo "--- 沙箱 ---"
    hdc_ shell "F=\$(ls -d /data/app/el2/*/base/$APP/haps/entry/files 2>/dev/null | head -1); \
        echo \"files=\$F\"; \
        ls -la \$F/guard.on \$F/live.jsonl 2>&1; \
        echo \"live lines=\$(wc -l < \$F/live.jsonl 2>/dev/null || echo 0)\""
    echo "--- guard.log 末尾 ---"
    hdc_ shell "tail -5 $DEV/guard.log 2>&1"
}

case "${1:-status}" in
    push)   do_push ;;
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)      echo "用法: $0 {push|start|stop|status}" >&2; exit 2 ;;
esac
