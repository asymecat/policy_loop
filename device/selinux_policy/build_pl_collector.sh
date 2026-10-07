#!/bin/bash
# =====================================================================
# 板端采集服务域 pl_collector 的策略构建（宿主侧）
#
#   板子原策略(CIL) + pl_collector.cil  →  secilc  →  新 policy.31
#
# 与上一轮 build_policy.sh 的关系：那份是 denial_check 域（走 type_transition
# 切域、且靠 typepermissive 才跑得起来）。这份是 init service 用的域，
# 走 secon 切域、**enforcing**。两份并存不冲突，但只需要装一份。
#
# 为什么是"补 CIL"而不是"重编整个 OHOS"：见 build_policy.sh 开头的说明。
# =====================================================================
set -euo pipefail

# 路径全部可用环境变量覆盖。默认值保持本机原样，换机器时按需覆盖：
#   OHOS_SRC   OH 源码树（提供 secilc / checkpolicy 两个宿主工具）
#   BOARD_FP   板子原始策略所在目录（board-policy.cil + policy.31）
#   PL_REPO    本仓库根目录（默认按脚本自身位置推导，一般不用设）
OHOS_SRC="${OHOS_SRC:-/home/szf/ohos_src}"
BOARD_FP="${BOARD_FP:-/home/szf/board-5.0.3-fingerprint}"
PL_REPO="${PL_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

SELINUX_SRC=$OHOS_SRC/third_party/selinux
SECILC=$SELINUX_SRC/secilc/secilc
CHECKPOLICY=$SELINUX_SRC/checkpolicy/checkpolicy
BASE=$BOARD_FP/board-policy.cil
ORIG_POLICY=$BOARD_FP/policy.31
PATCH=$PL_REPO/device/selinux_policy/pl_collector.cil
OUT=$PL_REPO/device/selinux_policy/out
POLICYVERS=31

# 可选：**预演专用**的额外授权。只在"用 su shell 手工复现 init 之外的环境"时用。
# 生产策略永远不该带这个文件 —— 它放宽的都是"从 su 继承了描述符"这类
# 真实服务根本不会遇到的情况。用法：
#   PL_EXTRA_CIL=.../pl_collector_rehearsal.cil bash build_pl_collector.sh
EXTRA="${PL_EXTRA_CIL:-}"

mkdir -p "$OUT"

for f in "$SECILC" "$CHECKPOLICY" "$BASE" "$ORIG_POLICY" "$PATCH"; do
    [ -e "$f" ] || { echo "缺少: $f" >&2
                     echo "  提示: OHOS_SRC / BOARD_FP 可覆盖外部路径(见脚本头部)" >&2
                     exit 1; }
done

echo "== 1. 合并 CIL =="
if [ -n "$EXTRA" ]; then
    [ -e "$EXTRA" ] || { echo "缺少: $EXTRA" >&2; exit 1; }
    cat "$BASE" "$PATCH" "$EXTRA" > "$OUT/pl_collector-patched.cil"
    echo "   ★★ 这是**预演构建**，含额外授权: $EXTRA"
    echo "   ★★ 不要 persist 这份 —— 生产要重跑一次不带 PL_EXTRA_CIL 的。"
else
    cat "$BASE" "$PATCH" > "$OUT/pl_collector-patched.cil"
fi
echo "   $(wc -l < "$OUT/pl_collector-patched.cil") 行"

echo "== 2. 编译(secilc -M true -c $POLICYVERS)=="
# secilc 会把 neverallow 违例直接报成错误。这里过了，就等于证明
# 我们这个新域**没有踩到板子策略里任何一条 neverallow**。
"$SECILC" -M true -c "$POLICYVERS" -o "$OUT/policy.31" "$OUT/pl_collector-patched.cil"
ls -la "$OUT/policy.31"

echo "== 3. 验证:头部必须与原版一致 =="
python3 - "$ORIG_POLICY" "$OUT/policy.31" << 'PY'
import sys
a = open(sys.argv[1], 'rb').read(32)
b = open(sys.argv[2], 'rb').read(32)
print("   原版:", ' '.join(f'{x:02x}' for x in a))
print("   新版:", ' '.join(f'{x:02x}' for x in b))
assert a[:16] == b[:16], "前 16 字节(magic/version/SE Linux/policyvers)必须一致"
assert a[16:20] == b[16:20], f"policyvers 必须一致: {a[16:20].hex()} vs {b[16:20].hex()}"
print("   ✓ 头部一致(policyvers =", int.from_bytes(b[16:20], 'little'), ")")
PY

echo "== 4. 验证:新域与关键授权确实进了二进制 =="
# checkpolicy 反编译会重排权限名，比对必须按"集合"而非字面串。
"$CHECKPOLICY" -b -C -M -o "$OUT/pl_collector-verify.cil" "$OUT/policy.31" 2>/dev/null
python3 - "$OUT/pl_collector-verify.cil" << 'PY'
import sys, re
lines = open(sys.argv[1], encoding='utf-8', errors='replace').read().split('\n')

def norm(stmt):
    m = re.match(r'^\((allow|typetransition|typepermissive|type)\s+(.*)\)$', stmt)
    if not m:
        return stmt
    kind, body = m.group(1), m.group(2)
    mm = re.match(r'^(\S+)\s+(\S+)\s+\((\S+)\s+\(([^)]*)\)\)$', body)
    if mm:
        src, tgt, cls, perms = mm.groups()
        return f'(allow {src} {tgt} ({cls} {{{" ".join(sorted(perms.split()))}}}))'
    return f'({kind} {body})'

have = set()
for l in lines:
    l = l.strip()
    if l.startswith('(allow '):
        have.add(norm(l))

expect = [
    # --- 前提：secon 这条路成立的依据 ---
    # init 对 "exec" 的检查是自检（hooks.c:6398），全靠这条撑着。
    # 它一旦不在，secon 会对所有服务失效——所以断言的是**板子原策略**的内容，
    # 顺带证明我们这个域确实不需要再补 transition。
    '(allow init self (process (fork sigstop signull signal getsched setsched getsession getpgid setpgid getcap setcap getattr setexec setrlimit setcurrent setsockcreate)))',
    # --- 域本身 ---
    '(type pl_collector)',
    '(roletype r pl_collector)',
    # ★★ 进域的两条硬门。第一版我断言这两条**不该存在**（当时只看了
    #    exec_sid 那几行，以为 secon 把 execve 的检查也免了）——错的。
    #    内核 exec_sid 那条路照旧走 else 分支，两条都查（hooks.c:2360-2372）。
    #    这条断言现在反过来，钉住这个教训。
    '(allow init pl_collector (process (transition siginh rlimitinh)))',
    '(allow pl_collector system_bin_file (file (read getattr open map execute entrypoint)))',
    # --- hilog 客户端。**缺了会 SIGSEGV**，不是可选项：
    #     libc 构造函数建不了 hilog 套接字 → 走 /dev/console 兜底 → 兜底也被拒
    #     → 进程崩。症状是连 --version 都起不来，极易误判成"二进制坏了"。
    '(allow pl_collector self (unix_dgram_socket (write create connect)))',
    '(allow pl_collector hilogd (unix_dgram_socket (sendto)))',
    # 这条没有任何 AVC 提示，是拿 hdcd 的三条对照出来的（见 pl_collector.cil 的注释）
    '(allow pl_collector hilog_input_socket (sock_file (write)))',
    # --- 存在的理由：读审计流 ---
    '(allow pl_collector kernel (system (syslog_read)))',
    '(allow pl_collector dev_kmsg_file (chr_file (read open)))',
    '(allow pl_collector self (capability2 (syslog)))',
    # --- 以 root 穿进 0700 的应用沙箱 ---
    '(allow pl_collector self (capability (dac_override dac_read_search)))',
    # --- 动态链接：musl 加载器 ---
    '(allow pl_collector system_lib_file (file (read getattr open map execute)))',
    # --- 数据出口 ---
    '(allow pl_collector debug_hap_data_file (dir (read write create getattr setattr open add_name remove_name search)))',
    '(allow pl_collector debug_hap_data_file (file (ioctl read write create getattr setattr lock append map unlink open)))',
    # --- 给别人的，不是给我们的：hiview 每 10s 扫一遍各进程 /proc，
    #     不补这两条就会产生"我们自己的改动引起的" denial 灌进我们自己的采集流。
    #     ★ 必须成对：dir search 负责进得去，file read 负责读 cmdline/stat。
    #       只给前者时每 10s 仍有两条 tclass=file 的 read 被拒。
    '(allow hiview pl_collector (dir (search)))',
    '(allow hiview pl_collector (file (read getattr open)))',
]

# ★ 反向断言：这个域**必须**是 enforcing 的。
#   上一轮的 denial_check 域带 (typepermissive denial_check)——那正是要摆脱的东西。
#   如果这条溜回来，整个"收权限"的论点就塌了，而且不会有任何报错。
absent = [
    '(typepermissive pl_collector)',
]

fail = 0
for e in expect:
    ok = (norm(e) in have) if e.startswith('(allow ') else (e in lines)
    print(('   ✓ ' if ok else '   ✗ 缺失: ') + e[:110])
    fail |= (not ok)

print("   --- 反向断言 ---")
for e in absent:
    ok = e not in lines
    print(('   ✓ 已排除: ' if ok else '   ✗ 竟然还在: ') + e)
    fail |= (not ok)

sys.exit(1 if fail else 0)
PY
[ $? = 0 ] || { echo "验证失败" >&2; exit 1; }

echo "== 5. 与原版做语义 diff(只应多出我们的语句)=="
"$CHECKPOLICY" -b -C -M -o "$OUT/pl_collector-orig.cil" "$ORIG_POLICY" 2>/dev/null
python3 - "$OUT/pl_collector-orig.cil" "$OUT/pl_collector-verify.cil" << 'PY'
import sys, re
a = open(sys.argv[1], encoding='utf-8', errors='replace').read().split('\n')
b = open(sys.argv[2], encoding='utf-8', errors='replace').read().split('\n')
sa, sb = set(a), set(b)
added = [l for l in b if l not in sa and l.strip()]
removed = [l for l in a if l not in sb and l.strip()]
print(f"   新增 {len(added)} 行 / 移除 {len(removed)} 行")
if removed:
    bad = [l for l in removed
           if not re.match(r'^\((typeattribute|typeattributeset) [A-Za-z0-9_]+', l)]
    print(f"   其中非『死属性』的移除: {len(bad)}")
    for l in bad[:10]: print("     !", l[:120])
    assert not bad, "出现了预期外的移除,不要安装"
    print("   ✓ 移除项全是 neverallow 残留死属性(CIL 往返编译的正常行为)")
print("   ✓ 新增项前 10 条:")
for l in added[:10]: print("     +", l[:120])
PY

echo
echo "构建完成: $OUT/policy.31"
echo "下一步: 把 policy.31 与 init cfg 送上板子（见 install_service.sh）"
