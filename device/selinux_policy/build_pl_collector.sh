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
# 板端修复服务域。**必须一起编进来**：修复本身是"整份策略替换"，base 里要是没有
# pl_fixer，第一次修复装载就会把修复器自己从策略里抹掉（自我湮灭），
# 而且失败发生在装载成功之后 —— 现象是"修完一次，修复服务就没了"。
PATCH_FIXER=$PL_REPO/device/selinux_policy/pl_fixer.cil
# 红线断言集（从源码 .te 重建，neverallow 不进二进制策略所以要单独带）。
# 板端修复要拿它当门禁，所以它是要**上板**的资产，这里顺手一起产出。
NA_ALL=$BOARD_FP/na_all.cil
OUT=$PL_REPO/device/selinux_policy/out
POLICYVERS=31

# 可选：**预演专用**的额外授权。只在"用 su shell 手工复现 init 之外的环境"时用。
# 生产策略永远不该带这个文件 —— 它放宽的都是"从 su 继承了描述符"这类
# 真实服务根本不会遇到的情况。用法：
#   PL_EXTRA_CIL=.../pl_collector_rehearsal.cil bash build_pl_collector.sh
EXTRA="${PL_EXTRA_CIL:-}"

mkdir -p "$OUT"

for f in "$SECILC" "$CHECKPOLICY" "$BASE" "$ORIG_POLICY" "$PATCH" "$PATCH_FIXER" "$NA_ALL"; do
    [ -e "$f" ] || { echo "缺少: $f" >&2
                     echo "  提示: OHOS_SRC / BOARD_FP 可覆盖外部路径(见脚本头部)" >&2
                     exit 1; }
done

echo "== 1. 合并 CIL =="
if [ -n "$EXTRA" ]; then
    [ -e "$EXTRA" ] || { echo "缺少: $EXTRA" >&2; exit 1; }
    cat "$BASE" "$PATCH" "$PATCH_FIXER" "$EXTRA" > "$OUT/pl_collector-patched.cil"
    echo "   ★★ 这是**预演构建**，含额外授权: $EXTRA"
    echo "   ★★ 不要 persist 这份 —— 生产要重跑一次不带 PL_EXTRA_CIL 的。"
else
    cat "$BASE" "$PATCH" "$PATCH_FIXER" > "$OUT/pl_collector-patched.cil"
fi
# 这就是要上板的 base.cil：修复时每次都拿它当底，再叠 applied.cil。
# 名字叫 base 而不是 patched，是因为在板端它扮演的角色是"基线"。
cp "$OUT/pl_collector-patched.cil" "$OUT/base.cil"
cp "$NA_ALL" "$OUT/na_all.cil"
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

    # ================= pl_fixer 域（板端修复服务）=================
    '(type pl_fixer)',
    '(allow init pl_fixer (process (transition siginh rlimitinh)))',
    # ★★ exec 板载 secilc 走的是 **EXECUTE_NO_TRANS**，不是 entrypoint。
    #    域没有类型转换 ⇒ new_sid == old_sid ⇒ 内核走 hooks.c:2356-2361 的
    #    第一分支，那条路上**只查 execute_no_trans**，entrypoint 根本不查。
    #    照抄 pl_collector 的 `execute entrypoint` 会恰好漏掉唯一被查的那一位，
    #    症状是 execve 返回 EACCES、secilc 起不来、什么都修不了。
    #    这条断言把方向钉死：给 entrypoint 是错的，给 execute_no_trans 才对。
    '(allow pl_fixer system_bin_file (file (read getattr open map execute execute_no_trans)))',
    '(allow pl_fixer self (capability (dac_override dac_read_search)))',
    '(allow pl_fixer data_local_tmp (file (read write create getattr setattr append unlink open)))',
    '(allow pl_fixer debug_hap_data_file (file (ioctl read write create getattr setattr lock append map unlink open)))',
    '(allow pl_fixer selinuxfs (file (read write open)))',
    # ★★★ 全策略唯一一份特权。目标类型必须是 **security**（SECINITSID_SECURITY），
    #     不是 kernel —— 内核 selinuxfs.c 对 load_policy / setenforce / setbool
    #     三者检查的都是 SECINITSID_SECURITY。而 na_all.cil:736 那条 neverallow
    #     把目标写成 kernel，所以**它对我们这条零约束力**。这是上游的缺陷
    #     （见 pl_fixer.cil 头部长注释），不是我们绕过门禁。
    #     checkpolicy 反编译把同 s/t/class 的权限位合并，所以这里断言合并后的形态。
    '(allow pl_fixer security (security (compute_av load_policy)))',
    '(allow hiview pl_fixer (dir (search)))',
    '(allow hiview pl_fixer (file (read getattr open)))',
]

# ★ 反向断言：这个域**必须**是 enforcing 的。
#   上一轮的 denial_check 域带 (typepermissive denial_check)——那正是要摆脱的东西。
#   如果这条溜回来，整个"收权限"的论点就塌了，而且不会有任何报错。
absent = [
    '(typepermissive pl_collector)',
    # 修复域同样不许 permissive：它拿着 load_policy，是整份策略里权限最大的
    # 一个域，一旦 permissive 就等于把内核策略装载权无条件敞开。
    '(typepermissive pl_fixer)',
    # 反向断言上面那条方向：pl_fixer **不该**有 entrypoint（它没有类型转换）。
    # 真加上了也不会有报错，只会让人误以为转换存在、进而去找不存在的 transition。
    '(allow pl_fixer system_bin_file (file (entrypoint)))',
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

echo "== 6. 唯一持有者证明: load_policy 全策略恰好 1 条、主体 pl_fixer =="
# 这一段是"pl_fixer 是全策略唯一持有 load_policy 的域"的**机器证明**，不是声明。
# 它有内容，因为基线产物里 load_policy 的 allow 是 **0 条** —— 板子上没有任何域
# 能合法调用它（install 之所以一直能成，纯粹因为 eng 版 su 是 typepermissive）。
python3 - "$OUT/pl_collector-verify.cil" "$OUT/pl_collector-orig.cil" << 'PY'
import re, sys

def holders(path, perm):
    out = []
    for l in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'^\(allow (\S+) (\S+) \((\S+) \(([^)]*)\)\)\)$', l.strip())
        if m and m.group(3) == 'security' and perm in m.group(4).split():
            out.append((m.group(1), m.group(2)))
    return out

old, new = holders(sys.argv[2], 'load_policy'), holders(sys.argv[1], 'load_policy')
print(f"   基线产物 load_policy 持有者: {len(old)} 条  {old}")
print(f"   本版产物 load_policy 持有者: {len(new)} 条  {new}")
ok = (old == [] and new == [('pl_fixer', 'security')])
print(('   ✓ ' if ok else '   ✗ ') +
      "恰好 1 条、主体 pl_fixer、目标 security（可执行性检查在 selinuxfs.c:625-627）")
if not ok:
    print("   ✗ 唯一持有者证明不成立 —— 这份策略不要装", file=sys.stderr)
sys.exit(0 if ok else 1)
PY
[ $? = 0 ] || { echo "唯一持有者证明失败" >&2; exit 1; }

echo "== 7. 红线门正控：na_all.cil 一起喂给 secilc 时**真的会响**吗 =="
# 板端修复器的门 7 是这么工作的：把 na_all.cil 与待加载的 CIL 一起喂给 secilc，
# stderr 里出现 neverallow 就判撞红线、丢弃产物。这条只有在断言**真的会被求值**
# 时才有意义 —— 一条写错目标的断言（本仓刚踩过一个，见 pl_fixer.cil 头注释）
# 在 secilc 里照样会响，但对着内核语义是死的；反过来，一份没接上的 na_all.cil
# 会让门 7 变成纯装饰，而这**不会有任何报错**。
#
# 所以要造一条必然违例的规则，验证它确实被拦下。而且**只测一遍不够**：
# 同一份规则不带 na_all.cil 时也必须 rc=0，否则第一遍的失败可以解释成
# 「探针语法写错了」而不是「断言拦下了」—— 一个拼错的探针也能让正控通过。
#
# 探针挑 setenforce 而不是 load_policy：两者落在**同一条**断言（na_all.cil:736）上，
# 但 setenforce 是我们一条都不碰的权限，拿它当探针就没有"用自己开的门测自己"的味道。
# 顺带这个测试证明了那条断言是活的 —— 我们的 rc=0 因此才有信息量：
# **我们没踩它，是因为目标类型写对了 security**，不是因为它不响。
#
# ⚠️ 边界（如实记，别把门 7 说得比它结实）：na_all.cil 只覆盖源树 494 条
# neverallow 里的 404 条。**没覆盖的 88 条含 `domain.te:272-273`
# 「任何域不得写 rootfs/system_file/vendor_file」**（它们包在 updater_only(...)
# 条件宏里，形态不支持，见 docs/known-limitations.md:85）。也就是说：如果流水线
# 哪天渲染出一条 `allow X system_file:file write`，**门 7 拦不住它**。
# 本流水线只渲染 ExplainCase/ApplyGuards 过完门的最小补丁，不自由造规则，
# 所以这条是纵深防御的缺口而不是主防线 —— 但不能说成"neverallow 一律拒放权"。
PROBE=$OUT/na_probe.cil
printf '(allow pl_fixer kernel (security (setenforce)))\n' > "$PROBE"

set +e
"$SECILC" -M true -c "$POLICYVERS" -o "$OUT/probe-red.31" \
    "$OUT/base.cil" "$OUT/na_all.cil" "$PROBE" >/dev/null 2>"$OUT/probe-red.err"
rc_red=$?
"$SECILC" -M true -c "$POLICYVERS" -o "$OUT/probe-clean.31" \
    "$OUT/base.cil" "$PROBE" >/dev/null 2>"$OUT/probe-clean.err"
rc_clean=$?
set -e
n_na=$(grep -c 'neverallow' "$OUT/probe-red.err" || true)
where=$(grep -m1 -o 'neverallow check failed at [^ ]*' "$OUT/probe-red.err" || true)

echo "   带 na_all.cil : rc=$rc_red, stderr 里 neverallow 命中 $n_na 次  ${where}"
echo "   不带 na_all.cil: rc=$rc_clean （必须 0，否则探针本身有问题）"

fail=0
if [ "$rc_red" = 0 ]; then
    echo "   ✗ 造了违例却没被拦 —— na_all.cil 没接上，门 7 是摆设" >&2; fail=1
fi
if [ "$n_na" = 0 ]; then
    echo "   ✗ 失败了但 stderr 里没有 neverallow —— 是别的原因，不能算正控" >&2; fail=1
fi
if [ "$rc_clean" != 0 ]; then
    echo "   ✗ 不带断言也编不过 ⇒ 探针规则本身有问题，正控无效。stderr:" >&2
    sed 's/^/     /' "$OUT/probe-clean.err" >&2; fail=1
fi
[ $fail = 0 ] || exit 1
echo "   ✓ 违例被拦下，且失败确实来自那条断言（不是探针写错）"
rm -f "$PROBE" "$OUT/probe-red.31" "$OUT/probe-clean.31"

echo
echo "构建完成: $OUT/policy.31"
echo "上板资产: $OUT/base.cil ($(stat -c%s "$OUT/base.cil") B), $OUT/na_all.cil ($(stat -c%s "$OUT/na_all.cil") B)"
echo "下一步: 把 policy.31、base.cil、na_all.cil 与两份 init cfg 送上板子（见 install_service.sh）"
