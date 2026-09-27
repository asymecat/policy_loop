#!/bin/bash
# =====================================================================
# 板端采集域策略构建(宿主侧)
#
#   板子原策略(CIL) + denial_check.cil 补丁  →  secilc  →  新 policy.31
#
# 为什么是"补 CIL"而不是"重编整个 OHOS":
#   板子的 policy.31 已经被 checkpolicy -b -C 反编译成 board-policy.cil,
#   而 CIL 往返编译已被验证语义等价(见 verify_roundtrip 输出),所以只需
#   在这份 CIL 后面追加语句即可,不用跑几小时的整包构建。
# =====================================================================
set -euo pipefail

SELINUX_SRC=/home/szf/ohos_src/third_party/selinux
SECILC=$SELINUX_SRC/secilc/secilc
CHECKPOLICY=$SELINUX_SRC/checkpolicy/checkpolicy
BASE=/home/szf/board-5.0.3-fingerprint/board-policy.cil
ORIG_POLICY=/home/szf/board-5.0.3-fingerprint/policy.31
PATCH=/home/szf/policy_loop/device/selinux_policy/denial_check.cil
OUT=/home/szf/policy_loop/device/selinux_policy/out
POLICYVERS=31

mkdir -p "$OUT"

for f in "$SECILC" "$CHECKPOLICY" "$BASE" "$ORIG_POLICY" "$PATCH"; do
    [ -e "$f" ] || { echo "缺少: $f" >&2; exit 1; }
done

echo "== 1. 合并 CIL =="
cat "$BASE" "$PATCH" > "$OUT/patched.cil"
echo "   $(wc -l < "$OUT/patched.cil") 行"

echo "== 2. 编译(secilc -M true -c $POLICYVERS)=="
"$SECILC" -M true -c "$POLICYVERS" -o "$OUT/policy.31" "$OUT/patched.cil"
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
# 注意:checkpolicy 反编译会把权限名重排(如 getattr/read/open/ioctl → ioctl/read/getattr/open),
# 所以比对必须按"集合"而非字面串,否则会把正确的策略判成缺失。
"$CHECKPOLICY" -b -C -M -o "$OUT/verify.cil" "$OUT/policy.31" 2>/dev/null
python3 - "$OUT/verify.cil" << 'PY'
import sys, re
lines = open(sys.argv[1], encoding='utf-8', errors='replace').read().split('\n')

def norm(stmt):
    """把 (allow S T (C (p1 p2))) 归一成可以集合比较的键"""
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
    '(type denial_check)',
    '(type denial_check_exec)',
    '(typepermissive denial_check)',
    '(allow denial_check dev_kmsg_file (chr_file (getattr read open ioctl)))',
    '(allow denial_check kernel (system (syslog_read)))',
    # ★ 本轮正路:按二进制天然的 data_local_tmp 类型切域,不打标签
    '(typetransition normal_hap data_local_tmp process denial_check)',
    '(typetransition system_basic_hap data_local_tmp process denial_check)',
    '(typetransition system_core_hap data_local_tmp process denial_check)',
    '(typetransition su data_local_tmp process denial_check)',
    '(typetransition sh data_local_tmp process denial_check)',
    # ★★ 光有 typetransition 不够!内核 security_compute_sid() 先查
    #    avc_has_perm(源域→新域, process, transition),不过就直接 EACCES。
    #    上一版一条都没有,su 靠 permissive 侥幸过关,应用域会硬失败。
    # 注意:hap_domain 这条反编译后**被展开成三个成员类型**(secilc 编译时本来就
    # 按成员展开,二进制里 (allow hap_domain …) 与三条具体 allow 完全等价),
    # 所以断言要按展开后的形态写,否则会把正确的策略判成缺失。
    '(allow normal_hap denial_check (process (transition)))',
    '(allow system_basic_hap denial_check (process (transition)))',
    '(allow system_core_hap denial_check (process (transition)))',
    '(allow su denial_check (process (transition)))',
    '(allow sh denial_check (process (transition)))',
    # 应用/调试域读+执行那个文件(权限集照抄板子 init→hilogd 的模式)
    '(allow hap_domain data_local_tmp (file (read getattr map open execute)))',
    '(allow hap_domain data_local_tmp (dir (read getattr open search)))',
    # 采集域读索引(索引同在 /data/local/tmp)
    '(allow denial_check data_local_tmp (file (ioctl read getattr lock map open watch watch_reads)))',
    # round-1 遗留窄路径:标签打不上时它永不触发,留着为回补窄路径备用
    '(allow hap_domain denial_check_exec (file (read getattr map open execute)))',
    '(typetransition normal_hap denial_check_exec process denial_check)',
]

# ★ 反向断言:下面这些"创建转换"会让**创建本身**返回 EACCES(见 .cil 附录 A2 的实测),
#   曾经把 mkdir/cp 全打挂;最后一条是**参数写反**的带名转换(名字 与 结果类型 互换),
#   内核里会变成"建一个叫 denial_check_exec 的文件 → 类型 denial_check"。
#   它们绝不能再溜回策略里。
absent = [
    '(typetransition su data_local_tmp dir denial_check_tmp)',
    '(typetransition su denial_check_tmp file denial_check_exec)',
    '(typetransition su system_bin_file file denial_check_exec)',
    '(typetransition su data_local_tmp file "denial_check_exec" denial_check)',
]

fail = 0
for e in expect:
    # 期望值也必须过一遍 norm():have 里存的是"权限已排序"的形式,
    # 拿原始字面串去比会把正确的策略判成缺失(上一版就是这个 bug)。
    ok = (norm(e) in have) if e.startswith('(allow ') else (e in lines)
    print(('   ✓ ' if ok else '   ✗ 缺失: ') + e)
    fail |= (not ok)

print("   --- 反向断言:已知有害的创建转换必须不在 ---")
for e in absent:
    ok = e not in lines
    print(('   ✓ 已排除: ' if ok else '   ✗ 竟然还在: ') + e)
    fail |= (not ok)

sys.exit(1 if fail else 0)
PY
[ $? = 0 ] || { echo "验证失败" >&2; exit 1; }

echo "== 5. 与原版做语义 diff(只应多出我们的语句)=="
"$CHECKPOLICY" -b -C -M -o "$OUT/orig.cil" "$ORIG_POLICY" 2>/dev/null
python3 - "$OUT/orig.cil" "$OUT/verify.cil" << 'PY'
import sys, re
a = open(sys.argv[1], encoding='utf-8', errors='replace').read().split('\n')
b = open(sys.argv[2], encoding='utf-8', errors='replace').read().split('\n')
sa, sb = set(a), set(b)
added = [l for l in b if l not in sa and l.strip()]
removed = [l for l in a if l not in sb and l.strip()]
print(f"   新增 {len(added)} 行 / 移除 {len(removed)} 行")
if removed:
    # 唯一允许的"移除"是 neverallow 残留的死属性(往返编译会裁掉)
    bad = [l for l in removed
           if not re.match(r'^\((typeattribute|typeattributeset) [A-Za-z0-9_]+', l)]
    print(f"   其中非『死属性』的移除: {len(bad)}")
    for l in bad[:10]: print("     !", l[:120])
    assert not bad, "出现了预期外的移除,不要安装"
    print("   ✓ 移除项全是 neverallow 残留死属性(CIL 往返编译的正常行为)")
print("   ✓ 新增项(我们的补丁)前 8 条:")
for l in added[:8]: print("     +", l[:120])
PY

echo
echo "构建完成: $OUT/policy.31"
echo "下一步: bash install_to_board.sh"
