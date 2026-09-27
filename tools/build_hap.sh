#!/usr/bin/env bash
#
# 构建 → 签名 → 安装板端控制台 HAP。
#
#   tools/build_hap.sh build    只构建（hvigor，出 unsigned hap）
#   tools/build_hap.sh sign     构建 + 生成 profile + 签名
#   tools/build_hap.sh install  sign + 装到板子 + 拉起
#
# 为什么签名要这么多步：hvigor 不会替你签（build-profile.json5 里 signingConfigs
# 是空的），走 DevEco 的那套在线签名这里也没有。所以用 OpenHarmony 自带的调试材料
# 本地签：先用 profile 密钥签一份 profile（里面写死 bundle-name 与本机 UDID），
# 再用应用密钥签 hap 本体，profile 作为附件打进去。
#
# 材料来自 ohos_src 里的 hapsigner/dist —— 它比 SDK toolchains/lib 全，
# 多一份 OpenHarmonyApplication.pem（签 hap 本体要用的应用证书）。
set -euo pipefail

PROJ="${PROJ:-/home/szf/ohos_audit/pl_console}"
BUNDLE="${BUNDLE:-com.policyloop.console}"
CMD_TOOLS=/home/szf/ohos_src/prebuilts/tool/command-line-tools/6.x
DIST=/home/szf/ohos_src/developtools/hapsigner/dist
OUT="${OUT:-/tmp/plc-build}"
HDC="${HDC:-$HOME/ohos_sdk_dl/tc_extract/toolchains/hdc}"
PW=123456

UNSIGNED="$PROJ/entry/build/default/outputs/default/entry-default-unsigned.hap"

do_build() {
    echo "== hvigor assembleHap =="
    # hvigorw 必须在项目根跑，否则报 00304004 Not Found。
    ( cd "$PROJ" && bash "$CMD_TOOLS/bin/hvigorw" assembleHap \
        --mode module -p product=default --no-daemon )
}

do_profile() {
    mkdir -p "$OUT"
    echo "== 生成 profile =="
    # 模板里的 bundle-name 是 com.OpenHarmony.app.test，必须改成自己的；
    # device-ids 也要换成真板子的 UDID，否则 debug profile 装不进去。
    # `bm get -u` 把 UDID 打在**冒号的下一行**，不是冒号后面 —— 按行首的十六进制串取，
    # 别按冒号切（那样会取到空行）。
    local udid
    udid="$("$HDC" shell "bm get -u" 2>/dev/null | tr -d '\r' \
            | grep -E '^[0-9A-Fa-f]{40,}$' | head -1)"
    if [ -z "$udid" ]; then
        echo "拿不到板子 UDID（板子连上了吗？）" >&2
        return 1
    fi
    python3 - "$DIST/UnsgnedDebugProfileTemplate.json" "$OUT/profile.json" \
              "$BUNDLE" "$udid" <<'PY'
import json, sys
src, dst, bundle, udid = sys.argv[1:5]
p = json.load(open(src))
p["bundle-info"]["bundle-name"] = bundle
p["debug-info"]["device-ids"] = [udid]
json.dump(p, open(dst, "w"), indent=4)
print(f"  bundle={bundle} udid={udid[:16]}…")
PY

    java -jar "$DIST/hap-sign-tool.jar" sign-profile \
        -keyAlias "openharmony application profile debug" \
        -signAlg SHA256withECDSA -mode localSign \
        -profileCertFile "$DIST/OpenHarmonyProfileDebug.pem" \
        -inFile "$OUT/profile.json" -outFile "$OUT/profile.p7b" \
        -keystoreFile "$DIST/OpenHarmony.p12" \
        -keyPwd $PW -keystorePwd $PW >/dev/null
    echo "  profile.p7b ok"
}

do_sign() {
    do_build
    do_profile
    echo "== 签名 hap =="
    java -jar "$DIST/hap-sign-tool.jar" sign-app \
        -keyAlias "openharmony application release" \
        -signAlg SHA256withECDSA -mode localSign \
        -appCertFile "$DIST/OpenHarmonyApplication.pem" \
        -profileFile "$OUT/profile.p7b" -inForm zip \
        -inFile "$UNSIGNED" -outFile "$OUT/plc-signed.hap" \
        -keystoreFile "$DIST/OpenHarmony.p12" \
        -keyPwd $PW -keystorePwd $PW >/dev/null
    echo "  $OUT/plc-signed.hap ($(stat -c%s "$OUT/plc-signed.hap") B)"
}

do_install() {
    do_sign
    echo "== 安装 =="
    "$HDC" install -r "$OUT/plc-signed.hap"
    "$HDC" shell "aa force-stop $BUNDLE" || true
    "$HDC" shell "aa start -a EntryAbility -b $BUNDLE"
    echo "已拉起 $BUNDLE"
}

case "${1:-install}" in
    build)   do_build ;;
    sign)    do_sign ;;
    install) do_install ;;
    *)       echo "用法: $0 {build|sign|install}" >&2; exit 2 ;;
esac
