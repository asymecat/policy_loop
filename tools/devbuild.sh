#!/usr/bin/env bash
#
# Host-side development build of the denial_check core.
#
# The device build goes through BUILD.gn and the OpenHarmony cross toolchain.
# This loop exists so that the differential testing against the Python engine
# (~90% of the verification, see tests/diff_device.py) runs on plain x86 with
# ASan/UBSan, where a memory bug is a stack trace instead of a silently wrong
# verdict discovered over a serial console days later.
#
#   ./tools/devbuild.sh            # sanitized build -> /tmp/denial_check_host
#   ./tools/devbuild.sh release    # -O2, for timing runs
#   ./tools/devbuild.sh check      # device-parity gate: exact device cflags, no
#                                  # sanitizers, plus a scan for banned headers
#
# Note: `check` is a portability gate, not a correctness gate. It catches use of
# std::filesystem / std::regex / exceptions, which compile on the host but are
# unavailable or unacceptable on the device image.

set -euo pipefail

ADAPTER="${ADAPTER:-$HOME/ohos_src/base/security/selinux_adapter}"
OUT="${OUT:-/tmp/denial_check_host}"
MODE="${1:-asan}"

# This repo carries a mirror of the component (device/), so the differential
# half of the verification runs without a full OpenHarmony tree. Prefer the live
# tree when there is one -- that is what actually ships -- and fall back to the
# mirror so a fresh clone is buildable on its own.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -d "$ADAPTER/interfaces/policycoreutils/include" &&
      -d "$REPO/device/selinux_adapter/interfaces/policycoreutils/include" ]]; then
    echo "devbuild: no OpenHarmony tree at $ADAPTER; using the mirror in device/" >&2
    ADAPTER="$REPO/device/selinux_adapter"
fi

INC="$ADAPTER/interfaces/policycoreutils/include"
SRCDIR="$ADAPTER/framework/policycoreutils/src"
TOOLDIR="$ADAPTER/framework/tools/denial_check"

if [[ ! -d "$INC" ]]; then
    echo "devbuild: adapter not found at $ADAPTER (set ADAPTER=)" >&2
    exit 1
fi

# Always name the tree that was compiled. The live tree wins over the repo
# mirror, so an edit made in device/ is silently *not* in the binary when an
# OpenHarmony checkout happens to exist -- which reads as "my change did
# nothing" and invites verifying the old code against itself. Say it out loud.
echo "devbuild: source tree $ADAPTER" >&2

# Every pl_*.cpp in the core, plus the tool's main(). Collected explicitly so a
# newly added module is a build error rather than a silent omission.
sources=()
while IFS= read -r f; do sources+=("$f"); done < <(find "$SRCDIR" -maxdepth 1 -name 'pl_*.cpp' | sort)
main_src=""
if [[ -f "$TOOLDIR/test.cpp" ]]; then
    main_src="$TOOLDIR/test.cpp"
fi

if [[ ${#sources[@]} -eq 0 ]]; then
    echo "devbuild: no pl_*.cpp found under $SRCDIR" >&2
    exit 1
fi

# Banned on the device: std::filesystem, std::regex and exceptions are either
# unavailable in the OH libc++ configuration or too costly in binary size. The
# core must stay on plain std::string/std::vector so that the only dynamic
# dependencies are libc/libc++/libm.
banned_hits=$(grep -nE '#[[:space:]]*include[[:space:]]*<(filesystem|regex|iostream)>|throw[[:space:]]' \
    "${sources[@]}" "$main_src" 2>/dev/null || true)
if [[ -n "$banned_hits" ]]; then
    echo "devbuild: device-parity violation(s):" >&2
    echo "$banned_hits" >&2
    exit 1
fi

common=(-D_GNU_SOURCE -Wall -Wextra -Werror -std=c++17 -I"$INC")

case "$MODE" in
    check)
        echo "devbuild: device-parity compile (no sanitizers)"
        g++ "${common[@]}" "${sources[@]}" ${main_src:+"$main_src"} -lz -o "$OUT"
        ;;
    release)
        echo "devbuild: release (-O2)"
        g++ "${common[@]}" -O2 "${sources[@]}" ${main_src:+"$main_src"} -lz -o "$OUT"
        ;;
    asan)
        echo "devbuild: sanitized (-O1 -g -fsanitize=address,undefined)"
        g++ "${common[@]}" -O1 -g -fno-omit-frame-pointer \
            -fsanitize=address,undefined \
            "${sources[@]}" ${main_src:+"$main_src"} -lz -o "$OUT"
        ;;
    *)
        echo "devbuild: unknown mode '$MODE' (asan|release|check)" >&2
        exit 2
        ;;
esac

echo "devbuild: $OUT ($(( ${#sources[@]} + ${main_src:+1} )) TU)"
