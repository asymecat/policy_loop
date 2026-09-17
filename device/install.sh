#!/usr/bin/env bash
#
# Lay the mirrored denial_check sources back into an OpenHarmony source tree.
#
#   ./device/install.sh                  # into $HOME/ohos_src
#   ./device/install.sh /path/to/ohos    # into an explicit tree
#
# What this repo holds is a mirror, not the source of truth for building: the
# component is compiled by OpenHarmony's own GN build inside a full source tree.
# This script puts the files where that build expects them.
#
# The BUILD.gn edit is applied as a patch rather than shipped as a whole file,
# so that upstream's copy stays upstream's -- if the tree has moved on, the
# patch is what reports the conflict instead of a silent overwrite.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIRROR="$HERE/selinux_adapter"
PATCH="$HERE/patches/selinux_adapter-BUILD.gn.patch"
OHOS="${1:-$HOME/ohos_src}"
TARGET="$OHOS/base/security/selinux_adapter"

if [[ ! -f "$TARGET/BUILD.gn" || ! -d "$TARGET/interfaces/policycoreutils" ]]; then
    echo "install: $TARGET does not look like the selinux_adapter part" >&2
    echo "install: pass the OpenHarmony source root, e.g. ./device/install.sh ~/ohos_src" >&2
    exit 1
fi

# Sources. BUILD.gn is deliberately not in this list -- it is patched below.
copied=0
while IFS= read -r rel; do
    mkdir -p "$TARGET/$(dirname "$rel")"
    cp "$MIRROR/$rel" "$TARGET/$rel"
    copied=$((copied + 1))
done < <(cd "$MIRROR" && find . -type f | sed 's|^\./||' | sort)
echo "install: $copied source file(s) -> $TARGET"

# BUILD.gn: apply, or report what state it is already in.
cd "$TARGET"
if git apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "install: BUILD.gn already carries the denial_check targets, left alone"
elif git apply --check "$PATCH" 2>/dev/null; then
    git apply "$PATCH"
    echo "install: BUILD.gn patched (+denial_check targets)"
else
    echo "install: BUILD.gn could NOT be patched -- the tree differs from the" >&2
    echo "install: baseline this patch was taken against. Add the two targets" >&2
    echo "install: in $PATCH by hand, then add \":denial_check\" to" >&2
    echo "install: selinux_group's deps." >&2
    exit 2
fi

echo "install: done. Build with the OHOS toolchain, e.g."
echo "install:   $OHOS/build.sh --product-name rk3568 --build-target denial_check"
