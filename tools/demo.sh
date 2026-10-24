#!/usr/bin/env bash
#
# 一条命令把「这台机器能不能跑」证完：自检 → 全套单测 → Agent 演示。
#
#   tools/demo.sh                      自动挑解释器（优先 3.12）
#   PYTHON=python3.12 tools/demo.sh    指定解释器
#
# 为什么要挑解释器：项目支持 CPython 3.10–3.12。3.13 上核心路径有已知的
# 随机 SIGSEGV（崩在解释器内部，见 docs/known-limitations.md §7），本机
# 默认 `python3` 恰好是 3.13 时，直接跑就是在拿概率赌演示。这里先把它换掉，
# 并把实际用的解释器打出来。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pick_python() {
    if [ -n "${PYTHON:-}" ]; then
        command -v "$PYTHON" >/dev/null
        echo "$PYTHON"
        return
    fi
    for cand in python3.12 python3.11 python3.10 python3; do
        if command -v "$cand" >/dev/null; then
            echo "$cand"
            return
        fi
    done
    echo "找不到 Python 3.10–3.12（试过 python3.12/3.11/3.10/python3）" >&2
    exit 2
}

PY="$(pick_python)"
VER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

case "$VER" in
    3.10|3.11|3.12) ;;
    *)
        echo "✗ $PY 是 Python $VER，超出支持范围（>=3.10,<3.13）。" >&2
        echo "  3.13 上核心路径有已知的随机段错误，见 docs/known-limitations.md §7。" >&2
        echo "  指定一个 3.12：PYTHON=python3.12 tools/demo.sh" >&2
        exit 3
        ;;
esac

echo "== 解释器：$PY（Python $VER）"
echo
echo "== 1/3 自检"
"$PY" -m policy_loop.selfcheck
echo
echo "== 2/3 单测"
"$PY" -m unittest discover -s tests -q
echo
echo "== 3/3 Agent 演示"
"$PY" -m policy_loop.agents.demo
echo
echo "== 全部通过（selfcheck + unittest + agents.demo）"
