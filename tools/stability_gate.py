#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""稳定性门 —— 把「解释器级间歇崩溃」变成可重复测量的数字。

为什么需要这道门
----------------
PolicyLoop 的核心路径（索引装载 + 判决）在 CPython 3.13 上会以约 3% 的概率
随机 SIGSEGV，而且**同一份输入、同一台机器、同一行命令**时崩时不崩。
这类问题读代码找不出来：3.12 上 480 次零崩，3.13 上 200 次崩 7 次，
唯一的变量是解释器本身。

崩溃点在解释器内部而不是本项目里 —— `_PyEval_EvalFrameDefault`，落在
`sorted()` 比较路径上（完整 C 回溯见 docs/known-limitations.md §7）。
进程是**直接死掉**的，Python 层没有机会捕获，所以本门必须逐轮拉起全新子进程，
不能用 try/except，也不能在同一进程里循环。

判据
----
每轮一个干净子进程，跑一遍完整核心路径：

    exit 0    N 轮零崩溃  → 通过
    exit 1    出现崩溃     → 受支持解释器上是**真回归**，要查
    exit 2    环境不满足   → 语料找不到 / 子进程根本没起来（不是崩溃）

项目支持的运行环境是 CPython 3.12。3.13 上出现崩溃属**已定位的上游缺陷**，
用 `--allow-known-unstable` 可以让它不判失败，但崩溃率仍会如实打印 ——
门可以放行，数字不能撒谎。

用法
----
    python3.12 tools/stability_gate.py                      # 60 轮，装载路径
    python3.12 tools/stability_gate.py --runs 200           # 对齐报告里的数字
    python3.12 tools/stability_gate.py --workload converge  # 连判决一起跑
    python3.12 tools/stability_gate.py --json /tmp/sg.json  # 机器可读结果

**用哪个解释器跑本门，就测哪个解释器**（子进程一律用 sys.executable）。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

DEFAULT_POLICY = REPO / "data" / "raw" / "oh-selinux" / "sepolicy"
DEFAULT_LOG = REPO / "data" / "corpus" / "real_denials.txt"

# 已知间歇性 SIGSEGV 的解释器下界。3.13 起命中。
KNOWN_UNSTABLE_MIN = (3, 13)


def _child_env() -> dict:
    """子进程环境：保证能从任意 cwd 导入 policy_loop。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _command(workload: str, policy: Path, log: Path, sys_executable: str) -> list:
    """本轮子进程的命令行。"""
    if workload == "load":
        # 只装载索引 —— 最短的可复现路径，也是崩溃率最高的一段
        code = (
            "from policy_loop.policy import load;"
            f"idx = load({str(policy)!r});"
            "print(len(idx.rules))"
        )
        return [sys_executable, "-X", "faulthandler", "-c", code]
    if workload == "converge":
        return [sys_executable, "-X", "faulthandler", "-m",
                "policy_loop.converge",
                "--log", str(log), "--policy", str(policy)]
    raise SystemExit(f"unknown workload: {workload}")


def _signal_name(returncode: int) -> str:
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"signal{-returncode}"


def _known_unstable(version_info: tuple) -> bool:
    return version_info[:2] >= KNOWN_UNSTABLE_MIN


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="重复运行核心路径，测解释器级间歇崩溃率")
    ap.add_argument("--runs", type=int, default=60,
                    help="重复轮数（每轮一个全新子进程），默认 60")
    ap.add_argument("--workload", choices=["load", "converge"], default="load",
                    help="load=只装载索引（默认，最快）；converge=连判决一起跑")
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY,
                    help=f"sepolicy 目录，默认 {DEFAULT_POLICY}")
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG,
                    help=f"denial 日志（仅 converge 用），默认 {DEFAULT_LOG}")
    ap.add_argument("--json", type=Path, help="把结果写成 JSON")
    ap.add_argument("--crash-log", type=Path,
                    default=Path("/tmp/policyloop-stability-crash.log"),
                    help="首次崩溃的 stderr（faulthandler 回溯）存这里")
    ap.add_argument("--allow-known-unstable", action="store_true",
                    help="在已知不稳定的解释器（>=3.13）上出现崩溃时不判失败")
    args = ap.parse_args(argv)

    if not args.policy.exists():
        print(f"[stability] 语料不存在：{args.policy}", file=sys.stderr)
        return 2
    if args.workload == "converge" and not args.log.exists():
        print(f"[stability] denial 日志不存在：{args.log}", file=sys.stderr)
        return 2

    version = ".".join(str(p) for p in sys.version_info[:3])
    unstable = _known_unstable(sys.version_info)

    print(f"[stability] 解释器    {sys.executable}")
    print(f"[stability] 版本      CPython {version}"
          f"{'  (已知不稳定，见 docs/known-limitations.md §7)' if unstable else ''}")
    print(f"[stability] 负载      {args.workload}  ×  {args.runs} 轮"
          f"（逐轮全新子进程）")
    print()

    crashes: list = []
    setup_failures: list = []
    started = time.time()

    for i in range(1, args.runs + 1):
        proc = subprocess.run(
            _command(args.workload, args.policy, args.log, sys.executable),
            env=_child_env(), cwd=str(REPO),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        rc = proc.returncode
        if rc < 0:
            sig = _signal_name(rc)
            crashes.append({"run": i, "signal": sig})
            print(f"  [{i:>4}/{args.runs}] 崩溃  {sig}")
            if not args.crash_log.exists():
                args.crash_log.write_bytes(
                    f"# stability_gate: run {i}, signal {sig}\n".encode()
                    + proc.stderr)
                print(f"          回溯 -> {args.crash_log}")
        elif rc != 0:
            # 非信号、非零退出：脚本本身的错误，不是崩溃
            setup_failures.append({"run": i, "returncode": rc,
                                   "stderr": proc.stderr.decode(
                                       "utf-8", "replace")[-2000:]})
            print(f"  [{i:>4}/{args.runs}] 非零退出 rc={rc}（不是崩溃）")
        elif i % max(1, args.runs // 10) == 0:
            print(f"  [{i:>4}/{args.runs}] ok")

    elapsed = time.time() - started
    n = args.runs
    rate = 100.0 * len(crashes) / n if n else 0.0

    print()
    print(f"[stability] 完成：{n} 轮 / {elapsed:.1f}s")
    print(f"[stability] 崩溃 {len(crashes)} 次（{rate:.2f}%）"
          f"  非零退出 {len(set(f['returncode'] for f in setup_failures))} 类")
    if crashes:
        by_sig: dict = {}
        for c in crashes:
            by_sig[c["signal"]] = by_sig.get(c["signal"], 0) + 1
        print(f"[stability] 信号分布："
              + "  ".join(f"{k}×{v}" for k, v in sorted(by_sig.items())))
        runs = ", ".join(str(c["run"]) for c in crashes)
        print(f"[stability] 崩溃轮次：{runs}")

    if not crashes and not setup_failures:
        verdict, ok = "PASS", True
        print("[stability] 判定  PASS —— 零崩溃")
    elif crashes and unstable and args.allow_known_unstable:
        verdict, ok = "KNOWN-UNSTABLE", True
        print("[stability] 判定  KNOWN-UNSTABLE —— 该解释器上的已定位上游缺陷，"
              "本次按放行处理（数字未变）")
    elif crashes:
        verdict, ok = "FAIL", False
        print("[stability] 判定  FAIL —— 出现崩溃")
        if unstable and not args.allow_known_unstable:
            print("[stability] 提示：当前解释器 ≥3.13，属已知不稳定区间。"
                  "请用 python3.12 重跑；确需放行加 --allow-known-unstable。")
    else:
        verdict, ok = "FAIL", False
        print("[stability] 判定  FAIL —— 无崩溃但有非零退出，先查子进程错误")

    result = {
        "interpreter": sys.executable,
        "python_version": version,
        "known_unstable": unstable,
        "workload": args.workload,
        "runs": n,
        "crashes": len(crashes),
        "crash_rate_pct": round(rate, 3),
        "crash_runs": crashes,
        "setup_failures": len(setup_failures),
        "elapsed_s": round(elapsed, 2),
        "verdict": verdict,
    }
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                             encoding="utf-8")
        print(f"[stability] JSON -> {args.json}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
