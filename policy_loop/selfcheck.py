"""PolicyLoop 环境自检:一键确认"clone 下来能不能跑"。

用法(仓库根 ~/policy_loop):
    python -m policy_loop.selfcheck
"""
from __future__ import annotations

import subprocess
import sys


def _battery() -> bool:
    """跑 avc 解析器全量用例,失败则环境不 OK。"""
    print("[1/2] 跑 avc 解析器用例...")
    r = subprocess.run(
        [sys.executable, "-m", "policy_loop.avc.tests.test_parser"],
        capture_output=True, text=True)
    print(r.stdout.rstrip())
    if r.returncode != 0:
        print(r.stderr)
        return False
    return True


def _import_smoke() -> bool:
    """import + 现编一条 denial 解析,证明包与解析链路活着。"""
    print("[2/2] import 冒烟:policy_loop.avc ...")
    from policy_loop.avc import parse_record
    rec = parse_record('avc:  denied  { read } for pid=1 comm="x" '
                       'scontext=u:r:smoke_test:s0 tcontext=u:object_r:smoke_obj:s0 '
                       'tclass=file permissive=1')
    if not (rec.parse_ok and rec.scontext_type() == "smoke_test"):
        print("✘ 冒烟解析失败:", rec.error)
        return False
    return True


def main() -> int:
    print("PolicyLoop 环境自检\n" + "=" * 34)
    try:
        battery_ok = _battery()
        smoke_ok = _import_smoke()
    except Exception as e:  # noqa: BLE001 —— 自检要兜住所有意外,给出可读报错
        print(f"✘ 自检抛出异常: {type(e).__name__}: {e}")
        return 1
    print("=" * 34)
    if battery_ok and smoke_ok:
        print(f"✔ 环境 OK —— Python {sys.version.split()[0]} 下 PolicyLoop 可正常跑")
        return 0
    print("✘ 自检失败,看上方哪一步红了")
    return 1


if __name__ == "__main__":
    sys.exit(main())
