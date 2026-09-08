"""L3 demo: denial -> Multi-Agent pipeline -> trace + human explanation +
least-privilege patch + verification. Fully deterministic / offline.

Usage:
    python -m policy_loop.agents.demo                 # built-in scenarios
    python -m policy_loop.agents.demo --denial "<avc...>"
    python -m policy_loop.agents.demo --policy data/raw/oh-selinux/sepolicy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from policy_loop.agents.orchestrator import Orchestrator
from policy_loop.policy import load_dir, load_text

# make stdout encoding-robust (GBK consoles / pipes)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_POLICY = _ROOT / "data" / "fixtures" / "sample_policy.te"

# built-in scenarios exercising distinct root causes (mirror OpenHarmony style)
SCENARIOS = [
    ("XPERM_GAP · media_service ioctl(0x6412) 不在白名单",
     'avc: denied { ioctl } for pid=7881, comm="/system/bin/media_service" '
     'path="/dev/camera/video0" dev="" ino=23 ioctlcmd=0x6412 '
     "scontext=u:r:media_service:s0 "
     "tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file permissive=1"),
    ("POTENTIAL_ESCALATION · normal_hap 触碰 neverallow",
     'avc: denied { read } for pid=9999 comm="some_app" '
     "scontext=u:r:normal_hap:s0 tcontext=u:object_r:dev_bbox:s0 "
     "tclass=chr_file permissive=1"),
    ("MISSING_RULE · media_service 对 sys_prod_file ioctl(0xf207) 缺 xperm 之外允许? "
     "(实际有 allow ioctl → 判定为 ALLOWED/噪声候选)",
     'avc: denied { ioctl } for pid=1068 comm="PlayerEngine" '
     'path="/vendor/etc/prod" dev="sda49" ino=29 ioctlcmd=0xf207 '
     "scontext=u:r:media_service:s0 tcontext=u:object_r:sys_prod_file:s0 "
     "tclass=file permissive=1"),
]


def _load_index(policy_path: Path):
    if policy_path.is_dir():
        return load_dir(policy_path)
    if policy_path.exists():
        return load_text(policy_path.read_text(encoding="utf-8"),
                         source=str(policy_path))
    raise FileNotFoundError(policy_path)


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="PolicyLoop L3 agent demo")
    ap.add_argument("--denial", help="analyze one denial text")
    ap.add_argument("--policy", type=Path, default=_DEFAULT_POLICY,
                    help="policy file/dir to index")
    args = ap.parse_args(argv)

    index = _load_index(args.policy)
    orch = Orchestrator(index=index)
    print(f"[PolicyLoop L3] policy rules indexed = {index.summary()['rules']}\n")

    if args.denial:
        scenarios = [("--denial", args.denial)]
    else:
        scenarios = SCENARIOS

    for label, raw in scenarios:
        case = orch.analyze(raw, label=label)
        print("=" * 78)
        print(f"# {case.id}  |  {label}")
        print("=" * 78)
        print(case.render_trace())
        print("-" * 78)
        print(f"[classification] {case.classification}")
        print(f"[explanation]   {case.explanation}")
        if case.candidates:
            print("[candidates]")
            for c in case.candidates:
                risk = c.get("risk", "")
                pd = c.get("patch_draft") or "—"
                print(f"   {c['id']}. [{risk:<10}] {pd}")
        print(f"[patch] {case.patch or '(none)'}")
        if case.patch_target_note:
            print(f"        {case.patch_target_note}")
        print(f"[review] {case.review}")
        print(f"[verify] {case.verify}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
