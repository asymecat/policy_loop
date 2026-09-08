"""Self-check entry: `python -m policy_loop.selfcheck`.

Checks environment, imports, and runs a smoke test over a real-format denial
plus a tiny policy — all deterministic, no network, no third-party deps.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# ---- embedded smoke samples (independent of repo data files) --------------

SAMPLE_DENIAL = (
    'avc: denied { ioctl } for pid=7881, comm="/system/bin/media_service" '
    'path="/dev/camera/video0" dev="" ino=23 ioctlcmd=0x6412 '
    "scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 "
    "tclass=chr_file permissive=1"
)

SAMPLE_POLICY = """
# synthetic sample (mirrors OpenHarmony sepolicy style)
type media_service;
type sys_prod_file;
type dev_camera_file;
attribute hap_domain;
type normal_hap, hap_domain;
type system_basic_hap, hap_domain;

allow media_service dev_camera_file:chr_file { open read };
allowxperm media_service dev_camera_file:chr_file ioctl { 0x641f };
allow media_service sys_prod_file:file { ioctl };
neverallow normal_hap dev_bbox:chr_file { read };
allow hap_domain sys_prod_file:file { read };
"""


def run() -> list:
    """Run all checks; returns a list of (ok: bool, message: str)."""
    results: list = []

    # 1. python version
    ok = sys.version_info >= (3, 10)
    results.append((ok, f"Python >= 3.10 ({sys.version.split()[0]})"))

    # 2. imports
    try:
        from policy_loop.denial import parse as parse_denial
        from policy_loop.policy import load_text
        results.append((True, "policy_loop.denial / policy imports OK"))
    except Exception as exc:  # pragma: no cover
        results.append((False, f"import failed: {exc!r}"))
        return results

    # 3. parse smoke
    rec = parse_denial(SAMPLE_DENIAL)[0]
    expect = {
        "source_domain": "media_service",
        "target_type": "dev_camera_file",
        "tclass": "chr_file",
        "permissions": ("ioctl",),
        "ioctl_cmd": "0x6412",
        "permissive": True,
    }
    bad = {k: getattr(rec, k) for k in expect if getattr(rec, k) != expect[k]}
    results.append(
        (not bad, f"parser smoke OK -> {json.dumps(expect, ensure_ascii=False)}"
         if not bad else f"parser mismatch: {bad}")
    )

    # 4. policy query smoke
    idx = load_text(SAMPLE_POLICY)
    ok_ro, _, _ = idx.has_access(
        "media_service", "dev_camera_file", "chr_file", frozenset({"read"})
    )
    ioctl_ok, reason, _ = idx.ioctl_allowed(
        "media_service", "dev_camera_file", "chr_file", "0x6412"
    )
    attr_ok, _, _ = idx.has_access(
        "normal_hap", "sys_prod_file", "file", frozenset({"read"})
    )
    nev = idx.neverallow_rules("normal_hap", "dev_bbox", "chr_file")

    results.append((ok_ro, "policy: read allowed = True"))
    results.append((not ioctl_ok,
                    f"policy: ioctl 0x6412 verdict = denied ({reason}) — "
                    "xperm gap detected"))
    results.append((attr_ok,
                    "policy: attribute expansion "
                    "(normal_hap via hap_domain) = True"))
    results.append((len(nev) == 1, "neverallow: normal_hap -> dev_bbox blocked"))

    # 5. data fixtures present (optional)
    root = Path(__file__).resolve().parents[1]
    fx = root / "data" / "fixtures"
    present = (fx / "sample_denials.txt").exists() and (
        fx / "sample_policy.te").exists()
    results.append((present, "data/fixtures present"))

    # 6. L3 agent pipeline smoke
    try:
        from policy_loop.agents import Orchestrator
        idx = load_text(SAMPLE_POLICY)
        case = Orchestrator(index=idx).analyze(SAMPLE_DENIAL)
        ok = case.record is not None and case.classification
        results.append(
            (ok, f"agents pipeline smoke OK "
                 f"(classification={case.classification}, "
                 f"review={case.review.get('status', 'n/a')})")
        )
    except Exception as exc:  # pragma: no cover
        results.append((False, f"agents pipeline failed: {exc!r}"))

    return results


def main(argv: list | None = None) -> int:
    results = run()
    failed = 0
    for ok, msg in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {msg}")
        failed += 0 if ok else 1
    print(f"\nselfcheck: {len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
