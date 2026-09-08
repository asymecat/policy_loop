"""L1 demo: denial -> structured -> policy verdict (deterministic).

Usage:
    python -m policy_loop.demo                 # demo over data/fixtures
    python -m policy_loop.demo --denial "<avc...>"   # arbitrary denial text
"""

from __future__ import annotations

import argparse
from pathlib import Path

from policy_loop.denial import parse
from policy_loop.policy import load_dir, load_text

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_DENIALS = _ROOT / "data" / "fixtures" / "sample_denials.txt"
_FIXTURE_POLICY = _ROOT / "data" / "fixtures" / "sample_policy.te"


def _verdict_label(idx, rec) -> str:
    cls = rec.tclass
    perms = frozenset(rec.permissions)
    if not cls or not perms:
        return "UNKNOWN (missing class/perms in denial)"

    allowed, granted, rules = idx.has_access(
        rec.source_domain, rec.target_type, cls, perms
    )

    # neverallow red line first
    nev = idx.neverallow_rules(rec.source_domain, rec.target_type, cls)
    if nev:
        return "POTENTIAL_ESCALATION (matches neverallow)"

    if allowed:
        # even if 'allowed' by policy, a permissive-mode denial is surprising;
        # flag as something else (e.g. NOISE / domain mismatch) for L2+.
        return f"ALLOWED by policy (granted={sorted(granted)})"

    if rec.ioctl_cmd and "ioctl" in perms:
        io_ok, reason, _ = idx.ioctl_allowed(
            rec.source_domain, rec.target_type, cls, rec.ioctl_cmd
        )
        if not io_ok and reason == "allowxperm":
            return f"XPERM_GAP (ioctl {rec.ioctl_cmd} not in allowxperm whitelist)"
        if not io_ok:
            return "MISSING_RULE (no allow for ioctl)"

    if rules:
        missing = sorted(set(perms) - set(granted))
        return f"MISSING_RULE (has {sorted(granted)}, needs {missing})"
    return "MISSING_RULE (no allow rule at all)"


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="PolicyLoop L1 demo")
    ap.add_argument("--denial", help="denial text to analyze")
    args = ap.parse_args(argv)

    policy = (_FIXTURE_POLICY.read_text(encoding="utf-8")
              if _FIXTURE_POLICY.exists() else "")
    if args.denial:
        idx = load_text(policy)
        records = parse(args.denial)
        src = "--denial"
    else:
        idx = load_dir(_FIXTURE_POLICY.parent) if _FIXTURE_POLICY.exists() else load_text("")
        records = parse(_FIXTURE_DENIALS.read_text(encoding="utf-8"))
        src = str(_FIXTURE_DENIALS)

    print(f"policy index summary: {idx.summary()}")
    print(f"input: {src}  ({len(records)} denial(s))\n")

    for i, rec in enumerate(records, 1):
        print(f"--- denial #{i} ---")
        print("raw   :", rec.raw)
        print("struct:", rec.to_dict())
        print("verdict:", _verdict_label(idx, rec))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
