"""Replay the golden denial->fix set against the full policy index.

Questions answered (L2 metrics):
1. coverage_all / coverage_any : do denials recorded upstream get fully
   permitted by the policy as indexed? (proxy for index recall + attribute/
   macro handling quality)
2. mismatch samples: which denials are NOT covered and why (unknown type,
   macro-only rule, attribute gap ...).
3. fix profile: how many permissions does a real fix grant vs how many the
   denial requests (least-privilege evidence; aggregated rules may be wider).

Usage:
    python -m policy_loop.eval.replay [--golden data/eval/golden.jsonl]
                                     [--root data/raw/oh-selinux/sepolicy]
                                     [--out data/reports/replay-report.json]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from policy_loop.policy import load_dir

_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "raw" / "oh-selinux" / "sepolicy"
_DEFAULT_GOLDEN = Path(__file__).resolve().parents[2] / "data" / "eval" / "golden.jsonl"
_DEFAULT_OUT = Path(__file__).resolve().parents[2] / "data" / "reports" / "replay-report.json"


def replay(golden_path: Path, root: Path) -> dict:
    idx = load_dir(root)
    stats = {
        "policy_rules": idx.summary()["rules"],
        "pairs": 0,
        "denials_total": 0,
        "denials_evaluable": 0,
        "skip_incomplete": 0,
        "coverage_all": 0,          # every requested perm granted
        "coverage_any": 0,          # at least one requested perm granted
        "class_counts": Counter(),
        "perm_gap_samples": [],     # capped list of uncovered denials
        "fix_vs_denial_perm_extra": [],
    }
    mismatches_all: list = []

    for line in golden_path.open(encoding="utf-8"):
        g = json.loads(line)
        stats["pairs"] += 1
        fix_perms = _perms_from_rule(g.get("rule_raw", ""))
        for d in g.get("denials", []):
            stats["denials_total"] += 1
            src = d.get("source_domain")
            tgt = d.get("target_type")
            cls = d.get("tclass")
            perms = set(d.get("permissions") or ())
            if not (src and tgt and cls and perms):
                stats["skip_incomplete"] += 1
                continue
            stats["denials_evaluable"] += 1
            stats["class_counts"][cls] += 1

            all_ok, granted, _ = idx.has_access(src, tgt, cls, frozenset(perms))
            if all_ok:
                stats["coverage_all"] += 1
            if granted:
                stats["coverage_any"] += 1

            if fix_perms:
                extra = len(fix_perms - perms)
                stats["fix_vs_denial_perm_extra"].append(extra)

            if not all_ok:
                mismatches_all.append({
                    "file": g.get("file"), "rule": g.get("rule_raw"),
                    "denial": d,
                    "missing": sorted(perms - set(granted or ())),
                })

    stats["coverage_all_rate"] = _rate(
        stats["coverage_all"], stats["denials_evaluable"])
    stats["coverage_any_rate"] = _rate(
        stats["coverage_any"], stats["denials_evaluable"])
    stats["class_counts"] = dict(stats["class_counts"].most_common())
    if stats["fix_vs_denial_perm_extra"]:
        xs = stats["fix_vs_denial_perm_extra"]
        stats["fix_extra_perm_avg"] = sum(xs) / len(xs)
        stats["fix_extra_perm_max"] = max(xs)
        stats["fix_exact_min_match_rate"] = _rate(
            sum(1 for x in xs if x == 0), len(xs))

    # attribution of the uncovered denials (guides next-milestone work)
    un = mismatches_all
    stats["uncovered_count"] = len(un)
    stats["uncovered_class_counts"] = dict(
        Counter(d["denial"]["tclass"] for d in un).most_common())
    stats["uncovered_source_hap_count"] = sum(
        1 for d in un if (d["denial"].get("source_domain") or "").endswith("_hap"))
    stats["uncovered_missing_perm_counts"] = dict(
        Counter(p for d in un for p in d["missing"]).most_common(15))
    stats["uncovered_all"] = un
    stats["uncovered_samples"] = un[:15]
    return stats


def _perms_from_rule(rule_raw: str) -> set:
    """Extract the permission set from an allow rule line (best effort)."""
    import re
    m = re.search(r"\{(.*?)\}", rule_raw)
    if m:
        return {t for t in m.group(1).split() if t}
    parts = rule_raw.split()
    if parts and parts[-1].endswith(";"):
        return {parts[-1].rstrip(";")}
    return set()


def _rate(a: int, b: int) -> float:
    return round(a / b, 4) if b else 0.0


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay golden set over policy index")
    ap.add_argument("--golden", type=Path, default=_DEFAULT_GOLDEN)
    ap.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = ap.parse_args(argv)

    if not args.golden.exists():
        print(f"golden set not found: {args.golden} "
              f"(run extract first)")
        return 1
    if not args.root.exists():
        print(f"policy root not found: {args.root}")
        return 1

    stats = replay(args.golden, args.root)

    print(f"policy rules           : {stats['policy_rules']}")
    print(f"golden pairs           : {stats['pairs']}")
    print(f"denials total          : {stats['denials_total']}")
    print(f"denials evaluable      : {stats['denials_evaluable']}")
    print(f"coverage_all rate      : {stats['coverage_all_rate']} "
          f"({stats['coverage_all']} cases)")
    print(f"coverage_any rate      : {stats['coverage_any_rate']}")
    if "fix_extra_perm_avg" in stats:
        print(f"fix vs denial extra perms avg: {stats['fix_extra_perm_avg']}")
        print(f"fix exact-min match rate     : {stats['fix_exact_min_match_rate']}")
    print(f"uncovered              : {stats['uncovered_count']}")
    print(f"  uncovered by class   : "
          f"{json.dumps(dict(list(stats['uncovered_class_counts'].items())[:8]), ensure_ascii=False)}")
    print(f"  uncovered *_hap src  : {stats['uncovered_source_hap_count']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"report written -> {args.out}")

    if stats["uncovered_samples"]:
        print("\n--- first uncovered samples ---")
        for s in stats["uncovered_samples"]:
            d = s["denial"]
            print(f"  {d.get('source_domain')} -> {d.get('target_type')}"
                  f":{d.get('tclass')} {{{','.join(d.get('permissions') or [])}}}"
                  f"  missing={s['missing']}  file={s['file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
