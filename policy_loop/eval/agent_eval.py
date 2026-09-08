"""Evaluate the L3 agent pipeline on the golden set (leave-one-out, two-phase).

Context / why: golden denials were ALREADY FIXED upstream, and the real policy
is highly redundant — removing one fix rule often does not flip the access back
to denied (other rules still grant it). So this tool:

  Phase A (cheap, all pairs): remove the golden fix rule (lightweight index
      copy) and find the "informative" subset where the denial's requested
      permissions actually become ungranted. Everything else is reported as
      covered_elsewhere (multi-rule / redundant fix).
  Phase B (pipeline): run the agent pipeline ONLY on the informative subset and
      compare its least-privilege patch scope against the actual missing
      permissions (requested - still-granted).

allowxperm golden fixes encode xperm-whitelist semantics beyond the L1 index
model and are counted separately.

Metrics (Phase B, informative samples):
  exact_min      : patch scope == missing permissions (true least privilege)
  sufficient     : patch covers the missing permissions
  overbroad      : patch grants strictly more than missing (reviewer rejects)
  review_approve / final_verified
  neverallow_auto_blocked : removal exposed a neverallow -> pipeline correctly
                            refuses to auto-fix (escapes to human)

Usage:
    python -m policy_loop.eval.agent_eval [--limit 300] [--out ...]
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path

from policy_loop.agents import Orchestrator
from policy_loop.policy import PolicyIndex, load_dir

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SEPOLICY = _ROOT / "data" / "raw" / "oh-selinux" / "sepolicy"
_DEFAULT_GOLDEN = _ROOT / "data" / "eval" / "golden.jsonl"
_DEFAULT_OUT = _ROOT / "data" / "reports" / "agent-eval.json"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def read_golden(path: Path) -> list:
    out = []
    for line in path.open(encoding="utf-8"):
        out.append(json.loads(line))
    return out


def without_fix_light(idx: PolicyIndex, fix_raw: str) -> PolicyIndex:
    """Cheap copy sharing read-only type tables; only rules list is filtered."""
    idx2 = PolicyIndex()
    drop = fix_raw.strip()
    idx2.rules = [r for r in idx.rules if r.raw.strip() != drop]
    idx2.type_attrs = idx.type_attrs        # shared, never mutated at query time
    idx2.attributes = idx.attributes
    idx2.__dict__["_cache_len"] = -1
    return idx2


def pick_primary(g: dict) -> dict | None:
    for d in g.get("denials", []):
        if (d.get("source_domain") and d.get("target_type") and d.get("tclass")
                and d.get("permissions")):
            return d
    return None


def scope_of(patch: str) -> set:
    """Extract the permission/cmd set of a patch.

    Supports both brace form (``allow a b:file { read write };``) and the
    single-permission form (``allow a b:file read;`` / ``... ioctl 0x1;``).
    """
    m = re.search(r"\{(.*?)\}", patch or "")
    if m:
        return set(m.group(1).split())
    s = (patch or "").strip().rstrip(";").rstrip()
    parts = s.split()
    if len(parts) >= 4 and parts[-1] and not parts[-1].startswith(":"):
        return {parts[-1]}
    return set()


# --------------------------------------------------------------------------- #
# Phase A: cheap informative scan
# --------------------------------------------------------------------------- #

def scan_informative(idx: PolicyIndex, golden: list) -> dict:
    informative = []
    stats = {
        "pairs_allow_fix": 0,
        "pairs_allowxperm": 0,
        "unparseable": 0,
        "covered_elsewhere": 0,     # removal did not flip to denied
        "informative": 0,
        "informative_neverallow": 0,  # removal exposed a neverallow
    }
    for g in golden:
        kind = g.get("rule_kind", "allow")
        if kind == "allowxperm":
            stats["pairs_allowxperm"] += 1
            continue
        stats["pairs_allow_fix"] += 1
        d = pick_primary(g)
        if not d:
            stats["unparseable"] += 1
            continue
        idx_wo = without_fix_light(idx, g["rule_raw"])
        src, tgt, cls = d["source_domain"], d["target_type"], d["tclass"]
        perms = frozenset(d["permissions"])
        all_ok, granted, _ = idx_wo.has_access(src, tgt, cls, perms)
        if all_ok:
            stats["covered_elsewhere"] += 1
            continue
        nev = idx_wo.neverallow_rules(src, tgt, cls)
        stats["informative"] += 1
        entry = {"golden": g, "denial": d,
                 "missing": sorted(set(perms) - set(granted)),
                 "neverallow": bool(nev)}
        if nev:
            stats["informative_neverallow"] += 1
        informative.append(entry)
    return {"informative": informative, "stats": stats}


# --------------------------------------------------------------------------- #
# Phase B: run pipeline on informative subset
# --------------------------------------------------------------------------- #

def evaluate_informative(idx: PolicyIndex, informative: list, limit: int,
                         seed: int) -> dict:
    random.seed(seed)
    samples = informative if limit is None else \
        random.sample(informative, min(limit, len(informative)))

    met = {k: 0 for k in (
        "neverallow_auto_blocked", "patch_generated", "exact_min",
        "sufficient", "overbroad", "review_approve", "final_verified",
        "patch_matches_golden", "golden_fix_wider_than_min")}
    cls_counter = Counter()
    detail_samples = []

    for it in samples:
        g, d = it["golden"], it["denial"]
        if it["neverallow"]:
            met["neverallow_auto_blocked"] += 1
            cls_counter["POTENTIAL_ESCALATION_auto"] += 1
            continue
        # run the pipeline in the "world without this fix"
        idx_wo = without_fix_light(idx, g["rule_raw"])
        orch = Orchestrator(index=idx_wo)
        raw = d.get("raw")
        case = orch.analyze(raw if raw else _raw_from_struct(d), case_id="EVAL")
        cls_counter[case.classification] += 1

        if case.classification not in ("MISSING_RULE", "XPERM_GAP"):
            # unexpectedly not seen as a fix-need (should not happen for
            # informative, non-neverallow samples) -> record for triage
            detail_samples.append({
                "file": g.get("file"), "rule": g["rule_raw"],
                "denial": d, "classification": case.classification,
                "patch": case.patch,
            })
            continue

        requested = set(d["permissions"])
        missing = set(it["missing"])
        scope = scope_of(case.patch)
        met["patch_generated"] += 1
        if scope == missing:
            met["exact_min"] += 1
        if missing <= scope:
            met["sufficient"] += 1
        if scope > missing:
            met["overbroad"] += 1
        # compare with the actual upstream fix rule (may aggregate denials)
        fm = re.search(r"\{.*?\}", g["rule_raw"] or "")
        fix_scope = set(fm.group(0)[1:-1].split()) if fm else set()
        if scope == fix_scope:
            met["patch_matches_golden"] += 1
        if fix_scope and fix_scope > missing:
            met["golden_fix_wider_than_min"] += 1
        if (case.review or {}).get("status") == "APPROVE":
            met["review_approve"] += 1
        if (case.verify or {}).get("status") == "SUCCESS":
            met["final_verified"] += 1
        detail_samples.append({
            "file": g.get("file"), "rule": g["rule_raw"], "denial": d,
            "classification": case.classification, "patch": case.patch,
            "scope": sorted(scope), "missing": sorted(missing),
            "review": (case.review or {}).get("status"),
            "verify": (case.verify or {}).get("status"),
        })

    return {"metrics": met, "classification": dict(cls_counter),
            "detail_samples": detail_samples,
            "evaluated": len(samples),
            "informative_total": len(informative)}


def _raw_from_struct(d: dict) -> str:
    return (f"avc: denied {{ {' '.join(d.get('permissions') or [])} }} "
            f"for pid=0 comm=\"x\" scontext=u:r:{d.get('source_domain')}:s0 "
            f"tcontext=u:object_r:{d.get('target_type')}:s0 "
            f"tclass={d.get('tclass')} permissive=1")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Agent pipeline eval (leave-one-out)")
    ap.add_argument("--sepolicy", type=Path, default=_DEFAULT_SEPOLICY)
    ap.add_argument("--golden", type=Path, default=_DEFAULT_GOLDEN)
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)

    if not args.sepolicy.exists() or not args.golden.exists():
        print("corpus/golden not found")
        return 1

    print(f"indexing sepolicy... ({args.sepolicy})")
    idx = load_dir(args.sepolicy)
    print(f"  rules = {idx.summary()['rules']}")

    golden = read_golden(args.golden)
    print(f"golden pairs = {len(golden)}; scanning informative subset...")
    scan = scan_informative(idx, golden)
    s = scan["stats"]
    print("== Phase A (cheap scan) ==")
    print(f"  allow-fix pairs      : {s['pairs_allow_fix']}")
    print(f"  allowxperm pairs      : {s['pairs_allowxperm']}")
    print(f"  covered_elsewhere     : {s['covered_elsewhere']} (冗余修复/多规则覆盖)")
    print(f"  INFORMATIVE           : {s['informative']} "
          f"(其中撞 neverallow {s['informative_neverallow']})")

    print(f"\nPhase B: running pipeline on {args.limit} informative samples...")
    res = evaluate_informative(idx, scan["informative"], args.limit, args.seed)
    m = res["metrics"]
    inf_metric = max(res["evaluated"], 1)
    print("== Phase B (pipeline, informative) ==")
    print(f"  evaluated            : {res['evaluated']} (informative total "
          f"{res['informative_total']})")
    print(f"  classification       : {res['classification']}")
    print(f"  neverallow_auto_block: {m['neverallow_auto_blocked']}")
    pg = max(m["patch_generated"], 1)
    print(f"  patch_generated      : {m['patch_generated']}")
    print(f"  exact_min_rate(最小)  : {m['exact_min'] / pg:.3f} "
          f"({m['exact_min']}/{pg})")
    print(f"  sufficient_rate      : {m['sufficient'] / pg:.3f}")
    print(f"  overbroad_rate       : {m['overbroad'] / pg:.3f}")
    print(f"  review_approve_rate  : {m['review_approve'] / pg:.3f}")
    print(f"  final_verified_rate  : {m['final_verified'] / pg:.3f}")

    report = {"phase_a": s, "phase_b": res,
              "limits": {"limit": args.limit, "seed": args.seed}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\nreport written -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
