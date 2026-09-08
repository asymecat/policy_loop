"""Quality-gate the golden (denial -> fix) set.

``eval/extract.py`` pairs each ``# avc: denied`` comment block with the adjacent
allow rule by *greedy adjacency*. Upstream .te comments are free-form (a block
often stacks several *different* denials, or sits above an unrelated rule that
happens to follow a blank line), so a meaningful fraction of the pairs are NOT
evidence of "this rule fixed this denial". Metrics computed on the raw set are
polluted by those noise pairs.

This module attributes every golden pair's rule to its denials using the same
attribute closure as the policy index, and tags each pair:

    trusted           rule alone fully fixes every denial it was paired with
                      (subject via attr closure, class, *all* requested perms,
                      allowxperm ioctl cmd). Clean evidence.
    service_gap       target is a default_* placeholder (samgr/hdf_devmgr) that
                      needs the M3 service->type mapping; not noise, but not yet
                      provable against the concrete sa_* type.
    attr_or_name_gap  subject/class/perms line up, but rule targets a different
                      concrete type than the denial (file-context / name
                      granularity); related but not provable -> leave out.
    partial_fix       rule grants only a subset of the requested perms.
    mispair           rule cannot possibly fix the denial (different domain /
                      object class / disjoint permissions) -> adjacency noise.
    unparseable       rule or denial cannot be parsed.

``golden.trusted.jsonl`` = trusted + service_gap (the metric-clean subset);
replay / agent_eval can be pointed at it with ``--golden``.

Deterministic, stdlib-only. Never edits the source corpus.

Usage:
    python -m policy_loop.eval.trust [--golden data/eval/golden.jsonl]
                                     [--root data/raw/oh-selinux/sepolicy]
                                     [--json data/reports/trust-report.json]
                                     [--out data/eval/golden.trusted.jsonl]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from policy_loop.policy import load_dir, load_text

_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "raw" / "oh-selinux" / "sepolicy"
_DEFAULT_GOLDEN = Path(__file__).resolve().parents[2] / "data" / "eval" / "golden.jsonl"
_DEFAULT_OUT = Path(__file__).resolve().parents[2] / "data" / "eval" / "golden.trusted.jsonl"
_DEFAULT_JSON = Path(__file__).resolve().parents[2] / "data" / "reports" / "trust-report.json"

# service-manager placeholder targets that need M3's service->type mapping
_PLACEHOLDER = frozenset({"default_service", "default_hdf_service"})
_PLACEHOLDER_CLASSES = frozenset({"samgr_class", "hdf_devmgr_class"})

# pair-kind labels (ordered by "how trusted")
TRUSTED = "trusted"
SERVICE_GAP = "service_gap"
ATTR_OR_NAME_GAP = "attr_or_name_gap"
PARTIAL = "partial_fix"
MISPAIR = "mispair"
UNPARSEABLE = "unparseable"

# per-denial verdict strings returned by denial_verdict()
V_MATCH = "matches"
V_TGT = "tgt_mismatch"        # rule target type differs (name/file granularity)
V_CLS = "class_mismatch"      # rule cannot fix: object class differs
V_SRC = "src_mismatch"        # rule cannot fix: subject domain differs
V_PERM = "perm_disjoint"      # rule cannot fix: requested perms disjoint
V_SVC = "service_gap"         # placeholder target needing service->type mapping
V_PARTIAL = "partial"         # rule grants a proper subset of requested perms
V_UNP = "unparseable"

_KEPT = frozenset({TRUSTED, SERVICE_GAP})       # -> golden.trusted.jsonl

_HARD_BAD = frozenset({V_SRC, V_CLS, V_PERM})   # rule cannot possibly fix


def _rule_of(raw: str):
    """Parse one allow/allowxperm line into an index Rule (or None)."""
    try:
        i = load_text(raw)
    except Exception:
        return None
    return i.rules[0] if i.rules else None


def denial_verdict(idx, rule, d: dict) -> str:
    """Verdict for one denial given its paired rule (see module docstring)."""
    src = d.get("source_domain")
    tgt = d.get("target_type")
    cls = d.get("tclass")
    req = set(d.get("permissions") or ())
    if not (src and tgt and cls and req):
        return V_UNP

    if not idx._matches(rule.src, rule.src_neg, rule.src_star,
                        src, idx._attrs(src)):
        return V_SRC
    if rule.cls != cls:
        return V_CLS

    # does this rule alone fully satisfy the requested permissions?
    full = False
    if rule.kind == "allow":
        if not rule.perms:                  # wildcard '*'
            full = True
        elif req <= rule.perms:
            full = True
    elif rule.kind == "allowxperm":
        if req <= {"ioctl"}:
            if not d.get("ioctl_cmd"):
                full = True
            elif d["ioctl_cmd"] in rule.xperms:
                full = True
    else:
        return V_UNP
    if not full:
        if rule.kind == "allow" and (rule.perms & req):
            return V_PARTIAL
        return V_PERM

    # target
    tgt_hit = idx._matches(rule.tgt, rule.tgt_neg, rule.tgt_star,
                           tgt, idx._attrs(tgt))
    if tgt in _PLACEHOLDER and cls in _PLACEHOLDER_CLASSES:
        return V_MATCH if tgt_hit else V_SVC
    if not tgt_hit:
        return V_TGT
    return V_MATCH


def pair_kind(entry: dict, idx) -> tuple:
    """Tag one golden pair. Returns (kind, denials_by_verdict, note)."""
    rule = _rule_of(entry.get("rule_raw", ""))
    if rule is None:
        return UNPARSEABLE, {}, "规则无法解析"
    counts = collections.Counter()
    for d in entry.get("denials", []):
        counts[denial_verdict(idx, rule, d)] += 1
    if not counts:
        return UNPARSEABLE, counts, "pair 无 denial"

    def has(*ks):
        return any(counts.get(k, 0) for k in ks)

    if has(*_HARD_BAD):
        kind, note = MISPAIR, "存在规则无法修复的 denial（域/类/权限不符）"
    elif has(V_TGT):
        kind, note = ATTR_OR_NAME_GAP, "主体类权限相符，但目标类型不同（名称/文件粒度）"
    elif has(V_SVC):
        kind, note = SERVICE_GAP, "目标为 default_* 占位，需 service->类型映射（M3）"
    elif has(V_PARTIAL):
        kind, note = PARTIAL, "规则仅覆盖部分请求权限"
    elif has(V_UNP):
        kind, note = UNPARSEABLE, "含无法解析的 denial"
    elif counts and counts.get(V_MATCH) == sum(counts.values()):
        kind, note = TRUSTED, "规则独立完整修复配对的所有 denial"
    else:
        kind, note = UNPARSEABLE, "无法归类"
    return kind, counts, note


def tag_golden(golden_path: Path, root: Path) -> dict:
    """Tag every pair; return report + per-pair rows."""
    idx = load_dir(root)
    rows = []
    kinds = collections.Counter()
    denial_kinds = collections.Counter()
    kept = []
    for line in golden_path.open(encoding="utf-8"):
        g = json.loads(line)
        kind, counts, note = pair_kind(g, idx)
        kinds[kind] += 1
        denial_kinds.update(counts)
        rows.append({"kind": kind, "note": note, "denials_by": dict(counts),
                     "entry": g})
        if kind in _KEPT:
            kept.append({**g, "pair_kind": kind})

    by_kind = {}
    for k, items in _group(rows, lambda r: r["kind"]).items():
        by_kind[k] = {"pairs": len(items),
                      "denials": sum(sum(r["denials_by"].values())
                                     for r in items)}
    report = {
        "policy_rules": idx.summary()["rules"],
        "pairs_total": len(rows),
        "by_kind": dict(kinds),
        "by_kind_detail": by_kind,
        "denials_by_verdict": dict(denial_kinds),
        "trusted_denials": sum(1 for r in rows
                               if r["kind"] in _KEPT
                               for _ in range(sum(r["denials_by"].values()))),
        "kept_pairs": len(kept),
        "samples": {
            k: [{**{kk: r["entry"][kk] for kk in ("file", "rule_line",
                                                   "rule_raw", "direction")},
                 "denial": r["entry"]["denials"][0],
                 "note": r["note"]}
                for r in items[:8]]
            for k, items in _group(rows, lambda r: r["kind"]).items()
            if k in (MISPAIR, ATTR_OR_NAME_GAP, SERVICE_GAP, PARTIAL)
        },
    }
    return {"report": report, "kept": kept}


def _group(rows, keyfn) -> dict:
    out = collections.OrderedDict()
    for r in rows:
        out.setdefault(keyfn(r), []).append(r)
    return out


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Quality-gate the golden set")
    ap.add_argument("--golden", type=Path, default=_DEFAULT_GOLDEN)
    ap.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    ap.add_argument("--json", type=Path, default=_DEFAULT_JSON)
    args = ap.parse_args(argv)

    if not args.golden.exists():
        print(f"golden set not found: {args.golden}")
        return 1
    if not args.root.exists():
        print(f"policy root not found: {args.root}")
        return 1

    result = tag_golden(args.golden, args.root)
    rep = result["report"]
    print(f"golden pairs total     : {rep['pairs_total']}")
    for k, n in rep["by_kind"].items():
        pct = round(100 * n / rep["pairs_total"], 1)
        print(f"  {k:<16}: {n:>4} ({pct}%)")
    print(f"trusted subset kept    : {rep['kept_pairs']} pairs / "
          f"{rep['trusted_denials']} denials")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for g in result["kept"]:
            fh.write(json.dumps(g, ensure_ascii=False) + "\n")
    print(f"trusted golden -> {args.out}")

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(rep, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    print(f"trust report  -> {args.json}")

    for k in (MISPAIR, ATTR_OR_NAME_GAP):
        print(f"\n--- {k} samples ---")
        for s in rep["samples"].get(k, [])[:4]:
            d = s["denial"]
            print(f"  {s['file']}:{s['rule_line']}")
            print(f"    rule   : {s['rule_raw']}")
            print(f"    denial : {d.get('source_domain')}->{d.get('target_type')}"
                  f":{d.get('tclass')} {{{','.join(d.get('permissions') or [])}}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
