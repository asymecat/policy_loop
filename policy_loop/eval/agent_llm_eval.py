"""LLM vs rule-guardrail comparison on the golden informative subset.

Question: if an LLM freely drafts the fix (the typical "just add allow" AI
tool behaviour), how often is it over-broad / insufficient / neverallow-
violating — and does the PolicyLoop ReviewerAgent guardrail catch it, followed
by a deterministic refine to a least-privilege patch?

Two fix sources on the SAME informative denials:
  * rule    : deterministic RepairAgent (least privilege) — the baseline
  * llm     : OpenAI-compatible provider (env OPENAI_API_KEY/...). If no key
              or the call fails, falls back to a reproducible "naive-LLM"
              profile that mimics typical over-granting (mode moderate/greedy)
              so the eval can run offline too.

Metrics: llm_exact_min / llm_overbroad / llm_insufficient /
         llm_neverallow / llm_review_approve|reject / refined_after_reject.

Usage:
    python -m policy_loop.eval.agent_llm_eval --limit 60 --mode greedy
    # with real LLM:
    set OPENAI_API_KEY=... & set OPENAI_MODEL=deepseek-chat ...
    python -m policy_loop.eval.agent_llm_eval --limit 60
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

from policy_loop.agents.providers import OpenAICompatibleProvider
from policy_loop.agents.reviewer import ReviewerAgent
from policy_loop.agents.security_case import SecurityCase
from policy_loop.eval.agent_eval import (read_golden, scan_informative,
                                         without_fix_light, scope_of)
from policy_loop.policy import load_dir

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SEPOLICY = _ROOT / "data" / "raw" / "oh-selinux" / "sepolicy"
_DEFAULT_GOLDEN = _ROOT / "data" / "eval" / "golden.jsonl"
_DEFAULT_OUT = _ROOT / "data" / "reports" / "agent-llm-eval.json"

_EXTRA_PERMS = {
    "moderate": {"read", "write", "open"},
    "greedy": {"read", "write", "open", "getattr", "setattr",
               "create", "unlink", "map", "ioctl", "append"},
}


def build_verdict(idx, d: dict) -> dict:
    src, tgt, cls = d["source_domain"], d["target_type"], d["tclass"]
    perms = frozenset(d["permissions"] or ())
    allowed, granted, _ = idx.has_access(src, tgt, cls, perms)
    nev = idx.neverallow_rules(src, tgt, cls)
    ioctl = None
    if "ioctl" in perms and d.get("ioctl_cmd"):
        io_ok, reason, _ = idx.ioctl_allowed(src, tgt, cls, d["ioctl_cmd"])
        ioctl = {"allowed": io_ok, "reason": reason, "cmd": d["ioctl_cmd"]}
    return {
        "src": src, "tgt": tgt, "cls": cls,
        "requested_perms": sorted(perms),
        "granted_perms": sorted(granted),
        "all_allowed": bool(allowed),
        "neverallow_hits": [r.raw for r in nev],
        "matching_rules": [],
        "ioctl": ioctl,
    }


def review_patch(idx, verdict: dict, patch: str) -> dict:
    case = SecurityCase(id="REVIEW")
    case.policy_verdict = verdict
    case.record = {}
    case.classification = "MISSING_RULE"
    case.candidates = []
    case.patch = patch
    ReviewerAgent(index=idx).run(case)
    return case.review


def minimal_patch(verdict: dict, missing: set) -> str:
    return (f"allow {verdict['src']} {verdict['tgt']}:{verdict['cls']} "
            f"{{ {' '.join(sorted(missing))} }};")


def naive_llm_patch(verdict: dict, mode: str) -> str:
    """Reproducible proxy for a typical over-granting AI suggestion."""
    perms = set(verdict["requested_perms"]) | _EXTRA_PERMS.get(mode, set())
    return (f"allow {verdict['src']} {verdict['tgt']}:{verdict['cls']} "
            f"{{ {' '.join(sorted(perms))} }};")


def _prompt_for(d: dict, verdict: dict) -> str:
    return (
        "You are an OpenHarmony SELinux policy engineer. Here is a real AVC "
        "denial and the current policy state.\n"
        f"denial: {d.get('raw', '')}\n"
        f"subject {verdict['src']} wants {verdict['requested_perms']} on "
        f"{verdict['tgt']}:{verdict['cls']}; currently granted: "
        f"{verdict['granted_perms']}.\n"
        "Reply with exactly ONE .te rule line (allow or allowxperm) that fixes "
        "this denial with the LEAST privilege, or reply NO if you believe the "
        "access should not be granted at all. No explanation."
    )


def extract_rule(text: str | None) -> str | None:
    if not text:
        return None
    for ln in text.splitlines():
        s = ln.strip().rstrip("`").strip()
        if re.match(r"^(allowxperm|allow)\s", s) and ":" in s:
            return s if s.endswith(";") else s + ";"
    return None


def compare(idx, informative: list, provider, limit: int, seed: int,
            mode: str) -> dict:
    random.seed(seed)
    candidates = [it for it in informative if not it["neverallow"]]
    samples = random.sample(candidates, min(limit, len(candidates)))

    m = {"n": 0,
         "rule_exact_min": 0,
         "llm_got_patch": 0, "llm_no_output": 0,
         "llm_exact_min": 0, "llm_overbroad": 0, "llm_insufficient": 0,
         "llm_neverallow": 0,
         "llm_review_approve": 0, "llm_review_reject": 0,
         "refined_after_reject": 0,
         "llm_source": {"llm": 0, "naive": 0}}
    detail = []
    for it in samples:
        g, d = it["golden"], it["denial"]
        idx_wo = without_fix_light(idx, g["rule_raw"])
        verdict = build_verdict(idx_wo, d)
        missing = set(it["missing"])
        m["n"] += 1

        # --- rule baseline -------------------------------------------------
        rp = minimal_patch(verdict, missing)
        rr = review_patch(idx_wo, verdict, rp)
        if (rr.get("status") == "APPROVE"
                and scope_of(rp) == missing):
            m["rule_exact_min"] += 1

        # --- llm fix source ------------------------------------------------
        source = "llm"
        text = provider.complete(_prompt_for(d, verdict)) \
            if (provider is not None and provider.available) else None
        if text is None:
            source = "naive"
            text = naive_llm_patch(verdict, mode)
        m["llm_source"][source] += 1

        patch = extract_rule(text)
        if not patch:
            m["llm_no_output"] += 1
            continue
        m["llm_got_patch"] += 1
        scope = scope_of(patch)
        vr = review_patch(idx_wo, verdict, patch)
        status = vr.get("status")
        reasons = vr.get("reasons", [])
        if scope == missing:
            m["llm_exact_min"] += 1
        elif missing <= scope:
            m["llm_overbroad"] += 1
        else:
            m["llm_insufficient"] += 1
        if any("neverallow" in r for r in reasons):
            m["llm_neverallow"] += 1
        if status == "APPROVE":
            m["llm_review_approve"] += 1
        else:
            m["llm_review_reject"] += 1
            # deterministic refine to least privilege
            rr2 = review_patch(idx_wo, verdict, rp)
            if rr2.get("status") == "APPROVE":
                m["refined_after_reject"] += 1
        detail.append({
            "file": g.get("file"), "rule": g["rule_raw"],
            "denial": {k: d.get(k) for k in
                       ("source_domain", "target_type", "tclass",
                        "permissions", "ioctl_cmd")},
            "missing": sorted(missing),
            "llm_patch": patch, "llm_scope": sorted(scope),
            "review": status,
        })
    return {"metrics": m, "detail": detail, "evaluated": len(samples),
            "informative_total": len(informative),
            "mode": mode}


def _rate(a, b):
    return round(a / max(b, 1), 4)


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="LLM vs rule guardrail eval")
    ap.add_argument("--sepolicy", type=Path, default=_DEFAULT_SEPOLICY)
    ap.add_argument("--golden", type=Path, default=_DEFAULT_GOLDEN)
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--mode", choices=["moderate", "greedy"], default="greedy",
                    help="naive-LLM profile used when no real API is configured")
    ap.add_argument("--force-naive", action="store_true",
                    help="ignore OPENAI_API_KEY and use the naive profile")
    args = ap.parse_args(argv)

    provider = None if args.force_naive else OpenAICompatibleProvider()
    use_real = provider is not None and provider.available
    prov_label = (f"REAL ({provider.model})" if use_real
                  else "naive-profile (no OPENAI_API_KEY)")
    print(f"LLM provider: {prov_label}")

    print(f"indexing sepolicy...")
    idx = load_dir(args.sepolicy)
    golden = read_golden(args.golden)
    scan = scan_informative(idx, golden)
    s = scan["stats"]
    print(f"informative = {s['informative']} "
          f"(non-neverallow {s['informative'] - s['informative_neverallow']}, "
          f"neverallow {s['informative_neverallow']})")

    res = compare(idx, scan["informative"], provider, args.limit, args.seed,
                  args.mode)
    m = res["metrics"]
    print("\n== LLM vs rule guardrail (same informative denials) ==")
    print(f"evaluated       : {res['evaluated']}")
    print(f"  source        : {m['llm_source']}")
    print(f"rule_exact_min  : {_rate(m['rule_exact_min'], m['n'])} "
          f"({m['rule_exact_min']}/{m['n']})  [deterministic baseline]")
    gp = max(m["llm_got_patch"], 1)
    print(f"llm_got_patch   : {m['llm_got_patch']}   no_output={m['llm_no_output']}")
    print(f"llm_exact_min   : {_rate(m['llm_exact_min'], gp)}")
    print(f"llm_overbroad   : {_rate(m['llm_overbroad'], gp)}")
    print(f"llm_insufficient: {_rate(m['llm_insufficient'], gp)}")
    print(f"llm_neverallow  : {m['llm_neverallow']}")
    print(f"llm_review_approve: {_rate(m['llm_review_approve'], gp)}")
    print(f"llm_review_reject : {_rate(m['llm_review_reject'], gp)}")
    print(f"refined_after_reject (-> least-privilege): "
          f"{m['refined_after_reject']}/{m['llm_review_reject']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    report = {"phase_a": s, "result": res, "use_real_llm": use_real,
              "config": {"limit": args.limit, "seed": args.seed,
                         "mode": args.mode}}
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"report -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
