"""PolicyAgent: answer "what does the current policy allow?" from the index."""

from __future__ import annotations

from policy_loop.agents.base import AgentResult, BaseAgent
from policy_loop.policy import is_service_placeholder


class PolicyAgent(BaseAgent):
    name = "PolicyAgent"

    def run(self, case) -> AgentResult:
        rec = case.record
        src, tgt, cls = (rec.get("source_domain"), rec.get("target_type"),
                         rec.get("tclass"))
        perms = frozenset(rec.get("permissions") or ())

        case.add_trace(self.name, "查询策略索引",
                       detail=f"{src} -> {tgt}:{cls} {{{','.join(perms)}}}")

        if self.index is None:
            case.add_trace(self.name, "未加载策略索引", status="skip")
            return AgentResult(self.name, ok=False, summary="no index",
                               data={"verdict": {}})

        # M3, the same resolution converge._quick_verdict does: a denial that
        # went through the service manager logs a placeholder tcontext, and
        # querying it verbatim asks whether the policy allows access to *the
        # placeholder* -- which it never does, so the answer reads as a real
        # gap. Query the concrete sa_*/hdf_* type the `service=` field names
        # instead.
        #
        # Only the queries move. `tgt` stays raw in the verdict below, so the
        # patch text, the reviewer's neverallow re-check and the verify
        # re-query keep operating on what the log actually carried.
        qtgt = tgt
        if is_service_placeholder(tgt):
            qtgt = (self.index.resolve_logical_target(
                        src, cls, tgt, rec.get("service"), perms) or tgt)

        allowed, granted, rules = self.index.has_access(src, qtgt, cls, perms)
        nev = self.index.neverallow_rules(src, qtgt, cls, perms)
        ioctl_verdict = None
        if "ioctl" in perms and rec.get("ioctl_cmd"):
            io_ok, reason, _ = self.index.ioctl_allowed(src, qtgt, cls,
                                                        rec["ioctl_cmd"])
            ioctl_verdict = {"allowed": io_ok, "reason": reason,
                             "cmd": rec["ioctl_cmd"]}

        verdict = {
            "src": src, "tgt": tgt, "cls": cls,
            "requested_perms": sorted(perms),
            "granted_perms": sorted(granted),
            "all_allowed": bool(allowed),
            "neverallow_hits": [r.raw for r in nev],
            "matching_rules": [r.raw for r in rules[:6]],
            "ioctl": ioctl_verdict,
        }
        case.policy_verdict = verdict
        detail = (f"允许={allowed} 已授予={sorted(granted)} "
                  f"撞neverallow={len(nev)}")
        case.add_trace(self.name, "策略判定结果", detail=detail)
        return AgentResult(self.name, ok=True,
                           summary=f"策略查询 → 允许={allowed}",
                           data=verdict)
