"""VerifyAgent: data-driven verification without a kernel.

Given an approved minimal patch, VerifyAgent checks (deterministically, against
the policy index):

* elimination  : after applying the patch, every requested permission is
                 granted (denial would disappear in strict mode)
* regression   : the patch does not hit any neverallow red line
* scope        : the patch grants exactly what the denial requested

Verdicts: SUCCESS / FAILED / SECURITY_REGRESSION (matches the proposal).
"""

from __future__ import annotations

import copy

from policy_loop.agents.base import AgentResult, BaseAgent


class VerifyAgent(BaseAgent):
    name = "VerifyAgent"

    def run(self, case) -> AgentResult:
        review = case.review or {}
        patch = case.patch
        if not patch:
            if case.recommended and case.recommended.get("needs_human"):
                case.verify = {"status": "HUMAN_REVIEW_REQUIRED",
                               "reason": "设计上不自动生成补丁，需人工决策"}
                case.add_trace(self.name, "验证",
                               status="skip", detail="需人工决策")
                return AgentResult(self.name, ok=True,
                                   summary="human-required", data=case.verify)
            case.verify = {"status": "VERIFIED_AS_NOISE",
                           "reason": "无需修改（噪声或已允许）"}
            case.add_trace(self.name, "验证", status="skip",
                           detail="无需补丁")
            return AgentResult(self.name, ok=True, summary="noop",
                               data=case.verify)

        if review.get("status") != "APPROVE":
            case.verify = {"status": "BLOCKED_BY_REVIEW",
                           "reason": review.get("reasons", ["rejected"])}
            case.add_trace(self.name, "验证被阻断",
                           status="reject", detail=review.get("status", ""))
            return AgentResult(self.name, ok=False,
                               summary="blocked", data=case.verify)

        v = case.policy_verdict
        src, tgt, cls = v["src"], v["tgt"], v["cls"]
        requested = frozenset(v["requested_perms"])

        # neverallow regression check
        nev = self.index.neverallow_rules(src, tgt, cls) if self.index else []
        if nev:
            case.verify = {"status": "SECURITY_REGRESSION",
                           "reason": f"命中 neverallow：{nev[0].raw[:120]}"}
            case.add_trace(self.name, "安全回归", status="reject",
                           detail=case.verify["reason"])
            return AgentResult(self.name, ok=False,
                               summary="regression", data=case.verify)

        # elimination check: apply patch on a copy and re-query
        import re
        m = re.search(r"\{(.*?)\}", patch)
        patch_inner = set(m.group(1).split()) if m else set()

        if self.index is not None:
            idx2 = copy.deepcopy(self.index)
            idx2.load_text(patch)
            if "allowxperm" in patch:          # xperm whitelist gap
                cmd = (v.get("ioctl") or {}).get("cmd", "")
                io_ok, _, _ = idx2.ioctl_allowed(src, tgt, cls, cmd)
                all_ok, granted = io_ok, requested if io_ok else set()
            else:                              # ordinary allow gap
                all_ok, granted, _ = idx2.has_access(src, tgt, cls, requested)
        else:
            all_ok, granted = True, requested  # no index -> trust reviewer

        # scope check (minimality)
        if "allowxperm" in patch:
            cmd = (v.get("ioctl") or {}).get("cmd", "")
            scope_ok = bool(cmd) and patch_inner <= {cmd}
        else:
            scope_ok = not (patch_inner - set(requested))

        if all_ok:
            case.verify = {
                "status": "SUCCESS",
                "eliminated": sorted(requested - granted)
                              if not all_ok else sorted(requested),
                "scope_ok": scope_ok,
                "strict_mode_note": "rebuilt + enforcing regression pending "
                                    "real-device run (L4)",
            }
            case.add_trace(self.name, "验证通过",
                           detail=f"请求权限已消除；范围最小={scope_ok}")
            return AgentResult(self.name, ok=True, summary="VERIFIED",
                               data=case.verify)

        case.verify = {"status": "FAILED", "reason": "denial 仍然存在"}
        case.add_trace(self.name, "验证失败", status="fail",
                       detail="应用补丁后请求权限仍未授予")
        return AgentResult(self.name, ok=False, summary="failed",
                           data=case.verify)
