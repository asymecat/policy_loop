"""ReviewerAgent: rejects over-broad or neverallow-violating patches."""

from __future__ import annotations

from policy_loop.agents.base import AgentResult, BaseAgent

_DANGER_PATTERNS = (
    "chmod 777",
    "permissive;",
    "permissive ;",
    "setenforce 0",
    ":file *;",
    ":dir *;",
    "system_file:file *",
)


class ReviewerAgent(BaseAgent):
    name = "ReviewerAgent"

    def run(self, case) -> AgentResult:
        patch = case.patch
        if not patch:
            reason = ("无自动补丁" if case.needs_human
                      else "无需修复（噪声/已允许）")
            case.review = {"status": "SKIP", "reason": reason}
            case.add_trace(self.name, "评审跳过（无补丁）", status="skip",
                           detail=reason)
            return AgentResult(self.name, ok=True, summary="skip", data=case.review)

        verdict = case.policy_verdict
        reasons = []

        # 1) danger patterns ------------------------------------------------
        for pat in _DANGER_PATTERNS:
            if pat in patch:
                reasons.append(f"危险模式 {pat!r}")
        if "*" in patch and "allowxperm" not in patch:
            reasons.append("通配权限不可接受")

        # 2) scope checks -----------------------------------------------
        # NOTE: for allowxperm the braces hold ioctl COMMAND numbers (an
        # xperm whitelist), NOT permission names — compare them against the
        # denial's ioctlcmd instead of against the permission set.
        import re
        v = verdict
        requested = set(v["requested_perms"])
        patch_perms = set()
        if "allowxperm" in patch:
            if v.get("ioctl"):
                cmd = v["ioctl"].get("cmd")
                m2 = re.search(r"\{(.*?)\}", patch)
                cmds = set(m2.group(1).split()) if m2 else set()
                patch_perms = cmds
                if cmd and cmds - {cmd}:
                    extra = sorted(cmds - {cmd})
                    reasons.append(
                        f"allowxperm 白名单含非本 denial 的命令号 {extra}")
        else:
            m = re.search(r"\{(.*?)\}", patch)
            patch_perms = set(m.group(1).split()) if m else set()
            if patch_perms and patch_perms - requested:
                extra = sorted(patch_perms - requested)
                reasons.append(
                    f"权限范围过大：多给了 {extra}，无 denial 证据支持")

        # 3) neverallow conflict ---------------------------------------------
        if self.index is not None:
            nev = self.index.neverallow_rules(v["src"], v["tgt"], v["cls"])
            if nev:
                reasons.append("与 neverallow 冲突：" + nev[0].raw[:120])

        if reasons:
            case.review = {"status": "REJECT", "reasons": reasons,
                           "patch": patch}
            case.add_trace(self.name, "补丁被拒绝",
                           status="reject", detail="; ".join(reasons))
            return AgentResult(self.name, ok=False, summary="reject",
                               data=case.review)

        case.review = {"status": "APPROVE", "reasons": [],
                       "scope": sorted(patch_perms), "patch": patch}
        case.add_trace(self.name, "安全评审",
                       detail=f"已通过（范围={sorted(patch_perms)}）")
        return AgentResult(self.name, ok=True, summary="approve",
                           data=case.review)
