"""RepairAgent: turn the recommended fix into a least-privilege patch."""

from __future__ import annotations

from policy_loop.agents.base import AgentResult, BaseAgent


class RepairAgent(BaseAgent):
    name = "RepairAgent"

    def run(self, case) -> AgentResult:
        cls_ = case.classification
        v = case.policy_verdict
        rec = case.record

        # build the minimal patch from candidate B (or none for human cases)
        cand_b = next((c for c in case.candidates if c["id"] == "B"), None)
        if case.needs_human or not cand_b or not cand_b.get("patch_draft"):
            case.add_trace(self.name, "不生成补丁（需人工决策）",
                           status="skip",
                           detail=case.recommended["title"] if case.recommended else "")
            return AgentResult(self.name, ok=True, summary="no-patch",
                               data={"patch": "", "needs_human": True})

        patch_text = cand_b["patch_draft"]
        structured = _structure_patch(cls_, v, patch_text, rec)
        case.patch = patch_text
        case.recommended = {**(case.recommended or {}), "patch": patch_text}
        case.add_trace(
            self.name, "生成最小权限补丁",
            detail=f"{patch_text}  ({structured['kind']})")

        # where the rule should live (system/vendor/public) is undecidable
        # without the source tree layout -> always surface as a note
        case.patch_target_note = (
            "落点提示：请按 OpenHarmony sepolicy 组织把该规则放到所属子系统的 "
            "system/ 或 vendor/ 目录（跨组件类型定义放 public/），本工具不自动写盘。"
        )
        case.add_trace(self.name, "补丁落点提示", detail=case.patch_target_note)
        return AgentResult(self.name, ok=True, summary="patch-ready",
                           data={"patch": patch_text})


def _structure_patch(cls_, verdict: dict, patch_text: str, rec) -> dict:
    """Parse our own minimal patch back into a structured form."""
    src, tgt = verdict["src"], verdict["tgt"]
    if cls_ == "XPERM_GAP" or "allowxperm" in patch_text:
        cmd = rec.get("ioctl_cmd")
        return {"kind": "allowxperm", "src": src, "tgt": tgt,
                "cls": verdict["cls"], "perm": "ioctl", "cmds": [cmd],
                "patch": patch_text}
    import re
    m = re.search(r"\{(.*?)\}", patch_text)
    perms = m.group(1).split() if m else []
    return {"kind": "allow", "src": src, "tgt": tgt, "cls": verdict["cls"],
            "perms": perms, "patch": patch_text}
