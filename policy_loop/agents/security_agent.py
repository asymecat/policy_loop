"""SecurityAgent: root-cause classification, plain-language explanation and
candidate fix comparison (rule-based; LLM optional for richer wording)."""

from __future__ import annotations

from policy_loop.agents.base import AgentResult, BaseAgent


# --------------------------------------------------------------------------- #
# Deterministic classification
# --------------------------------------------------------------------------- #

def classify(verdict: dict, permissive: bool) -> str:
    if verdict.get("neverallow_hits"):
        return "POTENTIAL_ESCALATION"
    ioctl = verdict.get("ioctl")
    if ioctl is not None and not ioctl["allowed"]:
        if ioctl["reason"] == "allowxperm":
            return "XPERM_GAP"
        return "MISSING_RULE"
    if verdict.get("all_allowed"):
        # policy already permits it, yet a denial was logged
        return "NOISE_OR_ALREADY_FIXED" if permissive else "DOMAIN_OR_LABEL_MISMATCH"
    return "MISSING_RULE"


_HUMAN = {
    "MISSING_RULE":
        "安全策略缺少允许规则：{src} 访问 {tgt}:{cls} 的 {{{missing}}} 权限，"
        "当前策略未授予。需要确认该访问是否合理后，按最小权限补齐缺失权限。",
    "XPERM_GAP":
        "{src} 对 {tgt}:{cls} 的 ioctl({cmd}) 被拒：策略已允许 ioctl 大类，但该"
        "命令号不在 allowxperm 白名单内，属于「细粒度权限缺口」而非「完全没有权限」。",
    "POTENTIAL_ESCALATION":
        "该访问命中 neverallow 红线：{src} 请求 {tgt}:{cls} {{{perms}}}。"
        "即使技术上可加规则，也极可能是越权或架构问题，PolicyLoop 拒绝自动放权。",
    "NOISE_OR_ALREADY_FIXED":
        "当前策略已允许该访问（denial 仍出现且处于 permissive），多为历史日志或"
        "噪声/已修复记录，不建议新增权限。",
    "DOMAIN_OR_LABEL_MISMATCH":
        "策略已允许但 enforcing 下仍被拒：疑似进程域或对象标签与实际不符，"
        "应检查 type_transition / file_contexts 等，而非加权限。",
}


class SecurityAgent(BaseAgent):
    name = "SecurityAgent"

    def run(self, case) -> AgentResult:
        v = case.policy_verdict
        rec = case.record
        cls_ = classify(v, bool(rec.get("permissive")))
        case.classification = cls_

        case.add_trace(self.name, "根因分类", detail=cls_)

        # ---- plain-language explanation (template; LLM optional) ----------
        explanation = _HUMAN[cls_].format(
            src=v["src"], tgt=v["tgt"], cls=v["cls"],
            missing=", ".join(sorted(set(v["requested_perms"])
                                     - set(v["granted_perms"]))) or v["cls"],
            cmd=(v.get("ioctl") or {}).get("cmd", ""),
            perms=", ".join(v["requested_perms"]),
        )
        llm = self._ask_llm(self.provider,
                            f"用 1-2 句人话解释这条 OpenHarmony denial:\n"
                            f"{case.denial_raw}\n分类:{cls_}")
        if llm:
            case.add_trace(self.name, "LLM 解释", detail=llm[:160])
            explanation = llm
        case.explanation = explanation
        case.add_trace(self.name, "生成人话解释",
                       detail=explanation[:120])

        # ---- candidate fixes ----------------------------------------------
        missing = sorted(set(v["requested_perms"]) - set(v["granted_perms"]))
        candidates = []

        # A: broad grant (kept only to show why it is rejected)
        if cls_ in ("MISSING_RULE",):
            a_perms = " ".join(sorted(set(v["requested_perms"]) | {"read", "write", "open"}))
            candidates.append({
                "id": "A",
                "title": "直接放权（偏宽）",
                "risk": "HIGH",
                "patch_draft": f"allow {v['src']} {v['tgt']}:{v['cls']} {{ {a_perms} }};",
                "note": "权限超出 denial 证据，Reviewer 将拒绝。",
            })
            # B: minimal
            candidates.append({
                "id": "B",
                "title": "最小权限补齐",
                "risk": "LOW",
                "patch_draft": (f"allow {v['src']} {v['tgt']}:{v['cls']} "
                                f"{{ {' '.join(missing)} }};"),
                "note": "仅授予被 denial 证明需要的权限。",
            })
        if cls_ == "XPERM_GAP":
            cmd = (v.get("ioctl") or {}).get("cmd", "")
            candidates.append({
                "id": "B",
                "title": "放行指定 ioctl 命令号",
                "risk": "LOW",
                "patch_draft": (f"allowxperm {v['src']} {v['tgt']}:{v['cls']} "
                                f"ioctl {{ {cmd} }};"),
                "note": "不放开整类 ioctl，只加白名单命令号。",
            })
            candidates.append({
                "id": "A",
                "title": "整类放开 ioctl",
                "risk": "MEDIUM-HIGH",
                "patch_draft": f"allow {v['src']} {v['tgt']}:{v['cls']} {{ ioctl }};",
                "note": "会绕过 xperm 细粒度管控，风险偏高。",
            })

        candidates.append({
            "id": "C",
            "title": "调整域/标签/调用路径（不动权限）",
            "risk": "LOW-MEDIUM",
            "patch_draft": None,
            "note": ("若根因是域错误/标签错误/调用不合理，应改 type_transition、"
                     "file_contexts/service_contexts 或调用方式，而非放权。"),
        })
        case.candidates = candidates

        # ---- recommendation ------------------------------------------------
        if cls_ == "POTENTIAL_ESCALATION":
            case.recommended = {"id": "C", "needs_human": True,
                                "title": "人工确认/架构调整（禁止自动放权）"}
            case.needs_human = True
        elif cls_ == "NOISE_OR_ALREADY_FIXED":
            case.recommended = {"id": "-", "needs_human": False,
                                "title": "无需修复（噪声/已修复）"}
        elif cls_ == "DOMAIN_OR_LABEL_MISMATCH":
            case.recommended = {"id": "C", "needs_human": True,
                                "title": "检查域与标签（非权限问题）"}
            case.needs_human = True
        else:
            case.recommended = {"id": "B", "needs_human": False,
                                "title": "最小权限补齐"}

        detail = (f"推荐 {case.recommended['id']} "
                  f"({case.recommended['title']})")
        case.add_trace(self.name, "候选修复方案与推荐",
                       detail=detail)
        return AgentResult(self.name, ok=True, summary=cls_, data={
            "classification": cls_,
            "recommended": case.recommended,
        })
