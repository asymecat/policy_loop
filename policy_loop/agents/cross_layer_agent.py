"""CrossLayerAgent: put a denial in front of the application layer, too.

The system layer answers "which rule is missing". That is the wrong answer to
give an application developer holding ``scontext=u:r:normal_hap:s0``: the domain
is not their app, it is *every* normal-APL app on the device, and the rule they
would be told to add is a platform-wide grant. Whether that grant is the fix,
or whether the platform is defending an APL boundary on purpose, cannot be read
off the ``.te`` tree -- it takes the ``sehap_contexts`` bridge.

The reasoning lives in :mod:`policy_loop.policy.cross_layer` (a deterministic
query over the index, testable with no agents involved); this agent is the
pipeline's thin wrapper around it, the same split every other agent here uses.
It **advises and does not decide**: it never changes ``classification``, the
patch, or the review/verify verdicts, so the host and the on-device tool keep
reaching byte-identical buckets (see ``tests/diff_device.py``) -- the device has
no ``@hap`` table to recompute a cross-layer bucket from.

LLM, when configured, only rewrites the wording, and only into the trace: the
view itself is a value the report and the diff harness read, so nothing
non-deterministic may enter it.
"""

from __future__ import annotations

from policy_loop.agents.base import AgentResult, BaseAgent
from policy_loop.policy.cross_layer import LAYER_LABEL, analyze


class CrossLayerAgent(BaseAgent):
    name = "CrossLayerAgent"
    deps = ("policy", "security")

    def run(self, case) -> AgentResult:
        v = case.policy_verdict or {}
        rec = case.record or {}
        if not v or self.index is None:
            case.add_trace(self.name, "缺策略判定或索引，跳过跨层分析",
                           status="skip")
            return AgentResult(self.name, ok=False, summary="no verdict")

        view = analyze(self.index, v["src"], v["tgt"], v["cls"],
                       v["requested_perms"], allowed=v.get("all_allowed"),
                       service=rec.get("service") or "")
        if view is None:
            case.add_trace(self.name, "索引不含 sehap_contexts，跨层不适用",
                           status="skip")
            return AgentResult(self.name, ok=False, summary="no APL bridge")

        case.cross_layer = view
        case.add_trace(self.name, "跨层归属",
                       detail=f"{LAYER_LABEL.get(view['fix_layer'], '?')} | "
                              f"{view['headline']}")

        llm = self._ask_llm(
            self.provider,
            "用 1-2 句人话向 OpenHarmony 应用开发者解释这条 denial 该改哪里：\n"
            f"{case.denial_raw}\n跨层结论：{view['headline']}")
        if llm:
            case.add_trace(self.name, "LLM 跨层解释", detail=llm[:160])

        return AgentResult(self.name, ok=True, summary=view["fix_layer"],
                           data={"cross_layer": view})
