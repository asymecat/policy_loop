"""Orchestrator: drives the agents through a SecurityCase and records traces.

The pipeline is a strict state machine — each agent consumes the SecurityCase
state produced by the previous one and appends to the shared trace:

    Log -> Policy -> Security -> CrossLayer -> Repair -> Review -> Verify

``cross_layer`` sits between the two layers on purpose: it reads the policy
verdict and the classification, and it answers *before* Repair proposes a rule,
because "the fix belongs in module.json, not in a .te" is a thing a developer
needs to hear instead of a patch. It is advisory only -- Repair and everything
after it ignore the view -- so adding it changes no verdict.
"""

from __future__ import annotations

from typing import Optional

from policy_loop.agents.base import BaseAgent
from policy_loop.agents.cross_layer_agent import CrossLayerAgent
from policy_loop.agents.log_agent import LogAgent
from policy_loop.agents.policy_agent import PolicyAgent
from policy_loop.agents.repair_agent import RepairAgent
from policy_loop.agents.reviewer import ReviewerAgent
from policy_loop.agents.security_agent import SecurityAgent
from policy_loop.agents.security_case import SecurityCase
from policy_loop.agents.verify_agent import VerifyAgent

_PIPELINE = ("log", "policy", "security", "cross_layer", "repair", "reviewer",
             "verify")


class Orchestrator:
    def __init__(self, index=None, provider=None) -> None:
        self.index = index
        self.provider = provider
        self.agents: dict = {
            "log": LogAgent(index, provider),
            "policy": PolicyAgent(index, provider),
            "security": SecurityAgent(index, provider),
            "cross_layer": CrossLayerAgent(index, provider),
            "repair": RepairAgent(index, provider),
            "reviewer": ReviewerAgent(index, provider),
            "verify": VerifyAgent(index, provider),
        }
        self._seq = 0

    def analyze(self, denial_raw: str, case_id: Optional[str] = None,
                label: str = "") -> SecurityCase:
        self._seq += 1
        cid = case_id or f"CASE-{self._seq:03d}"
        case = SecurityCase(id=cid, denial_raw=denial_raw)

        case.add_trace("Orchestrator", f"创建安全案例 {cid}",
                       detail=label or denial_raw[:60])

        for name in _PIPELINE:
            agent: BaseAgent = self.agents[name]
            result = agent.run(case)
            if name == "log" and not result.ok:
                case.add_trace("Orchestrator", "中止（denial 无法解析）",
                               status="fail")
                break

        # final summary event
        review_s = (case.review or {}).get("status", "n/a")
        verify_s = (case.verify or {}).get("status", "n/a")
        case.add_trace("Orchestrator", "最终结论",
                       detail=f"classification={case.classification} | "
                              f"review={review_s} | verify={verify_s}")
        return case
