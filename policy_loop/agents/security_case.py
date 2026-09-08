"""Security Case: the structured object flowing through the agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TraceEvent:
    """One recorded agent action (rendered as Agent Trace)."""

    agent: str
    action: str
    status: str = "ok"          # ok / reject / fail / skip
    detail: str = ""


@dataclass
class SecurityCase:
    """Aggregated state produced/consumed by the agent pipeline."""

    id: str
    denial_raw: str = ""
    record: Optional[dict] = None          # structured denial (parser output)
    # --- filled by LogAgent / PolicyAgent ------------------------------
    log_summary: str = ""
    policy_verdict: dict = field(default_factory=dict)
    # --- filled by SecurityAgent ----------------------------------------
    classification: str = ""
    explanation: str = ""
    candidates: list = field(default_factory=list)
    recommended: Optional[dict] = None
    # --- filled by RepairAgent -------------------------------------------
    patch: str = ""
    patch_target_note: str = ""
    needs_human: bool = False
    # --- filled by ReviewerAgent ------------------------------------------
    review: dict = field(default_factory=dict)
    # --- filled by VerifyAgent --------------------------------------------
    verify: dict = field(default_factory=dict)
    # --- trace -------------------------------------------------------------
    trace: list = field(default_factory=list)

    def add_trace(self, agent: str, action: str, status: str = "ok",
                  detail: str = "") -> None:
        self.trace.append(TraceEvent(agent, action, status, detail))

    def render_trace(self) -> str:
        lines = []
        icons = {"ok": "[ok]", "reject": "[x]", "fail": "[x]", "skip": "[-]"}
        for t in self.trace:
            if t.agent == "Orchestrator":
                prefix = "> "
            else:
                prefix = f"{icons.get(t.status, '[?]')} {t.agent:<14}"
            lines.append(f"{prefix} {t.action}"
                         + (f"  -- {t.detail}" if t.detail else ""))
        return "\n".join(lines)
