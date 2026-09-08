"""Base agent contract and per-agent result type."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from policy_loop.policy import PolicyIndex

    from .security_case import SecurityCase


@dataclass
class AgentResult:
    """A structured outcome an agent returns after acting on a SecurityCase."""

    agent: str
    ok: bool = True
    summary: str = ""
    data: dict = field(default_factory=dict)


class BaseAgent:
    """Every PolicyLoop agent wraps a deterministic core and records its
    actions on the SecurityCase trace. LLM is optional (see providers)."""

    name: str = "base"
    deps: tuple = ()   # names of agents/contexts expected before this one

    def __init__(self, index: "PolicyIndex | None" = None,
                 provider: Optional["LLMProvider"] = None) -> None:
        self.index = index
        self.provider = provider

    # -- subclasses implement ------------------------------------------------
    def run(self, case: "SecurityCase") -> AgentResult:
        raise NotImplementedError

    # -- shared helpers -------------------------------------------------------
    def _emit(self, case: "SecurityCase", action: str, status: str = "ok",
              detail: str = "") -> None:
        case.add_trace(self.name, action, status, detail)

    @staticmethod
    def _ask_llm(provider, prompt: str) -> Optional[str]:
        """Best-effort LLM enhancement; None means 'fall back to rules'."""
        if provider is None:
            return None
        try:
            return provider.complete(prompt)
        except Exception:  # never let LLM failure break the deterministic path
            return None
