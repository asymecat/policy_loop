"""Pluggable LLM provider.

The L3 agent loop is fully deterministic and runs offline. An LLM is OPTIONAL:
if a provider is configured it can enrich natural-language explanations and
candidate comparisons; otherwise every agent falls back to the rule-based
template path. The main loop never depends on network or an API key.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Protocol, runtime_checkable

# --------------------------------------------------------------------------- #
# Optional local .env support (keeps secrets out of the chat and out of git)
# --------------------------------------------------------------------------- #

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(root: Path = _PROJECT_ROOT) -> None:
    envf = root / ".env"
    if not envf.exists():
        return
    for line in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k.startswith("OPENAI_"):
            os.environ.setdefault(k, v)


_load_dotenv()

# --------------------------------------------------------------------------- #
# Protocol
# --------------------------------------------------------------------------- #


@runtime_checkable
class LLMProvider(Protocol):
    """Anything implementing ``complete(prompt: str) -> str | None``."""

    def complete(self, prompt: str) -> str | None:  # pragma: no cover
        ...


class NoopProvider:
    """Always returns None -> agents use deterministic rules."""

    def complete(self, prompt: str) -> str | None:
        return None


class EchoProvider:
    """For tests: returns a fixed text so pipeline behaviour is inspectable."""

    def __init__(self, text: str = "[llm-draft]"):
        self.text = text

    def complete(self, prompt: str) -> str | None:
        return self.text


# --------------------------------------------------------------------------- #
# Real OpenAI-compatible chat completion (zero third-party dependency)
# --------------------------------------------------------------------------- #


class OpenAICompatibleProvider:
    """Talk to any OpenAI-compatible chat endpoint via stdlib urllib.

    Credentials/config come from environment variables so secrets never flow
    through the chat:
        OPENAI_API_KEY   (required)
        OPENAI_BASE_URL  (default https://api.openai.com/v1 ;
                         e.g. https://api.deepseek.com/v1)
        OPENAI_MODEL     (default gpt-4o-mini ; e.g. deepseek-chat)

    Any network/parse error returns None so callers fall back to rules.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None, timeout: int = 90,
                 temperature: float = 0.2, max_tokens: int = 400) -> None:
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL")
                         or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key if api_key is not None \
            else os.environ.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, prompt: str) -> str | None:
        if not self.available:
            return None
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except Exception:  # never break the deterministic path
            return None

