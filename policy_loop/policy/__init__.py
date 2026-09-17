"""Policy index subpackage (deterministic, no LLM)."""
from pathlib import Path

from .index import (PLACEHOLDER_TARGETS, PolicyIndex, Rule,
                    is_service_placeholder, load_dir, load_text)
from .sehap import SEHAP_FILENAME, SehapEntry, SehapTable, load_sehap

__all__ = ["PolicyIndex", "Rule", "load", "load_dir", "load_text",
           "PLACEHOLDER_TARGETS", "is_service_placeholder",
           "SEHAP_FILENAME", "SehapEntry", "SehapTable", "load_sehap"]


def load(policy):
    """Load an index from a sepolicy *directory* or a single ``.te`` file.

    Every entry point takes the same ``--policy`` argument and has to accept
    either, so the rule for telling them apart lives here rather than being
    re-written at each one.
    """
    p = Path(policy)
    if p.is_dir():
        return load_dir(p)
    if p.exists():
        return load_text(p.read_text(encoding="utf-8", errors="replace"),
                         source=str(p))
    raise FileNotFoundError(f"policy not found: {policy}")
