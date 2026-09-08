"""Policy index subpackage (deterministic, no LLM)."""
from .index import PolicyIndex, Rule, load_dir, load_text

__all__ = ["PolicyIndex", "Rule", "load_dir", "load_text"]
