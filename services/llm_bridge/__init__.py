# services/llm_bridge/__init__.py
"""LLM Bridge package — backward compatible re-exports."""

from .bridge import LLMBridge, is_llm_ready, probe_llm_until_ready
from .models import ContextOverflowError

__all__ = [
    "LLMBridge",
    "is_llm_ready",
    "probe_llm_until_ready",
    "ContextOverflowError",
]
