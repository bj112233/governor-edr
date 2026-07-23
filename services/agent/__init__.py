# services/agent/__init__.py
# Re-exports — maintains full backward compatibility with `from services.agent import ...`

from services.agent.bypass._translation_utils import (
    normalize_ocr_text as _normalize_ocr_text,
)
from services.agent.bypass._translation_utils import (
    split_for_translation as _split_for_translation,
)
from services.agent.bypass._translation_utils import (
    strip_document_noise as _strip_document_noise,
)
from services.agent.bypass.currency import (
    _ELABORATE_INTENT_RE,
    _ELABORATE_MAX_QUESTION_CHARS,
    _SUMMARIZE_INTENT_RE,
    _TRANSLATION_INTENT_RE,
    _detect_currency_query,
    _direct_currency_bypass,
    _extract_currency_from_query,
    _find_currency_occurrences,
    _parse_currency_query,
)
from services.agent.bypass.elaborate import (
    _detect_elaborate_query,
    _direct_elaborate_bypass,
)
from services.agent.bypass.geocode import (
    _detect_geocode_query,
    _direct_geocode_bypass,
)
from services.agent.bypass.news import (
    _detect_news_topic,
    _direct_news_bypass,
    _extract_news_limit,
)
from services.agent.bypass.stocks import (
    _detect_stock_query,
    _direct_stock_bypass,
)
from services.agent.bypass.sysreport import (
    _detect_sysreport_query,
    _direct_sysreport_bypass,
)
from services.agent.bypass.translation import (
    _direct_translation_bypass,
)
from services.agent.bypass.weather import (
    _detect_weather_query,
    _direct_weather_bypass,
)
from services.agent.context import get_last_document, set_last_document
from services.agent.core import analyze_data, run_agent
from services.agent.prompts import (
    _AGENT_SYSTEM,
    _CONVERSATIONAL_SYSTEM,
    _load_context_files,
)
from services.agent.routing import (
    _CAPABILITY_PATTERNS,
    _CONVERSATIONAL_KEYWORDS,
    _SYSTEM_KEYWORDS,
    _filter_relevant_skills,
    _filter_relevant_tools,
    _is_conversational,
    init_skill_embeddings,
    init_tool_embeddings,
)
from services.agent.skill_keywords import _SKILL_KEYWORD_MAP
from services.agent.utils import (
    _is_truncated_response,
    _strip_markdown,
    _trim_messages,
)

# Explicit re-export of clean_ide_instructions (previously leaked via namespace).
# Required by _smoke_internal.py which imports it from services.agent.
from services.text_utils import clean_ide_instructions

__all__ = [
    "run_agent",
    "analyze_data",
    "_AGENT_SYSTEM",
    "_CONVERSATIONAL_SYSTEM",
    "_load_context_files",
    "set_last_document",
    "get_last_document",
    "_SKILL_KEYWORD_MAP",
    "_is_conversational",
    "_filter_relevant_skills",
    "_filter_relevant_tools",
    "init_skill_embeddings",
    "init_tool_embeddings",
    "_CONVERSATIONAL_KEYWORDS",
    "_CAPABILITY_PATTERNS",
    "_SYSTEM_KEYWORDS",
    "_trim_messages",
    "_strip_markdown",
    "_is_truncated_response",
    "clean_ide_instructions",
    "_TRANSLATION_INTENT_RE",
    "_SUMMARIZE_INTENT_RE",
    "_ELABORATE_INTENT_RE",
    "_ELABORATE_MAX_QUESTION_CHARS",
    "_detect_currency_query",
    "_find_currency_occurrences",
    "_parse_currency_query",
    "_extract_currency_from_query",
    "_direct_currency_bypass",
    "_detect_elaborate_query",
    "_direct_elaborate_bypass",
    "_detect_geocode_query",
    "_direct_geocode_bypass",
    "_detect_news_topic",
    "_extract_news_limit",
    "_direct_news_bypass",
    "_detect_stock_query",
    "_direct_stock_bypass",
    "_detect_sysreport_query",
    "_direct_sysreport_bypass",
    "_direct_translation_bypass",
    "_split_for_translation",
    "_normalize_ocr_text",
    "_strip_document_noise",
    "_detect_weather_query",
    "_direct_weather_bypass",
]
