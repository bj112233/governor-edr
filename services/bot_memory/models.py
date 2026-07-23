# services/bot_memory/models.py
"""Pydantic models and pure helpers for memory management."""

import logging
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Cap to avoid generating huge OR-chains in FTS5 MATCH expressions.
_FTS5_MAX_TOKENS = 16

# Semantic search tuning
_SEMANTIC_TOP_K_CANDIDATES = 20
_SEMANTIC_SIMILARITY_THRESHOLD = 0.65

# Topic keywords for auto-tagging (no HTTP calls — pure keyword overlap)
_TOPIC_LABELS = [
    ("cyber", "סייבר אבטחה פרצה וירוס תקיפה האקרים phishing ransomware malware"),
    ("economy", "כלכלה כסף מטבע בורסה מניה דולר שער שוק מסחר"),
    ("politics", "פוליטיקה כנסת ממשלה שר בחירות מפלגה חוק"),
    ("system", "מערכת מחשב CPU RAM דיסק תהליך רשת חיבור"),
    ("news", "חדשות מבזק כתבה עיתון תקשורת אירוע"),
    ("tech", "טכנולוגיה AI בינה מלאכותית סטארטאפ אפליקציה"),
    ("general", "כללי שאלה עזרה מידע תשובה עובדה"),
]

# Min length below which a response is treated as noise.
_MIN_PERSISTABLE_LEN = 4
_ERROR_PREFIXES = ("⚠️", "❌")


class MemoryEntry(BaseModel):
    """Pydantic model for memory validation."""

    id: int | None = None
    ts: str = Field(default_factory=lambda: datetime.now().isoformat())
    query: str
    response: str
    context: str = ""
    memory_type: str = "conversation"
    embedding: bytes | None = None
    cluster_id: str | None = None
    distance: float | None = 0.0  # transient: HNSW distance from last search


class MemoryQuery(BaseModel):
    """Query model for memory search."""

    query: str
    limit: int = 5
    memory_type: str | None = None


class MemoryEvent(BaseModel):
    """Pydantic model for episodic event validation."""

    id: int | None = None
    ts: str = Field(default_factory=lambda: datetime.now().isoformat())
    event_type: str  # alert | action | user_query | agent_response | escalation
    description: str
    severity: int = 1  # 1=info, 2=warning, 3=critical
    source: str = ""
    session_id: str = ""
    chain_id: str = ""
    metadata_json: str = "{}"


class EventQuery(BaseModel):
    """Query model for episodic event retrieval."""

    chain_id: str | None = None
    event_type: str | None = None
    source: str | None = None
    limit: int = 20
    since_hours: int | None = None


def _is_nonpersistable_response(response: str) -> bool:
    """True if response is an error/fallback string that must not pollute memory."""
    if not response:
        return True
    stripped = response.strip()
    if len(stripped) < _MIN_PERSISTABLE_LEN:
        return True
    return stripped.startswith(_ERROR_PREFIXES)


def _auto_tag_topic(text: str) -> str:
    """Classify text into a topic via keyword overlap. Returns topic name or 'general'."""
    q = text.lower()
    best_topic = "general"
    best_score = 0
    for topic_name, topic_text in _TOPIC_LABELS:
        keywords = set(topic_text.lower().split())
        score = sum(1 for kw in keywords if kw in q)
        if score > best_score:
            best_score = score
            best_topic = topic_name
    return best_topic if best_score > 0 else "general"
