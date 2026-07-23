# services/agent/bypass/intel.py
"""Deterministic bypass for intel-skill: IP/domain/hash lookups.

Routes simple IOC queries directly to the skill without waking the LLM.
Regex is strict — only triggers on explicit IP/domain/hash patterns with
intel keywords, leaving complex queries to the agent.
"""

import asyncio
import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)

# IPv4 pattern (strict — no partial matches)
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Domain pattern — requires at least one dot + TLD, excludes common false positives
_DOMAIN_RE = re.compile(
    r"\b((?!www\.|http)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\b"
)

# Hash patterns — md5 (32), sha1 (40), sha256 (64) hex
_HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

# Intel keywords (Hebrew + English) — must be present to trigger bypass
_INTEL_KEYWORDS = frozenset(
    [
        # Hebrew
        "בדוק",
        "בדיקת",
        "סרוק",
        "סריקת",
        "מוניטין",
        "זדוני",
        "חשוד",
        "אייפי",
        "דומיין",
        "וירוס",
        "תוכנה זדונית",
        "מלישיות",
        "שרת חשוד",
        # English
        "reputation",
        "lookup",
        "check ip",
        "scan domain",
        "threat",
        "blacklist",
        "malware",
        "suspicious",
        "whois",
        "dns lookup",
    ]
)

# Keywords that indicate a complex query needing the agent
_COMPLEX_KEYWORDS = frozenset(
    [
        "נתח",
        "analyze",
        "השווה",
        "compare",
        "דוח",
        "report",
        "סיכום",
        "summarize",
        "תפרט",
        "elaborate",
        "מה קורה",
    ]
)


def _detect_ip(q: str, q_lower: str) -> tuple[str, str] | None:
    """Detect IPv4 IOC. Returns (command, ip) or None."""
    m = _IPV4_RE.search(q)
    if not m:
        return None
    ip = m.group(1)
    parts = ip.split(".")
    if not all(0 <= int(p) <= 255 for p in parts):
        return None
    if "whois" in q_lower:
        return ("whois", ip)
    return ("ip", ip)


def _detect_hash(q: str) -> tuple[str, str] | None:
    """Detect hash IOC. Returns (command, hash) or None."""
    m = _HASH_RE.search(q)
    if not m:
        return None
    return ("hash", m.group(1))


_DOMAIN_EXCLUDED = {".py", ".js", ".txt", ".md", ".csv", ".json", ".html"}


def _detect_domain(q: str, q_lower: str) -> tuple[str, str] | None:
    """Detect domain IOC. Returns (command, domain) or None."""
    m = _DOMAIN_RE.search(q)
    if not m:
        return None
    domain = m.group(1)
    if any(domain.endswith(ext) for ext in _DOMAIN_EXCLUDED):
        return None
    if "whois" in q_lower:
        return ("whois", domain)
    if "dns" in q_lower:
        return ("dns", domain)
    return ("domain", domain)


def _has_intel_trigger(q_lower: str) -> bool:
    """Check if query has intel keywords or check verbs."""
    has_intel_kw = any(kw in q_lower for kw in _INTEL_KEYWORDS)
    has_check_verb = any(kw in q_lower for kw in ("check", "scan", "lookup", "בדוק", "סרוק"))
    return has_intel_kw or has_check_verb


def _detect_intel_query(q: str) -> tuple[str, str] | None:
    """Return (command, target) if this is a simple intel lookup, else None.

    Commands: ip, domain, hash, dns, whois
    """
    if not q or len(q) > 200:
        return None

    q_lower = q.lower()
    if any(kw in q_lower for kw in _COMPLEX_KEYWORDS):
        return None
    if not _has_intel_trigger(q_lower):
        return None

    return _detect_ip(q, q_lower) or _detect_hash(q) or _detect_domain(q, q_lower)


async def _direct_intel_bypass(command: str, target: str, user_question: str) -> str:
    """Deterministic bypass: call skill_intel-skill directly, return verbatim."""
    engine = get_skills_engine()
    logger.info(f"[AGENT] Intel bypass: {command} target={target}")
    try:
        result = await engine.execute("intel-skill", command, {"target": target})
    except Exception as e:
        logger.error(f"[AGENT] Intel bypass failed: {e}")
        return f"⚠️ שגיאה בבדיקת {command} עבור {target}."
    if not result or result.startswith("❌"):
        return f"⚠️ לא ניתן לקבל נתוני מודיעין עבור {target}."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
