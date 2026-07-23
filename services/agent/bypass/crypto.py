# services/agent/bypass/crypto.py
"""Deterministic bypass for crypto-skill: hash/encode/decode/uuid.

Routes simple cryptographic operations directly to the skill without
waking the LLM. Regex is strict — only triggers on explicit crypto
operation keywords with a clear target, leaving complex queries to agent.
"""

import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)

# Crypto operation patterns — maps Hebrew/English verbs to commands
# Each pattern: (regex, command, extract_group)
# The regex must capture the target text/hash/token.

# Hash requests: "hash hello", "sha256 of hello", "גיבוב של hello"
_HASH_RE = re.compile(
    r"(?:hash|sha256|sha1|md5|גיבוב|חשב)\s+(?:of\s+|של\s+)?[\"']?(.+?)[\"']?(?:\s+--algo|\s*$)",
    re.IGNORECASE,
)

# Base64 encode: "base64 encode hello", "קידוד base64 של hello"
_B64_ENCODE_RE = re.compile(
    r"(?:base64|b64)\s+(?:encode|קידוד)[\s:]+[\"']?(.+?)[\"']?(?:\s*$)",
    re.IGNORECASE,
)

# Base64 decode: "base64 decode aGVsbG8=", "פענח base64 aGVsbG8="
_B64_DECODE_RE = re.compile(
    r"(?:base64|b64)\s+(?:decode|פענח)[\s:]+[\"']?(.+?)[\"']?(?:\s*$)",
    re.IGNORECASE,
)

# UUID: "generate uuid", "צור uuid"
_UUID_RE = re.compile(r"(?:generate|create|צור|צור סיסמה|uuid)", re.IGNORECASE)

# Password: "generate password", "צור סיסמה"
_PASSWORD_RE = re.compile(
    r"(?:generate|create|צור)\s+(?:password|סיסמה)",
    re.IGNORECASE,
)

# JWT decode: "jwt decode eyJ...", "פענח jwt eyJ..."
_JWT_RE = re.compile(
    r"jwt\s+(?:decode|פענח)[\s:]+[\"']?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)[\"']?",
    re.IGNORECASE,
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
        "encrypt",
        "decrypt",
        "הצפן",
        "פענח הצפנה",  # these need key params — too complex for bypass
    ]
)


def _detect_crypto_query(q: str) -> tuple[str, dict] | None:
    """Return (command, args_dict) if this is a simple crypto op, else None.

    Commands: hash, b64, uuid, password, jwt
    """
    if not q or len(q) > 300:
        return None

    q_lower = q.lower()

    # Reject complex queries
    if any(kw in q_lower for kw in _COMPLEX_KEYWORDS):
        return None

    # Hash
    m = _HASH_RE.search(q)
    if m:
        text = m.group(1).strip().strip("\"'")
        algo = "sha256"
        if "md5" in q_lower:
            algo = "md5"
        elif "sha1" in q_lower:
            algo = "sha1"
        elif "sha256" in q_lower:
            algo = "sha256"
        return ("hash", {"text": text, "algo": algo})

    # Base64 encode
    m = _B64_ENCODE_RE.search(q)
    if m:
        text = m.group(1).strip().strip("\"'")
        return ("b64", {"encode": True, "text": text})

    # Base64 decode
    m = _B64_DECODE_RE.search(q)
    if m:
        text = m.group(1).strip().strip("\"'")
        return ("b64", {"decode": True, "text": text})

    # UUID
    if _UUID_RE.search(q) and "uuid" in q_lower:
        return ("uuid", {})

    # Password
    m = _PASSWORD_RE.search(q)
    if m:
        return ("password", {})

    # JWT decode
    m = _JWT_RE.search(q)
    if m:
        token = m.group(1).strip()
        return ("jwt", {"token": token})

    return None


async def _direct_crypto_bypass(command: str, args: dict, user_question: str) -> str:
    """Deterministic bypass: call skill_crypto-skill directly, return verbatim."""
    engine = get_skills_engine()
    logger.info(f"[AGENT] Crypto bypass: {command} args={list(args.keys())}")
    try:
        result = await engine.execute("crypto-skill", command, args)
    except Exception as e:
        logger.error(f"[AGENT] Crypto bypass failed: {e}")
        return f"⚠️ שגיאה בפעולת {command}."
    if not result or result.startswith("❌"):
        return f"⚠️ פעולת {command} נכשלה."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
