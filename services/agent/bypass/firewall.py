# services/agent/bypass/firewall.py
"""Deterministic bypass for firewall-skill: block/unblock/list/stats.

Routes simple firewall commands directly to the skill without waking the
LLM. Regex is strict — only triggers on explicit block/unblock/list/stats
with IP/CIDR target, leaving complex queries (attack analysis, trends) to agent.
"""

import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)

# IPv4 pattern
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# CIDR pattern
_CIDR_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b")

# Port pattern — 1-5 digit number after "port" keyword
_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)
# Also match "פורט" (Hebrew)
_PORT_HE_RE = re.compile(r"פורט\s+(\d{1,5})")

# Protocol detection
_UDP_RE = re.compile(r"\b(udp|UDP)\b")

# Block/unblock keywords
_BLOCK_RE = re.compile(r"\b(block|חסום|חסימה)\b", re.IGNORECASE)
_UNBLOCK_RE = re.compile(r"\b(unblock|שחרר|שחרור|הסר חסימה)\b", re.IGNORECASE)

# Simple query commands — no target needed
_LIST_RE = re.compile(r"\b(list|רשימה|רשימת חסימות|חסימות פעילות)\b", re.IGNORECASE)
_STATS_RE = re.compile(r"\b(stats|סטטיסטיקה|סטטיסטיקת|סטטוס חומת)\b", re.IGNORECASE)
_DROPS_RE = re.compile(r"\b(drops|drop events|אירועי drop|אירועי חסימה)\b", re.IGNORECASE)
_SWEEP_RE = re.compile(r"\b(sweep|נקה|ניקוי חסימות)\b", re.IGNORECASE)

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
        "מגמה",
        "trend",
        "מתקפה",
        "attack",
        "סרוק",
        "scan",
        "audit",
        "ביקורת",
        "whitelist",
        "רשימה לבנה",
        "תבדוק",
        "בדוק",
        "למה",
        "האם",
        "check if",
        "should",
    ]
)


def _parse_port(q: str) -> tuple[int, str] | None:
    """Extract (port, protocol) from query, or None if no valid port."""
    m = _PORT_RE.search(q) or _PORT_HE_RE.search(q)
    if not m:
        return None
    port = int(m.group(1))
    if not (1 <= port <= 65535):
        return None
    protocol = "UDP" if _UDP_RE.search(q) else "TCP"
    return (port, protocol)


def _parse_ip(q: str) -> str | None:
    """Extract validated IPv4 from query, or None."""
    m = _IPV4_RE.search(q)
    if not m:
        return None
    ip = m.group(1)
    parts = ip.split(".")
    if all(0 <= int(p) <= 255 for p in parts):
        return ip
    return None


def _parse_cidr(q: str) -> str | None:
    """Extract CIDR from query, or None."""
    m = _CIDR_RE.search(q)
    return m.group(1) if m else None


# Simple commands that need no target — dispatch table
_SIMPLE_COMMANDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_LIST_RE, "list"),
    (_STATS_RE, "stats"),
    (_DROPS_RE, "drops"),
    (_SWEEP_RE, "sweep"),
)


def _parse_block_command(q: str) -> tuple[str, dict] | None:
    """Parse block command: port → CIDR → IP priority."""
    port_info = _parse_port(q)
    if port_info:
        return ("block-port", {"port": port_info[0], "protocol": port_info[1]})
    cidr = _parse_cidr(q)
    if cidr:
        return ("block-cidr", {"network": cidr})
    ip = _parse_ip(q)
    if ip:
        return ("block", {"ip": ip})
    return None


def _parse_unblock_command(q: str) -> tuple[str, dict] | None:
    """Parse unblock command: port → IP priority."""
    port_info = _parse_port(q)
    if port_info:
        return ("unblock-port", {"port": port_info[0], "protocol": port_info[1]})
    ip = _parse_ip(q)
    if ip:
        return ("unblock", {"ip": ip})
    return None


def _detect_firewall_query(q: str) -> tuple[str, dict] | None:
    """Return (command, args_dict) if this is a simple firewall op, else None.

    Commands: block, unblock, block-cidr, list, stats, drops, sweep
    """
    if not q or len(q) > 200:
        return None

    q_lower = q.lower()

    # Reject complex queries — they need agent reasoning
    if any(kw in q_lower for kw in _COMPLEX_KEYWORDS):
        return None

    # Block / unblock — delegate to target parsers
    if _BLOCK_RE.search(q):
        return _parse_block_command(q)
    if _UNBLOCK_RE.search(q):
        return _parse_unblock_command(q)

    # Simple commands — dispatch table
    for pattern, cmd in _SIMPLE_COMMANDS:
        if pattern.search(q):
            return (cmd, {})

    return None


async def _direct_firewall_bypass(command: str, args: dict, user_question: str) -> str:
    """Deterministic bypass: call skill_firewall-skill directly, return verbatim."""
    engine = get_skills_engine()
    logger.info(f"[AGENT] Firewall bypass: {command} args={list(args.keys())}")
    try:
        result = await engine.execute("firewall-skill", command, args)
    except Exception as e:
        logger.error(f"[AGENT] Firewall bypass failed: {e}")
        return f"⚠️ שגיאה בפעולת {command}."
    if not result or result.startswith("❌"):
        return f"⚠️ פעולת {command} נכשלה."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
