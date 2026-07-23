# services/news_ai/reports.py
"""Report consolidation — single LLM call to merge cluster summaries."""

import logging
from typing import Optional

from ._security import FIREWALL_DIRECTIVE, sanitize, wrap_untrusted_block

logger = logging.getLogger(__name__)


async def consolidate_to_report(
    cluster_summaries: list[str],
    cluster_sentiments: list[str],
    topic: str,
    bridge,
    timeout: float = 30.0,
) -> str | None:
    """Consolidate multiple cluster summaries into a single unified report."""
    if not cluster_summaries or len(cluster_summaries) <= 1:
        return None

    lines = []
    for i, (summary, sentiment) in enumerate(zip(cluster_summaries, cluster_sentiments), start=1):
        lines.append(f"סיפור {i} (טון: {sentiment}):")
        lines.append(sanitize(summary))
        lines.append("")

    system_prompt = (
        "אתה עורך חדשות בכיר ומקצועי. תפקידך למזג דיווחים שונים לתקציר מאוחד אחד, "
        "ברור ותמציתי בעברית. שמר מונחי סייבר באנגלית: MITRE ATT&CK, TTP, IOC, "
        "Encoded Commands, Execution Policy Bypass, Defense Evasion, Persistence. "
        "החזר את התשובה בפורמט טקסט נקי בלבד. ללא הקדמות, ללא כותרות וללא תגיות Markdown מורכבות." + FIREWALL_DIRECTIVE
    )

    user_input = (
        "קרא את הסיפורים הבאים והפק דוח תקצירי אחד, מאוחד וקוהרנטי בעברית. "
        "הדוח צריך לפתוח עם פסקה כללית של 2-3 משפטים המסכמת את המגמות העיקריות, "
        "ולאחר מכן 3-5 נקודות מרכזיות (bullet points). "
        "אין צורך לחזור על כל פרט — התמקד במה שמשמעותי.\n\n"
        f"נושא: {topic}\n\n" + wrap_untrusted_block("\n".join(lines))
    )

    try:
        report = await bridge.complete(
            system_prompt=system_prompt,
            user_input=user_input,
            temperature=0.3,
            max_tokens=800,
            timeout=timeout,
        )
        return report.strip() if report else None
    except Exception as exc:
        logger.debug("[NewsAI] consolidate_to_report failed: %s", exc)
        return None
