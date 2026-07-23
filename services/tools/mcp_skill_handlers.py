"""MCP skill handlers — news, memory, file-analyst, web-scraper, intel, OSINT.

Extracted from mcp_handlers.py (SRP). These handlers delegate to the skills
engine or specialized services rather than implementing business logic directly.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)


# Keep references to background digest tasks to prevent GC cancellation.
_bg_digest_tasks: set[asyncio.Task] = set()


async def trigger_news_digest_tool(category: str = "") -> str:
    """Trigger the news digest (fire-and-forget).

    The full pipeline (RSS fetch → AI enrich → digest → SITREP) can take
    60-120s. The digest message and SITREP document are delivered to
    Telegram directly by the pipeline itself, so the caller doesn't need
    to wait. We start the work in the background and return immediately.
    """
    try:
        from services.scheduled_news import get_news_service

        service = get_news_service()
        await service.initialize()

        task = asyncio.create_task(service.trigger_manual_digest(category_filter=category))
        _bg_digest_tasks.add(task)
        task.add_done_callback(_bg_digest_tasks.discard)

        if category:
            return f"✅ הדייג׳סט התחיל (קטגוריה: {category}) — הקובץ יגיע לטלגרם"
        return "✅ הדייג׳סט התחיל — הקובץ יגיע לטלגרם"
    except Exception as e:
        logger.error("[mcp_skill_handlers] trigger_news_digest_tool failed: %s", e)
        return f"❌ שגיאה בהפעלת דייג׳סט: {e}"


async def recent_memory_tool(query: str = "recent", limit: int = 5) -> str:
    """Display recent conversation memories — Telegram-formatted (not LLM-context).

    Uses get_recent() directly instead of recall_context() (which returns
    LLM-injection format with [Context from memory:] header and truncated
    Q:q1... A:r1... placeholders). Adds DB stats footer.
    """
    try:
        from services.bot_memory.crud import get_memory_service
        from services.telegram.headers import SEPARATOR  # lazy: avoid circular import

        svc = get_memory_service()
        await svc._ensure_init()
        entries = await svc.get_recent(limit=int(limit), memory_type="conversation")

        # DB stats
        stats = await _get_memory_stats(svc)

        if not entries:
            return f"🧠 **זיכרונות אחרונים** (0)\n{SEPARATOR}\n\n📭 אין זיכרונות פעילים.\n\n{stats}"

        lines = [
            f"🧠 **זיכרונות אחרונים** ({len(entries)}):",
            SEPARATOR,
            "",
        ]
        for i, e in enumerate(entries, 1):
            ts_short = (e.ts or "")[:16].replace("T", " ")
            q = (e.query or "").replace("\n", " ").strip()
            a = (e.response or "").replace("\n", " ").strip()
            # Show query (truncated) + response preview
            q_display = q[:120] + ("…" if len(q) > 120 else "")
            a_display = a[:150] + ("…" if len(a) > 150 else "")
            lines.append(f"**#{i}**  `{ts_short}`")
            lines.append(f"  ❓ {q_display}")
            lines.append(f"  💬 {a_display}")
            lines.append("")

        lines.append(stats)
        return "\n".join(lines)
    except Exception as e:
        logger.error("[mcp_skill_handlers] recent_memory_tool failed: %s", e)
        return f"❌ שגיאת זיכרון: {e}"


async def _get_memory_stats(svc) -> str:
    """Fetch memory DB stats for /memory footer."""
    try:
        from services.bot_memory.crud import _pool

        async with _pool.acquire() as db:
            # Active conversations
            cursor = await db.execute(
                "SELECT COUNT(*) FROM memories WHERE is_archived = 0 AND memory_type = 'conversation'"
            )
            row = await cursor.fetchone()
            active = row[0] if row else 0

            # Archived
            cursor = await db.execute("SELECT COUNT(*) FROM memories WHERE is_archived = 1")
            row = await cursor.fetchone()
            archived = row[0] if row else 0

            # Summaries (Night Watchman compaction output)
            cursor = await db.execute("SELECT COUNT(*) FROM memories WHERE memory_type = 'summary'")
            row = await cursor.fetchone()
            summaries = row[0] if row else 0

            # Oldest active memory
            cursor = await db.execute("SELECT MIN(ts), MAX(ts) FROM memories WHERE is_archived = 0")
            row = await cursor.fetchone()
            oldest = (row[0] or "")[:10] if row and row[0] else "—"
            newest = (row[1] or "")[:10] if row and row[1] else "—"

        return (
            "📊 **סטטיסטיקות זיכרון:**\n"
            f"  • פעילים: {active} | מאורכבים: {archived} | סיכומים: {summaries}\n"
            f"  • טווח: {oldest} → {newest}\n"
            f"  • ניקוי: 04:00 יומי (7 ימים → ארכיון)\n"
            f"  • דחיסה: 05:00 יומי (30 ימים → סיכום LLM)"
        )
    except Exception as exc:
        logger.debug("[memory stats] failed: %s", exc)
        return "📊 סטטיסטיקות לא זמינות"


async def skill_file_analyst(path: str = "") -> str:
    """Call file-analyst skill."""
    if not path:
        return "❌ נדרש נתיב קובץ. לדוגמה: /analyze report.pdf"
    try:
        from services.skills_engine import get_skills_engine

        engine = get_skills_engine()
        return await engine.execute("file-analyst", "summarize", f"--path {path}")
    except Exception as e:
        logger.error("[mcp_skill_handlers] skill_file_analyst failed: %s", e)
        return f"❌ שגיאת file-analyst: {e}"


async def skill_web_scraper(url: str = "") -> str:
    """Call web-scraper skill."""
    if not url:
        return "❌ נדרש URL. לדוגמה: /scrape https://example.com"
    try:
        from services.skills_engine import get_skills_engine

        engine = get_skills_engine()
        return await engine.execute("web-scraper", "fetch", f"--url {url}")
    except Exception as e:
        logger.error("[mcp_skill_handlers] skill_web_scraper failed: %s", e)
        return f"❌ שגיאת web-scraper: {e}"


async def skill_intel(target: str = "") -> str:
    """Call intel-skill."""
    if not target:
        return "❌ נדרש IP או דומיין. לדוגמה: /intel 8.8.8.8 או /intel domain.il"
    try:
        from services.skills_engine import get_skills_engine

        engine = get_skills_engine()
        return await engine.execute("intel-skill", "israeli", f"--target {target}")
    except Exception as e:
        logger.error("[mcp_skill_handlers] skill_intel failed: %s", e)
        return f"❌ שגיאת intel: {e}"


async def osint_hunt_tool(topic: str = "") -> str:
    """OSINT hunt with local threat check."""
    if not topic:
        return "❌ נדרש נושא לחיפוש. לדוגמה: /hunt CVE-2024-1234"
    try:
        from services.osint_hunter import hunt_and_analyze

        result = await hunt_and_analyze(topic)
        lines = [f"🛡️ **דוח OSINT: {topic}**", ""]
        if result.get("critical_local_threat"):
            lines.append("🔴 **איום מקומי קריטי!**")
            lines.append(f"Matches: {result.get('local_matches', [])}")
            lines.append("")
        report = result.get("report", "")
        if report:
            lines.append(f"**דוח:**\n{report[:800]}")
        iocs = result.get("iocs", {})
        if iocs:
            lines.append("")
            lines.append("**IOCs:**")
            for key, values in iocs.items():
                if values:
                    lines.append(f"  {key}: {', '.join(str(v) for v in values[:10])}")
        lines.append(f"\n**Iterations:** {result.get('iterations', 0)}")
        return "\n".join(lines)
    except Exception as e:
        logger.error("[mcp_skill_handlers] osint_hunt_tool failed: %s", e)
        return f"❌ שגיאת OSINT hunt: {e}"
