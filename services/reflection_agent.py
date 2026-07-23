# services/reflection_agent.py
"""Weekly Auto-Reflection (Critic Node) — offline batch self-critique.

Runs Friday 16:00 via APScheduler. Queries the last 7 days of:
  - Error lessons (tool failures, hallucinations) — GROUP BY + COUNT (dedup)
  - Bot telemetry (aggregated stats only)
  - Threat hunt statistics (metadata only, NOT report content)

Pre-computes a compact XML-tagged block (<1000 tokens) and asks the LLM
for a 'Lessons Learned' reflection. Output: .md file + tasks/lessons.md
append + Telegram event bus delivery.

Architecture: NOT in startup/ (that's for bootstrap). This is a batch job.
"""

import logging
from pathlib import Path

from config import LLM_TIMEOUT

logger = logging.getLogger(__name__)

_REFLECTION_PROMPT = (
    "You are Sentinel's Critic Node. Review your operational metrics and "
    "errors from the last 7 days provided in the XML tags. Generate a "
    "'Lessons Learned' reflection. Focus on reducing tool errors, improving "
    "latency, and avoiding hallucinations.\n"
    "CRITICAL: Output the 3 bullet points of what went wrong and 2 actionable "
    "rules in Hebrew, but keep all technical terms (e.g., Latency, "
    "Hallucination, Tool Calls, JSON) strictly in English.\n"
    "Format: Markdown. No preamble. Start directly with the bullet points."
)


async def _build_reflection_block() -> str:
    """Pre-compute compact XML-tagged data block for the LLM (<1000 tokens).

    Aggregates via SQL (GROUP BY + COUNT) to avoid token bloat from
    repeated identical errors.
    """
    from services.error_memory import get_errors_last_7d
    from services.memory_db import get_hunts_last_7d
    from services.telemetry import get_telemetry

    parts = []

    # 1. Tool failures — deduplicated, max 15 unique patterns
    errors = await get_errors_last_7d(limit=15)
    if errors:
        lines = ["<TOOL_FAILURES>"]
        for e in errors:
            sig = (e["error_signature"] or "")[:120]
            tool = e["tool_name"] or "unknown"
            count = e["occurrences"]
            lines.append(f"- [{e['last_seen'][:10]}] {sig} (tool={tool}, occurred {count}x)")
        lines.append("</TOOL_FAILURES>")
        parts.append("\n".join(lines))

    # 2. Agent telemetry — aggregated stats only
    try:
        snap = get_telemetry().snapshot()
        llm = snap.get("llm", {})
        tools = snap.get("tools", {})
        top_tools = sorted(tools.get("per_tool", {}).items(), key=lambda kv: kv[1]["n"], reverse=True)[:3]
        tele_lines = ["<AGENT_TELEMETRY>"]
        tele_lines.append(f"- Total LLM Calls: {llm.get('calls', 0)}")
        tele_lines.append(f"- LLM Errors: {llm.get('errors', 0)}")
        tele_lines.append(f"- Average Latency (p95): {llm.get('p95_ms', 0)}ms")
        tele_lines.append(f"- Tool Calls: {tools.get('calls', 0)}")
        tele_lines.append(f"- Tool Errors: {tools.get('errors', 0)}")
        if top_tools:
            top_str = ", ".join(f"{name} ({st['n']}x)" for name, st in top_tools)
            tele_lines.append(f"- Top Used Tools: {top_str}")
        tele_lines.append("</AGENT_TELEMETRY>")
        parts.append("\n".join(tele_lines))
    except Exception as exc:
        logger.debug("[Reflection] Telemetry collection failed: %s", exc)

    # 3. Hunt statistics — metadata only (count, avg, dispatches)
    try:
        hunts = await get_hunts_last_7d()
        if hunts and hunts.get("total", 0) > 0:
            hunt_lines = ["<HUNT_STATISTICS>"]
            hunt_lines.append(f"- Total Hunts Executed: {hunts['total']}")
            hunt_lines.append(f"- Average Threat Score: {hunts['avg_score']}")
            hunt_lines.append(f"- High-Risk Dispatches (>0.8): {hunts['high_risk']}")
            hunt_lines.append(f"- Total Dispatches: {hunts['dispatched']}")
            hunt_lines.append("</HUNT_STATISTICS>")
            parts.append("\n".join(hunt_lines))
    except Exception as exc:
        logger.debug("[Reflection] Hunt stats failed: %s", exc)

    return "\n\n".join(parts) if parts else ""


async def run_weekly_reflection() -> str:
    """Main entry: generate weekly reflection report.

    Returns the reflection text (empty string on failure/no data).
    Saves .md file, appends to tasks/lessons.md, emits Telegram event.
    """
    logger.info("[Reflection] Starting weekly Critic Node reflection...")

    block = await _build_reflection_block()
    if not block:
        logger.info("[Reflection] No data to reflect on (empty block). Skipping.")
        return ""

    try:
        from services.llm_bridge import LLMBridge

        bridge = LLMBridge.get_instance()
        if not bridge.should_accept_traffic():
            logger.warning("[Reflection] LLM circuit open, skipping reflection.")
            return ""

        reflection = await bridge.complete(
            system_prompt=_REFLECTION_PROMPT,
            user_input=block,
            temperature=0.3,
            max_tokens=1024,
            timeout=float(LLM_TIMEOUT * 3),  # Reflection: 3x (longer generation)
        )
        reflection = (reflection or "").strip()
        if not reflection:
            logger.warning("[Reflection] LLM returned empty reflection. Skipping.")
            return ""
    except Exception as exc:
        logger.error("[Reflection] LLM call failed: %s", exc)
        return ""

    # Build full report via Jinja2 template (services.reports)
    from services.reports.env import get_report_env
    from services.time_format import format_report_date

    date_str = format_report_date()
    report = (
        get_report_env()
        .get_template("reflection.j2")
        .render(
            emoji="🧠",
            title=f"רפלקציה שבועית — Critic Node [{date_str}]",
            reflection=reflection,
        )
    )

    # Save .md file
    out_dir = Path("downloads/reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / f"reflection_{date_str}.md"
    filepath.write_text(report, encoding="utf-8")
    logger.info("[Reflection] Saved -> %s", filepath)

    # Append to tasks/lessons.md
    lessons_path = Path("tasks/lessons.md")
    if lessons_path.exists():
        with lessons_path.open("a", encoding="utf-8") as f:
            f.write(f"\n### [{date_str}] Weekly Reflection — Critic Node\n")
            f.write(f"{reflection}\n")
        logger.info("[Reflection] Appended to tasks/lessons.md")

    # Emit to Telegram via event bus
    try:
        from services.sentinel_events import send_weekly_reflection_event

        await send_weekly_reflection_event(report)
        logger.info("[Reflection] Emitted to event bus for Telegram delivery.")
    except Exception as exc:
        logger.warning("[Reflection] Event bus delivery failed: %s", exc)

    return report
