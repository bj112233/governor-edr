# services/tools/_ioc_history_handler.py
"""IOC historical memory handler — isolated from system_tools.py for SRP."""

from services.ioc_memory_store import recall_decayed_score, recall_history


async def query_ioc_history_handler(ioc: str) -> str:
    """Query IOC historical memory — decayed score + raw events. O(1) SQLite lookup."""
    import asyncio as _aio

    try:
        score, events = await _aio.gather(
            recall_decayed_score(str(ioc)),
            recall_history(str(ioc)),
        )
    except Exception as exc:
        return f"❌ IOC history query failed: {exc}"

    if not events and score == 0.0:
        return f"📭 No historical record for IOC: {ioc}"

    lines = [
        f"🧠 **IOC History: {ioc}**",
        f"Decayed score: **{score:.1f}/100** (14-day half-life)",
        f"Events: {len(events)}",
    ]
    for e in events[:5]:
        lines.append(
            f"  - {e.get('timestamp', '?')} | score={e.get('score', '?')} | src={e.get('context_source', '?')}"
        )
    if len(events) > 5:
        lines.append(f"  ... and {len(events) - 5} more")
    return "\n".join(lines)
