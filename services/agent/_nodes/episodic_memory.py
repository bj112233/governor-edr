"""Episodic Memory — fire-and-forget event storage for action/alert tracking.

Extracted from _executor.py as part of Sprint 4 SRP refactor.
"""

from .._helpers import _fire_and_forget


async def _store_action_event(tool_name: str, args: dict, result: str, session_id: str, chain_id: str) -> None:
    from services.bot_memory.highlevel import inject_event

    await inject_event(
        event_type="tool_action",
        description=f"{tool_name}({str(args)[:80]}) -> {str(result)[:80]}",
        source="executor",
        session_id=session_id,
        chain_id=chain_id,
    )


async def _store_alert_event(tool_name: str, error_text: str, session_id: str, chain_id: str) -> None:
    from services.bot_memory.highlevel import inject_event

    _fire_and_forget(
        inject_event(
            event_type="tool_error",
            description=f"{tool_name} failed: {error_text}",
            severity=2,
            source="executor",
            session_id=session_id,
            chain_id=chain_id,
        )
    )
