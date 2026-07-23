# services/agent/interfaces.py
"""Ports (abstract interfaces) for the Agent core layer.

These Protocols define the contracts the Agent depends on, without coupling
to any concrete adapter (Telegram, WhatsApp, Discord, etc.).

The Composition Root (main.py) is the only place that wires concrete adapters
to these ports via Dependency Injection.

Hexagonal Architecture: Agent = Hexagon, Telegram = Adapter.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class MessageGateway(Protocol):
    """Port: send messages + manage pairings through any messaging adapter."""

    async def send_message(self, chat_id: str | int, text: str, **kwargs: Any) -> bool:
        """Send a text message to a chat. Returns True on success."""
        ...

    async def list_pending_pairings(self) -> list[dict[str, Any]]:
        """Return pending pairing requests (for approval workflow)."""
        ...

    async def approve_pairing(self, code: str) -> dict[str, Any] | None:
        """Approve a pairing request by code. Returns user info or None."""
        ...


# ── Registry for DI ──────────────────────────────────────────────

_gateway: MessageGateway | None = None


def set_message_gateway(gateway: MessageGateway | None) -> None:
    """Inject the concrete MessageGateway (called from Composition Root)."""
    global _gateway
    _gateway = gateway


def get_message_gateway() -> MessageGateway | None:
    """Get the injected MessageGateway, or None if not wired."""
    return _gateway
