"""LAN background scan — fire-and-forget during boot. Leaf module."""

import logging

from services.device_registry import auto_discover_lan

logger = logging.getLogger(__name__)


async def _scan_lan_background() -> None:
    """Background LAN scan — non-blocking boot."""
    try:
        new_devices = await auto_discover_lan()
        # First Principles: Use %s to be immune to return type (int vs list/set)
        logger.info("[LAN] \u2705 LAN scan complete: %s new devices registered.", new_devices)
    except Exception as e:
        logger.error("[LAN] \u274c LAN scan failed: %s", e, exc_info=True)
