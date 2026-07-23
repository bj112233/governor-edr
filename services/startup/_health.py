"""Health observer — non-blocking TCP/HTTP probes for local services. Leaf module."""

import asyncio
import logging

logger = logging.getLogger(__name__)


async def _probe_mcp(port: int) -> bool:
    """HTTP health probe for MCP service with optional auth."""
    import httpx

    from config import MCP_AUTH_ENABLED, MCP_AUTH_TOKEN

    headers = {}
    if MCP_AUTH_ENABLED and MCP_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {MCP_AUTH_TOKEN}"
    async with httpx.AsyncClient(timeout=2.0) as client:
        resp = await client.get(f"http://127.0.0.1:{port}/mcp/health", headers=headers)
        return resp.status_code == 200


async def _probe_tcp(port: int) -> bool:
    """TCP connect probe for non-MCP services."""
    _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=2.0)
    writer.close()
    await writer.wait_closed()
    return True


async def _probe_service(name: str, port: int) -> bool:
    """Probe a single service. Returns True if ready."""
    try:
        if name == "MCP":
            return await _probe_mcp(port)
        return await _probe_tcp(port)
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False
    except Exception:
        return False


def _log_status(ports: dict[str, int], pending: set[str]) -> None:
    """Log current service status."""
    parts = [n + (" \u2705" if n not in pending else " \u23f3") for n in ports]
    logger.info("[Health] Waiting: %s", " | ".join(parts))


async def await_all_services(
    ports: dict[str, int],
    retry_interval: int = 5,
    max_wait: int = 300,
) -> None:
    """Block until all ports answer TCP connect (or HTTP with auth for MCP), or crash after max_wait seconds."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max_wait
    pending = set(ports.keys())

    while pending and loop.time() < deadline:
        newly_ready = set()
        for name in list(pending):
            if await _probe_service(name, ports[name]):
                newly_ready.add(name)
                logger.info("[Health] \u2705 %s (:%s) ready", name, ports[name])

        pending -= newly_ready
        if pending:
            _log_status(ports, pending)
            await asyncio.sleep(retry_interval)

    if pending:
        logger.error(
            "[Health] Services not ready after %ds: %s. "
            "Running in degraded mode (LLM features may be unavailable until services recover).",
            max_wait,
            ", ".join(pending),
        )
        return
    logger.info("[Health] \u2705 All services ready.")
