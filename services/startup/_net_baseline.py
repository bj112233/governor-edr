"""Net baseline collector — sync psutil calls, always run via asyncio.to_thread. Leaf module."""

import logging
from typing import Any

import psutil

logger = logging.getLogger(__name__)


def _collect_net_baseline_rows() -> list[dict[str, Any]]:
    """Sync collector for net baseline rows. MUST be invoked via asyncio.to_thread
    to keep psutil's blocking syscalls off the main event loop."""
    rows: list[dict[str, Any]] = []

    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue

            proc_name = "Unknown"
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            rows.append(
                {
                    "proc_name": proc_name,
                    "raddr_ip": str(c.raddr.ip),
                    "raddr_port": int(c.raddr.port),
                }
            )
    except psutil.AccessDenied as e:
        logger.warning("[NetBaseline] Access Denied executing net_connections. Run as Admin. Error: %s", e)
    except Exception as e:
        logger.error("[NetBaseline] Unexpected error collecting net baseline: %s", e, exc_info=True)

    return rows
