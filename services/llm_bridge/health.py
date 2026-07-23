# services/llm_bridge/health.py
"""Background health monitor — runs once at startup via main.py."""

import asyncio
import logging

from config import LLM_HEALTH_INTERVAL

from .models import _STATE_OPEN

logger = logging.getLogger(__name__)


def _boost_koboldcpp_priority() -> None:
    """Set koboldcpp.exe process priority to ABOVE_NORMAL (Windows only).

    Under 100% CPU load, the Windows OS scheduler starves the KoboldCpp
    HTTP thread, causing Connection Refused even when the GPU is idle.
    ABOVE_NORMAL ensures the HTTP server always gets CPU time to answer.
    """
    if not __import__("sys").platform.startswith("win"):
        return
    try:
        import psutil

        for proc in psutil.process_iter(["pid", "name"]):
            name = (proc.info.get("name") or "").lower()
            if "koboldcpp" in name:
                p = psutil.Process(proc.info["pid"])
                # ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
                # psutil maps this via psutil.ABOVE_NORMAL_PRIORITY_CLASS
                p.nice(psutil.ABOVE_NORMAL_PRIORITY_CLASS)
                logger.info("[Bridge] Set %s (PID=%d) priority → ABOVE_NORMAL", name, proc.info["pid"])
                return
    except Exception as exc:
        logger.warning("[Bridge] Could not boost KoboldCpp priority: %s", exc)


async def health_loop(
    probe_client,
    model: str,
    cb,
    semaphore: asyncio.Semaphore,
    ready_event: asyncio.Event,
) -> None:
    """Continuous background health monitor (never returns).

    Two-stage probe: (1) models.list() confirms HTTP endpoint;
    (2) a 1-token chat completion confirms model is loaded into VRAM.
    On first success, boosts KoboldCpp process priority to ABOVE_NORMAL.
    """
    attempt = 0
    while True:
        attempt += 1
        if cb.can_probe():
            cb.promote_half_open()
        try:
            await probe_client.models.list()
            if not ready_event.is_set() or cb.state == "half_open":
                async with semaphore:
                    await probe_client.with_options(timeout=10.0).chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": "ping"}],
                        max_tokens=1,
                        temperature=0.0,
                    )
            cb.on_success()
            if not ready_event.is_set():
                ready_event.set()
                _boost_koboldcpp_priority()
            logger.info("[Bridge] LLM OK (attempt %d)", attempt)
        except Exception as exc:
            cb.on_failure()
            logger.warning("[Bridge] LLM FAIL (attempt %d): %s", attempt, exc)
        await asyncio.sleep(LLM_HEALTH_INTERVAL)
