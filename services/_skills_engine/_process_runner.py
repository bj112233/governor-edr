# services/_skills_engine/_process_runner.py
"""Subprocess lifecycle: spawn, wait with timeout, kill.

Extracted from executor.py (SRP): isolates asyncio subprocess management
from retry-orchestration and output-routing concerns.
"""

import asyncio
import logging
import os

logger = logging.getLogger(__name__)


class _TimeoutResult:
    """Sentinel: process timed out and was killed."""

    def __repr__(self) -> str:
        return "_TimeoutResult()"


TIMEOUT = _TimeoutResult()


async def spawn_and_wait(
    cmd_list: list[str],
    cwd: str,
    timeout: int,
    env: dict[str, str] | None = None,
) -> tuple[bytes, bytes, int | _TimeoutResult]:
    """Spawn subprocess, wait with timeout, kill on expiry.

    Returns (stdout_bytes, stderr_bytes, returncode).
    If timed out, returncode is TIMEOUT sentinel.
    """
    if env is None:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["LANG"] = "he_IL.UTF-8"

    process = await asyncio.create_subprocess_exec(
        *cmd_list,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        try:
            process.kill()
            await process.wait()
        except ProcessLookupError:
            pass
        return b"", b"", TIMEOUT

    return stdout_b, stderr_b, process.returncode if process.returncode is not None else -1
