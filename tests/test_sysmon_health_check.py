# tests/test_sysmon_health_check.py
"""Tests for Sysmon service health check."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_check_sysmon_health_running():
    """When sc query returns RUNNING, health check returns True."""
    from services.startup._health import check_sysmon_health

    with patch(
        "services.startup._health._check_sysmon_service",
        return_value=True,
    ):
        result = await check_sysmon_health()
    assert result is True


@pytest.mark.asyncio
async def test_check_sysmon_health_not_running():
    """When Sysmon is not running, health check returns False (non-fatal)."""
    from services.startup._health import check_sysmon_health

    with patch(
        "services.startup._health._check_sysmon_service",
        return_value=False,
    ):
        result = await check_sysmon_health()
    assert result is False


def test_check_sysmon_service_parses_running_state():
    """_check_sysmon_service returns True when sc query output contains RUNNING."""
    from services.startup._health import _check_sysmon_service

    mock_output = """
SERVICE_NAME: Sysmon
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_output
        mock_run.return_value.returncode = 0
        result = _check_sysmon_service()
    assert result is True


def test_check_sysmon_service_stopped():
    """_check_sysmon_service returns False when service is stopped."""
    from services.startup._health import _check_sysmon_service

    mock_output = """
SERVICE_NAME: Sysmon
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_output
        mock_run.return_value.returncode = 0
        result = _check_sysmon_service()
    assert result is False


def test_check_sysmon_service_not_installed():
    """_check_sysmon_service returns False when service doesn't exist."""
    from services.startup._health import _check_sysmon_service

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 1060  # service not found
        result = _check_sysmon_service()
    assert result is False
