"""Lazy init for MonitorAI analyzer + alert dispatcher — leaf module, zero internal imports."""

import logging
from typing import TYPE_CHECKING, Optional

from config import (
    MONITOR_AI_ENABLED,
    MONITOR_ALERT_COOLDOWN_SECONDS,
    MONITOR_BASELINE_WINDOW_DAYS,
    MONITOR_MAX_ALERTS_PER_WINDOW,
    MONITOR_REQUIRED_CYCLES,
    MONITOR_Z_THRESHOLD,
)

if TYPE_CHECKING:
    from services.alert_dispatcher import AlertDispatcher
    from services.monitor_analyzer import MonitorAnalyzer

logger = logging.getLogger(__name__)

_monitor_analyzer: Optional["MonitorAnalyzer"] = None
_alert_dispatcher: Optional["AlertDispatcher"] = None


def _get_monitor_analyzer() -> Optional["MonitorAnalyzer"]:
    global _monitor_analyzer
    if _monitor_analyzer is None and MONITOR_AI_ENABLED:
        from services.monitor_analyzer import MonitorAnalyzer

        _monitor_analyzer = MonitorAnalyzer(
            z_threshold=MONITOR_Z_THRESHOLD,
            required_cycles=MONITOR_REQUIRED_CYCLES,
            window_days=MONITOR_BASELINE_WINDOW_DAYS,
        )
        logger.info(
            "[MonitorAI] Analyzer initialized (z=%.1f, cycles=%d, window=%dd)",
            MONITOR_Z_THRESHOLD,
            MONITOR_REQUIRED_CYCLES,
            MONITOR_BASELINE_WINDOW_DAYS,
        )
    return _monitor_analyzer


def _get_alert_dispatcher() -> Optional["AlertDispatcher"]:
    global _alert_dispatcher
    if _alert_dispatcher is None and MONITOR_AI_ENABLED:
        from services.alert_dispatcher import AlertDispatcher

        _alert_dispatcher = AlertDispatcher(
            cooldown_seconds=MONITOR_ALERT_COOLDOWN_SECONDS,
            rate_limit_window=600.0,
            max_alerts_per_window=MONITOR_MAX_ALERTS_PER_WINDOW,
        )
        logger.info(
            "[MonitorAI] Dispatcher initialized (cooldown=%ds, max=%d/10min)",
            MONITOR_ALERT_COOLDOWN_SECONDS,
            MONITOR_MAX_ALERTS_PER_WINDOW,
        )
    return _alert_dispatcher
