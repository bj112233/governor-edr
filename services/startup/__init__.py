"""Sentinel startup package — boot orchestration modules.

Public re-exports for backward compatibility.
"""

from ._broadcast import _telegram_event_broadcaster
from ._health import await_all_services
from ._monitor_ai import _get_alert_dispatcher, _get_monitor_analyzer
from ._net_baseline import _collect_net_baseline_rows
from ._reporting import build_daily_report, send_daily_digest
from ._scan_lan import _scan_lan_background
from ._scheduler import setup_scheduler
from ._signal import _cancel_gracefully, _setup_signal_handlers, get_shutdown_event
from ._workers import llm_analysis_worker, monitor_loop

__all__ = [
    "await_all_services",
    "build_daily_report",
    "get_shutdown_event",
    "llm_analysis_worker",
    "monitor_loop",
    "send_daily_digest",
    "setup_scheduler",
    "_cancel_gracefully",
    "_collect_net_baseline_rows",
    "_get_alert_dispatcher",
    "_get_monitor_analyzer",
    "_rule_based_analysis",
    "_scan_lan_background",
    "_setup_signal_handlers",
    "_telegram_event_broadcaster",
]
