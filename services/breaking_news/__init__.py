# services/breaking_news/__init__.py
"""Breaking News package — backward compatible re-exports."""

from .monitor import (
    BreakingNewsMonitor,
    get_monitor,
    start_monitor,
    stop_monitor,
)

# Backward compat aliases (old names used by main.py and others)
get_breaking_news_monitor = get_monitor
start_breaking_news_monitor = start_monitor
stop_breaking_news_monitor = stop_monitor

__all__ = [
    "BreakingNewsMonitor",
    "get_breaking_news_monitor",
    "start_breaking_news_monitor",
    "stop_breaking_news_monitor",
]
