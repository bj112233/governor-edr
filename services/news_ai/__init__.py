# services/news_ai/__init__.py
"""News AI package — backward compatible re-exports."""

from .batch import bulk_enrich
from .clusters import bulk_summarize_clusters
from .prompts import _is_title_echo
from .reports import consolidate_to_report

__all__ = [
    "bulk_enrich",
    "bulk_summarize_clusters",
    "consolidate_to_report",
    "_is_title_echo",
]
