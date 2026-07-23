"""Search engine strategy package — pluggable engines behind a uniform interface."""

from services.search_engines.base import BaseSearchEngine, SearchResult
from services.search_engines.ddg import DuckDuckGoEngine
from services.search_engines.startpage import StartpageEngine

__all__ = ["BaseSearchEngine", "SearchResult", "DuckDuckGoEngine", "StartpageEngine"]
