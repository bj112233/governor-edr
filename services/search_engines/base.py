"""Abstract base class for search engines — Strategy pattern + Circuit Breaker.

Every engine implements _do_search() and returns a uniform list of SearchResult.
The orchestrator (osint_search.py) tries engines in priority order and
falls through on failure (timeout, captcha, HTTP error).

Circuit Breaker: on consecutive failures, the engine "trips" and stays
open for a cooldown period (default 10 min). This prevents hammering a
blocked endpoint every hunt cycle (6h interval = wasted requests + IP ban risk).
"""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_CIRCUIT_COOLDOWN_S = 600  # 10 minutes
_CIRCUIT_FAILURE_THRESHOLD = 3  # trip after 3 consecutive failures


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str = ""
    engine: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, str]:
        d: dict[str, str] = {"title": self.title, "url": self.url, "snippet": self.snippet, "engine": self.engine}
        d.update(self.extra)
        return d


class BaseSearchEngine(abc.ABC):
    """Abstract search engine with circuit breaker. Subclasses implement _do_search()."""

    name: str = "base"
    timeout: int = 12

    def __init__(self) -> None:
        self._circuit_open_until: float = 0.0
        self._consecutive_failures: int = 0

    @abc.abstractmethod
    async def _do_search(self, query: str, page: int) -> list[SearchResult]:
        """Perform a single-page search. Return [] on any failure."""
        ...

    def _is_circuit_open(self) -> bool:
        """Check if circuit breaker is tripped (engine in cooldown)."""
        if self._circuit_open_until and time.time() < self._circuit_open_until:
            return True
        if self._circuit_open_until and time.time() >= self._circuit_open_until:
            # Cooldown expired — reset and allow retry
            logger.info("[SearchEngine:%s] circuit breaker cooldown expired — retrying", self.name)
            self._circuit_open_until = 0.0
            self._consecutive_failures = 0
        return False

    def _trip_circuit(self) -> None:
        """Trip the circuit breaker — engine enters cooldown."""
        self._circuit_open_until = time.time() + _CIRCUIT_COOLDOWN_S
        logger.warning(
            "[SearchEngine:%s] circuit tripped — cooldown %ds (failures=%d)",
            self.name,
            _CIRCUIT_COOLDOWN_S,
            self._consecutive_failures,
        )

    def _record_success(self) -> None:
        self._consecutive_failures = 0

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= _CIRCUIT_FAILURE_THRESHOLD:
            self._trip_circuit()

    async def search(self, query: str, max_pages: int = 1) -> list[SearchResult]:
        """Search up to max_pages pages. Logs failures, never raises.

        If circuit breaker is open, returns [] immediately (skips network).
        """
        if self._is_circuit_open():
            logger.debug("[SearchEngine:%s] circuit open — skipping", self.name)
            return []

        if max_pages <= 1:
            results = await self._safe_page(query, 0)
        else:
            tasks = [self._safe_page(query, p) for p in range(max_pages)]
            pages_results = await asyncio.gather(*tasks)
            results = [r for page in pages_results for r in page]

        if results:
            self._record_success()
            logger.info("[SearchEngine:%s] %d results for '%s'", self.name, len(results), query[:60])
        else:
            self._record_failure()
        return results

    async def _safe_page(self, query: str, page: int) -> list[SearchResult]:
        """Wrap a single page with timeout + error handling."""
        try:
            results = await asyncio.wait_for(self._do_search(query, page), timeout=self.timeout)
            return results
        except TimeoutError:
            logger.warning("[SearchEngine:%s] page %d timed out (>%ds)", self.name, page, self.timeout)
        except Exception as exc:
            logger.warning("[SearchEngine:%s] page %d failed: %s", self.name, page, exc)
        return []
