# services/llm_bridge/bridge.py
"""LLMBridge facade — singleton holding HTTP clients + circuit breaker state."""

import asyncio
import logging
import threading
from typing import Any

import httpx
import openai

from config import (
    LLM_API_BASE,
    LLM_API_KEY,
    LLM_MODEL,
    LLM_TIMEOUT,
)

from .circuit_breaker import CircuitBreaker
from .completion import agent_step, complete
from .embeddings import embed
from .health import health_loop
from .models import _STATE_CLOSED, ContextOverflowError

logger = logging.getLogger(__name__)

llm_semaphore = asyncio.Semaphore(1)

_custom_http_client = httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=2, max_connections=5))


class LLMBridge:
    """Singleton async bridge to the local LLM."""

    _instance: "LLMBridge | None" = None
    _instance_lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._client = openai.AsyncOpenAI(
            base_url=LLM_API_BASE,
            api_key=LLM_API_KEY,
            timeout=float(LLM_TIMEOUT),
            http_client=_custom_http_client,
        )
        self._probe_client = openai.AsyncOpenAI(
            base_url=LLM_API_BASE,
            api_key=LLM_API_KEY,
            timeout=3.0,
            http_client=_custom_http_client,
        )
        self.model = LLM_MODEL
        self._ready_event: asyncio.Event = asyncio.Event()
        self.cb = CircuitBreaker("main")
        self.embed_cb = CircuitBreaker("embed")
        logger.info("[Bridge] Initialized -> %s | model=%s", LLM_API_BASE, LLM_MODEL)

    @classmethod
    def get_instance(cls) -> "LLMBridge":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    async def aclose(self) -> None:
        if self._client:
            _http = getattr(self._client, "http_client", None)
            if _http:
                await _http.aclose()
        if self._probe_client:
            _http = getattr(self._probe_client, "http_client", None)
            if _http:
                await _http.aclose()

    def is_ready(self) -> bool:
        return self._ready_event.is_set()

    def should_accept_traffic(self) -> bool:
        return self.cb.should_accept()

    def is_degraded(self) -> bool:
        """True if circuit is in DEGRADED state (TPOT too high)."""
        from .models import _STATE_DEGRADED

        return self.cb.state == _STATE_DEGRADED

    def reset_baseline(self) -> None:
        self.cb.reset_baseline()

    # --- Public API delegates to stateless workers ---

    async def complete(
        self,
        system_prompt: str,
        user_input: str,
        temperature: float = 0.1,
        max_tokens: int = 2000,
        timeout: float | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        if not self.should_accept_traffic():
            raise openai.APIConnectionError(
                message="[Bridge] Circuit open — LLM endpoint unavailable.",
                request=httpx.Request("POST", LLM_API_BASE),
            )
        return await complete(
            client=self._client,
            model=self.model,
            system_prompt=system_prompt,
            user_input=user_input,
            cb=self.cb,
            semaphore=llm_semaphore,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            response_format=response_format,
        )

    async def agent_step(
        self,
        messages: list,
        max_tokens: int | None = None,
        json_schema: bool = True,
    ) -> openai.types.chat.ChatCompletionMessage:
        if not self.should_accept_traffic():
            raise openai.APIConnectionError(
                message="[Bridge] Circuit open — LLM endpoint unavailable.",
                request=httpx.Request("POST", LLM_API_BASE),
            )
        return await agent_step(
            client=self._client,
            model=self.model,
            messages=messages,
            cb=self.cb,
            semaphore=llm_semaphore,
            max_tokens=max_tokens,
            json_schema=json_schema,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return await embed(
            client=self._client,
            texts=texts,
            embed_cb=self.embed_cb,
            semaphore=llm_semaphore,
        )

    async def health_loop(self) -> None:
        """Background health monitor — run once at startup via main.py."""
        await health_loop(
            probe_client=self._probe_client,
            model=self.model,
            cb=self.cb,
            semaphore=llm_semaphore,
            ready_event=self._ready_event,
        )


def is_llm_ready() -> bool:
    bridge = LLMBridge.get_instance()
    return bridge.is_ready() or bridge.should_accept_traffic()


async def probe_llm_until_ready() -> None:
    """Background Task — delegates to health_loop()."""
    await LLMBridge.get_instance().health_loop()
