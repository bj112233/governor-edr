# services/llm_bridge/completion.py
"""Chat completion + agent_step — stateless workers receiving client + CB."""

import asyncio
import inspect
import logging
import time
from typing import Any

import httpx
import openai

from config import (
    LLM_AGENT_MAX_TOKENS,
    LLM_AGENT_TEMPERATURE,
    LLM_AGENT_TOP_P,
    LLM_API_BASE,
    LLM_MIN_P,
    LLM_PRESENCE_PENALTY,
    LLM_RETRY_ATTEMPTS,
    LLM_TIMEOUT,
    LLM_TOP_K,
    LLM_TOP_P,
)
from services.telemetry import get_telemetry

from .models import ContextOverflowError, _is_context_overflow

logger = logging.getLogger(__name__)

# KoboldCpp/LM Studio extensions (top_k, min_p, thinking disable).
# Not all openai-compatible SDKs accept extra_body — gate at runtime.
_EXTRA_BODY = {
    "top_k": LLM_TOP_K,
    "min_p": LLM_MIN_P,
    "chat_template_kwargs": {"enable_thinking": False},
}

# KoboldCpp perf endpoint: /api/extra/perf (strip /v1 from base URL)
_PERF_URL = LLM_API_BASE.rstrip("/").removesuffix("/v1") + "/api/extra/perf"
_PERF_TIMEOUT = 2.0  # short — don't block on telemetry


async def _fetch_koboldcpp_perf() -> dict[str, float] | None:
    """Fetch timing stats from KoboldCpp /api/extra/perf.

    Returns dict with keys: last_process_time, last_eval_time,
    last_input_count, last_token_count. Returns None on any error
    (non-KoboldCpp backends, network issues, etc).

    Uses the shared httpx client from bridge.py to avoid creating a new
    connection pool on every completion call (connection storm root cause).
    """
    try:
        from .bridge import _custom_http_client

        r = await _custom_http_client.get(_PERF_URL, timeout=_PERF_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            return {
                "prefill_time": float(data.get("last_process_time", 0)),
                "decode_time": float(data.get("last_eval_time", 0)),
                "input_count": int(data.get("last_input_count", 0)),
                "output_count": int(data.get("last_token_count", 0)),
            }
    except Exception:
        pass  # silent — perf endpoint is optional
    return None


def _client_accepts_extra_body(client: openai.AsyncOpenAI) -> bool:
    """True if the bound client.chat.completions.create accepts extra_body."""
    try:
        sig = inspect.signature(client.chat.completions.create)
        return "extra_body" in sig.parameters
    except Exception:
        return False


def _raise_if_circuit_open(cb) -> None:
    """TOCTOU double-check after semaphore acquisition.

    ``bridge.py`` checks ``should_accept()`` before calling ``complete`` /
    ``agent_step``, but ``async with semaphore`` yields the event loop —
    ``force_open()`` can trip the breaker in that window.  Re-check here
    so we never dispatch an HTTP request to an OPEN circuit.
    """
    if not cb.should_accept():
        raise openai.APIConnectionError(
            message="[Bridge] Circuit opened during dispatch (TOCTOU).",
            request=httpx.Request("POST", LLM_API_BASE),
        )


async def complete(
    client: openai.AsyncOpenAI,
    model: str,
    system_prompt: str,
    user_input: str,
    cb,
    semaphore: asyncio.Semaphore,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    timeout: float | None = None,
    response_format: dict[str, Any] | None = None,
) -> str:
    """Chat completion with retry + exponential backoff."""
    _client = client.with_options(timeout=float(timeout)) if timeout is not None else client
    _supports_extra = _client_accepts_extra_body(_client)
    if not _supports_extra:
        logger.debug("[Bridge] Client does not accept extra_body — skipping top_k/min_p.")
    last_exc: Exception = RuntimeError("No attempts made.")
    for attempt in range(1, LLM_RETRY_ATTEMPTS + 1):
        try:
            async with semaphore:
                _raise_if_circuit_open(cb)
                create_kwargs: dict[str, Any] = dict(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_input},
                    ],
                    temperature=temperature,
                    top_p=LLM_TOP_P,
                    max_tokens=max_tokens,
                    presence_penalty=LLM_PRESENCE_PENALTY,
                )
                if _supports_extra:
                    create_kwargs["extra_body"] = _EXTRA_BODY
                if response_format is not None:
                    create_kwargs["response_format"] = response_format
                _t0 = time.monotonic()
                async with get_telemetry().measure_llm("complete", model) as _tm:
                    response = await _client.chat.completions.create(**create_kwargs)
                    _usage = getattr(response, "usage", None)
                    _completion_tokens = 0
                    if _usage:
                        _tm["tokens_in"] = getattr(_usage, "prompt_tokens", 0) or 0
                        _completion_tokens = getattr(_usage, "completion_tokens", 0) or 0
                        _tm["tokens_out"] = _completion_tokens
                    # Fetch real timing from KoboldCpp /api/extra/perf
                    _perf = await _fetch_koboldcpp_perf()
                    _decode_time: float | None = None
                    if _perf and _perf["decode_time"] > 0:
                        _tm["decode_time"] = _perf["decode_time"]
                        _tm["prefill_time"] = _perf["prefill_time"]
                        _decode_time = _perf["decode_time"]
                cb.record_latency(time.monotonic() - _t0, _completion_tokens, decode_time=_decode_time)
                content = response.choices[0].message.content or ""
            cb.on_success()
            logger.debug("[Bridge] complete() -> %d chars", len(content))
            return content
        except openai.BadRequestError as exc:
            if _is_context_overflow(exc):
                logger.warning("[Bridge] complete() context_length_exceeded: %s", exc)
                raise ContextOverflowError(str(exc)) from exc
            logger.error("[Bridge] complete() bad request: %s", exc)
            raise
        except (
            TimeoutError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.APIStatusError,
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.TimeoutException,
            httpx.RemoteProtocolError,
        ) as exc:
            last_exc = exc
            cb.on_failure()
            backoff = 2**attempt
            logger.warning(
                "[Bridge] complete() attempt %d/%d failed: %s. Backoff %ds.",
                attempt,
                LLM_RETRY_ATTEMPTS,
                exc,
                backoff,
            )
            if attempt < LLM_RETRY_ATTEMPTS:
                await asyncio.sleep(backoff)
    raise last_exc


async def agent_step(
    client: openai.AsyncOpenAI,
    model: str,
    messages: list,
    cb,
    semaphore: asyncio.Semaphore,
    max_tokens: int | None = None,
    json_schema: bool = True,
    timeout: float | None = None,
) -> openai.types.chat.ChatCompletionMessage:
    """Single agentic step (tool-calling) with retry + exponential backoff."""
    # NOTE: with_options(timeout=...) returns a shallow copy that still shares
    # the underlying httpx transport. Per-call timeout override is best-effort.
    _client = client.with_options(timeout=float(timeout)) if timeout is not None else client
    last_exc: Exception = RuntimeError("No attempts made.")
    for attempt in range(1, LLM_RETRY_ATTEMPTS + 1):
        try:
            async with semaphore:
                _raise_if_circuit_open(cb)
                create_kwargs = dict(
                    model=model,
                    messages=messages,
                    temperature=LLM_AGENT_TEMPERATURE,
                    top_p=LLM_AGENT_TOP_P,
                    max_tokens=max_tokens or LLM_AGENT_MAX_TOKENS,
                    presence_penalty=LLM_PRESENCE_PENALTY,
                    extra_body={
                        "top_k": LLM_TOP_K,
                        "min_p": LLM_MIN_P,
                        "chat_template_kwargs": {"enable_thinking": False},
                    },
                )
                # NOTE: JSON-schema enforcement removed for 4B model reliability.
                # KoboldCpp wraps plain-text in JSON array when response_format is set.
                # ReAct output is now parsed as free-text with regex (see _react_parser.py).
                _t0 = time.monotonic()
                async with get_telemetry().measure_llm("agent_step", model) as _tm:
                    response = await _client.chat.completions.create(**create_kwargs)  # type: ignore[call-overload]
                    _usage = getattr(response, "usage", None)
                    _completion_tokens = 0
                    if _usage:
                        _tm["tokens_in"] = getattr(_usage, "prompt_tokens", 0) or 0
                        _completion_tokens = getattr(_usage, "completion_tokens", 0) or 0
                        _tm["tokens_out"] = _completion_tokens
                    # Fetch real timing from KoboldCpp /api/extra/perf
                    _perf = await _fetch_koboldcpp_perf()
                    _decode_time: float | None = None
                    if _perf and _perf["decode_time"] > 0:
                        _tm["decode_time"] = _perf["decode_time"]
                        _tm["prefill_time"] = _perf["prefill_time"]
                        _decode_time = _perf["decode_time"]
                cb.record_latency(time.monotonic() - _t0, _completion_tokens, decode_time=_decode_time)
                msg = response.choices[0].message
            cb.on_success()
            logger.debug("[Bridge] agent_step() -> tool_calls=%d", len(msg.tool_calls or []))
            return msg
        except openai.BadRequestError as exc:
            if _is_context_overflow(exc):
                logger.warning("[Bridge] agent_step() context_length_exceeded: %s", exc)
                raise ContextOverflowError(str(exc)) from exc
            logger.error("[Bridge] agent_step() bad request: %s", exc)
            raise
        except (
            TimeoutError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.APIStatusError,
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.TimeoutException,
            httpx.RemoteProtocolError,
        ) as exc:
            last_exc = exc
            cb.on_failure()
            backoff = 2**attempt
            logger.warning(
                "[Bridge] agent_step() attempt %d/%d failed: %s. Backoff %ds.",
                attempt,
                LLM_RETRY_ATTEMPTS,
                exc,
                backoff,
            )
            if attempt < LLM_RETRY_ATTEMPTS:
                await asyncio.sleep(backoff)
    raise last_exc
