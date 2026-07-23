# services/telemetry.py
"""
Self-observability telemetry for the single-user tactical bot.

Records LLM latency, tool execution time, and process resource usage
to an append-only JSONL file. Designed for a single-process, single-user
deployment - no per-user aggregation, no auth, no retention enforcement.

Overhead: ~10us per recorded event (perf_counter + json.dumps + write
offloaded to a worker thread to keep the asyncio loop unblocked).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import psutil

logger = logging.getLogger(__name__)


from services.telemetry_utils import _classify_llm_error, _percentile  # noqa: E402,F401

_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "memory" / "telemetry.jsonl"
_SAMPLE_WINDOW = 200  # rolling window for in-memory percentile calc
_MAX_BYTES = int(os.getenv("TELEMETRY_MAX_BYTES", str(5 * 1024 * 1024)))  # 5 MB
_BACKUP_SUFFIX = ".1"  # single rotated backup -> total disk <= 2 * _MAX_BYTES


class Telemetry:
    """Append-only JSONL telemetry - single-user, single-process."""

    _instance: Telemetry | None = None
    _instance_lock: threading.Lock = threading.Lock()

    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._proc = psutil.Process(os.getpid())
        # Prime CPU baseline (first call always returns 0.0)
        try:
            self._proc.cpu_percent(interval=None)
        except Exception:
            pass
        self._started = time.time()
        self._write_lock = asyncio.Lock()
        # Rolling latency samples (seconds)
        self._llm_samples: deque[float] = deque(maxlen=_SAMPLE_WINDOW)
        self._tool_samples: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=_SAMPLE_WINDOW))
        # Token throughput samples (tokens/sec) for TPOT
        self._tpot_samples: deque[float] = deque(maxlen=_SAMPLE_WINDOW)
        # Context size samples (prompt_tokens) for saturation
        self._ctx_samples: deque[int] = deque(maxlen=_SAMPLE_WINDOW)
        # Event loop lag samples (ms)
        self._loop_lag_samples: deque[float] = deque(maxlen=_SAMPLE_WINDOW)
        self._loop_lag_t0: float | None = None
        # Lifetime counters
        self._llm_calls = 0
        self._llm_errors = 0
        # Per-class error breakdown: {connection, timeout, http_5xx, rate_limit,
        # context_overflow, bad_request, http_4xx, other}. Sum equals _llm_errors.
        self._llm_errors_by_class: dict[str, int] = defaultdict(int)
        self._tool_calls = 0
        self._tool_errors = 0
        logger.info(f"[Telemetry] Initialized -> {self._path}")

    @classmethod
    def get_instance(cls) -> Telemetry:
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    async def _write(self, record: dict) -> None:
        """Append one JSON line. Safe under asyncio (lock + thread offload)."""
        try:
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        except Exception as exc:
            logger.warning(f"[Telemetry] serialize failed: {exc}")
            return
        async with self._write_lock:
            await asyncio.to_thread(self._append_line, line)

    def _maybe_rotate(self) -> None:
        """Size-based rotation. Keeps single backup at <path>.1, overwriting it.

        Called BEFORE each append. Total disk footprint <= 2 * _MAX_BYTES.
        Cheap stat() call; rotation itself is rare. Errors are swallowed —
        telemetry must never crash the bot.
        """
        try:
            if self._path.exists() and self._path.stat().st_size >= _MAX_BYTES:
                backup = self._path.with_suffix(self._path.suffix + _BACKUP_SUFFIX)
                if backup.exists():
                    backup.unlink()
                self._path.rename(backup)
                logger.info(
                    "[Telemetry] Rotated %s -> %s (>= %d bytes)",
                    self._path.name,
                    backup.name,
                    _MAX_BYTES,
                )
        except Exception as exc:
            logger.warning(f"[Telemetry] rotation failed: {exc}")

    def _append_line(self, line: str) -> None:
        try:
            self._maybe_rotate()
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as exc:
            # Telemetry must NEVER crash the bot
            logger.warning(f"[Telemetry] write failed: {exc}")

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- LLM ---

    @asynccontextmanager
    async def measure_llm(self, op: str, model: str = "") -> AsyncIterator[dict]:
        """Context manager. Mutate yielded dict to add tokens_in/tokens_out."""
        meta: dict = {"tokens_in": 0, "tokens_out": 0}
        t0 = time.perf_counter()
        ok = True
        err_class: str | None = None
        try:
            yield meta
        except BaseException as exc:
            ok = False
            err_class = _classify_llm_error(exc)
            raise
        finally:
            dt = time.perf_counter() - t0
            self._llm_calls += 1
            if not ok:
                self._llm_errors += 1
                if err_class:
                    self._llm_errors_by_class[err_class] += 1
            self._llm_samples.append(dt)
            # TPOT: tokens per second (only when we produced tokens)
            # Priority 1: Real decode_time from KoboldCpp /api/extra/perf
            # Priority 2: Heuristic — estimate decode proportionally by token ratio
            # Guard against ZeroDivisionError when prompt caching makes dt ≈ 0.
            _tok_out = meta.get("tokens_out", 0)
            _tok_in = meta.get("tokens_in", 0)
            _real_decode = meta.get("decode_time", 0.0)
            _total_tok = _tok_in + _tok_out
            if _tok_out > 0 and dt > 0:
                if _real_decode > 0:
                    # Real decode time from KoboldCpp perf endpoint
                    decode_time = max(_real_decode, 0.001)
                else:
                    # Heuristic fallback: proportional to output token fraction
                    decode_fraction = _tok_out / _total_tok if _total_tok > 0 else 1.0
                    decode_time = max(dt * decode_fraction, 0.001)
                self._tpot_samples.append(_tok_out / decode_time)
            if _tok_in > 0:
                self._ctx_samples.append(_tok_in)
            record = {
                "ts": self._now_iso(),
                "type": "llm",
                "op": op,
                "model": model,
                "latency_ms": round(dt * 1000, 1),
                "tokens_in": _tok_in,
                "tokens_out": _tok_out,
                "tpot_ms": round(dt * 1000 / _tok_out, 1) if _tok_out > 0 else 0,
                "ok": ok,
            }
            if err_class:
                record["err_class"] = err_class
            await self._write(record)

    # --- Tools ---

    @asynccontextmanager
    async def measure_tool(self, name: str) -> AsyncIterator[None]:
        t0 = time.perf_counter()
        ok = True
        try:
            yield
        except Exception:
            ok = False
            raise
        finally:
            dt = time.perf_counter() - t0
            self._tool_calls += 1
            if not ok:
                self._tool_errors += 1
            self._tool_samples[name].append(dt)
            await self._write(
                {
                    "ts": self._now_iso(),
                    "type": "tool",
                    "name": name,
                    "latency_ms": round(dt * 1000, 1),
                    "ok": ok,
                }
            )

    # --- Process snapshot ---

    def proc_snapshot(self) -> dict:
        """Cheap in-memory snapshot. Does NOT write to disk."""
        try:
            rss_mb = self._proc.memory_info().rss / (1024 * 1024)
            cpu = self._proc.cpu_percent(interval=None)
        except Exception:
            rss_mb, cpu = 0.0, 0.0
        return {
            "rss_mb": round(rss_mb, 1),
            "cpu_pct": round(cpu, 1),
            "uptime_s": int(time.time() - self._started),
        }

    async def record_proc(self) -> None:
        """Persist current process metrics to JSONL (called periodically)."""
        snap = self.proc_snapshot()
        await self._write({"ts": self._now_iso(), "type": "proc", **snap})

    async def proc_loop(self, interval_s: int = 60) -> None:
        """Background task - record proc metrics every `interval_s` seconds.

        Also measures event loop lag: schedules a sleep(0) callback and
        measures how long it actually takes to fire. If the loop is blocked
        by sync I/O, the callback fires late → high lag.
        """
        logger.info(f"[Telemetry] proc_loop started (interval={interval_s}s)")
        while True:
            try:
                await self._measure_loop_lag()
                await self.record_proc()
            except Exception as exc:
                logger.warning(f"[Telemetry] proc_loop tick failed: {exc}")
            await asyncio.sleep(interval_s)

    async def _measure_loop_lag(self) -> None:
        """Measure event loop lag by scheduling a minimal callback."""
        loop = asyncio.get_running_loop()
        scheduled_at = time.perf_counter()

        fut = loop.create_future()

        def _fire() -> None:
            if not fut.done():
                fut.set_result(None)

        loop.call_soon(_fire)
        await fut
        lag_ms = (time.perf_counter() - scheduled_at) * 1000
        self._loop_lag_samples.append(lag_ms)

    # --- Stats for /stats command ---

    def snapshot(self) -> dict:
        """Aggregate snapshot for /stats command (no disk I/O)."""
        llm = list(self._llm_samples)
        tpot = list(self._tpot_samples)
        ctx = list(self._ctx_samples)
        lag = list(self._loop_lag_samples)
        tools_pct: dict[str, dict] = {}
        for name, samples in self._tool_samples.items():
            vals = list(samples)
            if not vals:
                continue
            tools_pct[name] = {
                "n": len(vals),
                "p50_ms": round(_percentile(vals, 50) * 1000, 0),
                "p95_ms": round(_percentile(vals, 95) * 1000, 0),
            }
        # Context window from config (lazy import to avoid circular)
        try:
            from config import LLM_CONTEXT_WINDOW

            ctx_max = LLM_CONTEXT_WINDOW
        except Exception:
            ctx_max = 16384
        return {
            "proc": self.proc_snapshot(),
            "llm": {
                "calls": self._llm_calls,
                "errors": self._llm_errors,
                "errors_by_class": dict(self._llm_errors_by_class),
                "window_n": len(llm),
                "p50_ms": round(_percentile(llm, 50) * 1000, 0),
                "p95_ms": round(_percentile(llm, 95) * 1000, 0),
                "avg_ms": round((sum(llm) / len(llm)) * 1000, 0) if llm else 0,
                # TPOT: tokens per second + ms per token (1000/tps)
                "tpot_tps": round(sum(tpot) / len(tpot), 1) if tpot else 0,
                "tpot_p50_ms": round(1000 / _percentile(tpot, 50), 1) if tpot else 0,
                # Context saturation: avg prompt tokens / context window
                "ctx_avg": round(sum(ctx) / len(ctx)) if ctx else 0,
                "ctx_max": ctx_max,
                "ctx_sat_pct": round((sum(ctx) / len(ctx)) / ctx_max * 100, 1) if ctx else 0,
            },
            "tools": {
                "calls": self._tool_calls,
                "errors": self._tool_errors,
                "per_tool": tools_pct,
            },
            "loop_lag_ms": round(_percentile(lag, 50), 1) if lag else 0,
            "loop_lag_p95_ms": round(_percentile(lag, 95), 1) if lag else 0,
        }


def get_telemetry() -> Telemetry:
    return Telemetry.get_instance()
