"""Proactive threat hunting orchestrator — Agentic AI daemon.

Wakes every 6h (via APScheduler), runs pre-flight checks, gathers truncated
context, invokes the agent with a hunting prompt, extracts a threat score,
and dispatches to Telegram ONLY if the score exceeds threshold.

Adversarial constraints enforced:
  - Context window blowout: aggressive truncation (≤5 alerts, ≤500 chars memory)
  - Alert fatigue: dispatch only if threat_score > THREAT_HUNT_DISPATCH_THRESHOLD
  - Resource contention: ResourceGuard + LLM-ready + mutex + cooldown pre-flight

State Machine (for C2 dashboard observability):
  IDLE → SCANNING → ANALYZING → IDLE (with last_score)
  IDLE → COOLDOWN → IDLE (preflight rejected)
  IDLE → SKIPPED → IDLE (resource guard / LLM not ready / mutex busy)
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any

from config import (
    THREAT_HUNT_COOLDOWN_HOURS,
    THREAT_HUNT_DISPATCH_THRESHOLD,
    THREAT_HUNT_INTERVAL_HOURS,
    THREAT_HUNT_MAX_ALERTS,
    THREAT_HUNT_MAX_MEMORY_CHARS,
)
from services.agent._agent_loop import run_agent
from services.agent.resource_guard import ResourceGuard
from services.alert_history import get_recent_alerts
from services.alert_history_query import get_alerts_last_24h
from services.bot_memory.highlevel import recall_context
from services.hunt_prompt import build_hunt_prompt as _build_hunt_prompt
from services.hunt_prompt import extract_threat_score as _extract_threat_score
from services.llm_bridge.bridge import is_llm_ready
from services.memory_db import get_last_hunt, store_threat_hunt
from services.mitre_mapper import serialize_mitre
from services.monitor_engine import get_system_snapshot
from services.net_noise_filter import apply_snapshot_noise_filter
from services.pre_hunt_enricher import (
    PreHuntReport,
    any_ioc_malicious,
    enrich_iocs_from_context,
    format_hard_facts,
)
from services.sentinel_events import send_threat_hunt_event
from services.threat_score_cap import (
    _SCORE_CAP_BASE,
    _SCORE_CAP_NO_EVIDENCE,
    HALLUCINATION_FLAG,
)
from services.threat_score_cap import (
    clamp_llm_score as _clamp_llm_score,
)
from services.threat_score_cap import (
    flag_hallucination as _flag_hallucination,
)

logger = logging.getLogger(__name__)

__all__ = ["threat_hunt_job", "HuntResult", "get_hunt_status"]

_HUNT_MUTEX = asyncio.Lock()
_RESOURCE_GUARD = ResourceGuard()
_LAST_HUNT_TS: float = 0.0
_FORCE_HUNT: bool = False
_HUNT_QUERY = "threat hunt suspicious anomalies network connections security"

# ── Scoring constants ──────────────────────────────────────────────────────
_IOC_BONUS = 0.3  # bumps 0.4 → 0.7, crossing the 0.6 dispatch threshold
_SCORE_CLEAN_IOC_CLAMP = 0.4  # all IOCs clean per intel → floor (below 0.6 dispatch)
_NO_EXTERNAL_IOC_CLAMP = 0.4  # no external IOCs at all → floor (prevents hallucination on LAN traffic)
_AGENT_TIMEOUT_S = 420  # 7 min — DAG with 5 subtasks + synthesis needs ~300s, add 40% buffer


# ── Hunt Status (observability for C2 dashboard) ──────────────────────────
# Single-event-loop: dict assignment is atomic. get_hunt_status() does a
# non-blocking copy — never acquires _HUNT_MUTEX (would block the dashboard).


@dataclass
class _HuntStatus:
    """Mutable hunt state — read by get_hunt_status() for the C2 dashboard."""

    state: str = "IDLE"  # IDLE | SCANNING | ANALYZING | COOLDOWN | SKIPPED
    last_run_ts: float = 0.0
    last_score: float = 0.0
    last_dispatched: bool = False
    last_skip_reason: str = ""
    # Earliest next run = last_run_ts + cooldown. Scheduler tick = INTERVAL.
    next_run_eta: float = 0.0
    hunt_count: int = 0  # total hunts completed this session


_HUNT_STATUS = _HuntStatus()


def is_hunt_active() -> bool:
    """True if a threat hunt is currently running (SCANNING or ANALYZING).

    Used by the load-muting system to suppress cpu_spike/ram_spike alerts
    that are caused by the LLM inference engine (KoboldCpp) during hunts.
    """
    return _HUNT_STATUS.state in ("SCANNING", "ANALYZING")


def _set_hunt_state(state: str, **kwargs: Any) -> None:
    """Update hunt status fields atomically (single event loop)."""
    _HUNT_STATUS.state = state
    for key, val in kwargs.items():
        if hasattr(_HUNT_STATUS, key):
            setattr(_HUNT_STATUS, key, val)


def get_hunt_status() -> dict[str, Any]:
    """Non-blocking snapshot of current hunt state for the C2 dashboard.

    Never acquires _HUNT_MUTEX — returns a copy of the status dataclass.
    Safe to call from any coroutine (dashboard poll, MCP, etc).
    """
    now = time.time()
    cooldown_s = THREAT_HUNT_COOLDOWN_HOURS * 3600
    interval_s = THREAT_HUNT_INTERVAL_HOURS * 3600
    # If IDLE and past cooldown, next run is the next scheduler tick.
    # We don't know the exact scheduler tick, so estimate from last_run.
    if _HUNT_STATUS.last_run_ts > 0:
        earliest = _HUNT_STATUS.last_run_ts + cooldown_s
        # Scheduler runs every INTERVAL; next tick after earliest
        ticks_since_last = int((now - _HUNT_STATUS.last_run_ts) // interval_s)
        next_tick = _HUNT_STATUS.last_run_ts + (ticks_since_last + 1) * interval_s
        next_run = max(earliest, next_tick)
    else:
        next_run = 0.0  # never run — awaiting first scheduler tick
    return {
        "state": _HUNT_STATUS.state,
        "last_run_ts": _HUNT_STATUS.last_run_ts,
        "last_run_iso": (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(_HUNT_STATUS.last_run_ts))
            if _HUNT_STATUS.last_run_ts > 0
            else ""
        ),
        "last_score": round(_HUNT_STATUS.last_score, 2),
        "last_dispatched": _HUNT_STATUS.last_dispatched,
        "last_skip_reason": _HUNT_STATUS.last_skip_reason,
        "next_run_eta": next_run,
        "next_run_iso": (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_run)) if next_run > 0 else ""),
        "seconds_until_next": max(0, int(next_run - now)) if next_run > 0 else -1,
        "hunt_count": _HUNT_STATUS.hunt_count,
        "cooldown_hours": THREAT_HUNT_COOLDOWN_HOURS,
        "interval_hours": THREAT_HUNT_INTERVAL_HOURS,
    }


@dataclass(frozen=True)
class HuntResult:
    """Outcome of a single hunt cycle."""

    threat_score: float
    summary: str
    dispatched: bool
    skipped: str | None = None  # reason if hunt was skipped


async def threat_hunt_job() -> None:
    """Scheduler entry point — runs pre-flight, hunt, dispatch, store."""
    result = await _run_hunt()
    if result.skipped:
        logger.info("[ThreatHunter] Skipped: %s", result.skipped)
    elif result.dispatched:
        logger.warning("[ThreatHunter] Threat detected (score=%.2f) — dispatched.", result.threat_score)
    else:
        logger.info("[ThreatHunter] Hunt complete (score=%.2f) — no dispatch.", result.threat_score)


async def _run_hunt() -> HuntResult:
    global _FORCE_HUNT
    skip = _preflight() if not _FORCE_HUNT else None
    if skip:
        # Skips are transient (milliseconds) — record reason, stay IDLE.
        # SCANNING/ANALYZING are the only long-lived states the dashboard catches.
        _set_hunt_state("IDLE", last_skip_reason=skip)
        return HuntResult(0.0, "", False, skipped=skip)
    if _HUNT_MUTEX.locked():
        _set_hunt_state("IDLE", last_skip_reason="agent busy (mutex)")
        return HuntResult(0.0, "", False, skipped="agent busy (mutex)")
    async with _HUNT_MUTEX:
        force = _FORCE_HUNT
        _FORCE_HUNT = False  # reset after consumption
        return await _execute_hunt(force=force)


def _preflight() -> str | None:
    """Return skip reason if any pre-flight check fails, else None."""
    global _LAST_HUNT_TS
    permitted, reason = _RESOURCE_GUARD.check()
    if not permitted:
        return f"resource guard: {reason}"
    if not is_llm_ready():
        return "LLM not ready"
    cooldown_s = THREAT_HUNT_COOLDOWN_HOURS * 3600
    if (time.time() - _LAST_HUNT_TS) < cooldown_s:
        return "cooldown"
    return None


async def _finalize_hunt(
    prompt_hash: str,
    score: float,
    answer: str,
    dispatched: bool,
    snapshot: dict[str, Any],
    pre_hunt: PreHuntReport,
) -> HuntResult:
    """Dispatch event, store result, update hunt state, return HuntResult.

    Shared exit path for all scoring routes (TTP override, escape hatch, IOC bonus,
    no-IOC clamp). Ensures state-machine consistency — every hunt ends in IDLE
    with last_score/last_dispatched/hunt_count updated.
    """
    global _LAST_HUNT_TS
    if dispatched:
        await send_threat_hunt_event(snapshot, answer, score, serialize_mitre(pre_hunt.mitre_matches))
    await store_threat_hunt(prompt_hash, score, answer, dispatched)
    _LAST_HUNT_TS = time.time()
    _set_hunt_state(
        "IDLE",
        last_run_ts=_LAST_HUNT_TS,
        last_score=score,
        last_dispatched=dispatched,
        last_skip_reason="",
        hunt_count=_HUNT_STATUS.hunt_count + 1,
    )
    return HuntResult(score, answer, dispatched)


async def _check_dedup(force: bool, prompt_hash: str) -> HuntResult | None:
    """Return HuntResult if this prompt was already processed (dedup), else None."""
    global _LAST_HUNT_TS
    if force:
        return None
    last = await get_last_hunt()
    if last and last.get("prompt_hash") == prompt_hash:
        _LAST_HUNT_TS = time.time()
        _set_hunt_state(
            "IDLE",
            last_run_ts=_LAST_HUNT_TS,
            last_score=0.0,
            last_dispatched=False,
            last_skip_reason="duplicate prompt",
        )
        return HuntResult(0.0, "dedup", False, skipped="duplicate prompt")
    return None


async def _execute_hunt(force: bool = False) -> HuntResult:
    global _LAST_HUNT_TS
    _set_hunt_state("SCANNING", last_skip_reason="")
    snapshot, alerts, memory = await _gather_context()
    # ── Pre-hunt deterministic enrichment (strips LLM's choice to investigate) ──
    pre_hunt = await enrich_iocs_from_context(snapshot, alerts)
    hard_facts = format_hard_facts(pre_hunt)
    prompt = _build_hunt_prompt(snapshot, alerts, memory, hard_facts)
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
    dedup = await _check_dedup(force, prompt_hash)
    if dedup:
        return dedup
    _set_hunt_state("ANALYZING")
    try:
        answer = await asyncio.wait_for(
            run_agent(prompt, max_rounds=6, allow_bypasses=False),
            timeout=_AGENT_TIMEOUT_S,
        )
    except TimeoutError:
        logger.error("[ThreatHunter] Agent timed out after %ds — aborting hunt.", _AGENT_TIMEOUT_S)
        _LAST_HUNT_TS = time.time()
        _set_hunt_state(
            "IDLE",
            last_run_ts=_LAST_HUNT_TS,
            last_score=0.0,
            last_dispatched=False,
            last_skip_reason="agent timeout",
        )
        return HuntResult(0.0, "⏱️ פג זמן החקירה — הסוכן לא הגיב בזמן המוקצב.", False, skipped="agent timeout")

    # ── Agent error guard: error messages are NOT threat reports ───────────
    # The agent loop may return error strings (e.g. "🚨 Agent error: Connection
    # Error: ...") instead of raising. These must NOT enter the scoring pipeline
    # — they would be scored as threat reports and dispatched with score=1.0.
    if answer.startswith("🚨 Agent error:") or answer.startswith("❌"):
        logger.error(
            "[ThreatHunter] Agent returned error (not a report) — score=0.0, no dispatch. Error: %s", answer[:200]
        )
        _LAST_HUNT_TS = time.time()
        _set_hunt_state(
            "IDLE",
            last_run_ts=_LAST_HUNT_TS,
            last_score=0.0,
            last_dispatched=False,
            last_skip_reason="agent error",
        )
        return HuntResult(0.0, answer, False, skipped="agent error")

    llm_score = _clamp_llm_score(_extract_threat_score(answer), answer, iocs_enriched=len(pre_hunt.enriched))
    answer = _flag_hallucination(answer, llm_score, pre_hunt.has_any_ioc)

    # ── Global TTP Override (v3.3): local TTP is ground truth ──────────────
    # Physical law: "A clean/absent network signature does NOT cancel a
    # malicious behavioral signature." has_local_ttp runs cmdline_analyzer on
    # suspicious processes. A MITRE TTP match (e.g. T1059.001 encoded command)
    # overrides ALL IOC paths — no-IOC, mixed-IOC, and clean-IOC alike.
    #
    # GUARD (v3.3.1): TTP override must NOT bypass the hallucination firewall.
    # If llm_score == 0.0 (firewall triggered: fabricated IOCs), the override
    # is skipped — a hallucinated report cannot be elevated to score=1.0 even
    # if a suspicious process happens to match a TTP pattern.
    from services.behavioral_escape_hatch import has_local_ttp

    if llm_score > 0.0 and has_local_ttp(snapshot):
        logger.critical(
            "[ThreatHunter] Global TTP Override: MITRE TTP match — clamp lifted to 1.0 "
            "(local TTP is ground truth, overrides network IOCs). LLM=%.2f → 1.0",
            llm_score,
        )
        return await _finalize_hunt(prompt_hash, 1.0, answer, True, snapshot, pre_hunt)

    # ── Scoring v3.1: IOC bonus only if intel confirms malicious (IP/domain/hash) ──
    return await _compute_ioc_score(prompt_hash, llm_score, answer, snapshot, alerts, pre_hunt)


async def _compute_ioc_score(
    prompt_hash: str,
    llm_score: float,
    answer: str,
    snapshot: dict[str, Any],
    alerts: list[tuple],
    pre_hunt: PreHuntReport,
) -> HuntResult:
    """Apply IOC-based scoring: bonus for malicious, clamp for clean/absent.

    Pre-hunt enrichment already queried AbuseIPDB/VT/Maltiverse. If ALL IOCs are
    clean, the LLM's "beaconing" claim is hallucination → clamp to 0.4 (below
    dispatch). If at least one IOC is confirmed malicious → +0.3 bonus.
    """
    if pre_hunt.has_any_ioc:
        if any_ioc_malicious(pre_hunt):
            bonus = _IOC_BONUS
            logger.warning(
                "[ThreatHunter] Intel-confirmed malicious IOC(s) — +%.1f bonus. LLM=%.2f → final=%.2f",
                bonus,
                llm_score,
                min(llm_score + bonus, 1.0),
            )
        elif pre_hunt.all_clean:
            # ── Behavioral Escape Hatch (v3.2) ──────────────────────────────
            from services.behavioral_escape_hatch import compute_behavioral_clamp

            clamp_limit = compute_behavioral_clamp(snapshot, alerts, llm_score, _SCORE_CLEAN_IOC_CLAMP)
            score = min(llm_score, clamp_limit)
            dispatched = score > THREAT_HUNT_DISPATCH_THRESHOLD
            return await _finalize_hunt(prompt_hash, score, answer, dispatched, snapshot, pre_hunt)
        else:
            logger.info("[ThreatHunter] IOCs enriched but status mixed/unknown — no bonus, no clamp.")
            bonus = 0.0
    else:
        # No external IOCs — clamp to prevent hallucination dispatch on LAN traffic.
        bonus = 0.0
        if llm_score > _NO_EXTERNAL_IOC_CLAMP:
            logger.warning(
                "[ThreatHunter] No external IOCs — clamping LLM=%.2f to %.1f (no hallucination on LAN traffic).",
                llm_score,
                _NO_EXTERNAL_IOC_CLAMP,
            )
            llm_score = _NO_EXTERNAL_IOC_CLAMP
    score = min(llm_score + bonus, 1.0)
    dispatched = score > THREAT_HUNT_DISPATCH_THRESHOLD
    return await _finalize_hunt(prompt_hash, score, answer, dispatched, snapshot, pre_hunt)


async def _gather_context() -> tuple[dict[str, Any], list[tuple], str]:
    """Collect snapshot + alerts + memory in parallel, with truncation.

    Uses get_recent_alerts (not get_alerts_last_24h) to match what the LLM
    sees via the query_alert_history tool — Single Source of Truth. The LLM
    tool calls get_recent_alerts(limit=10) with no time filter, so the IOC
    detection layer must see the same window.
    """
    snapshot, alerts = await asyncio.gather(get_system_snapshot(), get_recent_alerts(THREAT_HUNT_MAX_ALERTS))
    memory = await recall_context(_HUNT_QUERY)
    # Baseline noise filter — known-benign conns (cloud CIDR / learned combo /
    # behavioral allowlist / intel whitelist) never reach the LLM prompt or the
    # IOC enrichment layer. No data → no "Lateral Movement" hallucination.
    await apply_snapshot_noise_filter(snapshot)
    return snapshot, alerts[:THREAT_HUNT_MAX_ALERTS], memory[:THREAT_HUNT_MAX_MEMORY_CHARS]
