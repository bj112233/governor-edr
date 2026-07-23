"""Alert dispatcher helpers — IP extraction, enrichment, emit/persist.

Extracted from alert_dispatcher.py to reduce AlertDispatcher.dispatch
from F(47) to manageable complexity.
"""

import hashlib
import ipaddress
import logging
import re
from typing import Any, Optional

from services.alert_history import save_alert
from services.sentinel_events import send_alert_event

logger = logging.getLogger(__name__)

# Active alert context cache: alert_id → {ip, port, proc_name}
ACTIVE_ALERTS_CACHE: dict[str, dict[str, Any]] = {}


def _extract_net_context(alert: dict[str, Any]) -> tuple[str | None, int | str | None, str, int]:
    """Extract IP, PID, process name, port from a net alert's details.

    Returns (ip, pid, proc_name, port). Falls back to scraping IP from
    reason string if not found in details dict.
    """
    d = alert.get("details") or {}
    ip: str | None = None
    pid: int | str | None = None
    proc: str = "unknown"
    port: int = 0

    if isinstance(d, dict):
        ip = d.get("remote_ip") or d.get("raddr_ip") or d.get("ip") or d.get("dst_ip") or d.get("address")
        pid = d.get("pid")
        if pid is None and d.get("pids"):
            pid = d.get("pids", [None])[0]
        proc = d.get("proc") or d.get("process") or d.get("proc_name") or "unknown"
        port = d.get("remote_port", 0) or d.get("port", 0) or 0

    # Fallback: scrape IP from reason string and entire alert payload
    if not ip:
        _search_text = alert.get("reason", "")
        if isinstance(d, dict):
            _search_text += " " + str(d)
        _ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _search_text)
        if _ip_match:
            ip = _ip_match.group(0)

    # Validate IP
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ip = None

    return ip, pid, proc, port


def _cache_alert_context(ip: str, port: int, proc: str, *, auto_kill_id: int = 0, auto_block_id: int = 0) -> str:
    """Cache alert context and return short alert_id for Telegram callbacks.

    Args:
        auto_kill_id: pending_actions row ID for auto-queued kill (if any)
        auto_block_id: pending_actions row ID for auto-queued block (if any)
    """
    combo_raw = f"{ip}:{port}:{proc}"
    alert_id = hashlib.md5(combo_raw.encode()).hexdigest()[:8]
    ACTIVE_ALERTS_CACHE[alert_id] = {
        "ip": ip,
        "port": port,
        "proc_name": proc,
        "_auto_kill_id": auto_kill_id,
        "_auto_block_id": auto_block_id,
    }
    return alert_id


async def _enrich_and_escalate(
    alert: dict[str, Any], ip: str | None, rem: dict, enrich_ip, is_clean_enrichment
) -> None:
    """Enrich IP with threat intel; escalate severity if malicious; whitelist if clean."""
    if not ip or enrich_ip is None:
        return
    enrichment = await enrich_ip(ip)
    if not enrichment:
        return
    rem["intel"] = enrichment
    alert["_intel_enrichment"] = enrichment

    _abuse = enrichment.get("abuse") or {}
    _vt = enrichment.get("virustotal") or {}
    _score = enrichment.get("score", 0)
    if _abuse.get("abuse_confidence", 0) >= 50 or _vt.get("malicious", 0) > 0 or _score >= 50:
        if alert.get("severity") != "critical":
            logger.warning(
                "[AlertDispatch] ESCALATING %s to CRITICAL (intel score=%s abuse=%s vt_mal=%s)",
                ip,
                _score,
                _abuse.get("abuse_confidence"),
                _vt.get("malicious"),
            )
            alert["severity"] = "critical"

    # Auto-queue block when score >= 85 (CRITICAL_ACTIONABLE threshold)
    if _score >= 85:
        try:
            from services.pending_actions import queue_action

            alert_id = alert.get("id", "")
            ctx = {
                "score": _score,
                "reason": f"intel_score={_score} abuse={_abuse.get('abuse_confidence', 0)} vt_mal={_vt.get('malicious', 0)}",
                "source": "alert_dispatcher",
            }
            row_id = await queue_action(
                action_type="block_ip",
                target=ip,
                correlation_id=str(alert_id),
                threat_context=ctx,
            )
            rem["auto_block_queued"] = row_id
            logger.warning(
                "[AlertDispatch] AUTO-QUEUE block_ip #%d for %s (score=%d >= 85)",
                row_id,
                ip,
                _score,
            )
        except Exception as exc:
            logger.error("[AlertDispatch] Failed to auto-queue block for %s: %s", ip, exc)

    if is_clean_enrichment is not None and is_clean_enrichment(enrichment):
        try:
            from services.net_baseline import record_intel_whitelist

            await record_intel_whitelist(ip)
        except Exception:
            pass


async def _send_alert_raw(payload: dict[str, Any]) -> None:
    """Pure network emit — RAISES on failure. No DLQ, no swallowing.

    Called by both _emit_and_persist (main flow) and sweep_dlq (recovery).
    Separation prevents the recursion paradox where the sweeper's failure
    re-enters the main flow's except-handler and creates duplicate DLQ rows.
    """
    await send_alert_event(
        snapshot=payload.get("snapshot") or {},
        analysis=payload.get("analysis"),
        remediation=payload.get("remediation"),
    )


async def _emit_and_persist(alert: dict[str, Any], text: str, rem: dict, snapshot: dict | None, key: str) -> bool:
    """Emit alert to event bus and persist to alert history DB.

    On emit failure: enqueues to DLQ for sweeper retry (recursion-safe —
    the sweeper calls _send_alert_raw directly, not this function).
    Returns True if emit succeeded on first attempt.
    """
    payload = {"snapshot": snapshot or {}, "analysis": text, "remediation": rem, "key": key}
    sent_ok = False
    try:
        await _send_alert_raw(payload)
        sent_ok = True
        logger.info("[AlertDispatch] Sent %s (%s)", key, alert["severity"])
    except Exception as exc:
        logger.warning("[AlertDispatch] emit failed for %s: %s — enqueuing to DLQ", key, exc)
        try:
            from services.alert_dlq import enqueue_dlq

            await enqueue_dlq(payload, str(exc))
        except Exception as dlq_exc:
            logger.error("[AlertDispatch] DLQ enqueue FAILED for %s: %s", key, dlq_exc)

    try:
        await save_alert(f"{alert['category']}:{alert['metric']}", text[:500])
    except Exception as exc:
        logger.error(
            "[AlertDispatch] CRITICAL: save_alert failed for %s — audit trail LOST: %s",
            key,
            exc,
        )
    return sent_ok
