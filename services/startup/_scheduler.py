"""APScheduler setup — all cron jobs + db cleanup wrapper. Imports leaf modules."""

import asyncio
import functools
import logging
import zoneinfo
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from config import DAILY_DIGEST_HOUR, THREAT_HUNT_INTERVAL_HOURS
from services.bot_memory import cleanup_old_memories
from services.bot_memory.maintenance import run_memory_maintenance
from services.breaking_news import get_breaking_news_monitor
from services.memory_db import cleanup_old_baselines, cleanup_old_conversations
from services.memory_summarizer import run_daily_summarization
from services.net_baseline import cleanup_intel_whitelist
from services.night_watchman import run_memory_compaction
from services.scheduled_news import get_news_service
from services.startup._reporting import send_daily_digest
from services.threat_hunter import threat_hunt_job

logger = logging.getLogger(__name__)

# Per-job timeout in seconds (5 min default, 10 min for threat hunt)
_DEFAULT_JOB_TIMEOUT = 300
_THREAT_HUNT_TIMEOUT = 600


async def _with_timeout(
    coro: Awaitable[Any],
    timeout_s: int,
    job_id: str,
) -> Any:
    """Wrap a coroutine with timeout. Logs + swallows on timeout or error."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_s)
    except TimeoutError:
        logger.error("[Scheduler] Job %s timed out (>%ds) — killed", job_id, timeout_s)
    except Exception as e:
        logger.error("[Scheduler] Job %s failed: %s", job_id, e, exc_info=True)
    return None


def _timed(
    fn: Callable[..., Awaitable[Any]],
    job_id: str,
    timeout_s: int = _DEFAULT_JOB_TIMEOUT,
) -> Callable[..., Awaitable[Any]]:
    """Decorator: wrap an async job function with timeout + error handling."""

    @functools.wraps(fn)
    async def _wrapper(*args: Any, **kwargs: Any) -> Any:
        return await _with_timeout(fn(*args, **kwargs), timeout_s, job_id)

    _wrapper.__name__ = job_id
    _wrapper.__qualname__ = job_id
    return _wrapper


async def _run_db_cleanup() -> None:
    """Wrapper for scheduled conversation cleanup with safe error handling."""
    try:
        count = await cleanup_old_conversations(days=30)
        logger.info("[DB CLEANUP] Deleted %d old conversation rows", count)
    except Exception as e:
        logger.error("[DB CLEANUP] Cleanup failed: %s", e, exc_info=True)


async def _run_intel_whitelist_cleanup() -> None:
    """Purge expired intel_whitelist entries (hard TTL enforcement)."""
    try:
        count = await cleanup_intel_whitelist()
        logger.info("[INTEL WHITELIST CLEANUP] Purged %d expired entries", count)
    except Exception as e:
        logger.error("[INTEL WHITELIST CLEANUP] Cleanup failed: %s", e, exc_info=True)


async def _skill_health_job() -> None:
    """Periodic skill health pulse — ping skills and hide unhealthy from LLM."""
    try:
        from services.skill_health import SkillHealthService
        from services.skills_engine import get_skills_engine

        engine = get_skills_engine()
        svc = SkillHealthService(engine)
        await svc.pulse_all()
    except Exception as e:
        logger.warning("[Scheduler] Skill health pulse failed: %s", e)


def setup_scheduler() -> AsyncIOScheduler:
    """Configure and start APScheduler with all Sentinel jobs."""
    scheduler = AsyncIOScheduler(timezone=zoneinfo.ZoneInfo("Asia/Jerusalem"))

    scheduler.add_job(
        _timed(send_daily_digest, "daily_digest"),
        "cron",
        hour=DAILY_DIGEST_HOUR,
        minute=0,
        id="daily_digest",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )

    # News digest if enabled
    try:
        news_service = get_news_service()
        delivery_cfg = news_service.delivery_config
        if delivery_cfg.get("enabled", False):
            schedule_time = delivery_cfg.get("schedule_time", "08:00")
            hour = int(schedule_time.split(":")[0])
            minute = int(schedule_time.split(":")[1])
            scheduler.add_job(
                _timed(news_service.send_daily_digest, "daily_news_digest"),
                "cron",
                hour=hour,
                minute=minute,
                id="daily_news_digest",
                max_instances=1,
                coalesce=True,
                misfire_grace_time=600,
            )
            logger.info("[Scheduler] News digest scheduled at %s", schedule_time)
        else:
            logger.warning("[Scheduler] News digest disabled in config — skipping schedule")
    except Exception as e:
        logger.warning("[Scheduler] Failed to schedule news job: %s", e)

    # Breaking news monitor
    try:
        breaking_monitor = get_breaking_news_monitor()
        scheduler.add_job(
            _timed(breaking_monitor.check_breaking_news, "breaking_news_monitor", 120),
            "interval",
            minutes=10,
            id="breaking_news_monitor",
            max_instances=1,
        )
        logger.info("[Scheduler] Breaking News Monitor scheduled every 10 minutes")
    except Exception as e:
        logger.warning("[Scheduler] Failed to schedule breaking news job: %s", e)

    # Maintenance jobs
    scheduler.add_job(
        _timed(_run_db_cleanup, "db_cleanup"),
        "cron",
        hour=3,
        minute=0,
        id="db_cleanup",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] DB cleanup scheduled at 03:00 daily")

    scheduler.add_job(
        _timed(_run_intel_whitelist_cleanup, "intel_whitelist_cleanup"),
        "cron",
        hour=3,
        minute=30,
        id="intel_whitelist_cleanup",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Intel whitelist cleanup scheduled at 03:30 daily")

    scheduler.add_job(
        _timed(cleanup_old_memories, "memories_cleanup"),
        "cron",
        hour=4,
        minute=0,
        id="memories_cleanup",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Old memories cleanup scheduled at 04:00 daily")

    scheduler.add_job(
        _timed(cleanup_old_baselines, "baselines_cleanup"),
        "cron",
        hour=4,
        minute=15,
        id="baselines_cleanup",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Old baselines cleanup scheduled at 04:15 daily")

    # Memory maintenance: FTS5 integrity check + embedding backfill
    scheduler.add_job(
        _timed(run_memory_maintenance, "memory_maintenance"),
        "cron",
        hour=4,
        minute=30,
        id="memory_maintenance",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Memory maintenance (FTS5 + embedding backfill) at 04:30 daily")

    scheduler.add_job(
        _timed(run_daily_summarization, "memory_summarization", 500),
        "cron",
        hour=2,
        minute=30,
        id="memory_summarization",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Memory summarization scheduled at 02:30 daily")

    scheduler.add_job(
        _timed(run_memory_compaction, "night_watchman_compaction"),
        "cron",
        hour=5,
        minute=0,
        id="night_watchman_compaction",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Night Watchman scheduled at 05:00 daily")

    # Proactive threat hunting — every N hours (Agentic AI daemon)
    scheduler.add_job(
        _timed(threat_hunt_job, "threat_hunt", _THREAT_HUNT_TIMEOUT),
        "interval",
        hours=THREAT_HUNT_INTERVAL_HOURS,
        id="threat_hunt",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Threat hunt scheduled every %d hours", THREAT_HUNT_INTERVAL_HOURS)

    # Skill health pulse — every 5 minutes, plus immediate startup run
    scheduler.add_job(
        _timed(_skill_health_job, "skill_health_pulse", 60),
        "interval",
        seconds=300,
        id="skill_health_pulse",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        _timed(_skill_health_job, "skill_health_startup", 60),
        "date",
        run_date=datetime.now(UTC),
        id="skill_health_startup",
        replace_existing=True,
    )
    logger.info("[Scheduler] Skill health pulse every 5 min + startup")

    # DLQ Sweeper — retry failed alert dispatches with exponential backoff.
    # max_instances=1 + coalesce=True: prevents parallel sweepers when
    # Telegram API hangs for >5 min (would cause duplicate sends).
    async def _dlq_sweeper_job() -> None:
        from services.alert_dlq import sweep_dlq

        stats = await sweep_dlq()
        if stats["delivered"] or stats["failed"]:
            logger.info(
                "[Scheduler] DLQ sweep: %d delivered, %d retried, %d dead, %d failed",
                stats["delivered"],
                stats["retried"],
                stats["dead"],
                stats["failed"],
            )

    scheduler.add_job(
        _timed(_dlq_sweeper_job, "dlq_sweeper", 120),
        "interval",
        minutes=5,
        id="dlq_sweeper",
        max_instances=1,
        coalesce=True,
    )
    logger.info("[Scheduler] DLQ sweeper every 5 min (max_instances=1, coalesce=True)")

    # Threat feed refresh — Abuse.ch (URLhaus + ThreatFox) every 2h.
    # Pre-populates shared disk cache so pre-hunt enrichment hits cache
    # instead of triggering a full network fetch on first IOC check.
    async def _feed_refresh_job() -> None:
        from services.threat_feeds import refresh_feeds

        counts = await refresh_feeds()
        logger.info(
            "[Scheduler] Feed refresh: URLhaus=%d, ThreatFox=%d",
            counts.get("urlhaus", 0),
            counts.get("threatfox", 0),
        )

    scheduler.add_job(
        _timed(_feed_refresh_job, "feed_refresh", 60),
        "interval",
        hours=2,
        id="feed_refresh",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=300,
    )
    # Immediate startup run — populate cache before first threat hunt
    scheduler.add_job(
        _timed(_feed_refresh_job, "feed_refresh_startup", 60),
        "date",
        run_date=datetime.now(UTC),
        id="feed_refresh_startup",
        replace_existing=True,
    )
    logger.info("[Scheduler] Threat feed refresh every 2h + startup pre-fetch")

    # Weekly Auto-Reflection (Critic Node) — Friday 16:00
    # Offline batch self-critique: error lessons + telemetry + hunt stats → LLM reflection
    from services.reflection_agent import run_weekly_reflection

    scheduler.add_job(
        _timed(run_weekly_reflection, "weekly_reflection", 600),
        "cron",
        day_of_week=4,  # Friday (0=Monday, 6=Sunday)
        hour=16,
        minute=0,
        id="weekly_reflection",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Weekly reflection (Critic Node) scheduled at Friday 16:00")

    # Daily CTI SITREP — 08:30 (between security digest at 08:00 and news at 09:00)
    # Fetches CTI RSS feeds → LLM English summary → Telegram document
    from services.cti_sitrep import run_cti_sitrep

    scheduler.add_job(
        _timed(run_cti_sitrep, "daily_cti_sitrep", 300),
        "cron",
        hour=8,
        minute=30,
        id="daily_cti_sitrep",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )
    logger.info("[Scheduler] Daily CTI SITREP scheduled at 08:30")

    scheduler.start()
    logger.info(
        "[Scheduler] APScheduler configured for daily digest at %s:00",
        DAILY_DIGEST_HOUR,
    )

    return scheduler
