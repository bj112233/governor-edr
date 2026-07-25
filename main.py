import asyncio
import logging
import os
import sys

from config import TELEGRAM_CHAT_ID
from logging_config import setup_logging
from services.breaking_news import (
    get_breaking_news_monitor,
    stop_breaking_news_monitor,
)
from services.channel_loader import load_channels_json
from services.interfaces import set_message_gateway
from services.llm_bridge import LLMBridge, is_llm_ready, probe_llm_until_ready
from services.local_mcp_server import start_local_mcp_server
from services.scheduled_news import get_news_service, stop_news_service
from services.sentinel_events import (
    get_alert_queue,
)
from services.telegram import TelegramChannel, init_telegram_channel
from services.telegram.mcp_bridge import close_mcp_client
from services.telemetry import get_telemetry
from services.web_c2 import C2DashboardServer

logger = logging.getLogger(__name__)

from services.startup._broadcast import _telegram_event_broadcaster
from services.startup._health import await_all_services
from services.startup._scan_lan import _scan_lan_background

_background_tasks: set[asyncio.Task] = set()


from services.startup._scheduler import setup_scheduler
from services.startup._signal import _cancel_gracefully, _setup_signal_handlers, get_shutdown_event
from services.startup._workers import llm_analysis_worker, monitor_loop


async def main():
    setup_logging()
    logger.info("🔧 Initializing Sentinel")
    logger.info("   MCP Enabled: True | Autonomous Monitor: True")

    # Initialize alert_history schema (was _init_db() at module level, now async)
    logger.info("🗄️  Initializing alert_history DB...")
    from services.alert_history import _init_db as _init_alert_history_db

    await _init_alert_history_db()
    logger.info("   Alert history DB ready.")

    # Initialize DLQ schema (dead-letter queue for failed alert dispatches)
    from services.alert_dlq import init_dlq_schema

    await init_dlq_schema()
    logger.info("   Alert DLQ schema ready.")

    # Sprint 5: Migrate baseline tables to metrics.db (one-time, idempotent)
    from services.metrics_db import migrate_from_alert_history

    migrated = await migrate_from_alert_history()
    if migrated > 0:
        logger.info("📊 Migrated %d rows to metrics.db", migrated)
    else:
        logger.info("📊 metrics.db already up to date")

    # Sprint 5 Phase 2: Migrate memory tables to memory.db (one-time, idempotent)
    from services.memory_store import migrate_from_alert_history as migrate_memory

    migrated_mem = await migrate_memory()
    if migrated_mem > 0:
        logger.info("🧠 Migrated %d rows to memory.db", migrated_mem)
    else:
        logger.info("🧠 memory.db already up to date")

    # Pre-load skills engine async-safe (offloads sync file I/O to thread pool)
    logger.info("🔧 Pre-loading skills engine...")
    from services.skills_engine import get_skills_engine

    skills_engine = get_skills_engine()
    await skills_engine.load_async()
    logger.info("   Skills loaded: %s", skills_engine.list_skill_names())

    # Self-awareness baseline: register Sentinel's own PID + executable hashes
    # Prevents the agent from detecting its own OSINT connections and
    # defeats process masquerading attacks (name spoofing + DLL injection).
    logger.info("🛡️  Registering self-awareness baseline...")
    from services.self_whitelist import register_self_hash, set_sentinel_pid

    set_sentinel_pid(os.getpid())
    register_self_hash(sys.executable)  # Sentinel's python.exe
    # Register koboldcpp if found in PATH or common locations
    import shutil

    for kobold_name in ("koboldcpp.exe", "koboldcpp-server.exe"):
        kobold_path = shutil.which(kobold_name)
        if kobold_path:
            register_self_hash(kobold_path)
            break
    logger.info("   Self-awareness baseline ready (PID=%d, hashes=%d)", os.getpid(), 1)

    # טען תצורת ערוצים והפעל Telegram אם מופעל
    logger.info("📡 Loading channel configuration...")
    channels_cfg = load_channels_json()

    tg_task = None
    tg_channel = None
    broadcaster_task = None
    if channels_cfg.telegram.enabled:
        logger.info("📱 Initializing Telegram Channel...")
        tg_channel = init_telegram_channel(channels_cfg.telegram)
        set_message_gateway(tg_channel)  # type: ignore[arg-type]  # structural Protocol match
        tg_task = asyncio.create_task(tg_channel.start(), name="telegram_channel")
        # Consumer שמעביר אירועי Sentinel מה-event bus ל-admin ב-Telegram
        broadcaster_task = asyncio.create_task(_telegram_event_broadcaster(tg_channel), name="telegram_broadcaster")
        logger.info(
            f"   Telegram: dmPolicy={channels_cfg.telegram.dm_policy}, groupPolicy={channels_cfg.telegram.group_policy}"
        )
    else:
        logger.info("   Telegram: disabled in channels.json")

    # סריקת LAN - משימה עצמאית
    logger.info("🔍 Scanning LAN for known devices (background)...")
    lan_scan_task = asyncio.create_task(_scan_lan_background(), name="lan_scan")
    _background_tasks.add(lan_scan_task)
    lan_scan_task.add_done_callback(_background_tasks.discard)

    # הפעל Scheduled News Service
    logger.info("📰 Starting Scheduled News Service...")
    try:
        news_service = get_news_service()
        await news_service.initialize()
    except Exception as e:
        logger.warning(f"[NewsService] Initialization failed: {e}")

    # הפעל Breaking News Monitor
    logger.info("🚨 Starting Breaking News Monitor...")
    try:
        breaking_monitor = get_breaking_news_monitor()
        await breaking_monitor.initialize()
    except Exception as e:
        logger.warning(f"[BreakingNews] Initialization failed: {e}")

    # הפעל Local MCP Server לפני health check (כדי שפורט 11123 יענה)
    logger.info("🔌 Starting Local MCP Server on port 11123...")

    async def _start_mcp_safe():
        try:
            await start_local_mcp_server()
        except OSError as e:
            logger.error("[Main] MCP server failed to start (port in use?): %s", e)
            await asyncio.Event().wait()
        except Exception as e:
            logger.error("[Main] MCP server unexpected error: %s", e)
            await asyncio.Event().wait()

    mcp_task = asyncio.create_task(_start_mcp_safe(), name="local_mcp")

    # Non-blocking health observer — הבוט עולה מיידית, השירותים המקומיים "מתחברים" כשמוכנים
    logger.info("⏳ Spawning background health observer for local services...")
    health_observer_task = asyncio.create_task(
        await_all_services(
            {"KoboldCpp": 5001, "MCP": 11123},
            retry_interval=5,
            max_wait=300,
        ),
        name="services_health_observer",
    )
    _background_tasks.add(health_observer_task)
    health_observer_task.add_done_callback(_background_tasks.discard)

    # Sysmon service health check — non-fatal, logs warning if not running.
    # The bot works without Sysmon (psutil path), but the 4 enriched checks
    # (T1059.005, T1027, T1548.002, T1036) require Sysmon Event 1 telemetry.
    from services.startup._health import check_sysmon_health
    asyncio.create_task(check_sysmon_health(), name="sysmon_health_check")

    # Pre-compute skill embeddings for semantic routing (non-blocking fallback on failure)
    try:
        from services.agent import init_skill_embeddings

        await init_skill_embeddings()
    except Exception as e:
        logger.warning(f"[Startup] Skill embedding init failed: {e}")

    # Pre-compute system tool embeddings for semantic routing (after LLM is confirmed ready)
    try:
        from services.agent.routing import init_tool_embeddings

        await init_tool_embeddings()
    except Exception as e:
        logger.warning(f"[Startup] Tool embedding init failed: {e}")

    # הפעלת מתזמן משימות מקצועי לדוח היומי
    scheduler = setup_scheduler()

    # ── Web C2 Dashboard (LAN, Basic-Auth gated) ──
    from config import WEB_C2_HOST, WEB_C2_PORT

    dashboard = None
    try:
        dashboard = C2DashboardServer(host=WEB_C2_HOST, port=WEB_C2_PORT)
        await dashboard.start()
        logger.info("📊 C2 Dashboard: http://%s:%d", WEB_C2_HOST, WEB_C2_PORT)
    except OSError as e:
        logger.error("[Main] Dashboard start failed (port in use?): %s", e)

    alert_queue = get_alert_queue()

    # ── Readiness Probe: block until LLM is loaded into VRAM ──
    # Start the health loop early so it probes immediately, then wait for
    # the ready event before launching any workers that depend on the LLM.
    # This prevents the boot race condition where the bot (0.2s startup)
    # starts processing before KoboldCpp (10-30s GGUF load) is ready.
    _LLM_BOOT_TIMEOUT = 180  # 3 minutes max wait for VRAM load
    probe_task = asyncio.create_task(probe_llm_until_ready(), name="llm_probe")
    logger.info("⏳ Waiting for LLM (KoboldCpp) to boot and load into VRAM...")
    try:
        await asyncio.wait_for(
            LLMBridge.get_instance()._ready_event.wait(),
            timeout=_LLM_BOOT_TIMEOUT,
        )
        logger.info("✅ LLM is ONLINE and ready. Starting Sentinel workers...")
    except TimeoutError:
        logger.error("🚨 CRITICAL: LLM failed to boot within %ds — aborting.", _LLM_BOOT_TIMEOUT)
        probe_task.cancel()
        raise RuntimeError("LLM Boot Timeout — KoboldCpp did not become ready") from None

    # Start File Integrity Monitor (watchdog → YARA auto-scan)
    try:
        from config import FIM_ENABLED

        if FIM_ENABLED:
            from services.fim_engine import start_fim

            _fim_started = start_fim(asyncio.get_running_loop())
            if _fim_started:
                logger.info("🛡️ FIM (File Integrity Monitor) started — YARA auto-scan active")
    except Exception as exc:
        logger.warning("[Startup] FIM failed to start: %s", exc)

    # Start YARA rules watcher (hot-reload on rules/yara/ changes)
    try:
        from services.yara_rules_watcher import start_watcher

        _watcher_started = start_watcher(asyncio.get_running_loop())
        if _watcher_started:
            logger.info("🛡️ YARA rules watcher started — hot-reload on .yar changes (2s debounce)")
    except Exception as exc:
        logger.warning("[Startup] YARA rules watcher failed to start: %s", exc)

    # הליבה הקריטית: אם אחד מה-Tasks האלו נופל, כל התוכנה קורסת (NSSM יאתחל אותה)
    tasks = [
        probe_task,
        asyncio.create_task(monitor_loop(alert_queue, _background_tasks), name="monitor"),
        asyncio.create_task(llm_analysis_worker(alert_queue), name="llm_analysis"),
        asyncio.create_task(get_telemetry().proc_loop(60), name="telemetry_proc"),
        mcp_task,
    ]

    # הוסף משימת Telegram אם הופעלה
    if tg_task:
        tasks.append(tg_task)
    if broadcaster_task:
        tasks.append(broadcaster_task)
        logger.info("   Telegram Channel + Broadcaster added to critical tasks")

    # משימת shutdown - מחכה ל-SIGTERM ומבטל את כל השאר
    async def _shutdown_waiter():
        await get_shutdown_event().wait()
        logger.info("🛑 Shutdown signal received, initiating graceful shutdown...")

    # הוסף את משימת ה-shutdown לרשימה
    tasks.append(asyncio.create_task(_shutdown_waiter(), name="shutdown_waiter"))

    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        for t in done:
            task_exc: BaseException | None = t.exception()
            if task_exc is not None and not isinstance(task_exc, asyncio.CancelledError):
                logger.critical("🚨 Task '%s' crashed: %s", t.get_name(), task_exc, exc_info=task_exc)

        all_tasks = list(done) + list(pending)
        await _cancel_gracefully(all_tasks, timeout=10.0)
    finally:
        logger.info("🛑 Shutting down Sentinel...")
        if tg_channel:
            try:
                await asyncio.wait_for(tg_channel.stop(), timeout=5.0)
            except Exception:
                logger.warning("[Shutdown] Telegram stop timed out or failed")
        try:
            await close_mcp_client()
        except Exception:
            logger.warning("[Shutdown] MCP client close failed")
        try:
            await LLMBridge.get_instance().aclose()
        except Exception:
            logger.warning("[Shutdown] LLMBridge close failed")
        if dashboard is not None:
            try:
                await dashboard.stop()
            except Exception:
                logger.warning("[Shutdown] Dashboard stop failed")
        try:
            from services.db_pool import close_all_pools

            await close_all_pools()
            logger.info("[Shutdown] DB pools closed")
        except Exception:
            logger.warning("[Shutdown] DB pool close failed")
        scheduler.shutdown(wait=True)
        await stop_news_service()
        await stop_breaking_news_monitor()
        # Stop FIM observer
        try:
            from services.fim_engine import stop_fim

            stop_fim()
        except Exception:
            pass
        logger.info("✅ Sentinel shutdown complete.")


if __name__ == "__main__":
    _setup_signal_handlers()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Sentinel Offline - User Interrupted.")
    except SystemExit:
        logger.info("🛑 Sentinel Offline - Service Stop Requested.")
    except Exception as e:
        logger.critical(f"🚨 Fatal Error: {e}")
