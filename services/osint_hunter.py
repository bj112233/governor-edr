# services/osint_hunter.py
"""OSINT Hunter - orchestrates autonomous threat hunting with local baseline cross-reference.

Flow: run_hunt() -> store_intel() -> query net_baselines -> flag CRITICAL if local match.
"""

import logging

import aiosqlite

from services.metrics_db import _METRICS_DB_PATH as _NET_BASELINE_DB
from services.osint_memory import store_intel
from services.osint_react_loop import run_hunt
from services.rdap_lookup import check_domains_age
from services.react_budget import compute_budget

logger = logging.getLogger(__name__)


async def _check_local_baseline(iocs: dict[str, list[str]]) -> dict:
    """Check if any extracted IP/domain exists in local net_baselines."""
    targets = list(dict.fromkeys(iocs.get("ips_v4", []) + iocs.get("ips_v6", []) + iocs.get("domains", [])))
    if not targets:
        return {"matches": [], "critical": False}

    matches: list[str] = []
    try:
        async with aiosqlite.connect(_NET_BASELINE_DB) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            # Verify table exists before querying (DB may exist but table not initialized)
            cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='net_baselines'")
            if not await cursor.fetchone():
                logger.debug("[OSINTHunter] net_baselines table not initialized yet")
                return {"matches": [], "critical": False}

            placeholders = ",".join("?" * len(targets))
            cursor = await db.execute(
                f"SELECT DISTINCT remote_ip FROM net_baselines WHERE remote_ip IN ({placeholders})",
                tuple(targets),
            )
            rows = await cursor.fetchall()
            matches = [r[0] for r in rows]
    except Exception as exc:
        logger.warning("[OSINTHunter] Baseline query failed: %s", exc)

    return {"matches": matches, "critical": len(matches) > 0}


async def hunt_and_analyze(topic: str, source_text: str = "") -> dict:
    """Run full OSINT pipeline: hunt -> store -> cross-ref with local baseline."""
    logger.info("[OSINTHunter] Starting hunt for topic='%s'", topic)

    # 1. Autonomous ReAct hunt — dynamic budget based on topic complexity
    budget = compute_budget(topic)
    logger.info("[OSINTHunter] Budget for topic='%s': %d iterations", topic, budget)
    hunt_result = await run_hunt(topic, max_iterations=budget)

    # 2. Combine source_text + final_answer for storage
    raw_combined = f"Topic: {topic}\nSource: {source_text}\n\nReport:\n{hunt_result.get('final_answer', '')}"

    # 3. Store to vector memory
    iocs = hunt_result.get("iocs", {})
    try:
        await store_intel(topic, raw_combined, iocs)
    except Exception as exc:
        logger.warning("[OSINTHunter] store_intel failed: %s", exc)

    # 4. Cross-reference with local net_baselines
    baseline_check = await _check_local_baseline(iocs)

    # 5. RDAP domain age check — zero-day infrastructure detection
    # Physical law: fresh domain (< 30d) on legit cloud IP = C2 TTP.
    # IP reputation (AbuseIPDB) returns clean for Azure/AWS — domain age
    # is the unforgeable signal.
    domains = iocs.get("domains", [])
    rdap_check = await check_domains_age(domains) if domains else {
        "checked": 0, "critical_domains": [], "suspicious_domains": [], "has_critical": False,
    }

    # 6. Build unified report
    result = {
        "topic": topic,
        "report": hunt_result.get("final_answer", ""),
        "iocs": iocs,
        "iterations": hunt_result.get("iterations", 0),
        "critical_local_threat": baseline_check["critical"],
        "local_matches": baseline_check["matches"],
        "critical_fresh_domains": rdap_check["critical_domains"],
        "suspicious_fresh_domains": rdap_check["suspicious_domains"],
        "has_zero_day_infra": rdap_check["has_critical"],
    }

    if result["critical_local_threat"]:
        logger.critical(
            "[OSINTHunter] CRITICAL LOCAL THREAT - %d baseline matches: %s",
            len(result["local_matches"]),
            result["local_matches"],
        )
    else:
        logger.info("[OSINTHunter] No local baseline matches")

    if result["has_zero_day_infra"]:
        logger.critical(
            "[OSINTHunter] CRITICAL ZERO-DAY INFRA - %d fresh domains (<30d): %s",
            len(result["critical_fresh_domains"]),
            [d["domain"] for d in result["critical_fresh_domains"]],
        )

    return result
