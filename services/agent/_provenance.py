# services/agent/_provenance.py
"""Data Provenance & Taint Tracking — entity-source verification gate.

The Entity Verification audit (_agent_tool_audit.py) checks whether entities
(PIDs, IPs, file paths) in the draft answer appear in tool_data. This catches
hallucinations FROM the model but is blind to injections FROM external sources:
if an attacker embeds "PID 12345" in an RSS feed, it enters tool_data and
passes the audit — the system treats it as a "verified fact" simply because
it exists.

This module closes that vector by tracking WHICH tool produced each entity:
  - TRUSTED sources (system sensors: get_process_list, get_external_connections,
    etc.) → entity may drive execution actions (terminate_process, block_ip).
  - TAINTED sources (external: web_search, osint_hunt, skill_news_monitor,
    skill_intel, etc.) → entity is marked "tainted-only" and BLOCKED from
    execution actions until cross-verified against a trusted internal tool.

Flow:
  1. tool_runner registers every tool's output entities → ProvenanceRegistry
  2. Execution handlers (block_ip, terminate_process) call verify_execution_gate
     before queueing → blocked if tainted-only, with a directive to cross-verify
  3. Agent calls trusted tool (e.g. get_external_connections) → entity gets
     trusted provenance → retry succeeds (cross-verification unlocked)
"""

import logging
import re

logger = logging.getLogger(__name__)

# ── Entity extraction (shared patterns with _agent_tool_audit.py) ──
_PID_RE = re.compile(r"\bPID[:\s]*}?(\d{3,8})\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_IP_WHITELIST = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

# ── Trust classification ──
# Trusted: tools that read live Windows system state via WMI/psutil/netsh.
# Their output is ground truth — entities they report are real system state.
#
# Kernel-trusted tier (strongest): sysmon_consumer + analyze_process_event
# read from Sysmon ETW kernel telemetry. Stronger than psutil-based tools
# because process hollowing can lie to user-space APIs (psutil) but cannot
# easily lie to Sysmon's kernel hooks. Currently classified as trusted
# (same execution gate); a separate KERNEL_TRUSTED_TOOLS tier can be split
# out if future logic needs to distinguish (e.g. auto-trust without
# cross-verification).
TRUSTED_SYSTEM_TOOLS: frozenset[str] = frozenset(
    {
        "get_system_snapshot",
        "sentinel_get_system_snapshot_full",
        "get_process_list",
        "get_running_processes",
        "get_external_connections",
        "get_listening_ports",
        "get_network_adapters",
        "get_disk_details",
        "get_amd_gpu_info",
        "get_active_sessions",
        "get_local_users",
        "get_known_devices",
        "scan_suspicious_procs",
        "get_event_log",
        "get_services",
        "get_startup_items",
        "get_firewall_drops",
        "get_scheduled_tasks_detail",
        "analyze_cmdline",
        "analyze_process_event",  # Sysmon-enriched wrapper (kernel-trusted)
        "query_baseline_deviation",
        "sentinel_get_pending_events",
        "scan_lan",
    }
)

# Tainted: tools that return data from external/untrusted sources.
# Derived from _EXTERNAL_FACING_TOOLS (services/agent/utils.py) — kept in sync
# here as a separate frozenset to avoid a circular import (utils → agent → ...).
TAINTED_EXTERNAL_TOOLS: frozenset[str] = frozenset(
    {
        "web_search",
        "osint_hunt",
        "scan_infrastructure",
        "scan_credential_leaks",
        "scan_file_yara",
        "skill_file_analyst",
        "skill_web_scraper",
        "skill_intel",
        "skill_pcap_analyst",
        "skill_email_forensics",
        "skill_news_monitor",
    }
)

# Execution actions — state-mutating operations that must NOT be driven by
# tainted-only entities.
EXECUTION_ACTIONS: frozenset[str] = frozenset(
    {
        "terminate_process",
        "block_ip",
        "unblock_ip",
        "manage_service",
        "run_powershell",
        "defender_scan",
    }
)


def _extract_entities(text: str) -> set[str]:
    """Extract PIDs and IPs from tool output text."""
    if not text:
        return set()
    entities: set[str] = set()
    for pid in _PID_RE.findall(text):
        entities.add(f"PID:{pid}")
    for ip in _IPV4_RE.findall(text):
        if ip not in _IP_WHITELIST:
            entities.add(f"IP:{ip}")
    return entities


def _normalize_tool_name(name: str) -> str:
    """Normalize skill tool names for robust provenance matching.

    Skills generate tool names like 'skill_intel-skill' or
    'skill_file-analyst' (from SKILL.md name field), but the
    TAINTED_EXTERNAL_TOOLS list uses 'skill_intel', 'skill_file_analyst'.
    This function strips the 'skill_' prefix and '-skill' suffix, then
    converts hyphens to underscores — producing a canonical base name
    that matches regardless of the naming convention used.

    Non-skill tool names (web_search, osint_hunt, etc.) pass through
    unchanged after lowercasing.
    """
    base = name.lower()
    if base.startswith("skill_"):
        base = base[len("skill_") :]
    if base.endswith("-skill"):
        base = base[: -len("-skill")]
    return base.replace("-", "_")


def _is_trusted_tool(tool_name: str) -> bool:
    return tool_name in TRUSTED_SYSTEM_TOOLS


def _is_tainted_tool(tool_name: str) -> bool:
    """Check if tool is tainted, with skill-name normalization.

    Skill tools generate names like 'skill_intel-skill' but the tainted
    list uses 'skill_intel'. Normalization bridges this gap so external
    skills are always classified as tainted regardless of naming variant.
    """
    if tool_name in TAINTED_EXTERNAL_TOOLS:
        return True
    # Skill tools: normalize and check against normalized tainted set
    if tool_name.startswith("skill_"):
        normalized = _normalize_tool_name(tool_name)
        return any(_normalize_tool_name(t) == normalized for t in TAINTED_EXTERNAL_TOOLS)
    return False


class ProvenanceRegistry:
    """Session-scoped registry mapping entities → source tool provenance.

    Thread-safe enough for single-agent async usage (no concurrent agents
    share a registry instance). Reset via clear() at session start.
    """

    def __init__(self) -> None:
        self._entity_sources: dict[str, set[str]] = {}

    def register(self, tool_name: str, tool_output: str) -> None:
        """Record provenance: extract entities from tool_output, map → tool_name.

        H6 fix: ALL tools register entities (not just classified ones).
        Unclassified tools (read_file, query_alert_history, etc.) are
        treated as UNKNOWN — is_tainted_only() considers them tainted
        (fail-closed). This prevents file-based injection from bypassing
        the gate via unclassified tools.
        """
        if not tool_output:
            return
        entities = _extract_entities(tool_output)
        if not entities:
            return
        for entity in entities:
            self._entity_sources.setdefault(entity, set()).add(tool_name)
        logger.debug(
            "[Provenance] Registered %d entities from %s (trusted=%s, tainted=%s)",
            len(entities),
            tool_name,
            _is_trusted_tool(tool_name),
            _is_tainted_tool(tool_name),
        )

    def is_trusted(self, entity: str) -> bool:
        """True if ANY trusted system tool produced this entity."""
        sources = self._entity_sources.get(entity, set())
        return any(_is_trusted_tool(s) for s in sources)

    def is_tainted_only(self, entity: str) -> bool:
        """True if entity was produced ONLY by tainted/unknown external tools.

        H6 fix (Zero Trust / fail-closed): UNKNOWN tools (not in trusted
        or tainted lists) are treated as tainted. An entity from only
        unclassified sources is blocked at the execution gate.

        M3 fix (Byzantine tolerance): When tainted sources are present,
        a SINGLE trusted source is insufficient to launder the entity.
        At least 2 independent trusted sources are required. This
        prevents an attacker who compromises one trusted tool from
        using it to "verify" malicious entities from external sources.

        Returns False if:
          - entity has no recorded provenance (unknown — not blocked)
          - entity has only trusted sources (no taint to launder)
          - entity has tainted + 2+ trusted sources (cross-verified)
        Returns True if:
          - entity has only tainted/unknown sources
          - entity has tainted + only 1 trusted source (insufficient)
        """
        sources = self._entity_sources.get(entity, set())
        if not sources:
            return False
        trusted_sources = [s for s in sources if _is_trusted_tool(s)]
        untrusted_sources = [s for s in sources if not _is_trusted_tool(s)]
        if not untrusted_sources:
            # Only trusted sources — no taint to launder
            return False
        if not trusted_sources:
            # Only untrusted sources — tainted
            return True
        # M3: Both trusted and untrusted present — require 2+ trusted
        return len(trusted_sources) < 2

    def get_sources(self, entity: str) -> set[str]:
        """Return the set of source tools for an entity (for audit/diagnostics)."""
        return set(self._entity_sources.get(entity, set()))

    def clear(self) -> None:
        """Reset registry — call at session start."""
        self._entity_sources.clear()


# Module-level singleton — one registry per process (single-agent deployment).
# Tests call clear() between cases.
_registry = ProvenanceRegistry()


def get_registry() -> ProvenanceRegistry:
    """Access the shared provenance registry."""
    return _registry


def verify_execution_gate(entity: str, action_type: str) -> tuple[bool, str]:
    """Gate check before queueing an execution action.

    Args:
        entity: Normalized entity key ("IP:1.2.3.4" or "PID:12345").
        action_type: The execution action ("block_ip", "terminate_process", etc.)

    Returns:
        (allowed, reason): allowed=True if entity is trusted or unknown.
        allowed=False if entity is tainted-only — reason explains cross-verify.
    """
    if action_type not in EXECUTION_ACTIONS:
        return True, ""

    if not entity:
        return True, ""  # No entity to verify (e.g. defender_scan, screenshot)

    # M3 fix: Check is_tainted_only FIRST — it now requires 2+ trusted
    # sources to launder a tainted entity. is_trusted() returns True with
    # just 1 trusted source, which is insufficient when taint is present.
    if _registry.is_tainted_only(entity):
        sources = _registry.get_sources(entity)
        source_list = ", ".join(sorted(sources))
        return False, (
            f"BLOCKED by Provenance Gate: {entity} originated from tainted "
            f"external source(s) [{source_list}]. Cross-verify against 2+ "
            f"independent trusted system tools (e.g. get_external_connections "
            f"for IPs, get_process_list for PIDs) before retrying {action_type}."
        )

    if _registry.is_trusted(entity):
        return True, ""

    # Entity unknown to registry — allow (no evidence of taint; HITL still gates)
    return True, ""
