"""Deterministic branch rules — conditional DAG routing based on tool results.

Evaluates subtask results against a static rule table and returns a routing
decision: skip remaining subtasks, inject a new subtask, or continue normally.

This is the "Step 1" of dynamic DAG: deterministic, no LLM, no side effects.
Rules are intentionally conservative — false positives (skipping needed work)
are worse than false negatives (running unnecessary work).

Hook point: task_completion.py → _handle_subtask_done, after the subtask is
marked done and before advancing to the next subtask.
"""

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BranchDecision:
    """Result of branch rule evaluation.

    action: "continue" — normal advance to next subtask
            "skip_to_final" — mark remaining subtasks skipped, synthesize now
            "inject" — insert a new subtask at current position, then continue
    inject_description: str — for "inject", the description of the new subtask
    reason: str — human-readable explanation for logging
    """

    action: str = "continue"
    inject_description: str = ""
    reason: str = ""


# ── Rule table: (pattern, action, payload) ──────────────────────────────────
# payload is either a reason string (skip_to_final) or a subtask description
# (inject). Rules are evaluated in order; first match wins.
#
# Conservative design:
# - skip_to_final requires BOTH a clean indicator AND no anomalies (two patterns
#   must match in the same result — checked in _evaluate_branch_rules, not here)
# - inject rules target specific, high-signal patterns (C2 ports, suspicious
#   IOC flags) — not generic keywords
# - All patterns are case-insensitive where appropriate
#
# Patterns match the ACTUAL tool output formats (verified via live runs):
#   sentinel_get_system_snapshot_full → Markdown Hebrew: "מצב מערכת: תקין"
#   scan_suspicious_procs → "[PROCESS_SCAN_RESULT] Found N suspicious-name..."
#   get_process_list → process table
#   scan_lan / port scan → JSON or text with port states
#
# IMPORTANT: skip_to_final is DISABLED for threat hunting. A clean surface
# snapshot ("מצב מערכת: תקין") does NOT mean the system is safe — deeper
# scans (process scan, network analysis) often reveal hidden threats.
# Threat hunting requires digging DEEPER when the surface looks clean,
# not skipping the deep scans. Only inject rules are active.

_SKIP_RULES: tuple[tuple[re.Pattern, str], ...] = ()

_NO_ANOMALY_RULES: tuple[tuple[re.Pattern, str], ...] = ()

_INJECT_RULES: tuple[tuple[re.Pattern, str, str], ...] = (
    # C2 port 4444 (Meterpreter default) → inject memory scan
    # Matches both JSON ("port": 4444, "state": "open") and natural text
    # ("Port 4444 is listening"). Does NOT match "closed" or "filtered".
    (
        re.compile(
            r"(?:"
            r'"port"\s*:\s*4444\b[^}]*?"state"\s*:\s*"(?:open|listening|active)"'  # JSON
            r"|"
            r"\b4444\b\s+(?:is\s+)?(?:open|listening|active)\b"  # natural text
            r")",
            re.IGNORECASE | re.DOTALL,
        ),
        "Scan process memory for injection artifacts using scan_memory_for_injection",
        "C2 port 4444 detected — injecting memory scan",
    ),
    # Suspicious IOC flag → inject IOC enrichment
    (
        re.compile(r'"suspicious"\s*:\s*true', re.IGNORECASE),
        "Enrich suspicious IOC with skill_intel-skill",
        "Suspicious IOC flag detected — injecting enrichment",
    ),
    # High TTP score (score=80+, indicates real threat) → inject deeper analysis
    (
        re.compile(r"TTP:\s*T\d{4}(?:\.\d{3})?\s*\(score=(?:8\d|9\d|100)\b"),
        "Perform deep MITRE TTP analysis and IOC extraction using skill_intel-skill",
        "High TTP score detected — injecting deep analysis",
    ),
    # Known malicious PID pattern → inject process detail fetch
    (
        re.compile(r'"malicious"_pid"\s*:\s*(\d+)', re.IGNORECASE),
        "Get detailed process information for the flagged PID using get_process_details",
        "Malicious PID flagged — injecting process detail fetch",
    ),
)


def _has_no_anomalies(result: str) -> bool:
    """Check if the result explicitly indicates no anomalies."""
    for pattern, _ in _NO_ANOMALY_RULES:
        if pattern.search(result):
            return True
    return False


def _evaluate_branch_rules(
    result: str,
    subtasks: list[dict],
    completed_idx: int,
) -> BranchDecision:
    """Evaluate branch rules against a completed subtask's result.

    Args:
        result: The subtask result text (tool output / synthesized data).
        subtasks: The full subtask list (for checking remaining work).
        completed_idx: Index of the just-completed subtask (0-based).

    Returns:
        BranchDecision with action, optional inject_description, and reason.
    """
    if not result or not subtasks:
        return BranchDecision(action="continue")

    remaining = subtasks[completed_idx + 1 :]
    if not remaining:
        return BranchDecision(action="continue")

    # ── Skip rules: require BOTH clean indicator AND no anomalies ──
    # When triggered, skip intermediate subtasks and jump directly to the
    # final_answer/synthesis subtask (if one exists). If no final_answer
    # subtask remains, skip all remaining and synthesize from what we have.
    for pattern, reason in _SKIP_RULES:
        if pattern.search(result) and _has_no_anomalies(result):
            logger.info(
                "[BRANCH-RULES] Skip-to-final triggered: %s (result preview: %.80s)",
                reason,
                result,
            )
            return BranchDecision(action="skip_to_final", reason=reason)

    # ── Inject rules: high-signal patterns → add subtask ──
    for pattern, inject_desc, reason in _INJECT_RULES:
        if pattern.search(result):
            logger.info(
                "[BRANCH-RULES] Inject triggered: %s (pattern=%s, result preview: %.80s)",
                reason,
                pattern.pattern,
                result,
            )
            return BranchDecision(
                action="inject",
                inject_description=inject_desc,
                reason=reason,
            )

    return BranchDecision(action="continue")
