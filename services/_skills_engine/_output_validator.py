# services/_skills_engine/_output_validator.py
"""Absolute Skill Sandboxing — schema-strict validation of skill output.

External skills run in isolated OS processes (shell=False), but their output
is text-injected into the LLM context window. Without a parsing layer, a
compromised or malformed skill could inject arbitrary text — including prompt
injection payloads — directly into the model's context.

This module enforces a hard schema boundary:
  - JSON output → validated as parseable JSON. Valid → passed through.
    Invalid → rejected with a structured error (raw text discarded).
  - Text output → allowed ONLY for skills in TEXT_OUTPUT_WHITELIST.
    Non-whitelisted skills returning free text → rejected.
  - Rejected output → replaced with a safe placeholder so the agent gets
    a deterministic signal instead of silence.

Policy: "JSON + whitelist text" — structured data is the default contract;
free text is an explicit opt-in per skill, reserved for summarizers whose
output IS the product (file-analyst summary, web-scraper content extract).
"""

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Skills whose output is legitimately free-form text (summaries, extracts).
# These are summarizers whose product IS natural language — not structured data.
# Adding a skill here is a deliberate trust decision: the skill's output goes
# through sanitize_injection_patterns + anomaly scoring downstream, but is NOT
# required to be JSON.
TEXT_OUTPUT_WHITELIST: frozenset[str] = frozenset(
    {
        "file-analyst",  # OCR + file summary — output is the analysis text
        "web-scraper",  # content extraction — output is the scraped text
        "translator-skill",  # translation — output is the translated text
        "report-maker",  # report generation — output is the rendered report
    }
)

# Skills that MUST return structured JSON (intel, OSINT, telemetry).
# Any skill NOT in TEXT_OUTPUT_WHITELIST is implicitly JSON-required.
JSON_REQUIRED_SKILLS: frozenset[str] = frozenset(
    {
        "intel-skill",
        "news-monitor",
        "pcap-analyst",
        "email-forensics",
        "persistence-hunter",
        "crypto-skill",
        "currency-skill",
        "geocode-skill",
        "stocks-skill",
        "weather-skill",
        "firewall-skill",
    }
)

_REJECTION_PLACEHOLDER = (
    "🛑 [SKILL-SANDBOX] Output rejected: did not match required schema "
    "(JSON expected for this skill). Raw output discarded for security. "
    "The skill may be malfunctioning or returning unstructured data."
)

_TEXT_REJECTION_PLACEHOLDER = (
    "🛑 [SKILL-SANDBOX] Output rejected: free-text output not permitted for "
    "this skill (not in text-output whitelist). Raw output discarded. "
    "The skill must return structured JSON."
)


@dataclass(frozen=True)
class ValidationResult:
    """Result of skill output validation.

    approved: True if output passes schema check and may proceed to LLM.
    sanitized_output: The output to inject (may be placeholder if rejected).
    rejected: True if output was discarded.
    reason: Human-readable explanation (for logging/audit).
    """

    approved: bool
    sanitized_output: str
    rejected: bool
    reason: str


def _is_valid_json(text: str) -> bool:
    """True if text is parseable JSON (object or array)."""
    if not text or not text.strip():
        return False
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return False
    try:
        json.loads(stripped)
        return True
    except json.JSONDecodeError:
        return False


def validate_skill_output(skill_name: str, raw_output: str) -> ValidationResult:
    """Validate skill output against the schema contract.

    Args:
        skill_name: The skill that produced the output (e.g. "intel-skill").
        raw_output: The decoded stdout from the skill subprocess.

    Returns:
        ValidationResult — approved output or rejection placeholder.
    """
    if not raw_output or not raw_output.strip():
        # Empty output is valid (e.g. "no results found" skills)
        return ValidationResult(True, raw_output, False, "empty output (allowed)")

    # Whitelisted text-output skills: free text is allowed
    if skill_name in TEXT_OUTPUT_WHITELIST:
        return ValidationResult(True, raw_output, False, "text-output whitelist match")

    # All other skills: JSON required
    if _is_valid_json(raw_output):
        return ValidationResult(True, raw_output, False, "valid JSON")

    # Rejection: non-whitelisted skill returning non-JSON text
    preview = raw_output.strip()[:120].replace("\n", " ")
    reason = f"non-JSON output from {skill_name} (not in text whitelist): preview='{preview}...'"
    logger.warning("[SKILL-SANDBOX] Rejected %s output: %s", skill_name, reason)
    placeholder = _TEXT_REJECTION_PLACEHOLDER if skill_name in JSON_REQUIRED_SKILLS else _REJECTION_PLACEHOLDER
    return ValidationResult(False, placeholder, True, reason)
