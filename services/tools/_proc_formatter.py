"""Process scan formatting — Pre-Compute Deterministic Enrichment.

Extracted from system_tools.py to respect 300-line file limit.

Architecture principle: scan_suspicious_procs + analyze_cmdline are unified
at the Python engine level. The LLM receives hard facts (pre-analyzed TTP
verdicts), not raw cmdlines it must chain-tool to analyze.

This prevents 4B model hallucination (inventing fake cmdlines).
"""

from services.cmdline_analyzer import analyze_cmdline
from services.monitor_engine import _scan_suspicious_procs


def format_cmdline_analysis(cmdline: str) -> str:
    """Format cmdline_analyzer results as Telegram-ready text."""
    matches = analyze_cmdline(cmdline)
    if not matches:
        return "✅ No suspicious patterns detected in command line."
    lines = [f"🚨 **MITRE TTP Analysis** ({len(matches)} match(es)):"]
    for m in matches:
        lines.append(f"- **{m.technique_id}** {m.name} ({m.tactic})")
        lines.append(f"  Confidence: {m.confidence:.0%} | Score: {m.suggested_score}")
        if m.signals:
            lines.append(f"  Signals: {', '.join(m.signals)}")
    return "\n".join(lines)


def format_suspicious_procs() -> str:
    """Format suspicious process scan + deterministic cmdline analysis.

    Pre-Compute Deterministic Enrichment: runs analyze_cmdline on every
    suspicious process at the engine level — the LLM receives hard facts,
    not raw cmdlines it must chain-tool to analyze.

    This prevents 4B model hallucination (inventing fake cmdlines).
    """
    procs = _scan_suspicious_procs()
    if not procs:
        return "✅ No suspicious processes detected (powershell, wmic, certutil, mshta)."

    lines = [f"[PROCESS_SCAN_RESULT] Found {len(procs)} suspicious-name process(es)."]
    any_ttp = False
    for p in procs:
        pid = p.get("pid", "?")
        name = p.get("name", "?")
        cmdline = p.get("cmdline", "")
        cmdline_display = cmdline[:200] or "(empty)"

        # Deterministic cmdline analysis at engine level
        matches = analyze_cmdline(cmdline) if cmdline else []
        if matches:
            any_ttp = True
            ttp_summary = "; ".join(
                f"{m.technique_id} (score={m.suggested_score}, {m.confidence:.0%})" for m in matches
            )
            lines.append(f"- PID {pid} | {name} | TTP: {ttp_summary} | cmdline: {cmdline_display}")
        else:
            lines.append(f"- PID {pid} | {name} | TTP: CLEAN (no MITRE patterns) | cmdline: {cmdline_display}")

    if not any_ttp:
        lines.append(
            "Cmdline analysis: CLEAN. No T1059.001 detected. No bypassed execution policies. No encoded commands."
        )
    return "\n".join(lines)
