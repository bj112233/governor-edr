"""CoVe response parser — extracted from _agent_critic.py (file-length gate).

Parses the plain-text CoVe block (VERDICT/CLAIMS/EVIDENCE/LOGICAL_FLAW/REASON)
into a structured dict for the critic evaluation pipeline.
"""

import re

# Regex: bullet item with flexible spacing — catches "- claim", "-  claim", "* claim"
_BULLET_RE = re.compile(r"^[-*]\s*(.+)$")


def _parse_cove(response: str) -> dict:
    """Parse CoVe plain-text block into structured fields.

    Robust to minor format drift (flexible spacing, * or - bullets).
    Returns {"parse_ok": False} on empty/unparseable output.
    """
    lines = [ln.rstrip() for ln in response.strip().splitlines() if ln.strip()]
    if not lines:
        return {"parse_ok": False}

    verdict: bool | None = None
    reason = ""
    logical_flaw = ""
    claims: list[str] = []
    evidence: list[tuple[str, str]] = []  # (claim, evidence_or_NONE)
    section: str | None = None

    for ln in lines:
        stripped = ln.strip()
        upper = stripped.upper()
        if upper.startswith("VERDICT:"):
            section = "VERDICT"
            v = stripped[len("VERDICT:") :].strip().strip(":").strip()
            vm = re.match(r"^(PASS|FAIL)", v, re.IGNORECASE)
            verdict = (vm.group(1).upper() == "PASS") if vm else None
        elif upper.startswith("CLAIMS:"):
            section = "CLAIMS"
        elif upper.startswith("EVIDENCE:"):
            section = "EVIDENCE"
        elif upper.startswith("LOGICAL_FLAW:"):
            section = "LOGICAL_FLAW"
            logical_flaw = stripped[len("LOGICAL_FLAW:") :].strip()
        elif upper.startswith("REASON:"):
            section = "REASON"
            reason = stripped[len("REASON:") :].strip()
        else:
            m = _BULLET_RE.match(stripped)
            if m:
                item = m.group(1).strip()
                if section == "CLAIMS":
                    claims.append(item)
                elif section == "EVIDENCE":
                    # format: "<claim>: <evidence or NONE>"
                    if ":" in item:
                        cl, ev = item.split(":", 1)
                        evidence.append((cl.strip(), ev.strip()))
                    else:
                        evidence.append((item, "NONE"))
            elif section == "REASON" and not reason:
                reason = stripped
            elif section == "LOGICAL_FLAW" and not logical_flaw:
                logical_flaw = stripped

    return {
        "parse_ok": True,
        "verdict": verdict,
        "reason": reason,
        "logical_flaw": logical_flaw,
        "claims": claims,
        "evidence": evidence,
    }
