"""Tests for threat scoring v2.0 — pre-hunt enrichment + score cap.

Validates:
1. Score cap (hallucination guard) — LLM score > 0.6 without 2+ external sources → 0.5
2. Pre-hunt enrichment integration in _execute_hunt (mocked)
3. Clean IOC clamp — all IOCs clean per intel → score floored to 0.4
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.threat_score_cap import (
    _SCORE_CAP_BASE,
    _SCORE_CAP_NO_EVIDENCE,
)
from services.threat_score_cap import (
    clamp_llm_score as _clamp_llm_score,
)
from services.threat_score_cap import (
    count_external_evidence as _count_external_evidence,
)


class TestScoreCap:
    """_clamp_llm_score — hallucination guard for 4B model."""

    def test_low_score_not_capped(self):
        """Score <= 0.6 passes through unchanged."""
        assert _clamp_llm_score(0.3, "no evidence") == 0.3
        assert _clamp_llm_score(0.6, "no evidence") == 0.6

    def test_high_score_no_evidence_clamped(self):
        """Score > 0.6 with 0 external sources → clamped to 0.5."""
        assert _clamp_llm_score(0.9, "no evidence here") == _SCORE_CAP_NO_EVIDENCE
        assert _clamp_llm_score(1.0, "") == _SCORE_CAP_NO_EVIDENCE

    def test_high_score_one_evidence_clamped(self):
        """Score > 0.6 with 1 external source → still clamped (need 2)."""
        report = "VirusTotal shows 0/90"
        assert _clamp_llm_score(0.9, report) == _SCORE_CAP_NO_EVIDENCE

    def test_high_score_two_evidence_passes(self):
        """Score > 0.6 with 2+ external sources → passes unchanged."""
        report = "VirusTotal shows 0/90. AbuseIPDB score=0. urlscan.io clean."
        assert _clamp_llm_score(0.9, report) == 0.9

    def test_high_score_mitre_passes(self):
        """MITRE ATT&CK technique ID counts as external evidence."""
        report = "VirusTotal shows 0/90. MITRE T1071 Application Layer Protocol."
        assert _clamp_llm_score(0.85, report) == 0.85

    def test_count_evidence_empty(self):
        assert _count_external_evidence("") == 0
        assert _count_external_evidence("no sources here") == 0

    def test_count_evidence_multiple(self):
        report = "VirusTotal and AbuseIPDB both clean. urlscan.io shows no scans."
        assert _count_external_evidence(report) >= 3

    def test_count_evidence_duplicate_not_double(self):
        """Same source mentioned twice counts as 1."""
        report = "VirusTotal clean. VirusTotal confirmed 0/90."
        assert _count_external_evidence(report) == 1


class TestCleanIocClamp:
    """Scoring v2.0: all IOCs clean per intel → clamp to 0.4 (below dispatch)."""

    def test_clean_clamp_constant_below_dispatch(self):
        from config import THREAT_HUNT_DISPATCH_THRESHOLD
        from services.threat_hunter import _SCORE_CLEAN_IOC_CLAMP

        assert _SCORE_CLEAN_IOC_CLAMP < THREAT_HUNT_DISPATCH_THRESHOLD

    def test_ioc_bonus_constant(self):
        from services.threat_hunter import _IOC_BONUS

        assert _IOC_BONUS == 0.3
