"""Tests for Temporal Decay — Over-fetch & Re-rank logic.

Verifies that final_score = semantic_score * decay_factor.

Calibration (2026-06-24): decay_lambda=0.001 → half-life ≈ 693h ≈ 29 days.
Design intent:
  - Recency is a TIEBREAKER, not a dominator.
  - Semantic match quality dominates ranking.
  - Deep past knowledge is NOT destroyed (only ~16% loss after 1 week).
  - Only true Ghost Penalties (very old + weak match) are suppressed.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from bot_memory.models import MemoryEntry

# Canonical production calibration — must match crud_search.py default.
DECAY_LAMBDA = 0.001  # half-life ≈ ln(2)/0.001 ≈ 693h ≈ 29 days


def test_combined_score_formula():
    """Pure unit test: verify the mathematical formula in isolation."""
    import math

    decay_lambda = DECAY_LAMBDA

    # Case 1: very recent, perfectly similar
    age_hours = 0.0
    distance = 0.0
    decay_factor = math.exp(-decay_lambda * age_hours)
    semantic_score = 1.0 / (1.0 + distance)
    final_score = semantic_score * decay_factor
    assert final_score == pytest.approx(1.0)

    # Case 2: 1 week old, perfectly similar — deep past knowledge survives
    # Under λ=0.001: exp(-0.168) ≈ 0.845 (only ~15.5% loss, NOT 82% like λ=0.01)
    age_hours = 168  # 1 week
    distance = 0.0
    decay_factor = math.exp(-decay_lambda * age_hours)
    semantic_score = 1.0 / (1.0 + distance)
    final_score = semantic_score * decay_factor
    assert final_score == pytest.approx(0.845, abs=0.01)

    # Case 3: recent but less semantically similar
    age_hours = 1.0
    distance = 0.5
    decay_factor = math.exp(-decay_lambda * age_hours)
    semantic_score = 1.0 / (1.0 + distance)
    final_score = semantic_score * decay_factor
    assert final_score == pytest.approx(0.666, abs=0.01)

    # Case 4: 1 week old AND semantically distant — true Ghost Penalty candidate
    age_hours = 168
    distance = 1.0
    decay_factor = math.exp(-decay_lambda * age_hours)
    semantic_score = 1.0 / (1.0 + distance)
    final_score = semantic_score * decay_factor
    assert final_score == pytest.approx(0.423, abs=0.01)

    # Case 5: 3 months old (2160h), perfectly similar — elephant memory
    # exp(-2.16) ≈ 0.115 — still retrievable if semantically perfect
    age_hours = 2160
    distance = 0.0
    decay_factor = math.exp(-decay_lambda * age_hours)
    semantic_score = 1.0 / (1.0 + distance)
    final_score = semantic_score * decay_factor
    assert final_score == pytest.approx(0.115, abs=0.01)


def test_memory_entry_has_distance_field():
    """MemoryEntry model accepts distance for HNSW propagation."""
    entry = MemoryEntry(query="q", response="r", distance=0.25)
    assert entry.distance == 0.25


def test_re_rank_sorting_order():
    """Verify re-rank sorts by final_score descending under λ=0.001.

    Design philosophy (29-day half-life):
      - Semantic match DOMINATES: a perfect old match beats a mediocre new one.
      - Recency is a TIEBREAKER: when semantic quality is equal, newer wins.
      - Deep past knowledge survives: 1-week-old perfect match retains ~84.5%.
    """
    import math

    decay_lambda = DECAY_LAMBDA
    now = datetime.now()

    def _score(entry: MemoryEntry) -> float:
        age_hours = (now - datetime.fromisoformat(entry.ts)).total_seconds() / 3600
        decay = math.exp(-decay_lambda * age_hours)
        semantic = 1.0 / (1.0 + entry.distance)
        return semantic * decay

    # recent + perfect → highest (recency tiebreak over old_perfect)
    recent_perfect = MemoryEntry(
        query="recent perfect",
        response="r",
        ts=now.isoformat(),
        distance=0.0,
    )

    # 1 week old + perfect → second (deep past knowledge survives at ~0.845)
    old_perfect = MemoryEntry(
        query="old perfect",
        response="r",
        ts=(now - timedelta(days=7)).isoformat(),
        distance=0.0,
    )

    # recent + weak semantic → third (recency cannot rescue poor match)
    recent_distant = MemoryEntry(
        query="recent distant",
        response="r",
        ts=now.isoformat(),
        distance=0.8,
    )

    entries = [recent_distant, old_perfect, recent_perfect]
    scored = [(e, _score(e)) for e in entries]
    scored.sort(key=lambda x: x[1], reverse=True)

    # recent_perfect wins (newest + perfect)
    assert scored[0][0] == recent_perfect
    # old_perfect second — semantic perfection survives the week (0.845 > 0.556)
    assert scored[1][0] == old_perfect
    # recent_distant last — weak semantic match loses despite recency
    assert scored[2][0] == recent_distant

    # Quantitative guards: prove the design intent numerically
    assert _score(old_perfect) == pytest.approx(0.845, abs=0.01)
    assert _score(recent_distant) == pytest.approx(0.556, abs=0.01)
    # The key invariant: old_perfect > recent_distant (semantic > recency)
    assert _score(old_perfect) > _score(recent_distant)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
